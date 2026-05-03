//! FF1 Format-Preserving Encryption as a PRP (HarmonyPIR1).
//!
//! # Overview
//!
//! FF1 is a NIST-standardized Format-Preserving Encryption scheme (SP 800-38G).
//! It encrypts values within an arbitrary domain while preserving the domain:
//! if the input is in [0, N'), the output is also in [0, N').
//!
//! HarmonyPIR1 uses FF1 to instantiate the random permutation over [2N].
//! This is much faster than the Hoang PRP (HarmonyPIR0) because FF1 uses
//! a Feistel structure with only ~10 rounds (vs. Θ(log N + 40) rounds for Hoang).
//!
//! # Security requirement
//!
//! Per NIST recommendation (SP 800-38G, Appendix A.2), the domain must contain
//! at least 10^6 elements for adequate security against known attacks.
//! This means 2N ≥ 10^6, so the database must have N ≥ 500,000 entries.
//!
//! # Cycle-walking
//!
//! FF1 with radix 2 operates on bit strings of fixed length `num_bytes * 8`.
//! The effective domain is 2^(num_bytes*8), which may be larger than our target
//! domain 2N. We use **cycle-walking**: encrypt repeatedly until the output
//! falls within [0, 2N). This terminates quickly since 2^(num_bytes*8) < 2*(2N).

use fpe::ff1::{BinaryNumeralString, FF1};

use super::Prp;

/// FF1-based PRP for HarmonyPIR1.
///
/// Wraps the `fpe` crate's FF1 implementation with cycle-walking
/// to handle non-power-of-2 domain sizes.
pub struct Ff1Prp {
    /// The FF1 instance (radix 2).
    ff1: FF1<aes::Aes128>,
    /// The target domain size (2N).
    domain_size: usize,
    /// Number of bytes for the BinaryNumeralString representation.
    /// Each byte provides 8 binary numerals. We use ceil(log2(domain_size) / 8) bytes.
    num_bytes: usize,
    /// Empty tweak (we don't use FF1 tweaks).
    tweak: Vec<u8>,
}

/// Minimum domain size for FF1 per NIST SP 800-38G.
pub const FF1_MIN_DOMAIN: usize = 1_000_000;

impl Ff1Prp {
    /// Create a new FF1 PRP.
    ///
    /// - `domain_size`: must be ≥ 1,000,000 per NIST recommendation.
    /// - `key`: 16-byte AES-128 key.
    ///
    /// # Panics
    /// Panics if `domain_size < FF1_MIN_DOMAIN`.
    pub fn new(domain_size: usize, key: &[u8; 16]) -> Self {
        assert!(
            domain_size >= FF1_MIN_DOMAIN,
            "FF1 domain {domain_size} < minimum {FF1_MIN_DOMAIN}"
        );

        // Number of bits needed to represent domain_size - 1.
        let num_bits = usize::BITS - (domain_size - 1).leading_zeros();
        // Number of bytes: ceil(num_bits / 8). Must be >= 1.
        let num_bytes = ((num_bits as usize + 7) / 8).max(1);

        // FF1::new takes key as &[u8] and radix.
        let ff1 = FF1::<aes::Aes128>::new(key, 2)
            .expect("FF1 construction should succeed with radix 2");

        Ff1Prp {
            ff1,
            domain_size,
            num_bytes,
            tweak: Vec::new(),
        }
    }

    /// Convert a usize to a BinaryNumeralString (little-endian byte encoding).
    ///
    /// The `fpe` crate's `BinaryNumeralString::from_bytes_le` interprets each
    /// byte in little-endian bit order. We encode `x` as `num_bytes` LE bytes.
    fn to_bns(&self, x: usize) -> BinaryNumeralString {
        let mut bytes = vec![0u8; self.num_bytes];
        let x_bytes = x.to_le_bytes();
        let copy_len = self.num_bytes.min(x_bytes.len());
        bytes[..copy_len].copy_from_slice(&x_bytes[..copy_len]);
        BinaryNumeralString::from_bytes_le(&bytes)
    }

    /// Convert a BinaryNumeralString back to usize.
    fn from_bns(&self, bns: &BinaryNumeralString) -> usize {
        let bytes = bns.to_bytes_le();
        let mut buf = [0u8; 8];
        let copy_len = bytes.len().min(8);
        buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
        u64::from_le_bytes(buf) as usize
    }
}

impl Prp for Ff1Prp {
    fn forward(&self, x: usize) -> usize {
        assert!(x < self.domain_size, "input {x} >= domain {}", self.domain_size);
        let mut val = x;
        loop {
            let bns = self.to_bns(val);
            let encrypted = self.ff1.encrypt(&self.tweak, &bns).expect("FF1 encrypt failed");
            val = self.from_bns(&encrypted);
            if val < self.domain_size {
                return val;
            }
            // Cycle-walk: encrypt again until in range.
        }
    }

    fn inverse(&self, y: usize) -> usize {
        assert!(y < self.domain_size, "input {y} >= domain {}", self.domain_size);
        let mut val = y;
        loop {
            let bns = self.to_bns(val);
            let decrypted = self.ff1.decrypt(&self.tweak, &bns).expect("FF1 decrypt failed");
            val = self.from_bns(&decrypted);
            if val < self.domain_size {
                return val;
            }
            // Cycle-walk: decrypt again until in range.
        }
    }

    fn domain(&self) -> usize {
        self.domain_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use the minimum domain for tests to keep them fast.
    const TEST_DOMAIN: usize = FF1_MIN_DOMAIN;

    #[test]
    fn test_forward_inverse_roundtrip() {
        let key = [0x42u8; 16];
        let prp = Ff1Prp::new(TEST_DOMAIN, &key);

        // Test a sample of values (full test of 10^6 values would be slow).
        for x in (0..TEST_DOMAIN).step_by(TEST_DOMAIN / 100) {
            let y = prp.forward(x);
            assert!(y < TEST_DOMAIN);
            let x_back = prp.inverse(y);
            assert_eq!(x_back, x, "inverse(forward({x})) = {x_back} != {x}");
        }
    }

    #[test]
    fn test_is_permutation_small_sample() {
        let key = [0xAB; 16];
        let prp = Ff1Prp::new(TEST_DOMAIN, &key);

        // Check a small range for injectivity.
        let range = 1000;
        let mut outputs: Vec<usize> = (0..range).map(|x| prp.forward(x)).collect();
        let len_before = outputs.len();
        outputs.sort();
        outputs.dedup();
        assert_eq!(outputs.len(), len_before, "forward is not injective in [0, {range})");
    }
}
