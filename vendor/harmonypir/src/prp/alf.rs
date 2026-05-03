//! ALF format-preserving encryption as a PRP.
//!
//! Wraps the `alf-nt` crate (entirely unsafe SIMD) with a safe API that
//! implements the HarmonyPIR [`Prp`] trait.
//!
//! # Performance characteristics
//!
//! - Per-element: ~83 ns single, ~24 ns batched (at domain ~6M on Apple Silicon).
//! - Batch encrypt uses 4-way AES-NI/NEON pipelining for binary domains.
//!
//! # Per-group differentiation
//!
//! ALF has native tweak support. Each PBC group gets a different 16-byte tweak
//! with the same key. Use [`AlfEngine`] as a factory to create per-group PRP
//! instances efficiently.
//!
//! # Domain requirements
//!
//! ALF requires bit_width >= 16, meaning domain >= 2^15 + 1 = 32769.
//! For safety, we enforce domain >= 65536 (2^16).

use alf_nt::alf_nt::AlfNt;
use alf_nt::bigint::M192i;
use alf_nt::ktm::Ktm;
use rayon::prelude::*;

use super::{BatchPrp, Prp};

/// Minimum domain size for ALF (bit_width must be >= 16).
pub const ALF_MIN_DOMAIN: usize = 65536;

/// ALF format-preserving encryption implementing the [`Prp`] trait.
///
/// Holds two `AlfNt` instances: one for encryption (forward), one for
/// decryption (inverse). This is necessary because `prepare_decrypt()`
/// mutates the round keys in-place.
pub struct AlfPrp {
    /// Instance configured for encryption.
    enc: AlfNt,
    /// Instance configured for decryption.
    dec: AlfNt,
    /// Domain size (qmax + 1).
    domain_size: usize,
    /// Number of data bytes ALF reads/writes: n + (1 if t > 0).
    data_bytes: usize,
}

impl AlfPrp {
    /// Create a new ALF PRP.
    ///
    /// - `key`: 16-byte AES key.
    /// - `domain_size`: permutation domain [0, domain_size). Must be >= 65536.
    /// - `tweak`: 16-byte tweak (use different tweaks per PBC group).
    /// - `app_id`: application identifier (fixed across all groups).
    ///
    /// # Panics
    ///
    /// Panics if `domain_size < 65536`.
    pub fn new(key: &[u8; 16], domain_size: usize, tweak: &[u8; 16], app_id: u64) -> Self {
        assert!(
            domain_size >= ALF_MIN_DOMAIN,
            "ALF domain {domain_size} < minimum {ALF_MIN_DOMAIN} (bit_width must be >= 16)"
        );

        let qmax = M192i::set1(domain_size as u64 - 1);

        unsafe {
            // Build encryption instance.
            let mut enc = AlfNt::new();
            enc.engine_init(qmax, 0);
            let mut ktm = Ktm::new();
            enc.key_init(&mut ktm, key, app_id);
            enc.tweak_init(&ktm, tweak);

            // Build decryption instance (same init, then prepare for decrypt).
            let mut dec = AlfNt::new();
            dec.engine_init(qmax, 0);
            let mut ktm_dec = Ktm::new();
            dec.key_init(&mut ktm_dec, key, app_id);
            dec.tweak_init(&ktm_dec, tweak);
            dec.prepare_decrypt();

            let data_bytes = enc.n + if enc.t > 0 { 1 } else { 0 };

            Self {
                enc,
                dec,
                domain_size,
                data_bytes,
            }
        }
    }

    /// Encrypt a single value (forward permutation).
    fn encrypt_value(&self, x: usize) -> usize {
        let mut buf = [0u8; 32];
        let x_bytes = (x as u64).to_le_bytes();
        let copy_len = self.data_bytes.min(8);
        buf[..copy_len].copy_from_slice(&x_bytes[..copy_len]);
        unsafe {
            self.enc.encrypt(&mut buf);
        }
        self.read_value(&buf)
    }

    /// Decrypt a single value (inverse permutation).
    fn decrypt_value(&self, y: usize) -> usize {
        let mut buf = [0u8; 32];
        let y_bytes = (y as u64).to_le_bytes();
        let copy_len = self.data_bytes.min(8);
        buf[..copy_len].copy_from_slice(&y_bytes[..copy_len]);
        unsafe {
            self.dec.decrypt(&mut buf);
        }
        self.read_value(&buf)
    }

    /// Read a domain value from the ALF output buffer (little-endian).
    fn read_value(&self, buf: &[u8]) -> usize {
        let mut val_bytes = [0u8; 8];
        let copy_len = self.data_bytes.min(8);
        val_bytes[..copy_len].copy_from_slice(&buf[..copy_len]);
        u64::from_le_bytes(val_bytes) as usize
    }
}

impl Prp for AlfPrp {
    fn forward(&self, x: usize) -> usize {
        assert!(
            x < self.domain_size,
            "input {x} >= domain {}",
            self.domain_size
        );
        self.encrypt_value(x)
    }

    fn inverse(&self, y: usize) -> usize {
        assert!(
            y < self.domain_size,
            "input {y} >= domain {}",
            self.domain_size
        );
        self.decrypt_value(y)
    }

    fn domain(&self) -> usize {
        self.domain_size
    }
}

impl BatchPrp for AlfPrp {
    fn batch_forward(&self) -> Vec<usize> {
        (0..self.domain_size)
            .into_par_iter()
            .map(|x| self.encrypt_value(x))
            .collect()
    }
}

/// Factory for creating [`AlfPrp`] instances with different tweaks.
///
/// In the Bitcoin UTXO PIR use case, all PBC groups share the same key
/// and domain size, but each gets a unique tweak. `AlfEngine` stores
/// the shared parameters and produces per-group PRP instances.
pub struct AlfEngine {
    key: [u8; 16],
    domain_size: usize,
    app_id: u64,
}

impl AlfEngine {
    /// Create a new engine.
    ///
    /// - `key`: 16-byte AES key (shared across all groups).
    /// - `domain_size`: permutation domain (same for all groups).
    /// - `app_id`: application identifier.
    pub fn new(key: [u8; 16], domain_size: usize, app_id: u64) -> Self {
        Self {
            key,
            domain_size,
            app_id,
        }
    }

    /// Create a PRP for a specific PBC group using an explicit tweak.
    pub fn create_prp(&self, tweak: &[u8; 16]) -> AlfPrp {
        AlfPrp::new(&self.key, self.domain_size, tweak, self.app_id)
    }

    /// Create a PRP using `group_id` encoded as a little-endian tweak.
    pub fn create_prp_for_group(&self, group_id: u64) -> AlfPrp {
        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&group_id.to_le_bytes());
        self.create_prp(&tweak)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DOMAIN: usize = ALF_MIN_DOMAIN; // 65536

    #[test]
    fn test_forward_inverse_roundtrip() {
        let key = [0x42u8; 16];
        let tweak = [0u8; 16];
        let prp = AlfPrp::new(&key, TEST_DOMAIN, &tweak, 0);

        // Test a sample (full 64K is slow in debug mode).
        for x in (0..TEST_DOMAIN).step_by(TEST_DOMAIN / 100) {
            let y = prp.forward(x);
            assert!(y < TEST_DOMAIN, "forward({x}) = {y} out of range");
            let x_back = prp.inverse(y);
            assert_eq!(x_back, x, "inverse(forward({x})) = {x_back} != {x}");
        }
    }

    #[test]
    fn test_is_permutation_sample() {
        let key = [0xAB; 16];
        let tweak = [1u8; 16];
        let prp = AlfPrp::new(&key, TEST_DOMAIN, &tweak, 0);

        let range = 1000;
        let mut outputs: Vec<usize> = (0..range).map(|x| prp.forward(x)).collect();
        let before = outputs.len();
        outputs.sort();
        outputs.dedup();
        assert_eq!(outputs.len(), before, "forward is not injective");
    }

    #[test]
    fn test_different_tweaks() {
        let key = [0x42u8; 16];
        let p1 = AlfPrp::new(&key, TEST_DOMAIN, &[0u8; 16], 0);
        let p2 = AlfPrp::new(&key, TEST_DOMAIN, &[1u8; 16], 0);
        let o1: Vec<usize> = (0..100).map(|x| p1.forward(x)).collect();
        let o2: Vec<usize> = (0..100).map(|x| p2.forward(x)).collect();
        assert_ne!(o1, o2, "different tweaks should give different permutations");
    }

    #[test]
    fn test_engine_factory() {
        let engine = AlfEngine::new([0x42u8; 16], TEST_DOMAIN, 0);
        let p0 = engine.create_prp_for_group(0);
        let p1 = engine.create_prp_for_group(1);
        let o0: Vec<usize> = (0..100).map(|x| p0.forward(x)).collect();
        let o1: Vec<usize> = (0..100).map(|x| p1.forward(x)).collect();
        assert_ne!(o0, o1, "different groups should give different permutations");
    }

    #[test]
    #[should_panic(expected = "ALF domain")]
    fn test_rejects_small_domain() {
        let key = [0u8; 16];
        let tweak = [0u8; 16];
        AlfPrp::new(&key, 128, &tweak, 0);
    }

    #[test]
    fn test_non_power_of_two_domain() {
        // 100,000 is not a power of two — ALF handles via cycle-walking.
        let domain = 100_000;
        let key = [0x42u8; 16];
        let tweak = [0u8; 16];
        let prp = AlfPrp::new(&key, domain, &tweak, 0);

        for x in (0..domain).step_by(domain / 50) {
            let y = prp.forward(x);
            assert!(y < domain, "forward({x}) = {y} out of domain {domain}");
            let x_back = prp.inverse(y);
            assert_eq!(x_back, x, "roundtrip failed for x={x}");
        }
    }
}
