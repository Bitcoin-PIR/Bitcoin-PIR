//! MuHash3072 — the incremental multiset hash Bitcoin Core uses for
//! `gettxoutsetinfo muhash` (`src/crypto/muhash.{h,cpp}`), reimplemented
//! bit-compatibly in Rust.
//!
//! The attested builder (see ../PLAN.md) ingests a `dumptxoutset`
//! snapshot, recomputes this hash over every coin, and refuses to build
//! the PIR database unless it matches the muhash pinned for the chain
//! anchor. Bit-compatibility with Core is the entire point: the pinned
//! value can be cross-checked by anyone with a stock full node.
//!
//! Algorithm (Core / `test_framework/crypto/muhash.py`):
//! - An element `x` maps to a 3072-bit integer: ChaCha20 keystream
//!   blocks 0..6 (zero nonce) keyed by SHA256(x), interpreted as a
//!   384-byte little-endian integer.
//! - The set hash is the product of all inserted elements divided by
//!   all removed elements, modulo the prime 2^3072 − 1103717.
//! - `digest()` = SHA256 of the 384-byte little-endian residue.
//!
//! NOT yet covered here (tracked in PLAN.md Phase 1): the per-coin
//! serialization Core feeds into `Insert` for `gettxoutsetinfo`
//! (outpoint ‖ VARINT(height·2+coinbase) ‖ compressed amount ‖
//! compressed script). That lives with the snapshot parser, which needs
//! the same compression primitives.

mod chacha20;

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Encoding, Invert, Uint, U3072};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

const LIMBS: usize = U3072::LIMBS;

/// The MuHash3072 group modulus: the prime 2^3072 − 1103717.
const MODULUS: U3072 = U3072::MAX.wrapping_sub(&Uint::from_u32(1_103_716));

/// Montgomery parameters for `MODULUS` (odd, so `new` cannot panic).
/// Computed lazily — const-evaluating them takes the compiler minutes
/// at 3072 bits.
fn params() -> DynResidueParams<LIMBS> {
    static PARAMS: OnceLock<DynResidueParams<LIMBS>> = OnceLock::new();
    *PARAMS.get_or_init(|| DynResidueParams::new(&MODULUS))
}

/// Map arbitrary element bytes to a 3072-bit group element, exactly like
/// Core's `MuHash3072::ToNum3072`: ChaCha20-expand SHA256(data) to 384
/// bytes, read little-endian.
fn to_num3072(data: &[u8]) -> U3072 {
    let key: [u8; 32] = Sha256::digest(data).into();
    let mut bytes384 = [0u8; 384];
    for counter in 0..6u32 {
        let block = chacha20::chacha20_block(&key, &[0u8; 12], counter);
        bytes384[64 * counter as usize..64 * (counter as usize + 1)].copy_from_slice(&block);
    }
    U3072::from_le_slice(&bytes384)
}

/// Incremental multiset hash over byte-string elements.
///
/// Insertion order does not matter; `remove` cancels a prior (or future)
/// `insert` of the same bytes. Division is deferred to [`digest`] so
/// every update is a single modular multiplication.
#[derive(Clone)]
pub struct MuHash3072 {
    numerator: DynResidue<LIMBS>,
    denominator: DynResidue<LIMBS>,
}

impl Default for MuHash3072 {
    fn default() -> Self {
        Self::new()
    }
}

impl MuHash3072 {
    /// The hash of the empty set.
    pub fn new() -> Self {
        Self {
            numerator: DynResidue::one(params()),
            denominator: DynResidue::one(params()),
        }
    }

    /// Add an element (by its serialized bytes) to the set.
    pub fn insert(&mut self, data: &[u8]) {
        self.numerator = self.numerator.mul(&DynResidue::new(&to_num3072(data), params()));
    }

    /// Remove an element (by its serialized bytes) from the set.
    pub fn remove(&mut self, data: &[u8]) {
        self.denominator = self.denominator.mul(&DynResidue::new(&to_num3072(data), params()));
    }

    /// Merge another accumulator into this one (set union of updates).
    /// Lets the snapshot scan shard across threads and combine at the end.
    pub fn combine(&mut self, other: &MuHash3072) {
        self.numerator = self.numerator.mul(&other.numerator);
        self.denominator = self.denominator.mul(&other.denominator);
    }

    /// Final 32-byte set hash: SHA256 of the 384-byte little-endian
    /// residue, matching Core's `MuHash3072::Finalize`.
    pub fn digest(&self) -> [u8; 32] {
        // The modulus is prime, so inversion only fails for a residue of
        // zero — which requires an input whose 3072-bit expansion hits a
        // multiple of the modulus (probability ~2^-3072, i.e. a broken
        // ChaCha20/SHA256, not a reachable runtime state).
        let inv = Option::from(Invert::invert(&self.denominator))
            .expect("denominator not invertible");
        let val = self.numerator.mul(&inv).retrieve();
        Sha256::digest(val.to_le_bytes()).into()
    }

    /// `digest()` in Core's display convention (byte-reversed hex), i.e.
    /// the exact string `gettxoutsetinfo muhash` prints.
    pub fn digest_display_hex(&self) -> String {
        let mut d = self.digest();
        d.reverse();
        d.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical cross-implementation vector, mirrored from Core's
    /// C++ unit test and `test_framework/crypto/muhash.py`:
    /// insert 0x00·32, insert 0x01‖0x00·31, remove 0x02‖0x00·31.
    #[test]
    fn core_muhash_vector() {
        let mut m = MuHash3072::new();
        m.insert(&[0u8; 32]);
        let mut e1 = [0u8; 32];
        e1[0] = 1;
        m.insert(&e1);
        let mut e2 = [0u8; 32];
        e2[0] = 2;
        m.remove(&e2);
        assert_eq!(
            m.digest_display_hex(),
            "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"
        );
    }

    #[test]
    fn insert_remove_cancels() {
        let empty = MuHash3072::new().digest();
        let mut m = MuHash3072::new();
        m.insert(b"some utxo");
        m.insert(b"another utxo");
        m.remove(b"some utxo");
        m.remove(b"another utxo");
        assert_eq!(m.digest(), empty);
    }

    #[test]
    fn order_independent() {
        let mut a = MuHash3072::new();
        a.insert(b"x");
        a.insert(b"y");
        a.remove(b"z");
        let mut b = MuHash3072::new();
        b.remove(b"z");
        b.insert(b"y");
        b.insert(b"x");
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn combine_matches_sequential() {
        let mut whole = MuHash3072::new();
        whole.insert(b"a");
        whole.insert(b"b");
        whole.remove(b"c");

        let mut shard1 = MuHash3072::new();
        shard1.insert(b"a");
        let mut shard2 = MuHash3072::new();
        shard2.insert(b"b");
        shard2.remove(b"c");
        shard1.combine(&shard2);
        assert_eq!(whole.digest(), shard1.digest());
    }

    #[test]
    fn multiset_semantics() {
        // Inserting the same element twice requires removing it twice.
        let empty = MuHash3072::new().digest();
        let mut m = MuHash3072::new();
        m.insert(b"dup");
        m.insert(b"dup");
        m.remove(b"dup");
        assert_ne!(m.digest(), empty);
        m.remove(b"dup");
        assert_eq!(m.digest(), empty);
    }
}
