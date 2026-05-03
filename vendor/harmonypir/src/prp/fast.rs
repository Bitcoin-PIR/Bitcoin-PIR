//! FastPRP wrapper (Stefanov & Shi 2012).
//!
//! Wraps the `fastprp` crate to implement the HarmonyPIR [`Prp`] trait.
//!
//! # Performance characteristics
//!
//! - Per-element: O(sqrt(N) * log N) — ~53 us at N=6M.
//! - `batch_permute()`: O(N log N) total — generates the full permutation table
//!   much faster than N individual `permute()` calls.
//!
//! # Per-group differentiation
//!
//! FastPRP has no tweak support. Each PBC group gets a distinct derived key:
//! `K_group = AES_ECB(master_key, group_id)`.
//!
//! # Cache persistence
//!
//! Construction builds an internal counter cache (~72KB at N=6M) that takes ~60ms.
//! Use [`FastPrpWrapper::save_cache`] and [`FastPrpWrapper::from_cache`] to persist
//! and reload this cache, avoiding the rebuild cost on subsequent runs.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Block};
use fastprp::{CounterCache, FastPrp, PartitionCache};
use serde::{Deserialize, Serialize};

use super::{BatchPrp, Prp};

/// Serializable representation of FastPrp's internal caches.
#[derive(Serialize, Deserialize)]
struct CacheData {
    stride: u64,
    num_depths: u32,
    n: u64,
    counter_cache: Vec<Vec<u32>>,
    partition_depths: Vec<Vec<(u64, u32)>>,
}

/// FastPRP wrapper implementing the HarmonyPIR [`Prp`] trait.
pub struct FastPrpWrapper {
    inner: FastPrp,
    domain_size: usize,
}

impl FastPrpWrapper {
    /// Create a new FastPRP for the given domain.
    ///
    /// Builds the internal counter cache (~60ms at N=6M).
    ///
    /// - `key`: 16-byte AES key.
    /// - `domain_size`: permutation domain [0, domain_size). Must be >= 2.
    pub fn new(key: &[u8; 16], domain_size: usize) -> Self {
        let inner = FastPrp::new(key, domain_size as u64);
        Self { inner, domain_size }
    }

    /// Create with a group-specific derived key.
    ///
    /// `K_group = AES_ECB(master_key, group_id as LE bytes)`.
    /// Use this for per-PBC-group differentiation.
    pub fn with_group(master_key: &[u8; 16], group_id: u64, domain_size: usize) -> Self {
        let derived = derive_group_key(master_key, group_id);
        Self::new(&derived, domain_size)
    }

    /// Reconstruct from a key and previously saved cache bytes.
    ///
    /// Skips the expensive cache-building step.
    pub fn from_cache(key: &[u8; 16], domain_size: usize, cache_bytes: &[u8]) -> Self {
        let data: CacheData =
            bincode::deserialize(cache_bytes).expect("failed to deserialize FastPRP cache");
        let cc = CounterCache::from_raw(data.stride, data.num_depths, data.n, data.counter_cache);
        let pc = PartitionCache::from_raw(data.partition_depths);
        let inner = FastPrp::from_parts(key, domain_size as u64, cc, pc);
        Self { inner, domain_size }
    }

    /// Serialize the internal caches for disk persistence.
    ///
    /// Returns bytes that can be passed to [`Self::from_cache`].
    pub fn save_cache(&self) -> Vec<u8> {
        let cc = self.inner.counter_cache();
        let pc = self.inner.partition_cache();
        let data = CacheData {
            stride: cc.stride,
            num_depths: cc.num_depths,
            n: cc.n,
            counter_cache: cc.raw_cache().clone(),
            partition_depths: pc.raw_depths().clone(),
        };
        bincode::serialize(&data).expect("failed to serialize FastPRP cache")
    }

    /// Expose the native `batch_permute()` returning `Vec<u64>`.
    ///
    /// Callers who work with `u64` directly can avoid the usize conversion overhead.
    pub fn batch_permute_raw(&self) -> Vec<u64> {
        self.inner.batch_permute()
    }
}

impl Prp for FastPrpWrapper {
    fn forward(&self, x: usize) -> usize {
        assert!(
            x < self.domain_size,
            "input {x} >= domain {}",
            self.domain_size
        );
        self.inner.permute(x as u64) as usize
    }

    fn inverse(&self, y: usize) -> usize {
        assert!(
            y < self.domain_size,
            "input {y} >= domain {}",
            self.domain_size
        );
        self.inner.unpermute(y as u64) as usize
    }

    fn domain(&self) -> usize {
        self.domain_size
    }
}

impl BatchPrp for FastPrpWrapper {
    fn batch_forward(&self) -> Vec<usize> {
        self.inner
            .batch_permute()
            .into_iter()
            .map(|v| v as usize)
            .collect()
    }
}

/// Derive a group-specific key: `AES_ECB(master_key, group_id)`.
fn derive_group_key(master_key: &[u8; 16], group_id: u64) -> [u8; 16] {
    let cipher = Aes128::new(master_key.into());
    let mut block = Block::default();
    block[..8].copy_from_slice(&group_id.to_le_bytes());
    cipher.encrypt_block(&mut block);
    block.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_inverse_roundtrip() {
        let key = [0x42u8; 16];
        let domain = 256;
        let prp = FastPrpWrapper::new(&key, domain);
        for x in 0..domain {
            let y = prp.forward(x);
            assert!(y < domain, "forward({x}) = {y} out of range");
            let x_back = prp.inverse(y);
            assert_eq!(x_back, x, "inverse(forward({x})) = {x_back} != {x}");
        }
    }

    #[test]
    fn test_is_permutation() {
        let key = [0xAB; 16];
        let domain = 128;
        let prp = FastPrpWrapper::new(&key, domain);
        let mut outputs: Vec<usize> = (0..domain).map(|x| prp.forward(x)).collect();
        outputs.sort();
        assert_eq!(outputs, (0..domain).collect::<Vec<_>>());
    }

    #[test]
    fn test_different_keys() {
        let domain = 64;
        let p1 = FastPrpWrapper::new(&[1u8; 16], domain);
        let p2 = FastPrpWrapper::new(&[2u8; 16], domain);
        let o1: Vec<usize> = (0..domain).map(|x| p1.forward(x)).collect();
        let o2: Vec<usize> = (0..domain).map(|x| p2.forward(x)).collect();
        assert_ne!(o1, o2);
    }

    #[test]
    fn test_group_key_derivation() {
        let master = [0x42u8; 16];
        let domain = 128;
        let p0 = FastPrpWrapper::with_group(&master, 0, domain);
        let p1 = FastPrpWrapper::with_group(&master, 1, domain);
        let o0: Vec<usize> = (0..domain).map(|x| p0.forward(x)).collect();
        let o1: Vec<usize> = (0..domain).map(|x| p1.forward(x)).collect();
        assert_ne!(o0, o1);
    }

    #[test]
    fn test_batch_matches_pointwise() {
        let key = [0x42u8; 16];
        let domain = 512;
        let prp = FastPrpWrapper::new(&key, domain);
        let table = prp.batch_forward();
        assert_eq!(table.len(), domain);
        for x in 0..domain {
            assert_eq!(table[x], prp.forward(x), "batch[{x}] != forward({x})");
        }
    }

    #[test]
    fn test_cache_save_load_roundtrip() {
        let key = [0x42u8; 16];
        let domain = 256;
        let prp1 = FastPrpWrapper::new(&key, domain);
        let cache_bytes = prp1.save_cache();
        let prp2 = FastPrpWrapper::from_cache(&key, domain, &cache_bytes);
        for x in 0..domain {
            assert_eq!(
                prp1.forward(x),
                prp2.forward(x),
                "cache roundtrip mismatch at x={x}"
            );
        }
    }

    #[test]
    fn test_non_power_of_two() {
        let key = [0x55u8; 16];
        let domain = 100;
        let prp = FastPrpWrapper::new(&key, domain);
        let mut outputs: Vec<usize> = (0..domain).map(|x| prp.forward(x)).collect();
        outputs.sort();
        assert_eq!(outputs, (0..domain).collect::<Vec<_>>());
        for x in 0..domain {
            assert_eq!(prp.inverse(prp.forward(x)), x);
        }
    }
}
