//! Cuckoo hash functions for scriptPubkey location computation.
//!
//! These hash functions are used to compute the two possible bucket locations
//! for a 20-byte script hash in the cuckoo hash table.

/// Size of the key in bytes (20 bytes for script hash)
pub const KEY_SIZE: usize = 20;

/// Size of each entry in the mmap (key + value)
/// For now, this is a placeholder - adjust based on actual data structure
pub const ENTRY_SIZE: usize = KEY_SIZE + 32; // 20-byte key + 32-byte value

/// Default number of buckets for the cuckoo hash table
pub const NUM_BUCKETS: usize = 14_008_287;

/// Hash function 1 for 20-byte script hash.
/// Uses FNV-1a style mixing over the key bytes.
#[inline(always)]
pub fn hash1(key: &[u8; KEY_SIZE], num_buckets: usize) -> usize {
    let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
    for i in 0..KEY_SIZE {
        h ^= key[i] as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV prime
    }
    // Extra mixing
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    (h as usize) % num_buckets
}

/// Hash function 2 for 20-byte script hash.
/// Different seed/constants.
#[inline(always)]
pub fn hash2(key: &[u8; KEY_SIZE], num_buckets: usize) -> usize {
    let mut h: u64 = 0x517cc1b727220a95; // Different seed
    for i in 0..KEY_SIZE {
        h ^= key[i] as u64;
        h = h.wrapping_mul(0x9e3779b97f4a7c15); // Different prime
    }
    h ^= h >> 32;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^= h >> 32;
    (h as usize) % num_buckets
}

/// Hash function 1 variant that works with a byte slice (for mmap compatibility).
/// Uses FNV-1a style mixing over the key bytes.
#[inline(always)]
pub fn hash1_slice(mmap: &[u8], entry_idx: u32, num_buckets: usize) -> usize {
    let offset = entry_idx as usize * ENTRY_SIZE;
    let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
    for i in 0..KEY_SIZE {
        h ^= mmap[offset + i] as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV prime
    }
    // Extra mixing
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    (h as usize) % num_buckets
}

/// Hash function 2 variant that works with a byte slice (for mmap compatibility).
/// Different seed/constants.
#[inline(always)]
pub fn hash2_slice(mmap: &[u8], entry_idx: u32, num_buckets: usize) -> usize {
    let offset = entry_idx as usize * ENTRY_SIZE;
    let mut h: u64 = 0x517cc1b727220a95; // Different seed
    for i in 0..KEY_SIZE {
        h ^= mmap[offset + i] as u64;
        h = h.wrapping_mul(0x9e3779b97f4a7c15); // Different prime
    }
    h ^= h >> 32;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^= h >> 32;
    (h as usize) % num_buckets
}

/// Compute both cuckoo hash locations for a script hash.
/// Returns (location1, location2) tuple.
#[inline(always)]
pub fn cuckoo_locations(key: &[u8; KEY_SIZE], num_buckets: usize) -> (usize, usize) {
    (hash1(key, num_buckets), hash2(key, num_buckets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_functions_produce_different_results() {
        let key = [0u8; KEY_SIZE];
        let h1 = hash1(&key, NUM_BUCKETS);
        let h2 = hash2(&key, NUM_BUCKETS);
        assert_ne!(h1, h2, "Hash functions should produce different results");
    }

    #[test]
    fn test_hash_within_bounds() {
        let key = [0xAB; KEY_SIZE];
        let h1 = hash1(&key, NUM_BUCKETS);
        let h2 = hash2(&key, NUM_BUCKETS);
        assert!(h1 < NUM_BUCKETS);
        assert!(h2 < NUM_BUCKETS);
    }

    #[test]
    fn test_cuckoo_locations() {
        let key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                   0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                   0x99, 0xAA, 0xBB, 0xCC];
        let (loc1, loc2) = cuckoo_locations(&key, NUM_BUCKETS);
        assert!(loc1 < NUM_BUCKETS);
        assert!(loc2 < NUM_BUCKETS);
        assert_ne!(loc1, loc2);
    }
}