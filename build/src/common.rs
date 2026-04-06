#![allow(dead_code)]
//! Shared constants and hash utilities for Batch PIR tools.
//!
//! This module re-exports everything from `pir-core` and provides backward-
//! compatible wrapper functions that use the legacy constant values. Existing
//! build binaries importing `use common::*;` continue to compile unchanged.

// Re-export all constants and types from pir-core
pub use pir_core::params::*;
pub use pir_core::codec::*;
pub use pir_core::pbc::*;

// Re-export primitive hashing functions directly (same signature)
pub use pir_core::hash::{
    splitmix64, sh_a, sh_b, sh_c,
    hash_for_group, cuckoo_hash, cuckoo_hash_int, compute_tag,
    hash_int_for_group,
};

// ─── Backward-compatible wrappers ──────────────────────────────────────────
// These match the original signatures that take no seed/k parameters,
// using the hardcoded INDEX or CHUNK constants.

/// Derive 3 distinct INDEX-level group indices for a script_hash (K=75).
pub fn derive_groups(script_hash: &[u8]) -> [usize; NUM_HASHES] {
    pir_core::hash::derive_groups_3(script_hash, K)
}

/// Derive a cuckoo hash function key for INDEX level (uses MASTER_SEED).
#[inline]
pub fn derive_cuckoo_key(group_id: usize, hash_fn: usize) -> u64 {
    pir_core::hash::derive_cuckoo_key(MASTER_SEED, group_id, hash_fn)
}

/// Hash a chunk_id with a nonce for CHUNK-level group assignment.
#[inline]
pub fn hash_chunk_for_group(chunk_id: u32, nonce: u64) -> u64 {
    pir_core::hash::hash_int_for_group(chunk_id, nonce)
}

/// Derive 3 distinct CHUNK-level group indices (K_CHUNK=80).
pub fn derive_chunk_groups(chunk_id: u32) -> [usize; NUM_HASHES] {
    pir_core::hash::derive_int_groups_3(chunk_id, K_CHUNK)
}

/// Derive a cuckoo hash function key for CHUNK level (uses CHUNK_MASTER_SEED).
#[inline]
pub fn derive_chunk_cuckoo_key(group_id: usize, hash_fn: usize) -> u64 {
    pir_core::hash::derive_cuckoo_key(CHUNK_MASTER_SEED, group_id, hash_fn)
}

/// Read bins_per_table and tag_seed from an INDEX-level cuckoo header (one per group).
pub fn read_cuckoo_header(data: &[u8]) -> (usize, u64) {
    pir_core::hash::read_cuckoo_header(data, MAGIC, HEADER_SIZE, true)
}

/// Read bins_per_table from a CHUNK-level cuckoo header.
pub fn read_chunk_cuckoo_header(data: &[u8]) -> usize {
    pir_core::hash::read_chunk_cuckoo_header(data)
}
