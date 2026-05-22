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

/// Hash a chunk_id with a nonce for CHUNK-level group assignment.
#[inline]
pub fn hash_chunk_for_group(chunk_id: u32, nonce: u64) -> u64 {
    pir_core::hash::hash_int_for_group(chunk_id, nonce)
}

/// Derive 3 distinct CHUNK-level group indices (K_CHUNK=80).
pub fn derive_chunk_groups(chunk_id: u32) -> [usize; NUM_HASHES] {
    pir_core::hash::derive_int_groups_3(chunk_id, K_CHUNK)
}

// NOTE: `derive_cuckoo_key` and `derive_chunk_cuckoo_key` legacy
// wrappers were deleted in Phase C2. Diagnostic binaries that compute
// cuckoo placements must now read the master seed from the cuckoo
// file's own header via `read_cuckoo_header_full` /
// `read_chunk_cuckoo_header_full` and pass it explicitly to
// `pir_core::hash::derive_cuckoo_key(master_seed, group_id, hash_fn)`.
// This keeps the diagnostic binaries working on chain-anchored
// databases (Phase B+) where the master seed is no longer the
// hardcoded constant.

/// Read bins_per_table and tag_seed from an INDEX-level cuckoo header (one per group).
///
/// Accepts both the legacy pre-Phase-C MAGIC (no anchor) and the
/// Phase-C v2 MAGIC variants (snapshot or delta anchor appended). The
/// anchor itself is discarded by this signature — callers that need it
/// should use [`pir_core::cuckoo::read_cuckoo_header_with_anchor`] directly.
pub fn read_cuckoo_header(data: &[u8]) -> (usize, u64) {
    let h = pir_core::cuckoo::read_cuckoo_header_with_anchor(
        data,
        &pir_core::params::INDEX_PARAMS,
    )
    .expect("INDEX cuckoo header parse");
    (h.bins_per_table, h.tag_seed)
}

/// Read bins_per_table, master_seed, and tag_seed from an INDEX-level cuckoo header.
///
/// Use this in diagnostic binaries that need to recompute cuckoo
/// placements (i.e., call [`pir_core::hash::derive_cuckoo_key`]) —
/// pass the returned `master_seed` rather than the hardcoded
/// `MASTER_SEED` const, so the binary keeps working on chain-anchored
/// databases (Phase B+).
pub fn read_cuckoo_header_full(data: &[u8]) -> (usize, u64, u64) {
    let h = pir_core::cuckoo::read_cuckoo_header_with_anchor(
        data,
        &pir_core::params::INDEX_PARAMS,
    )
    .expect("INDEX cuckoo header parse");
    (h.bins_per_table, h.master_seed, h.tag_seed)
}

/// Read bins_per_table from a CHUNK-level cuckoo header.
///
/// Accepts both legacy and Phase-C v2 MAGIC variants.
pub fn read_chunk_cuckoo_header(data: &[u8]) -> usize {
    let h = pir_core::cuckoo::read_cuckoo_header_with_anchor(
        data,
        &pir_core::params::CHUNK_PARAMS,
    )
    .expect("CHUNK cuckoo header parse");
    h.bins_per_table
}

/// Read bins_per_table and master_seed from a CHUNK-level cuckoo header.
///
/// See [`read_cuckoo_header_full`] for the rationale.
pub fn read_chunk_cuckoo_header_full(data: &[u8]) -> (usize, u64) {
    let h = pir_core::cuckoo::read_cuckoo_header_with_anchor(
        data,
        &pir_core::params::CHUNK_PARAMS,
    )
    .expect("CHUNK cuckoo header parse");
    (h.bins_per_table, h.master_seed)
}
