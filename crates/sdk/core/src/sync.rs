//! Sync planning and delta merging.
//!
//! This module provides:
//! - `compute_sync_plan()`: Find optimal path from current height to tip
//! - `merge_delta()`: Apply delta data to a snapshot result
//!
//! The sync algorithm uses BFS to find the shortest delta chain, with a
//! maximum chain length of 5 steps. Longer chains fall back to a full snapshot.

use crate::error::{PirError, PirResult};
use crate::types::{DatabaseCatalog, DatabaseInfo, DatabaseKind, QueryResult, UtxoEntry};
use std::collections::{HashMap, HashSet, VecDeque};

/// Maximum number of delta steps in a chain before falling back to full snapshot.
pub const MAX_DELTA_CHAIN_LENGTH: usize = 5;

/// A single step in a sync plan.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SyncStep {
    /// Database ID to query.
    pub db_id: u8,
    /// Database kind (full or delta).
    pub kind: DatabaseKind,
    /// Database name.
    pub name: String,
    /// Base height (0 for full snapshots).
    pub base_height: u32,
    /// Tip height after this step.
    pub tip_height: u32,
}

impl SyncStep {
    /// Create a step from a DatabaseInfo.
    pub fn from_db_info(db: &DatabaseInfo) -> Self {
        Self {
            db_id: db.db_id,
            kind: db.kind,
            name: db.name.clone(),
            base_height: db.base_height(),
            tip_height: db.height,
        }
    }

    /// Returns true if this is a full snapshot step.
    pub fn is_full(&self) -> bool {
        self.kind.is_full()
    }

    /// Returns true if this is a delta step.
    pub fn is_delta(&self) -> bool {
        self.kind.is_delta()
    }
}

/// A complete sync plan.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SyncPlan {
    /// Steps to execute (in order).
    pub steps: Vec<SyncStep>,
    /// Whether this is a fresh sync (starts from full snapshot).
    pub is_fresh_sync: bool,
    /// Target height after executing all steps.
    pub target_height: u32,
}

impl SyncPlan {
    /// Create an empty plan (already at tip).
    pub fn empty(current_height: u32) -> Self {
        Self {
            steps: Vec::new(),
            is_fresh_sync: false,
            target_height: current_height,
        }
    }

    /// Returns true if no steps are needed.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Number of steps in the plan.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Get a step by index.
    pub fn get(&self, index: usize) -> Option<&SyncStep> {
        self.steps.get(index)
    }

    /// Iterate over steps.
    pub fn iter(&self) -> impl Iterator<Item = &SyncStep> {
        self.steps.iter()
    }
}

/// Check that `PirClient::sync` was asked for a full sync.
///
/// `sync` keeps no results between calls, so it has nothing to apply a delta
/// chain to. A non-zero `last_height` is rejected before any network I/O;
/// resuming from a previous sync goes through `sync_with_plan` with that
/// sync's results.
pub fn require_fresh_sync(last_height: Option<u32>) -> PirResult<()> {
    match last_height {
        Some(height) if height > 0 => Err(PirError::InvalidState(format!(
            "sync() keeps no previous results, so it cannot resume from height {height}: \
             pass last_height = None for a full sync, or call sync_with_plan with the \
             previous sync's results"
        ))),
        _ => Ok(()),
    }
}

/// Check that `plan` can run on top of `base`.
///
/// A fresh plan starts from a full snapshot and ignores `base`. Any other
/// plan (a delta chain, or the empty plan at the tip) only describes what
/// changed since the previous sync, so it needs that sync's results, one per
/// script hash in the same order. Merging onto a missing base would report
/// every unchanged address as absent and lose every spend.
pub fn require_sync_base(
    plan: &SyncPlan,
    num_script_hashes: usize,
    base: Option<&[Option<QueryResult>]>,
) -> PirResult<()> {
    match base {
        Some(base) if base.len() != num_script_hashes => Err(PirError::InvalidState(format!(
            "sync base has {} results for {num_script_hashes} script hashes",
            base.len()
        ))),
        None if !plan.is_fresh_sync => Err(PirError::InvalidState(
            "this sync plan only applies changes since the previous sync: pass that \
             sync's results to sync_with_plan, or plan a full sync with last_height = None"
                .into(),
        )),
        _ => Ok(()),
    }
}

/// Compute an optimal sync plan from `last_height` to the catalog tip.
///
/// # Algorithm
///
/// 1. **Fresh sync** (`last_height` is `None` or 0):
///    - Pick the highest full snapshot
///    - Chain deltas from that snapshot to the catalog tip
///
/// 2. **Incremental sync**:
///    - If `last_height` == catalog tip, return empty plan
///    - Try BFS to find delta chain from `last_height` to tip
///    - If chain is too long (> [`MAX_DELTA_CHAIN_LENGTH`]) or doesn't
///      exist, fall back to full snapshot + deltas
///
/// # Arguments
///
/// * `catalog` - Database catalog from server
/// * `last_height` - Last synced height, or `None` for fresh sync
pub fn compute_sync_plan(
    catalog: &DatabaseCatalog,
    last_height: Option<u32>,
) -> PirResult<SyncPlan> {
    let latest_tip = catalog
        .latest_tip()
        .ok_or_else(|| PirError::InvalidCatalog("empty catalog".into()))?;
    let last = last_height.unwrap_or(0);
    if last > 0 && last >= latest_tip {
        return Ok(SyncPlan::empty(last));
    }

    let mut by_base: HashMap<u32, Vec<&DatabaseInfo>> = HashMap::new();
    for db in catalog.deltas() {
        by_base.entry(db.base_height()).or_default().push(db);
    }

    if last > 0 {
        if let Some(chain) = find_delta_chain(&by_base, last, latest_tip) {
            return Ok(SyncPlan {
                steps: chain.into_iter().map(SyncStep::from_db_info).collect(),
                is_fresh_sync: false,
                target_height: latest_tip,
            });
        }
    }

    // Fresh sync, or no usable chain: the best full snapshot plus a delta
    // chain from it to the tip when one exists.
    let best_full = catalog
        .best_full_snapshot()
        .ok_or_else(|| PirError::NoSyncPath("no full snapshot available".into()))?;
    let mut steps = vec![SyncStep::from_db_info(best_full)];
    if let Some(chain) = find_delta_chain(&by_base, best_full.height, latest_tip) {
        steps.extend(chain.into_iter().map(SyncStep::from_db_info));
    }
    let target_height = steps[steps.len() - 1].tip_height;
    Ok(SyncPlan {
        steps,
        is_fresh_sync: true,
        target_height,
    })
}

/// The shortest delta chain (BFS) from `start` to `end`, at most
/// [`MAX_DELTA_CHAIN_LENGTH`] steps long, if any.
fn find_delta_chain<'a>(
    by_base: &HashMap<u32, Vec<&'a DatabaseInfo>>,
    start: u32,
    end: u32,
) -> Option<Vec<&'a DatabaseInfo>> {
    if start >= end {
        return Some(Vec::new());
    }
    let mut queue = VecDeque::from([(start, Vec::new())]);
    let mut visited = HashSet::from([start]);
    while let Some((height, path)) = queue.pop_front() {
        if path.len() >= MAX_DELTA_CHAIN_LENGTH {
            continue;
        }
        for &delta in by_base.get(&height).into_iter().flatten() {
            if !visited.insert(delta.height) {
                continue;
            }
            let mut next = path.clone();
            next.push(delta);
            if delta.height >= end {
                return Some(next);
            }
            queue.push_back((delta.height, next));
        }
    }
    None
}

// ─── Delta Merging ──────────────────────────────────────────────────────────

/// Decoded delta data from a delta query result.
#[derive(Clone, Debug, Default)]
pub struct DeltaData {
    /// Outpoints that were spent (txid || vout_le, 36 bytes each).
    pub spent: Vec<[u8; 36]>,
    /// New UTXOs added.
    pub new_utxos: Vec<UtxoEntry>,
}

/// Decode delta data from raw chunk bytes.
///
/// Delta format (matches `tools/db-builder/src/delta_gen_1_build_chunks.rs` and
/// `web/src/codec.ts::decodeDeltaData`):
/// ```text
/// [varint num_spent]
///   per spent: [32B txid][varint vout]
/// [varint num_new]
///   per new:   [32B txid][varint vout][varint amount]
/// ```
///
/// Spent outpoints are materialized as `[32B txid][4B vout_le]` (36 bytes)
/// in memory so they match `UtxoEntry::outpoint()` for the spent-set lookup
/// in `apply_delta_data`; the wire format itself is varint-encoded.
pub fn decode_delta_data(raw: &[u8]) -> PirResult<DeltaData> {
    let mut pos = 0;

    // Read num_spent as varint
    let (num_spent, consumed) = read_varint(&raw[pos..])?;
    pos += consumed;

    // Read spent outpoints: [32B txid][varint vout]. The counts come from
    // the server, so the allocation is bounded by what the bytes can hold
    // (at least 33 bytes per spent entry, 34 per new UTXO).
    let mut spent = Vec::with_capacity((num_spent as usize).min(raw.len() / 33));
    for _ in 0..num_spent {
        if pos + 32 > raw.len() {
            return Err(PirError::Decode("truncated spent txid".into()));
        }
        let mut outpoint = [0u8; 36];
        outpoint[..32].copy_from_slice(&raw[pos..pos + 32]);
        pos += 32;

        let (vout, consumed) = read_varint(&raw[pos..])?;
        pos += consumed;
        if vout > u32::MAX as u64 {
            return Err(PirError::Decode("spent vout exceeds u32".into()));
        }
        outpoint[32..36].copy_from_slice(&(vout as u32).to_le_bytes());
        spent.push(outpoint);
    }

    // Read num_new as varint
    let (num_new, consumed) = read_varint(&raw[pos..])?;
    pos += consumed;

    // Read new UTXOs: [32B txid][varint vout][varint amount]
    let mut new_utxos = Vec::with_capacity((num_new as usize).min(raw.len() / 34));
    for _ in 0..num_new {
        if pos + 32 > raw.len() {
            return Err(PirError::Decode("truncated new UTXO txid".into()));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&raw[pos..pos + 32]);
        pos += 32;

        let (vout, consumed) = read_varint(&raw[pos..])?;
        pos += consumed;
        if vout > u32::MAX as u64 {
            return Err(PirError::Decode("new UTXO vout exceeds u32".into()));
        }

        let (amount_sats, consumed) = read_varint(&raw[pos..])?;
        pos += consumed;

        new_utxos.push(UtxoEntry {
            txid,
            vout: vout as u32,
            amount_sats,
        });
    }

    Ok(DeltaData { spent, new_utxos })
}

/// Read a varint from the buffer, returning (value, bytes_consumed).
fn read_varint(buf: &[u8]) -> PirResult<(u64, usize)> {
    pir_core::codec::try_read_varint(buf).map_err(|e| PirError::Decode(format!("varint: {e:?}")))
}

/// Merge delta data into a snapshot result.
///
/// This applies the delta's spent/new UTXOs to produce an updated result:
/// 1. Remove any UTXOs whose outpoints are in `delta.spent`
/// 2. Append `delta.new_utxos` to the remaining entries
///
/// # Arguments
///
/// * `snapshot` - The snapshot result to update
/// * `delta_raw` - Raw delta chunk data from the delta query
///
/// # Returns
///
/// A new QueryResult with the delta applied.
pub fn merge_delta(snapshot: &QueryResult, delta_raw: &[u8]) -> PirResult<QueryResult> {
    if delta_raw.is_empty() {
        return Ok(snapshot.clone());
    }

    let delta = decode_delta_data(delta_raw)?;
    let merged = apply_delta_data(&snapshot.entries, &delta);

    Ok(QueryResult {
        entries: merged,
        is_whale: snapshot.is_whale,
        // Inherit the snapshot's verification status. Callers that have
        // separately verified the delta should AND in its `merkle_verified`
        // on the returned value; `merge_delta_batch` does this automatically.
        merkle_verified: snapshot.merkle_verified,
        raw_chunk_data: None,
        // Inspector fields stay empty after a merge — the Merkle-trace view
        // is per-query, not per-merged-history, and re-verifying a merged
        // result would require re-querying anyway.
        index_bins: Vec::new(),
        chunk_bins: Vec::new(),
        matched_index_idx: None,
    })
}

/// Apply delta data to an entry list (pure function).
fn apply_delta_data(entries: &[UtxoEntry], delta: &DeltaData) -> Vec<UtxoEntry> {
    // Build a set of spent outpoints for O(1) lookup
    let spent_set: std::collections::HashSet<[u8; 36]> = delta.spent.iter().copied().collect();

    // Filter out spent entries
    let mut result: Vec<UtxoEntry> = entries
        .iter()
        .filter(|e| !spent_set.contains(&e.outpoint()))
        .cloned()
        .collect();

    // Append new UTXOs
    result.extend(delta.new_utxos.iter().cloned());

    result
}

/// Merge delta batch results into snapshot batch results.
///
/// This is a batch variant of `merge_delta` that processes multiple script hashes.
///
/// # Arguments
///
/// * `snapshots` - Snapshot results (one per script hash)
/// * `delta_results` - Delta query results (one per script hash)
///
/// # Returns
///
/// Merged results for each script hash.
pub fn merge_delta_batch(
    snapshots: &[Option<QueryResult>],
    delta_results: &[Option<QueryResult>],
) -> PirResult<Vec<Option<QueryResult>>> {
    if snapshots.len() != delta_results.len() {
        return Err(PirError::MergeError(format!(
            "batch size mismatch: {} snapshots vs {} deltas",
            snapshots.len(),
            delta_results.len()
        )));
    }

    let mut merged = Vec::with_capacity(snapshots.len());

    for (snapshot, delta) in snapshots.iter().zip(delta_results.iter()) {
        let result = match (snapshot, delta) {
            (Some(snap), Some(del)) => {
                // A merged result is Merkle-verified iff BOTH inputs were.
                // One untrusted source taints the merge.
                let merkle_verified = snap.merkle_verified && del.merkle_verified;
                if let Some(raw) = &del.raw_chunk_data {
                    let mut m = merge_delta(snap, raw)?;
                    m.merkle_verified = merkle_verified;
                    Some(m)
                } else {
                    // No delta data means no changes for this script hash
                    let mut m = snap.clone();
                    m.merkle_verified = merkle_verified;
                    Some(m)
                }
            }
            (Some(snap), None) => {
                // No delta entry means no changes
                Some(snap.clone())
            }
            (None, Some(del)) => {
                // New entry from delta (script hash didn't exist in snapshot).
                // Verification state inherits from the delta query alone —
                // there is no snapshot side to AND against.
                if let Some(raw) = &del.raw_chunk_data {
                    let delta_data = decode_delta_data(raw)?;
                    Some(QueryResult {
                        entries: delta_data.new_utxos,
                        is_whale: false,
                        merkle_verified: del.merkle_verified,
                        raw_chunk_data: None,
                        index_bins: Vec::new(),
                        chunk_bins: Vec::new(),
                        matched_index_idx: None,
                    })
                } else {
                    None
                }
            }
            (None, None) => None,
        };
        merged.push(result);
    }

    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_delta_data_rejects_a_hostile_count_without_allocating_it() {
        // num_spent = u64::MAX (10-byte varint), then nothing.
        let mut raw = vec![0xff; 9];
        raw.push(0x01);
        assert!(decode_delta_data(&raw).is_err());
    }

    fn make_entry(txid_byte: u8, vout: u32, amount: u64) -> UtxoEntry {
        let mut txid = [0u8; 32];
        txid[0] = txid_byte;
        UtxoEntry {
            txid,
            vout,
            amount_sats: amount,
        }
    }

    #[test]
    fn test_apply_delta_empty() {
        let entries = vec![make_entry(1, 0, 1000), make_entry(2, 1, 2000)];
        let delta = DeltaData::default();
        let result = apply_delta_data(&entries, &delta);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_apply_delta_spend() {
        let entries = vec![make_entry(1, 0, 1000), make_entry(2, 1, 2000)];
        let delta = DeltaData {
            spent: vec![entries[0].outpoint()],
            new_utxos: Vec::new(),
        };
        let result = apply_delta_data(&entries, &delta);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].txid[0], 2);
    }

    #[test]
    fn test_apply_delta_add() {
        let entries = vec![make_entry(1, 0, 1000)];
        let delta = DeltaData {
            spent: Vec::new(),
            new_utxos: vec![make_entry(3, 0, 3000)],
        };
        let result = apply_delta_data(&entries, &delta);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_apply_delta_both() {
        let entries = vec![make_entry(1, 0, 1000), make_entry(2, 1, 2000)];
        let delta = DeltaData {
            spent: vec![entries[0].outpoint()],
            new_utxos: vec![make_entry(3, 0, 3000)],
        };
        let result = apply_delta_data(&entries, &delta);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].txid[0], 2);
        assert_eq!(result[1].txid[0], 3);
    }

    #[test]
    fn test_read_varint() {
        // Single byte
        assert_eq!(read_varint(&[0x00]).unwrap(), (0, 1));
        assert_eq!(read_varint(&[0x01]).unwrap(), (1, 1));
        assert_eq!(read_varint(&[0x7F]).unwrap(), (127, 1));

        // Two bytes
        assert_eq!(read_varint(&[0x80, 0x01]).unwrap(), (128, 2));
        assert_eq!(read_varint(&[0xFF, 0x01]).unwrap(), (255, 2));

        // Three bytes
        assert_eq!(read_varint(&[0x80, 0x80, 0x01]).unwrap(), (16384, 3));
    }

    #[test]
    fn test_compute_sync_plan_empty_catalog() {
        let catalog = DatabaseCatalog::new();
        let result = compute_sync_plan(&catalog, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_sync_plan_at_tip() {
        let mut catalog = DatabaseCatalog::new();
        catalog.databases.push(DatabaseInfo {
            db_id: 0,
            kind: DatabaseKind::Full,
            name: "main".into(),
            height: 100,
            index_bins: 1000,
            chunk_bins: 2000,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0,
            dpf_n_index: 10,
            dpf_n_chunk: 11,
            has_bucket_merkle: false,
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        });

        let plan = compute_sync_plan(&catalog, Some(100)).unwrap();
        assert!(plan.is_empty());
        assert_eq!(plan.target_height, 100);
    }

    #[test]
    fn test_compute_sync_plan_fresh() {
        let mut catalog = DatabaseCatalog::new();
        catalog.databases.push(DatabaseInfo {
            db_id: 0,
            kind: DatabaseKind::Full,
            name: "main".into(),
            height: 100,
            index_bins: 1000,
            chunk_bins: 2000,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0,
            dpf_n_index: 10,
            dpf_n_chunk: 11,
            has_bucket_merkle: false,
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        });

        let plan = compute_sync_plan(&catalog, None).unwrap();
        assert!(plan.is_fresh_sync);
        assert_eq!(plan.steps.len(), 1);
        assert!(plan.steps[0].is_full());
    }

    // ─── Multi-hop BFS tests ─────────────────────────────────────────────
    //
    // The original test surface only covered 1-entry catalogs (full
    // snapshot only). These exercise the BFS, the in-bound + over-bound
    // chain length cases, the fall-back path, and the SyncPlanner reuse
    // contract.

    /// Build a catalog with 1 full snapshot at `base` plus `num_deltas`
    /// chained deltas of `step` blocks each.
    fn build_chained_catalog(base: u32, step: u32, num_deltas: u8) -> DatabaseCatalog {
        let mut catalog = DatabaseCatalog::new();
        catalog.databases.push(DatabaseInfo {
            db_id: 0,
            kind: DatabaseKind::Full,
            name: format!("full_{}", base),
            height: base,
            index_bins: 1024,
            chunk_bins: 2048,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0,
            dpf_n_index: 10,
            dpf_n_chunk: 11,
            has_bucket_merkle: false,
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        });
        let mut prev = base;
        for i in 0..num_deltas {
            let next = prev + step;
            catalog.databases.push(DatabaseInfo {
                db_id: 1 + i,
                kind: DatabaseKind::Delta { base_height: prev },
                name: format!("delta_{}_{}", prev, next),
                height: next,
                index_bins: 256,
                chunk_bins: 512,
                index_k: 75,
                chunk_k: 80,
                tag_seed: 0,
                dpf_n_index: 8,
                dpf_n_chunk: 9,
                has_bucket_merkle: false,
                index_master_seed: 0,
                chunk_master_seed: 0,
                anchor_kind: 0,
                anchor_bytes: Vec::new(),
            });
            prev = next;
        }
        catalog
    }

    #[test]
    fn test_compute_sync_plan_incremental_max_chain() {
        // 1 full + 5 deltas; ask for last_height = base, so we need to
        // walk ALL 5 deltas. That's exactly MAX_DELTA_CHAIN_LENGTH and
        // must be returned as an incremental plan (NOT a fresh-sync).
        let catalog = build_chained_catalog(1_000_000, 4_000, 5);
        let plan = compute_sync_plan(&catalog, Some(1_000_000)).unwrap();
        assert!(!plan.is_fresh_sync, "5-step chain is at-bound, not over");
        assert_eq!(plan.steps.len(), 5);
        assert!(plan.steps.iter().all(|s| s.is_delta()));
        assert_eq!(plan.target_height, 1_020_000);
    }

    #[test]
    fn test_compute_sync_plan_incremental_over_bound_falls_back() {
        // 1 full + 6 deltas; ask for last_height = base. 6 > MAX (5)
        // so the BFS pruning short-circuits and the planner falls back
        // to fresh sync.
        let catalog = build_chained_catalog(1_000_000, 4_000, 6);
        let plan = compute_sync_plan(&catalog, Some(1_000_000)).unwrap();
        assert!(plan.is_fresh_sync, "over-bound chain forces fresh sync");
        // Fresh-sync plan = full snapshot + the (necessarily-bounded)
        // deltas chained off it. The full snapshot is at height
        // 1_000_000 and the tip is at 1_024_000, so even if the BFS
        // can't span all 6 deltas in one go it should at minimum
        // include the full snapshot.
        assert!(!plan.steps.is_empty());
        assert!(plan.steps[0].is_full());
    }

    #[test]
    fn test_compute_sync_plan_incremental_short_chain() {
        // 1 full + 3 deltas; ask for last_height = anchor + 1 step.
        // Should return a 2-step incremental plan.
        let catalog = build_chained_catalog(1_000_000, 4_000, 3);
        let plan = compute_sync_plan(&catalog, Some(1_004_000)).unwrap();
        assert!(!plan.is_fresh_sync);
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.target_height, 1_012_000);
    }

    #[test]
    fn test_compute_sync_plan_no_full_snapshot() {
        // Catalog with deltas but no full snapshot. Fresh sync must
        // surface NoSyncPath.
        let mut catalog = DatabaseCatalog::new();
        catalog.databases.push(DatabaseInfo {
            db_id: 0,
            kind: DatabaseKind::Delta { base_height: 100 },
            name: "delta_100_200".into(),
            height: 200,
            index_bins: 256,
            chunk_bins: 512,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0,
            dpf_n_index: 8,
            dpf_n_chunk: 9,
            has_bucket_merkle: false,
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        });
        // last_height = None → fresh sync → NoSyncPath
        assert!(compute_sync_plan(&catalog, None).is_err());
        // last_height matches a delta base → incremental works
        let p = compute_sync_plan(&catalog, Some(100)).unwrap();
        assert!(!p.is_fresh_sync);
        assert_eq!(p.steps.len(), 1);
    }

    #[test]
    fn test_find_delta_chain_picks_shortest_path() {
        // Build a catalog with TWO ways to reach the tip from the
        // anchor: a 1-step "shortcut" delta and a 3-step "scenic
        // route". BFS must pick the shortcut.
        let mut catalog = DatabaseCatalog::new();
        catalog.databases.push(DatabaseInfo {
            db_id: 0,
            kind: DatabaseKind::Full,
            name: "anchor".into(),
            height: 1_000_000,
            index_bins: 1024,
            chunk_bins: 2048,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0,
            dpf_n_index: 10,
            dpf_n_chunk: 11,
            has_bucket_merkle: false,
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        });
        // 3-step scenic route (1m → 1.005m → 1.010m → 1.020m).
        for (id, base, tip) in [
            (1, 1_000_000, 1_005_000),
            (2, 1_005_000, 1_010_000),
            (3, 1_010_000, 1_020_000),
        ] {
            catalog.databases.push(DatabaseInfo {
                db_id: id,
                kind: DatabaseKind::Delta { base_height: base },
                name: format!("scenic_{}_{}", base, tip),
                height: tip,
                index_bins: 256,
                chunk_bins: 512,
                index_k: 75,
                chunk_k: 80,
                tag_seed: 0,
                dpf_n_index: 8,
                dpf_n_chunk: 9,
                has_bucket_merkle: false,
                index_master_seed: 0,
                chunk_master_seed: 0,
                anchor_kind: 0,
                anchor_bytes: Vec::new(),
            });
        }
        // 1-step shortcut (1m → 1.020m).
        catalog.databases.push(DatabaseInfo {
            db_id: 4,
            kind: DatabaseKind::Delta {
                base_height: 1_000_000,
            },
            name: "shortcut_1000000_1020000".into(),
            height: 1_020_000,
            index_bins: 256,
            chunk_bins: 512,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0,
            dpf_n_index: 8,
            dpf_n_chunk: 9,
            has_bucket_merkle: false,
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        });

        let plan = compute_sync_plan(&catalog, Some(1_000_000)).unwrap();
        assert!(!plan.is_fresh_sync);
        assert_eq!(
            plan.steps.len(),
            1,
            "BFS must pick the 1-step shortcut, not the 3-step scenic route"
        );
        assert_eq!(plan.target_height, 1_020_000);
    }

    #[test]
    fn test_find_delta_chain_no_path_returns_fresh() {
        // Catalog with deltas that don't connect from the anchor
        // (orphan deltas). Should fall back to fresh sync.
        let mut catalog = DatabaseCatalog::new();
        catalog.databases.push(DatabaseInfo {
            db_id: 0,
            kind: DatabaseKind::Full,
            name: "anchor".into(),
            height: 1_000_000,
            index_bins: 1024,
            chunk_bins: 2048,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0,
            dpf_n_index: 10,
            dpf_n_chunk: 11,
            has_bucket_merkle: false,
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        });
        // Orphan delta (base height doesn't match anything in the
        // catalog reachable from last_height).
        catalog.databases.push(DatabaseInfo {
            db_id: 1,
            kind: DatabaseKind::Delta {
                base_height: 999_999,
            },
            name: "orphan".into(),
            height: 1_010_000,
            index_bins: 256,
            chunk_bins: 512,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0,
            dpf_n_index: 8,
            dpf_n_chunk: 9,
            has_bucket_merkle: false,
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor_kind: 0,
            anchor_bytes: Vec::new(),
        });

        // last_height = 500_000 → no chain to tip → fresh sync.
        let plan = compute_sync_plan(&catalog, Some(500_000)).unwrap();
        assert!(plan.is_fresh_sync, "no reachable chain → fresh sync");
        assert!(plan.steps[0].is_full());
    }

    // ─── merkle_verified propagation tests ───────────────────────────────

    /// Encode a delta payload containing no spends and a single new UTXO.
    /// Mirrors the on-wire format built by `delta_gen_1_build_chunks.rs`
    /// and consumed by `decode_delta_data`.
    fn encode_delta_one_new(new: &UtxoEntry) -> Vec<u8> {
        let mut out = Vec::new();
        // spent_count varint = 0
        push_varint(&mut out, 0);
        // new_count varint = 1
        push_varint(&mut out, 1);
        // Per entry: txid(32) || varint vout || varint amount
        out.extend_from_slice(&new.txid);
        push_varint(&mut out, new.vout as u64);
        push_varint(&mut out, new.amount_sats);
        out
    }

    #[test]
    fn test_merge_delta_inherits_verified_from_snapshot() {
        let snap_entry = make_entry(1, 0, 1000);
        let mut snap = QueryResult::with_entries(vec![snap_entry]);
        snap.merkle_verified = true;

        let raw = encode_delta_one_new(&make_entry(2, 0, 2000));
        let merged = merge_delta(&snap, &raw).unwrap();
        assert!(merged.merkle_verified, "verified snapshot stays verified");
        assert_eq!(merged.entries.len(), 2);
    }

    #[test]
    fn test_merge_delta_inherits_unverified_from_snapshot() {
        let mut snap = QueryResult::with_entries(vec![make_entry(1, 0, 1000)]);
        snap.merkle_verified = false;

        let raw = encode_delta_one_new(&make_entry(2, 0, 2000));
        let merged = merge_delta(&snap, &raw).unwrap();
        assert!(
            !merged.merkle_verified,
            "unverified snapshot taints the merge (merge_delta inherits from snapshot)"
        );
    }

    #[test]
    fn test_merge_delta_batch_ands_verified_flags() {
        let raw = encode_delta_one_new(&make_entry(2, 0, 2000));

        // Base case: both verified -> merged verified.
        {
            let mut snap = QueryResult::with_entries(vec![make_entry(1, 0, 1000)]);
            snap.merkle_verified = true;
            let mut del = QueryResult::with_entries(vec![]);
            del.merkle_verified = true;
            del.raw_chunk_data = Some(raw.clone());

            let out = merge_delta_batch(&[Some(snap)], &[Some(del)]).unwrap();
            assert!(out[0].as_ref().unwrap().merkle_verified);
        }

        // Unverified snapshot -> merged unverified.
        {
            let mut snap = QueryResult::with_entries(vec![make_entry(1, 0, 1000)]);
            snap.merkle_verified = false;
            let mut del = QueryResult::with_entries(vec![]);
            del.merkle_verified = true;
            del.raw_chunk_data = Some(raw.clone());

            let out = merge_delta_batch(&[Some(snap)], &[Some(del)]).unwrap();
            assert!(!out[0].as_ref().unwrap().merkle_verified);
        }

        // Unverified delta -> merged unverified.
        {
            let mut snap = QueryResult::with_entries(vec![make_entry(1, 0, 1000)]);
            snap.merkle_verified = true;
            let mut del = QueryResult::with_entries(vec![]);
            del.merkle_verified = false;
            del.raw_chunk_data = Some(raw.clone());

            let out = merge_delta_batch(&[Some(snap)], &[Some(del)]).unwrap();
            assert!(
                !out[0].as_ref().unwrap().merkle_verified,
                "unverified delta taints the merge"
            );
        }
    }

    #[test]
    fn test_merge_delta_batch_new_from_delta_only() {
        // (None, Some(del)) path: no snapshot entry, delta introduces a new
        // UTXO set. The merged verification flag should come from the delta.
        let raw = encode_delta_one_new(&make_entry(5, 0, 5000));

        let mut del = QueryResult::with_entries(vec![]);
        del.merkle_verified = false;
        del.raw_chunk_data = Some(raw);

        let out = merge_delta_batch(&[None], &[Some(del)]).unwrap();
        let merged = out[0].as_ref().unwrap();
        assert!(!merged.merkle_verified, "unverified delta propagates");
        assert_eq!(merged.entries.len(), 1);
    }

    #[test]
    fn test_query_result_merkle_failed() {
        let qr = QueryResult::merkle_failed();
        assert!(!qr.merkle_verified);
        assert!(qr.entries.is_empty());
        assert!(!qr.is_whale);
        assert!(qr.raw_chunk_data.is_none());
    }

    #[test]
    fn test_query_result_constructors_default_unverified() {
        assert!(!QueryResult::empty().merkle_verified);
        assert!(!QueryResult::with_entries(vec![]).merkle_verified);
        assert!(!QueryResult::default().merkle_verified);
    }

    // ─── Wire-format compatibility tests ─────────────────────────────────
    //
    // The build pipeline (`tools/db-builder/src/delta_gen_1_build_chunks.rs:88-108`
    // and `delta_gen_1_onion.rs:300-317`) encodes delta chunks as:
    //   [varint num_spent]
    //     per spent: [32B txid][varint vout]
    //   [varint num_new]
    //     per new:   [32B txid][varint vout][varint amount]
    // The TS decoder in `web/src/codec.ts::decodeDeltaData` matches this.
    // `decode_delta_data` must agree byte-for-byte.

    fn push_varint(out: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    /// Encode one spent + two new entries using the real on-wire varint
    /// format. Mirrors `tools/db-builder/src/delta_gen_1_build_chunks.rs`.
    fn encode_wire_format_sample() -> (Vec<u8>, UtxoEntry, UtxoEntry, [u8; 36]) {
        let spent_txid = [0xAAu8; 32];
        let spent_vout: u32 = 3;
        let mut spent_outpoint = [0u8; 36];
        spent_outpoint[..32].copy_from_slice(&spent_txid);
        spent_outpoint[32..36].copy_from_slice(&spent_vout.to_le_bytes());

        let new1 = UtxoEntry {
            txid: [0xBBu8; 32],
            vout: 0,
            amount_sats: 42,
        };
        let new2 = UtxoEntry {
            txid: [0xCCu8; 32],
            vout: 500,                // > 127 to force a 2-byte varint
            amount_sats: 100_000_000, // 1 BTC — multi-byte varint
        };

        let mut out = Vec::new();
        // num_spent
        push_varint(&mut out, 1);
        out.extend_from_slice(&spent_txid);
        push_varint(&mut out, spent_vout as u64);
        // num_new
        push_varint(&mut out, 2);
        out.extend_from_slice(&new1.txid);
        push_varint(&mut out, new1.vout as u64);
        push_varint(&mut out, new1.amount_sats);
        out.extend_from_slice(&new2.txid);
        push_varint(&mut out, new2.vout as u64);
        push_varint(&mut out, new2.amount_sats);

        (out, new1, new2, spent_outpoint)
    }

    #[test]
    fn decode_delta_data_matches_wire_format() {
        let (raw, new1, new2, spent_outpoint) = encode_wire_format_sample();
        let decoded = decode_delta_data(&raw).expect("decode must succeed");

        assert_eq!(decoded.spent.len(), 1, "exactly one spent outpoint");
        assert_eq!(decoded.spent[0], spent_outpoint);

        assert_eq!(decoded.new_utxos.len(), 2, "exactly two new utxos");
        assert_eq!(decoded.new_utxos[0], new1);
        assert_eq!(decoded.new_utxos[1], new2);
    }

    #[test]
    fn decode_delta_data_rejects_truncated_varint_amount() {
        // Build a valid prefix: 0 spent + 1 new whose amount varint is cut off.
        let mut out = Vec::new();
        push_varint(&mut out, 0); // num_spent = 0
        push_varint(&mut out, 1); // num_new = 1
        out.extend_from_slice(&[0xDDu8; 32]);
        push_varint(&mut out, 0); // vout = 0
        out.push(0x80); // amount varint: continuation bit set but no follow-up
        assert!(decode_delta_data(&out).is_err());
    }
}
