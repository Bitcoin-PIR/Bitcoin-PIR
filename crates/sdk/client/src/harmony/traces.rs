use super::*;

// ─── Merkle verification traces ─────────────────────────────────────────────

/// Record of one INDEX cuckoo bin we checked during a query.
///
/// Mirrors `dpf.rs::IndexBinTrace`: populated for every cuckoo position probed
/// by `query_single`, consumed by the Merkle verifier to prove bin content is
/// consistent with the published root.
#[derive(Clone, Debug)]
pub(crate) struct IndexBinTrace {
    /// PBC group this bin belongs to (0..index_k).
    pub(crate) pbc_group: usize,
    /// Cuckoo bin index within the group's flat table.
    pub(crate) bin_index: u32,
    /// XOR-reconstructed bin content (INDEX_SLOTS_PER_BIN × INDEX_SLOT_SIZE bytes).
    pub(crate) bin_content: Vec<u8>,
}

/// Record of one CHUNK cuckoo bin we used to recover a retrieved chunk.
#[derive(Clone, Debug)]
pub(crate) struct ChunkBinTrace {
    /// PBC group this bin belongs to (0..chunk_k).
    pub(crate) pbc_group: usize,
    /// Cuckoo bin index within the group's flat table.
    pub(crate) bin_index: u32,
    /// XOR-reconstructed bin content.
    pub(crate) bin_content: Vec<u8>,
}

/// Metadata collected during a `query_single` call that downstream code
/// needs for Merkle verification. See `dpf.rs::QueryTraces` for the same
/// invariants.
#[derive(Clone, Debug)]
pub(crate) struct QueryTraces {
    /// Every INDEX bin we inspected. For NOT-FOUND this is all
    /// `INDEX_CUCKOO_NUM_HASHES` positions (required for the absence proof);
    /// for FOUND it can be up to the cuckoo position that matched.
    pub(crate) index_bins: Vec<IndexBinTrace>,
    /// If the query resolved to a match, the index in `index_bins` of the
    /// matching bin. `None` for NOT-FOUND or whale.
    pub(crate) matched_index_idx: Option<usize>,
    /// Per-chunk bin traces — one entry per chunk that was recovered.
    /// Empty for NOT-FOUND, whale, or zero-chunk matches.
    pub(crate) chunk_bins: Vec<ChunkBinTrace>,
}

// ─── Trace → BucketMerkleItem / BucketRef translators ───────────────────────
//
// These mirror the DPF client's helpers (`dpf.rs::items_from_trace` etc.):
// the point is to share exactly one item-layout convention between the
// hot-path Merkle verifier (which runs over fresh `QueryTraces`) and the
// deferred-verify path (which rebuilds items from already-persisted
// `QueryResult.index_bins` / `chunk_bins`). Any drift between the two
// sides would produce silent verification mismatches.

/// Per-group role for a single CHUNK PIR round.
///
/// `Real(chunk_id)` — the group has a real chunk to retrieve; the
/// caller computes the cuckoo target bin and dispatches via
/// [`harmonypir::remote::RemoteClient::build_request`].
///
/// `Dummy` — no real chunk is assigned to this group; caller falls
/// back to [`harmonypir::remote::RemoteClient::build_synthetic_dummy`],
/// whose T-1-padded shape is byte-shape-identical to a real request
/// per the existing "HarmonyPIR Per-Group Request-Count Symmetry"
/// invariant. The two branches of `run_chunk_round_pair` therefore emit
/// indistinguishable per-group payloads on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkGroupRole {
    Real(u32),
    Dummy,
}

/// Classify each of the `k_chunk` groups for one HarmonyPIR CHUNK
/// round.
///
/// Pure function: no I/O, no allocation outside the result `Vec`, no
/// RNG. The structural witness for **CHUNK Round-Presence Symmetry
/// P1** is `result.len() == k_chunk` regardless of
/// `real_queries.len()`. The structural witness for **P2** is
/// "every entry is `Dummy` when `real_queries.is_empty()`", which
/// makes the all-dummy round byte-shape-identical to any real round
/// (modulo fixed-shape `build_request` vs `build_synthetic_dummy`,
/// already established by the per-group request-count symmetry).
///
/// **Semantics on duplicate group_ids** — when `real_queries`
/// contains two entries with the same `group_id`, the *later* entry
/// wins. This matches the original `HashMap::collect` semantics that
/// the historical sequential implementation used pre-refactor; CHUNK PBC planning never
/// produces such duplicates within a single round, but preserving
/// the tie-break rule keeps the refactor observably equivalent.
///
/// **Out-of-range group_ids** — entries with `group_id >= k_chunk`
/// are silently ignored (the original code's `for g in 0..k_chunk`
/// loop never queried them). Same observable behaviour.
pub(crate) fn classify_chunk_groups(
    real_queries: &[(u32, u8)],
    k_chunk: u8,
) -> Vec<ChunkGroupRole> {
    let mut roles = vec![ChunkGroupRole::Dummy; k_chunk as usize];
    for &(cid, group) in real_queries {
        if (group as usize) < (k_chunk as usize) {
            // Last-wins matches HashMap::collect (pre-refactor behaviour).
            roles[group as usize] = ChunkGroupRole::Real(cid);
        }
    }
    roles
}

/// INDEX-side analog of [`ChunkGroupRole`], used by the Option-B
/// `index_max_items_per_group_per_level` closure. `Real(target_bin)`
/// marks a group as carrying a real INDEX query for some scripthash
/// in this round; `Dummy` marks a group as needing
/// `build_synthetic_dummy()`. The structural witness for the closure
/// is `result.len() == k_index` regardless of how many scripthashes
/// the PBC plan placed in this round — every wire INDEX request
/// covers all K groups, so the per-group payload count is a function
/// of `k_index` alone, not of the batch's collision pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexGroupRole {
    Real(u32),
    Dummy,
}

/// Classify each of the `k_index` groups for one batched HarmonyPIR
/// INDEX round (one cuckoo position `h` × one PBC round). Mirrors
/// [`classify_chunk_groups`] in shape: pure, no I/O, no RNG. Last
/// duplicate wins so the structural invariant is observably equivalent
/// to the pre-Option-B single-real-group path when the placement list
/// has exactly one entry.
pub(crate) fn classify_index_groups(placements: &[(u8, u32)], k_index: u8) -> Vec<IndexGroupRole> {
    let mut roles = vec![IndexGroupRole::Dummy; k_index as usize];
    for &(group, target_bin) in placements {
        if (group as usize) < (k_index as usize) {
            roles[group as usize] = IndexGroupRole::Real(target_bin);
        }
    }
    roles
}

/// Build `BucketMerkleItem`s for one query from its internal trace —
/// emits one item per probed INDEX cuckoo bin, with the query's CHUNK
/// bins attached to the first probed INDEX item (`bi == 0`). The layout
/// preserves the 🔒 Merkle INDEX Item-Count Symmetry invariant: every
/// query contributes exactly `INDEX_CUCKOO_NUM_HASHES` items regardless
/// of found / not-found / whale.
///
/// M=16 padding REMOVED (see docs/VERIFICATION_OVERVIEW.md): `trace.chunk_bins`
/// now holds exactly the query's REAL chunk count — `N` for a found query,
/// `0` for not-found / whale. The chunk-bin attachment stays unconditional
/// (all on `bi == 0`); a not-found query simply attaches zero chunk items,
/// and the per-bucket Merkle still issues >=1 all-dummy CHUNK-Merkle pass.
pub(crate) fn items_from_trace(trace: &QueryTraces) -> Vec<BucketMerkleItem> {
    trace
        .index_bins
        .iter()
        .enumerate()
        .map(|(bi, bin)| {
            let mut it = BucketMerkleItem {
                index_pbc_group: bin.pbc_group,
                index_bin_index: bin.bin_index,
                index_bin_content: bin.bin_content.clone(),
                chunk_pbc_groups: Vec::new(),
                chunk_bin_indices: Vec::new(),
                chunk_bin_contents: Vec::new(),
            };
            // Attach all chunk Merkle items to the first INDEX item
            // (`bi == 0`). A found query attaches its real chunks; a
            // not-found / whale query attaches none.
            if bi == 0 {
                for cb in &trace.chunk_bins {
                    it.chunk_pbc_groups.push(cb.pbc_group);
                    it.chunk_bin_indices.push(cb.bin_index);
                    it.chunk_bin_contents.push(cb.bin_content.clone());
                }
            }
            it
        })
        .collect()
}

/// Flatten a per-query traces list into a padded item list plus the
/// `item_index → query_index` backmapping the verifier needs to fold
/// per-item verdicts back to per-query verdicts.
pub(crate) fn collect_merkle_items_from_traces(
    traces: &[QueryTraces],
) -> (Vec<BucketMerkleItem>, Vec<usize>) {
    let mut items = Vec::new();
    let mut item_to_query = Vec::new();
    for (qi, trace) in traces.iter().enumerate() {
        for it in items_from_trace(trace) {
            items.push(it);
            item_to_query.push(qi);
        }
    }
    (items, item_to_query)
}

/// Convert an internal `IndexBinTrace` / `ChunkBinTrace` into the
/// public `BucketRef` shape. The public type widens `pbc_group` to
/// `u32` and drops the internal `ChunkBinTrace` vs `IndexBinTrace`
/// distinction — the discriminant is already encoded by which vec the
/// ref lives on (`QueryResult.index_bins` vs `QueryResult.chunk_bins`).
pub(crate) fn index_trace_to_bucket_ref(t: &IndexBinTrace) -> BucketRef {
    BucketRef {
        pbc_group: t.pbc_group as u32,
        bin_index: t.bin_index,
        bin_content: t.bin_content.clone(),
    }
}

pub(crate) fn chunk_trace_to_bucket_ref(t: &ChunkBinTrace) -> BucketRef {
    BucketRef {
        pbc_group: t.pbc_group as u32,
        bin_index: t.bin_index,
        bin_content: t.bin_content.clone(),
    }
}
