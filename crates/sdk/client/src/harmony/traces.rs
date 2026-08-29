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

/// Build `BucketMerkleItem`s for one query from a `QueryResult`'s
/// inspector-populated fields. Symmetric with [`items_from_trace`] —
/// same per-query-item layout, same ordering — but works on `QueryResult`
/// for the crate-internal membership stage. It is not a complete result
/// authenticity or release API.
pub(crate) fn items_from_inspector_result(result: &QueryResult) -> Vec<BucketMerkleItem> {
    result
        .index_bins
        .iter()
        .enumerate()
        .map(|(bi, bin)| {
            let mut it = BucketMerkleItem {
                index_pbc_group: bin.pbc_group as usize,
                index_bin_index: bin.bin_index,
                index_bin_content: bin.bin_content.clone(),
                chunk_pbc_groups: Vec::new(),
                chunk_bin_indices: Vec::new(),
                chunk_bin_contents: Vec::new(),
            };
            if result.matched_index_idx == Some(bi) {
                for cb in &result.chunk_bins {
                    it.chunk_pbc_groups.push(cb.pbc_group as usize);
                    it.chunk_bin_indices.push(cb.bin_index);
                    it.chunk_bin_contents.push(cb.bin_content.clone());
                }
            }
            it
        })
        .collect()
}

/// Flatten a per-query `QueryResult` list into a padded item list plus
/// the `item_index → query_index` backmapping. `None` results
/// contribute zero items (nothing to verify).
pub(crate) fn collect_merkle_items_from_results(
    results: &[Option<QueryResult>],
) -> (Vec<BucketMerkleItem>, Vec<usize>) {
    let mut items = Vec::new();
    let mut item_to_query = Vec::new();
    for (qi, maybe_r) in results.iter().enumerate() {
        if let Some(r) = maybe_r {
            for it in items_from_inspector_result(r) {
                items.push(it);
                item_to_query.push(qi);
            }
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

/// Move internal batched-query traces onto public results for the split
/// inspector flow. Absence gets a synthetic result so its proof trace survives;
/// every slot stays explicitly unverified until the standalone verifier
/// returns a positive verdict.
pub(crate) fn attach_inspector_traces(
    mut results: Vec<Option<QueryResult>>,
    traces: Vec<QueryTraces>,
) -> PirResult<Vec<Option<QueryResult>>> {
    if results.len() != traces.len() {
        return Err(PirError::InvalidState(format!(
            "Harmony query result/trace length mismatch: {} != {}",
            results.len(),
            traces.len(),
        )));
    }

    for (result, trace) in results.iter_mut().zip(traces) {
        let result = result.get_or_insert_with(QueryResult::empty);
        result.merkle_verified = false;
        result.index_bins = trace
            .index_bins
            .iter()
            .map(index_trace_to_bucket_ref)
            .collect();
        result.chunk_bins = trace
            .chunk_bins
            .iter()
            .map(chunk_trace_to_bucket_ref)
            .collect();
        result.matched_index_idx = trace.matched_index_idx;
    }

    Ok(results)
}

/// Reject incomplete/default public proof values before the split verifier can
/// produce a release verdict. Persisted Rust/WASM values are untrusted input;
/// a missing slot or missing INDEX trace must never become `true` by default.
pub(crate) fn validate_inspector_results(
    results: &[Option<QueryResult>],
    db_info: &DatabaseInfo,
) -> PirResult<()> {
    if results.is_empty() {
        return Err(PirError::MerkleVerificationFailed(
            "Harmony split verifier requires at least one result".into(),
        ));
    }

    let expected_index_bin_size = INDEX_SLOT_SIZE * INDEX_SLOTS_PER_BIN;
    let expected_chunk_bin_size = CHUNK_SLOT_SIZE * CHUNK_SLOTS_PER_BIN;
    for (query_index, result) in results.iter().enumerate() {
        let result = result.as_ref().ok_or_else(|| {
            PirError::MerkleVerificationFailed(format!(
                "Harmony split verifier result {query_index} is missing"
            ))
        })?;
        if result.index_bins.len() != INDEX_CUCKOO_NUM_HASHES {
            return Err(PirError::MerkleVerificationFailed(format!(
                "Harmony split verifier result {query_index} has {} INDEX traces; expected {INDEX_CUCKOO_NUM_HASHES}",
                result.index_bins.len(),
            )));
        }
        let expected_group = result.index_bins[0].pbc_group;
        for (trace_index, bin) in result.index_bins.iter().enumerate() {
            if bin.pbc_group != expected_group
                || bin.pbc_group >= u32::from(db_info.index_k)
                || bin.bin_index >= db_info.index_bins
                || bin.bin_content.len() != expected_index_bin_size
            {
                return Err(PirError::MerkleVerificationFailed(format!(
                    "Harmony split verifier result {query_index} has invalid INDEX trace {trace_index}"
                )));
            }
        }
        if result
            .matched_index_idx
            .is_some_and(|index| index >= INDEX_CUCKOO_NUM_HASHES)
        {
            return Err(PirError::MerkleVerificationFailed(format!(
                "Harmony split verifier result {query_index} has an invalid matched INDEX position"
            )));
        }
        if result.matched_index_idx.is_none() && !result.chunk_bins.is_empty() {
            return Err(PirError::MerkleVerificationFailed(format!(
                "Harmony split verifier result {query_index} has CHUNK traces without an INDEX match"
            )));
        }
        for (trace_index, bin) in result.chunk_bins.iter().enumerate() {
            if bin.pbc_group >= u32::from(db_info.chunk_k)
                || bin.bin_index >= db_info.chunk_bins
                || bin.bin_content.len() != expected_chunk_bin_size
            {
                return Err(PirError::MerkleVerificationFailed(format!(
                    "Harmony split verifier result {query_index} has invalid CHUNK trace {trace_index}"
                )));
            }
        }
    }

    Ok(())
}

/// Re-derive the input-dependent INDEX/CHUNK semantics from the exact native
/// bins retained by the query.  Release-safe callers run this before any
/// result crosses the WASM boundary; caller-supplied JSON is never accepted.
pub(crate) fn validate_inspector_semantics(
    script_hashes: &[ScriptHash],
    results: &[Option<QueryResult>],
    db_info: &DatabaseInfo,
) -> PirResult<()> {
    if script_hashes.len() != results.len() {
        return Err(PirError::MerkleVerificationFailed(format!(
            "Harmony verified inspector input/result length mismatch: {} != {}",
            script_hashes.len(),
            results.len(),
        )));
    }

    for (query_index, (script_hash, result)) in script_hashes.iter().zip(results.iter()).enumerate()
    {
        let result = result.as_ref().ok_or_else(|| {
            PirError::MerkleVerificationFailed(format!(
                "Harmony verified inspector result {query_index} is missing"
            ))
        })?;
        let group = result.index_bins[0].pbc_group as usize;
        if !pir_core::hash::derive_groups_3(script_hash, db_info.index_k as usize).contains(&group)
        {
            return Err(PirError::MerkleVerificationFailed(format!(
                "Harmony verified inspector result {query_index} INDEX group is not bound to its input"
            )));
        }
        let expected_tag = pir_core::hash::compute_tag(db_info.tag_seed, script_hash);
        let mut found: Option<(usize, u32, u8)> = None;

        for (h, bin) in result.index_bins.iter().enumerate() {
            let key = pir_core::hash::derive_cuckoo_key(db_info.index_master_seed, group, h);
            let expected_bin =
                pir_core::hash::cuckoo_hash(script_hash, key, db_info.index_bins as usize) as u32;
            if bin.bin_index != expected_bin {
                return Err(PirError::MerkleVerificationFailed(format!(
                    "Harmony verified inspector result {query_index} INDEX coordinate is not bound to its input"
                )));
            }
            if let Some((start, count)) = find_entry_in_index_result(&bin.bin_content, expected_tag)
            {
                if found.is_some() {
                    return Err(PirError::MerkleVerificationFailed(format!(
                        "Harmony verified inspector result {query_index} has duplicate INDEX matches"
                    )));
                }
                found = Some((h, start, count));
            }
        }

        if result.matched_index_idx != found.map(|(position, _, _)| position) {
            return Err(PirError::MerkleVerificationFailed(format!(
                "Harmony verified inspector result {query_index} matched INDEX position is not bound to its input"
            )));
        }

        let Some((_position, start_chunk_id, num_chunks)) = found else {
            if !result.entries.is_empty()
                || result.is_whale
                || result.raw_chunk_data.is_some()
                || !result.chunk_bins.is_empty()
            {
                return Err(PirError::MerkleVerificationFailed(format!(
                    "Harmony verified inspector absence result {query_index} carries unbound payload"
                )));
            }
            continue;
        };

        let expected_whale = num_chunks == 0;
        if result.is_whale != expected_whale {
            return Err(PirError::MerkleVerificationFailed(format!(
                "Harmony verified inspector result {query_index} whale flag disagrees with INDEX"
            )));
        }
        if expected_whale {
            if !result.entries.is_empty()
                || result.raw_chunk_data.is_some()
                || !result.chunk_bins.is_empty()
            {
                return Err(PirError::MerkleVerificationFailed(format!(
                    "Harmony verified inspector whale result {query_index} carries CHUNK payload"
                )));
            }
            continue;
        }

        let expected_count = num_chunks as usize;
        if result.chunk_bins.len() != expected_count {
            return Err(PirError::MerkleVerificationFailed(format!(
                "Harmony verified inspector result {query_index} has {} CHUNK traces; expected {expected_count}",
                result.chunk_bins.len(),
            )));
        }
        let mut rebuilt = Vec::with_capacity(expected_count * pir_core::params::CHUNK_SIZE);
        for (slot, bin) in result.chunk_bins.iter().enumerate() {
            let chunk_id = start_chunk_id.checked_add(slot as u32).ok_or_else(|| {
                PirError::MerkleVerificationFailed(format!(
                    "Harmony verified inspector result {query_index} CHUNK id overflow"
                ))
            })?;
            let chunk_group = bin.pbc_group as usize;
            let candidate_groups =
                pir_core::hash::derive_int_groups_3(chunk_id, db_info.chunk_k as usize);
            if !candidate_groups.contains(&chunk_group) {
                return Err(PirError::MerkleVerificationFailed(format!(
                    "Harmony verified inspector result {query_index} CHUNK {slot} group is not bound to its id"
                )));
            }
            let coordinate_matches = (0..CHUNK_CUCKOO_NUM_HASHES).any(|h| {
                let key =
                    pir_core::hash::derive_cuckoo_key(db_info.chunk_master_seed, chunk_group, h);
                pir_core::hash::cuckoo_hash_int(chunk_id, key, db_info.chunk_bins as usize) as u32
                    == bin.bin_index
            });
            if !coordinate_matches {
                return Err(PirError::MerkleVerificationFailed(format!(
                    "Harmony verified inspector result {query_index} CHUNK {slot} coordinate is not bound to its id"
                )));
            }
            let data = find_chunk_in_result(&bin.bin_content, chunk_id).ok_or_else(|| {
                PirError::MerkleVerificationFailed(format!(
                    "Harmony verified inspector result {query_index} CHUNK {slot} is missing from its verified bin"
                ))
            })?;
            if data.len() != pir_core::params::CHUNK_SIZE {
                return Err(PirError::MerkleVerificationFailed(format!(
                    "Harmony verified inspector result {query_index} CHUNK {slot} is truncated"
                )));
            }
            rebuilt.extend_from_slice(data);
        }
        if rebuilt.len() != expected_count * pir_core::params::CHUNK_SIZE {
            return Err(PirError::MerkleVerificationFailed(format!(
                "Harmony verified inspector result {query_index} CHUNK payload length mismatch"
            )));
        }
        let decoded = decode_utxo_entries(&rebuilt)?;
        if decoded != result.entries {
            return Err(PirError::MerkleVerificationFailed(format!(
                "Harmony verified inspector result {query_index} entries are not derived from verified CHUNK bins"
            )));
        }
        match (&db_info.kind, &result.raw_chunk_data) {
            (DatabaseKind::Delta { .. }, Some(raw)) if raw == &rebuilt => {}
            (DatabaseKind::Full, None) => {}
            _ => {
                return Err(PirError::MerkleVerificationFailed(format!(
                    "Harmony verified inspector result {query_index} raw CHUNK payload is not bound to the database kind"
                )))
            }
        }
    }

    Ok(())
}
