use super::*;

impl HarmonyClient {
    /// Execute CHUNK rounds to recover each chunk in `chunk_ids`.
    ///
    /// Returns `(chunk_data, chunk_bins)`:
    /// * `chunk_data` — assembled raw chunk bytes in the order of `chunk_ids`.
    /// * `chunk_bins` — per-chunk (pbc_group, bin_index, bin_content) for every
    ///   chunk we actually located. Used by the Merkle verifier to commit
    ///   the server to the chunk bin that served each slot.
    ///
    /// 🔒 CHUNK Round-Presence Symmetry (CLAUDE.md): if `chunk_ids` is
    /// empty (not-found / whale callers), this function still issues
    /// exactly one complete K_CHUNK-padded CHUNK pair (both cuckoo positions,
    /// all groups synthesised via `build_synthetic_dummy`) so the server cannot infer
    /// found-vs-not-found from absence of CHUNK traffic.
    #[allow(dead_code)]
    pub(crate) async fn query_chunk_level(
        &mut self,
        chunk_ids: &[u32],
        db_info: &DatabaseInfo,
    ) -> PirResult<(Vec<u8>, Vec<ChunkBinTrace>)> {
        let k_chunk = db_info.chunk_k as usize;
        let chunk_bins = db_info.chunk_bins as usize;

        // CHUNK Round-Presence Symmetry: empty input still emits one
        // K_CHUNK-padded pair so the wire signature is uniform across
        // found / not-found / whale. Both halves are mandatory under the V1
        // query DFA; emitting only h=0 would leave an ambiguous half-job.
        if chunk_ids.is_empty() {
            log::info!(
                "[PIR-AUDIT] HarmonyPIR CHUNK round-presence padding: emitting 1 dummy K_CHUNK-padded pair (all-synthetic, no real chunks)"
            );
            let _ = self
                .run_chunk_round_pair(
                    db_info.db_id,
                    &[],
                    chunk_bins,
                    db_info.chunk_master_seed,
                    0,
                    1,
                )
                .await?;
            return Ok((Vec::new(), Vec::new()));
        }

        // Map each chunk to its first candidate group. Two chunks may
        // collide on the same group — if so, only the first can be
        // queried in the current simple implementation. Follow-up work
        // could run PBC over multiple rounds the way the browser client
        // does; for now we fall back to whichever hash function places
        // the chunk in a free group.
        let mut pending: Vec<(u32, u8)> = Vec::new(); // (chunk_id, group)
        let mut used_groups: std::collections::HashSet<u8> = std::collections::HashSet::new();
        for &cid in chunk_ids {
            let candidates = pir_core::hash::derive_int_groups_3(cid, k_chunk);
            let mut placed = false;
            for &cand in &candidates {
                if !used_groups.contains(&(cand as u8)) {
                    pending.push((cid, cand as u8));
                    used_groups.insert(cand as u8);
                    placed = true;
                    break;
                }
            }
            if !placed {
                return Err(PirError::QueryFailed(format!(
                    "chunk {} collided on all {} candidate groups",
                    cid,
                    candidates.len()
                )));
            }
        }

        log::info!(
            "[PIR-AUDIT] HarmonyPIR CHUNK phase: {} chunks, k_chunk={}, bins={} (each round K_CHUNK-padded to {} groups)",
            chunk_ids.len(),
            k_chunk,
            chunk_bins,
            k_chunk
        );

        let mut chunk_data: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut chunk_trace_map: HashMap<u32, ChunkBinTrace> = HashMap::new();
        let mut recovered: std::collections::HashSet<u32> = std::collections::HashSet::new();

        // Always transmit both halves before looking at either answer. The
        // older sequential loop skipped h=1 when every chunk happened to hit
        // at h=0, making response contents control the paid wire shape and
        // violating the strict pair DFA.
        let (answers_h0, answers_h1) = self
            .run_chunk_round_pair(
                db_info.db_id,
                &pending,
                chunk_bins,
                db_info.chunk_master_seed,
                0,
                1,
            )
            .await?;
        for h in 0..CHUNK_CUCKOO_NUM_HASHES {
            let round_answers = if h == 0 { &answers_h0 } else { &answers_h1 };
            for (cid, group_id) in &pending {
                if recovered.contains(cid) {
                    continue;
                }
                if let Some(answer) = round_answers.get(group_id) {
                    if let Some(data) = find_chunk_in_result(answer, *cid) {
                        // Recompute the bin index the same way `run_chunk_round_pair`
                        // did, so our trace commits the server to the precise
                        // (group, bin) that served this chunk.
                        let key = pir_core::hash::derive_cuckoo_key(
                            db_info.chunk_master_seed,
                            *group_id as usize,
                            h,
                        );
                        let bin_index =
                            pir_core::hash::cuckoo_hash_int(*cid, key, chunk_bins) as u32;
                        chunk_data.insert(*cid, data.to_vec());
                        chunk_trace_map.insert(
                            *cid,
                            ChunkBinTrace {
                                pbc_group: *group_id as usize,
                                bin_index,
                                bin_content: answer.clone(),
                            },
                        );
                        log::info!(
                            "[PIR-AUDIT] HarmonyPIR CHUNK FOUND: chunk_id={}, group={}, bin={}, cuckoo_h={}",
                            cid, group_id, bin_index, h
                        );
                        recovered.insert(*cid);
                    }
                }
            }
        }

        for cid in chunk_ids {
            if !recovered.contains(cid) {
                return Err(PirError::MerkleVerificationFailed(format!(
                    "Harmony CHUNK missing: chunk_id={cid}"
                )));
            }
        }

        let mut out = Vec::with_capacity(chunk_ids.len() * CHUNK_SIZE);
        let mut traces = Vec::with_capacity(chunk_ids.len());
        for cid in chunk_ids {
            if let Some(data) = chunk_data.get(cid) {
                out.extend_from_slice(data);
            }
            if let Some(trace) = chunk_trace_map.remove(cid) {
                traces.push(trace);
            }
        }

        let expected_bytes = chunk_ids.len() * pir_core::params::CHUNK_SIZE;
        if traces.len() != chunk_ids.len() || out.len() != expected_bytes {
            return Err(PirError::MerkleVerificationFailed(format!(
                "Harmony CHUNK reassembly incomplete: recovered {} traces / {} bytes, expected {} / {}",
                traces.len(),
                out.len(),
                chunk_ids.len(),
                expected_bytes,
            )));
        }

        Ok((out, traces))
    }

    /// Batched CHUNK phase across multiple scripthashes — single
    /// network round-trip pair (CHUNK_CUCKOO_NUM_HASHES=2 wire rounds)
    /// per PBC round, instead of one full K_CHUNK-padded round per
    /// scripthash. Mirrors the [`query_index_phase_batched`] PBC
    /// pattern but for CHUNK queries.
    ///
    /// `per_query_chunks[i]` is the REAL chunk_id list for scripthash
    /// `i` — `N` ids for a found query with `N` UTXO chunks, empty for
    /// not-found / whale. (M=16 padding removed — see docs/VERIFICATION_OVERVIEW.md
    /// Phase 2; the per-query chunk count is now an admitted leak.)
    ///
    /// Returns one `(chunk_data, chunk_bins)` pair per scripthash, in
    /// the same order — `chunk_data` is concatenated payload bytes
    /// for that scripthash's slots, `chunk_bins` is the per-slot
    /// Merkle trace ready for `run_merkle_verification`.
    ///
    /// Wire-format and HarmonyGroup-state invariants are identical to
    /// the per-scripthash path's `run_chunk_round_pair` call: every wire
    /// round is K_CHUNK-padded, every group sends `T - 1` indices,
    /// every group consumes one hint per wire round. The only thing
    /// that changes is *how chunks are scheduled* into rounds —
    /// before, one scripthash filled one round (mostly padding);
    /// now, up to K_CHUNK chunks from any mix of scripthashes share
    /// a round.
    ///
    /// CHUNK Round-Presence Symmetry: when every per-scripthash list
    /// is empty (all not-found / whale in a "this DB has no found
    /// queries" batch), this function still issues one dummy
    /// K_CHUNK-padded `run_chunk_round_pair` — byte-shape-identical to
    /// a real single-PBC-round CHUNK fetch, so an all-not-found batch
    /// is wire-indistinguishable from a found batch.
    pub(crate) async fn query_chunk_phase_batched(
        &mut self,
        per_query_chunks: &[Vec<u32>],
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<(Vec<u8>, Vec<ChunkBinTrace>)>> {
        let k_chunk = db_info.chunk_k as usize;
        let chunk_bins = db_info.chunk_bins as usize;
        let n = per_query_chunks.len();

        // Empty: still emit one dummy round pair for symmetry. With the
        // M=16 padding removed (see docs/VERIFICATION_OVERVIEW.md) a
        // not-found / whale query owns 0 real chunks, so an
        // all-not-found batch reaches here. It must emit the SAME wire
        // shape as a found batch's single PBC round —
        // `run_chunk_round_pair`, two K_CHUNK-padded wire rounds
        // (h=0, h=1) — never an unpaired h=0-only request, or
        // found-vs-not-found would leak via the CHUNK round count.
        if per_query_chunks.iter().all(|cids| cids.is_empty()) {
            log::info!(
                "[PIR-AUDIT] HarmonyPIR CHUNK batched: emitting 1 dummy K_CHUNK-padded round pair (no real chunks across {} queries)",
                n,
            );
            let _ = self
                .run_chunk_round_pair(
                    db_info.db_id,
                    &[],
                    chunk_bins,
                    db_info.chunk_master_seed,
                    0,
                    1,
                )
                .await?;
            return Ok((0..n).map(|_| (Vec::new(), Vec::new())).collect());
        }

        // Flatten to a single global list: (sh_idx, slot_in_sh, chunk_id).
        // The slot is the chunk's position within its owning scripthash's
        // padded list — needed to put recovered bytes back in the right
        // order for `decode_utxo_entries`.
        let mut flat: Vec<(usize, usize, u32)> = Vec::new();
        for (sh_idx, cids) in per_query_chunks.iter().enumerate() {
            for (slot, &cid) in cids.iter().enumerate() {
                flat.push((sh_idx, slot, cid));
            }
        }

        // PBC plan: each chunk's NUM_HASHES = 3 candidate groups are
        // derived the same way the server's build path does it
        // (`derive_int_groups_3`), so the planner-assigned group is
        // valid for serving on the server side too.
        let candidate_groups: Vec<[usize; NUM_HASHES]> = flat
            .iter()
            .map(|&(_, _, cid)| pir_core::hash::derive_int_groups_3(cid, k_chunk))
            .collect();
        let rounds = pir_core::pbc::pbc_plan_rounds(&candidate_groups, k_chunk, NUM_HASHES, 500);
        log::info!(
            "[PIR-AUDIT] HarmonyPIR CHUNK batched: {} total chunks across {} queries → {} PBC round(s) × {} cuckoo positions = {} wire round(s) (K_CHUNK={})",
            flat.len(),
            n,
            rounds.len(),
            CHUNK_CUCKOO_NUM_HASHES,
            rounds.len() * CHUNK_CUCKOO_NUM_HASHES,
            k_chunk,
        );
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   CHUNK plan: {} chunks × {} queries → {} PBC × {} h = {} wire rounds",
                flat.len(), n, rounds.len(), CHUNK_CUCKOO_NUM_HASHES, rounds.len() * CHUNK_CUCKOO_NUM_HASHES,
            );
        }

        // Per-(sh, slot) outputs. We use HashMap<(sh, slot), _> rather
        // than HashMap<cid, _> because two scripthashes could pad to
        // the same synthetic chunk_id; (sh, slot) is the unambiguous
        // key.
        let mut chunk_data: HashMap<(usize, usize), Vec<u8>> = HashMap::new();
        let mut chunk_traces: HashMap<(usize, usize), ChunkBinTrace> = HashMap::new();
        let mut recovered: std::collections::HashSet<usize> = std::collections::HashSet::new(); // flat_idx

        // For each PBC round, pipeline the two cuckoo positions via
        // `run_chunk_round_pair`. The pre-2026-05-13 serial path looped
        // over `h ∈ 0..CHUNK_CUCKOO_NUM_HASHES` and filtered out
        // already-recovered chunks at h=1 — we lose that
        // "retry-only-missed-chunks" optimization here, but K_CHUNK
        // padding makes every wire round identical in shape anyway, so
        // bandwidth is unchanged. The benefit: one RTT + one
        // server-walk pipelined into the other, ~3 s of wall-time
        // saved per query batch against the public Hetzner deployment
        // (see `[HARMONY_BENCH]` numbers in
        // `docs/PLAN_HARMONY_PERF_AUDIT.md`).
        //
        // We assert `CHUNK_CUCKOO_NUM_HASHES == 2` here — pair-mode
        // would need generalisation to 3+ cuckoo positions. The
        // constant is fixed at 2 in `pir-core::params` so this is a
        // compile-time invariant; the assertion catches any future
        // params change.
        debug_assert_eq!(
            CHUNK_CUCKOO_NUM_HASHES, 2,
            "run_chunk_round_pair assumes exactly 2 cuckoo positions",
        );
        for (round_id, round) in rounds.iter().enumerate() {
            let still_pending: Vec<(usize, u8)> = round
                .iter()
                .map(|&(flat_idx, pbc_group)| (flat_idx, pbc_group as u8))
                .collect();
            if still_pending.is_empty() {
                continue;
            }

            let placements: Vec<(u32, u8)> = still_pending
                .iter()
                .map(|&(flat_idx, pbc_group)| {
                    let (_, _, cid) = flat[flat_idx];
                    (cid, pbc_group)
                })
                .collect();

            let round_tag_h0 = (round_id * CHUNK_CUCKOO_NUM_HASHES) as u16;
            let round_tag_h1 = (round_id * CHUNK_CUCKOO_NUM_HASHES + 1) as u16;
            let (answers_h0, answers_h1) = self
                .run_chunk_round_pair(
                    db_info.db_id,
                    &placements,
                    chunk_bins,
                    db_info.chunk_master_seed,
                    round_tag_h0,
                    round_tag_h1,
                )
                .await?;

            // Decode + reattribute to (sh_idx, slot). The chunk_id's
            // cuckoo placement deterministically picks ONE of h=0 / h=1
            // — try h=0 first, then h=1. The other position will
            // contain a different bin that doesn't have our chunk_id
            // slot (so `find_chunk_in_result` returns None), and we
            // skip it. If neither has the chunk, it's missing (e.g.
            // server lacks the entry).
            for &(flat_idx, pbc_group) in &still_pending {
                let (sh_idx, slot, cid) = flat[flat_idx];
                for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                    let answers = if h == 0 { &answers_h0 } else { &answers_h1 };
                    let Some(answer) = answers.get(&pbc_group) else {
                        continue;
                    };
                    let Some(data) = find_chunk_in_result(answer, cid) else {
                        continue;
                    };
                    let key = pir_core::hash::derive_cuckoo_key(
                        db_info.chunk_master_seed,
                        pbc_group as usize,
                        h,
                    );
                    let bin_index = pir_core::hash::cuckoo_hash_int(cid, key, chunk_bins) as u32;
                    chunk_data.insert((sh_idx, slot), data.to_vec());
                    chunk_traces.insert(
                        (sh_idx, slot),
                        ChunkBinTrace {
                            pbc_group: pbc_group as usize,
                            bin_index,
                            bin_content: answer.clone(),
                        },
                    );
                    recovered.insert(flat_idx);
                    break;
                }
            }
        }

        // Reassemble per-scripthash output, preserving slot order so
        // `decode_utxo_entries` reads bytes in the correct sequence.
        let mut output = Vec::with_capacity(n);
        for sh_idx in 0..n {
            let cids = &per_query_chunks[sh_idx];
            let mut data = Vec::with_capacity(cids.len() * pir_core::params::CHUNK_SIZE);
            let mut bins = Vec::with_capacity(cids.len());
            for slot in 0..cids.len() {
                if let Some(d) = chunk_data.get(&(sh_idx, slot)) {
                    data.extend_from_slice(d);
                }
                if let Some(t) = chunk_traces.get(&(sh_idx, slot)) {
                    bins.push(t.clone());
                }
            }
            let expected_bytes = cids.len() * pir_core::params::CHUNK_SIZE;
            if bins.len() != cids.len() || data.len() != expected_bytes {
                return Err(PirError::MerkleVerificationFailed(format!(
                    "Harmony batched CHUNK reassembly incomplete for query {sh_idx}: recovered {} traces / {} bytes, expected {} / {}",
                    bins.len(),
                    data.len(),
                    cids.len(),
                    expected_bytes,
                )));
            }
            output.push((data, bins));
        }

        Ok(output)
    }
}
