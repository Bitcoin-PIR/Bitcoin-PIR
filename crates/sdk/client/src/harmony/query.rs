use super::*;

impl HarmonyClient {
    /// Execute a single query step for a batch of script hashes.
    ///
    /// Runs PIR queries for each script hash, then — if the target database
    /// publishes a per-bucket Merkle tree (`DatabaseInfo::has_bucket_merkle`) —
    /// performs a single batched Merkle verification covering every INDEX
    /// cuckoo position inspected (two per not-found query) and every CHUNK
    /// bin that returned data. Items whose Merkle proof fails are coerced to
    /// `None` (treated as unverified; callers should treat them as an
    /// unknown/error state), mirroring the DPF client.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            backend = "harmony",
            db_id = _step.db_id,
            step = %_step.name,
            height = _step.tip_height,
            num_queries = script_hashes.len(),
        )
    )]
    pub(crate) async fn execute_step(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        // Root verification and trusted tree-top preflight are owned by the
        // sync orchestrator. Empty input has no hint, Payment-V1, or PIR work.
        if script_hashes.is_empty() {
            return Ok(Vec::new());
        }

        let bench = std::env::var("HARMONY_BENCH").is_ok();
        let t_step_start = Instant::now();
        let (mut results, traces) = self
            .execute_step_unverified(script_hashes, _step, db_info)
            .await?;

        let t_merkle_start = Instant::now();
        if db_info.has_bucket_merkle {
            self.run_merkle_verification(&mut results, &traces, db_info)
                .await?;
        } else {
            // Preserve the ordinary API's historical N/A-success semantics.
            // The split inspector API returns before this promotion.
            for result in results.iter_mut().flatten() {
                result.merkle_verified = true;
            }
            log::info!(
                "[PIR-AUDIT] HarmonyPIR Merkle verification SKIPPED (db_id={} has no bucket Merkle)",
                db_info.db_id
            );
        }
        if bench {
            eprintln!(
                "[HARMONY_BENCH] db={} Merkle verification: {:?}",
                db_info.db_id,
                t_merkle_start.elapsed()
            );
            eprintln!(
                "[HARMONY_BENCH] db={} TOTAL execute_step: {:?}",
                db_info.db_id,
                t_step_start.elapsed()
            );
        }

        Ok(results)
    }

    /// Execute the shared batched INDEX/CHUNK plan while retaining the
    /// per-query traces and deliberately stopping before Merkle verification.
    /// The hot path and split inspector path therefore have one Payment V1 DFA
    /// shape instead of the inspector issuing one job per address.
    pub(crate) async fn execute_step_unverified(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        db_info: &DatabaseInfo,
    ) -> PirResult<(Vec<Option<QueryResult>>, Vec<QueryTraces>)> {
        // Phase-level timing for diagnostics. Guarded by env var so it
        // only fires when the operator explicitly opts in.
        let _bench = std::env::var("HARMONY_BENCH").is_ok();
        let t_step_start = Instant::now();
        let t_hint_start = Instant::now();
        self.ensure_groups_ready(db_info, None).await?;
        let t_hint = t_hint_start.elapsed();
        if _bench {
            eprintln!(
                "[HARMONY_BENCH] db={} queries={} ensure_groups_ready: {:?}",
                db_info.db_id,
                script_hashes.len(),
                t_hint
            );
        }

        log::info!(
            "[PIR-AUDIT] HarmonyPIR execute_step: db_id={}, name={}, height={}, queries={}, has_bucket_merkle={}",
            db_info.db_id,
            db_info.name,
            db_info.height,
            script_hashes.len(),
            db_info.has_bucket_merkle
        );

        let mut results: Vec<Option<QueryResult>> = Vec::with_capacity(script_hashes.len());
        let mut traces: Vec<QueryTraces> = Vec::with_capacity(script_hashes.len());

        // Phase 1: batched INDEX via PBC plan. Drives one or more
        // K-padded HarmonyPIR INDEX rounds (one per cuckoo position
        // per PBC round) covering all scripthashes; each scripthash's
        // two INDEX Merkle items inherit a unique-per-batch
        // `pbc_group`, so `index_max_items_per_group_per_level = 2`
        // independently of the batch's collision pattern.
        let t_index_start = Instant::now();
        let index_outcomes = self
            .query_index_phase_batched(script_hashes, db_info)
            .await?;
        let t_index = t_index_start.elapsed();
        if _bench {
            eprintln!(
                "[HARMONY_BENCH] db={} INDEX phase: {:?}",
                db_info.db_id, t_index
            );
        }

        // Phase 2: per-scripthash CHUNK + result assembly. Each query
        // fetches/verifies its REAL chunk count — found queries fetch
        // their UTXO chunks, not-found / whale queries fetch none.
        //
        // M=16 chunk-Merkle padding REMOVED — 2026-05-17, see
        // Retired PLAN_MERKLE_CODING.md Phase 2 (mirrors the Phase 1 DPF
        // change). Found-vs-not-found stays hidden: an all-not-found
        // batch still emits one dummy K_CHUNK-padded CHUNK round pair
        // (`query_chunk_phase_batched`'s all-empty branch), and the
        // per-bucket Merkle always issues >=1 (all-dummy) CHUNK-Merkle
        // pass (the `chunk_sub_items.is_empty()` skip was removed in
        // merkle_verify.rs). The per-query chunk count is now an
        // admitted leak — mild; ~99% of addresses have 1 chunk.
        let t_chunk_start = Instant::now();

        // Phase 2 PREPROCESS: project each scripthash's INDEX outcome into
        // (real_count, is_whale, has_real_match, real_chunk_ids) up
        // front, in scripthash order. We need these lists indexable by
        // scripthash idx so the batched CHUNK fetch can run once and we
        // still emit per-scripthash QueryResults in original order.
        let outcomes: Vec<(Option<(u32, u8, bool)>, Vec<IndexBinTrace>, Option<usize>)> =
            index_outcomes.into_iter().collect();
        let mut per_q_real_count: Vec<usize> = Vec::with_capacity(outcomes.len());
        let mut per_q_is_whale: Vec<bool> = Vec::with_capacity(outcomes.len());
        let mut per_q_has_match: Vec<bool> = Vec::with_capacity(outcomes.len());
        let mut per_q_real_chunks: Vec<Vec<u32>> = Vec::with_capacity(outcomes.len());
        for (found_info, _ibins, _matched) in outcomes.iter() {
            let (real_chunk_ids, is_whale, has_real_match): (Vec<u32>, bool, bool) =
                match found_info {
                    Some((start, num, whale)) if *num > 0 => {
                        let end = start.checked_add(*num as u32).ok_or_else(|| {
                            PirError::MerkleVerificationFailed(format!(
                                "Harmony INDEX chunk range overflow: start={start} count={num}"
                            ))
                        })?;
                        ((*start..end).collect(), *whale, true)
                    }
                    Some((_start, _num, whale)) => (Vec::new(), *whale, true),
                    None => (Vec::new(), false, false),
                };
            per_q_real_count.push(real_chunk_ids.len());
            per_q_is_whale.push(is_whale);
            per_q_has_match.push(has_real_match);
            per_q_real_chunks.push(real_chunk_ids);
        }

        // Phase 2: BATCHED CHUNK fetch — one PBC plan over all queries'
        // REAL chunk lists; ceil(total_chunks / K_CHUNK) PBC rounds × 2
        // cuckoo positions of wire round-trips. For typical wallet syncs
        // (N ≫ 1) this batches every scripthash's chunks into shared
        // K_CHUNK-padded rounds. An all-not-found batch still emits one
        // dummy round pair (round-presence — see `query_chunk_phase_batched`).
        let chunk_results = self
            .query_chunk_phase_batched(&per_q_real_chunks, db_info)
            .await?;

        for (i, ((_found_info, index_bins, matched_idx), (chunk_data, chunk_bins))) in outcomes
            .into_iter()
            .zip(chunk_results.into_iter())
            .enumerate()
        {
            let q_traces = QueryTraces {
                index_bins,
                matched_index_idx: matched_idx,
                chunk_bins,
            };
            let real_count = per_q_real_count[i];
            let is_whale = per_q_is_whale[i];
            let has_real_match = per_q_has_match[i];
            log::info!(
                "[PIR-AUDIT] HarmonyPIR CHUNK: query #{} fetching {} real chunk(s)",
                i,
                real_count,
            );

            // The batched CHUNK phase fails closed unless every expected
            // slot is present, so truncation/fallback is forbidden here.
            let real_data_len = real_count * pir_core::params::CHUNK_SIZE;
            if q_traces.chunk_bins.len() != real_count || chunk_data.len() != real_data_len {
                return Err(PirError::MerkleVerificationFailed(format!(
                    "Harmony CHUNK closure failed for query {i}: recovered {} traces / {} bytes, expected {real_count} / {real_data_len}",
                    q_traces.chunk_bins.len(),
                    chunk_data.len(),
                )));
            }
            let chunk_data_len = chunk_data.len();
            let real_data = chunk_data;

            if !has_real_match {
                results.push(None);
                traces.push(q_traces);
                continue;
            }

            if !is_whale && real_count == 0 {
                log::warn!(
                    "[PIR-AUDIT] HarmonyPIR CHUNK closure: query #{} matched a non-whale INDEX entry with num_chunks=0; treating as whale",
                    i,
                );
            }

            // [DBG_HEX] Hex-dump the raw chunk bytes the server returned, so
            // we can manually trace the varint parse and confirm the decoder
            // is reading the right bytes. Gated on env to avoid noise.
            if std::env::var("PIR_DUMP_RAW_CHUNKS").is_ok() {
                let preview_len = std::cmp::min(real_data.len(), 80);
                let preview: String = real_data[..preview_len]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                eprintln!(
                    "[DBG_HEX] HarmonyPIR query #{} real_count={} real_data_len={} (raw chunk_data_len={}) bytes[0..{}]={}",
                    i, real_count, real_data.len(), chunk_data_len, preview_len, preview,
                );
            }

            let entries = decode_utxo_entries(&real_data)?;

            results.push(Some(QueryResult {
                entries,
                is_whale,
                // Results from this shared phase are quarantined until the
                // caller completes the inline or standalone Merkle verifier.
                merkle_verified: false,
                raw_chunk_data: if db_info.kind.is_delta() && real_count > 0 {
                    Some(real_data)
                } else {
                    None
                },
                index_bins: Vec::new(),
                chunk_bins: Vec::new(),
                matched_index_idx: None,
            }));
            traces.push(q_traces);
        }

        let t_chunk = t_chunk_start.elapsed();
        if _bench {
            eprintln!(
                "[HARMONY_BENCH] db={} CHUNK phase ({} queries): {:?}",
                db_info.db_id,
                script_hashes.len(),
                t_chunk
            );
            eprintln!(
                "[HARMONY_BENCH] db={} TOTAL execute_step_unverified: {:?}  (hint {:?} / index {:?} / chunk {:?})",
                db_info.db_id,
                t_step_start.elapsed(),
                t_hint,
                t_index,
                t_chunk,
            );
        }

        Ok((results, traces))
    }

    /// Batched INDEX phase for the Option-B
    /// `index_max_items_per_group_per_level` closure (Harmony analog
    /// of `DpfClient::query_index_phase_batched`).
    ///
    /// Plans PBC rounds over the batch's candidate groups, then for
    /// each PBC round runs `INDEX_CUCKOO_NUM_HASHES = 2` wire INDEX
    /// rounds (one per cuckoo position `h`) — each wire round packs
    /// every placed scripthash's bin for that `h` into the same
    /// K-padded HarmonyPIR INDEX request. Per-scripthash output is
    /// the same `(found_info, index_bins, matched_idx)` triple
    /// `query_single` produced pre-Option-B; the wire-observable
    /// difference is the round count is now `2 × n_pbc_rounds`
    /// (typically 2 for batches with `N ≤ k`) instead of
    /// `2 × N` (one per scripthash × 2 cuckoo positions).
    ///
    /// HarmonyPIR's per-group hint state is consumed in lock-step
    /// across placed groups: each wire round consumes one hint from
    /// every placed group's `HarmonyGroup`. For a single-query batch
    /// this matches pre-Option-B hint usage; for multi-query batches
    /// hint consumption is more balanced (no concentration on
    /// `derive_groups_3[0]`), which delays exhaustion-driven refresh
    /// rounds.
    #[tracing::instrument(level = "trace", skip_all, fields(backend = "harmony", db_id = db_info.db_id, num_queries = script_hashes.len()))]
    pub(crate) async fn query_index_phase_batched(
        &mut self,
        script_hashes: &[ScriptHash],
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<(Option<(u32, u8, bool)>, Vec<IndexBinTrace>, Option<usize>)>> {
        let k_index = db_info.index_k as usize;
        let index_bins = db_info.index_bins as usize;
        let tag_seed = db_info.tag_seed;
        let n = script_hashes.len();

        // PBC plan over each scripthash's three candidate groups.
        let (rounds, _) = crate::dpf::plan_index_pbc_rounds_for_hashes(script_hashes, k_index)?;

        // Build a placement view for downstream decode + Merkle traces.
        // Each scripthash's INDEX query (and its INDEX Merkle items)
        // inherits the planner-assigned group; this is the structural
        // change the closure relies on.
        let mut placement: Vec<(usize, usize)> = vec![(0, 0); n];
        for (round_id, round) in rounds.iter().enumerate() {
            for &(sh_idx, pbc_group) in round {
                placement[sh_idx] = (round_id, pbc_group);
            }
        }

        log::info!(
            "[PIR-AUDIT] HarmonyPIR INDEX batched query: {} queries planned into {} PBC round(s) (K={})",
            n, rounds.len(), k_index,
        );

        // Per-scripthash output buffers.
        let mut found_info: Vec<Option<(u32, u8, bool)>> = vec![None; n];
        let mut index_bins_per_sh: Vec<Vec<IndexBinTrace>> = (0..n)
            .map(|_| Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES))
            .collect();
        let mut matched_idx_per_sh: Vec<Option<usize>> = vec![None; n];

        // Pair-mode batching requires exactly 2 cuckoo positions per
        // scripthash (the wrapper's `build_request_pair` takes two query
        // indices). If `INDEX_CUCKOO_NUM_HASHES` ever changes, the
        // pair-mode path needs a redesign.
        const _: () = assert!(INDEX_CUCKOO_NUM_HASHES == 2);

        for (round_id, round) in rounds.iter().enumerate() {
            // Compute (group, target_bin) placements for both cuckoo
            // positions. The cuckoo key is keyed on the placed group,
            // matching what the server stores at build time.
            let mut placements_per_h: [Vec<(u8, u32)>; INDEX_CUCKOO_NUM_HASHES] =
                std::array::from_fn(|_| Vec::with_capacity(round.len()));
            for h in 0..INDEX_CUCKOO_NUM_HASHES {
                for &(sh_idx, pbc_group) in round {
                    let key =
                        pir_core::hash::derive_cuckoo_key(db_info.index_master_seed, pbc_group, h);
                    let target_bin =
                        pir_core::hash::cuckoo_hash(&script_hashes[sh_idx], key, index_bins);
                    placements_per_h[h].push((pbc_group as u8, target_bin as u32));
                }
            }

            // Pipelined pair INDEX round: 1 RTT instead of 2. Wire format
            // and hint accounting are identical to two sequential
            // `run_index_round` calls — see `run_index_round_pair` docs.
            // round_tag encodes (round_id, h) so audit logs can tell
            // which wire round corresponds to which (PBC round, cuckoo
            // position) pair.
            let round_tag_h0 = round_id * INDEX_CUCKOO_NUM_HASHES;
            let round_tag_h1 = round_tag_h0 + 1;
            let (answers_h0, answers_h1) = self
                .run_index_round_pair(
                    db_info.db_id,
                    &placements_per_h[0],
                    &placements_per_h[1],
                    round_tag_h0,
                    round_tag_h1,
                )
                .await?;
            let answers_per_h: [&HashMap<u8, Vec<u8>>; INDEX_CUCKOO_NUM_HASHES] =
                [&answers_h0, &answers_h1];

            // Map each placement back to its scripthash; record bin
            // trace + match. Iteration order (h=0 first, then h=1) is
            // unchanged from the sequential path, so per-scripthash
            // bookkeeping (matched_idx_per_sh, found_info, audit logs)
            // is bit-for-bit equivalent.
            for h in 0..INDEX_CUCKOO_NUM_HASHES {
                let answers = answers_per_h[h];
                for &(sh_idx, pbc_group) in round {
                    let g = pbc_group as u8;
                    let key =
                        pir_core::hash::derive_cuckoo_key(db_info.index_master_seed, pbc_group, h);
                    let target_bin =
                        pir_core::hash::cuckoo_hash(&script_hashes[sh_idx], key, index_bins) as u32;
                    let answer = answers.get(&g).ok_or_else(|| {
                        PirError::Protocol(format!(
                            "INDEX round group {} dropped for sh_idx {}",
                            g, sh_idx
                        ))
                    })?;

                    let pos = index_bins_per_sh[sh_idx].len();
                    index_bins_per_sh[sh_idx].push(IndexBinTrace {
                        pbc_group,
                        bin_index: target_bin,
                        bin_content: answer.clone(),
                    });

                    if found_info[sh_idx].is_some() {
                        log::info!(
                            "[PIR-AUDIT] HarmonyPIR INDEX[sh={}] extra probe at h={} (group={}, bin={}) — tracked for Merkle uniformity",
                            sh_idx, h, pbc_group, target_bin,
                        );
                        continue;
                    }

                    let my_tag = pir_core::hash::compute_tag(tag_seed, &script_hashes[sh_idx]);
                    if let Some(entry) = find_entry_in_index_result(answer, my_tag) {
                        let is_whale = entry.1 == 0;
                        log::info!(
                            "[PIR-AUDIT] HarmonyPIR INDEX[sh={}] FOUND at h={} (group={}, bin={}): start_chunk={}, num_chunks={}, whale={}",
                            sh_idx, h, pbc_group, target_bin, entry.0, entry.1, is_whale,
                        );
                        matched_idx_per_sh[sh_idx] = Some(pos);
                        found_info[sh_idx] = Some((entry.0, entry.1, is_whale));
                    } else {
                        log::info!(
                            "[PIR-AUDIT] HarmonyPIR INDEX[sh={}] miss at h={} (group={}, bin={})",
                            sh_idx,
                            h,
                            pbc_group,
                            target_bin,
                        );
                    }
                }
            }
        }

        // Suppress an unused-binding warning if no scripthashes were
        // placed (degenerate empty-batch case the planner handles gracefully).
        let _ = placement;

        Ok((0..n)
            .map(|i| {
                (
                    found_info[i],
                    std::mem::take(&mut index_bins_per_sh[i]),
                    matched_idx_per_sh[i],
                )
            })
            .collect())
    }

    /// Query a single script hash.
    ///
    /// Runs up to [`INDEX_CUCKOO_NUM_HASHES`] INDEX rounds (one per hash
    /// function); on a hit, runs the CHUNK rounds to recover UTXO bytes.
    ///
    /// Also returns `QueryTraces` describing every INDEX/CHUNK cuckoo bin we
    /// inspected, so the caller (`execute_step`) can run per-bucket Merkle
    /// verification if `DatabaseInfo::has_bucket_merkle` is set.
    // Retained as the reference single-input implementation for pair-mode
    // equivalence tests; production and inspector batches use the PBC executor.
    #[allow(dead_code)]
    #[tracing::instrument(level = "trace", skip_all, fields(backend = "harmony", db_id = db_info.db_id))]
    pub(crate) async fn query_single(
        &mut self,
        script_hash: &ScriptHash,
        db_info: &DatabaseInfo,
    ) -> PirResult<(Option<QueryResult>, QueryTraces)> {
        let k_index = db_info.index_k as usize;
        let index_bins = db_info.index_bins as usize;
        let tag_seed = db_info.tag_seed;

        // Pick the first of 3 candidate groups. The server replicates each
        // scripthash into ALL 3 candidate groups at build time
        // (see `tools/db-builder/src/build_cuckoo_generic.rs:87-90` and
        // `gen_4_build_merkle.rs:236-239`), so any one is sufficient to
        // retrieve an entry. This matches the reference Rust DPF binary
        // (`apps/server/src/bin/client.rs:246`) and every web TS client's
        // single-query behavior (all reduce to `candGroups[0]` at N=1 via
        // `planRounds`). If this path is ever extended to batch multiple
        // scripthashes per HarmonyPIR round, switch to `pbc_plan_rounds` to
        // spread real queries across groups — but K padding
        // (`INDEX_PADDED_GROUPS` queries per round) and the Merkle INDEX
        // item-count symmetry must be preserved.
        let real_group = pir_core::hash::derive_groups_3(script_hash, k_index)[0];
        let my_tag = pir_core::hash::compute_tag(tag_seed, script_hash);

        log::info!(
            "[PIR-AUDIT] HarmonyPIR INDEX query: script_hash={}, assigned_group={}, k={}, bins={} (K-padded to {} groups per round)",
            format_hash_short(script_hash),
            real_group,
            k_index,
            index_bins,
            k_index
        );

        let mut traces = QueryTraces {
            index_bins: Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES),
            matched_index_idx: None,
            chunk_bins: Vec::new(),
        };
        let mut hit: Option<(u32, u8, bool)> = None;

        // Probe BOTH cuckoo positions — even after a match — so the Merkle
        // item count is uniform (INDEX_CUCKOO_NUM_HASHES items per query)
        // across found / not-found / whale. This closes the side channel
        // where the server could infer presence from INDEX Merkle pass count.
        // Each extra probe costs one padded HarmonyPIR INDEX round (K queries,
        // server-side still padded) on found@h=0 queries.
        for h in 0..INDEX_CUCKOO_NUM_HASHES {
            let key = pir_core::hash::derive_cuckoo_key(db_info.index_master_seed, real_group, h);
            let target_bin = pir_core::hash::cuckoo_hash(script_hash, key, index_bins);

            let placements = [(real_group as u8, target_bin as u32)];
            let mut round_results = self.run_index_round(db_info.db_id, &placements, h).await?;
            let answer = round_results.remove(&(real_group as u8)).ok_or_else(|| {
                PirError::Protocol(format!(
                    "INDEX round dropped real group {} response",
                    real_group
                ))
            })?;

            let pos = traces.index_bins.len();
            traces.index_bins.push(IndexBinTrace {
                pbc_group: real_group,
                bin_index: target_bin as u32,
                bin_content: answer.clone(),
            });

            if hit.is_some() {
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR INDEX extra probe at cuckoo h={} (group={}, bin={}) — tracked for Merkle uniformity",
                    h, real_group, target_bin
                );
                continue;
            }

            if let Some(entry) = find_entry_in_index_result(&answer, my_tag) {
                let is_whale = entry.1 == 0;
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR INDEX FOUND at cuckoo h={} (group={}, bin={}): start_chunk={}, num_chunks={}, whale={}",
                    h, real_group, target_bin, entry.0, entry.1, is_whale
                );
                traces.matched_index_idx = Some(pos);
                hit = Some((entry.0, entry.1, is_whale));
            } else {
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR INDEX miss at cuckoo h={} (group={}, bin={})",
                    h,
                    real_group,
                    target_bin
                );
            }
        }

        let (start_chunk_id, num_chunks, is_whale) = match hit {
            Some(v) => v,
            None => {
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR INDEX NOT FOUND: verified {} cuckoo positions at group {} — all {} bins will be Merkle-verified for absence proof",
                    traces.index_bins.len(),
                    real_group,
                    traces.index_bins.len()
                );
                // 🔒 CHUNK Round-Presence Symmetry (CLAUDE.md): not-found
                // queries still issue one K_CHUNK-padded CHUNK PIR round so
                // the server cannot infer found-vs-not-found from CHUNK
                // round absence. Empty `chunk_ids` triggers the dummy-round
                // path inside `query_chunk_level`.
                let _ = self.query_chunk_level(&[], db_info).await?;
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR CHUNK round-presence padding: not-found query issued 1 dummy CHUNK pair"
                );
                return Ok((None, traces));
            }
        };

        if num_chunks == 0 {
            // Whale: same dummy CHUNK round as not-found for indistinguishability.
            let _ = self.query_chunk_level(&[], db_info).await?;
            log::info!(
                "[PIR-AUDIT] HarmonyPIR CHUNK round-presence padding: whale query issued 1 dummy CHUNK pair"
            );
            return Ok((
                Some(QueryResult {
                    entries: Vec::new(),
                    is_whale,
                    // Optimistic default — `run_merkle_verification` flips
                    // this to `false` if the INDEX proof fails.
                    merkle_verified: true,
                    raw_chunk_data: None,
                    // HarmonyClient doesn't surface inspector state to
                    // `QueryResult` today (the per-group hints and
                    // cuckoo-position machinery are internal to the query
                    // path). Kept empty here so the struct shape matches
                    // the other clients; the WASM-side HarmonyClient
                    // inspector extensions are Session 5 territory.
                    index_bins: Vec::new(),
                    chunk_bins: Vec::new(),
                    matched_index_idx: None,
                }),
                traces,
            ));
        }

        let end_chunk_id = start_chunk_id
            .checked_add(num_chunks as u32)
            .ok_or_else(|| {
                PirError::Decode(format!(
                    "chunk id range overflow: start={} count={}",
                    start_chunk_id, num_chunks
                ))
            })?;
        let chunk_ids: Vec<u32> = (start_chunk_id..end_chunk_id).collect();
        let (chunk_data, chunk_bins) = self.query_chunk_level(&chunk_ids, db_info).await?;
        traces.chunk_bins = chunk_bins;

        let entries = decode_utxo_entries(&chunk_data)?;
        Ok((
            Some(QueryResult {
                entries,
                is_whale,
                // Optimistic default — `run_merkle_verification` flips this
                // to `false` (and empties `entries`) if INDEX or CHUNK
                // proofs fail for this query.
                merkle_verified: true,
                raw_chunk_data: if db_info.kind.is_delta() {
                    Some(chunk_data)
                } else {
                    None
                },
                // See comment above — Harmony inspector state is out of
                // scope for Session 2.
                index_bins: Vec::new(),
                chunk_bins: Vec::new(),
                matched_index_idx: None,
            }),
            traces,
        ))
    }

    /// Build and send one INDEX batch (K groups, 1 sub-query each).
    /// `placements` lists the `(group_id, target_bin)` pairs that
    /// carry real queries this round; remaining groups send
    /// `build_synthetic_dummy()`. Returns a `HashMap<group_id,
    /// XOR-recovered bin content>` covering every group flagged as
    /// `Real`, leaving the caller to map placements back to scripthashes.
    ///
    /// Pre-Option-B this function only ever received a single placement
    /// (the assigned-group `derive_groups_3[0]` of the active
    /// scripthash). The Option-B closure for the
    /// `index_max_items_per_group_per_level` axis fans real placements
    /// across multiple groups within a single PBC round, halving the
    /// wire INDEX round count for batches and forcing
    /// `max_items_per_group_per_level = 2` regardless of input collision
    /// pattern. Wire format unchanged — the server still processes K
    /// BatchItems × (T-1) indices each indistinguishably.
    #[allow(dead_code)]
    pub(crate) async fn run_index_round(
        &mut self,
        db_id: u8,
        placements: &[(u8, u32)],
        round_tag: usize,
    ) -> PirResult<HashMap<u8, Vec<u8>>> {
        let k_index = self.index_groups.len() as u8;
        let roles = classify_index_groups(placements, k_index);
        let mut batch_items: Vec<BatchItem> = Vec::with_capacity(k_index as usize);

        for g in 0..k_index {
            let role = roles[g as usize];
            let group = self
                .index_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState(format!("missing INDEX group {}", g)))?;
            let bytes = match role {
                IndexGroupRole::Real(target_bin) => {
                    let req = group
                        .build_request(target_bin)
                        .map_err(|e| PirError::BackendState(format!("build_request: {:?}", e)))?;
                    req.into_bytes()
                }
                IndexGroupRole::Dummy => group.build_synthetic_dummy(),
            };
            batch_items.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes)?,
            });
        }

        let request = encode_batch_query(0, round_tag as u16, db_id, &batch_items);
        let request_bytes = request.len() as u64;
        // Per-group request shape: each group sends its `T - 1` indices
        // (the HarmonyPIR per-group invariant from CLAUDE.md). Capturing
        // `batch_items[g].indices.len()` lets a test assert the invariant
        // directly from the leakage profile.
        let items_per_group: Vec<u32> = batch_items
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();
        let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
        let response = conn.roundtrip(&request).await?;
        self.record_round(RoundProfile {
            kind: RoundKind::Index,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: items_per_group,
        });
        let raw_results = decode_batch_response_body(
            &response,
            0,
            round_tag as u16,
            k_index as usize,
            "Harmony INDEX response",
        )?;

        // Decode only groups marked `Real` — unprocessed dummy responses
        // mirror the chunk-side pattern, where decoding dummies would
        // advance HarmonyGroup state for no caller-visible benefit.
        let mut out = HashMap::new();
        for g in 0..k_index {
            if !matches!(roles[g as usize], IndexGroupRole::Real(_)) {
                continue;
            }
            let data = raw_results
                .get(&g)
                .ok_or_else(|| PirError::Protocol(format!("no INDEX response for group {}", g)))?;
            let group = self
                .index_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState("missing INDEX real group".into()))?;
            let answer = group
                .process_response(data)
                .map_err(|e| PirError::BackendState(format!("process_response: {:?}", e)))?;
            out.insert(g, answer);
        }
        Ok(out)
    }

    /// Pair-mode INDEX round: runs both cuckoo positions (h=0 and h=1) of
    /// one PBC round in a single pipelined network round-trip via the
    /// wrapper's `build_request_pair` / `process_response_pair` API.
    ///
    /// Wire format is identical to two back-to-back [`Self::run_index_round`]
    /// calls — each of the two emitted requests is K-padded with K
    /// `BatchItem`s of `T-1` indices, exactly as the sequential path. The
    /// only observable difference is the network ordering: both requests
    /// are sent before either response is awaited, so the two RTTs collapse
    /// into one (the second send overlaps the first response's flight
    /// time, and once both requests are in flight the responses arrive
    /// pipelined).
    ///
    /// Hint accounting is unchanged: each real group consumes 2 hints
    /// (one per cuckoo position), exactly as the sequential path. The
    /// upstream pair API guarantees bit-for-bit equivalence with two
    /// sequential `build_request` + `process_response` cycles given the
    /// same RNG seed (covered by upstream `remote` pair-equivalence tests).
    ///
    /// Dummy groups are *not* covered by the wrapper's `PendingPair`
    /// state — they call `build_synthetic_dummy()` twice (once per wire
    /// round). This is safe per the wrapper docs ("`build_synthetic_dummy`
    /// is safe to call" during the in-flight period — it only advances
    /// the RNG and never touches DS') and matches the sequential path's
    /// dummy emission shape.
    ///
    /// Both `placements_h0` and `placements_h1` MUST cover the same set
    /// of PBC groups (the same scripthashes are placed in the same groups
    /// across both cuckoo positions; only the `target_bin` differs). The
    /// function asserts this in debug builds.
    pub(crate) async fn run_index_round_pair(
        &mut self,
        db_id: u8,
        placements_h0: &[(u8, u32)],
        placements_h1: &[(u8, u32)],
        round_tag_h0: usize,
        round_tag_h1: usize,
    ) -> PirResult<(HashMap<u8, Vec<u8>>, HashMap<u8, Vec<u8>>)> {
        let k_index = self.index_groups.len() as u8;

        // Both cuckoo positions reuse the same group placement (a real
        // group at h=0 is also real at h=1; only the target_bin differs).
        // We classify from h=0 and assert the Real/Dummy split matches
        // h=1 — the actual bin index per Real group legitimately differs
        // between cuckoo positions, so we strip the Real(bin) payload
        // before comparing.
        let roles = classify_index_groups(placements_h0, k_index);
        debug_assert!(
            {
                let roles_h1 = classify_index_groups(placements_h1, k_index);
                roles.iter().zip(roles_h1.iter()).all(|(a, b)| {
                    matches!(
                        (a, b),
                        (IndexGroupRole::Real(_), IndexGroupRole::Real(_))
                            | (IndexGroupRole::Dummy, IndexGroupRole::Dummy),
                    )
                })
            },
            "pair-mode INDEX requires identical Real/Dummy split for h=0 and h=1",
        );

        // Per-group target-bin lookup. `placements_*` is a slice of
        // (group_id, target_bin); turn into a HashMap so we can pluck the
        // bin for each group during the pair build below.
        let h0_bins: HashMap<u8, u32> = placements_h0.iter().copied().collect();
        let h1_bins: HashMap<u8, u32> = placements_h1.iter().copied().collect();

        let mut batch_items_h0: Vec<BatchItem> = Vec::with_capacity(k_index as usize);
        let mut batch_items_h1: Vec<BatchItem> = Vec::with_capacity(k_index as usize);

        for g in 0..k_index {
            let role = roles[g as usize];
            let group = self
                .index_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState(format!("missing INDEX group {}", g)))?;
            let (bytes_h0, bytes_h1) = match role {
                IndexGroupRole::Real(_) => {
                    let bin_h0 = *h0_bins.get(&g).ok_or_else(|| {
                        PirError::InvalidState(format!("missing h=0 bin for real group {}", g))
                    })?;
                    let bin_h1 = *h1_bins.get(&g).ok_or_else(|| {
                        PirError::InvalidState(format!("missing h=1 bin for real group {}", g))
                    })?;
                    let pair = group.build_request_pair(bin_h0, bin_h1).map_err(|e| {
                        PirError::BackendState(format!("build_request_pair: {:?}", e))
                    })?;
                    let (req_1, req_2) = pair.into_parts();
                    (req_1.into_bytes(), req_2.into_bytes())
                }
                IndexGroupRole::Dummy => {
                    // Two independent K-padded synthetic dummies — one per
                    // wire round. RNG advances naturally so the two dummies
                    // differ on the wire. Per wrapper docs,
                    // `build_synthetic_dummy` is safe during the pair's
                    // in-flight period (it never touches DS').
                    let d_h0 = group.build_synthetic_dummy();
                    let d_h1 = group.build_synthetic_dummy();
                    (d_h0, d_h1)
                }
            };
            batch_items_h0.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes_h0)?,
            });
            batch_items_h1.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes_h1)?,
            });
        }

        let request_h0 = encode_batch_query(0, round_tag_h0 as u16, db_id, &batch_items_h0);
        let request_h1 = encode_batch_query(0, round_tag_h1 as u16, db_id, &batch_items_h1);
        let request_h0_bytes = request_h0.len() as u64;
        let request_h1_bytes = request_h1.len() as u64;
        let items_per_group_h0: Vec<u32> = batch_items_h0
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();
        let items_per_group_h1: Vec<u32> = batch_items_h1
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();

        // ── Pipelined network round-trip ──
        // Same fan-out treatment as `run_chunk_round_pair`: if a
        // secondary query socket is connected, send h=0 on conn0 and
        // h=1 on conn1 in parallel via `tokio::try_join!`. Each
        // socket gets its own TCP BDP budget at high RTT — the wire
        // saving is smaller for INDEX (~4 MB per side, ~1-2 s
        // typical) than for CHUNK (~15 MB per side, ~3 s) but the
        // logic is identical.
        //
        // Note: `conn.recv()` returns the raw frame INCLUDING the 4-byte
        // length prefix (unlike `conn.roundtrip()`, which strips it).
        // The strict frame decoder below validates and strips that prefix.
        let t_wire = Instant::now();
        let (response_h0, response_h1) = if self.query_conn_secondary.is_some() {
            let conn0 = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
            let conn1 = self
                .query_conn_secondary
                .as_mut()
                .expect("checked is_some above");
            #[cfg(not(target_arch = "wasm32"))]
            let (r0, r1) = tokio::try_join!(
                async {
                    conn0.send(request_h0).await?;
                    conn0.recv().await
                },
                async {
                    conn1.send(request_h1).await?;
                    conn1.recv().await
                },
            )?;
            #[cfg(target_arch = "wasm32")]
            let (r0, r1) = futures::future::try_join(
                async {
                    conn0.send(request_h0).await?;
                    conn0.recv().await
                },
                async {
                    conn1.send(request_h1).await?;
                    conn1.recv().await
                },
            )
            .await?;
            (r0, r1)
        } else {
            let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
            conn.send(request_h0).await?;
            conn.send(request_h1).await?;
            let r0 = conn.recv().await?;
            let r1 = conn.recv().await?;
            (r0, r1)
        };
        let dt_wire = t_wire.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            let mode = if self.query_conn_secondary.is_some() {
                "parallel-2-socket"
            } else {
                "pipelined-1-socket"
            };
            eprintln!(
                "[HARMONY_BENCH]   INDEX pair (round_tags={}/{}, {}): wire RTT {:?}  (req {}B+{}B resp {}B+{}B, k_index={})",
                round_tag_h0, round_tag_h1, mode, dt_wire,
                request_h0_bytes, request_h1_bytes,
                response_h0.len(), response_h1.len(),
                k_index,
            );
        }
        // Record both wire rounds in the leakage profile separately —
        // wire-observable shape is unchanged from the sequential path.
        // `response_bytes` is the raw frame length (length-prefix
        // included), matching the `dpf.rs` raw-recv path.
        self.record_round(RoundProfile {
            kind: RoundKind::Index,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes: request_h0_bytes,
            response_bytes: response_h0.len() as u64,
            items: items_per_group_h0,
        });
        self.record_round(RoundProfile {
            kind: RoundKind::Index,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes: request_h1_bytes,
            response_bytes: response_h1.len() as u64,
            items: items_per_group_h1,
        });

        let raw_results_h0 = decode_batch_response_frame(
            &response_h0,
            0,
            round_tag_h0 as u16,
            k_index as usize,
            "Harmony INDEX h=0 response",
        )?;
        let raw_results_h1 = decode_batch_response_frame(
            &response_h1,
            0,
            round_tag_h1 as u16,
            k_index as usize,
            "Harmony INDEX h=1 response",
        )?;

        // Decode real groups via the pair API. Dummies are not surfaced.
        let mut out_h0 = HashMap::new();
        let mut out_h1 = HashMap::new();
        for g in 0..k_index {
            if !matches!(roles[g as usize], IndexGroupRole::Real(_)) {
                continue;
            }
            let data_h0 = raw_results_h0.get(&g).ok_or_else(|| {
                PirError::Protocol(format!("no INDEX response (h=0) for group {}", g))
            })?;
            let data_h1 = raw_results_h1.get(&g).ok_or_else(|| {
                PirError::Protocol(format!("no INDEX response (h=1) for group {}", g))
            })?;
            let group = self
                .index_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState("missing INDEX real group".into()))?;
            let (answer_h0, answer_h1) = group
                .process_response_pair(data_h0, data_h1)
                .map_err(|e| PirError::BackendState(format!("process_response_pair: {:?}", e)))?;
            out_h0.insert(g, answer_h0);
            out_h1.insert(g, answer_h1);
        }
        Ok((out_h0, out_h1))
    }
}

impl HarmonyClient {
    /// Pipelined two-cuckoo-position CHUNK wire round, mirror of
    /// [`run_index_round_pair`](Self::run_index_round_pair).
    ///
    /// Performs both required cuckoo-position rounds (h=0 and h=1) for the SAME
    /// `real_queries` set, but pipelines the two requests so the two
    /// RTTs collapse into one — `conn.send(req_h0); conn.send(req_h1);
    /// conn.recv(); conn.recv();`. Privacy + wire-shape invariants are
    /// unchanged: each round is K_CHUNK-padded, every group emits
    /// either a real (T-1 sorted distinct indices) or synthetic
    /// (still T-1 indices) request.
    ///
    /// Bandwidth note: pair-mode always sends BOTH `h=0` and `h=1` for
    /// every group in `real_queries`. The serial path's "retry only
    /// missed chunks at h=1" optimization is removed — but K_CHUNK
    /// padding means the wire shape is invariant anyway, so the only
    /// real cost is the redundant decode of one extra response per
    /// real group. The wall-time saving (one RTT + one server walk
    /// pipelined into the other) typically dominates the decode
    /// overhead by ~3x.
    ///
    /// State invariant: every real group's `HarmonyGroup` consumes two
    /// hints (one per cuckoo position), exactly matching the serial
    /// path's `query_count += 2` semantics. The pair API (upstream
    /// `harmonypir`) is bit-for-bit equivalent to two sequential
    /// `build_request` + `process_response` cycles given the same RNG
    /// seed — see the upstream `remote` pair-equivalence tests.
    ///
    /// Returns `(out_h0, out_h1)` — two `HashMap<group_id, answer>`
    /// maps keyed by PBC group, containing the `process_response_pair`
    /// answers for the real groups only. Dummies are not surfaced.
    /// Callers run `find_chunk_in_result` on each map to extract the
    /// chunk_id slot from whichever cuckoo position actually held it.
    pub(crate) async fn run_chunk_round_pair(
        &mut self,
        db_id: u8,
        real_queries: &[(u32, u8)],
        chunk_bins: usize,
        chunk_master_seed: u64,
        round_id_h0: u16,
        round_id_h1: u16,
    ) -> PirResult<(HashMap<u8, Vec<u8>>, HashMap<u8, Vec<u8>>)> {
        let k_chunk = self.chunk_groups.len() as u8;
        let roles = classify_chunk_groups(real_queries, k_chunk);

        let mut batch_items_h0: Vec<BatchItem> = Vec::with_capacity(k_chunk as usize);
        let mut batch_items_h1: Vec<BatchItem> = Vec::with_capacity(k_chunk as usize);

        for g in 0..k_chunk {
            let role = roles[g as usize];
            let group = self
                .chunk_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState(format!("missing CHUNK group {}", g)))?;
            let (bytes_h0, bytes_h1) = match role {
                ChunkGroupRole::Real(cid) => {
                    let key_h0 =
                        pir_core::hash::derive_cuckoo_key(chunk_master_seed, g as usize, 0);
                    let key_h1 =
                        pir_core::hash::derive_cuckoo_key(chunk_master_seed, g as usize, 1);
                    let bin_h0 = pir_core::hash::cuckoo_hash_int(cid, key_h0, chunk_bins) as u32;
                    let bin_h1 = pir_core::hash::cuckoo_hash_int(cid, key_h1, chunk_bins) as u32;
                    let pair = group.build_request_pair(bin_h0, bin_h1).map_err(|e| {
                        PirError::BackendState(format!("build_request_pair (chunk): {:?}", e))
                    })?;
                    let (req_1, req_2) = pair.into_parts();
                    (req_1.into_bytes(), req_2.into_bytes())
                }
                ChunkGroupRole::Dummy => {
                    // Two independent K-padded synthetic dummies — one
                    // per wire round. Matches the dummy emission shape
                    // required pair (one dummy for each half).
                    let d_h0 = group.build_synthetic_dummy();
                    let d_h1 = group.build_synthetic_dummy();
                    (d_h0, d_h1)
                }
            };
            batch_items_h0.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes_h0)?,
            });
            batch_items_h1.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes_h1)?,
            });
        }

        let request_h0 = encode_batch_query(1, round_id_h0, db_id, &batch_items_h0);
        let request_h1 = encode_batch_query(1, round_id_h1, db_id, &batch_items_h1);
        let request_h0_bytes = request_h0.len() as u64;
        let request_h1_bytes = request_h1.len() as u64;
        let items_per_group_h0: Vec<u32> = batch_items_h0
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();
        let items_per_group_h1: Vec<u32> = batch_items_h1
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();

        // ── Pipelined network round-trip ──
        // Pool path: when a secondary query socket is connected, fan
        // h=0 onto conn0 and h=1 onto conn1 in parallel via
        // `tokio::try_join!`. Each socket gets its own TCP
        // bandwidth-delay-product budget — at high RTT this roughly
        // halves wall time vs. single-socket pipelining because the
        // two ~15 MB responses transfer concurrently instead of
        // sharing one stream's congestion window.
        //
        // Single-socket fallback: send both requests then recv both
        // (unchanged from pre-pool behaviour, kept identical so the
        // pool-size=1 code path is bit-for-bit equivalent).
        let t_wire = Instant::now();
        let (response_h0, response_h1) = if self.query_conn_secondary.is_some() {
            // Disjoint borrows on different `Option` fields → safe to
            // hold both `&mut` simultaneously.
            let conn0 = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
            let conn1 = self
                .query_conn_secondary
                .as_mut()
                .expect("checked is_some above");
            #[cfg(not(target_arch = "wasm32"))]
            let (r0, r1) = tokio::try_join!(
                async {
                    conn0.send(request_h0).await?;
                    conn0.recv().await
                },
                async {
                    conn1.send(request_h1).await?;
                    conn1.recv().await
                },
            )?;
            #[cfg(target_arch = "wasm32")]
            let (r0, r1) = futures::future::try_join(
                async {
                    conn0.send(request_h0).await?;
                    conn0.recv().await
                },
                async {
                    conn1.send(request_h1).await?;
                    conn1.recv().await
                },
            )
            .await?;
            (r0, r1)
        } else {
            let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
            conn.send(request_h0).await?;
            conn.send(request_h1).await?;
            let r0 = conn.recv().await?;
            let r1 = conn.recv().await?;
            (r0, r1)
        };
        let dt_wire = t_wire.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            let mode = if self.query_conn_secondary.is_some() {
                "parallel-2-socket"
            } else {
                "pipelined-1-socket"
            };
            eprintln!(
                "[HARMONY_BENCH]   CHUNK pair (round_ids={}/{}, {}): wire RTT {:?}  (req {}B+{}B resp {}B+{}B, k_chunk={})",
                round_id_h0, round_id_h1, mode, dt_wire,
                request_h0_bytes, request_h1_bytes,
                response_h0.len(), response_h1.len(),
                k_chunk,
            );
        }
        // Record both wire rounds in the leakage profile separately —
        // wire-observable shape is unchanged from the sequential path.
        self.record_round(RoundProfile {
            kind: RoundKind::Chunk,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes: request_h0_bytes,
            response_bytes: response_h0.len() as u64,
            items: items_per_group_h0,
        });
        self.record_round(RoundProfile {
            kind: RoundKind::Chunk,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes: request_h1_bytes,
            response_bytes: response_h1.len() as u64,
            items: items_per_group_h1,
        });

        let raw_results_h0 = decode_batch_response_frame(
            &response_h0,
            1,
            round_id_h0,
            k_chunk as usize,
            "Harmony CHUNK h=0 response",
        )?;
        let raw_results_h1 = decode_batch_response_frame(
            &response_h1,
            1,
            round_id_h1,
            k_chunk as usize,
            "Harmony CHUNK h=1 response",
        )?;

        // Decode only real groups, via the pair API.
        let t_decode = Instant::now();
        let mut out_h0 = HashMap::new();
        let mut out_h1 = HashMap::new();
        for g in 0..k_chunk {
            if !matches!(roles[g as usize], ChunkGroupRole::Real(_)) {
                continue;
            }
            let data_h0 = raw_results_h0.get(&g).ok_or_else(|| {
                PirError::Protocol(format!("no CHUNK pair response (h=0) for group {}", g))
            })?;
            let data_h1 = raw_results_h1.get(&g).ok_or_else(|| {
                PirError::Protocol(format!("no CHUNK pair response (h=1) for group {}", g))
            })?;
            let group = self
                .chunk_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState("missing CHUNK real group".into()))?;
            let (answer_h0, answer_h1) =
                group.process_response_pair(data_h0, data_h1).map_err(|e| {
                    PirError::BackendState(format!("process_response_pair (chunk): {:?}", e))
                })?;
            out_h0.insert(g, answer_h0);
            out_h1.insert(g, answer_h1);
        }
        let dt_decode = t_decode.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   CHUNK pair decode: {:?}  ({} real groups × 2)",
                dt_decode,
                out_h0.len(),
            );
        }

        Ok((out_h0, out_h1))
    }
}
