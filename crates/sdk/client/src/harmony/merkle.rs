use super::*;

impl HarmonyClient {
    /// Idempotent: re-runs are no-ops while `self.sibling_hints_loaded`
    /// matches the active db_id. Any change to `master_prp_key`,
    /// `prp_backend`, or `loaded_db_id` (via `invalidate_groups`) clears
    /// sibling state so the next call re-downloads.
    ///
    /// The number of sibling levels is derived from the server-supplied
    /// tree-tops: each tree's `cache_from_level` gives how many sibling
    /// rounds feed it, and the per-type max is the total sibling depth.
    /// `bins_per_table` at level L = `ceil(main_bins / arity^(L+1))`.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", db_id = db_info.db_id))]
    pub(crate) async fn ensure_sibling_groups_ready(
        &mut self,
        db_info: &DatabaseInfo,
        tree_tops: &[TreeTop],
    ) -> PirResult<()> {
        let _t_sib_start = Instant::now();
        let k_index = db_info.index_k as usize;
        let k_chunk = db_info.chunk_k as usize;
        if tree_tops.len() < k_index + k_chunk {
            return Err(PirError::Protocol(format!(
                "tree-tops has {} entries, expected at least {}",
                tree_tops.len(),
                k_index + k_chunk
            )));
        }
        let arity = BUCKET_MERKLE_ARITY as u64;
        let sib_w = BUCKET_MERKLE_SIB_ROW_SIZE as u32;

        let index_sib_levels = tree_tops[..k_index]
            .iter()
            .map(|t| t.cache_from_level)
            .max()
            .unwrap_or(0);
        let chunk_sib_levels = tree_tops[k_index..k_index + k_chunk]
            .iter()
            .map(|t| t.cache_from_level)
            .max()
            .unwrap_or(0);

        // Early-return only if our populated sibling state exactly
        // matches what the server-advertised tree-tops expect. Bare
        // "non-empty" was weaker: a cache restored from an older
        // snapshot with fewer levels would slip through and later
        // fail verification. This tighter check validates both
        // `sibling_hints_loaded` and the per-level group counts,
        // matching the invariants `persist_hints_to_cache` writes out.
        let expected_index_sib = index_sib_levels * k_index;
        let expected_chunk_sib = chunk_sib_levels * k_chunk;
        if self.sibling_hints_loaded == Some(db_info.db_id)
            && self.index_sib_groups.len() == expected_index_sib
            && self.chunk_sib_groups.len() == expected_chunk_sib
        {
            return Ok(());
        }

        // Reset any stale state before the refetch.
        self.index_sib_groups.clear();
        self.chunk_sib_groups.clear();
        self.sibling_hints_loaded = None;

        log::info!(
            "[PIR-AUDIT] HarmonyPIR sibling init: db_id={}, INDEX sib levels={}, CHUNK sib levels={}",
            db_info.db_id, index_sib_levels, chunk_sib_levels
        );

        // Capture readonly state to avoid borrow-checker conflicts when
        // taking mutable borrows of the various self fields below.
        let master_prp_key = self.master_prp_key;
        let prp_backend = self.prp_backend;
        let db_id = db_info.db_id;
        let index_bins_total = db_info.index_bins;
        let chunk_bins_total = db_info.chunk_bins;

        if self.hint_conn_secondary.is_some() {
            // ── Parallel path: INDEX siblings on hint primary, CHUNK
            // siblings on hint secondary. Each tree's levels stay
            // serial within its own future (level L+1 doesn't depend
            // on level L's hints — the dependency is at Merkle-verify
            // time, after sibling hints are loaded — but we keep the
            // intra-tree order to minimize peak memory growth from
            // group_init).
            //
            // Move everything the parallel futures need out of self
            // so they can hold disjoint mutable state. Restored after
            // the join.
            let mut index_sib_groups = std::mem::take(&mut self.index_sib_groups);
            let mut chunk_sib_groups = std::mem::take(&mut self.chunk_sib_groups);
            let mut hint_primary = self.hint_conn.take().ok_or(PirError::NotConnected)?;
            let mut hint_secondary = self
                .hint_conn_secondary
                .take()
                .expect("checked is_some above; field is private and not mutated mid-await");

            let index_fut = async {
                let mut profiles = Vec::with_capacity(index_sib_levels);
                let mut nodes: u64 = index_bins_total as u64;
                for sl in 0..index_sib_levels {
                    let level_n = nodes.div_ceil(arity);
                    nodes = level_n;
                    let t_init = Instant::now();
                    for g in 0..k_index {
                        let group = new_harmony_group(
                            level_n as u32,
                            sib_w,
                            0,
                            &master_prp_key,
                            ((k_index + k_chunk) + sl * k_index + g) as u32,
                            prp_backend,
                        )
                        .map_err(|e| {
                            PirError::BackendState(format!("INDEX sib HarmonyGroup init: {:?}", e))
                        })?;
                        index_sib_groups.insert((sl, g as u8), group);
                    }
                    let dt_init = t_init.elapsed();
                    let t_fetch = Instant::now();
                    let profile = fetch_and_load_sib_hints_into_map(
                        hint_primary.as_mut(),
                        &mut index_sib_groups,
                        sl,
                        db_id,
                        10 + sl as u8,
                        k_index as u8,
                        &master_prp_key,
                        prp_backend,
                    )
                    .await?;
                    let dt_fetch = t_fetch.elapsed();
                    if std::env::var("HARMONY_BENCH").is_ok() {
                        eprintln!(
                            "[HARMONY_BENCH]   sib INDEX L{} (parallel): group_init={:?}  fetch+load={:?}  (k={}, level_n={})",
                            sl, dt_init, dt_fetch, k_index, level_n,
                        );
                    }
                    profiles.push(profile);
                }
                Ok::<_, PirError>((hint_primary, index_sib_groups, profiles))
            };

            let chunk_fut = async {
                let mut profiles = Vec::with_capacity(chunk_sib_levels);
                let mut nodes: u64 = chunk_bins_total as u64;
                for sl in 0..chunk_sib_levels {
                    let level_n = nodes.div_ceil(arity);
                    nodes = level_n;
                    let t_init = Instant::now();
                    for g in 0..k_chunk {
                        let group = new_harmony_group(
                            level_n as u32,
                            sib_w,
                            0,
                            &master_prp_key,
                            ((k_index + k_chunk) + index_sib_levels * k_index + sl * k_chunk + g)
                                as u32,
                            prp_backend,
                        )
                        .map_err(|e| {
                            PirError::BackendState(format!("CHUNK sib HarmonyGroup init: {:?}", e))
                        })?;
                        chunk_sib_groups.insert((sl, g as u8), group);
                    }
                    let dt_init = t_init.elapsed();
                    let t_fetch = Instant::now();
                    let profile = fetch_and_load_sib_hints_into_map(
                        hint_secondary.as_mut(),
                        &mut chunk_sib_groups,
                        sl,
                        db_id,
                        20 + sl as u8,
                        k_chunk as u8,
                        &master_prp_key,
                        prp_backend,
                    )
                    .await?;
                    let dt_fetch = t_fetch.elapsed();
                    if std::env::var("HARMONY_BENCH").is_ok() {
                        eprintln!(
                            "[HARMONY_BENCH]   sib CHUNK L{} (parallel): group_init={:?}  fetch+load={:?}  (k={}, level_n={})",
                            sl, dt_init, dt_fetch, k_chunk, level_n,
                        );
                    }
                    profiles.push(profile);
                }
                Ok::<_, PirError>((hint_secondary, chunk_sib_groups, profiles))
            };

            #[cfg(not(target_arch = "wasm32"))]
            let (idx_out, chk_out) = tokio::try_join!(index_fut, chunk_fut)?;
            #[cfg(target_arch = "wasm32")]
            let (idx_out, chk_out) = futures::future::try_join(index_fut, chunk_fut).await?;

            let (hp, idx_groups, idx_profiles) = idx_out;
            let (hs, chk_groups, chk_profiles) = chk_out;

            // Restore connections + sib groups to self.
            self.hint_conn = Some(hp);
            self.hint_conn_secondary = Some(hs);
            self.index_sib_groups = idx_groups;
            self.chunk_sib_groups = chk_groups;

            // Record one round per fetched level (deferred from inside
            // the parallel futures — `record_round` needs `&mut self`
            // which we couldn't hold there).
            for p in idx_profiles {
                self.record_round(p);
            }
            for p in chk_profiles {
                self.record_round(p);
            }

            log::info!(
                "[PIR-AUDIT] HarmonyPIR sibling init (parallel 2-socket): INDEX L0..{} + CHUNK L0..{} fetched concurrently",
                index_sib_levels,
                chunk_sib_levels
            );
        } else {
            // ── Single-socket fallback path (pre-pool semantics) ──

            // ── INDEX sibling groups ───────────────────────────────────────
            let mut nodes: u64 = db_info.index_bins as u64;
            for sl in 0..index_sib_levels {
                let level_n = nodes.div_ceil(arity);
                nodes = level_n;
                let t_init = Instant::now();
                for g in 0..k_index {
                    let group = new_harmony_group(
                        level_n as u32,
                        sib_w,
                        0,
                        &self.master_prp_key,
                        // Matches server `compute_hints_for_group` for level 10+sl:
                        //   k_offset = (k_index + k_chunk) + sl * k_index
                        //   derived_key uses k_offset + group_id.
                        ((k_index + k_chunk) + sl * k_index + g) as u32,
                        self.prp_backend,
                    )
                    .map_err(|e| {
                        PirError::BackendState(format!("INDEX sib HarmonyGroup init: {:?}", e))
                    })?;
                    self.index_sib_groups.insert((sl, g as u8), group);
                }
                let dt_init = t_init.elapsed();
                let t_fetch = Instant::now();
                self.fetch_and_load_hints_into(
                    db_info.db_id,
                    10 + sl as u8,
                    k_index as u8,
                    HintTarget::IndexSib(sl),
                    None,
                )
                .await?;
                let dt_fetch = t_fetch.elapsed();
                if std::env::var("HARMONY_BENCH").is_ok() {
                    eprintln!(
                        "[HARMONY_BENCH]   sib INDEX L{}: group_init={:?}  fetch+load_hints={:?}  (k={}, level_n={})",
                        sl, dt_init, dt_fetch, k_index, level_n,
                    );
                }
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR INDEX sib L{}: loaded hints for {} groups (n={})",
                    sl,
                    k_index,
                    level_n
                );
            }

            // ── CHUNK sibling groups ───────────────────────────────────────
            let mut nodes: u64 = db_info.chunk_bins as u64;
            for sl in 0..chunk_sib_levels {
                let level_n = nodes.div_ceil(arity);
                nodes = level_n;
                let t_init = Instant::now();
                for g in 0..k_chunk {
                    let group = new_harmony_group(
                        level_n as u32,
                        sib_w,
                        0,
                        &self.master_prp_key,
                        // Matches server `compute_hints_for_group` for level 20+sl:
                        //   k_offset = (k_index + k_chunk)
                        //            + index_sib_levels * k_index
                        //            + sl * k_chunk
                        ((k_index + k_chunk) + index_sib_levels * k_index + sl * k_chunk + g)
                            as u32,
                        self.prp_backend,
                    )
                    .map_err(|e| {
                        PirError::BackendState(format!("CHUNK sib HarmonyGroup init: {:?}", e))
                    })?;
                    self.chunk_sib_groups.insert((sl, g as u8), group);
                }
                let dt_init = t_init.elapsed();
                let t_fetch = Instant::now();
                self.fetch_and_load_hints_into(
                    db_info.db_id,
                    20 + sl as u8,
                    k_chunk as u8,
                    HintTarget::ChunkSib(sl),
                    None,
                )
                .await?;
                let dt_fetch = t_fetch.elapsed();
                if std::env::var("HARMONY_BENCH").is_ok() {
                    eprintln!(
                        "[HARMONY_BENCH]   sib CHUNK L{}: group_init={:?}  fetch+load_hints={:?}  (k={}, level_n={})",
                        sl, dt_init, dt_fetch, k_chunk, level_n,
                    );
                }
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR CHUNK sib L{}: loaded hints for {} groups (n={})",
                    sl,
                    k_chunk,
                    level_n
                );
            }
        }

        self.sibling_hints_loaded = Some(db_info.db_id);

        // Persist the combined main + sibling hint state — this is
        // the "complete" snapshot the fast path in
        // `ensure_groups_ready` will restore next launch. Persist
        // errors are logged and ignored (read-only cache dirs must
        // not fail live queries).
        if let Err(e) = self.persist_hints_to_cache(db_info) {
            log::warn!(
                "[PIR-AUDIT] HarmonyPIR: failed to persist hints (main+sib) to cache: {}",
                e
            );
        }
        Ok(())
    }

    /// Build `BucketMerkleItem`s from collected query traces and verify them
    /// in one padded batch via HarmonyPIR sibling queries.
    ///
    /// Mirrors `dpf.rs::run_merkle_verification`: on any bin failing
    /// verification, the corresponding query is coerced to
    /// `Some(QueryResult::merkle_failed())` to signal an unverified
    /// (untrusted) result.
    ///
    /// Implementation is a thin shim over the helpers that also power the
    /// crate-internal membership stage: items come from per-query
    /// [`QueryTraces`], while the Merkle walker itself is shared.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", db_id = db_info.db_id))]
    pub(crate) async fn run_merkle_verification(
        &mut self,
        results: &mut [Option<QueryResult>],
        traces: &[QueryTraces],
        db_info: &DatabaseInfo,
    ) -> PirResult<()> {
        // Log the per-query outcome/item-count summary — kept here (not
        // in `collect_merkle_items_from_traces`) because this is the
        // path that feeds `[PIR-AUDIT]` audit logs. The crate-internal
        // membership stage rebuilds items from already-audited query results,
        // so it doesn't need to re-log the bin counts.
        for (qi, trace) in traces.iter().enumerate() {
            let outcome = match trace.matched_index_idx {
                Some(_) => {
                    let is_whale = results
                        .get(qi)
                        .and_then(|r| r.as_ref().map(|x| x.is_whale))
                        .unwrap_or(false);
                    if is_whale {
                        "WHALE"
                    } else {
                        "FOUND"
                    }
                }
                None => "NOT FOUND",
            };
            log::info!(
                "[PIR-AUDIT] HarmonyPIR Merkle: query #{} {} — verifying {} index bins + {} chunk bins",
                qi,
                outcome,
                trace.index_bins.len(),
                trace.chunk_bins.len()
            );
        }

        let (items, item_to_query) = collect_merkle_items_from_traces(traces);
        let verdicts = self
            .verify_merkle_items(&items, &item_to_query, results.len(), db_info)
            .await?;

        for (qi, verdict) in verdicts.into_iter().enumerate() {
            match verdict {
                None => continue, // not touched (no items attached to this query)
                Some(true) => {
                    log::info!("[PIR-AUDIT] HarmonyPIR Merkle PASSED for query #{}", qi);
                    if let Some(result) = results[qi].as_mut() {
                        result.merkle_verified = true;
                    }
                }
                Some(false) => {
                    log::warn!(
                        "[PIR-AUDIT] HarmonyPIR Merkle FAILED for query #{}: \
                         emitting QueryResult {{ merkle_verified: false, entries: [] }} (untrusted)",
                        qi
                    );
                    // Surface the failure as a distinct signal from "not found"
                    // (the old behaviour collapsed both to `None`). Entries are
                    // wiped so downstream callers cannot accidentally trust
                    // unverified data even if they ignore `merkle_verified`.
                    results[qi] = Some(QueryResult::merkle_failed());
                }
            }
        }

        Ok(())
    }

    /// Shared verifier backend used by both
    /// [`run_merkle_verification`](Self::run_merkle_verification) (inline,
    /// over fresh `QueryTraces`) and the crate-internal membership stage over
    /// ephemeral `QueryResult.index_bins/chunk_bins`.
    ///
    /// Runs the full Merkle pipeline: `REQ_BUCKET_MERKLE_TREE_TOPS`
    /// fetch on the query server, `ensure_sibling_groups_ready` (which
    /// hits the hint server on cache miss), then
    /// [`verify_bucket_merkle_batch_generic`] via a
    /// [`HarmonySiblingQuerier`] holding mutable borrows of the sibling
    /// group maps + query connection.
    ///
    /// Returns one verdict per query:
    /// * `None`    — no items attached (query skipped verification).
    /// * `Some(true)`  — all attached items verified.
    /// * `Some(false)` — at least one item failed.
    ///
    /// Padding invariant: per-item Merkle work is uniform by
    /// construction — callers must always attach
    /// `INDEX_CUCKOO_NUM_HASHES` INDEX items per query, regardless of
    /// found/not-found (see CLAUDE.md "Merkle INDEX Item-Count
    /// Symmetry").
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "harmony", db_id = db_info.db_id, num_items = items.len(), num_queries)
    )]
    pub(crate) async fn verify_merkle_items(
        &mut self,
        items: &[BucketMerkleItem],
        item_to_query: &[usize],
        num_queries: usize,
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<bool>>> {
        if items.is_empty() {
            log::info!("[PIR-AUDIT] HarmonyPIR Merkle: no items to verify — nothing to do");
            return Ok(vec![None; num_queries]);
        }

        // Fetch tree-tops blob via the query server (same blob both servers share).
        let leakage = self.leakage_recorder.clone();
        let tree_tops = if let Some(tops) = self.verified_tree_tops.get(&db_info.db_id) {
            tops.clone()
        } else {
            let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
            fetch_tree_tops(conn, db_info.db_id, leakage.as_ref(), "harmony", 0).await?
        };

        // Ensure sibling groups + hints are initialised.
        self.ensure_sibling_groups_ready(db_info, &tree_tops)
            .await?;

        // Drive the shared verifier with a Harmony-specific sibling querier.
        let index_k = db_info.index_k as usize;
        let chunk_k = db_info.chunk_k as usize;

        // Temporarily move sibling maps out of self so the querier can hold
        // mutable borrows of both them and the query connection. The maps
        // are restored before returning (on success OR failure).
        let mut index_sib_groups = std::mem::take(&mut self.index_sib_groups);
        let mut chunk_sib_groups = std::mem::take(&mut self.chunk_sib_groups);

        // Merkle leakage rounds are BUFFERED, not recorded inline:
        // `verify_bucket_merkle_batch_parallel` drives two queriers
        // concurrently on separate sockets, and recording inline would
        // interleave INDEX- and CHUNK-Merkle rounds in wall-clock order.
        // That interleaving varies run-to-run and correlates with
        // found-vs-not-found, making a found query wire-distinguishable
        // from a not-found one by Merkle-round ORDER alone. The buffers
        // are drained below in a fixed INDEX-then-CHUNK sequence.
        let mut merkle_rounds_first: Vec<RoundProfile> = Vec::new();
        let mut merkle_rounds_second: Vec<RoundProfile> = Vec::new();

        let per_item = if self.query_conn_secondary.is_some() {
            // ── Parallel path: split INDEX and CHUNK sib trees across
            // the two sockets. Each querier holds the full map for
            // its table_type, plus an empty placeholder for the other
            // (it will never be accessed because the parallel verifier
            // only ever calls table_type=0 on q_index and table_type=1
            // on q_chunk).
            let mut empty_chunk_placeholder: HashMap<(usize, u8), HarmonyGroup> = HashMap::new();
            let mut empty_index_placeholder: HashMap<(usize, u8), HarmonyGroup> = HashMap::new();

            // Disjoint borrows on the two `Option` fields.
            let conn0 = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
            let conn1 = self
                .query_conn_secondary
                .as_mut()
                .expect("checked is_some above");

            // `q_index` buffers INDEX-Merkle rounds, `q_chunk` buffers
            // CHUNK-Merkle rounds — into disjoint Vecs, so the two
            // concurrent sockets never interleave each other's rounds.
            let mut q_index = HarmonySiblingQuerier {
                query_conn: conn0,
                index_sib_groups: &mut index_sib_groups,
                chunk_sib_groups: &mut empty_chunk_placeholder,
                recorded: &mut merkle_rounds_first,
            };
            let mut q_chunk = HarmonySiblingQuerier {
                query_conn: conn1,
                index_sib_groups: &mut empty_index_placeholder,
                chunk_sib_groups: &mut chunk_sib_groups,
                recorded: &mut merkle_rounds_second,
            };

            verify_bucket_merkle_batch_parallel(
                &mut q_index,
                &mut q_chunk,
                items,
                db_info.index_bins,
                db_info.chunk_bins,
                index_k,
                chunk_k,
                db_info.db_id,
                &tree_tops,
            )
            .await
        } else {
            // ── Single-socket fallback: one querier verifies INDEX then
            // CHUNK sequentially, so `merkle_rounds_first` already ends
            // up in canonical INDEX-then-CHUNK order on its own.
            let query_conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
            let mut querier = HarmonySiblingQuerier {
                query_conn,
                index_sib_groups: &mut index_sib_groups,
                chunk_sib_groups: &mut chunk_sib_groups,
                recorded: &mut merkle_rounds_first,
            };
            verify_bucket_merkle_batch_generic(
                &mut querier,
                items,
                db_info.index_bins,
                db_info.chunk_bins,
                index_k,
                chunk_k,
                db_info.db_id,
                &tree_tops,
            )
            .await
        };

        // Restore sibling state regardless of success.
        self.index_sib_groups = index_sib_groups;
        self.chunk_sib_groups = chunk_sib_groups;

        // Emit the buffered Merkle leakage rounds in a fixed order — ALL
        // INDEX-Merkle rounds, then ALL CHUNK-Merkle rounds — regardless
        // of which socket's response landed first. This is the same
        // order the sequential DPF verifier produces, and it is what
        // keeps a found query's profile byte-identical to a not-found
        // query's (CLAUDE.md "found-vs-not-found"). Done here, after the
        // queriers drop and the sib maps are restored, because
        // `record_round` borrows `self`.
        for round in merkle_rounds_first {
            self.record_round(round);
        }
        for round in merkle_rounds_second {
            self.record_round(round);
        }

        let per_item = per_item?;

        // Aggregate per-item outcomes back to per-query verdicts: a
        // query passes iff ALL its items pass.
        let mut per_query: Vec<Option<bool>> = vec![None; num_queries];
        for (ii, ok) in per_item.iter().enumerate() {
            let qi = item_to_query[ii];
            per_query[qi] = match per_query[qi] {
                None => Some(*ok),
                Some(prev) => Some(prev && *ok),
            };
        }
        Ok(per_query)
    }

    /// Crate-internal first half of the verified inspector composition.
    /// Returns raw per-query results with inspector state populated and must
    /// never be exposed outside this crate before semantic and Merkle checks.
    ///
    /// # Shape vs. the trait-level `query_batch`
    ///
    /// Mirrors the DPF crate-internal raw stage. In short:
    ///
    /// * Every successful query returns `Some(QueryResult)` with
    ///   `index_bins` / `chunk_bins` / `matched_index_idx` populated
    ///   from the query's internal `QueryTraces`.
    /// * `matched_index_idx == None && entries.is_empty()` encodes
    ///   "not found".
    /// * `merkle_verified` is always `false` because Merkle was **not**
    ///   attempted. The atomic wrapper keeps entries quarantined, validates
    ///   exact input/decoded semantics, then runs the membership-only helper.
    /// * Empty input and databases without a bucket-Merkle commitment are
    ///   rejected before an address-dependent query frame is sent.
    ///
    /// # 🔒 Padding invariant
    ///
    /// This method uses the same batched PBC INDEX/CHUNK executor as the hot
    /// path rather than looping `query_single`. K=75 INDEX / K_CHUNK=80 CHUNK
    /// padding and the paired round-id sequence are unchanged. Payment V1
    /// therefore observes one logical job per PBC batch instead of one job per
    /// address.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "harmony", db_id, num_queries = script_hashes.len())
    )]
    pub(crate) async fn query_batch_with_inspector(
        &mut self,
        script_hashes: &[ScriptHash],
        db_id: u8,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }

        let catalog = self
            .catalog
            .clone()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;

        let db_info = catalog
            .get(db_id)
            .ok_or(PirError::DatabaseNotFound(db_id))?
            .clone();

        self.verified_roots.require_db(db_id)?;
        if script_hashes.is_empty() {
            return Err(PirError::MerkleVerificationFailed(
                "Harmony split inspector requires at least one query".into(),
            ));
        }
        if !db_info.has_bucket_merkle {
            return Err(PirError::MerkleVerificationFailed(
                "Harmony split inspector requires a bucket-Merkle commitment".into(),
            ));
        }
        self.preflight_bucket_tree_tops(&db_info).await?;

        let step = SyncStep::from_db_info(&db_info);
        let (results, traces) = self
            .execute_step_unverified(script_hashes, &step, &db_info)
            .await?;
        let results = attach_inspector_traces(results, traces)?;
        validate_inspector_results(&results, &db_info)?;
        Ok(results)
    }

    /// Release-safe inspector query. Query execution, semantic
    /// reconstruction, and Merkle proof verification are one native async
    /// operation, and the batch is released only when every slot passes.
    /// Success returns immutable, non-deserializable authority objects bound
    /// to each exact script hash and to `db_id`.
    pub async fn query_batch_verified_with_inspector(
        &mut self,
        script_hashes: &[ScriptHash],
        db_id: u8,
    ) -> PirResult<Vec<VerifiedQueryResult>> {
        let results = self
            .query_batch_with_inspector(script_hashes, db_id)
            .await?;
        let db_info = self
            .catalog
            .as_ref()
            .and_then(|catalog| catalog.get(db_id))
            .ok_or(PirError::DatabaseNotFound(db_id))?
            .clone();
        validate_inspector_results(&results, &db_info)?;
        validate_inspector_semantics(script_hashes, &results, &db_info)?;
        let verdicts = self
            .verify_merkle_batch_for_results(&results, db_id)
            .await?;
        if verdicts.len() != results.len() || verdicts.iter().any(|verdict| !verdict) {
            return Err(PirError::MerkleVerificationFailed(
                "Harmony verified inspector batch contains a failed inclusion proof".into(),
            ));
        }
        if results.len() != script_hashes.len() {
            return Err(PirError::MerkleVerificationFailed(format!(
                "Harmony verified inspector result count mismatch: expected {}, got {}",
                script_hashes.len(),
                results.len()
            )));
        }
        script_hashes
            .iter()
            .copied()
            .zip(results)
            .map(|(script_hash, result)| {
                result
                    .map(|result| VerifiedQueryResult::new(script_hash, db_id, result))
                    .ok_or_else(|| {
                        PirError::MerkleVerificationFailed(
                            "Harmony verified inspector released a missing result".into(),
                        )
                    })
            })
            .collect()
    }

    /// Crate-internal per-bucket Merkle membership stage for fresh results
    /// retained by the atomic verified-inspector call.
    ///
    /// This helper authenticates bin membership only. It does **not** bind
    /// `QueryResult.entries` to script-hash inputs and therefore must never be
    /// exposed as, or interpreted as, a complete result release verdict.
    ///
    /// Rebuilds the same `BucketMerkleItem` set the inline
    /// [`run_merkle_verification`](Self::run_merkle_verification) path
    /// builds, then runs the networked verifier via the shared
    /// [`verify_merkle_items`](Self::verify_merkle_items) helper.
    ///
    /// Returns one membership `bool` per input query:
    /// * `true`  — every required item for that query verified.
    /// * `false` — at least one attached item failed the proof; the
    ///   corresponding result must be treated as untrusted and should
    ///   be discarded or surfaced as `QueryResult::merkle_failed()`.
    ///
    /// Empty batches, `None` slots, default/empty inspector results, malformed
    /// trace geometry, and databases without bucket-Merkle commitments return
    /// `Err`; none can be interpreted as a successful absence proof.
    ///
    /// # 🔒 Padding invariant
    ///
    /// The underlying Merkle round is uniform by construction — the
    /// caller supplies items built from `INDEX_CUCKOO_NUM_HASHES`
    /// probes per query, and the shared verifier pads each level's
    /// sibling batch to K / K_CHUNK siblings (see CLAUDE.md "Query
    /// Padding").
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "harmony", db_id, num_results = results.len())
    )]
    pub(crate) async fn verify_merkle_batch_for_results(
        &mut self,
        results: &[Option<QueryResult>],
        db_id: u8,
    ) -> PirResult<Vec<bool>> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }

        let catalog = self
            .catalog
            .clone()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;

        let db_info = catalog
            .get(db_id)
            .ok_or(PirError::DatabaseNotFound(db_id))?
            .clone();

        self.verified_roots.require_db(db_id)?;
        if !db_info.has_bucket_merkle {
            return Err(PirError::MerkleVerificationFailed(
                "Harmony split verifier requires a bucket-Merkle commitment".into(),
            ));
        }
        validate_inspector_results(results, &db_info)?;
        self.preflight_bucket_tree_tops(&db_info).await?;

        // ensure_groups_ready + ensure_sibling_groups_ready need the
        // main groups to exist before sibling hints are fetched —
        // otherwise the HarmonySiblingQuerier would see empty
        // `index_sib_groups`/`chunk_sib_groups` maps.
        self.ensure_groups_ready(&db_info, None).await?;

        let (items, item_to_query) = collect_merkle_items_from_results(results);
        let verdicts = self
            .verify_merkle_items(&items, &item_to_query, results.len(), &db_info)
            .await?;

        // Defense in depth: validated inputs contribute exactly two INDEX
        // items, so a missing aggregate verdict is an internal verification
        // failure rather than a vacuous success.
        verdicts
            .into_iter()
            .enumerate()
            .map(|(query_index, verdict)| {
                verdict.ok_or_else(|| {
                    PirError::MerkleVerificationFailed(format!(
                        "Harmony split verifier produced no verdict for result {query_index}"
                    ))
                })
            })
            .collect()
    }

    /// Like [`PirClient::sync`], but drives a [`SyncProgress`] observer
    /// through every step of the computed [`SyncPlan`]. Intended for
    /// UI surfaces (terminal spinner, JS `onProgress` callback) that
    /// want granular feedback on multi-step sync chains.
    ///
    /// Progress events fire in this order:
    /// 1. Per step, `on_step_start(step_index, total_steps, description)`
    ///    where `description` is the [`SyncStep::name`]
    ///    (e.g. `"full @940611"` or `"delta 940611→944000"`).
    /// 2. Per step, `on_step_progress(step_index, 1.0)` once the step's
    ///    PIR + Merkle work returns (step granularity — sub-step
    ///    progress isn't wired through the current `execute_step`).
    /// 3. Per step, `on_step_complete(step_index)`.
    /// 4. Once all steps succeed, `on_complete(synced_height)`.
    /// 5. On any error, `on_error(&e)` before the error is propagated.
    ///
    /// Padding invariants are preserved — progress is purely
    /// observational and doesn't change what's sent on the wire.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "harmony", num_queries = script_hashes.len(), last_height = ?last_height)
    )]
    pub async fn sync_with_progress(
        &mut self,
        script_hashes: &[ScriptHash],
        last_height: Option<u32>,
        progress: &dyn SyncProgress,
    ) -> PirResult<SyncResult> {
        let run = async {
            if !self.is_connected() {
                self.connect().await?;
            }

            let catalog = match &self.catalog {
                Some(c) => c.clone(),
                None => self.fetch_catalog().await?,
            };

            let plan = self.compute_sync_plan(&catalog, last_height)?;

            if plan.is_empty() {
                return Ok(SyncResult {
                    results: vec![None; script_hashes.len()],
                    synced_height: plan.target_height,
                    was_fresh_sync: false,
                });
            }

            self.verified_roots.require_plan(&plan)?;

            let catalog = self
                .catalog
                .clone()
                .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;

            for step in &plan.steps {
                let db = catalog
                    .get(step.db_id)
                    .ok_or(PirError::DatabaseNotFound(step.db_id))?
                    .clone();
                self.preflight_bucket_tree_tops(&db).await?;
            }

            let total = plan.steps.len();
            let mut merged: Vec<Option<QueryResult>> = vec![None; script_hashes.len()];
            for (step_idx, step) in plan.steps.iter().enumerate() {
                progress.on_step_start(step_idx, total, &step.name);

                let db_info = catalog
                    .get(step.db_id)
                    .ok_or(PirError::DatabaseNotFound(step.db_id))?
                    .clone();

                let step_results = self.execute_step(script_hashes, step, &db_info).await?;

                // Single coarse tick per step — see doc comment above
                // for why finer granularity isn't wired yet.
                progress.on_step_progress(step_idx, 1.0);

                if step.is_full() {
                    merged = step_results;
                } else {
                    merged = merge_delta_batch(&merged, &step_results)?;
                }
                progress.on_step_complete(step_idx);
            }

            let result = SyncResult {
                results: merged,
                synced_height: plan.target_height,
                was_fresh_sync: plan.is_fresh_sync,
            };
            progress.on_complete(result.synced_height);
            Ok(result)
        }
        .await;

        if let Err(e) = &run {
            progress.on_error(e);
        }
        run
    }
}
