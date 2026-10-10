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
                self.fetch_and_load_hints_into(
                    db_info.db_id,
                    10 + sl as u8,
                    k_index as u8,
                    HintTarget::IndexSib(sl),
                    None,
                )
                .await?;
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
                self.fetch_and_load_hints_into(
                    db_info.db_id,
                    20 + sl as u8,
                    k_chunk as u8,
                    HintTarget::ChunkSib(sl),
                    None,
                )
                .await?;
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
    /// Mirrors `dpf.rs::run_merkle_verification`: a query whose bins fail
    /// verification keeps its result with `merkle_verified = false`; a
    /// not-found query becomes `Some(QueryResult::merkle_failed())`.
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
                        "[PIR-AUDIT] HarmonyPIR Merkle FAILED for query #{}: result kept with merkle_verified = false",
                        qi
                    );
                    // The result keeps its entries; a not-found query becomes
                    // an empty unverified result, distinct from a verified
                    // absence (`None`).
                    results[qi]
                        .get_or_insert_with(QueryResult::merkle_failed)
                        .merkle_verified = false;
                }
            }
        }

        Ok(())
    }

    /// Verifier backend for
    /// [`run_merkle_verification`](Self::run_merkle_verification).
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

        let tree_tops = self.tree_tops_for(db_info).await?;

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

    /// Bucket Merkle tree-tops for `db_info`: the proof-checked ones when the
    /// database has an installed root, else fetched from the query server
    /// (both servers share the blob).
    pub(crate) async fn tree_tops_for(
        &mut self,
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<TreeTop>> {
        if let Some(tops) = self.verified_tree_tops.get(&db_info.db_id) {
            return Ok(tops.clone());
        }
        let leakage = self.leakage_recorder.clone();
        let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
        fetch_tree_tops(conn, db_info.db_id, leakage.as_ref(), "harmony", 0).await
    }

    /// Like [`PirClient::query_batch`], but every slot is `Some` and carries
    /// the bins the query probed (`index_bins`, `chunk_bins`,
    /// `matched_index_idx`) for an inspector. A not-found query is an empty
    /// result holding its two INDEX bins; its `merkle_verified` is the
    /// absence proof's verdict.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "harmony", db_id, num_queries = script_hashes.len())
    )]
    pub async fn query_batch_with_inspector(
        &mut self,
        script_hashes: &[ScriptHash],
        db_id: u8,
    ) -> PirResult<Vec<QueryResult>> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        let db_info = self
            .catalog
            .as_ref()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?
            .get(db_id)
            .ok_or(PirError::DatabaseNotFound(db_id))?
            .clone();
        self.preflight_bucket_tree_tops(&db_info).await?;

        let step = SyncStep::from_db_info(&db_info);
        let (results, traces) = self
            .execute_step_traced(script_hashes, &step, &db_info)
            .await?;
        Ok(results
            .into_iter()
            .zip(traces)
            .map(|(result, trace)| {
                // A `None` slot is a not-found whose proof passed (a failed
                // proof is already `Some(merkle_failed())`).
                let mut result = result.unwrap_or_else(|| QueryResult {
                    merkle_verified: db_info.has_bucket_merkle,
                    ..QueryResult::empty()
                });
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
                result
            })
            .collect())
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
            require_fresh_sync(last_height)?;
            if !self.is_connected() {
                self.connect().await?;
            }

            let catalog = match &self.catalog {
                Some(c) => c.clone(),
                None => self.fetch_catalog().await?,
            };

            let plan = self.compute_sync_plan(&catalog, last_height)?;
            self.run_sync_plan(script_hashes, &plan, None, progress)
                .await
        }
        .await;

        if let Err(e) = &run {
            progress.on_error(e);
        }
        run
    }

    /// Run `plan` on top of `cached_results` (see [`require_sync_base`]),
    /// firing `progress` per step. Shared by `sync`, `sync_with_plan` and
    /// [`sync_with_progress`](Self::sync_with_progress).
    pub(super) async fn run_sync_plan(
        &mut self,
        script_hashes: &[ScriptHash],
        plan: &SyncPlan,
        cached_results: Option<&[Option<QueryResult>]>,
        progress: &dyn SyncProgress,
    ) -> PirResult<SyncResult> {
        require_sync_base(plan, script_hashes.len(), cached_results)?;
        if plan.is_empty() {
            progress.on_complete(plan.target_height);
            return Ok(SyncResult {
                results: cached_results
                    .map(|r| r.to_vec())
                    .unwrap_or_else(|| vec![None; script_hashes.len()]),
                synced_height: plan.target_height,
                was_fresh_sync: false,
            });
        }

        let catalog = self
            .catalog
            .clone()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;

        let mut merged: Vec<Option<QueryResult>> = cached_results
            .map(|r| r.to_vec())
            .unwrap_or_else(|| vec![None; script_hashes.len()]);

        for step in &plan.steps {
            let db = catalog
                .get(step.db_id)
                .ok_or(PirError::DatabaseNotFound(step.db_id))?
                .clone();
            self.preflight_bucket_tree_tops(&db).await?;
        }

        let total = plan.steps.len();
        for (step_idx, step) in plan.steps.iter().enumerate() {
            progress.on_step_start(step_idx, total, &step.name);
            log::info!(
                "[{}/{}] HarmonyPIR querying {} (db_id={}, height={})",
                step_idx + 1,
                total,
                step.name,
                step.db_id,
                step.tip_height
            );

            let db_info = catalog
                .get(step.db_id)
                .ok_or(PirError::DatabaseNotFound(step.db_id))?
                .clone();

            let step_results = self.execute_step(script_hashes, step, &db_info).await?;
            // Single coarse tick per step: `execute_step` reports no finer progress.
            progress.on_step_progress(step_idx, 1.0);

            if step.is_full() {
                merged = step_results;
            } else {
                merged = merge_delta_batch(&merged, &step_results)?;
            }
            progress.on_step_complete(step_idx);
        }

        progress.on_complete(plan.target_height);
        Ok(SyncResult {
            results: merged,
            synced_height: plan.target_height,
            was_fresh_sync: plan.is_fresh_sync,
        })
    }
}
