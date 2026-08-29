use super::*;

#[async_trait]
impl PirClient for HarmonyClient {
    fn backend_type(&self) -> PirBackendType {
        PirBackendType::Harmony
    }

    #[tracing::instrument(level = "info", skip_all, fields(backend = "harmony", hint = %self.hint_server_url, query = %self.query_server_url))]
    async fn connect(&mut self) -> PirResult<()> {
        // Preserve a complete live session on duplicate connect calls.  A
        // partial prior dial is instead replaced, so close all pool slots and
        // invalidate catalog/root/tree-top/hint bindings before re-dialing.
        if self.is_connected() {
            return Ok(());
        }
        self.close_transport_slots().await;
        self.invalidate_session_bindings();

        log::info!(
            "Connecting to HarmonyPIR servers: hint={}, query={}",
            self.hint_server_url,
            self.query_server_url
        );
        self.notify_state(ConnectionState::Connecting);

        // Pool sizes: 1 = single-socket (legacy behaviour); 2 = open a
        // secondary socket too so parallel paths can fan rounds across
        // A/B. We cap at 2 today — the structurally parallel axis
        // count maxes out at 3 and within-level fan-out beyond the
        // current pipelining gives diminishing returns. Default is 2
        // because the iperf data on the public deployment shows
        // ~3× wall-time savings vs single socket per server.
        //
        // `HARMONY_QUERY_POOL_SIZE` controls pir2 (query server).
        // `HARMONY_HINT_POOL_SIZE`  controls pir1 (hint  server).
        // Independent because the two servers have independent
        // bandwidth-delay-product characteristics.
        let query_pool: usize = std::env::var("HARMONY_QUERY_POOL_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2)
            .clamp(1, 2);
        let hint_pool: usize = std::env::var("HARMONY_HINT_POOL_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2)
            .clamp(1, 2);

        // Dial up to 4 sockets in parallel (2× hint, 2× query) so the
        // cold-connect cost is one RTT, not four. The secondary slots
        // for each server are `Option` because pool_size=1 leaves them
        // empty (single-socket fallback).
        type DialResult = PirResult<(
            Box<dyn PirTransport>,
            Option<Box<dyn PirTransport>>,
            Box<dyn PirTransport>,
            Option<Box<dyn PirTransport>>,
        )>;
        #[cfg(not(target_arch = "wasm32"))]
        let dial_result: DialResult = {
            // tokio::try_join! is variadic up to 64 args at compile
            // time; we use a small fixed shape (1-4 sockets) here.
            let hint_primary = WsConnection::connect(&self.hint_server_url);
            let query_primary = WsConnection::connect(&self.query_server_url);
            match (hint_pool >= 2, query_pool >= 2) {
                (true, true) => {
                    let hint_secondary = WsConnection::connect(&self.hint_server_url);
                    let query_secondary = WsConnection::connect(&self.query_server_url);
                    let (h, hs, q, qs) = tokio::try_join!(
                        hint_primary,
                        hint_secondary,
                        query_primary,
                        query_secondary
                    )?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        Some(Box::new(hs) as Box<dyn PirTransport>),
                        Box::new(q) as Box<dyn PirTransport>,
                        Some(Box::new(qs) as Box<dyn PirTransport>),
                    ))
                }
                (true, false) => {
                    let hint_secondary = WsConnection::connect(&self.hint_server_url);
                    let (h, hs, q) = tokio::try_join!(hint_primary, hint_secondary, query_primary)?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        Some(Box::new(hs) as Box<dyn PirTransport>),
                        Box::new(q) as Box<dyn PirTransport>,
                        None,
                    ))
                }
                (false, true) => {
                    let query_secondary = WsConnection::connect(&self.query_server_url);
                    let (h, q, qs) =
                        tokio::try_join!(hint_primary, query_primary, query_secondary)?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        None,
                        Box::new(q) as Box<dyn PirTransport>,
                        Some(Box::new(qs) as Box<dyn PirTransport>),
                    ))
                }
                (false, false) => {
                    let (h, q) = tokio::try_join!(hint_primary, query_primary)?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        None,
                        Box::new(q) as Box<dyn PirTransport>,
                        None,
                    ))
                }
            }
        };
        #[cfg(target_arch = "wasm32")]
        let dial_result: DialResult = async {
            use crate::wasm_transport::WasmWebSocketTransport;
            // wasm32 doesn't have a 4-tuple try_join; fall back to
            // try_join3 / try_join2 with the same shape conditionals.
            let hint_primary = WasmWebSocketTransport::connect(&self.hint_server_url);
            let query_primary = WasmWebSocketTransport::connect(&self.query_server_url);
            match (hint_pool >= 2, query_pool >= 2) {
                (true, true) => {
                    let hint_secondary = WasmWebSocketTransport::connect(&self.hint_server_url);
                    let query_secondary = WasmWebSocketTransport::connect(&self.query_server_url);
                    // Pair-up two try_joins to avoid needing a 4-arg variant.
                    let (a, b) = futures::future::try_join(
                        futures::future::try_join(hint_primary, hint_secondary),
                        futures::future::try_join(query_primary, query_secondary),
                    )
                    .await?;
                    let (h, hs) = a;
                    let (q, qs) = b;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        Some(Box::new(hs) as Box<dyn PirTransport>),
                        Box::new(q) as Box<dyn PirTransport>,
                        Some(Box::new(qs) as Box<dyn PirTransport>),
                    ))
                }
                (true, false) => {
                    let hint_secondary = WasmWebSocketTransport::connect(&self.hint_server_url);
                    let (h, hs, q) =
                        futures::future::try_join3(hint_primary, hint_secondary, query_primary)
                            .await?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        Some(Box::new(hs) as Box<dyn PirTransport>),
                        Box::new(q) as Box<dyn PirTransport>,
                        None,
                    ))
                }
                (false, true) => {
                    let query_secondary = WasmWebSocketTransport::connect(&self.query_server_url);
                    let (h, q, qs) =
                        futures::future::try_join3(hint_primary, query_primary, query_secondary)
                            .await?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        None,
                        Box::new(q) as Box<dyn PirTransport>,
                        Some(Box::new(qs) as Box<dyn PirTransport>),
                    ))
                }
                (false, false) => {
                    let (h, q) = futures::future::try_join(hint_primary, query_primary).await?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        None,
                        Box::new(q) as Box<dyn PirTransport>,
                        None,
                    ))
                }
            }
        }
        .await;

        let (hint_conn, hint_conn_secondary, query_conn, query_conn_secondary) = match dial_result {
            Ok(v) => v,
            Err(e) => {
                // Handshake failed — fall back to `Disconnected`, not
                // `Connecting`, so observers don't get stuck on an
                // intermediate state if they didn't install a catch-all.
                self.notify_state(ConnectionState::Disconnected);
                return Err(e);
            }
        };

        self.hint_conn = Some(hint_conn);
        self.hint_conn_secondary = hint_conn_secondary;
        self.query_conn = Some(query_conn);
        self.query_conn_secondary = query_conn_secondary;

        // Propagate any installed recorder to the fresh transports so
        // per-frame byte counts start flowing immediately. Done after
        // both slots are populated so a mid-connect observer can't see
        // half-installed state.
        if let Some(rec) = self.metrics_recorder.clone() {
            if let Some(ref mut c) = self.hint_conn {
                c.set_metrics_recorder(Some(rec.clone()), "harmony");
            }
            if let Some(ref mut c) = self.hint_conn_secondary {
                c.set_metrics_recorder(Some(rec.clone()), "harmony");
            }
            if let Some(ref mut c) = self.query_conn {
                c.set_metrics_recorder(Some(rec.clone()), "harmony");
            }
            if let Some(ref mut c) = self.query_conn_secondary {
                c.set_metrics_recorder(Some(rec), "harmony");
            }
        }

        log::info!(
            "Connected to HarmonyPIR servers (hint pool size {}, query pool size {})",
            if self.hint_conn_secondary.is_some() {
                2
            } else {
                1
            },
            if self.query_conn_secondary.is_some() {
                2
            } else {
                1
            },
        );
        self.fire_connect(&self.hint_server_url);
        if self.hint_conn_secondary.is_some() {
            self.fire_connect(&self.hint_server_url);
        }
        self.fire_connect(&self.query_server_url);
        if self.query_conn_secondary.is_some() {
            self.fire_connect(&self.query_server_url);
        }
        self.notify_state(ConnectionState::Connected);
        Ok(())
    }

    #[tracing::instrument(level = "info", skip_all, fields(backend = "harmony"))]
    async fn disconnect(&mut self) -> PirResult<()> {
        self.close_transport_slots().await;
        self.invalidate_session_bindings();
        self.fire_disconnect();
        self.notify_state(ConnectionState::Disconnected);
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.hint_conn.is_some() && self.query_conn.is_some()
    }

    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony"))]
    async fn fetch_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }

        // Prefer `REQ_GET_DB_CATALOG`: it carries real `height` and
        // `has_bucket_merkle` fields and reports every database the server
        // is serving (fresh + deltas), so `SyncResult::synced_height` is
        // accurate and cache-by-height works correctly. Fall back to the
        // legacy `REQ_HARMONY_GET_INFO` only for servers that don't support
        // the newer request (empty reply, unknown variant byte, or
        // `RESP_ERROR`).
        if let Some(catalog) = self.try_fetch_db_catalog().await? {
            log::info!(
                "[PIR-AUDIT] HarmonyClient fetched DatabaseCatalog via REQ_GET_DB_CATALOG: \
                 {} database(s), latest_tip={:?}",
                catalog.databases.len(),
                catalog.latest_tip()
            );
            self.verified_roots.reconcile_catalog(&catalog);
            self.verified_tree_tops
                .retain(|db_id, _| self.verified_roots.get(*db_id).is_some());
            self.catalog = Some(catalog.clone());
            return Ok(catalog);
        }

        log::warn!(
            "[PIR-AUDIT] HarmonyClient server did not respond to REQ_GET_DB_CATALOG; \
             falling back to legacy REQ_HARMONY_GET_INFO (height will be 0, Merkle off)"
        );
        let info = self.fetch_legacy_info().await?;
        let catalog = DatabaseCatalog {
            databases: vec![info],
        };
        self.verified_roots.reconcile_catalog(&catalog);
        self.verified_tree_tops
            .retain(|db_id, _| self.verified_roots.get(*db_id).is_some());
        self.catalog = Some(catalog.clone());
        Ok(catalog)
    }

    fn cached_catalog(&self) -> Option<&DatabaseCatalog> {
        self.catalog.as_ref()
    }

    fn compute_sync_plan(
        &self,
        catalog: &DatabaseCatalog,
        last_height: Option<u32>,
    ) -> PirResult<SyncPlan> {
        compute_sync_plan(catalog, last_height)
    }

    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(backend = "harmony", num_queries = script_hashes.len(), last_height = ?last_height)
    )]
    async fn sync(
        &mut self,
        script_hashes: &[ScriptHash],
        last_height: Option<u32>,
    ) -> PirResult<SyncResult> {
        if !self.is_connected() {
            self.connect().await?;
        }

        let catalog = match &self.catalog {
            Some(c) => c.clone(),
            None => self.fetch_catalog().await?,
        };

        let plan = self.compute_sync_plan(&catalog, last_height)?;
        self.sync_with_plan(script_hashes, &plan, None).await
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            backend = "harmony",
            num_queries = script_hashes.len(),
            num_steps = plan.steps.len(),
            target_height = plan.target_height,
            is_fresh_sync = plan.is_fresh_sync,
        )
    )]
    async fn sync_with_plan(
        &mut self,
        script_hashes: &[ScriptHash],
        plan: &SyncPlan,
        cached_results: Option<&[Option<QueryResult>]>,
    ) -> PirResult<SyncResult> {
        if plan.is_empty() {
            return Ok(SyncResult {
                results: cached_results
                    .map(|r| r.to_vec())
                    .unwrap_or_else(|| vec![None; script_hashes.len()]),
                synced_height: plan.target_height,
                was_fresh_sync: false,
            });
        }

        self.verified_roots.require_plan(plan)?;

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

        for (step_idx, step) in plan.steps.iter().enumerate() {
            log::info!(
                "[{}/{}] HarmonyPIR querying {} (db_id={}, height={})",
                step_idx + 1,
                plan.steps.len(),
                step.name,
                step.db_id,
                step.tip_height
            );

            let db_info = catalog
                .get(step.db_id)
                .ok_or(PirError::DatabaseNotFound(step.db_id))?
                .clone();

            let step_results = self.execute_step(script_hashes, step, &db_info).await?;

            if step.is_full() {
                merged = step_results;
            } else {
                merged = merge_delta_batch(&merged, &step_results)?;
            }
        }

        Ok(SyncResult {
            results: merged,
            synced_height: plan.target_height,
            was_fresh_sync: plan.is_fresh_sync,
        })
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "harmony", db_id, num_queries = script_hashes.len())
    )]
    async fn query_batch(
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
        self.preflight_bucket_tree_tops(&db_info).await?;

        // Fire query lifecycle callbacks so a recorder can time the
        // batch end-to-end without needing mid-layer hooks. `fire_*`
        // is a no-op when no recorder is installed; the
        // `Option<Instant>` returned by `fire_query_start` carries
        // the start moment when a recorder is installed and is `None`
        // otherwise (zero-overhead no-recorder path).
        let num_queries = script_hashes.len();
        let started_at = self.fire_query_start(db_id, num_queries);
        let step = SyncStep::from_db_info(&db_info);
        let result = self.execute_step(script_hashes, &step, &db_info).await;
        self.fire_query_end(db_id, num_queries, result.is_ok(), started_at);
        result
    }
}
