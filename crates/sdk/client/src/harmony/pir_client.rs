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

        // Two sockets per server, dialled in parallel so the cold-connect
        // cost is one RTT: the second one lets parallel paths fan rounds
        // across A/B (about 3x wall time against the public deployment).
        type DialResult = PirResult<(
            Box<dyn PirTransport>,
            Option<Box<dyn PirTransport>>,
            Box<dyn PirTransport>,
            Option<Box<dyn PirTransport>>,
        )>;
        #[cfg(not(target_arch = "wasm32"))]
        let dial_result: DialResult = async {
            let (h, hs, q, qs) = tokio::try_join!(
                WsConnection::connect(&self.hint_server_url),
                WsConnection::connect(&self.hint_server_url),
                WsConnection::connect(&self.query_server_url),
                WsConnection::connect(&self.query_server_url),
            )?;
            Ok((
                Box::new(h) as Box<dyn PirTransport>,
                Some(Box::new(hs) as Box<dyn PirTransport>),
                Box::new(q) as Box<dyn PirTransport>,
                Some(Box::new(qs) as Box<dyn PirTransport>),
            ))
        }
        .await;
        #[cfg(target_arch = "wasm32")]
        let dial_result: DialResult = async {
            use crate::wasm_transport::WasmWebSocketTransport;
            let ((h, hs), (q, qs)) = futures::future::try_join(
                futures::future::try_join(
                    WasmWebSocketTransport::connect(&self.hint_server_url),
                    WasmWebSocketTransport::connect(&self.hint_server_url),
                ),
                futures::future::try_join(
                    WasmWebSocketTransport::connect(&self.query_server_url),
                    WasmWebSocketTransport::connect(&self.query_server_url),
                ),
            )
            .await?;
            Ok((
                Box::new(h) as Box<dyn PirTransport>,
                Some(Box::new(hs) as Box<dyn PirTransport>),
                Box::new(q) as Box<dyn PirTransport>,
                Some(Box::new(qs) as Box<dyn PirTransport>),
            ))
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

        let catalog = self.fetch_db_catalog().await?;
        log::info!(
            "[PIR-AUDIT] HarmonyClient fetched DatabaseCatalog: {} database(s), latest_tip={:?}",
            catalog.databases.len(),
            catalog.latest_tip()
        );
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
        self.sync_with_progress(script_hashes, last_height, &NoProgress)
            .await
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
        self.run_sync_plan(script_hashes, plan, cached_results, &NoProgress)
            .await
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
