use super::*;

impl HarmonyClient {
    /// Create a new HarmonyPIR client.
    ///
    /// The master PRP key is drawn from the OS CSPRNG; use
    /// [`HarmonyClient::set_master_key`] to pin a specific key
    /// (useful for tests and for reusing cached hint state).
    pub fn new(hint_server_url: &str, query_server_url: &str) -> Self {
        // 🔒 C4 (docs/history/CODE_REVIEW_2026-06.md): this key determines the
        // real-vs-dummy slot pattern inside every T−1 request (V1
        // protocol + cache fingerprints), so it must be unpredictable to
        // the query server. The previous splitmix64(wall-clock)
        // derivation was brute-forceable from a timestamp guess —
        // especially on wasm32, where the clock is millisecond-coarse
        // and JS-observable. `getrandom` works on native and wasm32 (via
        // the `js` feature); failure means the platform has no entropy
        // source at all — unrecoverable and not server-triggerable, so
        // panicking in this infallible constructor is acceptable.
        let mut master_prp_key = [0u8; 16];
        getrandom::getrandom(&mut master_prp_key)
            .expect("OS entropy source unavailable for HarmonyPIR master PRP key");

        Self {
            hint_server_url: hint_server_url.to_string(),
            query_server_url: query_server_url.to_string(),
            hint_conn: None,
            hint_conn_secondary: None,
            query_conn: None,
            query_conn_secondary: None,
            catalog: None,
            prp_backend: PRP_HMR12,
            master_prp_key,
            loaded_db_id: None,
            index_groups: HashMap::new(),
            chunk_groups: HashMap::new(),
            index_sib_groups: HashMap::new(),
            chunk_sib_groups: HashMap::new(),
            sibling_hints_loaded: None,
            hint_cache_dir: None,
            state_listener: None,
            metrics_recorder: None,
            leakage_recorder: None,
            verified_roots: VerifiedRootState::default(),
            verified_tree_tops: HashMap::new(),
            use_v2_protocol: true,
        }
    }

    pub fn install_verified_database_roots(
        &mut self,
        roots: VerifiedDatabaseRoots,
    ) -> PirResult<()> {
        let catalog = self
            .catalog
            .as_ref()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;
        let db_id = roots.db_id;
        self.verified_roots.install(catalog, roots)?;
        self.verified_tree_tops.remove(&db_id);
        Ok(())
    }

    pub fn clear_verified_database_roots(&mut self) {
        self.verified_roots.clear();
        self.verified_tree_tops.clear();
    }

    /// Clear all catalog, proof, Merkle, and hint state bound to the current
    /// transport session.  Persisted hint bytes remain available on disk, but
    /// must be re-bound through the normal catalog/fingerprint path.
    pub(crate) fn invalidate_session_bindings(&mut self) {
        self.catalog = None;
        self.clear_verified_database_roots();
        self.invalidate_groups();
    }

    /// Gracefully close and remove every primary/secondary transport slot.
    /// This also handles partial failed sessions before a real re-dial.
    pub(crate) async fn close_transport_slots(&mut self) {
        if let Some(mut conn) = self.hint_conn.take() {
            let _ = conn.close().await;
        }
        if let Some(mut conn) = self.hint_conn_secondary.take() {
            let _ = conn.close().await;
        }
        if let Some(mut conn) = self.query_conn.take() {
            let _ = conn.close().await;
        }
        if let Some(mut conn) = self.query_conn_secondary.take() {
            let _ = conn.close().await;
        }
    }

    pub fn verified_database_roots(&self, db_id: u8) -> Option<&VerifiedDatabaseRoots> {
        self.verified_roots.get(db_id)
    }

    pub(crate) async fn preflight_bucket_tree_tops(&mut self, db: &DatabaseInfo) -> PirResult<()> {
        let Some(roots) = self.verified_roots.get(db.db_id).cloned() else {
            return Ok(());
        };
        if !db.has_bucket_merkle {
            return Err(PirError::VerificationFailed(format!(
                "db_id {} has verified bucket root but catalog disables bucket Merkle",
                db.db_id
            )));
        }
        if self.verified_tree_tops.contains_key(&db.db_id) {
            return Ok(());
        }
        let leakage = self.leakage_recorder.clone();
        let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
        let tops = fetch_tree_tops(conn, db.db_id, leakage.as_ref(), "harmony", 0).await?;
        verify_tree_tops_super_root(
            &tops,
            db.index_k as usize,
            db.chunk_k as usize,
            &roots.bucket_super_root,
        )?;
        self.verified_tree_tops.insert(db.db_id, tops);
        Ok(())
    }

    /// Fetch and bind the bucket Merkle tree-tops for `db_id` to an
    /// explicitly installed database proof before any private query is sent.
    ///
    /// Queries check the tree-tops against an installed root anyway; this
    /// runs the check up front.
    pub async fn preflight_verified_database(&mut self, db_id: u8) -> PirResult<()> {
        if self.verified_database_roots(db_id).is_none() {
            return Err(PirError::VerificationFailed(format!(
                "db_id {} has no installed database proof",
                db_id
            )));
        }
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        let catalog = match &self.catalog {
            Some(catalog) => catalog.clone(),
            None => self.fetch_catalog().await?,
        };
        let db = catalog
            .databases
            .iter()
            .find(|db| db.db_id == db_id)
            .cloned()
            .ok_or_else(|| PirError::Protocol(format!("db_id {} not present in catalog", db_id)))?;
        self.preflight_bucket_tree_tops(&db).await
    }

    /// Fetch and verify the attested-builder proof bundle for `db_id`.
    ///
    /// The proof is checked against the cached database catalog, fetching the
    /// catalog first if needed. Harmony servers answer the catalog/proof
    /// requests before role-specific hint/query dispatch, so the hint
    /// connection is sufficient and keeps this method consistent with
    /// `fetch_catalog`.
    pub async fn verify_database_proof(
        &mut self,
        db_id: u8,
        policy: &DatabaseProofPolicy,
    ) -> PirResult<VerifiedDatabaseRoots> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        let catalog = match &self.catalog {
            Some(c) => c.clone(),
            None => self.fetch_catalog().await?,
        };
        let db_info = catalog
            .databases
            .iter()
            .find(|db| db.db_id == db_id)
            .cloned()
            .ok_or_else(|| PirError::Protocol(format!("db_id {} not present in catalog", db_id)))?;
        let conn = self.hint_conn.as_mut().ok_or(PirError::NotConnected)?;
        let bundle = fetch_database_proof(conn.as_mut(), db_id).await?;
        verify_database_proof(&db_info, &bundle, policy)
    }

    // ─── Metrics recorder ──────────────────────────────────────────────────

    /// Install (or replace) a metrics recorder.
    ///
    /// The recorder receives:
    /// * Per-frame `on_bytes_sent` / `on_bytes_received` callbacks from
    ///   the hint + query transports (both labelled `"harmony"`).
    /// * Per-batch `on_query_start` / `on_query_end` callbacks at
    ///   [`query_batch`](PirClient::query_batch) entry / exit.
    /// * `on_connect` on successful `connect` (one per transport) and
    ///   `on_disconnect` on `disconnect` (once).
    ///
    /// If the client is already connected when the recorder is
    /// installed, the recorder is propagated to both transports
    /// immediately. Pass `None` to uninstall.
    pub fn set_metrics_recorder(&mut self, recorder: Option<Arc<dyn PirMetrics>>) {
        self.metrics_recorder = recorder.clone();
        if let Some(ref mut c) = self.hint_conn {
            c.set_metrics_recorder(recorder.clone(), "harmony");
        }
        if let Some(ref mut c) = self.hint_conn_secondary {
            c.set_metrics_recorder(recorder.clone(), "harmony");
        }
        if let Some(ref mut c) = self.query_conn {
            c.set_metrics_recorder(recorder.clone(), "harmony");
        }
        if let Some(ref mut c) = self.query_conn_secondary {
            c.set_metrics_recorder(recorder, "harmony");
        }
    }

    /// Fire `on_query_start` on the installed recorder, if any. Returns
    /// the `Instant` captured at start so a later
    /// [`fire_query_end`](Self::fire_query_end) can compute the
    /// wall-clock duration. `None` when no recorder is installed
    /// (preserves the zero-overhead no-recorder path).
    pub(crate) fn fire_query_start(&self, db_id: u8, num_queries: usize) -> Option<Instant> {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_query_start("harmony", db_id, num_queries);
            Some(Instant::now())
        } else {
            None
        }
    }

    /// Fire `on_query_end` on the installed recorder, if any. The
    /// `started_at` value comes from the matching
    /// [`fire_query_start`](Self::fire_query_start) call; `None`
    /// produces `Duration::ZERO` (best-effort observation per
    /// [`PirMetrics::on_query_end`] semantics).
    pub(crate) fn fire_query_end(
        &self,
        db_id: u8,
        num_queries: usize,
        success: bool,
        started_at: Option<Instant>,
    ) {
        if let Some(rec) = &self.metrics_recorder {
            let duration = started_at.map(|t| t.elapsed()).unwrap_or_default();
            rec.on_query_end("harmony", db_id, num_queries, success, duration);
        }
    }

    /// Fire `on_connect` for one transport, if a recorder is installed.
    pub(crate) fn fire_connect(&self, url: &str) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_connect("harmony", url);
        }
    }

    /// Fire `on_disconnect` on the installed recorder, if any.
    pub(crate) fn fire_disconnect(&self) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_disconnect("harmony");
        }
    }

    /// Install (or replace) a leakage recorder. Independent of
    /// [`set_metrics_recorder`](Self::set_metrics_recorder).
    /// `server_id = 0` is the query server, `1` is the hint server.
    /// Pass `None` to uninstall.
    pub fn set_leakage_recorder(&mut self, recorder: Option<Arc<dyn LeakageRecorder>>) {
        self.leakage_recorder = recorder;
    }

    /// Emit a [`RoundProfile`] to the installed leakage recorder, if any.
    pub(crate) fn record_round(&self, round: RoundProfile) {
        if let Some(rec) = &self.leakage_recorder {
            rec.record_round("harmony", round);
        }
    }

    // ─── Hint cache configuration ───────────────────────────────────────────

    /// Configure an on-disk cache directory for hint blobs.
    ///
    /// When set, [`ensure_groups_ready`](Self::ensure_groups_ready) and
    /// [`ensure_sibling_groups_ready`](Self::ensure_sibling_groups_ready)
    /// will transparently restore hints from disk (skipping the server
    /// roundtrips) and persist them back after any fresh fetch. Cache
    /// files are named by the SHA-256 fingerprint of
    /// `(master_prp_key, prp_backend, db_id, height, index_bins,
    /// chunk_bins, tag_seed, index_k, chunk_k)`, so snapshots for
    /// different master keys / backends / databases never collide on
    /// disk.
    ///
    /// The cache preserves `HarmonyGroup::query_count` and the
    /// relocation log across restarts, so a client that persists after
    /// each sync resumes exactly where it left off (the usual
    /// per-group `max_queries` budget still applies — once a group is
    /// exhausted the next launch will see a schema mismatch and
    /// refetch).
    ///
    /// Any I/O or schema error during restore is swallowed and falls
    /// through to the network fetch path; persist errors are logged
    /// but do not fail the parent `ensure_*` call.
    ///
    /// The builder form (consumes `self`) is convenient for one-line
    /// construction; use [`set_hint_cache_dir`](Self::set_hint_cache_dir)
    /// from mutable contexts.
    pub fn with_hint_cache_dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.hint_cache_dir = Some(dir.into());
        self
    }

    /// Mutable-reference counterpart to
    /// [`with_hint_cache_dir`](Self::with_hint_cache_dir). Passing
    /// `None` disables the on-disk cache for subsequent `ensure_*`
    /// calls without touching any already-restored in-memory state.
    pub fn set_hint_cache_dir(&mut self, dir: Option<PathBuf>) {
        self.hint_cache_dir = dir;
    }

    /// Return the currently configured cache directory, if any.
    pub fn hint_cache_dir(&self) -> Option<&std::path::Path> {
        self.hint_cache_dir.as_deref()
    }

    /// Resolve the on-disk cache path for `db_info` under the current
    /// `hint_cache_dir`. Returns `None` when no cache directory is
    /// configured.
    pub(crate) fn cache_path_for(&self, db_info: &DatabaseInfo) -> Option<PathBuf> {
        let dir = self.hint_cache_dir.as_ref()?;
        let key =
            hint_cache::CacheKey::from_db_info(self.master_prp_key, self.prp_backend, db_info);
        Some(dir.join(key.filename()))
    }
}

impl HarmonyClient {
    /// The two server URLs this client was configured with, in
    /// `(hint_server, query_server)` order. Useful for display-only
    /// surfaces that want to show "connected to …" without
    /// reconstructing the URLs from caller state.
    pub fn server_urls(&self) -> (&str, &str) {
        (&self.hint_server_url, &self.query_server_url)
    }

    /// Send REQ_ATTEST to one of the connected servers (`server_index`:
    /// 0 = hint server, 1 = query server) and return the verification
    /// result. See [`super::DpfClient::attest`] for the full semantics.
    pub async fn attest(
        &mut self,
        server_index: u8,
        nonce: [u8; 32],
    ) -> PirResult<crate::attest::AttestVerification> {
        let conn =
            match server_index {
                0 => self.hint_conn.as_mut().ok_or_else(|| {
                    PirError::Protocol("attest: hint server not connected".into())
                })?,
                1 => self.query_conn.as_mut().ok_or_else(|| {
                    PirError::Protocol("attest: query server not connected".into())
                })?,
                _ => {
                    return Err(PirError::Protocol(format!(
                        "attest: server_index must be 0 (hint) or 1 (query), got {}",
                        server_index
                    )))
                }
            };
        crate::attest::attest(conn.as_mut(), nonce).await
    }

    /// Send REQ_ANNOUNCE to the chosen server (0 = hint, 1 = query).
    /// See [`super::DpfClient::announce`] for full semantics.
    pub async fn announce(
        &mut self,
        server_index: u8,
    ) -> PirResult<crate::announce::AnnounceVerification> {
        let conn =
            match server_index {
                0 => self.hint_conn.as_mut().ok_or_else(|| {
                    PirError::Protocol("announce: hint server not connected".into())
                })?,
                1 => self.query_conn.as_mut().ok_or_else(|| {
                    PirError::Protocol("announce: query server not connected".into())
                })?,
                _ => {
                    return Err(PirError::Protocol(format!(
                        "announce: server_index must be 0 (hint) or 1 (query), got {}",
                        server_index
                    )))
                }
            };
        crate::announce::announce(conn.as_mut()).await
    }

    /// Present credits (`kind` and `payload` per [`crate::credits`]) on the
    /// hint (0) or query (1) server and return its receipt. Bearer material:
    /// call after the secure-channel upgrade.
    pub async fn present_credits(
        &mut self,
        server_index: u8,
        kind: u8,
        payload: &[u8],
    ) -> PirResult<crate::credits::CreditReceipt> {
        let conn = match server_index {
            0 => self.hint_conn.as_mut().ok_or_else(|| {
                PirError::Protocol("present_credits: hint server not connected".into())
            })?,
            1 => self.query_conn.as_mut().ok_or_else(|| {
                PirError::Protocol("present_credits: query server not connected".into())
            })?,
            _ => {
                return Err(PirError::Protocol(format!(
                    "present_credits: server_index must be 0 (hint) or 1 (query), got {}",
                    server_index
                )))
            }
        };
        crate::credits::present_credits(conn.as_mut(), kind, payload).await
    }

    /// Present an operator-issued API key on the hint (0) or query (1)
    /// server; see [`crate::DpfClient::present_api_key`].
    pub async fn present_api_key(&mut self, server_index: u8, key: &str) -> PirResult<()> {
        let conn = match server_index {
            0 => self.hint_conn.as_mut(),
            1 => self.query_conn.as_mut(),
            _ => {
                return Err(PirError::Protocol(format!(
                    "present_api_key: server_index must be 0 or 1, got {server_index}"
                )))
            }
        }
        .ok_or_else(|| {
            PirError::Protocol(format!(
                "present_api_key: {} server not connected",
                if server_index == 0 { "hint" } else { "query" }
            ))
        })?;
        crate::credits::present_api_key(conn.as_mut(), key).await
    }

    /// Pay the hint (0) or query (1) server's metered frames from
    /// `provider` when it requires credits; see
    /// [`crate::DpfClient::enable_credits`]. Call after the secure-channel
    /// upgrade (which also drops the secondary sockets, so one credited
    /// connection per server is all there is).
    pub async fn enable_credits(
        &mut self,
        server_index: u8,
        provider: std::sync::Arc<dyn crate::credit_transport::CreditProvider>,
    ) -> PirResult<crate::credit_transport::CreditStatus> {
        let slot = match server_index {
            0 => &mut self.hint_conn,
            1 => &mut self.query_conn,
            _ => {
                return Err(PirError::Protocol(format!(
                    "enable_credits: server_index must be 0 (hint) or 1 (query), got {}",
                    server_index
                )))
            }
        };
        let conn = slot.take().ok_or_else(|| {
            PirError::Protocol(format!(
                "enable_credits: {} server not connected",
                if server_index == 0 { "hint" } else { "query" }
            ))
        })?;
        let (conn, status) =
            crate::credit_transport::enable_credits(conn, provider, pir_credit::Backend::Harmony)
                .await;
        *slot = Some(conn);
        status
    }

    /// Replace both server connections with secure-channel-wrapped
    /// versions. See [`super::DpfClient::upgrade_to_secure_channel`]
    /// for the full semantics. Argument order matches the
    /// `(hint_server, query_server)` URL order.
    pub async fn upgrade_to_secure_channel(
        &mut self,
        hint_server_static_pub: [u8; 32],
        query_server_static_pub: [u8; 32],
    ) -> PirResult<()> {
        let mut eph_h = [0u8; 32];
        let mut nonce_h = [0u8; 32];
        let mut eph_q = [0u8; 32];
        let mut nonce_q = [0u8; 32];
        getrandom::getrandom(&mut eph_h)
            .map_err(|e| PirError::Protocol(format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut nonce_h)
            .map_err(|e| PirError::Protocol(format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut eph_q)
            .map_err(|e| PirError::Protocol(format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut nonce_q)
            .map_err(|e| PirError::Protocol(format!("getrandom: {}", e)))?;

        self.upgrade_to_secure_channel_with_seeds(
            hint_server_static_pub,
            eph_h,
            nonce_h,
            query_server_static_pub,
            eph_q,
            nonce_q,
        )
        .await
    }

    /// Binding-friendly overload: thread the same `eph_seed_*` you
    /// passed to [`crate::attest::attest_with_eph_binding`] for the
    /// corresponding server so the attestation covers this exact
    /// handshake. See
    /// [`super::DpfClient::upgrade_to_secure_channel_with_seeds`] for
    /// rationale. `hs_nonce_*` are HKDF salts (CSPRNG-fresh per call).
    pub async fn upgrade_to_secure_channel_with_seeds(
        &mut self,
        hint_server_static_pub: [u8; 32],
        eph_seed_hint: [u8; 32],
        hs_nonce_hint: [u8; 32],
        query_server_static_pub: [u8; 32],
        eph_seed_query: [u8; 32],
        hs_nonce_query: [u8; 32],
    ) -> PirResult<()> {
        let raw_hint = self
            .hint_conn
            .take()
            .ok_or_else(|| PirError::Protocol("upgrade: hint server not connected".into()))?;
        let raw_query = match self.query_conn.take() {
            Some(c) => c,
            None => {
                self.hint_conn = Some(raw_hint);
                return Err(PirError::Protocol(
                    "upgrade: query server not connected".into(),
                ));
            }
        };

        let wrapped_hint = crate::channel::establish(
            raw_hint,
            hint_server_static_pub,
            eph_seed_hint,
            hs_nonce_hint,
        )
        .await?;
        let wrapped_query = crate::channel::establish(
            raw_query,
            query_server_static_pub,
            eph_seed_query,
            hs_nonce_query,
        )
        .await?;

        self.hint_conn = Some(Box::new(wrapped_hint));
        self.query_conn = Some(Box::new(wrapped_query));

        // Drop both secondary sockets on secure-channel upgrade —
        // the channel handshake is single-socket today, and parallel
        // hint downloads / round-fanout would have to re-handshake each
        // secondary too.  Leaving the hint secondary installed would let
        // later hint paths send cleartext after the primaries were secured.
        // Single-socket fallback is correct (just slower) under
        // secure-channel mode; ship parallel-pool channel as a
        // follow-up if real users hit this combination.
        if let Some(mut c) = self.hint_conn_secondary.take() {
            let _ = c.close().await;
        }
        if let Some(mut c) = self.query_conn_secondary.take() {
            let _ = c.close().await;
        }
        Ok(())
    }

    /// Register a callback that will be invoked on every
    /// [`ConnectionState`] transition (`Connecting` → `Connected` /
    /// `Disconnected`). Replaces any previously registered listener
    /// — only one listener per client; share one
    /// `Arc<dyn StateListener>` across multiple clients if you need a
    /// fan-in sink.
    ///
    /// No-op invocation if the listener is `None`; passing a fresh
    /// `None` clears the slot.
    pub fn set_state_listener(&mut self, listener: Option<Arc<dyn StateListener>>) {
        self.state_listener = listener;
    }

    /// Emit a state transition to the registered listener, if any.
    /// Kept as an inherent method so the async `connect`/`disconnect`
    /// trait impls can fire it without re-borrowing `self`.
    pub(crate) fn notify_state(&self, state: ConnectionState) {
        if let Some(listener) = &self.state_listener {
            listener.on_state_change(state);
        }
    }

    /// Install pre-built transports directly, bypassing the URL-based
    /// [`PirClient::connect`] path.
    ///
    /// This is the test-injection escape hatch the `PirTransport` trait was
    /// designed around: state-machine tests can hand in a
    /// [`MockTransport`](crate::transport::MockTransport) (or any other
    /// impl) and drive the client without opening real WebSockets.
    /// `PirClient::is_connected` returns `true` after this call.
    ///
    /// Fires the same `Connected` state event a URL-driven `connect()`
    /// would — lets injection-driven tests exercise the state listener
    /// without a real WebSocket handshake.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony"))]
    pub fn connect_with_transport(
        &mut self,
        hint_conn: Box<dyn PirTransport>,
        query_conn: Box<dyn PirTransport>,
    ) {
        // An injected pair may replace a live pooled session.  Drop every
        // old primary/secondary slot and every session-bound trust/hint value
        // before making the new pair observable as connected.
        self.hint_conn = None;
        self.hint_conn_secondary = None;
        self.query_conn = None;
        self.query_conn_secondary = None;
        self.invalidate_session_bindings();
        self.hint_conn = Some(hint_conn);
        self.query_conn = Some(query_conn);
        // Propagate any installed recorder to the injected transports so
        // state-machine tests see per-frame byte counts just like the
        // URL-driven `connect()` path does. Both transports are
        // labelled `"harmony"`.
        if let Some(rec) = self.metrics_recorder.clone() {
            if let Some(ref mut c) = self.hint_conn {
                c.set_metrics_recorder(Some(rec.clone()), "harmony");
            }
            if let Some(ref mut c) = self.query_conn {
                c.set_metrics_recorder(Some(rec), "harmony");
            }
        }
        self.fire_connect(&self.hint_server_url);
        self.fire_connect(&self.query_server_url);
        self.notify_state(ConnectionState::Connected);
    }

    /// Override the master PRP key (16 bytes).
    pub fn set_master_key(&mut self, key: [u8; 16]) {
        self.master_prp_key = key;
        self.invalidate_groups();
    }

    /// Return the effective master PRP key for browser hint persistence.
    ///
    /// Under the V2 hint protocol the server assigns a fresh key during
    /// hint setup, replacing the key installed by `set_master_key`. Cache
    /// adapters must persist this effective value alongside `save_hints_bytes`
    /// so a later client can restore the blob without a fingerprint mismatch.
    pub fn cache_master_key(&self) -> [u8; 16] {
        self.master_prp_key
    }

    /// Return the effective PRP backend selected by V2 hint setup.
    pub fn cache_prp_backend(&self) -> u8 {
        self.prp_backend
    }

    /// Set the PRP backend (`PRP_HMR12` or `PRP_FASTPRP`).
    pub fn set_prp_backend(&mut self, backend: u8) {
        if backend != self.prp_backend {
            self.prp_backend = backend;
            self.invalidate_groups();
        }
    }

    /// Enable or disable V2 hint protocol (server-generated PRP key).
    ///
    /// Default: `true` for new clients. Set to `false` to fall back to V1
    /// (client sends PRP key in hint request — needed for older servers).
    pub fn set_use_v2_protocol(&mut self, v2: bool) {
        if v2 != self.use_v2_protocol {
            self.use_v2_protocol = v2;
            self.invalidate_groups();
        }
    }

    pub(crate) fn invalidate_groups(&mut self) {
        self.index_groups.clear();
        self.chunk_groups.clear();
        self.index_sib_groups.clear();
        self.chunk_sib_groups.clear();
        self.loaded_db_id = None;
        self.sibling_hints_loaded = None;
    }
}

impl HarmonyClient {
    // ─── Session 5 DB-switch + hint stats API ──────────────────────────────

    /// Get the db_id the currently loaded hint state corresponds to,
    /// or `None` if no hints are loaded.
    ///
    /// Mirrors `loaded_db_id` — after a
    /// [`set_db_id`](Self::set_db_id) to a different id, a subsequent
    /// `ensure_groups_ready` has to refetch hints (or restore from
    /// cache) before this matches again.
    pub fn db_id(&self) -> Option<u8> {
        self.loaded_db_id
    }

    /// Pre-fetch the main hint state for `db_info`, firing `progress`
    /// after each per-group response is processed.
    ///
    /// On a fresh fetch the callback is invoked exactly
    /// `db_info.index_k + db_info.chunk_k` times (typically 75 + 80 =
    /// 155), with `(done, total, phase)` reflecting cumulative progress.
    /// On a cache hit (or if hints for `db_info.db_id` are already
    /// loaded in memory) the callback fires once with
    /// `(total, total, "chunk")` so a UI driving its progress bar off
    /// this signal flips to "done" rather than silently sitting at 0%.
    ///
    /// This is a public entry point used by the WASM bridge to expose
    /// per-group progress to JS without forcing callers to issue a
    /// dummy query just to warm the hint state. After a successful
    /// call, [`db_id`](Self::db_id) returns `Some(db_info.db_id)` and
    /// subsequent queries skip the hint-fetch roundtrips.
    ///
    /// 🔒 Padding invariants are preserved — the wire shape is
    /// identical to the no-progress hint-fetch path; the callback is
    /// purely observational.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", db_id = db_info.db_id))]
    pub async fn fetch_hints_with_progress(
        &mut self,
        db_info: &DatabaseInfo,
        progress: &dyn HintProgress,
    ) -> PirResult<()> {
        if self.hint_conn.is_none() {
            return Err(PirError::NotConnected);
        }
        self.ensure_groups_ready(db_info, Some(progress)).await
    }

    /// [`fetch_hints_with_progress`](Self::fetch_hints_with_progress) plus
    /// the Merkle-sibling hint groups, so the whole set can be cached and no
    /// later query has to download hints.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", db_id = db_info.db_id))]
    pub async fn fetch_complete_hints_with_progress(
        &mut self,
        db_info: &DatabaseInfo,
        progress: &dyn HintProgress,
    ) -> PirResult<()> {
        if self.hint_conn.is_none() {
            return Err(PirError::NotConnected);
        }
        self.ensure_groups_ready(db_info, Some(progress)).await?;
        if db_info.has_bucket_merkle {
            let tree_tops = self.tree_tops_for(db_info).await?;
            self.ensure_sibling_groups_ready(db_info, &tree_tops)
                .await?;
        }
        Ok(())
    }

    /// Whether hints for `db_info` are loaded.
    pub fn has_hints_for(&self, db_info: &DatabaseInfo) -> bool {
        self.loaded_db_id == Some(db_info.db_id)
    }

    /// Invalidate any loaded hint state and pin subsequent queries to
    /// `db_id`. No network traffic yet; the next
    /// [`execute_step`](Self::execute_step) /
    /// [`query_batch`](Self::query_batch) /
    /// [`query_batch_with_inspector`](Self::query_batch_with_inspector)
    /// will see the db mismatch and refetch (or restore from the hint cache
    /// if configured).
    ///
    /// Use this when an app pins a wallet to a specific db_id ahead of
    /// time — e.g. a browser session that just fetched a fresh
    /// catalog and wants to preload hints for db_id=0 before the user
    /// initiates a query.
    ///
    /// Passing the *same* `db_id` that's already loaded is a no-op;
    /// switching to any other id clears all in-memory hint state.
    /// This intentionally drops cached sibling groups too — a
    /// different db has different tree tops, so stale siblings would
    /// fail verification on their next use.
    pub fn set_db_id(&mut self, db_id: u8) {
        if self.loaded_db_id == Some(db_id) {
            return;
        }
        self.invalidate_groups();
    }

    /// Minimum remaining per-group query budget across every loaded
    /// `HarmonyGroup` (main INDEX/CHUNK and sibling INDEX/CHUNK). If
    /// nothing is loaded, returns `None` — callers should treat that
    /// as "unknown, call `ensure_groups_ready` first".
    ///
    /// HarmonyPIR groups each carry a `max_queries` budget; once any
    /// group in the batch exhausts, the next PIR round will error out
    /// on that group. This accessor is the primitive the browser UI
    /// uses to decide "time to refresh hints" proactively.
    pub fn min_queries_remaining(&self) -> Option<u32> {
        let mut min: Option<u32> = None;
        for g in self.index_groups.values() {
            let r = g.queries_remaining();
            min = Some(match min {
                None => r,
                Some(m) => m.min(r),
            });
        }
        for g in self.chunk_groups.values() {
            let r = g.queries_remaining();
            min = Some(match min {
                None => r,
                Some(m) => m.min(r),
            });
        }
        for g in self.index_sib_groups.values() {
            let r = g.queries_remaining();
            min = Some(match min {
                None => r,
                Some(m) => m.min(r),
            });
        }
        for g in self.chunk_sib_groups.values() {
            let r = g.queries_remaining();
            min = Some(match min {
                None => r,
                Some(m) => m.min(r),
            });
        }
        min
    }

    /// Byte size of the blob [`save_hints_bytes`](Self::save_hints_bytes)
    /// would produce **right now**. Returns 0 when no state is loaded.
    ///
    /// This calls `save_hints_bytes()` internally and measures the
    /// resulting blob length. It is therefore O(total hint bytes) —
    /// fine for UI-polling-with-a-few-seconds-period cadence, but
    /// callers should not call it in the hot query path. Silently
    /// returns 0 on any internal error so UI surfaces don't have to
    /// care about transport state — this is a display-only estimate.
    pub fn estimate_hint_size_bytes(&self) -> usize {
        match self.save_hints_bytes() {
            Ok(Some(bytes)) => bytes.len(),
            _ => 0,
        }
    }

    /// 16-byte fingerprint of the on-disk / in-memory cache key for
    /// `db_info` under this client's current master key and PRP
    /// backend. Useful for JS-side cache eviction policies (e.g.
    /// IndexedDB key derivation) without recomputing the hash in TS.
    ///
    /// This is exactly the same fingerprint embedded in the
    /// [`save_hints_bytes`](Self::save_hints_bytes) blob header and
    /// used as the on-disk cache filename stem — so
    /// `fingerprint(db_info) == load_hints_bytes(save_hints_bytes()?.?,
    /// db_info)`'s expected fingerprint. The accessor is a pure
    /// function of `(master_prp_key, prp_backend, db_info)` — no
    /// network traffic, safe to call from anywhere.
    pub fn cache_fingerprint(&self, db_info: &DatabaseInfo) -> [u8; 16] {
        hint_cache::CacheKey::from_db_info(self.master_prp_key, self.prp_backend, db_info)
            .fingerprint()
    }
}
