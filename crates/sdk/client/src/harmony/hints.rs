use super::*;

impl HarmonyClient {
    /// Try to fetch the full `DatabaseCatalog` via `REQ_GET_DB_CATALOG`.
    ///
    /// Returns `Ok(Some(catalog))` on success, `Ok(None)` if the server
    /// replied with a shape the catalog decoder can't understand (e.g. a
    /// legacy hint server that doesn't implement `REQ_GET_DB_CATALOG` and
    /// echoes back some other variant byte, or a `RESP_ERROR`). A
    /// legitimate transport/I/O failure still bubbles up as `Err`.
    ///
    /// Both Harmony roles (hint + query) answer `REQ_GET_DB_CATALOG` —
    /// the match arm in `unified_server.rs` runs before any role check
    /// — so we can use whichever connection is convenient. We use
    /// `hint_conn` for consistency with `fetch_legacy_info`.
    pub(crate) async fn try_fetch_db_catalog(&mut self) -> PirResult<Option<DatabaseCatalog>> {
        let conn = self.hint_conn.as_mut().ok_or(PirError::NotConnected)?;
        let request = encode_request(REQ_GET_DB_CATALOG, &[]);
        let request_bytes = request.len() as u64;
        let response = conn.roundtrip(&request).await?;
        // `roundtrip` strips the 4-byte length prefix; add it back so the
        // recorded byte count matches what a wire-level observer sees.
        self.record_round(RoundProfile {
            kind: RoundKind::Info,
            server_id: 1,
            db_id: None,
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: Vec::new(),
        });

        if response.is_empty() {
            return Ok(None);
        }
        if decode_error_response_message(&response, "Harmony database catalog")?.is_some() {
            // Server explicitly doesn't support catalog — fall back to legacy.
            return Ok(None);
        }
        if response[0] != RESP_DB_CATALOG {
            // Any unexpected variant byte — treat as unsupported rather
            // than a hard protocol error so the legacy fallback can run.
            return Ok(None);
        }
        let catalog = decode_catalog(&response[1..])?;
        Ok(Some(catalog))
    }

    /// Fetch server info (legacy single-database path).
    ///
    /// `REQ_HARMONY_GET_INFO` predates `DatabaseCatalog` and returns a
    /// `ServerInfo` shape with no `height` or `has_bucket_merkle` fields.
    /// The catalog this synthesises therefore has `height = 0` and
    /// `has_bucket_merkle = false`, which is fine for servers that don't
    /// publish bucket Merkle roots but is strictly worse than the
    /// `REQ_GET_DB_CATALOG` path — callers that cache by height won't work
    /// against a legacy-only server.
    pub(crate) async fn fetch_legacy_info(&mut self) -> PirResult<DatabaseInfo> {
        let conn = self.hint_conn.as_mut().ok_or(PirError::NotConnected)?;

        let request = encode_request(REQ_HARMONY_GET_INFO, &[]);
        let request_bytes = request.len() as u64;
        let response = conn.roundtrip(&request).await?;
        self.record_round(RoundProfile {
            kind: RoundKind::Info,
            server_id: 1,
            db_id: None,
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: Vec::new(),
        });

        if response.is_empty() || response[0] != RESP_HARMONY_INFO {
            return Err(PirError::Protocol("invalid harmony info response".into()));
        }
        if response.len() < 19 {
            return Err(PirError::Protocol("harmony info response too short".into()));
        }

        let index_bins = u32::from_le_bytes(response[1..5].try_into().unwrap());
        let chunk_bins = u32::from_le_bytes(response[5..9].try_into().unwrap());
        let index_k = response[9];
        let chunk_k = response[10];
        let tag_seed = u64::from_le_bytes(response[11..19].try_into().unwrap());
        let (index_master_seed, chunk_master_seed, anchor_kind, anchor_bytes) =
            crate::protocol::parse_info_v2_tail(&response);

        let db_info = DatabaseInfo {
            db_id: 0,
            kind: DatabaseKind::Full,
            name: "main".into(),
            height: 0,
            index_bins,
            chunk_bins,
            index_k,
            chunk_k,
            tag_seed,
            dpf_n_index: pir_core::params::compute_dpf_n(index_bins as usize),
            dpf_n_chunk: pir_core::params::compute_dpf_n(chunk_bins as usize),
            has_bucket_merkle: false,
            index_master_seed,
            chunk_master_seed,
            anchor_kind,
            anchor_bytes,
        };
        db_info.verify_anchor_seeds().map_err(|e| {
            PirError::Protocol(format!("chain-anchor seed verification failed: {}", e))
        })?;
        Ok(db_info)
    }

    /// Ensure the per-group `HarmonyGroup` instances exist for `db_info`
    /// and their hints are loaded.
    ///
    /// Fast path: if [`with_hint_cache_dir`](Self::with_hint_cache_dir)
    /// was called and a valid cache file exists for this db_info,
    /// groups are rehydrated from disk and the server roundtrips are
    /// skipped entirely. On cache miss / cache reject, the network
    /// fetch runs as before and the result is persisted back to disk.
    /// Sibling hints are only persisted once
    /// [`ensure_sibling_groups_ready`](Self::ensure_sibling_groups_ready)
    /// has populated them (see that method for the second persist).
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", db_id = db_info.db_id))]
    pub(crate) async fn ensure_groups_ready(
        &mut self,
        db_info: &DatabaseInfo,
        progress: Option<&dyn HintProgress>,
    ) -> PirResult<()> {
        if self.loaded_db_id == Some(db_info.db_id)
            && !self.index_groups.is_empty()
            && !self.chunk_groups.is_empty()
        {
            // Fast path: hints already loaded from a prior call. Emit a
            // single terminal `total/total` tick so a UI driving its
            // progress bar off this callback flips to "done" rather than
            // silently sitting at the previous percentage.
            if let Some(p) = progress {
                let total = db_info.index_k as u32 + db_info.chunk_k as u32;
                if total > 0 {
                    p.on_group_complete(total, total, "chunk");
                }
            }
            return Ok(());
        }

        self.invalidate_groups();

        // ── Try the on-disk cache before hitting the wire ─────────────
        // Any cache error is swallowed and we fall through to network
        // fetch — the cache is a fast path, never a correctness
        // dependency. I/O errors propagate so the caller sees them.
        if self.restore_hints_from_cache(db_info)? && self.loaded_db_id == Some(db_info.db_id) {
            // Cache hit: emit one terminal tick so progress observers
            // mark the bar full even though no per-group wire roundtrips
            // happened.
            if let Some(p) = progress {
                let total = db_info.index_k as u32 + db_info.chunk_k as u32;
                if total > 0 {
                    p.on_group_complete(total, total, "chunk");
                }
            }
            return Ok(());
        }

        // Dispatch matrix for main hint fetch (cold cache only — the
        // warm-cache fast path returned above):
        //
        //   db_id != 0, legacy mode: → V1 (default V2 pool is bound to db0)
        //   pool=2 AND v2:           → V2-half (parallel; this commit)
        //   pool=2 AND v1-opt-in:    → V1 parallel (slow; bench/fallback only)
        //   pool=1 AND v2:           → V2 full single-stream
        //   pool=1 AND !v2:          → V1 single-stream serial
        //
        // V2 (full or half) uses the server's pre-computed hint pool —
        // zero server CPU per request, just stream bytes. V1 triggers
        // on-the-fly `compute_hints_for_group` server-side (several
        // seconds of CPU even on the pool-less path), so it's never
        // the default for cold-cache fetch.
        //
        // V2-half is preferred over V2 full when a secondary hint
        // socket is available because it splits the ~20 MB stream
        // across two TCP connections — each connection gets its own
        // bandwidth-delay-product budget, halving wall time on far
        // (high-RTT) clients. A malformed or interrupted V2 response is
        // fail-closed. The server's exact preamble-level pool-empty response
        // is permission to retry through V1.
        let use_v2_for_db = should_use_v2_hint_pool(self.use_v2_protocol, db_info.db_id);
        let want_v1_parallel =
            matches!(std::env::var("HARMONY_USE_V1_PARALLEL").as_deref(), Ok("1"));
        if (want_v1_parallel || !use_v2_for_db) && self.hint_conn_secondary.is_some() {
            return self
                .ensure_groups_ready_v1_parallel(db_info, progress)
                .await;
        }
        if use_v2_for_db && self.hint_conn_secondary.is_some() {
            match self.ensure_groups_ready_v2_half(db_info, progress).await {
                Ok(V2HintFetchOutcome::Loaded) => return Ok(()),
                Ok(V2HintFetchOutcome::PoolUnavailable) => {
                    log::warn!(
                        "[PIR-AUDIT] V2 hint pool temporarily unavailable; falling back to V1"
                    );
                    return self
                        .ensure_groups_ready_v1_parallel(db_info, progress)
                        .await;
                }
                Err(e) => return Err(e),
            }
        }
        if use_v2_for_db {
            match self.ensure_groups_ready_v2(db_info, progress).await? {
                V2HintFetchOutcome::Loaded => return Ok(()),
                V2HintFetchOutcome::PoolUnavailable => {
                    log::warn!(
                        "[PIR-AUDIT] V2 hint pool temporarily unavailable; falling back to V1"
                    );
                }
            }
        }
        if self.hint_conn_secondary.is_some() {
            return self
                .ensure_groups_ready_v1_parallel(db_info, progress)
                .await;
        }

        let k_index = db_info.index_k as usize;
        let k_chunk = db_info.chunk_k as usize;

        let index_w = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE;
        let chunk_w = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE;

        for g in 0..k_index {
            let group = new_harmony_group(
                db_info.index_bins,
                index_w as u32,
                0, // T=0 means "pick balanced T"
                &self.master_prp_key,
                g as u32,
                self.prp_backend,
            )
            .map_err(|e| PirError::BackendState(format!("HarmonyGroup init: {:?}", e)))?;
            self.index_groups.insert(g as u8, group);
        }

        for g in 0..k_chunk {
            let group = new_harmony_group(
                db_info.chunk_bins,
                chunk_w as u32,
                0,
                &self.master_prp_key,
                (k_index + g) as u32,
                self.prp_backend,
            )
            .map_err(|e| PirError::BackendState(format!("HarmonyGroup init: {:?}", e)))?;
            self.chunk_groups.insert(g as u8, group);
        }

        let total = (k_index + k_chunk) as u32;
        let mut done: u32 = 0;
        {
            let mut on_index = |_gid: u8| {
                done += 1;
                if let Some(p) = progress {
                    p.on_group_complete(done, total, "index");
                }
            };
            self.fetch_and_load_hints_with_callback(db_info.db_id, 0, k_index as u8, &mut on_index)
                .await?;
        }
        {
            let mut on_chunk = |_gid: u8| {
                done += 1;
                if let Some(p) = progress {
                    p.on_group_complete(done, total, "chunk");
                }
            };
            self.fetch_and_load_hints_with_callback(db_info.db_id, 1, k_chunk as u8, &mut on_chunk)
                .await?;
        }

        self.loaded_db_id = Some(db_info.db_id);

        // Persist the freshly-fetched main hints so a warm restart
        // gets the fast path. Sibling state isn't loaded yet; it will
        // be persisted again by `ensure_sibling_groups_ready` once the
        // tree-tops RPC returns. Persist errors are logged and
        // ignored so a read-only cache dir doesn't wedge queries.
        if let Err(e) = self.persist_hints_to_cache(db_info) {
            log::warn!(
                "[PIR-AUDIT] HarmonyPIR: failed to persist main hints to cache: {}",
                e
            );
        }
        Ok(())
    }

    /// V2 hint fetch: single round-trip for both INDEX and CHUNK levels.
    ///
    /// Sends `REQ_HARMONY_HINTS_V2`, receives the key preamble (server-
    /// generated PRP key + backend), creates HarmonyGroup instances, then
    /// receives all per-group frames from the pool.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", v2 = true, db_id = db_info.db_id))]
    pub(crate) async fn ensure_groups_ready_v2(
        &mut self,
        db_info: &DatabaseInfo,
        progress: Option<&dyn HintProgress>,
    ) -> PirResult<V2HintFetchOutcome> {
        let k_index = db_info.index_k as usize;
        let k_chunk = db_info.chunk_k as usize;
        let total = (k_index + k_chunk) as u32;
        let db_id = db_info.db_id;
        let expected_total_groups = u8::try_from(k_index + k_chunk).map_err(|_| {
            PirError::Protocol(format!(
                "V2 hint group count {} exceeds wire limit",
                k_index + k_chunk
            ))
        })?;
        let mut conn = self.hint_conn.take().ok_or(PirError::NotConnected)?;

        let result = async {

        // ── 1. Send V2 request ──────────────────────────────────────────
        let mut payload = Vec::with_capacity(4);
        payload.push(0xFFu8); // level_sentinel: all levels
        payload.push(0x00u8); // reserved
        if db_id != 0 {
            payload.push(db_id);
        }
        // Trailing db_id byte
        let request = crate::protocol::encode_request(REQ_HARMONY_HINTS_V2, &payload);
        let request_bytes = request.len() as u64;

        conn.send(request).await?;

        // ── 2. Receive key preamble ─────────────────────────────────────
        let preamble = conn.recv().await?;
        let (prp_backend, prp_key) = match parse_v2_key_preamble(
            &preamble,
            expected_total_groups,
            "V2 full",
        )? {
            V2KeyPreambleOutcome::Key {
                prp_backend,
                prp_key,
            } => (prp_backend, prp_key),
            V2KeyPreambleOutcome::PoolUnavailable => {
                return Ok(V2HintFetchOutcome::PoolUnavailable);
            }
        };

        self.prp_backend = prp_backend;
        self.master_prp_key = prp_key;

        // ── 3. Create HarmonyGroup instances with the server-assigned key ──
        let index_w = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE;
        let chunk_w = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE;

        for g in 0..k_index {
            let group = new_harmony_group(
                db_info.index_bins,
                index_w as u32,
                0,
                &self.master_prp_key,
                g as u32,
                self.prp_backend,
            )
            .map_err(|e| PirError::BackendState(format!("HarmonyGroup init: {:?}", e)))?;
            self.index_groups.insert(g as u8, group);
        }

        for g in 0..k_chunk {
            let group = new_harmony_group(
                db_info.chunk_bins,
                chunk_w as u32,
                0,
                &self.master_prp_key,
                (k_index + g) as u32,
                self.prp_backend,
            )
            .map_err(|e| PirError::BackendState(format!("HarmonyGroup init: {:?}", e)))?;
            self.chunk_groups.insert(g as u8, group);
        }

        // ── 4. Receive per-group INDEX frames ───────────────────────────
        let mut done: u32 = 0;
        let mut total_response_bytes: u64 = 0;
        let mut seen_index = vec![false; k_index];
        for _g in 0..k_index {
            let msg = conn.recv().await?;
            total_response_bytes = total_response_bytes.saturating_add(msg.len() as u64);
            let body = v2_record_body(&msg, "V2 full INDEX hint")?;
            if body.is_empty() {
                return Err(PirError::Protocol("empty V2 hint frame body".into()));
            }
            reject_error_response(body, "V2 full INDEX hint")?;
            if body[0] != RESP_HARMONY_HINTS {
                return Err(PirError::Protocol(format!(
                    "expected RESP_HARMONY_HINTS, got 0x{:02x}",
                    body[0]
                )));
            }
            if body.len() < 14 {
                return Err(PirError::Protocol("V2 hint frame header truncated".into()));
            }
            let group_id = body[1];
            let hints_data = &body[14..];

            let seen = seen_index.get_mut(group_id as usize).ok_or_else(|| {
                PirError::Protocol(format!("V2: unexpected INDEX group {}", group_id))
            })?;
            if *seen {
                return Err(PirError::Protocol(format!(
                    "V2: duplicate INDEX group {}",
                    group_id
                )));
            }
            *seen = true;

            let group = self.index_groups.get_mut(&group_id).ok_or_else(|| {
                PirError::Protocol(format!("V2: unexpected INDEX group {}", group_id))
            })?;
            group
                .load_hints(hints_data)
                .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;

            done += 1;
            if let Some(p) = progress {
                p.on_group_complete(done, total, "index");
            }
        }

        // ── 5. Receive per-group CHUNK frames ───────────────────────────
        let mut seen_chunk = vec![false; k_chunk];
        for _g in 0..k_chunk {
            let msg = conn.recv().await?;
            total_response_bytes = total_response_bytes.saturating_add(msg.len() as u64);
            let body = v2_record_body(&msg, "V2 full CHUNK hint")?;
            if body.is_empty() {
                return Err(PirError::Protocol("empty V2 hint frame body".into()));
            }
            reject_error_response(body, "V2 full CHUNK hint")?;
            if body[0] != RESP_HARMONY_HINTS {
                return Err(PirError::Protocol(format!(
                    "expected RESP_HARMONY_HINTS, got 0x{:02x}",
                    body[0]
                )));
            }
            if body.len() < 14 {
                return Err(PirError::Protocol("V2 hint frame header truncated".into()));
            }
            let group_id = body[1];
            let hints_data = &body[14..];

            let seen = seen_chunk.get_mut(group_id as usize).ok_or_else(|| {
                PirError::Protocol(format!("V2: unexpected CHUNK group {}", group_id))
            })?;
            if *seen {
                return Err(PirError::Protocol(format!(
                    "V2: duplicate CHUNK group {}",
                    group_id
                )));
            }
            *seen = true;

            // CHUNK groups are stored under the local offset (0..79),
            // matching the wire group_id byte.
            let group = self.chunk_groups.get_mut(&group_id).ok_or_else(|| {
                PirError::Protocol(format!("V2: unexpected CHUNK group {}", group_id))
            })?;
            group
                .load_hints(hints_data)
                .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;

            done += 1;
            if let Some(p) = progress {
                p.on_group_complete(done, total, "chunk");
            }
        }

        // ── 6. Receive terminal sentinel ────────────────────────────────
        let terminal = conn.recv().await?;
        validate_v2_terminal(&terminal, "V2 full")?;

        self.loaded_db_id = Some(db_info.db_id);

        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   V2 main hint stream: req {}B  resp_total {}B  (k_index={}, k_chunk={})",
                request_bytes, total_response_bytes, k_index, k_chunk,
            );
        }

        // Record the round.
        self.record_round(RoundProfile {
            kind: RoundKind::HarmonyHintRefresh,
            server_id: 1,
            db_id: Some(db_id),
            request_bytes,
            response_bytes: total_response_bytes,
            items: vec![1u32; total as usize],
        });

        // Persist to cache.
        if let Err(e) = self.persist_hints_to_cache(db_info) {
            log::warn!(
                "[PIR-AUDIT] HarmonyPIR V2: failed to persist main hints to cache: {}",
                e
            );
        }

        Ok(V2HintFetchOutcome::Loaded)
        }
        .await;

        match result {
            Ok(outcome) => {
                self.hint_conn = Some(conn);
                Ok(outcome)
            }
            Err(error) => {
                // A failed stream can leave unread coalesced records queued.
                // Closing is the only safe way to re-establish a request
                // boundary; the caller must reconnect before retrying.
                let _ = conn.close().await;
                self.index_groups.clear();
                self.chunk_groups.clear();
                self.loaded_db_id = None;
                Err(error)
            }
        }
    }

    /// V2 half-stream parallel main hint fetch.
    ///
    /// Splits the V2 main hint response across two TCP/WebSocket sockets:
    /// INDEX-half (side=0) goes to the primary hint socket, CHUNK-half
    /// (side=1) to the secondary. Both halves share a 16-byte session
    /// token that the server uses to match them to the same pool entry,
    /// so both halves carry the same PRP key in their preambles.
    ///
    /// The wire shape on each socket is identical to the corresponding
    /// portion of a full V2 response (key preamble + per-group frames +
    /// sentinel), so the per-half receive loop reuses the same parsing
    /// code as `ensure_groups_ready_v2`. Only the dispatch
    /// (parallel send + matched-key check after) differs.
    ///
    /// Wire, protocol, and unknown server errors are fail-closed. Only
    /// matching, complete pool-unavailable preambles on both sockets return
    /// `PoolUnavailable`, which permits the caller to retry through V1.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", v2_half = true, db_id = db_info.db_id))]
    pub(crate) async fn ensure_groups_ready_v2_half(
        &mut self,
        db_info: &DatabaseInfo,
        progress: Option<&dyn HintProgress>,
    ) -> PirResult<V2HintFetchOutcome> {
        #[cfg(target_arch = "wasm32")]
        async fn browser_delay(duration: std::time::Duration) -> PirResult<()> {
            use wasm_bindgen::{JsCast, JsValue};

            // Keep only the Send-capable oneshot receiver across `.await`.
            // Browser JS values and the callback are installed synchronously;
            // `once_into_js` releases the Rust closure after setTimeout invokes
            // it.  This preserves the async-trait Send bound on wasm32, where
            // JsFuture itself is !Send.
            let receiver = {
                let (sender, receiver) = futures_channel::oneshot::channel();
                let callback = wasm_bindgen::closure::Closure::once_into_js(move || {
                    let _ = sender.send(());
                });
                let global = js_sys::global();
                let timer = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
                    .map_err(|e| PirError::BackendState(format!("read setTimeout: {e:?}")))?
                    .dyn_into::<js_sys::Function>()
                    .map_err(|_| PirError::BackendState("setTimeout is not a function".into()))?;
                let delay_ms = i32::try_from(duration.as_millis())
                    .map_err(|_| PirError::BackendState("V2-half timeout is too large".into()))?;
                timer
                    .call2(&global, &callback, &JsValue::from(delay_ms))
                    .map_err(|e| PirError::BackendState(format!("setTimeout failed: {e:?}")))?;
                receiver
            };
            receiver
                .await
                .map_err(|_| PirError::BackendState("setTimeout callback dropped".into()))?;
            Ok(())
        }

        let k_index = db_info.index_k as usize;
        let k_chunk = db_info.chunk_k as usize;
        let total = (k_index + k_chunk) as u32;
        let db_id = db_info.db_id;
        let expected_total_groups = u8::try_from(k_index + k_chunk).map_err(|_| {
            PirError::Protocol(format!(
                "V2-half hint group count {} exceeds wire limit",
                k_index + k_chunk
            ))
        })?;

        // Generate a 16-byte random session token. Both halves carry
        // the same token; server matches them to the same pool entry.
        let mut session_token = [0u8; 16];
        getrandom::getrandom(&mut session_token)
            .map_err(|e| PirError::Protocol(format!("session_token getrandom: {}", e)))?;

        // Build the two half requests up front.
        let make_request = |side: u8| -> Vec<u8> {
            let mut payload = Vec::with_capacity(16 + 1 + 1);
            payload.extend_from_slice(&session_token);
            payload.push(side);
            if db_id != 0 {
                payload.push(db_id);
            }
            crate::protocol::encode_request(REQ_HARMONY_HINTS_V2_HALF, &payload)
        };
        let request_index = make_request(0);
        let request_chunk = make_request(1);
        let request_index_bytes = request_index.len() as u64;
        let request_chunk_bytes = request_chunk.len() as u64;

        // Take both hint sockets out of `self` so the parallel futures
        // can each hold one mutably. Restored after the join.
        let mut hint_primary = self.hint_conn.take().ok_or(PirError::NotConnected)?;
        let mut hint_secondary = self
            .hint_conn_secondary
            .take()
            .expect("only called when hint_conn_secondary is_some");

        let index_w = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE;
        let chunk_w = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE;

        // Per-half receive+build+load loop.
        //
        // The receive logic is identical to the V2-full path
        // (preamble → K frames → sentinel) but as soon as the preamble
        // arrives — i.e. as soon as the key is known — the loop builds
        // all this half's `HarmonyGroup` instances and then loads
        // hints into them per-frame as they stream in. This INTERLEAVES
        // the per-group PRP setup (~10–20 ms × K, single-thread CPU)
        // with the network wait time, instead of stacking them serial
        // after the join. Matches V2-full's wire-vs-CPU interleaving.
        //
        // Returns `(prp_backend, prp_key, built_groups, total_bytes)`.
        // The shared-key check on the call site runs against the
        // returned `prp_key`s; the built groups are then moved into
        // `self.{index,chunk}_groups`.
        type HalfData = (u8, [u8; 16], HashMap<u8, HarmonyGroup>, u64);
        enum HalfDrainOutcome {
            Loaded(HalfData),
            PoolUnavailable,
        }

        #[allow(clippy::too_many_arguments)]
        async fn drain_half_build(
            conn: &mut Box<dyn PirTransport>,
            num_groups: u8,
            expected_total_groups: u8,
            label: &str,
            // Group construction params (same for every group at this
            // level — only the per-group offset varies).
            bins: u32,
            slot_size: u32,
            base_offset: usize, // 0 for INDEX, k_index for CHUNK
        ) -> PirResult<HalfDrainOutcome> {
            // 1. Receive key preamble.
            let preamble = conn.recv().await?;
            let mut total_resp: u64 = preamble.len() as u64;
            let (prp_backend, prp_key) =
                match parse_v2_key_preamble(&preamble, expected_total_groups, label)? {
                    V2KeyPreambleOutcome::Key {
                        prp_backend,
                        prp_key,
                    } => (prp_backend, prp_key),
                    V2KeyPreambleOutcome::PoolUnavailable => {
                        return Ok(HalfDrainOutcome::PoolUnavailable);
                    }
                };

            // 2. Build all `num_groups` HarmonyGroup instances using
            //    the just-received key. This is the CPU-heavy part —
            //    overlapped with the upcoming `recv()` waits.
            let mut groups: HashMap<u8, HarmonyGroup> = HashMap::with_capacity(num_groups as usize);
            for g in 0..num_groups {
                let group = new_harmony_group(
                    bins,
                    slot_size,
                    0,
                    &prp_key,
                    (base_offset + g as usize) as u32,
                    prp_backend,
                )
                .map_err(|e| {
                    PirError::BackendState(format!("{}: HarmonyGroup init: {:?}", label, e))
                })?;
                groups.insert(g, group);
            }

            // 3. Receive N per-group frames and load hints in-place.
            let mut seen = vec![false; num_groups as usize];
            for _ in 0..num_groups {
                let msg = conn.recv().await?;
                total_resp = total_resp.saturating_add(msg.len() as u64);
                let body = v2_record_body(&msg, label)?;
                if body.is_empty() {
                    return Err(PirError::Protocol(format!(
                        "{}: empty V2-half hint frame body",
                        label
                    )));
                }
                reject_error_response(body, label)?;
                if body[0] != RESP_HARMONY_HINTS {
                    return Err(PirError::Protocol(format!(
                        "{}: expected RESP_HARMONY_HINTS, got 0x{:02x}",
                        label, body[0]
                    )));
                }
                if body.len() < 14 {
                    return Err(PirError::Protocol(format!(
                        "{}: V2-half hint frame header truncated",
                        label
                    )));
                }
                let group_id = body[1];
                // bytes 2..14 = (n, t, m) metadata — unused
                let hints_data = &body[14..];
                let was_seen = seen.get_mut(group_id as usize).ok_or_else(|| {
                    PirError::Protocol(format!("{}: unexpected group {}", label, group_id))
                })?;
                if *was_seen {
                    return Err(PirError::Protocol(format!(
                        "{}: duplicate group {}",
                        label, group_id
                    )));
                }
                *was_seen = true;
                let group = groups.get_mut(&group_id).ok_or_else(|| {
                    PirError::Protocol(format!("{}: unexpected group {}", label, group_id))
                })?;
                group
                    .load_hints(hints_data)
                    .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;
            }

            // 4. Receive terminal sentinel.
            let terminal = conn.recv().await?;
            validate_v2_terminal(&terminal, label)?;

            Ok(HalfDrainOutcome::Loaded((
                prp_backend,
                prp_key,
                groups,
                total_resp,
            )))
        }

        let t_half_start = Instant::now();

        let index_fut = async {
            hint_primary.send(request_index).await?;
            drain_half_build(
                &mut hint_primary,
                k_index as u8,
                expected_total_groups,
                "V2-half INDEX",
                db_info.index_bins,
                index_w as u32,
                0, // base_offset for INDEX groups
            )
            .await
        };
        let chunk_fut = async {
            hint_secondary.send(request_chunk).await?;
            drain_half_build(
                &mut hint_secondary,
                k_chunk as u8,
                expected_total_groups,
                "V2-half CHUNK",
                db_info.chunk_bins,
                chunk_w as u32,
                k_index, // base_offset for CHUNK groups
            )
            .await
        };

        #[cfg(not(target_arch = "wasm32"))]
        let join_result = {
            let joined = async { tokio::try_join!(index_fut, chunk_fut) };
            match tokio::time::timeout(V2_HALF_FETCH_TIMEOUT, joined).await {
                Ok(result) => result,
                Err(_) => Err(PirError::Timeout(format!(
                    "V2-half hint fetch exceeded {:?}",
                    V2_HALF_FETCH_TIMEOUT
                ))),
            }
        };
        #[cfg(target_arch = "wasm32")]
        let join_result = {
            use futures::future::{select, Either};

            let joined = Box::pin(futures::future::try_join(index_fut, chunk_fut));
            let deadline = Box::pin(async {
                browser_delay(V2_HALF_FETCH_TIMEOUT).await?;
                Err(PirError::Timeout(format!(
                    "V2-half hint fetch exceeded {:?}",
                    V2_HALF_FETCH_TIMEOUT
                )))
            });
            match select(joined, deadline).await {
                Either::Left((result, _)) | Either::Right((result, _)) => result,
            }
        };

        // An arbitrary error can leave unread coalesced hint records in either
        // transport (or leave the transport itself dead).  Reusing such a
        // socket would let a later request consume an old hint record as its
        // key preamble.  Short-circuit the peer future, close both sockets,
        // and force a reconnect instead.  The exact pool-empty response is an
        // `Ok(PoolUnavailable)` outcome, so both halves are still observed
        // before the deliberate V1 fallback below.
        let (idx_out, chk_out) = match join_result {
            Ok(outcomes) => outcomes,
            Err(error) => {
                let _ = hint_primary.close().await;
                let _ = hint_secondary.close().await;
                return Err(error);
            }
        };

        let (idx_data, chk_data) = match (idx_out, chk_out) {
            (HalfDrainOutcome::Loaded(index), HalfDrainOutcome::Loaded(chunk)) => (index, chunk),
            (HalfDrainOutcome::PoolUnavailable, HalfDrainOutcome::PoolUnavailable) => {
                // Both error envelopes were consumed completely, so these
                // sockets are at a clean request boundary for V1.
                self.hint_conn = Some(hint_primary);
                self.hint_conn_secondary = Some(hint_secondary);
                return Ok(V2HintFetchOutcome::PoolUnavailable);
            }
            _ => {
                let _ = hint_primary.close().await;
                let _ = hint_secondary.close().await;
                return Err(PirError::Protocol(
                    "V2-half INDEX and CHUNK pool availability responses disagree".into(),
                ));
            }
        };
        let (idx_backend, idx_key, idx_groups, idx_bytes) = idx_data;
        let (chk_backend, chk_key, chk_groups, chk_bytes) = chk_data;

        // Both halves must agree on the PRP key + backend; if they
        // don't, the server mis-paired the session — bail.
        if idx_key != chk_key {
            let _ = hint_primary.close().await;
            let _ = hint_secondary.close().await;
            return Err(PirError::Protocol(format!(
                "V2-half: INDEX and CHUNK PRP keys mismatch (INDEX={:02x?}..., CHUNK={:02x?}...)",
                &idx_key[..4],
                &chk_key[..4],
            )));
        }
        if idx_backend != chk_backend {
            let _ = hint_primary.close().await;
            let _ = hint_secondary.close().await;
            return Err(PirError::Protocol(format!(
                "V2-half: INDEX and CHUNK PRP backends mismatch ({} vs {})",
                idx_backend, chk_backend
            )));
        }

        // Both streams and their terminal sentinels were consumed, and their
        // session key/backend binding agrees.  Only now are the sockets safe
        // to return to the client state.
        self.hint_conn = Some(hint_primary);
        self.hint_conn_secondary = Some(hint_secondary);

        let dt_wire = t_half_start.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   V2-half parallel hint+build: total {:?} (req {}B+{}B, resp {}B+{}B, k_index={}, k_chunk={})",
                dt_wire,
                request_index_bytes, request_chunk_bytes,
                idx_bytes, chk_bytes,
                k_index, k_chunk,
            );
        }

        self.prp_backend = idx_backend;
        self.master_prp_key = idx_key;

        // Move the already-built + hint-loaded groups into self.
        self.index_groups = idx_groups;
        self.chunk_groups = chk_groups;

        // Surface a single terminal progress tick — per-group ticks
        // are buried inside the parallel build loops and the API
        // doesn't currently thread a callback through `drain_half_build`.
        if let Some(p) = progress {
            if total > 0 {
                p.on_group_complete(total, total, "chunk");
            }
        }

        self.loaded_db_id = Some(db_info.db_id);

        // Record both wire rounds.
        self.record_round(RoundProfile {
            kind: RoundKind::HarmonyHintRefresh,
            server_id: 1,
            db_id: Some(db_id),
            request_bytes: request_index_bytes,
            response_bytes: idx_bytes,
            items: vec![1u32; k_index],
        });
        self.record_round(RoundProfile {
            kind: RoundKind::HarmonyHintRefresh,
            server_id: 1,
            db_id: Some(db_id),
            request_bytes: request_chunk_bytes,
            response_bytes: chk_bytes,
            items: vec![1u32; k_chunk],
        });

        // Persist to cache.
        if let Err(e) = self.persist_hints_to_cache(db_info) {
            log::warn!(
                "[PIR-AUDIT] HarmonyPIR V2-half: failed to persist main hints to cache: {}",
                e
            );
        }
        Ok(V2HintFetchOutcome::Loaded)
    }

    /// V1-protocol parallel main hint fetch.
    ///
    /// Sends `REQ_HARMONY_HINTS` at level=0 (INDEX) on the primary
    /// hint socket and level=1 (CHUNK) on the secondary, awaited
    /// concurrently via `tokio::try_join!`. Each level's response is
    /// a stream of K independent hint frames; the two streams transfer
    /// in parallel on disjoint TCP connections, each getting its own
    /// bandwidth-delay-product budget.
    ///
    /// Functional contract identical to [`ensure_groups_ready_v2`]:
    /// `self.index_groups` and `self.chunk_groups` are populated with
    /// hint-loaded `HarmonyGroup` instances, `loaded_db_id` is set,
    /// and (on success) the combined state is persisted to cache.
    ///
    /// The client uses its own `master_prp_key` (set at `new()` time)
    /// rather than a server-generated key — see the dispatch comment
    /// in `ensure_groups_ready` for the threat-model rationale.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", v1_parallel = true, db_id = db_info.db_id))]
    pub(crate) async fn ensure_groups_ready_v1_parallel(
        &mut self,
        db_info: &DatabaseInfo,
        progress: Option<&dyn HintProgress>,
    ) -> PirResult<()> {
        let k_index = db_info.index_k as usize;
        let k_chunk = db_info.chunk_k as usize;

        let index_w = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE;
        let chunk_w = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE;

        // Build groups (CPU work; serial within each tree). The two
        // trees could be built in parallel via rayon on native but the
        // gain is small relative to the hint-download wall time, and
        // wasm32 is single-threaded anyway. Keep serial.
        for g in 0..k_index {
            let group = new_harmony_group(
                db_info.index_bins,
                index_w as u32,
                0,
                &self.master_prp_key,
                g as u32,
                self.prp_backend,
            )
            .map_err(|e| PirError::BackendState(format!("HarmonyGroup init: {:?}", e)))?;
            self.index_groups.insert(g as u8, group);
        }
        for g in 0..k_chunk {
            let group = new_harmony_group(
                db_info.chunk_bins,
                chunk_w as u32,
                0,
                &self.master_prp_key,
                (k_index + g) as u32,
                self.prp_backend,
            )
            .map_err(|e| PirError::BackendState(format!("HarmonyGroup init: {:?}", e)))?;
            self.chunk_groups.insert(g as u8, group);
        }

        // Move state into the two parallel futures so each holds
        // disjoint mutable borrows. Restored after the join.
        let mut index_groups = std::mem::take(&mut self.index_groups);
        let mut chunk_groups = std::mem::take(&mut self.chunk_groups);
        let mut hint_primary = self.hint_conn.take().ok_or(PirError::NotConnected)?;
        let mut hint_secondary = self
            .hint_conn_secondary
            .take()
            .expect("only called when hint_conn_secondary is_some");
        let master_prp_key = self.master_prp_key;
        let prp_backend = self.prp_backend;
        let db_id = db_info.db_id;

        let t_main_start = Instant::now();

        let index_fut = async {
            let profile = fetch_and_load_main_hints_into_map(
                hint_primary.as_mut(),
                &mut index_groups,
                db_id,
                0, // wire_level = 0 → INDEX main
                k_index as u8,
                &master_prp_key,
                prp_backend,
            )
            .await?;
            Ok::<_, PirError>((hint_primary, index_groups, profile))
        };

        let chunk_fut = async {
            let profile = fetch_and_load_main_hints_into_map(
                hint_secondary.as_mut(),
                &mut chunk_groups,
                db_id,
                1, // wire_level = 1 → CHUNK main
                k_chunk as u8,
                &master_prp_key,
                prp_backend,
            )
            .await?;
            Ok::<_, PirError>((hint_secondary, chunk_groups, profile))
        };

        #[cfg(not(target_arch = "wasm32"))]
        let (idx_out, chk_out) = tokio::try_join!(index_fut, chunk_fut)?;
        #[cfg(target_arch = "wasm32")]
        let (idx_out, chk_out) = futures::future::try_join(index_fut, chunk_fut).await?;

        let (hp, idx_groups, idx_profile) = idx_out;
        let (hs, chk_groups, chk_profile) = chk_out;

        let dt_main = t_main_start.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   V1 parallel main hint stream: total {:?} (req INDEX+CHUNK in parallel on 2 sockets, k_index={}, k_chunk={})",
                dt_main, k_index, k_chunk,
            );
        }

        // Restore state to self.
        self.hint_conn = Some(hp);
        self.hint_conn_secondary = Some(hs);
        self.index_groups = idx_groups;
        self.chunk_groups = chk_groups;

        // Record the two rounds (deferred from inside the parallel
        // futures because `record_round` needs `&mut self`).
        self.record_round(idx_profile);
        self.record_round(chk_profile);

        self.loaded_db_id = Some(db_info.db_id);

        // Emit one terminal progress tick — V1 parallel doesn't easily
        // surface per-group ticks since both streams are interleaved.
        // A future improvement would thread a per-group `on_group_complete`
        // callback through the free helper; not worth the API
        // complexity for the wall-time win.
        if let Some(p) = progress {
            let total = (k_index + k_chunk) as u32;
            if total > 0 {
                p.on_group_complete(total, total, "chunk");
            }
        }

        // Persist freshly-fetched main hints to disk cache so a warm
        // restart skips the download entirely. Errors are logged and
        // ignored — a read-only cache must never wedge live queries.
        if let Err(e) = self.persist_hints_to_cache(db_info) {
            log::warn!(
                "[PIR-AUDIT] HarmonyPIR V1 parallel: failed to persist main hints to cache: {}",
                e
            );
        }
        Ok(())
    }

    /// Send a hint request for all main groups at `level` (0=INDEX,
    /// 1=CHUNK) and load each response into its owning `HarmonyGroup`,
    /// invoking `on_group(group_id)` after each successful per-group
    /// load. The callback fires in the order responses arrive over the
    /// wire — usually but not strictly `0..num_groups`.
    pub(crate) async fn fetch_and_load_hints_with_callback(
        &mut self,
        db_id: u8,
        level: u8,
        num_groups: u8,
        on_group: &mut (dyn FnMut(u8) + Send),
    ) -> PirResult<()> {
        let target = if level == 0 {
            HintTarget::Index
        } else if level == 1 {
            HintTarget::Chunk
        } else {
            return Err(PirError::InvalidState(format!(
                "fetch_and_load_hints called with non-main level {}",
                level
            )));
        };
        self.fetch_and_load_hints_into(db_id, level, num_groups, target, Some(on_group))
            .await
    }

    /// Generalised hint fetch: issues a `REQ_HARMONY_HINTS` with the given
    /// `level` byte (0=INDEX, 1=CHUNK, 10+L=INDEX sib L, 20+L=CHUNK sib L)
    /// and streams responses into the group map pointed to by `target`.
    ///
    /// The server derives per-group PRP keys using `(prp_key, level, group_id)`
    /// internally — the client only needs to pass the correct `level` byte;
    /// the `k_offset` accounting in the server is transparent here.
    ///
    /// If `on_group` is `Some`, it is invoked with the just-loaded
    /// `group_id` after each per-group response is processed; sibling
    /// callers and tests pass `None`.
    pub(crate) async fn fetch_and_load_hints_into(
        &mut self,
        db_id: u8,
        level: u8,
        num_groups: u8,
        target: HintTarget,
        mut on_group: Option<&mut (dyn FnMut(u8) + Send)>,
    ) -> PirResult<()> {
        let mut payload = Vec::with_capacity(16 + 1 + 1 + 1 + num_groups as usize + 1);
        payload.extend_from_slice(&self.master_prp_key);
        payload.push(self.prp_backend);
        payload.push(level);
        payload.push(num_groups);
        for g in 0..num_groups {
            payload.push(g);
        }
        if db_id != 0 {
            payload.push(db_id);
        }
        let request = encode_request(REQ_HARMONY_HINTS, &payload);
        let request_bytes = request.len() as u64;

        let t_send = Instant::now();
        let conn = self.hint_conn.as_mut().ok_or(PirError::NotConnected)?;
        conn.send(request).await?;
        let dt_send = t_send.elapsed();

        // The hint server streams `num_groups` separate response frames.
        // Sum their sizes for a single `HarmonyHintRefresh` round event —
        // a wire observer sees one request followed by N responses, all
        // logically tied to this one hint refresh. Round is emitted only
        // on the success path; error returns mid-stream skip emission
        // (matches the early-error semantics of the other rounds).
        let mut received = 0u32;
        let mut seen = vec![false; num_groups as usize];
        let mut total_response_bytes: u64 = 0;
        let t_first_byte = Instant::now();
        let mut dt_first: Option<std::time::Duration> = None;
        let mut dt_recv_total = std::time::Duration::ZERO;
        let mut dt_load_total = std::time::Duration::ZERO;
        while received < num_groups as u32 {
            let t_msg = Instant::now();
            let msg = conn.recv().await?;
            dt_recv_total += t_msg.elapsed();
            if dt_first.is_none() {
                dt_first = Some(t_first_byte.elapsed());
            }
            total_response_bytes = total_response_bytes.saturating_add(msg.len() as u64);
            let body = v2_record_body(&msg, "Harmony V1 hint")?;
            if body.is_empty() {
                return Err(PirError::Protocol("empty hint response body".into()));
            }

            reject_error_response(body, "Harmony V1 hint")?;
            if body[0] != RESP_HARMONY_HINTS {
                return Err(PirError::Protocol(format!(
                    "unexpected hint response byte: 0x{:02x}",
                    body[0]
                )));
            }
            if body.len() < 14 {
                return Err(PirError::Protocol("hint response header truncated".into()));
            }

            let group_id = body[1];
            let was_seen = seen.get_mut(group_id as usize).ok_or_else(|| {
                PirError::Protocol(format!(
                    "hint for out-of-range group {} at level {}",
                    group_id, level
                ))
            })?;
            if *was_seen {
                return Err(PirError::Protocol(format!(
                    "duplicate hint for group {} at level {}",
                    group_id, level
                )));
            }
            *was_seen = true;
            // bytes 2..14 are (n, t, m) metadata — not needed here, the
            // local HarmonyGroup was constructed with the same params.
            let hints_data = &body[14..];

            let group = match target {
                HintTarget::Index => self.index_groups.get_mut(&group_id),
                HintTarget::Chunk => self.chunk_groups.get_mut(&group_id),
                HintTarget::IndexSib(sl) => self.index_sib_groups.get_mut(&(sl, group_id)),
                HintTarget::ChunkSib(sl) => self.chunk_sib_groups.get_mut(&(sl, group_id)),
            };
            let group = group.ok_or_else(|| {
                PirError::Protocol(format!(
                    "hint for unknown group {} at level {}",
                    group_id, level
                ))
            })?;
            let t_load = Instant::now();
            group
                .load_hints(hints_data)
                .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;
            dt_load_total += t_load.elapsed();

            if let Some(cb) = on_group.as_deref_mut() {
                cb(group_id);
            }

            received += 1;
        }

        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]     fetch_and_load_hints(level={:02}): send={:?} first_byte={:?} recv_total={:?} load_total={:?} groups={} bytes={}",
                level, dt_send,
                dt_first.unwrap_or_default(),
                dt_recv_total, dt_load_total,
                num_groups, total_response_bytes,
            );
        }

        self.record_round(RoundProfile {
            kind: RoundKind::HarmonyHintRefresh,
            server_id: 1,
            db_id: Some(db_id),
            request_bytes,
            response_bytes: total_response_bytes,
            items: vec![1u32; num_groups as usize],
        });
        Ok(())
    }
}

/// Free-function variant of [`HarmonyClient::fetch_and_load_hints_into`]
/// for MAIN hints (INDEX or CHUNK level, not sibling). Same structure
/// as [`fetch_and_load_sib_hints_into_map`] but the map key is just
/// `group_id: u8` (not `(sib_level, group_id)`).
///
/// Used by the parallel V1-protocol main hint path in
/// [`HarmonyClient::ensure_groups_ready_v1_parallel`]: client sends
/// `REQ_HARMONY_HINTS` at level=0 (INDEX) on the primary hint socket
/// and level=1 (CHUNK) on the secondary in parallel via
/// `tokio::try_join!`, so the two ~7-10 MB streams transfer
/// concurrently instead of sharing one TCP congestion window.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_and_load_main_hints_into_map(
    conn: &mut dyn PirTransport,
    main_groups: &mut HashMap<u8, HarmonyGroup>,
    db_id: u8,
    wire_level: u8,
    num_groups: u8,
    master_prp_key: &[u8; 16],
    prp_backend: u8,
) -> PirResult<RoundProfile> {
    let mut payload = Vec::with_capacity(16 + 1 + 1 + 1 + num_groups as usize + 1);
    payload.extend_from_slice(master_prp_key);
    payload.push(prp_backend);
    payload.push(wire_level);
    payload.push(num_groups);
    for g in 0..num_groups {
        payload.push(g);
    }
    if db_id != 0 {
        payload.push(db_id);
    }
    let request = encode_request(REQ_HARMONY_HINTS, &payload);
    let request_bytes = request.len() as u64;

    let t_send = Instant::now();
    conn.send(request).await?;
    let dt_send = t_send.elapsed();

    let mut received = 0u32;
    let mut seen = vec![false; num_groups as usize];
    let mut total_response_bytes: u64 = 0;
    let t_first_byte = Instant::now();
    let mut dt_first: Option<std::time::Duration> = None;
    let mut dt_recv_total = std::time::Duration::ZERO;
    let mut dt_load_total = std::time::Duration::ZERO;
    while received < num_groups as u32 {
        let t_msg = Instant::now();
        let msg = conn.recv().await?;
        dt_recv_total += t_msg.elapsed();
        if dt_first.is_none() {
            dt_first = Some(t_first_byte.elapsed());
        }
        total_response_bytes = total_response_bytes.saturating_add(msg.len() as u64);
        let body = v2_record_body(&msg, "Harmony V1 main hint")?;
        if body.is_empty() {
            return Err(PirError::Protocol("empty main hint response body".into()));
        }
        reject_error_response(body, "Harmony V1 main hint")?;
        if body[0] != RESP_HARMONY_HINTS {
            return Err(PirError::Protocol(format!(
                "unexpected main hint response byte: 0x{:02x}",
                body[0]
            )));
        }
        if body.len() < 14 {
            return Err(PirError::Protocol(
                "main hint response header truncated".into(),
            ));
        }
        let group_id = body[1];
        let was_seen = seen.get_mut(group_id as usize).ok_or_else(|| {
            PirError::Protocol(format!(
                "main hint for out-of-range group {} at wire level {}",
                group_id, wire_level
            ))
        })?;
        if *was_seen {
            return Err(PirError::Protocol(format!(
                "duplicate main hint for group {} at wire level {}",
                group_id, wire_level
            )));
        }
        *was_seen = true;
        let hints_data = &body[14..];
        let group = main_groups.get_mut(&group_id).ok_or_else(|| {
            PirError::Protocol(format!(
                "main hint for unknown group {} at wire level {}",
                group_id, wire_level
            ))
        })?;
        let t_load = Instant::now();
        group
            .load_hints(hints_data)
            .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;
        dt_load_total += t_load.elapsed();
        received += 1;
    }

    if std::env::var("HARMONY_BENCH").is_ok() {
        eprintln!(
            "[HARMONY_BENCH]   main_fetch(level={:02}): send={:?} first_byte={:?} recv_total={:?} load_total={:?} groups={} bytes={}",
            wire_level, dt_send,
            dt_first.unwrap_or_default(),
            dt_recv_total, dt_load_total,
            num_groups, total_response_bytes,
        );
    }

    Ok(RoundProfile {
        kind: RoundKind::HarmonyHintRefresh,
        server_id: 1,
        db_id: Some(db_id),
        request_bytes,
        response_bytes: total_response_bytes,
        items: vec![1u32; num_groups as usize],
    })
}

/// Free-function variant of [`HarmonyClient::fetch_and_load_hints_into`]
/// for sibling hints — takes the connection and the specific sib_groups
/// map by mutable reference so two instances can run on disjoint state
/// in parallel via `tokio::try_join!`.
///
/// Used by the parallel path in `ensure_sibling_groups_ready` when a
/// secondary hint socket is available: INDEX sibling hints fetch on
/// the primary hint conn into `index_sib_groups`, CHUNK sibling hints
/// on the secondary into `chunk_sib_groups`, with both futures
/// polled concurrently.
///
/// Returns the `RoundProfile` to be recorded by the caller after the
/// parallel join completes — `record_round` needs `&mut self`, which
/// we don't hold inside the parallel future.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_and_load_sib_hints_into_map(
    conn: &mut dyn PirTransport,
    sib_groups: &mut HashMap<(usize, u8), HarmonyGroup>,
    sib_level: usize,
    db_id: u8,
    wire_level: u8,
    num_groups: u8,
    master_prp_key: &[u8; 16],
    prp_backend: u8,
) -> PirResult<RoundProfile> {
    let mut payload = Vec::with_capacity(16 + 1 + 1 + 1 + num_groups as usize + 1);
    payload.extend_from_slice(master_prp_key);
    payload.push(prp_backend);
    payload.push(wire_level);
    payload.push(num_groups);
    for g in 0..num_groups {
        payload.push(g);
    }
    if db_id != 0 {
        payload.push(db_id);
    }
    let request = encode_request(REQ_HARMONY_HINTS, &payload);
    let request_bytes = request.len() as u64;

    let t_send = Instant::now();
    conn.send(request).await?;
    let dt_send = t_send.elapsed();

    let mut received = 0u32;
    let mut seen = vec![false; num_groups as usize];
    let mut total_response_bytes: u64 = 0;
    let t_first_byte = Instant::now();
    let mut dt_first: Option<std::time::Duration> = None;
    let mut dt_recv_total = std::time::Duration::ZERO;
    let mut dt_load_total = std::time::Duration::ZERO;
    while received < num_groups as u32 {
        let t_msg = Instant::now();
        let msg = conn.recv().await?;
        dt_recv_total += t_msg.elapsed();
        if dt_first.is_none() {
            dt_first = Some(t_first_byte.elapsed());
        }
        total_response_bytes = total_response_bytes.saturating_add(msg.len() as u64);
        let body = v2_record_body(&msg, "Harmony V1 sibling hint")?;
        if body.is_empty() {
            return Err(PirError::Protocol("empty sib hint response body".into()));
        }
        reject_error_response(body, "Harmony V1 sibling hint")?;
        if body[0] != RESP_HARMONY_HINTS {
            return Err(PirError::Protocol(format!(
                "unexpected sib hint response byte: 0x{:02x}",
                body[0]
            )));
        }
        if body.len() < 14 {
            return Err(PirError::Protocol(
                "sib hint response header truncated".into(),
            ));
        }
        let group_id = body[1];
        let was_seen = seen.get_mut(group_id as usize).ok_or_else(|| {
            PirError::Protocol(format!(
                "sibling hint for out-of-range group {} at wire level {}",
                group_id, wire_level
            ))
        })?;
        if *was_seen {
            return Err(PirError::Protocol(format!(
                "duplicate sibling hint for group {} at wire level {}",
                group_id, wire_level
            )));
        }
        *was_seen = true;
        let hints_data = &body[14..];
        let group = sib_groups.get_mut(&(sib_level, group_id)).ok_or_else(|| {
            PirError::Protocol(format!(
                "sib hint for unknown group ({}, {}) at wire level {}",
                sib_level, group_id, wire_level
            ))
        })?;
        let t_load = Instant::now();
        group
            .load_hints(hints_data)
            .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;
        dt_load_total += t_load.elapsed();
        received += 1;
    }

    if std::env::var("HARMONY_BENCH").is_ok() {
        eprintln!(
            "[HARMONY_BENCH]     sib_fetch(level={:02}): send={:?} first_byte={:?} recv_total={:?} load_total={:?} groups={} bytes={}",
            wire_level, dt_send,
            dt_first.unwrap_or_default(),
            dt_recv_total, dt_load_total,
            num_groups, total_response_bytes,
        );
    }

    Ok(RoundProfile {
        kind: RoundKind::HarmonyHintRefresh,
        server_id: 1,
        db_id: Some(db_id),
        request_bytes,
        response_bytes: total_response_bytes,
        items: vec![1u32; num_groups as usize],
    })
}
