use super::*;

impl HarmonyClient {
    // ─── Hint persistence: save / load ─────────────────────────────────────

    /// Serialize the currently loaded hint state (main + sibling groups)
    /// into a self-describing blob.
    ///
    /// Returns `Ok(None)` when nothing is loaded — callers can treat
    /// that as "no state to persist". On success the byte blob carries
    /// the cache key fingerprint in its header, so any later
    /// [`load_hints_bytes`](Self::load_hints_bytes) call that doesn't
    /// match the same master key + shape fails cleanly rather than
    /// silently loading mismatched state.
    ///
    /// This is the explicit byte-level API that Session 5 will wrap
    /// with IndexedDB persistence on wasm32. Native callers who want
    /// filesystem persistence should prefer
    /// [`with_hint_cache_dir`](Self::with_hint_cache_dir) +
    /// [`persist_hints_to_cache`](Self::persist_hints_to_cache),
    /// which handle path resolution and atomic rename for them.
    pub fn save_hints_bytes(&self) -> PirResult<Option<Vec<u8>>> {
        let db_id = match self.loaded_db_id {
            Some(id) => id,
            None => return Ok(None),
        };
        let catalog = self.catalog.as_ref().ok_or_else(|| {
            PirError::InvalidState(
                "save_hints_bytes: catalog not fetched (call fetch_catalog first)".into(),
            )
        })?;
        let db_info = catalog
            .get(db_id)
            .ok_or(PirError::DatabaseNotFound(db_id))?;

        let key =
            hint_cache::CacheKey::from_db_info(self.master_prp_key, self.prp_backend, db_info);
        let mut bundle = hint_cache::HintBundle::new();

        for (&gid, group) in &self.index_groups {
            bundle
                .main_index
                .insert(gid, serialize_harmony_group(group)?);
        }
        for (&gid, group) in &self.chunk_groups {
            bundle
                .main_chunk
                .insert(gid, serialize_harmony_group(group)?);
        }
        // Sibling level is stored in memory as `usize` but realistic
        // Merkle tree depths are well under 255 (typically <= 12);
        // narrow to u8 for the wire format.
        for (&(level, gid), group) in &self.index_sib_groups {
            debug_assert!(level < 256, "sibling level overflow at save time");
            bundle
                .index_sib
                .insert((level as u8, gid), serialize_harmony_group(group)?);
        }
        for (&(level, gid), group) in &self.chunk_sib_groups {
            debug_assert!(level < 256, "sibling level overflow at save time");
            bundle
                .chunk_sib
                .insert((level as u8, gid), serialize_harmony_group(group)?);
        }

        Ok(Some(hint_cache::encode_hints(&key, &bundle)))
    }

    /// Load hint state from a blob produced by
    /// [`save_hints_bytes`](Self::save_hints_bytes).
    ///
    /// The blob's embedded fingerprint is cross-checked against the
    /// caller-supplied `db_info` + this client's master key / PRP
    /// backend; a mismatch is reported as [`PirError::InvalidState`].
    /// Malformed or incompatible blobs surface as [`PirError::Decode`],
    /// so a calling `ensure_*` can treat any non-`Ok` outcome as
    /// "cache miss — fall back to network".
    ///
    /// On success, `loaded_db_id` is set to `db_info.db_id` and all
    /// groups present in the blob are materialised. If the blob
    /// includes sibling state, `sibling_hints_loaded` is also set;
    /// otherwise the sibling maps stay empty so the next
    /// [`ensure_sibling_groups_ready`](Self::ensure_sibling_groups_ready)
    /// will fetch them from the server.
    pub fn load_hints_bytes(&mut self, bytes: &[u8], db_info: &DatabaseInfo) -> PirResult<()> {
        let expected_fp =
            hint_cache::CacheKey::from_db_info(self.master_prp_key, self.prp_backend, db_info)
                .fingerprint();
        let decoded = hint_cache::decode_hints(bytes, Some(&expected_fp))?;
        self.load_bundle_into_groups(&decoded.bundle, db_info)?;
        Ok(())
    }

    /// Re-derive per-group `HarmonyGroup` instances from a
    /// [`hint_cache::HintBundle`].
    ///
    /// Group IDs follow the same layout convention as
    /// [`ensure_groups_ready`](Self::ensure_groups_ready) and
    /// [`ensure_sibling_groups_ready`](Self::ensure_sibling_groups_ready),
    /// so `HarmonyGroup::deserialize` can regenerate the same derived
    /// PRP keys the server uses:
    ///
    /// * main INDEX group g → `group_id = g`
    /// * main CHUNK group g → `group_id = k_index + g`
    /// * INDEX sib level L group g →
    ///   `group_id = (k_index + k_chunk) + L * k_index + g`
    /// * CHUNK sib level L group g →
    ///   `group_id = (k_index + k_chunk) + index_sib_levels * k_index
    ///              + L * k_chunk + g`
    ///
    /// `index_sib_levels` is inferred from the bundle (max cached
    /// level + 1); this is safe because the server always caches
    /// every level 0..N-1 together.
    pub(crate) fn load_bundle_into_groups(
        &mut self,
        bundle: &hint_cache::HintBundle,
        db_info: &DatabaseInfo,
    ) -> PirResult<()> {
        let k_index = db_info.index_k as usize;
        let k_chunk = db_info.chunk_k as usize;

        // Start from a clean slate so partial restores don't mix state
        // from an earlier `ensure_*` pass.
        self.index_groups.clear();
        self.chunk_groups.clear();
        self.index_sib_groups.clear();
        self.chunk_sib_groups.clear();
        self.loaded_db_id = None;
        self.sibling_hints_loaded = None;

        for (&gid, bytes) in &bundle.main_index {
            let group =
                HarmonyGroup::deserialize_legacy_state(bytes, &self.master_prp_key, gid as u32)
                    .map_err(|e| {
                        PirError::BackendState(format!(
                            "deserialize main INDEX group {}: {:?}",
                            gid, e
                        ))
                    })?;
            self.index_groups.insert(gid, group);
        }
        for (&gid, bytes) in &bundle.main_chunk {
            let group_id = (k_index + gid as usize) as u32;
            let group =
                HarmonyGroup::deserialize_legacy_state(bytes, &self.master_prp_key, group_id)
                    .map_err(|e| {
                        PirError::BackendState(format!(
                            "deserialize main CHUNK group {}: {:?}",
                            gid, e
                        ))
                    })?;
            self.chunk_groups.insert(gid, group);
        }

        let index_sib_levels = bundle
            .index_sib
            .keys()
            .map(|(l, _)| *l as usize + 1)
            .max()
            .unwrap_or(0);

        for (&(level, gid), bytes) in &bundle.index_sib {
            let sl = level as usize;
            let g = gid as usize;
            let group_id = ((k_index + k_chunk) + sl * k_index + g) as u32;
            let group =
                HarmonyGroup::deserialize_legacy_state(bytes, &self.master_prp_key, group_id)
                    .map_err(|e| {
                        PirError::BackendState(format!(
                            "deserialize INDEX sib L{} g{}: {:?}",
                            sl, g, e
                        ))
                    })?;
            self.index_sib_groups.insert((sl, gid), group);
        }
        for (&(level, gid), bytes) in &bundle.chunk_sib {
            let sl = level as usize;
            let g = gid as usize;
            let group_id =
                ((k_index + k_chunk) + index_sib_levels * k_index + sl * k_chunk + g) as u32;
            let group =
                HarmonyGroup::deserialize_legacy_state(bytes, &self.master_prp_key, group_id)
                    .map_err(|e| {
                        PirError::BackendState(format!(
                            "deserialize CHUNK sib L{} g{}: {:?}",
                            sl, g, e
                        ))
                    })?;
            self.chunk_sib_groups.insert((sl, gid), group);
        }

        // Only claim "loaded" when all main groups this db expects are
        // present — a partial bundle (e.g. from a truncated legacy
        // format) must trigger a network refetch rather than serve a
        // half-state. Note: `k_index` and `k_chunk` are from the
        // caller's `db_info`, and the bundle header has already been
        // fingerprint-checked, so this length compare is a sanity
        // guard rather than a trust boundary.
        let full_main = bundle.main_index.len() == k_index
            && bundle.main_chunk.len() == k_chunk
            && (0..k_index).all(|group| bundle.main_index.contains_key(&(group as u8)))
            && (0..k_chunk).all(|group| bundle.main_chunk.contains_key(&(group as u8)));
        if full_main {
            self.loaded_db_id = Some(db_info.db_id);
            // Tentatively claim sibling state if any are present; the
            // caller (`ensure_sibling_groups_ready`) will validate the
            // count against the server's tree-tops and re-fetch on
            // mismatch, so this is a fast-path hint rather than a
            // trust anchor.
            if !bundle.index_sib.is_empty() || !bundle.chunk_sib.is_empty() {
                self.sibling_hints_loaded = Some(db_info.db_id);
            }
        }
        Ok(())
    }

    // ─── Hint persistence: file-backed cache ───────────────────────────────

    /// Persist the current hint state to the configured cache directory.
    ///
    /// No-op when `hint_cache_dir` is unset or `save_hints_bytes`
    /// returns `None` (nothing loaded). Uses an atomic rename
    /// (`<file>.tmp` → `<file>`) so a crash mid-write leaves the
    /// previous cache file intact.
    pub fn persist_hints_to_cache(&self, db_info: &DatabaseInfo) -> PirResult<()> {
        let Some(path) = self.cache_path_for(db_info) else {
            return Ok(());
        };
        let Some(bytes) = self.save_hints_bytes()? else {
            return Ok(());
        };
        #[cfg(not(target_arch = "wasm32"))]
        {
            hint_cache::write_cache_file(&path, &bytes)?;
            log::info!(
                "[PIR-AUDIT] HarmonyPIR: persisted {} bytes to {}",
                bytes.len(),
                path.display()
            );
        }
        #[cfg(target_arch = "wasm32")]
        {
            // On wasm32 the filesystem path isn't available; Session 5
            // wires IndexedDB through the `save_hints_bytes` /
            // `load_hints_bytes` pair directly. Silently no-op rather
            // than fail so shared code paths stay oblivious.
            let _ = (path, bytes);
        }
        Ok(())
    }

    /// Try to restore hints from the configured cache directory.
    ///
    /// Returns `Ok(true)` if the cache file existed and was loaded
    /// successfully, `Ok(false)` when the cache is cold or the blob
    /// was rejected (bad magic, schema mismatch, fingerprint mismatch,
    /// truncation). Any transient I/O error (disk full, permissions,
    /// etc.) still bubbles up as `Err` so the caller can decide
    /// whether to retry or surface it.
    ///
    /// Always `Ok(false)` when `hint_cache_dir` is unset.
    pub fn restore_hints_from_cache(&mut self, db_info: &DatabaseInfo) -> PirResult<bool> {
        let Some(path) = self.cache_path_for(db_info) else {
            return Ok(false);
        };
        #[cfg(not(target_arch = "wasm32"))]
        {
            let Some(bytes) = hint_cache::read_cache_file(&path)? else {
                return Ok(false);
            };
            match self.load_hints_bytes(&bytes, db_info) {
                Ok(()) => {
                    log::info!(
                        "[PIR-AUDIT] HarmonyPIR: restored hints from {} \
                         ({} INDEX + {} CHUNK main, {} INDEX sib + {} CHUNK sib)",
                        path.display(),
                        self.index_groups.len(),
                        self.chunk_groups.len(),
                        self.index_sib_groups.len(),
                        self.chunk_sib_groups.len()
                    );
                    Ok(true)
                }
                Err(e) => {
                    log::warn!(
                        "[PIR-AUDIT] HarmonyPIR: rejected cache at {} ({}); refetching",
                        path.display(),
                        e
                    );
                    self.invalidate_groups();
                    Ok(false)
                }
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = path;
            Ok(false)
        }
    }
}
