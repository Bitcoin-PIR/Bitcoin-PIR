//! HarmonyPIR client implementation.
//!
//! HarmonyPIR is a two-server PIR protocol with:
//! - **Hint Server**: Computes offline hints based on PRP keys
//! - **Query Server**: Answers online queries using precomputed indices
//!
//! NOTE: This implementation is currently a placeholder. The full HarmonyPIR
//! protocol requires stateful per-group management with RelocationDS, but the
//! underlying harmonypir crate's Prp trait is not Send+Sync, making it incompatible
//! with the async PirClient trait. A complete implementation would require either:
//! 1. Modifying harmonypir to make Prp Send+Sync
//! 2. Using synchronization primitives (Mutex/RwLock)
//! 3. Recreating PRPs on each query (less efficient)
//!
//! For production use of HarmonyPIR, please use the WASM client (harmonypir-wasm)
//! which is designed for single-threaded browser environments.

use crate::connection::WsConnection;
use async_trait::async_trait;
use pir_sdk::{
    compute_sync_plan, merge_delta_batch, DatabaseCatalog, DatabaseInfo, DatabaseKind,
    PirBackendType, PirClient, PirError, PirResult, QueryResult, ScriptHash, SyncPlan, SyncResult,
    SyncStep,
};

// ─── HarmonyPIR Client ──────────────────────────────────────────────────────

/// HarmonyPIR client for two-server PIR queries.
///
/// **Current status**: Placeholder implementation. See module docs for details.
pub struct HarmonyClient {
    hint_server_url: String,
    query_server_url: String,
    hint_conn: Option<WsConnection>,
    query_conn: Option<WsConnection>,
    catalog: Option<DatabaseCatalog>,
    /// PRP backend to use (0=Hoang, 1=FastPRP, 2=ALF).
    prp_backend: u8,
    /// Master PRP key.
    master_prp_key: [u8; 16],
}

impl HarmonyClient {
    /// Create a new HarmonyPIR client.
    pub fn new(hint_server_url: &str, query_server_url: &str) -> Self {
        // Generate a random master key
        let mut master_prp_key = [0u8; 16];
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        for i in 0..2 {
            let h = pir_core::hash::splitmix64(seed.wrapping_add(i as u64));
            master_prp_key[i * 8..(i + 1) * 8].copy_from_slice(&h.to_le_bytes());
        }

        Self {
            hint_server_url: hint_server_url.to_string(),
            query_server_url: query_server_url.to_string(),
            hint_conn: None,
            query_conn: None,
            catalog: None,
            prp_backend: 1, // FastPRP by default
            master_prp_key,
        }
    }

    /// Set the PRP backend to use.
    ///
    /// - 0 = Hoang PRP
    /// - 1 = FastPRP (default, recommended)
    /// - 2 = ALF PRP
    pub fn set_prp_backend(&mut self, backend: u8) {
        self.prp_backend = backend;
    }

    /// Fetch server info for legacy servers.
    async fn fetch_legacy_info(&mut self) -> PirResult<DatabaseInfo> {
        let conn = self.hint_conn.as_mut().ok_or(PirError::NotConnected)?;

        // REQ_HARMONY_GET_INFO = 0x40
        let request = encode_request(0x40, &[]);
        let response = conn.roundtrip(&request).await?;

        if response.is_empty() || response[0] != 0x40 {
            return Err(PirError::Protocol("invalid harmony info response".into()));
        }

        // Parse: [4B index_bins][4B chunk_bins][1B index_k][1B chunk_k][8B tag_seed]
        if response.len() < 19 {
            return Err(PirError::Protocol("harmony info response too short".into()));
        }

        let index_bins = u32::from_le_bytes(response[1..5].try_into().unwrap());
        let chunk_bins = u32::from_le_bytes(response[5..9].try_into().unwrap());
        let index_k = response[9];
        let chunk_k = response[10];
        let tag_seed = u64::from_le_bytes(response[11..19].try_into().unwrap());

        Ok(DatabaseInfo {
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
        })
    }

    /// Execute a single query step.
    ///
    /// NOTE: This is a placeholder that returns None for all queries.
    async fn execute_step(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        _db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        log::warn!(
            "HarmonyPIR query not fully implemented - returning empty results for {} script hashes. \
             See pir-sdk-client/src/harmony.rs module docs for details.",
            script_hashes.len()
        );

        // Return None for all queries (placeholder)
        Ok(vec![None; script_hashes.len()])
    }
}

#[async_trait]
impl PirClient for HarmonyClient {
    fn backend_type(&self) -> PirBackendType {
        PirBackendType::Harmony
    }

    async fn connect(&mut self) -> PirResult<()> {
        log::info!(
            "Connecting to HarmonyPIR servers: hint={}, query={}",
            self.hint_server_url,
            self.query_server_url
        );

        let (hint_conn, query_conn) = tokio::try_join!(
            WsConnection::connect(&self.hint_server_url),
            WsConnection::connect(&self.query_server_url),
        )?;

        self.hint_conn = Some(hint_conn);
        self.query_conn = Some(query_conn);

        log::info!("Connected to both HarmonyPIR servers");
        log::warn!(
            "HarmonyPIR client is a placeholder implementation. \
             Queries will return empty results."
        );
        Ok(())
    }

    async fn disconnect(&mut self) -> PirResult<()> {
        if let Some(ref mut conn) = self.hint_conn {
            let _ = conn.close().await;
        }
        if let Some(ref mut conn) = self.query_conn {
            let _ = conn.close().await;
        }
        self.hint_conn = None;
        self.query_conn = None;
        self.catalog = None;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.hint_conn.is_some() && self.query_conn.is_some()
    }

    async fn fetch_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }

        let info = self.fetch_legacy_info().await?;
        let catalog = DatabaseCatalog {
            databases: vec![info],
        };
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

        let catalog = self
            .catalog
            .clone()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;

        let mut merged: Vec<Option<QueryResult>> = cached_results
            .map(|r| r.to_vec())
            .unwrap_or_else(|| vec![None; script_hashes.len()]);

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
                .ok_or_else(|| PirError::DatabaseNotFound(step.db_id))?
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
            .ok_or_else(|| PirError::DatabaseNotFound(db_id))?
            .clone();

        let step = SyncStep::from_db_info(&db_info);
        self.execute_step(script_hashes, &step, &db_info).await
    }
}

// ─── Protocol helpers ───────────────────────────────────────────────────────

fn encode_request(variant: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 1 + payload.len();
    let mut buf = Vec::with_capacity(4 + total_len);
    buf.extend_from_slice(&(total_len as u32).to_le_bytes());
    buf.push(variant);
    buf.extend_from_slice(payload);
    buf
}
