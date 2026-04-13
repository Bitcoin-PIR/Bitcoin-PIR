//! OnionPIR client implementation.
//!
//! OnionPIR is a single-server FHE-based PIR protocol. It provides:
//! - **Single server**: No trust assumptions between servers
//! - **Strong privacy**: Query privacy via fully homomorphic encryption
//! - **Higher latency**: FHE operations are computationally intensive
//!
//! NOTE: This is a placeholder implementation. The full OnionPIR protocol
//! requires integration with the OnionPIR FHE library which is not yet
//! available as a Rust crate. For production use, consider using the
//! DPF client for better performance in two-server deployments.

use crate::connection::WsConnection;
use async_trait::async_trait;
use pir_sdk::{
    compute_sync_plan, merge_delta_batch, DatabaseCatalog, DatabaseInfo, DatabaseKind,
    PirBackendType, PirClient, PirError, PirResult, QueryResult, ScriptHash, SyncPlan, SyncResult,
    SyncStep,
};

// ─── OnionPIR Client ────────────────────────────────────────────────────────

/// OnionPIR client for single-server FHE-based PIR queries.
///
/// **Current status**: Placeholder implementation. See module docs for details.
pub struct OnionClient {
    server_url: String,
    conn: Option<WsConnection>,
    catalog: Option<DatabaseCatalog>,
}

impl OnionClient {
    /// Create a new OnionPIR client.
    pub fn new(server_url: &str) -> Self {
        Self {
            server_url: server_url.to_string(),
            conn: None,
            catalog: None,
        }
    }

    /// Fetch server info.
    async fn fetch_server_info(&mut self) -> PirResult<DatabaseInfo> {
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;

        // REQ_GET_INFO = 0x01
        let request = encode_request(0x01, &[]);
        let response = conn.roundtrip(&request).await?;

        if response.is_empty() || response[0] != 0x01 {
            return Err(PirError::Protocol("invalid info response".into()));
        }

        // Parse: [4B index_bins][4B chunk_bins][1B index_k][1B chunk_k][8B tag_seed]
        if response.len() < 19 {
            return Err(PirError::Protocol("info response too short".into()));
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
            "OnionPIR query not implemented - returning empty results for {} script hashes. \
             See pir-sdk-client/src/onion.rs module docs for details.",
            script_hashes.len()
        );

        // Return None for all queries (placeholder)
        Ok(vec![None; script_hashes.len()])
    }
}

#[async_trait]
impl PirClient for OnionClient {
    fn backend_type(&self) -> PirBackendType {
        PirBackendType::Onion
    }

    async fn connect(&mut self) -> PirResult<()> {
        log::info!("Connecting to OnionPIR server: {}", self.server_url);

        let conn = WsConnection::connect(&self.server_url).await?;
        self.conn = Some(conn);

        log::info!("Connected to OnionPIR server");
        log::warn!(
            "OnionPIR client is a placeholder implementation. \
             Queries will return empty results."
        );
        Ok(())
    }

    async fn disconnect(&mut self) -> PirResult<()> {
        if let Some(ref mut conn) = self.conn {
            let _ = conn.close().await;
        }
        self.conn = None;
        self.catalog = None;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.conn.is_some()
    }

    async fn fetch_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }

        let info = self.fetch_server_info().await?;
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
                "[{}/{}] OnionPIR querying {} (db_id={}, height={})",
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
