//! DPF-PIR client implementation.
//!
//! This implements the two-level Batch PIR protocol using Distributed Point Functions.
//! Queries are split across two servers; XORing their responses reveals the actual data.

use crate::connection::WsConnection;
use async_trait::async_trait;
use libdpf::Dpf;
use pir_sdk::{
    compute_sync_plan, merge_delta_batch, DatabaseCatalog, DatabaseInfo, DatabaseKind,
    PirBackendType, PirClient, PirError, PirResult, QueryResult, ScriptHash, SyncPlan, SyncResult,
    SyncStep, UtxoEntry,
};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Number of cuckoo hash functions for index level.
const INDEX_CUCKOO_NUM_HASHES: usize = 2;

/// Number of cuckoo hash functions for chunk level.
const CHUNK_CUCKOO_NUM_HASHES: usize = 2;

/// Index slot size: 8B tag + 4B start_chunk_id + 1B num_chunks = 13 bytes.
const INDEX_SLOT_SIZE: usize = 13;

/// Slots per index bin.
const INDEX_SLOTS_PER_BIN: usize = 4;

/// Index result size per group.
const INDEX_RESULT_SIZE: usize = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE;

/// Tag size in bytes.
const TAG_SIZE: usize = 8;

/// Chunk data size.
const CHUNK_SIZE: usize = 40;

/// Chunk slot size: 4B chunk_id + 40B data.
const CHUNK_SLOT_SIZE: usize = 4 + CHUNK_SIZE;

/// Slots per chunk bin.
const CHUNK_SLOTS_PER_BIN: usize = 3;

/// Chunk result size per group.
const CHUNK_RESULT_SIZE: usize = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE;

/// Number of PBC hash functions.
const NUM_HASHES: usize = 3;

// ─── DPF Client ─────────────────────────────────────────────────────────────

/// DPF-PIR client for two-server PIR queries.
pub struct DpfClient {
    server0_url: String,
    server1_url: String,
    conn0: Option<WsConnection>,
    conn1: Option<WsConnection>,
    catalog: Option<DatabaseCatalog>,
}

impl DpfClient {
    /// Create a new DPF client.
    pub fn new(server0_url: &str, server1_url: &str) -> Self {
        Self {
            server0_url: server0_url.to_string(),
            server1_url: server1_url.to_string(),
            conn0: None,
            conn1: None,
            catalog: None,
        }
    }

    /// Fetch server info and build catalog entry for legacy servers.
    async fn fetch_legacy_info(&mut self) -> PirResult<DatabaseInfo> {
        let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;

        // REQ_GET_INFO = 0x01
        let request = encode_request(0x01, &[]);
        let response = conn0.roundtrip(&request).await?;

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

    /// Execute a single query step for a batch of script hashes.
    async fn execute_step(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        let mut results = Vec::with_capacity(script_hashes.len());

        for script_hash in script_hashes {
            let result = self.query_single(script_hash, db_info).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Query a single script hash against a database.
    async fn query_single(
        &mut self,
        script_hash: &ScriptHash,
        db_info: &DatabaseInfo,
    ) -> PirResult<Option<QueryResult>> {
        // Step 1: Index-level PIR query
        let index_result = self.query_index_level(script_hash, db_info).await?;

        let (start_chunk_id, num_chunks, is_whale) = match index_result {
            Some((start, num, whale)) => (start, num, whale),
            None => return Ok(None),
        };

        if num_chunks == 0 {
            return Ok(Some(QueryResult {
                entries: Vec::new(),
                is_whale,
                raw_chunk_data: None,
            }));
        }

        // Step 2: Chunk-level PIR queries (multi-round)
        let chunk_ids: Vec<u32> = (start_chunk_id..start_chunk_id + num_chunks as u32).collect();
        let chunk_data = self.query_chunk_level(&chunk_ids, db_info).await?;

        // Step 3: Decode UTXO entries
        let entries = decode_utxo_entries(&chunk_data);

        Ok(Some(QueryResult {
            entries,
            is_whale,
            raw_chunk_data: if db_info.kind.is_delta() {
                Some(chunk_data)
            } else {
                None
            },
        }))
    }

    /// Execute index-level PIR query.
    async fn query_index_level(
        &mut self,
        script_hash: &ScriptHash,
        db_info: &DatabaseInfo,
    ) -> PirResult<Option<(u32, u8, bool)>> {
        let k = db_info.index_k as usize;
        let bins = db_info.index_bins as usize;
        let dpf_n = db_info.dpf_n_index;
        let tag_seed = db_info.tag_seed;
        let master_seed = pir_core::params::INDEX_PARAMS.master_seed;

        // Compute candidate groups for our script hash
        let my_groups = pir_core::hash::derive_groups_3(script_hash, k);
        let assigned_group = my_groups[0];

        // Compute cuckoo hash locations in the assigned group
        let mut my_locs = Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES);
        for h in 0..INDEX_CUCKOO_NUM_HASHES {
            let key = pir_core::hash::derive_cuckoo_key(master_seed, assigned_group, h);
            my_locs.push(pir_core::hash::cuckoo_hash(script_hash, key, bins) as u64);
        }

        // Generate DPF keys for all K groups
        let dpf = Dpf::with_default_key();
        let mut rng = SimpleRng::new();

        let mut s0_keys: Vec<Vec<Vec<u8>>> = Vec::with_capacity(k);
        let mut s1_keys: Vec<Vec<Vec<u8>>> = Vec::with_capacity(k);

        for b in 0..k {
            let mut s0_group = Vec::new();
            let mut s1_group = Vec::new();

            for h in 0..INDEX_CUCKOO_NUM_HASHES {
                let alpha = if b == assigned_group {
                    my_locs[h]
                } else {
                    rng.next_u64() % bins as u64
                };
                let (k0, k1) = dpf.gen(alpha, dpf_n);
                s0_group.push(k0.to_bytes());
                s1_group.push(k1.to_bytes());
            }

            s0_keys.push(s0_group);
            s1_keys.push(s1_group);
        }

        // Send to both servers
        let req0 = encode_batch_query(0x11, 0, 0, db_info.db_id, &s0_keys);
        let req1 = encode_batch_query(0x11, 0, 0, db_info.db_id, &s1_keys);

        let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
        conn0.send(req0).await?;

        let conn1 = self.conn1.as_mut().ok_or(PirError::NotConnected)?;
        conn1.send(req1).await?;

        // Receive responses
        let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
        let resp0 = conn0.recv().await?;

        let conn1 = self.conn1.as_mut().ok_or(PirError::NotConnected)?;
        let resp1 = conn1.recv().await?;

        // Parse responses
        let results0 = decode_batch_response(&resp0[4..])?; // skip length prefix
        let results1 = decode_batch_response(&resp1[4..])?;

        // Compute expected tag
        let my_tag = pir_core::hash::compute_tag(tag_seed, script_hash);

        // XOR results for assigned group and look for our entry
        for h in 0..INDEX_CUCKOO_NUM_HASHES {
            let mut result = results0[assigned_group][h].clone();
            xor_into(&mut result, &results1[assigned_group][h]);

            if let Some((start_chunk, num_chunks)) = find_entry_in_index_result(&result, my_tag) {
                let is_whale = num_chunks == 0;
                return Ok(Some((start_chunk, num_chunks as u8, is_whale)));
            }
        }

        Ok(None)
    }

    /// Execute chunk-level PIR queries (multi-round).
    async fn query_chunk_level(
        &mut self,
        chunk_ids: &[u32],
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<u8>> {
        let k = db_info.chunk_k as usize;
        let bins = db_info.chunk_bins as usize;
        let dpf_n = db_info.dpf_n_chunk;
        let master_seed = pir_core::params::CHUNK_PARAMS.master_seed;

        // Plan multi-round chunk retrieval
        let rounds = plan_chunk_rounds(chunk_ids, k);

        let mut all_data = Vec::new();
        let mut chunk_data_map: std::collections::HashMap<u32, Vec<u8>> = std::collections::HashMap::new();

        for (round_id, round) in rounds.iter().enumerate() {
            // Generate DPF keys for this round
            let dpf = Dpf::with_default_key();
            let mut rng = SimpleRng::new();

            let mut s0_keys: Vec<Vec<Vec<u8>>> = vec![Vec::new(); k];
            let mut s1_keys: Vec<Vec<Vec<u8>>> = vec![Vec::new(); k];

            // Track which chunk is in which group for this round
            let mut group_to_chunk: std::collections::HashMap<usize, u32> = std::collections::HashMap::new();

            for &(chunk_id, group_id) in round {
                group_to_chunk.insert(group_id, chunk_id);
            }

            for g in 0..k {
                for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                    let alpha = if let Some(&chunk_id) = group_to_chunk.get(&g) {
                        let key = pir_core::hash::derive_cuckoo_key(master_seed, g, h);
                        pir_core::hash::cuckoo_hash_int(chunk_id, key, bins) as u64
                    } else {
                        rng.next_u64() % bins as u64
                    };

                    let (k0, k1) = dpf.gen(alpha, dpf_n);
                    s0_keys[g].push(k0.to_bytes());
                    s1_keys[g].push(k1.to_bytes());
                }
            }

            // Send to both servers
            let req0 = encode_batch_query(0x21, 1, round_id as u16, db_info.db_id, &s0_keys);
            let req1 = encode_batch_query(0x21, 1, round_id as u16, db_info.db_id, &s1_keys);

            let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
            conn0.send(req0).await?;

            let conn1 = self.conn1.as_mut().ok_or(PirError::NotConnected)?;
            conn1.send(req1).await?;

            // Receive responses
            let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
            let resp0 = conn0.recv().await?;

            let conn1 = self.conn1.as_mut().ok_or(PirError::NotConnected)?;
            let resp1 = conn1.recv().await?;

            // Parse and XOR results
            let results0 = decode_batch_response(&resp0[4..])?;
            let results1 = decode_batch_response(&resp1[4..])?;

            // Extract chunk data for each chunk in this round
            for &(chunk_id, group_id) in round {
                for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                    let mut result = results0[group_id][h].clone();
                    xor_into(&mut result, &results1[group_id][h]);

                    if let Some(data) = find_chunk_in_result(&result, chunk_id) {
                        chunk_data_map.insert(chunk_id, data.to_vec());
                        break;
                    }
                }
            }
        }

        // Assemble chunk data in order
        for chunk_id in chunk_ids {
            if let Some(data) = chunk_data_map.get(chunk_id) {
                all_data.extend_from_slice(data);
            }
        }

        Ok(all_data)
    }
}

#[async_trait]
impl PirClient for DpfClient {
    fn backend_type(&self) -> PirBackendType {
        PirBackendType::Dpf
    }

    async fn connect(&mut self) -> PirResult<()> {
        log::info!(
            "Connecting to servers: {}, {}",
            self.server0_url,
            self.server1_url
        );

        let (conn0, conn1) = tokio::try_join!(
            WsConnection::connect(&self.server0_url),
            WsConnection::connect(&self.server1_url),
        )?;

        self.conn0 = Some(conn0);
        self.conn1 = Some(conn1);

        log::info!("Connected to both servers");
        Ok(())
    }

    async fn disconnect(&mut self) -> PirResult<()> {
        if let Some(ref mut conn) = self.conn0 {
            let _ = conn.close().await;
        }
        if let Some(ref mut conn) = self.conn1 {
            let _ = conn.close().await;
        }
        self.conn0 = None;
        self.conn1 = None;
        self.catalog = None;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.conn0.is_some() && self.conn1.is_some()
    }

    async fn fetch_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }

        // Try to fetch full catalog first (REQ_GET_DB_CATALOG = 0x02)
        let request = encode_request(0x02, &[]);
        let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
        let response = conn0.roundtrip(&request).await?;

        if response.is_empty() {
            return Err(PirError::Protocol("empty catalog response".into()));
        }

        // Check if server supports catalog (RESP_DB_CATALOG = 0x02)
        if response[0] == 0x02 {
            let catalog = decode_catalog(&response[1..])?;
            self.catalog = Some(catalog.clone());
            return Ok(catalog);
        }

        // Fall back to legacy single-database info
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
                "[{}/{}] Querying {} (db_id={}, height={})",
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

/// Encode a simple request with length prefix.
fn encode_request(variant: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 1 + payload.len();
    let mut buf = Vec::with_capacity(4 + total_len);
    buf.extend_from_slice(&(total_len as u32).to_le_bytes());
    buf.push(variant);
    buf.extend_from_slice(payload);
    buf
}

/// Encode a batch query request.
fn encode_batch_query(
    variant: u8,
    level: u8,
    round_id: u16,
    db_id: u8,
    keys: &[Vec<Vec<u8>>],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(level);
    payload.extend_from_slice(&round_id.to_le_bytes());
    payload.push(db_id);
    payload.push(keys.len() as u8); // num_groups

    for group_keys in keys {
        payload.push(group_keys.len() as u8); // num_keys per group
        for key in group_keys {
            payload.extend_from_slice(&(key.len() as u16).to_le_bytes());
            payload.extend_from_slice(key);
        }
    }

    let total_len = 1 + payload.len();
    let mut buf = Vec::with_capacity(4 + total_len);
    buf.extend_from_slice(&(total_len as u32).to_le_bytes());
    buf.push(variant);
    buf.extend_from_slice(&payload);
    buf
}

/// Decode a batch response into per-group, per-key results.
fn decode_batch_response(data: &[u8]) -> PirResult<Vec<Vec<Vec<u8>>>> {
    if data.is_empty() {
        return Err(PirError::Decode("empty batch response".into()));
    }

    // Skip variant byte
    let _variant = data[0];
    let mut pos = 1;

    // level, round_id
    if pos + 3 > data.len() {
        return Err(PirError::Decode("truncated batch response header".into()));
    }
    let _level = data[pos];
    pos += 1;
    let _round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;

    // num_groups
    if pos >= data.len() {
        return Err(PirError::Decode("missing num_groups".into()));
    }
    let num_groups = data[pos] as usize;
    pos += 1;

    let mut results = Vec::with_capacity(num_groups);

    for _ in 0..num_groups {
        if pos >= data.len() {
            return Err(PirError::Decode("truncated group results".into()));
        }
        let num_keys = data[pos] as usize;
        pos += 1;

        let mut group_results = Vec::with_capacity(num_keys);
        for _ in 0..num_keys {
            if pos + 2 > data.len() {
                return Err(PirError::Decode("truncated result length".into()));
            }
            let result_len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;

            if pos + result_len > data.len() {
                return Err(PirError::Decode("truncated result data".into()));
            }
            group_results.push(data[pos..pos + result_len].to_vec());
            pos += result_len;
        }
        results.push(group_results);
    }

    Ok(results)
}

/// Decode a database catalog from response bytes.
fn decode_catalog(data: &[u8]) -> PirResult<DatabaseCatalog> {
    if data.len() < 2 {
        return Err(PirError::Decode("catalog too short".into()));
    }

    let num_dbs = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
    let mut pos = 2;
    let mut databases = Vec::with_capacity(num_dbs);

    for _ in 0..num_dbs {
        if pos + 2 > data.len() {
            return Err(PirError::Decode("truncated catalog entry".into()));
        }

        let db_id = data[pos];
        pos += 1;
        let db_type = data[pos];
        pos += 1;

        let name_len = data[pos] as usize;
        pos += 1;
        if pos + name_len > data.len() {
            return Err(PirError::Decode("truncated catalog name".into()));
        }
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).into_owned();
        pos += name_len;

        if pos + 26 > data.len() {
            return Err(PirError::Decode("truncated catalog fields".into()));
        }

        let base_height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let index_bins = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let chunk_bins = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let index_k = data[pos];
        pos += 1;
        let chunk_k = data[pos];
        pos += 1;
        let tag_seed = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let dpf_n_index = data[pos];
        pos += 1;
        let dpf_n_chunk = data[pos];
        pos += 1;
        let has_bucket_merkle = data[pos] != 0;
        pos += 1;

        let kind = if db_type == 1 {
            DatabaseKind::Delta { base_height }
        } else {
            DatabaseKind::Full
        };

        databases.push(DatabaseInfo {
            db_id,
            kind,
            name,
            height,
            index_bins,
            chunk_bins,
            index_k,
            chunk_k,
            tag_seed,
            dpf_n_index,
            dpf_n_chunk,
            has_bucket_merkle,
        });
    }

    Ok(DatabaseCatalog { databases })
}

// ─── PIR helpers ────────────────────────────────────────────────────────────

/// XOR src into dst.
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Find a matching tag in an index-level result.
fn find_entry_in_index_result(result: &[u8], expected_tag: u64) -> Option<(u32, u32)> {
    for slot in 0..INDEX_SLOTS_PER_BIN {
        let base = slot * INDEX_SLOT_SIZE;
        if base + INDEX_SLOT_SIZE > result.len() {
            break;
        }
        let slot_tag = u64::from_le_bytes(result[base..base + TAG_SIZE].try_into().unwrap());
        if slot_tag == expected_tag {
            let start_chunk_id =
                u32::from_le_bytes(result[base + TAG_SIZE..base + TAG_SIZE + 4].try_into().unwrap());
            let num_chunks = result[base + TAG_SIZE + 4] as u32;
            return Some((start_chunk_id, num_chunks));
        }
    }
    None
}

/// Find a chunk_id in a chunk-level result.
fn find_chunk_in_result(result: &[u8], chunk_id: u32) -> Option<&[u8]> {
    let target = chunk_id.to_le_bytes();
    for slot in 0..CHUNK_SLOTS_PER_BIN {
        let base = slot * CHUNK_SLOT_SIZE;
        if base + CHUNK_SLOT_SIZE > result.len() {
            break;
        }
        if result[base..base + 4] == target {
            return Some(&result[base + 4..base + CHUNK_SLOT_SIZE]);
        }
    }
    None
}

/// Plan multi-round chunk retrieval using PBC.
fn plan_chunk_rounds(chunk_ids: &[u32], k: usize) -> Vec<Vec<(u32, usize)>> {
    let cand_groups: Vec<[usize; 3]> = chunk_ids
        .iter()
        .map(|&cid| pir_core::hash::derive_int_groups_3(cid, k))
        .collect();

    let rounds = pir_core::pbc::pbc_plan_rounds(&cand_groups, k, NUM_HASHES, 500);

    rounds
        .into_iter()
        .map(|round| {
            round
                .into_iter()
                .map(|(item_idx, group)| (chunk_ids[item_idx], group))
                .collect()
        })
        .collect()
}

/// Decode UTXO entries from raw chunk data.
fn decode_utxo_entries(data: &[u8]) -> Vec<UtxoEntry> {
    let mut entries = Vec::new();
    let mut pos = 0;

    // Each chunk is 40 bytes: 32B txid + 4B vout + 4B amount (compressed)
    while pos + CHUNK_SIZE <= data.len() {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let vout = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // Amount is stored as 4 bytes (compressed satoshis)
        let amount_compressed = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // Skip empty slots (zero txid)
        if txid.iter().all(|&b| b == 0) {
            continue;
        }

        entries.push(UtxoEntry {
            txid,
            vout,
            amount_sats: amount_compressed as u64,
        });
    }

    entries
}

// ─── Simple RNG ─────────────────────────────────────────────────────────────

/// Simple PRNG for generating dummy query indices.
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        Self {
            state: pir_core::hash::splitmix64(seed),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        pir_core::hash::splitmix64(self.state)
    }
}
