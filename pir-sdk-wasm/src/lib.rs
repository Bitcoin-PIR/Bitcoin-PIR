//! WASM bindings for PIR SDK.
//!
//! Exposes sync planning, delta merging, and core types to JavaScript/TypeScript.
//!
//! # Usage in JavaScript
//!
//! ```javascript
//! import init, {
//!   computeSyncPlan,
//!   mergeDeltaBatch,
//!   WasmDatabaseCatalog,
//!   WasmSyncPlan,
//! } from 'pir-sdk-wasm';
//!
//! await init();
//!
//! // Build catalog from server response
//! const catalog = WasmDatabaseCatalog.fromJson(serverCatalogJson);
//!
//! // Compute sync plan
//! const plan = computeSyncPlan(catalog, lastSyncedHeight);
//! console.log(`Steps: ${plan.stepsCount}, target: ${plan.targetHeight}`);
//!
//! // Iterate steps
//! for (let i = 0; i < plan.stepsCount; i++) {
//!   const step = plan.getStep(i);
//!   console.log(`Step ${i}: ${step.name} (db_id=${step.dbId})`);
//! }
//! ```

use wasm_bindgen::prelude::*;
use pir_sdk::{
    DatabaseCatalog, DatabaseInfo, DatabaseKind, QueryResult, SyncPlan, SyncStep, UtxoEntry,
};

// ─── Helpers ────────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// ─── Database Catalog ───────────────────────────────────────────────────────

/// WASM wrapper for DatabaseCatalog.
#[wasm_bindgen]
pub struct WasmDatabaseCatalog {
    inner: DatabaseCatalog,
}

#[wasm_bindgen]
impl WasmDatabaseCatalog {
    /// Create an empty catalog.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: DatabaseCatalog::new(),
        }
    }

    /// Create a catalog from JSON.
    ///
    /// Expected format:
    /// ```json
    /// {
    ///   "databases": [
    ///     {
    ///       "dbId": 0,
    ///       "dbType": 0,  // 0 = full, 1 = delta
    ///       "name": "main",
    ///       "baseHeight": 0,
    ///       "height": 900000,
    ///       "indexBins": 750000,
    ///       "chunkBins": 1500000,
    ///       "indexK": 75,
    ///       "chunkK": 80,
    ///       "tagSeed": "0x123456789abcdef0"
    ///     }
    ///   ]
    /// }
    /// ```
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &JsValue) -> Result<WasmDatabaseCatalog, JsError> {
        let data: serde_json::Value = serde_wasm_bindgen::from_value(json.clone())
            .map_err(|e| JsError::new(&format!("JSON parse error: {}", e)))?;

        let databases_arr = data
            .get("databases")
            .and_then(|d| d.as_array())
            .ok_or_else(|| JsError::new("missing 'databases' array"))?;

        let mut databases = Vec::with_capacity(databases_arr.len());

        for db_val in databases_arr {
            let db_id = db_val
                .get("dbId")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u8;
            let db_type = db_val
                .get("dbType")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let base_height = db_val
                .get("baseHeight")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let height = db_val
                .get("height")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;

            let kind = if db_type == 0 {
                DatabaseKind::Full
            } else {
                DatabaseKind::Delta { base_height }
            };

            databases.push(DatabaseInfo {
                db_id,
                kind,
                name: db_val
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                height,
                index_bins: db_val
                    .get("indexBins")
                    .or_else(|| db_val.get("indexBinsPerTable"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                chunk_bins: db_val
                    .get("chunkBins")
                    .or_else(|| db_val.get("chunkBinsPerTable"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                index_k: db_val
                    .get("indexK")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(75) as u8,
                chunk_k: db_val
                    .get("chunkK")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(80) as u8,
                tag_seed: parse_tag_seed(db_val.get("tagSeed")),
                dpf_n_index: db_val
                    .get("dpfNIndex")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(17) as u8,
                dpf_n_chunk: db_val
                    .get("dpfNChunk")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(18) as u8,
                has_bucket_merkle: db_val
                    .get("hasBucketMerkle")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            });
        }

        Ok(WasmDatabaseCatalog {
            inner: DatabaseCatalog { databases },
        })
    }

    /// Number of databases in the catalog.
    #[wasm_bindgen(getter)]
    pub fn count(&self) -> usize {
        self.inner.databases.len()
    }

    /// Get latest tip height.
    #[wasm_bindgen(getter, js_name = latestTip)]
    pub fn latest_tip(&self) -> Option<u32> {
        self.inner.latest_tip()
    }

    /// Get database info as JSON.
    #[wasm_bindgen(js_name = getDatabase)]
    pub fn get_database(&self, index: usize) -> JsValue {
        if index >= self.inner.databases.len() {
            return JsValue::NULL;
        }
        let db = &self.inner.databases[index];
        let json = serde_json::json!({
            "dbId": db.db_id,
            "dbType": if db.kind.is_full() { 0 } else { 1 },
            "name": db.name,
            "baseHeight": db.base_height(),
            "height": db.height,
            "indexBins": db.index_bins,
            "chunkBins": db.chunk_bins,
            "indexK": db.index_k,
            "chunkK": db.chunk_k,
        });
        serde_wasm_bindgen::to_value(&json).unwrap_or(JsValue::NULL)
    }

    /// Convert to JSON.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> JsValue {
        let databases: Vec<serde_json::Value> = self
            .inner
            .databases
            .iter()
            .map(|db| {
                serde_json::json!({
                    "dbId": db.db_id,
                    "dbType": if db.kind.is_full() { 0 } else { 1 },
                    "name": db.name,
                    "baseHeight": db.base_height(),
                    "height": db.height,
                    "indexBins": db.index_bins,
                    "chunkBins": db.chunk_bins,
                    "indexK": db.index_k,
                    "chunkK": db.chunk_k,
                    "tagSeed": format!("0x{:016x}", db.tag_seed),
                    "dpfNIndex": db.dpf_n_index,
                    "dpfNChunk": db.dpf_n_chunk,
                    "hasBucketMerkle": db.has_bucket_merkle,
                })
            })
            .collect();
        serde_wasm_bindgen::to_value(&serde_json::json!({ "databases": databases }))
            .unwrap_or(JsValue::NULL)
    }
}

fn parse_tag_seed(v: Option<&serde_json::Value>) -> u64 {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => {
            if let Some(hex) = s.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).unwrap_or(0)
            } else {
                s.parse().unwrap_or(0)
            }
        }
        _ => 0,
    }
}

// ─── Sync Plan ──────────────────────────────────────────────────────────────

/// WASM wrapper for SyncPlan.
#[wasm_bindgen]
pub struct WasmSyncPlan {
    inner: SyncPlan,
}

#[wasm_bindgen]
impl WasmSyncPlan {
    /// Number of steps in the plan.
    #[wasm_bindgen(getter, js_name = stepsCount)]
    pub fn steps_count(&self) -> usize {
        self.inner.steps.len()
    }

    /// Whether this is a fresh sync.
    #[wasm_bindgen(getter, js_name = isFreshSync)]
    pub fn is_fresh_sync(&self) -> bool {
        self.inner.is_fresh_sync
    }

    /// Target height after sync.
    #[wasm_bindgen(getter, js_name = targetHeight)]
    pub fn target_height(&self) -> u32 {
        self.inner.target_height
    }

    /// Whether the plan is empty (already at tip).
    #[wasm_bindgen(getter, js_name = isEmpty)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get a step by index.
    #[wasm_bindgen(js_name = getStep)]
    pub fn get_step(&self, index: usize) -> JsValue {
        if index >= self.inner.steps.len() {
            return JsValue::NULL;
        }
        let step = &self.inner.steps[index];
        let json = serde_json::json!({
            "dbId": step.db_id,
            "dbType": if step.is_full() { "full" } else { "delta" },
            "name": step.name,
            "baseHeight": step.base_height,
            "tipHeight": step.tip_height,
        });
        serde_wasm_bindgen::to_value(&json).unwrap_or(JsValue::NULL)
    }

    /// Get all steps as JSON array.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> JsValue {
        let steps: Vec<serde_json::Value> = self
            .inner
            .steps
            .iter()
            .map(|step| {
                serde_json::json!({
                    "dbId": step.db_id,
                    "dbType": if step.is_full() { "full" } else { "delta" },
                    "name": step.name,
                    "baseHeight": step.base_height,
                    "tipHeight": step.tip_height,
                })
            })
            .collect();
        serde_wasm_bindgen::to_value(&serde_json::json!({
            "steps": steps,
            "isFreshSync": self.inner.is_fresh_sync,
            "targetHeight": self.inner.target_height,
        }))
        .unwrap_or(JsValue::NULL)
    }
}

// ─── Compute Sync Plan ──────────────────────────────────────────────────────

/// Compute an optimal sync plan from the catalog.
///
/// # Arguments
/// * `catalog` - Database catalog from server
/// * `last_synced_height` - Last synced height (0 or undefined for fresh sync)
///
/// # Returns
/// A WasmSyncPlan with steps to execute.
#[wasm_bindgen(js_name = computeSyncPlan)]
pub fn compute_sync_plan(
    catalog: &WasmDatabaseCatalog,
    last_synced_height: Option<u32>,
) -> Result<WasmSyncPlan, JsError> {
    let plan = pir_sdk::compute_sync_plan(&catalog.inner, last_synced_height)
        .map_err(|e| JsError::new(&format!("sync plan error: {}", e)))?;
    Ok(WasmSyncPlan { inner: plan })
}

// ─── Query Result ───────────────────────────────────────────────────────────

/// WASM wrapper for QueryResult.
#[wasm_bindgen]
pub struct WasmQueryResult {
    inner: QueryResult,
}

#[wasm_bindgen]
impl WasmQueryResult {
    /// Create an empty result.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: QueryResult::empty(),
        }
    }

    /// Create from JSON.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &JsValue) -> Result<WasmQueryResult, JsError> {
        let data: serde_json::Value = serde_wasm_bindgen::from_value(json.clone())
            .map_err(|e| JsError::new(&format!("JSON parse error: {}", e)))?;

        let entries_arr = data
            .get("entries")
            .and_then(|e| e.as_array())
            .ok_or_else(|| JsError::new("missing 'entries' array"))?;

        let mut entries = Vec::with_capacity(entries_arr.len());
        for entry_val in entries_arr {
            let txid_hex = entry_val
                .get("txid")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let txid_bytes = hex_decode(txid_hex)
                .map_err(|e| JsError::new(&format!("invalid txid hex: {}", e)))?;
            let mut txid = [0u8; 32];
            if txid_bytes.len() == 32 {
                txid.copy_from_slice(&txid_bytes);
            }

            entries.push(UtxoEntry {
                txid,
                vout: entry_val
                    .get("vout")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                amount_sats: entry_val
                    .get("amount")
                    .or_else(|| entry_val.get("amountSats"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            });
        }

        let is_whale = data
            .get("isWhale")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Default `merkleVerified` to `true` when absent — matches the
        // "no failure detected" semantics of `QueryResult::with_entries`.
        // JS callers that want to round-trip failed results must pass the
        // flag explicitly.
        let merkle_verified = data
            .get("merkleVerified")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        Ok(WasmQueryResult {
            inner: QueryResult {
                entries,
                is_whale,
                merkle_verified,
                raw_chunk_data: None,
            },
        })
    }

    /// Number of UTXO entries.
    #[wasm_bindgen(getter, js_name = entryCount)]
    pub fn entry_count(&self) -> usize {
        self.inner.entries.len()
    }

    /// Total balance in satoshis.
    #[wasm_bindgen(getter, js_name = totalBalance)]
    pub fn total_balance(&self) -> u64 {
        self.inner.total_balance()
    }

    /// Whether this is a whale address.
    #[wasm_bindgen(getter, js_name = isWhale)]
    pub fn is_whale(&self) -> bool {
        self.inner.is_whale
    }

    /// Whether the per-bucket Merkle proof verified for this result.
    ///
    /// `true` means the proof passed or the database doesn't publish
    /// Merkle commitments (no failure detected). `false` means
    /// verification was attempted and FAILED; the result should be
    /// treated as untrusted.
    #[wasm_bindgen(getter, js_name = merkleVerified)]
    pub fn merkle_verified(&self) -> bool {
        self.inner.merkle_verified
    }

    /// Get entry at index as JSON.
    #[wasm_bindgen(js_name = getEntry)]
    pub fn get_entry(&self, index: usize) -> JsValue {
        if index >= self.inner.entries.len() {
            return JsValue::NULL;
        }
        let entry = &self.inner.entries[index];
        let json = serde_json::json!({
            "txid": hex_encode(&entry.txid),
            "vout": entry.vout,
            "amountSats": entry.amount_sats,
        });
        serde_wasm_bindgen::to_value(&json).unwrap_or(JsValue::NULL)
    }

    /// Convert to JSON.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> JsValue {
        let entries: Vec<serde_json::Value> = self
            .inner
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "txid": hex_encode(&e.txid),
                    "vout": e.vout,
                    "amountSats": e.amount_sats,
                })
            })
            .collect();
        serde_wasm_bindgen::to_value(&serde_json::json!({
            "entries": entries,
            "isWhale": self.inner.is_whale,
            "totalBalance": self.inner.total_balance(),
            "merkleVerified": self.inner.merkle_verified,
        }))
        .unwrap_or(JsValue::NULL)
    }
}

// ─── Delta Merging ──────────────────────────────────────────────────────────

/// Decode delta data from raw bytes.
///
/// Returns JSON with `spent` (array of outpoint hex strings) and
/// `newUtxos` (array of UTXO entries).
#[wasm_bindgen(js_name = decodeDeltaData)]
pub fn decode_delta_data(raw: &[u8]) -> Result<JsValue, JsError> {
    let delta = pir_sdk::decode_delta_data(raw)
        .map_err(|e| JsError::new(&format!("decode error: {}", e)))?;

    let spent: Vec<String> = delta.spent.iter().map(|op| hex_encode(op)).collect();

    let new_utxos: Vec<serde_json::Value> = delta
        .new_utxos
        .iter()
        .map(|e| {
            serde_json::json!({
                "txid": hex_encode(&e.txid),
                "vout": e.vout,
                "amountSats": e.amount_sats,
            })
        })
        .collect();

    Ok(
        serde_wasm_bindgen::to_value(&serde_json::json!({
            "spent": spent,
            "newUtxos": new_utxos,
        }))
        .unwrap_or(JsValue::NULL),
    )
}

/// Merge delta into a snapshot result.
///
/// # Arguments
/// * `snapshot` - The snapshot QueryResult
/// * `delta_raw` - Raw delta chunk data bytes
///
/// # Returns
/// A new WasmQueryResult with the delta applied.
#[wasm_bindgen(js_name = mergeDelta)]
pub fn merge_delta(
    snapshot: &WasmQueryResult,
    delta_raw: &[u8],
) -> Result<WasmQueryResult, JsError> {
    let merged = pir_sdk::merge_delta(&snapshot.inner, delta_raw)
        .map_err(|e| JsError::new(&format!("merge error: {}", e)))?;
    Ok(WasmQueryResult { inner: merged })
}

// ─── Hash Functions (re-exported from pir-core) ─────────────────────────────

/// Splitmix64 finalizer. Returns 8 bytes (LE).
#[wasm_bindgen]
pub fn splitmix64(x_hi: u32, x_lo: u32) -> Vec<u8> {
    let x = ((x_hi as u64) << 32) | (x_lo as u64);
    pir_core::hash::splitmix64(x).to_le_bytes().to_vec()
}

/// Compute fingerprint tag. Returns 8 bytes (LE).
#[wasm_bindgen(js_name = computeTag)]
pub fn compute_tag(tag_seed_hi: u32, tag_seed_lo: u32, script_hash: &[u8]) -> Vec<u8> {
    let seed = ((tag_seed_hi as u64) << 32) | (tag_seed_lo as u64);
    pir_core::hash::compute_tag(seed, script_hash)
        .to_le_bytes()
        .to_vec()
}

/// Derive 3 group indices for a script hash.
#[wasm_bindgen(js_name = deriveGroups)]
pub fn derive_groups(script_hash: &[u8], k: u32) -> Vec<u32> {
    let groups = pir_core::hash::derive_groups_3(script_hash, k as usize);
    groups.iter().map(|&b| b as u32).collect()
}

/// Derive cuckoo hash key. Returns 8 bytes (LE).
#[wasm_bindgen(js_name = deriveCuckooKey)]
pub fn derive_cuckoo_key(
    master_seed_hi: u32,
    master_seed_lo: u32,
    group_id: u32,
    hash_fn: u32,
) -> Vec<u8> {
    let seed = ((master_seed_hi as u64) << 32) | (master_seed_lo as u64);
    pir_core::hash::derive_cuckoo_key(seed, group_id as usize, hash_fn as usize)
        .to_le_bytes()
        .to_vec()
}

/// Cuckoo hash a script hash.
#[wasm_bindgen(js_name = cuckooHash)]
pub fn cuckoo_hash(script_hash: &[u8], key_hi: u32, key_lo: u32, num_bins: u32) -> u32 {
    let key = ((key_hi as u64) << 32) | (key_lo as u64);
    pir_core::hash::cuckoo_hash(script_hash, key, num_bins as usize) as u32
}

/// Derive 3 group indices for a chunk ID.
#[wasm_bindgen(js_name = deriveChunkGroups)]
pub fn derive_chunk_groups(chunk_id: u32, k: u32) -> Vec<u32> {
    let groups = pir_core::hash::derive_int_groups_3(chunk_id, k as usize);
    groups.iter().map(|&b| b as u32).collect()
}

/// Cuckoo hash an integer chunk ID.
#[wasm_bindgen(js_name = cuckooHashInt)]
pub fn cuckoo_hash_int(chunk_id: u32, key_hi: u32, key_lo: u32, num_bins: u32) -> u32 {
    let key = ((key_hi as u64) << 32) | (key_lo as u64);
    pir_core::hash::cuckoo_hash_int(chunk_id, key, num_bins as usize) as u32
}

// ─── PBC Utilities ──────────────────────────────────────────────────────────

/// Cuckoo-place items into groups.
#[wasm_bindgen(js_name = cuckooPlace)]
pub fn cuckoo_place(
    cand_groups_flat: &[u32],
    num_items: u32,
    num_groups: u32,
    max_kicks: u32,
    num_hashes: u32,
) -> Vec<i32> {
    let ni = num_items as usize;
    let nh = num_hashes as usize;
    let nb = num_groups as usize;

    let cand_groups: Vec<Vec<usize>> = (0..ni)
        .map(|i| {
            (0..nh)
                .map(|h| cand_groups_flat[i * nh + h] as usize)
                .collect()
        })
        .collect();

    let mut group_owner: Vec<Option<usize>> = vec![None; nb];

    for qi in 0..ni {
        let saved = group_owner.clone();
        if !pir_core::pbc::pbc_cuckoo_place(
            &cand_groups,
            &mut group_owner,
            qi,
            max_kicks as usize,
            nh,
        ) {
            group_owner = saved;
        }
    }

    let mut assignments = vec![-1i32; ni];
    for (b, owner) in group_owner.iter().enumerate() {
        if let Some(qi) = owner {
            assignments[*qi] = b as i32;
        }
    }
    assignments
}

/// Plan multi-round PBC placement. Returns JSON.
#[wasm_bindgen(js_name = planRounds)]
pub fn plan_rounds(
    item_groups_flat: &[u32],
    items_per: u32,
    num_groups: u32,
    num_hashes: u32,
    max_kicks: u32,
) -> JsValue {
    let ip = items_per as usize;
    let num_items = item_groups_flat.len() / ip;

    let item_groups: Vec<Vec<usize>> = (0..num_items)
        .map(|i| {
            (0..ip)
                .map(|h| item_groups_flat[i * ip + h] as usize)
                .collect()
        })
        .collect();

    let rounds = pir_core::pbc::pbc_plan_rounds(
        &item_groups,
        num_groups as usize,
        num_hashes as usize,
        max_kicks as usize,
    );

    let json_rounds: Vec<Vec<[usize; 2]>> = rounds
        .iter()
        .map(|round| round.iter().map(|&(item, group)| [item, group]).collect())
        .collect();

    serde_wasm_bindgen::to_value(&json_rounds).unwrap_or(JsValue::NULL)
}

// ─── Varint Codec ───────────────────────────────────────────────────────────

/// Read a LEB128 varint. Returns [value_lo, value_hi, bytes_consumed].
#[wasm_bindgen(js_name = readVarint)]
pub fn read_varint(data: &[u8], offset: u32) -> Vec<u32> {
    let slice = &data[offset as usize..];
    let (value, consumed) = pir_core::codec::read_varint(slice);
    vec![value as u32, (value >> 32) as u32, consumed as u32]
}

/// Decode UTXO data from bytes. Returns JSON array.
#[wasm_bindgen(js_name = decodeUtxoData)]
pub fn decode_utxo_data(data: &[u8]) -> JsValue {
    let entries = pir_core::codec::parse_utxo_data(data);
    let json_entries: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "txid": hex_encode(&e.txid),
                "vout": e.vout,
                "amount": e.amount,
            })
        })
        .collect();
    serde_wasm_bindgen::to_value(&json_entries).unwrap_or(JsValue::NULL)
}
