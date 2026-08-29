use crate::cli::ServerRole;
use crate::harmony_hints::{harmony_batch_response, harmony_query_response};
use crate::onion::{OnionPirInfo, OnionPirMerkleInfo, PirCommand};
#[cfg(feature = "cuckoo-oram")]
use crate::oram::{
    direct_oram_response_padding_bytes, CuckooNativeLookupConfig, CuckooOramTables,
    DirectOramTables,
};
#[cfg(feature = "cuckoo-oram")]
use crate::unsafe_debug_log;
use libdpf::DpfKey;
use pir_core::params;
use rayon::prelude::*;
use runtime::eval::{self, GroupTiming};
use runtime::hint_pool;
use runtime::protocol::*;
use runtime::table::{DatabaseType, MappedDatabase, MappedSubTable, ServerState};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

// ─── Server state ───────────────────────────────────────────────────────────

/// A pool entry that has been "claimed" by one half of a V2-half session
/// and is waiting for the matching second half. Stored under the
/// client-supplied 16-byte `session_token` in
/// [`UnifiedServerData::v2_half_pending`].
///
/// The entry is held shared (`Arc`) because the half-stream serve loop
/// only reads from it; once both halves have been served, the entry is
/// simply dropped (the pool refills lazily).
pub(crate) struct V2HalfPending {
    /// Exact pool/database selected by the first half using this token.
    pub(crate) db_id: u8,
    /// The pool entry feeding both halves of this session. Shared so
    /// the second half's serve loop can read its frames without
    /// having to coordinate with the first half's lifetime.
    pub(crate) entry: Arc<hint_pool::PoolEntry>,
    /// Bitmask of sides already served (bit 0 = side 0 / INDEX,
    /// bit 1 = side 1 / CHUNK). Used to reject duplicate requests
    /// for the same side on the same token, and to determine when
    /// the entry can be evicted.
    pub(crate) sides_served: u8,
    /// When this token was first seen. Used by the cleanup task to
    /// expire lone entries.
    pub(crate) created_at: Instant,
}

/// TTL for a lone V2-half pending entry. Generous enough to absorb a
/// straggling second-half request from a flaky client, short enough
/// that orphaned entries don't deplete the pool. The pool fills at a
/// rate roughly determined by `--pool-size` × the generator's hint
/// computation throughput (a few entries / sec on the i7-8700), so
/// 30 s × that rate ≈ 100 entries is a safe steady-state bound on
/// the pending map.
pub(crate) const V2_HALF_PENDING_TTL_SECS: u64 = 30;

pub(crate) struct UnifiedServerData {
    pub(crate) state: ServerState,
    pub(crate) role: ServerRole,
    /// OnionPIR worker channels indexed by db_id.
    /// Each entry is `None` if that DB has no OnionPIR data (or if secondary role).
    /// Length matches `state.databases.len()`.
    pub(crate) onionpir_txs: Vec<Option<Arc<mpsc::Sender<PirCommand>>>>,
    /// Per-DB OnionPIR parameters (None if that DB has no OnionPIR data).
    /// Length matches `state.databases.len()`.
    pub(crate) onionpir_infos: Vec<Option<OnionPirInfo>>,
    /// OnionPIR per-bin Merkle info indexed by db_id.
    /// Each entry is `None` if that DB has no OnionPIR Merkle data (no
    /// `merkle_onion_*` sibling / root / tree-top files on disk).
    /// Length matches `state.databases.len()`.
    pub(crate) onionpir_merkle: Vec<Option<OnionPirMerkleInfo>>,
    /// Admin auth config — `Some` when the operator started the server with
    /// `--admin-pubkey-hex <hex>`. `None` means REQ_ADMIN_* requests fail.
    pub(crate) admin_config: Option<pir_runtime_core::admin::AdminConfig>,
    /// Data root for admin DB uploads: the directory `databases.toml`
    /// lives in (or `data_dir` for legacy invocations). Staging dirs
    /// land at `<data_root>/.staging/<name>/` and ACTIVATE renames into
    /// `<data_root>/<target_path>/`.
    pub(crate) data_root: PathBuf,
    /// Long-lived X25519 keypair for the inner encrypted channel
    /// (cloudflared-blind WSS frames). Generated inside the SEV-SNP
    /// guest at startup; the public half is committed to REPORT_DATA
    /// via `pir_core::attest::build_report_data` (V2). The secret half
    /// is consumed by per-connection handshakes via
    /// `channel_keypair.new_handshake()` in the dispatch loop's
    /// REQ_HANDSHAKE branch.
    pub(crate) channel_keypair: pir_runtime_core::channel::ChannelKeypair,
    /// Pre-computed HarmonyPIR V2 hint pools indexed by exact database ID.
    /// Empty when `--pool-size=0`.
    pub(crate) hint_pools: BTreeMap<u8, hint_pool::HintPool>,
    /// Optional legacy ORAM-backed INDEX/CHUNK cuckoo-table access indexed by
    /// db_id. This is kept only as a compatibility fallback for
    /// REQ_ORAM_LOOKUP; HarmonyPIR queries stay mmap-backed so ORAM state
    /// mutation cannot interfere with the ordinary PBC service path.
    #[cfg(feature = "cuckoo-oram")]
    pub(crate) cuckoo_oram: HashMap<u8, CuckooOramTables>,
    /// Optional direct-entry ORAM lookup tables indexed by db_id. These bypass
    /// the PBC-expanded cuckoo DB entirely and are used only by REQ_ORAM_LOOKUP.
    #[cfg(feature = "cuckoo-oram")]
    pub(crate) direct_oram: HashMap<u8, DirectOramTables>,
    /// Pending half-stream pool entries, keyed by client-supplied
    /// session token. The first arriving half of a logical V2-half
    /// session allocates a pool entry into this map; the second
    /// arriving half consumes the matching slot and clears the entry.
    /// Lone entries (one half arrives, the other never does) are
    /// garbage-collected by a background tokio task after 30 s.
    ///
    /// Wrapped in `tokio::sync::Mutex` because both the per-connection
    /// dispatch loop (under `tokio::main`) and the cleanup task touch
    /// it. The map itself is small (typically <16 pending entries at
    /// any moment), so lock contention is negligible vs the network
    /// IO it gates.
    pub(crate) v2_half_pending: Arc<tokio::sync::Mutex<HashMap<[u8; 16], V2HalfPending>>>,
    /// ARC presentation verifier + seen-tag set. Wrapped in a Mutex because
    /// `verify()` mutates the per-context tag set. `None` if ARC is disabled
    /// (server started without --require-arc).
    pub(crate) arc_verifier: Option<std::sync::Mutex<pir_runtime_core::arc_verifier::ArcVerifier>>,
    /// Whether ARC credential presentation is required for PIR queries.
    pub(crate) require_arc: bool,
    /// Cashu blind auth verifier.
    pub(crate) cashu_verifier:
        Option<std::sync::Mutex<pir_runtime_core::cashu_verifier::CashuVerifier>>,
    /// Whether Cashu BAT presentation is required for PIR queries.
    pub(crate) require_cashu: bool,
    /// Whether this server accepts `REQ_HARMONY_HINTS` /
    /// `REQ_HARMONY_HINTS_V2` opcodes (set via `--serve-hints`).
    /// Mirrors `CliArgs::serve_hints`. Gated in the dispatch loop.
    pub(crate) serve_hints: bool,
    /// Whether this server accepts PIR query opcodes (DPF + OnionPIR +
    /// HarmonyPIR query phase). Mirrors `CliArgs::serve_queries`.
    pub(crate) serve_queries: bool,
}

impl UnifiedServerData {
    /// Main UTXO database (db_id=0). Always present.
    pub(crate) fn main_db(&self) -> &MappedDatabase {
        self.state.get_db(0).expect("main database must be loaded")
    }

    /// Whether ANY database has OnionPIR data loaded (used as a request guard).
    pub(crate) fn has_any_onionpir(&self) -> bool {
        self.onionpir_txs.iter().any(|t| t.is_some())
    }

    /// Look up the OnionPIR worker channel for a specific db_id.
    /// Returns `None` if the db_id is out of range or if that DB has no OnionPIR data.
    pub(crate) fn onionpir_tx_for(&self, db_id: u8) -> Option<&Arc<mpsc::Sender<PirCommand>>> {
        self.onionpir_txs
            .get(db_id as usize)
            .and_then(|o| o.as_ref())
    }

    /// Look up the OnionPIR per-bin Merkle info for a specific db_id.
    /// Returns `None` if the db_id is out of range or if that DB has no Merkle data.
    pub(crate) fn onionpir_merkle_for(&self, db_id: u8) -> Option<&OnionPirMerkleInfo> {
        self.onionpir_merkle
            .get(db_id as usize)
            .and_then(|o| o.as_ref())
    }

    /// Whether ANY database has OnionPIR Merkle data loaded.
    pub(crate) fn has_any_onionpir_merkle(&self) -> bool {
        self.onionpir_merkle.iter().any(|m| m.is_some())
    }
}

impl UnifiedServerData {
    /// Append a single `OnionPirMerkleInfo` object to `json` preceded by
    /// `prefix`. Per-group schema (Phase 3): `arity`, `super_root`, the
    /// shared 155-tree tree-top blob's hash/size, and per-kind `{k,num_pt}`
    /// for the INDEX and DATA per-group sibling DBs.
    pub(crate) fn append_onionpir_merkle_json(
        json: &mut String,
        prefix: &str,
        om: &OnionPirMerkleInfo,
    ) {
        json.push_str(prefix);
        let top_hash = pir_core::merkle::sha256(&om.tree_tops);
        json.push_str(&format!(
            r#"{{"arity":{},"super_root":"{}","tree_tops_hash":"{}","tree_tops_size":{}"#,
            om.arity,
            om.super_root_hex,
            top_hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            om.tree_tops.len(),
        ));
        json.push_str(&format!(
            r#","index":{{"k":{},"num_pt":{}}},"data":{{"k":{},"num_pt":{}}}}}"#,
            om.index_k, om.index_num_pt, om.data_k, om.data_num_pt,
        ));
    }

    pub(crate) fn server_info(&self) -> ServerInfo {
        ServerInfo {
            index_bins_per_table: self.main_db().index.bins_per_table as u32,
            chunk_bins_per_table: self.main_db().chunk.bins_per_table as u32,
            index_k: self.main_db().index.params.k as u8,
            chunk_k: self.main_db().chunk.params.k as u8,
            tag_seed: self.main_db().index.tag_seed,
            index_master_seed: self.main_db().index.master_seed,
            chunk_master_seed: self.main_db().chunk.master_seed,
            anchor: self.main_db().index.anchor,
        }
    }

    /// Build a JSON server info string covering all protocols.
    pub(crate) fn server_info_json(&self) -> String {
        let mut json = format!(
            r#"{{"index_bins_per_table":{},"chunk_bins_per_table":{},"index_k":{},"chunk_k":{},"tag_seed":"0x{:016x}","index_dpf_n":{},"chunk_dpf_n":{},"index_slots_per_bin":{},"index_slot_size":{},"chunk_slots_per_bin":{},"chunk_slot_size":{},"role":"{}""#,
            self.main_db().index.bins_per_table,
            self.main_db().chunk.bins_per_table,
            self.main_db().index.params.k,
            self.main_db().chunk.params.k,
            self.main_db().index.tag_seed,
            params::compute_dpf_n(self.main_db().index.bins_per_table),
            params::compute_dpf_n(self.main_db().chunk.bins_per_table),
            self.main_db().index.params.slots_per_bin,
            self.main_db().index.params.slot_size,
            self.main_db().chunk.params.slots_per_bin,
            self.main_db().chunk.params.slot_size,
            match self.role {
                ServerRole::Primary => "primary",
                ServerRole::Secondary => "secondary",
            },
        );

        if let Some(Some(ref opi)) = self.onionpir_infos.first() {
            json.push_str(&format!(
                r#","onionpir":{{"total_packed_entries":{},"index_bins_per_table":{},"chunk_bins_per_table":{},"tag_seed":"0x{:016x}","index_master_seed":"0x{:016x}","chunk_master_seed":"0x{:016x}","index_k":{},"chunk_k":{},"index_slots_per_bin":{},"index_slot_size":{},"chunk_slots_per_bin":1,"chunk_slot_size":{}}}"#,
                opi.total_packed_entries, opi.index_bins_per_table, opi.chunk_bins_per_table,
                opi.tag_seed, opi.index_master_seed, opi.chunk_master_seed,
                opi.index_k, opi.chunk_k,
                opi.index_slots_per_bin, opi.index_slot_size,
                3840, // PACKED_ENTRY_SIZE = 3.75KB fixed bin size for OnionPIR chunks
            ));
        }

        // Top-level `onionpir_merkle` reflects the main DB (db_id=0) for
        // backward compatibility with clients that only look at the main
        // entry. Per-DB Merkle is also emitted under `databases[]` below.
        if let Some(om) = self.onionpir_merkle_for(0) {
            Self::append_onionpir_merkle_json(&mut json, ",\"onionpir_merkle\":", om);
        }

        // Legacy global N-ary tree Merkle ("merkle":{…}) removed — the
        // per-bucket bin Merkle below ("merkle_bucket":{…}) is the active
        // scheme. No DB carries N-ary Merkle data anymore.

        // Per-bucket bin Merkle info
        if self.main_db().has_bucket_merkle() {
            json.push_str(r#","merkle_bucket":{"arity":8,"#);

            // INDEX sibling levels
            json.push_str(r#""index_levels":["#);
            for (i, sib) in self
                .main_db()
                .bucket_merkle_index_siblings
                .iter()
                .enumerate()
            {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!(
                    r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                    params::compute_dpf_n(sib.bins_per_table),
                    sib.bins_per_table,
                ));
            }
            json.push_str("],");

            // CHUNK sibling levels
            json.push_str(r#""chunk_levels":["#);
            for (i, sib) in self
                .main_db()
                .bucket_merkle_chunk_siblings
                .iter()
                .enumerate()
            {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!(
                    r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                    params::compute_dpf_n(sib.bins_per_table),
                    sib.bins_per_table,
                ));
            }
            json.push_str("],");

            // Per-group roots as hex arrays
            if let Some(ref roots_data) = self.main_db().bucket_merkle_roots {
                let index_k = self.main_db().index.params.k;
                let chunk_k = self.main_db().chunk.params.k;

                json.push_str(r#""index_roots":["#);
                for g in 0..index_k {
                    if g > 0 {
                        json.push(',');
                    }
                    let root = &roots_data[g * 32..(g + 1) * 32];
                    json.push('"');
                    for b in root {
                        json.push_str(&format!("{:02x}", b));
                    }
                    json.push('"');
                }
                json.push_str("],");

                json.push_str(r#""chunk_roots":["#);
                for g in 0..chunk_k {
                    if g > 0 {
                        json.push(',');
                    }
                    let root = &roots_data[(index_k + g) * 32..(index_k + g + 1) * 32];
                    json.push('"');
                    for b in root {
                        json.push_str(&format!("{:02x}", b));
                    }
                    json.push('"');
                }
                json.push_str("],");
            }

            // Super-root
            if let Some(ref sr) = self.main_db().bucket_merkle_root {
                json.push_str(&format!(
                    r#""super_root":"{}","#,
                    sr.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                ));
            }

            // Tree-tops hash and size
            if let Some(ref tops) = self.main_db().bucket_merkle_tree_tops {
                let tops_hash = pir_core::merkle::sha256(tops);
                json.push_str(&format!(
                    r#""tree_tops_hash":"{}","tree_tops_size":{}"#,
                    tops_hash
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>(),
                    tops.len()
                ));
            }

            json.push('}');
        }

        // Per-database info array (Merkle availability + params for each DB)
        if self.state.databases.len() > 1
            || self.state.databases.iter().any(|db| db.has_bucket_merkle())
            || self.has_any_onionpir_merkle()
        {
            json.push_str(r#","databases":["#);
            for (i, db) in self.state.databases.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                let has_onionpir_merkle = self.onionpir_merkle_for(i as u8).is_some();
                let has_onionpir = self
                    .onionpir_txs
                    .get(i)
                    .map(|o| o.is_some())
                    .unwrap_or(false);
                json.push_str(&format!(
                    r#"{{"db_id":{},"has_bucket_merkle":{},"has_onionpir":{},"has_onionpir_merkle":{}"#,
                    i, db.has_bucket_merkle(), has_onionpir, has_onionpir_merkle
                ));

                // Per-DB OnionPIR parameters (so the web client can switch BFV
                // params when querying a delta with different bins_per_table).
                if let Some(Some(ref opi)) = self.onionpir_infos.get(i) {
                    json.push_str(&format!(
                        r#","onionpir":{{"total_packed_entries":{},"index_bins_per_table":{},"chunk_bins_per_table":{},"tag_seed":"0x{:016x}","index_k":{},"chunk_k":{},"index_slots_per_bin":{},"index_slot_size":{},"chunk_slots_per_bin":1,"chunk_slot_size":{}}}"#,
                        opi.total_packed_entries, opi.index_bins_per_table, opi.chunk_bins_per_table,
                        opi.tag_seed, opi.index_k, opi.chunk_k,
                        opi.index_slots_per_bin, opi.index_slot_size,
                        3840, // PACKED_ENTRY_SIZE
                    ));
                }

                if db.has_bucket_merkle() {
                    json.push_str(r#","merkle_bucket":{"arity":8,"#);

                    // INDEX sibling levels
                    json.push_str(r#""index_levels":["#);
                    for (li, sib) in db.bucket_merkle_index_siblings.iter().enumerate() {
                        if li > 0 {
                            json.push(',');
                        }
                        json.push_str(&format!(
                            r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                            params::compute_dpf_n(sib.bins_per_table),
                            sib.bins_per_table,
                        ));
                    }
                    json.push_str("],");

                    // CHUNK sibling levels
                    json.push_str(r#""chunk_levels":["#);
                    for (li, sib) in db.bucket_merkle_chunk_siblings.iter().enumerate() {
                        if li > 0 {
                            json.push(',');
                        }
                        json.push_str(&format!(
                            r#"{{"dpf_n":{},"bins_per_table":{}}}"#,
                            params::compute_dpf_n(sib.bins_per_table),
                            sib.bins_per_table,
                        ));
                    }
                    json.push_str("],");

                    // Per-group roots
                    if let Some(ref roots_data) = db.bucket_merkle_roots {
                        let index_k = db.index.params.k;
                        let chunk_k = db.chunk.params.k;

                        json.push_str(r#""index_roots":["#);
                        for g in 0..index_k {
                            if g > 0 {
                                json.push(',');
                            }
                            let root = &roots_data[g * 32..(g + 1) * 32];
                            json.push('"');
                            for b in root {
                                json.push_str(&format!("{:02x}", b));
                            }
                            json.push('"');
                        }
                        json.push_str("],");

                        json.push_str(r#""chunk_roots":["#);
                        for g in 0..chunk_k {
                            if g > 0 {
                                json.push(',');
                            }
                            let root = &roots_data[(index_k + g) * 32..(index_k + g + 1) * 32];
                            json.push('"');
                            for b in root {
                                json.push_str(&format!("{:02x}", b));
                            }
                            json.push('"');
                        }
                        json.push_str("],");
                    }

                    if let Some(ref sr) = db.bucket_merkle_root {
                        json.push_str(&format!(
                            r#""super_root":"{}","#,
                            sr.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                        ));
                    }

                    if let Some(ref tops) = db.bucket_merkle_tree_tops {
                        let tops_hash = pir_core::merkle::sha256(tops);
                        json.push_str(&format!(
                            r#""tree_tops_hash":"{}","tree_tops_size":{}"#,
                            tops_hash
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<String>(),
                            tops.len()
                        ));
                    }

                    json.push('}'); // close merkle_bucket
                }

                // Per-DB OnionPIR per-bin Merkle, when this DB has it
                if let Some(om) = self.onionpir_merkle_for(i as u8) {
                    Self::append_onionpir_merkle_json(&mut json, ",\"onionpir_merkle\":", om);
                }

                json.push('}'); // close database entry
            }
            json.push(']'); // close databases array
        }

        json.push('}');
        json
    }

    /// Encode a JSON info response as a length-prefixed binary message.
    pub(crate) fn encode_info_json_response(&self, variant: u8) -> Vec<u8> {
        let json = self.server_info_json();
        let json_bytes = json.as_bytes();
        // Wire: [4B length LE][1B variant][json bytes]
        let payload_len = 1 + json_bytes.len();
        let mut msg = Vec::with_capacity(4 + payload_len);
        msg.extend_from_slice(&(payload_len as u32).to_le_bytes());
        msg.push(variant);
        msg.extend_from_slice(json_bytes);
        msg
    }

    pub(crate) fn build_catalog(&self) -> DatabaseCatalog {
        DatabaseCatalog {
            databases: self
                .state
                .databases
                .iter()
                .enumerate()
                .map(|(i, db)| DatabaseCatalogEntry {
                    db_id: i as u8,
                    db_type: match db.descriptor.db_type {
                        DatabaseType::Full => 0,
                        DatabaseType::Delta => 1,
                    },
                    name: db.descriptor.name.clone(),
                    base_height: db.descriptor.base_height,
                    height: db.descriptor.height,
                    index_bins_per_table: db.index.bins_per_table as u32,
                    chunk_bins_per_table: db.chunk.bins_per_table as u32,
                    index_k: db.index.params.k as u8,
                    chunk_k: db.chunk.params.k as u8,
                    tag_seed: db.index.tag_seed,
                    dpf_n_index: params::compute_dpf_n(db.index.bins_per_table),
                    dpf_n_chunk: params::compute_dpf_n(db.chunk.bins_per_table),
                    has_bucket_merkle: db.has_bucket_merkle(),
                    index_master_seed: db.index.master_seed,
                    chunk_master_seed: db.chunk.master_seed,
                    anchor: db.index.anchor,
                })
                .collect(),
        }
    }

    pub(crate) fn process_index_batch(
        &self,
        query: &BatchQuery,
        db: &MappedDatabase,
    ) -> (BatchResult, std::time::Duration, std::time::Duration) {
        let k = db.index.params.k;
        let num_groups = query.keys.len().min(k);
        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b]
                    .iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = db.index.group_bytes(b);
                let (r0, r1, timing) = eval::process_index_group(
                    key_refs[0],
                    key_refs[1],
                    table_bytes,
                    db.index.bins_per_table,
                );
                (vec![r0, r1], timing)
            })
            .collect();

        let mut total_dpf = std::time::Duration::ZERO;
        let mut total_fetch = std::time::Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }
        (
            BatchResult {
                level: 0,
                round_id: 0,
                results,
            },
            total_dpf,
            total_fetch,
        )
    }

    pub(crate) fn process_chunk_batch(
        &self,
        query: &BatchQuery,
        db: &MappedDatabase,
    ) -> (BatchResult, std::time::Duration, std::time::Duration) {
        let k = db.chunk.params.k;
        let num_groups = query.keys.len().min(k);
        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b]
                    .iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = db.chunk.group_bytes(b);
                let (r, timing) =
                    eval::process_chunk_group(&key_refs, table_bytes, db.chunk.bins_per_table);
                (r, timing)
            })
            .collect();

        let mut total_dpf = std::time::Duration::ZERO;
        let mut total_fetch = std::time::Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }
        (
            BatchResult {
                level: 1,
                round_id: query.round_id,
                results,
            },
            total_dpf,
            total_fetch,
        )
    }

    /// Generic DPF batch evaluation against any MappedSubTable.
    pub(crate) fn process_generic_batch(
        &self,
        query: &BatchQuery,
        table: &MappedSubTable,
    ) -> (BatchResult, std::time::Duration, std::time::Duration) {
        let k = table.params.k;
        let result_size = table.params.bin_size();
        let num_groups = query.keys.len().min(k);

        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b]
                    .iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = table.group_bytes(b);
                let (r, timing) = eval::process_merkle_sibling_group(
                    &key_refs,
                    table_bytes,
                    table.bins_per_table,
                    result_size,
                );
                (r, timing)
            })
            .collect();

        let mut total_dpf = std::time::Duration::ZERO;
        let mut total_fetch = std::time::Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }
        (
            BatchResult {
                level: query.level,
                round_id: query.round_id,
                results,
            },
            total_dpf,
            total_fetch,
        )
    }

    pub(crate) fn handle_harmony_query(&self, query: &HarmonyQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };
        harmony_query_response(db, query)
    }

    pub(crate) fn handle_harmony_batch_query(&self, query: &HarmonyBatchQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };
        harmony_batch_response(db, query)
    }

    pub(crate) fn handle_oram_lookup(&self, query: &OramLookupRequest) -> Response {
        #[cfg(feature = "cuckoo-oram")]
        {
            if self.state.get_db(query.db_id).is_none() {
                return Response::Error(format!("unknown db_id {}", query.db_id));
            }
            if let Some(tables) = self.direct_oram.get(&query.db_id) {
                let t = Instant::now();
                let lookup = match tables.lookup_batch(&query.script_hashes, &query.slot_present) {
                    Ok(v) => v,
                    Err(e) => return Response::Error(format!("Direct ORAM lookup failed: {}", e)),
                };
                unsafe_debug_log!(
                    "[direct-oram-lookup] db={} slots={}, budget={} in {:.2?}",
                    query.db_id,
                    query.script_hashes.len(),
                    tables.access_budget,
                    t.elapsed(),
                );
                let actual_chunk_bytes = lookup.iter().try_fold(0usize, |acc, item| {
                    acc.checked_add(item.raw_chunk_data.len())
                        .ok_or_else(|| "direct ORAM response chunk byte count overflow".to_string())
                });
                let actual_chunk_bytes = match actual_chunk_bytes {
                    Ok(bytes) => bytes,
                    Err(e) => return Response::Error(e),
                };
                let trailing_padding_bytes = match direct_oram_response_padding_bytes(
                    tables.access_budget,
                    query.script_hashes.len(),
                    tables.index.hash_fns,
                    actual_chunk_bytes,
                ) {
                    Ok(bytes) => bytes,
                    Err(e) => return Response::Error(e),
                };
                return Response::OramLookupResult(OramLookupResult {
                    db_id: query.db_id,
                    items: lookup
                        .into_iter()
                        .map(|item| OramLookupItem {
                            found: item.found,
                            whale: item.whale,
                            start_chunk_id: item.start_chunk_id.unwrap_or(0),
                            num_chunks: item.num_chunks,
                            raw_chunk_data: item.raw_chunk_data,
                        })
                        .collect(),
                    trailing_padding_bytes,
                });
            }
            let db = self
                .state
                .get_db(query.db_id)
                .expect("unknown db_id checked above");
            let Some(tables) = self.cuckoo_oram.get(&query.db_id) else {
                return Response::Error(format!(
                    "ORAM not configured for db_id {}; start with --direct-oram-db {}=<dir> or --cuckoo-oram-db {}=<dir>",
                    query.db_id,
                    query.db_id, query.db_id
                ));
            };
            let t = Instant::now();
            if query.present_count() != query.script_hashes.len() {
                return Response::Error(
                    "padded empty ORAM slots require --direct-oram-db; legacy cuckoo ORAM fallback does not support explicit empty slots".into(),
                );
            }
            let lookup = match tables
                .lookup_batch(CuckooNativeLookupConfig::from_db(db), &query.script_hashes)
            {
                Ok(v) => v,
                Err(e) => return Response::Error(format!("ORAM lookup failed: {}", e)),
            };
            unsafe_debug_log!(
                "[oram-lookup] db={} {} scripthash(es) in {:.2?}",
                query.db_id,
                query.script_hashes.len(),
                t.elapsed(),
            );
            Response::OramLookupResult(OramLookupResult {
                db_id: query.db_id,
                items: lookup
                    .into_iter()
                    .map(|item| OramLookupItem {
                        found: item.found,
                        whale: item.whale,
                        start_chunk_id: item.start_chunk_id.unwrap_or(0),
                        num_chunks: item.num_chunks,
                        raw_chunk_data: item.raw_chunk_data,
                    })
                    .collect(),
                trailing_padding_bytes: 0,
            })
        }
        #[cfg(not(feature = "cuckoo-oram"))]
        {
            let _ = query;
            Response::Error(
                "ORAM lookup requires building unified_server with --features cuckoo-oram".into(),
            )
        }
    }
}
