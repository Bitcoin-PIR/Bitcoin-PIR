//! Request handler for PIR protocols.
//!
//! This module provides a reusable `RequestHandler` that processes PIR requests
//! against loaded databases. It can be used by both the `unified_server` binary
//! and the `pir-sdk-server` crate.

use crate::eval::{self, GroupTiming};
use crate::protocol::*;
use crate::table::{MappedDatabase, MappedSubTable, ServerState};
use libdpf::DpfKey;
use pir_core::params;
use rayon::prelude::*;
use std::time::Duration;

/// Parse one group's client-supplied DPF key blobs, rejecting malformed
/// ones instead of panicking (S1). `DpfKey::from_bytes` is not
/// panic-safe on adversarial bytes (`n - 7` u8 underflow for n < 7), so
/// blobs are re-validated here even though `decode_batch_query` already
/// screens wire traffic — handlers are also reachable with
/// programmatically built `Request`s.
fn parse_dpf_keys(group_keys: &[Vec<u8>]) -> Result<Vec<DpfKey>, String> {
    group_keys
        .iter()
        .map(|k| {
            validate_dpf_key_bytes(k).map_err(|e| format!("bad DPF key: {}", e))?;
            DpfKey::from_bytes(k).map_err(|e| format!("bad DPF key: {}", e))
        })
        .collect()
}

/// Handles PIR requests against a set of loaded databases.
pub struct RequestHandler {
    state: ServerState,
}

impl RequestHandler {
    /// Create a new request handler with the given databases. The
    /// channel-encryption pubkey defaults to all-zero — call
    /// [`Self::with_channel_pubkey`] to bind a real key into the V2
    /// REPORT_DATA layout. Production servers (unified_server) MUST
    /// set one; the all-zero default is fine for tests and the
    /// pre-channel transition window.
    pub fn new(databases: Vec<MappedDatabase>) -> Self {
        Self {
            state: ServerState {
                databases,
                server_static_pub: [0u8; 32],
                ark_pem: Vec::new(),
                ask_pem: Vec::new(),
                vcek_pem: Vec::new(),
                announcement_bundle: None,
            },
        }
    }

    /// Install the pre-encoded operator-signed announcement bundle —
    /// the bytes REQ_ANNOUNCE will return verbatim. See
    /// [`crate::identity::build_announcement_bundle`] for how to
    /// produce these bytes. Pass `None` to leave the server in
    /// "unannounced" mode (REQ_ANNOUNCE → RESP_ERROR).
    pub fn with_announcement_bundle(mut self, bundle: Option<Vec<u8>>) -> Self {
        self.state.announcement_bundle = bundle;
        self
    }

    /// Bind the long-lived X25519 channel pubkey the server generated
    /// inside its SEV-SNP guest at startup. The pubkey is committed to
    /// REPORT_DATA via `pir_core::attest::build_report_data`, and
    /// echoed back to clients in `AttestResult::server_static_pub`.
    pub fn with_channel_pubkey(mut self, server_static_pub: [u8; 32]) -> Self {
        self.state.server_static_pub = server_static_pub;
        self
    }

    /// Bundle the AMD VCEK chain (ARK + ASK + VCEK PEMs) into the
    /// server state so every AttestResult includes them. The browser's
    /// `pir-attest-verify` consumes these to chain-validate the SNP
    /// report's ECDSA-P384 signature back to AMD's known root without
    /// having to talk to `kdsintf.amd.com` directly (CORS-blocked).
    ///
    /// Pass empty Vecs to disable — the verifier falls back to V2-
    /// binding-only mode (still proves internal consistency, but no
    /// hardware anchor on the report itself).
    pub fn with_vcek_chain(mut self, ark_pem: Vec<u8>, ask_pem: Vec<u8>, vcek_pem: Vec<u8>) -> Self {
        self.state.ark_pem = ark_pem;
        self.state.ask_pem = ask_pem;
        self.state.vcek_pem = vcek_pem;
        self
    }

    /// Get a database by ID.
    pub fn get_db(&self, db_id: u8) -> Option<&MappedDatabase> {
        self.state.get_db(db_id)
    }

    /// Get the main database (db_id = 0).
    pub fn main_db(&self) -> &MappedDatabase {
        &self.state.databases[0]
    }

    /// Get all databases.
    pub fn databases(&self) -> &[MappedDatabase] {
        &self.state.databases
    }

    /// Build a ServerInfo response.
    pub fn server_info(&self) -> ServerInfo {
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

    /// Build a DatabaseCatalog response.
    pub fn build_catalog(&self) -> DatabaseCatalog {
        DatabaseCatalog {
            databases: self
                .state
                .databases
                .iter()
                .enumerate()
                .map(|(i, db)| DatabaseCatalogEntry {
                    db_id: i as u8,
                    db_type: match db.descriptor.db_type {
                        crate::table::DatabaseType::Full => 0,
                        crate::table::DatabaseType::Delta => 1,
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
                    // Real on-disk cuckoo seeds (chain-derived for v2 DBs,
                    // legacy const for older ones) so the client doesn't
                    // depend on the now-zeroed build-side constant. The
                    // anchor (if any) lets the client verify them.
                    index_master_seed: db.index.master_seed,
                    chunk_master_seed: db.chunk.master_seed,
                    anchor: db.index.anchor,
                })
                .collect(),
        }
    }

    /// Handle a PIR request and return a response.
    pub fn handle_request(&self, request: &Request) -> Response {
        match request {
            Request::Ping => Response::Pong,
            Request::GetInfo => Response::Info(self.server_info()),
            Request::GetDbCatalog => Response::DbCatalog(self.build_catalog()),
            Request::GetDbProof { db_id } => match self
                .state
                .get_db(*db_id)
                .and_then(|db| db.db_proof.as_ref())
            {
                Some(bundle) => Response::DbProof(bundle.clone()),
                None => Response::Error(format!("db proof not configured for db_id {}", db_id)),
            },
            Request::IndexBatch(query) => self.handle_index_batch(query),
            Request::ChunkBatch(query) => self.handle_chunk_batch(query),
            Request::BucketMerkleSibBatch(query) => self.handle_bucket_merkle_sib_batch(query),
            Request::HarmonyGetInfo => Response::HarmonyInfo(self.server_info()),
            Request::HarmonyHints(_) => {
                Response::Error("HarmonyPIR hints not supported in handler".into())
            }
            Request::HarmonyHintsV2(_) => {
                Response::Error("HarmonyPIR V2 hints not supported in handler".into())
            }
            Request::HarmonyHintsV2Half(_) => {
                Response::Error(
                    "HarmonyPIR V2 half-stream hints not supported in handler".into(),
                )
            }
            Request::HarmonyQuery(query) => self.handle_harmony_query(query),
            Request::HarmonyBatchQuery(query) => self.handle_harmony_batch_query(query),
            Request::OramLookup(_) => {
                Response::Error(
                    "ORAM lookup requires unified_server cuckoo-oram state and encrypted-channel gating".into(),
                )
            }
            Request::Attest { nonce } => Response::Attest(self.handle_attest(*nonce)),
            Request::Announce => match &self.state.announcement_bundle {
                Some(bytes) => Response::Announce(bytes.clone()),
                None => Response::Error(
                    "announce not configured: server lacks identity key or operator cert"
                        .into(),
                ),
            },
            // Handshake needs per-connection state to mint a fresh
            // ephemeral keypair, derive the session key, and stash it
            // for subsequent encrypted-frame open/seal. The stateless
            // RequestHandler can't do that — unified_server handles it
            // directly in its per-connection dispatch loop.
            Request::Handshake { .. } => {
                Response::Error(
                    "handshake requires per-connection state — use the unified_server's per-connection path".into(),
                )
            }
            // Admin requests need per-connection state, which the stateless
            // RequestHandler doesn't carry. Binaries that want admin
            // (unified_server) implement these directly in their dispatch
            // loop where per-connection state is naturally available.
            Request::AdminAuthChallenge
            | Request::AdminAuthResponse { .. }
            | Request::AdminDbUploadBegin { .. }
            | Request::AdminDbUploadChunk { .. }
            | Request::AdminDbUploadFinalize { .. }
            | Request::AdminDbActivate { .. } => {
                Response::Error(
                    "admin requests not supported via stateless RequestHandler — use the unified_server's per-connection path".into(),
                )
            }
        }
    }

    /// Build the attestation result for a client-supplied nonce.
    ///
    /// Folds: per-DB manifest roots (zero if no MANIFEST.toml present),
    /// SHA-256 of the running binary (cached), and the build's git rev
    /// into REPORT_DATA. On a SEV-SNP host the kernel signs the report
    /// with the chip's VCEK; on other hosts the `sev_snp_report` is
    /// returned empty.
    pub fn handle_attest(&self, nonce: [u8; 32]) -> AttestResult {
        let manifest_roots: Vec<[u8; 32]> = self
            .state
            .databases
            .iter()
            .map(|db| db.manifest_root.unwrap_or([0u8; 32]))
            .collect();
        let binary_sha256 = crate::attest::self_exe_sha256();
        let git_rev = crate::attest::GIT_REV;
        let server_static_pub = self.state.server_static_pub;
        let report_data = crate::attest::build_report_data(
            nonce,
            &manifest_roots,
            binary_sha256,
            server_static_pub,
            git_rev,
        );
        let sev_snp_report = match crate::attest::fetch_report(report_data) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => Vec::new(),
            Err(e) => {
                eprintln!("[attest] /dev/sev-guest ioctl errored: {}", e);
                Vec::new()
            }
        };
        AttestResult {
            sev_snp_report,
            manifest_roots,
            binary_sha256,
            server_static_pub,
            git_rev: git_rev.to_string(),
            ark_pem: self.state.ark_pem.clone(),
            ask_pem: self.state.ask_pem.clone(),
            vcek_pem: self.state.vcek_pem.clone(),
        }
    }

    /// Handle an index-level DPF batch query.
    fn handle_index_batch(&self, query: &BatchQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        match self.process_index_batch(query, db) {
            Ok((result, _dpf_time, _fetch_time)) => Response::IndexBatch(result),
            Err(msg) => Response::Error(msg),
        }
    }

    /// Handle a chunk-level DPF batch query.
    fn handle_chunk_batch(&self, query: &BatchQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        match self.process_chunk_batch(query, db) {
            Ok((result, _dpf_time, _fetch_time)) => Response::ChunkBatch(result),
            Err(msg) => Response::Error(msg),
        }
    }

    /// Handle a Merkle sibling batch query.
    /// Handle a bucket Merkle sibling batch query.
    fn handle_bucket_merkle_sib_batch(&self, query: &BatchQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        if !db.has_bucket_merkle() {
            return Response::Error("database has no bucket Merkle data".into());
        }

        // level encoding: 0-74 = INDEX sibling L{level/75} group {level%75}
        //                 75-154 = CHUNK sibling L{(level-75)/80} group {(level-75)%80}
        let level = query.level as usize;
        let index_k = db.index.params.k;

        let table = if level < index_k {
            // INDEX sibling, compute L from round_id
            let sib_level = (query.round_id as usize) / 100;
            if sib_level >= db.bucket_merkle_index_siblings.len() {
                return Response::Error(format!(
                    "invalid index sibling level {}",
                    sib_level
                ));
            }
            &db.bucket_merkle_index_siblings[sib_level]
        } else {
            // CHUNK sibling
            let sib_level = (query.round_id as usize) / 100;
            if sib_level >= db.bucket_merkle_chunk_siblings.len() {
                return Response::Error(format!(
                    "invalid chunk sibling level {}",
                    sib_level
                ));
            }
            &db.bucket_merkle_chunk_siblings[sib_level]
        };

        match self.process_generic_batch(query, table) {
            Ok((result, _dpf_time, _fetch_time)) => Response::BucketMerkleSibBatch(result),
            Err(msg) => Response::Error(msg),
        }
    }

    /// Handle a HarmonyPIR query (Query Server role).
    fn handle_harmony_query(&self, query: &HarmonyQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        let (sub_table, entry_size) = match query.level {
            0 => (&db.index, db.index.params.bin_size()),
            1 => (&db.chunk, db.chunk.params.bin_size()),
            _ => return Response::Error("invalid level".into()),
        };

        // S4: group_id comes straight off the wire — bounds-check it
        // before slicing the mmap.
        let group_id = query.group_id as usize;
        let table_bytes = match sub_table.try_group_bytes(group_id) {
            Some(b) => b,
            None => return Response::Error(format!("group_id {} out of range", query.group_id)),
        };

        // S5: validate the index count before allocating. A legitimate
        // query carries T − 1 distinct indices in [0, real_n), so more
        // indices than bins is invalid — reject it instead of reserving
        // indices.len() × entry_size bytes for an attacker-sized list.
        if query.indices.len() > sub_table.bins_per_table {
            return Response::Error(format!(
                "too many indices: {} > bins_per_table {}",
                query.indices.len(),
                sub_table.bins_per_table
            ));
        }

        let mut data = Vec::with_capacity(query.indices.len() * entry_size);
        for &idx in &query.indices {
            let idx_usize = idx as usize;
            if idx_usize >= sub_table.bins_per_table {
                return Response::Error(format!("index {} out of range", idx));
            }
            let offset = idx_usize * entry_size;
            data.extend_from_slice(&table_bytes[offset..offset + entry_size]);
        }

        Response::HarmonyQueryResult(HarmonyQueryResult {
            group_id: query.group_id,
            round_id: query.round_id,
            data,
        })
    }

    /// Handle a HarmonyPIR batch query.
    fn handle_harmony_batch_query(&self, query: &HarmonyBatchQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        let (sub_table, entry_size) = match query.level {
            0 => (&db.index, db.index.params.bin_size()),
            1 => (&db.chunk, db.chunk.params.bin_size()),
            _ => return Response::Error("invalid level".into()),
        };

        let items: Result<Vec<HarmonyBatchResultItem>, String> = query
            .items
            .par_iter()
            .map(|item| {
                // S4: group_id comes straight off the wire — bounds-check
                // it before slicing the mmap.
                let group_id = item.group_id as usize;
                let table_bytes = sub_table.try_group_bytes(group_id).ok_or_else(|| {
                    format!("group_id {} out of range", item.group_id)
                })?;

                let sub_results: Result<Vec<Vec<u8>>, String> = item
                    .sub_queries
                    .iter()
                    .map(|indices| {
                        // S5: validate the index count before allocating
                        // (see handle_harmony_query). Out-of-range indices
                        // within an accepted sub-query are still skipped,
                        // preserving the existing wire behavior.
                        if indices.len() > sub_table.bins_per_table {
                            return Err(format!(
                                "too many indices: {} > bins_per_table {}",
                                indices.len(),
                                sub_table.bins_per_table
                            ));
                        }
                        let mut data = Vec::with_capacity(indices.len() * entry_size);
                        for &idx in indices {
                            let idx_usize = idx as usize;
                            if idx_usize < sub_table.bins_per_table {
                                let offset = idx_usize * entry_size;
                                data.extend_from_slice(&table_bytes[offset..offset + entry_size]);
                            }
                        }
                        Ok(data)
                    })
                    .collect();

                Ok(HarmonyBatchResultItem {
                    group_id: item.group_id,
                    sub_results: sub_results?,
                })
            })
            .collect();

        let items = match items {
            Ok(items) => items,
            Err(msg) => return Response::Error(msg),
        };

        Response::HarmonyBatchResult(HarmonyBatchResult {
            level: query.level,
            round_id: query.round_id,
            sub_results_per_group: query.sub_queries_per_group,
            items,
        })
    }

    // ─── Internal processing methods ────────────────────────────────────────

    fn process_index_batch(
        &self,
        query: &BatchQuery,
        db: &MappedDatabase,
    ) -> Result<(BatchResult, Duration, Duration), String> {
        let k = db.index.params.k;
        let num_groups = query.keys.len().min(k);

        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys = parse_dpf_keys(&query.keys[b])?;
                // Need both cuckoo-position keys: anything less would
                // index key_refs[0]/key_refs[1] out of bounds (S3).
                if dpf_keys.len() < params::INDEX_CUCKOO_NUM_HASHES {
                    return Err(format!(
                        "INDEX group {} carries {} DPF keys, need {}",
                        b,
                        dpf_keys.len(),
                        params::INDEX_CUCKOO_NUM_HASHES
                    ));
                }
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = db.index.group_bytes(b);
                let (r0, r1, timing) = eval::process_index_group(
                    key_refs[0],
                    key_refs[1],
                    table_bytes,
                    db.index.bins_per_table,
                );
                Ok((vec![r0, r1], timing))
            })
            .collect::<Result<_, String>>()?;

        let mut total_dpf = Duration::ZERO;
        let mut total_fetch = Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }

        Ok((
            BatchResult {
                level: 0,
                round_id: 0,
                results,
            },
            total_dpf,
            total_fetch,
        ))
    }

    fn process_chunk_batch(
        &self,
        query: &BatchQuery,
        db: &MappedDatabase,
    ) -> Result<(BatchResult, Duration, Duration), String> {
        let k = db.chunk.params.k;
        let num_groups = query.keys.len().min(k);

        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys = parse_dpf_keys(&query.keys[b])?;
                // The eval fast path tracks per-key bits in a fixed
                // MAX_KEYS_PER_GROUP-slot array (S2).
                if dpf_keys.len() > eval::MAX_KEYS_PER_GROUP {
                    return Err(format!(
                        "group {} carries {} DPF keys, max {}",
                        b,
                        dpf_keys.len(),
                        eval::MAX_KEYS_PER_GROUP
                    ));
                }
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = db.chunk.group_bytes(b);
                let (r, timing) =
                    eval::process_chunk_group(&key_refs, table_bytes, db.chunk.bins_per_table);
                Ok((r, timing))
            })
            .collect::<Result<_, String>>()?;

        let mut total_dpf = Duration::ZERO;
        let mut total_fetch = Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }

        Ok((
            BatchResult {
                level: 1,
                round_id: query.round_id,
                results,
            },
            total_dpf,
            total_fetch,
        ))
    }

    fn process_generic_batch(
        &self,
        query: &BatchQuery,
        table: &MappedSubTable,
    ) -> Result<(BatchResult, Duration, Duration), String> {
        let k = table.params.k;
        let result_size = table.params.bin_size();
        let num_groups = query.keys.len().min(k);

        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys = parse_dpf_keys(&query.keys[b])?;
                // The eval fast path tracks per-key bits in a fixed
                // MAX_KEYS_PER_GROUP-slot array (S2).
                if dpf_keys.len() > eval::MAX_KEYS_PER_GROUP {
                    return Err(format!(
                        "group {} carries {} DPF keys, max {}",
                        b,
                        dpf_keys.len(),
                        eval::MAX_KEYS_PER_GROUP
                    ));
                }
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = table.group_bytes(b);
                let (r, timing) = eval::process_merkle_sibling_group(
                    &key_refs,
                    table_bytes,
                    table.bins_per_table,
                    result_size,
                );
                Ok((r, timing))
            })
            .collect::<Result<_, String>>()?;

        let mut total_dpf = Duration::ZERO;
        let mut total_fetch = Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }

        Ok((
            BatchResult {
                level: query.level,
                round_id: query.round_id,
                results,
            },
            total_dpf,
            total_fetch,
        ))
    }
}

#[cfg(test)]
mod dos_guard_tests {
    use super::*;
    use crate::table::{DatabaseDescriptor, DatabaseType};
    use libdpf::Dpf;
    use pir_core::cuckoo::write_header_with_anchor;
    use pir_core::params::{CHUNK_PARAMS, INDEX_PARAMS};
    use std::io::Write as _;

    /// bins_per_table for the synthetic test DB. 256 → DPF domain
    /// n = 8 (`compute_dpf_n`), comfortably above libdpf's structural
    /// minimum of n = 7.
    const TEST_BINS: usize = 256;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "handler_dos_{}_{}_{}.bin",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    /// Write a legacy (anchor-less) cuckoo file with k groups of
    /// TEST_BINS bins, every byte of bin `b` in group `g` set to
    /// `g ^ b`, then mmap it.
    fn make_subtable(tag: &str, params: pir_core::params::TableParams) -> MappedSubTable {
        let bin_size = params.bin_size();
        let mut bytes = write_header_with_anchor(&params, TEST_BINS, 0, None);
        for g in 0..params.k {
            for bin in 0..TEST_BINS {
                let marker = (g as u8) ^ (bin as u8);
                bytes.extend(std::iter::repeat(marker).take(bin_size));
            }
        }
        let path = temp_path(tag);
        std::fs::File::create(&path).unwrap().write_all(&bytes).unwrap();
        let st = MappedSubTable::load(&path, params);
        // mmap keeps the inode alive; unlink immediately so failing
        // tests don't leak temp files.
        std::fs::remove_file(&path).ok();
        st
    }

    fn make_handler() -> RequestHandler {
        make_handler_with_proof(None)
    }

    fn make_handler_with_proof(db_proof: Option<DatabaseProofBundle>) -> RequestHandler {
        let db = MappedDatabase {
            descriptor: DatabaseDescriptor {
                name: "dos-test".into(),
                db_type: DatabaseType::Full,
                base_height: 0,
                height: 0,
                index_params: INDEX_PARAMS.clone(),
                chunk_params: CHUNK_PARAMS.clone(),
            },
            index: make_subtable("idx", INDEX_PARAMS.clone()),
            chunk: make_subtable("chk", CHUNK_PARAMS.clone()),
            bucket_merkle_index_siblings: Vec::new(),
            bucket_merkle_chunk_siblings: Vec::new(),
            bucket_merkle_tree_tops: None,
            bucket_merkle_roots: None,
            bucket_merkle_root: None,
            manifest_root: None,
            manifest: None,
            db_proof,
        };
        RequestHandler::new(vec![db])
    }

    fn sample_db_proof() -> DatabaseProofBundle {
        DatabaseProofBundle {
            db_id: 0,
            build_evidence: b"evidence".to_vec(),
            root_bundle_payload: b"payload".to_vec(),
            sev_snp_report: b"report".to_vec(),
            database_manifest_sha256: b"database-sha".to_vec(),
            all_artifacts_manifest_sha256: b"all-sha".to_vec(),
            server_db_manifest_toml: b"manifest".to_vec(),
        }
    }

    fn expect_error(resp: Response, needle: &str) {
        match resp {
            Response::Error(msg) => {
                assert!(msg.contains(needle), "error {:?} missing {:?}", msg, needle)
            }
            other => panic!("expected Error, got {:?}", other),
        }
    }

    #[test]
    fn get_db_proof_returns_configured_bundle() {
        let bundle = sample_db_proof();
        let h = make_handler_with_proof(Some(bundle.clone()));

        match h.handle_request(&Request::GetDbProof { db_id: 0 }) {
            Response::DbProof(actual) => assert_eq!(actual, bundle),
            other => panic!("expected DbProof, got {:?}", other),
        }
    }

    #[test]
    fn get_db_proof_without_bundle_returns_error() {
        let h = make_handler();

        expect_error(
            h.handle_request(&Request::GetDbProof { db_id: 0 }),
            "db proof not configured",
        );
    }

    // ─── S1: malformed DPF key bytes ────────────────────────────────────

    /// A garbage key blob used to hit `DpfKey::from_bytes(..).expect(..)`
    /// → process abort. All-zero bytes additionally declare domain
    /// n = 0, whose `n - 7` underflows inside libdpf in debug builds.
    #[test]
    fn index_batch_garbage_key_returns_error_not_panic() {
        let h = make_handler();
        let q = BatchQuery {
            level: 0,
            round_id: 0,
            db_id: 0,
            keys: vec![vec![vec![0u8; 32], vec![0u8; 32]]],
        };
        expect_error(h.handle_request(&Request::IndexBatch(q)), "DPF key");
    }

    #[test]
    fn chunk_batch_short_key_returns_error_not_panic() {
        let h = make_handler();
        let q = BatchQuery {
            level: 1,
            round_id: 0,
            db_id: 0,
            keys: vec![vec![vec![0xAAu8; 5], vec![0xBBu8; 5]]],
        };
        expect_error(h.handle_request(&Request::ChunkBatch(q)), "DPF key");
    }

    // ─── S2/S3: key-count guards ────────────────────────────────────────

    /// S3: fewer than INDEX_CUCKOO_NUM_HASHES keys per group used to
    /// panic at `key_refs[1]`. Built programmatically to bypass the
    /// decode-time guard and prove the handler's own check.
    #[test]
    fn index_batch_single_key_group_returns_error_not_panic() {
        let h = make_handler();
        let dpf = Dpf::with_default_key();
        let q = BatchQuery {
            level: 0,
            round_id: 0,
            db_id: 0,
            keys: vec![vec![dpf.gen(3, 8).0.to_bytes()]],
        };
        expect_error(h.handle_request(&Request::IndexBatch(q)), "need 2");
    }

    /// S2: more keys than eval's fixed bit array used to write out of
    /// bounds.
    #[test]
    fn chunk_batch_oversized_key_count_returns_error_not_panic() {
        let h = make_handler();
        let dpf = Dpf::with_default_key();
        let keys: Vec<Vec<u8>> = (0..(eval::MAX_KEYS_PER_GROUP as u64 + 1))
            .map(|i| dpf.gen(i, 8).0.to_bytes())
            .collect();
        let q = BatchQuery { level: 1, round_id: 0, db_id: 0, keys: vec![keys] };
        expect_error(h.handle_request(&Request::ChunkBatch(q)), "max");
    }

    /// Happy path: a well-formed two-share INDEX query still XORs to the
    /// addressed bin's content through the hardened path.
    #[test]
    fn index_batch_valid_keys_still_xor_to_bin_content() {
        let h = make_handler();
        let alpha = 5u64;
        let n = params::compute_dpf_n(TEST_BINS);
        let dpf = Dpf::with_default_key();
        let (q0_s0, q0_s1) = dpf.gen(alpha, n);
        let (q1_s0, q1_s1) = dpf.gen(7, n);

        let run = |keys: Vec<Vec<Vec<u8>>>| -> BatchResult {
            match h.handle_request(&Request::IndexBatch(BatchQuery {
                level: 0,
                round_id: 0,
                db_id: 0,
                keys,
            })) {
                Response::IndexBatch(r) => r,
                other => panic!("expected IndexBatch, got {:?}", other),
            }
        };
        let r_s0 = run(vec![vec![q0_s0.to_bytes(), q1_s0.to_bytes()]]);
        let r_s1 = run(vec![vec![q0_s1.to_bytes(), q1_s1.to_bytes()]]);

        // share0 ⊕ share1 of the q0 accumulator = group 0, bin 5.
        let mut xored = r_s0.results[0][0].clone();
        for (b, s) in xored.iter_mut().zip(&r_s1.results[0][0]) {
            *b ^= s;
        }
        assert_eq!(xored, vec![5u8; eval::INDEX_RESULT_SIZE]);
    }

    // ─── S4: Harmony group_id bounds ────────────────────────────────────

    #[test]
    fn harmony_query_group_id_out_of_range_returns_error_not_panic() {
        let h = make_handler();
        let q = HarmonyQuery { level: 0, group_id: 250, round_id: 0, indices: vec![0], db_id: 0 };
        expect_error(h.handle_request(&Request::HarmonyQuery(q)), "group_id");
    }

    #[test]
    fn harmony_batch_query_group_id_out_of_range_returns_error_not_panic() {
        let h = make_handler();
        let q = HarmonyBatchQuery {
            level: 1,
            round_id: 0,
            sub_queries_per_group: 1,
            items: vec![HarmonyBatchItem { group_id: 200, sub_queries: vec![vec![0]] }],
            db_id: 0,
        };
        expect_error(h.handle_request(&Request::HarmonyBatchQuery(q)), "group_id");
    }

    // ─── S5: index-count clamp before allocation ────────────────────────

    #[test]
    fn harmony_query_oversized_index_count_returns_error_not_panic() {
        let h = make_handler();
        let q = HarmonyQuery {
            level: 1,
            group_id: 0,
            round_id: 0,
            indices: vec![0u32; TEST_BINS + 1],
            db_id: 0,
        };
        expect_error(h.handle_request(&Request::HarmonyQuery(q)), "too many indices");
    }

    #[test]
    fn harmony_batch_query_oversized_subquery_returns_error_not_panic() {
        let h = make_handler();
        let q = HarmonyBatchQuery {
            level: 0,
            round_id: 0,
            sub_queries_per_group: 1,
            items: vec![HarmonyBatchItem {
                group_id: 0,
                sub_queries: vec![vec![0u32; TEST_BINS + 1]],
            }],
            db_id: 0,
        };
        expect_error(h.handle_request(&Request::HarmonyBatchQuery(q)), "too many indices");
    }

    // ─── Harmony happy paths stay intact ────────────────────────────────

    #[test]
    fn harmony_query_in_range_still_works() {
        let h = make_handler();
        let q = HarmonyQuery {
            level: 0,
            group_id: 74, // last valid INDEX group (k = 75)
            round_id: 9,
            indices: vec![0, 5],
            db_id: 0,
        };
        match h.handle_request(&Request::HarmonyQuery(q)) {
            Response::HarmonyQueryResult(r) => {
                assert_eq!(r.group_id, 74);
                assert_eq!(r.round_id, 9);
                let entry = INDEX_PARAMS.bin_size();
                assert_eq!(r.data.len(), 2 * entry);
                assert!(r.data[..entry].iter().all(|&b| b == (74 ^ 0)));
                assert!(r.data[entry..].iter().all(|&b| b == (74 ^ 5)));
            }
            other => panic!("expected HarmonyQueryResult, got {:?}", other),
        }
    }

    /// Out-of-range indices inside an accepted batch sub-query keep the
    /// existing skip semantics (no error, entry omitted).
    #[test]
    fn harmony_batch_query_in_range_still_works_and_skips_bad_indices() {
        let h = make_handler();
        let q = HarmonyBatchQuery {
            level: 0,
            round_id: 0,
            sub_queries_per_group: 2,
            items: vec![HarmonyBatchItem {
                group_id: 3,
                sub_queries: vec![vec![2], vec![300]], // 300 ≥ TEST_BINS → skipped
            }],
            db_id: 0,
        };
        match h.handle_request(&Request::HarmonyBatchQuery(q)) {
            Response::HarmonyBatchResult(r) => {
                assert_eq!(r.items.len(), 1);
                let entry = INDEX_PARAMS.bin_size();
                assert_eq!(r.items[0].sub_results[0].len(), entry);
                assert!(r.items[0].sub_results[0].iter().all(|&b| b == (3 ^ 2)));
                assert!(r.items[0].sub_results[1].is_empty());
            }
            other => panic!("expected HarmonyBatchResult, got {:?}", other),
        }
    }
}
