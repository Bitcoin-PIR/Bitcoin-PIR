use crate::cli::ServerRole;
use crate::unsafe_debug_log;
use memmap2::Mmap;
use onionpir::{self, KeyStore, Server as PirServer};
use rayon::prelude::*;
use runtime::onionpir::*;
use runtime::protocol::*;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

// ─── OnionPIR worker thread ─────────────────────────────────────────────────

pub(crate) enum PirCommand {
    RegisterKeys {
        client_id: u64,
        galois_keys: Vec<u8>,
        gsw_keys: Vec<u8>,
        reply: oneshot::Sender<()>,
    },
    AnswerBatch {
        client_id: u64,
        level: u8,
        round_id: u16,
        queries: Vec<Vec<u8>>,
        reply: oneshot::Sender<Vec<Vec<u8>>>,
    },
}

// ─── OnionPIR file paths + headers ──────────────────────────────────────────

pub(crate) const ONION_NTT_FILE: &str = "onion_shared_ntt.bin";
pub(crate) const ONION_CHUNK_CUCKOO_FILE: &str = "onion_chunk_cuckoo.bin";
// Consolidated INDEX file produced by gen_3_onion. Replaces the legacy
// onion_index_pir/group_{0..K-1}.bin directory layout. Layout:
//   [master header 32B: magic u64 | K u64 | per_group_bytes u64 | reserved u64]
//   [group_0: per_group_bytes] [group_1: per_group_bytes] ... [group_{K-1}]
// Each per-group slice is exactly what OnionPIR's save_db_to_file produced
// (standard preproc header + NTT-form data) and is passed into
// PirServer::load_db_from_bytes — zero-copy via one outer mmap.
pub(crate) const ONION_INDEX_ALL_FILE: &str = "onion_index_all.bin";
pub(crate) const ONION_INDEX_META_FILE: &str = "onion_index_meta.bin";

pub(crate) const ONION_CHUNK_MAGIC: u64 = 0xBA7C_0010_0000_0001;
pub(crate) const ONION_INDEX_META_MAGIC: u64 = 0xBA7C_0010_0000_0002;
pub(crate) const ONION_INDEX_ALL_MAGIC: u64 = 0xBA7C_0010_0000_0003;
pub(crate) const ONION_INDEX_ALL_HEADER_BYTES: usize = 32;

/// XOR markers re-used from pir-core::cuckoo so v1 (legacy, no anchor)
/// vs v2 (snapshot/delta anchor appended) are discriminated by the
/// same bit pattern across all BitcoinPIR file formats.
pub(crate) const ONION_MAGIC_SNAPSHOT_XOR: u64 = pir_core::cuckoo::ANCHOR_MAGIC_SNAPSHOT_XOR;
pub(crate) const ONION_MAGIC_DELTA_XOR: u64 = pir_core::cuckoo::ANCHOR_MAGIC_DELTA_XOR;

/// Recognise legacy + v2 magics for an onion file header. Returns the
/// matched legacy magic (for downstream offset parsing) on success.
/// `Err` if the magic is unrecognised.
pub(crate) fn check_onion_magic(magic: u64, legacy: u64, file_label: &str) -> u64 {
    let snap = legacy ^ ONION_MAGIC_SNAPSHOT_XOR;
    let delta = legacy ^ ONION_MAGIC_DELTA_XOR;
    if magic == legacy || magic == snap || magic == delta {
        legacy
    } else {
        panic!(
            "Bad {} magic: expected 0x{:016x} (legacy), 0x{:016x} (v2 snapshot), or 0x{:016x} (v2 delta); got 0x{:016x}",
            file_label, legacy, snap, delta, magic
        );
    }
}

/// Parse the chain anchor appended after an onion file's `header_size`-byte
/// legacy header, when the magic indicates a v2 (snapshot/delta) layout.
/// `None` for a legacy (pre-anchor) file.
pub(crate) fn parse_onion_anchor(
    data: &[u8],
    legacy_magic: u64,
    header_size: usize,
) -> Option<pir_core::cuckoo::HeaderAnchor> {
    use pir_core::seeds::{ChainAnchor, DeltaAnchor, CHAIN_ANCHOR_BYTES, DELTA_ANCHOR_BYTES};
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    if magic == legacy_magic ^ ONION_MAGIC_SNAPSHOT_XOR {
        let end = header_size + CHAIN_ANCHOR_BYTES;
        ChainAnchor::from_bytes(data.get(header_size..end)?)
            .ok()
            .map(pir_core::cuckoo::HeaderAnchor::Snapshot)
    } else if magic == legacy_magic ^ ONION_MAGIC_DELTA_XOR {
        let end = header_size + DELTA_ANCHOR_BYTES;
        DeltaAnchor::from_bytes(data.get(header_size..end)?)
            .ok()
            .map(pir_core::cuckoo::HeaderAnchor::Delta)
    } else {
        None
    }
}

/// Self-verify that the onion INDEX/CHUNK seeds were honestly derived
/// from the embedded chain anchor. Panics (refuse-to-serve) on mismatch;
/// no-op for a legacy (anchor-less) onion DB. Mirrors the DPF/HarmonyPIR
/// `MappedSubTable::verify_anchor_consistency` defense-in-depth check.
pub(crate) fn verify_onion_anchor_seeds(
    anchor: &pir_core::cuckoo::HeaderAnchor,
    im_master: u64,
    im_tag: u64,
    ch_master: u64,
    label: &str,
) {
    pub(crate) fn check<C: pir_core::seeds::SeedContext>(
        a: &C,
        im_master: u64,
        im_tag: u64,
        ch_master: u64,
        label: &str,
    ) {
        use pir_core::seeds::{derive_seed_u64, domain};
        let dm = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, a);
        assert_eq!(
            dm, im_master,
            "[anchor] {} onion INDEX master_seed mismatch: derived 0x{:016x} vs header 0x{:016x} — refusing to serve",
            label, dm, im_master
        );
        let dt = derive_seed_u64(domain::INDEX_TAG_FINGERPRINT, a);
        assert_eq!(
            dt, im_tag,
            "[anchor] {} onion INDEX tag_seed mismatch — refusing to serve",
            label
        );
        let dc = derive_seed_u64(domain::CHUNK_CUCKOO_MASTER, a);
        assert_eq!(
            dc, ch_master,
            "[anchor] {} onion CHUNK master_seed mismatch — refusing to serve",
            label
        );
    }
    match anchor {
        pir_core::cuckoo::HeaderAnchor::Snapshot(a) => {
            check(a, im_master, im_tag, ch_master, label)
        }
        pir_core::cuckoo::HeaderAnchor::Delta(a) => check(a, im_master, im_tag, ch_master, label),
    }
}

pub(crate) struct OnionChunkHeader {
    pub(crate) k_chunk: usize,
    pub(crate) bins_per_table: usize,
    pub(crate) num_packed_entries: usize,
    /// CHUNK cuckoo master seed (chain-derived for v2 DBs). Layout:
    /// magic(8) k_chunk(4) cuckoo_hashes(4) bins(4) master_seed(8) ...
    pub(crate) master_seed: u64,
    /// Byte offset where the per-group bin→entry-id tables begin. For a
    /// v2 (chain-anchored) file the anchor is written BETWEEN the 36-byte
    /// header and the tables (same convention as the DPF cuckoo files),
    /// so the tables shift by the anchor length. The table reader MUST use
    /// this — a hardcoded 36 reads the anchor bytes as entry-ids, which
    /// then index out-of-bounds into the NTT store and segfault the query.
    pub(crate) data_offset: usize,
}

/// Legacy onion chunk-cuckoo header size (before any v2 anchor).
pub(crate) const ONION_CHUNK_HEADER_BYTES: usize = 36;

pub(crate) fn read_onion_chunk_header(data: &[u8]) -> OnionChunkHeader {
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let _ = check_onion_magic(magic, ONION_CHUNK_MAGIC, "onion chunk cuckoo");
    // The v2 anchor (if any) sits between the legacy header and the
    // per-group tables — so the table data offset must skip it too.
    let anchor_len = if magic == ONION_CHUNK_MAGIC ^ ONION_MAGIC_SNAPSHOT_XOR {
        pir_core::seeds::CHAIN_ANCHOR_BYTES
    } else if magic == ONION_CHUNK_MAGIC ^ ONION_MAGIC_DELTA_XOR {
        pir_core::seeds::DELTA_ANCHOR_BYTES
    } else {
        0
    };
    OnionChunkHeader {
        k_chunk: u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
        bins_per_table: u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize,
        master_seed: u64::from_le_bytes(data[20..28].try_into().unwrap()),
        num_packed_entries: u32::from_le_bytes(data[28..32].try_into().unwrap()) as usize,
        data_offset: ONION_CHUNK_HEADER_BYTES + anchor_len,
    }
}

pub(crate) struct OnionIndexMeta {
    pub(crate) k: usize,
    pub(crate) bins_per_table: usize,
    pub(crate) slots_per_bin: usize,
    pub(crate) tag_seed: u64,
    pub(crate) slot_size: usize,
    /// INDEX cuckoo master seed (chain-derived for v2 DBs). Layout:
    /// magic(8) k(4) cuckoo_hashes(4) slots_per_bin(4) bins(4) master_seed(8) tag_seed(8) slot_size(4)
    pub(crate) master_seed: u64,
    /// Chain anchor appended after the 44-byte legacy header in v2 files.
    pub(crate) anchor: Option<pir_core::cuckoo::HeaderAnchor>,
}

/// Legacy (pre-anchor) byte size of the onion index meta header.
pub(crate) const ONION_INDEX_META_HEADER_BYTES: usize = 44;

pub(crate) fn read_onion_index_meta(data: &[u8]) -> OnionIndexMeta {
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let _ = check_onion_magic(magic, ONION_INDEX_META_MAGIC, "onion index meta");
    OnionIndexMeta {
        k: u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
        bins_per_table: u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize,
        slots_per_bin: u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize,
        master_seed: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        tag_seed: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        slot_size: u32::from_le_bytes(data[40..44].try_into().unwrap()) as usize,
        anchor: parse_onion_anchor(data, ONION_INDEX_META_MAGIC, ONION_INDEX_META_HEADER_BYTES),
    }
}

pub(crate) struct OnionPirMerkleInfo {
    pub(crate) arity: usize,
    /// SHA256 of the concatenated 155 per-group roots — the §2f trust anchor.
    pub(crate) super_root_hex: String,
    /// `merkle_onion_tree_tops.bin` verbatim (75 INDEX + 80 DATA per-group
    /// tree-tops); served whole on either INDEX/DATA TREE_TOP request.
    pub(crate) tree_tops: Vec<u8>,
    /// Number of INDEX per-group sibling trees (= INDEX PBC group count).
    pub(crate) index_k: usize,
    /// Plaintexts in each INDEX per-group sibling DB.
    pub(crate) index_num_pt: usize,
    /// Number of DATA per-group sibling trees (= CHUNK PBC group count).
    pub(crate) data_k: usize,
    /// Plaintexts in each DATA per-group sibling DB.
    pub(crate) data_num_pt: usize,
}

#[derive(Clone)]
pub(crate) struct OnionPirInfo {
    pub(crate) total_packed_entries: u32,
    pub(crate) index_bins_per_table: u32,
    pub(crate) chunk_bins_per_table: u32,
    pub(crate) index_k: u8,
    pub(crate) chunk_k: u8,
    pub(crate) tag_seed: u64,
    pub(crate) index_slots_per_bin: u16,
    pub(crate) index_slot_size: u8,
    /// INDEX/CHUNK cuckoo master seeds (chain-derived for v2 DBs),
    /// delivered to the standalone OnionPIR TS client so it computes
    /// placements with the server's seed instead of a hardcoded const.
    pub(crate) index_master_seed: u64,
    pub(crate) chunk_master_seed: u64,
}

pub(crate) fn setup_onionpir_workers(
    args: &crate::cli::CliArgs,
    db_paths: &[(u8, String, std::path::PathBuf)],
) -> (
    Vec<Option<Arc<mpsc::Sender<PirCommand>>>>,
    Vec<Option<OnionPirInfo>>,
    Vec<Option<OnionPirMerkleInfo>>,
) {
    // ── Set up OnionPIR per-DB (primary only, if data available) ──────────
    //
    // Each database can have its own OnionPIR data. Loading is per-DB:
    //   onionpir_txs[db_id]    = Some(channel) if db has OnionPIR data
    //   onionpir_infos[db_id]  = Some(info)    if db has OnionPIR data
    //   onionpir_merkle[db_id] = Some(info)    if db has OnionPIR Merkle data
    //
    // db_paths was already populated alongside `all_databases` above; it's
    // a list of (db_id, label, source_dir) for every loaded database.

    let num_total_dbs = db_paths.len();
    let mut onionpir_txs: Vec<Option<Arc<mpsc::Sender<PirCommand>>>> = vec![None; num_total_dbs];
    let mut onionpir_infos: Vec<Option<OnionPirInfo>> = (0..num_total_dbs).map(|_| None).collect();
    let mut onionpir_merkle_per_db: Vec<Option<OnionPirMerkleInfo>> =
        (0..num_total_dbs).map(|_| None).collect();

    // Per-group OnionPIR Merkle (Phase 3): one consolidated sibling file
    // per kind, loaded per-DB alongside the OnionPIR worker setup.
    struct OnionSibFile {
        /// Number of per-group sibling DBs (= PBC group count).
        k: usize,
        /// Plaintexts per per-group sibling DB.
        num_pt: usize,
        /// Byte length of one per-group `save_db` blob.
        blob_len: usize,
        /// `merkle_onion_sib_{index,data}.bin` mmap: `[24B header][K blobs]`.
        mmap: Mmap,
    }

    /// Load one consolidated per-group sibling file (Phase 3). Returns
    /// `None` if the file is absent (DB has no per-group OnionPIR Merkle).
    fn load_onion_sib_file(
        data_dir: &std::path::Path,
        db_label: &str,
        tree_kind: &str,
    ) -> Option<OnionSibFile> {
        let path = data_dir.join(format!("merkle_onion_sib_{}.bin", tree_kind));
        if !path.exists() {
            return None;
        }
        let file = std::fs::File::open(&path).expect("open onion sibling file");
        let mmap = unsafe { Mmap::map(&file) }.expect("mmap onion sibling file");
        assert!(
            mmap.len() >= 24,
            "{}: too small ({} B) for the 24-byte header",
            path.display(),
            mmap.len(),
        );
        // Header: [8B magic][4B K][4B arity][4B num_pt][4B blob_len].
        let k = u32::from_le_bytes(mmap[8..12].try_into().unwrap()) as usize;
        let num_pt = u32::from_le_bytes(mmap[16..20].try_into().unwrap()) as usize;
        let blob_len = u32::from_le_bytes(mmap[20..24].try_into().unwrap()) as usize;
        let expected = 24 + k * blob_len;
        assert_eq!(
            mmap.len(),
            expected,
            "{}: size mismatch (header K={} blob_len={} → {} B, file is {} B)",
            path.display(),
            k,
            blob_len,
            expected,
            mmap.len(),
        );
        println!(
            "  [{}] onion sibling '{}': K={}, num_pt={}, blob={:.2} MB, total={:.2} MB",
            db_label,
            tree_kind,
            k,
            num_pt,
            blob_len as f64 / 1e6,
            mmap.len() as f64 / 1e6,
        );
        Some(OnionSibFile {
            k,
            num_pt,
            blob_len,
            mmap,
        })
    }

    if args.role == ServerRole::Primary && !args.disable_onion {
        for (db_id, db_label, db_dir) in db_paths {
            let ntt_path = db_dir.join(ONION_NTT_FILE);
            if !ntt_path.exists() {
                println!(
                    "[OnionPIR:{}] Not available (no {} in {})",
                    db_label,
                    ONION_NTT_FILE,
                    db_dir.display()
                );
                continue;
            }
            println!("[OnionPIR:{}] Loading data...", db_label);

            let chunk_cuckoo_path = db_dir.join(ONION_CHUNK_CUCKOO_FILE);
            let index_all_path = db_dir.join(ONION_INDEX_ALL_FILE);
            let index_meta_path = db_dir.join(ONION_INDEX_META_FILE);

            if !index_all_path.exists() {
                println!(
                    "[OnionPIR:{}] Skipping — {} missing in {}. Re-run scripts/build_delta_onion.sh (or gen_3_onion) to regenerate the consolidated INDEX layout.",
                    db_label, ONION_INDEX_ALL_FILE, db_dir.display(),
                );
                continue;
            }

            // Read OnionPIR-specific headers
            let cuckoo_data = std::fs::read(&chunk_cuckoo_path).expect("read onion chunk cuckoo");
            let ch = read_onion_chunk_header(&cuckoo_data);
            let meta_data = std::fs::read(&index_meta_path).expect("read onion index meta");
            let im = read_onion_index_meta(&meta_data);

            println!(
                "  Chunk: K={}, bins={}, packed={}",
                ch.k_chunk, ch.bins_per_table, ch.num_packed_entries
            );
            println!(
                "  Index: K={}, bins={}, slots_per_bin={}",
                im.k, im.bins_per_table, im.slots_per_bin
            );

            // Phase: self-verify onion seeds against the chain anchor embedded
            // in onion_index_meta.bin (v2 header). No-op for legacy onion DBs.
            if let Some(anchor) = im.anchor {
                verify_onion_anchor_seeds(
                    &anchor,
                    im.master_seed,
                    im.tag_seed,
                    ch.master_seed,
                    db_label,
                );
                println!("  anchor verified: onion INDEX/CHUNK seeds match chain-derived values");
            }

            onionpir_infos[*db_id as usize] = Some(OnionPirInfo {
                total_packed_entries: ch.num_packed_entries as u32,
                index_bins_per_table: im.bins_per_table as u32,
                chunk_bins_per_table: ch.bins_per_table as u32,
                index_k: im.k as u8,
                chunk_k: ch.k_chunk as u8,
                tag_seed: im.tag_seed,
                index_slots_per_bin: im.slots_per_bin as u16,
                index_slot_size: im.slot_size as u8,
                index_master_seed: im.master_seed,
                chunk_master_seed: ch.master_seed,
            });

            // Parse chunk cuckoo tables. ch.data_offset accounts for the v2
            // chain-anchor that sits between the header and the tables —
            // hardcoding 36 here read the anchor bytes as entry-ids and
            // segfaulted the onion query path (see OnionChunkHeader).
            let header_size = ch.data_offset;
            let mut chunk_tables: Vec<Vec<u32>> = Vec::with_capacity(ch.k_chunk);
            for g in 0..ch.k_chunk {
                let offset = header_size + g * ch.bins_per_table * 4;
                let mut table = Vec::with_capacity(ch.bins_per_table);
                for b in 0..ch.bins_per_table {
                    let pos = offset + b * 4;
                    let eid = u32::from_le_bytes(cuckoo_data[pos..pos + 4].try_into().unwrap());
                    table.push(eid);
                }
                chunk_tables.push(table);
            }

            // Load NTT store
            let ntt_file = std::fs::File::open(&ntt_path).expect("open NTT store");
            let ntt_mmap = unsafe { Mmap::map(&ntt_file) }.expect("mmap NTT store");
            println!("  NTT store: {:.2} GB", ntt_mmap.len() as f64 / 1e9);
            // Load consolidated INDEX file (onion_index_all.bin). Single mmap;
            // we parse the 32-byte master header here and hand per-group slices
            // to the PIR worker thread, which in turn feeds each slice into
            // `PirServer::load_db_from_bytes` (zero-copy aliased pointer).
            let index_all_file = std::fs::File::open(&index_all_path)
                .unwrap_or_else(|e| panic!("open {}: {}", index_all_path.display(), e));
            let index_all_mmap =
                unsafe { Mmap::map(&index_all_file) }.expect("mmap onion_index_all.bin");
            {
                if index_all_mmap.len() < ONION_INDEX_ALL_HEADER_BYTES {
                    panic!(
                        "{}: file too small ({} bytes) for index_all master header",
                        index_all_path.display(),
                        index_all_mmap.len(),
                    );
                }
                let magic = u64::from_le_bytes(index_all_mmap[0..8].try_into().unwrap());
                let file_k = u64::from_le_bytes(index_all_mmap[8..16].try_into().unwrap()) as usize;
                let file_per_group =
                    u64::from_le_bytes(index_all_mmap[16..24].try_into().unwrap()) as usize;
                // Accept legacy + v2 (anchor trailer) magic.
                let _ = check_onion_magic(magic, ONION_INDEX_ALL_MAGIC, "onion index-all master");
                assert_eq!(
                    file_k,
                    im.k,
                    "{}: K mismatch (file says {}, meta says {})",
                    index_all_path.display(),
                    file_k,
                    im.k,
                );
                // The K per-group payloads occupy [HEADER .. HEADER + K*per_group);
                // a v2 file then appends the chain anchor as a trailer.
                let data_len = ONION_INDEX_ALL_HEADER_BYTES + file_k * file_per_group;
                let all_anchor =
                    parse_onion_anchor(&index_all_mmap, ONION_INDEX_ALL_MAGIC, data_len);
                let expected_len = data_len
                    + match all_anchor {
                        None => 0,
                        Some(pir_core::cuckoo::HeaderAnchor::Snapshot(_)) => {
                            pir_core::seeds::CHAIN_ANCHOR_BYTES
                        }
                        Some(pir_core::cuckoo::HeaderAnchor::Delta(_)) => {
                            pir_core::seeds::DELTA_ANCHOR_BYTES
                        }
                    };
                assert_eq!(
                    index_all_mmap.len(),
                    expected_len,
                    "{}: total size mismatch (expected {}, got {})",
                    index_all_path.display(),
                    expected_len,
                    index_all_mmap.len(),
                );
                // Cross-file consistency: onion_index_all's trailer anchor must
                // match the one embedded in onion_index_meta.bin — catches a
                // mixed build where the two files came from different anchors.
                if let (Some(a), Some(m)) = (all_anchor, im.anchor) {
                    assert_eq!(
                        a, m,
                        "{}: index-all anchor disagrees with index-meta anchor — mixed build, refusing to serve",
                        index_all_path.display(),
                    );
                }
                println!(
                    "  Index-all: K={}, per_group={:.2} MB, total={:.2} MB",
                    file_k,
                    file_per_group as f64 / 1e6,
                    index_all_mmap.len() as f64 / 1e6,
                );
            }
            let index_all_per_group =
                u64::from_le_bytes(index_all_mmap[16..24].try_into().unwrap()) as usize;

            // Load the per-group OnionPIR Merkle sidecars (Phase 3
            // per-group redesign). A DB ships these only if
            // `gen_4_build_merkle_onion` has been run for it.
            let index_sib_file = load_onion_sib_file(db_dir, db_label, "index");
            let data_sib_file = load_onion_sib_file(db_dir, db_label, "data");

            let merkle_tree_tops: Option<Vec<u8>> = {
                let p = db_dir.join("merkle_onion_tree_tops.bin");
                if p.exists() {
                    Some(std::fs::read(&p).expect("read merkle_onion_tree_tops.bin"))
                } else {
                    None
                }
            };
            let merkle_super_root: Option<Vec<u8>> = {
                let p = db_dir.join("merkle_onion_root.bin");
                if p.exists() {
                    Some(std::fs::read(&p).expect("read merkle_onion_root.bin"))
                } else {
                    None
                }
            };

            // A DB has OnionPIR Merkle iff the full per-group set is on
            // disk: both consolidated sibling files plus the tree-top blob.
            let has_merkle_data =
                index_sib_file.is_some() && data_sib_file.is_some() && merkle_tree_tops.is_some();
            if has_merkle_data {
                let idx = index_sib_file.as_ref().unwrap();
                let dat = data_sib_file.as_ref().unwrap();
                let arity = onionpir::params_info(0).entry_size as usize / 32;
                let super_root_hex = merkle_super_root
                    .as_ref()
                    .map(|r| r.iter().map(|b| format!("{:02x}", b)).collect::<String>())
                    .unwrap_or_default();
                onionpir_merkle_per_db[*db_id as usize] = Some(OnionPirMerkleInfo {
                    arity,
                    super_root_hex,
                    tree_tops: merkle_tree_tops.unwrap_or_default(),
                    index_k: idx.k,
                    index_num_pt: idx.num_pt,
                    data_k: dat.k,
                    data_num_pt: dat.num_pt,
                });
            }

            let k_index = im.k;
            let k_chunk = ch.k_chunk;
            let index_bins = im.bins_per_table;
            let chunk_bins = ch.bins_per_table;
            let index_all_per_group_for_worker = index_all_per_group;
            let worker_label = db_label.clone();

            let (tx, mut pir_rx) = mpsc::channel::<PirCommand>(64);
            onionpir_txs[*db_id as usize] = Some(Arc::new(tx));

            // Spawn PIR worker thread (one per DB)
            std::thread::spawn(move || {
                // OnionPIRv2 port: KeyStore::new() takes no args now.
                let key_store = Box::new(KeyStore::new());

                // Set up chunk servers.
                //
                // OnionPIRv2 port (commit 6 / runtime-num_pt update): post the
                // upstream `target_num_pt` refactor (`fb14f4e447b...`),
                // `params_info(chunk_bins)` returns the LOCAL per-instance
                // shape (small server sized for `chunk_bins` ~37K plaintexts).
                // That's what each chunk worker's PirServer needs.
                let p_chunk = onionpir::params_info(chunk_bins as u64);
                let padded_chunk = p_chunk.num_entries as usize;
                // OnionPIRv2 port: `set_shared_database` now takes
                // `&[u64]` rather than a raw `*const u64` + count. The
                // unsafe slice construction below is sound for the same
                // reason the old raw-pointer call was: `ntt_mmap` is
                // captured by-move into this worker-thread closure and
                // outlives every `PirServer` we attach to it.
                //
                // SAFETY: `ntt_mmap` is a `&[u8]` with `len() % 8 == 0`
                // (preprocessed_db.bin payload is u64-aligned by build).
                let ntt_u64_slice: &[u64] = unsafe {
                    std::slice::from_raw_parts(ntt_mmap.as_ptr() as *const u64, ntt_mmap.len() / 8)
                };

                // Shared store's `num_pt` — what gen_2_onion's builder
                // `PirServer::new(num_packed_entries)` was created with,
                // which is what `set_shared_database`'s `shared_num_entries`
                // argument wants. Pre-`fb14f4e` we passed
                // `p_chunk.num_plaintexts` (the local per-instance value);
                // post-refactor those are different numbers and the local
                // one is wrong here. Derive from the NTT store file size
                // instead — `len() / 8 / coeff_val_cnt` is the count of
                // plaintext slots the builder saved.
                let coeff_val_cnt = onionpir::params_info(0).coeff_val_cnt as usize;
                assert!(
                    coeff_val_cnt > 0 && ntt_u64_slice.len().is_multiple_of(coeff_val_cnt),
                    "chunk NTT store len ({} u64s) not divisible by \
                     coeff_val_cnt ({}); file is the wrong shape",
                    ntt_u64_slice.len(),
                    coeff_val_cnt,
                );
                let chunk_shared_num_entries = (ntt_u64_slice.len() / coeff_val_cnt) as u64;

                let mut chunk_index_tables: Vec<Vec<u32>> = Vec::with_capacity(k_chunk);
                let mut chunk_servers: Vec<PirServer> = Vec::with_capacity(k_chunk);
                for (g, chunk_table) in chunk_tables.iter().enumerate().take(k_chunk) {
                    let mut server = PirServer::new(chunk_bins as u64);
                    let mut index_table = vec![0u32; padded_chunk];
                    for bin in 0..chunk_bins {
                        let eid = chunk_table[bin];
                        if eid != u32::MAX {
                            index_table[bin] = eid;
                        }
                    }
                    unsafe {
                        // OnionPIRv2 port: `set_shared_database` returns
                        // bool now (false on validation failure). Wrap in
                        // assert! so silent failures don't ship.
                        // OnionPIRv2 port (commit 3a): pass
                        // `num_plaintexts` (compile-time DB shape) as
                        // `shared_num_entries`, not the pre-port
                        // `num_packed_entries` (dataset size). The NTT
                        // store from gen_2_onion's post-port save_db
                        // payload is sized for the full num_plaintexts
                        // slot count; passing the smaller
                        // num_packed_entries would lie about the layout.
                        // Cuckoo placement only assigns to
                        // [0, num_packed_entries) so empty slots beyond
                        // that range are never queried.
                        assert!(
                            server.set_shared_database(
                                ntt_u64_slice,
                                chunk_shared_num_entries,
                                &index_table,
                            ),
                            "set_shared_database failed (chunk worker {} \
                             group {}; chunk_shared_num_entries={}, \
                             index_table.len={}, local_num_pt={})",
                            worker_label,
                            g,
                            chunk_shared_num_entries,
                            index_table.len(),
                            p_chunk.num_plaintexts,
                        );
                        // OnionPIRv2 port: `set_key_store` takes Option now.
                        server.set_key_store(Some(&key_store));
                    }
                    chunk_index_tables.push(index_table);
                    chunk_servers.push(server);
                }
                println!(
                    "  [OnionPIR:{}] {} chunk servers ready",
                    worker_label, k_chunk
                );

                // Set up index servers — each slices into the consolidated
                // onion_index_all.bin mmap via load_db_from_bytes (zero-copy).
                // The mmap handle must outlive every PirServer that aliases
                // it, which is satisfied by moving `index_all_mmap` into this
                // worker thread closure — the mmap drops only when the
                // thread exits, which happens on process shutdown.
                let mut index_servers: Vec<PirServer> = Vec::with_capacity(k_index);
                for b in 0..k_index {
                    let off = ONION_INDEX_ALL_HEADER_BYTES + b * index_all_per_group_for_worker;
                    let end = off + index_all_per_group_for_worker;
                    let slice = &index_all_mmap[off..end];
                    let mut server = PirServer::new(index_bins as u64);
                    // SAFETY: `index_all_mmap` is owned by this worker thread
                    // and lives as long as `server`. The PirServer will NOT
                    // munmap the borrowed buffer on drop (fd = -1 path inside
                    // load_db_from_borrowed).
                    assert!(
                        unsafe { server.load_db_from_borrowed(slice) },
                        "Failed to load index group {} from consolidated index_all (offset {}, len {})",
                        b, off, slice.len(),
                    );
                    // OnionPIRv2 port: `set_key_store` takes Option now.
                    unsafe {
                        server.set_key_store(Some(&key_store));
                    }
                    index_servers.push(server);
                }
                println!(
                    "  [OnionPIR:{}] {} index servers ready (via onion_index_all.bin mmap)",
                    worker_label, k_index
                );

                // Set up per-group OnionPIR Merkle sibling servers — one
                // PirServer per group, each zero-copy aliasing its
                // 24-byte-header sub-slice of merkle_onion_sib_*.bin.
                // Mirrors the index_servers block above.
                let build_sib_servers = |sib: &OnionSibFile, kind: &str| -> Vec<PirServer> {
                    let mut servers = Vec::with_capacity(sib.k);
                    for g in 0..sib.k {
                        let off = 24 + g * sib.blob_len;
                        let slice = &sib.mmap[off..off + sib.blob_len];
                        let mut server = PirServer::new(sib.num_pt as u64);
                        // SAFETY: `sib.mmap` is owned by this worker thread
                        // (moved into the closure) and outlives `server`.
                        assert!(
                            unsafe { server.load_db_from_borrowed(slice) },
                            "[OnionPIR:{}] load_db_from_borrowed failed for {} \
                             sibling group {} (offset {}, len {})",
                            worker_label,
                            kind,
                            g,
                            off,
                            slice.len(),
                        );
                        // OnionPIRv2 port: `set_key_store` takes Option now.
                        unsafe {
                            server.set_key_store(Some(&key_store));
                        }
                        servers.push(server);
                    }
                    println!(
                        "  [OnionPIR:{}] {} sibling servers ready ({} groups, num_pt={})",
                        worker_label, kind, sib.k, sib.num_pt,
                    );
                    servers
                };
                let mut index_sib_servers: Vec<PirServer> = match &index_sib_file {
                    Some(sib) => build_sib_servers(sib, "index"),
                    None => Vec::new(),
                };
                let mut data_sib_servers: Vec<PirServer> = match &data_sib_file {
                    Some(sib) => build_sib_servers(sib, "data"),
                    None => Vec::new(),
                };

                // Event loop
                while let Some(cmd) = pir_rx.blocking_recv() {
                    match cmd {
                        PirCommand::RegisterKeys {
                            client_id,
                            galois_keys,
                            gsw_keys,
                            reply,
                        } => {
                            let t = Instant::now();
                            key_store.set_galois_keys(client_id, &galois_keys);
                            key_store.set_gsw_key(client_id, &gsw_keys);
                            unsafe_debug_log!(
                                "  [OnionPIR:{}] client {} keys registered in {:.2?}",
                                worker_label,
                                client_id,
                                t.elapsed()
                            );
                            let _ = reply.send(());
                        }
                        PirCommand::AnswerBatch {
                            client_id,
                            level,
                            round_id,
                            queries,
                            reply,
                        } => {
                            let t = Instant::now();
                            // OnionPIRv2 port (2402b16): rayon-parallel `answer_query`
                            // across the per-group PirServer Vec. Safe after upstream
                            // 2402b16 made g_scratch / NTT cache / TimerLogger
                            // thread_local + added a mutex to SharedKeyStore. Each
                            // rayon worker gets one exclusive `&mut PirServer`
                            // (Send-but-not-Sync), so per-server state is single-
                            // threaded; the shared SharedKeyStore is mutex-guarded.
                            //
                            // The bd1a2928 attempt to ship this was reverted after a
                            // pir1 deploy showed 60 s registrations + empty
                            // answer_query. That turned out NOT to be a 2402b16 bug —
                            // it was a contaminated incremental libonionpir.a build
                            // from flipping the onionpir git rev repeatedly without a
                            // clean rebuild (see docs/history/PIR1_REGISTER_KEYS_TRUNCATION.md).
                            // With a clean build, 2402b16 registers keys in ~1 ms and
                            // the parallel path is sound.
                            //
                            // Wall-time projection (i7-8700, 6 cores):
                            //   INDEX 142 s → ~25 s ; CHUNK 157 s → ~25 s. Total batch
                            //   ≈ 60 s — under Cloudflare's ~100 s WS idle timeout.
                            let worker_label = &worker_label;
                            let queries_ref = &queries;
                            let (name, results): (&str, Vec<Vec<u8>>) = if level == 0 {
                                let results: Vec<Vec<u8>> = index_servers
                                    .par_iter_mut()
                                    .enumerate()
                                    .flat_map_iter(|(g, server)| {
                                        let q0 = &queries_ref[2 * g];
                                        let q1 = &queries_ref[2 * g + 1];
                                        // The workspace uses panic=abort, so an OnionPIR panic
                                        // terminates the process; there is no in-process isolation.
                                        // A process boundary is required if that policy changes.
                                        let r0 = server.answer_query(client_id, q0);
                                        let r1 = server.answer_query(client_id, q1);
                                        std::iter::once(r0).chain(std::iter::once(r1))
                                    })
                                    .collect();
                                ("index", results)
                            } else if level == 1 {
                                let results: Vec<Vec<u8>> = chunk_servers
                                    .par_iter_mut()
                                    .enumerate()
                                    .map(|(b, server)| {
                                        server.answer_query(client_id, &queries_ref[b])
                                    })
                                    .collect();
                                ("chunk", results)
                            } else if level == 10 || level == 11 {
                                // Per-group OnionPIR Merkle siblings:
                                // level 10 = INDEX trees, level 11 = DATA trees.
                                let (servers, kind): (&mut Vec<PirServer>, &str) = if level == 10 {
                                    (&mut index_sib_servers, "index-sibling")
                                } else {
                                    (&mut data_sib_servers, "data-sibling")
                                };
                                let results: Vec<Vec<u8>> = servers
                                    .par_iter_mut()
                                    .enumerate()
                                    .map(|(b, server)| {
                                        server.answer_query(client_id, &queries_ref[b])
                                    })
                                    .collect();
                                (kind, results)
                            } else {
                                unsafe_debug_log!(
                                    "[OnionPIR:{}] unknown level {}",
                                    worker_label,
                                    level
                                );
                                ("unknown", Vec::new())
                            };
                            // OnionPIRv2 port: report empty/nonempty result split
                            // alongside the existing wall-clock log so a future
                            // "all-empty batch" client-side report (see
                            // `crates/sdk/client/src/onion.rs::batch_looks_evicted`)
                            // can be triaged from server logs alone — either
                            // answer_query returned an all-empty batch quickly
                            // (empty=N/N → keystore drift or query malformed) or the
                            // matmul completed (empty=0/N, full wall time →
                            // client decode / decryption-noise bug).
                            let empty_count = results.iter().filter(|r| r.is_empty()).count();
                            let nonempty_bytes: usize = results
                                .iter()
                                .filter(|r| !r.is_empty())
                                .map(|r| r.len())
                                .sum();
                            let first_resp_len = results
                                .iter()
                                .find(|r| !r.is_empty())
                                .map(|r| r.len())
                                .unwrap_or(0);
                            unsafe_debug_log!(
                                "  [OnionPIR:{}] {} r{} {} queries in {:.2?} (empty={}/{}, nonempty_total={}B, resp_len={}B, client_id={})",
                                worker_label, name, round_id, queries.len(), t.elapsed(),
                                empty_count, results.len(), nonempty_bytes, first_resp_len, client_id,
                            );
                            let _ = reply.send(results);
                        }
                    }
                }
            });
        }
    }

    (onionpir_txs, onionpir_infos, onionpir_merkle_per_db)
}
