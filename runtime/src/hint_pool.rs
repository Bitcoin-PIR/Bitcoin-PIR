//! Pre-computed HarmonyPIR hint pool with background replenishment.
//!
//! The pool generates (prp_key, serialized hint frames) pairs in a background
//! thread and serves them to clients with zero computation on the hot path.
//!
//! ## Memory locality
//!
//! Each pool entry is generated key-at-a-time: one random PRP key, all 155
//! groups computed in parallel via rayon. This keeps each group's `hints`
//! array (~170-350 KB) in L2 cache and the `cell_of` array (~4-8 MB) in L3.
//! Cross-key batching would thrash the per-group hints across cache lines.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use harmonypir::params::Params;
use harmonypir::prp::BatchPrp;
use harmonypir::remote;

use pir_runtime_core::table::MappedDatabase;

// ─── Config ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct HintPoolConfig {
    /// Target number of entries to keep ready.
    pub pool_size: usize,
    /// PRP backend for background generation.
    pub prp_backend: u8,
    /// Directory for disk-backed pool persistence (None = in-memory only).
    pub pool_dir: Option<PathBuf>,
}

impl Default for HintPoolConfig {
    fn default() -> Self {
        Self {
            pool_size: 8,
            prp_backend: default_prp_backend(),
            pool_dir: None,
        }
    }
}

/// Select the fastest backend that is actually compiled into this binary.
/// A no-default-features build must advertise HMR12, not FastPRP backed by an
/// HMR12 computation.
pub const fn default_prp_backend() -> u8 {
    #[cfg(feature = "fastprp")]
    {
        remote::PRP_FASTPRP
    }
    #[cfg(not(feature = "fastprp"))]
    {
        remote::PRP_HMR12
    }
}

pub fn validate_prp_backend(prp_backend: u8) -> Result<(), String> {
    match prp_backend {
        remote::PRP_HMR12 => Ok(()),
        #[cfg(feature = "fastprp")]
        remote::PRP_FASTPRP => Ok(()),
        #[cfg(not(feature = "fastprp"))]
        remote::PRP_FASTPRP => {
            Err("FastPRP requested, but runtime was built without the `fastprp` feature".into())
        }
        other => Err(format!("unsupported HarmonyPIR PRP backend {}", other)),
    }
}

// ─── Key preamble wire format ────────────────────────────────────────────────

/// Sentinel value in the key-preamble `level` field meaning "applies to both
/// INDEX and CHUNK."
pub const HINT_LEVEL_ALL: u8 = 0xFF;

/// Response variant byte for the key preamble frame.
pub const RESP_HARMONY_HINTS_KEY: u8 = 0x44;

/// Response variant byte for per-group hint frames (reuses V1 format).
pub const RESP_HARMONY_HINTS: u8 = 0x41;

/// Build the key preamble frame (the first frame sent in response to a V2
/// hint request). The caller prepends the outer 4-byte length prefix.
pub fn build_key_preamble(prp_backend: u8, total_groups: u8, prp_key: &[u8; 16]) -> Vec<u8> {
    // Layout: [RESP_HARMONY_HINTS_KEY][1B prp_backend][1B level_sentinel=0xFF][1B total_groups][16B prp_key]
    let payload_len: u32 = 1 + 1 + 1 + 1 + 16;
    let mut frame = Vec::with_capacity(4 + payload_len as usize);
    frame.extend_from_slice(&payload_len.to_le_bytes());
    frame.push(RESP_HARMONY_HINTS_KEY);
    frame.push(prp_backend);
    frame.push(HINT_LEVEL_ALL);
    frame.push(total_groups);
    frame.extend_from_slice(prp_key);
    frame
}

// ─── Pool entry ──────────────────────────────────────────────────────────────

/// One pre-computed entry: a full set of per-group hint frames for both
/// INDEX and CHUNK levels, bound to a randomly-generated PRP key.
pub struct PoolEntry {
    /// Server-generated PRP key.
    pub prp_key: [u8; 16],
    /// PRP backend used.
    pub prp_backend: u8,
    /// Pre-serialized RESP_HARMONY_HINTS frames for INDEX groups (0..K-1).
    pub index_frames: Vec<Vec<u8>>,
    /// Pre-serialized RESP_HARMONY_HINTS frames for CHUNK groups (0..K_CHUNK-1).
    pub chunk_frames: Vec<Vec<u8>>,
    /// Pre-built key preamble frame (includes outer length prefix).
    pub key_preamble: Vec<u8>,
    /// When this entry was created.
    pub created_at: Instant,
    /// V2 pool file backing this entry, if it was persisted. The file remains
    /// present while the key is unused and is deleted before `take()` returns
    /// the entry, so a restart can never reuse a consumed key.
    persisted_path: Option<PathBuf>,
}

// ─── Hint pool ───────────────────────────────────────────────────────────────

/// Thread-safe pool of pre-computed hint entries.
///
/// A background thread keeps the pool filled to `config.pool_size`. When a
/// client connects, `take()` pops an entry — zero computation on the hot path.
pub struct HintPool {
    bound_db_id: u8,
    entries: Arc<Mutex<VecDeque<PoolEntry>>>,
    shutdown: Arc<AtomicBool>,
    _generator: Option<JoinHandle<()>>,
}

impl HintPool {
    /// Create a new pool and start the background generator.
    ///
    /// `db` is the database to generate hints against (typically db_id=0,
    /// the main UTXO snapshot).
    pub fn new(
        mut config: HintPoolConfig,
        bound_db_id: u8,
        db: &MappedDatabase,
    ) -> Result<Self, String> {
        validate_prp_backend(config.prp_backend)?;

        let entries = Arc::new(Mutex::new(VecDeque::with_capacity(config.pool_size)));
        let shutdown = Arc::new(AtomicBool::new(false));

        let disk_binding = if config.pool_dir.is_some() {
            PoolFileBinding::for_database(bound_db_id, db, config.prp_backend)?
        } else {
            None
        };
        if config.pool_dir.is_some() && disk_binding.is_none() {
            let dir = config.pool_dir.as_ref().expect("checked above");
            eprintln!(
                "[hint-pool] WARN: db {} lacks a verified manifest or 32-byte bucket Merkle root; disabling disk pool reuse",
                db.descriptor.name
            );
            purge_pool_files(dir);
            config.pool_dir = None;
        }
        if let Some(dir) = config.pool_dir.as_ref() {
            prepare_pool_directory(dir).map_err(|error| {
                format!(
                    "HarmonyPIR pool directory {} is not durably writable: {}",
                    dir.display(),
                    error
                )
            })?;
        }

        // Load any existing pool files from disk before starting generation.
        let initial_entries = match (config.pool_dir.as_ref(), disk_binding.as_ref()) {
            (Some(dir), Some(binding)) => load_pool_files(dir, binding, config.pool_size),
            _ => Vec::new(),
        };
        {
            let mut q = entries.lock().unwrap();
            for e in initial_entries {
                q.push_back(e);
            }
            println!(
                "[hint-pool] Loaded {} entries from disk, target pool size {}",
                q.len(),
                config.pool_size
            );
        }

        // Snapshot the immutable DB parameters for the generator thread.
        let db_params = DbParams {
            index_params: db.index.params.clone(),
            chunk_params: db.chunk.params.clone(),
            index_bins: db.index.bins_per_table,
            chunk_bins: db.chunk.bins_per_table,
            index_entry_size: db.index.params.bin_size(),
            chunk_entry_size: db.chunk.params.bin_size(),
            index_data_offset: db.index.data_offset,
            chunk_data_offset: db.chunk.data_offset,
        };
        let index_mmap_ptr = db.index.mmap.as_ptr() as usize;
        let index_mmap_len = db.index.mmap.len();
        let chunk_mmap_ptr = db.chunk.mmap.as_ptr() as usize;
        let chunk_mmap_len = db.chunk.mmap.len();

        let gen_config = config.clone();
        let gen_shutdown = Arc::clone(&shutdown);
        let gen_entries = Arc::clone(&entries);
        let gen_disk_binding = disk_binding;
        let handle = std::thread::spawn(move || {
            generation_loop(
                gen_config,
                gen_disk_binding,
                db_params,
                index_mmap_ptr,
                index_mmap_len,
                chunk_mmap_ptr,
                chunk_mmap_len,
                &gen_entries,
                &gen_shutdown,
            );
        });

        Ok(HintPool {
            bound_db_id,
            entries,
            shutdown,
            _generator: Some(handle),
        })
    }

    /// Database id whose immutable tables back every entry in this pool.
    pub fn database_id(&self) -> u8 {
        self.bound_db_id
    }

    /// Remove one immediately available entry without blocking the caller.
    /// Returns `None` when the pool is empty or all queued disk entries were
    /// already consumed by another process.
    pub fn try_take(&self) -> Option<PoolEntry> {
        loop {
            let mut entry = {
                let mut q = self.entries.lock().unwrap();
                q.pop_front()
            }?;

            if let Some(path) = entry.persisted_path.take() {
                match consume_pool_file(&path) {
                    Ok(()) => return Some(entry),
                    Err(e) => {
                        // Serving the key while its file is still reusable
                        // would permit the same PRP key to reappear after a
                        // restart. Discard this in-memory entry instead.
                        eprintln!(
                            "[hint-pool] Failed to consume {}: {}; discarding entry",
                            path.display(),
                            e
                        );
                        continue;
                    }
                }
            }
            return Some(entry);
        }
    }

    /// Number of entries currently in the pool.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// True if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for HintPool {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Generator thread will see shutdown=true and exit.
    }
}

// ─── Background generation ───────────────────────────────────────────────────

/// Snapshot of database parameters needed for hint generation.
struct DbParams {
    index_params: pir_core::params::TableParams,
    chunk_params: pir_core::params::TableParams,
    index_bins: usize,
    chunk_bins: usize,
    index_entry_size: usize,
    chunk_entry_size: usize,
    /// Anchor-aware byte offset to the per-group tables (legacy header +
    /// chain-anchor length). MUST be used instead of `*_params.header_size`,
    /// which is legacy-only and reads v2 (anchored) DBs `anchor_len` bytes
    /// too early — see `MappedSubTable::data_offset`. Hints computed at the
    /// wrong offset disagree with the anchor-correct eval path and corrupt
    /// HarmonyPIR reconstruction.
    index_data_offset: usize,
    chunk_data_offset: usize,
}

fn generation_loop(
    config: HintPoolConfig,
    disk_binding: Option<PoolFileBinding>,
    db_params: DbParams,
    index_mmap_ptr: usize,
    index_mmap_len: usize,
    chunk_mmap_ptr: usize,
    chunk_mmap_len: usize,
    entries: &Arc<Mutex<VecDeque<PoolEntry>>>,
    shutdown: &AtomicBool,
) {
    // SAFETY: the mmap lives for the lifetime of the server process.
    // The generator thread only reads from these slices.
    let index_mmap: &[u8] =
        unsafe { std::slice::from_raw_parts(index_mmap_ptr as *const u8, index_mmap_len) };
    let chunk_mmap: &[u8] =
        unsafe { std::slice::from_raw_parts(chunk_mmap_ptr as *const u8, chunk_mmap_len) };

    let index_k = db_params.index_params.k as u32;
    let chunk_k = db_params.chunk_params.k as u32;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Check if we need more entries.
        let need_more = {
            let q = entries.lock().unwrap();
            q.len() < config.pool_size
        };

        if !need_more {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }

        // Generate one pool entry.
        let t0 = Instant::now();
        match generate_pool_entry(
            &config,
            &db_params,
            index_mmap,
            chunk_mmap,
            index_k,
            chunk_k,
        ) {
            Ok(mut entry) => {
                let elapsed = t0.elapsed();
                let prp_key_hex: String = entry
                    .prp_key
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                println!(
                    "[hint-pool] Generated entry (prp_key={}..., {} groups) in {:.2?}",
                    &prp_key_hex[..8],
                    entry.index_frames.len() + entry.chunk_frames.len(),
                    elapsed,
                );

                // Persist to disk if configured.
                if let (Some(dir), Some(binding)) =
                    (config.pool_dir.as_ref(), disk_binding.as_ref())
                {
                    match persist_pool_entry(dir, binding, &entry) {
                        Ok(path) => entry.persisted_path = Some(path),
                        Err(e) => {
                            // A failed durable write (especially an
                            // AlreadyExists collision) must never fall back
                            // to serving an untracked in-memory copy: that
                            // could reuse the key already stored on disk.
                            eprintln!(
                                "[hint-pool] Failed to persist entry; discarding key: {}",
                                e
                            );
                            std::thread::sleep(Duration::from_secs(1));
                            continue;
                        }
                    }
                }

                let mut q = entries.lock().unwrap();
                q.push_back(entry);
            }
            Err(e) => {
                eprintln!("[hint-pool] Generation failed: {}", e);
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }

    println!("[hint-pool] Generator thread shutting down");
}

fn generate_pool_entry(
    config: &HintPoolConfig,
    db_params: &DbParams,
    index_mmap: &[u8],
    chunk_mmap: &[u8],
    index_k: u32,
    chunk_k: u32,
) -> Result<PoolEntry, String> {
    validate_prp_backend(config.prp_backend)?;

    use rand::RngCore;
    let mut prp_key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut prp_key);

    let total_groups = (index_k + chunk_k) as u8;

    // Generate INDEX frames in parallel.
    let index_frames: Vec<Vec<u8>> = (0..index_k)
        .into_par_iter()
        .map(|g| {
            compute_and_serialize_hint_frame(
                &prp_key,
                config.prp_backend,
                0, // level = INDEX
                g,
                0, // k_offset for INDEX groups
                index_mmap,
                db_params.index_data_offset,
                db_params.index_bins,
                db_params.index_entry_size,
            )
        })
        .collect::<Result<_, _>>()?;

    // Generate CHUNK frames in parallel.
    let chunk_frames: Vec<Vec<u8>> = (0..chunk_k)
        .into_par_iter()
        .map(|g| {
            compute_and_serialize_hint_frame(
                &prp_key,
                config.prp_backend,
                1, // level = CHUNK
                g,
                index_k, // k_offset for CHUNK groups
                chunk_mmap,
                db_params.chunk_data_offset,
                db_params.chunk_bins,
                db_params.chunk_entry_size,
            )
        })
        .collect::<Result<_, _>>()?;

    let key_preamble = build_key_preamble(config.prp_backend, total_groups, &prp_key);

    Ok(PoolEntry {
        prp_key,
        prp_backend: config.prp_backend,
        index_frames,
        chunk_frames,
        key_preamble,
        created_at: Instant::now(),
        persisted_path: None,
    })
}

// ─── Hint computation (extracted from unified_server) ────────────────────────

/// Derive a per-group PRP key from the master key. Must match the WASM client.
fn derive_group_key(master_key: &[u8; 16], group_id: u32) -> [u8; 16] {
    let mut key = *master_key;
    let id_bytes = group_id.to_le_bytes();
    for i in 0..4 {
        key[12 + i] ^= id_bytes[i];
    }
    key
}

/// XOR src into dst element-wise.
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

use rayon::prelude::*;

/// Compute hints for a single group and return the pre-serialized
/// RESP_HARMONY_HINTS frame (ready to send on the wire).
///
/// This is the same computation as `compute_hints_for_group()` in
/// `unified_server.rs`, but returns the wire-ready frame directly.
fn compute_and_serialize_hint_frame(
    prp_key: &[u8; 16],
    prp_backend: u8,
    _level: u8,
    group_id: u32,
    k_offset: u32,
    table_mmap: &[u8],
    header_size: usize,
    bins_per_table: usize,
    entry_size: usize,
) -> Result<Vec<u8>, String> {
    validate_prp_backend(prp_backend)?;

    let real_n = bins_per_table;
    let w = entry_size;
    let t_raw = remote::find_best_t(real_n as u32);
    let (padded_n, t_val) = remote::pad_n_for_t(real_n as u32, t_raw)
        .expect("validated non-zero HarmonyPIR hint-pool dimensions");
    let pn = padded_n as usize;
    let t = t_val as usize;

    let params = Params::new(pn, w, t).expect("valid params");
    let m = params.m;

    let derived_key = derive_group_key(prp_key, k_offset + group_id);
    let domain = 2 * pn;
    let r = remote::compute_rounds(padded_n);

    // Batch PRP evaluation.
    // PRP_ALF (= 2) is not part of the remote-client wire contract.
    // for the rationale (panic on domain<65536 crashed pir-vpsbg).
    let cell_of: Vec<usize> = match prp_backend {
        #[cfg(feature = "fastprp")]
        remote::PRP_FASTPRP => {
            use harmonypir::prp::fast::FastPrpWrapper;
            let prp = FastPrpWrapper::new(&derived_key, domain);
            prp.batch_forward()
        }
        remote::PRP_HMR12 => {
            use harmonypir::prp::hoang::HoangPrp;
            let prp = HoangPrp::new(domain, r, &derived_key);
            prp.batch_forward()
        }
        _ => unreachable!("backend validated above"),
    };

    // Scatter-XOR: for each row k, XOR its entry into hints[cell_of[k] / T].
    let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w]).collect();
    let table_offset = header_size + group_id as usize * bins_per_table * entry_size;
    for k in 0..pn {
        let segment = cell_of[k] / t;
        if k < real_n {
            let entry_off = table_offset + k * entry_size;
            let entry = &table_mmap[entry_off..entry_off + entry_size];
            xor_into(&mut hints[segment], entry);
        }
    }

    // Flatten hints and build the RESP_HARMONY_HINTS frame.
    // Frame layout (before outer length prefix):
    //   [RESP_HARMONY_HINTS][1B group_id][4B n LE][4B t LE][4B m LE][flat_hints]
    let flat: Vec<u8> = hints.into_iter().flat_map(|h| h.into_iter()).collect();
    let frame_payload_len: u32 = 1 + 1 + 4 + 4 + 4 + flat.len() as u32;
    let mut frame = Vec::with_capacity(4 + frame_payload_len as usize);
    frame.extend_from_slice(&frame_payload_len.to_le_bytes());
    frame.push(RESP_HARMONY_HINTS);
    frame.push(group_id as u8);
    frame.extend_from_slice(&padded_n.to_le_bytes());
    frame.extend_from_slice(&t_val.to_le_bytes());
    frame.extend_from_slice(&(m as u32).to_le_bytes());
    frame.extend_from_slice(&flat);
    Ok(frame)
}

// ─── Disk persistence ────────────────────────────────────────────────────────

const POOL_FILE_MAGIC: &[u8; 8] = b"HMPOOLV2";
const POOL_FILE_VERSION: u16 = 2;
const POOL_HEADER_LEN: usize = 96;
const POOL_CHECKSUM_LEN: usize = 32;
const MAX_HINT_FRAME_LEN: usize = 512 * 1024 * 1024;
const MAX_POOL_FILE_LEN: u64 = 16 * 1024 * 1024 * 1024;

fn pool_file_name(prp_key: &[u8; 16]) -> String {
    let key_hex: String = prp_key.iter().map(|b| format!("{:02x}", b)).collect();
    format!("pool_{}.hints", key_hex)
}

/// Everything a persisted hint must be bound to before it can be reused.
/// `fingerprint` includes the bucket Merkle super-root (which commits the
/// INDEX and CHUNK tables), manifest root, both chain anchors, geometry, and
/// backend. A manifest without the bucket root is insufficient because large
/// cuckoo files may use a zero hash sentinel in production manifests.
#[derive(Clone, Debug)]
struct PoolFileBinding {
    fingerprint: [u8; 32],
    bound_db_id: u8,
    prp_backend: u8,
    index_groups: usize,
    chunk_groups: usize,
    index_bins: usize,
    chunk_bins: usize,
    index_entry_size: usize,
    chunk_entry_size: usize,
}

impl PoolFileBinding {
    fn for_database(
        bound_db_id: u8,
        db: &MappedDatabase,
        prp_backend: u8,
    ) -> Result<Option<Self>, String> {
        validate_prp_backend(prp_backend)?;
        let Some(manifest_root) = db.manifest_root else {
            return Ok(None);
        };
        let Some(bucket_root) = db.bucket_merkle_root.as_deref() else {
            return Ok(None);
        };
        if bucket_root.len() != 32 {
            return Ok(None);
        }

        let index_groups = db.index.params.k;
        let chunk_groups = db.chunk.params.k;
        let total_groups = index_groups
            .checked_add(chunk_groups)
            .ok_or_else(|| "HarmonyPIR group count overflow".to_string())?;
        u8::try_from(total_groups)
            .map_err(|_| format!("HarmonyPIR total group count {} exceeds u8", total_groups))?;

        let mut preimage = Vec::with_capacity(384);
        preimage.extend_from_slice(b"BitcoinPIR/harmony-hint-pool-db/v2\0");
        preimage.push(bound_db_id);
        preimage.push(prp_backend);
        preimage.extend_from_slice(&manifest_root);
        preimage.extend_from_slice(bucket_root);
        preimage.push(match db.descriptor.db_type {
            pir_runtime_core::table::DatabaseType::Full => 0,
            pir_runtime_core::table::DatabaseType::Delta => 1,
        });
        preimage.extend_from_slice(&db.descriptor.base_height.to_le_bytes());
        preimage.extend_from_slice(&db.descriptor.height.to_le_bytes());
        append_anchor(&mut preimage, db.index.anchor);
        append_anchor(&mut preimage, db.chunk.anchor);
        append_subtable_geometry(&mut preimage, &db.index);
        append_subtable_geometry(&mut preimage, &db.chunk);

        Ok(Some(Self {
            fingerprint: pir_core::merkle::sha256(&preimage),
            bound_db_id,
            prp_backend,
            index_groups,
            chunk_groups,
            index_bins: db.index.bins_per_table,
            chunk_bins: db.chunk.bins_per_table,
            index_entry_size: db.index.params.bin_size(),
            chunk_entry_size: db.chunk.params.bin_size(),
        }))
    }

    fn total_groups(&self) -> u8 {
        u8::try_from(self.index_groups + self.chunk_groups)
            .expect("validated while constructing PoolFileBinding")
    }
}

fn append_anchor(out: &mut Vec<u8>, anchor: Option<pir_core::cuckoo::HeaderAnchor>) {
    match anchor {
        None => out.push(0),
        Some(pir_core::cuckoo::HeaderAnchor::Snapshot(anchor)) => {
            out.push(1);
            out.extend_from_slice(&anchor.to_bytes());
        }
        Some(pir_core::cuckoo::HeaderAnchor::Delta(anchor)) => {
            out.push(2);
            out.extend_from_slice(&anchor.to_bytes());
        }
    }
}

fn append_subtable_geometry(out: &mut Vec<u8>, table: &pir_runtime_core::table::MappedSubTable) {
    for value in [
        table.params.k,
        table.params.num_hashes,
        table.params.slots_per_bin,
        table.params.cuckoo_num_hashes,
        table.params.slot_size,
        table.params.dpf_n as usize,
        table.params.header_size,
        table.bins_per_table,
        table.table_byte_size,
        table.data_offset,
        table.mmap.len(),
    ] {
        out.extend_from_slice(&(value as u64).to_le_bytes());
    }
    out.extend_from_slice(&table.params.magic.to_le_bytes());
    out.extend_from_slice(&table.master_seed.to_le_bytes());
    out.extend_from_slice(&table.tag_seed.to_le_bytes());
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn encoded_body_len(entry: &PoolEntry) -> io::Result<u64> {
    entry
        .index_frames
        .iter()
        .chain(&entry.chunk_frames)
        .chain(std::iter::once(&entry.key_preamble))
        .try_fold(0u64, |sum, frame| {
            let len = u64::try_from(frame.len()).map_err(|_| invalid_data("frame too large"))?;
            sum.checked_add(4)
                .and_then(|v| v.checked_add(len))
                .ok_or_else(|| invalid_data("pool body length overflow"))
        })
}

fn build_pool_header(
    binding: &PoolFileBinding,
    entry: &PoolEntry,
    body_len: u64,
    created_ts: u64,
) -> io::Result<[u8; POOL_HEADER_LEN]> {
    let index_groups = u32::try_from(entry.index_frames.len())
        .map_err(|_| invalid_data("too many INDEX frames"))?;
    let chunk_groups = u32::try_from(entry.chunk_frames.len())
        .map_err(|_| invalid_data("too many CHUNK frames"))?;
    let mut header = [0u8; POOL_HEADER_LEN];
    header[0..8].copy_from_slice(POOL_FILE_MAGIC);
    header[8..10].copy_from_slice(&POOL_FILE_VERSION.to_le_bytes());
    header[10..12].copy_from_slice(&(POOL_HEADER_LEN as u16).to_le_bytes());
    header[12] = entry.prp_backend;
    header[13] = binding.bound_db_id;
    // 14..16 reserved and required to remain zero.
    header[16..48].copy_from_slice(&binding.fingerprint);
    header[48..64].copy_from_slice(&entry.prp_key);
    header[64..72].copy_from_slice(&created_ts.to_le_bytes());
    header[72..76].copy_from_slice(&index_groups.to_le_bytes());
    header[76..80].copy_from_slice(&chunk_groups.to_le_bytes());
    header[80..88].copy_from_slice(&body_len.to_le_bytes());
    // 88..96 reserved and required to remain zero.
    Ok(header)
}

fn entry_checksum(
    header: &[u8; POOL_HEADER_LEN],
    index_frames: &[Vec<u8>],
    chunk_frames: &[Vec<u8>],
    key_preamble: &[u8],
) -> [u8; 32] {
    // Hashing each large frame separately avoids constructing a second copy
    // of the complete (tens-of-MiB) pool file merely to checksum it.
    let mut preimage = Vec::with_capacity(
        32 + POOL_HEADER_LEN + (index_frames.len() + chunk_frames.len() + 1) * 40,
    );
    preimage.extend_from_slice(b"BitcoinPIR/harmony-hint-pool-file/v2\0");
    preimage.extend_from_slice(header);
    for frame in index_frames
        .iter()
        .chain(chunk_frames)
        .map(Vec::as_slice)
        .chain(std::iter::once(key_preamble))
    {
        preimage.extend_from_slice(&(frame.len() as u64).to_le_bytes());
        preimage.extend_from_slice(&pir_core::merkle::sha256(frame));
    }
    pir_core::merkle::sha256(&preimage)
}

fn expected_hint_frame_len(bins: usize, entry_size: usize) -> io::Result<(u32, u32, u32, usize)> {
    let bins_u32 = u32::try_from(bins).map_err(|_| invalid_data("bin count exceeds u32"))?;
    let t_raw = remote::find_best_t(bins_u32);
    let (padded_n, t_val) = remote::pad_n_for_t(bins_u32, t_raw)
        .expect("validated non-zero HarmonyPIR tree-top dimensions");
    let params = Params::new(padded_n as usize, entry_size, t_val as usize)
        .map_err(|e| invalid_data(format!("invalid persisted hint geometry: {}", e)))?;
    let flat_len = params
        .m
        .checked_mul(entry_size)
        .ok_or_else(|| invalid_data("hint frame length overflow"))?;
    let frame_len = 18usize
        .checked_add(flat_len)
        .ok_or_else(|| invalid_data("hint frame length overflow"))?;
    if frame_len > MAX_HINT_FRAME_LEN {
        return Err(invalid_data(format!(
            "hint frame length {} exceeds limit {}",
            frame_len, MAX_HINT_FRAME_LEN
        )));
    }
    Ok((padded_n, t_val, params.m as u32, frame_len))
}

fn validate_hint_frame(
    frame: &[u8],
    expected_group: usize,
    bins: usize,
    entry_size: usize,
) -> io::Result<()> {
    let (n, t, m, expected_len) = expected_hint_frame_len(bins, entry_size)?;
    if frame.len() != expected_len {
        return Err(invalid_data(format!(
            "hint frame length {} != expected {}",
            frame.len(),
            expected_len
        )));
    }
    let outer_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
    if outer_len != frame.len() - 4
        || frame[4] != RESP_HARMONY_HINTS
        || frame[5] as usize != expected_group
        || u32::from_le_bytes(frame[6..10].try_into().unwrap()) != n
        || u32::from_le_bytes(frame[10..14].try_into().unwrap()) != t
        || u32::from_le_bytes(frame[14..18].try_into().unwrap()) != m
    {
        return Err(invalid_data("persisted hint frame metadata mismatch"));
    }
    Ok(())
}

fn validate_pool_entry(binding: &PoolFileBinding, entry: &PoolEntry) -> io::Result<()> {
    validate_prp_backend(entry.prp_backend).map_err(invalid_data)?;
    if entry.prp_backend != binding.prp_backend {
        return Err(invalid_data("pool entry PRP backend mismatch"));
    }
    if entry.index_frames.len() != binding.index_groups
        || entry.chunk_frames.len() != binding.chunk_groups
    {
        return Err(invalid_data("pool entry group count mismatch"));
    }
    for (group, frame) in entry.index_frames.iter().enumerate() {
        validate_hint_frame(frame, group, binding.index_bins, binding.index_entry_size)?;
    }
    for (group, frame) in entry.chunk_frames.iter().enumerate() {
        validate_hint_frame(frame, group, binding.chunk_bins, binding.chunk_entry_size)?;
    }
    let expected_preamble =
        build_key_preamble(binding.prp_backend, binding.total_groups(), &entry.prp_key);
    if entry.key_preamble != expected_preamble {
        return Err(invalid_data("pool entry key preamble mismatch"));
    }
    Ok(())
}

fn write_lp(writer: &mut File, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| invalid_data("frame exceeds u32"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(bytes)
}

/// Persist a validated V2 pool entry using fsync + atomic rename. Returns the
/// final path so the in-memory entry can delete exactly that file on consume.
fn persist_pool_entry(
    pool_dir: &Path,
    binding: &PoolFileBinding,
    entry: &PoolEntry,
) -> io::Result<PathBuf> {
    validate_pool_entry(binding, entry)?;
    std::fs::create_dir_all(pool_dir)?;

    let body_len = encoded_body_len(entry)?;
    let total_len = (POOL_HEADER_LEN as u64)
        .checked_add(body_len)
        .and_then(|v| v.checked_add(POOL_CHECKSUM_LEN as u64))
        .ok_or_else(|| invalid_data("pool file length overflow"))?;
    if total_len > MAX_POOL_FILE_LEN {
        return Err(invalid_data(format!(
            "pool file length {} exceeds limit {}",
            total_len, MAX_POOL_FILE_LEN
        )));
    }

    let file_name = pool_file_name(&entry.prp_key);
    let path = pool_dir.join(&file_name);
    let tmp_path = pool_dir.join(format!("{}.tmp", file_name));
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("pool key file already exists: {}", path.display()),
        ));
    }

    let created_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let header = build_pool_header(binding, entry, body_len, created_ts)?;
    let checksum = entry_checksum(
        &header,
        &entry.index_frames,
        &entry.chunk_frames,
        &entry.key_preamble,
    );

    let write_result = (|| -> io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(&header)?;
        for frame in &entry.index_frames {
            write_lp(&mut file, frame)?;
        }
        for frame in &entry.chunk_frames {
            write_lp(&mut file, frame)?;
        }
        write_lp(&mut file, &entry.key_preamble)?;
        file.write_all(&checksum)?;
        file.sync_all()?;
        std::fs::rename(&tmp_path, &path)?;
        sync_directory(pool_dir)
    })();

    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(error);
    }
    Ok(path)
}

fn read_lp(
    file: &mut File,
    body_read: &mut u64,
    body_len: u64,
    expected_len: usize,
) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    file.read_exact(&mut len_bytes)?;
    *body_read = body_read
        .checked_add(4)
        .ok_or_else(|| invalid_data("pool body offset overflow"))?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len != expected_len || len > MAX_HINT_FRAME_LEN {
        return Err(invalid_data(format!(
            "persisted frame length {} != expected {}",
            len, expected_len
        )));
    }
    let new_body_read = body_read
        .checked_add(len as u64)
        .ok_or_else(|| invalid_data("pool body offset overflow"))?;
    if new_body_read > body_len {
        return Err(invalid_data("persisted frame exceeds declared body length"));
    }
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes)?;
    *body_read = new_body_read;
    Ok(bytes)
}

fn load_pool_file(path: &Path, binding: &PoolFileBinding) -> io::Result<PoolEntry> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len > MAX_POOL_FILE_LEN {
        return Err(invalid_data("pool file exceeds maximum length"));
    }

    let mut header = [0u8; POOL_HEADER_LEN];
    file.read_exact(&mut header)?;
    if &header[0..8] != POOL_FILE_MAGIC {
        return Err(invalid_data("not a HarmonyPIR pool V2 file"));
    }
    if u16::from_le_bytes(header[8..10].try_into().unwrap()) != POOL_FILE_VERSION
        || u16::from_le_bytes(header[10..12].try_into().unwrap()) as usize != POOL_HEADER_LEN
    {
        return Err(invalid_data(
            "unsupported pool file version or header length",
        ));
    }
    if header[14..16] != [0u8; 2] || header[88..96] != [0u8; 8] {
        return Err(invalid_data("non-zero reserved pool header bytes"));
    }

    let prp_backend = header[12];
    validate_prp_backend(prp_backend).map_err(invalid_data)?;
    if prp_backend != binding.prp_backend {
        return Err(invalid_data("pool file PRP backend mismatch"));
    }
    if header[13] != binding.bound_db_id {
        return Err(invalid_data("pool file database id mismatch"));
    }
    if header[16..48] != binding.fingerprint {
        return Err(invalid_data("pool file database fingerprint mismatch"));
    }

    let index_groups = u32::from_le_bytes(header[72..76].try_into().unwrap()) as usize;
    let chunk_groups = u32::from_le_bytes(header[76..80].try_into().unwrap()) as usize;
    if index_groups != binding.index_groups || chunk_groups != binding.chunk_groups {
        return Err(invalid_data("pool file group geometry mismatch"));
    }
    let body_len = u64::from_le_bytes(header[80..88].try_into().unwrap());
    let expected_file_len = (POOL_HEADER_LEN as u64)
        .checked_add(body_len)
        .and_then(|v| v.checked_add(POOL_CHECKSUM_LEN as u64))
        .ok_or_else(|| invalid_data("pool file length overflow"))?;
    if file_len != expected_file_len {
        return Err(invalid_data(format!(
            "pool file length {} != declared {}",
            file_len, expected_file_len
        )));
    }

    let mut prp_key = [0u8; 16];
    prp_key.copy_from_slice(&header[48..64]);
    let expected_name = pool_file_name(&prp_key);
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
        return Err(invalid_data("pool filename does not match its PRP key"));
    }
    let (_, _, _, index_frame_len) =
        expected_hint_frame_len(binding.index_bins, binding.index_entry_size)?;
    let (_, _, _, chunk_frame_len) =
        expected_hint_frame_len(binding.chunk_bins, binding.chunk_entry_size)?;
    let mut body_read = 0u64;
    let mut index_frames = Vec::with_capacity(index_groups);
    for group in 0..index_groups {
        let frame = read_lp(&mut file, &mut body_read, body_len, index_frame_len)?;
        validate_hint_frame(&frame, group, binding.index_bins, binding.index_entry_size)?;
        index_frames.push(frame);
    }
    let mut chunk_frames = Vec::with_capacity(chunk_groups);
    for group in 0..chunk_groups {
        let frame = read_lp(&mut file, &mut body_read, body_len, chunk_frame_len)?;
        validate_hint_frame(&frame, group, binding.chunk_bins, binding.chunk_entry_size)?;
        chunk_frames.push(frame);
    }
    let expected_preamble = build_key_preamble(prp_backend, binding.total_groups(), &prp_key);
    let key_preamble = read_lp(&mut file, &mut body_read, body_len, expected_preamble.len())?;
    if key_preamble != expected_preamble || body_read != body_len {
        return Err(invalid_data(
            "pool file key preamble or body length mismatch",
        ));
    }

    let mut stored_checksum = [0u8; POOL_CHECKSUM_LEN];
    file.read_exact(&mut stored_checksum)?;
    let expected_checksum = entry_checksum(&header, &index_frames, &chunk_frames, &key_preamble);
    if stored_checksum != expected_checksum {
        return Err(invalid_data("pool file checksum mismatch"));
    }
    let mut trailing = [0u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(invalid_data("pool file has trailing bytes"));
    }

    Ok(PoolEntry {
        prp_key,
        prp_backend,
        index_frames,
        chunk_frames,
        key_preamble,
        created_at: Instant::now(),
        persisted_path: Some(path.to_path_buf()),
    })
}

/// Load only matching, unconsumed V2 entries. Every legacy, mismatched,
/// corrupt, temporary, or surplus file is deleted safely and replenished by
/// the generator.
fn load_pool_files(pool_dir: &Path, binding: &PoolFileBinding, pool_size: usize) -> Vec<PoolEntry> {
    let read_dir = match std::fs::read_dir(pool_dir) {
        Ok(read_dir) => read_dir,
        Err(_) => return Vec::new(),
    };
    let mut candidates = Vec::new();
    for dir_entry in read_dir.flatten() {
        let path = dir_entry.path();
        let name = dir_entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("pool_") {
            continue;
        }
        if name.ends_with(".hints.tmp") || name.ends_with(".hints.consumed") {
            let _ = std::fs::remove_file(path);
        } else if name.ends_with(".hints") {
            match dir_entry.file_type() {
                Ok(file_type) if file_type.is_file() => candidates.push(path),
                _ => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }
    candidates.sort();

    let mut entries = Vec::with_capacity(pool_size.min(candidates.len()));
    let mut loaded_keys = std::collections::HashSet::new();
    for path in candidates {
        if entries.len() >= pool_size {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        match load_pool_file(&path, binding) {
            Ok(entry) if loaded_keys.insert(entry.prp_key) => entries.push(entry),
            Ok(_) => {
                eprintln!(
                    "[hint-pool] Removing duplicate PRP key file {}",
                    path.display()
                );
                let _ = std::fs::remove_file(&path);
            }
            Err(error) => {
                eprintln!(
                    "[hint-pool] Removing unusable {}: {}",
                    path.display(),
                    error
                );
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    entries
}

fn is_pool_artifact(name: &str) -> bool {
    name.starts_with("pool_")
        && (name.ends_with(".hints")
            || name.ends_with(".hints.tmp")
            || name.ends_with(".hints.consumed"))
}

fn purge_pool_files(pool_dir: &Path) {
    let Ok(read_dir) = std::fs::read_dir(pool_dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        let name = entry.file_name();
        if is_pool_artifact(&name.to_string_lossy()) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    let _ = sync_directory(pool_dir);
}

fn consume_pool_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn prepare_pool_directory(path: &Path) -> io::Result<()> {
    use rand::RngCore;

    std::fs::create_dir_all(path)?;
    if !std::fs::metadata(path)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configured pool path is not a directory",
        ));
    }

    let nonce = rand::thread_rng().next_u64();
    let probe_name = format!(".hmpool-probe-{}-{:016x}", std::process::id(), nonce);
    let tmp_path = path.join(format!("{}.tmp", probe_name));
    let final_path = path.join(probe_name);
    let result = (|| -> io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(b"HMPOOL-DURABILITY-PROBE")?;
        file.sync_all()?;
        std::fs::rename(&tmp_path, &final_path)?;
        sync_directory(path)?;
        std::fs::remove_file(&final_path)?;
        sync_directory(path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        let _ = std::fs::remove_file(&final_path);
    }
    result
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let unique = NEXT_TEST_DIR.fetch_add(1, AtomicOrdering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "bitcoinpir-hint-pool-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                unique
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_binding(fingerprint: u8) -> PoolFileBinding {
        PoolFileBinding {
            fingerprint: [fingerprint; 32],
            bound_db_id: 0,
            prp_backend: remote::PRP_HMR12,
            index_groups: 2,
            chunk_groups: 1,
            index_bins: 8,
            chunk_bins: 6,
            index_entry_size: 4,
            chunk_entry_size: 5,
        }
    }

    fn test_hint_frame(group: usize, bins: usize, entry_size: usize) -> Vec<u8> {
        let (n, t, m, len) = expected_hint_frame_len(bins, entry_size).unwrap();
        let mut frame = Vec::with_capacity(len);
        frame.extend_from_slice(&((len - 4) as u32).to_le_bytes());
        frame.push(RESP_HARMONY_HINTS);
        frame.push(group as u8);
        frame.extend_from_slice(&n.to_le_bytes());
        frame.extend_from_slice(&t.to_le_bytes());
        frame.extend_from_slice(&m.to_le_bytes());
        frame.resize(len, group as u8);
        frame
    }

    fn test_entry(binding: &PoolFileBinding) -> PoolEntry {
        let prp_key = [0x42; 16];
        PoolEntry {
            prp_key,
            prp_backend: binding.prp_backend,
            index_frames: (0..binding.index_groups)
                .map(|group| test_hint_frame(group, binding.index_bins, binding.index_entry_size))
                .collect(),
            chunk_frames: (0..binding.chunk_groups)
                .map(|group| test_hint_frame(group, binding.chunk_bins, binding.chunk_entry_size))
                .collect(),
            key_preamble: build_key_preamble(binding.prp_backend, binding.total_groups(), &prp_key),
            created_at: Instant::now(),
            persisted_path: None,
        }
    }

    #[test]
    fn pool_v2_roundtrip() {
        let dir = TestDir::new();
        let binding = test_binding(0x11);
        let entry = test_entry(&binding);
        let path = persist_pool_entry(&dir.0, &binding, &entry).unwrap();

        let loaded = load_pool_files(&dir.0, &binding, 4);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].prp_key, entry.prp_key);
        assert_eq!(loaded[0].index_frames, entry.index_frames);
        assert_eq!(loaded[0].chunk_frames, entry.chunk_frames);
        assert_eq!(loaded[0].persisted_path.as_deref(), Some(path.as_path()));
        assert!(path.exists(), "unused key must remain durable until take");
    }

    #[test]
    fn legacy_v1_file_is_rejected_and_deleted() {
        let dir = TestDir::new();
        let path = dir.0.join("pool_00000000.hints");
        let mut legacy = vec![0u8; POOL_HEADER_LEN + POOL_CHECKSUM_LEN];
        legacy[..7].copy_from_slice(b"HMPOOL\x01");
        std::fs::write(&path, legacy).unwrap();

        assert!(load_pool_files(&dir.0, &test_binding(1), 4).is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn fingerprint_mismatch_is_rejected_and_deleted() {
        let dir = TestDir::new();
        let original = test_binding(0x22);
        let path = persist_pool_entry(&dir.0, &original, &test_entry(&original)).unwrap();

        assert!(load_pool_files(&dir.0, &test_binding(0x23), 4).is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn database_id_mismatch_is_rejected_and_deleted() {
        let dir = TestDir::new();
        let original = test_binding(0x24);
        let path = persist_pool_entry(&dir.0, &original, &test_entry(&original)).unwrap();
        let mut other_database = original.clone();
        other_database.bound_db_id = 1;

        assert!(load_pool_files(&dir.0, &other_database, 4).is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn noncanonical_key_filename_is_rejected_and_deleted() {
        let dir = TestDir::new();
        let binding = test_binding(0x25);
        let canonical = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let copied_name = dir
            .0
            .join("pool_00000000000000000000000000000000.hints");
        std::fs::rename(&canonical, &copied_name).unwrap();

        assert!(load_pool_files(&dir.0, &binding, 4).is_empty());
        assert!(!copied_name.exists());
    }

    #[test]
    fn take_deletes_the_backing_file() {
        let dir = TestDir::new();
        let binding = test_binding(0x33);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let loaded = load_pool_files(&dir.0, &binding, 1);
        let pool = HintPool {
            bound_db_id: binding.bound_db_id,
            entries: Arc::new(Mutex::new(VecDeque::from(loaded))),
            shutdown: Arc::new(AtomicBool::new(false)),
            _generator: None,
        };

        assert_eq!(pool.database_id(), 0);
        assert!(pool.try_take().is_some());
        assert!(
            !path.exists(),
            "take must delete a consumed key before returning it"
        );
    }

    #[test]
    fn take_discards_entry_when_another_process_consumed_the_file() {
        let dir = TestDir::new();
        let binding = test_binding(0x34);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let loaded = load_pool_files(&dir.0, &binding, 1);
        std::fs::remove_file(&path).unwrap();
        let pool = HintPool {
            bound_db_id: binding.bound_db_id,
            entries: Arc::new(Mutex::new(VecDeque::from(loaded))),
            shutdown: Arc::new(AtomicBool::new(true)),
            _generator: None,
        };

        assert!(
            pool.try_take().is_none(),
            "a missing file means this key may already be consumed"
        );
    }

    #[test]
    fn empty_pool_is_immediately_nonblocking_under_concurrency() {
        let pool = Arc::new(HintPool {
            bound_db_id: 0,
            entries: Arc::new(Mutex::new(VecDeque::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            _generator: None,
        });
        let workers: Vec<_> = (0..32)
            .map(|_| {
                let pool = Arc::clone(&pool);
                std::thread::spawn(move || assert!(pool.try_take().is_none()))
            })
            .collect();

        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn pool_directory_durability_probe_succeeds_and_cleans_up() {
        let dir = TestDir::new();
        prepare_pool_directory(&dir.0).unwrap();
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);

        let not_a_directory = dir.0.join("file");
        std::fs::write(&not_a_directory, b"x").unwrap();
        assert!(prepare_pool_directory(&not_a_directory).is_err());
    }

    #[test]
    fn unsupported_backend_is_an_error() {
        let error =
            compute_and_serialize_hint_frame(&[0u8; 16], 0xfe, 0, 0, 0, &[], 0, 1, 1).unwrap_err();
        assert!(error.contains("unsupported"));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let dir = TestDir::new();
        let binding = test_binding(0x44);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();

        assert!(load_pool_files(&dir.0, &binding, 1).is_empty());
        assert!(!path.exists());
    }

    #[cfg(not(feature = "fastprp"))]
    #[test]
    fn no_fastprp_build_defaults_to_hmr12() {
        assert_eq!(default_prp_backend(), remote::PRP_HMR12);
        assert!(validate_prp_backend(remote::PRP_FASTPRP).is_err());
    }
}
