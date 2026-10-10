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
//!
//! ## Disk persistence
//!
//! With `pool_dir`, every generated entry is also written to
//! `pool_<key>.hints` (format `HMPOOLV2`, bound to its database by a
//! fingerprint) and loaded again at startup. Taking an entry removes its file
//! first, so a hint set is served at most once even when processes share the
//! directory.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use harmonypir::params::Params;
use harmonypir::prp::BatchPrp;
use harmonypir::remote;

use pir_runtime_core::table::MappedDatabase;

#[cfg(feature = "test-only-unsafe-query-logging")]
macro_rules! unsafe_hint_pool_log {
    ($($arg:tt)*) => {
        eprintln!($($arg)*);
    };
}

#[cfg(not(feature = "test-only-unsafe-query-logging"))]
macro_rules! unsafe_hint_pool_log {
    ($($arg:tt)*) => {{}};
}

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
    /// The `pool_<key>.hints` file holding this entry, if it was persisted.
    persisted_path: Option<PathBuf>,
}

// ─── Hint pool ───────────────────────────────────────────────────────────────

/// Thread-safe pool of pre-computed hint entries.
///
/// A background thread keeps the pool filled to `config.pool_size`. When a
/// client connects, `try_take()` pops an entry — zero computation on the hot
/// path.
pub struct HintPool {
    entries: Arc<Mutex<VecDeque<PoolEntry>>>,
    shutdown: Arc<AtomicBool>,
    generator: Option<JoinHandle<()>>,
}

impl HintPool {
    /// Create a new pool and start the background generator.
    ///
    /// `db` is the database `bound_db_id` names; every entry is computed from
    /// its tables.
    pub fn new(
        config: HintPoolConfig,
        bound_db_id: u8,
        db: &MappedDatabase,
    ) -> Result<Self, String> {
        validate_prp_backend(config.prp_backend)?;

        // Files are bound to the database fingerprint, which needs the
        // manifest and bucket Merkle roots; without them the pool stays in
        // memory.
        let mut disk = None;
        if let Some(dir) = config.pool_dir.clone() {
            match PoolFileBinding::for_database(bound_db_id, db, config.prp_backend)? {
                Some(binding) => disk = Some((dir, binding)),
                None => eprintln!(
                    "[hint-pool] WARN: db {} lacks a manifest or 32-byte bucket Merkle root; the pool is memory-only",
                    db.descriptor.name
                ),
            }
        }

        let mut entries = VecDeque::with_capacity(config.pool_size);
        if let Some((dir, binding)) = disk.as_ref() {
            let loaded = open_pool_directory(dir, binding, config.pool_size).map_err(|error| {
                format!("HarmonyPIR pool directory {}: {}", dir.display(), error)
            })?;
            entries.extend(loaded);
        }
        println!(
            "[hint-pool] Loaded {} entries from disk, target pool size {}",
            entries.len(),
            config.pool_size
        );
        let entries = Arc::new(Mutex::new(entries));
        let shutdown = Arc::new(AtomicBool::new(false));

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
        // The worker owns strong references to both mappings, so the bytes it
        // reads stay alive whatever order the server state drops in.
        let index_mmap = Arc::clone(&db.index.mmap);
        let chunk_mmap = Arc::clone(&db.chunk.mmap);

        let generator = {
            let entries = Arc::clone(&entries);
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                generation_loop(
                    config,
                    bound_db_id,
                    disk,
                    db_params,
                    index_mmap,
                    chunk_mmap,
                    &entries,
                    &shutdown,
                );
            })
        };

        Ok(HintPool {
            entries,
            shutdown,
            generator: Some(generator),
        })
    }

    /// Pop one entry. A persisted entry's file is removed before the entry is
    /// returned; when another process sharing the directory already took it,
    /// the entry is skipped.
    pub fn try_take(&self) -> Option<PoolEntry> {
        loop {
            let mut entry = self.entries.lock().unwrap().pop_front()?;
            let Some(path) = entry.persisted_path.take() else {
                return Some(entry);
            };
            match std::fs::remove_file(&path) {
                Ok(()) => return Some(entry),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                // A file that stays could be loaded and served again after a
                // restart, so the entry is dropped instead.
                Err(_error) => {
                    eprintln!("[hint-pool] Failed to remove a served entry's file");
                    unsafe_hint_pool_log!(
                        "[hint-pool] remove detail for {}: {}",
                        path.display(),
                        _error
                    );
                }
            }
        }
    }
}

impl Drop for HintPool {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(generator) = self.generator.take() {
            // After Drop returns no worker reads the database mappings.
            let _ = generator.join();
        }
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

/// How often the generator prints its aggregate timing summary.
const GENERATION_TIMING_REPORT_INTERVAL: Duration = Duration::from_secs(3600);

/// Aggregate wall-clock timing of hint-set generation, reported once per
/// interval for capacity planning and pricing (pain point 3 of
/// docs/history/PIR2_DEPLOYMENT_PAIN_POINTS_2026-09.md). The summary carries
/// only a count and mean/max seconds per generated entry: no key, no group,
/// no per-entry line, and it is emitted on the interval boundary from the
/// generator's idle loop rather than at generation time, so its timestamp
/// does not mark when a client took a hint set.
struct GenerationTimingWindow {
    db_id: u8,
    interval: Duration,
    window_started: Instant,
    count: u64,
    total: Duration,
    max: Duration,
}

impl GenerationTimingWindow {
    fn new(db_id: u8, interval: Duration, now: Instant) -> Self {
        Self {
            db_id,
            interval,
            window_started: now,
            count: 0,
            total: Duration::ZERO,
            max: Duration::ZERO,
        }
    }

    fn record(&mut self, generation_time: Duration) {
        self.count += 1;
        self.total += generation_time;
        self.max = self.max.max(generation_time);
    }

    /// The summary line once `interval` has passed, then a fresh window.
    fn due(&mut self, now: Instant) -> Option<String> {
        if now.saturating_duration_since(self.window_started) < self.interval {
            return None;
        }
        let mean_secs = if self.count == 0 {
            0.0
        } else {
            self.total.as_secs_f64() / self.count as f64
        };
        let line = format!(
            "[hint-pool db={}] last {}s: generated={} wall_mean_s={:.1} wall_max_s={:.1}",
            self.db_id,
            self.interval.as_secs(),
            self.count,
            mean_secs,
            self.max.as_secs_f64(),
        );
        self.window_started = now;
        self.count = 0;
        self.total = Duration::ZERO;
        self.max = Duration::ZERO;
        Some(line)
    }
}

#[allow(clippy::too_many_arguments)]
fn generation_loop(
    config: HintPoolConfig,
    db_id: u8,
    disk: Option<(PathBuf, PoolFileBinding)>,
    db_params: DbParams,
    index_mmap: Arc<memmap2::Mmap>,
    chunk_mmap: Arc<memmap2::Mmap>,
    entries: &Mutex<VecDeque<PoolEntry>>,
    shutdown: &AtomicBool,
) {
    let index_k = db_params.index_params.k as u32;
    let chunk_k = db_params.chunk_params.k as u32;
    let mut timing =
        GenerationTimingWindow::new(db_id, GENERATION_TIMING_REPORT_INTERVAL, Instant::now());

    while !shutdown.load(Ordering::Acquire) {
        // Aggregate timing summary on the interval boundary (idle or busy),
        // never on a generation event.
        if let Some(line) = timing.due(Instant::now()) {
            println!("{line}");
        }
        if entries.lock().unwrap().len() >= config.pool_size {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }

        let started = Instant::now();
        let mut entry = match generate_pool_entry(
            &config,
            &db_params,
            &index_mmap,
            &chunk_mmap,
            index_k,
            chunk_k,
        ) {
            Ok(entry) => entry,
            Err(_error) => {
                eprintln!("[hint-pool] Hint generation failed");
                unsafe_hint_pool_log!("[hint-pool] hint generation detail: {}", _error);
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        timing.record(started.elapsed());
        #[cfg(feature = "test-only-unsafe-query-logging")]
        {
            let elapsed = started.elapsed();
            unsafe_hint_pool_log!(
                "[hint-pool] Generated entry (prp_key={}..., {} groups) in {:.2?}",
                hex_prefix(&entry.prp_key),
                entry.index_frames.len() + entry.chunk_frames.len(),
                elapsed,
            );
        }
        if let Some((dir, binding)) = disk.as_ref() {
            match persist_pool_entry(dir, binding, &entry) {
                Ok(path) => entry.persisted_path = Some(path),
                // Still served from memory; only reuse after a restart is lost.
                Err(_error) => {
                    eprintln!("[hint-pool] Failed to persist a generated entry");
                    unsafe_hint_pool_log!(
                        "[hint-pool] generated-entry persistence detail: {}",
                        _error
                    );
                }
            }
        }
        entries.lock().unwrap().push_back(entry);
    }

    println!("[hint-pool] Generator thread shutting down");
}

#[cfg(feature = "test-only-unsafe-query-logging")]
fn hex_prefix(key: &[u8; 16]) -> String {
    key[..4].iter().map(|byte| format!("{byte:02x}")).collect()
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
/// `unified_server/`, but returns the wire-ready frame directly.
#[allow(clippy::too_many_arguments)] // Mirrors the wire computation's fixed inputs.
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
    for (k, cell) in cell_of.iter().copied().enumerate().take(pn) {
        let segment = cell / t;
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
const BINDING_MARKER_FILE: &str = ".hmpool-binding-v1";
const BINDING_MARKER_TMP_PREFIX: &str = ".hmpool-binding-v1.tmp.";
const BINDING_MARKER_MAGIC: &[u8; 8] = b"HMPBIND1";
const BINDING_MARKER_VERSION: u16 = 1;
const BINDING_MARKER_LEN: usize = 96;
const TMP_MARKER: &str = ".hints.tmp.";

fn pool_file_name(prp_key: &[u8; 16]) -> String {
    let key_hex: String = prp_key.iter().map(|b| format!("{:02x}", b)).collect();
    format!("pool_{}.hints", key_hex)
}

/// Pool files hold PRP keys, so they are owner-only, like the directory.
fn create_owner_only(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

/// Create or reuse `pool_dir` for `binding`: write the binding marker, drop
/// interrupted writes, and load up to `pool_size` entries. Files that are
/// corrupt or belong to another database or backend are removed.
fn open_pool_directory(
    pool_dir: &Path,
    binding: &PoolFileBinding,
    pool_size: usize,
) -> io::Result<Vec<PoolEntry>> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(pool_dir)?;
    write_binding_marker(pool_dir, binding)?;

    let mut candidates = Vec::new();
    for dir_entry in std::fs::read_dir(pool_dir)? {
        let path = dir_entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("pool_") && name.contains(TMP_MARKER) {
            let _ = std::fs::remove_file(&path);
        } else if name.starts_with("pool_") && name.ends_with(".hints") {
            candidates.push(path);
        }
    }
    candidates.sort();

    let mut entries = Vec::new();
    for path in candidates {
        if entries.len() >= pool_size {
            break;
        }
        match File::open(&path).and_then(|mut file| load_pool_file(&path, binding, &mut file)) {
            Ok(entry) => entries.push(entry),
            Err(_error) => {
                eprintln!("[hint-pool] Removing an unusable pool file");
                unsafe_hint_pool_log!(
                    "[hint-pool] unusable pool file {}: {}",
                    path.display(),
                    _error
                );
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    Ok(entries)
}

/// The marker records which database and backend the directory's files
/// belong to; earlier releases refuse a directory with pool files but no
/// marker. A new database rewrites it, and the old files then fail their
/// fingerprint check on load.
fn write_binding_marker(pool_dir: &Path, binding: &PoolFileBinding) -> io::Result<()> {
    let expected = binding.marker_bytes()?;
    let marker = pool_dir.join(BINDING_MARKER_FILE);
    if std::fs::read(&marker).is_ok_and(|actual| actual == expected) {
        return Ok(());
    }
    let tmp = pool_dir.join(format!("{BINDING_MARKER_TMP_PREFIX}{}", std::process::id()));
    create_owner_only(&tmp)?.write_all(&expected)?;
    std::fs::rename(&tmp, &marker)
}

/// Write `entry` to `pool_<key>.hints` through a temporary name, so the final
/// name only ever holds a complete file. The checksum catches a file torn by
/// a crash; it is removed on the next load.
fn persist_pool_entry(
    pool_dir: &Path,
    binding: &PoolFileBinding,
    entry: &PoolEntry,
) -> io::Result<PathBuf> {
    let file_name = pool_file_name(&entry.prp_key);
    let path = pool_dir.join(&file_name);
    let stem = file_name
        .strip_suffix(".hints")
        .expect("pool filenames end in .hints");
    let tmp_path = pool_dir.join(format!("{stem}{TMP_MARKER}{}", std::process::id()));

    let body_len = encoded_body_len(entry)?;
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

    let result = (|| {
        let mut file = create_owner_only(&tmp_path)?;
        file.write_all(&header)?;
        for frame in entry.index_frames.iter().chain(&entry.chunk_frames) {
            write_lp(&mut file, frame)?;
        }
        write_lp(&mut file, &entry.key_preamble)?;
        file.write_all(&checksum)?;
        std::fs::rename(&tmp_path, &path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result.map(|()| path)
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

    fn marker_bytes(&self) -> io::Result<[u8; BINDING_MARKER_LEN]> {
        let mut marker = [0u8; BINDING_MARKER_LEN];
        marker[0..8].copy_from_slice(BINDING_MARKER_MAGIC);
        marker[8..10].copy_from_slice(&BINDING_MARKER_VERSION.to_le_bytes());
        marker[10..12].copy_from_slice(&(BINDING_MARKER_LEN as u16).to_le_bytes());
        marker[12..44].copy_from_slice(&self.fingerprint);
        marker[44] = self.bound_db_id;
        marker[45] = self.prp_backend;
        for (index, value) in [
            self.index_groups,
            self.chunk_groups,
            self.index_bins,
            self.chunk_bins,
            self.index_entry_size,
            self.chunk_entry_size,
        ]
        .into_iter()
        .enumerate()
        {
            let value = u64::try_from(value)
                .map_err(|_| invalid_data("pool binding geometry exceeds u64"))?;
            let offset = 48 + index * 8;
            marker[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        Ok(marker)
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

fn write_lp(writer: &mut File, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| invalid_data("frame exceeds u32"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(bytes)
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
    if len != expected_len {
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

fn load_pool_file(
    path: &Path,
    binding: &PoolFileBinding,
    file: &mut File,
) -> io::Result<PoolEntry> {
    let file_len = file.metadata()?.len();

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
        let frame = read_lp(file, &mut body_read, body_len, index_frame_len)?;
        validate_hint_frame(&frame, group, binding.index_bins, binding.index_entry_size)?;
        index_frames.push(frame);
    }
    let mut chunk_frames = Vec::with_capacity(chunk_groups);
    for group in 0..chunk_groups {
        let frame = read_lp(file, &mut body_read, body_len, chunk_frame_len)?;
        validate_hint_frame(&frame, group, binding.chunk_bins, binding.chunk_entry_size)?;
        chunk_frames.push(frame);
    }
    let expected_preamble = build_key_preamble(prp_backend, binding.total_groups(), &prp_key);
    let key_preamble = read_lp(file, &mut body_read, body_len, expected_preamble.len())?;
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
        persisted_path: Some(path.to_path_buf()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

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

    fn test_entry(binding: &PoolFileBinding, prp_key: [u8; 16]) -> PoolEntry {
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
            persisted_path: None,
        }
    }

    fn test_pool(entries: Vec<PoolEntry>) -> HintPool {
        HintPool {
            entries: Arc::new(Mutex::new(entries.into())),
            shutdown: Arc::new(AtomicBool::new(true)),
            generator: None,
        }
    }

    fn test_mapped_subtable(
        params: pir_core::params::TableParams,
    ) -> pir_runtime_core::table::MappedSubTable {
        let mmap = memmap2::MmapOptions::new()
            .len(1)
            .map_anon()
            .unwrap()
            .make_read_only()
            .unwrap();
        pir_runtime_core::table::MappedSubTable {
            mmap: Arc::new(mmap),
            params,
            bins_per_table: 0,
            table_byte_size: 0,
            data_offset: 0,
            tag_seed: 0,
            master_seed: 0,
            anchor: None,
        }
    }

    #[test]
    fn persisted_entry_round_trips_through_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let binding = test_binding(0x11);
        assert!(open_pool_directory(dir.path(), &binding, 4)
            .unwrap()
            .is_empty());
        let entry = test_entry(&binding, [0x42; 16]);
        let path = persist_pool_entry(dir.path(), &binding, &entry).unwrap();

        let loaded = open_pool_directory(dir.path(), &binding, 4).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].prp_key, entry.prp_key);
        assert_eq!(loaded[0].index_frames, entry.index_frames);
        assert_eq!(loaded[0].chunk_frames, entry.chunk_frames);
        assert_eq!(loaded[0].key_preamble, entry.key_preamble);
        assert_eq!(loaded[0].persisted_path.as_deref(), Some(path.as_path()));
    }

    // Earlier releases only load owner-only, single-link files from a 0700
    // directory, so a rollback keeps these.
    #[test]
    fn pool_directory_and_files_are_owner_only() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("pool");
        let binding = test_binding(0x12);
        open_pool_directory(&dir, &binding, 1).unwrap();
        let path = persist_pool_entry(&dir, &binding, &test_entry(&binding, [1; 16])).unwrap();

        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&dir.join(BINDING_MARKER_FILE)), 0o600);
        assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 1);
    }

    #[test]
    fn take_removes_the_file_so_each_entry_is_served_once() {
        let dir = tempfile::tempdir().unwrap();
        let binding = test_binding(0x13);
        open_pool_directory(dir.path(), &binding, 1).unwrap();
        let path =
            persist_pool_entry(dir.path(), &binding, &test_entry(&binding, [2; 16])).unwrap();

        // Two processes sharing the directory both load the entry.
        let first = test_pool(open_pool_directory(dir.path(), &binding, 1).unwrap());
        let second = test_pool(open_pool_directory(dir.path(), &binding, 1).unwrap());
        assert_eq!(first.try_take().unwrap().prp_key, [2; 16]);
        assert!(!path.exists());
        assert!(second.try_take().is_none());

        // A memory-only entry has no file to remove.
        let memory = test_pool(vec![test_entry(&binding, [3; 16])]);
        assert!(memory.try_take().is_some());
        assert!(memory.try_take().is_none());
    }

    #[test]
    fn files_for_another_database_or_backend_are_removed_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let original = test_binding(0x14);
        open_pool_directory(dir.path(), &original, 1).unwrap();
        let path =
            persist_pool_entry(dir.path(), &original, &test_entry(&original, [4; 16])).unwrap();

        // A new database rewrites the marker; the old file fails its
        // fingerprint check.
        let rotated = test_binding(0x15);
        assert!(open_pool_directory(dir.path(), &rotated, 1)
            .unwrap()
            .is_empty());
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(dir.path().join(BINDING_MARKER_FILE)).unwrap(),
            rotated.marker_bytes().unwrap()
        );
    }

    #[test]
    fn corrupt_files_and_interrupted_writes_are_removed_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let binding = test_binding(0x16);
        open_pool_directory(dir.path(), &binding, 1).unwrap();
        let path =
            persist_pool_entry(dir.path(), &binding, &test_entry(&binding, [5; 16])).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(&[0xff]).unwrap();
        let tmp = dir
            .path()
            .join(format!("pool_{}{TMP_MARKER}123", "06".repeat(16)));
        std::fs::write(&tmp, b"partial").unwrap();

        assert!(open_pool_directory(dir.path(), &binding, 1)
            .unwrap()
            .is_empty());
        assert!(!path.exists());
        assert!(!tmp.exists());
    }

    #[test]
    fn generator_owns_mmaps_and_drop_joins_before_releasing_them() {
        let index_params = pir_core::params::INDEX_PARAMS.clone();
        let chunk_params = pir_core::params::CHUNK_PARAMS.clone();
        let db = MappedDatabase {
            descriptor: pir_runtime_core::table::DatabaseDescriptor {
                name: "hint-worker-lifetime".to_owned(),
                db_type: pir_runtime_core::table::DatabaseType::Full,
                base_height: 0,
                height: 0,
                index_params: index_params.clone(),
                chunk_params: chunk_params.clone(),
            },
            index: test_mapped_subtable(index_params),
            chunk: test_mapped_subtable(chunk_params),
            bucket_merkle_index_siblings: Vec::new(),
            bucket_merkle_chunk_siblings: Vec::new(),
            bucket_merkle_tree_tops: None,
            bucket_merkle_roots: None,
            bucket_merkle_root: None,
            manifest_root: None,
            manifest: None,
            db_proof: None,
            db_proof_v2: None,
        };
        let index_owner = Arc::clone(&db.index.mmap);
        let chunk_owner = Arc::clone(&db.chunk.mmap);
        let pool = HintPool::new(
            HintPoolConfig {
                pool_size: 0,
                prp_backend: remote::PRP_HMR12,
                pool_dir: None,
            },
            0,
            &db,
        )
        .unwrap();

        assert_eq!(Arc::strong_count(&index_owner), 3);
        drop(db);
        assert_eq!(Arc::strong_count(&index_owner), 2);
        drop(pool);
        assert_eq!(Arc::strong_count(&index_owner), 1);
        assert_eq!(Arc::strong_count(&chunk_owner), 1);
    }

    #[test]
    fn generation_timing_window_reports_aggregates_on_the_interval_only() {
        let start = Instant::now();
        let mut window = GenerationTimingWindow::new(3, Duration::from_secs(60), start);
        assert_eq!(window.due(start), None);
        window.record(Duration::from_secs(10));
        window.record(Duration::from_secs(14));
        assert_eq!(window.due(start + Duration::from_secs(59)), None);
        assert_eq!(
            window.due(start + Duration::from_secs(60)).unwrap(),
            "[hint-pool db=3] last 60s: generated=2 wall_mean_s=12.0 wall_max_s=14.0"
        );
        // The window resets: an idle interval reports zero, not the old numbers.
        assert_eq!(
            window.due(start + Duration::from_secs(120)).unwrap(),
            "[hint-pool db=3] last 60s: generated=0 wall_mean_s=0.0 wall_max_s=0.0"
        );
    }

    #[cfg(not(feature = "fastprp"))]
    #[test]
    fn no_fastprp_build_defaults_to_hmr12() {
        assert_eq!(default_prp_backend(), remote::PRP_HMR12);
        assert!(validate_prp_backend(remote::PRP_FASTPRP).is_err());
    }
}
