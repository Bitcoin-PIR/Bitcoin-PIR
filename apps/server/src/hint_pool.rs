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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    /// When this entry was created.
    pub created_at: Instant,
    /// Ready-state V2 pool file backing this entry, if it was persisted.
    /// Reservation holds an exclusive advisory lock on this ready inode;
    /// only a post-credential commit permanently consumes its directory name.
    persisted_path: Option<PathBuf>,
}

// ─── Hint pool ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct PoolState {
    entries: VecDeque<PoolEntry>,
    reservations: usize,
    reserved_keys: std::collections::HashSet<[u8; 16]>,
    generation_in_progress: usize,
}

struct DurablePoolReservation {
    ready_path: PathBuf,
    /// Held for the complete authorization attempt. A different process can
    /// reserve the artifact only after this handle is dropped or the owner
    /// process crashes. Keeping the ready name in place makes an AUTH reject a
    /// zero-write operation: no rename or directory fsync is attacker-driven.
    _lock: File,
}

/// Compatibility representation for a reservation artifact created by an
/// earlier Payment V1 build. New reservations never create these names, but a
/// clean startup still recovers an interrupted ready -> reserved transition.
struct LegacyReservedPoolArtifact {
    ready_path: PathBuf,
    reserved_path: PathBuf,
    _lock: File,
}

/// An entry reserved before credential verification. Dropping an unfinished
/// reservation restores it so malformed credentials and cancelled connections
/// cannot turn pool capacity into expensive refill work.
pub struct PoolReservation {
    entry: Option<PoolEntry>,
    prp_key: [u8; 16],
    durable: Option<DurablePoolReservation>,
    state: Arc<Mutex<PoolState>>,
    target_size: usize,
    finalized: bool,
}

impl PoolReservation {
    /// Permanently consume the durable artifact after credential commit. The
    /// caller must not expose the returned entry's PRP key before this succeeds.
    pub fn commit_consume(self) -> io::Result<PoolEntry> {
        self.commit_consume_with_sync(sync_directory)
    }

    fn commit_consume_with_sync(
        mut self,
        sync_after_unlink: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<PoolEntry> {
        let sync_result = if let Some(durable) = self.durable.as_ref() {
            let parent = durable
                .ready_path
                .parent()
                .ok_or_else(|| invalid_data("ready pool artifact has no parent"))?;
            let _capacity_lock = lock_pool_capacity(parent)?;
            let current = open_private_pool_file(&durable.ready_path, false)?;
            if !open_files_have_same_identity(&durable._lock, &current)? {
                return Err(invalid_data(
                    "ready pool artifact identity changed during authorization",
                ));
            }
            std::fs::remove_file(&durable.ready_path)?;
            sync_after_unlink(parent)
        } else {
            Ok(())
        };

        // Once unlink succeeded, never let Drop recreate an ambiguously
        // consumed artifact. A directory-fsync failure is fail-closed and the
        // still-unexposed in-memory entry is discarded.
        self.durable.take();
        let mut entry = self.entry.take().expect("unfinished reservation has entry");
        entry.persisted_path = None;
        self.finish_local_reservation(None);
        self.finalized = true;
        sync_result?;
        Ok(entry)
    }

    /// Restore a rejected or otherwise uncommitted reservation to ready state.
    /// The result reports whether this process also re-enqueued it in memory.
    pub fn restore(mut self) -> io::Result<bool> {
        self.restore_inner()
    }

    fn restore_inner(&mut self) -> io::Result<bool> {
        if self.finalized {
            return Ok(false);
        }
        let mut entry = self.entry.take().expect("unfinished reservation has entry");
        if let Some(durable) = self.durable.as_ref() {
            entry.persisted_path = Some(durable.ready_path.clone());
        }
        // Releasing the inode lock is the complete durable rollback. The
        // ready name was never changed before credential verification.
        self.durable.take();
        let restored = self.finish_local_reservation(Some(entry));
        self.finalized = true;
        Ok(restored)
    }

    fn finish_local_reservation(&self, entry: Option<PoolEntry>) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.reservations = state.reservations.saturating_sub(1);
        state.reserved_keys.remove(&self.prp_key);
        let Some(entry) = entry else {
            return false;
        };
        if state.entries.len().saturating_add(state.reservations) >= self.target_size {
            return false;
        }
        state.entries.push_front(entry);
        true
    }
}

impl Drop for PoolReservation {
    fn drop(&mut self) {
        if self.finalized {
            return;
        }
        // Lock release plus local requeue cannot perform filesystem I/O and is
        // therefore safe on malformed-auth and disconnect paths.
        let _ = self.restore_inner();
    }
}

/// Thread-safe pool of pre-computed hint entries.
///
/// A background thread keeps the pool filled to `config.pool_size`. When a
/// client connects, `take()` pops an entry — zero computation on the hot path.
pub struct HintPool {
    bound_db_id: u8,
    target_size: usize,
    state: Arc<Mutex<PoolState>>,
    shutdown: Arc<AtomicBool>,
    _generator: Option<JoinHandle<()>>,
}

impl HintPool {
    /// Create a new pool and start the background generator.
    ///
    /// `db` is the exact database selected by `bound_db_id`. Payment V1 keeps
    /// one pool/database binding per provider process; the default remains the
    /// main UTXO snapshot at db_id=0.
    pub fn new(
        mut config: HintPoolConfig,
        bound_db_id: u8,
        db: &MappedDatabase,
    ) -> Result<Self, String> {
        validate_prp_backend(config.prp_backend)?;

        let state = Arc::new(Mutex::new(PoolState {
            entries: VecDeque::with_capacity(config.pool_size),
            ..PoolState::default()
        }));
        let shutdown = Arc::new(AtomicBool::new(false));

        if let Some(dir) = config.pool_dir.as_ref() {
            prepare_pool_directory(dir).map_err(|error| {
                format!(
                    "HarmonyPIR pool directory {} is not a private, durably writable directory: {}",
                    dir.display(),
                    error
                )
            })?;
        }

        let disk_binding = if config.pool_dir.is_some() {
            PoolFileBinding::for_database(bound_db_id, db, config.prp_backend)?
        } else {
            None
        };
        if config.pool_dir.is_some() && disk_binding.is_none() {
            eprintln!(
                "[hint-pool] WARN: db {} lacks a verified manifest or 32-byte bucket Merkle root; disabling disk pool reuse",
                db.descriptor.name
            );
            // This directory may be shared by independently starting provider
            // processes. An unbound process must never delete a live peer's
            // ready, reserved, staged, or generation artifacts.
            config.pool_dir = None;
        }

        if let (Some(dir), Some(binding)) = (config.pool_dir.as_ref(), disk_binding.as_ref()) {
            ensure_pool_directory_binding(dir, binding).map_err(|error| {
                format!(
                    "HarmonyPIR pool directory {} is not exclusively bound to this database/backend: {}",
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
            let mut state = state.lock().unwrap();
            for e in initial_entries {
                state.entries.push_back(e);
            }
            println!(
                "[hint-pool] Loaded {} entries from disk, target pool size {}",
                state.entries.len(),
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
        // The worker owns strong references to both mappings. This keeps the
        // bytes alive independently of the server state's field-drop order and
        // makes the safe `HintPool::new` API uphold the generated slices'
        // lifetime without relying on a raw-pointer convention.
        let index_mmap = Arc::clone(&db.index.mmap);
        let chunk_mmap = Arc::clone(&db.chunk.mmap);

        let gen_config = config.clone();
        let gen_shutdown = Arc::clone(&shutdown);
        let gen_state = Arc::clone(&state);
        let gen_disk_binding = disk_binding.clone();
        let handle = std::thread::spawn(move || {
            generation_loop(
                gen_config,
                gen_disk_binding,
                db_params,
                index_mmap,
                chunk_mmap,
                &gen_state,
                &gen_shutdown,
            );
        });

        Ok(HintPool {
            bound_db_id,
            target_size: config.pool_size,
            state,
            shutdown,
            _generator: Some(handle),
        })
    }

    /// Database id whose immutable tables back every entry in this pool.
    pub fn database_id(&self) -> u8 {
        self.bound_db_id
    }

    /// Reserve one entry without consuming its durable artifact. An exclusive
    /// inode lock competes across provider processes sharing a pool; the ready
    /// directory entry is deliberately unchanged until credential commit.
    pub fn try_reserve(&self) -> Option<PoolReservation> {
        self.try_reserve_preserving_ready_floor(0)
    }

    /// Reserve while leaving at least `minimum_ready_after` currently lockable
    /// ready entries for another admission class. Disk-backed pools enforce the
    /// floor under the cross-process capacity lock; memory-only pools enforce
    /// it under `PoolState`.
    pub fn try_reserve_preserving_ready_floor(
        &self,
        minimum_ready_after: usize,
    ) -> Option<PoolReservation> {
        // A stale cross-process lock is rotated behind the other candidates,
        // but one call examines only the snapshot-sized candidate set. This
        // avoids both head-of-line starvation and a busy loop when every inode
        // is owned by another process.
        let mut candidates_remaining = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .entries
            .len();
        while candidates_remaining > 0 {
            candidates_remaining -= 1;
            let (entry, validated_ready_paths) = {
                let mut state = self.state.lock().unwrap();
                if state.entries.len() <= minimum_ready_after {
                    return None;
                }
                let entry = state.entries.pop_front()?;
                let validated_ready_paths = if minimum_ready_after > 0 {
                    state
                        .entries
                        .iter()
                        .filter_map(|candidate| candidate.persisted_path.clone())
                        .collect()
                } else {
                    Vec::new()
                };
                state.reservations = state.reservations.saturating_add(1);
                state.reserved_keys.insert(entry.prp_key);
                (entry, validated_ready_paths)
            };

            let durable = match entry.persisted_path.clone() {
                Some(path) => {
                    match reserve_pool_file_preserving_ready_floor(
                        &path,
                        minimum_ready_after,
                        &validated_ready_paths,
                    ) {
                        Ok(reservation) => Some(reservation),
                        Err(error) => {
                            let mut state = self
                                .state
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner());
                            state.reservations = state.reservations.saturating_sub(1);
                            state.reserved_keys.remove(&entry.prp_key);
                            match error {
                                PoolFileReservationError::SelectedLocked => {
                                    state.entries.push_back(entry);
                                    continue;
                                }
                                PoolFileReservationError::SelectedStale => {
                                    // A peer may already have consumed the old
                                    // name. Discard only this process's stale
                                    // in-memory copy and inspect the next entry.
                                    continue;
                                }
                                PoolFileReservationError::FloorUnavailable(_error) => {
                                    // Capacity-lock contention, an unstable
                                    // scan, or a true floor exhaustion is
                                    // transient and applies to the whole pool.
                                    state.entries.push_front(entry);
                                    return None;
                                }
                                PoolFileReservationError::Fatal(_error) => {
                                    eprintln!(
                                        "[hint-pool] Durable entry was unavailable during reservation"
                                    );
                                    unsafe_hint_pool_log!(
                                        "[hint-pool] durable reservation detail for {}: {}",
                                        path.display(),
                                        _error
                                    );
                                    continue;
                                }
                            }
                        }
                    }
                }
                None => None,
            };
            return Some(PoolReservation {
                prp_key: entry.prp_key,
                entry: Some(entry),
                durable,
                state: Arc::clone(&self.state),
                target_size: self.target_size,
                finalized: false,
            });
        }
        None
    }

    /// Compatibility helper for non-admission V2 requests: reserve and consume
    /// in one step. A consume failure never returns an observable PRP key.
    pub fn try_take(&self) -> Option<PoolEntry> {
        let reservation = self.try_reserve()?;
        match reservation.commit_consume() {
            Ok(entry) => Some(entry),
            Err(_error) => {
                eprintln!("[hint-pool] Failed to consume a durable entry");
                unsafe_hint_pool_log!("[hint-pool] durable consume detail: {}", _error);
                None
            }
        }
    }

    /// Number of entries currently in the pool.
    pub fn len(&self) -> usize {
        self.state.lock().unwrap().entries.len()
    }

    /// True if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for HintPool {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(generator) = self._generator.take() {
            // Joining is part of the ownership boundary: after Drop returns no
            // worker may retain filesystem claims or access database mappings.
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

enum GenerationClaim {
    Memory(LocalGenerationClaim),
    Disk(DiskGenerationClaim),
}

fn refresh_state_from_disk_background(
    config: &HintPoolConfig,
    disk_binding: Option<&PoolFileBinding>,
    state: &Arc<Mutex<PoolState>>,
) {
    let (Some(pool_dir), Some(binding)) = (config.pool_dir.as_ref(), disk_binding) else {
        return;
    };
    let (available, excluded_keys) = {
        let state = state.lock().unwrap_or_else(|poison| poison.into_inner());
        let available = config.pool_size.saturating_sub(
            state
                .entries
                .len()
                .saturating_add(state.reservations)
                .saturating_add(state.generation_in_progress),
        );
        let mut excluded_keys = state.reserved_keys.clone();
        excluded_keys.extend(state.entries.iter().map(|entry| entry.prp_key));
        (available, excluded_keys)
    };
    if available == 0 {
        return;
    }

    // This function is called only by the one background worker owned by a
    // HintPool. Potentially large file reads never run on an unauthenticated
    // connection's async task and are therefore naturally single-flight per
    // process.
    let loaded = load_pool_files_excluding(pool_dir, binding, available, &excluded_keys);
    let mut state = state.lock().unwrap_or_else(|poison| poison.into_inner());
    for entry in loaded {
        if state
            .entries
            .len()
            .saturating_add(state.reservations)
            .saturating_add(state.generation_in_progress)
            >= config.pool_size
        {
            break;
        }
        if state
            .entries
            .iter()
            .all(|existing| existing.prp_key != entry.prp_key)
            && !state.reserved_keys.contains(&entry.prp_key)
        {
            state.entries.push_back(entry);
        }
    }
}

struct LocalGenerationClaim {
    state: Arc<Mutex<PoolState>>,
    active: bool,
}

impl Drop for LocalGenerationClaim {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.generation_in_progress = state.generation_in_progress.saturating_sub(1);
    }
}

struct DiskGenerationClaim {
    path: PathBuf,
    _lock: File,
    active: bool,
}

impl DiskGenerationClaim {
    fn finish(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        std::fs::remove_file(&self.path)?;
        if let Some(parent) = self.path.parent() {
            sync_directory(parent)?;
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for DiskGenerationClaim {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let _ = std::fs::remove_file(&self.path);
        if let Some(parent) = self.path.parent() {
            let _ = sync_directory(parent);
        }
    }
}

fn claim_generation_capacity(
    config: &HintPoolConfig,
    state: &Arc<Mutex<PoolState>>,
) -> io::Result<Option<GenerationClaim>> {
    if let Some(pool_dir) = config.pool_dir.as_ref() {
        return try_claim_disk_generation(pool_dir, config.pool_size)
            .map(|claim| claim.map(GenerationClaim::Disk));
    }

    let mut state_guard = state.lock().unwrap_or_else(|poison| poison.into_inner());
    let occupied = state_guard
        .entries
        .len()
        .saturating_add(state_guard.reservations)
        .saturating_add(state_guard.generation_in_progress);
    if occupied >= config.pool_size {
        return Ok(None);
    }
    state_guard.generation_in_progress = state_guard.generation_in_progress.saturating_add(1);
    drop(state_guard);
    Ok(Some(GenerationClaim::Memory(LocalGenerationClaim {
        state: Arc::clone(state),
        active: true,
    })))
}

fn finalize_generated_entry(
    claim: GenerationClaim,
    config: &HintPoolConfig,
    disk_binding: Option<&PoolFileBinding>,
    state: &Arc<Mutex<PoolState>>,
    mut entry: PoolEntry,
) -> io::Result<bool> {
    match claim {
        GenerationClaim::Memory(mut claim) => {
            let mut state = state.lock().unwrap_or_else(|poison| poison.into_inner());
            state.generation_in_progress = state.generation_in_progress.saturating_sub(1);
            claim.active = false;
            let occupied = state
                .entries
                .len()
                .saturating_add(state.reservations)
                .saturating_add(state.generation_in_progress);
            if occupied >= config.pool_size {
                return Ok(false);
            }
            state.entries.push_back(entry);
            Ok(true)
        }
        GenerationClaim::Disk(mut claim) => {
            let pool_dir = config
                .pool_dir
                .as_ref()
                .ok_or_else(|| invalid_data("disk generation claim without pool directory"))?;
            let binding = disk_binding
                .ok_or_else(|| invalid_data("disk generation claim without database binding"))?;
            let prepared = prepare_pool_persistence(pool_dir, binding, &entry)?;

            // Hold the cross-process lock only long enough to recheck capacity
            // and create+lock the private staging inode. The potentially very
            // large write and file fsync happen outside this lock so a hot-path
            // reservation is never queued behind hint serialization.
            let mut staged = {
                let _capacity_lock = lock_pool_capacity(pool_dir)?;
                let occupied = disk_capacity_count_locked(pool_dir, Some(&claim.path), None)?;
                if occupied >= config.pool_size {
                    claim.finish()?;
                    return Ok(false);
                }
                StagedPoolPersistence::create(&prepared)?
            };
            staged.write_and_sync(&prepared, &entry)?;

            // Publication is a second short critical section. A final capacity
            // recheck covers another process publishing while our write was in
            // flight; the generation claim remains live and counted throughout.
            let persisted_path = {
                let _capacity_lock = lock_pool_capacity(pool_dir)?;
                let occupied = disk_capacity_count_locked(
                    pool_dir,
                    Some(&claim.path),
                    Some(&staged.tmp_path),
                )?;
                if occupied >= config.pool_size {
                    staged.discard()?;
                    claim.finish()?;
                    return Ok(false);
                }
                let path = staged.publish()?;
                claim.finish()?;
                path
            };
            entry.persisted_path = Some(persisted_path);
            let mut state = state.lock().unwrap_or_else(|poison| poison.into_inner());
            if state.entries.len().saturating_add(state.reservations) < config.pool_size {
                state.entries.push_back(entry);
            }
            Ok(true)
        }
    }
}

fn generation_loop(
    config: HintPoolConfig,
    disk_binding: Option<PoolFileBinding>,
    db_params: DbParams,
    index_mmap: Arc<memmap2::Mmap>,
    chunk_mmap: Arc<memmap2::Mmap>,
    state: &Arc<Mutex<PoolState>>,
    shutdown: &AtomicBool,
) {
    let index_k = db_params.index_params.k as u32;
    let chunk_k = db_params.chunk_params.k as u32;

    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }

        refresh_state_from_disk_background(&config, disk_binding.as_ref(), state);

        let generation_claim = match claim_generation_capacity(&config, state) {
            Ok(Some(claim)) => claim,
            Ok(None) => {
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
            Err(_error) => {
                eprintln!("[hint-pool] Failed to reconcile generation capacity");
                unsafe_hint_pool_log!("[hint-pool] generation capacity detail: {}", _error);
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };

        // Generate one pool entry.
        #[cfg(feature = "test-only-unsafe-query-logging")]
        let t0 = Instant::now();
        match generate_pool_entry(
            &config,
            &db_params,
            &index_mmap,
            &chunk_mmap,
            index_k,
            chunk_k,
        ) {
            Ok(entry) => {
                #[cfg(feature = "test-only-unsafe-query-logging")]
                {
                    let elapsed = t0.elapsed();
                    unsafe_hint_pool_log!(
                        "[hint-pool] Generated entry (prp_key={}..., {} groups) in {:.2?}",
                        hex_prefix(&entry.prp_key),
                        entry.index_frames.len() + entry.chunk_frames.len(),
                        elapsed,
                    );
                }
                match finalize_generated_entry(
                    generation_claim,
                    &config,
                    disk_binding.as_ref(),
                    state,
                    entry,
                ) {
                    Ok(_) => {}
                    Err(_error) => {
                        eprintln!("[hint-pool] Failed to persist a generated entry");
                        unsafe_hint_pool_log!(
                            "[hint-pool] generated-entry persistence detail: {}",
                            _error
                        );
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            }
            Err(_error) => {
                drop(generation_claim);
                eprintln!("[hint-pool] Hint generation failed");
                unsafe_hint_pool_log!("[hint-pool] hint generation detail: {}", _error);
                std::thread::sleep(Duration::from_secs(1));
            }
        }
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
const MAX_HINT_FRAME_LEN: usize = 512 * 1024 * 1024;
const MAX_POOL_FILE_LEN: u64 = 16 * 1024 * 1024 * 1024;
const CAPACITY_LOCK_FILE: &str = ".hmpool-capacity.lock";
const BINDING_MARKER_FILE: &str = ".hmpool-binding-v1";
const BINDING_MARKER_TMP_PREFIX: &str = ".hmpool-binding-v1.tmp.";
const BINDING_MARKER_MAGIC: &[u8; 8] = b"HMPBIND1";
const BINDING_MARKER_VERSION: u16 = 1;
const BINDING_MARKER_LEN: usize = 96;
const GENERATION_PREFIX: &str = ".hmpool-generating.";
const RESERVED_MARKER: &str = ".hints.reserved.";
const TMP_MARKER: &str = ".hints.tmp.";
const PRIVATE_POOL_LABEL: &str = "HarmonyPIR hint-pool artifact";
static NEXT_ARTIFACT_ID: AtomicU64 = AtomicU64::new(0);

fn pool_file_name(prp_key: &[u8; 16]) -> String {
    let key_hex: String = prp_key.iter().map(|b| format!("{:02x}", b)).collect();
    format!("pool_{}.hints", key_hex)
}

fn private_fs_error(error: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, error)
}

/// Validate the complete parent walk and the final pool directory. The shared
/// private-file boundary creates missing components as euid-owned mode 0700,
/// rejects symlinks, and (on macOS) rejects inherited ACL grants.
fn validate_private_pool_directory(pool_dir: &Path, create_missing: bool) -> io::Result<()> {
    let sentinel = pool_dir.join(".hmpool-private-boundary");
    pir_private_files::prepare_private_parent_v1(&sentinel, create_missing, PRIVATE_POOL_LABEL)
        .map(|_| ())
        .map_err(private_fs_error)
}

fn create_private_pool_file(path: &Path) -> io::Result<File> {
    pir_private_files::create_new_private_file_v1(path, PRIVATE_POOL_LABEL)
        .map_err(private_fs_error)
}

/// Open an existing pool artifact without following its final component. The
/// shared private-files boundary first pins the complete parent walk; fstat and
/// ACL checks then validate the exact returned descriptor. This preserves
/// `NotFound` for a concurrent ready->reserved rename, so a loader never
/// mistakes a live reservation for a corrupt file that should be deleted.
fn open_private_pool_file(path: &Path, read_write: bool) -> io::Result<File> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("pool artifact has no parent"))?;
    validate_private_pool_directory(parent, false)?;
    let access = if read_write {
        rustix::fs::OFlags::RDWR
    } else {
        rustix::fs::OFlags::RDONLY
    };
    let fd = rustix::fs::open(
        path,
        access
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let stat = rustix::fs::fstat(&fd).map_err(io::Error::from)?;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HarmonyPIR hint-pool artifact changed or is not a private single-link file",
        ));
    }
    let file = File::from(fd);
    pir_private_files::reject_extended_acl_v1(&file, PRIVATE_POOL_LABEL)
        .map_err(private_fs_error)?;
    Ok(file)
}

fn lock_pool_capacity(pool_dir: &Path) -> io::Result<File> {
    validate_private_pool_directory(pool_dir, false)?;
    let path = pool_dir.join(CAPACITY_LOCK_FILE);
    let file = match create_private_pool_file(&path) {
        Ok(file) => file,
        Err(_) => open_private_pool_file(&path, true)?,
    };
    file.lock()?;
    Ok(file)
}

/// Hot-path variant: cross-process contention is ordinary overload, so never
/// block a Tokio worker waiting for the advisory capacity lock.
fn try_lock_pool_capacity(pool_dir: &Path) -> io::Result<File> {
    validate_private_pool_directory(pool_dir, false)?;
    let path = pool_dir.join(CAPACITY_LOCK_FILE);
    let file = match create_private_pool_file(&path) {
        Ok(file) => file,
        Err(_) => open_private_pool_file(&path, true)?,
    };
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "HarmonyPIR capacity lock is busy",
        )),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

fn unique_artifact_suffix() -> String {
    let counter = NEXT_ARTIFACT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{}-{counter:016x}", std::process::id())
}

#[cfg(test)]
fn reserve_pool_file(ready_path: &Path) -> io::Result<DurablePoolReservation> {
    reserve_pool_file_preserving_ready_floor(ready_path, 0, &[]).map_err(|error| match error {
        PoolFileReservationError::SelectedLocked => {
            io::Error::new(io::ErrorKind::WouldBlock, "ready pool artifact is locked")
        }
        PoolFileReservationError::SelectedStale => {
            io::Error::new(io::ErrorKind::NotFound, "ready pool artifact is stale")
        }
        PoolFileReservationError::FloorUnavailable(error)
        | PoolFileReservationError::Fatal(error) => error,
    })
}

#[derive(Debug)]
enum PoolFileReservationError {
    /// The selected inode is live in another process; rotate to another
    /// already-validated candidate from this process's snapshot.
    SelectedLocked,
    /// The selected namespace entry disappeared before its lock was acquired.
    SelectedStale,
    /// A pool-wide atomic floor decision could not safely be made.
    FloorUnavailable(io::Error),
    /// The selected artifact itself violated the durable-file contract.
    Fatal(io::Error),
}

fn reserve_pool_file_preserving_ready_floor(
    ready_path: &Path,
    minimum_ready_after: usize,
    validated_ready_paths: &[PathBuf],
) -> Result<DurablePoolReservation, PoolFileReservationError> {
    let parent = ready_path.parent().ok_or_else(|| {
        PoolFileReservationError::Fatal(invalid_data("ready pool artifact has no parent"))
    })?;
    let _capacity_lock =
        try_lock_pool_capacity(parent).map_err(PoolFileReservationError::FloorUnavailable)?;
    disk_capacity_count_locked(parent, None, None)
        .map_err(PoolFileReservationError::FloorUnavailable)?;
    let file = match open_private_pool_file(ready_path, true) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(PoolFileReservationError::SelectedStale)
        }
        Err(error) => return Err(PoolFileReservationError::Fatal(error)),
    };
    let reservation = match finish_pool_file_reservation(ready_path, file) {
        Ok(reservation) => reservation,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            return Err(PoolFileReservationError::SelectedLocked)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(PoolFileReservationError::SelectedStale)
        }
        Err(error) => return Err(PoolFileReservationError::Fatal(error)),
    };
    if minimum_ready_after > 0 {
        let lockable =
            lockable_ready_pool_files_locked(parent, Some(ready_path), validated_ready_paths)
                .map_err(PoolFileReservationError::FloorUnavailable)?;
        if lockable < minimum_ready_after {
            return Err(PoolFileReservationError::FloorUnavailable(io::Error::new(
                io::ErrorKind::WouldBlock,
                "HarmonyPIR ready-entry floor would be exhausted",
            )));
        }
    }
    Ok(reservation)
}

/// Count canonical ready names that can be locked now. The caller holds the
/// capacity lock, so every conforming process either completed its reservation
/// before this scan or must wait until after it. The selected inode is excluded
/// explicitly because flock semantics for a second open in the same process
/// differ across supported Unix kernels.
fn lockable_ready_pool_files_locked(
    pool_dir: &Path,
    excluded_ready: Option<&Path>,
    validated_ready_paths: &[PathBuf],
) -> io::Result<usize> {
    for _ in 0..16 {
        let snapshot = stable_pool_directory_snapshot(pool_dir)?;
        let mut lockable = 0usize;
        let mut changed = false;
        for path in snapshot.iter().filter(|path| {
            validated_ready_paths
                .iter()
                .any(|validated| validated == *path)
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("pool_") && name.ends_with(".hints"))
        }) {
            if excluded_ready == Some(path.as_path()) {
                continue;
            }
            let file = match open_private_pool_file(path, true) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    changed = true;
                    break;
                }
                Err(error) => return Err(error),
            };
            match file.try_lock() {
                Ok(()) => {
                    let current = match open_private_pool_file(path, false) {
                        Ok(current) => current,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            changed = true;
                            break;
                        }
                        Err(error) => return Err(error),
                    };
                    if !open_files_have_same_identity(&file, &current)? {
                        changed = true;
                        break;
                    }
                    lockable = lockable.saturating_add(1);
                }
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(std::fs::TryLockError::Error(error)) => return Err(error),
            }
        }
        if !changed && snapshot == stable_pool_directory_snapshot(pool_dir)? {
            return Ok(lockable);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "HarmonyPIR ready-entry floor scan did not stabilize",
    ))
}

fn finish_pool_file_reservation(
    ready_path: &Path,
    file: File,
) -> io::Result<DurablePoolReservation> {
    file.try_lock()?;
    // Re-open after taking the inode lock. This rejects a stale descriptor if
    // an older/non-cooperating process removed and replaced the ready name
    // between our first open and lock acquisition.
    let current = open_private_pool_file(ready_path, false)?;
    if !open_files_have_same_identity(&file, &current)? {
        return Err(invalid_data(
            "ready pool artifact changed before reservation completed",
        ));
    }
    Ok(DurablePoolReservation {
        ready_path: ready_path.to_path_buf(),
        _lock: file,
    })
}

fn restore_legacy_reserved_pool_file_locked(
    reservation: &LegacyReservedPoolArtifact,
) -> io::Result<()> {
    let parent = reservation
        .reserved_path
        .parent()
        .ok_or_else(|| invalid_data("reserved pool artifact has no parent"))?;
    match std::fs::hard_link(&reservation.reserved_path, &reservation.ready_path) {
        Ok(()) => sync_directory(parent)?,
        Err(error)
            if error.kind() == io::ErrorKind::AlreadyExists
                && paths_are_same_file(&reservation.reserved_path, &reservation.ready_path)? => {}
        Err(error) => return Err(error),
    }
    std::fs::remove_file(&reservation.reserved_path)?;
    sync_directory(parent)
}

#[cfg(unix)]
fn paths_are_same_file(left: &Path, right: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let left = std::fs::metadata(left)?;
    let right = std::fs::metadata(right)?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(not(unix))]
fn paths_are_same_file(_left: &Path, _right: &Path) -> io::Result<bool> {
    Ok(false)
}

fn ready_path_for_reservation(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid_data("reserved pool artifact filename is not UTF-8"))?;
    let (ready_name, _) = name
        .split_once(RESERVED_MARKER)
        .ok_or_else(|| invalid_data("invalid reserved pool artifact filename"))?;
    Ok(path.with_file_name(format!("{ready_name}.hints")))
}

fn ready_path_for_temporary_publish(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid_data("temporary pool artifact filename is not UTF-8"))?;
    let (ready_stem, suffix) = name
        .split_once(TMP_MARKER)
        .ok_or_else(|| invalid_data("invalid temporary pool artifact filename"))?;
    if ready_stem.is_empty() || suffix.is_empty() {
        return Err(invalid_data("invalid temporary pool artifact filename"));
    }
    Ok(path.with_file_name(format!("{ready_stem}.hints")))
}

#[cfg(unix)]
fn is_recoverable_publish_pair(tmp_path: &Path, ready_path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let tmp = std::fs::symlink_metadata(tmp_path)?;
    let ready = match std::fs::symlink_metadata(ready_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let euid = rustix::process::geteuid().as_raw();
    Ok(tmp.file_type().is_file()
        && ready.file_type().is_file()
        && tmp.uid() == euid
        && ready.uid() == euid
        && tmp.permissions().mode() & 0o7777 == 0o600
        && ready.permissions().mode() & 0o7777 == 0o600
        && tmp.nlink() == 2
        && ready.nlink() == 2
        && tmp.dev() == ready.dev()
        && tmp.ino() == ready.ino())
}

#[cfg(not(unix))]
fn is_recoverable_publish_pair(_tmp_path: &Path, _ready_path: &Path) -> io::Result<bool> {
    Ok(false)
}

fn read_pool_directory_snapshot(pool_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(pool_dir)? {
        paths.push(entry?.path());
    }
    paths.sort();
    Ok(paths)
}

/// A staged-write Drop can remove its temporary name without the capacity
/// lock, and an older binary may not honor any current lock. Two identical
/// fresh enumerations keep capacity accounting fail-closed if a directory is
/// changing while it is scanned.
fn stable_pool_directory_snapshot(pool_dir: &Path) -> io::Result<Vec<PathBuf>> {
    for _ in 0..16 {
        let first = read_pool_directory_snapshot(pool_dir)?;
        let second = read_pool_directory_snapshot(pool_dir)?;
        if first == second {
            return Ok(second);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "HarmonyPIR pool directory did not stabilize for capacity accounting",
    ))
}

/// Recover the only valid interrupted publish state: a complete final name and
/// its same-inode temporary hard link. A locked nlink=1 staging inode belongs to
/// a live writer and is left alone; every other temporary name is discarded.
/// This runs under the cross-process capacity lock, so no live publisher can be
/// inside the final hard-link transition while reconciliation runs.
fn reconcile_temporary_publishes_locked(
    pool_dir: &Path,
    excluded_temporary: Option<&Path>,
) -> io::Result<()> {
    for _ in 0..64 {
        let before = stable_pool_directory_snapshot(pool_dir)?;
        let mut mutated = false;
        for tmp_path in before.iter().filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("pool_") && name.contains(TMP_MARKER))
        }) {
            if excluded_temporary == Some(tmp_path.as_path()) {
                continue;
            }
            let ready_path = ready_path_for_temporary_publish(tmp_path).ok();
            let recoverable = match ready_path.as_deref() {
                Some(ready_path) => is_recoverable_publish_pair(tmp_path, ready_path)?,
                None => false,
            };
            if !recoverable {
                let file = match open_private_pool_file(tmp_path, true) {
                    Ok(file) => file,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        mutated = true;
                        break;
                    }
                    // EMFILE/EIO and validation failures do not prove that an
                    // expensive live staged writer is absent. Preserve the
                    // name and fail closed instead of bypassing its inode lock.
                    Err(error) => return Err(error),
                };
                match file.try_lock() {
                    Ok(()) => {}
                    Err(std::fs::TryLockError::WouldBlock) => continue,
                    Err(std::fs::TryLockError::Error(error)) => return Err(error),
                }
            }
            // A recoverable nlink=2 pair becomes a canonical nlink=1 ready
            // artifact. An unlocked private nlink=1 temp is crash residue.
            match std::fs::remove_file(tmp_path) {
                Ok(()) => sync_directory(pool_dir)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            if recoverable {
                let ready_path = ready_path.expect("recoverable pair has ready path");
                let _ = open_private_pool_file(&ready_path, false)?;
            }
            mutated = true;
            break;
        }
        if mutated {
            continue;
        }
        if before == stable_pool_directory_snapshot(pool_dir)? {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "HarmonyPIR temporary publish reconciliation did not stabilize",
    ))
}

fn disk_capacity_count_locked(
    pool_dir: &Path,
    excluded_generation: Option<&Path>,
    excluded_temporary: Option<&Path>,
) -> io::Result<usize> {
    for _ in 0..64 {
        reconcile_temporary_publishes_locked(pool_dir, excluded_temporary)?;
        let snapshot = stable_pool_directory_snapshot(pool_dir)?;
        let mut entry_keys = std::collections::HashSet::new();
        let mut active_generations = 0usize;
        let mut mutated = false;
        for path in &snapshot {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if is_legacy_pool_residue_name(name) {
                return Err(invalid_data(
                    "legacy HarmonyPIR pool residue requires offline migration; refusing online cleanup",
                ));
            }
            if name.starts_with("pool_") && name.ends_with(".hints") {
                entry_keys.insert(name.to_owned());
                continue;
            }
            if name.starts_with("pool_") && name.contains(RESERVED_MARKER) {
                let ready_path = match ready_path_for_reservation(path) {
                    Ok(path) => path,
                    Err(_) => {
                        entry_keys.insert(name.to_owned());
                        continue;
                    }
                };
                // Crash between restore's durable hard-link and reserved-name
                // unlink leaves both names on one private nlink=2 inode. A live
                // restore holds this capacity lock, so this pair is stale.
                if is_recoverable_publish_pair(path, &ready_path)? {
                    std::fs::remove_file(path)?;
                    sync_directory(pool_dir)?;
                    mutated = true;
                    break;
                }
                let key = ready_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or(name)
                    .to_owned();
                entry_keys.insert(key);
                let file = match open_private_pool_file(path, true) {
                    Ok(file) => file,
                    Err(_) => continue,
                };
                match file.try_lock() {
                    Ok(()) => {
                        let stale = LegacyReservedPoolArtifact {
                            ready_path,
                            reserved_path: path.clone(),
                            _lock: file,
                        };
                        restore_legacy_reserved_pool_file_locked(&stale)?;
                        mutated = true;
                        break;
                    }
                    Err(std::fs::TryLockError::WouldBlock) => {}
                    Err(std::fs::TryLockError::Error(_error)) => {
                        unsafe_hint_pool_log!(
                            "[hint-pool] reservation lock inspection detail: {}",
                            _error
                        );
                    }
                }
                continue;
            }
            if name.starts_with(GENERATION_PREFIX) {
                if excluded_generation == Some(path.as_path()) {
                    continue;
                }
                let file = match open_private_pool_file(path, true) {
                    Ok(file) => file,
                    Err(_) => {
                        active_generations = active_generations.saturating_add(1);
                        continue;
                    }
                };
                match file.try_lock() {
                    Ok(()) => {
                        match std::fs::remove_file(path) {
                            Ok(()) => sync_directory(pool_dir)?,
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error),
                        }
                        mutated = true;
                        break;
                    }
                    Err(std::fs::TryLockError::WouldBlock) => {
                        active_generations = active_generations.saturating_add(1);
                    }
                    Err(std::fs::TryLockError::Error(_)) => {
                        active_generations = active_generations.saturating_add(1);
                    }
                }
            }
        }
        if mutated {
            continue;
        }
        if snapshot != stable_pool_directory_snapshot(pool_dir)? {
            continue;
        }
        return Ok(entry_keys.len().saturating_add(active_generations));
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "HarmonyPIR capacity reconciliation did not stabilize",
    ))
}

fn try_claim_disk_generation(
    pool_dir: &Path,
    target_size: usize,
) -> io::Result<Option<DiskGenerationClaim>> {
    let _capacity_lock = lock_pool_capacity(pool_dir)?;
    if disk_capacity_count_locked(pool_dir, None, None)? >= target_size {
        return Ok(None);
    }
    for _ in 0..16 {
        let path = pool_dir.join(format!("{GENERATION_PREFIX}{}", unique_artifact_suffix()));
        match create_private_pool_file(&path) {
            Ok(file) => {
                file.lock()?;
                sync_directory(pool_dir)?;
                return Ok(Some(DiskGenerationClaim {
                    path,
                    _lock: file,
                    active: true,
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate a unique hint-generation claim",
    ))
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

fn is_legacy_pool_residue_name(name: &str) -> bool {
    name.starts_with("pool_") && (name.ends_with(".hints.tmp") || name.ends_with(".hints.consumed"))
}

fn is_pool_state_artifact_name(name: &str) -> bool {
    name.starts_with("pool_") || name.starts_with(GENERATION_PREFIX)
}

/// Atomically create or verify the durable directory binding. A directory
/// with old markerless state is never adopted automatically because a rolling
/// upgrade could otherwise reinterpret or delete another database/backend's
/// expensive hints.
fn ensure_pool_directory_binding(pool_dir: &Path, binding: &PoolFileBinding) -> io::Result<()> {
    let expected = binding.marker_bytes()?;
    let _capacity_lock = lock_pool_capacity(pool_dir)?;

    // Complete/abort only marker publications made by this protocol. Holding
    // the capacity lock proves no conforming writer can still own these names.
    let mut removed_marker_tmp = false;
    for dir_entry in std::fs::read_dir(pool_dir)? {
        let dir_entry = dir_entry?;
        let name = dir_entry.file_name();
        if name
            .to_string_lossy()
            .starts_with(BINDING_MARKER_TMP_PREFIX)
        {
            match std::fs::remove_file(dir_entry.path()) {
                Ok(()) => removed_marker_tmp = true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    if removed_marker_tmp {
        sync_directory(pool_dir)?;
    }

    let marker_path = pool_dir.join(BINDING_MARKER_FILE);
    match open_private_pool_file(&marker_path, false) {
        Ok(mut marker_file) => {
            if marker_file.metadata()?.len() != BINDING_MARKER_LEN as u64 {
                return Err(invalid_data(
                    "HarmonyPIR pool binding marker length mismatch",
                ));
            }
            let mut actual = [0u8; BINDING_MARKER_LEN];
            marker_file.read_exact(&mut actual)?;
            if actual != expected {
                return Err(invalid_data(
                    "HarmonyPIR pool binding marker does not match this database/backend",
                ));
            }
            for dir_entry in std::fs::read_dir(pool_dir)? {
                let name = dir_entry?.file_name();
                if is_legacy_pool_residue_name(&name.to_string_lossy()) {
                    return Err(invalid_data(
                        "legacy HarmonyPIR pool residue requires offline migration",
                    ));
                }
            }
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    for dir_entry in std::fs::read_dir(pool_dir)? {
        let name = dir_entry?.file_name();
        if is_pool_state_artifact_name(&name.to_string_lossy()) {
            return Err(invalid_data(
                "markerless HarmonyPIR pool state requires offline migration or a new directory",
            ));
        }
    }

    let tmp_path = pool_dir.join(format!(
        "{BINDING_MARKER_TMP_PREFIX}{}",
        unique_artifact_suffix()
    ));
    let result = (|| -> io::Result<()> {
        let mut tmp_file = create_private_pool_file(&tmp_path)?;
        tmp_file.write_all(&expected)?;
        tmp_file.sync_all()?;
        std::fs::hard_link(&tmp_path, &marker_path)?;
        sync_directory(pool_dir)?;
        std::fs::remove_file(&tmp_path)?;
        sync_directory(pool_dir)?;
        let mut marker_file = open_private_pool_file(&marker_path, false)?;
        let mut actual = [0u8; BINDING_MARKER_LEN];
        marker_file.read_exact(&mut actual)?;
        if actual != expected {
            return Err(invalid_data(
                "new HarmonyPIR pool binding marker failed readback",
            ));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        let _ = sync_directory(pool_dir);
    }
    result
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

struct PreparedPoolPersistence {
    path: PathBuf,
    tmp_path: PathBuf,
    header: [u8; POOL_HEADER_LEN],
    checksum: [u8; POOL_CHECKSUM_LEN],
}

struct StagedPoolPersistence {
    tmp_path: PathBuf,
    path: PathBuf,
    file: Option<File>,
    tmp_exists: bool,
}

impl StagedPoolPersistence {
    /// Must be called while holding the cross-process capacity lock. Locking
    /// the new inode before releasing that lock lets reconciliation distinguish
    /// a live out-of-lock write from crash residue.
    fn create(prepared: &PreparedPoolPersistence) -> io::Result<Self> {
        let file = create_private_pool_file(&prepared.tmp_path)?;
        if let Err(error) = file.lock() {
            let _ = std::fs::remove_file(&prepared.tmp_path);
            return Err(error);
        }
        Ok(Self {
            tmp_path: prepared.tmp_path.clone(),
            path: prepared.path.clone(),
            file: Some(file),
            tmp_exists: true,
        })
    }

    /// Potentially multi-gigabyte work. Deliberately does not hold the shared
    /// capacity lock; the inode lock and generation claim remain live.
    fn write_and_sync(
        &mut self,
        prepared: &PreparedPoolPersistence,
        entry: &PoolEntry,
    ) -> io::Result<()> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| invalid_data("staged pool artifact has no open file"))?;
        file.write_all(&prepared.header)?;
        for frame in &entry.index_frames {
            write_lp(file, frame)?;
        }
        for frame in &entry.chunk_frames {
            write_lp(file, frame)?;
        }
        write_lp(file, &entry.key_preamble)?;
        file.write_all(&prepared.checksum)?;
        file.sync_all()
    }

    /// Must be called while holding the capacity lock. `hard_link` publishes
    /// without replacement; the temporary link is then durably removed and
    /// the final inode is revalidated as private and single-link.
    fn publish(mut self) -> io::Result<PathBuf> {
        let pool_dir = self
            .path
            .parent()
            .ok_or_else(|| invalid_data("pool artifact has no parent"))?;
        std::fs::hard_link(&self.tmp_path, &self.path)?;
        sync_directory(pool_dir)?;
        std::fs::remove_file(&self.tmp_path)?;
        self.tmp_exists = false;
        sync_directory(pool_dir)?;
        let _ = open_private_pool_file(&self.path, false)?;
        Ok(self.path.clone())
    }

    fn discard(mut self) -> io::Result<()> {
        if !self.tmp_exists {
            return Ok(());
        }
        match std::fs::remove_file(&self.tmp_path) {
            Ok(()) => {
                self.tmp_exists = false;
                let parent = self
                    .tmp_path
                    .parent()
                    .ok_or_else(|| invalid_data("temporary pool artifact has no parent"))?;
                sync_directory(parent)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.tmp_exists = false;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for StagedPoolPersistence {
    fn drop(&mut self) {
        if !self.tmp_exists {
            return;
        }
        let _ = std::fs::remove_file(&self.tmp_path);
        if let Some(parent) = self.tmp_path.parent() {
            let _ = sync_directory(parent);
        }
    }
}

fn prepare_pool_persistence(
    pool_dir: &Path,
    binding: &PoolFileBinding,
    entry: &PoolEntry,
) -> io::Result<PreparedPoolPersistence> {
    validate_pool_entry(binding, entry)?;
    validate_private_pool_directory(pool_dir, true)?;

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
    let ready_stem = file_name
        .strip_suffix(".hints")
        .expect("pool filenames always end in .hints");
    let tmp_path = pool_dir.join(format!(
        "{ready_stem}{TMP_MARKER}{}",
        unique_artifact_suffix()
    ));

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

    Ok(PreparedPoolPersistence {
        path,
        tmp_path,
        header,
        checksum,
    })
}

/// Test/helper path exercising the same staged write and short publication
/// windows as the production generator.
#[cfg(test)]
fn persist_pool_entry(
    pool_dir: &Path,
    binding: &PoolFileBinding,
    entry: &PoolEntry,
) -> io::Result<PathBuf> {
    ensure_pool_directory_binding(pool_dir, binding)?;
    let prepared = prepare_pool_persistence(pool_dir, binding, entry)?;
    let mut staged = {
        let _capacity_lock = lock_pool_capacity(pool_dir)?;
        StagedPoolPersistence::create(&prepared)?
    };
    staged.write_and_sync(&prepared, entry)?;
    {
        let _capacity_lock = lock_pool_capacity(pool_dir)?;
        staged.publish()
    }
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

fn load_pool_file(
    path: &Path,
    binding: &PoolFileBinding,
    file: &mut File,
) -> io::Result<PoolEntry> {
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
        created_at: Instant::now(),
        persisted_path: Some(path.to_path_buf()),
    })
}

/// Load only matching, unconsumed V2 entries. Legacy, mismatched, corrupt, or
/// temporary files are deleted safely and replenished by the generator;
/// surplus ready entries remain available to other processes.
fn load_pool_files(pool_dir: &Path, binding: &PoolFileBinding, pool_size: usize) -> Vec<PoolEntry> {
    load_pool_files_excluding(
        pool_dir,
        binding,
        pool_size,
        &std::collections::HashSet::new(),
    )
}

fn ready_pool_key(path: &Path) -> Option<[u8; 16]> {
    let name = path.file_name()?.to_str()?;
    let encoded = name.strip_prefix("pool_")?.strip_suffix(".hints")?;
    if encoded.len() != 32 {
        return None;
    }
    let mut key = [0u8; 16];
    hex::decode_to_slice(encoded, &mut key).ok()?;
    Some(key)
}

#[cfg(unix)]
fn open_files_have_same_identity(left: &File, right: &File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(not(unix))]
fn open_files_have_same_identity(_left: &File, _right: &File) -> io::Result<bool> {
    // The production private-file boundary is Unix/POSIX. Refuse disk reuse
    // rather than approximate identity on unsupported platforms.
    Ok(false)
}

struct ReadyPoolSnapshot {
    /// Stable open descriptor. Construction briefly probes the inode lock so a
    /// reservation that already exists is skipped, but the lock is released
    /// before the potentially multi-gigabyte read. Final revalidation probes
    /// again and discards a snapshot raced by AUTH.
    file: File,
}

fn open_ready_pool_snapshot(pool_dir: &Path, path: &Path) -> io::Result<Option<ReadyPoolSnapshot>> {
    let _capacity_lock = lock_pool_capacity(pool_dir)?;
    disk_capacity_count_locked(pool_dir, None, None)?;
    match open_private_pool_file(path, false) {
        Ok(file) => match file.try_lock() {
            Ok(()) => {
                file.unlock()?;
                Ok(Some(ReadyPoolSnapshot { file }))
            }
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(error)) => Err(error),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        // Never unlink a ready namespace entry that we could not safely open
        // and lock. A concurrent AUTH reservation may own the inode even if a
        // permissions/ACL/link-count fault makes validation fail. Leaving the
        // name in place fails availability closed and requires operator repair.
        Err(error) => Err(error),
    }
}

fn ready_pool_snapshot_is_current(
    pool_dir: &Path,
    path: &Path,
    snapshot: &ReadyPoolSnapshot,
) -> io::Result<bool> {
    let _capacity_lock = lock_pool_capacity(pool_dir)?;
    disk_capacity_count_locked(pool_dir, None, None)?;
    let current = match open_private_pool_file(path, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !open_files_have_same_identity(&snapshot.file, &current)? {
        return Ok(false);
    }
    match current.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

fn remove_ready_pool_snapshot_if_current(
    pool_dir: &Path,
    path: &Path,
    snapshot: &ReadyPoolSnapshot,
) -> io::Result<bool> {
    let _capacity_lock = lock_pool_capacity(pool_dir)?;
    disk_capacity_count_locked(pool_dir, None, None)?;
    let current = match open_private_pool_file(path, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Ok(false),
    };
    if !open_files_have_same_identity(&snapshot.file, &current)? {
        return Ok(false);
    }
    // Cleanup takes only this short final lock; disk reads never hold it. A
    // concurrent AUTH reservation wins and forces cleanup to leave the name.
    match current.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(false),
        Err(std::fs::TryLockError::Error(error)) => return Err(error),
    }
    std::fs::remove_file(path)?;
    sync_directory(pool_dir)?;
    Ok(true)
}

fn load_pool_files_excluding(
    pool_dir: &Path,
    binding: &PoolFileBinding,
    pool_size: usize,
    excluded_keys: &std::collections::HashSet<[u8; 16]>,
) -> Vec<PoolEntry> {
    {
        let _capacity_lock = match lock_pool_capacity(pool_dir) {
            Ok(lock) => lock,
            Err(_) => return Vec::new(),
        };
        if disk_capacity_count_locked(pool_dir, None, None).is_err() {
            return Vec::new();
        }
    }
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
        if name.ends_with(".hints.tmp")
            || name.contains(TMP_MARKER)
            || name.ends_with(".hints.consumed")
            || name.contains(RESERVED_MARKER)
            || name.starts_with(GENERATION_PREFIX)
        {
            // Lock-aware reconciliation already ran while holding the shared
            // capacity lock. Never unlink these names in this unlocked scan:
            // another process may still own and publish/consume them.
            continue;
        } else if name.ends_with(".hints") {
            if ready_pool_key(&path).is_some_and(|key| excluded_keys.contains(&key)) {
                continue;
            }
            candidates.push(path);
        }
    }
    candidates.sort();

    let mut entries = Vec::with_capacity(pool_size.min(candidates.len()));
    let mut loaded_keys = std::collections::HashSet::new();
    for path in candidates {
        if entries.len() >= pool_size {
            break;
        }
        let mut snapshot = match open_ready_pool_snapshot(pool_dir, &path) {
            Ok(Some(file)) => file,
            Ok(None) => continue,
            Err(_error) => {
                eprintln!("[hint-pool] Removing an unusable ready entry");
                unsafe_hint_pool_log!(
                    "[hint-pool] unusable ready-entry open detail for {}: {}",
                    path.display(),
                    _error
                );
                continue;
            }
        };
        match load_pool_file(&path, binding, &mut snapshot.file) {
            Ok(entry) => {
                match ready_pool_snapshot_is_current(pool_dir, &path, &snapshot) {
                    Ok(true) if loaded_keys.insert(entry.prp_key) => entries.push(entry),
                    Ok(true) => {
                        eprintln!("[hint-pool] Removing a duplicate ready entry");
                        unsafe_hint_pool_log!(
                            "[hint-pool] duplicate ready-entry path: {}",
                            path.display()
                        );
                        let _ = remove_ready_pool_snapshot_if_current(pool_dir, &path, &snapshot);
                    }
                    // A peer reserved or consumed the file after our stable
                    // open. The snapshot remains safe to drop, but its former
                    // namespace must not be removed or restored by this load.
                    Ok(false) | Err(_) => {}
                }
            }
            Err(_error) => {
                eprintln!("[hint-pool] Removing an unusable ready entry");
                unsafe_hint_pool_log!(
                    "[hint-pool] unusable ready-entry detail for {}: {}",
                    path.display(),
                    _error
                );
                let _ = remove_ready_pool_snapshot_if_current(pool_dir, &path, &snapshot);
            }
        }
    }
    entries
}

fn prepare_pool_directory(path: &Path) -> io::Result<()> {
    use rand::RngCore;

    validate_private_pool_directory(path, true)?;

    let nonce = rand::thread_rng().next_u64();
    let probe_name = format!(".hmpool-probe-{}-{:016x}", std::process::id(), nonce);
    let probe_path = path.join(probe_name);
    let result = (|| -> io::Result<()> {
        let mut file = create_private_pool_file(&probe_path)?;
        file.write_all(b"HMPOOL-DURABILITY-PROBE")?;
        file.sync_all()?;
        drop(file);
        let _ = open_private_pool_file(&probe_path, false)?;
        std::fs::remove_file(&probe_path)?;
        sync_directory(path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&probe_path);
    }
    result
}

fn sync_directory(path: &Path) -> io::Result<()> {
    validate_private_pool_directory(path, false)?;
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)?;
    File::from(fd).sync_all()
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
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
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
        test_entry_with_key(binding, [0x42; 16])
    }

    fn test_entry_with_key(binding: &PoolFileBinding, prp_key: [u8; 16]) -> PoolEntry {
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

    fn test_pool(target_size: usize, entries: impl IntoIterator<Item = PoolEntry>) -> HintPool {
        HintPool {
            bound_db_id: 0,
            target_size,
            state: Arc::new(Mutex::new(PoolState {
                entries: entries.into_iter().collect(),
                ..PoolState::default()
            })),
            shutdown: Arc::new(AtomicBool::new(true)),
            _generator: None,
        }
    }

    fn test_disk_pool(
        _dir: &Path,
        binding: &PoolFileBinding,
        target_size: usize,
        entries: Vec<PoolEntry>,
    ) -> HintPool {
        HintPool {
            bound_db_id: binding.bound_db_id,
            target_size,
            state: Arc::new(Mutex::new(PoolState {
                entries: entries.into_iter().collect(),
                ..PoolState::default()
            })),
            shutdown: Arc::new(AtomicBool::new(true)),
            _generator: None,
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

    fn test_mapped_database_for_worker_lifetime() -> MappedDatabase {
        let index_params = pir_core::params::INDEX_PARAMS.clone();
        let chunk_params = pir_core::params::CHUNK_PARAMS.clone();
        MappedDatabase {
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
        }
    }

    fn reserved_artifacts(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(RESERVED_MARKER))
            })
            .collect()
    }

    fn make_legacy_reserved_artifact(ready_path: &Path) -> LegacyReservedPoolArtifact {
        let parent = ready_path.parent().unwrap();
        let _capacity_lock = lock_pool_capacity(parent).unwrap();
        let file = open_private_pool_file(ready_path, true).unwrap();
        file.lock().unwrap();
        let file_name = ready_path.file_name().unwrap().to_string_lossy();
        let reserved_path =
            parent.join(format!("{file_name}.reserved.{}", unique_artifact_suffix()));
        std::fs::rename(ready_path, &reserved_path).unwrap();
        sync_directory(parent).unwrap();
        LegacyReservedPoolArtifact {
            ready_path: ready_path.to_path_buf(),
            reserved_path,
            _lock: file,
        }
    }

    #[test]
    fn default_hint_pool_logs_have_no_prp_group_or_timing_fields() {
        fn direct_log_calls<'a>(source: &'a str, needle: &str) -> Vec<&'a str> {
            let mut calls = Vec::new();
            let mut offset = 0;
            while let Some(relative) = source[offset..].find(needle) {
                let start = offset + relative;
                if needle == "println!(" && start != 0 && source.as_bytes()[start - 1] == b'e' {
                    offset = start + needle.len();
                    continue;
                }
                let tail = &source[start..];
                let end = tail.find(");").map(|end| end + 2).unwrap_or(tail.len());
                calls.push(&tail[..end]);
                offset = start + end;
            }
            calls
        }

        let source = include_str!("hint_pool.rs");
        let non_test = source
            .split_once("#[cfg(test)]\nmod tests")
            .expect("hint-pool source test boundary")
            .0;
        for call in direct_log_calls(non_test, "println!(")
            .into_iter()
            .chain(direct_log_calls(non_test, "eprintln!("))
        {
            for forbidden in [
                "prp_key",
                "hex_prefix",
                "elapsed",
                "index_frames",
                "chunk_frames",
                "path.display()",
            ] {
                assert!(
                    !call.contains(forbidden),
                    "default hint-pool log contains `{forbidden}`: {call}"
                );
            }
        }

        let default_macro = source
            .split_once("#[cfg(not(feature = \"test-only-unsafe-query-logging\"))]")
            .expect("default unsafe-log macro gate")
            .1
            .split_once("// ─── Config")
            .expect("default unsafe-log macro end")
            .0;
        assert!(!default_macro.contains("eprintln!"));
        assert!(!default_macro.contains("format_args!"));

        let sensitive_generation_log = source
            .find("Generated entry (prp_key=")
            .expect("feature-only diagnostic remains available");
        let gate = &source[sensitive_generation_log.saturating_sub(256)..sensitive_generation_log];
        assert!(gate.contains("#[cfg(feature = \"test-only-unsafe-query-logging\")]"));
    }

    #[test]
    fn generator_owns_mmaps_and_drop_joins_before_releasing_them() {
        let db = test_mapped_database_for_worker_lifetime();
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
        assert_eq!(Arc::strong_count(&chunk_owner), 3);
        drop(db);
        assert_eq!(Arc::strong_count(&index_owner), 2);
        assert_eq!(Arc::strong_count(&chunk_owner), 2);

        drop(pool);
        assert_eq!(Arc::strong_count(&index_owner), 1);
        assert_eq!(Arc::strong_count(&chunk_owner), 1);

        let source = include_str!("hint_pool.rs");
        let non_test = source
            .split_once("#[cfg(test)]\nmod tests")
            .expect("hint-pool source test boundary")
            .0;
        assert!(!non_test.contains("from_raw_parts"));
        assert!(!non_test.contains("mmap_ptr"));
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

    #[cfg(unix)]
    #[test]
    fn persisted_pool_artifacts_are_private_single_link_files() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = TestDir::new();
        let binding = test_binding(0x12);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let directory = std::fs::symlink_metadata(&dir.0).unwrap();
        let artifact = std::fs::symlink_metadata(&path).unwrap();

        assert!(directory.file_type().is_dir());
        assert_eq!(directory.permissions().mode() & 0o7777, 0o700);
        assert!(artifact.file_type().is_file());
        assert_eq!(artifact.permissions().mode() & 0o7777, 0o600);
        assert_eq!(artifact.nlink(), 1);
    }

    #[test]
    fn tmp_only_publish_crash_residue_is_removed() {
        let dir = TestDir::new();
        let binding = test_binding(0x13);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let tmp_path = dir.0.join(format!(
            "{}{}crashed",
            path.file_stem().unwrap().to_string_lossy(),
            TMP_MARKER
        ));
        std::fs::rename(&path, &tmp_path).unwrap();
        sync_directory(&dir.0).unwrap();

        assert!(load_pool_files(&dir.0, &binding, 1).is_empty());
        assert!(!tmp_path.exists());
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn final_plus_same_inode_tmp_publish_crash_recovers_final() {
        use std::os::unix::fs::MetadataExt;

        let dir = TestDir::new();
        let binding = test_binding(0x14);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let tmp_path = dir.0.join(format!(
            "{}{}crashed",
            path.file_stem().unwrap().to_string_lossy(),
            TMP_MARKER
        ));
        std::fs::hard_link(&path, &tmp_path).unwrap();
        sync_directory(&dir.0).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 2);

        let loaded = load_pool_files(&dir.0, &binding, 1);
        assert_eq!(loaded.len(), 1);
        assert!(!tmp_path.exists());
        assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn unrecognized_hardlink_is_never_loaded_or_unlinked_online() {
        let dir = TestDir::new();
        let binding = test_binding(0x15);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let preserved_link = dir.0.join("not-a-pool-artifact");
        std::fs::hard_link(&path, &preserved_link).unwrap();

        assert!(load_pool_files(&dir.0, &binding, 1).is_empty());
        assert!(
            path.exists(),
            "a name whose inode cannot be safely locked must require operator repair"
        );
        assert!(preserved_link.exists());
    }

    #[cfg(unix)]
    #[test]
    fn nonprivate_or_symlinked_ready_artifacts_are_never_loaded_or_unlinked_online() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = TestDir::new();
        let binding = test_binding(0x17);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_pool_files(&dir.0, &binding, 1).is_empty());
        assert!(path.exists());
        std::fs::remove_file(&path).unwrap();

        let target = dir.0.join("private-target");
        pir_private_files::write_new_private_file_v1(&target, b"not-a-hint", "test target")
            .unwrap();
        symlink(&target, &path).unwrap();
        assert!(load_pool_files(&dir.0, &binding, 1).is_empty());
        assert!(
            path.exists(),
            "online loader must not unlink a name it cannot open and lock"
        );
        assert!(
            target.exists(),
            "loader must never follow the symlink target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_or_nonprivate_pool_boundaries_fail_closed() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = TestDir::new();
        let real = root.0.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let linked = root.0.join("linked");
        symlink(&real, &linked).unwrap();
        assert!(prepare_pool_directory(&linked).is_err());

        let public = root.0.join("public");
        std::fs::create_dir(&public).unwrap();
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(prepare_pool_directory(&public).is_err());
    }

    #[test]
    fn staged_hint_write_does_not_hold_the_capacity_lock() {
        let dir = TestDir::new();
        let binding = test_binding(0x16);
        let entry = test_entry(&binding);
        let prepared = prepare_pool_persistence(&dir.0, &binding, &entry).unwrap();
        let mut staged = {
            let _capacity_lock = lock_pool_capacity(&dir.0).unwrap();
            StagedPoolPersistence::create(&prepared).unwrap()
        };

        // This is the lock needed by hot-path reservation. It remains
        // available for the whole large staging write window.
        let capacity_lock = lock_pool_capacity(&dir.0).unwrap();
        drop(capacity_lock);
        staged.write_and_sync(&prepared, &entry).unwrap();
        {
            let _capacity_lock = lock_pool_capacity(&dir.0).unwrap();
            assert_eq!(
                disk_capacity_count_locked(&dir.0, None, Some(&staged.tmp_path)).unwrap(),
                0
            );
            assert!(
                staged.tmp_path.exists(),
                "final recheck must not reconcile its own staged inode"
            );
        }
        staged.discard().unwrap();
    }

    #[test]
    fn unlocked_loader_never_unlinks_a_live_staged_publish() {
        let dir = TestDir::new();
        let binding = test_binding(0x18);
        let entry = test_entry(&binding);
        let prepared = prepare_pool_persistence(&dir.0, &binding, &entry).unwrap();
        let mut staged = {
            let _capacity_lock = lock_pool_capacity(&dir.0).unwrap();
            StagedPoolPersistence::create(&prepared).unwrap()
        };
        staged.write_and_sync(&prepared, &entry).unwrap();

        assert!(load_pool_files(&dir.0, &binding, 1).is_empty());
        assert!(
            staged.tmp_path.exists(),
            "an unlocked ready-file scan must not unlink a live writer's tmp"
        );

        let published = {
            let _capacity_lock = lock_pool_capacity(&dir.0).unwrap();
            assert_eq!(
                disk_capacity_count_locked(&dir.0, None, Some(&staged.tmp_path)).unwrap(),
                0
            );
            staged.publish().unwrap()
        };
        assert!(published.exists());
        assert_eq!(load_pool_files(&dir.0, &binding, 1).len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn temporary_open_failure_is_preserved_and_fails_reconciliation_closed() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new();
        let target = dir.0.join("unrelated-private-target");
        pir_private_files::write_new_private_file_v1(&target, b"target", "tmp target test")
            .unwrap();
        let tmp_path = dir.0.join(format!(
            "pool_42424242424242424242424242424242{TMP_MARKER}invalid"
        ));
        symlink(&target, &tmp_path).unwrap();

        let _capacity_lock = lock_pool_capacity(&dir.0).unwrap();
        assert!(disk_capacity_count_locked(&dir.0, None, None).is_err());
        assert!(tmp_path.exists());
        assert!(target.exists());
    }

    #[test]
    fn unbound_startup_never_purges_a_live_peer_reservation() {
        let dir = TestDir::new();
        let binding = test_binding(0x19);
        let ready = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let entries = load_pool_files(&dir.0, &binding, 1);
        let bound_pool = test_disk_pool(&dir.0, &binding, 1, entries);
        let reservation = bound_pool.try_reserve().unwrap();
        assert!(ready.exists());
        assert!(reserved_artifacts(&dir.0).is_empty());

        let db = test_mapped_database_for_worker_lifetime();
        let unbound_pool = HintPool::new(
            HintPoolConfig {
                pool_size: 0,
                prp_backend: remote::PRP_HMR12,
                pool_dir: Some(dir.0.clone()),
            },
            0,
            &db,
        )
        .unwrap();
        assert!(
            ready.exists(),
            "an unbound peer startup must not delete a locked ready artifact"
        );

        drop(unbound_pool);
        drop(db);
        assert!(reservation.restore().unwrap());
        assert!(ready.exists());
        assert!(reserved_artifacts(&dir.0).is_empty());
    }

    #[test]
    fn legacy_v1_file_is_rejected_and_deleted() {
        let dir = TestDir::new();
        let path = dir.0.join("pool_00000000.hints");
        let mut legacy = vec![0u8; POOL_HEADER_LEN + POOL_CHECKSUM_LEN];
        legacy[..7].copy_from_slice(b"HMPOOL\x01");
        pir_private_files::write_new_private_file_v1(&path, &legacy, "legacy pool test").unwrap();

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
        let copied_name = dir.0.join("pool_00000000000000000000000000000000.hints");
        std::fs::rename(&canonical, &copied_name).unwrap();

        assert!(load_pool_files(&dir.0, &binding, 4).is_empty());
        assert!(!copied_name.exists());
    }

    #[test]
    fn durable_reservation_is_consumed_only_on_commit() {
        let dir = TestDir::new();
        let binding = test_binding(0x33);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let loaded = load_pool_files(&dir.0, &binding, 1);
        let pool = test_disk_pool(&dir.0, &binding, 1, loaded);

        assert_eq!(pool.database_id(), 0);
        let reservation = pool.try_reserve().expect("one durable reservation");
        assert!(
            path.exists(),
            "AUTH reservation must leave the durable ready name unchanged"
        );
        assert!(reserved_artifacts(&dir.0).is_empty());
        let entry = reservation.commit_consume().unwrap();
        assert_eq!(entry.prp_key, [0x42; 16]);
        assert!(
            !path.exists(),
            "post-credential commit must permanently consume the ready artifact"
        );
        assert!(reserved_artifacts(&dir.0).is_empty());
    }

    #[test]
    fn unlink_then_directory_fsync_failure_never_returns_the_prp_entry() {
        let dir = TestDir::new();
        let binding = test_binding(0x38);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let loaded = load_pool_files(&dir.0, &binding, 1);
        let pool = test_disk_pool(&dir.0, &binding, 1, loaded);
        let reservation = pool.try_reserve().unwrap();

        let result = reservation.commit_consume_with_sync(|_| {
            Err(io::Error::other("injected directory fsync failure"))
        });
        let error = match result {
            Ok(_) => panic!("ambiguous durable unlink must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("injected"));
        assert!(!path.exists());
        assert!(reserved_artifacts(&dir.0).is_empty());
        let state = pool.state.lock().unwrap();
        assert_eq!(state.reservations, 0);
        assert!(
            state.entries.is_empty(),
            "ambiguous consume must discard PRP"
        );
    }

    #[test]
    fn rejected_reservation_restores_the_durable_ready_artifact() {
        let dir = TestDir::new();
        let binding = test_binding(0x34);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let loaded = load_pool_files(&dir.0, &binding, 1);
        let pool = test_disk_pool(&dir.0, &binding, 1, loaded);

        let reservation = pool.try_reserve().expect("one durable reservation");
        assert!(path.exists());
        assert!(reservation.restore().unwrap());
        assert!(
            path.exists(),
            "AUTH rejection must restore durable ready state"
        );
        assert_eq!(pool.len(), 1);
        assert!(reserved_artifacts(&dir.0).is_empty());
    }

    #[test]
    fn reservation_rejects_a_stale_open_descriptor_after_same_name_replacement() {
        let dir = TestDir::new();
        let binding = test_binding(0x76);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let stale = open_private_pool_file(&path, true).unwrap();
        std::fs::remove_file(&path).unwrap();
        persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();

        let error = match finish_pool_file_reservation(&path, stale) {
            Ok(_) => panic!("stale inode must not reserve a replacement name"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("changed"));
        assert!(path.exists());
    }

    #[test]
    fn corruption_cleanup_never_unlinks_an_auth_reserved_ready_inode() {
        let dir = TestDir::new();
        let binding = test_binding(0x77);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let pool = test_disk_pool(&dir.0, &binding, 1, load_pool_files(&dir.0, &binding, 1));
        let reservation = pool.try_reserve().unwrap();

        assert!(
            open_ready_pool_snapshot(&dir.0, &path).unwrap().is_none(),
            "loader must skip an AUTH-reserved inode before reading or cleanup"
        );
        assert!(path.exists());
        assert!(reservation.restore().unwrap());
        let snapshot = open_ready_pool_snapshot(&dir.0, &path)
            .unwrap()
            .expect("lock released after reservation restore");
        assert!(remove_ready_pool_snapshot_if_current(&dir.0, &path, &snapshot).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn loader_cleanup_never_unlinks_a_same_name_replacement() {
        let dir = TestDir::new();
        let binding = test_binding(0x7b);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let snapshot = open_ready_pool_snapshot(&dir.0, &path).unwrap().unwrap();

        std::fs::remove_file(&path).unwrap();
        let replacement = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        assert!(
            !remove_ready_pool_snapshot_if_current(&dir.0, &path, &snapshot).unwrap(),
            "cleanup of the old open inode must not remove its replacement"
        );
        assert!(replacement.exists());
    }

    #[test]
    fn loader_read_does_not_hold_the_reservation_lock_and_late_auth_wins() {
        let dir = TestDir::new();
        let binding = test_binding(0x7d);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let snapshot = open_ready_pool_snapshot(&dir.0, &path).unwrap().unwrap();

        let reservation =
            reserve_pool_file(&path).expect("background read must not make the AUTH hot path busy");
        assert!(
            !ready_pool_snapshot_is_current(&dir.0, &path, &snapshot).unwrap(),
            "final loader revalidation must discard a snapshot raced by AUTH"
        );
        drop(reservation);
        assert!(ready_pool_snapshot_is_current(&dir.0, &path, &snapshot).unwrap());
    }

    #[test]
    fn committed_reservation_cannot_be_resurrected_by_an_older_loader_snapshot() {
        let dir = TestDir::new();
        let binding = test_binding(0x78);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let mut snapshot = open_ready_pool_snapshot(&dir.0, &path).unwrap().unwrap();
        let snapshot_entry = load_pool_file(&path, &binding, &mut snapshot.file).unwrap();
        assert!(ready_pool_snapshot_is_current(&dir.0, &path, &snapshot).unwrap());
        drop(snapshot);
        let pool = test_disk_pool(&dir.0, &binding, 1, load_pool_files(&dir.0, &binding, 1));

        let consumed = pool.try_reserve().unwrap().commit_consume().unwrap();
        assert_eq!(consumed.prp_key, snapshot_entry.prp_key);
        assert!(!path.exists());
        let stale_loader_pool = test_disk_pool(&dir.0, &binding, 1, vec![snapshot_entry]);
        assert!(
            stale_loader_pool.try_reserve().is_none(),
            "an entry queued from an older snapshot cannot resurrect an unlinked key"
        );
    }

    #[test]
    fn loader_skips_a_locked_first_candidate_and_reads_the_next_ready_key() {
        let dir = TestDir::new();
        let binding = test_binding(0x7c);
        let first = test_entry_with_key(&binding, [0x10; 16]);
        let second = test_entry_with_key(&binding, [0x20; 16]);
        let first_path = persist_pool_entry(&dir.0, &binding, &first).unwrap();
        persist_pool_entry(&dir.0, &binding, &second).unwrap();
        let reservation = reserve_pool_file(&first_path).unwrap();

        let loaded = load_pool_files(&dir.0, &binding, 1);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].prp_key, [0x20; 16]);
        drop(reservation);
    }

    #[test]
    fn auth_hot_path_never_loads_disk_and_background_refresh_excludes_local_keys() {
        let dir = TestDir::new();
        let binding = test_binding(0x79);
        let first = test_entry_with_key(&binding, [0x10; 16]);
        let second = test_entry_with_key(&binding, [0x20; 16]);
        persist_pool_entry(&dir.0, &binding, &first).unwrap();
        persist_pool_entry(&dir.0, &binding, &second).unwrap();
        let pool = test_disk_pool(&dir.0, &binding, 2, vec![first]);
        let config = HintPoolConfig {
            pool_size: 2,
            prp_backend: binding.prp_backend,
            pool_dir: Some(dir.0.clone()),
        };

        // With memory empty the connection path returns immediately; it does
        // not scan or deserialize either potentially huge hint file.
        let empty = test_disk_pool(&dir.0, &binding, 2, Vec::new());
        assert!(empty.try_reserve().is_none());
        assert_eq!(empty.len(), 0);

        refresh_state_from_disk_background(&config, Some(&binding), &pool.state);
        let state = pool.state.lock().unwrap();
        let keys: std::collections::HashSet<_> =
            state.entries.iter().map(|entry| entry.prp_key).collect();
        assert_eq!(keys, [[0x10; 16], [0x20; 16]].into_iter().collect());
    }

    #[test]
    fn rejected_durable_reservation_never_opens_generation_capacity() {
        let dir = TestDir::new();
        let binding = test_binding(0x3c);
        persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let loaded = load_pool_files(&dir.0, &binding, 1);
        let pool = test_disk_pool(&dir.0, &binding, 1, loaded);
        let config = HintPoolConfig {
            pool_size: 1,
            prp_backend: binding.prp_backend,
            pool_dir: Some(dir.0.clone()),
        };

        let reservation = pool.try_reserve().unwrap();
        assert!(claim_generation_capacity(&config, &pool.state)
            .unwrap()
            .is_none());
        assert!(reservation.restore().unwrap());
        assert!(claim_generation_capacity(&config, &pool.state)
            .unwrap()
            .is_none());
    }

    #[test]
    fn live_cross_process_reservation_is_counted_without_namespace_mutation() {
        let dir = TestDir::new();
        let binding = test_binding(0x39);
        let ready = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let durable = reserve_pool_file(&ready).unwrap();

        {
            let _capacity_lock = lock_pool_capacity(&dir.0).unwrap();
            assert_eq!(disk_capacity_count_locked(&dir.0, None, None).unwrap(), 1);
        }
        assert!(ready.exists(), "reservation must not rename the ready file");
        assert!(reserve_pool_file(&ready).is_err());
        assert!(try_claim_disk_generation(&dir.0, 1).unwrap().is_none());

        drop(durable); // model owner-process crash: OS releases its file lock.
        {
            let _capacity_lock = lock_pool_capacity(&dir.0).unwrap();
            assert_eq!(disk_capacity_count_locked(&dir.0, None, None).unwrap(), 1);
        }
        assert!(ready.exists(), "lock release leaves the ready name intact");
        drop(reserve_pool_file(&ready).unwrap());
    }

    #[test]
    fn online_reservation_floor_uses_current_ready_capacity_not_target_size() {
        let dir = TestDir::new();
        let binding = test_binding(0x38);
        let only = test_entry_with_key(&binding, [0x10; 16]);
        persist_pool_entry(&dir.0, &binding, &only).unwrap();
        let pool = test_disk_pool(&dir.0, &binding, 8, vec![only]);

        assert!(pool.try_reserve_preserving_ready_floor(1).is_none());
        let local = pool
            .try_reserve()
            .expect("provider-local admission keeps the last ready entry");
        assert_eq!(local.prp_key, [0x10; 16]);
        assert!(local.restore().unwrap());
    }

    #[test]
    fn two_pool_handles_preserve_one_cross_process_lockable_ready_inode() {
        let dir = TestDir::new();
        let binding = test_binding(0x37);
        let first = test_entry_with_key(&binding, [0x10; 16]);
        let second = test_entry_with_key(&binding, [0x20; 16]);
        persist_pool_entry(&dir.0, &binding, &first).unwrap();
        persist_pool_entry(&dir.0, &binding, &second).unwrap();
        let left = test_disk_pool(&dir.0, &binding, 2, load_pool_files(&dir.0, &binding, 2));
        let right = test_disk_pool(&dir.0, &binding, 2, load_pool_files(&dir.0, &binding, 2));

        let online = left
            .try_reserve_preserving_ready_floor(1)
            .expect("first online reservation leaves one ready entry");
        assert!(
            right.try_reserve_preserving_ready_floor(1).is_none(),
            "a second process cannot consume the cross-process ready floor"
        );
        let local = right
            .try_reserve()
            .expect("provider-local admission can use the preserved entry");
        assert_ne!(online.prp_key, local.prp_key);
        assert!(local.restore().unwrap());
        assert!(online.restore().unwrap());
    }

    #[test]
    fn unvalidated_canonical_surplus_never_counts_toward_online_floor() {
        let dir = TestDir::new();
        let binding = test_binding(0x34);
        let first = test_entry_with_key(&binding, [0x10; 16]);
        let second = test_entry_with_key(&binding, [0x20; 16]);
        let first_path = persist_pool_entry(&dir.0, &binding, &first).unwrap();
        let second_path = persist_pool_entry(&dir.0, &binding, &second).unwrap();
        let loaded = load_pool_files(&dir.0, &binding, 2);
        assert_eq!(loaded.len(), 2);

        // Another process owns the second validated inode. A same-shaped but
        // unvalidated canonical name must not masquerade as the floor and let
        // online admission take the only remaining usable entry.
        let held = reserve_pool_file(&second_path).unwrap();
        let corrupt_surplus = dir.0.join(pool_file_name(&[0x30; 16]));
        pir_private_files::write_new_private_file_v1(
            &corrupt_surplus,
            b"not-a-valid-hint-pool-entry",
            "corrupt floor surplus",
        )
        .unwrap();
        let pool = test_disk_pool(&dir.0, &binding, 3, loaded);
        assert!(pool.try_reserve_preserving_ready_floor(1).is_none());
        assert!(first_path.exists());
        drop(held);
    }

    #[test]
    fn locked_queue_head_rotates_to_a_usable_candidate_without_bypassing_floor() {
        let dir = TestDir::new();
        let binding = test_binding(0x33);
        let first = test_entry_with_key(&binding, [0x10; 16]);
        let second = test_entry_with_key(&binding, [0x20; 16]);
        let third = test_entry_with_key(&binding, [0x30; 16]);
        let first_path = persist_pool_entry(&dir.0, &binding, &first).unwrap();
        persist_pool_entry(&dir.0, &binding, &second).unwrap();
        persist_pool_entry(&dir.0, &binding, &third).unwrap();
        let loaded = load_pool_files(&dir.0, &binding, 3);
        assert_eq!(loaded.len(), 3);
        let held = reserve_pool_file(&first_path).unwrap();
        let pool = test_disk_pool(&dir.0, &binding, 3, loaded);

        let online = pool
            .try_reserve_preserving_ready_floor(1)
            .expect("a locked queue head must not hide the next usable entry");
        assert_eq!(online.prp_key, [0x20; 16]);
        assert!(online.restore().unwrap());
        drop(held);
    }

    #[cfg(unix)]
    #[test]
    fn crash_between_restore_link_and_unlink_completes_to_one_ready_link() {
        use std::os::unix::fs::MetadataExt;

        let dir = TestDir::new();
        let binding = test_binding(0x3d);
        let ready = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let durable = make_legacy_reserved_artifact(&ready);
        let reserved = durable.reserved_path.clone();
        std::fs::hard_link(&reserved, &ready).unwrap();
        sync_directory(&dir.0).unwrap();
        drop(durable);
        assert_eq!(std::fs::metadata(&ready).unwrap().nlink(), 2);

        {
            let _capacity_lock = lock_pool_capacity(&dir.0).unwrap();
            assert_eq!(disk_capacity_count_locked(&dir.0, None, None).unwrap(), 1);
        }
        assert!(ready.exists());
        assert!(!reserved.exists());
        assert_eq!(std::fs::metadata(&ready).unwrap().nlink(), 1);
    }

    #[test]
    fn generation_completion_rechecks_capacity_before_persist_and_enqueue() {
        let dir = TestDir::new();
        let binding = test_binding(0x3a);
        let first = test_entry_with_key(&binding, [0x10; 16]);
        persist_pool_entry(&dir.0, &binding, &first).unwrap();
        let config = HintPoolConfig {
            pool_size: 2,
            prp_backend: binding.prp_backend,
            pool_dir: Some(dir.0.clone()),
        };
        let state = Arc::new(Mutex::new(PoolState::default()));
        let claim = claim_generation_capacity(&config, &state)
            .unwrap()
            .expect("one free generation slot");

        // Another process fills the last slot while this expensive generation
        // is running. The completion check must discard our third entry.
        let second = test_entry_with_key(&binding, [0x20; 16]);
        persist_pool_entry(&dir.0, &binding, &second).unwrap();
        let generated = test_entry_with_key(&binding, [0x30; 16]);
        assert!(
            !finalize_generated_entry(claim, &config, Some(&binding), &state, generated,).unwrap()
        );
        let ready_count = std::fs::read_dir(&dir.0)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".hints"))
            .count();
        assert_eq!(ready_count, 2);
        assert!(state.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn multiple_stale_generation_claims_are_removed_with_stable_rescans() {
        let dir = TestDir::new();
        let binding = test_binding(0x7e);
        persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let first_path = dir
            .0
            .join(format!("{GENERATION_PREFIX}{}", unique_artifact_suffix()));
        let second_path = dir
            .0
            .join(format!("{GENERATION_PREFIX}{}", unique_artifact_suffix()));
        drop(create_private_pool_file(&first_path).unwrap());
        drop(create_private_pool_file(&second_path).unwrap());
        sync_directory(&dir.0).unwrap();

        let _capacity_lock = lock_pool_capacity(&dir.0).unwrap();
        assert_eq!(disk_capacity_count_locked(&dir.0, None, None).unwrap(), 1);
        assert!(!first_path.exists());
        assert!(!second_path.exists());
    }

    #[test]
    fn two_pool_processes_have_one_durable_reservation_winner() {
        let dir = TestDir::new();
        let binding = test_binding(0x3b);
        persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let left = Arc::new(test_disk_pool(
            &dir.0,
            &binding,
            1,
            load_pool_files(&dir.0, &binding, 1),
        ));
        let right = Arc::new(test_disk_pool(
            &dir.0,
            &binding,
            1,
            load_pool_files(&dir.0, &binding, 1),
        ));
        let start = Arc::new(std::sync::Barrier::new(2));
        let hold = Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = [left, right]
            .into_iter()
            .map(|pool| {
                let start = Arc::clone(&start);
                let hold = Arc::clone(&hold);
                std::thread::spawn(move || {
                    start.wait();
                    let reservation = pool.try_reserve();
                    let won = reservation.is_some();
                    hold.wait();
                    drop(reservation);
                    won
                })
            })
            .collect();
        let winners = workers
            .into_iter()
            .map(|worker| worker.join().unwrap() as usize)
            .sum::<usize>();
        assert_eq!(winners, 1);
    }

    #[test]
    fn subprocess_file_lock_probe() {
        let Ok(path) = std::env::var("BITCOINPIR_HINT_POOL_LOCK_PROBE_PATH") else {
            return;
        };
        let expect_blocked =
            std::env::var_os("BITCOINPIR_HINT_POOL_LOCK_PROBE_EXPECT_BLOCKED").is_some();
        let file = open_private_pool_file(Path::new(&path), true).unwrap();
        let blocked = match file.try_lock() {
            Ok(()) => false,
            Err(std::fs::TryLockError::WouldBlock) => true,
            Err(std::fs::TryLockError::Error(error)) => panic!("lock probe failed: {error}"),
        };
        assert_eq!(blocked, expect_blocked);
    }

    #[test]
    fn subprocess_online_floor_probe() {
        let Ok(pool_dir) = std::env::var("BITCOINPIR_HINT_POOL_FLOOR_PROBE_DIR") else {
            return;
        };
        let ready_signal =
            PathBuf::from(std::env::var("BITCOINPIR_HINT_POOL_FLOOR_PROBE_READY").unwrap());
        let go_signal =
            PathBuf::from(std::env::var("BITCOINPIR_HINT_POOL_FLOOR_PROBE_GO").unwrap());
        let binding = test_binding(0x32);
        let entries = load_pool_files(Path::new(&pool_dir), &binding, 2);
        assert_eq!(entries.len(), 2, "child must snapshot both ready entries");
        std::fs::write(&ready_signal, b"ready").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !go_signal.exists() {
            assert!(
                Instant::now() < deadline,
                "parent did not release floor probe"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let pool = test_disk_pool(Path::new(&pool_dir), &binding, 2, entries);
        assert!(
            pool.try_reserve_preserving_ready_floor(1).is_none(),
            "child online admission must preserve the cross-process floor"
        );
        let local = pool
            .try_reserve()
            .expect("child provider-local admission must acquire the preserved entry");
        assert!(local.restore().unwrap());
    }

    #[test]
    fn independent_process_online_floor_preserves_provider_local_entry() {
        let dir = TestDir::new();
        let binding = test_binding(0x32);
        let first = test_entry_with_key(&binding, [0x10; 16]);
        let second = test_entry_with_key(&binding, [0x20; 16]);
        persist_pool_entry(&dir.0, &binding, &first).unwrap();
        persist_pool_entry(&dir.0, &binding, &second).unwrap();
        let parent_entries = load_pool_files(&dir.0, &binding, 2);
        let parent_pool = test_disk_pool(&dir.0, &binding, 2, parent_entries);
        let ready_signal = dir.0.join("floor-probe-child-ready");
        let go_signal = dir.0.join("floor-probe-parent-go");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("subprocess_online_floor_probe")
            .arg("--test-threads=1")
            .env("BITCOINPIR_HINT_POOL_FLOOR_PROBE_DIR", &dir.0)
            .env("BITCOINPIR_HINT_POOL_FLOOR_PROBE_READY", &ready_signal)
            .env("BITCOINPIR_HINT_POOL_FLOOR_PROBE_GO", &go_signal)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready_signal.exists() {
            assert!(
                Instant::now() < deadline,
                "child did not load pool snapshot"
            );
            assert!(
                child.try_wait().unwrap().is_none(),
                "child exited before barrier"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let parent_online = parent_pool
            .try_reserve_preserving_ready_floor(1)
            .expect("parent online admission leaves one ready inode");
        std::fs::write(&go_signal, b"go").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "subprocess floor probe failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(parent_online.restore().unwrap());
    }

    #[test]
    fn reservation_lock_excludes_an_independent_process_and_releases_on_drop() {
        fn run_probe(path: &Path, expect_blocked: bool) {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .arg("subprocess_file_lock_probe")
                .arg("--test-threads=1")
                .env("BITCOINPIR_HINT_POOL_LOCK_PROBE_PATH", path);
            if expect_blocked {
                command.env("BITCOINPIR_HINT_POOL_LOCK_PROBE_EXPECT_BLOCKED", "1");
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "subprocess lock probe failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let dir = TestDir::new();
        let binding = test_binding(0x7a);
        let ready = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let reservation = reserve_pool_file(&ready).unwrap();
        run_probe(&ready, true);
        drop(reservation);
        run_probe(&ready, false);
    }

    #[test]
    fn reservation_discards_stale_local_entry_when_another_process_claimed_file() {
        let dir = TestDir::new();
        let binding = test_binding(0x35);
        let path = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let loaded = load_pool_files(&dir.0, &binding, 1);
        std::fs::remove_file(&path).unwrap();
        let pool = test_disk_pool(&dir.0, &binding, 1, loaded);

        assert!(
            pool.try_reserve().is_none(),
            "a missing file means another process may already own the key"
        );
    }

    #[test]
    fn reserved_entry_can_be_returned_after_auth_rejection_or_pre_use_disconnect() {
        let binding = test_binding(0x36);
        let expected_key = test_entry(&binding).prp_key;
        let pool = test_pool(1, [test_entry(&binding)]);

        let reservation = pool.try_reserve().expect("one reservation");
        assert!(pool.is_empty());
        assert!(reservation.restore().unwrap());
        assert_eq!(pool.len(), 1);
        assert_eq!(
            pool.try_take().expect("returned reservation").prp_key,
            expected_key
        );
    }

    #[test]
    fn reservation_counts_against_memory_generation_capacity() {
        let binding = test_binding(0x37);
        let pool = test_pool(1, [test_entry(&binding)]);

        let reservation = pool.try_reserve().unwrap();
        let config = HintPoolConfig {
            pool_size: 1,
            prp_backend: binding.prp_backend,
            pool_dir: None,
        };
        assert!(claim_generation_capacity(&config, &pool.state)
            .unwrap()
            .is_none());
        assert!(reservation.restore().unwrap());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn concurrent_reservation_of_one_entry_has_exactly_one_winner() {
        let binding = test_binding(0x36);
        let pool = Arc::new(test_pool(1, [test_entry(&binding)]));
        let winners = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let start = Arc::new(std::sync::Barrier::new(32));
        let all_attempted = Arc::new(std::sync::Barrier::new(32));
        let workers: Vec<_> = (0..32)
            .map(|_| {
                let pool = Arc::clone(&pool);
                let winners = Arc::clone(&winners);
                let start = Arc::clone(&start);
                let all_attempted = Arc::clone(&all_attempted);
                std::thread::spawn(move || {
                    start.wait();
                    let reservation = pool.try_reserve();
                    if reservation.is_some() {
                        winners.fetch_add(1, AtomicOrdering::SeqCst);
                    }
                    all_attempted.wait();
                    drop(reservation);
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(winners.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(pool.len(), 1, "winner Drop must restore the reservation");
    }

    #[test]
    fn empty_pool_is_immediately_nonblocking_under_concurrency() {
        let pool = Arc::new(test_pool(1, std::iter::empty()));
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

    #[cfg(unix)]
    #[test]
    fn pool_directory_binding_marker_is_private_atomic_and_idempotent() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = TestDir::new();
        let binding = test_binding(0x71);
        prepare_pool_directory(&dir.0).unwrap();
        ensure_pool_directory_binding(&dir.0, &binding).unwrap();
        ensure_pool_directory_binding(&dir.0, &binding).unwrap();

        let marker = dir.0.join(BINDING_MARKER_FILE);
        let metadata = std::fs::symlink_metadata(&marker).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(
            std::fs::read(&marker).unwrap(),
            binding.marker_bytes().unwrap()
        );
        assert!(std::fs::read_dir(&dir.0).unwrap().flatten().all(|entry| {
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with(BINDING_MARKER_TMP_PREFIX)
        }));
    }

    #[test]
    fn concurrent_identical_binding_initialization_has_one_canonical_result() {
        let dir = TestDir::new();
        prepare_pool_directory(&dir.0).unwrap();
        let binding = test_binding(0x72);
        let start = Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let dir = dir.0.clone();
                let binding = binding.clone();
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    ensure_pool_directory_binding(&dir, &binding)
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        assert_eq!(
            std::fs::read(dir.0.join(BINDING_MARKER_FILE)).unwrap(),
            binding.marker_bytes().unwrap()
        );
    }

    #[test]
    fn mismatched_binding_fails_without_touching_ready_artifacts() {
        let dir = TestDir::new();
        let binding = test_binding(0x73);
        let ready = persist_pool_entry(&dir.0, &binding, &test_entry(&binding)).unwrap();
        let mut mismatched = binding.clone();
        mismatched.prp_backend = remote::PRP_FASTPRP;

        let error = ensure_pool_directory_binding(&dir.0, &mismatched).unwrap_err();
        assert!(error.to_string().contains("does not match"));
        assert!(ready.exists());
        assert_eq!(
            std::fs::read(dir.0.join(BINDING_MARKER_FILE)).unwrap(),
            binding.marker_bytes().unwrap()
        );
    }

    #[test]
    fn corrupt_binding_marker_fails_closed_and_is_never_replaced() {
        let dir = TestDir::new();
        let binding = test_binding(0x74);
        prepare_pool_directory(&dir.0).unwrap();
        ensure_pool_directory_binding(&dir.0, &binding).unwrap();
        let marker = dir.0.join(BINDING_MARKER_FILE);
        let original = std::fs::read(&marker).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&marker)
            .unwrap();
        file.write_all(b"partial").unwrap();
        file.sync_all().unwrap();

        assert!(ensure_pool_directory_binding(&dir.0, &binding).is_err());
        assert_eq!(std::fs::read(&marker).unwrap(), b"partial");
        assert_ne!(std::fs::read(&marker).unwrap(), original);
    }

    #[test]
    fn markerless_or_legacy_pool_state_requires_offline_migration() {
        let dir = TestDir::new();
        let binding = test_binding(0x75);
        prepare_pool_directory(&dir.0).unwrap();
        let markerless = dir.0.join("pool_42424242424242424242424242424242.hints");
        pir_private_files::write_new_private_file_v1(
            &markerless,
            b"old-state",
            "markerless pool test",
        )
        .unwrap();
        assert!(ensure_pool_directory_binding(&dir.0, &binding).is_err());
        assert!(markerless.exists());

        std::fs::remove_file(&markerless).unwrap();
        ensure_pool_directory_binding(&dir.0, &binding).unwrap();
        let legacy_tmp = dir
            .0
            .join("pool_42424242424242424242424242424242.hints.tmp");
        pir_private_files::write_new_private_file_v1(
            &legacy_tmp,
            b"old-staged-state",
            "legacy pool tmp test",
        )
        .unwrap();
        assert!(ensure_pool_directory_binding(&dir.0, &binding).is_err());
        let _capacity_lock = lock_pool_capacity(&dir.0).unwrap();
        assert!(disk_capacity_count_locked(&dir.0, None, None).is_err());
        assert!(legacy_tmp.exists());
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
