use pir_core::params::{CHUNK_PARAMS, INDEX_PARAMS};
use runtime::table::{MappedDatabase, MappedSubTable};

#[cfg(feature = "cuckoo-oram")]
use crate::unsafe_debug_log;
#[cfg(feature = "cuckoo-oram")]
use crate::unsafe_oram_detail;
#[cfg(feature = "cuckoo-oram")]
use bitcoinpir_oram::{
    circuit_meta_page_bytes, circuit_payload_page_bytes, AeadPageStore, CircuitCuckooBinReader,
    CircuitDirectChunkReader, CircuitDirectIndexReader, CircuitOram, CircuitOramState,
    CircuitStoreAuthLayout, CircuitStoreAuthState, CuckooLevel, CuckooTableInfo, DirectLevel,
    DirectOramDatasetBindingV1, DirectTableMetadata, EmbeddedTreePageStore, FilePageStore,
    FrontCachedPageStore, OramParams, PageStore, PathPageStore, Result as OramResult,
    TieredMerklePageStore, TieredMerkleState, AEAD_OVERHEAD, DIRECT_CHUNK_RECORD_SIZE,
    EMBEDDED_TREE_AUTH_BYTES_PER_PAGE,
};
#[cfg(all(feature = "cuckoo-oram", test))]
use bitcoinpir_oram::{
    CuckooPackedBlockReader, DirectChunkPackedBlockReader, DirectIndexPackedBlockReader,
    DirectTableInfo, DIRECT_INDEX_INPUT_RECORD_SIZE,
};

/// Narrow read interface for BitcoinPIR cuckoo-table rows.
///
/// The mmap implementation below preserves the current behavior exactly. The
/// shape is intentionally smaller than `MappedSubTable` so an ORAM-backed table
/// can serve the same `group_id + index` requests without exposing full group
/// slices. HarmonyPIR is the first caller because its query protocol already
/// sends explicit bin indices; a native ORAM backend can reuse the same layer.
pub(crate) trait CuckooTableAccess: Sync {
    fn bins_per_table(&self) -> usize;
    fn entry_size(&self) -> usize;
    fn group_exists(&self, group_id: usize) -> bool;
    fn append_entry(&self, group_id: usize, idx: usize, dst: &mut Vec<u8>) -> Result<(), String>;

    fn append_entries(
        &self,
        group_id: usize,
        indices: &[u32],
        zero_fill_oob: bool,
        dst: &mut Vec<u8>,
    ) -> Result<(), String> {
        for &idx in indices {
            let idx_usize = idx as usize;
            if idx_usize < self.bins_per_table() {
                self.append_entry(group_id, idx_usize, dst)?;
            } else if zero_fill_oob {
                dst.extend(std::iter::repeat_n(0u8, self.entry_size()));
            } else {
                return Err(format!("index {} out of range", idx));
            }
        }
        Ok(())
    }

    fn finish_request(&self) -> Result<(), String> {
        Ok(())
    }

    fn abort_request(&self, _reason: &str) {}
}

pub(crate) struct MmapCuckooTable<'a> {
    pub(crate) sub_table: &'a MappedSubTable,
    pub(crate) entry_size: usize,
}

impl<'a> MmapCuckooTable<'a> {
    pub(crate) const fn new(sub_table: &'a MappedSubTable, entry_size: usize) -> Self {
        Self {
            sub_table,
            entry_size,
        }
    }
}

impl CuckooTableAccess for MmapCuckooTable<'_> {
    fn bins_per_table(&self) -> usize {
        self.sub_table.bins_per_table
    }

    fn entry_size(&self) -> usize {
        self.entry_size
    }

    fn group_exists(&self, group_id: usize) -> bool {
        self.sub_table.try_group_bytes(group_id).is_some()
    }

    fn append_entry(&self, group_id: usize, idx: usize, dst: &mut Vec<u8>) -> Result<(), String> {
        let table_bytes = self
            .sub_table
            .try_group_bytes(group_id)
            .ok_or_else(|| format!("group_id {} out of range", group_id))?;
        if idx >= self.sub_table.bins_per_table {
            return Err(format!("index {} out of range", idx));
        }
        let offset = idx * self.entry_size;
        dst.extend_from_slice(&table_bytes[offset..offset + self.entry_size]);
        Ok(())
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) type CuckooRawPageStore = Box<dyn PageStore + Send>;

#[cfg(feature = "cuckoo-oram")]
pub(crate) enum CuckooOramStore {
    Plain(CuckooRawPageStore),
    Sidecar(TieredMerklePageStore<CuckooRawPageStore, CuckooRawPageStore>),
    Embedded(EmbeddedTreePageStore<CuckooRawPageStore>),
}

#[cfg(feature = "cuckoo-oram")]
impl PathPageStore for CuckooOramStore {
    fn page_size(&self) -> usize {
        match self {
            Self::Plain(store) => PageStore::page_size(&**store),
            Self::Sidecar(store) => PageStore::page_size(store),
            Self::Embedded(store) => PathPageStore::page_size(store),
        }
    }

    fn page_count(&self) -> usize {
        match self {
            Self::Plain(store) => PageStore::page_count(&**store),
            Self::Sidecar(store) => PageStore::page_count(store),
            Self::Embedded(store) => PathPageStore::page_count(store),
        }
    }

    fn read_path_pages(&mut self, path: &[usize]) -> OramResult<Vec<Vec<u8>>> {
        match self {
            Self::Plain(store) => PageStore::read_pages(&mut **store, path),
            Self::Sidecar(store) => PathPageStore::read_path_pages(store, path),
            Self::Embedded(store) => store.read_path_pages(path),
        }
    }

    fn write_path_pages(&mut self, path: &[usize], pages: &[Vec<u8>]) -> OramResult<()> {
        match self {
            Self::Plain(store) => PageStore::write_pages(&mut **store, path, pages),
            Self::Sidecar(store) => PathPageStore::write_path_pages(store, path, pages),
            Self::Embedded(store) => store.write_path_pages(path, pages),
        }
    }

    fn read_paths_pages(&mut self, paths: &[Vec<usize>]) -> OramResult<Vec<Vec<Vec<u8>>>> {
        match self {
            Self::Plain(store) => PathPageStore::read_paths_pages(&mut **store, paths),
            Self::Sidecar(store) => PathPageStore::read_paths_pages(store, paths),
            Self::Embedded(store) => PathPageStore::read_paths_pages(store, paths),
        }
    }

    fn write_paths_pages(
        &mut self,
        paths: &[Vec<usize>],
        pages: &[Vec<Vec<u8>>],
    ) -> OramResult<()> {
        match self {
            Self::Plain(store) => PathPageStore::write_paths_pages(&mut **store, paths, pages),
            Self::Sidecar(store) => PathPageStore::write_paths_pages(store, paths, pages),
            Self::Embedded(store) => PathPageStore::write_paths_pages(store, paths, pages),
        }
    }

    fn flush(&mut self) -> OramResult<()> {
        match self {
            Self::Plain(store) => PageStore::flush(&mut **store),
            Self::Sidecar(store) => PageStore::flush(store),
            Self::Embedded(store) => PathPageStore::flush(store),
        }
    }

    fn tiered_merkle_state(&self) -> Option<TieredMerkleState> {
        match self {
            Self::Plain(store) => PageStore::tiered_merkle_state(&**store),
            Self::Sidecar(store) => Some(store.trusted_state()),
            Self::Embedded(_) => None,
        }
    }

    fn embedded_tree_state(&self) -> Option<bitcoinpir_oram::EmbeddedTreeState> {
        match self {
            Self::Embedded(store) => Some(store.state()),
            Self::Plain(_) | Self::Sidecar(_) => None,
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) type CuckooOramBinReader = CircuitCuckooBinReader<CuckooOramStore, CuckooOramStore>;

#[cfg(feature = "cuckoo-oram")]
pub(crate) struct CuckooOramTable {
    pub(crate) reader: std::sync::Mutex<CuckooOramBinReader>,
    pub(crate) poisoned: std::sync::Mutex<Option<String>>,
    pub(crate) dirty: std::sync::atomic::AtomicBool,
    pub(crate) level: CuckooLevel,
    pub(crate) k: usize,
    pub(crate) bins_per_table: usize,
    pub(crate) entry_size: usize,
    pub(crate) state_path: PathBuf,
    pub(crate) auth_state_path: Option<PathBuf>,
    pub(crate) state_key: Option<[u8; 32]>,
    pub(crate) drain_per_access: u64,
    pub(crate) save_state: bool,
}

#[cfg(feature = "cuckoo-oram")]
impl CuckooOramTable {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        db_dir: &std::path::Path,
        oram_dir: &std::path::Path,
        level: CuckooLevel,
        pack: usize,
        drain_per_access: u64,
        encrypted: bool,
        key_hex: Option<&str>,
        state_key_hex: Option<&str>,
        cache_levels: usize,
        auth_store: bool,
        save_state: bool,
    ) -> Result<Self, String> {
        if pack == 0 {
            return Err("--cuckoo-oram-pack must be > 0".into());
        }
        let table = CuckooTableInfo::from_file(level, db_dir.join(level.filename()))
            .map_err(|e| e.to_string())?;
        let paths = CuckooOramPaths::new(oram_dir, level);
        let state_key = parse_optional_32_hex(state_key_hex)?;
        let loaded = match state_key {
            Some(key) => {
                CircuitOramState::load_encrypted(&paths.state, key).map_err(|e| e.to_string())?
            }
            None => CircuitOramState::load(&paths.state).map_err(|e| e.to_string())?,
        };
        let bound_auth = loaded.auth.clone();
        let params = loaded.params.clone();
        let cached_pages = cached_pages_for_oram_levels(&params, cache_levels)?;
        let (meta_store, payload_store) = open_existing_circuit_oram_stores(
            &paths,
            level,
            &params,
            encrypted,
            key_hex,
            cached_pages,
            auth_store,
            bound_auth.as_ref(),
            state_key,
        )?;
        let oram = CircuitOram::from_state(meta_store, payload_store, loaded)
            .map_err(|e| e.to_string())?;
        let reader = CircuitCuckooBinReader::new(&table, pack, oram).map_err(|e| e.to_string())?;

        println!(
            "  Cuckoo ORAM {}: dir={}, pack={}, bins={}, bin_size={}, logical_blocks={}, cache_levels={}, auth_store={}, save_state={}",
            level,
            oram_dir.display(),
            pack,
            table.total_bins(),
            table.bin_size(),
            reader.oram().params().logical_blocks,
            cache_levels,
            auth_store,
            save_state,
        );

        Ok(Self {
            reader: std::sync::Mutex::new(reader),
            poisoned: std::sync::Mutex::new(None),
            dirty: std::sync::atomic::AtomicBool::new(false),
            level,
            k: table.k,
            bins_per_table: table.bins_per_table,
            entry_size: table.bin_size(),
            state_path: paths.state,
            auth_state_path: auth_store.then_some(paths.auth_state),
            state_key,
            drain_per_access,
            save_state,
        })
    }

    pub(crate) fn check_not_poisoned(&self) -> Result<(), String> {
        let poisoned = self
            .poisoned
            .lock()
            .map_err(|_| format!("Cuckoo ORAM {} poison mutex poisoned", self.level))?;
        if let Some(reason) = poisoned.as_ref() {
            Err(format!(
                "Cuckoo ORAM {} table is poisoned: {}",
                self.level, reason
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) fn poison(
        &self,
        coarse_reason: &'static str,
        unsafe_detail: Option<String>,
    ) -> String {
        eprintln!(
            "Cuckoo ORAM {} table poisoned: {}",
            self.level, coarse_reason
        );
        if let Some(detail) = unsafe_detail.as_ref() {
            unsafe_debug_log!("Cuckoo ORAM {} poison detail: {}", self.level, detail);
        }
        let retained_reason = unsafe_detail.unwrap_or_else(|| coarse_reason.to_string());
        if let Ok(mut poisoned) = self.poisoned.lock() {
            if poisoned.is_none() {
                *poisoned = Some(retained_reason.clone());
            }
        }
        retained_reason
    }

    pub(crate) fn poison_after_dirty(
        &self,
        coarse_reason: &'static str,
        unsafe_detail: Option<String>,
    ) {
        if self.dirty.load(std::sync::atomic::Ordering::SeqCst) {
            self.poison(coarse_reason, unsafe_detail);
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
impl CuckooTableAccess for CuckooOramTable {
    fn bins_per_table(&self) -> usize {
        self.bins_per_table
    }

    fn entry_size(&self) -> usize {
        self.entry_size
    }

    fn group_exists(&self, group_id: usize) -> bool {
        group_id < self.k
    }

    fn append_entry(&self, group_id: usize, idx: usize, dst: &mut Vec<u8>) -> Result<(), String> {
        self.append_entries(group_id, &[idx as u32], false, dst)
    }

    fn append_entries(
        &self,
        group_id: usize,
        indices: &[u32],
        zero_fill_oob: bool,
        dst: &mut Vec<u8>,
    ) -> Result<(), String> {
        self.check_not_poisoned()?;
        if !self.group_exists(group_id) {
            return Err(format!("group_id {} out of range", group_id));
        }
        for &idx in indices {
            let idx_usize = idx as usize;
            if idx_usize >= self.bins_per_table && !zero_fill_oob {
                return Err(format!("index {} out of range", idx));
            }
        }

        let mut reader = self
            .reader
            .lock()
            .map_err(|_| "Cuckoo ORAM reader mutex poisoned".to_string())?;
        for &idx in indices {
            let idx_usize = idx as usize;
            if idx_usize >= self.bins_per_table {
                dst.extend(std::iter::repeat_n(0u8, self.entry_size));
                continue;
            }
            let bin_id = group_id
                .checked_mul(self.bins_per_table)
                .and_then(|base| base.checked_add(idx_usize))
                .ok_or_else(|| "global ORAM bin id overflow".to_string())?;
            self.dirty.store(true, std::sync::atomic::Ordering::SeqCst);
            let got = match reader.read_bin(bin_id, self.drain_per_access) {
                Ok(got) => got,
                Err(_error) => {
                    let msg = self.poison(
                        "Cuckoo ORAM read failed after mutation",
                        unsafe_oram_detail!(
                            "ORAM bin {} read failed after mutation: {}",
                            bin_id,
                            _error
                        ),
                    );
                    return Err(msg);
                }
            };
            if got.payload.len() != self.entry_size {
                let msg = self.poison(
                    "Cuckoo ORAM read returned an invalid payload length",
                    unsafe_oram_detail!(
                        "ORAM bin {} returned {} bytes, expected {}",
                        bin_id,
                        got.payload.len(),
                        self.entry_size
                    ),
                );
                return Err(msg);
            }
            dst.extend_from_slice(&got.payload);
        }
        Ok(())
    }

    fn finish_request(&self) -> Result<(), String> {
        self.check_not_poisoned()?;
        if !self.dirty.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        if !self.save_state {
            self.dirty.store(false, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| "Cuckoo ORAM reader mutex poisoned".to_string())?;
        if let Err(_error) = reader.oram_mut().flush() {
            drop(reader);
            let msg = self.poison(
                "Cuckoo ORAM flush failed after mutation",
                unsafe_oram_detail!("ORAM flush failed after mutation: {}", _error),
            );
            return Err(msg);
        }
        let snapshot = reader.oram().snapshot();
        let auth_snapshot = match self.auth_state_path.as_ref() {
            Some(_) => match reader.oram().store_auth_state() {
                Some(state) => Some(state),
                None => {
                    drop(reader);
                    let msg = self.poison(
                        "Cuckoo ORAM auth-store state unavailable after mutation",
                        None,
                    );
                    return Err(msg);
                }
            },
            None => None,
        };
        drop(reader);
        let saved = match self.state_key {
            Some(key) => snapshot
                .save_encrypted_atomic(&self.state_path, key)
                .map_err(|e| e.to_string()),
            None => snapshot
                .save_atomic(&self.state_path)
                .map_err(|e| e.to_string()),
        };
        if let Err(_error) = saved {
            let msg = self.poison(
                "Cuckoo ORAM state save failed after mutation",
                unsafe_oram_detail!("ORAM state save failed after mutation: {}", _error),
            );
            return Err(msg);
        }
        if let (Some(path), Some(auth_snapshot)) =
            (self.auth_state_path.as_ref(), auth_snapshot.as_ref())
        {
            if let Err(_error) = save_circuit_store_auth(auth_snapshot, path, self.state_key) {
                let msg = self.poison(
                    "Cuckoo ORAM auth-state save failed after mutation",
                    unsafe_oram_detail!("ORAM auth state save failed after mutation: {}", _error),
                );
                return Err(msg);
            }
        }
        self.dirty.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn abort_request(&self, _reason: &str) {
        self.poison_after_dirty(
            "Cuckoo ORAM request aborted after mutation",
            unsafe_oram_detail!("request aborted after ORAM mutation: {}", _reason),
        );
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) struct CuckooOramTables {
    pub(crate) index: CuckooOramTable,
    pub(crate) chunk: CuckooOramTable,
    /// Serializes the complete legacy lookup transaction for this database,
    /// including both table mutations and both controller/auth-state commits.
    pub(crate) request_transaction: std::sync::Mutex<()>,
}

#[cfg(feature = "cuckoo-oram")]
impl CuckooOramTables {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        db_dir: &std::path::Path,
        oram_dir: &std::path::Path,
        pack: usize,
        drain_per_access: u64,
        encrypted: bool,
        key_hex: Option<&str>,
        state_key_hex: Option<&str>,
        cache_levels: usize,
        auth_store: bool,
        save_state: bool,
    ) -> Result<Self, String> {
        Ok(Self {
            index: CuckooOramTable::open(
                db_dir,
                oram_dir,
                CuckooLevel::Index,
                pack,
                drain_per_access,
                encrypted,
                key_hex,
                state_key_hex,
                cache_levels,
                auth_store,
                save_state,
            )?,
            chunk: CuckooOramTable::open(
                db_dir,
                oram_dir,
                CuckooLevel::Chunk,
                pack,
                drain_per_access,
                encrypted,
                key_hex,
                state_key_hex,
                cache_levels,
                auth_store,
                save_state,
            )?,
            request_transaction: std::sync::Mutex::new(()),
        })
    }

    pub(crate) fn lookup_batch(
        &self,
        config: CuckooNativeLookupConfig,
        script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
    ) -> Result<Vec<CuckooNativeLookupResult>, String> {
        let _transaction = self.request_transaction.lock().map_err(|_| {
            "Cuckoo ORAM request transaction mutex poisoned; refusing further mutations".to_string()
        })?;
        self.index.check_not_poisoned()?;
        self.chunk.check_not_poisoned()?;
        cuckoo_native_lookup_batch_from_tables(&self.index, &self.chunk, config, script_hashes)
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) type DirectOramIndexReader = CircuitDirectIndexReader<CuckooOramStore, CuckooOramStore>;

#[cfg(feature = "cuckoo-oram")]
pub(crate) type DirectOramChunkReader = CircuitDirectChunkReader<CuckooOramStore, CuckooOramStore>;

#[cfg(feature = "cuckoo-oram")]
pub(crate) struct DirectOramIndexTable {
    pub(crate) reader: std::sync::Mutex<DirectOramIndexReader>,
    pub(crate) poisoned: std::sync::Mutex<Option<String>>,
    pub(crate) dirty: std::sync::atomic::AtomicBool,
    pub(crate) hash_fns: usize,
    pub(crate) metadata: DirectTableMetadata,
    pub(crate) state_path: PathBuf,
    pub(crate) auth_state_path: Option<PathBuf>,
    pub(crate) state_key: Option<[u8; 32]>,
    pub(crate) drain_per_access: u64,
    pub(crate) save_state: bool,
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) struct DirectOramChunkTable {
    pub(crate) reader: std::sync::Mutex<DirectOramChunkReader>,
    pub(crate) poisoned: std::sync::Mutex<Option<String>>,
    pub(crate) dirty: std::sync::atomic::AtomicBool,
    pub(crate) total_chunks: usize,
    pub(crate) metadata: DirectTableMetadata,
    pub(crate) state_path: PathBuf,
    pub(crate) auth_state_path: Option<PathBuf>,
    pub(crate) state_key: Option<[u8; 32]>,
    pub(crate) drain_per_access: u64,
    pub(crate) save_state: bool,
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) struct DirectOramTables {
    pub(crate) index: DirectOramIndexTable,
    pub(crate) chunk: DirectOramChunkTable,
    pub(crate) access_budget: usize,
    /// Serializes the complete mutating lookup transaction for this database.
    ///
    /// The index and chunk reader mutexes only protect individual in-memory
    /// ORAM operations.  A request also flushes both readers and atomically
    /// replaces their controller/auth-state files, whose save helpers use
    /// fixed `.tmp` paths.  Without this outer per-DB mutex, two requests can
    /// interleave those phases and race the same temp files (or persist an
    /// index state from one request with a chunk state from another).
    pub(crate) request_transaction: std::sync::Mutex<()>,
}

#[cfg(feature = "cuckoo-oram")]
impl DirectOramTables {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        oram_dir: &std::path::Path,
        drain_per_access: u64,
        access_budget: usize,
        encrypted: bool,
        key_hex: Option<&str>,
        state_key_hex: Option<&str>,
        cache_levels: usize,
        auth_store: bool,
        save_state: bool,
    ) -> Result<Self, String> {
        Self::open_with_trusted_state(
            oram_dir,
            None,
            drain_per_access,
            access_budget,
            encrypted,
            key_hex,
            state_key_hex,
            cache_levels,
            auth_store,
            save_state,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_with_trusted_state(
        oram_dir: &std::path::Path,
        trusted_state_dir: Option<&std::path::Path>,
        drain_per_access: u64,
        access_budget: usize,
        encrypted: bool,
        key_hex: Option<&str>,
        state_key_hex: Option<&str>,
        cache_levels: usize,
        auth_store: bool,
        save_state: bool,
    ) -> Result<Self, String> {
        if access_budget == 0 {
            return Err("--direct-oram-access-budget must be > 0".into());
        }
        Ok(Self {
            index: DirectOramIndexTable::open(
                oram_dir,
                trusted_state_dir,
                drain_per_access,
                encrypted,
                key_hex,
                state_key_hex,
                cache_levels,
                auth_store,
                save_state,
            )?,
            chunk: DirectOramChunkTable::open(
                oram_dir,
                trusted_state_dir,
                drain_per_access,
                encrypted,
                key_hex,
                state_key_hex,
                cache_levels,
                auth_store,
                save_state,
            )?,
            access_budget,
            request_transaction: std::sync::Mutex::new(()),
        })
    }

    pub(crate) fn lookup_batch(
        &self,
        script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
        slot_present: &[bool],
    ) -> Result<Vec<DirectNativeLookupResult>, String> {
        direct_native_lookup_slots(self, script_hashes, slot_present)
    }

    pub(crate) fn validate_dataset_binding(&self, database: &MappedDatabase) -> Result<(), String> {
        let manifest_root = database.manifest_root.ok_or_else(|| {
            "production Direct ORAM requires an exact verified server DB manifest root".to_owned()
        })?;
        let direct = database
            .manifest
            .as_ref()
            .and_then(|manifest| manifest.direct_oram.as_ref())
            .ok_or_else(|| {
                "production Direct ORAM requires typed [direct_oram] data in MANIFEST.toml"
                    .to_owned()
            })?
            .validate()
            .map_err(|error| error.to_string())?;
        let expected = DirectOramDatasetBindingV1 {
            server_db_manifest_sha256: manifest_root,
            index_sha256: direct.index_sha256,
            index_bytes: direct.index_bytes,
            index_records: direct.index_records,
            chunk_sha256: direct.chunk_sha256,
            chunk_bytes: direct.chunk_bytes,
            chunk_records: direct.chunk_records,
            index_slots_per_bin: direct.index_slots_per_bin,
            index_hash_fns: direct.index_hash_fns,
            index_load_factor_ppb: direct.index_load_factor_ppb,
            index_seed: direct.index_seed,
        };
        expected.validate().map_err(|error| error.to_string())?;
        let index = *self
            .index
            .metadata
            .require_dataset_binding()
            .map_err(|error| error.to_string())?;
        let chunk = *self
            .chunk
            .metadata
            .require_dataset_binding()
            .map_err(|error| error.to_string())?;
        if index != chunk {
            return Err(
                "Direct ORAM INDEX and CHUNK metadata have different dataset bindings".into(),
            );
        }
        if index != expected || index.digest() != expected.digest() {
            return Err(format!(
                "Direct ORAM metadata does not match verified DB manifest binding {}",
                hex::encode(expected.digest())
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "cuckoo-oram")]
impl DirectOramIndexTable {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        oram_dir: &std::path::Path,
        trusted_state_dir: Option<&std::path::Path>,
        drain_per_access: u64,
        encrypted: bool,
        key_hex: Option<&str>,
        state_key_hex: Option<&str>,
        cache_levels: usize,
        auth_store: bool,
        save_state: bool,
    ) -> Result<Self, String> {
        let paths = DirectOramPaths::new_with_trusted_state(
            oram_dir,
            trusted_state_dir,
            DirectLevel::Index,
        );
        let metadata = DirectTableMetadata::load(&paths.metadata).map_err(|e| e.to_string())?;
        if metadata.level != DirectLevel::Index {
            return Err(format!(
                "direct index metadata {} has level {}",
                paths.metadata.display(),
                metadata.level
            ));
        }
        let state_key = parse_optional_32_hex(state_key_hex)?;
        let loaded = load_circuit_oram_state(&paths.state, state_key)?;
        let bound_auth = loaded.auth.clone();
        let params = loaded.params.clone();
        let cached_pages = cached_pages_for_oram_levels(&params, cache_levels)?;
        let (meta_store, payload_store) = open_existing_direct_oram_stores(
            &paths,
            DirectLevel::Index,
            &params,
            encrypted,
            key_hex,
            cached_pages,
            auth_store,
            bound_auth.as_ref(),
            state_key,
        )?;
        let oram = CircuitOram::from_state(meta_store, payload_store, loaded)
            .map_err(|e| e.to_string())?;
        let reader =
            CircuitDirectIndexReader::new(metadata.clone(), oram).map_err(|e| e.to_string())?;

        println!(
            "  Direct ORAM index: dir={}, items={}, pack={}, logical_blocks={}, hash_fns={}, cache_levels={}, auth_store={}, save_state={}",
            oram_dir.display(),
            metadata.total_items,
            metadata.items_per_block,
            reader.oram().params().logical_blocks,
            metadata.hash_fns,
            cache_levels,
            auth_store,
            save_state,
        );

        Ok(Self {
            reader: std::sync::Mutex::new(reader),
            poisoned: std::sync::Mutex::new(None),
            dirty: std::sync::atomic::AtomicBool::new(false),
            hash_fns: metadata.hash_fns,
            metadata,
            state_path: paths.state,
            auth_state_path: auth_store.then_some(paths.auth_state),
            state_key,
            drain_per_access,
            save_state,
        })
    }

    pub(crate) fn lookup_many(
        &self,
        script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
    ) -> Result<Vec<bitcoinpir_oram::DirectIndexLookup>, String> {
        if script_hashes.is_empty() {
            return Ok(Vec::new());
        }
        self.check_not_poisoned()?;
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| "Direct ORAM index reader mutex poisoned".to_string())?;
        self.dirty.store(true, std::sync::atomic::Ordering::SeqCst);
        match reader.lookup_many_batched(script_hashes, self.drain_per_access) {
            Ok(got) => Ok(got.lookups),
            Err(_error) => {
                let msg = self.poison(
                    "Direct ORAM index lookup failed after mutation",
                    unsafe_oram_detail!(
                        "Direct ORAM index batch lookup failed after mutation: {}",
                        _error
                    ),
                );
                Err(msg)
            }
        }
    }

    pub(crate) fn finish_request(&self) -> Result<(), String> {
        finish_direct_oram_request(
            "index",
            &self.reader,
            &self.dirty,
            &self.poisoned,
            &self.state_path,
            self.auth_state_path.as_deref(),
            self.state_key,
            self.save_state,
        )
    }

    pub(crate) fn abort_request(&self, _reason: &str) {
        self.poison_after_dirty(
            "Direct ORAM index request aborted after mutation",
            unsafe_oram_detail!("request aborted after direct index mutation: {}", _reason),
        );
    }

    pub(crate) fn check_not_poisoned(&self) -> Result<(), String> {
        check_direct_poisoned("index", &self.poisoned)
    }

    pub(crate) fn poison(
        &self,
        coarse_reason: &'static str,
        unsafe_detail: Option<String>,
    ) -> String {
        poison_direct("index", &self.poisoned, coarse_reason, unsafe_detail)
    }

    pub(crate) fn poison_after_dirty(
        &self,
        coarse_reason: &'static str,
        unsafe_detail: Option<String>,
    ) {
        if self.dirty.load(std::sync::atomic::Ordering::SeqCst) {
            self.poison(coarse_reason, unsafe_detail);
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
impl DirectOramChunkTable {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        oram_dir: &std::path::Path,
        trusted_state_dir: Option<&std::path::Path>,
        drain_per_access: u64,
        encrypted: bool,
        key_hex: Option<&str>,
        state_key_hex: Option<&str>,
        cache_levels: usize,
        auth_store: bool,
        save_state: bool,
    ) -> Result<Self, String> {
        let paths = DirectOramPaths::new_with_trusted_state(
            oram_dir,
            trusted_state_dir,
            DirectLevel::Chunk,
        );
        let metadata = DirectTableMetadata::load(&paths.metadata).map_err(|e| e.to_string())?;
        if metadata.level != DirectLevel::Chunk {
            return Err(format!(
                "direct chunk metadata {} has level {}",
                paths.metadata.display(),
                metadata.level
            ));
        }
        let state_key = parse_optional_32_hex(state_key_hex)?;
        let loaded = load_circuit_oram_state(&paths.state, state_key)?;
        let bound_auth = loaded.auth.clone();
        let params = loaded.params.clone();
        let cached_pages = cached_pages_for_oram_levels(&params, cache_levels)?;
        let (meta_store, payload_store) = open_existing_direct_oram_stores(
            &paths,
            DirectLevel::Chunk,
            &params,
            encrypted,
            key_hex,
            cached_pages,
            auth_store,
            bound_auth.as_ref(),
            state_key,
        )?;
        let oram = CircuitOram::from_state(meta_store, payload_store, loaded)
            .map_err(|e| e.to_string())?;
        let reader =
            CircuitDirectChunkReader::new(metadata.clone(), oram).map_err(|e| e.to_string())?;

        println!(
            "  Direct ORAM chunk: dir={}, chunks={}, pack={}, logical_blocks={}, cache_levels={}, auth_store={}, save_state={}",
            oram_dir.display(),
            metadata.total_items,
            metadata.items_per_block,
            reader.oram().params().logical_blocks,
            cache_levels,
            auth_store,
            save_state,
        );

        Ok(Self {
            reader: std::sync::Mutex::new(reader),
            poisoned: std::sync::Mutex::new(None),
            dirty: std::sync::atomic::AtomicBool::new(false),
            total_chunks: metadata.total_items,
            metadata,
            state_path: paths.state,
            auth_state_path: auth_store.then_some(paths.auth_state),
            state_key,
            drain_per_access,
            save_state,
        })
    }

    pub(crate) fn read_chunks(&self, chunk_ids: &[usize]) -> Result<Vec<Vec<u8>>, String> {
        if chunk_ids.is_empty() {
            return Ok(Vec::new());
        }
        self.check_not_poisoned()?;
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| "Direct ORAM chunk reader mutex poisoned".to_string())?;
        self.dirty.store(true, std::sync::atomic::Ordering::SeqCst);
        let got = match reader.read_chunks(chunk_ids, self.drain_per_access) {
            Ok(got) => got,
            Err(_error) => {
                let msg = self.poison(
                    "Direct ORAM chunk read failed after mutation",
                    unsafe_oram_detail!(
                        "Direct ORAM chunk batch read failed after mutation: {}",
                        _error
                    ),
                );
                return Err(msg);
            }
        };

        let mut payloads = Vec::with_capacity(got.reads.len());
        for read in got.reads {
            if read.payload.len() != DIRECT_CHUNK_RECORD_SIZE {
                let msg = self.poison(
                    "Direct ORAM chunk read returned an invalid payload length",
                    unsafe_oram_detail!(
                        "Direct ORAM chunk {} returned {} bytes, expected {}",
                        read.chunk_id,
                        read.payload.len(),
                        DIRECT_CHUNK_RECORD_SIZE
                    ),
                );
                return Err(msg);
            }
            payloads.push(read.payload);
        }
        Ok(payloads)
    }

    pub(crate) fn read_dummy_many(&self, count: usize) -> Result<(), String> {
        if count == 0 {
            return Ok(());
        }
        if self.total_chunks == 0 {
            return Err("direct ORAM chunk table is empty; cannot issue dummy read".into());
        }
        self.check_not_poisoned()?;
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| "Direct ORAM chunk reader mutex poisoned".to_string())?;
        self.dirty.store(true, std::sync::atomic::Ordering::SeqCst);
        match reader.read_dummy_many(count, self.drain_per_access) {
            Ok(_) => Ok(()),
            Err(_error) => {
                let msg = self.poison(
                    "Direct ORAM dummy chunk read failed after mutation",
                    unsafe_oram_detail!(
                        "Direct ORAM chunk dummy batch read failed after mutation: {}",
                        _error
                    ),
                );
                Err(msg)
            }
        }
    }

    pub(crate) fn finish_request(&self) -> Result<(), String> {
        finish_direct_oram_request(
            "chunk",
            &self.reader,
            &self.dirty,
            &self.poisoned,
            &self.state_path,
            self.auth_state_path.as_deref(),
            self.state_key,
            self.save_state,
        )
    }

    pub(crate) fn abort_request(&self, _reason: &str) {
        self.poison_after_dirty(
            "Direct ORAM chunk request aborted after mutation",
            unsafe_oram_detail!("request aborted after direct chunk mutation: {}", _reason),
        );
    }

    pub(crate) fn check_not_poisoned(&self) -> Result<(), String> {
        check_direct_poisoned("chunk", &self.poisoned)
    }

    pub(crate) fn poison(
        &self,
        coarse_reason: &'static str,
        unsafe_detail: Option<String>,
    ) -> String {
        poison_direct("chunk", &self.poisoned, coarse_reason, unsafe_detail)
    }

    pub(crate) fn poison_after_dirty(
        &self,
        coarse_reason: &'static str,
        unsafe_detail: Option<String>,
    ) {
        if self.dirty.load(std::sync::atomic::Ordering::SeqCst) {
            self.poison(coarse_reason, unsafe_detail);
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) trait DirectReaderState {
    fn flush_oram(&mut self) -> Result<(), String>;
    fn snapshot_oram(&self) -> CircuitOramState;
    fn auth_state(&self) -> Option<CircuitStoreAuthState>;
}

#[cfg(feature = "cuckoo-oram")]
impl DirectReaderState for DirectOramIndexReader {
    fn flush_oram(&mut self) -> Result<(), String> {
        self.oram_mut().flush().map_err(|e| e.to_string())
    }

    fn snapshot_oram(&self) -> CircuitOramState {
        self.oram().snapshot()
    }

    fn auth_state(&self) -> Option<CircuitStoreAuthState> {
        self.oram().store_auth_state()
    }
}

#[cfg(feature = "cuckoo-oram")]
impl DirectReaderState for DirectOramChunkReader {
    fn flush_oram(&mut self) -> Result<(), String> {
        self.oram_mut().flush().map_err(|e| e.to_string())
    }

    fn snapshot_oram(&self) -> CircuitOramState {
        self.oram().snapshot()
    }

    fn auth_state(&self) -> Option<CircuitStoreAuthState> {
        self.oram().store_auth_state()
    }
}

#[cfg(feature = "cuckoo-oram")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_direct_oram_request<R: DirectReaderState>(
    label: &str,
    reader: &std::sync::Mutex<R>,
    dirty: &std::sync::atomic::AtomicBool,
    poisoned: &std::sync::Mutex<Option<String>>,
    state_path: &std::path::Path,
    auth_state_path: Option<&std::path::Path>,
    state_key: Option<[u8; 32]>,
    save_state: bool,
) -> Result<(), String> {
    check_direct_poisoned(label, poisoned)?;
    if !dirty.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }
    if !save_state {
        dirty.store(false, std::sync::atomic::Ordering::SeqCst);
        return Ok(());
    }

    let mut reader = reader
        .lock()
        .map_err(|_| format!("Direct ORAM {label} reader mutex poisoned"))?;
    if let Err(_error) = reader.flush_oram() {
        drop(reader);
        let msg = poison_direct(
            label,
            poisoned,
            "Direct ORAM flush failed after mutation",
            unsafe_oram_detail!("Direct ORAM {label} flush failed after mutation: {_error}"),
        );
        return Err(msg);
    }
    let snapshot = reader.snapshot_oram();
    let auth_snapshot = match auth_state_path {
        Some(_) => match reader.auth_state() {
            Some(state) => Some(state),
            None => {
                drop(reader);
                let msg = poison_direct(
                    label,
                    poisoned,
                    "Direct ORAM auth-store state unavailable after mutation",
                    unsafe_oram_detail!(
                        "Direct ORAM {label} auth-store state unavailable after mutation"
                    ),
                );
                return Err(msg);
            }
        },
        None => None,
    };
    drop(reader);

    if let Err(_error) = save_circuit_oram_state(&snapshot, state_path, state_key) {
        let msg = poison_direct(
            label,
            poisoned,
            "Direct ORAM state save failed after mutation",
            unsafe_oram_detail!("Direct ORAM {label} state save failed after mutation: {_error}"),
        );
        return Err(msg);
    }
    if let (Some(path), Some(auth_snapshot)) = (auth_state_path, auth_snapshot.as_ref()) {
        if let Err(_error) = save_circuit_store_auth(auth_snapshot, path, state_key) {
            let msg = poison_direct(
                label,
                poisoned,
                "Direct ORAM auth-state save failed after mutation",
                unsafe_oram_detail!(
                    "Direct ORAM {label} auth state save failed after mutation: {_error}"
                ),
            );
            return Err(msg);
        }
    }
    dirty.store(false, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn check_direct_poisoned(
    label: &str,
    poisoned: &std::sync::Mutex<Option<String>>,
) -> Result<(), String> {
    let poisoned = poisoned
        .lock()
        .map_err(|_| format!("Direct ORAM {label} poison mutex poisoned"))?;
    if let Some(reason) = poisoned.as_ref() {
        Err(format!("Direct ORAM {label} table is poisoned: {reason}"))
    } else {
        Ok(())
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn poison_direct(
    label: &str,
    poisoned: &std::sync::Mutex<Option<String>>,
    coarse_reason: &'static str,
    unsafe_detail: Option<String>,
) -> String {
    eprintln!("Direct ORAM {label} table poisoned: {coarse_reason}");
    if let Some(detail) = unsafe_detail.as_ref() {
        unsafe_debug_log!("Direct ORAM {label} poison detail: {detail}");
    }
    let retained_reason = unsafe_detail.unwrap_or_else(|| coarse_reason.to_string());
    if let Ok(mut poisoned) = poisoned.lock() {
        if poisoned.is_none() {
            *poisoned = Some(retained_reason.clone());
        }
    }
    retained_reason
}

#[cfg(feature = "cuckoo-oram")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectNativeLookupResult {
    pub(crate) found: bool,
    pub(crate) whale: bool,
    pub(crate) start_chunk_id: Option<u32>,
    pub(crate) num_chunks: u8,
    pub(crate) raw_chunk_data: Vec<u8>,
}

#[cfg(feature = "cuckoo-oram")]
#[cfg(test)]
pub(crate) fn direct_native_lookup_batch(
    tables: &DirectOramTables,
    script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
) -> Result<Vec<DirectNativeLookupResult>, String> {
    let slot_present = vec![true; script_hashes.len()];
    tables.lookup_batch(script_hashes, &slot_present)
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn direct_native_lookup_slots(
    tables: &DirectOramTables,
    script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
    slot_present: &[bool],
) -> Result<Vec<DirectNativeLookupResult>, String> {
    let _transaction = tables.request_transaction.lock().map_err(|_| {
        "Direct ORAM request transaction mutex poisoned; refusing further mutations".to_string()
    })?;
    if slot_present.len() != script_hashes.len() {
        return Err(format!(
            "direct ORAM slot-present length {} does not match script hash count {}",
            slot_present.len(),
            script_hashes.len(),
        ));
    }
    let index_budget = tables
        .index
        .hash_fns
        .checked_mul(script_hashes.len())
        .ok_or_else(|| "direct ORAM index budget overflow".to_string())?;
    if index_budget > tables.access_budget {
        return Err(format!(
            "direct ORAM access budget {} too small for {} script hashes and {} index reads each",
            tables.access_budget,
            script_hashes.len(),
            tables.index.hash_fns,
        ));
    }
    let chunk_budget = tables.access_budget - index_budget;

    // Fail before mutating either half if a prior request already made the
    // paired database unusable. The transaction lock keeps this preflight
    // valid until both tables have committed or the request fails closed.
    tables.index.check_not_poisoned()?;
    tables.chunk.check_not_poisoned()?;

    let lookups = match tables.index.lookup_many(script_hashes) {
        Ok(batch) => {
            if batch.len() != script_hashes.len() {
                let msg = format!(
                    "direct ORAM index batch returned {} lookup(s), expected {}",
                    batch.len(),
                    script_hashes.len()
                );
                tables.index.abort_request(&msg);
                tables.chunk.abort_request(&msg);
                return Err(msg);
            }
            batch
        }
        Err(e) => {
            tables.index.abort_request(&e);
            tables.chunk.abort_request(&e);
            return Err(e);
        }
    };

    let mut chunk_plan: Vec<(usize, u32)> = Vec::new();
    let mut out = Vec::with_capacity(lookups.len());
    for (lookup, present) in lookups.iter().zip(slot_present) {
        if !*present {
            out.push(DirectNativeLookupResult {
                found: false,
                whale: false,
                start_chunk_id: None,
                num_chunks: 0,
                raw_chunk_data: Vec::new(),
            });
            continue;
        }

        let found = lookup.found;
        let whale = found && lookup.num_chunks == 0;
        if found && lookup.num_chunks > 0 {
            let end = match lookup.start_chunk_id.checked_add(lookup.num_chunks as u32) {
                Some(end) => end,
                None => {
                    let msg = "direct INDEX entry chunk range overflows u32".to_string();
                    tables.index.abort_request(&msg);
                    tables.chunk.abort_request(&msg);
                    return Err(msg);
                }
            };
            for chunk_id in lookup.start_chunk_id..end {
                chunk_plan.push((out.len(), chunk_id));
            }
        }
        out.push(DirectNativeLookupResult {
            found,
            whale,
            start_chunk_id: found.then_some(lookup.start_chunk_id),
            num_chunks: lookup.num_chunks,
            raw_chunk_data: Vec::new(),
        });
    }

    if chunk_plan.len() > chunk_budget {
        if let Err(e) = tables.chunk.read_dummy_many(chunk_budget) {
            tables.index.abort_request(&e);
            tables.chunk.abort_request(&e);
            return Err(e);
        }
        let msg = format!(
            "direct ORAM chunk demand {} exceeds remaining access budget {}",
            chunk_plan.len(),
            chunk_budget,
        );
        if let Err(e) = tables.index.finish_request() {
            tables.chunk.abort_request(&e);
            return Err(e);
        }
        tables.chunk.finish_request()?;
        return Err(msg);
    }

    let real_reads = chunk_plan.len();
    let chunk_ids = chunk_plan
        .iter()
        .map(|(_, chunk_id)| *chunk_id as usize)
        .collect::<Vec<_>>();
    let payloads = match tables.chunk.read_chunks(&chunk_ids) {
        Ok(payloads) => payloads,
        Err(e) => {
            tables.index.abort_request(&e);
            tables.chunk.abort_request(&e);
            return Err(e);
        }
    };
    for ((result_idx, _), payload) in chunk_plan.iter().zip(payloads) {
        out[*result_idx].raw_chunk_data.extend_from_slice(&payload);
    }
    if let Err(e) = tables.chunk.read_dummy_many(chunk_budget - real_reads) {
        tables.index.abort_request(&e);
        tables.chunk.abort_request(&e);
        return Err(e);
    }

    if let Err(e) = tables.index.finish_request() {
        tables.chunk.abort_request(&e);
        return Err(e);
    }
    tables.chunk.finish_request()?;
    Ok(out)
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn direct_oram_response_padding_bytes(
    access_budget: usize,
    slots: usize,
    hash_fns: usize,
    actual_chunk_bytes: usize,
) -> Result<usize, String> {
    let index_budget = hash_fns
        .checked_mul(slots)
        .ok_or_else(|| "direct ORAM response index budget overflow".to_string())?;
    if index_budget > access_budget {
        return Err(format!(
            "direct ORAM access budget {} too small for {} slots and {} index reads each",
            access_budget, slots, hash_fns,
        ));
    }
    let max_chunk_bytes = (access_budget - index_budget)
        .checked_mul(DIRECT_CHUNK_RECORD_SIZE)
        .ok_or_else(|| "direct ORAM response padding byte count overflow".to_string())?;
    if actual_chunk_bytes > max_chunk_bytes {
        return Err(format!(
            "direct ORAM response has {} chunk bytes, exceeding public budget {}",
            actual_chunk_bytes, max_chunk_bytes,
        ));
    }
    Ok(max_chunk_bytes - actual_chunk_bytes)
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CuckooNativeLookupConfig {
    pub(crate) index_k: usize,
    pub(crate) chunk_k: usize,
    pub(crate) index_master_seed: u64,
    pub(crate) chunk_master_seed: u64,
    pub(crate) tag_seed: u64,
}

#[allow(dead_code)]
impl CuckooNativeLookupConfig {
    pub(crate) const fn from_db(db: &MappedDatabase) -> Self {
        Self {
            index_k: db.index.params.k,
            chunk_k: db.chunk.params.k,
            index_master_seed: db.index.master_seed,
            chunk_master_seed: db.chunk.master_seed,
            tag_seed: db.index.tag_seed,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CuckooBinRead {
    pub(crate) pbc_group: u32,
    pub(crate) bin_index: u32,
    pub(crate) bin_content: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CuckooNativeLookupResult {
    pub(crate) found: bool,
    pub(crate) whale: bool,
    pub(crate) start_chunk_id: Option<u32>,
    pub(crate) num_chunks: u8,
    pub(crate) raw_chunk_data: Vec<u8>,
    pub(crate) index_bin_reads: Vec<CuckooBinRead>,
    pub(crate) chunk_bin_reads: Vec<CuckooBinRead>,
}

#[allow(dead_code)]
pub(crate) fn cuckoo_native_lookup_batch_mmap(
    db: &MappedDatabase,
    script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
) -> Result<Vec<CuckooNativeLookupResult>, String> {
    let index_table = MmapCuckooTable::new(&db.index, db.index.params.bin_size());
    let chunk_table = MmapCuckooTable::new(&db.chunk, db.chunk.params.bin_size());
    cuckoo_native_lookup_batch_from_tables(
        &index_table,
        &chunk_table,
        CuckooNativeLookupConfig::from_db(db),
        script_hashes,
    )
}

#[allow(dead_code)]
pub(crate) fn cuckoo_native_lookup_batch_from_tables<I, C>(
    index_table: &I,
    chunk_table: &C,
    config: CuckooNativeLookupConfig,
    script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
) -> Result<Vec<CuckooNativeLookupResult>, String>
where
    I: CuckooTableAccess,
    C: CuckooTableAccess,
{
    cuckoo_native_lookup_batch_from_tables_with_dummy(
        index_table,
        chunk_table,
        config,
        script_hashes,
        rand::random::<u32>,
    )
}

#[allow(dead_code)]
pub(crate) fn cuckoo_native_lookup_batch_from_tables_with_dummy<I, C>(
    index_table: &I,
    chunk_table: &C,
    config: CuckooNativeLookupConfig,
    script_hashes: &[[u8; pir_core::params::SCRIPT_HASH_SIZE]],
    mut next_dummy_chunk_id: impl FnMut() -> u32,
) -> Result<Vec<CuckooNativeLookupResult>, String>
where
    I: CuckooTableAccess,
    C: CuckooTableAccess,
{
    if config.index_k < pir_core::params::NUM_HASHES
        || config.chunk_k < pir_core::params::NUM_HASHES
    {
        return Err(format!(
            "invalid cuckoo lookup geometry: index_k={}, chunk_k={} (need >= {})",
            config.index_k,
            config.chunk_k,
            pir_core::params::NUM_HASHES,
        ));
    }
    if index_table.bins_per_table() == 0 || chunk_table.bins_per_table() == 0 {
        return Err("cuckoo lookup table has zero bins".into());
    }

    let mut out = Vec::with_capacity(script_hashes.len());
    for script_hash in script_hashes {
        match cuckoo_native_lookup_one(
            index_table,
            chunk_table,
            config,
            script_hash,
            &mut next_dummy_chunk_id,
        ) {
            Ok(item) => out.push(item),
            Err(e) => {
                index_table.abort_request(&e);
                chunk_table.abort_request(&e);
                return Err(e);
            }
        }
    }

    if let Err(e) = index_table.finish_request() {
        chunk_table.abort_request(&e);
        return Err(e);
    }
    chunk_table.finish_request()?;
    Ok(out)
}

pub(crate) fn cuckoo_native_lookup_one<I, C>(
    index_table: &I,
    chunk_table: &C,
    config: CuckooNativeLookupConfig,
    script_hash: &[u8; pir_core::params::SCRIPT_HASH_SIZE],
    next_dummy_chunk_id: &mut impl FnMut() -> u32,
) -> Result<CuckooNativeLookupResult, String>
where
    I: CuckooTableAccess,
    C: CuckooTableAccess,
{
    let index_group = pir_core::hash::derive_groups_3(script_hash, config.index_k)[0];
    let expected_tag = pir_core::hash::compute_tag(config.tag_seed, script_hash);
    let mut index_bin_reads = Vec::with_capacity(INDEX_PARAMS.cuckoo_num_hashes);
    let mut found_entry: Option<(u32, u8)> = None;

    for h in 0..INDEX_PARAMS.cuckoo_num_hashes {
        let key = pir_core::hash::derive_cuckoo_key(config.index_master_seed, index_group, h);
        let bin = pir_core::hash::cuckoo_hash(script_hash, key, index_table.bins_per_table());
        let bin_content = read_cuckoo_bin(index_table, index_group, bin)?;
        if found_entry.is_none() {
            found_entry = find_entry_in_index_bin(&bin_content, expected_tag);
        }
        index_bin_reads.push(CuckooBinRead {
            pbc_group: checked_u32(index_group, "index group")?,
            bin_index: checked_u32(bin, "index bin")?,
            bin_content,
        });
    }

    let (start_chunk_id, num_chunks) = found_entry.unwrap_or((0, 0));
    let found = found_entry.is_some();
    let whale = found && num_chunks == 0;
    let mut real_chunk_ids = Vec::new();
    if found && num_chunks > 0 {
        let end = start_chunk_id
            .checked_add(num_chunks as u32)
            .ok_or_else(|| "INDEX entry chunk range overflows u32".to_string())?;
        real_chunk_ids.extend(start_chunk_id..end);
    }

    // CHUNK round-presence analogue for TEE/ORAM: even not-found and
    // whale results issue one full two-position dummy chunk probe, so the
    // host does not learn found-vs-not-found from zero CHUNK ORAM reads.
    let (probe_ids, dummy_probe) = if real_chunk_ids.is_empty() {
        (vec![next_dummy_chunk_id()], true)
    } else {
        (real_chunk_ids.clone(), false)
    };

    let mut chunk_bin_reads = Vec::with_capacity(probe_ids.len() * CHUNK_PARAMS.cuckoo_num_hashes);
    let mut raw_chunk_data =
        Vec::with_capacity(real_chunk_ids.len() * pir_core::params::CHUNK_SIZE);
    for chunk_id in probe_ids {
        let chunk_group = pir_core::hash::derive_int_groups_3(chunk_id, config.chunk_k)[0];
        let mut recovered: Option<Vec<u8>> = None;
        for h in 0..CHUNK_PARAMS.cuckoo_num_hashes {
            let key = pir_core::hash::derive_cuckoo_key(config.chunk_master_seed, chunk_group, h);
            let bin = pir_core::hash::cuckoo_hash_int(chunk_id, key, chunk_table.bins_per_table());
            let bin_content = read_cuckoo_bin(chunk_table, chunk_group, bin)?;
            if !dummy_probe && recovered.is_none() {
                if let Some(data) = find_chunk_in_bin(&bin_content, chunk_id) {
                    recovered = Some(data.to_vec());
                }
            }
            chunk_bin_reads.push(CuckooBinRead {
                pbc_group: checked_u32(chunk_group, "chunk group")?,
                bin_index: checked_u32(bin, "chunk bin")?,
                bin_content,
            });
        }
        if !dummy_probe {
            let data = recovered
                .ok_or_else(|| format!("chunk_id {} missing from cuckoo table", chunk_id))?;
            raw_chunk_data.extend_from_slice(&data);
        }
    }

    Ok(CuckooNativeLookupResult {
        found,
        whale,
        start_chunk_id: found.then_some(start_chunk_id),
        num_chunks,
        raw_chunk_data,
        index_bin_reads,
        chunk_bin_reads,
    })
}

pub(crate) fn checked_u32(value: usize, label: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{label} {} does not fit in u32", value))
}

pub(crate) fn read_cuckoo_bin<T: CuckooTableAccess>(
    table: &T,
    group_id: usize,
    bin_index: usize,
) -> Result<Vec<u8>, String> {
    let mut bin = Vec::with_capacity(table.entry_size());
    table.append_entry(group_id, bin_index, &mut bin)?;
    if bin.len() != table.entry_size() {
        return Err(format!(
            "cuckoo bin read returned {} bytes, expected {}",
            bin.len(),
            table.entry_size(),
        ));
    }
    Ok(bin)
}

pub(crate) fn find_entry_in_index_bin(result: &[u8], expected_tag: u64) -> Option<(u32, u8)> {
    for slot in 0..INDEX_PARAMS.slots_per_bin {
        let base = slot * INDEX_PARAMS.slot_size;
        if base + INDEX_PARAMS.slot_size > result.len() {
            break;
        }
        let slot_tag = u64::from_le_bytes(
            result[base..base + pir_core::params::TAG_SIZE]
                .try_into()
                .ok()?,
        );
        if slot_tag == expected_tag {
            let start = base + pir_core::params::TAG_SIZE;
            let start_chunk_id = u32::from_le_bytes(result[start..start + 4].try_into().ok()?);
            let num_chunks = result[start + 4];
            return Some((start_chunk_id, num_chunks));
        }
    }
    None
}

pub(crate) fn find_chunk_in_bin(result: &[u8], chunk_id: u32) -> Option<&[u8]> {
    let target = chunk_id.to_le_bytes();
    for slot in 0..CHUNK_PARAMS.slots_per_bin {
        let base = slot * CHUNK_PARAMS.slot_size;
        if base + CHUNK_PARAMS.slot_size > result.len() {
            break;
        }
        if result[base..base + 4] == target {
            return Some(&result[base + 4..base + CHUNK_PARAMS.slot_size]);
        }
    }
    None
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) struct CuckooOramPaths {
    pub(crate) meta_image: PathBuf,
    pub(crate) payload_image: PathBuf,
    pub(crate) meta_hash_image: PathBuf,
    pub(crate) payload_hash_image: PathBuf,
    pub(crate) state: PathBuf,
    pub(crate) auth_state: PathBuf,
}

#[cfg(feature = "cuckoo-oram")]
impl CuckooOramPaths {
    pub(crate) fn new(oram_dir: &std::path::Path, level: CuckooLevel) -> Self {
        let label = level.label();
        Self {
            meta_image: oram_dir.join(format!("{label}.meta.oram")),
            payload_image: oram_dir.join(format!("{label}.payload.oram")),
            meta_hash_image: oram_dir.join(format!("{label}.meta.hash.oram")),
            payload_hash_image: oram_dir.join(format!("{label}.payload.hash.oram")),
            state: oram_dir.join(format!("{label}.state")),
            auth_state: oram_dir.join(format!("{label}.auth.state")),
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) struct DirectOramPaths {
    pub(crate) meta_image: PathBuf,
    pub(crate) payload_image: PathBuf,
    pub(crate) meta_hash_image: PathBuf,
    pub(crate) payload_hash_image: PathBuf,
    pub(crate) state: PathBuf,
    pub(crate) auth_state: PathBuf,
    pub(crate) metadata: PathBuf,
}

#[cfg(feature = "cuckoo-oram")]
impl DirectOramPaths {
    #[cfg(test)]
    pub(crate) fn new(oram_dir: &std::path::Path, level: DirectLevel) -> Self {
        Self::new_with_trusted_state(oram_dir, None, level)
    }

    pub(crate) fn new_with_trusted_state(
        oram_dir: &std::path::Path,
        trusted_state_dir: Option<&std::path::Path>,
        level: DirectLevel,
    ) -> Self {
        let label = format!("direct-{}", level.label());
        let trusted_state_dir = trusted_state_dir.unwrap_or(oram_dir);
        Self {
            meta_image: oram_dir.join(format!("{label}.meta.oram")),
            payload_image: oram_dir.join(format!("{label}.payload.oram")),
            meta_hash_image: oram_dir.join(format!("{label}.meta.hash.oram")),
            payload_hash_image: oram_dir.join(format!("{label}.payload.hash.oram")),
            state: trusted_state_dir.join(format!("{label}.state")),
            auth_state: trusted_state_dir.join(format!("{label}.auth.state")),
            metadata: trusted_state_dir.join(format!("{label}.metadata")),
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn open_existing_oram_store(
    path: &std::path::Path,
    page_count: usize,
    plaintext_page_size: usize,
    encrypted: bool,
    key_hex: Option<&str>,
    key_flag: &str,
    cached_pages: usize,
) -> Result<CuckooRawPageStore, String> {
    let backing_page_size = plaintext_page_size + if encrypted { AEAD_OVERHEAD } else { 0 };
    let expected_len = page_count
        .checked_mul(backing_page_size)
        .ok_or_else(|| "ORAM image length overflow".to_string())?;
    let actual_len = std::fs::metadata(path)
        .map_err(|e| format!("open ORAM image {}: {}", path.display(), e))?
        .len() as usize;
    if actual_len != expected_len {
        return Err(format!(
            "ORAM image {} has {} bytes, expected {}",
            path.display(),
            actual_len,
            expected_len
        ));
    }

    let store: CuckooRawPageStore = if encrypted {
        let key = parse_required_32_hex(key_hex, key_flag)?;
        let file =
            FilePageStore::open(path, page_count, backing_page_size).map_err(|e| e.to_string())?;
        Box::new(AeadPageStore::new(file, key, plaintext_page_size).map_err(|e| e.to_string())?)
    } else {
        Box::new(
            FilePageStore::open(path, page_count, plaintext_page_size)
                .map_err(|e| e.to_string())?,
        )
    };

    if cached_pages == 0 {
        Ok(store)
    } else {
        Ok(Box::new(
            FrontCachedPageStore::new(store, cached_pages).map_err(|e| e.to_string())?,
        ))
    }
}

#[cfg(feature = "cuckoo-oram")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn open_existing_circuit_oram_stores(
    paths: &CuckooOramPaths,
    level: CuckooLevel,
    params: &OramParams,
    encrypted: bool,
    key_hex: Option<&str>,
    cached_pages: usize,
    auth_store: bool,
    bound_auth: Option<&CircuitStoreAuthState>,
    state_key: Option<[u8; 32]>,
) -> Result<(CuckooOramStore, CuckooOramStore), String> {
    if !auth_store {
        let meta_store = open_existing_oram_store(
            &paths.meta_image,
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
            encrypted,
            key_hex,
            "--cuckoo-oram-key-hex",
            cached_pages,
        )?;
        let payload_store = open_existing_oram_store(
            &paths.payload_image,
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
            encrypted,
            key_hex,
            "--cuckoo-oram-key-hex",
            cached_pages,
        )?;
        return Ok((
            CuckooOramStore::Plain(meta_store),
            CuckooOramStore::Plain(payload_store),
        ));
    }

    let auth = match bound_auth {
        Some(auth) => auth.clone(),
        None => load_circuit_store_auth(&paths.auth_state, state_key)?,
    };
    match auth.layout {
        CircuitStoreAuthLayout::TieredMerkle { meta, payload } => {
            let expected_meta_id = circuit_auth_store_id(level, CircuitAuthStoreKind::Meta);
            let expected_payload_id = circuit_auth_store_id(level, CircuitAuthStoreKind::Payload);
            if meta.store_id != expected_meta_id || payload.store_id != expected_payload_id {
                return Err(format!(
                    "Cuckoo ORAM {} auth sidecar store_id does not match expected level/store domains",
                    level
                ));
            }

            let meta_store = open_existing_oram_store(
                &paths.meta_image,
                params.bucket_count(),
                circuit_meta_page_bytes(params.bucket_size),
                encrypted,
                key_hex,
                "--cuckoo-oram-key-hex",
                cached_pages,
            )?;
            let payload_store = open_existing_oram_store(
                &paths.payload_image,
                params.bucket_count(),
                circuit_payload_page_bytes(params.bucket_size, params.block_size),
                encrypted,
                key_hex,
                "--cuckoo-oram-key-hex",
                cached_pages,
            )?;
            let meta_hash_store = open_existing_hash_store(
                &paths.meta_hash_image,
                &meta,
                encrypted,
                key_hex,
                "--cuckoo-oram-key-hex",
            )?;
            let payload_hash_store = open_existing_hash_store(
                &paths.payload_hash_image,
                &payload,
                encrypted,
                key_hex,
                "--cuckoo-oram-key-hex",
            )?;
            let meta = TieredMerklePageStore::from_trusted_state(meta_store, meta_hash_store, meta)
                .map_err(|e| e.to_string())?;
            let payload = TieredMerklePageStore::from_trusted_state(
                payload_store,
                payload_hash_store,
                payload,
            )
            .map_err(|e| e.to_string())?;
            Ok((
                CuckooOramStore::Sidecar(meta),
                CuckooOramStore::Sidecar(payload),
            ))
        }
        CircuitStoreAuthLayout::EmbeddedTree { meta, payload } => {
            let expected_meta_id = circuit_auth_store_id(level, CircuitAuthStoreKind::Meta);
            let expected_payload_id = circuit_auth_store_id(level, CircuitAuthStoreKind::Payload);
            if meta.store_id != expected_meta_id || payload.store_id != expected_payload_id {
                return Err(format!(
                    "Cuckoo ORAM {} embedded auth store_id does not match expected level/store domains",
                    level
                ));
            }

            let meta_store = open_existing_oram_store(
                &paths.meta_image,
                params.bucket_count(),
                circuit_meta_page_bytes(params.bucket_size) + EMBEDDED_TREE_AUTH_BYTES_PER_PAGE,
                encrypted,
                key_hex,
                "--cuckoo-oram-key-hex",
                cached_pages,
            )?;
            let payload_store = open_existing_oram_store(
                &paths.payload_image,
                params.bucket_count(),
                circuit_payload_page_bytes(params.bucket_size, params.block_size)
                    + EMBEDDED_TREE_AUTH_BYTES_PER_PAGE,
                encrypted,
                key_hex,
                "--cuckoo-oram-key-hex",
                cached_pages,
            )?;
            let meta =
                EmbeddedTreePageStore::from_state(meta_store, meta).map_err(|e| e.to_string())?;
            let payload = EmbeddedTreePageStore::from_state(payload_store, payload)
                .map_err(|e| e.to_string())?;
            Ok((
                CuckooOramStore::Embedded(meta),
                CuckooOramStore::Embedded(payload),
            ))
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn open_existing_direct_oram_stores(
    paths: &DirectOramPaths,
    level: DirectLevel,
    params: &OramParams,
    encrypted: bool,
    key_hex: Option<&str>,
    cached_pages: usize,
    auth_store: bool,
    bound_auth: Option<&CircuitStoreAuthState>,
    state_key: Option<[u8; 32]>,
) -> Result<(CuckooOramStore, CuckooOramStore), String> {
    if !auth_store {
        let meta_store = open_existing_oram_store(
            &paths.meta_image,
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
            encrypted,
            key_hex,
            "--direct-oram-key-hex",
            cached_pages,
        )?;
        let payload_store = open_existing_oram_store(
            &paths.payload_image,
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
            encrypted,
            key_hex,
            "--direct-oram-key-hex",
            cached_pages,
        )?;
        return Ok((
            CuckooOramStore::Plain(meta_store),
            CuckooOramStore::Plain(payload_store),
        ));
    }

    let auth = match bound_auth {
        Some(auth) => auth.clone(),
        None => load_circuit_store_auth(&paths.auth_state, state_key)?,
    };
    match auth.layout {
        CircuitStoreAuthLayout::TieredMerkle { meta, payload } => {
            let expected_meta_id = direct_auth_store_id(level, CircuitAuthStoreKind::Meta);
            let expected_payload_id = direct_auth_store_id(level, CircuitAuthStoreKind::Payload);
            if meta.store_id != expected_meta_id || payload.store_id != expected_payload_id {
                return Err(format!(
                    "Direct ORAM {} auth sidecar store_id does not match expected level/store domains",
                    level
                ));
            }

            let meta_store = open_existing_oram_store(
                &paths.meta_image,
                params.bucket_count(),
                circuit_meta_page_bytes(params.bucket_size),
                encrypted,
                key_hex,
                "--direct-oram-key-hex",
                cached_pages,
            )?;
            let payload_store = open_existing_oram_store(
                &paths.payload_image,
                params.bucket_count(),
                circuit_payload_page_bytes(params.bucket_size, params.block_size),
                encrypted,
                key_hex,
                "--direct-oram-key-hex",
                cached_pages,
            )?;
            let meta_hash_store = open_existing_hash_store(
                &paths.meta_hash_image,
                &meta,
                encrypted,
                key_hex,
                "--direct-oram-key-hex",
            )?;
            let payload_hash_store = open_existing_hash_store(
                &paths.payload_hash_image,
                &payload,
                encrypted,
                key_hex,
                "--direct-oram-key-hex",
            )?;
            let meta = TieredMerklePageStore::from_trusted_state(meta_store, meta_hash_store, meta)
                .map_err(|e| e.to_string())?;
            let payload = TieredMerklePageStore::from_trusted_state(
                payload_store,
                payload_hash_store,
                payload,
            )
            .map_err(|e| e.to_string())?;
            Ok((
                CuckooOramStore::Sidecar(meta),
                CuckooOramStore::Sidecar(payload),
            ))
        }
        CircuitStoreAuthLayout::EmbeddedTree { meta, payload } => {
            let expected_meta_id = direct_auth_store_id(level, CircuitAuthStoreKind::Meta);
            let expected_payload_id = direct_auth_store_id(level, CircuitAuthStoreKind::Payload);
            if meta.store_id != expected_meta_id || payload.store_id != expected_payload_id {
                return Err(format!(
                    "Direct ORAM {} embedded auth store_id does not match expected level/store domains",
                    level
                ));
            }

            let meta_store = open_existing_oram_store(
                &paths.meta_image,
                params.bucket_count(),
                circuit_meta_page_bytes(params.bucket_size) + EMBEDDED_TREE_AUTH_BYTES_PER_PAGE,
                encrypted,
                key_hex,
                "--direct-oram-key-hex",
                cached_pages,
            )?;
            let payload_store = open_existing_oram_store(
                &paths.payload_image,
                params.bucket_count(),
                circuit_payload_page_bytes(params.bucket_size, params.block_size)
                    + EMBEDDED_TREE_AUTH_BYTES_PER_PAGE,
                encrypted,
                key_hex,
                "--direct-oram-key-hex",
                cached_pages,
            )?;
            let meta =
                EmbeddedTreePageStore::from_state(meta_store, meta).map_err(|e| e.to_string())?;
            let payload = EmbeddedTreePageStore::from_state(payload_store, payload)
                .map_err(|e| e.to_string())?;
            Ok((
                CuckooOramStore::Embedded(meta),
                CuckooOramStore::Embedded(payload),
            ))
        }
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn open_existing_hash_store(
    path: &std::path::Path,
    auth: &TieredMerkleState,
    encrypted: bool,
    key_hex: Option<&str>,
    key_flag: &str,
) -> Result<CuckooRawPageStore, String> {
    let hash_pages = tiered_hash_pages(auth.page_count, auth.hash_page_size, auth.trusted_levels)?;
    open_existing_oram_store(
        path,
        hash_pages,
        auth.hash_page_size,
        encrypted,
        key_hex,
        key_flag,
        0,
    )
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn tiered_hash_pages(
    data_pages: usize,
    hash_page_size: usize,
    trusted_levels: usize,
) -> Result<usize, String> {
    TieredMerklePageStore::<CuckooRawPageStore, CuckooRawPageStore>::required_hash_pages(
        data_pages,
        hash_page_size,
        trusted_levels,
    )
    .map_err(|e| e.to_string())
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn load_circuit_store_auth(
    path: &std::path::Path,
    state_key: Option<[u8; 32]>,
) -> Result<CircuitStoreAuthState, String> {
    match state_key {
        Some(key) => CircuitStoreAuthState::load_encrypted(path, key).map_err(|e| e.to_string()),
        None => CircuitStoreAuthState::load(path).map_err(|e| e.to_string()),
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn load_circuit_oram_state(
    path: &std::path::Path,
    state_key: Option<[u8; 32]>,
) -> Result<CircuitOramState, String> {
    match state_key {
        Some(key) => CircuitOramState::load_encrypted(path, key).map_err(|e| e.to_string()),
        None => CircuitOramState::load(path).map_err(|e| e.to_string()),
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn save_circuit_oram_state(
    state: &CircuitOramState,
    path: &std::path::Path,
    state_key: Option<[u8; 32]>,
) -> Result<(), String> {
    match state_key {
        Some(key) => state
            .save_encrypted_atomic(path, key)
            .map_err(|e| e.to_string()),
        None => state.save_atomic(path).map_err(|e| e.to_string()),
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn save_circuit_store_auth(
    state: &CircuitStoreAuthState,
    path: &std::path::Path,
    state_key: Option<[u8; 32]>,
) -> Result<(), String> {
    match state_key {
        Some(key) => state
            .save_encrypted_atomic(path, key)
            .map_err(|e| e.to_string()),
        None => state.save_atomic(path).map_err(|e| e.to_string()),
    }
}

#[cfg(feature = "cuckoo-oram")]
#[derive(Clone, Copy)]
pub(crate) enum CircuitAuthStoreKind {
    Meta,
    Payload,
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn circuit_auth_store_id(level: CuckooLevel, kind: CircuitAuthStoreKind) -> [u8; 16] {
    match (level, kind) {
        (CuckooLevel::Index, CircuitAuthStoreKind::Meta) => *b"bpir-idx-meta-v1",
        (CuckooLevel::Index, CircuitAuthStoreKind::Payload) => *b"bpir-idx-data-v1",
        (CuckooLevel::Chunk, CircuitAuthStoreKind::Meta) => *b"bpir-chk-meta-v1",
        (CuckooLevel::Chunk, CircuitAuthStoreKind::Payload) => *b"bpir-chk-data-v1",
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn direct_auth_store_id(level: DirectLevel, kind: CircuitAuthStoreKind) -> [u8; 16] {
    match (level, kind) {
        (DirectLevel::Index, CircuitAuthStoreKind::Meta) => *b"bpir-diridx-meta",
        (DirectLevel::Index, CircuitAuthStoreKind::Payload) => *b"bpir-diridx-data",
        (DirectLevel::Chunk, CircuitAuthStoreKind::Meta) => *b"bpir-dirchk-meta",
        (DirectLevel::Chunk, CircuitAuthStoreKind::Payload) => *b"bpir-dirchk-data",
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn cached_pages_for_oram_levels(
    params: &OramParams,
    cache_levels: usize,
) -> Result<usize, String> {
    if cache_levels == 0 {
        return Ok(0);
    }
    if cache_levels > params.height() {
        return Err(format!(
            "--cuckoo-oram-cache-levels {} > ORAM tree height {}",
            cache_levels,
            params.height()
        ));
    }
    Ok((1usize << cache_levels) - 1)
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn parse_optional_32_hex(input: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    match input {
        Some(input) => parse_32_hex(input).map(Some),
        None => Ok(None),
    }
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn parse_required_32_hex(input: Option<&str>, flag: &str) -> Result<[u8; 32], String> {
    let input = input.ok_or_else(|| format!("{flag} is required"))?;
    parse_32_hex(input)
}

#[cfg(feature = "cuckoo-oram")]
pub(crate) fn parse_32_hex(input: &str) -> Result<[u8; 32], String> {
    if input.len() != 64 {
        return Err(format!(
            "expected 32-byte hex string (64 chars), got {} chars",
            input.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let start = i * 2;
        *byte = u8::from_str_radix(&input[start..start + 2], 16)
            .map_err(|_| format!("invalid hex byte at offset {}", start))?;
    }
    Ok(out)
}
