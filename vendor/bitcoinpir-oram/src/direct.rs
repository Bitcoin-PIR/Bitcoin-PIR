//! Direct-entry BitcoinPIR ORAM layouts.
//!
//! The existing [`crate::cuckoo`] module wraps the DPF/Harmony PBC-expanded
//! cuckoo files. This module is the smaller ORAM-native layout: one global
//! INDEX dictionary over script hashes, and one packed CHUNK array addressed
//! directly by chunk id.

use crate::{
    ct, CircuitOram, Error, OramBlock, OramParams, PageStore, Result, TrustedBlockSource,
    AEAD_OVERHEAD,
};
use memmap2::{Mmap, MmapOptions};
use serde::{Deserialize, Serialize};
use std::{
    fmt, fs,
    fs::File,
    path::{Path, PathBuf},
};

/// Direct input INDEX file produced by the BitcoinPIR chunk builder.
pub const DIRECT_INDEX_INPUT_FILE: &str = "utxo_chunks_index_nodust.bin";
/// Direct input CHUNK file produced by the BitcoinPIR chunk builder.
pub const DIRECT_CHUNKS_INPUT_FILE: &str = "utxo_chunks_nodust.bin";

/// HASH160 script hash bytes.
pub const DIRECT_SCRIPT_HASH_SIZE: usize = 20;
/// Intermediate INDEX record: `[20B script_hash][4B start_chunk_id][1B num_chunks]`.
pub const DIRECT_INDEX_INPUT_RECORD_SIZE: usize = DIRECT_SCRIPT_HASH_SIZE + 4 + 1;
/// Direct INDEX ORAM slot: `[1B occupied][20B script_hash][4B start_chunk_id][1B num_chunks]`.
pub const DIRECT_INDEX_SLOT_SIZE: usize = 1 + DIRECT_INDEX_INPUT_RECORD_SIZE;
/// Direct CHUNK record bytes.
pub const DIRECT_CHUNK_RECORD_SIZE: usize = 40;

/// Default slots per direct INDEX cuckoo bin.
pub const DIRECT_INDEX_DEFAULT_SLOTS_PER_BIN: usize = 4;
/// Default number of direct INDEX cuckoo hash functions.
pub const DIRECT_INDEX_DEFAULT_HASH_FNS: usize = 2;
/// Default direct INDEX load factor.
pub const DIRECT_INDEX_DEFAULT_LOAD_FACTOR: f64 = 0.95;
/// Deterministic seed used when the caller does not supply a direct INDEX seed.
pub const DIRECT_INDEX_DEFAULT_SEED: u64 = 0x6f72_616d_6469_7231;

const DIRECT_METADATA_VERSION: u32 = 1;
const EMPTY_SLOT: u32 = u32::MAX;
const CUCKOO_KEY_MIX: u64 = 0x517c_c1b7_2722_0a95;
const GOLDEN_RATIO: u64 = 0x9e37_79b9_7f4a_7c15;
const DIRECT_CUCKOO_MAX_KICKS: usize = 10_000;

/// Direct ORAM table level.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DirectLevel {
    /// Global script-hash dictionary.
    Index,
    /// Direct chunk-id array.
    Chunk,
}

impl DirectLevel {
    /// Human-readable lowercase label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Index => "index",
            Self::Chunk => "chunk",
        }
    }
}

impl fmt::Display for DirectLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Parsed source-table metadata for a direct ORAM build.
#[derive(Clone, Debug)]
pub struct DirectTableInfo {
    /// INDEX or CHUNK.
    pub level: DirectLevel,
    /// Source file path.
    pub path: PathBuf,
    /// Source file bytes.
    pub file_bytes: u64,
    /// Input records: INDEX records or CHUNK records.
    pub records: usize,
    /// Direct INDEX slots per bin. Always 1 for CHUNK.
    pub slots_per_bin: usize,
    /// Direct INDEX cuckoo hash functions. Always 0 for CHUNK.
    pub hash_fns: usize,
    /// Direct INDEX load factor. Always 1.0 for CHUNK.
    pub load_factor: f64,
    /// Direct INDEX hash seed. Always 0 for CHUNK.
    pub seed: u64,
    /// Addressable direct items before ORAM packing: INDEX bins or CHUNK records.
    pub total_items: usize,
    /// Bytes per addressable direct item: INDEX bin bytes or CHUNK bytes.
    pub item_size: usize,
}

impl DirectTableInfo {
    /// Parse direct INDEX source metadata.
    pub fn from_index_file(
        path: impl AsRef<Path>,
        slots_per_bin: usize,
        hash_fns: usize,
        load_factor: f64,
        seed: u64,
    ) -> Result<Self> {
        if slots_per_bin == 0 {
            return Err(Error::InvalidInput("slots_per_bin must be > 0".into()));
        }
        if hash_fns == 0 {
            return Err(Error::InvalidInput("hash_fns must be > 0".into()));
        }
        if !(load_factor > 0.0 && load_factor < 1.0) {
            return Err(Error::InvalidInput(
                "load_factor must be greater than 0 and less than 1".into(),
            ));
        }

        let path = path.as_ref();
        let file_bytes = fs::metadata(path)?.len();
        if !(file_bytes as usize).is_multiple_of(DIRECT_INDEX_INPUT_RECORD_SIZE) {
            return Err(Error::InvalidInput(format!(
                "direct index file {} has {} bytes, not a multiple of {}",
                path.display(),
                file_bytes,
                DIRECT_INDEX_INPUT_RECORD_SIZE
            )));
        }
        let records = file_bytes as usize / DIRECT_INDEX_INPUT_RECORD_SIZE;
        let total_items = compute_direct_index_bins(records, slots_per_bin, load_factor)?;

        Ok(Self {
            level: DirectLevel::Index,
            path: path.to_path_buf(),
            file_bytes,
            records,
            slots_per_bin,
            hash_fns,
            load_factor,
            seed,
            total_items,
            item_size: slots_per_bin * DIRECT_INDEX_SLOT_SIZE,
        })
    }

    /// Parse direct CHUNK source metadata.
    pub fn from_chunks_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file_bytes = fs::metadata(path)?.len();
        if !(file_bytes as usize).is_multiple_of(DIRECT_CHUNK_RECORD_SIZE) {
            return Err(Error::InvalidInput(format!(
                "direct chunks file {} has {} bytes, not a multiple of {}",
                path.display(),
                file_bytes,
                DIRECT_CHUNK_RECORD_SIZE
            )));
        }
        let records = file_bytes as usize / DIRECT_CHUNK_RECORD_SIZE;
        Ok(Self {
            level: DirectLevel::Chunk,
            path: path.to_path_buf(),
            file_bytes,
            records,
            slots_per_bin: 1,
            hash_fns: 0,
            load_factor: 1.0,
            seed: 0,
            total_items: records,
            item_size: DIRECT_CHUNK_RECORD_SIZE,
        })
    }

    /// Fixed direct item bytes.
    pub const fn item_size(&self) -> usize {
        self.item_size
    }

    /// Number of direct items packed by the ORAM source.
    pub const fn total_items(&self) -> usize {
        self.total_items
    }
}

/// Metadata persisted next to a direct ORAM image.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirectTableMetadata {
    /// Format version.
    pub version: u32,
    /// INDEX or CHUNK.
    pub level: DirectLevel,
    /// Source path used at build time.
    pub source_path: PathBuf,
    /// Source file bytes used at build time.
    pub source_file_bytes: u64,
    /// Input records: INDEX records or CHUNK records.
    pub source_records: usize,
    /// Addressable direct items before ORAM packing.
    pub total_items: usize,
    /// Bytes per addressable direct item.
    pub item_size: usize,
    /// Direct items packed into one ORAM logical block.
    pub items_per_block: usize,
    /// Direct INDEX slots per bin. Always 1 for CHUNK.
    pub slots_per_bin: usize,
    /// Direct INDEX cuckoo hash functions. Always 0 for CHUNK.
    pub hash_fns: usize,
    /// Direct INDEX load factor, in parts per billion. Always 1e9 for CHUNK.
    pub load_factor_ppb: u32,
    /// Direct INDEX hash seed. Always 0 for CHUNK.
    pub seed: u64,
    /// ORAM logical block count.
    pub logical_blocks: usize,
    /// ORAM payload bytes per logical block.
    pub block_payload_bytes: usize,
}

impl DirectTableMetadata {
    /// Build persisted metadata from source metadata and an ORAM pack factor.
    pub fn from_info(info: &DirectTableInfo, items_per_block: usize) -> Result<Self> {
        if items_per_block == 0 {
            return Err(Error::InvalidInput("items_per_block must be > 0".into()));
        }
        let logical_blocks = info.total_items.div_ceil(items_per_block);
        let block_payload_bytes = info.item_size * items_per_block;
        Ok(Self {
            version: DIRECT_METADATA_VERSION,
            level: info.level,
            source_path: info.path.clone(),
            source_file_bytes: info.file_bytes,
            source_records: info.records,
            total_items: info.total_items,
            item_size: info.item_size,
            items_per_block,
            slots_per_bin: info.slots_per_bin,
            hash_fns: info.hash_fns,
            load_factor_ppb: (info.load_factor * 1_000_000_000.0).round() as u32,
            seed: info.seed,
            logical_blocks,
            block_payload_bytes,
        })
    }

    /// Save direct metadata.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, bincode::serialize(self)?)?;
        Ok(())
    }

    /// Load direct metadata.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = fs::read(path)?;
        let metadata: Self = bincode::deserialize(&bytes)?;
        metadata.validate()?;
        Ok(metadata)
    }

    /// Check metadata invariants.
    pub fn validate(&self) -> Result<()> {
        if self.version != DIRECT_METADATA_VERSION {
            return Err(Error::InvalidInput(format!(
                "unsupported direct metadata version {}",
                self.version
            )));
        }
        if self.items_per_block == 0 {
            return Err(Error::InvalidInput(
                "direct metadata has items_per_block=0".into(),
            ));
        }
        if self.item_size == 0 {
            return Err(Error::InvalidInput(
                "direct metadata has item_size=0".into(),
            ));
        }
        if self.logical_blocks != self.total_items.div_ceil(self.items_per_block) {
            return Err(Error::InvalidInput(
                "direct metadata logical_blocks does not match total_items/items_per_block".into(),
            ));
        }
        if self.block_payload_bytes != self.item_size * self.items_per_block {
            return Err(Error::InvalidInput(
                "direct metadata block_payload_bytes does not match item_size/items_per_block"
                    .into(),
            ));
        }
        match self.level {
            DirectLevel::Index => {
                if self.item_size != self.slots_per_bin * DIRECT_INDEX_SLOT_SIZE {
                    return Err(Error::InvalidInput(
                        "direct index metadata item_size does not match slots_per_bin".into(),
                    ));
                }
                if self.slots_per_bin == 0 || self.hash_fns == 0 {
                    return Err(Error::InvalidInput(
                        "direct index metadata requires slots_per_bin and hash_fns".into(),
                    ));
                }
            }
            DirectLevel::Chunk => {
                if self.item_size != DIRECT_CHUNK_RECORD_SIZE {
                    return Err(Error::InvalidInput(
                        "direct chunk metadata item_size does not match chunk size".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// ORAM sizing options for direct-entry tables.
#[derive(Clone, Copy, Debug)]
pub struct DirectOramSizing {
    /// Consecutive direct items packed into one logical ORAM block.
    pub items_per_block: usize,
    /// Use `next_power_of_two(ceil(logical_blocks / leaf_divisor))` leaves.
    pub leaf_divisor: usize,
    /// Physical Circuit ORAM bucket size.
    pub bucket_size: usize,
    /// Fixed trusted stash slots.
    pub stash_capacity: usize,
    /// Public top ORAM tree levels cached in trusted memory.
    pub cache_levels: usize,
}

impl DirectOramSizing {
    /// Estimate ORAM sizes for one direct table.
    pub fn estimate(&self, table: &DirectTableInfo) -> Result<DirectOramEstimate> {
        if self.items_per_block == 0 {
            return Err(Error::InvalidParams("items_per_block must be > 0".into()));
        }
        if self.leaf_divisor == 0 {
            return Err(Error::InvalidParams("leaf_divisor must be > 0".into()));
        }

        let logical_blocks = table.total_items.div_ceil(self.items_per_block);
        let target_leaves = logical_blocks.div_ceil(self.leaf_divisor).max(2);
        let leaves = checked_next_power_of_two(target_leaves)?;
        let block_payload_bytes = table.item_size * self.items_per_block;
        let params = OramParams::with_leaves(logical_blocks, block_payload_bytes, leaves)?
            .with_bucket_size(self.bucket_size)?
            .with_stash_capacity(self.stash_capacity)?;
        let page_plaintext_bytes = params.bucket_bytes();
        let page_aead_bytes = page_plaintext_bytes + AEAD_OVERHEAD;
        let bucket_pages = params.bucket_count();
        let image_plaintext_bytes = bucket_pages as u64 * page_plaintext_bytes as u64;
        let image_aead_bytes = bucket_pages as u64 * page_aead_bytes as u64;
        let pos_map_bytes = logical_blocks as u64 * 4;
        let stash_slot_bytes = OramBlock::serialized_len(block_payload_bytes) as u64;
        let trusted_stash_bytes = self.stash_capacity as u64 * stash_slot_bytes;
        let trusted_state_floor_bytes = pos_map_bytes + trusted_stash_bytes;
        let effective_cache_levels = self.cache_levels.min(params.height());
        let cached_pages = if effective_cache_levels == 0 {
            0
        } else {
            (1usize << effective_cache_levels) - 1
        };
        let front_cache_plaintext_bytes = cached_pages as u64 * page_plaintext_bytes as u64;
        let front_cache_aead_bytes = cached_pages as u64 * page_aead_bytes as u64;
        let uncached_levels = params.height() - effective_cache_levels;
        let disk_pages_per_access_no_flush = uncached_levels * 2;
        let disk_aead_bytes_per_access_no_flush =
            disk_pages_per_access_no_flush as u64 * page_aead_bytes as u64;

        Ok(DirectOramEstimate {
            level: table.level,
            items_per_block: self.items_per_block,
            leaf_divisor: self.leaf_divisor,
            source_records: table.records,
            total_items: table.total_items,
            item_size: table.item_size,
            logical_blocks,
            block_payload_bytes,
            bucket_size: self.bucket_size,
            leaves,
            height: params.height(),
            bucket_pages,
            page_plaintext_bytes,
            page_aead_bytes,
            image_plaintext_bytes,
            image_aead_bytes,
            pos_map_bytes,
            trusted_stash_bytes,
            trusted_state_floor_bytes,
            cached_pages,
            front_cache_plaintext_bytes,
            front_cache_aead_bytes,
            disk_pages_per_access_no_flush,
            disk_aead_bytes_per_access_no_flush,
            tree_slot_load_percent: logical_blocks as f64 * 100.0
                / (bucket_pages as f64 * self.bucket_size as f64),
        })
    }
}

/// Estimated ORAM sizes for one direct table.
#[derive(Clone, Debug)]
pub struct DirectOramEstimate {
    /// INDEX or CHUNK.
    pub level: DirectLevel,
    /// Direct items per logical ORAM block.
    pub items_per_block: usize,
    /// Leaf divisor.
    pub leaf_divisor: usize,
    /// Input record count.
    pub source_records: usize,
    /// Addressable direct items before ORAM packing.
    pub total_items: usize,
    /// Bytes per direct item.
    pub item_size: usize,
    /// ORAM logical block count.
    pub logical_blocks: usize,
    /// Payload bytes in one logical ORAM block.
    pub block_payload_bytes: usize,
    /// Physical Circuit ORAM bucket size.
    pub bucket_size: usize,
    /// Number of ORAM leaves.
    pub leaves: usize,
    /// Tree height, including root and leaves.
    pub height: usize,
    /// Number of physical bucket pages.
    pub bucket_pages: usize,
    /// Plaintext bytes per bucket page.
    pub page_plaintext_bytes: usize,
    /// AEAD-backed bytes per bucket page.
    pub page_aead_bytes: usize,
    /// Plaintext ORAM image bytes.
    pub image_plaintext_bytes: u64,
    /// AEAD-backed ORAM image bytes.
    pub image_aead_bytes: u64,
    /// Trusted position-map bytes.
    pub pos_map_bytes: u64,
    /// Trusted fixed-stash bytes, excluding serde Vec overhead.
    pub trusted_stash_bytes: u64,
    /// Trusted state lower-bound bytes: position map + fixed stash.
    pub trusted_state_floor_bytes: u64,
    /// Public prefix pages cached in trusted memory.
    pub cached_pages: usize,
    /// Plaintext bytes in the trusted front cache.
    pub front_cache_plaintext_bytes: u64,
    /// AEAD-sized bytes represented by the trusted front cache.
    pub front_cache_aead_bytes: u64,
    /// Disk page reads+writes per access before flushing cached prefix pages.
    pub disk_pages_per_access_no_flush: usize,
    /// AEAD disk bytes per access before flushing cached prefix pages.
    pub disk_aead_bytes_per_access_no_flush: u64,
    /// Occupancy of all physical ORAM slots.
    pub tree_slot_load_percent: f64,
}

/// Location of one direct item inside a packed ORAM logical block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedDirectItemLocation {
    /// ORAM logical block id.
    pub logical_block: usize,
    /// Byte offset inside the logical block.
    pub byte_offset: usize,
    /// Number of bytes in the direct item.
    pub byte_len: usize,
}

impl PackedDirectItemLocation {
    fn byte_range(self) -> std::ops::Range<usize> {
        self.byte_offset..self.byte_offset + self.byte_len
    }
}

/// Map a direct item id to its packed ORAM block and byte range.
pub fn locate_packed_direct_item(
    total_items: usize,
    items_per_block: usize,
    item_size: usize,
    item_id: usize,
) -> Result<PackedDirectItemLocation> {
    if items_per_block == 0 {
        return Err(Error::InvalidInput("items_per_block must be > 0".into()));
    }
    if item_size == 0 {
        return Err(Error::InvalidInput("item_size must be > 0".into()));
    }
    if item_id >= total_items {
        return Err(Error::InvalidInput(format!(
            "direct item_id {} out of range {}",
            item_id, total_items
        )));
    }

    let slot_in_block = item_id % items_per_block;
    Ok(PackedDirectItemLocation {
        logical_block: item_id / items_per_block,
        byte_offset: slot_in_block * item_size,
        byte_len: item_size,
    })
}

/// Streaming source for direct INDEX logical blocks.
pub struct DirectIndexPackedBlockReader {
    info: DirectTableInfo,
    metadata: DirectTableMetadata,
    next_block: usize,
    mmap: Mmap,
    placement: Vec<u32>,
}

impl DirectIndexPackedBlockReader {
    /// Build a direct INDEX placement and open it as a packed ORAM source.
    pub fn build(info: DirectTableInfo, items_per_block: usize) -> Result<Self> {
        if info.level != DirectLevel::Index {
            return Err(Error::InvalidInput(
                "DirectIndexPackedBlockReader requires index table info".into(),
            ));
        }
        let file = File::open(&info.path)?;
        // SAFETY: the file is opened read-only and is not mutated by this reader.
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        let placement = build_direct_index_placement(&info, &mmap)?;
        let metadata = DirectTableMetadata::from_info(&info, items_per_block)?;
        Ok(Self {
            info,
            metadata,
            next_block: 0,
            mmap,
            placement,
        })
    }

    /// Persisted metadata for this source.
    pub const fn metadata(&self) -> &DirectTableMetadata {
        &self.metadata
    }

    /// Number of logical ORAM blocks produced by this reader.
    pub const fn logical_blocks(&self) -> usize {
        self.metadata.logical_blocks
    }

    /// Fixed payload bytes in each logical ORAM block.
    pub const fn block_payload_bytes(&self) -> usize {
        self.metadata.block_payload_bytes
    }

    /// Read one direct INDEX bin by global bin id.
    pub fn read_bin(&mut self, bin_id: usize) -> Result<Vec<u8>> {
        let location = locate_packed_direct_item(
            self.metadata.total_items,
            self.metadata.items_per_block,
            self.metadata.item_size,
            bin_id,
        )?;
        let block = self.read_block(location.logical_block)?;
        Ok(block[location.byte_range()].to_vec())
    }

    /// Read one packed logical block without changing iterator progress.
    pub fn read_block(&mut self, logical_block: usize) -> Result<Vec<u8>> {
        if logical_block >= self.metadata.logical_blocks {
            return Err(Error::InvalidInput(format!(
                "logical block {} out of range {}",
                logical_block, self.metadata.logical_blocks
            )));
        }
        let start_item = logical_block * self.metadata.items_per_block;
        let remaining = self.metadata.total_items - start_item;
        let items_to_encode = remaining.min(self.metadata.items_per_block);
        let mut payload = vec![0u8; self.metadata.block_payload_bytes];
        for item_offset in 0..items_to_encode {
            let bin_id = start_item + item_offset;
            let byte_start = item_offset * self.metadata.item_size;
            let byte_end = byte_start + self.metadata.item_size;
            self.encode_bin(bin_id, &mut payload[byte_start..byte_end])?;
        }
        Ok(payload)
    }

    fn encode_bin(&self, bin_id: usize, out: &mut [u8]) -> Result<()> {
        if out.len() != self.metadata.item_size {
            return Err(Error::InvalidInput(format!(
                "direct index bin output len {} != expected {}",
                out.len(),
                self.metadata.item_size
            )));
        }
        let base = bin_id
            .checked_mul(self.info.slots_per_bin)
            .ok_or_else(|| Error::InvalidInput("direct index bin offset overflow".into()))?;
        for slot_idx in 0..self.info.slots_per_bin {
            let entry_idx = self.placement[base + slot_idx];
            let slot_start = slot_idx * DIRECT_INDEX_SLOT_SIZE;
            let slot = &mut out[slot_start..slot_start + DIRECT_INDEX_SLOT_SIZE];
            if entry_idx == EMPTY_SLOT {
                slot.fill(0);
            } else {
                let record = index_record(&self.mmap, entry_idx as usize)?;
                slot[0] = 1;
                slot[1..].copy_from_slice(record);
            }
        }
        Ok(())
    }
}

impl Iterator for DirectIndexPackedBlockReader {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_block >= self.metadata.logical_blocks {
            return None;
        }
        let block_idx = self.next_block;
        self.next_block += 1;
        Some(self.read_block(block_idx))
    }
}

impl TrustedBlockSource for DirectIndexPackedBlockReader {
    fn logical_blocks(&self) -> usize {
        self.logical_blocks()
    }

    fn block_size(&self) -> usize {
        self.block_payload_bytes()
    }

    fn read_block(&mut self, logical_id: usize) -> Result<Vec<u8>> {
        DirectIndexPackedBlockReader::read_block(self, logical_id)
    }
}

/// Streaming source for direct CHUNK logical blocks.
pub struct DirectChunkPackedBlockReader {
    metadata: DirectTableMetadata,
    next_block: usize,
    mmap: Mmap,
}

impl DirectChunkPackedBlockReader {
    /// Open a direct CHUNK array as a packed ORAM source.
    pub fn open(info: DirectTableInfo, items_per_block: usize) -> Result<Self> {
        if info.level != DirectLevel::Chunk {
            return Err(Error::InvalidInput(
                "DirectChunkPackedBlockReader requires chunk table info".into(),
            ));
        }
        let file = File::open(&info.path)?;
        // SAFETY: the file is opened read-only and is not mutated by this reader.
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        Ok(Self {
            metadata: DirectTableMetadata::from_info(&info, items_per_block)?,
            next_block: 0,
            mmap,
        })
    }

    /// Persisted metadata for this source.
    pub const fn metadata(&self) -> &DirectTableMetadata {
        &self.metadata
    }

    /// Number of logical ORAM blocks produced by this reader.
    pub const fn logical_blocks(&self) -> usize {
        self.metadata.logical_blocks
    }

    /// Fixed payload bytes in each logical ORAM block.
    pub const fn block_payload_bytes(&self) -> usize {
        self.metadata.block_payload_bytes
    }

    /// Read one direct chunk by chunk id.
    pub fn read_chunk(&mut self, chunk_id: usize) -> Result<Vec<u8>> {
        let location = locate_packed_direct_item(
            self.metadata.total_items,
            self.metadata.items_per_block,
            self.metadata.item_size,
            chunk_id,
        )?;
        let block = self.read_block(location.logical_block)?;
        Ok(block[location.byte_range()].to_vec())
    }

    /// Read one packed logical block without changing iterator progress.
    pub fn read_block(&mut self, logical_block: usize) -> Result<Vec<u8>> {
        if logical_block >= self.metadata.logical_blocks {
            return Err(Error::InvalidInput(format!(
                "logical block {} out of range {}",
                logical_block, self.metadata.logical_blocks
            )));
        }
        let start_item = logical_block * self.metadata.items_per_block;
        let remaining = self.metadata.total_items - start_item;
        let items_to_read = remaining.min(self.metadata.items_per_block);
        let bytes_to_read = items_to_read * self.metadata.item_size;
        let offset = start_item * self.metadata.item_size;
        let end = offset + bytes_to_read;
        if end > self.mmap.len() {
            return Err(Error::InvalidInput(format!(
                "direct chunk logical block {} reaches byte {} past mapped file length {}",
                logical_block,
                end,
                self.mmap.len()
            )));
        }
        let mut payload = vec![0u8; self.metadata.block_payload_bytes];
        payload[..bytes_to_read].copy_from_slice(&self.mmap[offset..end]);
        Ok(payload)
    }
}

impl Iterator for DirectChunkPackedBlockReader {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_block >= self.metadata.logical_blocks {
            return None;
        }
        let block_idx = self.next_block;
        self.next_block += 1;
        Some(self.read_block(block_idx))
    }
}

impl TrustedBlockSource for DirectChunkPackedBlockReader {
    fn logical_blocks(&self) -> usize {
        self.logical_blocks()
    }

    fn block_size(&self) -> usize {
        self.block_payload_bytes()
    }

    fn read_block(&mut self, logical_id: usize) -> Result<Vec<u8>> {
        DirectChunkPackedBlockReader::read_block(self, logical_id)
    }
}

/// Result of a direct INDEX lookup through Circuit ORAM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectIndexLookup {
    /// Queried script hash.
    pub script_hash: [u8; DIRECT_SCRIPT_HASH_SIZE],
    /// Whether the script hash was present.
    pub found: bool,
    /// Start chunk id when present.
    pub start_chunk_id: u32,
    /// Number of chunks when present.
    pub num_chunks: u8,
    /// Candidate direct INDEX bins read.
    pub candidate_bins: Vec<usize>,
    /// ORAM logical blocks touched.
    pub logical_blocks: Vec<usize>,
    /// Public eviction paths drained after reads.
    pub drained_evictions: u64,
}

/// Reader that resolves script hashes through a direct INDEX Circuit ORAM.
pub struct CircuitDirectIndexReader<M, P> {
    metadata: DirectTableMetadata,
    oram: CircuitOram<M, P>,
}

impl<M: PageStore, P: PageStore> CircuitDirectIndexReader<M, P> {
    /// Wrap an opened Circuit ORAM controller for a direct INDEX image.
    pub fn new(metadata: DirectTableMetadata, oram: CircuitOram<M, P>) -> Result<Self> {
        metadata.validate()?;
        if metadata.level != DirectLevel::Index {
            return Err(Error::InvalidInput(
                "CircuitDirectIndexReader requires index metadata".into(),
            ));
        }
        validate_oram_dimensions(&metadata, &oram)?;
        Ok(Self { metadata, oram })
    }

    /// Borrow the underlying Circuit ORAM controller.
    pub const fn oram(&self) -> &CircuitOram<M, P> {
        &self.oram
    }

    /// Mutably borrow the underlying Circuit ORAM controller.
    pub fn oram_mut(&mut self) -> &mut CircuitOram<M, P> {
        &mut self.oram
    }

    /// Consume the reader and return the underlying Circuit ORAM controller.
    pub fn into_oram(self) -> CircuitOram<M, P> {
        self.oram
    }

    /// Read all candidate direct INDEX bins and return the matched record, if any.
    pub fn lookup(
        &mut self,
        script_hash: [u8; DIRECT_SCRIPT_HASH_SIZE],
        drain_per_read: u64,
    ) -> Result<DirectIndexLookup> {
        let candidate_bins = direct_index_candidate_bins(
            &script_hash,
            self.metadata.seed,
            self.metadata.hash_fns,
            self.metadata.total_items,
        )?;
        let mut found = 0u8;
        let mut start_chunk_id = 0u32;
        let mut num_chunks = 0u8;
        let mut logical_blocks = Vec::with_capacity(candidate_bins.len());
        let mut drained_evictions = 0u64;

        for &bin_id in &candidate_bins {
            let location = locate_packed_direct_item(
                self.metadata.total_items,
                self.metadata.items_per_block,
                self.metadata.item_size,
                bin_id,
            )?;
            let block = self.oram.read(location.logical_block as u64)?;
            logical_blocks.push(location.logical_block);
            let bin = &block[location.byte_range()];
            select_index_record_from_bin(
                bin,
                self.metadata.slots_per_bin,
                &script_hash,
                &mut found,
                &mut start_chunk_id,
                &mut num_chunks,
            )?;
            drained_evictions += self.oram.drain_evictions(drain_per_read)?;
        }

        Ok(DirectIndexLookup {
            script_hash,
            found: found == 1,
            start_chunk_id,
            num_chunks,
            candidate_bins,
            logical_blocks,
            drained_evictions,
        })
    }
}

/// Result of reading one direct chunk through Circuit ORAM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectChunkRead {
    /// Original chunk id.
    pub chunk_id: usize,
    /// ORAM logical block id read to recover this chunk.
    pub logical_block: usize,
    /// Byte offset inside the packed ORAM block.
    pub byte_offset: usize,
    /// Chunk payload bytes.
    pub payload: Vec<u8>,
    /// Public eviction paths drained after the read.
    pub drained_evictions: u64,
}

/// Reader that exposes direct CHUNK ids through a Circuit ORAM image.
pub struct CircuitDirectChunkReader<M, P> {
    metadata: DirectTableMetadata,
    oram: CircuitOram<M, P>,
}

impl<M: PageStore, P: PageStore> CircuitDirectChunkReader<M, P> {
    /// Wrap an opened Circuit ORAM controller for a direct CHUNK image.
    pub fn new(metadata: DirectTableMetadata, oram: CircuitOram<M, P>) -> Result<Self> {
        metadata.validate()?;
        if metadata.level != DirectLevel::Chunk {
            return Err(Error::InvalidInput(
                "CircuitDirectChunkReader requires chunk metadata".into(),
            ));
        }
        validate_oram_dimensions(&metadata, &oram)?;
        Ok(Self { metadata, oram })
    }

    /// Borrow the underlying Circuit ORAM controller.
    pub const fn oram(&self) -> &CircuitOram<M, P> {
        &self.oram
    }

    /// Mutably borrow the underlying Circuit ORAM controller.
    pub fn oram_mut(&mut self) -> &mut CircuitOram<M, P> {
        &mut self.oram
    }

    /// Consume the reader and return the underlying Circuit ORAM controller.
    pub fn into_oram(self) -> CircuitOram<M, P> {
        self.oram
    }

    /// Read one direct chunk and drain public eviction debt.
    pub fn read_chunk(
        &mut self,
        chunk_id: usize,
        drain_per_access: u64,
    ) -> Result<DirectChunkRead> {
        let location = locate_packed_direct_item(
            self.metadata.total_items,
            self.metadata.items_per_block,
            self.metadata.item_size,
            chunk_id,
        )?;
        let block = self.oram.read(location.logical_block as u64)?;
        let payload = block[location.byte_range()].to_vec();
        let drained_evictions = self.oram.drain_evictions(drain_per_access)?;

        Ok(DirectChunkRead {
            chunk_id,
            logical_block: location.logical_block,
            byte_offset: location.byte_offset,
            payload,
            drained_evictions,
        })
    }
}

fn validate_oram_dimensions<M: PageStore, P: PageStore>(
    metadata: &DirectTableMetadata,
    oram: &CircuitOram<M, P>,
) -> Result<()> {
    if oram.params().logical_blocks != metadata.logical_blocks {
        return Err(Error::InvalidInput(format!(
            "direct {} ORAM logical_blocks {} != metadata logical_blocks {}",
            metadata.level,
            oram.params().logical_blocks,
            metadata.logical_blocks
        )));
    }
    if oram.params().block_size != metadata.block_payload_bytes {
        return Err(Error::InvalidInput(format!(
            "direct {} ORAM block_size {} != metadata block_payload_bytes {}",
            metadata.level,
            oram.params().block_size,
            metadata.block_payload_bytes
        )));
    }
    Ok(())
}

fn compute_direct_index_bins(
    records: usize,
    slots_per_bin: usize,
    load_factor: f64,
) -> Result<usize> {
    if records == 0 {
        return Ok(0);
    }
    let bins = ((records as f64) / (slots_per_bin as f64 * load_factor)).ceil() as usize;
    Ok(bins.max(1))
}

fn build_direct_index_placement(info: &DirectTableInfo, mmap: &[u8]) -> Result<Vec<u32>> {
    if info.records > u32::MAX as usize {
        return Err(Error::InvalidInput(format!(
            "direct index records {} exceed u32 placement id range",
            info.records
        )));
    }
    let slot_count = info
        .total_items
        .checked_mul(info.slots_per_bin)
        .ok_or_else(|| Error::InvalidInput("direct index slot count overflow".into()))?;
    let mut placement = vec![EMPTY_SLOT; slot_count];

    for record_idx in 0..info.records {
        insert_index_record(info, mmap, &mut placement, record_idx as u32)?;
    }
    Ok(placement)
}

fn insert_index_record(
    info: &DirectTableInfo,
    mmap: &[u8],
    placement: &mut [u32],
    record_idx: u32,
) -> Result<()> {
    let mut current = record_idx;
    let mut current_bin = first_candidate_bin(info, mmap, current as usize)?;

    if try_place_in_any_candidate(info, mmap, placement, current)? {
        return Ok(());
    }

    for kick in 0..DIRECT_CUCKOO_MAX_KICKS {
        let slot = eviction_slot(info.seed, current, kick, info.slots_per_bin);
        let offset = current_bin * info.slots_per_bin + slot;
        let evicted = placement[offset];
        placement[offset] = current;
        if evicted == EMPTY_SLOT {
            return Ok(());
        }

        current = evicted;
        if try_place_in_any_candidate_except(info, mmap, placement, current, current_bin)? {
            return Ok(());
        }
        current_bin = alternate_candidate_bin(info, mmap, current as usize, current_bin, kick + 1)?;
    }

    Err(Error::InvalidInput(format!(
        "direct index cuckoo insertion failed after {} kicks; records={} bins={} slots_per_bin={} hash_fns={} load_factor={:.4}",
        DIRECT_CUCKOO_MAX_KICKS,
        info.records,
        info.total_items,
        info.slots_per_bin,
        info.hash_fns,
        info.load_factor
    )))
}

fn try_place_in_any_candidate(
    info: &DirectTableInfo,
    mmap: &[u8],
    placement: &mut [u32],
    record_idx: u32,
) -> Result<bool> {
    let record = index_record(mmap, record_idx as usize)?;
    let script_hash = script_hash_from_record(record);
    for bin in direct_index_candidate_bins(script_hash, info.seed, info.hash_fns, info.total_items)?
    {
        if place_in_empty_slot(placement, bin, info.slots_per_bin, record_idx) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn try_place_in_any_candidate_except(
    info: &DirectTableInfo,
    mmap: &[u8],
    placement: &mut [u32],
    record_idx: u32,
    except_bin: usize,
) -> Result<bool> {
    let record = index_record(mmap, record_idx as usize)?;
    let script_hash = script_hash_from_record(record);
    for bin in direct_index_candidate_bins(script_hash, info.seed, info.hash_fns, info.total_items)?
    {
        if bin == except_bin {
            continue;
        }
        if place_in_empty_slot(placement, bin, info.slots_per_bin, record_idx) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn place_in_empty_slot(
    placement: &mut [u32],
    bin: usize,
    slots_per_bin: usize,
    record_idx: u32,
) -> bool {
    let base = bin * slots_per_bin;
    for slot in &mut placement[base..base + slots_per_bin] {
        if *slot == EMPTY_SLOT {
            *slot = record_idx;
            return true;
        }
    }
    false
}

fn first_candidate_bin(info: &DirectTableInfo, mmap: &[u8], record_idx: usize) -> Result<usize> {
    let record = index_record(mmap, record_idx)?;
    let script_hash = script_hash_from_record(record);
    let bins =
        direct_index_candidate_bins(script_hash, info.seed, info.hash_fns, info.total_items)?;
    Ok(bins[0])
}

fn alternate_candidate_bin(
    info: &DirectTableInfo,
    mmap: &[u8],
    record_idx: usize,
    current_bin: usize,
    kick: usize,
) -> Result<usize> {
    let record = index_record(mmap, record_idx)?;
    let script_hash = script_hash_from_record(record);
    let bins =
        direct_index_candidate_bins(script_hash, info.seed, info.hash_fns, info.total_items)?;
    if let Some(pos) = bins.iter().position(|&bin| bin == current_bin) {
        Ok(bins[(pos + 1) % bins.len()])
    } else {
        Ok(bins[kick % bins.len()])
    }
}

fn eviction_slot(seed: u64, record_idx: u32, kick: usize, slots_per_bin: usize) -> usize {
    let h = splitmix64(
        seed ^ (record_idx as u64).wrapping_add((kick as u64).wrapping_mul(GOLDEN_RATIO)),
    );
    (h as usize) % slots_per_bin
}

/// Direct INDEX candidate bins for one script hash.
pub fn direct_index_candidate_bins(
    script_hash: &[u8],
    seed: u64,
    hash_fns: usize,
    bins: usize,
) -> Result<Vec<usize>> {
    if script_hash.len() != DIRECT_SCRIPT_HASH_SIZE {
        return Err(Error::InvalidInput(format!(
            "script_hash len {} != {}",
            script_hash.len(),
            DIRECT_SCRIPT_HASH_SIZE
        )));
    }
    if hash_fns == 0 {
        return Err(Error::InvalidInput("hash_fns must be > 0".into()));
    }
    if bins == 0 {
        return Err(Error::InvalidInput("bins must be > 0".into()));
    }

    let mut out = Vec::with_capacity(hash_fns);
    let mut nonce = 0usize;
    while out.len() < hash_fns {
        let key = derive_direct_cuckoo_key(seed, nonce);
        let bin = direct_cuckoo_hash(script_hash, key, bins);
        if !out.contains(&bin) {
            out.push(bin);
        }
        nonce += 1;
    }
    Ok(out)
}

fn derive_direct_cuckoo_key(seed: u64, hash_fn: usize) -> u64 {
    splitmix64(seed.wrapping_add((hash_fn as u64).wrapping_mul(CUCKOO_KEY_MIX)))
}

fn direct_cuckoo_hash(script_hash: &[u8], key: u64, bins: usize) -> usize {
    let mut h = sh_a(script_hash) ^ key;
    h ^= sh_b(script_hash);
    h = splitmix64(h ^ sh_c(script_hash));
    (h % bins as u64) as usize
}

fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

fn sh_a(script_hash: &[u8]) -> u64 {
    u64::from_le_bytes(script_hash[0..8].try_into().expect("slice len"))
}

fn sh_b(script_hash: &[u8]) -> u64 {
    u64::from_le_bytes(script_hash[8..16].try_into().expect("slice len"))
}

fn sh_c(script_hash: &[u8]) -> u64 {
    u32::from_le_bytes(script_hash[16..20].try_into().expect("slice len")) as u64
}

fn index_record(mmap: &[u8], record_idx: usize) -> Result<&[u8]> {
    let start = record_idx
        .checked_mul(DIRECT_INDEX_INPUT_RECORD_SIZE)
        .ok_or_else(|| Error::InvalidInput("direct index record offset overflow".into()))?;
    let end = start + DIRECT_INDEX_INPUT_RECORD_SIZE;
    if end > mmap.len() {
        return Err(Error::InvalidInput(format!(
            "direct index record {} reaches byte {} past mapped file length {}",
            record_idx,
            end,
            mmap.len()
        )));
    }
    Ok(&mmap[start..end])
}

fn script_hash_from_record(record: &[u8]) -> &[u8] {
    &record[..DIRECT_SCRIPT_HASH_SIZE]
}

fn select_index_record_from_bin(
    bin: &[u8],
    slots_per_bin: usize,
    script_hash: &[u8; DIRECT_SCRIPT_HASH_SIZE],
    found: &mut u8,
    start_chunk_id: &mut u32,
    num_chunks: &mut u8,
) -> Result<()> {
    if bin.len() != slots_per_bin * DIRECT_INDEX_SLOT_SIZE {
        return Err(Error::InvalidInput(format!(
            "direct index bin len {} != expected {}",
            bin.len(),
            slots_per_bin * DIRECT_INDEX_SLOT_SIZE
        )));
    }
    for slot_idx in 0..slots_per_bin {
        let slot_start = slot_idx * DIRECT_INDEX_SLOT_SIZE;
        let slot = &bin[slot_start..slot_start + DIRECT_INDEX_SLOT_SIZE];
        let occupied = ct::choice_from_bool(slot[0] == 1);
        let mut diff = 0u8;
        for i in 0..DIRECT_SCRIPT_HASH_SIZE {
            diff |= slot[1 + i] ^ script_hash[i];
        }
        let is_match = ct::and(occupied, ct::is_zero_u64(diff as u64));
        let select = ct::and(is_match, ct::not(*found));
        let candidate_start =
            u32::from_le_bytes(slot[21..25].try_into().expect("direct index slot"));
        let candidate_chunks = slot[25];
        ct::cmov_u8(found, 1, select);
        ct::cmov_u32(start_chunk_id, candidate_start, select);
        ct::cmov_u8(num_chunks, candidate_chunks, select);
    }
    Ok(())
}

fn checked_next_power_of_two(value: usize) -> Result<usize> {
    value.checked_next_power_of_two().ok_or_else(|| {
        Error::InvalidParams(format!("value {value} exceeds usize next_power_of_two"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuit_meta_page_bytes, circuit_payload_page_bytes, MemPageStore};
    use std::io::Write as _;

    #[test]
    fn direct_index_source_finds_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DIRECT_INDEX_INPUT_FILE);
        write_index_records(&path, 32);
        let info = DirectTableInfo::from_index_file(&path, 4, 2, 0.80, 7).unwrap();
        let mut source = DirectIndexPackedBlockReader::build(info, 3).unwrap();

        for record_idx in [0usize, 7, 31] {
            let record = read_test_record(&path, record_idx);
            let script_hash: [u8; DIRECT_SCRIPT_HASH_SIZE] =
                record[..DIRECT_SCRIPT_HASH_SIZE].try_into().unwrap();
            let bins = direct_index_candidate_bins(
                &script_hash,
                source.metadata.seed,
                source.metadata.hash_fns,
                source.metadata.total_items,
            )
            .unwrap();
            let mut matched = false;
            for bin in bins {
                let payload = source.read_bin(bin).unwrap();
                for slot in payload.chunks_exact(DIRECT_INDEX_SLOT_SIZE) {
                    if slot[0] == 1 && slot[1..21] == script_hash {
                        assert_eq!(&slot[1..], record.as_slice());
                        matched = true;
                    }
                }
            }
            assert!(matched, "record {record_idx} should be in a candidate bin");
        }
    }

    #[test]
    fn direct_chunk_source_reads_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DIRECT_CHUNKS_INPUT_FILE);
        write_chunks(&path, 11);
        let info = DirectTableInfo::from_chunks_file(&path).unwrap();
        let mut source = DirectChunkPackedBlockReader::open(info, 4).unwrap();

        assert_eq!(source.logical_blocks(), 3);
        assert_eq!(
            source.read_chunk(0).unwrap(),
            vec![0u8; DIRECT_CHUNK_RECORD_SIZE]
        );
        assert_eq!(
            source.read_chunk(7).unwrap(),
            vec![7u8; DIRECT_CHUNK_RECORD_SIZE]
        );
        assert_eq!(
            source.read_chunk(10).unwrap(),
            vec![10u8; DIRECT_CHUNK_RECORD_SIZE]
        );
        assert!(source.read_chunk(11).is_err());
    }

    #[test]
    fn circuit_direct_readers_match_sources() {
        let dir = tempfile::tempdir().unwrap();
        let index_path = dir.path().join(DIRECT_INDEX_INPUT_FILE);
        let chunk_path = dir.path().join(DIRECT_CHUNKS_INPUT_FILE);
        write_index_records(&index_path, 40);
        write_chunks(&chunk_path, 17);

        let index_info = DirectTableInfo::from_index_file(&index_path, 4, 2, 0.80, 11).unwrap();
        let index_source = DirectIndexPackedBlockReader::build(index_info, 3).unwrap();
        let index_metadata = index_source.metadata().clone();
        let index_params = OramParams::with_leaves(
            index_source.logical_blocks(),
            index_source.block_payload_bytes(),
            index_source.logical_blocks().max(2).next_power_of_two(),
        )
        .unwrap()
        .with_bucket_size(2)
        .unwrap()
        .with_stash_capacity(128)
        .unwrap();
        let index_meta_store = MemPageStore::new(
            index_params.bucket_count(),
            circuit_meta_page_bytes(index_params.bucket_size),
        )
        .unwrap();
        let index_payload_store = MemPageStore::new(
            index_params.bucket_count(),
            circuit_payload_page_bytes(index_params.bucket_size, index_params.block_size),
        )
        .unwrap();
        let index_oram = CircuitOram::build_trusted_from_source(
            index_params,
            index_meta_store,
            index_payload_store,
            index_source,
            [41; 32],
        )
        .unwrap();
        let mut index_reader = CircuitDirectIndexReader::new(index_metadata, index_oram).unwrap();
        let record = read_test_record(&index_path, 19);
        let script_hash: [u8; DIRECT_SCRIPT_HASH_SIZE] =
            record[..DIRECT_SCRIPT_HASH_SIZE].try_into().unwrap();
        let lookup = index_reader.lookup(script_hash, 2).unwrap();
        assert!(lookup.found);
        assert_eq!(
            lookup.start_chunk_id,
            u32::from_le_bytes(record[20..24].try_into().unwrap())
        );
        assert_eq!(lookup.num_chunks, record[24]);

        let chunk_info = DirectTableInfo::from_chunks_file(&chunk_path).unwrap();
        let chunk_source = DirectChunkPackedBlockReader::open(chunk_info, 5).unwrap();
        let chunk_metadata = chunk_source.metadata().clone();
        let chunk_params = OramParams::with_leaves(
            chunk_source.logical_blocks(),
            chunk_source.block_payload_bytes(),
            chunk_source.logical_blocks().max(2).next_power_of_two(),
        )
        .unwrap()
        .with_bucket_size(2)
        .unwrap()
        .with_stash_capacity(128)
        .unwrap();
        let chunk_meta_store = MemPageStore::new(
            chunk_params.bucket_count(),
            circuit_meta_page_bytes(chunk_params.bucket_size),
        )
        .unwrap();
        let chunk_payload_store = MemPageStore::new(
            chunk_params.bucket_count(),
            circuit_payload_page_bytes(chunk_params.bucket_size, chunk_params.block_size),
        )
        .unwrap();
        let chunk_oram = CircuitOram::build_trusted_from_source(
            chunk_params,
            chunk_meta_store,
            chunk_payload_store,
            chunk_source,
            [42; 32],
        )
        .unwrap();
        let mut chunk_reader = CircuitDirectChunkReader::new(chunk_metadata, chunk_oram).unwrap();
        let got = chunk_reader.read_chunk(16, 2).unwrap();
        assert_eq!(got.payload, vec![16u8; DIRECT_CHUNK_RECORD_SIZE]);
    }

    fn write_index_records(path: &Path, records: usize) {
        let mut file = File::create(path).unwrap();
        for idx in 0..records {
            let mut record = [0u8; DIRECT_INDEX_INPUT_RECORD_SIZE];
            for (byte_idx, byte) in record[..DIRECT_SCRIPT_HASH_SIZE].iter_mut().enumerate() {
                *byte = splitmix64(((idx * 257 + byte_idx) as u64) ^ 0xa5).to_le_bytes()[0];
            }
            let start_chunk = (idx as u32) * 3;
            record[20..24].copy_from_slice(&start_chunk.to_le_bytes());
            record[24] = (idx % 8 + 1) as u8;
            file.write_all(&record).unwrap();
        }
    }

    fn write_chunks(path: &Path, chunks: usize) {
        let mut file = File::create(path).unwrap();
        for idx in 0..chunks {
            file.write_all(&[idx as u8; DIRECT_CHUNK_RECORD_SIZE])
                .unwrap();
        }
    }

    fn read_test_record(path: &Path, record_idx: usize) -> Vec<u8> {
        let bytes = fs::read(path).unwrap();
        let start = record_idx * DIRECT_INDEX_INPUT_RECORD_SIZE;
        bytes[start..start + DIRECT_INDEX_INPUT_RECORD_SIZE].to_vec()
    }
}
