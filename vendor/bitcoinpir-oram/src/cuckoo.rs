//! BitcoinPIR DPF/Harmony cuckoo-table sizing helpers.
//!
//! This module intentionally mirrors only the stable on-disk layout needed by
//! the ORAM adapter. OnionPIR artifacts have a different encoding and are out
//! of scope for this crate.

use crate::{
    CircuitOram, Error, OramBlock, OramParams, PageStore, Result, TrustedBlockSource, AEAD_OVERHEAD,
};
use memmap2::{Mmap, MmapOptions};
use std::{
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

/// Filename of the shared DPF/Harmony INDEX cuckoo table.
pub const INDEX_CUCKOO_FILE: &str = "batch_pir_cuckoo.bin";
/// Filename of the shared DPF/Harmony CHUNK cuckoo table.
pub const CHUNK_CUCKOO_FILE: &str = "chunk_pir_cuckoo.bin";

const INDEX_MAGIC: u64 = 0xBA7C_C000_C000_0004;
const CHUNK_MAGIC: u64 = 0xBA7C_C000_C000_0002;
const ANCHOR_MAGIC_SNAPSHOT_XOR: u64 = 0x0000_0001_0000_0000;
const ANCHOR_MAGIC_DELTA_XOR: u64 = 0x0000_0002_0000_0000;
const CHAIN_ANCHOR_BYTES: usize = 36;
const DELTA_ANCHOR_BYTES: usize = 72;

/// BitcoinPIR cuckoo table level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CuckooLevel {
    /// Scripthash -> chunk range index table.
    Index,
    /// Chunk id -> UTXO chunk data table.
    Chunk,
}

impl CuckooLevel {
    /// Human-readable lowercase label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Index => "index",
            Self::Chunk => "chunk",
        }
    }

    /// Cuckoo filename under a BitcoinPIR DB directory.
    pub const fn filename(self) -> &'static str {
        match self {
            Self::Index => INDEX_CUCKOO_FILE,
            Self::Chunk => CHUNK_CUCKOO_FILE,
        }
    }

    const fn base_magic(self) -> u64 {
        match self {
            Self::Index => INDEX_MAGIC,
            Self::Chunk => CHUNK_MAGIC,
        }
    }

    const fn base_header_size(self) -> usize {
        match self {
            Self::Index => 40,
            Self::Chunk => 32,
        }
    }

    const fn slot_size(self) -> usize {
        match self {
            Self::Index => 13,
            Self::Chunk => 44,
        }
    }
}

impl fmt::Display for CuckooLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Chain-anchor variant encoded in a Phase-C cuckoo header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CuckooAnchorKind {
    /// Legacy pre-anchor header.
    Legacy,
    /// Snapshot anchor follows the legacy header.
    Snapshot,
    /// Delta anchor follows the legacy header.
    Delta,
}

impl CuckooAnchorKind {
    /// Bytes appended after the legacy header.
    pub const fn extra_header_bytes(self) -> usize {
        match self {
            Self::Legacy => 0,
            Self::Snapshot => CHAIN_ANCHOR_BYTES,
            Self::Delta => DELTA_ANCHOR_BYTES,
        }
    }
}

impl fmt::Display for CuckooAnchorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Legacy => "legacy",
            Self::Snapshot => "snapshot",
            Self::Delta => "delta",
        })
    }
}

/// Parsed metadata for one DPF/Harmony cuckoo table file.
#[derive(Clone, Debug)]
pub struct CuckooTableInfo {
    /// INDEX or CHUNK.
    pub level: CuckooLevel,
    /// File path.
    pub path: PathBuf,
    /// Total file size on disk.
    pub file_bytes: u64,
    /// Header magic as stored on disk.
    pub magic: u64,
    /// Anchor kind inferred from the magic.
    pub anchor_kind: CuckooAnchorKind,
    /// Offset where group table data begins.
    pub data_offset: usize,
    /// Number of PBC groups.
    pub k: usize,
    /// Slots per cuckoo bin.
    pub slots_per_bin: usize,
    /// Bins per PBC group.
    pub bins_per_table: usize,
    /// Number of PBC item-to-group hashes.
    pub num_hashes: usize,
    /// Master cuckoo seed from the header.
    pub master_seed: u64,
    /// INDEX tag seed, if present.
    pub tag_seed: Option<u64>,
    /// Fixed bytes per slot for this level.
    pub slot_size: usize,
}

impl CuckooTableInfo {
    /// Parse metadata for `level` from a table file.
    pub fn from_file(level: CuckooLevel, path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut file = File::open(path)?;
        let file_bytes = file.metadata()?.len();
        let mut header = [0u8; 40];
        file.read_exact(&mut header[..level.base_header_size()])?;

        let magic = u64::from_le_bytes(header[0..8].try_into().expect("slice len"));
        let anchor_kind = parse_anchor_kind(level, magic)?;
        let data_offset = level.base_header_size() + anchor_kind.extra_header_bytes();
        let k = u32::from_le_bytes(header[8..12].try_into().expect("slice len")) as usize;
        let slots_per_bin =
            u32::from_le_bytes(header[12..16].try_into().expect("slice len")) as usize;
        let bins_per_table =
            u32::from_le_bytes(header[16..20].try_into().expect("slice len")) as usize;
        let num_hashes = u32::from_le_bytes(header[20..24].try_into().expect("slice len")) as usize;
        let master_seed = u64::from_le_bytes(header[24..32].try_into().expect("slice len"));
        let tag_seed = if level == CuckooLevel::Index {
            Some(u64::from_le_bytes(
                header[32..40].try_into().expect("slice len"),
            ))
        } else {
            None
        };

        let info = Self {
            level,
            path: path.to_path_buf(),
            file_bytes,
            magic,
            anchor_kind,
            data_offset,
            k,
            slots_per_bin,
            bins_per_table,
            num_hashes,
            master_seed,
            tag_seed,
            slot_size: level.slot_size(),
        };
        info.validate()?;
        Ok(info)
    }

    /// Parse INDEX and CHUNK tables from a BitcoinPIR DB directory.
    pub fn load_pair(db_dir: impl AsRef<Path>) -> Result<[Self; 2]> {
        let db_dir = db_dir.as_ref();
        Ok([
            Self::from_file(
                CuckooLevel::Index,
                db_dir.join(CuckooLevel::Index.filename()),
            )?,
            Self::from_file(
                CuckooLevel::Chunk,
                db_dir.join(CuckooLevel::Chunk.filename()),
            )?,
        ])
    }

    /// Bytes in one cuckoo bin payload.
    pub const fn bin_size(&self) -> usize {
        self.slots_per_bin * self.slot_size
    }

    /// Total logical bins across all PBC groups.
    pub fn total_bins(&self) -> usize {
        self.k * self.bins_per_table
    }

    /// Bytes in one PBC group's flat table.
    pub fn table_byte_size(&self) -> usize {
        self.bins_per_table * self.bin_size()
    }

    /// Expected file length from header fields.
    pub fn expected_file_bytes(&self) -> usize {
        self.data_offset + self.k * self.table_byte_size()
    }

    fn validate(&self) -> Result<()> {
        if self.k == 0 {
            return Err(Error::InvalidInput(format!(
                "{} cuckoo table has k=0",
                self.level
            )));
        }
        if self.slots_per_bin == 0 {
            return Err(Error::InvalidInput(format!(
                "{} cuckoo table has slots_per_bin=0",
                self.level
            )));
        }
        if self.bins_per_table == 0 {
            return Err(Error::InvalidInput(format!(
                "{} cuckoo table has bins_per_table=0",
                self.level
            )));
        }
        if self.num_hashes == 0 {
            return Err(Error::InvalidInput(format!(
                "{} cuckoo table has num_hashes=0",
                self.level
            )));
        }
        let expected = self.expected_file_bytes() as u64;
        if self.file_bytes != expected {
            return Err(Error::InvalidInput(format!(
                "{} cuckoo file {} has {} bytes, expected {} from header",
                self.level,
                self.path.display(),
                self.file_bytes,
                expected
            )));
        }
        Ok(())
    }
}

/// ORAM sizing options for packing cuckoo bins into logical ORAM blocks.
#[derive(Clone, Copy, Debug)]
pub struct CuckooOramSizing {
    /// Consecutive cuckoo bins packed into one logical ORAM block.
    pub bins_per_block: usize,
    /// Use `next_power_of_two(ceil(logical_blocks / leaf_divisor))` leaves.
    pub leaf_divisor: usize,
    /// Physical Path ORAM bucket size.
    pub bucket_size: usize,
    /// Fixed trusted stash slots.
    pub stash_capacity: usize,
    /// Public top tree levels cached in trusted memory.
    pub cache_levels: usize,
}

impl CuckooOramSizing {
    /// Estimate ORAM sizes for one table.
    pub fn estimate(&self, table: &CuckooTableInfo) -> Result<CuckooOramEstimate> {
        if self.bins_per_block == 0 {
            return Err(Error::InvalidParams("bins_per_block must be > 0".into()));
        }
        if self.leaf_divisor == 0 {
            return Err(Error::InvalidParams("leaf_divisor must be > 0".into()));
        }

        let logical_blocks = table.total_bins().div_ceil(self.bins_per_block);
        let target_leaves = logical_blocks.div_ceil(self.leaf_divisor).max(2);
        let leaves = checked_next_power_of_two(target_leaves)?;
        let block_payload_bytes = table.bin_size() * self.bins_per_block;
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

        Ok(CuckooOramEstimate {
            level: table.level,
            bins_per_block: self.bins_per_block,
            leaf_divisor: self.leaf_divisor,
            total_bins: table.total_bins(),
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

/// Estimated ORAM sizes for one table and one sizing choice.
#[derive(Clone, Debug)]
pub struct CuckooOramEstimate {
    /// INDEX or CHUNK.
    pub level: CuckooLevel,
    /// Cuckoo bins per logical ORAM block.
    pub bins_per_block: usize,
    /// Leaf divisor.
    pub leaf_divisor: usize,
    /// Total cuckoo bins across all PBC groups.
    pub total_bins: usize,
    /// Logical ORAM block count.
    pub logical_blocks: usize,
    /// Payload bytes in one logical ORAM block.
    pub block_payload_bytes: usize,
    /// Physical Path ORAM bucket size.
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

/// Streaming reader that packs consecutive cuckoo bins into ORAM logical blocks.
pub struct CuckooPackedBlockReader {
    table: CuckooTableInfo,
    bins_per_block: usize,
    logical_blocks: usize,
    block_payload_bytes: usize,
    next_block: usize,
    mmap: Mmap,
}

impl CuckooPackedBlockReader {
    /// Open a packed block reader for one DPF/Harmony cuckoo table.
    pub fn open(table: CuckooTableInfo, bins_per_block: usize) -> Result<Self> {
        if bins_per_block == 0 {
            return Err(Error::InvalidInput("bins_per_block must be > 0".into()));
        }
        let file = File::open(&table.path)?;
        // SAFETY: the table file is opened read-only and this process never
        // mutates it while the reader is alive. The parsed header validated the
        // file length before we create slices from the mapping.
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        let logical_blocks = table.total_bins().div_ceil(bins_per_block);
        let block_payload_bytes = table.bin_size() * bins_per_block;
        Ok(Self {
            table,
            bins_per_block,
            logical_blocks,
            block_payload_bytes,
            next_block: 0,
            mmap,
        })
    }

    /// Number of logical ORAM blocks produced by this reader.
    pub const fn logical_blocks(&self) -> usize {
        self.logical_blocks
    }

    /// Fixed payload bytes in each logical ORAM block.
    pub const fn block_payload_bytes(&self) -> usize {
        self.block_payload_bytes
    }

    /// Read one original cuckoo bin payload by global bin id.
    pub fn read_bin(&mut self, bin_id: usize) -> Result<Vec<u8>> {
        let location = locate_packed_cuckoo_bin(
            self.table.total_bins(),
            self.bins_per_block,
            self.table.bin_size(),
            bin_id,
        )?;
        let block = self.read_block(location.logical_block)?;
        Ok(block[location.byte_range()].to_vec())
    }

    /// Read one packed logical block without changing iterator progress.
    pub fn read_block(&mut self, logical_block: usize) -> Result<Vec<u8>> {
        if logical_block >= self.logical_blocks {
            return Err(Error::InvalidInput(format!(
                "logical block {} out of range {}",
                logical_block, self.logical_blocks
            )));
        }

        let start_bin = logical_block * self.bins_per_block;
        let remaining_bins = self.table.total_bins() - start_bin;
        let bins_to_read = remaining_bins.min(self.bins_per_block);
        let bytes_to_read = bins_to_read * self.table.bin_size();
        let offset = self.table.data_offset + start_bin * self.table.bin_size();
        let end = offset + bytes_to_read;
        if end > self.mmap.len() {
            return Err(Error::InvalidInput(format!(
                "logical block {} reaches byte {} past mapped file length {}",
                logical_block,
                end,
                self.mmap.len()
            )));
        }
        let mut payload = vec![0u8; self.block_payload_bytes];
        payload[..bytes_to_read].copy_from_slice(&self.mmap[offset..end]);
        Ok(payload)
    }
}

/// Location of one cuckoo bin inside a packed ORAM logical block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedCuckooBinLocation {
    /// ORAM logical block id.
    pub logical_block: usize,
    /// Byte offset inside the logical block.
    pub byte_offset: usize,
    /// Number of bytes in the bin.
    pub byte_len: usize,
}

impl PackedCuckooBinLocation {
    fn byte_range(self) -> std::ops::Range<usize> {
        self.byte_offset..self.byte_offset + self.byte_len
    }
}

/// Map a global cuckoo bin id to its packed ORAM block and byte range.
pub fn locate_packed_cuckoo_bin(
    total_bins: usize,
    bins_per_block: usize,
    bin_size: usize,
    bin_id: usize,
) -> Result<PackedCuckooBinLocation> {
    if bins_per_block == 0 {
        return Err(Error::InvalidInput("bins_per_block must be > 0".into()));
    }
    if bin_size == 0 {
        return Err(Error::InvalidInput("bin_size must be > 0".into()));
    }
    if bin_id >= total_bins {
        return Err(Error::InvalidInput(format!(
            "bin_id {} out of range {}",
            bin_id, total_bins
        )));
    }

    let slot_in_block = bin_id % bins_per_block;
    Ok(PackedCuckooBinLocation {
        logical_block: bin_id / bins_per_block,
        byte_offset: slot_in_block * bin_size,
        byte_len: bin_size,
    })
}

/// Result of reading one cuckoo bin through a Circuit ORAM image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitCuckooBinRead {
    /// Original global cuckoo bin id.
    pub bin_id: usize,
    /// ORAM logical block id read to recover this bin.
    pub logical_block: usize,
    /// Byte offset inside the packed ORAM block.
    pub byte_offset: usize,
    /// Cuckoo bin payload bytes.
    pub payload: Vec<u8>,
    /// Public eviction paths drained after the read.
    pub drained_evictions: u64,
}

/// Reader that exposes original cuckoo bins through a packed Circuit ORAM image.
pub struct CircuitCuckooBinReader<M, P> {
    level: CuckooLevel,
    total_bins: usize,
    bins_per_block: usize,
    bin_size: usize,
    oram: CircuitOram<M, P>,
}

impl<M: PageStore, P: PageStore> CircuitCuckooBinReader<M, P> {
    /// Wrap an opened Circuit ORAM controller for the matching cuckoo table.
    pub fn new(
        table: &CuckooTableInfo,
        bins_per_block: usize,
        oram: CircuitOram<M, P>,
    ) -> Result<Self> {
        if bins_per_block == 0 {
            return Err(Error::InvalidInput("bins_per_block must be > 0".into()));
        }
        let expected_logical_blocks = table.total_bins().div_ceil(bins_per_block);
        let expected_block_size = table.bin_size() * bins_per_block;
        if oram.params().logical_blocks != expected_logical_blocks {
            return Err(Error::InvalidInput(format!(
                "{} ORAM logical_blocks {} != packed cuckoo logical_blocks {}",
                table.level,
                oram.params().logical_blocks,
                expected_logical_blocks
            )));
        }
        if oram.params().block_size != expected_block_size {
            return Err(Error::InvalidInput(format!(
                "{} ORAM block_size {} != packed cuckoo block_size {}",
                table.level,
                oram.params().block_size,
                expected_block_size
            )));
        }

        Ok(Self {
            level: table.level,
            total_bins: table.total_bins(),
            bins_per_block,
            bin_size: table.bin_size(),
            oram,
        })
    }

    /// BitcoinPIR cuckoo level served by this reader.
    pub const fn level(&self) -> CuckooLevel {
        self.level
    }

    /// Total original cuckoo bins addressable through this reader.
    pub const fn total_bins(&self) -> usize {
        self.total_bins
    }

    /// Original cuckoo bin payload size.
    pub const fn bin_size(&self) -> usize {
        self.bin_size
    }

    /// Packed bins per ORAM logical block.
    pub const fn bins_per_block(&self) -> usize {
        self.bins_per_block
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

    /// Read one original cuckoo bin and drain public eviction debt.
    pub fn read_bin(
        &mut self,
        bin_id: usize,
        drain_per_access: u64,
    ) -> Result<CircuitCuckooBinRead> {
        let location =
            locate_packed_cuckoo_bin(self.total_bins, self.bins_per_block, self.bin_size, bin_id)?;
        let block = self.oram.read(location.logical_block as u64)?;
        let payload = block[location.byte_range()].to_vec();
        let drained_evictions = self.oram.drain_evictions(drain_per_access)?;

        Ok(CircuitCuckooBinRead {
            bin_id,
            logical_block: location.logical_block,
            byte_offset: location.byte_offset,
            payload,
            drained_evictions,
        })
    }
}

impl Iterator for CuckooPackedBlockReader {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_block >= self.logical_blocks {
            return None;
        }

        let block_idx = self.next_block;
        self.next_block += 1;
        Some(self.read_block(block_idx))
    }
}

impl TrustedBlockSource for CuckooPackedBlockReader {
    fn logical_blocks(&self) -> usize {
        self.logical_blocks()
    }

    fn block_size(&self) -> usize {
        self.block_payload_bytes()
    }

    fn read_block(&mut self, logical_id: usize) -> Result<Vec<u8>> {
        CuckooPackedBlockReader::read_block(self, logical_id)
    }
}

fn parse_anchor_kind(level: CuckooLevel, magic: u64) -> Result<CuckooAnchorKind> {
    let base = level.base_magic();
    if magic == base {
        Ok(CuckooAnchorKind::Legacy)
    } else if magic == (base ^ ANCHOR_MAGIC_SNAPSHOT_XOR) {
        Ok(CuckooAnchorKind::Snapshot)
    } else if magic == (base ^ ANCHOR_MAGIC_DELTA_XOR) {
        Ok(CuckooAnchorKind::Delta)
    } else {
        Err(Error::InvalidInput(format!(
            "{} cuckoo table has unknown magic 0x{magic:016x}",
            level
        )))
    }
}

fn checked_next_power_of_two(value: usize) -> Result<usize> {
    value.checked_next_power_of_two().ok_or_else(|| {
        Error::InvalidParams(format!("value {value} exceeds usize next_power_of_two"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuit_meta_page_bytes, circuit_payload_page_bytes, CircuitOram, MemPageStore};
    use std::io::Write as _;

    fn write_sample_table(path: &Path, level: CuckooLevel, bins_per_table: u32) {
        write_table(path, level, bins_per_table, None);
    }

    fn write_pattern_table(path: &Path, level: CuckooLevel, bins_per_table: u32) {
        write_table(path, level, bins_per_table, Some(pattern_bin));
    }

    fn write_table(
        path: &Path,
        level: CuckooLevel,
        bins_per_table: u32,
        fill_bin: Option<fn(usize, &mut [u8])>,
    ) {
        let k = match level {
            CuckooLevel::Index => 75u32,
            CuckooLevel::Chunk => 80u32,
        };
        let slots = match level {
            CuckooLevel::Index => 4u32,
            CuckooLevel::Chunk => 3u32,
        };
        let mut header = vec![0u8; level.base_header_size()];
        header[0..8].copy_from_slice(&level.base_magic().to_le_bytes());
        header[8..12].copy_from_slice(&k.to_le_bytes());
        header[12..16].copy_from_slice(&slots.to_le_bytes());
        header[16..20].copy_from_slice(&bins_per_table.to_le_bytes());
        header[20..24].copy_from_slice(&3u32.to_le_bytes());
        header[24..32].copy_from_slice(&7u64.to_le_bytes());
        if level == CuckooLevel::Index {
            header[32..40].copy_from_slice(&9u64.to_le_bytes());
        }
        let bin_size = slots as usize * level.slot_size();
        let total_bins = k as usize * bins_per_table as usize;
        let mut body = vec![0u8; total_bins * bin_size];
        if let Some(fill_bin) = fill_bin {
            for bin_idx in 0..total_bins {
                let start = bin_idx * bin_size;
                fill_bin(bin_idx, &mut body[start..start + bin_size]);
            }
        }
        let mut file = File::create(path).unwrap();
        file.write_all(&header).unwrap();
        file.write_all(&body).unwrap();
    }

    fn pattern_bin(bin_idx: usize, out: &mut [u8]) {
        out.fill((bin_idx % 251) as u8);
    }

    #[test]
    fn parses_sample_index_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(INDEX_CUCKOO_FILE);
        write_sample_table(&path, CuckooLevel::Index, 16);

        let info = CuckooTableInfo::from_file(CuckooLevel::Index, &path).unwrap();
        assert_eq!(info.level, CuckooLevel::Index);
        assert_eq!(info.anchor_kind, CuckooAnchorKind::Legacy);
        assert_eq!(info.k, 75);
        assert_eq!(info.slots_per_bin, 4);
        assert_eq!(info.bins_per_table, 16);
        assert_eq!(info.bin_size(), 52);
        assert_eq!(info.tag_seed, Some(9));
    }

    #[test]
    fn estimates_packed_oram_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CHUNK_CUCKOO_FILE);
        write_sample_table(&path, CuckooLevel::Chunk, 32);
        let info = CuckooTableInfo::from_file(CuckooLevel::Chunk, &path).unwrap();

        let estimate = CuckooOramSizing {
            bins_per_block: 8,
            leaf_divisor: 4,
            bucket_size: 4,
            stash_capacity: 128,
            cache_levels: 3,
        }
        .estimate(&info)
        .unwrap();

        assert_eq!(estimate.total_bins, 80 * 32);
        assert_eq!(estimate.logical_blocks, 320);
        assert_eq!(estimate.block_payload_bytes, 1056);
        assert_eq!(estimate.leaves, 128);
        assert_eq!(estimate.height, 8);
        assert_eq!(estimate.cached_pages, 7);
        assert!(estimate.image_aead_bytes > estimate.image_plaintext_bytes);
    }

    #[test]
    fn packed_block_reader_pads_final_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(INDEX_CUCKOO_FILE);
        write_pattern_table(&path, CuckooLevel::Index, 2);
        let info = CuckooTableInfo::from_file(CuckooLevel::Index, &path).unwrap();
        let bin_size = info.bin_size();
        let mut reader = CuckooPackedBlockReader::open(info, 64).unwrap();

        assert_eq!(reader.logical_blocks(), 3);
        assert_eq!(reader.block_payload_bytes(), 64 * bin_size);

        let first = reader.next().unwrap().unwrap();
        assert_eq!(&first[..bin_size], vec![0u8; bin_size]);
        assert_eq!(&first[bin_size..2 * bin_size], vec![1u8; bin_size]);

        let second = reader.next().unwrap().unwrap();
        assert_eq!(&second[..bin_size], vec![64u8; bin_size]);

        let third = reader.next().unwrap().unwrap();
        assert_eq!(&third[..bin_size], vec![128u8; bin_size]);
        assert_eq!(&third[21 * bin_size..22 * bin_size], vec![149u8; bin_size]);
        assert!(third[22 * bin_size..].iter().all(|&byte| byte == 0));
        assert!(reader.next().is_none());
    }

    #[test]
    fn packed_block_random_read_does_not_advance_iterator() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CHUNK_CUCKOO_FILE);
        write_pattern_table(&path, CuckooLevel::Chunk, 2);
        let info = CuckooTableInfo::from_file(CuckooLevel::Chunk, &path).unwrap();
        let bin_size = info.bin_size();
        let mut reader = CuckooPackedBlockReader::open(info, 10).unwrap();

        let random = reader.read_block(2).unwrap();
        assert_eq!(&random[..bin_size], vec![20u8; bin_size]);

        let first = reader.next().unwrap().unwrap();
        assert_eq!(&first[..bin_size], vec![0u8; bin_size]);
    }

    #[test]
    fn locates_packed_cuckoo_bins() {
        assert_eq!(
            locate_packed_cuckoo_bin(25, 8, 52, 0).unwrap(),
            PackedCuckooBinLocation {
                logical_block: 0,
                byte_offset: 0,
                byte_len: 52,
            }
        );
        assert_eq!(
            locate_packed_cuckoo_bin(25, 8, 52, 17).unwrap(),
            PackedCuckooBinLocation {
                logical_block: 2,
                byte_offset: 52,
                byte_len: 52,
            }
        );
        assert!(locate_packed_cuckoo_bin(25, 8, 52, 25).is_err());
        assert!(locate_packed_cuckoo_bin(25, 0, 52, 0).is_err());
    }

    #[test]
    fn packed_block_reader_reads_individual_bins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(INDEX_CUCKOO_FILE);
        write_pattern_table(&path, CuckooLevel::Index, 3);
        let info = CuckooTableInfo::from_file(CuckooLevel::Index, &path).unwrap();
        let bin_size = info.bin_size();
        let mut reader = CuckooPackedBlockReader::open(info, 7).unwrap();

        assert_eq!(reader.read_bin(0).unwrap(), vec![0u8; bin_size]);
        assert_eq!(reader.read_bin(8).unwrap(), vec![8u8; bin_size]);
        assert_eq!(reader.read_bin(224).unwrap(), vec![224u8; bin_size]);
        assert!(reader.read_bin(225).is_err());
    }

    #[test]
    fn circuit_cuckoo_bin_reader_matches_original_bins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(INDEX_CUCKOO_FILE);
        write_pattern_table(&path, CuckooLevel::Index, 3);
        let info = CuckooTableInfo::from_file(CuckooLevel::Index, &path).unwrap();
        let pack = 7;
        let source = CuckooPackedBlockReader::open(info.clone(), pack).unwrap();
        let params = OramParams::with_leaves(
            source.logical_blocks(),
            source.block_payload_bytes(),
            source.logical_blocks().max(2).next_power_of_two(),
        )
        .unwrap()
        .with_bucket_size(2)
        .unwrap()
        .with_stash_capacity(128)
        .unwrap();
        let meta_store = MemPageStore::new(
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
        )
        .unwrap();
        let payload_store = MemPageStore::new(
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
        )
        .unwrap();
        let oram = CircuitOram::build_trusted_from_source(
            params,
            meta_store,
            payload_store,
            source,
            [31; 32],
        )
        .unwrap();
        let mut oram_reader = CircuitCuckooBinReader::new(&info, pack, oram).unwrap();
        let mut original = CuckooPackedBlockReader::open(info, pack).unwrap();

        for bin_id in [0usize, 1, 6, 7, 55, 224] {
            let got = oram_reader.read_bin(bin_id, 2).unwrap();
            let expected = original.read_bin(bin_id).unwrap();
            assert_eq!(got.payload, expected);
            assert_eq!(got.bin_id, bin_id);
            assert_eq!(got.logical_block, bin_id / pack);
            assert_eq!(got.drained_evictions, 2);
        }
        assert_eq!(oram_reader.oram().pending_evictions().unwrap(), 0);
        assert_eq!(oram_reader.oram().stash_len(), 0);
    }
}
