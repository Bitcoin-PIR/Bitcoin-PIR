use std::fmt;

use crate::{Error, GiB, PAGE_SIZE, RegionState, Regions, Result};

pub const SIZE_OF_REGION_METADATA: usize = PAGE_SIZE; // 4096 bytes for atomic writes
const SIZE_OF_U64: usize = std::mem::size_of::<u64>();
const MAX_REGION_ID_LEN: usize = 1024;
const MAX_RESERVED_SIZE: usize = 1024 * GiB; // 1 TiB

/// Serializable metadata for a region (one page, atomic writes).
#[derive(Debug)]
pub struct RegionMetadata {
    start: usize,
    len: usize,
    reserved: usize,
    id: String,
    state: RegionState,
}

impl RegionMetadata {
    fn validate_id(id: &str) {
        assert!(!id.is_empty(), "Region id must not be empty");
        assert!(
            id.len() <= MAX_REGION_ID_LEN,
            "Region id must be <= {} bytes",
            MAX_REGION_ID_LEN
        );
        assert!(
            !id.chars().any(|c| c.is_control()),
            "Region id must not contain control characters"
        );
    }

    pub fn new(id: String, start: usize, len: usize, reserved: usize) -> Self {
        assert!(start.is_multiple_of(PAGE_SIZE));
        assert!(reserved >= PAGE_SIZE);
        assert!(reserved.is_multiple_of(PAGE_SIZE));
        assert!(len <= reserved);
        Self::validate_id(&id);

        Self {
            id,
            len,
            reserved,
            start,
            state: RegionState::new_dirty(), // New region needs write
        }
    }

    #[inline(always)]
    pub fn start(&self) -> usize {
        self.start
    }

    #[inline]
    pub fn set_start(&mut self, start: usize) {
        assert!(start.is_multiple_of(PAGE_SIZE));
        Self::update_value_if_different(&mut self.start, start, &self.state)
    }

    #[allow(clippy::len_without_is_empty)]
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn set_len(&mut self, len: usize) {
        assert!(len <= self.reserved());
        Self::update_value_if_different(&mut self.len, len, &self.state)
    }

    #[inline(always)]
    pub fn reserved(&self) -> usize {
        self.reserved
    }

    #[inline(always)]
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn set_id(&mut self, id: String) {
        Self::validate_id(&id);
        Self::update_value_if_different(&mut self.id, id, &self.state)
    }

    pub fn set_reserved(&mut self, reserved: usize) {
        assert!(self.len() <= reserved);
        assert!(reserved >= PAGE_SIZE);
        assert!(reserved.is_multiple_of(PAGE_SIZE));
        assert!(reserved <= MAX_RESERVED_SIZE);

        Self::update_value_if_different(&mut self.reserved, reserved, &self.state)
    }

    #[inline]
    fn update_value_if_different<T>(own: &mut T, other: T, state: &RegionState)
    where
        T: Eq,
    {
        if own != &other {
            *own = other;
            state.set_needs_write();
        }
    }

    #[inline(always)]
    pub fn remaining(&self) -> usize {
        self.reserved - self.len
    }

    pub(crate) fn write_if_dirty(&self, index: usize, regions: &Regions) {
        let state = &self.state;
        if state.needs_write() {
            regions.write_at(index, &self.to_bytes());
            state.set_needs_flush();
        }
    }

    pub(crate) fn flush(&self, index: usize, regions: &Regions) -> Result<bool> {
        let state = &self.state;
        if state.is_clean() {
            return Ok(false);
        } else if state.needs_write() {
            return Err(Error::RegionMetadataUnwritten);
        }
        // Schedule writeback, then mark clean. Caller ensures durability via sync_data().
        regions
            .mmap()
            .flush_async_range(index * SIZE_OF_REGION_METADATA, SIZE_OF_REGION_METADATA)?;
        state.set_is_clean();
        Ok(true)
    }

    #[inline]
    pub(crate) fn needs_flush(&self) -> bool {
        self.state.needs_flush()
    }

    #[inline]
    pub(crate) fn mark_clean(&self) {
        self.state.set_is_clean();
    }

    fn to_bytes(&self) -> [u8; SIZE_OF_REGION_METADATA] {
        let mut pos = 0;
        let mut bytes = [0u8; SIZE_OF_REGION_METADATA];

        bytes[pos..pos + SIZE_OF_U64].copy_from_slice(&(self.start as u64).to_le_bytes());
        pos += SIZE_OF_U64;

        bytes[pos..pos + SIZE_OF_U64].copy_from_slice(&(self.len as u64).to_le_bytes());
        pos += SIZE_OF_U64;

        bytes[pos..pos + SIZE_OF_U64].copy_from_slice(&(self.reserved as u64).to_le_bytes());
        pos += SIZE_OF_U64;

        let id_bytes = self.id.as_bytes();
        let id_len = id_bytes.len();
        bytes[pos..pos + SIZE_OF_U64].copy_from_slice(&(id_len as u64).to_le_bytes());
        pos += SIZE_OF_U64;

        bytes[pos..pos + id_len].copy_from_slice(id_bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIZE_OF_REGION_METADATA {
            return Err(Error::InvalidMetadataSize {
                expected: SIZE_OF_REGION_METADATA,
                actual: bytes.len(),
            });
        }

        let start = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
        let len = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        let reserved = u64::from_le_bytes(bytes[16..24].try_into().unwrap()) as usize;
        let id_len = u64::from_le_bytes(bytes[24..32].try_into().unwrap()) as usize;

        if start == 0 && len == 0 && reserved == 0 && id_len == 0 {
            return Err(Error::EmptyMetadata);
        }

        if id_len > MAX_REGION_ID_LEN {
            return Err(Error::CorruptedMetadata(format!(
                "id_len {} exceeds maximum {}",
                id_len, MAX_REGION_ID_LEN
            )));
        }

        if 32 + id_len > SIZE_OF_REGION_METADATA {
            return Err(Error::CorruptedMetadata(format!(
                "id_len {} would exceed metadata size",
                id_len
            )));
        }

        let id = String::from_utf8(bytes[32..32 + id_len].to_vec())
            .map_err(|_| Error::InvalidRegionId)?;

        if !start.is_multiple_of(PAGE_SIZE) {
            return Err(Error::CorruptedMetadata(format!(
                "start {} is not page-aligned",
                start
            )));
        }
        if reserved < PAGE_SIZE {
            return Err(Error::CorruptedMetadata(format!(
                "reserved {} is less than PAGE_SIZE",
                reserved
            )));
        }
        if !reserved.is_multiple_of(PAGE_SIZE) {
            return Err(Error::CorruptedMetadata(format!(
                "reserved {} is not page-aligned",
                reserved
            )));
        }
        if len > reserved {
            return Err(Error::CorruptedMetadata(format!(
                "len {} exceeds reserved {}",
                len, reserved
            )));
        }

        Ok(Self {
            id,
            start,
            len,
            reserved,
            state: RegionState::new_clean(), // Loaded from disk
        })
    }
}

impl Clone for RegionMetadata {
    fn clone(&self) -> Self {
        Self {
            start: self.start,
            len: self.len,
            reserved: self.reserved,
            id: self.id.clone(),
            state: RegionState::new_clean(),
        }
    }
}

impl fmt::Display for RegionMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' (start={}, len={}, reserved={})",
            self.id, self.start, self.len, self.reserved
        )
    }
}
