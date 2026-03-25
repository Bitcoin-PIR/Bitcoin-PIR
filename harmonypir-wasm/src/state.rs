//! Multi-bucket state file I/O for HarmonyPIR.
//!
//! The state file contains the full client state for all PBC buckets
//! (75 index + 80 chunk). It is written during the offline phase (hint
//! generation) and updated after each online query session.
//!
//! File format:
//! ```text
//! [Header: 48 bytes]
//!   magic:    u64 LE
//!   version:  u32 LE
//!   backend:  u8
//!   _pad:     [u8; 3]
//!   prp_key:  [u8; 16]
//!   index_bins_per_table: u32 LE
//!   chunk_bins_per_table: u32 LE
//!   tag_seed: u64 LE
//! [Bucket count: 4 bytes]
//!   num_buckets: u32 LE
//! [Per-bucket: repeated num_buckets times]
//!   bucket_id: u32 LE
//!   level:     u8
//!   _pad:      [u8; 3]
//!   data_len:  u32 LE  (length of serialized bucket data that follows)
//!   data:      [u8; data_len]  (output of HarmonyBucket::serialize())
//! ```

use std::io::{self, Read, Write};

pub const STATE_FILE_MAGIC: u64 = 0xBA7C_4841_524D_0001;
pub const STATE_FILE_VERSION: u32 = 1;
pub const HEADER_SIZE: usize = 48;

/// Parsed state file header.
#[derive(Debug, Clone)]
pub struct StateFileHeader {
    pub prp_backend: u8,
    pub prp_key: [u8; 16],
    pub index_bins_per_table: u32,
    pub chunk_bins_per_table: u32,
    pub tag_seed: u64,
}

/// One bucket's state in the file.
#[derive(Debug, Clone)]
pub struct BucketEntry {
    pub bucket_id: u32,
    pub level: u8,
    pub data: Vec<u8>,
}

/// Complete parsed state file.
#[derive(Debug, Clone)]
pub struct StateFile {
    pub header: StateFileHeader,
    pub buckets: Vec<BucketEntry>,
}

/// Write a state file.
pub fn write_state_file(
    w: &mut impl Write,
    header: &StateFileHeader,
    buckets: &[BucketEntry],
) -> io::Result<()> {
    // Header (48 bytes).
    w.write_all(&STATE_FILE_MAGIC.to_le_bytes())?;
    w.write_all(&STATE_FILE_VERSION.to_le_bytes())?;
    w.write_all(&[header.prp_backend, 0, 0, 0])?;
    w.write_all(&header.prp_key)?;
    w.write_all(&header.index_bins_per_table.to_le_bytes())?;
    w.write_all(&header.chunk_bins_per_table.to_le_bytes())?;
    w.write_all(&header.tag_seed.to_le_bytes())?;

    // Bucket count.
    w.write_all(&(buckets.len() as u32).to_le_bytes())?;

    // Per-bucket.
    for entry in buckets {
        w.write_all(&entry.bucket_id.to_le_bytes())?;
        w.write_all(&[entry.level, 0, 0, 0])?;
        w.write_all(&(entry.data.len() as u32).to_le_bytes())?;
        w.write_all(&entry.data)?;
    }

    Ok(())
}

/// Read a state file.
pub fn read_state_file(r: &mut impl Read) -> io::Result<StateFile> {
    // Header.
    let mut buf8 = [0u8; 8];
    let mut buf4 = [0u8; 4];
    let mut buf16 = [0u8; 16];

    r.read_exact(&mut buf8)?;
    let magic = u64::from_le_bytes(buf8);
    if magic != STATE_FILE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad magic: 0x{magic:016x}, expected 0x{STATE_FILE_MAGIC:016x}"),
        ));
    }

    r.read_exact(&mut buf4)?;
    let version = u32::from_le_bytes(buf4);
    if version != STATE_FILE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported version: {version}"),
        ));
    }

    let mut pad4 = [0u8; 4];
    r.read_exact(&mut pad4)?;
    let prp_backend = pad4[0];

    r.read_exact(&mut buf16)?;
    let prp_key = buf16;

    r.read_exact(&mut buf4)?;
    let index_bins_per_table = u32::from_le_bytes(buf4);

    r.read_exact(&mut buf4)?;
    let chunk_bins_per_table = u32::from_le_bytes(buf4);

    r.read_exact(&mut buf8)?;
    let tag_seed = u64::from_le_bytes(buf8);

    let header = StateFileHeader {
        prp_backend,
        prp_key,
        index_bins_per_table,
        chunk_bins_per_table,
        tag_seed,
    };

    // Bucket count.
    r.read_exact(&mut buf4)?;
    let num_buckets = u32::from_le_bytes(buf4) as usize;

    // Per-bucket.
    let mut buckets = Vec::with_capacity(num_buckets);
    for _ in 0..num_buckets {
        r.read_exact(&mut buf4)?;
        let bucket_id = u32::from_le_bytes(buf4);

        r.read_exact(&mut pad4)?;
        let level = pad4[0];

        r.read_exact(&mut buf4)?;
        let data_len = u32::from_le_bytes(buf4) as usize;

        let mut data = vec![0u8; data_len];
        r.read_exact(&mut data)?;

        buckets.push(BucketEntry {
            bucket_id,
            level,
            data,
        });
    }

    Ok(StateFile { header, buckets })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_file_roundtrip() {
        let header = StateFileHeader {
            prp_backend: 0,
            prp_key: [0x42; 16],
            index_bins_per_table: 1000,
            chunk_bins_per_table: 2000,
            tag_seed: 0xDEADBEEF,
        };
        let buckets = vec![
            BucketEntry { bucket_id: 0, level: 0, data: vec![1, 2, 3, 4] },
            BucketEntry { bucket_id: 1, level: 1, data: vec![5, 6, 7] },
        ];

        let mut buf = Vec::new();
        write_state_file(&mut buf, &header, &buckets).unwrap();

        let parsed = read_state_file(&mut &buf[..]).unwrap();
        assert_eq!(parsed.header.prp_key, header.prp_key);
        assert_eq!(parsed.header.index_bins_per_table, 1000);
        assert_eq!(parsed.header.tag_seed, 0xDEADBEEF);
        assert_eq!(parsed.buckets.len(), 2);
        assert_eq!(parsed.buckets[0].data, vec![1, 2, 3, 4]);
        assert_eq!(parsed.buckets[1].bucket_id, 1);
        assert_eq!(parsed.buckets[1].level, 1);
    }
}
