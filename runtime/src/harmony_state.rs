//! Deployment state-file I/O for HarmonyPIR runtime tools.
//!
//! This container format is specific to BitcoinPIR deployments. The serialized
//! per-group payload remains the upstream
//! [`harmonypir::remote::RemoteClient::serialize_legacy_state`] format.

use std::io::{self, Read, Write};

pub const STATE_FILE_MAGIC: u64 = 0xBA7C_4841_524D_0001;
pub const STATE_FILE_VERSION: u32 = 1;
pub const HEADER_SIZE: usize = 48;

#[derive(Debug, Clone)]
pub struct StateFileHeader {
    pub prp_backend: u8,
    pub prp_key: [u8; 16],
    pub index_bins_per_table: u32,
    pub chunk_bins_per_table: u32,
    pub tag_seed: u64,
}

#[derive(Debug, Clone)]
pub struct GroupEntry {
    pub group_id: u32,
    pub level: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StateFile {
    pub header: StateFileHeader,
    pub groups: Vec<GroupEntry>,
}

pub fn write_state_file(
    writer: &mut impl Write,
    header: &StateFileHeader,
    groups: &[GroupEntry],
) -> io::Result<()> {
    writer.write_all(&STATE_FILE_MAGIC.to_le_bytes())?;
    writer.write_all(&STATE_FILE_VERSION.to_le_bytes())?;
    writer.write_all(&[header.prp_backend, 0, 0, 0])?;
    writer.write_all(&header.prp_key)?;
    writer.write_all(&header.index_bins_per_table.to_le_bytes())?;
    writer.write_all(&header.chunk_bins_per_table.to_le_bytes())?;
    writer.write_all(&header.tag_seed.to_le_bytes())?;
    writer.write_all(&(groups.len() as u32).to_le_bytes())?;

    for entry in groups {
        writer.write_all(&entry.group_id.to_le_bytes())?;
        writer.write_all(&[entry.level, 0, 0, 0])?;
        writer.write_all(&(entry.data.len() as u32).to_le_bytes())?;
        writer.write_all(&entry.data)?;
    }

    Ok(())
}

pub fn read_state_file(reader: &mut impl Read) -> io::Result<StateFile> {
    let mut buf8 = [0u8; 8];
    let mut buf4 = [0u8; 4];
    let mut buf16 = [0u8; 16];

    reader.read_exact(&mut buf8)?;
    let magic = u64::from_le_bytes(buf8);
    if magic != STATE_FILE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad magic: 0x{magic:016x}, expected 0x{STATE_FILE_MAGIC:016x}"),
        ));
    }

    reader.read_exact(&mut buf4)?;
    let version = u32::from_le_bytes(buf4);
    if version != STATE_FILE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported version: {version}"),
        ));
    }

    let mut pad4 = [0u8; 4];
    reader.read_exact(&mut pad4)?;
    let prp_backend = pad4[0];
    reader.read_exact(&mut buf16)?;
    let prp_key = buf16;
    reader.read_exact(&mut buf4)?;
    let index_bins_per_table = u32::from_le_bytes(buf4);
    reader.read_exact(&mut buf4)?;
    let chunk_bins_per_table = u32::from_le_bytes(buf4);
    reader.read_exact(&mut buf8)?;
    let tag_seed = u64::from_le_bytes(buf8);

    let header = StateFileHeader {
        prp_backend,
        prp_key,
        index_bins_per_table,
        chunk_bins_per_table,
        tag_seed,
    };

    reader.read_exact(&mut buf4)?;
    let num_groups = u32::from_le_bytes(buf4) as usize;
    let mut groups = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        reader.read_exact(&mut buf4)?;
        let group_id = u32::from_le_bytes(buf4);
        reader.read_exact(&mut pad4)?;
        let level = pad4[0];
        reader.read_exact(&mut buf4)?;
        let data_len = u32::from_le_bytes(buf4) as usize;
        let mut data = vec![0u8; data_len];
        reader.read_exact(&mut data)?;
        groups.push(GroupEntry {
            group_id,
            level,
            data,
        });
    }

    Ok(StateFile { header, groups })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_file_roundtrip() {
        let header = StateFileHeader {
            prp_backend: 0,
            prp_key: [0x42; 16],
            index_bins_per_table: 1000,
            chunk_bins_per_table: 2000,
            tag_seed: 0xDEADBEEF,
        };
        let groups = vec![
            GroupEntry {
                group_id: 0,
                level: 0,
                data: vec![1, 2, 3, 4],
            },
            GroupEntry {
                group_id: 1,
                level: 1,
                data: vec![5, 6, 7],
            },
        ];

        let mut bytes = Vec::new();
        write_state_file(&mut bytes, &header, &groups).unwrap();
        let parsed = read_state_file(&mut &bytes[..]).unwrap();
        assert_eq!(parsed.header.prp_key, header.prp_key);
        assert_eq!(parsed.header.index_bins_per_table, 1000);
        assert_eq!(parsed.header.tag_seed, 0xDEADBEEF);
        assert_eq!(parsed.groups.len(), 2);
        assert_eq!(parsed.groups[0].data, vec![1, 2, 3, 4]);
        assert_eq!(parsed.groups[1].group_id, 1);
        assert_eq!(parsed.groups[1].level, 1);
    }

    #[test]
    fn state_file_v1_has_a_stable_golden_fixture() {
        let header = StateFileHeader {
            prp_backend: 1,
            prp_key: [0x42; 16],
            index_bins_per_table: 8,
            chunk_bins_per_table: 16,
            tag_seed: 0x0102_0304_0506_0708,
        };
        let groups = [GroupEntry {
            group_id: 7,
            level: 2,
            data: vec![0xaa, 0xbb],
        }];
        let mut bytes = Vec::new();
        write_state_file(&mut bytes, &header, &groups).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&STATE_FILE_MAGIC.to_le_bytes());
        expected.extend_from_slice(&STATE_FILE_VERSION.to_le_bytes());
        expected.extend_from_slice(&[1, 0, 0, 0]);
        expected.extend_from_slice(&[0x42; 16]);
        expected.extend_from_slice(&8u32.to_le_bytes());
        expected.extend_from_slice(&16u32.to_le_bytes());
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.extend_from_slice(&[2, 0, 0, 0]);
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&[0xaa, 0xbb]);

        assert_eq!(bytes, expected);
    }
}
