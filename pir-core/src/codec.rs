//! Binary codec utilities: varint encoding/decoding and UTXO data parsing.

// ─── Varint (LEB128 unsigned) ───────────────────────────────────────────────

/// Read a LEB128 unsigned varint from `data`. Returns (value, bytes_consumed).
///
/// # Panics
/// Panics if the varint exceeds 64 bits or data ends mid-varint.
pub fn read_varint(data: &[u8]) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return (result, i + 1);
        }
        shift += 7;
        if shift >= 64 {
            panic!("VarInt too large");
        }
    }
    panic!("Unexpected end of data while reading varint");
}

/// Encode a u64 as LEB128 unsigned varint, appending to `out`.
pub fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Compute the encoded byte length of a varint without writing it.
pub fn varint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

// ─── UTXO data parsing ─────────────────────────────────────────────────────

/// A single UTXO entry parsed from chunk data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
}

/// Parse UTXO entries from serialized chunk data.
///
/// Format: `[varint count][per entry: 32B txid, varint vout, varint amount]`
/// Padding bytes after the last entry are ignored.
pub fn parse_utxo_data(data: &[u8]) -> Vec<UtxoEntry> {
    if data.is_empty() {
        return Vec::new();
    }

    let (count, mut pos) = read_varint(data);
    let mut entries = Vec::with_capacity(count as usize);

    for _ in 0..count {
        if pos + 32 > data.len() {
            break;
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let (vout, consumed) = read_varint(&data[pos..]);
        pos += consumed;

        let (amount, consumed) = read_varint(&data[pos..]);
        pos += consumed;

        entries.push(UtxoEntry {
            txid,
            vout: vout as u32,
            amount,
        });
    }

    entries
}

/// Serialize UTXO entries into the chunk format.
///
/// Format: `[varint count][per entry: 32B txid, varint vout, varint amount]`
pub fn serialize_utxo_data(entries: &[UtxoEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(entries.len() as u64, &mut out);
    for entry in entries {
        out.extend_from_slice(&entry.txid);
        write_varint(entry.vout as u64, &mut out);
        write_varint(entry.amount, &mut out);
    }
    out
}

// ─── Delta data parsing ────────────────────────────────────────────────────

/// A spent UTXO reference (txid + vout, no amount).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentEntry {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// Parsed delta data for a single scripthash.
#[derive(Clone, Debug)]
pub struct DeltaData {
    pub spent: Vec<SpentEntry>,
    pub new_utxos: Vec<UtxoEntry>,
}

/// Parse delta data from serialized chunk data.
///
/// Format:
/// ```text
/// [varint num_spent]
///   per spent: [32B txid][varint vout]
/// [varint num_new]
///   per new: [32B txid][varint vout][varint amount]
/// ```
pub fn parse_delta_data(data: &[u8]) -> DeltaData {
    let mut pos = 0;

    let (num_spent, consumed) = read_varint(&data[pos..]);
    pos += consumed;

    let mut spent = Vec::with_capacity(num_spent as usize);
    for _ in 0..num_spent {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let (vout, consumed) = read_varint(&data[pos..]);
        pos += consumed;

        spent.push(SpentEntry {
            txid,
            vout: vout as u32,
        });
    }

    let (num_new, consumed) = read_varint(&data[pos..]);
    pos += consumed;

    let mut new_utxos = Vec::with_capacity(num_new as usize);
    for _ in 0..num_new {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let (vout, consumed) = read_varint(&data[pos..]);
        pos += consumed;

        let (amount, consumed) = read_varint(&data[pos..]);
        pos += consumed;

        new_utxos.push(UtxoEntry {
            txid,
            vout: vout as u32,
            amount,
        });
    }

    DeltaData { spent, new_utxos }
}

/// Serialize delta data for a single scripthash.
pub fn serialize_delta_data(delta: &DeltaData) -> Vec<u8> {
    let mut out = Vec::new();

    write_varint(delta.spent.len() as u64, &mut out);
    for entry in &delta.spent {
        out.extend_from_slice(&entry.txid);
        write_varint(entry.vout as u64, &mut out);
    }

    write_varint(delta.new_utxos.len() as u64, &mut out);
    for entry in &delta.new_utxos {
        out.extend_from_slice(&entry.txid);
        write_varint(entry.vout as u64, &mut out);
        write_varint(entry.amount, &mut out);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        for &val in &[0u64, 1, 127, 128, 255, 300, 16383, 16384, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(val, &mut buf);
            let (decoded, consumed) = read_varint(&buf);
            assert_eq!(decoded, val);
            assert_eq!(consumed, buf.len());
            assert_eq!(consumed, varint_len(val));
        }
    }

    #[test]
    fn test_utxo_roundtrip() {
        let entries = vec![
            UtxoEntry { txid: [0xAA; 32], vout: 0, amount: 50000 },
            UtxoEntry { txid: [0xBB; 32], vout: 1, amount: 100000 },
        ];
        let serialized = serialize_utxo_data(&entries);
        let parsed = parse_utxo_data(&serialized);
        assert_eq!(entries, parsed);
    }

    #[test]
    fn test_delta_roundtrip() {
        let delta = DeltaData {
            spent: vec![
                SpentEntry { txid: [0x11; 32], vout: 0 },
                SpentEntry { txid: [0x22; 32], vout: 3 },
            ],
            new_utxos: vec![
                UtxoEntry { txid: [0x33; 32], vout: 0, amount: 75000 },
            ],
        };
        let serialized = serialize_delta_data(&delta);
        let parsed = parse_delta_data(&serialized);
        assert_eq!(delta.spent, parsed.spent);
        assert_eq!(delta.new_utxos, parsed.new_utxos);
    }
}
