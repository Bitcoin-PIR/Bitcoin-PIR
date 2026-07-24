//! Binary codec utilities: varint encoding/decoding and UTXO data parsing.

// ─── Varint (LEB128 unsigned) ───────────────────────────────────────────────

/// Malformed-varint error returned by [`try_read_varint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VarintError {
    /// The encoding continued past 64 bits of payload.
    TooLarge,
    /// The buffer ended before the final (continuation-bit-clear) byte.
    Truncated,
}

impl core::fmt::Display for VarintError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VarintError::TooLarge => write!(f, "varint exceeds 64 bits"),
            VarintError::Truncated => write!(f, "data ended mid-varint"),
        }
    }
}

impl std::error::Error for VarintError {}

/// Read a LEB128 unsigned varint from `data`. Returns (value, bytes_consumed).
///
/// Panic-free counterpart of [`read_varint`] — use this for any bytes an
/// untrusted peer controls (e.g. server-supplied UTXO chunk data, which
/// is parsed *before* Merkle verification; see C2 in
/// `docs/CODE_REVIEW_2026-06.md`).
pub fn try_read_varint(data: &[u8]) -> Result<(u64, usize), VarintError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return Err(VarintError::TooLarge);
        }
    }
    Err(VarintError::Truncated)
}

/// Read a LEB128 unsigned varint from `data`. Returns (value, bytes_consumed).
///
/// Only for trusted input (locally produced bytes, build pipeline) —
/// untrusted-input paths must use [`try_read_varint`] instead.
///
/// # Panics
/// Panics if the varint exceeds 64 bits or data ends mid-varint.
pub fn read_varint(data: &[u8]) -> (u64, usize) {
    match try_read_varint(data) {
        Ok(out) => out,
        Err(VarintError::TooLarge) => panic!("VarInt too large"),
        Err(VarintError::Truncated) => panic!("Unexpected end of data while reading varint"),
    }
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
///
/// Panic-free on hostile input: chunk bytes come from the server and are
/// parsed *before* Merkle verification, so malformed or truncated data
/// stops at the last complete entry instead of panicking (this is also
/// the contract `web/src/sdk-bridge.ts` documents for the WASM
/// `decodeUtxoData` export built on this function). The declared `count`
/// never drives the allocation — capacity is capped by what the buffer
/// could physically hold.
pub fn parse_utxo_data(data: &[u8]) -> Vec<UtxoEntry> {
    if data.is_empty() {
        return Vec::new();
    }

    let Ok((count, mut pos)) = try_read_varint(data) else {
        return Vec::new();
    };
    // Smallest possible entry: 32B txid + 1B vout + 1B amount.
    let max_entries = data.len().saturating_sub(pos) / 34;
    let mut entries = Vec::with_capacity((count as usize).min(max_entries));

    for _ in 0..count {
        if pos + 32 > data.len() {
            break;
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let Ok((vout, consumed)) = try_read_varint(&data[pos..]) else {
            break;
        };
        pos += consumed;

        let Ok((amount, consumed)) = try_read_varint(&data[pos..]) else {
            break;
        };
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
            // The fallible reader agrees with the panicking one on valid input.
            assert_eq!(try_read_varint(&buf), Ok((val, consumed)));
        }
    }

    #[test]
    fn test_try_read_varint_truncated_is_error_not_panic() {
        assert_eq!(try_read_varint(&[]), Err(VarintError::Truncated));
        // Continuation bit set on every byte — data ends mid-varint.
        assert_eq!(try_read_varint(&[0x80]), Err(VarintError::Truncated));
        assert_eq!(
            try_read_varint(&[0xFF, 0xFF, 0x80]),
            Err(VarintError::Truncated)
        );
    }

    #[test]
    fn test_try_read_varint_overflow_is_error_not_panic() {
        // A 10th continuation byte pushes the shift past 64 bits.
        assert_eq!(try_read_varint(&[0xFF; 10]), Err(VarintError::TooLarge));
        assert_eq!(try_read_varint(&[0xFF; 64]), Err(VarintError::TooLarge));
    }

    #[test]
    fn test_parse_utxo_data_malformed_input_is_lenient_not_panic() {
        // Count varint overflows 64 bits (previously panicked).
        assert!(parse_utxo_data(&[0xFF; 16]).is_empty());
        // Data ends mid-count-varint (previously panicked).
        assert!(parse_utxo_data(&[0x80]).is_empty());

        // A valid first entry followed by an entry whose amount varint is
        // cut mid-stream: keep the complete entry, drop the torn one.
        let entries = vec![
            UtxoEntry { txid: [0xAA; 32], vout: 0, amount: 50000 },
            UtxoEntry { txid: [0xBB; 32], vout: 1, amount: 100000 },
        ];
        let mut serialized = serialize_utxo_data(&entries);
        // Drop the amount's final byte, leaving a dangling continuation bit.
        serialized.pop();
        assert_eq!(parse_utxo_data(&serialized), &entries[..1]);
    }

    #[test]
    fn test_parse_utxo_data_huge_declared_count_does_not_allocate() {
        // count = u64::MAX with no entry bytes behind it — the capacity
        // hint must be capped by the buffer, not the declared count.
        let mut buf = Vec::new();
        write_varint(u64::MAX, &mut buf);
        assert!(parse_utxo_data(&buf).is_empty());
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
