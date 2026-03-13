# UTXO Chunks Builder — Detailed Plan

## Overview

Build a Rust binary (`build_utxo_chunks`) that reads the remapped UTXO set from
`/Volumes/Bitcoin/data/remapped_utxo_set.bin`, groups entries by ScriptPubKey hash,
and writes a compact representation to two output files:
- `/Volumes/Bitcoin/data/utxo_chunks.bin` — compact UTXO data grouped by address
- `/Volumes/Bitcoin/data/utxo_chunks_index.bin` — index mapping ScriptPubKey hash → offset

## Input Format

File: `/Volumes/Bitcoin/data/remapped_utxo_set.bin`

Each entry is **40 bytes** (fixed-size, sequential):

| Offset | Size | Field               |
|--------|------|---------------------|
| 0      | 20   | ScriptPubKey hash   |
| 20     | 4    | TXID (u32 LE)       |
| 24     | 4    | vout (u32 LE)       |
| 28     | 4    | height (u32 LE)     |
| 32     | 8    | amount (u64 LE)     |

Total entries ≈ 165M → file size ≈ 6.6 GB.

## Data Structures

### ShortenedEntry (20 bytes, fields 2–5)
```rust
struct ShortenedEntry {
    txid: u32,    // 4 bytes
    vout: u32,    // 4 bytes
    height: u32,  // 4 bytes
    amount: u64,  // 8 bytes
}
```

### Grouping
```
HashMap<[u8; 20], Vec<ShortenedEntry>>
```
- Key: 20-byte ScriptPubKey hash
- Value: Vector of ShortenedEntry

## Processing Steps

### Step 1: Memory-map the input file
- Open `/Volumes/Bitcoin/data/remapped_utxo_set.bin` read-only
- Use `memmap2::Mmap` (already a dependency) to mmap the entire file
- Validate: file size must be divisible by 40
- Compute entry count: `file_size / 40`

### Step 2: Build the HashMap
- Iterate over mmap in 40-byte chunks
- For each chunk:
  - Extract first 20 bytes → `[u8; 20]` ScriptPubKey hash (the key)
  - Extract bytes 20..40 → parse into ShortenedEntry (txid, vout, height, amount)
  - Insert into `HashMap<[u8; 20], Vec<ShortenedEntry>>`
- Track progress (print every 1%)
- Report: total entries, unique ScriptPubKey hashes, HashMap memory estimate

### Step 3: Open output files
- `/Volumes/Bitcoin/data/utxo_chunks.bin` → `BufWriter<File>` (1 MB buffer)
- `/Volumes/Bitcoin/data/utxo_chunks_index.bin` → `BufWriter<File>` (1 MB buffer)

### Step 4: Process and write each group ("take" pattern)
Use `HashMap::drain()` to consume entries one group at a time, freeing memory as we go.

For each `(script_hash, mut entries)` pair:

#### 4a. Sort entries by height (descending — higher heights first)
```rust
entries.sort_unstable_by(|a, b| b.height.cmp(&a.height));
```

#### 4b. Record start offset
```rust
let start_offset: u64 = current_position_in_chunks_file;
```

#### 4c. Write to `utxo_chunks.bin`
1. Write the 20-byte ScriptPubKey hash
2. For each entry `entries[i]`:
   - **TXID encoding**:
     - `i == 0`: Write the raw 4-byte TXID (u32 LE)
     - `i > 0`: Write `VarInt(entries[i-1].txid - entries[i].txid)` (delta from previous; wrapping u32 subtraction encoded as u64 VarInt)
   - **vout**: Write as VarInt
   - **amount**: Write as VarInt

#### 4d. Write to `utxo_chunks_index.bin`
- Write the 20-byte ScriptPubKey hash
- Write the start offset as u64 LE (8 bytes)
- → Each index entry is 28 bytes

### Step 5: Flush and report
- Flush both BufWriters
- Print summary statistics

## VarInt Encoding

Standard unsigned LEB128 (Little-Endian Base 128):
- Each byte: 7 data bits + 1 continuation bit (MSB)
- If MSB=1, more bytes follow; if MSB=0, this is the last byte
- Example: 300 → `0xAC 0x02`

```rust
fn write_varint(writer: &mut impl Write, mut value: u64) -> io::Result<usize> {
    let mut bytes_written = 0;
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer.write_all(&[byte])?;
        bytes_written += 1;
        if value == 0 {
            break;
        }
    }
    Ok(bytes_written)
}
```

## Output File Formats

### `utxo_chunks.bin`
Variable-length records, concatenated:
```
[20B script_hash][4B txid_0][varint vout_0][varint amount_0]
                  [varint Δtxid_1][varint vout_1][varint amount_1]
                  [varint Δtxid_2][varint vout_2][varint amount_2]
                  ...
[20B script_hash][4B txid_0][varint vout_0][varint amount_0]
                  ...
```

### `utxo_chunks_index.bin`
Fixed-size entries (28 bytes each):
```
[20B script_hash][8B offset_u64_LE]
```

## Memory Considerations

- Input file is mmap'd (no RAM for raw data)
- HashMap overhead:
  - ~165M entries, but grouped by unique ScriptPubKey (~50-80M unique addresses estimated)
  - Each ShortenedEntry: 20 bytes + Vec overhead
  - Keys: 20 bytes each + HashMap bucket overhead
  - Estimated total: ~5-8 GB RAM
- Using `drain()` releases memory progressively during output phase

## Implementation Checklist

- [ ] Create `pir/src/bin/build_utxo_chunks.rs`
- [ ] Implement mmap of input file with validation
- [ ] Implement HashMap building with progress reporting
- [ ] Implement VarInt encoding (LEB128)
- [ ] Implement sorting (height descending) per group
- [ ] Implement compact writing to `utxo_chunks.bin`
- [ ] Implement index writing to `utxo_chunks_index.bin`
- [ ] Add summary statistics and timing
- [ ] Test compilation

## Note on Height

The compact output format as specified writes **txid, vout, amount** but does **not** write height.
Height is used only for sorting. If height needs to be included in the output, it can be added as
an additional VarInt per entry.
