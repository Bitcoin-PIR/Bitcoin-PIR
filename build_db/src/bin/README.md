# build_db/src/bin - Database Building Tools

This directory contains binary utilities for building and verifying the Bitcoin PIR database. The tools are categorized into **Data Generation** (produce output files) and **Verification/Analysis** (validate or inspect data).

---

## Quick Reference

| File | Purpose | Category |
|------|---------|----------|
| `gen_txid_file.rs` | Extract TXIDs from blk*.dat files | Generation |
| `gen_mphf.rs` | Build Minimal Perfect Hash Function | Generation |
| `gen_location_index.rs` | Build MPHF hash → txid position mapping | Generation |
| `gen_remapped_utxo.rs` | Extract UTXOs with 4-byte TXIDs | Generation |
| `gen_txid_mapping.rs` | Build 4B→32B TXID mapping | Generation |
| `gen_utxo_chunks.rs` | Build compact UTXO chunks by address | Generation |
| `gen_cuckoo_txid.rs` | Build cuckoo hash for TXID mapping | Generation |
| `gen_cuckoo_chunks.rs` | Build cuckoo hash for chunks index | Generation |
| `calc_total_tx_count.rs` | Sum transaction counts | Analysis |
| `calc_biggest_utxo.rs` | Find largest UTXO chunk | Analysis |
| `debug_count_utxo_script.rs` | Count UTXOs for a script | Debug |
| `debug_find_script.rs` | Find script by RIPEMD160 hash | Debug |
| `debug_search_txid.rs` | Search TXID in txid.bin | Debug |
| `debug_parse_block.rs` | Parse and display block contents | Debug |
| `test_brk_reader.rs` | Test brk_reader crate | Test |
| `verify_txid_mapping.rs` | Verify TXID mapping file | Verification |

---

## Naming Convention

Files follow a prefix-based naming convention:

- **`gen_*.rs`** - Tools that generate/produce output files
- **`calc_*.rs`** - Tools that calculate/analyze without writing files
- **`verify_*.rs`** - Tools that verify data integrity
- **`debug_*.rs`** - Debug/inspection tools
- **`test_*.rs`** - Test utilities

---

## Data Generation Tools

### `gen_txid_file.rs`

**Purpose:** Extracts all transaction IDs from Bitcoin's blk*.dat files using high-performance `brk_reader`.

**Output:** `/Volumes/Bitcoin/data/txid.bin`
- Format: Sequence of 32-byte TXIDs (little-endian)
- Size: ~38 GB for ~1.2B transactions

**Usage:**
```bash
cargo run --bin gen_txid_file -- /Volumes/Bitcoin/bitcoin
```

**Notes:**
- Requires Bitcoin Core running (for cookie authentication)
- Processes 100,000 blocks per run
- Resumes from progress file
- Much faster than RPC-based approach

---

### `gen_mphf.rs`

**Purpose:** Builds a Minimal Perfect Hash Function (MPHF) for O(1) TXID lookups.

**Output:** `/Volumes/Bitcoin/data/txid_mphf.bin`
- Serialized MPHF using bincode
- Maps 32-byte TXID → unique index

**Usage:**
```bash
cargo run --bin gen_mphf
```

**Notes:**
- Uses streaming iterator to avoid loading all TXIDs into memory
- May skip a few problematic TXIDs (listed in source)
- Critical for the remapping pipeline

---

### `gen_location_index.rs`

**Purpose:** Builds the reverse mapping from MPHF hash to TXID position in txid.bin.

**Output:** `/Volumes/Bitcoin/data/txid_locations.bin`
- Format: Sequence of u32 values (4 bytes per entry)
- Index = MPHF hash, Value = position in txid.bin

**Usage:**
```bash
# First create sparse file:
truncate -s <size> /Volumes/Bitcoin/data/txid_locations.bin

cargo run --bin gen_location_index
```

**Notes:**
- Processes 100M TXIDs per run
- Uses memory-mapped file for efficient random writes
- Run multiple times to complete

---

### `gen_remapped_utxo.rs`

**Purpose:** Reads Bitcoin chainstate LevelDB and extracts UTXOs with 4-byte TXID references.

**Input:**
- Bitcoin chainstate LevelDB
- `txid_mphf.bin`
- `txid_locations.bin`

**Output:** `/Volumes/Bitcoin/data/remapped_utxo_set.bin`
- Format: 40 bytes per UTXO
  - 20 bytes: RIPEMD-160 hash of script
  - 4 bytes: TXID (mapped via MPHF)
  - 4 bytes: vout
  - 4 bytes: block height
  - 8 bytes: amount

**Usage:**
```bash
cargo run --bin gen_remapped_utxo -- /Volumes/Bitcoin/bitcoin
```

**Notes:**
- **Must stop bitcoind first** - requires exclusive lock on chainstate
- Uses advisory lock for safety
- Skips UTXOs above certain block height

---

### `gen_txid_mapping.rs`

**Purpose:** Counts unique 4-byte TXIDs in remapped UTXO set and builds mapping to 32-byte TXIDs.

**Input:**
- `remapped_utxo_set.bin`
- `txid.bin`

**Output:** `/Volumes/Bitcoin/data/utxo_4b_to_32b.bin`
- Format: 36 bytes per entry
  - 4 bytes: 4-byte TXID (index)
  - 32 bytes: original 32-byte TXID

**Usage:**
```bash
cargo run --bin gen_txid_mapping
```

**Notes:**
- Creates sorted mapping for binary search
- Used by PIR server to translate TXIDs

---

### `gen_utxo_chunks.rs`

**Purpose:** Groups UTXOs by script hash and creates compact storage format.

**Input:** `remapped_utxo_set.bin`

**Output:**
- `/Volumes/Bitcoin/data/utxo_chunks.bin` - Compact UTXO data
- `/Volumes/Bitcoin/data/utxo_chunks_index.bin` - Index (script_hash → offset)

**Format:**
- Index: 24 bytes per entry (20B script_hash + 4B offset)
- Chunks: VarInt-encoded entries with delta compression

**Usage:**
```bash
cargo run --bin gen_utxo_chunks
```

**Notes:**
- Groups UTXOs by address (script hash)
- Sorts by height (newest first)
- Uses delta encoding for TXIDs
- Achieves significant compression

---

### `gen_cuckoo_txid.rs`

**Purpose:** Builds bucketed cuckoo hash table for 4B→32B TXID mapping.

**Input:** `utxo_4b_to_32b.bin`

**Output:** `/Volumes/Bitcoin/data/utxo_4b_to_32b_cuckoo.bin`

**Parameters:**
- Bucket size: 4
- Load factor: 0.95
- Hash functions: 2

**Usage:**
```bash
cargo run --bin gen_cuckoo_txid
```

**Notes:**
- Alternative to linear mapping
- O(1) lookup with good cache locality
- ~5% space overhead vs 100% for simple 2n table

---

### `gen_cuckoo_chunks.rs`

**Purpose:** Builds bucketed cuckoo hash table for UTXO chunks index.

**Input:** `utxo_chunks_index.bin`

**Output:** `/Volumes/Bitcoin/data/utxo_chunks_cuckoo.bin`

**Usage:**
```bash
cargo run --bin gen_cuckoo_chunks
```

**Notes:**
- Enables O(1) script hash lookup
- Uses 20-byte script hash as key

---

## Verification Tools

### `verify_txid_mapping.rs`

**Purpose:** Verifies that the 4B→32B TXID mapping is consistent with MPHF.

**Input:**
- `utxo_4b_to_32b.bin`
- `txid_mphf.bin`

**Usage:**
```bash
cargo run --bin verify_txid_mapping
```

**Notes:**
- For each entry, checks that MPHF(32b_txid) == 4b_txid
- Reports any mismatches
- Essential validation before production use

---

## Analysis Tools

### `calc_total_tx_count.rs`

**Purpose:** Calculates total number of transactions from block transaction counts.

**Input:** `block_tx_counts.bin`

**Usage:**
```bash
cargo run --bin calc_total_tx_count
```

**Output:** Prints total transaction count and average per block.

---

### `calc_biggest_utxo.rs`

**Purpose:** Finds the UTXO chunk with the most entries.

**Input:**
- `utxo_chunks_index.bin`
- `utxo_chunks.bin`

**Usage:**
```bash
cargo run --bin calc_biggest_utxo
```

**Notes:**
- Useful for understanding data distribution
- Helps size buffers appropriately

---

## Debug Tools

### `debug_count_utxo_script.rs`

**Purpose:** Counts UTXOs for a specific script pubkey by scanning chainstate.

**Usage:**
```bash
cargo run --bin debug_count_utxo_script -- <script_hex> [datadir]
```

**Notes:**
- Must stop bitcoind first
- Useful for verifying UTXO counts

---

### `debug_find_script.rs`

**Purpose:** Searches chainstate for UTXOs matching a RIPEMD160 script hash.

**Usage:**
```bash
cargo run --bin debug_find_script -- [datadir] [chainstate_dir]
```

**Notes:**
- Edit `TARGET_HASH` in source to change search target
- Shows TXID, vout, amount, script details

---

### `debug_search_txid.rs`

**Purpose:** Performs linear search for a TXID in txid.bin.

**Usage:**
```bash
cargo run --bin debug_search_txid -- <txid_hex>
```

**Notes:**
- Slow (linear scan) - for debugging only
- Use MPHF for production lookups

---

### `debug_parse_block.rs`

**Purpose:** Parses a single block and displays transaction details.

**Usage:**
```bash
cargo run --bin debug_parse_block -- <datadir> <block_number>
```

**Notes:**
- Shows all inputs/outputs for each transaction
- Also builds BIP158 filter for comparison
- Useful for understanding block structure

---

## Test Tools

### `test_brk_reader.rs`

**Purpose:** Tests the `brk_reader` crate functionality.

**Usage:**
```bash
cargo run --bin test_brk_reader -- /Volumes/Bitcoin/bitcoin
```

**Notes:**
- Requires Bitcoin Core running
- Tests reading from various block ranges
- Demonstrates TXID extraction

---

## Typical Build Pipeline

The tools should be run in this order:

```
1. gen_txid_file.rs            # Extract all TXIDs
2. gen_mphf.rs                 # Build MPHF for TXIDs
3. gen_location_index.rs       # Build reverse index
4. gen_remapped_utxo.rs        # Extract UTXOs with 4B TXIDs
5. gen_txid_mapping.rs         # Build 4B→32B mapping
6. gen_utxo_chunks.rs          # Build compact UTXO storage
7. gen_cuckoo_chunks.rs        # Build cuckoo hash index (optional)
```

---

## File Dependencies

```
txid.bin ← gen_txid_file.rs
       ↓
txid_mphf.bin ← gen_mphf.rs
       ↓
txid_locations.bin ← gen_location_index.rs
       ↓
remapped_utxo_set.bin ← gen_remapped_utxo.rs
       ↓
utxo_4b_to_32b.bin ← gen_txid_mapping.rs
utxo_chunks.bin + utxo_chunks_index.bin ← gen_utxo_chunks.rs
       ↓
utxo_chunks_cuckoo.bin ← gen_cuckoo_chunks.rs
```
