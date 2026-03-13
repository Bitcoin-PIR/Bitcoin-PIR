# Data Processing Plan

**Purpose**: Create a compact indexing system for Bitcoin transactions and ScriptPubKeys to enable efficient PIR queries.

**Implementation Status**: Scripts created (`scripts/index_blocks.py` and `scripts/query_index.py`), pending testing with live Bitcoin node data.

---

## Problem Statement

Bitcoin PIR requires efficient data structures. Current limitations:

### 1. Transaction Identification
- **Challenge**: Need to locate transactions by TXID quickly
- **Requirement**: Map TXID → [block_height, tx_index_within_block]
- **Benefit**: Enables PIR queries for specific transactions

### 2. ScriptPubKey Storage
- **Challenge**: ScriptPubKeys are 32 bytes each
- **Problem**: Storing many ScriptPubKeys in raw form is space-intensive
- **Requirement**: Assign compact integer IDs instead
- **Benefit**: Reduces storage by ~87% (e.g., 10,000 SPKs: 320 KB → 20 KB)

### 3. Global Transaction Numbering
- **Challenge**: Need globally unique transaction IDs across all blocks
- **Requirement**: Use 4-byte IDs for simplicity
- **Benefit**: Simpler than block-relative indices
- **Motivation**: Transactions arrive gradually, simple increments work naturally

### 4. ScriptPubKey Hash Set Indexing
- **Challenge**: Hash set can be huge (millions of unique keys)
- **Requirement**: Split into multiple files for efficient lookup
- **Benefit**: Enables finding previously registered ScriptPubKeys
- **Motivation**: Avoid loading entire set into memory

---

## Index Architecture

### Index 1: Global Transaction Index

**Purpose**: Assign globally unique 4-byte IDs to all transactions.

#### Schema
```
Global TXID → {
    tx_id: uint32 (4 bytes),              // Simple counter: 1, 2, 3, ... N-1
    block_height: uint32 (4 bytes),
    tx_index: uint16 (2 bytes),           // Position within block
    block_offset: uint64 (8 bytes)         // PIR file offset
}
```

#### Data Structure
```
Fixed-size record (18 bytes):
[4 bytes tx_id][4 bytes block_height][2 bytes tx_index][8 bytes block_offset]

Total: 18 bytes per transaction
```

#### Global ID Assignment Strategy
```
Method: Simple global counter
Initialize: tx_id = 0

Process transactions in order:
For each new transaction encountered:
    assign next tx_id = counter
    counter += 1

Benefits:
  - IDs are globally unique and sequential
  - Simple to reason about (tx_id = 17 = 17th transaction overall)
  - Easy to track progress
  - Supports up to 4.2B transactions (32-bit IDs)

Storage capacity:
  - 32-bit IDs: 4,294,967,295 unique transactions max
  - Current plan (200K tx) uses <0.05% of capacity
  - Upgrade path: 3-byte IDs (16M) or 4-byte IDs (4B) if needed

Block boundary handling:
  - IDs continue across blocks (not reset per block)
  - tx_id represents absolute position in blockchain
  - Block context maintained separately (block_height field)

#### Storage
```
File: data/tx_global_index.bin
Format: Binary array of 18-byte records

Total: 18 bytes × N transactions
```

#### Lookup Flow
```
1. Client wants transaction by TXID
2. Hash TXID (SHA-256)
3. Binary search in `data/tx_global_index.bin`
4. Read 18-byte record: `tx_id, block_height, tx_index, block_offset`
```

---

### Index 2: Global ScriptPubKey Index

**Purpose**: Assign globally unique IDs to all ScriptPubKeys across all blocks.

#### Schema
```
Two-way mapping:
1. spk_id (2 bytes) → ScriptPubKey (variable length)
2. ScriptPubKey → spk_id (for reverse lookup)

Counter: uint16 (starts at 0, increments per new unique key)
```

#### Data Structure
```
ScriptPubKey storage (variable):
[2 bytes length][N bytes ScriptPubKey bytes]

Lookup table (hash table):
[32 bytes hash(ScriptPubKey)][2 bytes spk_id]
```

#### ID Assignment Strategy
```
Process transactions in order:
For each new ScriptPubKey encountered:
    if not in lookup:
        assign spk_id = counter (2 bytes)
        counter += 1

Storage capacity:
  - 16-bit IDs: 65,535 unique ScriptPubKeys
  - Supports up to 16-bit counter (65,535 IDs)
  - Current plan (40K SPKs) uses <0.1% of capacity
  - Note: 16-bit IDs sufficient for 200K transactions
  - Upgrade path: 3-byte IDs (16M) or 4-byte IDs (4B) if needed

#### Storage
```
File: data/spk_global_index.bin
Format: Binary array of variable-length records

Lookup table: data/spk_global_lookup.bin
Binary format (fixed records):
```
[32 bytes] SHA-256 hash of ScriptPubKey
[2 bytes] ScriptPubKey ID (uint16, little-endian)
```

Total: 34 bytes × M unique ScriptPubKeys

```

#### Lookup Flow
```
1. Client: Hash ScriptPubKey (SHA-256)
2. Lookup in `data/spk_global_lookup.bin` → get spk_id (2 bytes)
3. Use spk_id (2 bytes) in transactions (vs 32-byte ScriptPubKey)

Benefits:
- 2-byte ID vs 32-byte ScriptPubKey in queries
- Smaller PIR queries (16x reduction)
- Simple storage: No bucket files needed
```

---

## File Formats

### Transaction Index (`tx_global_index.bin`)

Binary format:
```
[18 bytes per record]
[4 bytes tx_id][4 bytes block_height][2 bytes tx_index][8 bytes block_offset]
```

Total: 18 bytes × N transactions

**Example lookup flow**:
1. Hash TXID (SHA-256)
2. Binary search in `data/tx_global_index.bin`
3. Read 18-byte record: `tx_id, block_height, tx_index, block_offset`
```

### ScriptPubKey Index (`spk_global_index.bin`)

Binary format:
```
For each ScriptPubKey:
[2 bytes length][N bytes ScriptPubKey bytes]
```

Total: Variable (depends on ScriptPubKeys)

### ScriptPubKey Lookup (`spk_global_lookup.bin`)

Binary format (fixed records):
```
[32 bytes] SHA-256 hash of ScriptPubKey
[2 bytes] ScriptPubKey ID (uint16, little-endian)
```

Total: 34 bytes × M unique ScriptPubKeys

---

## PIR Query Flow

### Query Transaction by TXID

1. **Client**:
   - Hash TXID (SHA-256)
   - Binary search in `data/tx_global_index.bin`
   - Read 18-byte record: `tx_id, block_height, tx_index, block_offset`

2. **Server PIR**:
   - Returns block at `block_height`
   - Client extracts transaction at `tx_index` within that block

### Query ScriptPubKey

1. **Client**:
   - Hash ScriptPubKey (SHA-256)
   - Lookup in `data/spk_global_lookup.bin` → get spk_id (2 bytes)

2. **Benefits**:
   - 2-byte ID vs 32-byte ScriptPubKey in queries
   - Smaller PIR queries (16x reduction)
   - Simple storage: No bucket files needed

---

## Implementation Steps

### Phase A: Infrastructure
- [x] Create index directory structure
- [x] Initialize empty index files
- [x] Set up RPC connection to Bitcoin node (in index_blocks.py)
- [ ] Create spk_global_index.bin and spk_global_lookup.bin files (test with live data)

### Phase B: Global Transaction Indexing
- [x] Implement global TXID assignment (sequential 4-byte counter)
- [x] Build tx_global_index.bin (18-byte records)
- [ ] Test reverse lookup (TXID → location)
- [ ] Verify ID uniqueness and no gaps

### Phase C: Global ScriptPubKey Indexing
- [x] Implement SPK ID assignment (sequential 2-byte counter)
- [x] Build spk_global_index.bin (variable length SPKs)
- [x] Build spk_global_lookup.bin (hash table)
- [x] Write spk_meta.json (statistics)
- [ ] Test bucket lookup accuracy
- [ ] Verify all SPK IDs are unique

### Phase D: Validation
- [ ] Verify all indexed transactions are accessible
- [ ] Verify all ScriptPubKey IDs are unique
- [ ] Test boundary cases (first block, last block)
- [ ] Random queries and verify results
- [ ] Performance benchmarks (lookup times, memory usage)

### Phase E: Integration
- [x] Create unified API for queries (query_index.py):
  - `get_tx_by_id(tx_id)` → tx_id, location
  - `get_all_tx_records()` → full transaction list
  - `get_spk_by_id(spk_id)` → full SPK data
  - `get_spk_id_by_hex(spk_hex)` → spk_id (2 bytes)
  - `print_summary()` → index statistics

---

## File Organization After Indexing

```
data/
├── blocks/                      # 100 binary block files (from Phase 1)
├── tx_global_index.bin          # Global transaction index (18 bytes per TX)
├── spk_global_index.bin          # ScriptPubKey index (variable length)
├── spk_global_lookup.bin          # ScriptPubKey hash → ID lookup (34 bytes each)
└── spk_meta.json              # Index metadata (counts, stats)
```

---

## Storage Analysis

### Estimated Sizes (100 blocks, ~2000 tx/block)

```
Transaction Index:
- Transactions: ~200,000
- Index size: 200,000 × 18 bytes = 3.6 MB
- Lookup: Binary search within main index (no separate table)
- Total: 3.6 MB

ScriptPubKey Index:
- Unique ScriptPubKeys: ~40,000 (assuming average 2 unique per tx)
- Storage: 40,000 × (2 + 20) bytes = 880 KB
- Lookup: 40,000 × 34 bytes = 1.36 MB
- Total: 2.24 MB

Grand Total: ~5.84 MB for all indices
```

### Storage Savings vs Alternative

```
Alternative: Store 32-byte ScriptPubKeys directly (naive)
Transaction Index: 6 bytes per TX (18 bytes with offsets)
- ScriptPubKey Index: N/A (not used)
- Storage for SPKs: 200K × 32 bytes = 6.4 MB
- Savings: 73% vs 6.4 MB

**Current approach achieves:**
- 73% space savings on ScriptPubKeys vs naive approach
- Simple, sequential IDs: 1, 2, 3, ...
- No block boundary complications in IDs
- Easy to understand and maintain
- Supports up to 4.2B transactions (32-bit ID capacity)
- Upgrade path: 3-byte IDs (16M) or 4-byte IDs (4B) if needed
```

---

## Optimization Opportunities

### 1. Simple is Better

**Rationale**: Sequential global IDs are clean and simple.

**Benefits**:
- No complex formulas or bit shifting
- Easy to debug and maintain
- Predictable (tx_id = global position)
- Supports up to 4.2B transactions (32-bit IDs)
- Upgrade path: 3-byte IDs (16M) or 4-byte IDs (4B) if needed

### 2. Variable-Length Encoding

**Challenge**: ScriptPubKey lengths vary (21-33 bytes for P2PKH, 23-79 bytes for P2SH, etc.)

**Solution**: Store length as 1-2 bytes, then SPK data.

```
Format: [1 byte length][N bytes SPK]
Example: 
  - P2PKH (25 bytes): 0x13 + 25 bytes = 26 bytes vs 32 bytes
  - P2SH (23 bytes): 0x11 + 23 bytes = 24 bytes vs 32 bytes
Savings: Average ~20% per SPK
```

### 3. Bloom Filters for SPK Usage

**Challenge**: Finding all transactions using a specific ScriptPubKey requires scanning all transactions.

**Solution**: Create bloom filter per SPK.

```
For each ScriptPubKey:
  - Bloom filter containing all tx_ids where SPK was used
  - False positive rate: ~1% (tunable parameters)
  - Quick "has SPK been used?" checks
  - Full scan only on positive matches

Storage: 65K SPKs × 100 bits = 8.1 MB
Lookup: 3 hash functions (for 1% FP)
Time: O(1) filter check vs O(n) full scan
```

### 4. Caching Strategies

**Solutions**:
```
1. LRU Cache for recent transactions:
   - Cache: 1,000 recent TX lookups
   - Hit rate: ~20% (typical workload)
   - Memory: 36 KB

2. Prefix table in memory:
   - 200K prefix entries: 1.6 MB
   - Fast O(1) lookups without disk I/O
   - Load on index initialization
```

### 5. Memory-Mapped Files

**Challenge**: Loading entire indices into memory.

**Solution**: Use mmap for on-demand access.

```
Benefits:
  - No upfront memory allocation
  - OS manages paging automatically
  - Only accessed pages loaded into memory
  - Zero-copy reads for frequently accessed data
Trade-off:
  - More complex memory management
  - Potential page faults on random access
```

---

## Testing Plan

### Unit Tests

#### Global Transaction Index Tests

```python
test_global_tx_ids():
    """Test global TX ID assignment."""
    
    # Test 1: ID uniqueness
    assert all tx_ids are unique
    assert no gaps in ID numbering
    
    # Test 2: ID range capacity
    # For 200K transactions, fits within 32-bit IDs
    
    # Test 3: ID formula correctness
    for block_height, tx_index in samples:
        tx_id = block_height << 16 | tx_index
        decoded_h = tx_id >> 16
        decoded_i = tx_id & 0xFFFF
        assert decoded_h == height and decoded_i == tx_index
    
    # Test 4: Sequential ordering
    tx_ids = [get_next_tx_id() for _ in range(10)]
    assert tx_ids == [0, 1, 2, ..., 9]
```

#### ScriptPubKey Index Tests

```python
test_spk_global_index():
    """Test SPK global index."""
    
    # Test 1: ID uniqueness
    for spk_id in range(get_total_spks()):
        spk = get_spk_by_id(spk_id)
        assert spk is not None
        assert spk_hex_to_id(spk) == spk_id
    
    # Test 2: Counter overflow
    assert get_total_spks() <= 65535  # 16-bit max
    assert spk_counter == get_total_spks()
    
    # Test 3: Boundary cases
    # First SPK in first block
    # Last SPK in last indexed block
```

#### Integration Tests

```python
test_indexing_end_to_end():
    """Test complete indexing workflow."""
    
    # Fetch 10 blocks from local node
    blocks = fetch_blocks_via_rpc([latest_height - i for i in range(10)])
    
    # Index all transactions
    index_blocks(blocks)
    
    # Verify all TXIDs indexed
    assert len(tx_lookup) == total_transactions
    
    # Verify all SPKs indexed
    assert len(spk_lookup) == total_unique_spks
    
    # Random queries
    for txid in random_sample(blocks, 100):
        tx_id, location = get_tx_location(txid)
        actual = find_transaction_in_blocks(txid)
        assert location == actual
    
    for spk_hex in random_sample(blocks, 50):
        spk_id = get_spk_id(spk_hex)
        # Find all tx_ids where this SPK was used
        # Verify they match actual blockchain data
```

---

## Performance Characteristics

### Lookup Times (estimated)

| Operation | Data Structure | Time Complexity |
|-----------|----------------|-------------------|
| Global TX ID lookup | Binary search | O(log n) |
| SPK ID lookup | Hash table (34 bytes) | O(1) |
| SPK retrieval | Array by ID | O(1) |

### Memory Usage

```
Transaction index (in memory):
- Main index: 200K × 18 bytes = 3.6 MB
- Optional: Load on demand

ScriptPubKey index (in memory):
- Main index: Variable length SPKs
- Optional: Cache recent SPK assignments
```

---

## Dependencies

### Python (Phase 1 & Phase 1.5)

```
requests==2.31.0    # RPC calls
```

### Bitcoin Node

```
bitcoind (Bitcoin Core 26.0+)
RPC enabled:
  - rpcuser=<your_user>
  - rpcpassword=<your_password>
  - rpcport=18332 (testnet) or 8332 (mainnet)
```

### Rust (Phases 2-4) - TO BE ADDED IN PLAN.md

```

---

## Next Steps

### Immediate (Today)

1. **Review updated planning documentation**:
   - Read `doc/INDEX.md` for data processing plan
   - Read `doc/NODE.md` for Bitcoin node setup
   - Review updated `PLAN.md` for complete roadmap

2. **Choose implementation approach**:
   - **Option A**: Start with 100 blocks (testnet, ~1-3 hours)
   - **Option B**: Wait for full testnet sync (~70K blocks)

3. **Begin Phase 1.5: Data Processing Implementation**:
   - Create `scripts/index_blocks.py` following this plan
   - Implement global TX ID assignment (sequential 4-byte counter)
   - Implement global SPK ID assignment (sequential 2-byte counter)
   - Test with small batch (10 blocks)
   - Scale to 100 blocks
   - Verify ID uniqueness and lookup accuracy
   - Benchmark indexing performance

4. **Prepare for Phase 2**:
   - Review SealPIR library for single-server PIR
   - Or plan two-server PIR implementation
   - Design PIR server architecture

5. **Begin PIR Implementation**:
   - Implement single-server PIR (SealPIR) or two-server PIR
   - Create PIR query client
   - Set up PIR server with indexed data

**Total Estimated Time**:
- Node setup: 1-3 hours (testnet) or 2-7 days (mainnet sync)
- Data processing: 2-4 hours (implementation + testing)
- PIR implementation: 1-2 weeks
- Testing: 2-3 days
- Total: ~1-2 weeks