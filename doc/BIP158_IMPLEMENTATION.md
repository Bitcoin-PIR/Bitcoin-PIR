# BIP158 Implementation Plan for BitcoinPIR

## Decision: Use rust-bitcoin/bip158

**Chosen Implementation**: `rust-bitcoin/bip158` crate (part of rust-bitcoin library)

**Reasons**:
- ✅ Production-ready and battle-tested (2.6k stars on main repo)
- ✅ Full BIP158 implementation (GCS filters, Golomb-Rice coding, SipHash)
- ✅ Excellent documentation with inline examples
- ✅ No external dependencies
- ✅ Active maintenance
- ✅ MSRV 1.74.0+ (recent Rust)
- ✅ No-std support (for embedded/async use cases)

**Repository**: https://github.com/rust-bitcoin/rust-bitcoin/tree/master/bip158

---

## Project Structure

```
BitcoinPIR/
├── pir/                      # Rust BIP158 implementation
│   ├── Cargo.toml           # Rust project configuration
│   └── src/
│       └── lib.rs          # BlockIndexer with BIP158 support
├── scripts/                  # Python utilities (deprecated)
│   ├── index_blocks.py      # Phase 1.5 (original PIR indexing)
│   └── query_index.py      # Query original indices
├── data/
│   ├── blocks/             # Binary block files (from Bitcoin node)
│   └── filters/            # BIP158 filters (to be created)
└── doc/                     # Documentation
    ├── BIP158.md          # BIP158 overview
    ├── RUST_BIP158.md     # Rust implementations guide
    └── ...
```

---

## Implementation Approach

### Step 1: Setup Rust Project

```bash
cd pir
cargo build
```

**Dependencies** (see `pir/Cargo.toml`):
```toml
[dependencies]
bitcoin = "0.32"          # Main bitcoin crate
bitcoin-bip158 = "0.0.0"   # BIP158 module
tokio = "1.35"
serde = "1.0"
anyhow = "1.0"
```

### Step 2: Index Blocks with BIP158 Filters

```rust
use bitcoinpir::BlockIndexer;

fn main() -> anyhow::Result<()> {
    let mut indexer = BlockIndexer::new();
    
    // For each block from Bitcoin node:
    let (filter, tx_count) = indexer.add_block(&block)?;
    
    // Save filter to disk
    BlockIndexer::save_filter(block_hash, &filter, "data/filters/")?;
    
    println!("Created filter for block {}: {} bytes, {} txs", 
             block_height, filter.content.len(), tx_count);
    
    Ok(())
}
```

### Step 3: Query Filters

```rust
use bitcoinpir::BlockIndexer;

fn check_wallet_addresses(
    block_hash: BlockHash,
    filter: &BlockFilter,
    wallet_scripts: &[bitcoin::ScriptBuf]
) -> anyhow::Result<bool> {
    BlockIndexer::filter_matches_any(
        filter,
        block_hash,
        wallet_scripts
    )
}
```

---

## Comparison: Original Index vs BIP158

### Original Approach (Phase 1.5)

**Data Structures**:
- `tx_global_index.bin`: 18 bytes per transaction
- `spk_global_index.bin`: Variable length ScriptPubKeys
- `spk_global_lookup.bin`: 34 bytes per unique SPK

**Query Flow**:
1. Client queries for transaction by TXID
2. Binary search in `tx_global_index.bin`
3. Read 18-byte record
4. **Problem**: Reveals which transaction is being queried (no privacy!)

**Storage** (100 blocks, ~200K txs):
- TX index: 3.6 MB
- SPK index: 2.2 MB
- Total: 5.84 MB

### BIP158 Approach

**Data Structures**:
- `filters/{block_hash}.filter`: ~50 bytes per block

**Query Flow**:
1. Client downloads filter (~50 bytes)
2. Client tests filter against wallet scripts locally
3. **Benefit**: Server doesn't learn which scripts are relevant!

**Storage** (100 blocks):
- Filters: ~5 KB
- **Savings**: 99.9% vs original index!

---

## Privacy Comparison

| Aspect | Original Index | BIP158 |
|---------|----------------|----------|
| Server learns which TX is queried | ✅ Yes (privacy leak!) | ❌ No |
| Server learns which SPK is queried | ✅ Yes (privacy leak!) | ❌ No |
| Bandwidth per query | ~18 bytes (index record) | ~50 bytes (filter) |
| False positives | ❌ No | ✅ 0.001% (1 in 100K) |
| Client complexity | Simple binary search | Filter matching |
| Setup | Create indices | Create filters |

**Winner**: BIP158 provides better privacy at similar bandwidth cost!

---

## Hybrid Approach (Optional)

Combine BIP158 with PIR for maximum privacy:

1. **Step 1**: Use BIP158 to narrow candidate blocks
   - Download filters for all blocks in range
   - Test against wallet scripts locally
   - Identify blocks containing relevant transactions
   
2. **Step 2**: Use PIR only for relevant blocks
   - Instead of downloading full blocks
   - Use PIR to retrieve specific blocks
   - **Benefit**: Server learns even less!

**Privacy Benefits**:
- Without BIP158: Server sees PIR queries for many blocks
- With BIP158: Server sees PIR queries for only relevant blocks
- **Result**: Reduced server knowledge

**Trade-offs**:
- More complex implementation
- Higher client-side computation (filter matching)
- Slightly higher initial bandwidth (download all filters first)

---

## Implementation Steps

### Phase A: Infrastructure (1-2 hours)
- [ ] Create `pir/` Rust project
- [ ] Add `bitcoin = "0.32"` dependency
- [ ] Add `bitcoin-bip158 = "0.0.0"` dependency
- [ ] Implement basic `BlockIndexer` structure
- [ ] Create `data/filters/` directory

### Phase B: Filter Creation (2-3 hours)
- [ ] Implement `add_block()` method
- [ ] Implement UTXO tracking for input scripts
- [ ] Test filter creation on sample block
- [ ] Verify filter size (~50 bytes average)
- [ ] Add filter serialization to disk

### Phase C: Filter Querying (1-2 hours)
- [ ] Implement `filter_matches_any()` method
- [ ] Implement `filter_matches_all()` method
- [ ] Test query against wallet scripts
- [ ] Verify false positive rate (<0.001%)

### Phase D: Integration with Bitcoin Node (2-3 hours)
- [ ] Fetch blocks via Bitcoin RPC
- [ ] Process blocks in batch (10, 100 blocks)
- [ ] Create filters for all blocks
- [ ] Save filters to `data/filters/`

### Phase E: Testing & Benchmarking (1-2 hours)
- [ ] Test filter creation speed (target: <0.5ms per block)
- [ ] Test filter query speed (target: <0.1ms per query)
- [ ] Measure storage usage (target: ~5 KB for 100 blocks)
- [ ] Verify privacy properties (server learns nothing)

**Total Estimated Time**: 7-12 hours

---

## Usage Examples

### Creating Filters for All Blocks

```rust
use bitcoinpir::BlockIndexer;
use bitcoin::Block;
use std::path::PathBuf;

fn create_all_filters(blocks: Vec<Block>) -> anyhow::Result<()> {
    let mut indexer = BlockIndexer::new();
    
    for block in &blocks {
        let (filter, tx_count) = indexer.add_block(block)?;
        
        let filter_path: PathBuf = format!("data/filters/{:x}.filter", block.block_hash())
            .into();
        
        BlockIndexer::save_filter(block.block_hash(), &filter, "data/filters/")?;
        
        println!("Block {}: {} txs, filter size: {} bytes", 
                 block.block_hash(), tx_count, filter.content.len());
    }
    
    Ok(())
}
```

### Scanning Blockchain for Wallet

```rust
use bitcoinpir::BlockIndexer;
use bitcoin::BlockHash;
use std::fs;

fn scan_for_wallet(
    start_height: u32,
    end_height: u32,
    wallet_scripts: &[bitcoin::ScriptBuf]
) -> anyhow::Result<Vec<BlockHash>> {
    let mut matching_blocks = Vec::new();
    
    for height in start_height..=end_height {
        let block_hash = get_block_hash(height)?;
        let filter = BlockIndexer::load_filter(format!("data/filters/{:x}.filter", block_hash))?;
        
        if BlockIndexer::filter_matches_any(&filter, block_hash, wallet_scripts)? {
            println!("Block {} matches wallet!", height);
            matching_blocks.push(block_hash);
        }
    }
    
    Ok(matching_blocks)
}
```

### Full Wallet Sync Workflow

```rust
use bitcoinpir::BlockIndexer;
use bitcoin::{Address, Network};
use tokio::runtime::Runtime;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Connect to Bitcoin node
    let rpc_url = "http://127.0.0.1:18332";
    let rpc_user = "user";
    let rpc_password = "pass";
    
    let client = BitcoinRpcClient::new(rpc_url, rpc_user, rpc_password)?;
    
    // 2. Get wallet addresses to watch
    let wallet_addresses = get_wallet_addresses()?;
    let wallet_scripts: Vec<bitcoin::ScriptBuf> = wallet_addresses
        .iter()
        .map(|addr| addr.script_pubkey())
        .collect();
    
    // 3. Scan blockchain
    let tip_height = client.get_block_count()?;
    let mut indexer = BlockIndexer::new();
    
    for height in 0..=tip_height {
        // Fetch block
        let block_hash = client.get_block_hash(height)?;
        let block_data = client.get_block(&block_hash, 2)?;
        let block = bitcoin::consensus::deserialize(&block_data)?;
        
        // Create filter (or load from disk)
        let filter = indexer.create_filter_for_block(&block, &utxo_set)?;
        
        // Test against wallet scripts
        if BlockIndexer::filter_matches_any(&filter, block_hash, &wallet_scripts)? {
            println!("Relevant block found at height {}", height);
            
            // Download and process block
            for tx in block.transactions() {
                process_transaction_for_wallet(&tx)?;
            }
        }
    }
    
    Ok(())
}
```

---

## Performance Targets

Based on rust-bitcoin/bip158 benchmarks:

| Metric | Target | Rationale |
|--------|---------|------------|
| Filter creation (2K tx block) | <0.5 ms | Rust implementation is fast |
| Filter creation (2 tx block) | <0.1 ms | Small blocks are faster |
| Filter size (average) | 50-100 bytes | ~10-50 bytes per tx |
| Query (single element) | <0.05 ms | SipHash + binary search |
| Query (100 elements) | <0.1 ms | Batch processing |
| Storage (100 blocks) | <10 KB | Very compact |
| False positive rate | <0.001% | BIP158 specification |

---

## Integration with Existing Phase 1.5

The original Phase 1.5 implementation (`scripts/index_blocks.py`) created binary indices. We now have two options:

### Option 1: Replace with BIP158
- Keep Bitcoin node setup
- Replace `scripts/index_blocks.py` with Rust BIP158 implementation
- Delete old index files
- **Benefit**: Better privacy, simpler code

### Option 2: Keep Both
- Keep original indices for fast TXID lookups
- Add BIP158 filters for private queries
- Use indices for non-sensitive queries
- Use filters for sensitive queries
- **Benefit**: Flexibility, performance tuning

**Recommendation**: Option 1 (replace with BIP158) for cleaner architecture.

---

## Migration Path

### From Original Indices to BIP158

```bash
# 1. Remove old indices
rm data/tx_global_index.bin
rm data/spk_global_index.bin
rm data/spk_global_lookup.bin
rm data/index_meta.json

# 2. Create filters directory
mkdir -p data/filters

# 3. Run Rust filter creator
cd pir
cargo run --release -- -- create-filters \
    --rpc-url http://127.0.0.1:18332 \
    --rpc-user <user> \
    --rpc-password <password> \
    --start-height 0 \
    --count 100

# 4. Verify filters
ls -lh data/filters/
# Should see ~100 filter files, each ~50-100 bytes
```

---

## Next Steps

1. **Complete Phase A** (Infrastructure):
   - Create Rust project structure
   - Add dependencies
   - Implement `BlockIndexer`

2. **Complete Phase B** (Filter Creation):
   - Implement filter creation logic
   - Test with sample block
   - Verify filter sizes

3. **Complete Phase C** (Filter Querying):
   - Implement query methods
   - Test against wallet scripts
   - Verify correctness

4. **Complete Phase D** (Integration):
   - Connect to Bitcoin node via RPC
   - Fetch blocks and create filters
   - Save filters to disk

5. **Complete Phase E** (Testing):
   - Benchmark performance
   - Verify privacy properties
   - Document results

---

## References

- **rust-bitcoin/bip158**: https://github.com/rust-bitcoin/rust-bitcoin/tree/master/bip158
- **BIP158 specification**: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
- **Rust BIP158 guide**: `doc/RUST_BIP158.md`
- **BIP158 overview**: `doc/BIP158.md`
