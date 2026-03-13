# Bitcoin PIR Project

This project implements Private Information Retrieval (PIR) and BIP158 compact block filters for querying Bitcoin blockchain data while hiding which block is being accessed.

**Current Approach**: Using BIP158 (rust-bitcoin/bip158) for production-ready, privacy-preserving blockchain queries.

## Project Status

### ✅ Decision: Use rust-bitcoin/bip158

**Chosen Implementation**: `rust-bitcoin/bip158` crate (production-ready, 2.6k stars)

**Reasons**:
- Production-ready and battle-tested
- Full BIP158 implementation (GCS filters, Golomb-Rice coding)
- Excellent documentation
- No external dependencies
- Better privacy than original indexing approach

**Implementation Status**: Rust project created in `pir/` directory

---

### 🔄 Phase 1: Data Acquisition (Node Setup)

**Approach: Local Bitcoin node via RPC (unlimited access)**

**Data Summary:**
- Blocks to fetch: 100 (initial target)
- Network: Bitcoin testnet (faster sync, no real money)
- Setup time: ~1-3 hours (node sync)
- Data format: Raw binary blocks + full transaction data
- Storage location: `data/blocks/`

**Status:**
- Node setup required (see `doc/NODE.md`)
- Previous API-based fetch attempts deprecated (rate limiting)
- Phase 1.5 scripts created (not yet tested with live data)

**Phase 1.5: Data Processing** (Scripts Created, Pending Testing)
- **Original Approach** (Python):
  - `scripts/index_blocks.py`: Index blockchain data via RPC
  - `scripts/query_index.py`: Query generated indices
  - Global transaction index: 4-byte sequential IDs
  - Global ScriptPubKey index: 2-byte sequential IDs
  - Space savings: ~73% for ScriptPubKeys
  - **Problem**: Reveals which transaction/script is being queried (privacy leak!)

- **New Approach** (Rust + BIP158):
  - `pir/`: Rust project using `rust-bitcoin/bip158`
  - BIP158 compact block filters: ~50 bytes per block
  - **Benefit**: Server doesn't learn which scripts are relevant!
  - **Storage**: ~5 KB for 100 blocks (99.9% savings vs original)
  - **Status**: Implementation plan created (`doc/BIP158_IMPLEMENTATION.md`)

**Privacy Analysis**: `doc/LIGHT_CLIENT_DATA.md` - Detailed analysis of light client data requirements and privacy implications

**Key Finding**: BIP158 provides good privacy at practical bandwidth (10-100 MB vs 600 GB for naive approach)

**Reference**: `doc/BIP158.md`, `doc/RUST_BIP158.md`, `doc/BIP158_IMPLEMENTATION.md`, `doc/LIGHT_CLIENT_DATA.md`

### 🚧 Phase 2: Single-Server PIR (Pending)
Implementation using Microsoft's SealPIR library.

### 🚧 Phase 3: Two-Server PIR (Pending)
Implementation using information-theoretic PIR with two non-colluding servers.

### 🚧 Phase 4: Testing & Benchmarking (Pending)
Correctness verification and performance measurement.

---

## Directory Structure

```
BitcoinPIR/
├── doc/
│   ├── PLAN.md                         # Detailed implementation plan
│   ├── NODE.md                        # Bitcoin node setup guide
│   ├── INDEX.md                       # Data processing plan (TXID/SPK indexing)
│   ├── BIP158.md                       # BIP158 compact block filters
│   ├── RUST_BIP158.md                # Rust BIP158 implementation guide
│   ├── BIP158_IMPLEMENTATION.md        # BIP158 implementation plan for BitcoinPIR
│   ├── LIGHT_CLIENT_DATA.md            # Privacy analysis & data requirements
│   └── README.md                    # Documentation overview
├── scripts/
│   ├── fetch_blocks.py.broken       # Deprecated: blockchain.info API fetcher
│   ├── fetch_blocks_v2.py           # Deprecated: BlockCypher API fetcher (rate limited)
│   ├── continue_fetch.py            # Deprecated: API-based continuation
│   ├── index_blocks.py             # Phase 1.5: Original indexing (Python)
│   └── query_index.py              # Query the generated indices
├── pir/                              # BIP158 Rust implementation (NEW)
│   ├── Cargo.toml                    # Rust project configuration
│   └── src/
│       └── lib.rs                 # BlockIndexer with BIP158 support
├── data/
│   ├── blocks/                     # Binary block files (from local node, to be created)
│   ├── filters/                    # BIP158 compact block filters (to be created)
│   ├── tx_global_index.bin          # Global transaction index (original approach)
│   ├── spk_global_index.bin         # ScriptPubKey index (original approach)
│   ├── spk_global_lookup.bin        # ScriptPubKey hash → ID lookup (original approach)
│   └── index_meta.json             # Index metadata (original approach)
├── pir/                        # PIR implementations (to be created)
│   ├── single_server/         # Single-server PIR
│   └── two_server/           # Two-server PIR
├── tests/                      # Unit tests (to be created)
└── requirements.txt            # Python dependencies
```

---

## Usage

### 1. Setup Bitcoin Node

See `doc/NODE.md` for complete setup instructions:

```bash
# Option A: Testnet (recommended for development, 1-3 hours sync)
bitcoin-qt -testnet -rpcuser=<user> -rpcpassword=<pass> -rpcport=18332

# Option B: Mainnet (for production, 2-7 days sync)
bitcoin-qt -rpcuser=<user> -rpcpassword=<pass> -rpcport=8332
```

### 2. Index Blockchain Data (Phase 1.5)

After node syncs, run the indexer:

```bash
# Install dependencies
pip install -r requirements.txt

# Create global indices for transactions and ScriptPubKeys
python3 scripts/index_blocks.py --start-height <height> --count <count> --rpc-user <user> --rpc-password <pass>

# Example: Index 100 blocks starting at tip
python3 scripts/index_blocks.py --count 100 --from-tip --rpc-user <user> --rpc-password <pass>

# Example: Index specific block range
python3 scripts/index_blocks.py --start-height 1000000 --count 100 --rpc-user <user> --rpc-password <pass>

# Reset and re-index
python3 scripts/index_blocks.py --count 100 --from-tip --reset --rpc-user <user> --rpc-password <pass>
```

### 3. Query Indices

After indexing, query the indices:

```bash
# Show index summary
python3 scripts/query_index.py --summary

# Get transaction by global ID
python3 scripts/query_index.py --get-tx 42

# List first 10 transactions
python3 scripts/query_index.py --get-all-tx

# Get ScriptPubKey by global ID
python3 scripts/query_index.py --get-spk 10

# Get ScriptPubKey ID by hex value
python3 scripts/query_index.py --get-spk-by-hex <spk_hex>

# List first 10 ScriptPubKeys
python3 scripts/query_index.py --get-all-spk
```

### 4. Create BIP158 Filters (Alternative to PIR)

After indexing, use BIP158 for private queries:

```bash
# Build Rust filter creator
cd pir
cargo build --release

# Create filters for 100 blocks
cargo run --release -- -- create-filters \
    --rpc-url http://127.0.0.1:18332 \
    --rpc-user <user> \
    --rpc-password <password> \
    --start-height 0 \
    --count 100

# Query filters
cargo run --release -- -- query-filters \
    --filters-dir data/filters/ \
    --wallet-addresses <address1>,<address2>
```

### 5. Query PIR Server (Phase 2+)

After PIR implementation, query the server:

```bash
# Query transaction by TXID
python3 scripts/pir_client.py --query-tx <txid>

# Query all transactions using a ScriptPubKey
python3 scripts/pir_client.py --query-spk <spk_hex>
```

---

## Next Steps

1. **Set up Bitcoin node**:
    - Follow `doc/NODE.md` instructions
    - Choose: testnet (1-3 hours) or mainnet (2-7 days)
    - Wait for blockchain sync

2. **Implement BIP158 filter creation** (NEW):
    - Complete Phase A: Setup Rust project in `pir/`
    - Complete Phase B: Implement filter creation logic
    - Complete Phase C: Implement filter query logic
    - Complete Phase D: Integrate with Bitcoin node RPC
    - Complete Phase E: Test and benchmark
    - See `doc/BIP158_IMPLEMENTATION.md` for details

3. **Optional: Implement PIR** (or use BIP158 instead):
    - Single-server PIR (SealPIR) if needed
    - Two-server PIR (information-theoretic) if needed
    - Consider hybrid: BIP158 to narrow + PIR for retrieval

4. **Testing & Benchmarking**:
    - Verify BIP158 correctness
    - Benchmark filter creation and query performance
    - Compare BIP158 vs PIR approaches
    - Document results

---

## Dependencies

### Python (Phase 1 & Phase 1.5)
```bash
pip install -r requirements.txt
```
Current dependencies:
```
requests==2.31.0    # RPC calls to Bitcoin node
```

### Rust (Phases 2-4, to be installed)
```
tokio = "1.35"
serde = "1.0"
bytes = "1.5"
rand = "0.8"
sealpir (or similar PIR library)
```

---

## Technical Notes

### Local Bitcoin Node
- **RPC Methods**: `getblock <hash> 2`, `getbestblockhash`, `getblockhash <height>`
- **Format**: Full block data with all transactions (inputs, outputs, scripts)
- **Benefits**: Unlimited access, complete transaction data, no rate limits
- **Setup**: See `doc/NODE.md` for detailed instructions

### Index Architecture
- **Transaction IDs**: 4-byte sequential global IDs (1, 2, 3, ... N)
  - Independent of block boundaries
  - Supports up to 4.2B transactions
  - Storage: 18 bytes per transaction record
- **ScriptPubKey IDs**: 2-byte sequential global IDs
  - 87% space savings vs 32-byte hashes
  - Storage: 34 bytes per unique SPK in lookup table
- **Reference**: `doc/INDEX.md` for complete specification

---

## Troubleshooting

### Bitcoin Node Issues
- **Node won't start**: Check `~/.bitcoin/debug.log` for errors
- **RPC connection refused**: Verify RPC credentials and port (testnet: 18332, mainnet: 8332)
- **Sync stuck**: Check network connectivity and disk space

### Indexing Issues
- **No blocks indexed**: Ensure Bitcoin node is synced
- **RPC timeout**: Increase RPC timeout in script settings
- **Index file errors**: Delete `data/` directory and re-index

---

## References

- **Plan**: See `doc/PLAN.md` for detailed implementation roadmap
- **Node Setup**: See `doc/NODE.md` for Bitcoin node installation
- **Index Design**: See `doc/INDEX.md` for data processing specification
- **PIR Background**:
  - Microsoft SealPIR: https://github.com/microsoft/SealPIR
  - PIR Tutorial: https://learnblockchain.cn/article/21987

---

## License

MIT License - See LICENSE file for details
