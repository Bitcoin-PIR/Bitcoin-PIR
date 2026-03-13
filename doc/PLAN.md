# Bitcoin PIR Implementation Plan

**Goal**: Implement single-server and two-server Private Information Retrieval (PIR) for querying Bitcoin blocks while hiding which block is being accessed.

**Tech Stack**:
- **Data fetching**: Python (easiest integration with Bitcoin APIs)
- **Core PIR**: Rust (memory safety, performance)
- **PIR approaches**: Both single-server (computational) and two-server (information-theoretic)
- **Block storage**: Raw binary format (most compact, optimal for PIR)

---

## Phase 1: Data Acquisition & Storage

### Objective
Set up local Bitcoin node, fetch blocks, and create compact indices for PIR operations.

### 1.1 Bitcoin Node Setup
- **Installation**: Install Bitcoin Core (bitcoind)
- **Configuration**: Set up RPC access and data directory
- **Network**: Use testnet for development (faster sync, no real money)
- **Detailed instructions**: See `doc/NODE.md`
- **Setup time**: 1-3 hours (testnet) or 2-7 days (mainnet)

### 1.2 Python Block Fetcher (RPC-based)
- Connect to local Bitcoin node via JSON-RPC
- Latest block: `getbestblockhash` RPC call
- Block by hash: `getblock <hash> 0` RPC call (0 = full block data)
- Block by height: `getblockhash <height>` → `getblock <hash> 0`
- Implement reverse traversal: follow `previousblockhash` to get 100 blocks
- Store each block as `.bin` file (raw binary serialization)
- **No rate limiting**: Local node = unlimited access!
- **Full transaction data**: Complete inputs, outputs, scripts

### 1.3 Block Index & Metadata
- Create index file mapping: `block_hash → file_offset + metadata`
- Store for each block:
  - Block height
  - Timestamp
  - Block hash
  - Merkle root
  - Transaction count (all transactions)
  - File size/offset
- Use JSON for simplicity: `data/index.json`

### 1.4 Data Processing & Indexing (NEW!)
- **Purpose**: Create compact indices for efficient PIR queries
- **Reference**: See `doc/INDEX.md` for detailed plan
- **Two indices**:
  1. **Transaction Location Index**: Maps TXID → [block_height, tx_index]
     - Storage: 6 bytes per transaction
     - Enables PIR queries for specific transactions
  2. **ScriptPubKey Index**: Assigns compact integer IDs to ScriptPubKeys
     - Storage: 2 bytes per ScriptPubKey (vs 32 bytes raw)
     - Savings: ~73% space reduction
- **Data Sources**: Bitcoin node RPC (`getblock` with full transaction data)
- **Implementation**: `scripts/index_blocks.py`

### Deliverables
- **Node setup**: Local Bitcoin Core running and synced
- `scripts/fetch_blocks_rpc.py` - Fetches 100 blocks via RPC
- `scripts/index_blocks.py` - Creates TXID and ScriptPubKey indices
- `data/blocks/*.bin` - Raw binary block files
- `data/index.json` - Block metadata index
- `data/tx_index.bin` - Transaction location records
- `data/tx_index_table.bin` - TXID lookup table
- `data/spk_index.bin` - ScriptPubKey storage by ID
- `data/spk_lookup.bin` - ScriptPubKey hash → ID lookup

---

## Phase 1.5: Data Processing & Indexing

### Objective
Create compact, efficient indices for Bitcoin transactions and ScriptPubKeys.

### Deliverables
- `scripts/index_blocks.py` - Indexes all transactions and ScriptPubKeys
- `data/tx_index.bin` - Transaction location records (6 bytes each)
- `data/tx_index_table.bin` - TXID lookup table (34 bytes each)
- `data/spk_index.bin` - ScriptPubKey storage by ID (variable length)
- `data/spk_lookup.bin` - ScriptPubKey hash → ID lookup (34 bytes each)
- `data/spk_meta.json` - Index metadata (counts, statistics)

**Detailed plan**: See `doc/INDEX.md`

---

## Phase 2: Single-Server PIR (SealPIR-based)

### Objective
Implement computational PIR using Microsoft's SealPIR library for single-server scenario.

### 2.1 Research & Selection
- **Primary choice**: Microsoft SealPIR (C++)
  - Proven implementation, 274× query compression
  - IEEE S&P 2018 paper backing
- **Rust integration options**:
  - Option A: FFI wrapper around compiled C++ library
  - Option B: Python SealPIR wrapper + subprocess from Rust
  - Option C: Pure Rust FHE implementation (e.g., `fhe-rs`)

### 2.2 Database Preparation
- Convert raw Bitcoin blocks to PIR-ready format:
  - Pad all blocks to uniform size (e.g., 4MB max)
  - Flat binary layout: `[block_header | tx_count | tx_1 | ... | tx_n]`
  - Calculate required SealPIR parameters based on total size
- Create database file: `data/pir_database.bin`

### 2.3 Server Implementation (Rust + FFI)
- Load PIR database into memory
- Implement endpoints:
  - `/setup` - Initialize PIR parameters
  - `/query` - Accept encrypted query, return encrypted response
- Use SealPIR C++ library via FFI for heavy operations

### 2.4 Client Implementation (Rust)
- Generate encrypted query for block index
- Send query to server via HTTP/gRPC
- Receive and decrypt response
- Verify retrieved block matches expected hash

### Deliverables
- `pir/single_server/server.rs` - PIR server
- `pir/single_server/client.rs` - PIR client
- `pir/single_server/libsealpir/` - Compiled SealPIR library
- `pir/single_server/ffi.rs` - FFI bindings

---

## Phase 3: Two-Server PIR (Information-Theoretic)

### Objective
Implement classical two-server PIR requiring no collusion between servers.

### 3.1 Protocol Design
- Use Distributed Point Functions (DPF) or simple XOR-based PIR
- Client generates random subset R of ~N/2 indices
- Server 1 receives: subset S1 = R
- Server 2 receives: subset S2 = R ⊕ {i} (XOR with queried index)
- Both servers compute XOR sum of blocks at their subset indices
- Client XORs both responses to retrieve block[i]

### 3.2 Server Implementation
- Two independent Rust servers serving identical database
- **Server 1**: Port 8080
  - Endpoint: `/query` (POST: subset indices)
  - Returns: XOR sum of blocks at indices
- **Server 2**: Port 8081
  - Endpoint: `/query` (POST: subset indices)
  - Returns: XOR sum of blocks at indices
- Both servers store full block database in memory

### 3.3 Client Implementation (Rust)
- Input: desired block index i
- Generate random subset R (cryptographically secure)
- Send parallel queries to both servers
- XOR responses: result = response_1 ⊕ response_2
- Extract block[i] from result

### 3.4 Optimizations
- Precompute XOR sums for common query patterns
- Batch multiple block queries
- Use rayon for parallel processing
- Implement SIMD for XOR operations (AVX2/NEON)

### Deliverables
- `pir/two_server/server1.rs` - First PIR server
- `pir/two_server/server2.rs` - Second PIR server
- `pir/two_server/client.rs` - Two-server PIR client
- `pir/two_server/dpf/` - DPF implementation (if using DPF)

---

## Phase 4: Testing & Benchmarking

### Objective
Verify correctness, measure performance, compare PIR approaches.

### 4.1 Correctness Tests
- **Single-server**:
  - Query 100 random blocks
  - Verify against direct file read
  - Test edge cases (index 0, index 99, out-of-bounds)
- **Two-server**:
  - Query 100 random blocks
  - Verify responses match database
  - Test with one server offline (should fail)

### 4.2 Performance Metrics
- **Single-server**:
  - Query time (latency)
  - Response size (bytes)
  - Server CPU usage per query
  - Memory footprint
- **Two-server**:
  - Total query time (parallel requests)
  - Network bandwidth (both servers)
  - Server load distribution
- **Baseline**: Direct file read time

### 4.3 Scalability Tests
- Test with varying database sizes: 10, 100, 1000 blocks
- Measure memory vs. database size
- Identify bottlenecks (network, CPU, I/O)

### Deliverables
- `tests/test_single_server.rs` - Unit tests
- `tests/test_two_server.rs` - Unit tests
- `benchmarks/bench_pir.rs` - Performance benchmarks
- `scripts/run_tests.py` - Test orchestration

---

## Project Structure

```
BitcoinPIR/
├── doc/
│   ├── PLAN.md                  # This file
│   ├── NODE.md                 # Bitcoin node setup guide
│   ├── INDEX.md                # Data processing plan
│   └── API.md                  # API documentation
├── scripts/
│   ├── fetch_blocks.py          # Phase 1: Fetch blocks (API-based, deprecated)
│   ├── fetch_blocks_rpc.py     # Phase 1.2: Fetch blocks via RPC
│   └── index_blocks.py         # Phase 1.4: Create TXID and SPK indices
├── data/
│   ├── blocks/                 # Raw binary blocks
│   │   ├── block_000001.bin
│   │   ├── block_000002.bin
│   │   └── ...
│   ├── index.json             # Block metadata
│   ├── tx_index.bin           # Transaction location records (6 bytes each)
│   ├── tx_index_table.bin     # TXID lookup table (34 bytes each)
│   ├── spk_index.bin          # ScriptPubKey storage by ID
│   ├── spk_lookup.bin          # ScriptPubKey hash → ID lookup
│   └── spk_meta.json          # Index metadata
├── pir/
│   ├── single_server/
│   │   ├── Cargo.toml
│   │   ├── build.rs
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── server.rs
│   │   │   ├── client.rs
│   │   │   └── ffi.rs
│   │   └── libsealpir/        # C++ SealPIR library
│   │       ├── CMakeLists.txt
│   │       └── src/
│   └── two_server/
│       ├── Cargo.toml
│       ├── server1.rs
│       ├── server2.rs
│       ├── client.rs
│       └── dpf/
│           └── lib.rs
├── tests/
│   ├── test_single_server.rs
│   └── test_two_server.rs
├── benchmarks/
│   └── bench_pir.rs
├── Cargo.toml                 # Rust workspace
├── requirements.txt            # Python dependencies
└── README.md
```

---

## Dependencies

### Python (Phase 1)
```
requests==2.31.0
```

### Rust (Phases 2-4)
```
[workspace]
members = ["pir/single_server", "pir/two_server"]

[dependencies]
tokio = { version = "1.35", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
bytes = "1.5"
rand = "0.8"
anyhow = "1.0"

# Single-server specific
libsealpir-sys = "0.1"  # FFI wrapper

# Two-server specific
crossbeam = "0.8"
aes = "0.8"
rayon = "1.8"

# Dev dependencies
criterion = "0.5"
```

### C++ (SealPIR wrapper)
```
Microsoft SEAL 4.0.0+
CMake 3.20+
```

---

## Timeline Estimate

- **Phase 1**: 1-3 hours (node setup) + 2-7 days (sync) OR 1-3 hours (testnet sync)
- **Phase 1.4**: 1-2 hours (indexing 100 blocks)
- **Phase 2**: 1-2 weeks (SealPIR integration + optimization)
- **Phase 3**: 3-5 days (two-server implementation)
- **Phase 4**: 2-3 days (testing + benchmarking)
- **Total**: ~2-4 weeks

**Note**: For faster development, use Bitcoin testnet (syncs in 1-3 hours). Mainnet sync takes 2-7 days but provides production data.

---

## Next Steps

Once plan is approved:
1. **Phase 1 Setup**: Follow `doc/NODE.md` to set up local Bitcoin node
2. **Wait for sync**: Bitcoin node must sync with network (testnet: 1-3 hours, mainnet: 2-7 days)
3. **Implement RPC fetcher**: Create `scripts/fetch_blocks_rpc.py` using JSON-RPC
4. **Fetch 100 blocks**: Test with small batch, then scale to 100
5. **Phase 1.4 Implementation**: Follow `doc/INDEX.md` to create TXID and ScriptPubKey indices
6. **Validate data**: Verify block integrity and completeness
7. **Proceed to Phase 2**: Implement Single-Server PIR with full block data and indices

---

## Architecture Change (Updated 2026-03-05)

### Original Approach (Abandoned)
- Fetch blocks from public APIs (BlockCypher, blockchain.info)
- **Problem**: Persistent rate limiting prevented completing Phase 1
- **Status**: Reached 91/100 blocks before hitting hard rate limits

### New Approach (Current)
- Run local Bitcoin Core node
- Use JSON-RPC for unlimited block access
- **Advantages**:
  - ✅ No rate limits
  - ✅ Full block data (all transactions)
  - ✅ True Bitcoin binary format
  - ✅ Faster (local access, no network latency)
  - ✅ Production-ready

### Trade-offs
| Aspect | API Approach | Local Node Approach |
|---------|---------------|-------------------|
| Setup time | Minutes | Hours (testnet) / Days (mainnet) |
| Disk space | 144 MB | 50 GB+ (full chain) |
| Rate limits | Yes | No |
| Data completeness | Partial (500 tx/block) | Full (all transactions) |
| Network dependency | Yes | No (after sync) |
| Production ready | No | Yes |

**Decision**: Local node approach chosen for production-quality PIR implementation.

---

## References

- **Node Setup**: `doc/NODE.md` - Complete Bitcoin Core setup guide
- **Bitcoin RPC**: https://developer.bitcoin.org/reference/rpc/
- **SealPIR**: https://github.com/microsoft/SealPIR
- **BlockCypher API**: https://www.blockcypher.com/dev/api/ (deprecated for this project)
