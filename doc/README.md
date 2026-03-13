# Documentation Summary

This document provides an overview of all planning and setup documentation created for the Bitcoin PIR project.

---

## Documentation Files

| File | Purpose | Status |
|-------|----------|--------|
| `PLAN.md` | Complete implementation roadmap for all phases | ✅ Updated |
| `NODE.md` | Bitcoin node setup guide (bitcoind) | ✅ Complete |
| `INDEX.md` | Data processing plan (TXID & SPK indexing) | ✅ Complete |
| `BIP158.md` | BIP158 compact block filters overview | ✅ New |
| `RUST_BIP158.md` | Rust BIP158 implementation guide | ✅ New |
| `BIP158_IMPLEMENTATION.md` | BIP158 implementation plan for BitcoinPIR | ✅ New |
| `LIGHT_CLIENT_DATA.md` | Light client privacy & data requirements analysis | ✅ New |
| `PIR_AFTER_BIP158.md` | Why use PIR after BIP158? (hybrid approach) | ✅ New |
| `PHASE1_COMPLETE.md` | Initial Phase 1 completion report | ⚠️ Deprecated |
| `PHASE1_FINAL.md` | Final Phase 1 status report | ⚠️ Deprecated |

---

## PIR_AFTER_BIP158.md - Why PIR After BIP158?

**Purpose**: Explains when and why to use PIR after BIP158, addressing the key privacy nuance.

**Key Questions Answered**:
- What does PIR add to BIP158 approach?
- Why not just use BIP158 alone?
- What's the "dummy query" problem?
- When is hybrid worth the complexity?

**Key Findings**:
- PIR's primary value: **Hide which blocks matched** (not just retrieve them)
- Without PIR: Server sees `getblock(hash_102)`, `getblock(hash_104)` → knows exactly which blocks contain wallet TXs
- With PIR: Server sees PIR queries for blocks 0-1000 → cannot distinguish matches
- Critical insight: To get privacy, you must PIR-query ALL blocks (including non-matches)
- Alternative: Use PIR alone with BIP158 for client-side filtering

**Recommendation**:
- Use BIP158 alone for most practical use cases (good privacy, fast, simple)
- Consider PIR for research scenarios requiring information-theoretic privacy
- Hybrid approach is complex and has "dummy query" problem

---

**Purpose**: Analysis of data requirements for Bitcoin light clients and privacy implications of different approaches.

**Sections**:
1. Scenario analysis (verify TX, broadcast TX, sync wallet)
2. Information leakage by approach (naive SPV, BIP158, PIR)
3. Bandwidth requirements comparison
4. Privacy hierarchy (best to worst)
5. Minimum data requirements by scenario
6. Privacy-enhanced architecture design
7. Recommendations for BitcoinPIR

**Key Findings**:
- **Most sensitive scenario**: Wallet sync (reveals most information)
- **Privacy hierarchy**: PIR (best) > BIP158 > Naive SPV (worst)
- **Bandwidth**: BIP158 ~10-100 MB vs Naive ~600 GB (99% savings!)
- **Recommendation**: Use BIP158 as primary, add PIR for sensitive operations
- **Hybrid approach**: Best balance of privacy and practicality

**Critical Insight**: BIP158 reveals block ranges but not which scripts are being tested, which is much better than naive SPV.

---

**Purpose**: Overview of BIP158 (Compact Block Filters) as an alternative to PIR for private blockchain queries.

**Sections**:
1. Overview and purpose
2. How BIP158 works (GCS filters, Golomb-Rice coding)
3. Implementation options (Bitcoin Core, Rust, Python, Go)
4. Using BIP158 in your project
5. BIP158 vs PIR comparison
6. Hybrid approach (BIP158 + PIR)
7. Performance benchmarks
8. Light client integration example
9. References and resources

**Key Insights**:
- ✅ BIP158 is production-ready and implemented in Bitcoin Core since v0.19.0
- ✅ Faster than PIR (~1ms vs 10-100ms per query)
- ✅ No false positives with proper implementation
- ❌ Requires pre-downloading filter headers (~5 MB for full chain)
- ❌ Server can lie about matches (vs information-theoretic PIR)
- ✅ Bandwidth efficient (~50 bytes per filter vs 1-2 GB per 100 blocks)

**Use Cases**:
- Light client wallets
- Mobile applications
- SPV clients
- Alternative to PIR for BitcoinPIR

---

## RUST_BIP158.md - Rust BIP158 Implementations

**Purpose**: Comprehensive guide to Rust implementations of BIP158 for BitcoinPIR project.

**Sections**:
1. Summary of Rust BIP158 implementations (2 production-ready)
2. rust-bitcoin/bip158 (recommended)
   - Repository info, features, API overview
   - Usage examples with code snippets
   - Performance characteristics
   - Integration in Cargo.toml
3. niebla-158 (alternative, WIP)
   - High-level orchestrator design
   - Wallet integration traits
   - Comparison with rust-bitcoin
4. electrs (production server)
   - Full Electrum/BIP158 server
5. Recommendations for BitcoinPIR
6. Integration examples for PIR server
7. Performance benchmarks
8. Test coverage
9. Documentation quality

**Key Findings**:
- ✅ **rust-bitcoin/bip158** (Recommended for BitcoinPIR):
  - Production-ready, 2.6k stars
  - Full BIP158 implementation
  - Excellent documentation
  - No external dependencies
  - Active maintenance
- ⚠️ **niebla-158**:
  - Still work-in-progress
  - High-level workflow automation
  - Async/await support
  - Not yet production-tested
- ✅ **electrs**:
  - Full production server implementation
  - 1.3k stars
  - Battle-tested

**Recommendation**: Use `rust-bitcoin/bip158` for BitcoinPIR due to maturity and integration with rust-bitcoin ecosystem.

---

## PLAN.md - Main Roadmap

**Purpose**: Master plan for entire PIR implementation project.

**Sections**:
1. Overview (Tech stack, goals)
2. Phase 1: Data Acquisition (node setup, RPC fetching, block indexing)
3. Phase 1.4: Data Processing (TXID index, ScriptPubKey index) - **NEW**
4. Phase 2: Single-Server PIR (SealPIR integration)
5. Phase 3: Two-Server PIR (information-theoretic)
6. Phase 4: Testing & Benchmarking
7. Project structure
8. Dependencies
9. Timeline estimate

**Key Changes (2026-03-05)**:
- **Architecture Update**: From block-relative to global transaction IDs
  - Global 4-byte TX IDs: `(height << 16) | tx_index`
  - Block-independent queries enabled
  - Supports up to 65,536 transactions per block
- **SPK Index Enhancement**: From single file to multi-file buckets
  - 2-byte hash prefixes split into 65,536 files
  - Binary search within buckets: O(log M) vs O(n)
  - Space savings: 87% (2-byte IDs vs 32-byte hashes)
  - Memory efficient: Load only relevant bucket
- **File Structure Update**:
  - New files: tx_global_index.bin, tx_global_prefix_index.bin
  - SPK bucket files: spk_0000.bin to spk_ffff.bin (65,536 files)
  - Total index storage: ~60 MB for 100 blocks
- **Timeline Update**: Added Phase 1.4 (Data Processing): 2-4 hours
- **Dependencies**: Added Python requests for Bitcoin JSON-RPC
Schema: TXID (32 bytes) → [block_height (4 bytes), tx_index (2 bytes), block_offset (8 bytes)]
Storage: 6 bytes per transaction
File: data/tx_index.bin
```

### Index 2: ScriptPubKey Index
```
Schema:
  - spk_index.bin: ID (2 bytes) → ScriptPubKey (variable length)
  - spk_lookup.bin: hash(ScriptPubKey) (32 bytes) → ID (2 bytes)
  - spk_meta.json: Metadata (total count, next ID)

ID Assignment Strategy:
  - Counter starts at 0
  - Each new unique ScriptPubKey gets next ID
  - Counter increments per new key

Storage Savings:
  10,000 SPKs: 320 KB (raw) → 20 KB (indexed) = 300 KB saved (94%)
  1,000,000 SPKs: 32 MB (raw) → 2 MB (indexed) = 30 MB saved (94%)
```

**Data Sources**:
- Bitcoin RPC: `getblock <hash> 2` (gets full transaction data)
- Process `vin` and `vout` arrays for ScriptPubKeys
- Extract all unique ScriptPubKeys

**Estimated Sizes (100 blocks, ~2000 tx/block)**:
- Transaction index: 8 MB total
- ScriptPubKey index: 2.2 MB total
- Grand total: ~10 MB for all indices

**Query Flow**:
1. Client queries: "Find transaction by TXID"
   - Hash TXID → lookup in tx_index_table.bin
   - Read record → know block height and position
2. Client queries: "Show SPK usage history"
   - Hash SPK → lookup in spk_lookup.bin
   - Get ID (2 bytes instead of 32 bytes)
   - Query transactions using this ID

**Optimization Opportunities**:
1. Compression (variable-length encoding, delta encoding)
2. Bloom filters for quick "exists?" checks
3. Sharding by block height ranges
4. Caching recent assignments

**Implementation Phases**:
- Phase A: Infrastructure (directory structure, RPC connection)
- Phase B: ScriptPubKey Indexing (ID assignment, storage)
- Phase C: Transaction Indexing (TXID mapping, file writes)
- Phase D: Validation (verify accessibility, uniqueness)
- Phase E: Integration (unified query API)

---

## PHASE1_COMPLETE.md & PHASE1_FINAL.md (Deprecated)

**Status**: These files document the initial API-based approach that was abandoned due to rate limiting.

**Content**:
- Initial attempts with Blockchain.info API (failed: HTTP 429)
- Switched to BlockCypher API (partially successful: 71/100 blocks)
- Hit persistent rate limits even with backoff
- Decision: Switch to local Bitcoin node approach

**Recommendation**: These documents kept for reference but superseded by local node approach in `PLAN.md`.

---

## Updated Workflow

### Current Implementation Plan

```
1. Setup Bitcoin Node (doc/NODE.md)
   ├─ Install Bitcoin Core
   ├─ Configure RPC access
   └─ Wait for sync (1-3 hours testnet)

2. Fetch Blocks (PLAN.md Phase 1.2)
   ├─ Use JSON-RPC: getbestblockhash, getblockhash, getblock
   ├─ Store as raw binary (.bin files)
   ├─ No rate limits (unlimited access!)
   └─ Full transaction data

3. Process Blocks (doc/INDEX.md)
    ├─ Index transactions: Global TX ID assignment
    │   ├─ 4-byte IDs: Simple formula (height << 16) | tx_index
    │   ├─ 18-byte records: tx_id, height, tx_index, offset
    │   └─ Supports: 65,536 transactions per block
    ├─ Index ScriptPubKeys: Bucketed by 2-byte hash prefix
    │   ├─ 2-byte IDs: Save 87% space vs 32-byte hashes
    │   ├─ 65,536 bucket files: spk_0000.bin to spk_ffff.bin
    │   ├─ Binary search within buckets: O(log M) lookup
    │   └─ Optional: spk_global_hash.bin for O(1) lookup
    ├─ Create prefix table for O(1) TX lookups
    ├─ Create lookup tables for SPK
    ├─ Create metadata files
    └─ Total: ~10 MB of indices (~2 MB SPK + buckets)
    └─ Full transaction data via JSON-RPC

4. Implement PIR (PLAN.md Phase 2)
   ├─ Single-server (SealPIR)
   ├─ Two-server (information-theoretic)
   └─ Test & benchmark
```

### Decision: Why Local Node?

| Aspect | API Approach | Local Node |
|---------|--------------|-------------|
| Setup time | Minutes | Hours (testnet) / Days (mainnet) |
| Rate limits | Yes (persistent) | No |
| Data completeness | Partial (500 tx/block) | Full (all transactions) |
| Network dependency | Yes | No (after sync) |
| Production ready | No | Yes |

**Result**: Local node approach chosen for production-quality PIR.

---

## Quick Reference

### Start Here

1. **Read `doc/PIR_AFTER_BIP158.md`** (NEW) to understand:
    - What PIR adds to BIP158 approach
    - Why PIR's main value is hiding which blocks matched
    - When hybrid is worth the complexity
2. **Read `doc/LIGHT_CLIENT_DATA.md`** to understand:
    - What data light clients need
    - Privacy implications of different approaches
    - Why wallet sync is the privacy bottleneck
3. **Read `doc/BIP158.md`** to understand compact block filters
4. **Read `doc/RUST_BIP158.md`** to learn about Rust implementations
2. **Read `doc/RUST_BIP158.md`** to learn about Rust implementations
3. **Read `doc/BIP158_IMPLEMENTATION.md`** for BitcoinPIR implementation plan
4. **Read `doc/NODE.md`** for node setup instructions
2. **Follow setup steps** for your platform (macOS/Linux/Windows)
3. **Choose testnet** for faster development (recommended)
4. **Wait for sync** (monitor progress)
5. **When synced**, proceed to Phase 1.2 block fetching

### Then

1. **Implement BIP158 filters** (Recommended approach):
    - Read `doc/BIP158_IMPLEMENTATION.md` for detailed plan
    - Complete Phases A-E in `pir/` directory
    - Create filters for blocks from Bitcoin node
    - Query filters against wallet scripts
    - **Benefit**: Better privacy than original indexing!

2. **Understand PIR's role in hybrid approach** (if needed):
    - Read `doc/PIR_AFTER_BIP158.md` for detailed explanation
    - Key insight: PIR hides WHICH blocks matched (not just retrieves them)
    - Learn about "dummy query" problem and alternatives
    - Decide: PIR alone, BIP158 alone, or hybrid

3. **Alternative: Continue with original approach** (deprecated):
    - Implement `scripts/index_blocks.py` (Python)
    - Create binary indices (privacy leak!)
    - **Not recommended**: Poor privacy compared to BIP158

2. **Implement block fetcher** using RPC (see PLAN.md Phase 1.2)
3. **Implement data processor** (see doc/INDEX.md)
4. **Test with small batch** (10 blocks)
5. **Scale to 100 blocks**
5. **Proceed to Phase 2**: PIR implementation

---

## File Sizes Reference

```
doc/
├── PLAN.md                         372 lines (main roadmap)
├── NODE.md                        465 lines (setup guide)
├── INDEX.md                       657 lines (data processing plan)
├── BIP158.md                       645 lines (compact block filters)
├── RUST_BIP158.md                800+ lines (Rust implementation guide)
├── BIP158_IMPLEMENTATION.md        600+ lines (implementation plan for BitcoinPIR)
├── LIGHT_CLIENT_DATA.md            600+ lines (privacy & data requirements analysis)
├── PIR_AFTER_BIP158.md            500+ lines (why PIR after BIP158)
├── PHASE1_COMPLETE.md            170 lines (deprecated)
└── PHASE1_FINAL.md                186 lines (deprecated)

Total: ~5,000+ lines of documentation
```

---

## Next Actions

### Immediate (Today)

1. **Review updated planning documentation**:
    - Read `doc/BIP158.md` for BIP158 compact block filters
    - Read `doc/RUST_BIP158.md` for Rust implementation options
    - Read `doc/BIP158_IMPLEMENTATION.md` for BitcoinPIR implementation plan
    - Read `doc/INDEX.md` for data processing architecture (original approach)
    - Read `doc/NODE.md` for Bitcoin node setup
    - Review updated `PLAN.md` for complete roadmap
    - Review this `README.md` for overview

2. **Choose implementation approach**:
    - **Option A (Recommended)**: Use BIP158 filters (rust-bitcoin/bip158)
      - Production-ready, privacy-preserving
      - Better than original indexing
      - See `doc/BIP158_IMPLEMENTATION.md` for plan
    - **Option B**: Original indexing approach (Python, `scripts/index_blocks.py`)
      - Privacy leak (server learns which TX/SPK you query!)
      - Kept for reference, not recommended
    - **Option C**: Implement PIR (single-server or two-server)
      - Information-theoretic privacy
      - Slower than BIP158
      - See `PLAN.md` Phase 2-3
    - **Option D**: Hybrid approach (BIP158 + PIR)
      - Use BIP158 to narrow blocks
      - Use PIR only for relevant blocks
      - Maximum privacy at cost of complexity
    - **Recommendation**: Option A for production (BIP158), Option D for research (hybrid)

3. **Set up Bitcoin testnet node**:
   - Follow `doc/NODE.md` installation steps
   - Wait for partial sync (1-2 hours sufficient)
   - Start indexing in parallel with sync

4. **Begin BIP158 implementation** (Recommended):
    - Complete Phase A (Infrastructure): Create `pir/` Rust project
    - Complete Phase B (Filter Creation): Implement `BlockIndexer`
    - Complete Phase C (Filter Querying): Implement query methods
    - Complete Phase D (Integration): Connect to Bitcoin node
    - Complete Phase E (Testing): Benchmark and verify
    - See `doc/BIP158_IMPLEMENTATION.md` for details
    - **Estimated time**: 7-12 hours

5. **Alternative: Continue with PIR** (if needed):
    - Review SealPIR library for single-server PIR
    - Or plan two-server PIR implementation
    - Design PIR server architecture
    - See `PLAN.md` Phases 2-3

### Short Term (This Week)

1. **Complete BIP158 implementation**:
    - Successfully implement all phases (A-E) in `pir/`
    - Create filters for 100 blocks
    - Verify filter creation and query performance
    - Achieve <0.5ms filter creation, <0.1ms query

2. **Optional: Implement PIR** (if needed for research):
    - Implement single-server PIR (SealPIR integration)
    - Or implement two-server PIR (XOR-based, two servers)
    - Set up PIR server with indexed data
    - Create PIR query client

### Long Term (Following Week)

1. **Expand dataset** (if needed):
    - Create filters for additional blocks from synced testnet
    - Or switch to mainnet for production data

2. **Performance optimization**:
    - Benchmark and optimize filter creation speed
    - Add caching for frequently accessed filters
    - Consider filter compression for long-term storage

3. **Documentation**:
    - Write usage examples for BIP158 components
    - Document BIP158 query patterns
    - Create integration guide

4. **Research** (if using hybrid approach):
    - Compare BIP158 vs PIR performance
    - Optimize hybrid BIP158+PIR approach
    - Publish results
