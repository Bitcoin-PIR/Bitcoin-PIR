# Bitcoin Light Client Data Requirements

## Question: What information does a Bitcoin light client need to retrieve from a server in order to complete a transaction?

This analysis explores the data requirements for different scenarios, with focus on privacy implications for PIR/BIP158 approaches.

---

## Scenario Analysis

### Scenario 1: Verify an Existing Transaction

**Use Case**: User wants to verify that a specific transaction exists in the blockchain and get its details.

**Light Client Needs**:

1. **Transaction Data** (required):
   ```
   {
     "version": int,
     "locktime": uint32,
     "vin": [
       {
         "txid": hash,              // Previous transaction ID
         "vout": uint32,           // Output index in previous tx
         "scriptSig": bytes,       // Input signature script
         "sequence": uint32,        // Sequence number
         "witness": [bytes]        // Witness data (if SegWit)
       }
     ],
     "vout": [
       {
         "value": uint64,           // Amount in satoshis
         "scriptPubKey": bytes,     // Output locking script
         "n": uint32               // Output index
       }
     ]
   }
   ```

2. **Block Header** (required for inclusion proof):
   ```
   {
     "version": int,
     "prev_block": hash,
     "merkle_root": hash,
     "timestamp": uint32,
     "bits": uint32,
     "nonce": uint32
   }
   ```

3. **Merkle Proof** (required to verify transaction is in block):
   ```
   {
     "branch": [hash, hash, ...],  // Merkle branch hashes
     "index": uint32                    // Transaction index in block
   }
   ```

4. **Previous Transaction Data** (optional, for full validation):
   - Previous transaction's output at `vin[vout]`
   - Needed to verify input spends valid UTXO
   - **Most SPV clients skip this** for speed

**Total Data Size**: ~200-500 bytes per transaction

---

### Scenario 2: Broadcast a New Transaction

**Use Case**: User wants to create and broadcast a new transaction to the network.

**Light Client Needs**:

1. **Current Block Height** (for fee estimation):
   - From block header of latest block

2. **UTXO Data** (for each input):
   ```
   {
     "txid": hash,
     "vout": uint32,
     "value": uint64,
     "scriptPubKey": bytes
   }
   ```

3. **Mempool Status** (optional):
   - Check if any inputs are already double-spent
   - Check for conflicts

**Total Data Size**: ~50-150 bytes per input

---

### Scenario 3: Sync Wallet History

**Use Case**: User wants to find all transactions relevant to their wallet addresses.

**Light Client Needs**:

This is the **key scenario** for privacy implications!

#### Option A: Without Filters (Naive SPV)

1. **Scan all blocks** sequentially
2. **For each block**:
   - Download full block data
   - Parse all transactions
   - Check if any output matches wallet addresses
   - Save relevant transactions

**Privacy Problem**:
- Server learns: User is scanning entire blockchain
- Server learns: Block heights accessed (sequential pattern)
- Bandwidth: Massive (600 GB for full mainnet)

**Total Data Size**: 600 GB (full mainnet blocks)

#### Option B: With BIP158 Filters

1. **Download filter headers** (~5 MB for full chain):
   ```
   [{
     "block_hash": hash,
     "filter_hash": hash,        // Hash of BIP158 filter
     "prev_header_hash": hash
   }, ...]
   ```

2. **Download filters for blocks in range**:
   - Or request filters individually
   - Filter size: ~50 bytes per block

3. **Test filters locally**:
   - For each block, test filter against wallet scripts
   - If match, download full block
   - Extract relevant transactions

**Privacy Benefits**:
- Server sees: Block range requests (less suspicious than sequential scan)
- Server does NOT see: Which scripts are being tested (local matching)
- Bandwidth: ~5 MB (filters) + relevant blocks only

**Total Data Size**:
- Filters: ~5 MB (full chain)
- Relevant blocks: Depends on wallet activity
- Typical wallet: ~10-100 MB

#### Option C: With PIR

1. **PIR query for each block** (or batch of blocks):
   - Query reveals NOTHING about which block is accessed
   - Get block data without server knowing which block

**Privacy Benefits**:
- Server sees: PIR queries (cannot identify target block)
- Information-theoretic privacy
- Bandwidth: Same as Option B (filters + blocks)

**Total Data Size**:
- PIR overhead: Additional query/response sizes
- Blocks: Same as Option B

---

## Detailed Comparison: What's Revealed?

### Table 1: Information Leakage by Approach

| Scenario | Without Filters (Naive) | With BIP158 | With PIR |
|----------|------------------------|-------------|-----------|
| **Block being accessed** | ✅ Revealed | ⚠️ Partial (range) | ❌ Hidden |
| **Transaction being queried** | ✅ Revealed | ❌ Hidden | ❌ Hidden |
| **ScriptPubKeys being tested** | ✅ Revealed | ❌ Hidden | ❌ Hidden |
| **Block range accessed** | ⚠️ Revealed (sequential) | ⚠️ Revealed (range) | ⚠️ Revealed (random/PIR) |
| **Wallet addresses** | ✅ Revealed (in queries) | ❌ Hidden | ❌ Hidden |

### Table 2: Bandwidth Requirements

| Approach | Initial Download | Per Transaction | Full Chain |
|----------|-----------------|---------------|-------------|
| **Naive SPV** | 0 | 200-500 bytes | 600 GB |
| **BIP158** | 5 MB (filters) | 200-500 bytes | ~10-100 MB |
| **PIR** | 0 | 200-500 bytes + PIR overhead | ~10-100 MB |
| **Hybrid** (BIP158 + PIR) | 5 MB (filters) | 200-500 bytes + PIR overhead | ~10-100 MB |

---

## Privacy Analysis

### Scenario 1: Verify Transaction (Single TX)

**Without PIR/BIP158**:
- Client requests: `gettransaction <txid>`
- Server knows: Which transaction client is interested in
- **Leakage**: Reveals client's transaction interest

**With BIP158**:
- Client downloads block filters
- Client finds block containing transaction
- Client requests: `getblock <blockhash>`
- Server knows: Block height range (less specific)
- **Leakage**: Partial (block range, not specific TX)

**With PIR**:
- Client makes PIR query for block
- Server cannot distinguish which block
- **Leakage**: None (information-theoretic)

### Scenario 2: Sync Wallet (Most Privacy-Sensitive)

**Without Filters**:
- Client scans all blocks sequentially
- Server sees: Access pattern 0, 1, 2, 3, ...
- **Obvious**: User is syncing entire blockchain!
- **Worst privacy**: Reveals wallet activity over time

**With BIP158**:
- Client downloads filter headers (one-time 5 MB)
- Client tests filters locally against wallet scripts
- Client requests only blocks with matches
- Server sees: Block ranges with gaps
- **Better**: Server doesn't know which scripts matched
- **Still**: Server can infer wallet activity from block requests

**With PIR**:
- Client makes PIR queries for all blocks
- Server sees: Indistinguishable queries
- **Best**: Server learns nothing
- **Trade-off**: Slower (PIR overhead)

---

## Data Flow: Verifying a Transaction

### Traditional Light Client (SPV) without PIR

```
Client                                          Server
------                                          ------
1. getblockcount --------------------------------> 
                                                count (800,000)
2. getblockhash 800,000 --------------------------> 
                                                hash (abc123...)
3. getblock abc123... ----------------------------> 
                                                full block (1 MB)
4. Parse block, find transaction -------------------
5. Get Merkle proof from block -------------------
6. Verify transaction is valid --------------------
```

**What Server Knows**:
- ✅ Client wants block at height 800,000
- ✅ Client is interested in transaction at specific hash (inferred)

### With BIP158

```
Client                                          Server
------                                          ------
1. getblockcount --------------------------------> 
                                                count (800,000)
2. getcfheaders 0, 800,000 ------------------> 
                                                filter headers (5 MB)
3. For each filter:
     - Test locally against wallet scripts
     - If match:
       4. getblock <hash> ------------------> 
                                                full block (1 MB)
5. Extract relevant transactions -----------------
6. Verify transactions --------------------------
```

**What Server Knows**:
- ⚠️ Client wants filter headers for range 0-800,000
- ❌ Does NOT know which scripts matched
- ⚠️ Can infer blocks with relevant transactions (from requests)

### With PIR

```
Client                                          Server
------                                          ------
1. getblockcount --------------------------------> 
                                                count (800,000)
2. For each block height:
     3. PIR_Query(height) ---------------------> 
                                                block (via PIR)
                                                server can't distinguish which block
3. Extract relevant transactions -----------------
4. Verify transactions --------------------------
```

**What Server Knows**:
- ❌ Nothing about which block was accessed
- ❌ Nothing about which transactions are relevant
- ❌ Nothing about wallet scripts

---

## Critical Finding: Wallet Sync is the Privacy Bottleneck

**Most Common Scenario**: User syncing wallet for first time or after offline period.

**Privacy Hierarchy** (best to worst):

1. **PIR Only**: Server learns nothing
   - Pros: Maximum privacy
   - Cons: Slower, higher latency

2. **Hybrid (BIP158 + PIR)**: Server learns minimal
   - Client uses BIP158 to narrow candidates
   - Client uses PIR only for candidate blocks
   - Pros: Faster than PIR-only, good privacy
   - Cons: More complex

3. **BIP158 Only**: Server learns block ranges
   - Pros: Faster than PIR, simpler
   - Cons: Server can infer wallet activity from pattern

4. **Naive SPV**: Server learns everything
   - Pros: Simplest, fastest
   - Cons: Terrible privacy

**Recommendation for BitcoinPIR**:

**Primary Approach**: BIP158 (rust-bitcoin/bip158)
- Production-ready, fast, reasonable privacy
- Server learns block ranges but not scripts
- Much better than naive SPV

**Enhancement**: Add PIR for critical operations
- Use BIP158 for most queries
- Use PIR when maximum privacy needed
- Hybrid approach balances speed and privacy

---

## Minimum Data Requirements by Scenario

### 1. Verify Single Transaction Exists

| Data | Required For | Privacy Impact |
|-------|--------------|-----------------|
| Transaction data | Display, verification | High (reveals TX interest) |
| Block header | Inclusion proof | Medium (reveals block height) |
| Merkle proof | Inclusion proof | Medium (reveals block + index) |
| Previous TX data | Full validation | High (reveals more context) |

**Minimum**: Transaction + Block header + Merkle proof (~300 bytes)

### 2. Broadcast New Transaction

| Data | Required For | Privacy Impact |
|-------|--------------|-----------------|
| Block height (tip) | Fee estimation | Low (public info) |
| UTXO data | Input validation | High (reveals wallet inputs) |
| Mempool check | Double-spend detection | Medium (reveals pending TX) |

**Minimum**: UTXOs for all inputs (~50-150 bytes per input)

### 3. Sync Wallet History

| Data | Required For | Privacy Impact (Naive) | Privacy Impact (BIP158) | Privacy Impact (PIR) |
|-------|--------------|------------------------|------------------------|---------------------|
| All block data | Find relevant TXs | 🔴 Extreme | 🟡 Medium | 🟢 None |
| Filters + matching blocks | Find relevant TXs | N/A | 🟡 Medium | 🟡 Medium |
| Block data (PIR) | Find relevant TXs | N/A | N/A | 🟢 None |

**Minimum (Naive)**: 600 GB (full chain)
**Minimum (BIP158)**: 5 MB (filters) + ~50 MB (matching blocks)
**Minimum (PIR)**: ~50 MB (matching blocks via PIR)

---

## Privacy-Enhanced Light Client Design

### Architecture with BIP158

```
┌─────────────────────────────────────────────────────────┐
│                  Wallet (Client Side)                │
└─────────────────────────────────────────────────────────┘
                        │
                        │ (1. One-time: Download filters)
                        ▼
┌─────────────────────────────────────────────────────────┐
│              Bitcoin Node (Server Side)               │
│  • getcfheaders                                    │
│  • getblock (only for matching blocks)             │
└─────────────────────────────────────────────────────────┘
                        │
                        │ (2. Return filter headers)
                        ▼
┌─────────────────────────────────────────────────────────┐
│                  Filter Store (Local)                │
│  • Test filters against wallet scripts              │
│  • Identify candidate blocks                      │
└─────────────────────────────────────────────────────────┘
                        │
                        │ (3. PIR queries for candidates)
                        ▼
┌─────────────────────────────────────────────────────────┐
│               PIR Server (or regular server)        │
│  • Return blocks (PIR: hidden, regular: known)  │
└─────────────────────────────────────────────────────────┘
                        │
                        │ (4. Return block data)
                        ▼
┌─────────────────────────────────────────────────────────┐
│                  Wallet (Client Side)                │
│  • Parse blocks                                   │
│  • Extract relevant transactions                    │
│  • Update wallet balance                          │
└─────────────────────────────────────────────────────────┘
```

### Privacy Guarantees by Approach

| Approach | Server Knows | Server Can Infer | Privacy Level |
|----------|--------------|-------------------|---------------|
| **Naive SPV** | Block heights accessed | Wallet activity, all TXs | 🔴 Poor |
| **BIP158** | Block ranges accessed | Rough wallet activity | 🟡 Medium |
| **BIP158 + Random Ordering** | Block ranges (random) | Wallet timing but not pattern | 🟢 Good |
| **PIR** | Nothing | Nothing | 🟢 Excellent |
| **Hybrid (BIP158 + PIR)** | Nothing (PIR) | Minimal activity (block access count) | 🟢 Excellent |

---

## Recommendations for BitcoinPIR

### 1. Primary Implementation: BIP158

**Why**:
- Production-ready (rust-bitcoin/bip158)
- Good privacy (better than naive SPV)
- Efficient bandwidth (10-100 MB vs 600 GB)
- Fast queries (0.1-0.5 ms filter matching)
- Compatible with existing Bitcoin nodes

**Implementation**:
- Use BIP158 for most wallet sync operations
- Randomize block request order to hide access patterns
- Cache filters locally

### 2. Enhancement: Add PIR for Critical Operations

**When to use PIR**:
- High-value transactions (large amounts)
- Sensitive addresses (donation addresses, cold storage)
- Research scenarios requiring information-theoretic privacy

**Implementation**:
- Use BIP158 to identify candidate blocks
- Use PIR only for retrieving those candidates
- Reduces PIR queries by 95%+ (only relevant blocks)

### 3. Hybrid Architecture

```
Wallet → [BIP158 Filter Matching] → Candidate Blocks
                              → [PIR Queries] → Block Data → Wallet
```

**Benefits**:
- 99% bandwidth savings vs naive (filters: 5 MB vs blocks: 600 GB)
- Information-theoretic privacy (PIR)
- Practical speed (most queries via fast BIP158 matching)
- Flexibility (choose PIR vs regular based on sensitivity)

---

## Conclusion

### What a Light Client Needs:

**Minimum for single TX**:
- Transaction data (200-500 bytes)
- Block header (80 bytes)
- Merkle proof (variable, ~50-200 bytes)

**Minimum for wallet sync**:
- All blocks containing wallet transactions (500 MB average for active wallet)
- OR: Filters (5 MB) + matching blocks (50 MB)

### Privacy Hierarchy:

1. **Worst**: Naive SPV (reveals everything)
2. **Better**: BIP158 (reveals block ranges)
3. **Best**: PIR (reveals nothing)
4. **Recommended**: Hybrid BIP158 + PIR (practical best)

### For BitcoinPIR:

**Primary**: BIP158 (rust-bitcoin/bip158)
- Good enough for most use cases
- Fast, efficient, production-ready

**Optional**: PIR for sensitive operations
- Information-theoretic privacy when needed
- Hybrid approach for balance

This provides a **practical path forward**: Implement BIP158 first, add PIR later if needed.
