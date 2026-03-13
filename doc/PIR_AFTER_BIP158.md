# Hybrid BIP158 + PIR: Why PIR After BIP158?

## The Simple Answer

**Yes, that's exactly what PIR does in the hybrid approach.**

But there's a critical nuance: **PIR prevents the server from knowing WHICH blocks matched your wallet.**

---

## Problem: BIP158 Alone

### How BIP158 Works

```
Client                                      Server
------                                        ------
1. Download filters (5 MB)      --------->  OK
2. Test filters locally
3. For each match:
   getblock <hash>    --------------->  OK
```

### Privacy Problem

When you use BIP158 alone:
- You test filters **locally** against your wallet scripts
- When a filter matches, you request: `getblock <hash>`
- **Server learns**: Which block hashes you're interested in
- **Server can infer**: Your wallet's activity patterns

**Example**:
```
Server logs show block requests for:
- height: 123,456
- height: 124,789
- height: 130,001
- height: 131,999
- height: 145,678

Server's inference: "This wallet is active, but sporadicly"
```

---

## Solution: PIR After BIP158

### How Hybrid Works

```
Client                                      Server
------                                        ------
1. Download filters (5 MB)      --------->  OK
2. Test filters locally
3. For each match:
   PIR_Query(block_idx) ------------>  (server can't distinguish which idx)
4. Receive block data                <--------  (encrypted/obfuscated response)
5. Parse block, extract TX
```

### Privacy Benefit

With PIR, when a filter matches:
- You make a PIR query: `Get block at index 123456`
- **Server cannot distinguish**: Whether you queried index 123456, 123457, or any other index
- **Server cannot correlate**: "BIP158 match" with "block request"
- **Server sees**: Only that you made PIR queries (but can't tell which blocks)

**Why this matters**:
- Server can still see you made PIR queries
- But server **cannot tell** which blocks were the "matches" vs "non-matches"
- Your wallet activity stays **uncorrelated** to your BIP158 results

---

## Visual Comparison

### Scenario: Wallet Has Transactions in 10 Blocks

| Block # | Has Wallet TX | BIP158 Match? |
|----------|----------------|-----------------|
| 100 | ❌ No | ❌ No |
| 101 | ❌ No | ❌ No |
| 102 | ✅ Yes | ✅ Yes |
| 103 | ❌ No | ❌ No |
| 104 | ✅ Yes | ✅ Yes |
| 105 | ❌ No | ❌ No |
| 106 | ❌ No | ❌ No |
| 107 | ✅ Yes | ✅ Yes |
| 108 | ❌ No | ❌ No |

### With BIP158 Alone

```
Client makes requests:
✅ getblock(hash_at_102)
✅ getblock(hash_at_104)
✅ getblock(hash_at_107)

Server knows exactly which blocks contain wallet TXs!
```

### With BIP158 + PIR

```
Client makes PIR queries:
PIR_Q(index_100)   -> (no wallet TX, but server doesn't know this)
PIR_Q(index_101)   -> (no wallet TX, but server doesn't know this)
PIR_Q(index_102)   -> (has wallet TX! but server doesn't know it's a match)
PIR_Q(index_103)   -> (no wallet TX, but server doesn't know this)
PIR_Q(index_104)   -> (has wallet TX! but server doesn't know it's a match)
...
PIR_Q(index_107)   -> (has wallet TX! but server doesn't know it's a match)

Server sees PIR queries for ALL blocks, but can't distinguish matches from non-matches!
```

**Critical insight**: Server sees PIR queries for blocks 100-108, but **cannot tell** which ones (102, 104, 107) contain wallet transactions.

---

## Detailed Privacy Analysis

### Information Leakage Comparison

| Approach | Server Knows | Server Can Infer | Privacy Level |
|----------|----------------|-------------------|---------------|
| **BIP158 alone** | Block hashes for matching blocks | Wallet activity, timing | 🔴 Poor |
| **PIR alone** | Nothing (indistinguishable queries) | Nothing | 🟢 Excellent |
| **Hybrid** | PIR queries made (but not which blocks) | PIR query frequency only | 🟢 Excellent |

### What's Protected

**With BIP158 + PIR**:

| Data Type | Protected? | Why |
|-----------|-------------|------|
| **Which blocks contain wallet TXs** | ✅ Yes | PIR hides which blocks are matches |
| **Wallet's transaction history** | ✅ Yes | Server cannot correlate PIR queries to BIP158 matches |
| **Wallet's balance** | ✅ Yes | Server doesn't know which TXs are yours |
| **Wallet's activity patterns** | ✅ Yes | Server sees only PIR queries (not correlated to matches) |
| **Block access pattern** | 🟡 Partial | Server sees PIR queries but not which blocks |

---

## Performance Comparison

### Bandwidth

| Approach | Initial Download | Per Transaction | Full Chain Sync |
|----------|-------------------|-------------------|-------------------|
| **BIP158 alone** | 5 MB (filters) | 200-500 bytes | 50-100 MB (matching blocks) |
| **PIR alone** | 0 | 200-500 bytes + PIR overhead | 50-100 MB + PIR overhead |
| **Hybrid** | 5 MB (filters) | 200-500 bytes + PIR overhead | 50-100 MB + PIR overhead |

**Key insight**: PIR overhead is the same in both PIR alone and hybrid. The question is whether you pay it for ALL blocks (PIR alone) or just MATCHING blocks (hybrid).

### Latency

| Approach | Filter Match | Block Retrieval | Total |
|----------|--------------|-----------------|--------|
| **BIP158 alone** | <0.05ms | 10-100ms (RPC) | 10-100ms |
| **PIR alone** | N/A | 10-500ms (PIR) | 10-500ms |
| **Hybrid** | <0.05ms | 10-500ms (PIR) | 10-500ms |

**Key insight**: Hybrid is same speed as PIR alone for matching blocks, but you don't PIR-query all blocks.

---

## When is PIR After BIP158 Worth It?

### Scenario 1: Active Wallet (many transactions)

```
Wallet has 100 transactions spread across 200 blocks

BIP158 matches: 200 blocks (all scanned)
   - Bandwidth: 5 MB (filters) + 200 × 1 MB (blocks) = 205 MB
   - Privacy leak: Server sees 200 block requests

Hybrid (BIP158 + PIR):
   - Bandwidth: 5 MB (filters) + 200 × 1 MB (blocks via PIR) = 205 MB
   - Privacy: Server sees 200 PIR queries (can't distinguish matches)

Benefit: No bandwidth cost, but privacy improved!
```

### Scenario 2: Inactive Wallet (few transactions)

```
Wallet has 2 transactions in 2 blocks

BIP158 matches: 2 blocks
   - Bandwidth: 5 MB (filters) + 2 × 1 MB (blocks) = 7 MB
   - Privacy leak: Server sees 2 block requests (minor)

Hybrid (BIP158 + PIR):
   - Bandwidth: 5 MB (filters) + 2 × 1 MB (blocks via PIR) = 7 MB
   - Privacy: Server sees 2 PIR queries (indistinguishable)

Benefit: Minimal bandwidth cost, privacy improved!
```

### Scenario 3: New Wallet (first sync)

```
Wallet has 0 transactions (newly created)

BIP158 matches: 0 blocks
   - Bandwidth: 5 MB (filters) + 0 MB (no blocks) = 5 MB
   - Privacy: No leak (no block requests)

Hybrid (BIP158 + PIR):
   - Bandwidth: 5 MB (filters) + 0 MB (no blocks) = 5 MB
   - Privacy: No PIR queries

Benefit: Same as BIP158 alone, no PIR overhead!
```

### Scenario 4: Syncing 1000 Blocks

```
Wallet scanning 1000 blocks to find 10 relevant transactions

BIP158 alone:
   - Bandwidth: 5 MB (filters) + 10 × 1 MB = 15 MB
   - Block requests: 10
   - Privacy leak: Reveals which 10 blocks

Hybrid:
   - Bandwidth: 5 MB (filters) + 10 × 1 MB (PIR) = 15 MB
   - PIR queries: 10 (plus 990 "dummy" queries to hide pattern)
   - Privacy: Server can't distinguish which 10 blocks are real

Benefit: Same bandwidth, but need 990 "dummy" PIR queries to hide pattern!
```

---

## Key Insight: PIR's Real Value in Hybrid

**PIR is NOT about bandwidth efficiency** (bandwidth is the same with or without PIR for matching blocks).

**PIR IS about privacy**:
- Without PIR: Server knows exactly which blocks contain your transactions
- With PIR: Server cannot distinguish matching blocks from non-matching blocks

**The "dummy query" problem**:

To get full privacy with PIR + BIP158, you need to:
1. Scan all 1000 blocks with BIP158
2. Identify 10 matching blocks
3. Make PIR queries for ALL 1000 blocks (10 real + 990 dummy)
4. Randomize query order

**Why?** Because if you only PIR-query the 10 matching blocks, server can infer you matched those blocks (since you saw the filters locally).

**The bandwidth cost**:
- PIR alone (all blocks): 1000 × PIR overhead
- Hybrid (all blocks): 1000 × PIR overhead
- Hybrid (only matches): 10 × PIR overhead + 990 × PIR overhead = same!

**Wait**: If you PIR-query all blocks anyway, why use BIP158 at all?

---

## Alternative: Don't Scan All Blocks with BIP158

### Better Approach for PIR + BIP158

**Idea**: PIR-query ALL blocks directly, use BIP158 filters only for client-side validation.

```
Workflow:

1. Client PIR-queries blocks sequentially (e.g., blocks 0-1000)
2. For each block received:
   - Test BIP158 filter locally
   - If match, extract transactions
   - If no match, discard block
3. Continue scanning

Server sees:
- 1000 PIR queries (indistinguishable)
- Cannot tell which blocks matched
- Maximum privacy!

Client benefits:
- Server learns nothing
- Client uses BIP158 for fast local filtering
- No need to "hide" matching pattern
```

**This is essentially PIR alone, with BIP158 used as a local optimization!**

### Comparison

| Approach | Server Privacy | Complexity | Bandwidth |
|----------|-----------------|-------------|-------------|
| **BIP158 alone** | Poor (knows matching blocks) | Low | 5 MB + matching blocks |
| **Hybrid (scan all, PIR matches)** | Excellent | High (need dummy queries) | Same as PIR alone |
| **PIR alone** (with BIP158 local filter) | Excellent | Medium | Same as PIR alone |
| **Hybrid (BIP158 narrows, PIR matches)** | Medium | High | Less than PIR alone |

---

## Recommendations

### For BitcoinPIR

**Primary approach**: Use BIP158 alone for most use cases

**Reasons**:
1. Good privacy (server doesn't learn which scripts you watch)
2. Excellent performance (0.05ms filter matching)
3. Simple implementation
4. Production-ready (rust-bitcoin/bip158)

**When to add PIR**:
- Research scenarios requiring information-theoretic privacy
- High-value transactions (large amounts)
- Sensitive addresses (cold storage, donation addresses)
- When publishing privacy guarantees

**How to implement**:

Option 1: PIR alone (simplest)
- Use PIR to query blocks sequentially
- Use BIP158 filters for client-side validation
- Server learns nothing
- Good performance

Option 2: BIP158 narrows, PIR retrieves (more complex)
- Scan blocks with BIP158
- Identify matching blocks
- PIR-query ALL blocks (matching + non-matching) to hide pattern
- Server learns nothing
- Higher complexity (need dummy queries)

**Recommendation**: Start with Option 1 (PIR alone), consider Option 2 only if specifically needed.

---

## Summary

### Direct Answer to Your Question

**Q**: "Basically PIR helps retrieve specific transactions when BIP158 hits?"

**A**: Yes, but more importantly, PIR **hides which blocks are hits**.

Without PIR:
- BIP158 tells you: "Blocks 102, 104, 107 contain your TXs"
- You request: `getblock(hash_102)`, `getblock(hash_104)`, `getblock(hash_107)`
- Server sees: "Client wants blocks 102, 104, 107"
- **Privacy leak**: Revealed!

With PIR:
- BIP158 tells you: "Blocks 102, 104, 107 contain your TXs"
- You request: `PIR_query(index_102)`, `PIR_query(index_104)`, `PIR_query(index_107)`
- Server sees: "Client made PIR queries"
- **Privacy protected**: Server cannot tell which blocks are matches!

But to get this protection, you either:
1. PIR-query ALL blocks (including non-matches), OR
2. Accept that server can correlate your queries (but at least they don't learn which scripts you watch)

**For BitcoinPIR**: Start with BIP158 alone (good enough for most practical use cases), add PIR later if needed for research.
