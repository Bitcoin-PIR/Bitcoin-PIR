# PLAN: Merkle Sibling-Family Co-location + K=75 Unification

Status: proposed (2026-05-17). Local working doc (PLAN_*.md are gitignored).
Targets the DATA-Merkle batch-size leak identified in the leakage review
this session.

---

## 1. Motivation

OnionPIR per-bin Merkle verification (`pir-sdk-client/src/onion_merkle.rs`)
leaks the batch size `N` through the **count of sibling PBC rounds**.

Cause chain:

1. Every query is padded to `CHUNK_MERKLE_ITEMS_PER_QUERY = M = 16` chunk
   Merkle items (the `chunk_max` closure — CLAUDE.md "CHUNK Merkle
   Item-Count Symmetry").
2. The DATA Merkle leaf is indexed by **cuckoo bin** —
   `leaf_pos = group * chunk_bins + bin` ([onion.rs:1701](pir-sdk-client/src/onion.rs)).
   The chunk cuckoo scatters entry_ids, so a query's 16 items land in
   ~16 unrelated Merkle node groups (`gid = leaf_pos / arity`).
3. A batch of `N` queries → ~`16N` distinct gids.
4. The sibling level runs `pbc_plan_rounds(gids, k, 3, 500)`; wire round
   count = `ceil(gids / ~0.9k)`. With the OnionPIR Merkle's
   `adaptive_k = 25` ([gen_4_build_merkle_onion.rs:55](build/src/gen_4_build_merkle_onion.rs)),
   the DATA Merkle spills past 1 round at **N = 2**.
5. The round count is wire-observable → it reveals `N`.

The verifier already groups items by parent and fetches whole families
(`group_to_items` keyed by `node_idx / arity`, onion_merkle.rs; the
sibling bin holds all `arity` child hashes). Items that share a `gid`
already collapse to one fetch. They don't collapse today **only because
the leaf order scatters them.** So the fix is a build-time layout change;
the verifier code is untouched.

---

## 2. Goal & non-goals

**Goal.** Make a query's `M` DATA-Merkle items land in **one sibling
family** (one `gid` per level), and pin every Merkle PBC plan to
`K = 75`. Result: DATA Merkle = exactly **1 round per level** for batches
up to ~68 — the round count is constant in that range, so it stops
leaking `N`.

**Non-goals (explicit).**

- **Chunk DATA PIR is out of scope.** It still fetches `16N` chunk
  entry_ids into `K_CHUNK = 80` groups and still spills at **N ≈ 5**.
  After this plan the protocol-wide batch-size leak floor is the chunk
  data PIR, not the Merkle. Closing that needs wide ("superblock") PIR
  entries — a separate, costlier change. This plan does **not** claim a
  protocol-wide close; it closes the Merkle layer specifically.
- No change to `K_CHUNK = 80` or INDEX `K = 75` (the PIR layers). "K=75
  everywhere" in this plan means **all Merkle PBC plans**, killing the
  OnionPIR-Merkle-specific `adaptive_k = 25`.

---

## 3. Core idea

Index the chunk Merkle tree by **entry_id**, not by cuckoo bin. An
address already owns a contiguous entry_id run
(`start_chunk_id .. start_chunk_id + num_chunks`; INDEX slot carries
both — params.rs:77). In entry_id order those leaves are adjacent, so
`gid = entry_id / arity` is constant across the run. The chunk data DB
and chunk cuckoo are untouched — only the Merkle tree's leaf ordering
and sibling tables change (leaf hash is still `SHA256(chunk bin)`, just
placed at the entry_id index).

---

## 4. Design

### 4.1 Entry-id leaf ordering (OnionPIR DATA Merkle)

- **Build** (`build/src/gen_4_build_merkle_onion.rs`): build the DATA
  tree over `leaf_hash[entry_id]` in entry_id order. For each entry_id,
  `leaf_hash = SHA256(bin holding entry_id)`; the chunk cuckoo is
  deterministic so the builder can resolve `entry_id → bin`. Gap
  entry_ids (see 4.2) get `ZERO_HASH`.
- **Client** (`pir-sdk-client/src/onion.rs`): one-line change at the
  `data_merkle.insert` site — `leaf_pos = q.entry_id` instead of
  `q.group * chunk_bins + q.bin`.
- **Verifier** (`onion_merkle.rs`): unchanged. `gid = leaf_pos / arity`,
  `child_pos = leaf_pos % arity` already.
- **Server** (`runtime/src/bin/unified_server.rs`): serves whatever the
  build produced — sibling tables + tree-top now in entry_id order.
  Mechanical.

### 4.2 Straddle handling — pick one

A query's `M = 16`-item block is co-located iff it does not cross an
`arity`-boundary (`gid = entry_id/arity` constant). `arity = entry_size/32`
≈ 104 for OnionPIR.

| Variant | Guarantee | Merkle tree size | Notes |
|---|---|---|---|
| **Unaligned** | clean 1 round to N≈34; flicker N≈34–68 | ~815K leaves (smaller than today's 2.6M) | round count flickers 1↔2 on straddle pattern in the flicker zone — small content-dependent leak |
| **Selective straddle-pad** (recommended) | deterministic 1 round to N≈68 | ~1.5M leaves (~2×) | when an address's run would cross an `arity`-boundary, bump `start_chunk_id` to the boundary; skipped entry_ids become `ZERO_HASH` gap leaves |
| **Full 16-align** | deterministic; 1 gid even for N=1 | ~10.9M leaves (~4×) | every address padded to a 16-slot block |

Recommendation: **selective straddle-pad** — deterministic leak-free to
the full K=75 capacity, ~2× Merkle tree storage (data DB untouched; gap
leaves are `ZERO_HASH`, cheap). Straddle-padding is done in the chunk
packer (`build/src/gen_1_onion.rs`) when it assigns entry_id runs.

### 4.3 K = 75 unification

Replace `adaptive_k` (gen_4_build_merkle_onion.rs:55) with a constant
`75` for all Merkle sibling levels. Valid because sibling levels only
exist where `num_groups > TREE_TOP_GROUP_THRESHOLD = 4096 ≫ 75` — the
`25` / `(num_groups/10)` branches were a tuning choice, not a constraint.

Effect: every sibling round sends exactly 75 FHE queries (the existing
`for b in 0..level_info.k` padding loop in onion_merkle.rs, just with
`k = 75`). Per-round wire cost 3× vs k=25, but **far fewer rounds** for
batches — net win for N > 1, 3× cost for N = 1.

### 4.4 Synthetic-padding subsumption

With families, the family **is** the fixed-size unit, so the scattered
synthetic padding becomes unnecessary:

- An address with `N` real chunks → family = `N` real leaves +
  `(M − N)` `ZERO_HASH` gap leaves. One family fetch covers all 16.
- A not-found query fetches a **random valid family gid** (replaces the
  16 SHA-256 synthetics).
- `pad_chunk_ids_to_m` / `derive_chunk_pad_seed` (onion.rs ~1508–1535)
  is removed from the Merkle path. Integrity is preserved: the verifier
  checks all 16 family slots (real-hash or known `ZERO_HASH`) against
  the committed family — a server lying about any of them fails the
  query.

Note: the chunk **data** PIR still needs its own M-padding (it fetches
real chunk bytes; fetching only `N` would leak `N`). Subsumption applies
to the Merkle layer only.

---

## 5. Leakage outcome

The round count becomes `ceil(unique_gids / ~68)`:

- **Selective-pad + K=75**: `unique_gids = N` (queries sharing a family
  even collapse below `N`). Exactly **1 DATA Merkle round per level for
  N ≤ ~68**, deterministic, content-independent → no leak in that range.
- **Unaligned + K=75**: `unique_gids ∈ [N, 2N]`. Clean to N≈34; flicker
  34–68.
- Either way, **N > ~68** → ≥2 rounds, count leaks again. That ceiling
  is identical to the INDEX PIR's own K=75 ceiling; only a fixed batch
  size removes it entirely.
- **Co-location is load-bearing**: K=75 *without* it still spills at
  N≈4 (`16N` items).

---

## 6. Backend coverage (DPF / Harmony)

`verify_sibling_levels` (`pir-sdk-client/src/merkle_verify.rs`) is
structurally identical — `items_by_group`, `node_idx / arity`,
`max_items_per_group` ([:977,:1037,:981](pir-sdk-client/src/merkle_verify.rs)).
DPF/Harmony items are bin-indexed (`it.bin_index`) → same scatter. The
same entry_id-order fix applies, in the shared build pipeline
(`build/src/gen_4_build_merkle.rs` + `merkle_bucket_builder.rs`) and the
DPF/Harmony chunk-Merkle leaf construction (`dpf.rs` / `harmony.rs`).

One nuance: the per-bucket Merkle **arity is 8** (merkle_verify.rs:16),
and `M = 16 > 8`, so even co-located, 16 items span 2 families. Bump
that arity to ≥ 16 (≥ 32 for headroom) to reach 1. Audit DPF/Harmony
Merkle `K` — pin to 75 if not already.

---

## 7. Changes by file

- `build/src/gen_4_build_merkle_onion.rs` — entry_id-order DATA tree;
  `adaptive_k` → `75`.
- `build/src/gen_1_onion.rs` — straddle-padding in entry_id assignment.
- `build/src/gen_4_build_merkle.rs`, `merkle_bucket_builder.rs` — same
  for DPF/Harmony per-bucket Merkle; arity 8 → ≥16.
- `pir-sdk-client/src/onion.rs` — `leaf_pos = entry_id`; drop Merkle-side
  `pad_chunk_ids_to_m`; not-found → random family gid.
- `pir-sdk-client/src/onion_merkle.rs` — verifier unchanged; check JSON
  metadata still parses.
- `pir-sdk-client/src/dpf.rs`, `harmony.rs` — chunk-Merkle leaf
  construction; arity.
- `pir-sdk-client/src/merkle_verify.rs` — verifier unchanged; arity param.
- `runtime/src/bin/unified_server.rs` — emit Merkle JSON with `k = 75`;
  serve new layout (mechanical).
- `web/src/onionpir_client.ts` — mirror the standalone TS client.
- `proofs/easycrypt/Leakage.ec`, leakage integration tests, CLAUDE.md
  empirical witnesses — see §9.

---

## 8. Costs

- **Storage**: selective-pad ~2× the DATA Merkle tree + sibling NTT
  store (data DB untouched). Full-align ~4×. Unaligned: smaller than
  today.
- **K=75 bandwidth**: 3× FHE queries per sibling round vs k=25; offset
  by far fewer rounds for batches; 3× cost for the N=1 case.
- **>16-chunk addresses** (~1% of mainnet): span `ceil(num_chunks/16)`
  families → multiple gids. Options: accept (already coarsely
  distinguishable), fold into the whale path, or pad all queries to a
  max family count. Open question — see §10.

---

## 9. Verification

- Re-measure empirical witnesses against Hetzner: `IndexMerkleSiblings`
  / `ChunkMerkleSiblings` round counts for N = 1, 10, 34, 68 batches.
  Target: `ChunkMerkleSiblings = n_levels` (1 round/level) constant up
  to N≈68.
- Update `onion_*_found_vs_not_found` and `*_multi_query_collision`
  leakage integration tests.
- EasyCrypt: the `chunk_max_items_per_group_per_level` axis prose
  flips again — per-level pass count stays 1, and the round count is
  now constant in the 1-round regime. Keep the axis admitted for
  N > capacity.
- Update CLAUDE.md: "CHUNK Merkle Item-Count Symmetry" section + "What
  the Server Learns" — document that batch size N is hidden up to ~68
  (Merkle) but still leaks via the chunk DATA PIR at N≈5.

---

## 10. Open questions

1. >16-chunk addresses: accept the multi-family leak, or pad to a max
   family count?
2. Selective-pad vs full-align — confirm the ~2× sibling NTT store cost
   is acceptable against the production storage budget.
3. Does the entry_id-ordered Merkle complicate delta sync (incremental
   updates append entry_ids — alignment must hold across deltas)?
4. INDEX Merkle (2 items/query, no natural entry_id run) — leave at
   K=75 / ~2N (clean to N≈34) or attempt co-location separately?

---

## 11. Implementation order

1. **K=75 unification only** (`adaptive_k → 75`). Small, isolated,
   shippable on its own — round width 75, round count unchanged. Rebuild
   OnionPIR Merkle, verify.
2. **Entry-id leaf ordering** for OnionPIR DATA Merkle (build + client +
   server). The core change.
3. **Straddle handling** — implement selective-pad in the packer.
4. **Synthetic-padding subsumption** — remove Merkle-side
   `pad_chunk_ids_to_m`; not-found → random family.
5. **DPF / Harmony port** + arity bump.
6. **Spec + tests + CLAUDE.md** updates.

Each step is independently testable; 1 and 2 gate the rest.
