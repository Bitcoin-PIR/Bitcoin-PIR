# Scripthash-derived synthetic CHUNK padding

Status: design + plan (not yet implemented). Follow-up to commit
`986fd72a` (batched CHUNK phase).

## Problem

`pad_chunk_ids_to_m()` ([pir-sdk-client/src/dpf.rs:2565](pir-sdk-client/src/dpf.rs:2565))
pads every query's chunk list to `M = CHUNK_MERKLE_ITEMS_PER_QUERY = 16`
by emitting deterministic synthetic IDs `0, 1, 2, …` (skipping reals).
For not-found / whale queries the real list is empty, so every such
query ends up with the identical padding `[0, 1, …, 15]`.

When many not-found queries are batched (typical for wallet sync —
most scanned addresses won't have any UTXOs), the flat 128-element
chunk list collapses onto only 16 distinct chunk IDs, all targeting
the same `derive_int_groups_3` candidate group set. The PBC cuckoo
planner can't pack 128 items into 2 rounds of 80, and emits 4 PBC
rounds instead.

Empirical impact, 8-batch not-found benchmark on pir2 v13:
- theoretical optimum: 2 PBC × 2 cuckoo = **4 wire rounds**
- actual: 4 PBC × 2 cuckoo = **8 wire rounds**, CHUNK phase ~8.4 s

Mixed found/not-found wallet syncs (real chunk IDs scattered across
the chunk space) don't hit this pathology, but the not-found-heavy
case is the common steady state for wallet scanning.

## Fix

Replace the deterministic `0..M` padding with a deterministic
**scripthash-derived** padding. Each query gets a distinct synthetic
chunk set with the same shape but different IDs, so the PBC planner
can pack densely.

### Construction (sketch)

```rust
/// Derive M synthetic chunk IDs from a per-query seed.
/// Output is a sorted, deduplicated Vec<u32> of length M whose
/// entries are pairwise distinct, disjoint from `real_chunks`, and
/// in `[0, num_chunks)`.
pub(crate) fn derive_synthetic_chunk_ids(
    seed: &[u8; 32],      // e.g. SHA-256(scripthash || "chunk_pad" || M_le)
    m: usize,
    num_chunks: u32,
    real_chunks: &[u32],
) -> Vec<u32> { … }
```

Algorithm: use the seed to instantiate a ChaCha20 (or SHA-based KDF)
stream, draw `u32 % num_chunks` repeatedly, reject duplicates and
real-list collisions until we have `m` distinct IDs. Stream-based, so
output is fully determined by `(seed, m, num_chunks, real_chunks)`.

Then update `pad_chunk_ids_to_m` to take an additional `seed: &[u8; 32]`
parameter (or build a new helper `pad_chunk_ids_to_m_seeded`) and
thread the seed through the call sites.

### Threading the seed

Three call sites today (all in `execute_step`):
- `pir-sdk-client/src/dpf.rs::execute_step` (per-scripthash loop)
- `pir-sdk-client/src/harmony.rs::execute_step` (preprocess phase added in `986fd72a`)
- `pir-sdk-client/src/onion.rs::query_chunk_level` (slightly different shape — packs M ids per query)

For each, the seed is derived from the scripthash being queried —
e.g. `seed = sha256("BPIR-CHUNK-PAD" || scripthash || query_index)`.
The `query_index` byte keeps the M synthetic IDs distinct across
multiple queries in the same scripthash batch (paranoia; not strictly
needed since different scripthashes already give different seeds).

For OnionPIR there's a separate `pad_chunk_ids_to_m` call inside
`onion.rs::query_chunk_level` — same change applies.

## Security review checklist

Before merging, verify each of these holds:

1. **Per-query disjointness (Kani):** within one query, synthetic IDs
   are pairwise distinct and disjoint from the real chunk list. The
   existing 4 Kani harnesses in `pir-sdk-client/src/dpf.rs` need to be
   updated to use the new helper but the property is unchanged.

2. **Wire-format symmetry:** every query (found / not-found / whale)
   still emits exactly `M = CHUNK_MERKLE_ITEMS_PER_QUERY` chunk Merkle
   items. The PBC planner still emits K_CHUNK-padded wire requests.
   No round-count change.

3. **Server-side validity:** synthetic IDs land in `[0, num_chunks)`.
   `derive_synthetic_chunk_ids` takes `num_chunks` as a parameter and
   reduces modulo, so this holds by construction. Verify the existing
   server-side validation path (in `runtime/src/bin/unified_server.rs`
   and `pir-runtime-core/src/eval.rs`) doesn't assume contiguous
   padding starting at 0.

4. **No new leakage (EasyCrypt sweep):** the formal simulator argument
   in `proofs/easycrypt/{Simulator,Theorem,Leakage}.ec` relies on the
   wire-observable profile being a function of the *batch shape*, not
   the *query content*. Cross-query padding identity isn't part of the
   shape (server can't see which chunks are real vs synthetic anyway,
   that's the PIR property), so the simulator-property proofs should
   continue to hold. **Walk through Theorem.ec lemma-by-lemma to
   confirm nothing depends on cross-query padding identity.** This is
   the non-trivial bit.

5. **Live integration tests:** `cargo test -p pir-sdk-client --test
   leakage_integration_test -- --test-threads=1 --ignored` — all
   harmony + dpf simulator-property tests must still pass.
   Specifically these check byte-identical wire profiles across
   curated scripthash batches, which is exactly the invariant we need
   to preserve.

## Acceptance criteria

- All Kani harnesses pass (updated to use seeded helper).
- All EasyCrypt proofs still close (zero admits, unchanged lemma count).
- The full `harmony_*` + `dpf_*` integration suite passes against pir1/pir2.
- `harmony_amortization_bench` on the 8-batch not-found case shows
  CHUNK phase wall time drop from ~8.4 s to ~4–5 s (theoretical
  optimum 4 wire rounds × ~1 s/round).
- `dpf_amortization_bench` shows similar batched-CHUNK improvement
  on the DPF side (`pir-sdk-client/src/dpf.rs::execute_step` will
  also need the same treatment if not already done in a parallel
  refactor).

## Out of scope

- Changing the value of `M = CHUNK_MERKLE_ITEMS_PER_QUERY`. Pinned
  at 16 in `pir-core::params`.
- Wire-format changes. Padding is a client-side decision; the server
  serves whatever chunk IDs the client asks for, and the
  privacy-padding invariants are at the *wire-round shape* layer, not
  the per-chunk-ID layer.
- DPF / OnionPIR batched CHUNK refactor (parallel work — same shape
  as the Harmony refactor in `986fd72a`, can land independently).
