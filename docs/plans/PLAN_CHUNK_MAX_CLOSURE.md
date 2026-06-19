# PLAN: Close `chunk_max_items_per_group_per_level` Leakage Axis — DONE (2026-04-29)

> **Status: shipped end-to-end.** DPF (commit `565ea47`), Harmony
> (`08ec736`), OnionPIR (`f915a65`), standalone TS OnionPirWebClient
> (`eb5128c`). Pure helper `pad_chunk_ids_to_m` Kani-verified (4
> harnesses). `Leakage.ec` axis 2 prose updated; CLAUDE.md gained a
> new "CHUNK Merkle Item-Count Symmetry (MANDATORY for Privacy)"
> section. Empirical: found and not-found queries produce
> byte-identical leakage profiles on every backend. The closure
> shipped a different (simpler, cheaper) shape than this plan
> originally proposed — see [docs/VERIFICATION_OVERVIEW.md](docs/VERIFICATION_OVERVIEW.md)
> for the as-built design.

## What this closes

`proofs/easycrypt/Leakage.ec` admits the axis
`chunk_max_items_per_group_per_level : int` — the maximum number of
CHUNK Merkle items the wire reveals concentrated in any one
chunk-PBC group, per Merkle level. The wire reveals it via the
per-level `ChunkMerkleSiblings` pass count.

Two queries with the same total chunk-Merkle-item count but
different chunk-ID distributions across chunk-PBC groups produce
distinguishable transcripts. Specifically, a server can fit the
per-level pass-count distribution to candidate UTXO sets and rule
out queries whose chunk-IDs would have collided differently.

This is the strongest remaining residual leak in the wire-shape
model (CLAUDE.md "What the Server Learns" already names it).

## Closure shape (analogous to CHUNK Round-Presence Symmetry)

The recently-landed CHUNK Round-Presence Symmetry pads every query
to ≥1 CHUNK PIR round so chunk-round absence stops leaking found-vs-
not-found. This closure follows the same pattern but at the
CHUNK Merkle layer:

1. Pad CHUNK Merkle items to a fixed `M` per query, regardless of
   the query's actual chunk count. Found queries with N chunks
   contribute N real items + (M − N) synthetic dummy items; not-
   found queries contribute M synthetic dummies.
2. Distribute the M items uniformly across chunk-PBC groups so the
   per-group max is bounded and *deterministic* (a function of M
   and the PBC plan, not query content).
3. Server-side: the dummy items are valid Merkle proofs over real
   bin contents (server doesn't need to know they're dummies); the
   client verifies all M proofs and discards the M − N dummies in
   post-processing.

Result: per-level pass count becomes `M / K_chunk` (rounded up),
constant across queries. The axis disappears from `L`.

## Choice of M

Trade-off:
- Smaller M = cheaper queries but covers fewer real UTXO counts
- Larger M = more privacy but quadratic cost (M items × Merkle
  verification × wire bytes)

Three candidate strategies:

**(i) Fixed M = max_practical_utxos.** Pick M such that 99%+ of
real-world Bitcoin scripthashes have ≤ M UTXOs. Pad small queries
up to M. Tail of >M-UTXO scripthashes (whales) are handled by the
existing whale-exclusion path (no chunk Merkle items emitted; the
INDEX entry's `num_chunks = 0` is committed to the INDEX root).

**(ii) Tiered M.** Pick a small set {M_1 < M_2 < M_3} of allowed
sizes; client picks the smallest M_i ≥ N. Tier choice is wire-
observable but reveals only "approximate UTXO size class," which
is a much coarser leak than the current per-pass-count fingerprint.

**(iii) Logarithmic tiers.** M ∈ {1, 2, 4, 8, 16, ...}. Constant-
factor overhead, exponentially decreasing per-class privacy
granularity.

Recommendation: **(i)** with M chosen empirically from the live
UTXO distribution (look at the 99th percentile of UTXOs-per-
scripthash on the indexed height; pick M slightly above that).
Tier strategies (ii) and (iii) trade some privacy for cost, but
strategy (i) closes the axis cleanly when the long tail is
absorbed by the existing whale path.

## Implementation steps (rough order, multi-week)

1. **Add `M` to `DatabaseInfo`.** Server-published parameter
   alongside K, K_CHUNK, etc. Required for client + server
   agreement on the padded item count.

2. **Server-side: emit synthetic Merkle items.** When a query
   produces N < M real chunk Merkle items, the server (or the
   client, depending on protocol layer) generates M − N synthetic
   bins drawn from `chunk_pbc_groups` not used by the real query.
   These synthetic items have valid Merkle proofs (the bins they
   reference exist in the database), so the client's verification
   passes uniformly across found and not-found queries.

3. **Client-side: distribute synthetic items uniformly.** Use a
   deterministic-from-query-content placement plan that fills the
   M items into chunk-PBC groups so per-group max is constant
   (M / K_chunk rounded up). Existing PBC plan code in
   `pir-core::pbc::pbc_plan_rounds` should adapt.

4. **Client-side: discard dummies post-verification.** After all
   M items verify against the chunk Merkle root, drop the M − N
   synthetic ones from the UTXO assembly path. Synthetic chunks
   produce decoded entries that don't match the scripthash's tag
   so they're filtered naturally — but verify this assumption
   doesn't accidentally leak via timing.

5. **Update Kani harnesses.** New pure helper
   `pad_chunk_merkle_items_to_M` that takes (real_items, M, plan)
   and returns the padded M-item list. Kani-verify it always
   emits M items with the deterministic distribution. Mirror
   shape of `pad_chunk_rounds_for_presence`.

6. **Update integration tests.** `dpf_*_per_message_invariants_*`
   to assert ChunkMerkleSiblings per-level pass count is constant
   `M / K_chunk` across queries. Flip `chunk_merkle_item_count`
   admitted-leak tests to "should match" (analogous to the
   `dpf_found_vs_not_found_have_same_round_count` flip post-
   CHUNK Round-Presence).

7. **Update LeakageProfile + cross-language diff.** No type
   changes (item counts are already in `RoundProfile.items`); the
   diff test gets stronger because chunk Merkle profiles now
   match across queries instead of only across same-content
   queries.

8. **Remove `chunk_max_items_per_group_per_level` from
   `proofs/easycrypt/Leakage.ec`.** Update Theorem.ec lemma (e)
   to argue the axis is now constant, not query-dependent.

9. **Document in CLAUDE.md.** New section "CHUNK Merkle Item-Count
   Symmetry (MANDATORY for Privacy)" parallel to the existing
   CHUNK Round-Presence Symmetry. Move the corresponding entry
   from "What the Server Learns" to "What the Server Cannot Learn."

## Estimated cost

- Steps 1–4 (server + client implementation): ~1 week per backend
  × 3 backends = 3 weeks. Onion is hardest (FHE-encrypted dummies
  need to decrypt validly).
- Steps 5–8 (verification): ~1 week.
- Step 9 (docs): ~1 day.
- Total: 4–5 weeks of focused work.

## Why not now

This session has limited time and the work needs careful design
(particularly step 2's choice of synthetic-bin selection — must
not leak via the PBC plan choice). Queued for a future focused
session; the spec amendment in commit `0909bb0` is the
prerequisite.

## Resume instructions for a future session

1. Re-read this doc + `proofs/easycrypt/Leakage.ec` for the axis
   definition.
2. Pick M empirically from `databases.toml` UTXO distribution (need
   a script to scan a delta DB and compute the 99p UTXO count per
   scripthash).
3. Start with DPF (simplest backend); land the pure helper +
   Kani harness first. Then server-side dummy emission. Then the
   client decode path. Then integration test asserting
   ChunkMerkleSiblings pass count is M/K_chunk rounded up,
   constant.
4. Repeat for Harmony and Onion.
5. Once all three backends land, update `Leakage.ec` (delete the
   axis), `Theorem.ec` (lemma update), CLAUDE.md (new invariant
   section), and `PLAN_LEAKAGE_VERIFICATION.md` (status table).
