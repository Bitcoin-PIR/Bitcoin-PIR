# Leakage Verification Plan — DONE (2026-04-29)

> **Status: every item in this plan is closed.** The project shipped:
> all 4 privacy invariants closed end-to-end across DPF / HarmonyPIR /
> OnionPIR (Rust) + WASM bindings + standalone TS OnionPirWebClient;
> 31/31 EasyCrypt lemmas mechanically closed (zero admits); 18+ Kani
> harnesses verified; cross-language Rust↔TS equivalence verified
> live against Hetzner. See [docs/VERIFICATION_OVERVIEW.md](docs/VERIFICATION_OVERVIEW.md)
> for the consolidated final-state summary. This file is preserved
> as the historical plan-of-record; do not edit further.

## Goal

Formally characterize what a malicious server can learn from observing
client traffic, given that PIR primitives (DPF, OnionPIR FHE,
HarmonyPIR PRP) are assumed secure as black boxes. The verification
target is the *composition* layer: padding, batching, round structure,
and per-message item counts.

## Status

| Approach | Status | What it gives |
|---|---|---|
| **2 — Cross-implementation differential testing** | **✅ DONE** | Empirical verification that the wire shape doesn't leak query content for the corpus inputs |
| **1 — Kani / Creusot bounded model checking** | **✅ DONE (partial)** | items_from_trace, items_from_inspector_result, build_index_alphas K-padding, plus the user's CHUNK Round-Presence harnesses |
| **3 — EasyCrypt / Lean simulator proof** | **✅ SCAFFOLDING** | Spec landed at `proofs/easycrypt/` (commit `0909bb0`); proofs `admit`-stubbed (closure is multi-month) |

## Open work (post-amendment)

After the L-spec amendment in commit `0909bb0`, three new admitted axes
are now declared in the formal model. They reflect what the wire
actually reveals — not what the existing single-query corpus
empirically observes. Concrete next moves:

| # | Task | Effort | Status / cost rationale |
|---|---|---|---|
| **A.0** | batch_size=2 integration test that captures the `index_max_items_per_group_per_level` axis shape | ✅ DONE (`9ea67f9`) | `dpf_per_message_invariants_batch_2_not_found` — prints round counts, asserts K-padding shape on the multi-query path |
| **A.1** | Multi-query simulator-property witness (DPF, Harmony, OnionPIR) — curated colliding scripthash batches drive `max_items_per_group` from 2 to 4 on DPF/Harmony; OnionPIR axis is structurally trivial at batch=2 (`pbc_plan_rounds`-packs into 1 round per level), all three Onion profiles equivalent | ✅ DONE (`6eda18a` DPF + Harmony, follow-up commit OnionPIR) | DPF A=24/B=24/C=12 IndexMerkleSiblings (= 2× C), Harmony A=12/B=12/C=6, OnionPIR A=B=C with 1 round per level. See `pir-sdk-client/tests/leakage_integration_test.rs::*_simulator_property_multi_query_collision` |
| **B** | Close `chunk_max_items_per_group_per_level` via Merkle-item padding | High (multi-week, see `PLAN_CHUNK_MAX_CLOSURE.md`) | Pad chunk Merkle items to fixed M per query; distribute uniformly across chunk-PBC groups. Mirrors CHUNK Round-Presence Symmetry shape but more expensive (round count scales with M) |
| **C** | Close `index_max_items_per_group_per_level` (analogue of B at the INDEX side) | Medium (week) | Same shape as B but cheaper since INDEX_CUCKOO_NUM_HASHES = 2 caps per-query items; closure is "pad multi-query batches to a fixed M total INDEX Merkle items distributed uniformly". The empirical witness in A.1 is the regression test that closure must keep at `A == C` after the padding change lands |
| **D** | Close axis 3 (`session_query_index`) for HarmonyPIR | Out of scope | Refresh timing is intrinsic to HarmonyPIR's protocol design; reduces to "session length is public", documented in proof |
| **E** | Engage EasyCrypt collaborator to close `Theorem.ec` admits | Out of scope (months, expert) | Per-axis simulator-property proofs require pRHL fluency; queue as research-paper deliverable |

---

## Framework: leakage simulator

Define a leakage function `L(q)` per query that explicitly enumerates
what the protocol admits to leak:

```
L(q) = {
    chunk_round_occurred:   bool,   // reveals found vs not-found (non-whale)
    chunk_merkle_item_count: u32,   // reveals approximate UTXO count (if found)
    timing_bucket:           ...,
}
```

The security theorem (informal):

```
∀ q1, q2.  L(q1) = L(q2)  ⇒  Transcript(q1) ≡_obs  Transcript(q2)
```

where `≡_obs` is observational equivalence modulo uniform randomness in
DPF keys / FHE ciphertexts / PRP outputs. Equivalently: there exists a
simulator `Sim` such that `Transcript(q) ≡ Sim(L(q), $)`.

The padding invariants from CLAUDE.md ("CRITICAL SECURITY REQUIREMENTS")
are exactly the per-message preconditions this theorem depends on.

---

## Approach 2 (DONE) — Cross-implementation differential testing

The four implementations of the INDEX-Merkle item-count invariant
(`pir-sdk-client/src/{dpf,harmony,onion}.rs` plus
`web/src/onionpir_client.ts`) can drift independently. Differential
testing catches the realistic regression class without committing to
proof-assistant infrastructure.

### Phase 2.1 — `LeakageProfile` capture (✅ DONE)

Implemented in `pir-sdk/src/leakage.rs`:

- `LeakageRecorder` trait + `BufferingLeakageRecorder` (Mutex-backed
  buffer for tests).
- `RoundProfile { kind, server_id, db_id, request_bytes,
  response_bytes, items }` with `kind` discriminator covering
  `Index`, `Chunk`, `IndexMerkleSiblings { level }`,
  `ChunkMerkleSiblings { level }`, `HarmonyHintRefresh`,
  `OnionKeyRegister`, `Info`, `MerkleTreeTops`.
- `items` semantics encodes per-backend per-message invariants:
  - DPF Index: `[INDEX_CUCKOO_NUM_HASHES; K]` per server
  - Harmony Index: `[batch_items[g].indices.len(); K]` (= T-1 per
    slot — directly captures the HarmonyPIR Per-Group Request-Count
    Symmetry invariant in the profile)
  - Onion Index: `[INDEX_CUCKOO_NUM_HASHES; K]`
- serde derives gated on the existing `serde` feature; JSON shape is
  flat (`{"kind": "index", ...}`) and pinned by
  `leakage_profile_json_shape_is_pinned`.

Wired into all three Rust clients (`set_leakage_recorder` setter,
`record_round` helper, emission at every transport-level roundtrip).
The recorder is independent of `PirMetrics` — install neither, either,
or both.

### Phase 2.2 — Rust property tests (✅ DONE)

`pir-sdk-client/tests/leakage_integration_test.rs` — `#[ignore]`
integration tests that drive real PIR queries against real servers
(default: public Hetzner deployment; env-overridable via `PIR_*_URL`).

**Per-message invariants** verified empirically:

- DPF Index: `items.len() == K` and uniform `items[g] = 2`.
- DPF Merkle siblings: `items.len() == K`, `items[g] = 1`.
- Harmony Index/Chunk: `items.len() == K`, uniform `items[g] = T-1`
  (don't hardcode T — it's a per-DB function of the bin count).
- Onion Index: `items[g] = 2`. Onion's Merkle uses a separate
  `K_merkle = 25` (vs `K_pir = 75`); within-level uniformity
  asserted by `assert_merkle_per_level_uniform`.

**Simulator-property tests** verified empirically:

- DPF: two distinct not-found scripthashes produce **byte-identical**
  transcripts (modulo random DPF key contents — but per-round byte
  *counts* are identical because the protocol shape is fixed).
- Onion: same property holds (FHE ciphertexts are fixed-length per
  parameter set).

### Phase 2.2 hardening — FOUND path + admitted-leak validation (✅ DONE)

Beyond the not-found path, `leakage_integration_test.rs` covers:

- `*_found_query_includes_chunk_rounds` — known-found script-hashes
  (HASH160 of `web/src/example_spks.json` entries) trigger Chunk +
  ChunkMerkle rounds. If a server rebuild drops the example UTXOs,
  the test fires loudly.
- `*_found_vs_not_found_profiles_differ` — admitted-leak validation.
  Found queries emit MORE rounds than not-found (Chunk + ChunkMerkle
  present); the test asserts this distinguishability. If `L` ever
  over-claims that found and not-found are indistinguishable, this
  test catches it.
- `dpf_two_found_queries_both_follow_found_shape` — opportunistic
  same-class check; logs per-round divergences for future tightening
  with curated equal-UTXO-count corpora.

**Deferred coverage** (low priority; absence does not weaken the work
in place):

- `found@h=0 vs found@h=1` — needs scripthashes whose cuckoo positions
  are known. Would catch a hypothetical leak where the cuckoo position
  somehow shows on the wire.
- `whale vs not-found` — needs known whale entries (matched, no chunks).
- `found+10 utxos vs found+1000 utxos` — explicit "should differ" on
  `chunk_merkle_item_count`. The current test logs the relevant
  divergences but doesn't assert them as the documented admitted leak.

### Phase 2.3 — OnionPIR Rust ↔ TS cross-language diff (✅ DONE)

DPF and Harmony web clients are WASM glue over the Rust client and
inherit Phase 2.2 by construction. OnionPIR is the only genuinely
duplicated implementation (SEAL doesn't compile to wasm32).

Implemented in three layers:

1. **TS port** (`web/src/leakage.ts`) — `BufferingLeakageRecorder`
   class plus helpers (`itemsUniform`, `kindMatches`, `roundsOfKind`,
   `countOfKind`, `roundProfilesEqual`, `leakageProfilesEqual`).
   JSON shape pinned by parallel tests against the Rust serde output.
2. **Wiring** (`web/src/onionpir_client.ts`) — `setLeakageRecorder`
   method + emission at every wire site, mirroring the Rust client
   1:1. The shared `fetchServerInfoJson` / `fetchDatabaseCatalog`
   helpers gained optional `onRoundtrip(req, resp)` callbacks (DPF
   adapter passes nothing; OnionPIR caller passes a recorder hook).
3. **Diff harness** (`pir-sdk-client/examples/onion_leakage_dump.rs`,
   `web/src/__tests__/onion_leakage_diff.test.ts`) — Rust example
   binary connects to a server, runs a fixed two-query corpus, dumps
   JSON. Vitest test loads the JSON, drives the same scripthashes
   through `OnionPirWebClient` in node (with `ws` polyfill +
   Emscripten WASM in node mode), asserts byte-identical profiles
   round-for-round.

Verified live against `wss://pir1.chenweikeng.com`: 17.7 s end-to-end,
profiles match round-for-round.

**Architectural divergence** documented for future cleanup: Rust's
`OnionClient::query_batch` bundles Merkle verification, but TS exposes
`verifyMerkleBatch` as a separate call (the production UI in
`web/index.html` chains them). The diff test chains them too;
collapsing the TS API to match Rust would simplify cross-language
equivalence reasoning.

### Phase 2.4 — Resolution policy (active)

When a diff fires:

- **Real leakage bug** → patch the implementation. Add the
  triggering query as a regression case to the corpus.
- **Admitted leak** → document the leakage axis in `L` (extend the
  `LeakageProfile` shape) and the CLAUDE.md "What the Server Learns"
  section. Update the simulator-property tests to expect divergence
  along the new axis.
- **Never** resolve a diff by loosening the equality check. The
  equality check IS the leakage definition.

### Run commands

```bash
# pir-sdk lib tests (incl. JSON-shape pin)
cargo test -p pir-sdk --features serde --lib leakage::

# pir-sdk-client lib tests (incl. recorder wiring)
cargo test -p pir-sdk-client --lib
cargo test -p pir-sdk-client --features onion --lib

# web vitest (incl. corpus shape verification)
cd web && npm test

# Rust integration tests against live server (--ignored)
cargo test -p pir-sdk-client --features onion --test leakage_integration_test -- --ignored

# Regenerate the cross-language corpus from a live server
cargo run --release -p pir-sdk-client --features onion --example onion_leakage_dump -- \
    --output web/test/fixtures/onion_corpus.json

# Live cross-language diff (Rust ↔ TS), 17s vs Hetzner
cd web && RUN_LIVE_DIFF=1 npx vitest run src/__tests__/onion_leakage_diff.test.ts
```

---

## Approach 1 (NEXT) — Kani / Creusot bounded model checking

`LeakageProfile` is in place; the next research step is bounded
all-paths verification of the request builders. Kani harnesses for:

- INDEX request builder (each backend) — assert `items.len() == K`
  and `items[g] == EXPECTED` for every input.
- HarmonyPIR `build_request` / `build_synthetic_dummy` — assert
  per-slot length is exactly `T - 1` for every (`real_n`, `T`) pair
  in a small bound.
- Bucket-Merkle sibling request builder — assert items per query is
  exactly `INDEX_CUCKOO_NUM_HASHES = 2`.

Kani gives bounded all-paths coverage: for batch size ≤ 4 and the
four query outcomes (found@h=0, found@h=1, not-found, whale), Kani
exhausts `4^4 = 256` combinations per harness. This catches
optimization regressions that property tests with a finite seed corpus
might miss — the property tests are unbounded in input space but
corpus-limited; Kani is corpus-unbounded but bound-limited. They are
complementary.

Implementation outline:

1. Add Kani as a workspace tool (`cargo install kani-verifier`,
   `cargo kani setup` for the host).
2. Per-builder harnesses in `pir-sdk-client/kani/` (or
   `tests/kani_harnesses.rs` gated behind `#[cfg(kani)]`).
3. CI integration: a separate workflow that runs `cargo kani` on the
   harnesses; failure gates the merge.

Cost estimate: a few days for the harnesses + scaffolding, plus
ongoing Kani-runtime time per CI run (Kani is slow but bounded).

## Approach 3 (DEFERRED) — EasyCrypt / Lean simulator proof

The only approach that proves *completeness* of `L` — i.e., that
nothing leaks beyond what `L` admits.

Sketch:

1. Model the round structure in EasyCrypt's pRHL.
2. Encode the padding invariants from CLAUDE.md as preconditions (the
   theorems Approaches 1+2 establish on the implementation side).
3. Define `L` and construct `Sim(L, $)` — a transcript generator that
   has access only to `L(q)` and uniform randomness.
4. Prove `Pr[Real(q) = t] = Pr[Sim(L(q), $) = t]` for all transcripts
   `t` (perfect simulation), modulo PIR primitive assumptions.

The work in 2.1 is reusable: `LeakageProfile` is essentially the
informal version of the simulator's output type. Writing the EasyCrypt
model amounts to formalizing that shape and proving the implementation
realises it.

Why deferred: multi-month effort, requires EasyCrypt expertise,
publication-grade rather than CI-grade. Worth pursuing once 2.x is
stable (it is) and a paper-quality theorem becomes a goal.

---

## Progression rationale

| approach | catches | cost |
|----------|---------|------|
| 2 — diff tests | Implementation drift across the four redundant clients; concrete invariant violations on the test corpus | Low (done — days) |
| 1 — Kani | Invariant violations on inputs the corpus didn't sample | Medium (weeks) |
| 3 — EasyCrypt | Leakage axes we forgot to enumerate in `L` | High (months) |

2 was a strict prerequisite for 1 and 3 — both reuse the
`LeakageProfile` shape and the corpus. Approach 1 is now unblocked.
