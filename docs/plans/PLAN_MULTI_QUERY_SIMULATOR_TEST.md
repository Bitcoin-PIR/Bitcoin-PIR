# PLAN: Multi-Query Simulator-Property Test — DONE (2026-04-29)

> **Status: shipped end-to-end.** DPF + Harmony in `6eda18a`,
> OnionPIR (with the structural-triviality argument) in `dfe3508`.
> Six scripthashes pinned via the deterministic curation helper
> (`pir-sdk-client/examples/find_colliding_scripthashes.rs`); three
> integration tests prove `profile_A == profile_B == profile_C`
> byte-identical post-closure. The EasyCrypt analog
> (`simulator_property_multi_query`) is also closed non-vacuously
> in `3ab3f1a` via list induction over batch transcripts. See
> [docs/VERIFICATION_OVERVIEW.md](docs/VERIFICATION_OVERVIEW.md) for the consolidated
> summary.

## Goal

Empirically validate the EasyCrypt spec's `index_max_items_per_group_per_level` leakage axis: show that two batches with the same per-batch leakage record produce byte-identical `LeakageProfile`s, while two batches that differ on that axis produce *distinguishable* profiles. This is the empirical complement to the (admit-stubbed) `simulator_property_multi_query` lemma in `proofs/easycrypt/Theorem.ec`.

The current `dpf_per_message_invariants_batch_2_not_found` test (commit `9ea67f9`) confirmed batch=2 emits 21 rounds with `IndexMerkleSiblings` per-level = 4 (= `max_items_per_group × 2 servers`). That validated the *shape* but not the *L-equivalence claim*.

This test pins down the L-equivalence claim by curating colliding-vs-non-colliding scripthash batches.

## What it proves and what it doesn't

**Proves (empirically, against Hetzner):**
- Two batches with `L_eq = true` (same per-batch leakage record) produce byte-identical `LeakageProfile`s.
- Two batches with `L_eq = false` (different `index_max_items_per_group_per_level`) produce profiles that differ at the `IndexMerkleSiblings` rounds.

**Does not prove:**
- That the leakage record `L` captures *every* axis the wire reveals (a missing axis would still give equal profiles in this test if the curated batches happen to agree on it). The completeness check is the simulator-property *lemma*, not this test.
- Anything about timing, network metadata, OnionPIR LRU eviction, or compression. Those are explicit non-claims in `proofs/easycrypt/Leakage.ec`.

## Design

### Curation: find colliding and non-colliding scripthash pairs

For DPF (`K = 75`), each scripthash has `assigned_group = derive_groups_3(scripthash, K)[0]`. Two scripthashes "collide" iff they share `assigned_group`.

For the INDEX Merkle layer, `max_items_per_group_per_level` is determined by the per-level PBC plan over the batch's INDEX Merkle items. For a batch of N queries, total INDEX Merkle items = 2N (each query contributes `INDEX_CUCKOO_NUM_HASHES = 2`). Their distribution across PBC groups depends on the batch's *combined* assigned-group multiset.

**To curate scripthashes:**
1. Generate ~1000 random 20-byte scripthashes (all not-found w.h.p.).
2. For each, compute `derive_groups_3(scripthash, K)[0]`.
3. Bucket by assigned_group.
4. Pick three batches:
   - **`batch_A` (colliding)**: 2 scripthashes from the *same* assigned_group bucket.
   - **`batch_B` (colliding)**: 2 *different* scripthashes from the *same* bucket as `batch_A`.
   - **`batch_C` (non-colliding)**: 2 scripthashes from *different* buckets.

By construction `L_eq(batch_A, batch_B)` (both have the same assigned-group collision pattern) but `¬ L_eq(batch_A, batch_C)`.

### Test assertions

Run all three batches against the Hetzner staging server (`wss://pir1.chenweikeng.com` + `wss://pir2.chenweikeng.com`) with a `LeakageRecorder` installed. Capture three `LeakageProfile`s.

Assertions:
1. `profile_A == profile_B` (byte-identical, including per-round `request_bytes` / `response_bytes` / `items`).
2. `profile_A != profile_C`.
3. The difference between `profile_A` and `profile_C` is *localised* to the `IndexMerkleSiblings` rounds (every other round agrees). Document the exact diff.

Repeat for HarmonyPIR and OnionPIR backends with their respective `LeakageProfile`s.

## Implementation steps

1. **Add a curation helper** in `pir-sdk-client/examples/find_colliding_scripthashes.rs` (or as a `#[cfg(test)]` helper in the integration test file). Inputs: `K`, target collision pattern, RNG seed. Output: 6 scripthashes (3 batches of 2). Use `pir_core::pbc::derive_groups_3` and `INDEX_CUCKOO_NUM_HASHES = 2` constants.

2. **Pin the curated scripthashes** as constants in the integration test (so the test is deterministic, not dependent on runtime curation). Re-curate only when `K` changes.

3. **Add the integration test** as `dpf_simulator_property_multi_query_collision` in `pir-sdk-client/tests/leakage_integration_test.rs`. Default-target `wss://pir1.chenweikeng.com`; `#[ignore]` so it runs only when explicitly requested. Pattern follows the existing `dpf_simulator_property_*` tests.

4. **Repeat for Harmony and Onion**: `harmony_simulator_property_multi_query_collision` (against the Hetzner Harmony endpoint) and `onion_simulator_property_multi_query_collision`. The collision-detection logic is the same (DPF and Harmony share `K=75` for the INDEX layer; Onion has its own parameters).

5. **TS port**: Add the equivalent vitest test in `web/src/__tests__/onion_leakage_multi_query.test.ts` to verify the cross-language `OnionPirWebClient` produces matching profiles for the same curated batches.

6. **Document the empirical diff** in `PLAN_LEAKAGE_VERIFICATION.md` status table — flip the multi-query simulator-property row from "queued" to "empirically validated".

## Acceptance criteria

- `cargo test -p pir-sdk-client --test leakage_integration_test dpf_simulator_property_multi_query_collision -- --ignored` passes against Hetzner.
- All 3 backends have an analogous test passing.
- The TS port passes via `npm test`.
- A `git log` line points to the commit; memory `project_leakage_verification.md` is updated to reflect the new empirical-validation column.

## Estimated cost

- Curation script + DPF integration test: ~1.5 hours.
- Harmony + Onion ports: ~1 hour each.
- TS port: ~30 min.
- Docs / memory update: ~15 min.
- **Total: ~4-5 hours of focused work.**

## After this lands — the rest of the queue

In order of priority:

### A. Close the 2 remaining EasyCrypt admits

`simulator_property_per_query` and `simulator_property_constructive` in `proofs/easycrypt/Theorem.ec`. Both are admit-stubbed not for missing math but for tactic glue: the EasyCrypt incantation to translate `equiv [proc1 ~ proc2 : pre ==> ={res}]` into the corresponding functional equality on the underlying `op` is version-specific.

The math is captured by closed lemmas:
- `simulator_property_per_query` = `Real_proc_eq_op` + `real_transcript_factors_through_L` (both closed).
- `simulator_property_constructive` = `Real_proc_eq_op` + `Sim_proc_eq_op` + `real_eq_sim_op` (all closed).

Attempts that bounced off in this session: `proc; auto`, `wp; skip => />`, `progress; exact:`, `smt(hint)`, `apply` with explicit + implicit args. Each got close but missed by some specific unification or substitution detail. Needs hands-on iteration with the EasyCrypt REPL and probably a `byequiv` / `transitivity*` / `inline *` chain that I didn't try.

**Estimated cost:** hours-to-days for someone with pRHL fluency. **Recommendation:** consult with an EasyCrypt user (or post on the EasyCrypt mailing list) before sinking more solo time into this.

### B. `index_max_items_per_group_per_level` closure

Pad INDEX Merkle items to a fixed `M` per query, distribute across PBC groups uniformly. Per `PLAN_CHUNK_MAX_CLOSURE.md` shape, simpler than `chunk_max` because per-query items are fixed = 2.

Implementation steps:
1. Extract `pad_index_merkle_items_uniformly` pure helper in `pir-sdk-client`.
2. Kani harness for the helper (pattern: existing `pad_chunk_rounds_for_presence_*` harnesses).
3. Update DPF / Harmony / Onion clients to call the helper.
4. Update server-side bin handling.
5. Integration test asserting per-level pass count is constant across batch contents (only function of batch size).
6. Once landed, remove `index_max_items_per_group_per_level` from `proofs/easycrypt/Leakage.ec` and update `Theorem.ec` proof obligations.

**Estimated cost:** ~1 week across 3 backends.

### C. `chunk_max_items_per_group_per_level` closure

Per `PLAN_CHUNK_MAX_CLOSURE.md`. The big one. ~4-5 weeks. Highest privacy impact (closes the strongest residual leak).

### D. EasyCrypt: split per-backend `Protocol_*.ec`

Refactor `Protocol.ec` so each backend has its own file. Lets per-backend proofs evolve independently. ~half day.

### E. EasyCrypt: `query_batch` extension to make `simulator_property_multi_query` non-vacuous

After the multi-query test (this plan) lands, the EasyCrypt analog is to extend `Real` and `Sim` with a `query_batch` procedure and prove the multi-query lemma. Multi-day; depends on threading HarmonyPIR session state.

## Resume instructions for the next session

The next session should:

1. **First action:** Read this file, then read `proofs/easycrypt/README.md` for context on the spec status.
2. **Curate scripthashes:** Write the helper from step 1 above; run it locally to get the 6 curated values.
3. **Add the DPF integration test** with the curated values pinned as constants. Run against Hetzner. If profiles match the design predictions, lock the test in.
4. **Repeat for Harmony and Onion.**
5. **Commit and report.** A reasonable commit message: `test(leakage): multi-query simulator-property test with curated colliding scripthashes`.
6. **Don't try to close the EasyCrypt admits in this session** — that's queued for after a real EasyCrypt expert is available, or after several days of focused time. The 12/14 closed lemmas already capture the math.

Continue to subsequent priorities (B → C → D → E) only when the multi-query test is fully landed and committed.
