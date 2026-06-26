# PLAN: Per-Group Merkle Redesign + M=16 Removal — Coding Plan

**Status:** Phases 1–3d DONE + deployed live on Hetzner pir1; 3d↔3b
end-to-end test passed (2026-05-18). **3e (TS client) + Phase 4 remain**
— see §E.
**Design authority:** `MERKLE_COLOCATION_REVIEW.md` v2.2 (keep in sync).
**Working style:** main checkout only (no worktrees); commit at each phase
gate; multi-session — fill the §E session log as we go.

---

## A. Scope — two workstreams

- **WS-A — Remove the M=16 chunk-Merkle padding.** Applies to **all three
  backends** (DPF, HarmonyPIR, OnionPIR) + the standalone TS client.
- **WS-B — OnionPIR per-group Merkle redesign.** **OnionPIR only** —
  DPF/Harmony already have per-group (per-bucket) trees; they are the
  reference implementation to port from.

WS-A is independent per backend. WS-B is coupled with OnionPIR's WS-A
(the per-group verifier natively handles the 0-item case — see Phase 1
task 1.4). So: DPF and Harmony get WS-A only; OnionPIR gets WS-A folded
into WS-B.

## B. Sequencing `[HUMAN]`

**DPF → HarmonyPIR → OnionPIR.** Each backend fully working + verified
before the next. DPF first establishes the M=16-removal pattern + the
test-update pattern on the simplest backend.

## C. Cross-cutting invariants — must hold at every gate

1. **Round-presence.** Every query — found / not-found / whale — still
   performs ≥1 CHUNK PIR round **and** ≥1 CHUNK-Merkle pass (all-dummy
   when it has 0 chunks). This hides found-vs-not-found. **It is NOT
   automatic once M=16 is gone** — see Phase 1 task 1.4.
2. The INDEX path is untouched (M=16 is CHUNK-only).
3. New admitted leak: per-query real chunk count becomes observable.
   This is intended (`[HUMAN]`, 2026-05-17) and must be reflected in the
   leakage spec — Phase 4.

---

## Phase 1 — DPF: remove M=16   `[~1–2 sessions]`

**Goal:** a DPF query fetches/verifies its *real* chunk count, not 16.
Round-presence kept; found-vs-not-found preserved; perf improved.

1.1 **Map the DPF chunk path.** Read `dpf.rs` `chunk_pad_m` (≈L744),
    the `pad_chunk_ids_to_m` / `derive_chunk_pad_seed` call (≈L790-791),
    `query_chunk_level`, `items_from_trace`. Note where chunk-ids are
    gathered → padded → queried → turned into `BucketMerkleItem`s.

1.2 **Remove the pad call** (`dpf.rs` ≈L744, L790-791). `query_chunk_level`
    runs over the address's *real* chunk-ids. Not-found → empty list →
    keep the existing `query_chunk_level(&[], …)` round-presence path.

1.3 **Result assembly.** `items_from_trace` currently attaches 16 chunk
    Merkle items/query; attach the real count instead (still all on the
    first INDEX item).

1.4 **Found-vs-not-found guard `[critical]`.**
    `verify_bucket_merkle_batch_generic` (`merkle_verify.rs`) currently
    does `if chunk_sub_items.is_empty() { Vec::new() }` — i.e. **skips
    CHUNK-Merkle entirely for an all-not-found batch**. With M=16 gone
    that path is reachable → an all-not-found batch emits 0 CHUNK-Merkle
    traffic while a batch with ≥1 found emits ≥1 pass → found-vs-not-found
    leaks. **Fix:** when `chunk_sub_items` is empty, still issue **one
    all-dummy CHUNK-Merkle pass**. (`verify_sibling_levels`' `max(1,…)`
    handles ≥1 item; the empty-batch branch is the gap.) This guard lives
    in `merkle_verify.rs` → shared, so Phase 2 inherits it.

1.5 **Update the DPF leakage test.**
    `dpf_found_vs_not_found_have_byte_identical_profiles`
    (`leakage_integration_test.rs`): semantics change — found-vs-not-found
    is byte-identical only when chunk counts yield the same pass count.
    Restructure: assert found-c=1 ≡ not-found (both 1 pass); document
    that found-c-large differs (the accepted UTXO-count leak).

1.6 **Verify (gate).**
    - `cargo test -p pir-sdk-client --lib` green.
    - DPF integration test green against Hetzner.
    - Leakage check: an all-not-found DPF batch still emits ≥1
      ChunkMerkleSiblings round; found-c=1 ≡ not-found byte-identical.
    - Perf: measure DPF chunk-phase round count / wall time before vs
      after — expect a large drop for typical 1-chunk queries.
    - Commit: "feat(dpf): remove M=16 chunk-Merkle padding".

---

## Phase 2 — HarmonyPIR: remove M=16   `[~1 session]`

Apply the Phase 1 pattern to Harmony. Same shape; Harmony's hint-state
machinery is orthogonal to the M-padding.

2.1 Map: `harmony.rs` `chunk_pad_m` (≈L2434), pad call (≈L2478-2479).
2.2 Remove the pad call; query over real chunk-ids; keep round-presence.
2.3 Result assembly (Harmony's `items_from_trace` analog).
2.4 Found-vs-not-found guard — inherited from 1.4 (shared
    `verify_bucket_merkle_batch_generic`); just verify it triggers for
    Harmony.
2.5 Update `harmony_found_vs_not_found_have_byte_identical_profiles`.
2.6 **Gate:** Harmony lib tests + integration green; round-presence held;
    perf improved. Commit: "feat(harmony): remove M=16 chunk-Merkle padding".

---

## Pre-flight for Phase 3 (do during Phase 1–2, in parallel)

- Resolve `MERKLE_COLOCATION_REVIEW.md` §8.2 open items: **root/commitment
  format** (155 roots vs super-root vs signed snapshot) and the **FHE
  per-group sibling-DB** storage/NTT layout + params (§3).
- Get Codex's final sign-off on v2.2 §2f + §3.
- Phase 3 does not start until these are settled.

---

## Phase 3 — OnionPIR: per-group redesign + M=16 removal   `[~5–7 sessions]`

Implements `MERKLE_COLOCATION_REVIEW.md` §2–§6. WS-A (M=16 removal) is
folded in here — the per-group verifier handles 0-item queries natively.

**3a — Build pipeline** `[~2 sessions]`
- Rewrite `build/src/gen_4_build_merkle_onion.rs`: replace flat `build_tree`
  with per-group building — 80 CHUNK + 75 INDEX trees (port
  `merkle_bucket_builder.rs` shape, arity ≈104). **Keep OnionPIR's
  no-prefix leaf hash** (§2e). Emit per-group tree-tops, per-group level-0
  sibling DBs (NTT-preprocessed), 155 roots + super-root (§2f).
- `build/src/merkle_builder.rs`: shared tree-top writer.
- Gate: build runs; tree shapes match §2d; super-root stable.

**3b — Server** `[~1 session]`
- `runtime/src/bin/unified_server.rs`: serve the 155-tree tree-top blob;
  per-group sibling FHE-PIR handler (one query/group); new `onionpir_merkle`
  JSON (per-group shape + super-root).
- Gate: server starts; serves a hand-checked tree-top + sibling response.

**3c — Regenerate Merkle data + deploy** `[~0.5 session]`
- Run the new build; deploy to a non-production test server.

**3d — OnionPIR client: per-group Merkle verifier** `[~2 sessions]`

**Status:** DONE 2026-05-18 — client committed (`79e422b4`, on
`origin/main`), deployed live, 3d↔3b end-to-end test passed.
SOUNDNESS-CRITICAL — `onion_merkle.rs` is the verifier that proves the
server did not lie.

*File 1 — `pir-sdk-client/src/onion_merkle.rs` (1308 lines).*
- `verify_sub_tree` (≈L700): replace the per-level flat-tree walk with
  a per-group walk — one sibling level (leaf → level-1), one FHE-PIR
  query per PBC group into that group's sibling DB, walk the cached
  per-group tree-top to the group root, check the root against the
  pinned super-root.
- **Delete** the gid-cuckoo machinery (gone in the per-group design,
  §2c): `build_sib_cuckoo_for_group` (≈L480), `find_in_sib_cuckoo`
  (≈L562), `entries_in_sib_pbc_group` (≈L583), `sib_level_master_seed`
  / `sib_derive_cuckoo_key` / `sib_cuckoo_hash` (≈L459-478), the gid
  `pbc_plan_rounds` call (≈L790), `SibRng` (≈L600), and the now-unused
  `SIB_CUCKOO_MAX_KICKS` / `EMPTY` / `NUM_PBC_HASHES`.
- `parse_onion_tree_top_cache` (≈L344): rework for the 155-tree blob
  `merkle_onion_tree_tops.bin` — `[4B num_trees]`, then per tree
  `[1B cache_from_level][4B total_nodes][2B arity][1B num_cached_levels]`,
  then per level `[4B num_nodes][num_nodes×32B]`. The whole blob is
  served on either TREE_TOP opcode; parse all 155 (75 INDEX, then 80
  DATA).
- Structs (≈L162-201) + `parse_onionpir_merkle` (≈L226) /
  `parse_sub_tree` (≈L240): per-group shape — `super_root` + per-kind
  `{k, num_pt}`, matching the server JSON
  (`unified_server.rs::append_onionpir_merkle_json`: `{arity,
  super_root, tree_tops_hash, tree_tops_size, index:{k,num_pt},
  data:{k,num_pt}}`).
- Round-presence: a 0-item (not-found / whale) query still issues ≥1
  all-dummy CHUNK-Merkle pass — the per-group verifier handles the
  0-item case natively (K dummy FHE queries, one per group).

*File 2 — `pir-sdk-client/src/onion.rs` (3372 lines).*
- Remove the M=16 `pad_chunk_ids_to_m` call (≈L1508, L1527-1530) —
  query the real chunk-id list. OnionPIR's WS-A M=16 removal, folded
  into 3d (§A); the per-group verifier handles 0-item queries so
  round-presence holds without padding. After this, `dpf.rs`'s
  `pad_chunk_ids_to_m` / `derive_chunk_pad_seed` /
  `derive_synthetic_chunk_ids` lose their last caller — tighten their
  `#[cfg_attr(not(feature = "onion"), allow(dead_code))]` to an
  unconditional `#[allow(dead_code)]` (Phase 4 deletes them outright).
- Re-key `OnionMerkleLeaf` by `(pbc_group, bin)`.

*Wire protocol — unchanged.* 3b kept `runtime/src/onionpir.rs`: 4
opcodes `0x53-0x56`, `OnionPirBatchQuery`/`OnionPirBatchResult`
framing. SIBLING is single-level (K queries ↔ K PBC groups;
`round_id`'s `/100` level encoding is vestigial — send 0). TREE_TOP
returns the whole 155-tree blob on either opcode.

*Gate.* `cargo test -p pir-sdk-client --features onion --lib` green +
`cargo build -p pir-sdk-client --features onion` clean. End-to-end
needs the 3b `unified_server` running against the 3c-regenerated data
(on Hetzner at `checkpoints/948454`) — the new server is NOT deployed
(cloudflared fronts only 8091; the firewall may block spare ports), so
coordinate the end-to-end run with the human. Found-vs-not-found held;
one sibling pass per kind; perf improved vs the gid-cuckoo path.
Commit at the gate.

**3e — Standalone TS client** `[~1 session]`
- `web/src/onionpir_client.ts`: mirror the per-group verifier; remove
  `padChunkIdsToM` usage from `queryBatch`.
- Gate: `npm test` green; cross-language diff vs the Rust client.

---

## Phase 4 — Spec & docs cleanup   `[~1 session]`

4.1 **EasyCrypt** — re-open the `chunk_max` axis in
    `proofs/easycrypt/Leakage.ec` (+ touch `Protocol/Theorem/Simulator.ec`):
    flip from closed/constant to an **admitted axis = per-query real chunk
    count**. `make check` green. (Between Phase 1 and here the spec is
    knowingly stale — acceptable; or do this first if you prefer
    spec-leads-code.)
4.2 **Delete dead M=16 code** (now unused after all 3 backends):
    `pad_chunk_ids_to_m` + `derive_chunk_pad_seed` + Kani harnesses
    (`dpf.rs` ≈L2598, L2757, L3362-3457); `CHUNK_MERKLE_ITEMS_PER_QUERY`
    (`params.rs:180`); `padChunkIdsToM` + `onion_pad_chunk_ids.test.ts`.
4.3 **CLAUDE.md** — rewrite "CHUNK Merkle Item-Count Symmetry" as a
    documented trade-off; update "What the Server Learns".
4.4 Regenerate `web/test/fixtures/onion_corpus.json`; update
    `onion_leakage_diff.test.ts`, `docs/VERIFICATION_OVERVIEW.md`.
4.5 Gate: full CI green (`cargo test`, `wasm-pack`, `tsc`, `vitest`,
    `make check`).

---

## D. Risks

- **Found-vs-not-found regression** — the §1.4 guard is the single most
  important check; verify it at every backend gate.
- **Privacy-model change** — M=16 removal reverts a CLAUDE.md MANDATORY
  invariant; the leakage spec/tests MUST be updated to stay honest (WS
  Phase 4 + per-phase test updates).
- **Phase 3 is large** — needs a Merkle data rebuild + server redeploy;
  do it against a test server, not production.
- **Stale-spec window** — between Phase 1 and Phase 4 the EasyCrypt
  `chunk_max` axis lags the code. Tracked, accepted.

## E. Session log

_(fill as we go: date, phase/task, commit, gate status)_

- **2026-05-17 — Phase 1 (DPF), tasks 1.1–1.5.** Removed the M=16 pad
  from `dpf.rs::execute_step` (queries real chunk-ids now); removed the
  `chunk_sub_items.is_empty()` skip in `merkle_verify.rs` (`_generic` +
  `_parallel`) → found-vs-not-found guard (always >=1 all-dummy
  CHUNK-Merkle pass); updated the DPF leakage tests to the
  round-presence model. `cargo test -p pir-sdk-client --lib` → 170
  pass; lib + integration test compile clean.
- **2026-05-17 — Phase 1 (DPF) COMPLETE.** Committed `337aaf47`, pushed
  to `origin/main`. DPF leakage suite run server-side on Hetzner,
  strictly sequential (`-- --test-threads=1`): **10/10 passed** (99.8s)
  — incl. `dpf_found_vs_not_found_have_byte_identical_profiles`, so the
  found-vs-not-found guard is verified end-to-end. **Phase 1 gate
  closed.** (Local leakage-test runs are now blocked by a `PreToolUse`
  hook in `.claude/settings.json` — run server-side only, sequential.)
  Next: Phase 2 (HarmonyPIR M=16 removal).
- **2026-05-17 — Phase 2 (HarmonyPIR), tasks 2.1–2.5.** Removed the M=16
  pad from `harmony.rs::execute_step` — `query_chunk_phase_batched` now
  takes real chunk-ids (`per_q_real_chunks`); `items_from_trace` +
  `query_chunk_phase_batched` doc comments updated to the no-M model;
  Harmony leakage test updated to the round-presence model.
  **Round-presence subtlety found:** removing M=16 made
  `query_chunk_phase_batched`'s all-empty branch *live* (it was dead
  code while every query padded to 16). That branch emitted a single
  `run_chunk_round` (1 wire CHUNK round), but a found query's CHUNK
  phase emits a `run_chunk_round_pair` (2 wire rounds) — so an
  all-not-found batch would have leaked found-vs-not-found via the
  CHUNK round count. **Fix:** the all-empty branch now calls
  `run_chunk_round_pair`. The `merkle_verify.rs` CHUNK-Merkle guard is
  inherited from Phase 1 (shared, unchanged). `dpf.rs` M=16 helpers
  (`pad_chunk_ids_to_m` / `derive_chunk_pad_seed` /
  `derive_synthetic_chunk_ids`) lost their last default-build caller →
  gated `#[cfg_attr(not(feature = "onion"), allow(dead_code))]`
  (onion-only until Phase 3; deleted in Phase 4). `cargo test
  -p pir-sdk-client --lib` → 170 pass; default + `--features onion`
  builds + leakage test compile clean.
- **2026-05-17 — Phase 2 (HarmonyPIR) COMPLETE.** Committed `5e732672`,
  pushed to `origin/main`; Hetzner fast-forwarded. Harmony leakage
  suite run server-side on Hetzner, strictly sequential
  (`-- --ignored --test-threads=1`): all 6 harmony tests pass.
  `harmony_found_vs_not_found_have_byte_identical_profiles` (the Phase 2
  gate test) passed **3/3** runs — found-vs-not-found stays
  byte-identical after M=16 removal, so the round-presence guard + the
  all-empty `run_chunk_round_pair` fix are verified end-to-end.
  `harmony_simulator_property_{multi_query_collision,two_not_found}`
  each failed once then passed on retry — the documented HarmonyPIR
  flakes (wasm-bindgen-on-native panic; round-ordering nondeterminism
  in `assert_profiles_equivalent`'s positional comparison), not Phase 2
  regressions. **Phase 2 gate closed.** Next: Phase 3 (OnionPIR
  per-group redesign) — blocked on the `MERKLE_COLOCATION_REVIEW.md`
  §8.2 open items + Codex sign-off; do not start without the human.
- **2026-05-17 — Phase 3 (OnionPIR) — design decisions pinned, started.**
  `[HUMAN]` resolved the two pre-flight `[DESIGN — TO PIN]` items:
  **§2f → (b)** — a single **super-root** = `SHA256(concat 155 roots)`
  as the pinned trust anchor (mirrors `merkle_bucket_builder.rs`); the
  155 per-group roots ride in the public tree-top blob.
  **§3.1 → 155 per-group sibling DBs** (not one shared DB).
  **§3.2 (FHE params):** `[HUMAN]` expects the existing OnionPIR FHE
  params to work for the tiny ~99 (INDEX) / ~364 (CHUNK) -row sibling
  DBs — just a smaller query ciphertext — and asked to **experiment**
  to confirm. First Phase-3 task is therefore a small-DB FHE-PIR
  experiment (correctness + query/response ciphertext sizes at n≈99
  and n≈364) to de-risk §3.2 before the 3a build-pipeline rewrite.
- **2026-05-17 — Phase 3 §3.2 FHE-params experiment (DONE).** New tool
  `build/src/experiment_onion_sibling_pir.rs` (bin
  `experiment_onion_sibling_pir`, registered in `build/Cargo.toml`)
  sweeps `params_info()` + runs full query→answer→decrypt round-trips
  against `onionpir` git rev `f164451` (the rev the `build` crate
  resolves — NOT `vendor/onionpir/`, whose API differs). Findings:
  • **Correctness ✅** — round-trips at req n=99, 364, 4096 all pass
    (`decrypt_response == get_original_plaintext` for every boundary
    index). The degenerate single-dimension case (`other_dim_sz=1`)
    works. The `[HUMAN]` "the parameters should work" expectation holds.
  • **1024-plaintext floor ⚠️** — `calculate_db_shape` rounds ANY
    request ≤1024 up to exactly `num_plaintexts=1024` (`fst_dim=1024,
    other_dim=1`). The 99-row INDEX and 364-row CHUNK sibling DBs BOTH
    become a 1024-plaintext OnionPIR DB; no smaller DB exists.
  • **No "smaller query" ⚠️** — query=32776 B, resp=11264 B,
    galois=2560 KB, gsw=512 KB are CONSTANT across n=99/364/4096 (fixed
    by the compile-time SEAL params, not the DB size). The `[HUMAN]`
    "smaller query ciphertext" expectation does NOT hold.
  • **Cost** — each per-group sibling DB = 1024 pt = 3.25 MB logical /
    16 MB physical (post-NTT), ~500 ms/answer. §3.1's 155 per-group DBs
    ⇒ ~2.5 GB physical server storage. MERKLE_COLOCATION_REVIEW §5's
    ~122 MB estimate is far too low — it assumed DBs sized to the 99/364
    logical row counts; the 1024-floor + NTT expansion inflate it ~20×.
  • Noise budget after decryption = 1–2 (correct, but tight margin).
  **Open for [HUMAN]+Codex before 3a:** accept the 1024-floor cost, or
  revisit §3.1 (per-group vs shared/packed) / investigate whether the
  floor is lowerable via OnionPIR compile-time constants.
- **2026-05-18 — Phase 3 §3.2 RESOLVED — OnionPIRv2 small-DB fix
  verified.** The OnionPIRv2-fork landed the single-dimension DB-shape
  fix (`calculate_db_shape` sizes `other_dim_sz==1` DBs to the exact
  `target_num_pt`, no 1024 floor) on `main` @ `aa7710d`. Re-pinned
  `onionpir` → `aa7710d2493e97d7edef03e75d51ee05b0eab6c5` in `build/`,
  `pir-sdk-client/`, `runtime/` Cargo.toml. Re-ran
  `experiment_onion_sibling_pir`:
  • `params_info` now sizes exactly — n=99 → num_pt=fst_dim=99,
    other_dim=1; n=364 → 364/364/1; non-pow-2 OK (257→257). No floor.
  • Round-trips PASS at n=99, 364, 1024 (FFI query→answer→decrypt
    correct, noise budget 2).
  • **Per-query: n=99 ≈52 ms, n=364 ≈181 ms, n=1024 ≈547 ms** — linear
    in fst_dim (~0.5 ms/row); a 99-pt sibling DB is ~10.5× faster than
    the old 1024-floored shape.
  • Storage: n=99 = 1.55 MB physical (post-NTT), n=364 = 5.69 MB →
    155 sibling DBs ≈ 571 MB total (was ~2.5 GB pre-fix).
  • query/resp/key sizes still constant (query 32776 B) — fixed by the
    SEAL params, not the DB size.
  §3.2 closed: the existing OnionPIR params work for the per-group
  sibling DBs at their true sizes.
- **2026-05-18 — Phase 3 re-pin committed + §3.1 architecture pinned.**
  The `aa7710d` re-pin (3 Cargo.toml + Cargo.lock) and the
  `experiment_onion_sibling_pir` harness are committed as `5d4b3bda`
  (local — not pushed; `build/` is `.gitignore`'d so the harness was
  `git add -f`'d, consistent with the rest of the force-tracked
  `build/` crate).
  **§3.1 multi-DB architecture decided:** stand up the 155 per-group
  sibling DBs as **155 `onionpir::Server` instances** — one per group
  (75 INDEX @ ~99-pt + 80 CHUNK @ ~364-pt), mirroring
  `unified_server.rs`'s existing one-`PirServer`-per-PBC-group pattern
  for the data DBs (each `load_db_from_borrowed`-ing a sub-slice of one
  consolidated mmap'd file) — **plus one shared `onionpir::KeyStore`**
  attached via `Server::set_key_store`, so each client's galois
  (2.5 MB) + gsw (512 KB) keys are deserialized once rather than 155×.
  **Skip `set_shared_database`** — the indirect-DB path is for
  multi-tenant *overlap*; the 155 sibling DBs hold disjoint data, so
  there is nothing to dedup.
  **No upstream OnionPIRv2 change needed for shared keys** — `KeyStore`
  + `Server::set_key_store` already exist (`onionpir` lib.rs L405/L554;
  LRU cap 100 clients); `unified_server.rs` already runs a KeyStore for
  the data path. To confirm at 3a/3d: OnionPIR client keys are
  shape-specific, so the client side needs **2 `Client`s** — one per
  sibling-DB shape (99-pt INDEX, 364-pt CHUNK) — and the KeyStore holds
  2 key sets, not 1 and not 155.
  Next: **3a** — rewrite `gen_4_build_merkle_onion.rs` for per-group
  trees (80 CHUNK + 75 INDEX trees), per §6.
- **2026-05-18 — Phase 3 / 3a (build pipeline) — gen_4_build_merkle_onion
  rewritten.** Replaced the flat per-table OnionPIR Merkle build with
  per-group trees: one arity-104 tree per PBC group (75 INDEX + 80 DATA).
  The gid-cuckoo (`build_cuckoo_bs1`, `derive_pbc_groups`, `adaptive_k`,
  the per-level `_sib_L{N}_*` files) is gone (§2c). Leaves read verbatim
  from `onion_{index,data}_bin_hashes.bin` (no-prefix SHA256 — §2e
  preserved; never recomputed). New outputs:
  `merkle_onion_sib_{index,data}.bin` — consolidated per-group sibling
  FHE-PIR DBs (`[24B header][K save_db blobs]`, one
  `load_db_from_borrowed` sub-slice per group); `merkle_onion_tree_tops.bin`
  — 155 per-group tree-tops; `merkle_onion_roots.bin` (155 roots) +
  `merkle_onion_root.bin` (super-root = SHA256(concat), §2f). One PIR
  sibling level (leaf → level-1, `CACHE_FROM_LEVEL = 1`); levels 1+
  cached client-side.
  **Gate met:** `cargo check -p build` clean (the onion bin has zero
  warnings; pre-existing warnings live in other bins). Ran a synthetic
  smoke test (K=2, bins 10239 / 37853) — tree shapes **[10239,99,1]** and
  **[37853,364,4,1]** are exact §2d matches; sibling DBs sized 99 / 364
  plaintexts/group; all 5 output files byte-identical across two
  independent runs (deterministic — no RNG; `push_plaintexts`, not the
  random `gen_data`). Running against the real gen_2/gen_3 outputs is a
  build-host step (`onion_*_bin_hashes.bin` absent on this machine).
  Committed `449799d7`. Next: **3b** — serve the per-group OnionPIR
  Merkle in `unified_server.rs` (§6 item 3).
- **2026-05-18 — Phase 3 / 3b (server) — unified_server.rs rewritten for
  per-group OnionPIR Merkle.** Reworked the OnionPIR Merkle serving in
  `runtime/src/bin/unified_server.rs` across ~8 sites:
  • `OnionPirMerkleInfo` → `{arity, super_root_hex, tree_tops: Vec<u8>,
    index_k, index_num_pt, data_k, data_num_pt}`; dropped
    `OnionPirMerkleSubTree` / `OnionPirMerkleLevelInfo`.
  • Loading: dropped `load_merkle_sib_levels` (per-level
    `_sib_L{N}_{ntt,cuckoo}.bin` + per-tree `_root`/`_tree_top` reads);
    new `load_onion_sib_file` mmaps `merkle_onion_sib_{index,data}.bin`
    (24B header), reads `merkle_onion_tree_tops.bin` +
    `merkle_onion_root.bin`.
  • Worker: replaced the per-level `set_shared_database` loop with
    per-group `Server::new(num_pt)` + `load_db_from_borrowed` of each
    24B-header sub-slice (mirrors the `index_servers` block); dispatch
    `level==10` → INDEX sibling servers, `level==11` → DATA.
  • Handlers: TREE_TOP serves the whole 155-tree blob (`om.tree_tops`)
    on either opcode; SIBLING dropped the `round_id/100` level math
    (INDEX→level 10, DATA→level 11).
  • JSON: per-group schema (`arity`, `super_root`, `tree_tops_hash/size`,
    per-kind `{k,num_pt}`).
  `runtime/src/onionpir.rs` unchanged — the 4 opcodes 0x53-0x56 +
  `OnionPirBatchQuery`/`Result` framing stand. **Gate:** `cargo check -p
  runtime --bin unified_server` → Finished; zero warnings from the
  edited code (the 3 `main_data_dir` warnings are pre-existing —
  confirmed identical vs HEAD). The full "server starts + serves a
  hand-checked response" gate needs per-group Merkle data on disk + the
  3d client — deferred. Committed `121ea5c3`. Next: **3c** (regenerate
  Merkle data) / **3d** (client) per §6.
- **2026-05-18 — Phase 3 / 3c (regenerate data) — DONE (regen-only;
  test-server run deferred).** Pushed the 3 Phase-3 commits to
  `origin/main` (`5e732672..121ea5c3`); Hetzner fast-forwarded. Built
  `gen_4_build_merkle_onion` on Hetzner (cold onionpir@aa7710d C++
  rebuild, 2m16s) and ran it against the live main DB
  `/home/pir/data/checkpoints/948454` (decoded bin counts = §2d exactly:
  INDEX K=75/10239, DATA K=80/37853). gen_4 itself: 3.9s. Output:
  • `merkle_onion_sib_index.bin` 121.7 MB (75 × 1 622 064 B),
    `merkle_onion_sib_data.bin` 477.1 MB (80 × 5 963 824 B),
    `merkle_onion_tree_tops.bin` 1.19 MB (155 trees),
    `merkle_onion_roots.bin` 4960 B (155×32), `merkle_onion_root.bin`
    32 B (super-root `21b07dd2c4b926fe…`).
  • Tree shapes `[10239,99,1]` / `[37853,364,4,1]` — exact §2d matches.
  • Non-destructive: the old flat-tree files
    (`merkle_onion_index_sib_L0_*`, `_index_root.bin`, `_tree_top.bin`)
    are intact → the live pir-primary (old binary) is unaffected; the
    155 `.savetmp` temps were all cleaned up.
  Test-server run deferred — `[HUMAN]`: cloudflared maps only port 8091
  and the firewall may block other ports, so a spare-port test instance
  isn't reachable. The new `unified_server` (3b) gets exercised once 3d
  (client) lands and the full server+client path can be tested together.
  Next: **3d** — rewrite `pir-sdk-client/src/onion_merkle.rs` for the
  per-group verifier (§6 item 4).
- **2026-05-18 — Phase 3 / 3d (client) — mapped; not started.** Surveyed
  `pir-sdk-client/src/onion_merkle.rs` (1308 lines — the OnionPIR Merkle
  verifier) + `onion.rs` (3372 lines). The full file:line plan is
  written up in the **Phase 3d** section above (the per-group
  `verify_sub_tree` rewrite, the gid-cuckoo deletions, the
  tree-top/struct/JSON reshape, the `onion.rs` M=16 removal, the
  wire-unchanged note, the gate). 3d is soundness-critical and
  ~2 sessions — to be done as a fresh focused session; a self-contained
  kickoff prompt was handed to the human.
- **2026-05-18 — Phase 3 / 3d (client) — DONE.** Rewrote the
  soundness-critical OnionPIR Merkle verifier for the per-group model.
  • `onion_merkle.rs`: `verify_sub_tree` is now a per-group walk —
    fetch the consolidated 155-tree tree-top blob, bind it to the
    pinned `super_root` via the new `check_tree_top_anchor`
    (**SOUNDNESS-CRITICAL**: `SHA256(concat 155 per-group roots) ==
    super_root`, plus `tree_tops_hash` / `tree_tops_size` integrity and
    per-tree arity cross-check), then run `max(1, max_items_per_group)`
    K-padded FHE sibling passes (one query/group — real row `bin/arity`
    or random-row dummy), fold the decrypted sibling row into each
    leaf's running hash, and `walk_tree_top_to_root` to the per-group
    root. On anchor mismatch every leaf fails and sibling rounds are
    skipped (catastrophic abort).
  • Deleted the gid-cuckoo machinery (§2c): `build_sib_cuckoo_for_group`,
    `find_in_sib_cuckoo`, `entries_in_sib_pbc_group`,
    `sib_level_master_seed` / `sib_derive_cuckoo_key` / `sib_cuckoo_hash`,
    the gid `pbc_plan_rounds`, `SibRng`, and the now-unused consts
    (`SIB_CUCKOO_MAX_KICKS`, `EMPTY`, `NUM_PBC_HASHES`,
    `INDEX/DATA_SIBLING_SEED_BASE`,
    `ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES`). Dummy-row RNG reuses
    `merkle_verify::SimpleRng`.
  • `parse_onion_tree_top_cache` → `Vec<OnionTreeTopCache>` (155 trees,
    `[4B num_trees]` framing — identical to the shared per-bucket
    blob). Structs reshaped to the 3b server JSON schema:
    `OnionMerkleInfo { arity, super_root, tree_tops_hash,
    tree_tops_size, index/data: OnionMerkleKindInfo{k, num_pt} }`;
    `OnionMerkleLeaf` / verdict map re-keyed by `(pbc_group, bin)`;
    dropped `OnionMerkleSubTree` / `OnionMerkleLevelInfo`.
  • `onion.rs`: removed the M=16 `pad_chunk_ids_to_m` call —
    `query_chunk_level` now queries real chunk-ids; `IndexBinMerkle` /
    `data_merkle` / `OnionMerkleLeaf` re-keyed by `(pbc_group, bin)`;
    the now-unused `script_hashes` param dropped. **CHUNK PIR
    round-presence kept explicitly** (invariant C.1 — beyond the literal
    3d §6 wording, which only named the CHUNK-Merkle pass): a batch
    whose scripthashes are all not-found / whale (`unique` empty) still
    issues exactly one all-dummy K_CHUNK CHUNK PIR round
    (`rounds = vec![Vec::new()]`); only a genuinely empty batch (no
    scripthashes) skips. CHUNK-Merkle round-presence is handled
    natively by `verify_sub_tree` (always ≥1 all-dummy DATA pass).
  • `dpf.rs`: `pad_chunk_ids_to_m` / `derive_chunk_pad_seed` /
    `derive_synthetic_chunk_ids` lost their last caller — tightened
    `#[cfg_attr(not(feature="onion"), allow(dead_code))]` →
    `#[allow(dead_code)]` (Phase 4 deletes them outright).
  `runtime/src/onionpir.rs` unchanged — the 4 opcodes `0x53-0x56` +
  `OnionPirBatchQuery`/`Result` framing stand; `round_id` is sent as 0.
  **Gate met:** `cargo test -p pir-sdk-client --features onion --lib`
  → **199 pass** (incl. 16 new `onion_merkle` tests: super-root
  accept/reject, tampered-blob / wrong-tree-count / arity-drift
  rejection, multi-tree parse, tree-top walk good / tampered / deep).
  `cargo build -p pir-sdk-client --features onion` builds; the only
  warnings are 4 pre-existing ones (`ChunkSlot*` dead-code + `mut
  keygen` — confirmed unchanged vs HEAD via `git diff`), zero from the
  3d-edited code. Default (non-onion) `cargo test -p pir-sdk-client
  --lib` → 170 pass; `leakage_integration_test.rs` compiles
  (`--no-run`). **End-to-end deferred** — needs the 3b `unified_server`
  live against the 3c-regenerated data (not deployed; cloudflared
  fronts only 8091). `[HUMAN]` to coordinate the server+client
  end-to-end run. Committed `79e422b4` (local — not pushed; matches the
  3a/3b/3c pattern of committing each step to `main`). Next: **3e** —
  mirror the per-group verifier in the standalone TS client
  `web/src/onionpir_client.ts`; remove `padChunkIdsToM`.
- **2026-05-18 — Phase 3 / 3b deploy attempt — FAILED + rolled back
  (incident).** `[HUMAN]` asked to swap the live Hetzner `pir-primary`
  onto the 3b `unified_server` for the 3d↔3b end-to-end test. Built 3b
  on the host (git already at `121ea5c3`), backed up the old binary,
  restarted — **the 3b server crash-looped, and so did the OLD binary**
  on its next restart. **Root cause: 3c regenerated the per-group Merkle
  files into `checkpoints/948454` (2026-05-17) but did NOT regenerate
  `MANIFEST.toml`.** `pir-runtime-core/src/table.rs::MappedDatabase::load`
  verifies every file in the DB dir against `MANIFEST.toml` (a
  security/attestation boundary — "refusing to mmap unaccounted bytes")
  and `panic!`s on any unlisted file. The 5 new files
  (`merkle_onion_sib_{index,data}.bin`, `merkle_onion_tree_tops.bin`,
  `merkle_onion_root{,s}.bin`) were unlisted ⇒ panic at load. A latent
  landmine — it never hit the running server (load runs once, at
  startup) but crashes ANY restart since 3c. The 3c log's "live
  pir-primary unaffected" held only until a restart. **NOT a 3d/3b code
  bug.**
  **Recovery:** stopped the crash-loop, moved the 5 unlisted files to
  `/home/pir/data/pergroup_merkle_948454_staging/` (DB dir back to its
  known-good 27-file manifest state), restored the pre-3b binary
  (`mv`-swap — `cp` hit `Text file busy` against the crash-looping
  process), restarted PIR + cloudflared. Production fully restored +
  verified (real WS handshake OK on `wss://weikeng1` + `wss://weikeng2`,
  all 3 services active). ~35 min outage.
  **Blockers for a real 3b deploy (`[HUMAN]` to resolve):**
  1. `MANIFEST.toml` must include the per-group files: move the 5 back
     into `checkpoints/948454`, run `scripts/build_db_manifest.sh`. The
     3c procedure / build pipeline must be fixed to do this — `gen_4`
     emits the files but does not update the manifest. ⚠️ Regenerating
     `MANIFEST.toml` changes `manifest_root` — confirm whether the
     attestation pins depend on it before regenerating (flag, do not
     assume).
  2. The 3b server emits the new per-group OnionPIR Merkle JSON; the
     deployed web `onionpir_client.ts` is still the old flat-tree client
     (3e not done) ⇒ deploying 3b breaks OnionPIR Merkle for old
     clients. Bundle the 3b server deploy with 3e.
  Host `target/` note: cargo metadata reflects the 3b build but
  `release/unified_server` was `mv`'d back to the old binary — a future
  deploy must force a relink (`rm target/release/unified_server` first,
  or `touch` the source) or cargo will cache-hit and not rebuild.
- **2026-05-18 — MANIFEST.toml fixed; 3b deploy attempt #2 — FAILED on
  a deeper blocker; auto-rolled-back.** `[HUMAN]` cleared the
  attestation concern (pir1/Hetzner has no TEE attestation, manifest
  regeneration is fine). Moved the 5 per-group files back into
  `checkpoints/948454`, regenerated `MANIFEST.toml` via
  `scripts/build_db_manifest.sh` → 32 files, dir/manifest consistent
  (this also de-mined the old binary — a reboot no longer crashes it).
  Rebuilt + redeployed 3b. It cleared the manifest check, and 3b's NEW
  per-group sibling FILE loading worked — `load_onion_sib_file` parsed
  both consolidated files (`index` K=75/num_pt=99, `data`
  K=80/num_pt=364 — exact §2d match). But it then **panicked in the
  EXISTING (pre-3b) `index_servers` loop** (`unified_server.rs:1941`):
  `load_db_from_borrowed` returned false for `index group 0` of
  `onion_index_all.bin`. **Root cause: the `onionpir@aa7710d` re-pin
  (3c / `5d4b3bda`) made the binary incompatible with the existing
  OnionPIR data DB.** `onion_index_all.bin` (+ `onion_shared_ntt.bin`,
  …) were built with the pre-`aa7710d` onionpir; `aa7710d`'s
  `load_db_from_borrowed` rejects them. 3c re-pinned to `aa7710d` and
  regenerated only the *Merkle* data (gen_4), NOT the OnionPIR *data*
  DB (gen_2/gen_3), and validated only the small sibling DBs
  (`experiment_onion_sibling_pir` n=99/364/1024) — never the big data
  DBs. Auto-rollback (built into the deploy command) worked: stopped
  3b, restored the old binary, restarted — production recovered. ~6 min
  OnionPIR-inclusive downtime.
  **3b CANNOT be deployed against the current production data.**
  **Investigated — NOT an `aa7710d` regression** (confirmed against the
  `onionpirv2-fork` git history): `aa7710d`'s `calculate_db_shape` diff
  is a single inserted `if (target_num_pt>0 && target_num_pt<=capacity)
  return {target_num_pt,1};` fast path; the multi-dimension loop is
  byte-identical. The per-group OnionPIR INDEX data DBs are **small
  single-dimension DBs** (`target_num_pt < 1024`): the pre-`aa7710d`
  `calculate_db_shape` floored every `≤1024`-plaintext DB to exactly
  1024 plaintexts (16777264 B/group blob — matches the crash's `len`);
  `aa7710d` removes that floor and sizes them exactly. So
  `onion_index_all.bin` (built pre-`aa7710d`, 1024-floored blobs) no
  longer matches what the `aa7710d` binary expects — `load_db_from_borrowed`
  correctly rejects it. Same floor the §3.2 experiment found for the
  sibling DBs; 3c fixed the sibling data (gen_4) but not the OnionPIR
  data DBs. **Real fix:** regenerate the OnionPIR data DBs
  (`onion_index_all.bin`, `onion_shared_ntt.bin`, chunk data) for
  checkpoint 948454 at `onionpir@aa7710d` (gen_2/gen_3 pipeline) — also
  a perf win (smaller, un-floored per-group DBs). Then validate 3b on a
  TEST instance before any live deploy. **No more live-deploy attempts
  until the OnionPIR data is rebuilt.** Production verified stable on
  the old binary (real WS handshake OK, weikeng1 + weikeng2).
- **2026-05-18 — OnionPIR data regenerated at aa7710d; 3b DEPLOYED LIVE.**
  Regenerated the OnionPIR data DBs for both main (checkpoint 948454)
  and the delta (940611_948454) at `onionpir@aa7710d`
  (gen_1_onion → gen_2_onion → gen_3_onion → gen_4_build_merkle_onion;
  gen_2/gen_3 self-tests PASS for both). gen_3 refined the diagnosis:
  the main's per-group INDEX DB is **multi-dimension**
  (`fst_dim=512, padded=10752`) while the delta's is **single-dimension**
  (`fst_dim=965, other_dim=1`) — so aa7710d's single-dim fix affects
  the delta but not the main; the old `onion_index_all.bin` was a stale
  build inconsistent with the rest of the checkpoint. Validated on
  Hetzner: a 3b `unified_server` test instance on spare port :8093
  loaded the regenerated main, then the full main+delta config —
  `[OnionPIR:{main,delta}] 75 index servers ready (via
  onion_index_all.bin mmap)`, all per-group Merkle sibling servers
  ready, :8093 WS 101 — zero impact on the live server. **Deployed
  live:** assembled `checkpoints/948454_aa7710d` +
  `deltas/940611_948454_aa7710d` (regenerated onion files + hardlinked
  non-onion files + fresh MANIFEST.toml), swapped the binary
  (`target/release/unified_server` → 3b) + `databases.toml` (→ the
  _aa7710d dirs), restarted pir-primary + pir-secondary. Both up,
  NRestarts=0, :8091 + :8092 listening, public `wss://weikeng1` real WS
  handshake OK, hint pool running; ~3 min restart downtime. Rollback
  artifacts kept: `unified_server.bak-pre3b-20260518`,
  `databases.toml.bak-pre-aa7710d`, untouched old dirs
  `checkpoints/948454` + `deltas/940611_948454`. **3b is live on
  production.** Remaining: (1) the deployed web `onionpir_client.ts` is
  still the old flat-tree client (3e) — old OnionPIR clients get
  Merkle-unverified results until 3e ships (DPF/Harmony unaffected,
  OnionPIR data queries still work); (2) the 3d↔3b end-to-end test
  (3d client, real verified query) not yet run — needs 3d (`79e422b4`,
  local-only) on Hetzner.
- **2026-05-18 — 3d pushed; 3d↔3b end-to-end test PASSED. Phase 3
  complete.** Pushed 3d (`79e422b4`) to `origin/main`
  (`121ea5c3..79e422b4`); Hetzner pulled it. Ran the OnionPIR
  integration tests (`pir-sdk-client/tests/integration_test.rs`, the
  `onion_*` tests) server-side on Hetzner against the live 3b server
  (`PIR_ONION_URL=ws://localhost:8091`): `test_onion_client_connect`,
  `test_onion_client_fetch_catalog`, `test_onion_client_query_batch` —
  **3/3 passed** (FHE decrypt noise budget 1–2). The 3d per-group
  Merkle verifier does a real OnionPIR query + verification against the
  live 3b per-group server + the regenerated `aa7710d` data — the full
  Rust stack is validated live. (The `leakage_integration_test.rs`
  `onion_*` tests were NOT run — their wire-profile assertions are
  stale post-M=16-removal; updating them is Phase 4.) **Phases 3a–3d
  complete + live.** Remaining: **3e** (standalone TS client
  `web/src/onionpir_client.ts` — mirror the per-group verifier) +
  **Phase 4** (spec/docs). A self-contained 3e kickoff prompt was
  handed to the human.
- **2026-05-18 — Phase 3 / 3e (standalone TS client) — DONE.** Mirrored
  the 3d per-group verifier into the hand-rolled TS client
  (`web/src/onionpir_client.ts`), the direct port of
  `pir-sdk-client/src/onion_merkle.rs @ 79e422b4`.
  • New module-scope helpers (the TS twins of `onion_merkle.rs`):
    `parseOnionTreeTopCache` ([4B num_trees] 155-tree blob — bounds-
    checked, throws on truncation / arity=0), `checkTreeTopAnchor`
    (**SOUNDNESS-CRITICAL** — tree count, `tree_tops_size` /
    `tree_tops_hash` integrity, per-tree arity, and
    `SHA256(concat 155 roots) == super_root`), `walkTreeTopToRoot`,
    `onionTreeTopRoot`, `bytesEqual`.
  • `verifyMerkleBatch` / `verifySubTree` rewritten as a per-group walk
    — fetch the 155-tree tree-top blob, anchor-check it, run
    `max(1, maxItemsPerGroup)` K-padded FHE sibling passes (one query
    per PBC group, real row `bin/arity` or random-row dummy), fold the
    decrypted sibling row into each leaf, walk the cached per-group
    tree-top to the group root. **Both** sub-trees always verified —
    an empty DATA sub-tree still issues one all-dummy K_CHUNK sibling
    pass (CHUNK-Merkle round-presence). Deleted the gid-cuckoo
    machinery (`deriveIntGroups3` / `deriveCuckooKeyGeneric` /
    `cuckooHashInt` / `ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES`
    imports, `fetchTreeTopCache`, the `index/dataTreeTopCache` fields,
    the `merkle.ts::parseTreeTopCache` import) and the
    `setDbId` tree-top-cache invalidation.
  • `queryBatch`: dropped the `padChunkIdsToM` call — the CHUNK phase
    now queries the *real* chunk-id list (`chunkOwnedPerQuery[i]` = N
    reals for found, 0 for not-found / whale). **CHUNK PIR
    round-presence kept explicitly**: a non-empty batch whose
    scripthashes are all not-found / whale (`uniqueEntryIds` empty)
    still issues exactly one all-dummy K_CHUNK CHUNK round
    (`chunkRounds = [[]]` fallback); only a genuinely empty batch
    (N === 0) skips. INDEX / DATA Merkle leaves re-keyed by
    `(pbcGroup, bin)`.
  • Types reshaped to the 3b server JSON: `server-info.ts` —
    `OnionPirMerkleInfoJson { arity, super_root, tree_tops_hash,
    tree_tops_size, index/data: OnionPirMerkleKindInfo{k,num_pt} }`
    (dropped `OnionPirMerkleSubTreeInfo` / `OnionPirMerkleLevelInfo`);
    `types.ts` `QueryResult` — `merkleSuperRoot` +
    `indexBinLeaves` / `dataBinLeaves` (each `{hash,pbcGroup,bin}[]`),
    dropped `merkleIndexRoot` / `merkleDataRoot` / `indexLeafPos` /
    `allIndexBinHashes` / `dataBinHashes` / `dataLeafPositions`.
    `indexBinHash` kept as the UI's "verifiable" marker
    (index.html filters on it). `hasMerkleForDb` fail-safe: requires a
    64-hex `super_root`.
  • `padChunkIdsToM` / `deriveChunkPadSeed` / `deriveSyntheticChunkIds`
    / `CHUNK_MERKLE_ITEMS_PER_QUERY` kept as dead exported helpers
    (their `onion_pad_chunk_ids.test.ts` still passes) — Phase 4
    deletes them, matching the 3d treatment of `dpf.rs`.
  `runtime/src/onionpir.rs` unchanged — `round_id` sent as 0; the whole
  155-tree blob fetched on either TREE_TOP opcode.
  **Gate met:** `cd web && npx tsc --noEmit` clean; `npm test` →
  158 passed, 2 skipped (the `RUN_LIVE_DIFF`-gated cross-language diff).
  No test files modified — the pure-fn onion tests
  (`onion_chunk_slot_classifier`, `onion_pad_chunk_ids`) and the
  static-fixture `onion_leakage_corpus` test are independent of the
  verifier rewrite. End-to-end live diff vs the 3b server +
  `onion_corpus.json` regeneration are Phase 4. Next: **Phase 4**
  (spec/docs cleanup).
- **2026-05-18 — Phase 4 (spec & docs cleanup) — locally-doable parts
  DONE; two operational items flagged for a server-side session.**
  • **4.2 dead M=16 code deleted.** `dpf.rs`: removed
    `derive_chunk_pad_seed` / `derive_synthetic_chunk_ids` /
    `pad_chunk_ids_to_m` (~230 lines) + their 4 Kani harnesses
    (`pad_chunk_ids_to_m_*` in `mod kani_harnesses`).
    `pir-core/src/params.rs`: removed `CHUNK_MERKLE_ITEMS_PER_QUERY`
    (left a NOTE comment). `web/src/onionpir_client.ts`: removed
    `CHUNK_MERKLE_ITEMS_PER_QUERY` / `deriveChunkPadSeed` /
    `deriveSyntheticChunkIds` / `padChunkIdsToM` (~190 lines); deleted
    `web/src/__tests__/onion_pad_chunk_ids.test.ts` (23 tests). The
    `classify_chunk_slots` / `classifyChunkSlots` round-presence
    helpers were NOT touched (pre-existing dead code, not M=16, not in
    the kickoff's explicit list). Stale `CHUNK_MERKLE_ITEMS_PER_QUERY`
    comment ref in `dpf.rs` (`items_from_trace_found_at_h0` test doc)
    reworded.
  • **4.3 CLAUDE.md.** "CHUNK Merkle Item-Count Symmetry (MANDATORY)"
    rewritten as "CHUNK Merkle Item-Count — Documented Trade-off (NOT
    an invariant)"; "What the Server Learns" updated (approximate
    per-query UTXO count moved from *cannot* to *can* observe);
    fixed the now-stale `pad_chunk_ids_to_m` / `padChunkIdsToM` bullets
    in the "CHUNK Round-Presence Symmetry" section.
  • **4.1 EasyCrypt.** Re-opened the `chunk_max` axis in
    `proofs/easycrypt/Leakage.ec` axis-2 comment (closed→re-opened,
    admitted = per-query real chunk count); updated `README.md`
    "Closure status". **No structural EC change was needed** —
    `Protocol.ec` / `Simulator.ec` / `Theorem.ec` already model
    `chunk_max` as an abstract per-query `int` (never the literal 16),
    so the proof obligations are unchanged. `make check` → exit 0,
    415 verification points, no errors.
  • **4.4 (partial).** Updated the OnionPIR leakage-test comments +
    failure messages in `leakage_integration_test.rs`
    (`onion_found_vs_not_found_have_{same_round_count,byte_identical_profiles}`)
    to the round-presence model, mirroring the Phase-1 DPF restructure;
    added the `nf_cms >= 1` round-presence guard to the byte-identical
    test. Updated `docs/VERIFICATION_OVERVIEW.md` (wire-leakage summary,
    Kani harness count 18→14, Invariant 4 → trade-off section,
    Invariant 2 "subsumed by" note) and the stale comment in
    `web/src/__tests__/onion_leakage_diff.test.ts`. One stray
    `pad_chunk_ids_to_m` ref in `docs/BDK_WALLET_PROTOTYPE.md` fixed.
  **Gate met (locally):** `cargo test -p pir-core --lib` 45 pass,
  `-p pir-sdk-client --lib` 170 pass, `--features onion --lib` 199
  pass; `cargo check -p pir-sdk-client --features onion --tests`
  clean (compiles the edited `leakage_integration_test.rs`);
  `cd web && npx tsc --noEmit` clean + `npm test` 135 pass / 2 skipped
  (−23 from the deleted suite); `make check` exit 0; `wasm-pack build`
  Done. No new warnings.
  **Operational items deferred to a server-side session `[HUMAN]`:**
  (1) regenerate `web/test/fixtures/onion_corpus.json` via
  `cargo run --release -p pir-sdk-client --features onion --example
  onion_leakage_dump` against the live 3b server (the committed corpus
  is the stale M=16-era recording — `npm test` is unaffected because
  the shape-test never runs the client and the cross-language diff is
  `RUN_LIVE_DIFF`-gated); (2) run the OnionPIR leakage integration
  tests server-side, strictly sequential, to confirm
  `onion_found_vs_not_found_have_byte_identical_profiles` and the
  other `onion_*` leakage tests still pass post-3e / post-M=16-removal
  (they cannot run locally — PreToolUse hook + local-network rule).
  **Phases 3 + 4 code/spec/doc work complete; only the two server-side
  confirmations remain.** Committed `f93160fe` (Phase 3e + Phase 4, 13
  files, +1008 / −1490) and pushed to `origin/main`
  (`79e422b4..f93160fe`). The pre-existing unrelated `README.md`
  working-tree change was deliberately left unstaged.
- **2026-05-18 — Phase 4 server-side confirmations DONE.** Ran the two
  deferred operational items on Hetzner (`pir1`, the live 3b
  per-group server).
  • **OnionPIR leakage suite — 7/7 pass.** First full run: 5/7 (incl.
    the two Phase-4-restructured `onion_found_vs_not_found_*` tests —
    verified live). `onion_round_count_is_function_of_batch_size_only`
    failed run 1 on a transport flake (`Connection reset`), passed on
    retry. `onion_simulator_property_multi_query_collision` failed
    run 1 on a **stale flat-tree assertion** — `IndexMerkleSiblings
    == 1` (the per-group verifier does 2: each query's 2 INDEX cuckoo
    positions are 2 leaves in its one per-group tree; measured
    A=B=C=2, the load-bearing `assert_profiles_equivalent` held).
    Fixed in `143fea31`: rewrote the test's gid-cuckoo header + pinned
    the count at 2; updated the `7/1 -> 10/2` witness in CLAUDE.md /
    Leakage.ec axis-1 / VERIFICATION_OVERVIEW.md. Retry then hit a
    fresh Cloudflare-path 240s timeout flake → passed on retry via
    `ws://localhost:8091`.
  • **`onion_corpus.json` regenerated** (`6eb4e962`) via
    `onion_leakage_dump` against the live server. The 2 not-found
    queries now capture the post-Phase-3e/4 per-group profile (10
    rounds, byte-identical): `Info, Info, OnionKeyRegister, Index,
    Chunk, MerkleTreeTops, IndexMerkleSiblings{0} x2, MerkleTreeTops,
    ChunkMerkleSiblings{0}` — exactly what the 3e TS verifier
    produces, an independent confirmation that the 3e per-group
    verifier rewrite is wire-correct.
  Commits `143fea31` + `6eb4e962` pushed to `origin/main`. DPF /
  Harmony leakage suites were not re-run — Phase 3e/4 does not touch
  their client behaviour (the deleted M=16 code was already dead;
  Phases 1/2 ran their suites). **Phase 3 + Phase 4 fully complete and
  server-confirmed.**
