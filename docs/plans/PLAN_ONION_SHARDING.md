# OnionPIR Sharding — Plan & Handoff

> Working doc for the OnionPIR multi-shard effort (the Fly.io scale-to-zero
> enabler). Written 2026-05-22 as a session-restart handoff. Captures: where
> the project is, the #2 (client routing) design, the architecture findings
> behind it, and the open decisions. A fresh Claude session should be able to
> resume #2 from this file alone.

---

## STATUS (2026-05-22) — #2 Rust client DONE + validated

**#2 (Rust `OnionClient` multi-shard routing) is implemented and validated.**
Uncommitted in the working tree on branch `wip/seeds-dense-onion`, layered on
top of the (also-uncommitted) identity WIP in `onion.rs` — a future
sharding-only commit will need the same kind of split as seeds+dense.

Implemented (`pir-sdk-client/src/onion.rs` + `onion_merkle.rs`):
- `OnionShard` + `shards: Vec<OnionShard>` (was single `conn`); `ShardConfig`
  + `new_sharded()` with `validate_shard_coverage` (ranges must tile
  `0..K` / `0..K_CHUNK`). `new()` = 1 shard, full ranges = byte-identical
  single-server. Per-shard `connect` / `disconnect` / `register_keys`;
  `is_connected` = all shards up; control-plane ops (attest/announce/upgrade/
  info) use the primary shard.
- `dispatch_sharded_batch(...)` — slices the full padded positional batch by
  each shard's group range (stride 2 INDEX, stride 1 CHUNK), per-shard
  `onionpir_batch_rpc(shard_idx, …)` with per-shard LRU re-register retry,
  merges responses back by position. Wired into `query_index_level` +
  `query_chunk_level`.
- Merkle: `verify_onion_merkle_batch` / `verify_sub_tree` now take
  `&mut [MerkleShardConn]`; tree-top blob fetched from shard 0, sibling
  passes split by per-tree group range + merged by position.
- Dispatch is **concurrent** (commit `bd4b7277`): per-shard roundtrips fan
  out via `futures_util::future::join_all` (INDEX/CHUNK in
  `dispatch_sharded_batch` + merkle siblings in `verify_sub_tree`); each
  future owns a disjoint `&mut shard.conn`. The rare LRU re-register retry
  runs sequentially after (needs `&mut self`). N=1 = one future = identical.

Validated:
- `cargo build/test -p pir-sdk-client --features onion` green; **217 lib
  tests pass**, incl. new `new_sharded_validates_full_coverage` (gaps /
  overlaps / bounds) + `dispatch_sharded_batch_splits_and_merges_by_position`
  (faithful 2-shard INDEX + 1-shard CHUNK MockTransport split→merge).
- **N=1 regression vs production `wss://weikeng1.bitcoinpir.org`**: the 3
  `test_onion_client_*` integration tests pass (connect / catalog /
  query_batch → `[None]` with FHE decrypt). Byte-identical end-to-end.

**Committed on `wip/seeds-dense-onion`** (split from the still-uncommitted
identity WIP via the strip-commit-restore dance — see §below): `793502b9`
(sharding routing) + `bd4b7277` (concurrent dispatch) + `4787ac12` (#3 server
group-range flag + ShardConfig re-export + sharded integration test). Pushed.

**#3 server flag** (`4787ac12`): `--onion-index-group-range lo:hi` /
`--onion-chunk-group-range lo:hi` make `unified_server` load only groups
`[lo,hi)` into the per-group server Vecs (dense + shared CHUNK, INDEX, both
Merkle sibling trees). The query handler is unchanged — it already applies the
client's positional `query[i]` to `servers[i]`, so loading exactly `[lo,hi)`
makes it answer the client's slice with no offset logic. Catalog still reports
the GLOBAL k_index/k_chunk; tree-tops served wholesale (client fetches from
shard 0). `pir_sdk_client::ShardConfig` now re-exported (was a #2 gap).

**N>1 e2e VALIDATED on pir1 (2026-05-22).** 3 shards (`unified_server`
`--onion-index-group-range` / `--onion-chunk-group-range`) on :8099/:8100/:8101
serving INDEX 0:25/25:50/50:75 + CHUNK 0:27/27:54/54:80 of a rebuilt dense
checkpoint; each loaded only its slice (25/25/25 index, 27/27/26 chunk +
matching sib servers). `test_onion_client_sharded_query_batch`
(`PIR_ONION_SHARDS=...`) passed — `Sharded query result: [None]`, FHE
decryption across all 3 shards, 40 s. Prod (8091/8092) untouched throughout;
scratch cleaned. **The full OnionPIR sharding path (client #2 + server #3)
works end-to-end** — the Fly.io scale-to-zero enabler is functional.

**TS mirror DONE** (`1fe3e2fb`): `web/src/onionpir_client.ts` —
`OnionShardConfig` + `OnionPirClientConfig.shards`, `shards: OnionShard[]`
(multi-WebSocket), `dispatchShardedBatch` (concurrent `Promise.all` split +
merge) for INDEX/CHUNK, per-tree-range merkle sibling split, per-shard
`registerKeys`, `validateShardRangeCoverage` (unit-tested). tsc clean; 144
vitest tests pass; N=1 byte-identical. `onionpir_client.ts` had no identity
WIP, so committed directly (no strip dance).

**The full OnionPIR sharding stack is implemented + committed**: dense build
(`gen_2_onion_dense`) + dense server loader + Rust client routing (#2) +
concurrent dispatch + server group-range flag (#3, e2e-validated) + TS client
mirror. All on `wip/seeds-dense-onion` (pushed).

**Remaining** (deployment, not code):
- A real multi-machine Fly.io sharded deploy (3× ≤16 GB suspendable machines,
  each holding its group slice — the original cost goal).
- Land `wip/seeds-dense-onion` (separate from the identity WIP — the
  strip-commit-restore pattern documented below has kept every sharding commit
  identity-free).

---

## 0. Where we are right now (read first)

- **Branch:** `wip/seeds-dense-onion` (you are likely on it locally). Pushed to
  `origin` (github.com/Bitcoin-PIR/Bitcoin-PIR).
- **Committed (`eca6752d`):** the *seeds + dense* subset — `pir-core::seeds`
  (chain-anchor seed derivation) + `cuckoo` anchor API, the build-pipeline
  migration, `build/src/gen_2_onion_dense.rs` (per-group dense CHUNK builder),
  and the `unified_server` dense CHUNK loader. **No identity/announce code** is
  in this commit.
- **Uncommitted (intact in working tree):** the identity/announce WIP — ~37
  files (`pir-identity/`, `pir-runtime-core/src/identity.rs`,
  `pir-sdk-client/src/announce.rs`, `bpir-admin/src/{generate,sign}_identity.rs`,
  edits to handler/protocol/cashu/lib, web/, root `Cargo.toml` adds the
  `pir-identity` member, etc.). Do **not** lose these; they are deliberately
  left out of the seeds+dense commit.
- **Cargo.lock:** committed lock lacks the `pir-core → sha2` edge; `cargo build`
  adds it automatically (sha2 0.10.9 already locked). Not a problem.
- **#14 DONE + validated** on pir1 (Hetzner). The dense `unified_server` boots
  (`80 chunk servers ready (dense, via onion_chunk_all.bin mmap)` + `75 index
  servers ready`) and answers a real OnionPIR query end-to-end (connect /
  fetch_catalog / query_batch all-zero → `[None]` not-found, with FHE
  decryption + merkle verification). pir1 scratch was cleaned; prod
  (8091/8092 + cloudflared) untouched and healthy. Full context in memory
  `project_onionpir_fly_migration.md`.
- **Gotcha learned:** `onion_chunk_cuckoo.bin` / `onion_*_bin_hashes.bin` are
  port-*independent* (cuckoo + SHA), but `onion_index_all.bin` and the dense
  CHUNK FHE payloads are port-*dependent* (entry_size 3840→3328 across the
  OnionPIRv2 port). A stale pre-port `onion_index_all.bin` fails
  `load_db_from_borrowed`. Rebuild INDEX with current `gen_3_onion` +
  merkle with `gen_4_build_merkle_onion` for a loadable post-port checkpoint.

The sharding work (this doc) is the **next phase**: make scale-to-zero cheap by
splitting the working set across N ≤16 GB suspendable machines.

- **#2 — client multi-shard routing** (THIS doc's focus; user said "start with 2")
- **#3 — server per-shard group-range flag** (serve only groups `[lo,hi)`)

---

## 1. Goal & privacy model

**Vertical sharding:** each shard machine holds a contiguous *range* of both
INDEX groups and CHUNK groups (and their per-group merkle sibling DBs). The
client sends each shard only the queries for its groups and merges the
per-shard responses.

**Privacy (non-negotiable — see CLAUDE.md "MANDATORY" invariants):**
- The client builds the **full padded batch exactly as today** — K=75 INDEX
  groups (× `INDEX_CUCKOO_NUM_HASHES=2` cuckoo positions), K_CHUNK=80 CHUNK
  groups, per-group merkle — with real queries in their cuckoo positions and
  random dummies everywhere else. **Only then** does it slice the batch by
  group-range and dispatch per shard.
- **Never reduce K per shard.** Global K=75 / K_CHUNK=80 is preserved; we only
  partition *which machine answers which group*.
- An honest, non-colluding shard sees only its already-padded slice → learns
  nothing it couldn't already (same as the single-server view restricted to
  those groups). Full collusion of all shards = today's single-server baseline.
- Key registration (galois + GSW, ~3 MB) multiplies by N shards (each shard
  needs the client's keys to answer FHE queries).

---

## 2. Architecture findings (the exploration behind the design)

All line numbers are in **`pir-sdk-client/src/onion.rs`** (3400 lines) unless noted.

### Wire format is POSITIONAL (the key enabler)
- `encode_onionpir_batch_query` (**:2216**): request =
  `[1B variant][2B round_id][1B num_queries]({ [4B len][query_bytes] })*[1B db_id?]`.
  No group indices — query[i] is implicitly for group i.
- `decode_onionpir_batch_result` (**:2267**): response =
  `[2B round_id][1B num_groups]({ [4B len][bytes] })*`. Positional too.
- **Implication:** a shard serving groups `[lo,hi)` receives the positional
  sub-batch and maps received query[i] → its local group `lo+i`. **No protocol
  byte changes needed** — the positional offset is the server's job (#3). The
  client just splits the positional list by range and concatenates responses
  back in order.

### Single transport today
- `OnionClient` (**:434**): `server_url: String`, `conn: Option<Box<dyn PirTransport>>`
  (ONE connection). Needs to become a `Vec` of per-shard conns.
- `connect` (PirClient impl, **:1743**), `disconnect` (**:1776**),
  `is_connected` (**:1793**).

### RPC layer
- `onionpir_batch_rpc` (**:1186**) → `onionpir_batch_rpc_once` (**:1253**):
  sends `msg` to `self.conn` (single), decodes `Vec<Vec<u8>>` (one PIR response
  per group/position). Has LRU-eviction re-register-and-retry-once logic.
  `items_per_group` is for leakage profiling (`RoundProfile`).
- `get_level_client` (**:1284**): per-(db_id, level) `onionpir::Client` for
  encrypt/decrypt. The FHE client is keyed by `num_entries` = the per-group DB
  size, which is the SAME for every group at a level → one level-client works
  for all shards' groups. Good (no per-shard FHE client needed).

### INDEX phase — `query_index_level` (**:1338**)
- Plans PBC rounds (`pbc_plan_rounds`). For each round, builds **`2*K`
  positional queries**: `[g0_h0, g0_h1, g1_h0, g1_h1, …]` (group g → positions
  `[g*2, g*2+1]`). Real groups get cuckoo-hashed bins; empty groups get random
  dummies (the padding).
- Sends the full `2*K` batch via `onionpir_batch_rpc` (variant
  `REQ_ONIONPIR_INDEX_QUERY`, `RESP_ONIONPIR_INDEX_RESULT`).
- Decodes by `qi = group*INDEX_CUCKOO_NUM_HASHES + h`. **Both** cuckoo
  positions are always probed (no early exit) — Merkle INDEX item-count
  symmetry (CLAUDE.md). Emits 2 `IndexBinMerkle` traces per scripthash.
- **Shard split:** for shard serving INDEX groups `[lo,hi)`, send query
  positions `[lo*2 .. hi*2)`; merge responses back at those positions.

### CHUNK phase — `query_chunk_level` (**:1502**)
- Collects each query's *real* chunk entry_ids (M=16 pad removed in Phase 4 —
  found-with-N → N reals, not-found/whale → 0). Plans PBC rounds over unique
  entry_ids. **All-not-found batch → one empty round** (`vec![Vec::new()]`) so
  exactly one all-dummy K_CHUNK round still goes out — CHUNK Round-Presence
  Symmetry (CLAUDE.md). Genuinely empty batch (no scripthashes) → no round.
- Each round builds **`K_CHUNK` positional queries** (one per chunk group),
  real or random dummy. Same `onionpir_batch_rpc` path
  (`REQ_ONIONPIR_CHUNK_QUERY` / `RESP_ONIONPIR_CHUNK_RESULT`).
- **Shard split:** for shard serving CHUNK groups `[lo,hi)`, send positions
  `[lo .. hi)`; merge back.

### Merkle — `run_merkle_verification` (**:880**) → `verify_onion_merkle_batch`
- Builds a flat `leaves: Vec<OnionMerkleLeaf>` (INDEX + DATA), each leaf
  carrying `pbc_group`, `bin`, `hash`, `result_idx`. Calls
  `verify_onion_merkle_batch(conn, &info, &leaves, …)` in
  **`pir-sdk-client/src/onion_merkle.rs`** with a **single conn**.
- Phase-3 per-group OnionPIR Merkle: 75 INDEX trees + 80 DATA trees; the single
  sibling level (leaf → level-1) is served by tiny **per-group** OnionPIR
  FHE-PIR DBs (`merkle_onion_sib_{index,data}.bin`), exactly like INDEX/CHUNK.
  So merkle sibling fetches are ALSO positional-per-group.
- **This is the most involved split:** `verify_onion_merkle_batch` (in
  `onion_merkle.rs`) must route each group's sibling query to the shard serving
  that group. It currently takes one `conn` — needs a shard-router (or a
  per-group `conn` mapping) passed in. Read `onion_merkle.rs` fully before
  implementing; confirm whether siblings are batched per-tree-kind across all
  groups (positional like INDEX/CHUNK) — they almost certainly are.

### Key registration
- `register_keys` (**:1106**), `ensure_keys_registered` (**:1093**),
  `encode_register_keys` (**:2198**, `REQ_REGISTER_KEYS`). With sharding,
  register the client's galois+GSW keys to **every** shard conn.

### Entry point
- `query_batch` (PirClient impl, **:1895**) → `execute_step` (**:731** /
  **:1018**) orchestrates INDEX → CHUNK → merkle.

---

## 3. Design for #2 (client multi-shard routing)

### Shard layout abstraction
```
struct OnionShard {
    url: String,
    conn: Option<Box<dyn PirTransport>>,
    index_range: Range<usize>,   // INDEX groups this shard serves, e.g. 0..25
    chunk_range: Range<usize>,   // CHUNK groups this shard serves, e.g. 0..27
    // (merkle index/data ranges == index_range/chunk_range by construction)
}
struct OnionClient {
    shards: Vec<OnionShard>,     // replaces `server_url` + `conn`
    // ... rest unchanged (catalog, onion_params, onion_merkle, fhe, recorders)
}
```
- **N=1 shard** with `index_range = 0..K`, `chunk_range = 0..K_CHUNK` ==
  today's exact behavior. `OnionClient::new(url)` stays as the 1-shard
  constructor (backward compat — keeps every existing test/usage working).
  Add `OnionClient::new_sharded(Vec<ShardConfig>)`.
- The union of all shards' ranges MUST cover `[0,K)` / `[0,K_CHUNK)` with no
  gaps/overlaps; validate at construction.

### Dispatch pattern (apply to INDEX, CHUNK, and merkle)
1. Build the full padded positional batch (UNCHANGED code).
2. For each shard, slice the batch to its range, `encode_onionpir_batch_query`
   the sub-list, send to that shard's conn. **Dispatch concurrently**
   (`futures::future::join_all`) — sequential would kill the latency win.
   (Watch the borrow checker: `&mut self` per-conn — likely restructure so the
   per-shard sends borrow only the conns, not all of `self`.)
3. Concatenate the per-shard responses back into the full positional
   `Vec<Vec<u8>>` (shard with range `[lo,hi)` fills response positions
   `[lo,hi)`), then run the existing decrypt/scan logic unchanged.
- LRU-eviction retry (`onionpir_batch_rpc`) becomes per-shard.
- `register_keys` → loop over shards.
- `connect`/`disconnect` → loop over shards.

### What does NOT change
- The padding, PBC planning, cuckoo hashing, FHE encrypt/decrypt, merkle
  verification math, and the wire bytes per group. Sharding is purely a
  *routing* layer over an unchanged per-group batch.

---

## 4. #3 (server group-range) — sketch (needed to TEST N>1)

In `runtime/src/bin/unified_server.rs`, the OnionPIR worker already loads
per-group `chunk_servers[0..k_chunk]` + `index_servers[0..k_index]` + merkle
sibling servers (the dense loader does this via `load_db_from_borrowed`). Add:
- `--onion-index-group-range lo:hi` and `--onion-chunk-group-range lo:hi`
  (or one combined flag) so a shard loads/serves ONLY groups `[lo,hi)`.
- The query handler maps incoming positional query[i] → local group `lo+i`
  and returns responses for exactly `hi-lo` positions. (Find the server-side
  onion query handler — likely in `pir-runtime-core` or the worker loop in
  `unified_server.rs`; I did not read it this session. Confirm where query[i]
  is applied to `chunk_servers[i]` / `index_servers[i]`.)
- Shard serves only its slice of the dense `onion_chunk_all.bin` /
  `onion_index_all.bin` (can mmap the whole file and load only `[lo,hi)`
  groups, or build per-shard files — start with mmap-whole, load-subset for
  simplicity; the cheap-storage win comes later from shipping only the slice).
- A shard answers all positions it receives — **no padding logic server-side**
  (padding is entirely client-decided).

**Test plan (mirror the #14 method):** on pir1, fresh clone, build, then run
e.g. 3 `unified_server` instances on :8099/:8100/:8101 each with a group-range
covering [0,25)/[25,50)/[50,75) INDEX and the matching CHUNK ranges, point a
sharded `OnionClient` (integration test, `PIR_ONION_SHARDS=...`) at all three,
and confirm the all-zero query returns `[None]` identically to the single
server. Keep it niced; never touch prod 8091/8092.

---

## 5. DECISIONS (resolved 2026-05-22)

1. **Shard config model → EXPLICIT operator config.** Client built with a shard
   list `new_sharded([{url, index_range, chunk_range}, ...])`. Fully decoupled
   from #3; build + regression-test the client with no server changes. A helper
   may split K evenly. Server-advertised discovery is a later enhancement.
2. **N>1 validation → STANDALONE #2 first.** Implement client routing only.
   Regression-test the N=1 (full-range) path against the existing single server
   to prove byte-identical behavior; unit-test the split/merge math + a
   MockTransport multi-shard dispatch test. Defer real N>1 e2e to #3 (server
   group-range flag), done separately.

---

## 6. TS client mirror (after Rust)

`web/src/onionpir_client.ts` is the hand-rolled standalone TS OnionPIR client
(SEAL doesn't compile to wasm32, so it stays). It has the same positional
batch query + per-group merkle structure and MUST get the same sharding
treatment (and preserve the same privacy invariants — CLAUDE.md calls out
`web/src/onionpir_client.ts::queryBatch` explicitly). Do Rust first, validate,
then mirror.

---

## 7. Suggested order on resume

1. Settle the two open decisions (§5).
2. Implement `OnionShard` / `shards: Vec<...>` + N=1 backward-compat path in
   `onion.rs`; get `cargo build -p pir-sdk-client --features onion` +
   existing tests green (N=1 must be byte-identical behavior).
3. INDEX split/merge, then CHUNK split/merge.
4. Merkle: read `onion_merkle.rs` fully, refactor `verify_onion_merkle_batch`
   to route per-group to the right shard conn.
5. Per-shard `connect` / `register_keys` / disconnect.
6. (If chosen) minimal #3 group-range flag in `unified_server.rs`; e2e test on
   pir1 with N=3 shards.
7. Mirror into `web/src/onionpir_client.ts`.

**Privacy regression guard:** the leakage integration tests
(`pir-sdk-client/tests/leakage_integration_test.rs`) are the backstop — but
they must run **server-side, `--test-threads=1`, never locally** (memory
`operational_leakage_test_no_local.md`). N=1 sharding must produce
byte-identical wire profiles to today.
