# BitcoinPIR Project Memory

## Project Overview
Bitcoin Private Information Retrieval (PIR) system with three backends: DPF-PIR, OnionPIR, HarmonyPIR. Supports full snapshots and delta synchronization for incremental updates.

---

## CRITICAL SECURITY REQUIREMENTS

### Query Padding (MANDATORY for Privacy)

**NEVER OPTIMIZE AWAY PADDING. The padding is INTENTIONAL and REQUIRED for privacy.**

Within each PIR round, queries are padded to FIXED counts:
- **INDEX queries**: Always K=75 groups (regardless of how many real queries)
- **CHUNK queries**: Always K_CHUNK=80 groups (regardless of how many real chunks)
- **MERKLE queries**: Always 25 sibling queries (regardless of proof depth)

**Why:** If the server sees varying numbers of queries, it can infer information about which groups contain real queries vs padding. By always sending exactly K queries, the server cannot distinguish real queries from dummy queries.

**How padding works:**
1. Real queries are placed in their computed cuckoo positions
2. Remaining empty groups get random DPF keys (dummy queries)
3. Server processes ALL groups identically, cannot tell which are real

### Cuckoo Hashing and "Not Found" Verification

Each scripthash maps to INDEX_CUCKOO_NUM_HASHES=2 possible cuckoo positions. To prove a scripthash is "not found", ALL positions must be checked and verified:
- Client checks position h=0, then h=1
- If neither contains the scripthash, it's definitively not in the database
- Merkle verification must cover ALL checked bins to prove "not found"

### Merkle INDEX Item-Count Symmetry (MANDATORY for Privacy)

**All five clients (TS DPF/Onion/Harmony, Rust DPF/Harmony) MUST emit exactly
`INDEX_CUCKOO_NUM_HASHES = 2` Merkle items per INDEX query, regardless of
query outcome (found at h=0, found at h=1, not-found, or whale).**

The per-level sibling **pass count** (`max_items_per_group`) is directly
observable on the wire. If a found query emits 1 INDEX Merkle item and a
not-found query emits 2, the server can infer found-vs-not-found from
the batched sibling request size for every INDEX Merkle level. That
defeats the "chunk rounds reveal found/not-found" trade-off at the INDEX
level and leaks cuckoo-position (h=0 vs h=1) as well.

**Invariants clients must preserve:**
1. Both cuckoo positions are probed for every INDEX query — no early exit
   on match. (In DPF and Onion the extra probe is tracking-only since
   both bins are XOR'd from the same batch response; in Harmony it costs
   one extra wire round per found@h=0 query.)
2. The Merkle item builder iterates the full `all_index_bins` list
   unconditionally, emitting one `BucketMerkleItem` per probed bin.
3. Whales emit INDEX Merkle items from their probed bins too — the
   whale's INDEX entry (`num_chunks=0`) is committed to the INDEX Merkle
   root, so whale-exclusion is a verifiable property.
4. Chunk-level Merkle items attach only to the matched INDEX bin.
   CHUNK Merkle item counts still vary with UTXO count — that is a
   separate, documented trade-off (see "What the Server Learns" below).

### What the Server Learns (Documented Trade-offs)

The server **cannot** learn:
- Which specific groups contain real queries (due to padding)
- Which specific scripthash was queried
- Whether a query was found or not-found at the INDEX Merkle level
  (closed by the item-count symmetry invariant above)
- Which cuckoo position (h=0 vs h=1) a found query matched at

The server **can** observe (known trade-offs):
- Whether CHUNK rounds occur (reveals found vs not-found for non-whale
  queries — chunk rounds are skipped entirely when no INDEX match)
- Whether CHUNK Merkle rounds occur, and how many CHUNK Merkle items
  (reveals approximate UTXO count for found queries)
- Timing patterns across rounds

To fully hide found/not-found, the client would need to send dummy chunk
and chunk-Merkle rounds even when no results were found. This is a
documented privacy/efficiency trade-off that is distinct from — and
strictly weaker than — the INDEX-Merkle leak closed above.

---

## Recent Work: PIR SDK Implementation

### Completed
1. **pir-sdk/** - Core SDK crate with:
   - Database catalog types and sync planning (BFS delta chain, max 5 steps)
   - Delta merging logic
   - Hash function wrappers (splitmix64, cuckooHash, etc.)

2. **pir-sdk-wasm/** - WASM bindings for browser use:
   - `WasmDatabaseCatalog`, `WasmSyncPlan`, `WasmQueryResult` classes
   - `computeSyncPlan()`, `mergeDelta()`, `decodeDeltaData()` functions
   - Hash functions exposed to JS
   - Built with `wasm-pack build --target web`

3. **pir-sdk-client/** - Native Rust client. All three backends are fully
   implemented:
   - `DpfClient` — per-bucket Merkle verification via `merkle_verify.rs`
     (see item 8 below).
   - `HarmonyClient` — per-bucket Merkle verification via the shared
     `BucketMerkleSiblingQuerier` trait (see item 8 below).
   - `OnionClient` — per-bin Merkle verification via a separate module
     `onion_merkle.rs` (INDEX + DATA flat trees, FHE sibling queries;
     see item 10 below). Feature-gated behind `onion`.

4. **pir-sdk-server/** - Server-side SDK placeholder

5. **Web SDK Integration**:
   - `web/src/sdk-bridge.ts` - Bridge with automatic fallback to TypeScript
   - `web/src/sync-controller.ts` - Now uses `computeSyncPlanSdk` from SDK
   - `web/index.html` - Calls `initSdkWasm()` at startup
   - `web/package.json` - Added `pir-sdk-wasm` dependency

6. **Merkle Verification for "Not Found" Results** (web TS clients, commit `60fe19c`):
   - All three **web TypeScript** PIR clients (DPF, OnionPIR, HarmonyPIR)
     track ALL bins checked.
   - For "not found", verifies ALL INDEX_CUCKOO_NUM_HASHES=2 positions.
   - Proves scripthash is truly absent from the database.
   - Enables Merkle verification of delta databases even when no activity.

7. **Human-Verifiable Audit Logging** (commit `9a693c5`):
   - `[PIR-AUDIT]` prefixed logs in web TS clients (DPF, OnionPIR, HarmonyPIR)
     and in the native Rust `DpfClient` (see item 8).
   - Logs show: query parameters, padding reminders, per-query FOUND/NOT FOUND
     status, bin indices, chunk IDs, Merkle verification details.
   - Enables humans to verify PIR operations are correct.

8. **Native Rust per-bucket Merkle verification (DPF + Harmony)**:
   - Module [`pir-sdk-client/src/merkle_verify.rs`](pir-sdk-client/src/merkle_verify.rs)
     implements the shared verifier: bin-leaf hash, K-padded sibling batches,
     tree-top parsing, full walk-to-root. 12 unit tests cover good proofs,
     tampered content, wrong bin index, encoding/decoding round-trips, and
     partial-cache walks against `pir-core::merkle`.
   - Backend-agnostic driver: a `BucketMerkleSiblingQuerier` trait abstracts
     one K-padded sibling-query round, with `DpfSiblingQuerier`
     (two-server DPF, `REQ_BUCKET_MERKLE_SIB_BATCH = 0x33`) and
     `HarmonySiblingQuerier` (single-server Harmony query,
     `REQ_HARMONY_BATCH_QUERY = 0x43` with `level = 10+L` INDEX or `20+L`
     CHUNK) both implementing it. `verify_bucket_merkle_batch_generic`
     drives the shared walk.
   - [`DpfClient`](pir-sdk-client/src/dpf.rs) and
     [`HarmonyClient`](pir-sdk-client/src/harmony.rs) now track every INDEX
     cuckoo bin they inspect (both `INDEX_CUCKOO_NUM_HASHES=2` positions for
     not-found, the matching position for found) and every CHUNK bin that
     returned a UTXO, then batch-verify them against the per-group root
     from the tree-top blob. Queries whose Merkle proof fails are coerced
     to `None`.
   - HarmonyPIR sibling groups and hints are lazily initialised per
     `(db_id, merkle_level)` — sibling-group count is derived from the
     server-supplied tree-tops (`cache_from_level`), and the sibling
     group's `derived_key` offset matches the server's
     `compute_hints_for_group` layout:
     * INDEX sib L, group g → `(k_index + k_chunk) + L*k_index + g`
     * CHUNK sib L, group g →
       `(k_index + k_chunk) + index_sib_levels*k_index + L*k_chunk + g`
   - Gated on `DatabaseInfo::has_bucket_merkle`. Padding (K=75 INDEX,
     K_CHUNK=80 CHUNK, 25 MERKLE) is preserved — see CLAUDE.md "Query Padding"
     section above.
   - Whales **are** Merkle-verified on their INDEX bin (so the client can
     prove the address really is whale-excluded). Whales have no chunk
     chain, so chunk-level Merkle info is empty by construction.
   - `OnionClient` Merkle verification is wired via a **separate**
     module [`pir-sdk-client/src/onion_merkle.rs`](pir-sdk-client/src/onion_merkle.rs)
     — see item 10 below. (OnionPIR uses its own two flat trees +
     FHE sibling queries, so the per-bucket `merkle_verify.rs` machinery
     doesn't apply.)

10. **Native Rust OnionPIR per-bin Merkle verification**:
    - Module [`pir-sdk-client/src/onion_merkle.rs`](pir-sdk-client/src/onion_merkle.rs)
      implements the OnionPIR Merkle subsystem, which is **distinct**
      from per-bucket Merkle:
      * Two flat trees (INDEX + DATA), not per-PBC-bucket trees.
      * Leaf hash: `SHA256(decrypted_bin_bytes)` (no bin-index prefix).
      * Sibling cuckoo: 6 hash functions, 1 slot per bin, per-level
        master seed `SEED_BASE + level`
        (`INDEX_SIBLING_SEED_BASE = 0xBA7C_51B1_FEED_0100`,
         `DATA_SIBLING_SEED_BASE  = 0xBA7C_51B1_FEED_0200`).
      * Sibling queries are FHE-encrypted: `0x53` INDEX, `0x55` DATA.
        Tree-top fetches: `0x54` INDEX, `0x56` DATA.
    - `OnionClient::query_index_level` now tracks every probed INDEX
      cuckoo bin (both `INDEX_CUCKOO_NUM_HASHES = 2` positions, matched
      or not, whale or found, see invariant #9) and emits a
      `(pbc_group * index_bins + bin, SHA256(bin))` trace per bin.
    - `OnionClient::query_chunk_level` emits a DATA trace per decrypted
      entry_id: `(pbc_group * chunk_bins + bin, SHA256(packed))`.
    - `run_merkle_verification` aggregates traces into
      `Vec<OnionMerkleLeaf>`, calls `verify_onion_merkle_batch`, and
      coerces failed queries to `None` (same "untrusted ⇒ absent"
      pattern as DpfClient/HarmonyClient). A local `SibSendClient`
      newtype makes `onionpir::Client` `Send` across `.await` for the
      sibling roundtrips.
    - Gated behind the `onion` cargo feature (same as `OnionClient`'s
      query path). Padding is preserved (K per sibling round, dummy
      FHE queries fill empty groups).
    - JSON parsing: `parse_onion_merkle_per_db` handles top-level
      `onionpir_merkle` (db_id=0) and per-entry `onionpir_merkle` inside
      `databases[]` — symmetric with `parse_onion_params_per_db`. The
      subtree parser tolerates whitespace after `"root":` and
      `"levels":` so pretty-printed JSON works.
    - 46 unit tests cover tree-top parsing, sibling cuckoo
      (INDEX + DATA, 6-hash roundtrip), seed-base invariants, wire
      encoder/decoder, and JSON parse shapes.

9. **Merkle INDEX item-count symmetry (all five clients)**:
   - All five clients — TS DPF (`web/src/client.ts`), TS OnionPIR
     (`web/src/onionpir_client.ts`), TS HarmonyPIR
     (`web/src/harmonypir_client.ts`), Rust DPF
     (`pir-sdk-client/src/dpf.rs`), Rust Harmony
     (`pir-sdk-client/src/harmony.rs`) — now probe BOTH cuckoo positions
     unconditionally and emit `INDEX_CUCKOO_NUM_HASHES = 2` Merkle items
     per INDEX query regardless of outcome.
   - Closes the side channel where `max_items_per_group` (per-level
     sibling pass count) leaked found-vs-not-found and cuckoo h-position.
   - Costs: DPF and Onion free (both bins already XOR'd from the same
     batch response). Rust Harmony adds one wire round per found@h=0
     query. TS Onion adds one FHE decrypt (~100ms) per found@h=0 query.
   - Whales participate in INDEX Merkle verification via a new
     `whaleIndexInfo`/trace bin-info path in each client.
   - CHUNK Merkle item count still varies with UTXO count — documented
     trade-off, separate from INDEX symmetry. See "Merkle INDEX
     Item-Count Symmetry" under CRITICAL SECURITY REQUIREMENTS.

---

## SDK Roadmap

The full SDK work plan lives in [SDK_ROADMAP.md](SDK_ROADMAP.md) — P0
through P4 priorities, with in-progress items tracked at the bottom.
Consult it before starting new SDK work so nothing gets duplicated or
forgotten. Padding/privacy invariants (🔒 items in the roadmap) must
not be optimized away — see "Query Padding" above.

Short-term active work:
- _(none — all P0 and P1 items closed. Four P1 items completed in
  one batch: **HarmonyClient REQ_GET_DB_CATALOG**, **Connection
  resilience**, **OnionPIR LRU-eviction retry**, and **Thread-safety
  audit for `unsafe impl Sync for SendClient`**.)_ Next work should
  pick from the P2 list in [SDK_ROADMAP.md](SDK_ROADMAP.md) —
  `pir-sdk-wasm` full client wrappers is the highest-leverage item
  since it would unify Rust + TS query paths and drop the web
  client's duplicate Merkle-verification implementations.

### Completed milestones
- PIR SDK + WASM bindings + web integration (commit `19cbf5f`).
- Merkle verification for "not found" results in the web clients
  (commit `60fe19c`).
- `[PIR-AUDIT]` logging in web clients (commit `9a693c5`).
- Native Rust `HarmonyClient` + `OnionClient` un-stub (commit `f37db8f`).
- Native Rust `DpfClient` per-bucket Merkle verification (commit `8bd4b7b`).
- Native Rust `HarmonyClient` per-bucket Merkle verification via
  shared `BucketMerkleSiblingQuerier` trait (commit `6aee562`).
- Merkle INDEX item-count symmetry across all five clients + whale
  INDEX Merkle verification (closes found-vs-not-found / h-position
  side channel at the INDEX Merkle level).
- Native Rust `OnionClient` per-bin Merkle verification via
  feature-gated `onion_merkle.rs` module (P0 #1 — see item 10 above).
- INDEX PBC placement verified (P0 #1 closed — not a bug): server
  replicates each scripthash into all 3 candidate groups at build time
  (`build/src/build_cuckoo_generic.rs:87-90`), so `my_groups[0]` in
  single-query paths is correct and matches the reference Rust binary
  (`runtime/src/bin/client.rs:246`) and every web TS / Python client.
  Explanatory comments added at `DpfClient::query_index_level` and
  `HarmonyClient::query_single` to prevent future re-flagging.
- **`merkle_verified: bool` on `QueryResult`** (last P0): a failed
  per-bucket Merkle proof is now surfaced as
  `Some(QueryResult::merkle_failed())` — `merkle_verified = false`,
  empty entries, `is_whale = false` — instead of being coerced to
  `None`. `None` in `SyncResult::results` is now purely "not found"
  (verified absent when the DB publishes Merkle, via the symmetric
  INDEX bin probes). All three native Rust clients (`DpfClient`,
  `HarmonyClient`, `OnionClient`) and the WASM bindings propagate the
  flag. `merge_delta_batch` ANDs snapshot × delta so a single untrusted
  input taints the merge. New unit tests in `pir-sdk/src/sync.rs`
  cover AND semantics, `(None, Some(del))` propagation, and the
  `merkle_failed()` / default-verified state.
- **CI integration tests against live public PIR servers** (first P1):
  `pir-sdk-client/tests/integration_test.rs` now defaults to the
  public deployment (`wss://pir1.chenweikeng.com` /
  `wss://pir2.chenweikeng.com`) with per-URL env var overrides, and
  `.github/workflows/pir-sdk-integration.yml` runs all 12 ignored tests
  on every push/PR plus a daily canary. Surfaced and fixed three
  protocol mismatches that were blocking live-server runs: (1) the
  DPF batch wire format (`encode_batch_query` had a spurious leading
  `level` byte, wrongly-positioned `db_id`, and per-group `num_keys`
  counts instead of a single top-level `keys_per_group`), (2) catalog
  `num_dbs` was decoded as u16 instead of u8 — single-entry catalogs
  looked corrupted because the `db_id` byte was being read as the
  high byte of the count, (3) `wss://` support needed `rustls` with
  an explicit `ring` crypto provider (lazy-installed via `OnceLock`)
  plus bumping the WebSocket max-frame-size to 256 MiB so fresh-sync
  chunk batches (~32 MiB) fit in a single frame. OnionPIR integration
  tests now exist too, gated behind `--features onion`. See
  [SDK_ROADMAP.md](SDK_ROADMAP.md) Completed section for details.
- **OnionPIR CI job** (follow-up to the CI milestone): the
  `integration-onion` job in
  `.github/workflows/pir-sdk-integration.yml` builds `pir-sdk-client`
  with `--features onion` (which compiles SEAL + libonionpir from
  source via CMake + GCC) and runs the new `onion_tests::` module
  against `wss://pir1.chenweikeng.com`. It's a separate job from the
  DPF/Harmony integration job because the C++ build is slow
  (~5–10 min cold); PRs that only touch DPF/Harmony code still get
  fast feedback. Two things the runner needs that plain
  ubuntu-latest doesn't give for free: `CARGO_NET_GIT_FETCH_WITH_CLI=true`
  + a `url.https://github.com/.insteadOf git@github.com:` git config
  rewrite so Cargo can fetch the SEAL submodule (its `.gitmodules`
  uses an SSH URL which the runner has no credentials for).
- **HarmonyClient `REQ_GET_DB_CATALOG` with legacy fallback** (P1):
  Previously `HarmonyClient::fetch_catalog` always called the legacy
  `REQ_HARMONY_GET_INFO = 0x40`, whose `ServerInfo` wire shape predates
  `DatabaseCatalog` and carries no `height` / `has_bucket_merkle`
  fields. As a result `SyncResult::synced_height` was pinned to `0`
  for every Harmony deployment and cache-by-height was broken.
  `fetch_catalog` now tries `REQ_GET_DB_CATALOG = 0x02` first via a
  new `try_fetch_db_catalog`, returning `Ok(None)` on empty reply /
  `RESP_ERROR` / unknown-variant so `fetch_legacy_info` can still
  serve older servers. Both Harmony unified_server roles (hint pir2,
  query pir1) already answer `REQ_GET_DB_CATALOG` — the match arm in
  `unified_server.rs::REQ_GET_DB_CATALOG` runs before any role check —
  so sending it over `hint_conn` works for both. Integration test
  `test_harmony_client_sync_single` now asserts `synced_height > 0`
  end-to-end against the public servers (was previously relaxed with
  a NOTE comment). Also deduplicated the three copies of
  `encode_request` / `decode_catalog` that the DPF, Harmony, and
  OnionPIR clients each maintained into a single shared
  [`pir-sdk-client/src/protocol.rs`](pir-sdk-client/src/protocol.rs)
  module (4 new unit tests for wire-format and catalog decoding) —
  future catalog-format changes now live in one place instead of
  three.
- **Connection resilience: per-request deadlines + reconnect with
  exponential backoff** (P1):
  [`pir-sdk-client/src/connection.rs`](pir-sdk-client/src/connection.rs)
  now wraps every `send` / `recv` / `roundtrip` on `WsConnection` in
  `tokio::time::timeout` (default `DEFAULT_REQUEST_TIMEOUT = 90s`,
  overridable via `with_request_timeout`), and wraps the initial
  TLS/WebSocket handshake in a separate `connect_timeout` (default
  `DEFAULT_CONNECT_TIMEOUT = 30s`). A wedged server no longer hangs a
  query indefinitely — the caller gets `PirError::Timeout` in bounded
  time and can decide what to do next. `WsConnection::connect` now
  internally calls `connect_with_backoff(url, RetryPolicy::default())`;
  the default policy retries up to
  `DEFAULT_MAX_CONNECT_ATTEMPTS = 5` times with
  `DEFAULT_INITIAL_BACKOFF_DELAY = 250ms`→`DEFAULT_MAX_BACKOFF_DELAY
  = 5s` exponential backoff. `reconnect(&mut self)` re-handshakes to
  the same URL using the stored retry policy and replaces the
  sink/stream in place — higher-level clients can use it as an escape
  hatch, but must remember that server-side session state (Harmony
  hints, Onion FHE keys, in-flight round IDs) is gone after a
  reconnect and needs to be re-negotiated. Seven new unit tests cover
  retry-policy shape, backoff doubling + clamping, u32-overflow
  safety, and DNS-fail / route-unreachable timeout paths; a new
  live-server integration test `test_wsconnection_reconnect_roundtrip`
  proves the transport works post-reconnect. `RetryPolicy` and the
  `DEFAULT_*` constants are re-exported from the crate root so
  downstream callers can dial custom policies.
- **OnionPIR LRU-eviction retry in INDEX/CHUNK query rounds** (P1):
  The OnionPIR server's SEAL `KeyStore` evicts registered clients FIFO
  at a 100-client cap; any `answer_query` for an evicted client panics
  inside SEAL and the server's `catch_unwind` surfaces the failure as
  an all-empty batch response (every slot `Vec::new()`). Both query
  rounds in [`pir-sdk-client/src/onion.rs`](pir-sdk-client/src/onion.rs)
  now send through a single chokepoint `onionpir_batch_rpc` that
  (a) detects the eviction signal via a free-standing `batch_looks_evicted`
  helper (≥1-slot batch where every slot is empty — legit FHE responses
  can never match because all slots share one `client_id`), (b) drops
  the `registered[db_id]` flag so `register_keys` actually re-registers,
  (c) replays Galois + GSW keys via `register_keys(db_id)`, and
  (d) retries the exact same encoded query once. A second all-empty
  response surfaces as `PirError::ServerError` instead of looping —
  that case indicates FHE param drift, unreachable DB, or similar. The
  Merkle sibling path in `onion_merkle.rs` is intentionally left
  uncovered; its failure mode ("Merkle proof fails ⇒ result coerced to
  `merkle_failed()`") is already conservative, so post-eviction Merkle
  failures surface as untrusted-⇒-absent rather than stale cache.
  Three new unit tests lock the `batch_looks_evicted` contract
  (all-empty triggers, mixed/full don't, zero-length doesn't either so
  decode bugs can't masquerade as eviction); the helper is `pub(crate)`
  free-standing so it's testable on non-`onion` builds.
- **Thread-safety audit for `unsafe impl Sync for SendClient`** (P1,
  final P1 item): Walked the full public API of `onionpir::Client`
  @ rev `946550a` and confirmed only `id(&self) -> u64` and
  `export_secret_key(&self) -> Vec<u8>` take `&self`; everything else
  is `&mut self`. Cross-checked the C++ side
  (`rust/onionpir-fork/src/ffi.cpp` + `ffi_c.cpp`): both read-only
  entry points accept `const OnionPirClient&` and delegate to
  `client.inner.get_client_id()` (pure integer read) and
  `SecretKey::save(stringstream)` (SEAL const member; uses the default
  thread-safe `MemoryPool`). No `mutable` fields, no globals, no
  thread-locals, no OpenMP parallel regions in those paths. The Sync
  impl is sound, and in practice the SDK never actually shares
  `&SendClient` across threads — `FheState.level_clients` is reached
  only via `&mut OnionClient`, so the Sync impl exists purely to
  satisfy the `PirClient: Send + Sync` trait bound. Recorded the
  audit in a long-form safety comment in
  [`pir-sdk-client/src/onion.rs`](pir-sdk-client/src/onion.rs) and
  locked in compile-time assertions via `const _: fn() = || {
  assert_send_sync::<OnionClient>(); ... }` probes that fail at the
  declaration site if someone adds an `Rc<>` / `RefCell<>` / raw
  pointer to `FheState` or `SendClient`. Added a feature-gated
  concurrency smoke test `test_send_client_sync_smoke` that spawns 8
  threads sharing `Arc<SendClient>` and hammers `id` +
  `export_secret_key` from each (runs in the `integration-onion` CI
  job; plain `cargo test -p pir-sdk-client` doesn't need the C++
  toolchain). `onion_merkle.rs::SibSendClient` picked up a matching
  `assert_send` probe and a cross-reference to the audit.

---

## Key Files
- `pir-sdk/src/lib.rs` - SDK entry point
- `pir-sdk-wasm/src/lib.rs` - WASM bindings
- `web/src/sdk-bridge.ts` - JS/TS bridge to WASM
- `web/src/sync-controller.ts` - Uses SDK for sync planning

## Build Commands
```bash
# Build SDK WASM
cd pir-sdk-wasm && wasm-pack build --target web --out-dir pkg

# Run web dev server
cd web && npm run dev

# Test SDK
cd pir-sdk && cargo test
```
