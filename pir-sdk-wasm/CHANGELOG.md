# Changelog

All notable changes to `pir-sdk-wasm` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — initial release

### Added

- **Async client wrappers** over the native `pir-sdk-client`:
  - `WasmDpfClient` — two-server DPF (recommended default).
  - `WasmHarmonyClient` — two-server HarmonyPIR (hint + query).
  - No `WasmOnionClient`: the upstream `onionpir` crate depends
    on a C++ SEAL build that does not compile to
    `wasm32-unknown-unknown`. Browsers that need the
    single-server FHE backend continue to use the hand-written
    `onionpir_client.ts` in the reference web app.
- **Full PIR flow behind a `Promise`-returning API**:
  - `connect()` / `disconnect()` / `isConnected`.
  - `fetchCatalog()` → `WasmDatabaseCatalog`.
  - `sync(scriptHashes, lastHeight?)` → `WasmSyncResult`.
  - `queryBatch(scriptHashes, dbId)` → `WasmQueryResult[]`.
  - `queryBatchRaw(scriptHashes, dbId)` (skip inline Merkle
    verify) and `verifyMerkleBatch(results, dbId)` (standalone
    run) — split-verify workflow.
  - `serverUrls()`, `onStateChange(cb)` — connection lifecycle.
  - `syncWithProgress(scriptHashes, lastHeight?, onEvent)` —
    progress events.
  - `setMetricsRecorder(metrics)` / `clearMetricsRecorder()` —
    per-client observability toggle.
  - `WasmHarmonyClient` adds `setMasterKey(Uint8Array[16])`,
    `setPrpBackend(u8)` (with `PRP_HMR12` / `PRP_FASTPRP` /
    `PRP_ALF` free-function constants), `dbId()` / `setDbId(u8)`
    for catalog switching (invalidates hints),
    `minQueriesRemaining()`, `estimateHintSizeBytes()`,
    `fingerprint(catalog, dbId)` (16-byte cache key),
    `saveHints() → Uint8Array | null` / `loadHints(bytes, catalog,
    dbId)` for IndexedDB-backed hint persistence.
- **Per-bucket Merkle verifier (pure crypto half)**:
  - `WasmBucketMerkleTreeTops.fromBytes(bytes)` — parses the
    `REQ_BUCKET_MERKLE_TREE_TOPS` (0x34) blob; wire-compatible
    with `pir-sdk-client::merkle_verify::parse_tree_tops`.
  - `verifyBucketMerkleItem(binIndex, content, pbcGroup,
    siblingRowsFlat, treeTops)` — walks one proof from leaf to
    cached root given pre-fetched XOR'd sibling rows.
  - Supporting primitives: `bucketMerkleLeafHash`,
    `bucketMerkleParentN`, `bucketMerkleSha256`, `xorBuffers`.
  - The *network* half (K-padded sibling batches over DPF) is
    owned by `WasmDpfClient` / `WasmHarmonyClient` — these
    primitives expose the leaf/parent/walk math for callers that
    manage the wire loop themselves.
- **Sync planning, delta merging, hash primitives**:
  - `computeSyncPlan(catalog, lastHeight?)` → `WasmSyncPlan`.
  - `decodeDeltaData(raw)` → `{ spent, newUtxos, entriesIter }`.
  - `mergeDelta(snapshot, deltaRaw)` → `WasmQueryResult`.
  - `mergeDeltaBatch(snapshots[], deltas[])`.
  - `splitmix64`, `computeTag`, `deriveGroups`,
    `deriveCuckooKey`, `cuckooHash`, `deriveChunkGroups`,
    `cuckooHashInt`, `cuckooPlace`, `planRounds`, `readVarint`,
    `decodeUtxoData`.
- **`WasmAtomicMetrics`** — `#[wasm_bindgen]` wrapper over
  `Arc<pir_sdk::AtomicMetrics>`; `new()` + `snapshot()` returning
  a plain JS object with twelve `bigint` fields
  (`queriesStarted` / `queriesCompleted` / `queryErrors` /
  `bytesSent` / `bytesReceived` / `framesSent` / `framesReceived`
  / `connects` / `disconnects` / `totalQueryLatencyMicros` /
  `minQueryLatencyMicros` / `maxQueryLatencyMicros`).
  - `min` field initialised to `0xFFFF_FFFF_FFFF_FFFFn` sentinel
    meaning "no measurements yet"; JS consumers should render
    "—" rather than the raw sentinel.
  - `bigint` rather than `Number` because byte counters in a
    long-running session could exceed 2^53 (≈9 PB ceiling).
- **`initTracingSubscriber()`** — installs `tracing-wasm` as the
  browser's global `tracing` subscriber; routes every Phase 1
  span on `DpfClient` / `HarmonyClient` / `OnionClient` /
  `WsConnection` / `WasmWebSocketTransport` to the DevTools
  console with the consistent `backend="dpf"/"harmony"/"onion"`
  field. Guarded by `std::sync::Once` so repeat calls are no-ops
  (`tracing-wasm`'s `set_as_global_default` panics on the second
  call otherwise).
- **`WasmQueryResult.toJson()` / `fromJson()`** — round-trip
  shape with hex-encoded `txid` / `binContent` / `rawChunkData`.
  `rawChunkData` hex-decodes symmetrically so persisted results
  survive `fromJson` → `verifyMerkleBatch` byte-exact.
- **`WasmDatabaseCatalog.getEntry(dbId)` / `hasBucketMerkle(dbId)`**
  accessors for the browser adapter layer.

### Documentation

- Module-level docs cover the wire-format boundary contract (packed
  `Uint8Array` of 20*N bytes for `N` HASH160 script hashes; length
  not a multiple of 20 throws `Error`).
- All `bigint` fields documented — JS `Number` can't safely
  represent `u64` byte counters past 2^53.
- Per-class `.free()` reminder: wasm-bindgen classes own
  linear-memory handles; forgetting `.free()` leaks WASM memory.

### Security

- PIR padding invariants (K=75 INDEX, K_CHUNK=80 CHUNK, 25 MERKLE)
  are enforced in the native `pir-sdk-client` query path and are
  not reachable through the wasm-bindgen surface — the wrappers
  are thin translation shims that cannot bypass them.
- INDEX-Merkle item-count symmetry preserved: every INDEX query
  emits exactly 2 Merkle items regardless of outcome.

[Unreleased]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/releases/tag/v0.1.0
