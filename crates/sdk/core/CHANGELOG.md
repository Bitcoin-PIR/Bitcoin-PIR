# Changelog

All notable changes to `pir-sdk` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — initial release

### Added

- **Core types**: `ScriptHash`, `UtxoEntry`, `QueryResult`, `SyncResult`,
  `DatabaseCatalog`, `DatabaseInfo`, `SyncPlan`, `BucketRef`.
- **Error taxonomy** (`PirError` + `ErrorKind`):
  - Eight-variant categorical classifier — `TransientNetwork`,
    `SessionEvicted`, `ProtocolSkew`, `MerkleVerificationFailed`,
    `ServerError`, `ClientError`, `DataError`, `Other`.
  - Four new variants: `Transient { origin, context }`,
    `ProtocolSkew { expected, actual }`, `SessionEvicted(String)`,
    `MerkleVerificationFailed(String)`.
  - Four retry / inspection helpers: `is_transient_network`,
    `is_session_lost`, `is_verification_failure`, `is_protocol_skew`.
  - `is_retryable` broadened to cover `TransientNetwork | SessionEvicted`.
- **Client / backend traits**: `PirClient` (common async client surface —
  `connect`, `sync`, `query_batch`, `fetch_catalog`,
  `compute_sync_plan`), `PirBackend` (server-side hook).
- **Sync planning**: `compute_sync_plan` — BFS delta-chain discovery
  (max 5 steps) + optimal-path selection. `SyncPlan` records step
  metadata (`db_id`, `tip_height`, `name`).
- **Delta merging**: `merge_delta`, `merge_delta_batch` — applies delta
  updates to snapshot query results; ANDs `merkle_verified` across
  snapshot × delta so a single untrusted input taints the merge.
- **`merkle_verified: bool` on `QueryResult`**: a failed per-bucket
  Merkle proof surfaces as `Some(QueryResult::merkle_failed())`
  instead of being coerced to `None`. `None` is now purely
  "not found" (verified absent when the DB publishes Merkle).
- **Observability** (`PirMetrics` trait + recorders):
  - Six defaulted callbacks — `on_query_start`, `on_query_end`,
    `on_bytes_sent`, `on_bytes_received`, `on_connect`,
    `on_disconnect`.
  - `NoopMetrics` (ZST placeholder) and `AtomicMetrics`
    (lock-free, 12 `AtomicU64` counters including three latency
    fields: total / min / max query latency in micros).
  - `on_query_end` carries a `Duration` parameter; `min` counter
    initialised to `u64::MAX` sentinel so the first observation
    always wins without a CAS loop.
  - `AtomicMetrics::snapshot()` returns a `Copy`
    `AtomicMetricsSnapshot` with `Ordering::Relaxed` loads.
- **`web-time` dep + `Instant` / `Duration` re-exports**: drop-in
  `std::time` replacements that delegate to `performance.now()` on
  `wasm32-unknown-unknown`, so the same metrics code works across
  native and browser targets.
- **`serde` feature** (off by default): derives `Serialize` /
  `Deserialize` on the public types.

### Security

- Documents the **Merkle INDEX item-count symmetry** invariant: all
  PIR clients must emit exactly `INDEX_CUCKOO_NUM_HASHES = 2` Merkle
  items per INDEX query regardless of outcome, closing a side channel
  where `max_items_per_group` would leak found-vs-not-found and
  cuckoo h-position.

[Unreleased]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/releases/tag/v0.1.0
