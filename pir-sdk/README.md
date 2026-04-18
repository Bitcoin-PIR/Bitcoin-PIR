# pir-sdk

[![Crates.io](https://img.shields.io/crates/v/pir-sdk.svg)](https://crates.io/crates/pir-sdk)
[![Docs.rs](https://docs.rs/pir-sdk/badge.svg)](https://docs.rs/pir-sdk)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Core types, traits, and abstractions for **Private Information Retrieval** (PIR)
on Bitcoin UTXO data. This crate is the foundation layer shared by the native
client (`pir-sdk-client`), the browser bindings (`pir-sdk-wasm`), and the
server-side SDK (`pir-sdk-server`).

PIR is a family of cryptographic protocols where a client can look up an entry
in a server-hosted database without revealing which entry was looked up — even
the server cannot tell which address a wallet is querying.

## Crate layout

| Crate             | Role                                                    |
|-------------------|---------------------------------------------------------|
| `pir-sdk`         | **You are here** — shared types, traits, sync planning  |
| `pir-sdk-client`  | Native Rust client for DPF / Harmony / Onion backends   |
| `pir-sdk-server`  | Server-side builder (load databases, serve requests)    |
| `pir-sdk-wasm`    | WASM bindings (sync planning, Merkle verify, client)    |

## What this crate provides

- **Common types**: `UtxoEntry`, `QueryResult`, `DatabaseCatalog`, `DatabaseInfo`,
  `SyncPlan`, `ScriptHash`, `BucketRef`.
- **Error taxonomy**: [`PirError`] and [`ErrorKind`] — a categorical classifier
  (`TransientNetwork` / `SessionEvicted` / `ProtocolSkew` /
  `MerkleVerificationFailed` / `ServerError` / `ClientError` / `DataError` /
  `Other`) plus retry helpers (`is_transient_network`, `is_session_lost`,
  `is_verification_failure`, `is_protocol_skew`, `is_retryable`).
- **Client trait**: [`PirClient`] — common async interface (`connect`, `sync`,
  `query_batch`, `fetch_catalog`, `compute_sync_plan`) implemented by all three
  backend clients.
- **Backend trait**: [`PirBackend`] — server-side hook for handling PIR
  requests.
- **Sync planning**: [`compute_sync_plan`] — BFS delta-chain discovery (max 5
  steps) and optimal path selection between published databases.
- **Delta merging**: [`merge_delta`], [`merge_delta_batch`] — applies delta
  updates to snapshot query results.
- **Observability** ([`PirMetrics`] trait + [`AtomicMetrics`] recorder):
  lock-free atomic counters for queries, bytes, connects, latency. Pluggable
  via `on_query_start` / `on_query_end(duration)` / `on_bytes_sent` /
  `on_bytes_received` / `on_connect` / `on_disconnect` callbacks.

## Quick start

```toml
# Cargo.toml
[dependencies]
pir-sdk = "0.1"
```

```rust,ignore
use pir_sdk::{compute_sync_plan, DatabaseCatalog};

// Given a server-supplied catalog, plan a sync to tip starting from
// a previous sync height (or None for a fresh sync).
let plan = compute_sync_plan(&catalog, Some(last_synced_height))?;

for step in &plan.steps {
    println!("{} (db_id={}, height={})", step.name, step.db_id, step.tip_height);
}
```

For a full working client, see [`pir-sdk-client`](https://crates.io/crates/pir-sdk-client)
which wires this SDK to async WebSocket transports and the DPF / Harmony /
Onion PIR protocols.

## Core types

### `ScriptHash`

A 20-byte HASH160 of a Bitcoin script — the primary identifier when querying
UTXOs.

```rust,ignore
pub type ScriptHash = [u8; 20];
```

### `UtxoEntry`

A single unspent transaction output.

```rust,ignore
pub struct UtxoEntry {
    pub txid: [u8; 32],   // little-endian transaction ID
    pub vout: u32,        // output index
    pub amount_sats: u64, // amount in satoshis
}
```

### `QueryResult`

Per-script-hash result of a PIR query.

```rust,ignore
pub struct QueryResult {
    pub entries: Vec<UtxoEntry>,
    pub is_whale: bool,                    // true if the address is excluded
    pub merkle_verified: bool,             // true if the Merkle proof passed
    pub raw_chunk_data: Option<Vec<u8>>,   // retained for delta merging
    pub index_bins: Vec<BucketRef>,        // optional inspector state
    pub chunk_bins: Vec<BucketRef>,        // optional inspector state
    pub matched_index_idx: Option<u32>,    // which cuckoo slot matched
}
```

`merkle_verified == false` with `entries.is_empty()` means a Merkle proof failed
— treat as "untrusted → absent". `merge_delta_batch` ANDs `merkle_verified`
across snapshot × delta so a single bad input taints the merge.

### `SyncResult`

```rust,ignore
pub struct SyncResult {
    pub results: Vec<Option<QueryResult>>, // one per script hash
    pub synced_height: u32,                // block height after sync
    pub was_fresh_sync: bool,              // true if started from a snapshot
}
```

## Error taxonomy

[`PirError`] exposes a categorical [`ErrorKind`] classifier so callers can
dispatch on cause without matching every variant:

| Kind                         | Examples                                              | Retryable?           |
|------------------------------|-------------------------------------------------------|----------------------|
| `TransientNetwork`           | Timeout, `ConnectionClosed`, `Transient { .. }`       | Yes, with backoff    |
| `SessionEvicted`             | Onion server LRU eviction, stale Harmony hints        | Yes, after re-setup  |
| `ProtocolSkew`               | Catalog vs. server disagree on Merkle / K / version   | No (needs upgrade)   |
| `MerkleVerificationFailed`   | Pipeline-level Merkle proof failed                    | No (abort batch)     |
| `ServerError`                | Server returned `RESP_ERROR`                          | Maybe                |
| `ClientError`                | Misuse (`NotConnected`, `InvalidState`)               | No                   |
| `DataError`                  | `Decode` / `Encode` / `Io`                            | No                   |
| `Other`                      | Untagged / legacy variants                            | No                   |

```rust,ignore
match client.sync(&hashes, Some(h)).await {
    Err(e) if e.is_transient_network() => retry_with_backoff().await,
    Err(e) if e.is_session_lost()      => reconnect_and_retry().await,
    Err(e) if e.is_protocol_skew()     => return Err(e), // upgrade needed
    result => result,
}
```

## Observability

`pir-sdk` ships an observer trait so callers can attach structured metrics
without touching the query code:

```rust,ignore
use std::sync::Arc;
use pir_sdk::{AtomicMetrics, PirMetrics};

let recorder = Arc::new(AtomicMetrics::new());
client.set_metrics_recorder(Some(recorder.clone()));

// ... run queries ...

let snap = recorder.snapshot();
println!(
    "queries: {} done, {} errors, {} µs mean",
    snap.query_successes,
    snap.query_failures,
    snap.mean_query_latency_micros().unwrap_or(0),
);
```

The trait has six callbacks (`on_query_start` / `on_query_end(duration)` /
`on_bytes_sent` / `on_bytes_received` / `on_connect` / `on_disconnect`), all
defaulted to no-ops. `AtomicMetrics` is the built-in lock-free recorder;
`NoopMetrics` is the zero-sized placeholder.

The `Instant` clock source is [`web_time::Instant`] (re-exported as
`pir_sdk::Instant`) — `std::time::Instant` on native and `performance.now()` on
`wasm32-unknown-unknown`, so the same metrics code works across targets.

## Sync planning

```rust,ignore
use pir_sdk::compute_sync_plan;

let catalog = client.fetch_catalog().await?;
let plan    = compute_sync_plan(&catalog, Some(last_height))?;

if plan.is_fresh_sync {
    // Fallback: no usable delta chain, run a full snapshot sync.
}

for step in &plan.steps {
    println!("  {} → height {}", step.name, step.tip_height);
}
```

The planner runs a bounded BFS over the catalog's delta graph (max 5 hops),
preferring fewer / shorter delta chains over fresh re-syncs.

## Features

| Feature | Default | What it enables                                            |
|---------|:-------:|------------------------------------------------------------|
| `serde` | off     | Derives `Serialize`/`Deserialize` on the public types.     |

See [`FEATURES.md`](../FEATURES.md) at the workspace root for a full
feature-flag matrix covering every publishable crate.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[`PirError`]: https://docs.rs/pir-sdk/latest/pir_sdk/enum.PirError.html
[`ErrorKind`]: https://docs.rs/pir-sdk/latest/pir_sdk/enum.ErrorKind.html
[`PirClient`]: https://docs.rs/pir-sdk/latest/pir_sdk/trait.PirClient.html
[`PirBackend`]: https://docs.rs/pir-sdk/latest/pir_sdk/trait.PirBackend.html
[`PirMetrics`]: https://docs.rs/pir-sdk/latest/pir_sdk/trait.PirMetrics.html
[`AtomicMetrics`]: https://docs.rs/pir-sdk/latest/pir_sdk/struct.AtomicMetrics.html
[`compute_sync_plan`]: https://docs.rs/pir-sdk/latest/pir_sdk/fn.compute_sync_plan.html
[`merge_delta`]: https://docs.rs/pir-sdk/latest/pir_sdk/fn.merge_delta.html
[`merge_delta_batch`]: https://docs.rs/pir-sdk/latest/pir_sdk/fn.merge_delta_batch.html
[`web_time::Instant`]: https://docs.rs/web-time/latest/web_time/struct.Instant.html
