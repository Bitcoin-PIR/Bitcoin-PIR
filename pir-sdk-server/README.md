# pir-sdk-server

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Server-side SDK for [Bitcoin PIR](https://github.com/Bitcoin-PIR/Bitcoin-PIR) —
load pre-built PIR databases (snapshot + delta files) and serve DPF, HarmonyPIR,
and OnionPIR queries over WebSocket.

> **Pre-publish note.** This crate is not yet on crates.io. It depends on two
> workspace-internal binary crates (`runtime`, `build`) that contain the PIR
> protocol wire implementation. Publishing requires factoring out a
> `pir-runtime-core` library. Until then, use this crate via a path dependency
> from a Git checkout. See [`PUBLISHING.md`](../PUBLISHING.md) for the
> refactoring sketch.

## What this crate provides

- [`PirServerBuilder`] — a fluent builder for a configured PIR server:
  - `port(u16)` — WebSocket listen port.
  - `add_full_db(path, height)` — register a snapshot database.
  - `add_delta_db(path, base_height, tip_height)` — register a delta database.
  - `role(ServerRole::Primary | Hint)` — pick Harmony hint-server vs.
    query-server role.
  - `warmup(bool)` — pre-touch mmap'd pages at startup (default on).
  - `from_config(path)` — load all of the above from a TOML file.
- [`PirServer`] — the built, ready-to-run server. `run().await` blocks until
  `ShutdownHandle::shutdown()` is called or a signal terminates the process.
- [`ServerConfig`] — serde-deserializable configuration record, usable directly
  or via the builder.
- [`DatabaseLoader`] — lower-level helper if you want to handle the TCP
  listener yourself.

## Quick start

```rust,ignore
use pir_sdk_server::PirServerBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = PirServerBuilder::new()
        .port(8091)
        .add_full_db("/data/snapshot_900000.bin", 900_000)
        .add_delta_db("/data/delta_900000_910000.bin", 900_000, 910_000)
        .warmup(true)
        .build()
        .await?;

    println!("Listening on {:?}", server.local_addr());
    server.run().await?;
    Ok(())
}
```

## Configuration via TOML

```toml
# server.toml
port = 8091
role = "Primary"   # or "Hint" for the HarmonyPIR hint server
warmup = true

[[databases]]
path = "/data/snapshot_900000.bin"
height = 900000

[[databases]]
path = "/data/delta_900000_910000.bin"
base_height = 900000
height = 910000
```

```rust,ignore
let server = PirServerBuilder::new()
    .from_config("server.toml")?
    .build()
    .await?;
server.run().await?;
```

## Graceful shutdown

```rust,ignore
let server = /* build as above */;
let shutdown = server.shutdown_handle();

tokio::spawn(async move {
    tokio::signal::ctrl_c().await.unwrap();
    shutdown.shutdown();
});

server.run().await?;
```

## Example binary

The `simple_server` example wraps the builder with a small CLI:

```bash
# Single snapshot
cargo run -p pir-sdk-server --example simple_server -- \
    --port 8091 \
    --db /data/snapshot_900000.bin:900000

# Snapshot + delta
cargo run -p pir-sdk-server --example simple_server -- \
    --port 8091 \
    --db /data/snapshot_900000.bin:900000 \
    --db /data/delta_900000_910000.bin:900000:910000

# Load from a TOML config
cargo run -p pir-sdk-server --example simple_server -- --config server.toml
```

Run `simple_server --help` for the full flag list.

## Building the database files

`pir-sdk-server` does not itself build database files — it consumes files
produced by the workspace-level `build/` pipeline. See
[`doc/DEPLOYMENT.md`](../doc/DEPLOYMENT.md) for the end-to-end pipeline
(Bitcoin Core UTXO snapshot → chunked UTXO data → cuckoo tables →
Merkle trees → PIR-ready database).

## How it relates to the rest of the workspace

| Layer                   | Crate                | Role                                |
|-------------------------|----------------------|-------------------------------------|
| Shared types            | `pir-sdk`            | `DatabaseCatalog`, `PirError`, ...  |
| Server                  | `pir-sdk-server`     | **You are here** — serve requests   |
| Native client           | `pir-sdk-client`     | Query servers from native Rust      |
| Browser bindings        | `pir-sdk-wasm`       | Query servers from JS/TS            |
| Core primitives         | `pir-core`           | Hashes, codec, cuckoo placement     |
| Reference binaries      | `runtime/`           | Stand-alone `server`, `client`      |
| Database pipeline       | `build/`             | `gen_0` ... `gen_4` build stages    |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[`PirServerBuilder`]: https://docs.rs/pir-sdk-server/latest/pir_sdk_server/struct.PirServerBuilder.html
[`PirServer`]: https://docs.rs/pir-sdk-server/latest/pir_sdk_server/struct.PirServer.html
[`ServerConfig`]: https://docs.rs/pir-sdk-server/latest/pir_sdk_server/struct.ServerConfig.html
[`DatabaseLoader`]: https://docs.rs/pir-sdk-server/latest/pir_sdk_server/struct.DatabaseLoader.html
