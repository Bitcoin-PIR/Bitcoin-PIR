# Changelog

All notable changes to `pir-sdk-server` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-publish note.** This crate is not yet on crates.io. It depends on
> two workspace-internal binary crates (`runtime`, `build`) that contain
> the PIR protocol wire implementation. Publishing requires factoring out
> a `pir-runtime-core` library. See [`PUBLISHING.md`](../PUBLISHING.md)
> for the refactoring sketch.

## [Unreleased]

## [0.1.0] — initial release (unpublished)

### Added

- `PirServerBuilder` — fluent builder for a configured PIR server:
  - `port(u16)` — WebSocket listen port.
  - `add_full_db(path, height)` — register a snapshot database.
  - `add_delta_db(path, base_height, tip_height)` — register a
    delta database.
  - `role(ServerRole::Primary | Hint)` — pick Harmony hint-server
    vs. query-server role.
  - `warmup(bool)` — pre-touch mmap'd pages at startup
    (default on).
  - `from_config(path)` — load all of the above from a TOML file.
- `PirServer` — the built, ready-to-run server. `run().await`
  blocks until `ShutdownHandle::shutdown()` is called or a signal
  terminates the process.
- `ServerConfig` — serde-deserializable configuration record,
  usable directly or via the builder.
- `DatabaseLoader` — lower-level helper for callers that want to
  handle the TCP listener themselves.
- `simple_server` example binary — thin CLI wrapper over the
  builder, forwarding `--port` / `--db` / `--config` flags.

[Unreleased]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/releases/tag/v0.1.0
