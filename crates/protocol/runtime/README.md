# pir-runtime-core

Server-side runtime primitives for Bitcoin PIR. This crate contains the
parts of the server that are protocol-version- and data-format-specific,
but transport-agnostic: the wire protocol, the memory-mapped database
table layout, the DPF evaluation engine, and the request handler that
dispatches PIR queries against loaded databases.

It is consumed by `apps/server/`, the workspace-internal binary crate that
owns the production `unified_server` binary and the CLI clients.

Modules:

- [`protocol`] — wire format for `Request` / `Response` variants.
- [`table`] — `MappedDatabase` / `DatabaseDescriptor` for mmap'd
  on-disk database layout.
- [`eval`] — DPF evaluation helpers and timing instrumentation.
- [`handler`] — `RequestHandler` that dispatches `Request` to the
  matching backend over a set of loaded databases.

This crate does not own a transport, a listener, or a config loader.
Those live in `apps/server/`.

## Licence

Dual-licensed under MIT OR Apache-2.0.
