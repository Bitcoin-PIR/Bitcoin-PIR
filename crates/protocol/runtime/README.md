# pir-runtime-core

Server-side runtime primitives for Bitcoin PIR. This crate contains the
parts of the server that are protocol-version- and data-format-specific,
but transport-agnostic: the wire protocol, the memory-mapped database
table layout and the DPF evaluation engine.

It is consumed by `apps/server/`, which owns the `unified_server` binary
and its request dispatch.

Modules:

- [`protocol`] — wire format for `Request` / `Response` variants.
- [`table`] — `MappedDatabase` / `DatabaseDescriptor` for mmap'd
  on-disk database layout.
- [`eval`] — DPF evaluation helpers and timing instrumentation.

This crate does not own a transport, a listener, or a config loader.
Those live in `apps/server/`.

## Licence

Dual-licensed under MIT OR Apache-2.0.
