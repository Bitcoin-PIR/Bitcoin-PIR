# pir-core

[![Crates.io](https://img.shields.io/crates/v/pir-core.svg)](https://crates.io/crates/pir-core)
[![Docs.rs](https://docs.rs/pir-core/badge.svg)](https://docs.rs/pir-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Core primitives shared by the [Bitcoin PIR](https://github.com/Bitcoin-PIR/Bitcoin-PIR)
stack — hash functions, Probabilistic Batch Code (PBC) placement, cuckoo
hashing, Merkle tree math, and the binary codec used by the delta /
snapshot file formats.

This crate is a low-level foundation. Most users want one of the higher-level
crates instead:

- [`pir-sdk`](https://crates.io/crates/pir-sdk) — client / backend trait,
  sync planning, delta merging, error taxonomy, metrics observer.
- [`pir-sdk-client`](https://crates.io/crates/pir-sdk-client) — native
  async Rust client for DPF / HarmonyPIR / OnionPIR backends.
- [`pir-sdk-wasm`](https://crates.io/crates/pir-sdk-wasm) — WASM bindings
  for the browser (async clients, Merkle verifier, sync planner).

## What lives in this crate

| Module    | Summary                                                          |
|-----------|------------------------------------------------------------------|
| `hash`    | `splitmix64`, `compute_tag`, `derive_groups_{2,3}`, `derive_int_groups_{2,3}`, `derive_cuckoo_key`. |
| `cuckoo`  | `cuckoo_hash`, `cuckoo_hash_int`, `cuckoo_place`, `build_int_keyed_table`. |
| `pbc`     | `pbc_plan_rounds` — plans PIR query rounds covering a group set. |
| `merkle`  | SHA-256 wrapper, N-ary parent hash, leaf hash, walk helpers, `compute_tree_top_cache`. |
| `codec`   | Varint reader, UTXO data decoder.                                |
| `params`  | Compile-time constants (K=75 INDEX, K_CHUNK=80 CHUNK, etc.).     |

All functions are pure — no I/O, no async, no global state.

## Quick start

```toml
[dependencies]
pir-core = "0.1"
```

```rust
use pir_core::hash::{splitmix64, compute_tag};

let tag = compute_tag(splitmix64(0x1234_5678), &[0u8; 20]);
```

## Versioning

Follows [Semantic Versioning](https://semver.org). Pre-1.0, minor bumps
may contain breaking changes — expect `0.2.x → 0.3.x` to require call-site
updates. Patch bumps (`0.x.y → 0.x.(y+1)`) are non-breaking.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
