# Changelog

All notable changes to `pir-core` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — initial release

### Added

- **Hash primitives** (`hash.rs`): `splitmix64`, `compute_tag`,
  `derive_groups_2` / `derive_groups_3` (2-way / 3-way group
  derivation for PBC placement), `derive_int_groups_2` /
  `derive_int_groups_3` for int-keyed tables, `derive_cuckoo_key`.
- **Cuckoo hashing** (`cuckoo.rs`): `cuckoo_hash`, `cuckoo_place`,
  `cuckoo_hash_int`, `build_int_keyed_table`.
- **PBC (probabilistic batch codes)** (`pbc.rs`):
  `pbc_plan_rounds` — plan PIR query rounds covering all groups
  with K-padded queries.
- **Merkle primitives** (`merkle.rs`):
  - SHA-256 wrapper (`sha256`), N-ary parent hash
    (`parent_n`), leaf hash, walk helpers.
  - `compute_tree_top_cache` — builds a cached top-N-level blob
    from a full tree for tree-top broadcasts.
- **Codec** (`codec.rs`): varint reader, UTXO data decoder.

### Fixed

- Cleared five pre-existing clippy warnings so the workspace can
  safely adopt `-D warnings` in CI:
  - Three `needless_range_loop` refactors in `hash.rs`, `pbc.rs`,
    `cuckoo.rs`.
  - One `manual_div_ceil` fix in `merkle.rs`
    (`(prev.len() + arity - 1) / arity` →
    `prev.len().div_ceil(arity)`).

[Unreleased]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/releases/tag/v0.1.0
