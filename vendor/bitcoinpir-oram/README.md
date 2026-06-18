# BitcoinPIR ORAM

BitcoinPIR-shaped disk-backed ORAM prototype.

This repository is intentionally **not** a generic oblivious map. BitcoinPIR
already owns the public mapping from `scripthash` to PBC/cuckoo positions; this
crate provides an oblivious array layer that hides which logical block a TEE
accesses.

## Current Scope

Implemented:

- Path ORAM controller with in-TEE position map and stash.
- Fixed-capacity stash slots with full-slot scans for path read/write.
- Trusted, non-oblivious bulk initialization for offline image creation.
- `MemPageStore` for tests.
- `FilePageStore` for NVMe/page-file backed storage.
- `AeadPageStore` wrapper using ChaCha20-Poly1305 per page.
- `MerklePageStore` / `TieredMerklePageStore` wrappers that detect runtime
  rollback of disk-backed pages against trusted in-memory roots.
- Trusted controller-state checkpoint/reopen (`OramState`), with optional
  ChaCha20-Poly1305 state-file encryption.
- Fixed-prefix front cache (`FrontCachedPageStore`) for keeping public top ORAM
  tree levels in trusted memory.
- Mask-based CMOV-style helpers for stash lookup, stash insert, and path
  eviction selection.
- `oramctl` CLI for building deterministic test images and running random-read
  benchmarks.
- `oramctl size-cuckoo` for estimating ORAM images over existing DPF/Harmony
  cuckoo tables.
- `oramctl build-circuit` for building split metadata/payload Circuit ORAM
  images from existing DPF/Harmony cuckoo tables.
- `oramctl bench-circuit` for reopening split Circuit ORAM images, running
  random reads, and optionally verifying each read against the original cuckoo
  table payload.
- `oramctl verify-circuit-bins` and `CircuitCuckooBinReader` for validating
  original cuckoo bin reads through packed Circuit ORAM images.
- Fixed trace-shape tests: each logical access reads and rewrites a complete
  root-to-leaf path.
- Circuit ORAM deterministic eviction scheduler and design notes.
- `oramctl stress-circuit` metadata-only stash-pressure simulator for the
  planned Circuit ORAM controller.
- Split metadata/payload `CircuitOram` controller prototype with deterministic
  delayed eviction, metadata-planned eviction placement, and fixed-shape
  page-trace tests.
- Trusted `CircuitOramState` snapshot/reopen, including RNG state and public
  eviction counters, with optional ChaCha20-Poly1305 state-file encryption.
- Circuit ORAM trusted bulk initialization that plans metadata first, writes
  metadata/payload bucket pages sequentially, and uses mmap-backed cuckoo table
  reads for source payloads.

Intentionally not implemented yet:

- The exact optimized Circuit ORAM `deepest`/`target` circuit from the paper.
  The current `CircuitOram` controller uses two fixed metadata scans to plan a
  deepest-first placement, then applies that plan in one fixed payload scan.
- Recursive position map.
- Oblivious bulk initialization.
- Wiring Merkle roots into `CircuitOramState` and the `oramctl` image build /
  reopen path.
- Full production bulk-build pipeline for very large all-level snapshots.
- Crash-safe Circuit ORAM WAL / epoch protocol.
- Release assembly / SEV-SNP ciphertext-channel audit of the constant-shape hot
  loops.
- Multi-client sharding.

## Design

The runtime shape is:

```text
trusted memory:
  position map: logical_id -> current random leaf
  stash
  ORAM controller

disk / untrusted storage:
  encrypted bucket pages
```

Each access:

1. Reads every bucket on the old random root-to-leaf path.
2. Moves real blocks into the stash.
3. Assigns the target logical block a fresh random leaf.
4. Rewrites every bucket on the same path from the stash.

The backing store sees random ORAM paths, not BitcoinPIR logical ids.

The planned production direction is Circuit ORAM with deterministic delayed
eviction, `Z=2`, and packed DPF/Harmony cuckoo bins. See
[`docs/CIRCUIT_ORAM_DESIGN.md`](docs/CIRCUIT_ORAM_DESIGN.md).

## Build

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

## CLI Smoke Test

Build an encrypted test image:

```bash
KEY_HEX=4242424242424242424242424242424242424242424242424242424242424242
STATE_KEY_HEX=7373737373737373737373737373737373737373737373737373737373737373

cargo run --bin oramctl -- build \
  --image /tmp/bpir-oram.pages \
  --state /tmp/bpir-oram.state \
  --state-key-hex "$STATE_KEY_HEX" \
  --blocks 1024 \
  --block-size 64 \
  --encrypted \
  --key-hex "$KEY_HEX" \
  --cache-levels 4
```

Run random reads against it:

```bash
cargo run --bin oramctl -- bench \
  --image /tmp/bpir-oram.pages \
  --state /tmp/bpir-oram.state \
  --state-key-hex "$STATE_KEY_HEX" \
  --ops 1000 \
  --encrypted \
  --key-hex "$KEY_HEX" \
  --cache-levels 4
```

`--cache-levels 4` caches `(1 << 4) - 1 = 15` public top-tree pages in trusted
memory. Use `0` to disable this wrapper.

## Cuckoo Table Sizing

Estimate ORAM images for the DPF/Harmony cuckoo tables in one or more existing
BitcoinPIR DB directories:

```bash
cargo run --bin oramctl -- size-cuckoo \
  --db-dir /Volumes/Bitcoin/data/checkpoints/948454 \
  --db-dir /Volumes/Bitcoin/data/deltas/940611_948454 \
  --packs 4,8,16 \
  --leaf-divisors 1,2,4,8 \
  --cache-levels 5
```

`pack` is the number of consecutive cuckoo bins stored in one logical ORAM
block. INDEX bins are 52 B and CHUNK bins are 132 B, so `pack=8` uses 416 B
INDEX blocks and 1056 B CHUNK blocks. `leaf_divisor` controls tree density:
`leaves = next_power_of_two(ceil(logical_blocks / leaf_divisor))`. Higher values
reduce disk size but increase stash pressure and must be stress-tested before
production use.

## Circuit ORAM Stress Simulation

Run a metadata-only Circuit ORAM stash-pressure simulation over DPF/Harmony
cuckoo table sizes:

```bash
cargo run --bin oramctl -- stress-circuit \
  --db-dir /Volumes/Bitcoin/data/checkpoints/940611 \
  --packs 16 \
  --leaf-divisors 4 \
  --bucket-size 2 \
  --stash-capacity 4096 \
  --ops 100000 \
  --warmup-ops 10000 \
  --pattern random \
  --drain-per-access 2
```

To model public delayed eviction, reduce `--drain-per-access` and set a public
debt cap:

```bash
cargo run --bin oramctl -- stress-circuit \
  --db-dir /Volumes/Bitcoin/data/checkpoints/940611 \
  --drain-per-access 0 \
  --max-debt 128 \
  --ops 100000
```

The simulator stores only logical block ids, leaf labels, tree slots, and stash
entries. It uses greedy path eviction as a stress model for Circuit ORAM's
deterministic eviction schedule. It is useful for choosing `Z`, stash capacity,
tree density, and public eviction-debt bounds; it is not a proof and it does
not replace the controller trace audit. The controller now uses a split-store
metadata-planned eviction path; the simulator remains an intentionally cheap
approximation for parameter sweeps.

## Circuit ORAM Build

Build split metadata/payload ORAM images from an existing DPF/Harmony DB
directory:

```bash
KEY_HEX=4242424242424242424242424242424242424242424242424242424242424242
STATE_KEY_HEX=7373737373737373737373737373737373737373737373737373737373737373

cargo run --bin oramctl -- build-circuit \
  --db-dir /Volumes/Bitcoin/data/checkpoints/940611 \
  --out-dir /tmp/bpir-circuit-oram \
  --level all \
  --pack 16 \
  --leaf-divisor 4 \
  --bucket-size 2 \
  --stash-capacity 4096 \
  --encrypted \
  --key-hex "$KEY_HEX" \
  --state-key-hex "$STATE_KEY_HEX"
```

The command writes:

```text
index.meta.oram
index.payload.oram
index.state
chunk.meta.oram
chunk.payload.oram
chunk.state
```

Use `--level index` or `--level chunk` for a one-level trial before building
both images.

The builder keeps bucket metadata and trusted controller state in memory. It
uses trusted, non-oblivious initialization because BitcoinPIR snapshots are
public and the ORAM image is generated before serving: first assign random
leaves, place metadata as close to leaves as possible, then write every metadata
page and every payload page exactly once in page order. This follows the same
bulk-build principle as the Oblix/EnigMap initialization line of work, but
without their oblivious sorting requirement because the input cuckoo table is
not a private map. Cuckoo payload source reads are mmap-backed, so bucket-order
payload assembly does not issue one `seek`/`read` syscall pair per logical
block.

For runtime rollback safety, the page-store layer now has two authentication
wrappers. `MerklePageStore` keeps the whole hash tree in trusted memory and is
useful for small tests. `TieredMerklePageStore` keeps only a public number of
top tree levels in trusted memory and spills lower hash nodes into a second
`PageStore`; reads recompute the page's authentication path to the trusted
frontier, and writes update the leaf-to-root path.

`oramctl build-circuit --auth-store` writes authenticated sidecars:

```text
index.meta.hash.oram
index.payload.hash.oram
index.auth.state
chunk.meta.hash.oram
chunk.payload.hash.oram
chunk.auth.state
```

Use the same `--auth-store` flag when reopening with `bench-circuit` or
`verify-circuit-bins`; the CLI then loads the trusted top-tree hashes from
`*.auth.state`, verifies data pages against them, and writes updated roots back
unless `--no-save` is set.

Current real `940611` snapshot baseline with `pack=16`, `leaf_divisor=4`,
`Z=2`, encrypted pages, and `cache_levels=0`:

```text
INDEX-only build:
  image/state: 108 MiB metadata + 3.3 GiB payload + 13 MiB state
  build time: 33645 ms (34.054s shell wall)
  verify bench: 100/100 reads, avg_us=6333.697

CHUNK-only build:
  image/state: 216 MiB metadata + 17 GiB payload + 29 MiB state
  build time: 168803 ms (2:48.99 shell wall)
  verify bench: 100/100 reads, avg_us=10520.597

Full all-level build:
  image/state: 20 GiB total directory
  build time: 4:13.41 shell wall
  verify bench: INDEX 100/100 avg_us=9692.053,
                CHUNK 100/100 avg_us=15353.855

Long all-level online verification, 10000 reads per level:
  cache_levels=0: INDEX 10000/10000 avg_us=3309.935,
                  CHUNK 10000/10000 avg_us=12285.031
  cache_levels=5: INDEX 10000/10000 avg_us=4173.953,
                  CHUNK 10000/10000 avg_us=8688.095

Bin-level ORAM reader verification, 1000 random original cuckoo bins per level:
  INDEX 1000/1000 avg_us=6635.897
  CHUNK 1000/1000 avg_us=10893.037
```

Verify and benchmark the generated images against the original cuckoo tables:

```bash
cargo run --bin oramctl -- bench-circuit \
  --oram-dir /tmp/bpir-circuit-oram \
  --db-dir /Volumes/Bitcoin/data/checkpoints/940611 \
  --pack 16 \
  --ops 1000 \
  --drain-per-access 2 \
  --encrypted \
  --key-hex "$KEY_HEX" \
  --state-key-hex "$STATE_KEY_HEX"
```

Verify the finer-grained cuckoo-bin reader path (`bin_id -> ORAM block -> bin
slice`) against the original cuckoo files:

```bash
cargo run --bin oramctl -- verify-circuit-bins \
  --oram-dir /tmp/bpir-circuit-oram \
  --db-dir /Volumes/Bitcoin/data/checkpoints/940611 \
  --pack 16 \
  --bins 1000 \
  --drain-per-access 2 \
  --encrypted \
  --key-hex "$KEY_HEX" \
  --state-key-hex "$STATE_KEY_HEX"
```

For `bench-circuit`, omit `--db-dir` for a pure random-read benchmark without
byte-for-byte verification. Because ORAM reads mutate image pages, use
`--no-save` only for disposable images that you will discard or rebuild
afterward.

## Prototype Warning

This is a correctness and storage-shape prototype. Before production use inside
SEV-SNP, the hot loops still need release assembly and trace inspection on the
target build. The stash is fixed-capacity, and online stash lookup, stash insert,
and path eviction selection now use full-slot scans plus mask-based CMOV-style
helpers. That is an implementation hardening step, not a formal constant-time
guarantee from Rust or LLVM.

The `.state` file contains the position map, stash, RNG state, and, for Circuit
ORAM, the public delayed-eviction counters. It is trusted controller state. Do
not write it to untrusted storage in plaintext in a real deployment. Use
`--state-key-hex` for prototype AEAD protection; production should replace that
key path with SEV-sealed storage.
