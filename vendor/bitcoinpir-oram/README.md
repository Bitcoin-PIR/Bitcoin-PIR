# BitcoinPIR ORAM

BitcoinPIR-shaped disk-backed ORAM prototype.

This repository is intentionally **not** a generic oblivious map. BitcoinPIR
already owns the public mapping from `scripthash` to PBC/cuckoo positions; this
crate provides an oblivious array layer that hides which logical block a TEE
accesses.

## Current Conclusion

The current selected path is **direct-entry Circuit ORAM**, not Ring ORAM. The
Ring ORAM experiment remains useful as a sizing/stress model, but for the
BitcoinPIR batch workload its storage and authentication overheads are too high
relative to the benefit. The practical optimization direction is:

- build ORAM images from direct INDEX and CHUNK records;
- batch fixed-shape online reads for the public request width;
- use embedded-tree authentication instead of Merkle sidecar images;
- hide trusted-memory access patterns with branchless full scans and masked
  movement for the position map, stash, direct INDEX slot selection, and greedy
  eviction planner.

See [`DESIGN_README.md`](DESIGN_README.md) for the design conclusion, leakage
boundary, side-channel hardening rules, and current benchmark numbers.

## Current Scope

Implemented:

- Split metadata/payload Circuit ORAM controller with in-TEE position map and
  fixed-capacity stash.
- Fixed-capacity stash slots with full-slot scans for access and eviction.
- Trusted, non-oblivious bulk initialization for offline image creation.
- `MemPageStore` for tests.
- `FilePageStore` for NVMe/page-file backed storage.
- `AeadPageStore` wrapper using ChaCha20-Poly1305 per page.
- `MerklePageStore` / `TieredMerklePageStore` wrappers that detect runtime
  rollback of disk-backed pages against trusted in-memory roots.
- Trusted Circuit controller-state checkpoint/reopen (`CircuitOramState`), with
  optional ChaCha20-Poly1305 state-file encryption.
- Fixed-prefix front cache (`FrontCachedPageStore`) for keeping public top ORAM
  tree levels in trusted memory.
- Mask-based CMOV-style helpers for stash lookup, stash insert, position-map
  lookup/update, direct INDEX slot selection, and online target-path removal.
- `oramctl` CLI for sizing, building, verifying, benchmarking, and stress
  testing Circuit ORAM images.
- `oramctl size-cuckoo` for estimating ORAM images over existing DPF/Harmony
  cuckoo tables.
- `oramctl size-direct`, `build-direct`, and `bench-direct` for direct-entry
  INDEX/CHUNK source files.
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
- `oramctl stress-ring-direct` metadata-only Ring ORAM experiment over direct
  INDEX+CHUNK geometries, with current-page and slot-addressable IO estimates.
- `oramctl plan-direct-batch-io` for estimating fixed-offset direct-entry batch
  IO under sidecar and embedded authentication layouts.
- Split metadata/payload `CircuitOram` controller prototype with deterministic
  delayed eviction, metadata-planned eviction placement, and fixed-shape
  page-trace tests.
- Trusted `CircuitOramState` snapshot/reopen, including RNG state, public
  eviction counters, and authenticated-store roots when auth is enabled, with
  optional ChaCha20-Poly1305 state-file encryption.
- Circuit ORAM trusted bulk initialization that plans metadata first, writes
  metadata/payload bucket pages sequentially, and uses mmap-backed cuckoo table
  reads for source payloads.
- Sidecar and embedded-tree authentication layouts for split Circuit ORAM
  stores. New controller snapshots carry the trusted roots; `*.auth.state`
  remains as a compatibility/export file for older tooling and old snapshots.

Intentionally not implemented yet:

- The exact optimized Circuit ORAM `deepest`/`target` circuit from the paper.
  The current `CircuitOram` controller uses two fixed metadata scans to plan a
  deepest-first placement, then applies that plan in one fixed payload scan.
- Recursive position map.
- Oblivious bulk initialization.
- Replacing the prototype dual-file auth compatibility path with one sealed,
  atomic production state envelope.
- Production-serving integration for direct-entry ORAM images.
- Crash-safe Circuit ORAM WAL / epoch protocol.
- Target release assembly / SEV-SNP ciphertext-channel audit of all
  constant-shape hot loops. A local aarch64 release assembly spot-check covers
  position-map scan/update, direct INDEX slot selection, and target-path removal.
  `scripts/audit-ct-assembly.sh` now makes that spot-check repeatable, but the
  actual SEV-SNP target build still needs to run through it.
- Formal constant-time proof for the Circuit ORAM eviction planner. The current
  greedy planner now uses a fixed public candidate universe plus masked
  selection/movement, but it still needs target release assembly review and a
  SEV-SNP side-channel audit before treating CPU/cache traces as hardened.
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

Each online read:

1. Reads every bucket on the old random root-to-leaf path.
2. Removes the target block with a full path scan and inserts it into the
   stash.
3. Assigns the target logical block a fresh random leaf.
4. Rewrites every bucket on the same path so the write set does not reveal
   where the target was found.
5. Drains a public number of deterministic eviction paths.

The backing store sees random ORAM paths, not BitcoinPIR logical ids.

The planned production direction is direct-entry Circuit ORAM with
deterministic delayed eviction, `Z=2`, packed direct records, embedded-tree page
authentication, and a fixed public batch shape. See
[`DESIGN_README.md`](DESIGN_README.md) and
[`docs/CIRCUIT_ORAM_DESIGN.md`](docs/CIRCUIT_ORAM_DESIGN.md).

## Build

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

## CLI Smoke Test

Check the CLI and run the trusted position-map full-scan microbenchmark:

```bash
cargo run --bin oramctl -- --help
cargo run --bin oramctl -- bench-pos-map \
  --sizes 1024,16384 \
  --ops 20 \
  --warmup-ops 2 \
  --batch-sizes 16,50
```

For image-level smoke tests, use `build-circuit` / `bench-circuit` for existing
DPF/Harmony cuckoo tables, or `build-direct` / `bench-direct` for direct
INDEX/CHUNK source files.

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

## Ring ORAM Direct Stress Simulation

Run the first-pass metadata-only Ring ORAM experiment from
[`docs/RING_ORAM_EXPERIMENT_PLAN.md`](docs/RING_ORAM_EXPERIMENT_PLAN.md):

```bash
cargo run --bin oramctl -- stress-ring-direct \
  --case-label FULL \
  --index-file /Volumes/Bitcoin/data/checkpoints/948454/utxo_chunks_index_nodust.bin \
  --chunks-file /Volumes/Bitcoin/data/checkpoints/948454/utxo_chunks_nodust.bin \
  --packs 16 \
  --leaf-divisors 2 \
  --bucket-sizes 4,8,16,32 \
  --eviction-periods 4,8,16,32,48 \
  --stash-capacities 128,256,512 \
  --cache-levels 0,2,3,4 \
  --auth-store \
  --ops 100000 \
  --warmup-ops 10000
```

For a DELTA run, point `--index-file` and `--chunks-file` at the delta direct
files and change `--case-label DELTA`. The command does not build payload
images and does not touch the deployment repo. It tracks real-slot stash
pressure, per-bucket read counters, public `A`-period evictions, early
reshuffles, crash-state inventory, and two IO models:

- `layout=current_page`: the current bucket page granularity, where ReadPath
  still reads a full payload bucket page per uncached path bucket.
- `layout=slot_addressable`: a future layout where ReadPath reads one selected
  payload slot per uncached path bucket, while EvictPath and early reshuffle
  still rewrite full buckets.

Ring ORAM also needs `S` reserved dummy slots per bucket. The first-pass CLI
defaults to `S=A` for each run and prints `dummy_slots`; use `--dummy-slots` to
hold `S` fixed while sweeping `A`.

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

`oramctl build-circuit --auth-store` writes authenticated sidecars by default:

```text
index.meta.hash.oram
index.payload.hash.oram
index.auth.state
chunk.meta.hash.oram
chunk.payload.hash.oram
chunk.auth.state
```

Use `--auth-layout embedded-tree` to skip the hash images and instead append 64
plaintext authentication bytes to every metadata/payload bucket page. In that
layout, the trusted controller state stores the two embedded-tree roots;
`*.auth.state` is still written for compatibility and external tooling.

Use the same `--auth-store` flag when reopening with `bench-circuit` or
`verify-circuit-bins`; the CLI then prefers auth roots bound inside the
controller state, falls back to `*.auth.state` for legacy snapshots, verifies
data pages against those roots, and writes updated roots back unless
`--no-save` is set.

For native batch callers, `CircuitOram::read_batch` performs the online phase
for several logical ids through one path-page batch. Direct readers expose that
through `lookup_batched` for INDEX candidates and `read_chunks` for direct CHUNK
ids; callers then drain the accumulated public eviction debt after the online
batch. `CircuitOram::dummy_access_batch` gives padded empty slots the same
batched random-path shape, and `CircuitOram::drain_evictions` batches the
deterministic eviction paths for the requested public budget. Position-map
lookups and updates use full scans; batch access scans the map once per lookup
or update pass while comparing each map entry against the whole requested batch.
Repeated logical ids use the previous occurrence's remapped random leaf instead
of branching to a sequential slow path.

`oramctl bench-circuit --batch-size N` exercises the same batch boundary for
random logical-block reads while keeping the default `--batch-size 1` behavior
unchanged.

For direct-entry images built by `build-direct`, `oramctl bench-direct` verifies
native batched INDEX lookups and CHUNK reads against the direct source files.

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
position-map lookup/update, direct INDEX slot selection, and target-path removal
now use full scans plus `subtle`-backed mask/CMOV-style helpers. The greedy
Circuit ORAM eviction planner now scans a fixed public candidate universe
(stash slots plus eviction-path slots) and uses masked selection/movement for
placement, stash clearing, path-block reinsertion, and bucket writeback. Run
`scripts/audit-ct-assembly.sh` after changing these hot loops; pass
`--target x86_64-unknown-linux-gnu` or set `CT_TARGET` for the SEV-SNP build
target. These are implementation hardening steps, not a formal constant-time
guarantee from Rust, LLVM, or the target hardware.

The `.state` file contains the position map, stash, RNG state, and, for Circuit
ORAM, the public delayed-eviction counters. It is trusted controller state. Do
not write it to untrusted storage in plaintext in a real deployment. Use
`--state-key-hex` for prototype AEAD protection; production should replace that
key path with SEV-sealed storage.
