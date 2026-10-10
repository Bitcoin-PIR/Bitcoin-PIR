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
- `oramctl` CLI for sizing, building, benchmarking, and stress testing
  direct-entry Circuit ORAM images.
- `oramctl size-direct`, `build-direct`, and `bench-direct` for direct-entry
  INDEX/CHUNK source files.
- Fixed trace-shape tests: each logical access reads and rewrites a complete
  root-to-leaf path.
- Circuit ORAM deterministic eviction scheduler and design notes.
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
- Circuit ORAM trusted bulk initialization that plans metadata first and writes
  metadata/payload bucket pages sequentially.
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

For image-level smoke tests, use `build-direct` / `bench-direct` on the direct
INDEX/CHUNK source files.

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

`oramctl build-direct` builds split metadata/payload ORAM images from the
direct INDEX/CHUNK source files (`utxo_chunks_index_nodust.bin`,
`utxo_chunks_nodust.bin`); `oramctl bench-direct` verifies native batched INDEX
lookups and CHUNK reads against the same files.

The builder keeps bucket metadata and trusted controller state in memory. It
uses trusted, non-oblivious initialization because BitcoinPIR snapshots are
public and the ORAM image is generated before serving: first assign random
leaves, place metadata as close to leaves as possible, then write every metadata
page and every payload page exactly once in page order. This follows the same
bulk-build principle as the Oblix/EnigMap initialization line of work, but
without their oblivious sorting requirement because the input is not a private
map.

For runtime rollback safety, the page-store layer now has two authentication
wrappers. `MerklePageStore` keeps the whole hash tree in trusted memory and is
useful for small tests. `TieredMerklePageStore` keeps only a public number of
top tree levels in trusted memory and spills lower hash nodes into a second
`PageStore`; reads recompute the page's authentication path to the trusted
frontier, and writes update the leaf-to-root path.

`--auth-store` writes authenticated sidecar hash images by default. Use
`--auth-layout embedded-tree` to skip the hash images and instead append 64
plaintext authentication bytes to every metadata/payload bucket page. In that
layout, the trusted controller state stores the two embedded-tree roots;
`*.auth.state` is still written for compatibility and external tooling.

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
