# Circuit ORAM Design

This document fixes the next ORAM backend direction for BitcoinPIR: a
disk-backed Circuit ORAM controller tuned for the existing DPF/Harmony cuckoo
tables.

`CircuitOram` is now the only controller in this crate. The older Path ORAM
baseline was removed because it did not have the same trusted-memory
side-channel hardening. The current Circuit ORAM eviction implementation uses
two fixed metadata scans to produce a deepest-first placement plan, then applies
the plan with one fixed payload scan. Replacing that planning routine with the
exact optimized `deepest`/`target` circuit from the Circuit ORAM paper remains
the next algorithmic hardening step.

## Goals

- Hide the logical cuckoo block touched by a SEV-SNP guest.
- Target `Z=2` buckets, because Circuit ORAM's deterministic eviction supports
  much lower bucket capacity than vanilla Path ORAM in practice.
- Keep the ORAM tree outside trusted memory; trusted state should be position
  map, fixed-capacity stash, RNG state, scheduler state, and a small public top
  cache.
- Preserve BitcoinPIR's existing public KV mapping and PBC batching. ORAM is an
  oblivious array over packed cuckoo bins, not a generic map.
- Support delayed/background eviction without secret-dependent timing.

## Non-goals

- OnionPIR database support.
- Recursive position map in the first implementation.
- Data-dependent stash-drain heuristics.
- A generic oblivious map API.

## Parameters

Initial candidate for the production-ish DPF/Harmony tables:

```text
pack = 16
bucket_size Z = 2
leaf_divisor = 4
evictions_per_access = 2
stash_capacity = stress-test result, not a fixed assumption yet
```

This keeps the tree slot load around 63 percent for the current checkpoint
sizes, similar to the aggressive `Z=4, leaf_divisor=8` Path ORAM estimate but
with a design that is meant to operate at `Z=2`.

Reject configurations whose tree slot load exceeds 100 percent. They may look
small in a simple sizing pass but cannot hold all logical blocks.

## Logical Block Layout

The ORAM logical address is a packed cuckoo-bin block:

```text
logical_block_id = table-local packed bin id
payload = pack consecutive cuckoo bins
```

For `pack=16`:

```text
INDEX payload = 16 * 52 B = 832 B
CHUNK payload = 16 * 132 B = 2112 B
```

INDEX and CHUNK should remain separate ORAM instances. Snapshot and delta can
also remain separate instances initially, matching the current DPF/Harmony DB
directory boundary.

## Storage Layout

Circuit ORAM's benefit depends on making metadata scans cheap. Do not store the
only copy of metadata inside the payload page if that forces metadata-only
eviction planning to read full payload buckets.

Use two physical stores per ORAM instance:

```text
metadata store:
  per bucket slot:
    occupied bit
    logical id
    leaf label
    dummy/freshness metadata needed by the controller

payload store:
  per bucket slot:
    encrypted packed cuckoo payload
```

Both stores must be accessed in a fixed public shape for the selected operation.
Metadata pages can be much smaller than payload pages, so Circuit ORAM's
`deepest` and `target` scans do not pay the full payload I/O cost.

Disk pages must also be rollback-authenticated against trusted memory. The page
store layer currently has two wrappers:

- `MerklePageStore`: keeps the full SHA-256 Merkle tree in trusted memory.
- `TieredMerklePageStore`: keeps only a public number of top levels in trusted
  memory and stores lower hash nodes in a second `PageStore`.

`TieredMerklePageStore` is a correctness baseline, but it is not the preferred
production boundary for Circuit ORAM. It authenticates every data page as a leaf
of a separate Merkle tree, so one ORAM path read/write turns into many scattered
hash-store page reads and writes.

The production candidate should be an embedded authenticated ORAM tree. Store two
child subtree hashes inside each physical bucket page:

```text
physical bucket page =
  logical bucket bytes
  left_child_subtree_hash[32]
  right_child_subtree_hash[32]
```

The trusted state stores the root hash. A path read verifies top-down using the
child hash already present in the parent page on the same ORAM path. A path write
updates bottom-up, rewriting the path pages and the trusted root. This adds 64
plaintext bytes to each bucket page and removes the lower Merkle sidecar from the
steady-state request IO path.

`oramctl build-circuit --auth-store` still defaults to per-level
metadata/payload hash images plus an auth-state sidecar for the existing
baseline. `--auth-layout embedded-tree` builds physical bucket pages with the
64-byte embedded trailer. New controller snapshots carry the embedded roots;
`*.auth.state` remains a compatibility/export file for older tooling and old
snapshots.
`EmbeddedTreePageStore` is the path-level store for this format: it builds
embedded child hashes, verifies `read_path`, updates hashes on `write_path`, and
has trace tests showing a verified read followed by a write touches only the path
pages. The path-level store trait is wired into `CircuitOram` runtime access and
eviction.

For request batches, `CircuitOram::read_batch` prefetches all online old-leaf
paths into metadata/payload overlays, applies each access in caller order, then
writes the touched paths back through `PathPageStore::write_paths_pages`.
`EmbeddedTreePageStore` handles overlapping authenticated paths by updating child
hashes in an overlay before writing dirty physical pages. `drain_evictions`
uses the same multi-path boundary for deterministic eviction paths, while still
applying those paths in public schedule order. Padded request slots use
`CircuitOram::dummy_access_batch`, so random dummy paths also share the same
batched authenticated page boundary instead of falling back to one path
roundtrip per dummy.

The position map is trusted in-TEE state, but the online hot path no longer
indexes it directly by logical id. Single access uses full-scan lookup and
full-scan update. Batch access scans the map once per lookup/update pass and
compares each entry against the whole logical-id batch, so a 50-query batch does
not become 50 independent position-map scans. Repeated logical ids use the
previous occurrence's freshly remapped random leaf instead of branching to a
sequential slow path.

## Access State Machine

Each real read has an online phase and an eviction phase.

Online phase:

```text
old_leaf = position_map[logical_block_id]
read and remove matching block from old_leaf path into stash
full-scan stash to select the requested block
position_map[logical_block_id] = random_leaf()
stash updated block with new leaf
record one issued access
return payload
```

Eviction phase:

```text
for each due public eviction path:
  leaf = bit_reverse(completed_evictions mod leaves)
  metadata scan 1: collect candidate movement metadata
  metadata scan 2: compute target slot decisions
  payload scan: apply the target decisions
  completed_evictions += 1
```

The deterministic Circuit ORAM schedule adds two eviction paths per real
access:

```text
access t schedules paths bit_reverse(2t) and bit_reverse(2t + 1)
```

The implementation should store only public counters:

```text
issued_accesses
completed_evictions
```

Pending eviction debt is derived:

```text
pending = issued_accesses * 2 - completed_evictions
```

No secret-dependent queue is needed.

## Deferred Eviction Policy

Eviction may be delayed only if the delay policy is public. Acceptable policies:

- Drain exactly `D` eviction paths after each real access.
- Drain up to a fixed public budget on a fixed public timer.
- Bound public debt with `max_eviction_debt`, where request admission waits
  when the public debt counter reaches the cap.

Avoid policies whose external timing depends on stash length, hit/miss behavior,
UTXO count, or logical address. A stash high-watermark can be useful for local
debugging, but it is not a production scheduling signal unless hidden behind a
fixed-shape public schedule.

## Stash Risk

Circuit ORAM's published proof covers deterministic eviction with `Z >= 4`.
The `Z=2` choice is supported by empirical results in the paper and by later
TEE-oriented systems, not by the same clean theorem. For BitcoinPIR this means
`Z=2` is a candidate that must pass workload-specific stress testing.

The `oramctl stress-circuit` tool now simulates:

```text
random query sequence
round-robin worst-case sequence
bursty deferred eviction with max debt Q
snapshot and delta tables separately
INDEX and CHUNK tables separately
pack=16, Z=2, leaf_divisor=4
```

Required output:

```text
max stash occupancy
p99/p999 stash occupancy
overflow count for configured capacity
eviction debt distribution
metadata and payload page I/O per logical access
```

The simulator is metadata-only. It tracks logical ids, leaf labels, bucket
slots, stash occupancy, and public eviction debt, and it models Circuit ORAM's
deterministic eviction schedule with greedy path eviction. This is the right
tool for parameter exploration, but it is not a replacement for auditing the
controller's final metadata-planned eviction trace or replacing the current
planner with the optimized paper `deepest`/`target` circuit.

## Crash Consistency

The trusted state checkpoint must include:

```text
position map
stash slots
RNG state
issued_accesses
completed_evictions
metadata store root/version
payload store root/version
```

`CircuitOramState` now checkpoints the position map, fixed stash, RNG state,
and public scheduler counters (`issued_accesses`, `completed_evictions`). It
does not yet bind the metadata/payload stores to a root or epoch.

If online reads can return before queued evictions are flushed, the checkpoint
must be able to replay or resume the exact public eviction debt. Production
should use a small WAL or epoch checkpoint protocol before allowing async
eviction to cross a durable boundary.

## Implementation Milestones

1. Add deterministic Circuit ORAM scheduler and tests. Done.
2. Add `oramctl stress-circuit` simulator over real cuckoo table sizes. Done.
3. Split metadata/payload page models in the simulator and sizing output.
   Partly done: the controller uses split stores; sizing still needs explicit
   split-store byte reporting.
4. Implement a `CircuitOram` controller using the existing `PageStore` traits.
   Done as a split-store metadata-planned prototype; exact optimized
   `deepest`/`target` circuit replacement is pending.
5. Add encrypted metadata and payload stores with fixed-shape trace tests.
   Partly done: split-store fixed-shape trace tests and `CircuitOramState`
   state-file encryption are in place; metadata/payload image encryption CLI
   wiring is still pending.
6. Add runtime rollback authentication for disk pages.
   Done for the two supported layouts: `TieredMerklePageStore` keeps trusted top
   levels while spilling lower hash nodes to sidecar images, and
   `EmbeddedTreePageStore` stores child hashes inside physical bucket pages.
   `oramctl build-circuit --auth-store --auth-layout embedded-tree` and
   `bench-circuit --auth-store` build, reopen, verify, and save updated roots in
   controller state, with `*.auth.state` retained for compatibility.
7. Add native online batch reads.
   Done at the library boundary: `PathPageStore` supports multi-path reads and
   writes, `CircuitOram::read_batch` batches the online phase, and direct readers
   expose batched INDEX candidate and CHUNK reads. `CircuitOram::dummy_access_batch`
   covers padded request slots, and `CircuitOram::drain_evictions` batches
   deterministic eviction paths for a public budget. Position-map lookup/update
   is full-scan, with batch access checking each map entry against the whole
   requested batch.
   `oramctl bench-circuit --batch-size` exercises the batch boundary for random
   logical-block reads, and `oramctl bench-direct --batch-size` verifies batched
   direct INDEX/CHUNK queries. Pending production wiring: direct server request
   handling.
8. Add a crash-safe WAL or epoch protocol for delayed eviction.
9. Add a build path from existing DPF/Harmony cuckoo tables into ORAM images.
   Done for trusted/offline initialization via `oramctl build-circuit`.
   `oramctl bench-circuit --db-dir ...` reopens the split images and verifies
   random reads against the original packed cuckoo payload. High-throughput
   bulk placement and final manifest wiring are still pending.
10. Run release assembly and SEV-SNP page-trace audit on the hot loops.
   Partially done on the local `aarch64-apple-darwin` release build:
   position-map scan/update, direct INDEX slot selection, and target-path
   removal compile to compare/select or mask/bit operations rather than
   secret-dependent branches. The local constant-time primitive wrapper now
   delegates `Choice`, equality, and scalar conditional assignment to `subtle`.
   One LLVM transform did turn a conditional payload clear into a secret branch
   to `_bzero`; `clear_payload_if` now uses volatile byte stores plus an opaque
   mask to keep the assembly branchless on the local backend. Run
   `scripts/audit-ct-assembly.sh` to regenerate the release assembly and inspect
   the current hot symbols. The greedy eviction placement planner has been
   rewritten to use a fixed public candidate universe plus masked selection and
   movement for stash/path candidates. Still pending: repeat this audit on the
   actual SEV-SNP target build and treat the result as an implementation audit,
   not a formal constant-time proof for Rust/LLVM/hardware.

## Current Design Choice

Proceed with Circuit ORAM, not full Ring ORAM, for the first BitcoinPIR ORAM
backend.

Ring ORAM also separates reads and background eviction, and it has an explicit
public `A` parameter for one eviction after every `A` reads. However, it needs
extra dummy slots, per-bucket read counters, and EarlyReshuffle machinery. Those
features optimize online bandwidth, but they add substantial controller
complexity. Circuit ORAM directly targets the main pressure point for the
current servers: lower storage with `Z=2`.
