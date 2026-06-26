# Direct-entry ORAM batching plan

## Motivation

The current deployed ORAM image wraps the DPF/Harmony `INDEX + CHUNK` PBC
cuckoo tables. That preserves compatibility, but it also preserves the PBC
storage expansion. For a TEE-backed ORAM lookup, the server can execute the
key lookup internally and return results over the encrypted channel, so the
PBC group expansion is no longer necessary.

The next ORAM format should be built from the direct intermediate records:

- `utxo_chunks_index_nodust.bin`: 25-byte records
  `[20B script_hash][4B start_chunk_id][1B num_chunks]`.
- `utxo_chunks_nodust.bin`: direct 40-byte chunk payloads addressed by
  `chunk_id`.

The delta pipeline uses the same direct index/chunk record shape.

## Position-map scan benchmark

`oramctl bench-pos-map` measures three trusted position-map access shapes:

- `direct`: ordinary indexed load.
- `scan`: branchless full scan to select one leaf.
- `scan_update`: branchless full scan that selects the old leaf and writes a
  new leaf with a constant-shape store to every entry.
- `batch_scan` / `batch_scan_update`: one full map pass per batch lookup/update,
  comparing each map entry against every requested logical id in that batch.

VPSBG results for the current canonical direct-entry packed sizes, `ops=2000`,
`warmup_ops=200`:

| Direct table | Packed ORAM blocks | Map size | Scan | Scan + update |
| --- | ---: | ---: | ---: | ---: |
| Canonical DELTA direct index | 82,808 | 0.316 MiB | 14.5 us | 28.3 us |
| Canonical DELTA direct chunks | 531,611 | 2.028 MiB | 92.6 us | 178.7 us |
| FULL direct index | 885,445 | 3.378 MiB | 153.7 us | 297.5 us |
| FULL direct chunks | 5,061,532 | 19.308 MiB | 877.9 us | 1.71 ms |

Conclusion: full-scan position-map access is acceptable for the current packed
block counts. It is not acceptable if we make every 40-byte chunk its own ORAM
logical block and grow the position map by 16x.

Online batch access uses the same full-scan idea without doing one complete map
pass per query: each map entry is compared against the whole requested logical-id
batch, and repeated logical ids use the previous occurrence's freshly remapped
random leaf.

A local release build against the current FULL direct dimensions, with
`--batch-sizes 50,100 --ops 5 --warmup-ops 1`, measured the expected request-size
batch widths:

| Direct table | Batch width | Batch scan | Batch scan + update |
| --- | ---: | ---: | ---: |
| FULL direct index | 100 | 8.3 ms | 33.1 ms |
| FULL direct chunks | 50 | 28.5 ms | 95.0 ms |

These local batch numbers are small-sample CPU measurements, not disk timings.
They show that a 50-user request shape can hide position-map memory access with
roughly hundreds of milliseconds of extra CPU work rather than 50 independent
map scans.

A local macOS development-machine run against the canonical direct dimensions
used a temporary standalone ORAM checkout outside the main BitcoinPIR cargo
vendor override:

```text
cargo run --release --bin oramctl -- \
  bench-pos-map --sizes 82808,531611,885445,5061532 \
  --ops 2000 --warmup-ops 200
```

| Direct table | Packed ORAM blocks | Map size | Scan | Scan + update |
| --- | ---: | ---: | ---: | ---: |
| Canonical DELTA direct index | 82,808 | 0.316 MiB | 30.5 us | 34.2 us |
| Canonical DELTA direct chunks | 531,611 | 2.028 MiB | 251.0 us | 329.6 us |
| FULL direct index | 885,445 | 3.378 MiB | 409.6 us | 424.4 us |
| FULL direct chunks | 5,061,532 | 19.308 MiB | 1.99 ms | 3.32 ms |

The VPSBG numbers are the production-relevant ones. The local run is still a
useful guardrail: even on the slower local path, full CHUNK map scan+update is
single-digit milliseconds for `pack=16`, so it is not the dominant term in the
current server-smoke timings. Do not reduce `pack` to 1 for CHUNK without
redoing this benchmark, because that would grow the CHUNK position map by about
16x.

## Direct-entry layout

Keep separate direct ORAM tables:

1. `direct_index`
   - Payload slot: collision-free
     `[1B occupied][20B script_hash][4B start_chunk_id][1B num_chunks]`.
   - Lookup structure: non-PBC cuckoo table over all script hashes, with a small
     fixed number of candidate bins.
   - ORAM payload block packs consecutive direct index bins, for example
     `pack=16`.

2. `direct_chunk`
   - Payload record: direct 40-byte chunk payload.
   - Logical key: `chunk_id`.
   - ORAM payload block packs consecutive chunk records, for example `pack=16`.

The index table may still use cuckoo hashing, but only as a direct dictionary.
It should not be split into 75 PBC groups, and each entry should be stored once
rather than once per candidate PBC group.

## Batched request shape

Add a native ORAM batch endpoint with a fixed public access budget:

```text
OramDirectBatchRequest {
    db_id,
    padded_slots[],
    slot_present[],
    access_budget,
}
```

The server should execute a fixed schedule:

1. For each padded slot, perform a fixed number of direct-index ORAM reads.
   Real slots probe the candidate direct-index bins; explicit empty slots spend
   the same count as random dummy INDEX ORAM path accesses.
2. Decode matches inside the TEE only for real slots.
3. Build a private list of required chunk IDs.
4. Execute up to the remaining fixed chunk-read budget.
5. Fill unused CHUNK access slots with dummy CHUNK ORAM path accesses.
6. If real chunks exceed the budget, return a continuation token/state so the
   client can request another fixed-budget batch.

The important distinction is that the public padding width is the number of
script-hash slots, while the server access budget is the number of ORAM path
accesses. Empty slots do not read a logical INDEX element and therefore do not
create CHUNK demand, but they still read/rewrite random ORAM paths and add the
usual eviction debt.

For a padded request with two direct-index candidates per slot, the budget is:

```text
padded_index_reads = direct_index_candidates * padded_slots.len()
chunk_budget = access_budget - padded_index_reads
```

The request should reject or split batches when
`padded_index_reads > access_budget`.

With the current `hash_fns=2`:

- `padded_slots=50` spends 100 INDEX ORAM path accesses before any CHUNK read.
- `access_budget=120` leaves 20 CHUNK reads for those 50 slots.
- `access_budget=150` leaves 50 CHUNK reads for those 50 slots.
- The old `access_budget=50` can only support 25 padded slots with no CHUNK
  budget, or fewer padded slots if found results need CHUNK reads.

The implemented first cut keeps the request length public and fixed-fills only
within that request's access budget. If real CHUNK demand exceeds the remaining
budget, the server drains the remaining dummy chunk budget, persists the mutated
ORAM state, and returns an error. A production wallet-sync planner should split
such batches ahead of time or add an explicit continuation token.

The web adapter exposes this as an opt-in fixed-budget planner instead of the
DPF/Harmony PBC batch planner:

```ts
planOramScriptHashBatches(scriptHashes, {
  accessBudget: 120,
  indexReadsPerScriptHash: 2,
  expectedChunkReadsPerScriptHash: 1,
  paddedSlotCount: 50,
  chunkReadReserve: 0,
});
```

This example sends every request as 50 explicit slots and derives 20 real
script hashes per request because 100 ORAM accesses are reserved for INDEX and
20 remain for expected CHUNK reads. If the operator wants up to 50 real
script-hash slots with one expected CHUNK each, set `accessBudget` to at least
150. For safer ordinary wallet sync, keep a chunk reserve or an explicit
`maxScriptHashesPerRequest` cap.

## Engineering sequence

1. Add direct table builders in the standalone ORAM repo:
   - parse direct index/chunk intermediate files;
   - emit `direct-index.*` and `direct-chunk.*` ORAM images plus metadata;
   - keep the same tiered Merkle/auth-state machinery.
2. Add an `oramctl size-direct` estimator before building images. (Done.)
3. Add an `oramctl build-direct` command for FULL and DELTA. (Done for the
   standalone ORAM image format.)
4. Add a runtime direct-ORAM reader beside the current cuckoo reader. (Done in
   the main repo worktree; built and smoked from the VPSBG test checkout.)
5. Add a native direct batch request/response type in `pir-sdk-client` and
   `unified_server`. (Done in the main repo worktree.)
6. Keep HarmonyPIR/DPF on their mmap-backed PBC databases. ORAM lookup is a
   separate `REQ_ORAM_LOOKUP` path; legacy PBC-cuckoo ORAM should be only a
   compatibility fallback for that ORAM opcode.
7. Benchmark fixed budgets: 16, 32, 50, 64 ORAM accesses. (Pending beyond the
   50-access synthetic smoke.)
8. Add client-side batch planning: choose `script_hashes.len()` so
   `hash_fns * len + expected_chunks <= access_budget`, split otherwise, and
   later replace overflow errors with continuation tokens if large wallets need
   it.

## Fixed-offset batch IO planning

`oramctl plan-direct-batch-io` estimates the disk roundtrip shape for the current
direct Circuit ORAM layout without building images. It samples public online
paths for a batch, adds the deterministic eviction paths implied by
`--drain-per-access`, then reports:

- current page operations under the existing per-page `PageStore` API;
- unique pages and sorted contiguous runs for data pages;
- current and coalesced lower Merkle hash-store page touches when `--auth-store`
  is enabled with `--auth-layout sidecar`;
- the proposed embedded-tree layout, where every bucket page carries its two
  child subtree hashes and the trusted state keeps only the root.

Example for the current FULL direct inputs:

```bash
cargo run --bin oramctl -- plan-direct-batch-io \
  --case-label FULL \
  --index-file /Volumes/Bitcoin/data/intermediate/full_948454/utxo_chunks_index_nodust.bin \
  --chunks-file /Volumes/Bitcoin/data/intermediate/full_948454/utxo_chunks_nodust.bin \
  --level all \
  --pack 16 \
  --leaf-divisor 2 \
  --bucket-size 2 \
  --cache-levels 5 \
  --queries 50 \
  --drain-per-access 2 \
  --auth-store \
  --auth-layout sidecar \
  --auth-trusted-levels 1 \
  --auth-hash-page-size 4096 \
  --encrypted
```

Representative local planning results for 50 queries plus 100 deterministic
eviction paths:

| Case | Level | Auth layout | Current page ops | Sorted run floor | Current backing bytes |
| --- | --- | --- | ---: | ---: | ---: |
| FULL | index | sidecar | 530,500 | 14,332 | 2.06 GiB |
| FULL | chunk | sidecar | 700,300 | 27,176 | 2.71 GiB |
| FULL | index | embedded-tree | 10,500 | 6,812 | 15.4 MiB |
| FULL | chunk | embedded-tree | 12,600 | 8,548 | 7.9 MiB |
| DELTA canonical | index | sidecar | 384,100 | 6,364 | 1.45 GiB |
| DELTA canonical | chunk | sidecar | 530,500 | 14,160 | 2.00 GiB |
| DELTA canonical | index | embedded-tree | 8,400 | 4,944 | 12.3 MiB |
| DELTA canonical | chunk | embedded-tree | 10,500 | 6,764 | 6.6 MiB |

The important result is that batching helps the fixed-offset disk path, but the
current Merkle sidecar dominates the roundtrip count. With authentication
disabled, 50 queries plus 100 deterministic eviction paths touch only thousands
of data-page runs and single-digit to low-double-digit MiB. With
`TieredMerklePageStore` at `auth_trusted_levels=1`, every data page read/write
walks many 32-byte hash nodes and currently reads or writes a whole 4 KiB hash
page per node. For the same FULL run, raising trusted Merkle levels to 12 cuts
current hash page ops by about half, but the sorted run floor barely changes
because the lower hash pages are still scattered.

The stronger candidate is not a larger sidecar page. It is an embedded
authenticated ORAM tree:

```text
physical bucket page =
  logical bucket bytes
  left_child_subtree_hash[32]
  right_child_subtree_hash[32]
```

The trusted state stores the root hash. A path read verifies top-down: root hash
authenticates the root page, each parent page authenticates the next child page
through the stored child hash. A path write updates bottom-up: recompute the leaf
hash, then update each parent page's selected child hash and page hash until the
trusted root changes. This is compatible with ORAM because online access and
eviction already read/write complete root-to-leaf paths. It would not be a good
generic random-page `PageStore`, but it matches the Circuit ORAM operation
boundary.

`EmbeddedTreePageStore` is the current implementation of this layout. It is
intentionally path-level rather than a transparent `PageStore`: a single page
cannot be verified efficiently without its ancestors, but a full ORAM path can be
verified and updated with only the path pages. The runtime controller now uses a
path-level store trait: ordinary `PageStore` implementations use a loop fallback,
while `EmbeddedTreePageStore` supplies path authentication directly. The CLI can
build and reopen these images with `--auth-store --auth-layout embedded-tree`.

The library now has a native online batch boundary:

- `PathPageStore::read_paths_pages` / `write_paths_pages` carry multiple public
  paths at once;
- `EmbeddedTreePageStore` verifies all unique pages for the batch, applies path
  writes through an authenticated overlay, and writes dirty pages once;
- `CircuitOram::read_batch` applies several logical reads in ORAM order over a
  metadata/payload page overlay, then writes the touched paths back;
- position-map lookup/update is full-scan; the batch path scans once per
  lookup/update pass and compares each entry against every logical id in the
  requested batch;
- direct readers expose this as `lookup_batched` for INDEX candidates and
  `lookup_many_batched` for INDEX batches, `read_chunks` for direct CHUNK ids,
  and batched dummy padding for empty INDEX slots and unused CHUNK budget.
- `CircuitOram::drain_evictions` batches deterministic eviction paths for a
  public budget, applying them in schedule order over the same overlay model.
- `AeadPageStore` and `FrontCachedPageStore` preserve the bulk boundary instead
  of falling back to per-page calls. This matters for the production encrypted
  and top-level cached store stack: the bottom `FilePageStore` can still see
  sorted contiguous runs and approach the planner's `Sorted run floor`.

`oramctl bench-circuit --batch-size N` exercises the batch boundary for random
logical-block reads, and `oramctl bench-direct --batch-size N` verifies batched
INDEX lookups plus CHUNK reads against direct source files.

The remaining large I/O question is request-level durability, not page-run
coalescing. The runtime currently flushes dirty ORAM stores at the end of a
mutating request; `FilePageStore::flush()` calls `sync_all()`, and the trusted
controller/auth state is then written atomically. Relaxing this to epoch flushes,
`sync_data`, or a WAL would likely reduce latency, but it changes crash-recovery
semantics and should be designed as a separate durability mode rather than hidden
inside the page-store batching work.

This points to the next useful implementation direction:

1. Keep using direct-entry Circuit ORAM rather than moving to Ring/Burst ORAM.
2. Keep `FilePageStore` positional, so page accesses do not depend on a shared
   file cursor.
3. Use embedded-tree authenticated page format for Circuit ORAM stores when
   building new authenticated images.
4. Keep production direct requests on the native batch APIs with a fixed public
   access budget per request. `bench-circuit --batch-size` and
   `bench-direct --batch-size` cover local benchmarking.
5. Treat request-level WAL/epoch flushing as the next separate optimization if
   per-request `sync_all()` shows up in runtime latency traces.
6. Keep sidecar hash-page coalescing only as a fallback migration path for
   existing images.

The README previously compared the trusted bulk builder to the Oblix/EnigMap
initialization line of work: assign leaves in trusted memory, place blocks close
to their leaves, and write the final disk image in public bucket order. The local
repo does not include the EnigMap paper/link, and a quick public search did not
turn up a reliable primary source under that exact name, so this document keeps
the engineering takeaway rather than relying on a precise citation.

## VPSBG smoke status

Built direct images:

- FULL: `/home/pir/data/oram/checkpoints/948454-direct-pack16-z2-div2-stash128-auth`
- canonical DELTA:
  `/home/pir/data/oram/deltas/940611_948454_canonical-direct-pack16-z2-div2-stash128-auth`

The canonical DELTA direct input pair was regenerated from the attested-builder
txoutset inputs at builder commit `01e8db91d76037cd5562fce85c40e832ad156431`:

- `utxo_chunks_index_nodust.bin`: 125,867,300 bytes,
  SHA-256 `e06fc3dedf30096124888acef3024f21a9c049d59fd8c7d518aaf8a58ac6aa16`;
- `utxo_chunks_nodust.bin`: 340,230,840 bytes,
  SHA-256 `536acb605396056118c7c0836988f369c5abbfc3f7e90732ad93e819d5188e0a`.

Two-db direct server smoke passed on VPSBG using the real `databases.toml`,
direct FULL as db_id 0, and direct canonical DELTA as db_id 1. The smoke
verified cleartext ORAM rejection and encrypted-channel ORAM queries with
`sev_status=ReportDataMatch`. Synthetic not-found lookup timings were:

- db_id 0 FULL: 647.54 ms;
- db_id 1 canonical DELTA: 698.85 ms.

A second smoke used one known-present FULL script hash and one known-present
canonical DELTA script hash in the same fixed-budget request. It verified found
results, direct CHUNK reads, and client-side result decoding:

- db_id 0 FULL, two script hashes: 635.24 ms, one found UTXO;
- db_id 1 canonical DELTA, two script hashes: 575.75 ms, one found delta
  record.
