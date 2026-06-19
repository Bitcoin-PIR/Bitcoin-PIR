# BitcoinPIR ORAM Design README

Status: current design conclusion, 2026-06-21.

This branch started as a Ring ORAM experiment. The useful conclusion is not to
move BitcoinPIR to Ring ORAM for the current workload. Ring/Burst-style ORAMs
can amortize some online work, but their bucket and dummy-slot overheads are
large, and our user queries are already naturally batched. The better direction
is to keep the ORAM simple and focus on:

- direct-entry INDEX and CHUNK layouts instead of PBC-expanded cuckoo payloads;
- batched fixed-shape Circuit ORAM accesses;
- fewer storage round trips through embedded authentication data;
- constant-shape trusted-memory scans for every secret-dependent selection.

## Selected Design

The selected prototype design is a direct-entry split-store Circuit ORAM.

Direct source files:

- `utxo_chunks_index_nodust.bin`: direct INDEX records,
  `[20B script_hash][4B start_chunk_id][1B num_chunks]`.
- `utxo_chunks_nodust.bin`: direct 40-byte CHUNK records addressed by chunk id.

Built ORAM images:

- `direct-index.meta.oram` and `direct-index.payload.oram`;
- `direct-chunk.meta.oram` and `direct-chunk.payload.oram`;
- `direct-index.state` and `direct-chunk.state`;
- optional `direct-*.auth.state` plus either sidecar hash images or embedded
  authentication bytes.

The current production-shaped parameter set is:

```text
pack=16
bucket_size=2
leaf_divisor=2 for direct-entry FULL images
stash_capacity=4096 in the large local benchmark
encrypted pages enabled
embedded-tree auth preferred over sidecar auth
cache_levels=5 for public top-tree page caching
drain_per_access=2 public eviction paths per online logical ORAM read
```

`pack=16` is important: each ORAM logical block holds 16 direct INDEX bins or 16
direct CHUNK records. Without packing, the CHUNK position map and tree would be
about 16x larger for no privacy benefit.

## Request Shape

The server should expose a fixed public batch shape. A representative batch is
50 users:

```text
INDEX phase:
  50 script hashes
  2 direct INDEX candidate bins per hash
  100 direct-index ORAM logical reads

CHUNK phase:
  fixed public CHUNK budget
  for example 50 direct CHUNK ids
  50 direct-chunk ORAM logical reads

Eviction phase:
  drain a public number of deterministic eviction paths
  current benchmark uses drain_per_access=2
```

Empty or padded slots must still spend the same public access budget. The code
provides dummy batched access paths so a padded request does not create a
shorter page trace.

## What The Untrusted Host Sees

Untrusted disk sees:

- encrypted metadata and payload bucket pages;
- page reads and writes for random ORAM paths;
- public deterministic eviction paths;
- public image sizes, table choice, batch size, cache level, and request budget;
- authentication state updates when auth is enabled.

Untrusted disk should not see:

- which `script_hash` was queried;
- which INDEX candidate matched;
- which direct CHUNK id was the real target;
- which position-map entry or stash slot held a block.

The page trace is still an ORAM trace, not a RAM-oblivious program trace. The
host can see public path counts and random leaf paths. That is expected. The
privacy goal here is that those paths are independent of BitcoinPIR logical ids.

## Trusted State

Trusted controller state contains:

- the position map, `logical_id -> current random leaf`;
- the fixed-capacity stash;
- RNG state;
- public delayed-eviction counters;
- authentication roots when auth is enabled.

Prototype `.state` files can be encrypted with `--state-key-hex`, but production
should seal this state to the SEV-SNP guest. A plaintext state file is not safe
on untrusted storage.

## Hiding Trusted-Memory Access Patterns

The implementation avoids secret-dependent memory access in the hot trusted
loops by using fixed scans and masked moves.

Position map:

- a single lookup scans every `u32` entry and mask-selects the matching leaf;
- an update scans every entry, mask-selects the old leaf, and performs a
  constant-shape masked write at every entry;
- batch lookup/update scans the whole map once per pass and compares each map
  entry against every logical id in the public batch width;
- repeated logical ids are handled by masked previous-occurrence selection,
  rather than branching into a sequential fallback.

Stash:

- stash capacity is fixed;
- lookup, insert, clear, and occupancy accounting scan all slots;
- slot metadata and payload movement use `subtle::Choice` through local
  `ct::*` helpers.

Path access:

- online access reads and rewrites every bucket on a full root-to-leaf path;
- target-block removal from a path scans all path buckets and slots;
- direct INDEX slot selection scans every slot in the candidate bin.

Eviction planner:

- the greedy planner scans a fixed public candidate universe: every stash slot
  plus every slot on the public eviction path;
- placement selection is done with masked `cmov`-style updates, not by building
  a secret-length candidate list;
- apply/writeback scans all candidates for each bucket slot instead of indexing
  by a secret placement result;
- unselected path candidates are reinserted into the stash through fixed scans.

These rules hide memory access patterns at the source-code level: loop bounds
are public, accessed arrays are scanned in public order, and secret values only
affect masks. The implementation uses the `subtle` crate for `Choice` and
keeps a repeatable release-assembly spot check in:

```bash
scripts/audit-ct-assembly.sh
```

For the SEV-SNP target, run the same audit against the target release build, for
example:

```bash
scripts/audit-ct-assembly.sh --target x86_64-unknown-linux-gnu
```

This is still not a formal constant-time proof. Rust, LLVM, the CPU, and the
SEV-SNP threat model must be reviewed together before treating the hot loops as
production-hardened.

## Authentication Layout

Sidecar Merkle authentication works but is too expensive for batched random
page IO: each data page access walks many hash nodes, and each hash-node touch
currently becomes a separate hash-page operation.

The preferred prototype layout is embedded-tree authentication:

```text
physical bucket page =
  logical bucket bytes
  left_child_subtree_hash[32]
  right_child_subtree_hash[32]
```

The trusted auth state keeps the roots. This avoids separate hash images and
keeps page authentication tied to the same data-page IO. It increases each
physical page by 64 plaintext auth bytes before AEAD overhead, which is much
cheaper than the sidecar roundtrip shape for this workload.

## Current Benchmark Snapshot

Local benchmark environment:

```text
Darwin 25.5.0 arm64
rustc 1.96.0-nightly (900485642 2026-04-08)
real direct FULL input under /Volumes/Bitcoin/data/intermediate
encrypted pages
embedded-tree auth
cache_levels=5
drain_per_access=2
```

Build result:

```text
direct-index:
  logical_blocks=882373
  leaves=524288
  height=20
  build elapsed=68.6s

direct-chunk:
  logical_blocks=5049871
  leaves=4194304
  height=23
  build elapsed=324.1s

combined temp image directory: about 15 GiB
```

Online benchmark, `bench-direct --ops 250 --batch-size 50`:

```text
INDEX:
  250 source-level lookups
  2 candidate ORAM reads per lookup
  elapsed=23.30s
  avg=93.19 ms per source-level lookup
  about 4.66s per 50-user INDEX batch

CHUNK:
  250 direct CHUNK reads
  elapsed=8.60s
  avg=34.41 ms per chunk
  about 1.72s per 50-user CHUNK batch

Combined:
  about 6.38s per 50-user INDEX+CHUNK batch
```

Position-map full-scan microbenchmark on the same logical block counts:

```text
INDEX position map, batch width 100:
  lookup 94.3 ms
  update 101.9 ms
  total about 196 ms

CHUNK position map, batch width 50:
  lookup 265.7 ms
  update 310.7 ms
  total about 576 ms
```

So the branchless full-scan position-map work is material, but it is not the
dominant cost in the current local benchmark. Most time is still in ORAM path
IO, AEAD, embedded authentication, direct INDEX candidate reads, and
eviction-planner/apply work.

## Commands

Build direct ORAM images:

```bash
cargo run --release --bin oramctl -- build-direct \
  --index-file /Volumes/Bitcoin/data/intermediate/utxo_chunks_index_nodust.bin \
  --chunks-file /Volumes/Bitcoin/data/intermediate/utxo_chunks_nodust.bin \
  --out-dir /tmp/bpir-direct-oram \
  --level all \
  --pack 16 \
  --leaf-divisor 2 \
  --bucket-size 2 \
  --stash-capacity 4096 \
  --encrypted \
  --key-hex "$KEY_HEX" \
  --state-key-hex "$STATE_KEY_HEX" \
  --auth-store \
  --auth-layout embedded-tree \
  --auth-trusted-levels 2
```

Benchmark a 50-user batch shape:

```bash
cargo run --release --bin oramctl -- bench-direct \
  --oram-dir /tmp/bpir-direct-oram \
  --index-file /Volumes/Bitcoin/data/intermediate/utxo_chunks_index_nodust.bin \
  --chunks-file /Volumes/Bitcoin/data/intermediate/utxo_chunks_nodust.bin \
  --level all \
  --ops 250 \
  --batch-size 50 \
  --drain-per-access 2 \
  --encrypted \
  --key-hex "$KEY_HEX" \
  --state-key-hex "$STATE_KEY_HEX" \
  --cache-levels 5 \
  --auth-store
```

Run the side-channel assembly spot check:

```bash
scripts/audit-ct-assembly.sh
```

Run the normal verification suite:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
git diff --check
```

## Remaining Work

- Run and inspect the release assembly audit on the actual SEV-SNP target build.
- Decide the exact public production batch shape and enforce it at the API
  boundary.
- Replace prototype state keys with SEV-sealed state handling.
- Replace the prototype dual-file auth-state compatibility path with one
  sealed, atomic production state envelope.
- Add crash-safe WAL or epoch handling for image and state updates.
- Integrate the direct-entry ORAM reader into the serving path.
- Keep Ring ORAM as a documented non-selected experiment, not the main path.
