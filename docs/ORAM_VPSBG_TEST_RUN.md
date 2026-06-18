# ORAM VPSBG Runbook

This runbook covers the upgraded VPSBG single-machine ORAM deployment path.
The bulk ORAM payload/meta/hash images live on local VPSBG disk. Trusted memory
is limited to the ORAM reader state, stash, auth roots/state, and any explicitly
configured top-level cache.

Current target shape:

- one local server hosts normal Harmony/DPF data plus ORAM images;
- db_id 0 is the FULL checkpoint;
- db_id 1 is the canonical DELTA;
- OnionPIR is not part of this ORAM backend;
- ORAM uses direct INDEX+CHUNK entry images, not the PBC-expanded cuckoo
  buckets used by Harmony/DPF;
- startup uses explicit per-db ORAM flags rather than a global ORAM directory.

## Current VPSBG Candidate

Observed upgraded host:

```text
vCPU: 4 AMD EPYC 9745
RAM: 61 GiB
rootfs: 193 GiB, about 81 GiB free after the direct FULL image,
        canonical direct DELTA image, and test checkout
```

Accepted direct ORAM parameters:

```text
pack = 16
Z = 2
leaf_divisor = 2
stash_capacity = 128
drain_per_access = 2
direct_access_budget = 50
direct_index_slots_per_bin = 4
direct_index_hash_fns = 2
direct_index_load_factor = 0.95
auth_store = 1
cache_levels = 0
```

Direct images are built from the raw Harmony/DPF source tables. Keep these
outside the runtime checkpoint/delta dirs so `MANIFEST.toml` and server startup
do not hash ORAM-build inputs:

```text
FULL INDEX source:  /home/pir/data/oram-inputs/checkpoints/948454/utxo_chunks_index_nodust.bin
FULL CHUNK source:  /home/pir/data/oram-inputs/checkpoints/948454/utxo_chunks_nodust.bin
DELTA INDEX source: /home/pir/data/oram-inputs/deltas/940611_948454_canonical_20260615/utxo_chunks_index_nodust.bin
DELTA CHUNK source: /home/pir/data/oram-inputs/deltas/940611_948454_canonical_20260615/utxo_chunks_nodust.bin
```

Current VPSBG state:

```text
FULL INDEX source copied and verified:
  size   1,345,875,975 bytes
  sha256 d0b9573488abdda8e17dc52bb52bf5ff11520b4511683020f5f1a22bc8d8d26c
FULL CHUNK source recovered from PBC and verified:
  size   3,239,380,480 bytes
  sha256 9a81a02bf82af49414b5f2ae6380c97c1f231fcac6890b605f6cde22b0adc521

Canonical DELTA CHUNK source recovered from PBC and verified:
  size   340,230,840 bytes
  sha256 536acb605396056118c7c0836988f369c5abbfc3f7e90732ad93e819d5188e0a
Canonical DELTA INDEX source regenerated from the attested-builder
txoutset inputs at commit 01e8db91d76037cd5562fce85c40e832ad156431:
  size   125,867,300 bytes
  sha256 e06fc3dedf30096124888acef3024f21a9c049d59fd8c7d518aaf8a58ac6aa16
Canonical DELTA anchor:
  sha256 e0c43201f1b8adc4332175cb02ff218cd8651cc82a991e71427b16460f34e37a

Noncanonical DELTA direct-input pair exists for direct-layout comparison only:
  index sha256 9d33ec8ac10b94b8883ae4ee511ad880e357536f780f34f9f589721e1ac81427
  chunk sha256 c6e22b7b036e199400796e839c4835a8c3baade9c4c78335c501cbd8c0060734
```

Existing VPSBG checkpoint/delta dirs only contained the PBC cuckoo outputs when
first checked. If direct INDEX source tables are missing, regenerate/copy them
first. New full or delta builds can set `KEEP_ORAM_DIRECT_INPUTS=1` in
`scripts/build_full.sh` or `scripts/build_delta.sh`. For the renamed canonical
delta directory, also set
`ORAM_DIRECT_INPUT_DIR=/home/pir/data/oram-inputs/deltas/<canonical-name>` when
building/copying the direct inputs.

If only `utxo_chunks_nodust.bin` is missing, it can be recovered losslessly from
`chunk_pir_cuckoo.bin`:

```bash
DB_DIR=/home/pir/data/checkpoints/948454 \
DIRECT_SOURCE_DIR=/home/pir/data/oram-inputs/checkpoints/948454 \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh real-extract-direct-chunks
```

The INDEX source cannot be recovered exactly from `batch_pir_cuckoo.bin`,
because deployed INDEX slots contain only an 8-byte fingerprint tag plus chunk
range, not the original 20-byte script hash.

Previous PBC/cuckoo candidate images, kept only as legacy reference:

```text
FULL:
  /home/pir/data/oram/checkpoints/948454-pack16-z2-div2-stash128-auth
  size: 42G
  build: 3:32 wall, about 11.6G max RSS

DELTA:
  /home/pir/data/oram/deltas/940611_948454_canonical-pack16-z2-div2-stash128-auth
  size: 4.8G
  build: 21.9s wall, about 1.2G max RSS
```

Verification already performed on the legacy PBC/cuckoo candidate images:

```text
FULL verify-circuit-bins --bins 1000:
  INDEX avg_us ~= 8561
  CHUNK avg_us ~= 7359
  max RSS ~= 111M

DELTA verify-circuit-bins --bins 1000:
  INDEX avg_us ~= 6213
  CHUNK avg_us ~= 7017
  max RSS ~= 72M
```

Random stress with 1M accesses, warmup 100k, and drain_per_access=2 observed
`max_stash=0` for FULL and DELTA INDEX/CHUNK with these legacy parameters.

Direct non-PBC images built on VPSBG:

```text
FULL:
  /home/pir/data/oram/checkpoints/948454-direct-pack16-z2-div2-stash128-auth
  size: 15G
  build: 2:25 wall, about 3.6G max RSS
  direct-index logical_blocks: 885,445
  direct-chunk logical_blocks: 5,061,532
  trusted state floor from size-direct: about 23.0 MiB

Noncanonical DELTA staging, removed after canonical DELTA was built:
  /home/pir/data/oram/deltas/940611_948454-direct-pack16-z2-div2-stash128-auth
  size: 1.9G
  build: 15.2s wall, about 402M max RSS
  direct-index logical_blocks: 82,813
  direct-chunk logical_blocks: 531,673

Canonical DELTA:
  /home/pir/data/oram/deltas/940611_948454_canonical-direct-pack16-z2-div2-stash128-auth
  size: 1.9G
  build: 14.1s wall, about 402M max RSS
  direct-index logical_blocks: 82,808
  direct-chunk logical_blocks: 531,611
```

The noncanonical DELTA image is not suitable for production db_id=1 while
`databases.toml` points to
`deltas/940611_948454_canonical_20260615`.

Runtime status:

```text
Live /home/pir/BitcoinPIR systemd binary still uses legacy --cuckoo-oram-db.
Direct-capable runtime was built and smoked from:
  /home/pir/BitcoinPIR-oram-direct-test
```

## Safety Boundary

For build/verify modes, stop the production `pir-vpsbg` service first. ORAM
builds read the source database and write large image files; running them beside
production makes memory and page-cache behavior harder to interpret.

For server smoke tests, also prefer stopping `pir-vpsbg` unless the test is
explicitly intended to measure co-residency.

```bash
sudo systemctl stop pir-vpsbg
```

The helper refuses real modes while `pir-vpsbg` is active unless:

```bash
ALLOW_PIR_SERVICE_ACTIVE=1
```

## Repos

Expected layout on VPSBG:

```bash
/home/pir/BitcoinPIR
/home/pir/bitcoin-pir/oram
/home/pir/data/databases.toml
/home/pir/data/checkpoints/948454
/home/pir/data/deltas/940611_948454_canonical_20260615
```

`/home/pir/bitcoin-pir/oram` provides `oramctl`; `/home/pir/BitcoinPIR`
provides the ORAM-enabled `unified_server` and smoke client.

## Preflight

```bash
cd /home/pir/BitcoinPIR

DB_DIR=/home/pir/data/checkpoints/948454 \
ORAM_LAYOUT=direct \
DIRECT_SOURCE_DIR=/home/pir/data/oram-inputs/checkpoints/948454 \
ORAM_DIR=/home/pir/data/oram/checkpoints/948454-direct-pack16-z2-div2-stash128-auth \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh preflight
```

Default thresholds:

```text
REAL_MIN_FREE_GIB=80
REAL_MIN_MEM_GIB=12
SERVER_MIN_MEM_GIB=16
```

## Build Or Verify One Image

Build/verify still operates on one DB directory at a time.

FULL:

```bash
DB_DIR=/home/pir/data/checkpoints/948454 \
ORAM_LAYOUT=direct \
DIRECT_SOURCE_DIR=/home/pir/data/oram-inputs/checkpoints/948454 \
ORAM_DIR=/home/pir/data/oram/checkpoints/948454-direct-pack16-z2-div2-stash128-auth \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
PACK=16 LEAF_DIVISOR=2 BUCKET_SIZE=2 STASH_CAPACITY=128 DIRECT_ACCESS_BUDGET=50 \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh real-build
```

DELTA:

```bash
DB_DIR=/home/pir/data/deltas/940611_948454_canonical_20260615 \
ORAM_LAYOUT=direct \
DIRECT_SOURCE_DIR=/home/pir/data/oram-inputs/deltas/940611_948454_canonical_20260615 \
ORAM_DIR=/home/pir/data/oram/deltas/940611_948454_canonical-direct-pack16-z2-div2-stash128-auth \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
PACK=16 LEAF_DIVISOR=2 BUCKET_SIZE=2 STASH_CAPACITY=128 DIRECT_ACCESS_BUDGET=50 \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh real-build
```

Verify:

```bash
ORAM_LAYOUT=direct ./scripts/oram_vpsbg_test.sh real-verify
```

For direct images, `real-verify` currently performs structural checks for
`direct-index.*` and `direct-chunk.*`. Use `server-smoke` for behavioral lookup
verification. The legacy cuckoo layout still supports `VERIFY_BINS=1000`.

Do not set `NO_SAVE=1` for persistent ORAM images. ORAM reads mutate page
images and state; skipping state/auth-state save leaves the image unsuitable
for reuse.

## Position-Map Scan Benchmark

Direct ORAM keeps the position map in trusted memory. If the position-map index
itself must not be visible through the guest's memory address stream, use a
branchless full scan instead of an indexed load:

```bash
cd /home/pir/BitcoinPIR

ORAM_REPO=/home/pir/bitcoin-pir/oram \
ORAM_LAYOUT=direct \
POS_MAP_SIZES=82808,531611,885445,5061532 \
BENCH_OPS=200 POS_MAP_WARMUP_OPS=20 \
CARGO_JOBS=1 CARGO_TOOLCHAIN=stable \
./scripts/oram_vpsbg_test.sh pos-map-bench
```

Measured on VPSBG with the current direct dimensions:

```text
82,813-entry map, 0.316 MiB: scan ~= 14.4 us, scan+update ~= 28.1 us
531,673-entry map, 2.028 MiB: scan ~= 93.7 us, scan+update ~= 180.0 us
885,445-entry map, 3.378 MiB: scan ~= 154.3 us, scan+update ~= 301.5 us
5,061,532-entry map, 19.308 MiB: scan ~= 812.0 us, scan+update ~= 1.72 ms
```

These are, respectively, the staging DELTA index/chunk and FULL index/chunk
position-map sizes with `pack=16`; the canonical DELTA sizes are nearly
identical at 82,808 and 531,611 entries. The scan cost is low enough for the
current 50-access ORAM batch plan. It would become too expensive if every
40-byte chunk were its own ORAM logical block, because the CHUNK position map
would grow by about 16x.

The web ORAM adapter does not use the DPF/Harmony PBC batch planner. By
default it sends one script hash per fixed-budget ORAM request, so each lookup
gets the full remaining chunk budget after its direct INDEX probes. The adapter
has `maxScriptHashesPerRequest` for measured deployments that want to batch
multiple script hashes into one 50-access server request.

## Production-Shaped Server Smoke

This starts an ORAM-enabled localhost server with the real `databases.toml` and
the direct FULL plus canonical DELTA images.

```bash
cd /home/pir/BitcoinPIR
sudo systemctl stop pir-vpsbg

CONFIG_PATH=/home/pir/data/databases.toml \
ORAM_LAYOUT=direct \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
ORAM_DIR=/home/pir/data/oram/checkpoints/948454-direct-pack16-z2-div2-stash128-auth \
ORAM_DB_SPECS='0=/home/pir/data/oram/checkpoints/948454-direct-pack16-z2-div2-stash128-auth 1=/home/pir/data/oram/deltas/940611_948454_canonical-direct-pack16-z2-div2-stash128-auth' \
SMOKE_DB_IDS='0 1' \
PACK=16 DRAIN_PER_ACCESS=2 DIRECT_ACCESS_BUDGET=50 CACHE_LEVELS=0 \
AUTH_STORE=1 \
SERVER_STARTUP_WAIT_SECS=240 \
PORT=18091 \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh server-smoke
```

The `bitcoinpir-oram` crate is vendored through `.cargo/config.toml`, so this
build does not require GitHub credentials on VPSBG. For local ORAM repo
experiments, `PATCH_LOCAL_ORAM=1` temporarily patches the runtime dependency to
`ORAM_REPO` for the smoke build and restores `.cargo/config.toml` and
`Cargo.lock` before exit.

Expected evidence:

```text
Direct ORAM: enabled for db_id=0 ...
Direct ORAM: enabled for db_id=1 ...
cleartext_reject=ok
secure_channel=established
[direct-oram-lookup] db=0 ...
[direct-oram-lookup] db=1 ...
server_smoke=ok
```

Observed db_id=0 direct FULL smoke on VPSBG:

```text
Direct ORAM: enabled for db_id=0 name=main
Direct ORAM index logical_blocks=885445 hash_fns=2 auth_store=true
Direct ORAM chunk logical_blocks=5061532 auth_store=true
cleartext_reject=ok
sev_status=ReportDataMatch
secure_channel=established
result[0].found=false
[direct-oram-lookup] db=0 1 scripthash(es), budget=50 in 706.28ms
```

Observed db_id=0 plus db_id=1 direct smoke on VPSBG after regenerating the
canonical DELTA direct INDEX:

```text
Cuckoo ORAM: disabled
Direct ORAM: enabled for db_id=0 name=main
Direct ORAM index logical_blocks=885445 hash_fns=2 auth_store=true
Direct ORAM chunk logical_blocks=5061532 auth_store=true
Direct ORAM: enabled for db_id=1 name=delta_940611_948454
Direct ORAM index logical_blocks=82808 hash_fns=2 auth_store=true
Direct ORAM chunk logical_blocks=531611 auth_store=true
cleartext_reject=ok
sev_status=ReportDataMatch
secure_channel=established
result[0].found=false
[direct-oram-lookup] db=0 1 scripthash(es), budget=50 in 647.54ms
[direct-oram-lookup] db=1 1 scripthash(es), budget=50 in 698.85ms
server_smoke=ok
```

Observed found-result smoke with two known-present script hashes:

```text
SCRIPT_HASHES='00000003f13983c3a719c42b25eadf94446075b3 000005ac1a192e408d3d1bc2402c7ec909e09153'

db_id=0:
  result[0].found=true
  result[0].utxo_count=1
  result[0].total_balance=10000
  result[0].raw_chunk_data_len=40
  result[1].found=false
  [direct-oram-lookup] db=0 2 scripthash(es), budget=50 in 635.24ms

db_id=1:
  result[0].found=false
  result[1].found=true
  result[1].utxo_count=1
  result[1].total_balance=0
  result[1].raw_chunk_data_len=40
  [direct-oram-lookup] db=1 2 scripthash(es), budget=50 in 575.75ms
```

The first smoke proves encrypted-channel plumbing and not-found behavior. The
found-result smoke additionally exercises direct INDEX match, direct CHUNK read,
raw chunk decoding, and client-side result translation for both FULL and
canonical DELTA.

The helper writes per-db smoke logs:

```text
$LOG_DIR/server-smoke-cleartext-db0.log
$LOG_DIR/server-smoke-encrypted-db0.log
$LOG_DIR/server-smoke-encrypted-db1.log
```

## Production Flags

The production service should use explicit per-db flags:

```bash
--direct-oram-db 0=/home/pir/data/oram/checkpoints/948454-direct-pack16-z2-div2-stash128-auth
--direct-oram-db 1=/home/pir/data/oram/deltas/940611_948454_canonical-direct-pack16-z2-div2-stash128-auth
--direct-oram-drain-per-access 2
--direct-oram-access-budget 50
--direct-oram-cache-levels 0
--direct-oram-auth-store
```

The legacy `--cuckoo-oram-*` flags remain accepted for comparison runs only.
`--cuckoo-oram-dir <dir>` maps to db_id 0.

## Memory And Disk Planning

Disk:

- direct FULL ORAM image: 15G built;
- canonical direct DELTA image: 1.9G built;
- noncanonical direct DELTA staging image: 1.9G built during testing, now
  removed;
- legacy PBC/cuckoo FULL image: about 42G;
- legacy PBC/cuckoo DELTA image: about 4.8G;
- keep at least one extra rebuild window if regenerating in place is not used.

Runtime memory:

- the normal Harmony/DPF mapped DBs still exist unless we later remove mmap
  fallback loading;
- ORAM payload/meta/hash files stay disk-backed;
- the ORAM trusted memory surface is reader/controller state, stash, auth state,
  and optional `cache_levels`;
- `cache_levels=0` is the current conservative default.

With 61 GiB RAM, the upgraded VPSBG host is suitable for the current local
single-machine test plan. Before enabling the systemd service permanently,
measure RSS and page-cache behavior during a production-shaped server smoke.

## Rollback And Crash Notes

The safest recovery policy remains regeneration from the canonical source DB.
If the process crashes after ORAM reads mutate disk-backed pages but before
state/auth-state is persisted, discard and rebuild that ORAM image.

Disk rollback is not prevented by SEV-SNP itself. The authenticated page store
detects tampering relative to the trusted state it has, but a full rollback of
disk image plus trusted state requires an external freshness source or a
regeneration-on-start policy.
