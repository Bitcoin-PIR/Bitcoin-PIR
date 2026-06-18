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
- startup uses explicit per-db ORAM flags rather than a global ORAM directory.

## Current VPSBG Candidate

Observed upgraded host:

```text
vCPU: 4 AMD EPYC 9745
RAM: 61 GiB
rootfs: 193 GiB, about 115 GiB free after ORAM images
```

Accepted ORAM parameters:

```text
pack = 16
Z = 2
leaf_divisor = 2
stash_capacity = 128
drain_per_access = 2
auth_store = 1
cache_levels = 0
```

Built ORAM images:

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

Verification already performed on the candidate images:

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
`max_stash=0` for FULL and DELTA INDEX/CHUNK with these parameters.

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
ORAM_DIR=/home/pir/data/oram/checkpoints/948454-pack16-z2-div2-stash128-auth \
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
ORAM_DIR=/home/pir/data/oram/checkpoints/948454-pack16-z2-div2-stash128-auth \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
PACK=16 LEAF_DIVISOR=2 BUCKET_SIZE=2 STASH_CAPACITY=128 \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh real-build
```

DELTA:

```bash
DB_DIR=/home/pir/data/deltas/940611_948454_canonical_20260615 \
ORAM_DIR=/home/pir/data/oram/deltas/940611_948454_canonical-pack16-z2-div2-stash128-auth \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
PACK=16 LEAF_DIVISOR=2 BUCKET_SIZE=2 STASH_CAPACITY=128 \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh real-build
```

Verify:

```bash
VERIFY_BINS=1000 ./scripts/oram_vpsbg_test.sh real-verify
```

Do not set `NO_SAVE=1` for persistent ORAM images. ORAM reads mutate page
images and state; skipping state/auth-state save leaves the image unsuitable
for reuse.

## Production-Shaped Server Smoke

This starts an ORAM-enabled localhost server with the real `databases.toml` and
two ORAM images:

```bash
cd /home/pir/BitcoinPIR
sudo systemctl stop pir-vpsbg

CONFIG_PATH=/home/pir/data/databases.toml \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
ORAM_DIR=/home/pir/data/oram/server-smoke \
LOG_DIR=/home/pir/data/oram/server-smoke/logs \
ORAM_DB_SPECS='0=/home/pir/data/oram/checkpoints/948454-pack16-z2-div2-stash128-auth 1=/home/pir/data/oram/deltas/940611_948454_canonical-pack16-z2-div2-stash128-auth' \
SMOKE_DB_IDS='0 1' \
PACK=16 DRAIN_PER_ACCESS=2 CACHE_LEVELS=0 \
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
Cuckoo ORAM: enabled for db_id=0 ...
Cuckoo ORAM: enabled for db_id=1 ...
cleartext_reject=ok
secure_channel=established
[oram-lookup] db=0 ...
[oram-lookup] db=1 ...
server_smoke=ok
```

The helper writes per-db smoke logs:

```text
$LOG_DIR/server-smoke-cleartext-db0.log
$LOG_DIR/server-smoke-encrypted-db0.log
$LOG_DIR/server-smoke-encrypted-db1.log
```

## Production Flags

The production service should use explicit per-db flags:

```bash
--cuckoo-oram-db 0=/home/pir/data/oram/checkpoints/948454-pack16-z2-div2-stash128-auth
--cuckoo-oram-db 1=/home/pir/data/oram/deltas/940611_948454_canonical-pack16-z2-div2-stash128-auth
--cuckoo-oram-pack 16
--cuckoo-oram-drain-per-access 2
--cuckoo-oram-cache-levels 0
--cuckoo-oram-auth-store
```

The legacy `--cuckoo-oram-dir <dir>` remains accepted as db_id 0 only.

## Memory And Disk Planning

Disk:

- FULL ORAM image: about 42G;
- DELTA ORAM image: about 4.8G;
- both images together: about 47G;
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
