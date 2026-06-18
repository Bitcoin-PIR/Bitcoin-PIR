# ORAM VPSBG Non-TEE Test Run

This runbook prepares a VPSBG/Slice-2 test of the ORAM backend without relying
on Tier-3 UKI boot or SEV-SNP attestation. The goal is to measure the real host
budget for ORAM image build/reopen/verify/server plumbing while avoiding the
memory pressure of the normal PIR services.

## Safety Boundary

Do not run the full ORAM build/verify while the production `pir-vpsbg` query
service is active. The production service maps the PIR database and may keep
additional page cache hot. ORAM build/verify also reads the same database and
writes a large ORAM directory.

For the first real run:

- use Slice 2 / rootfs SSH, not Tier 3;
- stop `pir-vpsbg` before real DB modes;
- keep `cloudflared` running only if you need connectivity;
- use one `--data-dir` checkpoint or delta, not `/home/pir/data/databases.toml`;
- do not start Harmony hint pools;
- keep OnionPIR disabled;
- compile with `CARGO_JOBS=1` on the VPSBG host.

The helper script refuses real DB modes while `pir-vpsbg` is active unless
`ALLOW_PIR_SERVICE_ACTIVE=1` is set.

## Repos

Expected layout on VPSBG:

```bash
/home/pir/BitcoinPIR
/home/pir/bitcoin-pir/oram
/home/pir/data/checkpoints/<height>
```

Both repos should be on their remote `main` branches for the production-shaped
test. The BitcoinPIR main repo currently pins `bitcoinpir-oram` through the
runtime `cuckoo-oram` feature, but the helper also runs `oramctl` directly from
the standalone ORAM repo.

## Phase 0: Tiny Plumbing Smoke

This uses a synthetic fixture and is safe to run before stopping production
services.

```bash
cd /home/pir/BitcoinPIR
ORAM_REPO=/home/pir/bitcoin-pir/oram \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh tiny-smoke
```

It verifies:

- tiny DPF/Harmony-shaped cuckoo fixture generation;
- authenticated split-store Circuit ORAM image build;
- ORAM bin verification;
- ORAM-enabled `unified_server` startup on localhost;
- cleartext ORAM rejection;
- encrypted-channel ORAM lookup.

## Phase 1: Real DB Preflight

Pick exactly one checkpoint or delta directory. Do not pass
`/home/pir/data/databases.toml`; that would cause server-side tests to map more
than one database.

```bash
cd /home/pir/BitcoinPIR
sudo systemctl stop pir-vpsbg

DB_DIR=/home/pir/data/checkpoints/940611 \
ORAM_DIR=/home/pir/data/oram-test/940611-pack16-z2-div4-auth \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh preflight
```

Default real-mode thresholds are conservative:

- `REAL_MIN_FREE_GIB=80`
- `REAL_MIN_MEM_GIB=12`
- `SERVER_MIN_MEM_GIB=16`

Override only for an intentional experiment:

```bash
ALLOW_LOW_DISK=1 ALLOW_LOW_MEMORY=1 ./scripts/oram_vpsbg_test.sh preflight
```

## Phase 2: Build Authenticated ORAM Images

Default parameters:

```text
pack = 16
Z = 2
leaf_divisor = 4
drain_per_access = 2
auth_store = 1
cache_levels = 0
```

Run:

```bash
DB_DIR=/home/pir/data/checkpoints/940611 \
ORAM_DIR=/home/pir/data/oram-test/940611-pack16-z2-div4-auth \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh real-build
```

The script writes logs into:

```text
$ORAM_DIR/logs/size-cuckoo.log
$ORAM_DIR/logs/build-circuit.log
$ORAM_DIR/logs/du-after-build.log
```

Record:

- total ORAM directory size;
- INDEX metadata/payload/state sizes;
- CHUNK metadata/payload/state sizes;
- auth hash image and auth state sizes;
- elapsed build time;
- peak memory if you are watching with `htop` / `vmstat`.

## Phase 3: Verify ORAM Images

Run random cuckoo-bin verification against the original DB bytes:

```bash
DB_DIR=/home/pir/data/checkpoints/940611 \
ORAM_DIR=/home/pir/data/oram-test/940611-pack16-z2-div4-auth \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
VERIFY_BINS=1000 \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh real-verify
```

Then benchmark random ORAM reads:

```bash
DB_DIR=/home/pir/data/checkpoints/940611 \
ORAM_DIR=/home/pir/data/oram-test/940611-pack16-z2-div4-auth \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
BENCH_OPS=1000 \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh real-bench
```

Do not set `NO_SAVE=1` unless the ORAM directory is disposable. ORAM reads
mutate image pages; skipping state/auth-state save leaves that image unsuitable
for reuse.

## Phase 4: Optional Server Smoke

This is the highest-memory local test because the server maps the real DB and
opens the ORAM images. It still avoids the production topology:

- one `--data-dir`;
- `--disable-onion`;
- `--serve-queries` only;
- no `--pool-size`;
- no `--config`;
- localhost port only.

```bash
DB_DIR=/home/pir/data/checkpoints/940611 \
ORAM_DIR=/home/pir/data/oram-test/940611-pack16-z2-div4-auth \
ORAM_REPO=/home/pir/bitcoin-pir/oram \
PORT=18091 \
CARGO_JOBS=1 \
./scripts/oram_vpsbg_test.sh server-smoke
```

By default the smoke queries a synthetic not-found scripthash:

```text
4242424242424242424242424242424242424242
```

To query known hashes:

```bash
SCRIPT_HASHES="hash1 hash2 hash3" ./scripts/oram_vpsbg_test.sh server-smoke
```

The expected server-side evidence is:

```text
[oram-lookup] db=0 N scripthash(es) ...
```

## What To Decide From The Run

The VPSBG run should answer:

1. Is `pack=16, Z=2, leaf_divisor=4, auth_store=1` acceptable for disk size?
2. Is startup regeneration feasible for the service restart budget?
3. Does `TieredMerklePageStore` add tolerable latency on the target NVMe?
4. Is `cache_levels=0` good enough, or does a small trusted top cache help?
5. Can server-smoke run without colliding with production PIR memory needs?

If Phase 2 and Phase 3 pass but Phase 4 is too memory-heavy, the next design
step is not more ORAM algorithm work. It is deployment shaping: keep ORAM as a
separate experimental backend process or run it in a maintenance window until
we have VPSBG memory headroom.
