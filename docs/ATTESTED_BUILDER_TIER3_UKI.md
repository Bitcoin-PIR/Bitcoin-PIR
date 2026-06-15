# Attested Builder Tier 3 UKI

This runbook is for the temporary VPSBG SEV-SNP builder image. It is separate
from the production pir2 Tier 3 UKI. The builder UKI has no sshd, no
cloudflared, and no runit service tree. It boots, mounts `/home/pir/data`, runs
`pir-attested-builder` once in roots-only mode, writes Merkle roots, the root
payload, manifests, and SEV-SNP evidence, then powers off. It does not produce a
server-loadable BitcoinPIR database.

## Build the UKI on VPSBG Slice 2

The standalone `attested-builder` checkout is expected at:

```bash
/home/pir/bitcoin-pir/attested-builder
```

Build:

```bash
ssh vpsbg-pir
cd /home/pir/BitcoinPIR
sudo ./scripts/build_uki_attested_builder_tier3.sh
```

The output UKI is:

```bash
/tmp/bpir-attested-builder-tier3.efi
```

Useful overrides:

```bash
sudo ATTESTED_BUILDER_REPO=/home/pir/bitcoin-pir/attested-builder \
  OUT=/tmp/bpir-attested-builder-tier3.efi \
  ./scripts/build_uki_attested_builder_tier3.sh
```

## Provision Runtime Inputs

Prepare these while the server is still in Slice 2:

```bash
sudo mkdir -p /home/pir/data/attested-builder/inputs
sudo mkdir -p /home/pir/data/attested-builder-runs
sudo tee /home/pir/data/attested-builder/config.env >/dev/null <<'CONFIG'
SNAPSHOT=/home/pir/data/attested-builder/inputs/txoutset_<height>.dat
EXPECTED_MUHASH=<64-byte-Core-display-muhash>
NETWORK_MAGIC=f9beb4d9
ANCHOR_HEIGHT=<height>
# ANCHOR_HASH=<optional-block-hash>
CORE_VERSION=<bitcoind-version-string>
RUN_ID=mainnet_<height>_sev_snp
MIN_FREE_KB=50000000
# Optional read-only progress API while the UKI is running.
# PROGRESS_HTTP=1
# PROGRESS_HTTP_PORT=18080
# PROGRESS_INTERVAL_SECONDS=15
# PROGRESS_LOG_LINES=120
CONFIG
```

`SNAPSHOT`, optional reference manifests, `OUT_BASE`, and `OUT_DIR` must live
under `/home/pir/data` inside the builder UKI. This is deliberate: the initramfs
only exposes that rootfs subtree to the builder.

The config parser accepts plain `KEY=VALUE` lines only; it does not execute the
file as shell. This keeps the unmeasured rootfs config in the role of data
input, not runtime code.

The baked runner exports `ROOTS_ONLY=1`, `STAGE_SERVER_DB=0`, and
`RUN_ONION_FFI=0`. The build still creates transient cuckoo/bin-hash files while
computing the commitments, but Merkle sibling/tree-top artifacts are skipped and
large intermediate files are removed as soon as their roots no longer need them.

## Optional Read-Only Progress API

For long mainnet runs, the UKI can expose a tiny read-only status surface. Enable
it in `config.env` before booting the UKI:

```bash
PROGRESS_HTTP=1
PROGRESS_HTTP_PORT=18080
PROGRESS_INTERVAL_SECONDS=15
PROGRESS_LOG_LINES=120
```

When DHCP succeeds in the initramfs, the UKI serves static files on:

```bash
http://<vpsbg-ip>:18080/status.json
http://<vpsbg-ip>:18080/status.txt
http://<vpsbg-ip>:18080/log-tail.txt
```

The endpoint is intentionally static and read-only: it has no shell, no control
commands, no upload path, and no write API. A background heartbeat refreshes the
files under `/run/bpir-builder-progress/www` and also updates the persistent
status file under `/home/pir/data/attested-builder-runs/`.

Example polling command:

```bash
watch -n 15 'curl -fsS http://87.120.8.198:18080/status.json || true'
```

This is a best-effort observability path. If VPSBG does not expose networking to
the temporary UKI, the builder still proceeds normally; use the VPSBG console
heartbeat during the run and inspect `builder-tier3-*.status` plus
`builder-tier3-init.log` after switching back to Slice 2.

## Boot and Recover

Upload `/tmp/bpir-attested-builder-tier3.efi` in the VPSBG Measured Boot UI and
reboot. The image powers off after success or failure.

After it powers off:

1. Switch Measured Boot back to `None`.
2. Boot the normal Slice 2 rootfs.
3. Collect outputs from:

```bash
/home/pir/data/attested-builder-runs/latest/
```

Important files:

```bash
build-summary.txt
build-evidence.bin
build-evidence.report-data
build-evidence.sev-snp-report.bin
build-evidence.verify.txt
root-bundle-payload.bin
database.manifest.sha256
all-artifacts.manifest.sha256
server-db/MANIFEST.toml
```

`server-db/MANIFEST.toml` is a roots-only evidence manifest in this UKI. It
records the bucket/onion super roots plus hashes of the small retained files, so
`write-build-evidence` can bind it. It is deliberately marked
`server_loadable = false` and must not be used as a production server DB.

The runner also writes coarse status/log files under:

```bash
/home/pir/data/attested-builder-runs/builder-tier3-*.status
/home/pir/data/attested-builder-runs/builder-tier3-init.log
```

## Verify After Boot

On Slice 2 or another host with the same attested-builder binary:

```bash
pir-attested-builder verify-build-evidence \
  /home/pir/data/attested-builder-runs/latest/build-evidence.bin \
  --snapshot /home/pir/data/attested-builder/inputs/txoutset_<height>.dat \
  --builder-bin /path/to/pir-attested-builder \
  --payload /home/pir/data/attested-builder-runs/latest/root-bundle-payload.bin \
  --database-manifest /home/pir/data/attested-builder-runs/latest/database.manifest.sha256 \
  --all-artifacts-manifest /home/pir/data/attested-builder-runs/latest/all-artifacts.manifest.sha256 \
  --server-db-manifest /home/pir/data/attested-builder-runs/latest/server-db/MANIFEST.toml \
  --expected-muhash <64-byte-Core-display-muhash> \
  --expected-anchor-height <height> \
  --expected-anchor-hash <block-hash> \
  --sev-snp-report /home/pir/data/attested-builder-runs/latest/build-evidence.sev-snp-report.bin
```

The SEV-SNP quote's `REPORT_DATA` binds the 64-byte report data derived from
`build-evidence.bin`. The evidence file binds the snapshot hash, Core MuHash,
roots-only manifests, root-bundle payload hash, roots-only manifest hash, and
the baked builder binary hash.
