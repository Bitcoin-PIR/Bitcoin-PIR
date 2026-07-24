# Attested Builder Tier 3 UKI

This runbook is for the temporary VPSBG SEV-SNP builder image. It is separate
from the production pir2 Tier 3 UKI. The builder UKI has no sshd, no
cloudflared, and no runit service tree. It boots, mounts `/home/pir/data`, runs
one selected attested-builder workflow, writes SEV-SNP evidence, then powers
off. It supports both a roots-only snapshot build and a v2 re-attestation scan
of retained production serving images. Neither mode produces a new
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

The script also archives every successful UKI build under:

```bash
/home/pir/uki-archive/attested-builder/
```

The archive copy includes the `.efi`, a `.sha256` file, and a `.meta` file with
the builder binary hash, builder git commit, kernel, and kernel version. Treat
`/tmp` as disposable; the archive copy is the retention copy.

If the UKI is generated on a host other than the durable Hetzner host, mirror it
to Hetzner during the build:

```bash
sudo UKI_ARCHIVE_REMOTE=pir-hetzner:/home/pir/uki-archive/attested-builder \
  ./scripts/build_uki_attested_builder_tier3.sh
```

Useful overrides:

```bash
sudo ATTESTED_BUILDER_REPO=/home/pir/bitcoin-pir/attested-builder \
  OUT=/tmp/bpir-attested-builder-tier3.efi \
  ./scripts/build_uki_attested_builder_tier3.sh
```

## Provision v2 re-attestation inputs

This mode scans db 0 and db 1 in sequence. It validates the retained cuckoo,
bin-hash, Merkle, preprocessed INDEX/NTT, and sibling images; binds their exact
hashes into each v2 payload; obtains a new SNP report; and verifies the result
inside the guest. It does not rebuild either database.

```bash
sudo mkdir -p /home/pir/data/attested-builder-runs
sudo tee /home/pir/data/attested-builder/config.env >/dev/null <<'CONFIG'
MODE=reattest-existing-v2
RUN_ID=db-proof-v2-948454
V2_JOB_COUNT=2
V2_DB0_PREDECESSOR_PROOF_DIR=/home/pir/data/attestations/mainnet_948454_sev_snp
V2_DB0_ARTIFACT_DIR=/home/pir/data/checkpoints/948454_deterministic
V2_DB0_OUT_DIR=/home/pir/data/attestations/mainnet_948454_v2_sev_snp
V2_DB1_PREDECESSOR_PROOF_DIR=/home/pir/data/attestations/delta_940611_948454_sev_snp
V2_DB1_ARTIFACT_DIR=/home/pir/data/deltas/940611_948454_canonical_20260615
V2_DB1_OUT_DIR=/home/pir/data/attestations/delta_940611_948454_v2_sev_snp
CONFIG
```

All configured paths must be under `/home/pir/data`. Output directories must
not already exist. Set `V2_JOB_COUNT=1` and use the db0 variables when
intentionally running or retrying only one database.

Successful outputs are written to the two configured output directories, with
convenience links at:

```text
/home/pir/data/attested-builder-runs/v2-db0-latest
/home/pir/data/attested-builder-runs/v2-db1-latest
```

Each directory includes `build-evidence.bin`, the SNP report and report data,
`root-bundle-payload.bin`, `build-evidence.verify.txt`, and `SHA256SUMS`.

## Provision roots-only rebuild inputs

Prepare these while the server is still in Slice 2:

```bash
sudo mkdir -p /home/pir/data/attested-builder/inputs
sudo mkdir -p /home/pir/data/attested-builder-runs
sudo tee /home/pir/data/attested-builder/config.env >/dev/null <<'CONFIG'
SNAPSHOT=/home/pir/data/attested-builder/inputs/txoutset_<height>.dat
MODE=full-build
EXPECTED_MUHASH=<64-byte-Core-display-muhash>
NETWORK_MAGIC=f9beb4d9
ANCHOR_HEIGHT=<height>
# ANCHOR_HASH=<optional-block-hash>
CORE_VERSION=<bitcoind-version-string>
RUN_ID=mainnet_<height>_sev_snp
MIN_FREE_KB=50000000
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
