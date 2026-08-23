# Attested Builder Tier 3 UKI

This is the **producer** UKI used by Flow H in
[Production operations](PRODUCTION_OPERATIONS.md). It is not the
serving pir2 UKI (Flow E, `scripts/build_uki_tier3.sh`). Placing
`config.env` and collecting outputs is Flow F
(`scripts/vpsbg-data-disk.sh`), not the VPSBG portal.

What the producer covers (DPF/Harmony INDEX+CHUNK, Onion v2, Direct
ORAM inputs, MuHash, BuildEvidence v2, SEV-SNP) and what it does not
(Harmony hints, BHTM, k-of-n builder quorum, Nitro) is the attested-builder
README, not this UKI runbook.

This runbook is for the one-shot VPSBG SEV-SNP builder image. The
builder UKI has no sshd, no cloudflared, and no runit service tree. It
boots, mounts `/home/pir/data`, runs one selected attested-builder
workflow, writes SEV-SNP evidence, then powers off. The reviewed
producer commit is the value bound by
`PRODUCTION_ORAM_DB_PROOF_V2_PINS` in
[`web/src/attest-pin.ts`](../web/src/attest-pin.ts) and by
`scripts/build_uki_attested_builder_tier3.sh`; do not copy it into
other prose. That producer provides native predecessor-free full-build
V2 pipelines for both snapshots and deltas.
`MODE=native-full-build-v2-snapshot` and
`MODE=native-full-build-v2-delta` stage the complete server-loadable database,
typed Direct ORAM inputs/manifest, BuildEvidence V2 and SNP report as one
output. The runner verifies the evidence and refuses to publish `latest` or an
eligibility claim unless it observes V2, `evidence_mode=full_build`, and no
predecessor hashes. `MODE=reattest-existing-v2` remains a proof migration tool
only and is ineligible for production TEE-ORAM.

## Build the producer UKI

The standalone `attested-builder` checkout is expected at:

```bash
/home/pir/bitcoin-pir/attested-builder
```

Build on an approved Linux host that already has that checkout
(stock-rootfs SSH is Flow F if that host is the VPSBG guest):

```bash
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

The status file deliberately reports `direct_oram_eligible=no`. Re-attestation
cannot legally add `[direct_oram]` after the predecessor artifacts have been
built: doing so after BuildEvidence or quote creation would invalidate the
commitment. These outputs may continue to serve non-ORAM proof use cases, but
production TEE-ORAM must reject them.

## Provision a native full-build V2 generation

Use the snapshot mode for a new full database:

Prepare these on the stock rootfs (Flow F) before attaching the builder UKI:

```bash
sudo mkdir -p /home/pir/data/attested-builder/inputs
sudo mkdir -p /home/pir/data/attested-builder-runs
sudo tee /home/pir/data/attested-builder/config.env >/dev/null <<'CONFIG'
SNAPSHOT=/home/pir/data/attested-builder/inputs/txoutset_<height>.dat
MODE=native-full-build-v2-snapshot
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

For a delta, replace the snapshot-specific fields with:

```text
MODE=native-full-build-v2-delta
FROM_SNAPSHOT=/home/pir/data/attested-builder/inputs/txoutset_<from-height>.dat
FROM_EXPECTED_MUHASH=<64-byte-Core-display-muhash>
FROM_ANCHOR_HEIGHT=<from-height>
TO_SNAPSHOT=/home/pir/data/attested-builder/inputs/txoutset_<to-height>.dat
TO_EXPECTED_MUHASH=<64-byte-Core-display-muhash>
TO_ANCHOR_HEIGHT=<to-height>
# TO_ANCHOR_HASH=<optional-block-hash>
NETWORK_MAGIC=f9beb4d9
CORE_VERSION=<bitcoind-version-string>
RUN_ID=delta_<from-height>_<to-height>_sev_snp
MIN_FREE_KB=50000000
```

The baked runner accepts only those two native build modes or the separately
ineligible re-attestation mode. For a native build it exports
`ROOTS_ONLY=0`, `STAGE_SERVER_DB=1`, `RUN_ONION_FFI=1`, and V2 evidence/quote
settings before invoking the measured snapshot or delta pipeline. The producer
must finish the server database, Direct inputs and exact typed manifest before
creating BuildEvidence and the SNP report.

### Native producer acceptance gate

Do not remove the runner's final version/mode gate merely because the typed
manifest is present. The pinned external producer now supplies the native
full-build V2 path, and producer review requires that it:

- creates canonical BuildParamsV2 and the v2 root payload inside the measured
  full snapshot or delta pipeline;
- emits BuildEvidence v2 with `evidence_mode=full_build` and no predecessor
  evidence/report hashes;
- stages and hashes the final typed server manifest before evidence;
- regenerates and validates the contents of both database and all-artifacts
  manifest sidecars after all payload/manifest changes;
- derives v2 `REPORT_DATA` and emits the raw SNP report; and
- has migration tests showing that v1 and `reattest_existing` remain rejected
  while a golden full-build-v2 artifact is accepted.

The measured runner enforces the output/evidence properties at runtime;
producer migration tests are review evidence, not an in-guest runtime
assertion. The release/public-proof workflow separately retains and pins the
matching AMD ARK/ASK/VCEK certificate chain; those certificates are not native
builder output.

Changing BitcoinPIR's wrapper alone cannot satisfy this contract, and a future
producer commit requires its own review and UKI identity update.
The measured strict `oramctl` rebuild also rejects anything other than
predecessor-free full-build-v2 evidence as a defense-in-depth gate.

This mode retains the complete server database and build intermediates. The
staged `server-db` normally uses hard links because it is under the same
`OUT_DIR`, but that does not make `MIN_FREE_KB=50000000` a capacity estimate.
Before boot, calculate the snapshot, database, Onion/Merkle, direct-input and
temporary materialization peak for that height with `df`/`du`, and raise
`MIN_FREE_KB` accordingly. A builder UKI run that cannot demonstrate sufficient
space must be treated as failed, not retried by deleting proof inputs.

### Native delta path

The baked UKI includes both `build-snapshot-database.sh` and
`build-delta-database.sh`. The delta mode consumes the two exact Core snapshots,
checks both endpoint MuHash/height inputs, stages a complete delta `server-db`
and Direct input set, and creates typed predecessor-free BuildEvidence V2 only
after those bytes are final. The retained `940611 -> 948454` native output is
the db1 evidence/source bundle used by the current source verifier.

That capability removes the old producer-format blocker; it does not authorize
a new build, measured-boot switch, database activation or policy release. A new
full snapshot may replace db1 only after an explicit database/query-plan
migration; it is not an automatic substitute for the current delta.

## Boot and Recover

Building/uploading the UKI, switching measured boot and rebooting are separate
production operations and require explicit authorization; the source runbook
or a prepared config does not grant it.

Upload and switch with Flow E commands
(`scripts/vpsbg-measured-boot.sh upload` then `switch`) as their own
authorization. The builder image powers off after success or failure.

After it powers off:

1. Flow F `open` (detach `{"kernel_image_id":null}`, stock rootfs, SSH).
2. Collect outputs from the configured `OUT_DIR`. A successful native V2
   run updates `/home/pir/data/attested-builder-runs/latest/` only after
   its evidence gate passes.
3. Flow F `close` with the recorded **runtime** image id when the guest
   should serve again. Do not leave the builder UKI attached.

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
oram-direct-inputs/direct-inputs.sha256
```

For either native mode, `server-db/MANIFEST.toml` is the server-loadable
manifest with a typed `[direct_oram]` section. The producer commits that final
manifest digest—not a pre-augmentation digest—and the runner requires
V2/full-build/no-predecessor evidence before shutdown is considered successful.
Re-attestation output remains ineligible even when its retained serving files
are otherwise valid.

The runner also writes coarse status/log files under:

```bash
/home/pir/data/attested-builder-runs/builder-tier3-*.status
/home/pir/data/attested-builder-runs/builder-tier3-init.log
```

## Verify After Boot

On the stock rootfs or another host with the same attested-builder binary:

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
database/artifact manifests, root-bundle payload hash, the final typed
server-database manifest hash, and the baked builder binary hash.
