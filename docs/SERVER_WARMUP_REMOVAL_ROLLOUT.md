# Server warmup removal rollout

This runbook deploys the removal of the public residency endpoint and the
startup page-touch warmup. The server continues to use memory-mapped database
files, but the operating system decides which pages remain resident. Operators
do not need to preload or prioritize the full dataset in main memory.

The production topology has two different deployment paths:

- `weikeng1.bitcoinpir.org` (Hetzner) runs `pir-primary` and the local
  `pir-secondary` fallback as systemd services.
- `weikeng2.bitcoinpir.org` (VPSBG) runs the ORAM-enabled `unified_server`
  from the measured Tier 3 UKI. The Tier 3 environment intentionally has no
  SSH service.
- The web client deploys from `main` through `.github/workflows/deploy-web.yml`.

## Compatibility and ordering

The frontend and backend changes are wire-compatible during rollout. A new
frontend never sends the retired `0x04` request. A new server rejects an old
client's `0x04` request as unsupported while continuing to serve PIR queries.

The production frontend pins the `unified_server` binary hash for both public
servers and additionally pins the VPSBG launch measurement. Rebuilding the
binary therefore requires a coordinated pin update. Prepare the binary, UKI,
hashes, and pin change before starting the maintenance window.

Use this order:

1. Merge the warmup-removal PR and let the GitHub Pages deployment finish.
   The old servers remain compatible with the new frontend.
2. Build one ORAM-enabled release binary from the exact merge commit. Use this
   same binary for Hetzner and as the input to the Tier 3 UKI build.
3. Build and archive the Tier 3 UKI. Do not upload an image that lacks the
   durable Hetzner archive copy and its `.sha256` and `.meta` sidecars.
4. Prepare, but do not yet merge, the follow-up frontend pin change.
5. Deploy and verify VPSBG first. If it fails, restore the known-good UKI and
   leave Hetzner unchanged.
6. Atomically replace the Hetzner binary, restart its services, and verify it.
7. Merge the prepared pin change and wait for the web deployment.

Between steps 5 and 7 the public frontend can report a binary-pin mismatch for
an updated server. Treat this as a short maintenance window; do not weaken or
disable verification to hide it.

## 1. Prepare an exact-source build

Record the merge commit as `REV` and use a clean checkout on the Hetzner build
host. Do not build from an uncommitted production working tree.

```bash
REV=<warmup-removal-merge-commit>
BUILD=/tmp/bitcoinpir-$REV

git clone https://github.com/Bitcoin-PIR/Bitcoin-PIR.git "$BUILD"
cd "$BUILD"
git checkout "$REV"

RUSTFLAGS="--remap-path-prefix=$PWD=/build/repo --remap-path-prefix=/home/pir=/build" \
SOURCE_DATE_EPOCH=0 \
  cargo build --locked --release -p runtime --features cuckoo-oram \
    --bin unified_server
strip --strip-debug target/release/unified_server
sha256sum target/release/unified_server
```

Keep the resulting binary hash. The binary embedded in the UKI and installed
on Hetzner must be byte-identical.

## 2. Build and retain the Tier 3 UKI

Build from the same clean checkout and binary. The archive helper stores the
UKI, its SHA-256, and metadata under `/home/pir/uki-archive/tier3` on the
Hetzner host. If building anywhere else, set `UKI_ARCHIVE_REMOTE` so the build
fails if the Hetzner mirror cannot be written.

```bash
cd "$BUILD"
sudo env \
  OUT="/tmp/bpir-tier3-warmup-removal-$REV.efi" \
  UKI_ARCHIVE_LABEL="warmup-removal-$REV" \
  BINARY="$BUILD/target/release/unified_server" \
  BPIR_UNIFIED_SERVER_BIN="$BUILD/target/release/unified_server" \
  ./scripts/build_uki_tier3.sh
```

Before upload, verify all of the following:

- the build reports the expected binary SHA-256;
- the initramfs validation finds the required SEV-SNP modules;
- the archive contains the `.efi`, `.efi.sha256`, and `.efi.meta` files;
- a known-good previous Tier 3 UKI is still available for rollback;
- the new UKI SHA-256 and predicted or captured launch measurement are
  recorded with the release commit.

## 3. Clean obsolete database configuration

`priority` and `warmup` are no longer server configuration fields. Existing
unknown TOML fields are ignored, so they do not block the new binary, but remove
them to prevent operators from assuming they still affect memory residency.

On Hetzner, back up and edit `/home/pir/data/databases.toml` before restarting
the services. On VPSBG, edit the rootfs copy during a planned `UKI: None`
maintenance boot, because the Tier 3 environment has no SSH service.

```bash
cp -a /home/pir/data/databases.toml \
  /home/pir/data/databases.toml.before-warmup-removal
sed -i -E '/^[[:space:]]*(priority|warmup)[[:space:]]*=/d' \
  /home/pir/data/databases.toml
```

This cleanup does not require loading the database into memory and does not
change the database files or Merkle roots.

## 4. Prepare the attestation pin update

Prepare a small follow-up PR that updates:

- `PIR1_PIN.binarySha256Hex` in `web/src/attest-pin.ts`;
- `PIR2_TIER3_PIN.binarySha256Hex` in `web/src/attest-pin.ts`;
- `PIR2_TIER3_PIN.measurementHex` in `web/src/attest-pin.ts`;
- the expected binary and measurement defaults in
  `scripts/verify_oram_tier3_deploy.sh`.

Do not merge this follow-up until both production endpoints run the new binary
and VPSBG reports the new measurement.

## 5. Deploy VPSBG first

Use the VPSBG measured-boot portal to upload the new archived UKI and reboot.
Tier 3 has no SSH by design, so verify through the public encrypted endpoint.

```bash
EXPECT_BINARY=<new-binary-sha256> \
EXPECT_MEASUREMENT=<new-launch-measurement> \
  ./scripts/verify_oram_tier3_deploy.sh
```

The gate must pass attestation, VCEK/ARK validation, `REPORT_DATA` binding,
encrypted channel setup, and direct ORAM lookup smoke tests for database IDs 0
and 1. If the tunnel does not recover or a gate fails, restore the previous UKI
through the portal before proceeding.

## 6. Deploy Hetzner

Copy the exact binary used for the UKI to a temporary path, verify its hash,
then rename it over the service path. Keep the previous binary until the full
rollout is verified.

```bash
install -m 0755 "$BUILD/target/release/unified_server" \
  /home/pir/BitcoinPIR/target/release/unified_server.new
sha256sum /home/pir/BitcoinPIR/target/release/unified_server.new

cp -a /home/pir/BitcoinPIR/target/release/unified_server \
  /home/pir/BitcoinPIR/target/release/unified_server.before-warmup-removal
mv /home/pir/BitcoinPIR/target/release/unified_server.new \
  /home/pir/BitcoinPIR/target/release/unified_server

systemctl restart pir-primary pir-secondary
systemctl is-active pir-primary pir-secondary
journalctl -u pir-primary -n 80 --no-pager
journalctl -u pir-secondary -n 80 --no-pager
```

Confirm both services load the catalog, listen on their expected ports, and do
not log repeated restarts. Then run the public DPF, HarmonyPIR, and OnionPIR
integration smoke tests.

## 7. Publish pins and verify the web client

After both endpoints report the new binary hash and VPSBG reports the new
measurement, merge the prepared pin PR. Wait for the GitHub Pages workflow and
the live integration workflow to pass, then verify:

- the warmup/residency control is absent from `www.bitcoinpir.org`;
- both servers show successful basic verification;
- DPF and HarmonyPIR complete across both servers;
- OnionPIR completes against Hetzner;
- direct ORAM lookup completes against VPSBG;
- retired opcode `0x04` returns an unsupported-request error rather than data.

Keep the previous Hetzner binary, UKI, configuration backup, and new archive
metadata until these checks pass. Roll back binary, configuration, and UKI as a
single release set if verification fails.
