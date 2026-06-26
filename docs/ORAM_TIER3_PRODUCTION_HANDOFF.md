# ORAM Tier 3 Production Handoff

Status as of 2026-06-27: the strict-source-bound ORAM-enabled Tier 3 UKI is
live on pir2. The SEV-SNP report, binary pin, AMD VCEK chain, encrypted
channel, and direct ORAM lookup smoke tests all pass against
`wss://weikeng2.bitcoinpir.org`.

## Source Revisions

BitcoinPIR:

```text
f402466a Pin runtime ORAM dependency to source-binding build
a8863f82 Mirror ORAM clippy fix
cf5e3b13 Wire direct ORAM source evidence into attested builds
```

ORAM dependency:

```text
https://github.com/Bitcoin-PIR/oram.git
5f366492504d8e853cbd60d25a6adbf021a78746
```

The ORAM rev above exists on GitHub and is the value pinned in
`runtime/Cargo.toml`, `Cargo.lock`, and `.cargo/config.toml`.

## Final Artifact

Local UKI:

```text
~/Downloads/bpir-tier3-oram-f402466a-20260626T164616Z-3ef8249b673e.efi
```

Remote build-host copy:

```text
pir-hetzner:/tmp/bpir-tier3-oram-f402466a.efi
```

Durable build-host archive:

```text
pir-hetzner:/home/pir/uki-archive/tier3/oram-f402466a/
```

Hashes:

```text
unified_server sha256:
233541886714f1eec9ca90cf876c33774b9fd07cae2d6e3a2c9d555ef5e53fb3

UKI sha256:
3ef8249b673efc96ea5cdc74671871558b35948beeb6411186226b367fb40a60
```

The final initrd was unpacked on `pir-hetzner`; the baked
`usr/local/bin/unified_server` hash matched the clean release binary hash above.

Live attested MEASUREMENT:

```text
f0d449e04c27ba2bf5b96790d58d9b1d5b789c7c560f16bc9d3f8bb26c78391ae7d3bb55deeea1bf7ef07c1671ad8da0
```

## Build Recipe

The final binary and UKI were built on `pir-hetzner` from a clean checkout:

```bash
export PATH="/home/pir/.cargo/bin:$PATH"
BUILD=/tmp/bpir-oram-runtime-f402466
git clone https://github.com/Bitcoin-PIR/Bitcoin-PIR.git "$BUILD"
cd "$BUILD"
git checkout a8863f82cd880d911fe49a7186b0ad4c0b6139d7
git fetch /tmp/bpir-oram-runtime-f402466.bundle \
    refs/heads/codex/oram-runtime-5f36649:refs/heads/codex/oram-runtime-5f36649
git checkout f402466af1ee21d02e0a65b457ad338ceb1216c0
RUSTFLAGS="--remap-path-prefix=$PWD=/build/repo --remap-path-prefix=/home/pir=/build" \
SOURCE_DATE_EPOCH=0 cargo build --locked --release -p runtime --features cuckoo-oram --bin unified_server
strip --strip-debug target/release/unified_server

OUT=/tmp/bpir-tier3-oram-f402466a.efi \
UKI_ARCHIVE_LABEL=oram-f402466a \
BINARY="$PWD/target/release/unified_server" \
BPIR_UNIFIED_SERVER_BIN="$PWD/target/release/unified_server" \
./scripts/build_uki_tier3.sh
```

The build used kernel `7.0.0-15-generic` and confirmed these SEV-SNP modules in
the initramfs:

```text
ccp
sev-guest
tsm_report
```

## Verified Gates

Local and build-host checks completed:

```text
cargo check --locked -p runtime --features cuckoo-oram --bin unified_server
cargo check --locked --release -p runtime --features cuckoo-oram --bin unified_server
cargo test --locked -p runtime --features cuckoo-oram --bin unified_server direct_oram
cargo test --locked -p pir-runtime-core oram_lookup
cargo test --locked -p pir-sdk-client lookup_raw_ignores_trailing_response_padding
rustfmt --edition 2021 --check pir-runtime-core/src/protocol.rs pir-sdk-client/src/oram.rs runtime/src/bin/unified_server.rs
git diff --check
```

The source bundle and one-commit patch are archived next to the UKI:

```text
bpir-oram-runtime-f402466.bundle
f402466a.patch
```

The important query privacy properties are still:

- direct ORAM lookup slots are padded before index lookup;
- every padded slot contributes to the public index-read budget;
- chunk reads are padded with dummy reads to the public access budget;
- direct ORAM response frames are padded to the public chunk-byte budget inside
  the encrypted channel.

## Live Verification

Live checks were run on 2026-06-27 after uploading
`bpir-tier3-oram-f402466a-20260626T164616Z-3ef8249b673e.efi` through the VPSBG measured-boot
portal.

```bash
./scripts/verify_oram_tier3_deploy.sh
```

The wrapper verifies:

```text
server:              wss://weikeng2.bitcoinpir.org
expected measurement: f0d449e04c27ba2bf5b96790d58d9b1d5b789c7c560f16bc9d3f8bb26c78391ae7d3bb55deeea1bf7ef07c1671ad8da0
expected binary:     233541886714f1eec9ca90cf876c33774b9fd07cae2d6e3a2c9d555ef5e53fb3
expected ARK fp:     1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a
```

Observed live values:

```text
binary_sha256:
233541886714f1eec9ca90cf876c33774b9fd07cae2d6e3a2c9d555ef5e53fb3

git_rev:
f402466af1ee21d02e0a65b457ad338ceb1216c0

channel pubkey for this boot:
73d8aa08c98c0047e9031fbf342f08018ced95816d594eae1d28863d1df97b08

REPORT_DATA binding:
ReportDataMatch

db_id=0 manifest root:
d13ae468118366c1c1ad05bd069092cd7fa079ac205c9043d38e2954efdd7848

db_id=1 manifest root:
c816f067117bca98256ee246c4469591ee8f537b2271d65b38d1536a70887963
```

The wrapper passed both `bpir-admin attest` and `bpir-admin channel-test`.
The attest step reported `ReportDataMatch`; the expected `REPORT_DATA` value is
nonce-dependent and recomputed by the verifier for each run. The channel test
verified the VCEK chain, matched the pinned ARK fingerprint, completed the
encrypted handshake, and completed ping/get_info checks.

Direct ORAM lookup smoke tests also passed over the encrypted channel:

```bash
HASH=4242424242424242424242424242424242424242
cargo run --locked -p pir-sdk-client --example oram_local_smoke -- \
  --server wss://weikeng2.bitcoinpir.org --db-id 0 --padded-slots 25 "$HASH"
cargo run --locked -p pir-sdk-client --example oram_local_smoke -- \
  --server wss://weikeng2.bitcoinpir.org --db-id 1 --padded-slots 25 "$HASH"
```

```text
db_id=0: sev_status=ReportDataMatch, secure_channel=established, found=false
db_id=1: sev_status=ReportDataMatch, secure_channel=established, found=false
```

`found=false` is expected for the all-`42` smoke hash; the important signal is
that the padded direct ORAM request and response complete successfully for both
production databases.

## Redeployment / Reverification

The live artifact is:

```text
~/Downloads/bpir-tier3-oram-f402466a-20260626T164616Z-3ef8249b673e.efi
```

Portal path:

```text
VPSBG dashboard -> Confidentiality & Protection -> Advanced: Measured Boot
-> UKI -> Upload -> Save & Reboot
```

After any reboot or re-upload, rerun:

```bash
./scripts/verify_oram_tier3_deploy.sh
```

If a new binary or UKI is built, capture the new SEV-SNP MEASUREMENT from
`attest` and update the web/runtime pins only after attest, channel-test, and
ORAM lookup smoke tests pass.

## Recovery

If the upload keeps pir2 at HTTP 530, use:

```text
docs/PHASE3_SLICE3_RECOVERY.md
```

Tier 3 has no SSH by design. Recovery is through the VPSBG portal by uploading a
known-good Slice 2 UKI or selecting "None" in measured boot to return to the
rootfs boot path.
