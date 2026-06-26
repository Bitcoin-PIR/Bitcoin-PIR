# ORAM Tier 3 Production Handoff

Status as of 2026-06-26: the ORAM-enabled Tier 3 UKI is live on pir2. The
SEV-SNP report, binary pin, AMD VCEK chain, encrypted channel, and direct ORAM
lookup smoke tests all pass against `wss://weikeng2.bitcoinpir.org`.

## Source Revisions

BitcoinPIR:

```text
668dd36b Correct ORAM dependency pin
8ee1bed4 Allow Tier 3 UKI builds to select server binary
f57debfd Pad direct ORAM lookup responses
1a3d18f0 Pin hardened ORAM backend for runtime
```

ORAM dependency:

```text
https://github.com/Bitcoin-PIR/oram.git
11c66c337b9a6130cdffd69462b06b34deedcd64
```

The ORAM rev above exists on GitHub and is the value pinned in
`runtime/Cargo.toml`, `Cargo.lock`, and `.cargo/config.toml`.

## Final Artifact

Local UKI:

```text
deploy/uki/bpir-tier3-oram-668dd36b.efi
```

Remote build-host copy:

```text
pir-hetzner:/tmp/bpir-tier3-oram-668dd36b.efi
```

Durable build-host archive:

```text
pir-hetzner:/home/pir/uki-archive/tier3/oram-668dd36b/
```

Hashes:

```text
unified_server sha256:
457590cf4e17221c709be806a40d7d68a7f0978e365789cbe37f4a4d1e9aaaf1

UKI sha256:
718c7728142f9a3a1c6663711853d1b51ee14fde62debc8d2fb1c8662855b18b
```

The final initrd was unpacked on `pir-hetzner`; the baked
`usr/local/bin/unified_server` hash matched the clean release binary hash above.

Live attested MEASUREMENT:

```text
1e6256d9c01562b04470081d260d878436340fc406bf7d5567e5824c9b94ffcfd2c95dbd2648e7030f75023223912746
```

## Build Recipe

The final binary and UKI were built on `pir-hetzner` from a clean checkout:

```bash
export PATH="/home/pir/.cargo/bin:$PATH"
BUILD=/tmp/bpir-oram-prod-668dd36b
git clone https://github.com/Bitcoin-PIR/Bitcoin-PIR.git "$BUILD"
cd "$BUILD"
git checkout 668dd36b
cargo build --locked --release -p runtime --features cuckoo-oram --bin unified_server

OUT=/tmp/bpir-tier3-oram-668dd36b.efi \
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

The ORAM release assembly audit passed on `pir-hetzner` with Rust `1.94.1`:

```bash
export PATH="/home/pir/.cargo/bin:$PATH"
export RUSTUP_TOOLCHAIN=1.94.1
cd /tmp/oram-audit-11c66c3
./scripts/audit-ct-assembly.sh
```

The audit still prints non-fatal review notes for global `memset` references and
variable shifts. Those are not failures from the audit script. The important
query privacy properties are still:

- direct ORAM lookup slots are padded before index lookup;
- every padded slot contributes to the public index-read budget;
- chunk reads are padded with dummy reads to the public access budget;
- direct ORAM response frames are padded to the public chunk-byte budget inside
  the encrypted channel.

## Live Verification

Live checks were run on 2026-06-26 after uploading
`deploy/uki/bpir-tier3-oram-668dd36b.efi` through the VPSBG measured-boot
portal.

```bash
./scripts/verify_oram_tier3_deploy.sh
```

The wrapper verifies:

```text
server:              wss://weikeng2.bitcoinpir.org
expected measurement: 1e6256d9c01562b04470081d260d878436340fc406bf7d5567e5824c9b94ffcfd2c95dbd2648e7030f75023223912746
expected binary:     457590cf4e17221c709be806a40d7d68a7f0978e365789cbe37f4a4d1e9aaaf1
expected ARK fp:     1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a
```

Observed live values:

```text
binary_sha256:
457590cf4e17221c709be806a40d7d68a7f0978e365789cbe37f4a4d1e9aaaf1

git_rev:
668dd36b812f51f8c6a63af6fd3025cc07455bfd

channel pubkey for this boot:
77bbbc1064d3907b17a7a6c95d80a9a671a130304f954e75a1edc738b90b8f06

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
deploy/uki/bpir-tier3-oram-668dd36b.efi
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
