# ORAM Tier 3 Production Handoff

Status as of 2026-06-26: the ORAM-enabled Tier 3 UKI is built and locally
available, but pir2 is not live on that artifact yet. Live checks currently
fail at the Cloudflare tunnel with HTTP 530.

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

Hashes:

```text
unified_server sha256:
457590cf4e17221c709be806a40d7d68a7f0978e365789cbe37f4a4d1e9aaaf1

UKI sha256:
718c7728142f9a3a1c6663711853d1b51ee14fde62debc8d2fb1c8662855b18b
```

The final initrd was unpacked on `pir-hetzner`; the baked
`usr/local/bin/unified_server` hash matched the clean release binary hash above.

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

## Live Status

As of this handoff, pir2 is not accepting WebSocket connections:

```bash
./target/debug/bpir-admin attest wss://weikeng2.bitcoinpir.org \
  --expect-binary 457590cf4e17221c709be806a40d7d68a7f0978e365789cbe37f4a4d1e9aaaf1

./target/debug/bpir-admin channel-test wss://weikeng2.bitcoinpir.org \
  --expect-ark-fingerprint 1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a
```

Both currently fail with:

```text
HTTP error: 530
```

This indicates the live tunnel/service is not reachable. It does not prove a
binary mismatch.

## Deployment Steps

Upload this UKI via the VPSBG portal:

```text
deploy/uki/bpir-tier3-oram-668dd36b.efi
```

Portal path:

```text
VPSBG dashboard -> Confidentiality & Protection -> Advanced: Measured Boot
-> UKI -> Upload -> Save & Reboot
```

After reboot, run:

```bash
./target/debug/bpir-admin attest wss://weikeng2.bitcoinpir.org \
  --expect-binary 457590cf4e17221c709be806a40d7d68a7f0978e365789cbe37f4a4d1e9aaaf1

./target/debug/bpir-admin channel-test wss://weikeng2.bitcoinpir.org \
  --expect-ark-fingerprint 1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a
```

Capture the new SEV-SNP MEASUREMENT from `attest` and update the web/runtime
pins only after both commands pass.

## Recovery

If the upload keeps pir2 at HTTP 530, use:

```text
docs/PHASE3_SLICE3_RECOVERY.md
```

Tier 3 has no SSH by design. Recovery is through the VPSBG portal by uploading a
known-good Slice 2 UKI or selecting "None" in measured boot to return to the
rootfs boot path.
