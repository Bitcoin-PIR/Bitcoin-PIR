---
name: bitcoinpir-production-workflow
description: Run BitcoinPIR's production workflow through its repository commands.
---

# BitcoinPIR production workflow

Run each step in order. The wrapper steps print `PASS` and `NEXT_STEP=...`.
Begin a wrapper that supports `--dry-run` with that option, then use the live
form shown by its runbook for the selected operation.

## 1. Current status

Input: VPSBG server ID (when the deployment includes VPSBG).

```bash
scripts/vpsbg-measured-boot.sh status --server-id ID
```

Success: `PASS action=status`. Record the returned status fields; a concrete
image ID is available only when the status output reports one. Next: build
payment artifacts.

## 2. Payment artifacts

Inputs: the selected BAT V2 builder and its `bpir-admin payment-artifact`
arguments. Obtain the exact arguments first.

```bash
scripts/payment-v1-artifacts.sh bat-v2-class --help
scripts/payment-v1-artifacts.sh bat-v2-class [original CLI arguments] --dry-run
scripts/payment-v1-artifacts.sh bat-v2-class [original CLI arguments]
```

Success: `PASS artifact=bat-v2-class`. Next: initialize issuer state or the
sealed release, as reported by `NEXT_STEP`.

## 3. Issuer state

Inputs: issuer store path, issuer ID, and network.

```bash
scripts/payment-v1-issuer-state.sh init --store /secure/issuer.sqlite3 --issuer-id-hex HEX --network bitcoin --dry-run
scripts/payment-v1-issuer-state.sh init --store /secure/issuer.sqlite3 --issuer-id-hex HEX --network bitcoin
```

Success: `PASS issuer_state=init`. Next: build the UKI.

## 4. UKI

Inputs: approved root build host plus explicit kernel, ORAM-enabled runtime,
oramctl, proof, service policy, output, and archive paths. Read
`docs/runbooks/uki-build.md`; Nix and attested-builder outputs are different
reproducibility blocks and are not substitutes for this runtime UKI.

```bash
sudo env KERNEL=/boot/vmlinuz-EXACT-generic BINARY=/absolute/unified_server BPIR_UNIFIED_SERVER_BIN=/absolute/unified_server ORAMCTL=/absolute/oramctl BHTM_FROM_LEAF_PROOF=/absolute/height-940611.leaf-proof.json BPIR_TIER3_SERVICE_POLICY=/absolute/service-policy.bin OUT=/absolute/release.efi UKI_ARCHIVE_REMOTE=archive-host:/home/pir/uki-archive/tier3 UKI_ARCHIVE_REMOTE_REQUIRED=1 scripts/build_uki_tier3.sh --dry-run
sudo env KERNEL=/boot/vmlinuz-EXACT-generic BINARY=/absolute/unified_server BPIR_UNIFIED_SERVER_BIN=/absolute/unified_server ORAMCTL=/absolute/oramctl BHTM_FROM_LEAF_PROOF=/absolute/height-940611.leaf-proof.json BPIR_TIER3_SERVICE_POLICY=/absolute/service-policy.bin OUT=/absolute/release.efi UKI_ARCHIVE_REMOTE=archive-host:/home/pir/uki-archive/tier3 UKI_ARCHIVE_REMOTE_REQUIRED=1 scripts/build_uki_tier3.sh
```

Success: a directly Zstandard-compressed initramfs, the required measured
inventory, an EFI no larger than 256 MiB, `wrote tier3 UKI: ...`,
`tier3 uki sha256: ...`, dual archive evidence, and `PASS uki_build`.
Next: inspect or change VPSBG measured boot with `$vpsbg-measured-boot`.

## 5. VPSBG image

Inputs: server ID, built UKI, and the prior image ID for rollback.

```bash
scripts/vpsbg-measured-boot.sh status --server-id ID
scripts/vpsbg-measured-boot.sh upload --uki /absolute/release.efi --dry-run
scripts/vpsbg-measured-boot.sh upload --uki /absolute/release.efi --apply
scripts/vpsbg-measured-boot.sh switch --server-id ID --image-id IMAGE_ID --apply
```

Success: `PASS action=switch server_id=ID image_id=IMAGE_ID`. Next: run sealed phases.

## 6. Sealed release phases

Inputs for each phase: an unused startup-file path, ordinal, verifier nonce,
current policy digest, BAT V2 class digest, public artifact-set SHA-256, and
minimum authorization epoch. Use the exact measured UKI/OVMF values and
Observe receipt for the release.

```bash
scripts/pir2-sealed-ceremony.sh phase --phase observe --out /absolute/observe.startup.env --ordinal ORDINAL --verifier-nonce-hex HEX64 --policy-digest-hex HEX64 --class-digest-hex HEX64 --artifact-set-sha256 HEX64 --minimum-authorization-epoch EPOCH --dry-run
scripts/pir2-sealed-ceremony.sh phase --phase observe --out /absolute/observe.startup.env --ordinal ORDINAL --verifier-nonce-hex HEX64 --policy-digest-hex HEX64 --class-digest-hex HEX64 --artifact-set-sha256 HEX64 --minimum-authorization-epoch EPOCH
scripts/pir2-sealed-ceremony.sh release --help
scripts/pir2-sealed-ceremony.sh release [release options] --dry-run
scripts/pir2-sealed-ceremony.sh release [release options]
```

After the Observe config passes, use that exact file as
`/home/pir/data/pir2-sealed/startup.env` and boot the measured UKI. After the
Observe receipt and release pass, repeat the `phase` command with fresh inputs
and output files for `enroll`, `probe`, and `ready`, booting each in that order.
Success: release prints `PASS sealed_release`; every phase file prints
`PASS sealed_phase_config=<phase>` and `NEXT_STEP`.

## 7. Private start and production source readiness

Private inputs: absolute publisher plan and apply-approval paths, plus the
approved plan, source, launcher, launcher-manifest, and approval SHA-256
values. `production` has no command arguments.

```bash
scripts/payment-v1-activate.sh private --plan /absolute/publisher-plan --approved-plan-sha256 HEX64 --approved-source-sha256 HEX64 --approved-launcher-sha256 HEX64 --approved-manifest-sha256 HEX64 --approval /absolute/apply-approval.json --approved-approval-sha256 HEX64 --dry-run
scripts/payment-v1-activate.sh private --plan /absolute/publisher-plan --approved-plan-sha256 HEX64 --approved-source-sha256 HEX64 --approved-launcher-sha256 HEX64 --approved-manifest-sha256 HEX64 --approval /absolute/apply-approval.json --approved-approval-sha256 HEX64 --apply
scripts/payment-v1-activate.sh production --dry-run
scripts/payment-v1-activate.sh production
```

Private success is `PASS private_start`; production source success is
`PASS production_source_readiness`. Follow the printed `NEXT_STEP`.
