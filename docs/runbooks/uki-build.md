# Build and reproduce a Tier 3 UKI

This is the current operator entry for the production `unified_server` runtime
UKI. It keeps four different concerns separate so a historical experiment
cannot silently become the release recipe.

## 1. Source and runtime binary

Use a clean checkout at the exact reviewed release commit. Build the pir2
runtime with its production feature profile, then strip only debug data:

```sh
cargo build --locked --release -p runtime \
  --features cuckoo-oram --bin unified_server
strip --strip-debug target/release/unified_server
```

Record the commit and binary SHA-256. `scripts/build_unified_server.sh` and
`nix build .#unified-server` are reproducibility/development harnesses; neither
is the production pir2 binary authority.

## 2. UKI assembly inputs

Run [`scripts/build_uki_tier3.sh`](../../scripts/build_uki_tier3.sh) as root on
the approved Linux build host. Set every release input explicitly:

- `KERNEL`: exact readable VPSBG-compatible kernel image;
- `BINARY` and `BPIR_UNIFIED_SERVER_BIN`: the same stripped pir2 binary;
- `ORAMCTL`: exact executable to embed;
- `BHTM_FROM_LEAF_PROOF`: exact retained proof input;
- `BPIR_TIER3_SERVICE_POLICY`: reviewed policy matching the source lock;
- `OUT`: unique absolute candidate path;
- archive locations, including a required off-host mirror when applicable.

The script pins Zstandard compression, excludes early microcode, GPU firmware,
and unrelated globally installed BitcoinPIR dracut modules, validates the
measured inventory, and refuses to archive an EFI larger than 256 MiB. Compare
the candidate's file class and size with the retained image-265 release record
in [`../data-retention/production-release-image-265.env`](../data-retention/production-release-image-265.env).
An unexplained change from that mature class is a failed build, not a release.

```sh
sudo env \
  KERNEL=/boot/vmlinuz-EXACT-generic \
  BINARY=/absolute/clean-checkout/target/release/unified_server \
  BPIR_UNIFIED_SERVER_BIN=/absolute/clean-checkout/target/release/unified_server \
  ORAMCTL=/absolute/oramctl \
  BHTM_FROM_LEAF_PROOF=/absolute/height-940611.leaf-proof.json \
  BPIR_TIER3_SERVICE_POLICY=/absolute/service-policy.bin \
  OUT=/absolute/unique-release.efi \
  UKI_ARCHIVE_REMOTE=archive-host:/home/pir/uki-archive/tier3 \
  UKI_ARCHIVE_REMOTE_REQUIRED=1 \
  scripts/build_uki_tier3.sh --dry-run

# Repeat the exact command without --dry-run after reviewing its inputs.
```

Before the real build, report its expected duration, a 15-minute hard stop,
and the progress signals: runtime binary, dracut initrd, inventory gates,
`ukify`, SHA-256, and dual archive.

## 3. Build-host choice

Hetzner may build the candidate only when its exact kernel/modules and build
dependencies satisfy the command above. The script must not inherit host
compression or unrelated dracut modules.

If those inputs are unavailable, the fallback is the established VPSBG
maintenance shape: separately authorize changing measured boot to no attached
UKI, reboot into the stock root filesystem, build there, archive off-host, and
reattach the recorded rollback image if the maintenance build fails. Do not
assume the VPSBG API's `null`/`None` behavior; confirm the operator action and
rollback image before changing the server.

## 4. Reproducibility and verification

These are distinct claims:

| Block | Current authority | What it proves |
| --- | --- | --- |
| Source | exact Git commit plus `Cargo.lock` | reviewed code and dependency selection |
| pir2 binary | bare Cargo command above plus binary SHA-256 | exact ORAM-enabled runtime bytes used by the UKI |
| UKI assembly | this runbook and `build_uki_tier3.sh` | exact kernel, initramfs inputs, compression, inventory, EFI and archive metadata |
| Independent launch check | retained EFI + pinned OVMF + required VPSBG launch tuple | predicted SEV measurement can be compared with the chip readback |
| Nix harness | `flake.nix` / historical reproducibility plan | development reproducibility only; not a production pir2 UKI |
| Attested-builder UKI | `build_uki_attested_builder_tier3.sh` | one-shot database producer; never the runtime server UKI |

Full cross-host byte reproduction requires the same declared kernel/modules
and toolchain inputs. A matching binary hash or predicted measurement alone
does not authorize upload, switch, reboot, sealed release, or activation.

Successful completion prints `PASS uki_build` and `NEXT_STEP`. Record the EFI,
SHA-256, metadata and both archive locations, then continue with the
[VPSBG image runbook](vpsbg-image.md).
