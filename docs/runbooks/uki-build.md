# Build and reproduce a Tier 3 UKI

This is Flow E step 3 in
[Production operations](../PRODUCTION_OPERATIONS.md). It is the current
operator entry for the production `unified_server` **runtime** UKI. The
attested-builder producer UKI is Flow H
([Attested-builder Tier 3 UKI](../ATTESTED_BUILDER_TIER3_UKI.md)); do
not substitute it here. It keeps four different concerns separate so a
historical experiment cannot silently become the release recipe.

## 1. Source and runtime binaries

Use a clean checkout at the exact reviewed release commit, with nothing
uncommitted: the `unified_server` build compiles `git rev-parse HEAD` into
the binary and appends `-dirty` when `git status --porcelain` prints
anything. Point `CARGO_HOME` at a new, empty directory outside the checkout:
cargo then downloads every dependency for this build and checks each
registry crate against the SHA-256 in `Cargo.lock`, which it does not repeat
for a crate already in its cache. Leave `RUSTFLAGS` unset: the variable
replaces the `target-feature` flags of `.cargo/config.toml` instead of
adding to them. Build the pir2 runtime with its production feature profile
and `oramctl` from its own lockfile, then strip only debug data:

```sh
export CARGO_HOME=/absolute/new-empty-directory
cargo build --locked --release -p runtime \
  --features cuckoo-oram --bin unified_server
strip --strip-debug target/release/unified_server
cargo build --locked --release \
  --manifest-path vendor/bitcoinpir-oram/Cargo.toml --bin oramctl
strip --strip-debug vendor/bitcoinpir-oram/target/release/oramctl
```

Record the commit and both binaries' SHA-256, together with what their bytes
depend on besides the source:

- the absolute paths of the checkout and of `CARGO_HOME`: the binary
  contains the source paths of its dependencies, which are under
  `CARGO_HOME`;
- `rustc -vV`, `c++ --version`, `cmake --version` and `ld --version`;
- whether the OnionPIR build found Intel HEXL: `grep HEXL_DIR
  target/release/build/onionpir-*/out/build/CMakeCache.txt` names a directory
  when it did.

`nix build .#unified-server` is a development harness, not the production
binary authority.

## 2. UKI assembly inputs

Run [`scripts/build_uki_tier3.sh`](../../scripts/build_uki_tier3.sh) as root on
the approved Linux build host. Set every release input explicitly:

- `KERNEL`: exact readable VPSBG-compatible kernel image;
- `BINARY` and `BPIR_UNIFIED_SERVER_BIN`: the same stripped pir2 binary;
- `ORAMCTL`: exact executable to embed;
- `BHTM_FROM_LEAF_PROOF`: exact retained proof input;
- `OUT`: unique absolute candidate path;
- archive locations, including a required off-host mirror when applicable;
- `/usr/local/bin/cloudflared` on the build host: the official static
  `cloudflared-linux-amd64` release that the script pins by version and
  SHA-256 (`TIER3_CLOUDFLARED_VERSION`, `TIER3_CLOUDFLARED_SHA256`). It is
  baked into the initramfs and therefore into MEASUREMENT, so the pin moves
  only together with a new image; place the pinned asset on the build host
  before building, and after the build extract `/usr/local/bin/cloudflared` from
  the candidate UKI's initrd to confirm it is the pinned bytes.

The script pins Zstandard compression, excludes early microcode, GPU firmware,
and unrelated globally installed BitcoinPIR dracut modules, and validates the
measured inventory. Compare
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
  OUT=/absolute/unique-release.efi \
  UKI_ARCHIVE_REMOTE=archive-host:/home/pir/uki-archive/tier3 \
  scripts/build_uki_tier3.sh
```

Before the real build, report its expected duration, a 15-minute hard stop,
and the progress signals: runtime binary, dracut initrd, inventory gates,
`ukify`, SHA-256, and dual archive.

Runtime behaviour baked into the image: runit's `finish` hook records each
start time and the consecutive-failure count under `/run`; after three
short-lived failures in a row it runs `sv down unified_server` and leaves a
reason/status file. It never reboots the machine or deletes data.

## 3. Build-host choice

Hetzner may build the candidate only when its exact kernel/modules and build
dependencies satisfy the command above. The script must not inherit host
compression or unrelated dracut modules.

If those inputs are unavailable, the fallback is Flow F in
[Production operations](../PRODUCTION_OPERATIONS.md):
`scripts/vpsbg-data-disk.sh open`, build on the stock root filesystem,
archive off-host, then `close` with the image ID `open` printed if the
maintenance build fails.

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

Full cross-host byte reproduction requires the same declared kernel/modules,
toolchain inputs and build paths. A matching binary hash or predicted
measurement alone does not authorize upload, switch, reboot, or activation.

Record the EFI, SHA-256, metadata and both archive locations, then continue
with the [VPSBG image runbook](vpsbg-image.md).
