#!/usr/bin/env bash
# Build the one-shot attested-builder Tier 3 UKI for VPSBG SEV-SNP.
#
# This is separate from scripts/build_uki_tier3.sh, which bakes the production
# pir2 unified_server + cloudflared service image. This UKI has no sshd,
# cloudflared, or runit. It runs attested-builder once, writes artifacts under
# /home/pir/data/attested-builder-runs, then powers off.

set -euo pipefail

PATH="/home/pir/.cargo/bin:$PATH"
export PATH

if [ "$EUID" != "0" ]; then
    echo "error: build_uki_attested_builder_tier3.sh must run as root" >&2
    echo "       re-run on VPSBG Slice 2 as:" >&2
    echo "         sudo /home/pir/BitcoinPIR/scripts/build_uki_attested_builder_tier3.sh" >&2
    exit 1
fi

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|y|Y) return 0 ;;
        *) return 1 ;;
    esac
}

hash_one() {
    sha256sum "$1" | awk '{print $1}'
}

path_owner() {
    stat -c '%U' "$1" 2>/dev/null || stat -f '%Su' "$1" 2>/dev/null || printf ''
}

run_as_path_owner() {
    local path=$1
    shift
    local owner
    owner=$(path_owner "$path")
    if [ -n "$owner" ] && [ "$owner" != "root" ] &&
        command -v sudo >/dev/null 2>&1 && id -u "$owner" >/dev/null 2>&1; then
        sudo -u "$owner" env PATH="$PATH" "$@"
    else
        "$@"
    fi
}

git_in_repo() {
    local repo=$1
    shift
    git -C "$repo" "$@" 2>/dev/null && return 0
    run_as_path_owner "$repo" git -C "$repo" "$@" 2>/dev/null
}

current_git_commit() {
    local repo=$1
    local rev
    rev=$(git_in_repo "$repo" rev-parse --verify HEAD 2>/dev/null || printf unknown)
    if [[ "$rev" != "unknown" ]] &&
        { ! git_in_repo "$repo" diff --quiet -- 2>/dev/null ||
          ! git_in_repo "$repo" diff --cached --quiet -- 2>/dev/null; }; then
        printf '%s-dirty\n' "$rev"
    else
        printf '%s\n' "$rev"
    fi
}

require_tool() {
    local tool=$1
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: $tool not installed" >&2
        exit 1
    }
}

# Defaults. Override via env.
KERNEL=${KERNEL:-}
OUT=${OUT:-/tmp/bpir-attested-builder-tier3.efi}
CUSTOM_INITRD=${CUSTOM_INITRD:-/tmp/bpir-attested-builder-tier3-initrd.img}
ATTESTED_BUILDER_REPO=${ATTESTED_BUILDER_REPO:-/home/pir/bitcoin-pir/attested-builder}
ATTESTED_BUILDER_BIN=${ATTESTED_BUILDER_BIN:-$ATTESTED_BUILDER_REPO/target/release/pir-attested-builder}
SKIP_BUILDER_CARGO_BUILD=${SKIP_BUILDER_CARGO_BUILD:-0}
ATTESTED_BUILDER_GIT_COMMIT=${ATTESTED_BUILDER_GIT_COMMIT:-}

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DRACUT_MODULE_DIR="$SCRIPT_DIR/dracut"
ARCHIVE_SCRIPT="$SCRIPT_DIR/archive_uki_artifact.sh"

for tool in ukify dracut sha256sum awk sed find sort grep lsinitrd; do
    require_tool "$tool"
done

if [ ! -d "$ATTESTED_BUILDER_REPO" ]; then
    echo "error: attested-builder repo not found: $ATTESTED_BUILDER_REPO" >&2
    exit 1
fi
if [ ! -f "$ATTESTED_BUILDER_REPO/scripts/build-snapshot-database.sh" ]; then
    echo "error: missing attested-builder pipeline script" >&2
    echo "       $ATTESTED_BUILDER_REPO/scripts/build-snapshot-database.sh" >&2
    exit 1
fi

if ! is_truthy "$SKIP_BUILDER_CARGO_BUILD"; then
    require_tool cargo
    echo "building pir-attested-builder release binary..."
    (
        cd "$ATTESTED_BUILDER_REPO"
        run_as_path_owner "$ATTESTED_BUILDER_REPO" \
            cargo build -q --release -p pir-attested-builder
    )
fi

[ -x "$ATTESTED_BUILDER_BIN" ] || {
    echo "error: $ATTESTED_BUILDER_BIN not executable" >&2
    exit 1
}

if [ -z "$ATTESTED_BUILDER_GIT_COMMIT" ]; then
    ATTESTED_BUILDER_GIT_COMMIT=$(current_git_commit "$ATTESTED_BUILDER_REPO")
fi
ATTESTED_BUILDER_BIN_SHA256=$(hash_one "$ATTESTED_BUILDER_BIN")

if [ -z "$KERNEL" ]; then
    KERNEL=$(ls -1 /boot/vmlinuz-*-generic 2>/dev/null | sort -V | tail -1)
    if [ -z "$KERNEL" ]; then
        echo "error: no kernel found under /boot/vmlinuz-*-generic; set KERNEL=" >&2
        exit 1
    fi
    echo "auto-detected kernel: $KERNEL"
fi
[ -r "$KERNEL" ] || { echo "error: $KERNEL not readable" >&2; exit 1; }

KVER=$(basename "$KERNEL" | sed 's/^vmlinuz-//')
[ -d "/usr/lib/modules/$KVER" ] || {
    echo "error: /usr/lib/modules/$KVER missing" >&2
    echo "  reinstall with: apt install --reinstall linux-modules-$KVER" >&2
    exit 1
}

SEV_MODULES_DIR="/usr/lib/modules/$KVER/kernel/drivers"
REQUIRED_SEV_MODS="ccp sev-guest"
OPTIONAL_SEV_MODS="tsm_report"
SEV_DRIVER_LIST="ccp sev-guest"
for mod in $OPTIONAL_SEV_MODS; do
    if find "$SEV_MODULES_DIR" -name "${mod}.ko*" -print -quit 2>/dev/null | grep -q .; then
        REQUIRED_SEV_MODS="$REQUIRED_SEV_MODS $mod"
        SEV_DRIVER_LIST="$SEV_DRIVER_LIST $mod"
    fi
done

MISSING_REQUIRED=""
for mod in $REQUIRED_SEV_MODS; do
    found=$(find "$SEV_MODULES_DIR" -name "${mod}.ko*" -print -quit 2>/dev/null)
    if [ -z "$found" ]; then
        MISSING_REQUIRED="$MISSING_REQUIRED $mod"
    fi
done
if [ -n "$MISSING_REQUIRED" ]; then
    echo "error: SEV kernel module(s) missing under $SEV_MODULES_DIR:$MISSING_REQUIRED" >&2
    echo "  these are required for /dev/sev-guest in the builder UKI" >&2
    exit 1
fi

for mod in 96bpir-attested-builder 97bpir-builder-tier3-init; do
    src="$DRACUT_MODULE_DIR/$mod"
    dst="/usr/lib/dracut/modules.d/$mod"
    [ -d "$src" ] || { echo "error: dracut module dir missing: $src" >&2; exit 1; }
    mkdir -p "$dst"
    cp -fp "$src"/* "$dst/"
    chmod 0755 "$dst"/*
    find "$dst" -type f -exec touch -d @0 {} +
    echo "dracut module installed: $dst"
done

export ATTESTED_BUILDER_REPO
export ATTESTED_BUILDER_BIN
export ATTESTED_BUILDER_GIT_COMMIT
export ATTESTED_BUILDER_BIN_SHA256

echo "kernel:                     $KERNEL"
echo "kernel version:             $KVER"
echo "attested-builder repo:      $ATTESTED_BUILDER_REPO"
echo "attested-builder commit:    $ATTESTED_BUILDER_GIT_COMMIT"
echo "attested-builder binary:    $ATTESTED_BUILDER_BIN"
echo "attested-builder sha256:    $ATTESTED_BUILDER_BIN_SHA256"
echo "SEV modules:                $REQUIRED_SEV_MODS"
echo

DRIVER_LIST="virtio_blk $SEV_DRIVER_LIST"
echo "generating attested-builder Tier 3 initrd..."
SOURCE_DATE_EPOCH=0 dracut --force --no-hostonly --reproducible --nostrip \
    --add "bpir-attested-builder bpir-builder-tier3-init" \
    --add-drivers " $DRIVER_LIST " \
    --kver "$KVER" \
    "$CUSTOM_INITRD"
echo "initrd:                     $CUSTOM_INITRD ($(du -h "$CUSTOM_INITRD" | cut -f1))"

echo "verifying initrd contents..."
INITRD_LISTING=$(/usr/bin/lsinitrd "$CUSTOM_INITRD" 2>/dev/null)
[ -n "$INITRD_LISTING" ] || { echo "error: lsinitrd produced no output" >&2; exit 1; }

MISSING_ITEMS=""
for item in \
    "usr/local/bin/pir-attested-builder" \
    "usr/local/bin/bpir-builder-run" \
    "usr/local/lib/attested-builder/scripts/build-snapshot-database.sh" \
    "sbin/bpir-builder-tier3-init" \
    "etc/bpir-builder/baked.env"; do
    if ! grep -q "$item" <<< "$INITRD_LISTING"; then
        MISSING_ITEMS="$MISSING_ITEMS $item"
    fi
done
for mod in $REQUIRED_SEV_MODS; do
    if ! grep -q "${mod}\.ko" <<< "$INITRD_LISTING"; then
        MISSING_ITEMS="$MISSING_ITEMS ${mod}.ko"
    fi
done
if [ -n "$MISSING_ITEMS" ]; then
    echo "error: initrd missing required item(s):$MISSING_ITEMS" >&2
    exit 1
fi
echo "initrd required files confirmed"

CMDLINE="rdinit=/sbin/bpir-builder-tier3-init console=ttyS0,115200 console=tty1 quiet loglevel=3"
echo "cmdline:                    $CMDLINE"
echo

ukify build \
    --linux="$KERNEL" \
    --initrd="$CUSTOM_INITRD" \
    --cmdline="$CMDLINE" \
    --output="$OUT"

SIZE=$(du -h "$OUT" | cut -f1)
UKI_SHA=$(hash_one "$OUT")
echo
echo "wrote builder Tier 3 UKI:   $OUT ($SIZE)"
echo "builder Tier 3 UKI sha256:  $UKI_SHA"
"$ARCHIVE_SCRIPT" attested-builder "$OUT" \
    "kernel=$KERNEL" \
    "kernel_version=$KVER" \
    "builder_repo=$ATTESTED_BUILDER_REPO" \
    "builder_git_commit=$ATTESTED_BUILDER_GIT_COMMIT" \
    "builder_binary_sha256=$ATTESTED_BUILDER_BIN_SHA256"
echo
cat <<EOF
Before booting this UKI, provision runtime inputs on VPSBG Slice 2:

  sudo mkdir -p /home/pir/data/attested-builder/inputs /home/pir/data/attested-builder-runs
  sudo tee /home/pir/data/attested-builder/config.env >/dev/null <<'CONFIG'
SNAPSHOT=/home/pir/data/attested-builder/inputs/txoutset_<height>.dat
EXPECTED_MUHASH=<64-byte-Core-display-muhash>
NETWORK_MAGIC=f9beb4d9
ANCHOR_HEIGHT=<height>
# ANCHOR_HASH=<optional-block-hash>
CORE_VERSION=<bitcoind-version-string>
RUN_ID=mainnet_<height>_sev_snp
MIN_FREE_KB=50000000
CONFIG

Upload $OUT in VPSBG Measured Boot as a temporary UKI and reboot.
The UKI will power off after completion. Then switch Measured Boot back to
"None", boot Slice 2, and collect:

  /home/pir/data/attested-builder-runs/latest/build-summary.txt
  /home/pir/data/attested-builder-runs/latest/build-evidence.bin
  /home/pir/data/attested-builder-runs/latest/build-evidence.sev-snp-report.bin
  /home/pir/data/attested-builder-runs/latest/server-db/MANIFEST.toml

This UKI runs ROOTS_ONLY=1. server-db/MANIFEST.toml is an evidence manifest,
not a server-loadable database manifest.

Archive policy:

  The UKI was copied into the configured archive directory. If this build host
  is not the durable Hetzner host, set UKI_ARCHIVE_REMOTE before building, for
  example:

    UKI_ARCHIVE_REMOTE=pir-hetzner:/home/pir/uki-archive/attested-builder
EOF
