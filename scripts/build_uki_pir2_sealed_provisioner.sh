#!/usr/bin/env bash
# Build the deliberately small, offline, one-shot pir2 sealed provisioner UKI.
set -euo pipefail

[ "${EUID}" = 0 ] || { echo "error: must run as root" >&2; exit 1; }
for tool in dracut ukify sha256sum; do command -v "$tool" >/dev/null || { echo "error: missing $tool" >&2; exit 1; }; done

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
MODULE_SRC="$SCRIPT_DIR/dracut/97bpir-pir2-sealed-provisioner"
PAYLOAD_DIR=${BPIR_PIR2_SEALED_PROVISIONER_PAYLOAD_DIR:?error: set BPIR_PIR2_SEALED_PROVISIONER_PAYLOAD_DIR}
MANIFEST=${BPIR_PIR2_SEALED_PROVISIONER_MANIFEST:?error: set BPIR_PIR2_SEALED_PROVISIONER_MANIFEST}
KERNEL=${KERNEL:-}
OUT=${OUT:-/tmp/bpir-pir2-sealed-provisioner.efi}
INITRD=${INITRD:-/tmp/bpir-pir2-sealed-provisioner.img}

[ -d "$PAYLOAD_DIR" ] || { echo "error: payload dir missing" >&2; exit 1; }
[ -r "$MANIFEST" ] || { echo "error: manifest missing" >&2; exit 1; }
[ -d "$MODULE_SRC" ] || { echo "error: module missing" >&2; exit 1; }
if [ -z "$KERNEL" ]; then KERNEL=$(ls -1 /boot/vmlinuz-*-generic 2>/dev/null | sort -V | tail -1); fi
[ -r "$KERNEL" ] || { echo "error: kernel unreadable" >&2; exit 1; }
KVER=$(basename "$KERNEL" | sed 's/^vmlinuz-//')
[ -d "/usr/lib/modules/$KVER" ] || { echo "error: modules missing for $KVER" >&2; exit 1; }

dst=/usr/lib/dracut/modules.d/97bpir-pir2-sealed-provisioner
mkdir -p "$dst"
cp -fp "$MODULE_SRC"/* "$dst/"
chmod 0755 "$dst"/*
find "$dst" -type f -exec touch -d @0 {} +
export BPIR_PIR2_SEALED_PROVISIONER_PAYLOAD_DIR="$PAYLOAD_DIR"
export BPIR_PIR2_SEALED_PROVISIONER_MANIFEST="$MANIFEST"

SOURCE_DATE_EPOCH=0 dracut --force --no-hostonly --reproducible \
    --add bpir-pir2-sealed-provisioner --add-drivers " virtio_blk " \
    --kver "$KVER" "$INITRD"
ukify build --linux="$KERNEL" --initrd="$INITRD" \
    --cmdline="rdinit=/sbin/bpir-pir2-sealed-provisioner-init quiet" --output="$OUT"
printf 'wrote %s\nsha256 %s\n' "$OUT" "$(sha256sum "$OUT" | awk '{print $1}')"
