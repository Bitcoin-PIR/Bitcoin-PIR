#!/usr/bin/env bash
# Build a one-shot SEV-SNP UKI for a tiny encrypted Direct ORAM fixture.

set -euo pipefail

if [ "$EUID" != 0 ]; then
    echo "error: build_uki_oram_debug.sh must run as root" >&2
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DRACUT_MODULE_DIR="$SCRIPT_DIR/dracut"
ARCHIVE_SCRIPT="$SCRIPT_DIR/archive_uki_artifact.sh"
KERNEL=${KERNEL:-}
ORAMCTL_BIN=${ORAMCTL_BIN:-/home/pir/data/oram-debug/stock-none-20260811/source-current/vendor/bitcoinpir-oram/target/release/oramctl}
RELEASE_ID=${RELEASE_ID:-$(git -C "$(dirname "$SCRIPT_DIR")" rev-parse --short HEAD 2>/dev/null || printf unknown)-$(date -u +%Y%m%dT%H%M%SZ)}
RUN_ID=${RUN_ID:-oram-tee-debug-$RELEASE_ID}
OUT=${OUT:-/tmp/bpir-oram-debug-$RELEASE_ID.efi}
CUSTOM_INITRD=${CUSTOM_INITRD:-/tmp/bpir-oram-debug-$RELEASE_ID-initrd.img}
FIXTURE_DIR=${FIXTURE_DIR:-/tmp/bpir-oram-debug-$RELEASE_ID-fixture}

for tool in ukify dracut sha256sum awk grep lsinitrd python3 git; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: missing build tool: $tool" >&2
        exit 1
    }
done
[ -x "$ORAMCTL_BIN" ] || { echo "error: oramctl missing: $ORAMCTL_BIN" >&2; exit 1; }
[[ "$RUN_ID" =~ ^[A-Za-z0-9._=-]+$ ]] || { echo "error: unsafe RUN_ID" >&2; exit 1; }

mkdir -p "$FIXTURE_DIR"
python3 - "$FIXTURE_DIR" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
index = bytearray()
chunks = bytearray()
for record in range(16):
    row = bytearray(25)
    for offset in range(20):
        row[offset] = (record * 31 + offset) & 0xff
    row[20:24] = record.to_bytes(4, "little")
    row[24] = 1
    index.extend(row)
    chunks.extend(bytes([record]) * 40)
(root / "utxo_chunks_index_nodust.bin").write_bytes(index)
(root / "utxo_chunks_nodust.bin").write_bytes(chunks)
PY

INDEX_FIXTURE="$FIXTURE_DIR/utxo_chunks_index_nodust.bin"
CHUNK_FIXTURE="$FIXTURE_DIR/utxo_chunks_nodust.bin"
ORAMCTL_SHA256=$(sha256sum "$ORAMCTL_BIN" | awk '{print $1}')
INDEX_SHA256=$(sha256sum "$INDEX_FIXTURE" | awk '{print $1}')
CHUNK_SHA256=$(sha256sum "$CHUNK_FIXTURE" | awk '{print $1}')

if [ -z "$KERNEL" ]; then
    KERNEL=$(ls -1 /boot/vmlinuz-*-generic 2>/dev/null | sort -V | tail -1)
fi
[ -r "$KERNEL" ] || { echo "error: no readable kernel" >&2; exit 1; }
KVER=$(basename "$KERNEL" | sed 's/^vmlinuz-//')
[ -d "/usr/lib/modules/$KVER" ] || { echo "error: modules missing for $KVER" >&2; exit 1; }

SEV_MODULES_DIR="/usr/lib/modules/$KVER/kernel/drivers"
REQUIRED_SEV_MODS="ccp sev-guest"
SEV_DRIVER_LIST="ccp sev-guest"
if find "$SEV_MODULES_DIR" -name 'tsm_report.ko*' -print -quit | grep -q .; then
    REQUIRED_SEV_MODS="$REQUIRED_SEV_MODS tsm_report"
    SEV_DRIVER_LIST="$SEV_DRIVER_LIST tsm_report"
fi
for mod in $REQUIRED_SEV_MODS; do
    find "$SEV_MODULES_DIR" -name "${mod}.ko*" -print -quit | grep -q . || {
        echo "error: missing SEV module $mod" >&2
        exit 1
    }
done

export BPIR_ORAM_DEBUG_ORAMCTL_BIN="$ORAMCTL_BIN"
export BPIR_ORAM_DEBUG_INDEX_FIXTURE="$INDEX_FIXTURE"
export BPIR_ORAM_DEBUG_CHUNK_FIXTURE="$CHUNK_FIXTURE"
export BPIR_ORAM_DEBUG_ORAMCTL_SHA256="$ORAMCTL_SHA256"
export BPIR_ORAM_DEBUG_INDEX_SHA256="$INDEX_SHA256"
export BPIR_ORAM_DEBUG_CHUNK_SHA256="$CHUNK_SHA256"
export BPIR_ORAM_DEBUG_RUN_ID="$RUN_ID"

src="$DRACUT_MODULE_DIR/97bpir-oram-debug"
dst=/usr/lib/dracut/modules.d/97bpir-oram-debug
[ -d "$src" ] || { echo "error: missing dracut module: $src" >&2; exit 1; }
mkdir -p "$dst"
cp -fp "$src"/* "$dst/"
chmod 0755 "$dst"/*
find "$dst" -type f -exec touch -d @0 {} +

DRIVER_LIST="virtio_net virtio_pci virtio_blk $SEV_DRIVER_LIST"
echo "building Direct ORAM debug UKI"
echo "run id:          $RUN_ID"
echo "oramctl sha256:  $ORAMCTL_SHA256"
echo "index sha256:    $INDEX_SHA256"
echo "chunk sha256:    $CHUNK_SHA256"
SOURCE_DATE_EPOCH=0 dracut --force --no-hostonly --reproducible --nostrip \
    --add 'bpir-oram-debug' \
    --omit 'bpir-cloudflared bpir-unified-server bpir-tier3-init bpir-attested-builder bpir-builder-tier3-init' \
    --add-drivers " $DRIVER_LIST " \
    --kver "$KVER" \
    "$CUSTOM_INITRD"

listing=$(lsinitrd "$CUSTOM_INITRD")
for item in usr/local/bin/oramctl sbin/bpir-oram-debug-init \
    usr/local/bin/bpir-oram-debug-run etc/bpir-oram-debug/baked.env \
    usr/share/bitcoinpir/oram-debug/utxo_chunks_index_nodust.bin \
    usr/share/bitcoinpir/oram-debug/utxo_chunks_nodust.bin; do
    grep -q "$item" <<<"$listing" || { echo "error: initrd missing $item" >&2; exit 1; }
done
for mod in $REQUIRED_SEV_MODS; do
    grep -q "${mod}\.ko" <<<"$listing" || { echo "error: initrd missing ${mod}.ko" >&2; exit 1; }
done
for forbidden in usr/local/bin/unified_server usr/local/bin/cloudflared \
    usr/bin/runit usr/bin/runsvdir etc/sv/unified_server \
    usr/local/bin/pir-attested-builder; do
    if grep -q "$forbidden" <<<"$listing"; then
        echo "error: debug initrd contains forbidden production component: $forbidden" >&2
        exit 1
    fi
done

CMDLINE='rdinit=/sbin/bpir-oram-debug-init console=ttyS0,115200 console=tty1 quiet loglevel=3'
ukify build --linux="$KERNEL" --initrd="$CUSTOM_INITRD" --cmdline="$CMDLINE" --output="$OUT"
UKI_SHA256=$(sha256sum "$OUT" | awk '{print $1}')
UKI_BYTES=$(stat -c '%s' "$OUT")
[ "$UKI_BYTES" -lt 1000000000 ] || { echo "error: UKI exceeds VPSBG upload limit" >&2; exit 1; }
echo "UKI:             $OUT"
echo "UKI bytes:       $UKI_BYTES"
echo "UKI sha256:      $UKI_SHA256"
"$ARCHIVE_SCRIPT" oram-debug "$OUT" \
    "run_id=$RUN_ID" \
    "kernel_version=$KVER" \
    "oramctl_sha256=$ORAMCTL_SHA256" \
    "index_sha256=$INDEX_SHA256" \
    "chunk_sha256=$CHUNK_SHA256" \
    "status_url=http://87.120.8.198:22/current/status.env"
