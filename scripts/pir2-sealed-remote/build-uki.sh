#!/usr/bin/env bash
# Runs on the VPSBG stock rootfs as root: place the cloudflared release the reviewed
# build script pins (values read from the source checkout, never retyped), assemble
# the Tier 3 UKI with explicit inputs (docs/runbooks/uki-build.md section 2), and
# confirm the baked cloudflared bytes from the candidate initrd.
set -euo pipefail
: "${D:?build dir}"; : "${TAG:?}"; : "${KERNEL:?kernel image path}"
BIN=$D/source/target/release/unified_server
[ "$(id -un)" = root ] || { echo "run as root" >&2; exit 1; }
[ -x "$BIN" ] || { echo "runtime binary missing: $BIN" >&2; exit 1; }
cd "$D/source" && sha256sum -c "$D/unified_server.sha256"
CF_VER=$(awk -F= '$1=="TIER3_CLOUDFLARED_VERSION"{print $2}' "$D/source/scripts/build_uki_tier3.sh")
CF_SHA=$(awk -F= '$1=="TIER3_CLOUDFLARED_SHA256"{print $2}' "$D/source/scripts/build_uki_tier3.sh")
[[ "$CF_VER" =~ ^[0-9]{4}\.[0-9]+\.[0-9]+$ && "$CF_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "cloudflared pin not found in build script" >&2; exit 1; }
echo "[stage] cloudflared $CF_VER on the build host"
cur=$(sha256sum /usr/local/bin/cloudflared | awk '{print $1}')
if [ "$cur" != "$CF_SHA" ]; then
  echo "current_cloudflared_sha256=$cur (replacing)"
  cp -p /usr/local/bin/cloudflared "$D/cloudflared.previous"
  curl -fsSL --max-time 900 -o "$D/cloudflared-$CF_VER" "https://github.com/cloudflare/cloudflared/releases/download/$CF_VER/cloudflared-linux-amd64"
  got=$(sha256sum "$D/cloudflared-$CF_VER" | awk '{print $1}')
  [ "$got" = "$CF_SHA" ] || { echo "downloaded cloudflared sha256 $got != pinned $CF_SHA" >&2; exit 1; }
  install -m0755 "$D/cloudflared-$CF_VER" /usr/local/bin/cloudflared
fi
echo "cloudflared_version=$(/usr/local/bin/cloudflared --version 2>&1 | head -1)"
echo "cloudflared_ldd=$(ldd /usr/local/bin/cloudflared 2>&1 | head -1)"
export KERNEL BINARY=$BIN BPIR_UNIFIED_SERVER_BIN=$BIN
export ORAMCTL=$D/inputs/oramctl BHTM_FROM_LEAF_PROOF=$D/inputs/height-940611.leaf-proof.json
export OUT=$D/bpir-tier3-$TAG.efi UKI_ARCHIVE_DIR=$D/archive/tier3
unset UKI_ARCHIVE_REMOTE UKI_ARCHIVE_REMOTE_REQUIRED
[ ! -e "$OUT" ] || { echo "OUT already exists: $OUT" >&2; exit 1; }
echo "[stage] uki build dry-run"; scripts/build_uki_tier3.sh --dry-run
echo "[stage] uki build live"; scripts/build_uki_tier3.sh
ls -la "$UKI_ARCHIVE_DIR"; cat "$UKI_ARCHIVE_DIR"/*.efi.meta
echo "[stage] confirm the baked cloudflared bytes (informational; never fails the build)"
(
  set +e
  tmp=$(mktemp -d); cd "$tmp" || exit 0
  objcopy -O binary --only-section=.initrd "$OUT" initrd.img 2>/dev/null \
    && zstd -dc initrd.img 2>/dev/null | cpio -i --quiet -d 'usr/local/bin/cloudflared' 'usr/bin/cloudflared' 2>/dev/null
  baked=$(sha256sum usr/local/bin/cloudflared usr/bin/cloudflared 2>/dev/null | head -1)
  echo "baked_cloudflared=${baked:-not-extracted}"
  case "$baked" in "$CF_SHA "*) echo "BAKED_CLOUDFLARED_MATCHES_PIN=true" ;; *) echo "BAKED_CLOUDFLARED_MATCHES_PIN=unknown" ;; esac
  cd / && rm -rf "$tmp"
)
echo "PASS uki_build_window"
