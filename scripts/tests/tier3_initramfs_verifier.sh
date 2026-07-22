#!/usr/bin/env bash
set -euo pipefail

command -v busybox >/dev/null 2>&1 || {
    echo "SKIP: busybox is required for the synthetic initramfs verifier test"
    exit 0
}

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
VERIFY=$REPO_ROOT/scripts/verify_tier3_initramfs.sh
MODULE=$REPO_ROOT/scripts/dracut/97bpir-tier3-init
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
ROOT=$TMP/root

mkdir -p "$ROOT/sbin" "$ROOT/bin" "$ROOT/usr/bin" "$ROOT/usr/local/bin" \
    "$ROOT/etc/sv/unified_server" "$ROOT/etc/sv/unified_server_watchdog" \
    "$ROOT/etc/sv/cloudflared"
cp "$(command -v busybox)" "$ROOT/usr/bin/busybox"
ln -s ../usr/bin/busybox "$ROOT/bin/sh"
cp "$MODULE/bpir-tier3-init.sh" "$ROOT/sbin/bpir-tier3-init"
cp "$MODULE/unified-server-run.sh" "$ROOT/etc/sv/unified_server/run"
cp "$MODULE/unified-server-finish.sh" "$ROOT/etc/sv/unified_server/finish"
cp "$MODULE/startup-watchdog-run.sh" "$ROOT/etc/sv/unified_server_watchdog/run"
cp "$MODULE/cloudflared-run.sh" "$ROOT/etc/sv/cloudflared/run"
cp "$MODULE/ready-check.sh" "$ROOT/usr/local/bin/bpir-ready-check"
cp "$MODULE/read-tunnel-token.sh" "$ROOT/usr/local/bin/bpir-read-tunnel-token"

for path in usr/bin/runsvdir usr/bin/runsv usr/bin/sv usr/local/bin/cloudflared; do
    printf '#!/bin/sh\nexit 0\n' > "$ROOT/$path"
done
printf '#!/bin/sh\necho synthetic server\n' > "$ROOT/usr/local/bin/unified_server"
chmod 0755 \
    "$ROOT/sbin/bpir-tier3-init" \
    "$ROOT/usr/bin"/* \
    "$ROOT/usr/local/bin"/* \
    "$ROOT/etc/sv/unified_server"/* \
    "$ROOT/etc/sv/unified_server_watchdog"/* \
    "$ROOT/etc/sv/cloudflared"/*

SERVER_SHA=$(sha256sum "$ROOT/usr/local/bin/unified_server" | awk '{print $1}')
"$VERIFY" "$ROOT" "$SERVER_SHA" >/dev/null

mv "$ROOT/usr/local/bin/bpir-ready-check" "$TMP/ready-check"
mkdir "$ROOT/usr/local/bin/bpir-ready-check"
chmod 0755 "$ROOT/usr/local/bin/bpir-ready-check"
if "$VERIFY" "$ROOT" "$SERVER_SHA" >/dev/null 2>&1; then
    echo "FAIL: verifier accepted a directory in place of an executable" >&2
    exit 1
fi
rmdir "$ROOT/usr/local/bin/bpir-ready-check"
mv "$TMP/ready-check" "$ROOT/usr/local/bin/bpir-ready-check"

# Model the Nix initramfs layout: required entry points are absolute symlinks
# into a store that must itself be present beneath the extracted root.
NIX_SERVER=$ROOT/nix/store/fake-unified-server/bin/unified_server
mkdir -p "${NIX_SERVER%/*}"
mv "$ROOT/usr/local/bin/unified_server" "$NIX_SERVER"
ln -s /nix/store/fake-unified-server/bin/unified_server \
    "$ROOT/usr/local/bin/unified_server"
"$VERIFY" "$ROOT" "$SERVER_SHA" >/dev/null

mv "$NIX_SERVER" "$TMP/missing-nix-server"
if "$VERIFY" "$ROOT" "$SERVER_SHA" >/dev/null 2>&1; then
    echo "FAIL: verifier followed an absolute symlink outside extracted root" >&2
    exit 1
fi
mv "$TMP/missing-nix-server" "$NIX_SERVER"

rm "$ROOT/usr/local/bin/unified_server"
ln -s /bin/true "$ROOT/usr/local/bin/unified_server"
if "$VERIFY" "$ROOT" "$(sha256sum /bin/true | awk '{print $1}')" >/dev/null 2>&1; then
    echo "FAIL: verifier accepted a host-only absolute symlink target" >&2
    exit 1
fi
rm "$ROOT/usr/local/bin/unified_server"
ln -s /nix/store/fake-unified-server/bin/unified_server \
    "$ROOT/usr/local/bin/unified_server"

mv "$ROOT/etc/sv/unified_server/finish" "$TMP/finish"
if "$VERIFY" "$ROOT" "$SERVER_SHA" >/dev/null 2>&1; then
    echo "FAIL: verifier accepted initramfs without runit finish" >&2
    exit 1
fi
mv "$TMP/finish" "$ROOT/etc/sv/unified_server/finish"

chmod 0644 "$ROOT/etc/sv/unified_server_watchdog/run"
if "$VERIFY" "$ROOT" "$SERVER_SHA" >/dev/null 2>&1; then
    echo "FAIL: verifier accepted non-executable watchdog" >&2
    exit 1
fi
chmod 0755 "$ROOT/etc/sv/unified_server_watchdog/run"

BAD_SHA=$(printf '0%.0s' {1..64})
if "$VERIFY" "$ROOT" "$BAD_SHA" >/dev/null 2>&1; then
    echo "FAIL: verifier accepted wrong unified_server hash" >&2
    exit 1
fi

echo "Tier 3 initramfs verifier synthetic tests passed"
