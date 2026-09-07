#!/usr/bin/env bash
# Runs on the VPSBG stock rootfs as root at the start of a build window: create the
# per-release build directory (owned by pir so the runtime build can clone into it)
# and copy the retained UKI inputs from a previous build directory, checking them
# against the sha256 values the operator passes from that release's sidecar.
set -euo pipefail
: "${D:?build dir}"; : "${INPUTS_FROM:?previous build dir}"; : "${ORAMCTL_SHA256:?}"; : "${BHTM_SHA256:?}"
[ "$(id -un)" = root ] || { echo "run as root" >&2; exit 1; }
[ ! -e "$D" ] || { echo "build dir already exists: $D" >&2; exit 1; }
mkdir -p "$D/inputs" "$D/archive/tier3"
cp -p "$INPUTS_FROM/inputs/oramctl" "$D/inputs/oramctl"
cp -p "$INPUTS_FROM/inputs/height-940611.leaf-proof.json" "$D/inputs/height-940611.leaf-proof.json"
a=$(sha256sum "$D/inputs/oramctl" | awk '{print $1}'); [ "$a" = "$ORAMCTL_SHA256" ] || { echo "oramctl sha256 $a != $ORAMCTL_SHA256" >&2; exit 1; }
b=$(sha256sum "$D/inputs/height-940611.leaf-proof.json" | awk '{print $1}'); [ "$b" = "$BHTM_SHA256" ] || { echo "leaf proof sha256 $b != $BHTM_SHA256" >&2; exit 1; }
echo "inputs_ok oramctl=$a bhtm=$b"
chown -R pir:pir "$D"
echo "cloudflared_on_host=$(/usr/local/bin/cloudflared --version 2>&1 | head -1)"
echo "PASS prep_inputs"
