#!/usr/bin/env bash
# Unattended run of scripts/directory-publish.sh for launchd
# (deploy/launchd/org.bitcoinpir.directory-publish.plist.example). launchd
# starts it with a bare environment, so it sets PATH (the newest nvm Node for
# the readback, then the system directories), points BPIR_ADMIN at the release
# build, opens the SSH port-forward to the pir1 publisher lane for the run and
# closes it again. Arguments go through to directory-publish.sh
# (--validate-only). Needs an ssh_config host `pir-hetzner` with key
# authentication; stdout and stderr go to the log file the plist names.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
node_bin=$(ls -d "$HOME"/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -n 1)
export PATH="${node_bin:+$node_bin:}/usr/bin:/bin:/usr/sbin:/sbin"
export BPIR_ADMIN=${BPIR_ADMIN:-$REPO/target/release/bpir-admin}

echo "== $(date -u +%FT%TZ) directory-publish start"
ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -L 8097:127.0.0.1:8097 pir-hetzner &
forward=$!
trap 'kill "$forward" 2>/dev/null || true' EXIT
for ((i = 0; i < 30; i++)); do
  nc -z 127.0.0.1 8097 2>/dev/null && break
  sleep 1
done
"$REPO/scripts/directory-publish.sh" "$REPO/.keys/directory" "$@"
echo "== $(date -u +%FT%TZ) directory-publish done"
