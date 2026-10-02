#!/usr/bin/env bash
# Read-only pir1 SSH health plus a public attest of the pir2 MacBook node.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/production-status.sh [--dry-run]

Prints pir1 systemd/port/disk health over SSH, then attests the pir2
MacBook node over its public endpoint against PIR2_MACBOOK_PIN. The
endpoint and pin are read from web/src. The VPSBG pir2 host was retired
on 2026-10-02; scripts/vpsbg-production-status.sh covers a future VPSBG
host only. This command never restarts a service and does not inspect
Signet or functional-beta units.

BPIR_ADMIN=/absolute/path/to/bpir-admin runs a prebuilt binary; otherwise
the attest runs through `cargo run --release -p bpir-admin`.
EOF
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly HETZNER_HOST=65.21.91.217
readonly HETZNER_KNOWN_HOSTS="$root/deploy/known_hosts"
readonly PIN_FILE="$root/web/src/attest-pin.ts"
readonly PROVIDERS_FILE="$root/web/src/production-providers.ts"

dry_run=0
while (($#)); do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -r "$HETZNER_KNOWN_HOSTS" && -s "$HETZNER_KNOWN_HOSTS" ]] || {
  echo "Hetzner known_hosts is missing or empty: $HETZNER_KNOWN_HOSTS" >&2
  exit 2
}

pir2=$(python3 - "$PROVIDERS_FILE" "$PIN_FILE" <<'PY'
import re
import sys

providers = open(sys.argv[1], encoding="utf-8").read()
pins = open(sys.argv[2], encoding="utf-8").read()
provider = re.search(r"export const PIR2_PROVIDER\b.*?\n\};", providers, re.S)
pin = re.search(r"export const PIR2_MACBOOK_PIN\b.*?\n\};", pins, re.S)
endpoint = provider and re.search(r"endpoint:\s*'(wss://[^']+)'", provider.group(0))
binary = pin and re.search(r"binarySha256Hex:\s*'([0-9a-fA-F]{64})'", pin.group(0))
if not endpoint or not binary:
    sys.stderr.write("PIR2_PROVIDER.endpoint or PIR2_MACBOOK_PIN.binarySha256Hex is missing\n")
    sys.exit(2)
print(endpoint.group(1))
print(binary.group(1).lower())
PY
)
pir2_url=${pir2%%$'\n'*}
pir2_binary=${pir2#*$'\n'}

if ((dry_run)); then
  echo '[stage] production status preview'
  echo "pir1_host=$HETZNER_HOST"
  echo "pir1_known_hosts=$HETZNER_KNOWN_HOSTS"
  echo "pir2_url=$pir2_url"
  echo "pir2_pin_source=$PIN_FILE"
  echo 'PASS production_status dry_run=true'
  echo 'NEXT_STEP=run without --dry-run for the live pir1 SSH and pir2 attest snapshot'
  exit 0
fi

if [[ -n "${BPIR_ADMIN:-}" ]]; then
  [[ "$BPIR_ADMIN" == /* && -f "$BPIR_ADMIN" && -x "$BPIR_ADMIN" ]] \
    || { echo "BPIR_ADMIN must be an absolute path to an executable file: $BPIR_ADMIN" >&2; exit 2; }
  admin=("$BPIR_ADMIN")
else
  admin=(cargo run --quiet --release --manifest-path "$root/Cargo.toml" -p bpir-admin --)
fi

echo '[stage] pir1 Hetzner health'
echo "pir1_host=$HETZNER_HOST"
pir1_out=$(
  ssh -o BatchMode=yes -o ConnectTimeout=20 \
    -o UserKnownHostsFile="$HETZNER_KNOWN_HOSTS" \
    -o StrictHostKeyChecking=yes \
    "root@$HETZNER_HOST" 'bash -s' <<'REMOTE'
set -euo pipefail
primary=$(systemctl is-active pir-primary 2>/dev/null || true)
cloudflared=$(systemctl is-active cloudflared 2>/dev/null || true)
if ss -tln 2>/dev/null | grep -Eq ':8091\b'; then
  port=listening
else
  port=missing
fi
disk=$(df -P /home/pir | awk 'NR==2 { print $5 }')
printf 'pir1_primary=%s\n' "${primary:-unavailable}"
printf 'pir1_cloudflared=%s\n' "${cloudflared:-unavailable}"
printf 'pir1_port_8091=%s\n' "$port"
printf 'pir1_disk_used=%s\n' "${disk:-unavailable}"
REMOTE
) || {
  echo 'pir1 SSH health check failed or exceeded 20s' >&2
  exit 1
}
printf '%s\n' "$pir1_out"
echo 'PASS host=pir1'

echo '[stage] pir2 MacBook node attest'
echo "pir2_url=$pir2_url"
"${admin[@]}" attest "$pir2_url" --expect-binary "$pir2_binary" || {
  echo 'pir2 attest failed or binary_sha256 does not match PIR2_MACBOOK_PIN' >&2
  exit 1
}
echo 'PASS host=pir2'
echo 'PASS production_status'
echo 'NEXT_STEP=change the pir2 MacBook node only through docs/runbooks/pir2-macbook-replacement.md after this run is authorized'
