#!/usr/bin/env bash
# Read-only pir1 SSH health, a public attest of the pir2 MacBook node, and the
# Direct ORAM TEE host's VPSBG status plus its pinned SEV-SNP attest.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/production-status.sh [--server-id ID] [--dry-run]

Prints pir1 systemd/port/disk health over SSH, then attests the pir2
MacBook node over its public endpoint against PIR2_MACBOOK_PIN. Then it
shows the Direct ORAM TEE host's VPSBG control-plane status
(scripts/vpsbg-production-status.sh, default server 26939) and attests the
host against PIR2_TIER3_PIN (MEASUREMENT + binary) under the AMD ARK that
ORAM_PROVIDER names. Endpoints and pins are read from web/src; while
ORAM_PROVIDER is null the ORAM host is reported paused and skipped. This
command never restarts a service and does not inspect Signet or
functional-beta units.

BPIR_ADMIN=/absolute/path/to/bpir-admin runs a prebuilt binary; otherwise
the attests run through `cargo run --release -p bpir-admin`. The VPSBG
status reads VPSBG_API_TOKEN_FILE or <repo>/.secrets/vpsbg-api-token.
EOF
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly HETZNER_HOST=65.21.91.217
readonly HETZNER_KNOWN_HOSTS="$root/deploy/known_hosts"
readonly PIN_FILE="$root/web/src/attest-pin.ts"
readonly PROVIDERS_FILE="$root/web/src/production-providers.ts"
readonly DEFAULT_ORAM_SERVER_ID=26939

server_id=$DEFAULT_ORAM_SERVER_ID dry_run=0
while (($#)); do
  case "$1" in
    --server-id) server_id=${2:?missing server ID}; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ "$server_id" =~ ^[0-9]+$ ]] || { echo 'server ID must be numeric' >&2; exit 2; }
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
binary = pin and re.search(r"\bbinarySha256Hex:\s*'([0-9a-fA-F]{64})'", pin.group(0))
transition = pin and re.search(r"transitionBinarySha256Hex:\s*'([0-9a-fA-F]{64})'", pin.group(0))
if not endpoint or not binary:
    sys.stderr.write("PIR2_PROVIDER.endpoint or PIR2_MACBOOK_PIN.binarySha256Hex is missing\n")
    sys.exit(2)
print(endpoint.group(1))
print(binary.group(1).lower())
print(transition.group(1).lower() if transition else "-")

# The Direct ORAM host: ORAM_PROVIDER names its pin and its ARK constant;
# the ARK hex sits next to that constant as <NAME>_HEX.
oram = re.search(r"export const ORAM_PROVIDER\b[^=]*=\s*(null;|\{.*?\n\};)", providers, re.S)
if not oram:
    sys.stderr.write("ORAM_PROVIDER is missing\n")
    sys.exit(2)
if oram.group(1) == "null;":
    print("-\n-\n-\n-")
    sys.exit(0)
block = oram.group(1)
oram_endpoint = re.search(r"endpoint:\s*'(wss://[^']+)'", block)
pin_name = re.search(r"serverPin:\s*([A-Z0-9_]+)", block)
ark_name = re.search(r"expectedArkFingerprint:\s*([A-Z0-9_]+)", block)
oram_pin = pin_name and re.search(rf"export const {pin_name.group(1)}\b.*?\n\}};", pins, re.S)
measurement = oram_pin and re.search(r"\bmeasurementHex:\s*'([0-9a-fA-F]{96})'", oram_pin.group(0))
oram_binary = oram_pin and re.search(r"\bbinarySha256Hex:\s*'([0-9a-fA-F]{64})'", oram_pin.group(0))
ark = ark_name and re.search(rf"export const {ark_name.group(1)}_HEX\s*=\s*'([0-9a-fA-F]{{64}})'", pins)
if not (oram_endpoint and measurement and oram_binary and ark):
    sys.stderr.write("ORAM_PROVIDER endpoint, its pin's MEASUREMENT/binary, or its ARK hex is missing\n")
    sys.exit(2)
print(oram_endpoint.group(1))
print(measurement.group(1).lower())
print(oram_binary.group(1).lower())
print(ark.group(1).lower())
PY
)
{
  read -r pir2_url; read -r pir2_binary; read -r pir2_transition
  read -r oram_url; read -r oram_measurement; read -r oram_binary; read -r oram_ark
} <<<"$pir2"

if ((dry_run)); then
  echo '[stage] production status preview'
  echo "pir1_host=$HETZNER_HOST"
  echo "pir1_known_hosts=$HETZNER_KNOWN_HOSTS"
  echo "pir2_url=$pir2_url"
  echo "pir2_pin_source=$PIN_FILE"
  echo "pir2_transition_pin=$([[ "$pir2_transition" == - ]] && echo none || echo set)"
  if [[ "$oram_url" == - ]]; then
    echo 'oram=paused'
  else
    echo "oram_url=$oram_url"
    echo "oram_server_id=$server_id"
    echo "oram_pin_source=$PIN_FILE"
  fi
  echo 'PASS production_status dry_run=true'
  echo 'NEXT_STEP=run without --dry-run for the live pir1 SSH, pir2 attest and ORAM host snapshot'
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
attest_out=$("${admin[@]}" attest "$pir2_url" 2>&1) || {
  printf '%s\n' "$attest_out"
  echo 'pir2 attest failed' >&2
  exit 1
}
printf '%s\n' "$attest_out"
running=$(awk '$1 == "binary_sha256:" { print tolower($2) }' <<<"$attest_out")
if [[ "$running" == "$pir2_binary" ]]; then
  echo '✓ binary_sha256 matches PIR2_MACBOOK_PIN'
elif [[ "$pir2_transition" != - && "$running" == "$pir2_transition" ]]; then
  echo '✓ binary_sha256 matches the transition build of PIR2_MACBOOK_PIN (switch pending)'
else
  echo "pir2 binary_sha256 ${running:-unavailable} matches neither build PIR2_MACBOOK_PIN accepts" >&2
  exit 1
fi
echo 'PASS host=pir2'

echo '[stage] Direct ORAM TEE host'
if [[ "$oram_url" == - ]]; then
  echo 'oram=paused (ORAM_PROVIDER is null)'
else
  echo "oram_url=$oram_url"
  "$root/scripts/vpsbg-production-status.sh" --server-id "$server_id"
  oram_out=$("${admin[@]}" attest "$oram_url" \
    --expect-measurement "$oram_measurement" \
    --expect-binary "$oram_binary" \
    --expect-ark-fingerprint "$oram_ark" 2>&1) || {
    printf '%s\n' "$oram_out"
    echo 'ORAM host attest failed: MEASUREMENT, binary, or AMD chain differs from the pins' >&2
    exit 1
  }
  printf '%s\n' "$oram_out"
  echo 'PASS host=oram'
fi
echo 'PASS production_status'
echo 'NEXT_STEP=change the pir2 MacBook node only through docs/runbooks/pir2-macbook-replacement.md, and the ORAM host only through Flows E-G, after this run is authorized'
