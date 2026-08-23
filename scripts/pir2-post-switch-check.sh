#!/usr/bin/env bash
# Wait for pir2 measured boot, then verify against web/src/attest-pin.ts.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/pir2-post-switch-check.sh [--server-id ID] [--status-url URL]
       [--pin-file PATH] [--dry-run]

Reads PIR2 measurement and binary pins from web/src/attest-pin.ts (or
--pin-file), waits until VPSBG reports boot_mode=measured and
running=true, then runs scripts/verify_oram_tier3_deploy.sh. A pin
mismatch is a hard stop; this command never edits attest-pin.ts.
EOF
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly DEFAULT_PIN_FILE="$root/web/src/attest-pin.ts"
readonly HARD_STOP_SECONDS=900

server_id= status_url= pin_file=$DEFAULT_PIN_FILE dry_run=0
while (($#)); do
  case "$1" in
    --server-id) server_id=${2:?missing server ID}; shift 2 ;;
    --status-url) status_url=${2:?missing status URL}; shift 2 ;;
    --pin-file) pin_file=${2:?missing pin file}; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -z "$server_id" || "$server_id" =~ ^[0-9]+$ ]] || { echo 'server ID must be numeric' >&2; exit 2; }
[[ -r "$pin_file" && -s "$pin_file" ]] || { echo "pin file is missing or empty: $pin_file" >&2; exit 2; }

parsed=$(python3 - "$pin_file" <<'PY'
import re
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8").read()
block = re.search(
    r"export const PIR2_TIER3_PIN\s*:\s*ServerAttestPin\s*=\s*\{(.*?)\n\};",
    text,
    re.S,
)
if not block:
    sys.stderr.write("PIR2_TIER3_PIN is missing from the pin file\n")
    sys.exit(2)

def field(name: str) -> str:
    match = re.search(
        rf"{name}\s*:\s*['\"]([0-9a-fA-F]+)['\"]",
        block.group(1),
    )
    return match.group(1).lower() if match else ""

measurement = field("measurementHex")
binary = field("binarySha256Hex")
if len(measurement) != 96:
    sys.stderr.write("PIR2_TIER3_PIN.measurementHex is missing or not 96 hex characters\n")
    sys.exit(2)
if len(binary) != 64:
    sys.stderr.write("PIR2_TIER3_PIN.binarySha256Hex is missing or not 64 hex characters\n")
    sys.exit(2)
print(measurement)
print(binary)
PY
)
measurement=${parsed%%$'\n'*}
binary=${parsed#*$'\n'}

echo "pin_source=$pin_file"
echo 'pin_fields=measurementHex,binarySha256Hex'
echo "hard_stop_seconds=$HARD_STOP_SECONDS"

if ((dry_run)); then
  echo '[stage] post-switch check preview'
  echo 'PASS action=post_switch_check dry_run=true'
  echo 'NEXT_STEP=run without --dry-run after the guest reports running'
  exit 0
fi

status_args=()
[[ -z "$server_id" ]] || status_args+=(--server-id "$server_id")
[[ -z "$status_url" ]] || status_args+=(--status-url "$status_url")

status_field() {
  local key=$1
  awk -F= -v key="$key" '$1 == key { print $2; found=1 } END { if (!found) print "unavailable" }'
}

echo '[stage] wait for measured boot'
started=$(date -u +%s)
while :; do
  now=$(date -u +%s)
  if (( now - started >= HARD_STOP_SECONDS )); then
    echo "hard stop: pir2 did not reach boot_mode=measured and running=true in ${HARD_STOP_SECONDS}s" >&2
    exit 1
  fi
  snapshot=$("$root/scripts/vpsbg-production-status.sh" "${status_args[@]}")
  boot_mode=$(status_field boot_mode <<<"$snapshot")
  running=$(status_field control_plane_running <<<"$snapshot")
  image_id=$(status_field image_id <<<"$snapshot")
  printf 'boot_mode=%s control_plane_running=%s image_id=%s elapsed_seconds=%s\n' \
    "$boot_mode" "$running" "$image_id" "$((now - started))"
  if [[ "$boot_mode" == measured && "$running" == true ]]; then
    break
  fi
  sleep 10
done

echo "image_id=$image_id"
echo '[stage] verify live attest against pin file'
EXPECT_MEASUREMENT=$measurement EXPECT_BINARY=$binary \
  "$root/scripts/verify_oram_tier3_deploy.sh"
echo 'PASS action=post_switch_check'
echo 'NEXT_STEP=leave attest-pin.ts unchanged unless a separate pin-update is authorized'
