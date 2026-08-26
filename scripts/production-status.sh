#!/usr/bin/env bash
# Read-only pir1 SSH health plus pir2 VPSBG control-plane status.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/production-status.sh [--server-id ID] [--dry-run]

Prints pir1 systemd/port/disk health over SSH, then the existing pir2
VPSBG status snapshot. This command never restarts a service and does
not inspect Signet or functional-beta units.
EOF
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly HETZNER_HOST=65.21.91.217
readonly HETZNER_KNOWN_HOSTS="$root/deploy/known_hosts"
readonly DEFAULT_TOKEN_FILE="$root/.secrets/vpsbg-api-token"

server_id= dry_run=0
while (($#)); do
  case "$1" in
    --server-id) server_id=${2:?missing server ID}; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ -z "$server_id" || "$server_id" =~ ^[0-9]+$ ]] || { echo 'server ID must be numeric' >&2; exit 2; }

[[ -r "$HETZNER_KNOWN_HOSTS" && -s "$HETZNER_KNOWN_HOSTS" ]] || {
  echo "Hetzner known_hosts is missing or empty: $HETZNER_KNOWN_HOSTS" >&2
  exit 2
}
token_file=${VPSBG_API_TOKEN_FILE:-$DEFAULT_TOKEN_FILE}

if ((dry_run)); then
  echo '[stage] production status preview'
  echo "pir1_host=$HETZNER_HOST"
  echo "pir1_known_hosts=$HETZNER_KNOWN_HOSTS"
  echo "pir2_token_file=$token_file"
  [[ -n "$server_id" ]] && echo "server_id=$server_id"
  echo 'PASS production_status dry_run=true'
  echo 'NEXT_STEP=run without --dry-run for the live pir1 SSH and pir2 API snapshot'
  exit 0
fi

[[ -r "$token_file" && -s "$token_file" ]] || {
  echo "VPSBG API token file is missing or empty: $token_file" >&2
  exit 2
}

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

echo '[stage] pir2 VPSBG status'
status_args=()
[[ -z "$server_id" ]] || status_args+=(--server-id "$server_id")
# POSIX-safe empty-array expansion: a bare quoted-at expansion is an unbound
# variable under `set -u` on bash < 4.4 (e.g. macOS /bin/bash 3.2).
"$root/scripts/vpsbg-production-status.sh" "${status_args[@]+"${status_args[@]}"}"
echo 'PASS host=pir2'
echo 'PASS production_status'
echo 'NEXT_STEP=use scripts/vpsbg-measured-boot.sh or scripts/vpsbg-data-disk.sh only after this run is authorized'
