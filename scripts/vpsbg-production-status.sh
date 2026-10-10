#!/usr/bin/env bash
# Read-only VPSBG control-plane and Direct ORAM progress snapshot.
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: vpsbg-production-status.sh [--server-id ID] [--status-url URL]

GETs /servers/{id} from the VPSBG API and the host's public /status.json.
USAGE
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
server_id=${VPSBG_SERVER_ID:-26939}
status_url=${VPSBG_ORAM_STATUS_URL:-https://weikeng2.bitcoinpir.org/status.json}
while (($#)); do
  case "$1" in
    --server-id) server_id=${2:?missing server ID}; shift 2 ;;
    --status-url) status_url=${2:?missing status URL}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

token=$(tr -d '\r\n' <"${VPSBG_API_TOKEN_FILE:-$root/.secrets/vpsbg-api-token}")
curl --fail --silent --show-error --max-time 20 -H 'Accept: application/json' \
  -H "Authorization: Bearer $token" "https://api.vpsbg.eu/v1/servers/$server_id" | jq -r '
  "control_plane_server_id=\(.id)",
  "control_plane_hostname=\(.hostname)",
  "control_plane_state=\(.status)",
  "control_plane_virtualization=\(.virtualization)",
  "control_plane_reachable=\(.state.node_reachable)",
  "control_plane_running=\(.state.running)",
  "control_plane_sev_level=\(.state.amd_sev_level)",
  "boot_mode=\(if .state.measured_boot == null then "stock" else "measured" end)",
  "image_id=\(.state.measured_boot.kernel_image.id // "unavailable")",
  "image_name=\(.state.measured_boot.kernel_image.name // "unavailable")"'

case "$status_url" in
  *\?*) status_url="$status_url&ts=$(date -u +%s)" ;;
  *) status_url="$status_url?ts=$(date -u +%s)" ;;
esac
if status=$(curl --fail --silent --max-time 20 -H 'Accept: application/json' \
  -H 'Cache-Control: no-cache, no-store' "$status_url"); then
  jq -r --argjson now "$(date -u +%s)" '
    "oram_stage=\(.stage)",
    "oram_started_at_epoch=\(.started_at_epoch)",
    "oram_updated_at_epoch=\(.updated_at_epoch)",
    "oram_elapsed_seconds=\(if (.started_at_epoch | type) == "number" then $now - .started_at_epoch else "unavailable" end)",
    "oram_hard_stop_seconds=\(.hard_stop_seconds)",
    "oram_reason=\(.reason)"' <<<"$status" || echo 'oram_status=unparseable'
else
  echo 'oram_status=unavailable'
fi
