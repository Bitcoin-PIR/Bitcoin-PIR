#!/usr/bin/env bash
# Read-only VPSBG control-plane and Direct ORAM progress snapshot.
set -euo pipefail

readonly API_BASE='https://api.vpsbg.eu/v1'
readonly DEFAULT_STATUS_URL='https://weikeng2.bitcoinpir.org/status.json'
readonly DEFAULT_TOKEN_FILE="${XDG_CONFIG_HOME:-${HOME:?HOME is required}/.config}/bitcoinpir/secrets/vpsbg-api-token"

usage() {
  cat <<'USAGE'
usage: vpsbg-production-status.sh [--server-id ID] [--status-url URL]
       vpsbg-production-status.sh --root EVIDENCE_ROOT [--server-id ID]

Default mode performs only GET /servers, GET /servers/{id}, and GET
/status.json.  --root is an offline evidence directory containing servers.json
and server.json; status.json is optional.
USAGE
}

server_id="${VPSBG_SERVER_ID:-}"
status_url="${VPSBG_ORAM_STATUS_URL:-$DEFAULT_STATUS_URL}"
root=
while (($#)); do
  case "$1" in
    --server-id) server_id=${2:?missing server ID}; shift 2 ;;
    --status-url) status_url=${2:?missing status URL}; shift 2 ;;
    --root) root=${2:?missing evidence root}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -z "$server_id" || "$server_id" =~ ^[0-9]+$ ]] || { echo 'server ID must be numeric' >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo 'jq is required' >&2; exit 2; }

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/bpir-vpsbg-status.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
servers_file="$tmpdir/servers.json"
server_file="$tmpdir/server.json"
status_file="$tmpdir/status.json"
offline=0
oram_status_source=unavailable

copy_json() {
  local source=$1 destination=$2
  [[ -r "$source" ]] || { echo "offline JSON is unreadable: $source" >&2; exit 2; }
  jq -e . "$source" >"$destination"
}

if [[ -n "$root" ]]; then
  [[ -d "$root" ]] || { echo 'evidence root is not a directory' >&2; exit 2; }
  offline=1
  copy_json "$root/servers.json" "$servers_file"
  copy_json "$root/server.json" "$server_file"
  if [[ -e "$root/status.json" ]]; then
    copy_json "$root/status.json" "$status_file"
    oram_status_source=offline-evidence
  else
    printf '%s\n' '{}' >"$status_file"
  fi
else
  token_file="${VPSBG_API_TOKEN_FILE:-$DEFAULT_TOKEN_FILE}"
  [[ -r "$token_file" && -s "$token_file" ]] || { echo 'VPSBG API token file is missing or empty' >&2; exit 2; }
  token=$(tr -d '\r\n' <"$token_file")
  [[ -n "$token" ]] || { echo 'VPSBG API token is empty' >&2; exit 2; }
  curl --fail --silent --show-error --max-time 20 --retry 0 -H 'Accept: application/json' -H "Authorization: Bearer $token" "$API_BASE/servers" | jq -e . >"$servers_file"
fi

list_filter='if type == "object" and (.data | type) == "array" then .data else error("expected {data:[...]}") end'
server_count=$(jq -er "$list_filter | length" "$servers_file")
if [[ -n "$server_id" ]]; then
  selected_count=$(jq -er --argjson id "$server_id" "$list_filter | map(select(.id == \$id)) | length" "$servers_file")
  [[ "$selected_count" == 1 ]] || { echo 'selected VPSBG server is absent or ambiguous' >&2; exit 2; }
else
  [[ "$server_count" == 1 ]] || { echo 'VPSBG server selection is ambiguous; pass --server-id or VPSBG_SERVER_ID' >&2; exit 2; }
  server_id=$(jq -er "$list_filter | .[0].id | if type == \"number\" and floor == . and . >= 0 then tostring else error(\"invalid server id\") end" "$servers_file")
fi

if ((offline)); then
  server=$(jq -ec --argjson id "$server_id" 'if type == "object" and .id == $id then . else error("detail does not match selected server") end' "$server_file")
else
  curl --fail --silent --show-error --max-time 20 --retry 0 -H 'Accept: application/json' -H "Authorization: Bearer $token" "$API_BASE/servers/$server_id" | jq -e 'if type == "object" then . else error("expected server detail object") end' >"$server_file"
  server=$(cat "$server_file")
  case "$status_url" in
    *\?*) status_request_url="$status_url&ts=$(date -u +%s)" ;;
    *) status_request_url="$status_url?ts=$(date -u +%s)" ;;
  esac
  if curl --fail --silent --max-time 20 --retry 0 \
    -H 'Accept: application/json' -H 'Cache-Control: no-cache, no-store' \
    -H 'Pragma: no-cache' "$status_request_url" | jq -e . >"$status_file"; then
    oram_status_source=public-status-json
  else
    printf '%s\n' '[status] public /status.json unavailable' >&2
    printf '%s\n' '{}' >"$status_file"
  fi
  unset token
fi

safe_string() { [[ ${1:-} =~ ^[A-Za-z0-9._:/@+=,-]+$ ]] && printf '%s\n' "$1" || printf '%s\n' unavailable; }
json_string() { jq -er "$1 | if type == \"string\" then . else error(\"not string\") end" <<<"$2" 2>/dev/null | while IFS= read -r v; do safe_string "$v"; done || printf unavailable; }
json_bool() { jq -r "$1 | if type == \"boolean\" then tostring else \"unavailable\" end" <<<"$2"; }
json_uint() { jq -r "$1 | if type == \"number\" and floor == . and . >= 0 then tostring else \"unavailable\" end" <<<"$2"; }

hostname=$(json_string '.hostname' "$server")
state=$(json_string '.status' "$server")
virtualization=$(json_string '.virtualization' "$server")
reachable=$(json_bool '.state.node_reachable' "$server")
running=$(json_bool '.state.running' "$server")
sev_level=$(json_uint '.state.amd_sev_level' "$server")
boot_mode=unavailable image_id=unavailable image_name=unavailable
measured_boot_kind=$(jq -r '. as $server | if ($server.state | type) == "object" and ($server.state | has("measured_boot")) then if $server.state.measured_boot == null then "stock" else "measured" end else "unavailable" end' <<<"$server")
if [[ "$measured_boot_kind" == stock ]]; then
  boot_mode=stock
elif [[ "$measured_boot_kind" == measured ]] && jq -e '.state.measured_boot.kernel_image | type == "object"' <<<"$server" >/dev/null; then
  boot_mode=measured
  image_id=$(json_uint '.state.measured_boot.kernel_image.id' "$server")
  image_name=$(json_string '.state.measured_boot.kernel_image.name' "$server")
fi

progress_valid=0
if [[ "$oram_status_source" != unavailable ]]; then
  if jq -e '
    type == "object" and (keys | sort) == ["hard_stop_seconds","reason","schema_version","stage","started_at_epoch","updated_at_epoch"] and
    .schema_version == 1 and
    (.stage as $s | ["input-validation","db0-build","db1-build","publish","failed"] | index($s)) and
    ([.started_at_epoch,.updated_at_epoch,.hard_stop_seconds] | all(type == "number" and floor == . and . >= 0)) and
    (.reason | type == "string" and test("^[A-Za-z0-9._-]+$"))
  ' "$status_file" >/dev/null; then
    progress_valid=1
  else
    if ((offline)); then
      echo 'offline status.json violates the Direct ORAM progress schema' >&2
      exit 2
    fi
    echo '[status] public /status.json violates the progress schema' >&2
    oram_status_source=unavailable
  fi
fi

oram_stage=unavailable oram_started_at_epoch=unavailable oram_updated_at_epoch=unavailable oram_elapsed_seconds=unavailable oram_hard_stop_seconds=unavailable oram_reason=unavailable
if ((progress_valid)); then
  oram_stage=$(jq -r '.stage' "$status_file")
  oram_started_at_epoch=$(jq -r '.started_at_epoch' "$status_file")
  oram_updated_at_epoch=$(jq -r '.updated_at_epoch' "$status_file")
  oram_hard_stop_seconds=$(jq -r '.hard_stop_seconds' "$status_file")
  oram_reason=$(jq -r '.reason' "$status_file")
  now=$(date -u +%s)
  if [[ "$now" =~ ^[0-9]+$ && "$now" -ge "$oram_started_at_epoch" ]]; then oram_elapsed_seconds=$((now - oram_started_at_epoch)); fi
fi

cat <<EOF
production_status=v3
control_plane_server_id=$server_id
control_plane_hostname=$hostname
control_plane_state=$state
control_plane_virtualization=$virtualization
control_plane_reachable=$reachable
control_plane_running=$running
control_plane_sev_level=$sev_level
boot_mode=$boot_mode
image_id=$image_id
image_name=$image_name
oram_status_source=$oram_status_source
oram_stage=$oram_stage
oram_started_at_epoch=$oram_started_at_epoch
oram_updated_at_epoch=$oram_updated_at_epoch
oram_elapsed_seconds=$oram_elapsed_seconds
oram_hard_stop_seconds=$oram_hard_stop_seconds
oram_reason=$oram_reason
EOF
