#!/usr/bin/env bash
# Thin operator entry point for the VPSBG measured-boot API.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/vpsbg-measured-boot.sh <status|images|upload|switch|rollback> [options]

Read-only:
  status [--server-id ID] [--status-url URL]
  images [--token-file PATH]

Mutations (require --apply; --dry-run is the default-safe preview):
  upload   --uki FILE [--token-file PATH] [--apply]
  switch   --server-id ID --image-id ID [--token-file PATH] [--apply]
  rollback --server-id ID --image-id ID [--token-file PATH] [--apply]

Status and images use VPSBG_API_TOKEN_FILE or
<repo>/.secrets/vpsbg-api-token. Mutations also accept --token-file PATH.
There is no delete action. Output is [stage] progress plus PASS and
NEXT_STEP. --dry-run neither reads the token nor contacts VPSBG.
EOF
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
action=${1:-}
[[ "$action" != --help && "$action" != -h ]] || { usage; exit 0; }
[[ -n "$action" ]] || { usage >&2; exit 2; }
shift || true
server_id= image= image_id= token_file= apply=0 dry_run=0 status_url_set=0 status_args=()
while (($#)); do
  case "$1" in
    --server-id) server_id=${2:?missing server ID}; status_args+=("$1" "$2"); shift 2 ;;
    --status-url) status_args+=("$1" "${2:?missing status URL}"); status_url_set=1; shift 2 ;;
    --uki) image=${2:?missing UKI path}; shift 2 ;;
    --image-id) image_id=${2:?missing image ID}; shift 2 ;;
    --token-file) token_file=${2:?missing token file}; shift 2 ;;
    --apply) apply=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ "$action" =~ ^(status|images|upload|switch|rollback)$ ]] || { usage >&2; exit 2; }
[[ -z "$server_id" || "$server_id" =~ ^[0-9]+$ ]] || { echo 'server ID must be numeric' >&2; exit 2; }
[[ -z "$image_id" || "$image_id" =~ ^[0-9]+$ ]] || { echo 'image ID must be numeric' >&2; exit 2; }

case "$action" in
  status)
    [[ -z "$image" && -z "$image_id" && -z "$token_file" ]] || { echo 'status accepts neither --uki, --image-id, nor --token-file' >&2; exit 2; }
    ;;
  images)
    [[ -z "$image" && -z "$image_id" && -z "$server_id" && "$status_url_set" == 0 ]] || {
      echo 'images accepts neither --uki, --image-id, --server-id, nor --status-url' >&2
      exit 2
    }
    ;;
  upload)
    [[ -z "$server_id" && -z "$image_id" && "$status_url_set" == 0 ]] || { echo 'upload accepts neither --server-id, --image-id, nor --status-url' >&2; exit 2; }
    ;;
  switch|rollback)
    [[ -z "$image" && "$status_url_set" == 0 ]] || { echo "$action accepts neither --uki nor --status-url" >&2; exit 2; }
    ;;
esac

if [[ "$action" == status ]]; then
  (( ! apply )) || { echo 'status does not accept --apply' >&2; exit 2; }
  if ((dry_run)); then
    echo '[stage] status preview'
    echo 'PASS action=status dry_run=true'
    echo 'NEXT_STEP=run without --dry-run for the read-only VPSBG status snapshot'
    exit 0
  fi
  echo '[stage] read-only VPSBG production status'
  "$root/scripts/vpsbg-production-status.sh" "${status_args[@]}"
  echo 'PASS action=status'
  echo 'NEXT_STEP=choose upload, switch, or rollback with explicit --apply when authorized'
  exit 0
fi

default_token_file="$root/.secrets/vpsbg-api-token"

if [[ "$action" == images ]]; then
  (( ! apply )) || { echo 'images does not accept --apply' >&2; exit 2; }
  if ((dry_run)); then
    echo '[stage] images preview'
    echo "token_file=${token_file:-${VPSBG_API_TOKEN_FILE:-$default_token_file}}"
    echo 'PASS action=images dry_run=true'
    echo 'NEXT_STEP=run without --dry-run to list uploaded VPSBG measured-boot images'
    exit 0
  fi
  command -v curl >/dev/null 2>&1 || { echo 'curl is required for a live VPSBG image list' >&2; exit 2; }
  command -v jq >/dev/null 2>&1 || { echo 'jq is required for a live VPSBG image list' >&2; exit 2; }
  token_file=${token_file:-${VPSBG_API_TOKEN_FILE:-$default_token_file}}
  [[ -s "$token_file" ]] || { echo "VPSBG API token file is missing or empty: $token_file" >&2; exit 2; }
  token=$(tr -d '\r\n' <"$token_file")
  trap 'unset token' EXIT
  echo '[stage] read-only VPSBG measured-boot images'
  response=$(curl --fail --silent --show-error --max-time 20 --retry 0 \
    -H 'Accept: application/json' -H "Authorization: Bearer $token" \
    https://api.vpsbg.eu/v1/measured-boot-images)
  unset token
  trap - EXIT
  images_json=$(jq -ec '
    if type == "object" and (.data | type) == "array" then .data
    elif type == "array" then .
    else error("expected {data:[...]} or an image array")
    end
  ' <<<"$response") || { echo 'VPSBG image list response is not an image array' >&2; exit 1; }
  jq -e '
    type == "array" and all(
      type == "object" and
      (.id | type == "number" and floor == . and . >= 0) and
      (.name | type == "string")
    )
  ' <<<"$images_json" >/dev/null \
    || { echo 'VPSBG image list entries are missing numeric id or name' >&2; exit 1; }
  image_count=$(jq -er 'length' <<<"$images_json")
  jq -r '
    .[] |
    "image_id=" + (.id | tostring) +
    " image_name=" + .name +
    " image_size=" + (
      .size as $size |
      if ($size | type) == "number" and ($size | floor) == $size and $size >= 0
      then ($size | tostring) else "unavailable" end
    ) +
    " image_in_use=" + (
      .in_use as $used |
      if ($used | type) == "boolean" then ($used | tostring) else "unavailable" end
    )
  ' <<<"$images_json"
  printf 'image_count=%s\n' "$image_count"
  printf 'image_quota=5\n'
  echo "PASS action=images count=$image_count/5"
  echo 'NEXT_STEP=record unused image IDs before upload; deleting an image needs separate authorization'
  exit 0
fi

if [[ "$action" == upload ]]; then
  [[ -n "$image" ]] || { echo 'upload requires --uki FILE' >&2; exit 2; }
elif [[ -z "$server_id" || -z "$image_id" ]]; then
  echo "$action requires --server-id ID and --image-id ID" >&2; exit 2
fi

if ((dry_run || !apply)); then
  echo "[stage] ${action} preview"
  [[ -n "$image" ]] && printf 'candidate_image=%s\n' "$image"
  [[ -n "$server_id" ]] && printf 'server_id=%s\n' "$server_id"
  [[ -n "$image_id" ]] && printf 'image_id=%s\n' "$image_id"
  echo "PASS action=$action dry_run=true"
  echo 'NEXT_STEP=review the values, then rerun with --apply to issue the VPSBG API request'
  exit 0
fi

command -v curl >/dev/null 2>&1 || { echo 'curl is required for a live VPSBG mutation' >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo 'jq is required for a live VPSBG mutation' >&2; exit 2; }
token_file=${token_file:-${VPSBG_API_TOKEN_FILE:-$default_token_file}}
[[ -s "$token_file" ]] || { echo "VPSBG API token file is missing or empty: $token_file" >&2; exit 2; }
token=$(tr -d '\r\n' <"$token_file")
trap 'unset token' EXIT
api_base=https://api.vpsbg.eu/v1
echo "[stage] VPSBG $action request"
if [[ "$action" == upload ]]; then
  [[ -f "$image" ]] || { echo "image is not a regular file: $image" >&2; exit 2; }
  size=$(wc -c <"$image" | tr -d '[:space:]')
  ((size < 1000000000)) || { echo 'image must be smaller than 1 GB' >&2; exit 2; }
  response=$(curl --fail --silent --show-error -H 'Accept: application/json' -H "Authorization: Bearer $token" -F "file=@$image" "$api_base/measured-boot-images")
  jq -e 'type == "object" and (.id | type == "number" and floor == . and . >= 0) and (.name | type == "string")' <<<"$response" >/dev/null \
    || { echo 'VPSBG upload response is not the expected image object' >&2; exit 1; }
  returned_image_id=$(jq -r '.id' <<<"$response")
  returned_image_name=$(jq -r '.name' <<<"$response")
  returned_image_size=$(jq -r '.size as $size | if ($size | type) == "number" and ($size | floor) == $size and $size >= 0 then $size else "unavailable" end' <<<"$response")
  printf 'image_id=%s image_name=%s image_size=%s\n' "$returned_image_id" "$returned_image_name" "$returned_image_size"
  echo "PASS action=upload image_id=$returned_image_id"
  echo 'NEXT_STEP=record the returned image ID, then run switch with --apply when authorized'
else
  response=$(curl --fail --silent --show-error -H 'Accept: application/json' -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "{\"kernel_image_id\":$image_id}" "$api_base/servers/$server_id/measured-boot")
  jq -e --argjson expected_server_id "$server_id" 'type == "object" and (.id | type == "number" and floor == . and . == $expected_server_id)' <<<"$response" >/dev/null \
    || { echo 'VPSBG measured-boot response does not match the selected server' >&2; exit 1; }
  printf 'server_id=%s image_id=%s\n' "$server_id" "$image_id"
  echo "PASS action=$action server_id=$server_id image_id=$image_id"
  echo 'NEXT_STEP=wait for VPSBG to report running, then complete attestation and channel verification'
fi
