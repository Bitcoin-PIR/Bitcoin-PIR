#!/usr/bin/env bash
# Operator entry point for the VPSBG measured-boot API.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/vpsbg-measured-boot.sh <command> [options]

  status [--server-id ID] [--status-url URL]  VPSBG and public status snapshot
  images                                     list uploaded measured-boot images
  upload --uki FILE                          upload a UKI; prints its image ID
  switch --server-id ID --image-id ID        attach an image (also to roll back)

The API token comes from --token-file PATH, VPSBG_API_TOKEN_FILE, or
<repo>/.secrets/vpsbg-api-token.
EOF
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
action=${1:-}
case "$action" in
  status|images|upload|switch) shift ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
server_id= image= image_id= token_file= status_args=()
while (($#)); do
  case "$1" in
    --server-id) server_id=${2:?missing server ID}; status_args+=("$1" "$2"); shift 2 ;;
    --status-url) status_args+=("$1" "${2:?missing status URL}"); shift 2 ;;
    --uki) image=${2:?missing UKI path}; shift 2 ;;
    --image-id) image_id=${2:?missing image ID}; shift 2 ;;
    --token-file) token_file=${2:?missing token file}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
token_file=${token_file:-${VPSBG_API_TOKEN_FILE:-$root/.secrets/vpsbg-api-token}}

if [[ "$action" == status ]]; then
  # The empty-array expansion form keeps `set -u` happy on bash 3.2 (macOS).
  VPSBG_API_TOKEN_FILE=$token_file \
    "$root/scripts/vpsbg-production-status.sh" "${status_args[@]+"${status_args[@]}"}"
  exit 0
fi

token=$(tr -d '\r\n' <"$token_file")
api() {
  curl --fail --silent --show-error -H 'Accept: application/json' \
    -H "Authorization: Bearer $token" "$@"
}
api_base=https://api.vpsbg.eu/v1

case "$action" in
  images)
    api --max-time 20 "$api_base/measured-boot-images" | jq -r '
      (if type == "object" then .data else . end)[] |
      "image_id=\(.id) image_name=\(.name) image_size=\(.size) image_in_use=\(.in_use)"'
    ;;
  upload)
    [[ -n "$image" ]] || { echo 'upload requires --uki FILE' >&2; exit 2; }
    api -F "file=@$image" "$api_base/measured-boot-images" |
      jq -r '"image_id=\(.id) image_name=\(.name) image_size=\(.size)"'
    ;;
  switch)
    [[ -n "$server_id" && -n "$image_id" ]] || { echo 'switch requires --server-id ID and --image-id ID' >&2; exit 2; }
    api -H 'Content-Type: application/json' -d "{\"kernel_image_id\":$image_id}" \
      "$api_base/servers/$server_id/measured-boot" | jq -r '"server_id=\(.id)"'
    echo "image_id=$image_id"
    ;;
esac
