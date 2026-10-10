#!/usr/bin/env bash
# Open a VPSBG stock-rootfs window, copy files on the data disk, then reattach a UKI.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/vpsbg-data-disk.sh <open|put|get|ssh|close> [options]

  open  [--server-id ID]                  detach measured boot, wait for stock SSH
  put   --local FILE --remote PATH         copy a file to the guest
  get   --remote PATH --local FILE         copy a file from the guest
  ssh   [--] [REMOTE_COMMAND...]           shell or one command on the guest
  close --image-id ID [--server-id ID]    reattach a measured-boot image

open prints the live image ID before it detaches; close back to it. All SSH
and SCP steps of a window share one connection (ControlMaster socket under
VPSBG_SSH_CONTROL_DIR, default /tmp/bpir-vpsbg-ssh-<uid>); open and close
tear it down. The API token comes from --token-file PATH,
VPSBG_API_TOKEN_FILE, or <repo>/.secrets/vpsbg-api-token.
EOF
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly API_BASE='https://api.vpsbg.eu/v1'
readonly VPSBG_HOST=212.73.134.61

action=${1:-}
case "$action" in
  open|put|get|ssh|close) shift ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

server_id=26939
image_id= local_path= remote_path= token_file= ssh_key= known_hosts=
ssh_cmd=()
while (($#)); do
  case "$1" in
    --server-id) server_id=${2:?missing server ID}; shift 2 ;;
    --image-id) image_id=${2:?missing image ID}; shift 2 ;;
    --local) local_path=${2:?missing local path}; shift 2 ;;
    --remote) remote_path=${2:?missing remote path}; shift 2 ;;
    --token-file) token_file=${2:?missing token file}; shift 2 ;;
    --ssh-key) ssh_key=${2:?missing SSH key}; shift 2 ;;
    --known-hosts) known_hosts=${2:?missing known_hosts}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; ssh_cmd+=("$@"); break ;;
    *)
      [[ "$action" == ssh ]] || { echo "unknown option: $1" >&2; usage >&2; exit 2; }
      ssh_cmd+=("$1"); shift
      ;;
  esac
done
token_file=${token_file:-${VPSBG_API_TOKEN_FILE:-$root/.secrets/vpsbg-api-token}}
export VPSBG_API_TOKEN_FILE=$token_file

status_field() {
  awk -F= -v key="$1" '$1 == key { print $2; found=1 } END { if (!found) print "unavailable" }'
}

read_status() {
  "$root/scripts/vpsbg-production-status.sh" --server-id "$server_id"
}

# Prints the HTTP status code and never fails, so 423 (a transition is in
# progress) is just retried on the next poll.
api_post_code() {
  local token
  token=$(tr -d '\r\n' <"$token_file")
  curl --silent --max-time 30 -o /dev/null -w '%{http_code}' \
    -H 'Accept: application/json' -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' -d "$2" "$API_BASE$1" || printf '000'
}

# One TCP connection per window: the stock rootfs rate-limits new SSH
# connections (ufw limit: 6 per 30 s per source). The first successful probe
# becomes the ControlMaster and later steps are channels on it.
ssh_base() {
  local dir=${VPSBG_SSH_CONTROL_DIR:-/tmp/bpir-vpsbg-ssh-$(id -u)}
  mkdir -p -m 700 "$dir"
  SSH_COMMON=(
    -i "${ssh_key:-${VPSBG_SSH_KEY:-$root/.keys/vpsbg-ssh.key}}"
    -o IdentitiesOnly=yes
    -o UserKnownHostsFile="${known_hosts:-${VPSBG_KNOWN_HOSTS:-$root/deploy/vpsbg_known_hosts}}"
    -o StrictHostKeyChecking=yes
    -o ConnectTimeout=20
    -o ControlMaster=auto
    -o ControlPath="$dir/%C"
    -o ControlPersist=600
  )
}

ssh_control_exit() {
  ssh_base
  ssh "${SSH_COMMON[@]}" -O exit "root@$VPSBG_HOST" >/dev/null 2>&1 || true
}

# Wait for the stock rootfs with SSH after a detach. The detach reboots the
# guest into stock, but the platform sometimes leaves it on the old kernel
# (a stop applies the detach; an early stop answers 423 and lands later) or
# powered off (a start brings it back). Poll the readback and nudge.
settle() {
  local t0 now snapshot boot_mode running code last_start=0 stopped=0
  t0=$(date -u +%s)
  ssh_base
  while :; do
    now=$(date -u +%s)
    snapshot=$(read_status) || true
    boot_mode=$(status_field boot_mode <<<"$snapshot")
    running=$(status_field control_plane_running <<<"$snapshot")
    echo "boot_mode=$boot_mode control_plane_running=$running elapsed_seconds=$((now - t0))"
    if [[ "$boot_mode" == stock && "$running" == true ]] &&
       ssh "${SSH_COMMON[@]}" -o BatchMode=yes "root@$VPSBG_HOST" true >/dev/null 2>&1; then
      return 0
    fi
    if [[ "$boot_mode" == stock && "$running" == false ]]; then
      if (( now - last_start >= 30 )); then
        echo "start http=$(api_post_code "/servers/$server_id/start" '{}')"
        last_start=$now
      fi
    elif (( ! stopped )) && { [[ "$boot_mode" == measured ]] || (( now - t0 >= 180 )); }; then
      code=$(api_post_code "/servers/$server_id/stop" '{}')
      echo "stop http=$code"
      [[ "$code" != 2* ]] || stopped=1
    fi
    sleep 10
  done
}

case "$action" in
  open)
    snapshot=$(read_status)
    printf '%s\n' "$snapshot"
    echo "close_image_id=$(status_field image_id <<<"$snapshot")"
    ssh_control_exit
    if [[ "$(status_field boot_mode <<<"$snapshot")" != stock ]]; then
      code=$(api_post_code "/servers/$server_id/measured-boot" '{"kernel_image_id":null}')
      [[ "$code" == 2* ]] || { echo "detach failed: http=$code" >&2; exit 1; }
    fi
    settle
    echo 'stock rootfs reachable over SSH'
    ;;
  close)
    [[ -n "$image_id" ]] || { echo 'close requires --image-id ID' >&2; exit 2; }
    ssh_control_exit
    "$root/scripts/vpsbg-measured-boot.sh" switch --server-id "$server_id" --image-id "$image_id"
    ;;
  put)
    [[ -n "$local_path" && -n "$remote_path" ]] || { echo 'put requires --local FILE and --remote PATH' >&2; exit 2; }
    ssh_base
    scp "${SSH_COMMON[@]}" "$local_path" "root@$VPSBG_HOST:$remote_path"
    ;;
  get)
    [[ -n "$local_path" && -n "$remote_path" ]] || { echo 'get requires --remote PATH and --local FILE' >&2; exit 2; }
    ssh_base
    scp "${SSH_COMMON[@]}" "root@$VPSBG_HOST:$remote_path" "$local_path"
    ;;
  ssh)
    ssh_base
    if ((${#ssh_cmd[@]})); then
      ssh "${SSH_COMMON[@]}" -o BatchMode=yes "root@$VPSBG_HOST" "${ssh_cmd[@]}"
    else
      ssh "${SSH_COMMON[@]}" "root@$VPSBG_HOST"
    fi
    ;;
esac
