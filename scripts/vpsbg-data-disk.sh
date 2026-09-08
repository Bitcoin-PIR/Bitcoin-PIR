#!/usr/bin/env bash
# Open a VPSBG stock-rootfs window, copy files on /home/pir/data/, then reattach a UKI.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/vpsbg-data-disk.sh <open|put|get|ssh|close> [options]

  open  --image-id ID [--server-id ID] [--token-file PATH] (--dry-run | --apply)
  close --image-id ID [--server-id ID] [--token-file PATH] (--dry-run | --apply)
  put   --local FILE --remote /home/pir/data/... [--server-id ID] (--dry-run | --apply)
  get   --remote /home/pir/data/... --local FILE [--server-id ID]
  ssh   [--server-id ID] [--] [REMOTE_COMMAND...]

open detaches measured boot (kernel_image_id=null), then settles the guest
by readback: a still-measured guest gets a stop request (HTTP 423 is retried,
not fatal), a stock-but-off guest gets a start (at most 3), and open returns
once boot_mode=stock and SSH answers. All SSH/SCP steps of a window share one
connection (ControlMaster socket under VPSBG_SSH_CONTROL_DIR, default
/tmp/bpir-vpsbg-ssh-<uid>, ControlPersist 600 s); open and close tear it
down. close switches back to the
caller-supplied image ID; it never remembers the previous image. put/get/ssh
refuse to run unless the guest is already stock. There is no provisioner UKI
path. Mutations default to a dry-run preview unless --apply is set.
EOF
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly API_BASE='https://api.vpsbg.eu/v1'
readonly DEFAULT_SERVER_ID=25285
readonly VPSBG_HOST=87.120.8.198
readonly HARD_STOP_SECONDS=${VPSBG_DATA_DISK_HARD_STOP_SECONDS:-900}
# Status poll interval while waiting for the stock rootfs (tests set 0).
readonly POLL_SECONDS=${VPSBG_DATA_DISK_POLL_SECONDS:-10}
# Starts the wrapper may issue while settling one open (the platform's delayed
# stop can land after a start and leave the guest off again).
readonly MAX_SETTLE_STARTS=3
readonly START_COOLDOWN_SECONDS=${VPSBG_DATA_DISK_START_COOLDOWN_SECONDS:-30}
# A guest that reports stock+running but never answers SSH is still on the old
# measured kernel: after this long, ask for a stop so the detach takes effect.
readonly STALL_SECONDS=${VPSBG_DATA_DISK_STALL_SECONDS:-180}
readonly DEFAULT_TOKEN_FILE="$root/.secrets/vpsbg-api-token"
readonly DEFAULT_SSH_KEY="$root/.keys/vpsbg-ssh.key"
readonly DEFAULT_KNOWN_HOSTS="$root/deploy/vpsbg_known_hosts"

action=${1:-}
[[ "$action" != --help && "$action" != -h ]] || { usage; exit 0; }
[[ "$action" =~ ^(open|put|get|ssh|close)$ ]] || { usage >&2; exit 2; }
shift || true

server_id=$DEFAULT_SERVER_ID
image_id= local_path= remote_path= token_file= ssh_key= known_hosts=
apply=0 dry_run=0
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
    --apply) apply=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; ssh_cmd+=("$@"); break ;;
    *)
      if [[ "$action" == ssh ]]; then
        ssh_cmd+=("$1"); shift
      else
        echo "unknown option: $1" >&2
        usage >&2
        exit 2
      fi
      ;;
  esac
done

[[ "$server_id" =~ ^[0-9]+$ ]] || { echo 'server ID must be numeric' >&2; exit 2; }
[[ -z "$image_id" || "$image_id" =~ ^[0-9]+$ ]] || { echo 'image ID must be numeric' >&2; exit 2; }
printf 'server_id=%s\n' "$server_id"

reject_provisioner() {
  local value
  for value in "$@"; do
    [[ "$value" != *provisioner* ]] || {
      echo 'provisioner UKI path is forbidden; use stock-rootfs SSH' >&2
      exit 2
    }
  done
}

require_data_path() {
  local path=$1
  [[ "$path" == /home/pir/data/* ]] || {
    echo "remote path must be under /home/pir/data/: $path" >&2
    exit 2
  }
  [[ "$path" != *..* ]] || { echo "remote path must not contain ..: $path" >&2; exit 2; }
  if [[ "$(basename "$path")" == startup.env ]]; then
    [[ "$path" == /home/pir/data/pir2-sealed/startup.env ]] || {
      echo 'startup.env must be placed at /home/pir/data/pir2-sealed/startup.env' >&2
      exit 2
    }
  fi
}

require_startup_env_schema() {
  local path=$1
  [[ -f "$path" && -s "$path" ]] || { echo "local startup.env is missing or empty: $path" >&2; exit 2; }
  grep -qx 'schema=bitcoinpir-pir2-sealed-startup-v3' "$path" \
    || { echo 'startup.env is not a ceremony v2 file' >&2; exit 2; }
  grep -qx 'profile=pir2-snp-sealed-v1' "$path" \
    || { echo 'startup.env is not a pir2 sealed profile file' >&2; exit 2; }
  grep -Eq '^phase=(observe|enroll|probe|ready)$' "$path" \
    || { echo 'startup.env phase is not observe, enroll, probe, or ready' >&2; exit 2; }
}

status_field() {
  local key=$1
  awk -F= -v key="$key" '$1 == key { print $2; found=1 } END { if (!found) print "unavailable" }'
}

read_status() {
  "$root/scripts/vpsbg-production-status.sh" --server-id "$server_id"
}

ssh_opts() {
  ssh_key=${ssh_key:-${VPSBG_SSH_KEY:-$DEFAULT_SSH_KEY}}
  known_hosts=${known_hosts:-${VPSBG_KNOWN_HOSTS:-$DEFAULT_KNOWN_HOSTS}}
  [[ -r "$ssh_key" && -s "$ssh_key" ]] || { echo "VPSBG SSH key is missing or empty: $ssh_key" >&2; exit 2; }
  [[ -r "$known_hosts" && -s "$known_hosts" ]] || { echo "VPSBG known_hosts is missing or empty: $known_hosts" >&2; exit 2; }
}

# One TCP connection per window. The stock rootfs rate-limits new SSH
# connections (ufw limit: 6 per 30 s per source), so a scripted window that
# opened one connection per put/get/ssh step locked itself out. With a
# ControlMaster socket the first successful probe becomes the master and every
# later step is a channel on it; the master is torn down at close (the guest
# reboots) and before open (a stale master must not mask a dead guest).
ssh_control_dir() {
  local dir=${VPSBG_SSH_CONTROL_DIR:-/tmp/bpir-vpsbg-ssh-$(id -u)}
  if [[ ! -d "$dir" ]]; then
    mkdir -m 700 "$dir" || { echo "cannot create SSH control directory $dir" >&2; exit 2; }
  fi
  [[ -O "$dir" ]] || { echo "SSH control directory is not owned by this user: $dir" >&2; exit 2; }
  chmod 700 "$dir"
  printf '%s' "$dir"
}

ssh_common_opts() {
  local dir; dir=$(ssh_control_dir)
  SSH_COMMON=(
    -i "$ssh_key"
    -o IdentitiesOnly=yes
    -o UserKnownHostsFile="$known_hosts"
    -o StrictHostKeyChecking=yes
    -o ConnectTimeout=20
    -o ControlMaster=auto
    -o ControlPath="$dir/%C"
    -o ControlPersist=600
  )
}

ssh_base() {
  ssh_opts
  ssh_common_opts
  SSH_BASE=(ssh "${SSH_COMMON[@]}")
}

scp_base() {
  ssh_opts
  ssh_common_opts
  SCP_BASE=(scp "${SSH_COMMON[@]}")
}

# Best-effort teardown of a control master for the guest; silent when none.
ssh_control_exit() {
  ssh_base
  "${SSH_BASE[@]}" -o BatchMode=yes -O exit "root@$VPSBG_HOST" >/dev/null 2>&1 || true
}

require_stock() {
  local snapshot boot_mode
  snapshot=$(read_status)
  printf '%s\n' "$snapshot"
  boot_mode=$(status_field boot_mode <<<"$snapshot")
  [[ "$boot_mode" == stock ]] || {
    echo "refusing SSH/copy while boot_mode=$boot_mode; run open first" >&2
    exit 2
  }
}

api_token() {
  token_file=${token_file:-${VPSBG_API_TOKEN_FILE:-$DEFAULT_TOKEN_FILE}}
  [[ -s "$token_file" ]] || { echo "VPSBG API token file is missing or empty: $token_file" >&2; exit 2; }
  tr -d '\r\n' <"$token_file"
}

api_post() {
  local path=$1 body=$2
  local token
  token=$(api_token)
  curl --fail --silent --show-error --max-time 30 --retry 0 \
    -H 'Accept: application/json' \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    -d "$body" \
    "$API_BASE$path"
  unset token
}

# Like api_post, but never fails the script: prints the HTTP status code so
# the caller can treat 423 (guest locked by a transition in progress) as
# "retry later" instead of aborting a half-done open.
api_post_code() {
  local path=$1 body=$2
  local token code
  token=$(api_token)
  code=$(curl --silent --max-time 30 --retry 0 -o /dev/null -w '%{http_code}' \
    -H 'Accept: application/json' \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    -d "$body" \
    "$API_BASE$path" || printf '000')
  unset token
  printf '%s\n' "$code"
}

# Settle the guest onto the stock rootfs with SSH after a detach, driving the
# VPSBG control plane by readback instead of by a fixed stop/start sequence.
# Observed platform behaviour this handles: the detach itself reboots the
# guest into stock; an immediate stop answers HTTP 423 (locked) and then lands
# tens of seconds later, leaving the guest off; a guest that is stock but off
# never comes back without a start. Each iteration reads status and acts on
# it: still measured → request a stop (423 is retried next round); stock and
# off → start (bounded by MAX_SETTLE_STARTS); stock and running → probe SSH.
settle_to_stock_ssh() {
  local started now snapshot boot_mode running ssh_ready code
  local starts=0 last_start=0 stop_requested=0
  started=$(date -u +%s)
  ssh_base
  echo "[stage] settle onto stock rootfs with SSH (hard_stop_seconds=$HARD_STOP_SECONDS)"
  while :; do
    now=$(date -u +%s)
    if (( now - started >= HARD_STOP_SECONDS )); then
      echo "hard stop: guest did not reach boot_mode=stock with SSH in ${HARD_STOP_SECONDS}s" >&2
      exit 1
    fi
    snapshot=$(read_status) || true
    boot_mode=$(status_field boot_mode <<<"$snapshot")
    running=$(status_field control_plane_running <<<"$snapshot")
    ssh_ready=false
    if [[ "$boot_mode" == stock && "$running" == true ]]; then
      if "${SSH_BASE[@]}" -o BatchMode=yes "root@$VPSBG_HOST" true >/dev/null 2>&1; then
        ssh_ready=true
      fi
    fi
    printf 'boot_mode=%s control_plane_running=%s ssh_ready=%s starts=%s elapsed_seconds=%s\n' \
      "$boot_mode" "$running" "$ssh_ready" "$starts" "$((now - started))"
    if [[ "$ssh_ready" == true ]]; then
      return 0
    fi
    if [[ "$boot_mode" == stock && "$running" == false ]]; then
      if (( starts >= MAX_SETTLE_STARTS )); then
        echo "guest is stock but off after $starts start requests; refusing to loop" >&2
        exit 1
      fi
      if (( now - last_start >= START_COOLDOWN_SECONDS )); then
        code=$(api_post_code "/servers/$server_id/start" '{}')
        starts=$((starts + 1)); last_start=$now
        echo "[stage] start guest (stock but off) http=$code"
      fi
    elif [[ "$boot_mode" == measured ]] || (( now - started >= STALL_SECONDS )); then
      # The detach is applied by a power cycle. The platform usually does it
      # by itself (a locked guest answers 423 meanwhile); if the guest still
      # reports the old kernel, or sits stock+running without sshd past the
      # stall limit, ask for the stop once and let the readback drive the
      # start.
      if (( ! stop_requested )); then
        code=$(api_post_code "/servers/$server_id/stop" '{}')
        case "$code" in
          2*) stop_requested=1; echo "[stage] stop guest http=$code" ;;
          423) echo "[stage] stop deferred (HTTP 423: transition in progress)" ;;
          *) echo "[stage] stop request answered http=$code; retrying" ;;
        esac
      fi
    fi
    sleep "$POLL_SECONDS"
  done
}

reject_provisioner "$local_path" "$remote_path" "${ssh_cmd[@]+"${ssh_cmd[@]}"}"

case "$action" in
  open)
    [[ -n "$image_id" ]] || { echo 'open requires --image-id ID as the recorded close target' >&2; exit 2; }
    (( dry_run + apply <= 1 )) || { echo 'open accepts only one of --dry-run or --apply' >&2; exit 2; }
    echo 'expected_duration=up to 15 minutes'
    echo "hard_stop_seconds=$HARD_STOP_SECONDS"
    echo 'progress=detach,settle(stop|start by readback),boot_mode=stock,ssh_ready'
    echo "recorded_close_image_id=$image_id"
    echo 'detach_body={"kernel_image_id":null}'
    if ((dry_run || !apply)); then
      echo '[stage] open preview'
      echo 'PASS action=open dry_run=true'
      echo 'NEXT_STEP=review recorded_close_image_id, then rerun with --apply'
      exit 0
    fi
    command -v curl >/dev/null 2>&1 || { echo 'curl is required for open --apply' >&2; exit 2; }
    command -v jq >/dev/null 2>&1 || { echo 'jq is required for open --apply' >&2; exit 2; }
    echo '[stage] read live VPSBG status before detach'
    snapshot=$(read_status)
    printf '%s\n' "$snapshot"
    live_image_id=$(status_field image_id <<<"$snapshot")
    live_boot_mode=$(status_field boot_mode <<<"$snapshot")
    printf 'live_image_id=%s\n' "$live_image_id"
    printf 'live_boot_mode=%s\n' "$live_boot_mode"
    if [[ "$live_boot_mode" == measured && "$live_image_id" != "$image_id" ]]; then
      echo "recorded close image $image_id does not match live image $live_image_id" >&2
      exit 2
    fi
    ssh_control_exit
    if [[ "$live_boot_mode" != stock ]]; then
      echo '[stage] detach measured boot'
      api_post "/servers/$server_id/measured-boot" '{"kernel_image_id":null}' >/dev/null
    else
      echo '[stage] already stock; skip detach'
    fi
    settle_to_stock_ssh
    echo 'PASS action=open'
    echo "NEXT_STEP=copy files with put/get/ssh, then close --image-id $image_id --apply"
    ;;
  close)
    [[ -n "$image_id" ]] || { echo 'close requires --image-id ID' >&2; exit 2; }
    (( dry_run + apply <= 1 )) || { echo 'close accepts only one of --dry-run or --apply' >&2; exit 2; }
    if ((dry_run || !apply)); then
      echo '[stage] close preview'
      echo "image_id=$image_id"
      echo 'PASS action=close dry_run=true'
      echo 'NEXT_STEP=rerun with --apply to switch this exact image'
      exit 0
    fi
    echo '[stage] close SSH control master'
    ssh_control_exit
    echo '[stage] switch measured-boot image'
    "$root/scripts/vpsbg-measured-boot.sh" switch --server-id "$server_id" --image-id "$image_id" --apply
    echo 'PASS action=close'
    echo 'NEXT_STEP=run scripts/pir2-post-switch-check.sh after the guest reports running'
    ;;
  put)
    [[ -n "$local_path" && -n "$remote_path" ]] || { echo 'put requires --local FILE and --remote PATH' >&2; exit 2; }
    require_data_path "$remote_path"
    [[ "$local_path" == /* ]] || { echo 'local path must be absolute' >&2; exit 2; }
    if [[ "$(basename "$remote_path")" == startup.env ]]; then
      require_startup_env_schema "$local_path"
    fi
    (( dry_run + apply <= 1 )) || { echo 'put accepts only one of --dry-run or --apply' >&2; exit 2; }
    if ((dry_run || !apply)); then
      echo '[stage] put preview'
      echo "local_path=$local_path"
      echo "remote_path=$remote_path"
      echo 'PASS action=put dry_run=true'
      echo 'NEXT_STEP=confirm stock boot, then rerun with --apply'
      exit 0
    fi
    [[ -f "$local_path" && -s "$local_path" ]] || { echo "local file is missing or empty: $local_path" >&2; exit 2; }
    require_stock
    scp_base
    echo '[stage] copy local file to VPSBG data disk'
    "${SCP_BASE[@]}" "$local_path" "root@$VPSBG_HOST:$remote_path"
    echo "copied=$remote_path"
    echo 'PASS action=put'
    echo 'NEXT_STEP=close with the recorded image ID when the data-disk edit is done'
    ;;
  get)
    (( ! apply && ! dry_run )) || { echo 'get is read-only and accepts neither --apply nor --dry-run' >&2; exit 2; }
    [[ -n "$local_path" && -n "$remote_path" ]] || { echo 'get requires --remote PATH and --local FILE' >&2; exit 2; }
    require_data_path "$remote_path"
    [[ "$local_path" == /* ]] || { echo 'local path must be absolute' >&2; exit 2; }
    require_stock
    scp_base
    echo '[stage] copy VPSBG data-disk file to local path'
    "${SCP_BASE[@]}" "root@$VPSBG_HOST:$remote_path" "$local_path"
    echo "copied=$local_path"
    echo 'PASS action=get'
    echo 'NEXT_STEP=inspect the local copy; close is a separate authorized step'
    ;;
  ssh)
    (( ! apply && ! dry_run )) || { echo 'ssh accepts neither --apply nor --dry-run' >&2; exit 2; }
    require_stock
    ssh_base
    echo '[stage] SSH to stock VPSBG rootfs'
    if ((${#ssh_cmd[@]})); then
      "${SSH_BASE[@]}" -o BatchMode=yes "root@$VPSBG_HOST" "${ssh_cmd[@]}"
    else
      "${SSH_BASE[@]}" "root@$VPSBG_HOST"
    fi
    echo 'PASS action=ssh'
    echo 'NEXT_STEP=close with the recorded image ID when the data-disk edit is done'
    ;;
esac
