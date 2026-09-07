#!/usr/bin/env bash
set -u
S=$FAKE_VPSBG_STATE
url=""; data=""; fail=0; want_code=0
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  a=${args[$i]}
  case "$a" in
    --fail) fail=1 ;;
    -d) data=${args[$((i+1))]}; i=$((i+1)) ;;
    -w) want_code=1; i=$((i+1)) ;;
    -o|-H|--max-time|--retry) i=$((i+1)) ;;
    http*) url=$a ;;
  esac
done
rd(){ cat "$S/$1"; }
reply(){ # $1=code $2=body
  if ((want_code)); then printf '%s' "$1"; exit 0; fi
  if [[ "$1" == 2* ]]; then printf '%s' "$2"; exit 0; fi
  if ((fail)); then echo "curl: (22) The requested URL returned error: $1" >&2; exit 22; fi
  printf '%s' "$2"; exit 0
}
echo "$url ${data:+POST}" >> "$S/log"
case "$url" in
  *status.json*) echo "curl: (22) The requested URL returned error: 502" >&2; exit 22 ;;
  */servers/25285/measured-boot)
    # The detach changes the boot config at once (status reads stock) while
    # the guest keeps running the old kernel until a power cycle.
    echo stock > "$S/mode"; echo true > "$S/running"; echo 1 > "$S/detached"; reply 200 '{}' ;;
  */servers/25285/stop)
    code=$(rd stop_http)
    if [[ "$code" == 423-always ]]; then reply 423 '{}'; fi
    echo 200 > "$S/stop_http"
    if [[ "$code" == 2* ]]; then echo false > "$S/running"; fi
    reply "$code" '{}' ;;
  */servers/25285/start)
    if [[ "$(rd start_works)" == 1 ]]; then echo true > "$S/running"; printf 'noop\nssh-up\n' >> "$S/script"; else echo false > "$S/running"; fi
    reply 200 '{}' ;;
  */servers/25285)
    # advance the script by one event per read
    ev=$(head -n1 "$S/script" 2>/dev/null || true); tail -n +2 "$S/script" > "$S/script.tmp" 2>/dev/null || true; mv "$S/script.tmp" "$S/script"
    case "$ev" in stop-lands) echo false > "$S/running" ;; ssh-up) echo 1 > "$S/ssh" ;; esac
    mode=$(rd mode); running=$(rd running)
    if [[ "$mode" == measured ]]; then mb='{"kernel_image":{"id":303,"name":"img"}}'; else mb='null'; fi
    reply 200 "{\"id\":25285,\"hostname\":\"pir-server-vpsbg\",\"status\":\"active\",\"virtualization\":\"kvm\",\"state\":{\"node_reachable\":true,\"running\":$running,\"amd_sev_level\":3,\"measured_boot\":$mb}}" ;;
  */servers) reply 200 '{"data":[{"id":25285}]}' ;;
  *) echo "fake curl: unexpected url $url" >&2; exit 99 ;;
esac
