#!/usr/bin/env bash
# Thin offline wrapper around payment-issuer state initialization and checks.
set -euo pipefail
usage() { cat <<'EOF'
usage: scripts/payment-v1-issuer-state.sh <init|check> --store PATH --issuer-id-hex HEX --network NETWORK (--rollback-authority PATH | --remote-rollback-authority-config PATH) [--store-instance-id-hex HEX] [--dry-run]

NETWORK is bitcoin, testnet, signet, or regtest.  `init` creates fresh issuer
state; `check` runs the startup-equivalent check.  --dry-run validates only the
wrapper shape and never reads paths, secrets, or network state.
EOF
}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
action=${1:-}; [[ "$action" != --help && "$action" != -h ]] || { usage; exit 0; }
[[ "$action" =~ ^(init|check)$ ]] || { usage >&2; exit 2; }; shift || true
dry_run=0; args=()
for arg in "$@"; do [[ "$arg" == --dry-run ]] && { dry_run=1; continue; }; args+=("$arg"); done
if ((${#args[@]})) && [[ "${args[0]}" == --help || "${args[0]}" == -h ]]; then
  (cd "$root" && exec cargo run --locked --offline -p payment-issuer -- "$([[ "$action" == init ]] && echo init-store || echo check-store)" --help)
  exit $?
fi
option_count() {
  local expected=$1 arg count=0
  for arg in "${args[@]}"; do
    [[ "$arg" != "$expected" ]] || count=$((count + 1))
  done
  printf '%s\n' "$count"
}
require_one_value() {
  local expected=$1 count index
  count=$(option_count "$expected")
  [[ "$count" == 1 ]] || { echo "$action requires exactly one $expected" >&2; exit 2; }
  for ((index=0; index<${#args[@]}; index++)); do
    if [[ "${args[index]}" == "$expected" ]]; then
      (( index + 1 < ${#args[@]} )) && [[ -n "${args[index + 1]}" && "${args[index + 1]}" != --* ]] \
        || { echo "$expected requires a value" >&2; exit 2; }
    fi
  done
}
for required in --store --issuer-id-hex --network; do require_one_value "$required"; done
local_authority=$(option_count --rollback-authority)
remote_authority=$(option_count --remote-rollback-authority-config)
store_instance=$(option_count --store-instance-id-hex)
(( local_authority + remote_authority == 1 )) || { echo "$action requires exactly one rollback authority option" >&2; exit 2; }
((local_authority == 0)) || require_one_value --rollback-authority
((remote_authority == 0)) || require_one_value --remote-rollback-authority-config
((store_instance <= 1)) || { echo '--store-instance-id-hex may be provided once' >&2; exit 2; }
((store_instance == 0)) || require_one_value --store-instance-id-hex
if [[ "$action" == init ]] && ((remote_authority == 1)); then
  ((store_instance == 1)) || { echo 'remote init requires --store-instance-id-hex' >&2; exit 2; }
elif ((store_instance == 1)); then
  echo '--store-instance-id-hex is used only by init with a remote rollback authority' >&2
  exit 2
fi
cmd_name=$([[ "$action" == init ]] && echo init-store || echo check-store)
cmd=(cargo run --locked --offline -p payment-issuer -- "$cmd_name" "${args[@]}")
if ((dry_run)); then
  echo "[stage] issuer $action preview"; printf 'COMMAND='; printf '%q ' "${cmd[@]}"; echo
  echo "PASS issuer_state=$action dry_run=true"; echo 'NEXT_STEP=run without --dry-run in the selected issuer-state environment'; exit 0
fi
echo "[stage] issuer $action"; (cd "$root" && "${cmd[@]}")
echo "PASS issuer_state=$action"; echo 'NEXT_STEP=continue with the matching artifact registration or deployment preflight'
