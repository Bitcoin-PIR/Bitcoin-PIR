#!/usr/bin/env bash
# Run browser acquisition plus the browser -> payment issuer -> production
# provider gate -> verified DPF query path with three fresh native CLN nodes
# and Bitcoin Core on an isolated local regtest.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export LC_ALL=C

readonly ACKNOWLEDGEMENT="--acknowledge-local-regtest-only"

usage() {
  cat <<'EOF'
Usage:
  scripts/payment-v1-cln-regtest-e2e.sh --acknowledge-local-regtest-only

This opt-in test creates a temporary Bitcoin Core regtest and three temporary
Core Lightning regtest nodes in a payer -> router -> issuer topology. It never
uses mainnet, testnet, signet, default ~/.bitcoin or ~/.lightning data, or real
funds. It runs both claim-recovery and joined two-provider query verification.
EOF
}

die() {
  printf 'payment-v1 CLN regtest E2E: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
if [[ "$#" -ne 1 || "$1" != "$ACKNOWLEDGEMENT" ]]; then
  usage >&2
  die "refusing to start without the exact local-regtest-only acknowledgement"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
readonly REPOSITORY_ROOT
[[ -f "$REPOSITORY_ROOT/Cargo.toml" && -f "$REPOSITORY_ROOT/web/package.json" ]] \
  || die "could not resolve the BitcoinPIR repository root"

require_command() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 \
    || die "missing required command '$name' (see docs/payment/CLN_REGTEST.md)"
}

for command_name in bitcoind bitcoin-cli lightningd lightning-cli jq npm node python3 ps wasm-pack; do
  require_command "$command_name"
done

BITCOIND="$(command -v bitcoind)"
readonly BITCOIND
BITCOIN_CLI="$(command -v bitcoin-cli)"
readonly BITCOIN_CLI
LIGHTNINGD="$(command -v lightningd)"
readonly LIGHTNINGD
LIGHTNING_CLI="$(command -v lightning-cli)"
readonly LIGHTNING_CLI
JQ="$(command -v jq)"
readonly JQ
PYTHON3="$(command -v python3)"
readonly PYTHON3
readonly CLI_CALL_TIMEOUT_SECONDS="10"

# Bound every synchronous native probe/RPC independently. `wait_until` bounds
# the number of retries, but without this inner deadline one wedged CLI call
# could otherwise outlive the advertised wait forever.
run_bounded_command() {
  "$PYTHON3" - "$CLI_CALL_TIMEOUT_SECONDS" "$@" <<'PY'
import subprocess
import sys

timeout_seconds = float(sys.argv[1])
command = sys.argv[2:]
if not command:
    raise SystemExit(2)
try:
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        check=False,
        timeout=timeout_seconds,
    )
except subprocess.TimeoutExpired:
    raise SystemExit(124)
raise SystemExit(completed.returncode)
PY
}

[[ -x "$REPOSITORY_ROOT/web/node_modules/.bin/playwright" \
  && -x "$REPOSITORY_ROOT/web/node_modules/.bin/tsc" \
  && -x "$REPOSITORY_ROOT/web/node_modules/.bin/vite" ]] \
  || die "web dependencies are missing; run 'npm ci' in $REPOSITORY_ROOT/web first"

# Never trust an existing generated package merely because it is present: a
# source change after the last wasm-pack run would make the browser exercise
# stale Rust. Rebuild offline before any daemon is started so a compile failure
# cannot strand temporary Core/CLN processes.
printf 'payment-v1 CLN regtest E2E: rebuilding the generated WASM boundary offline\n'
(
  cd "$REPOSITORY_ROOT"
  CARGO_NET_OFFLINE=true wasm-pack build crates/sdk/wasm \
    --target web --out-dir pkg --mode no-install --no-opt \
    -- --locked --offline
)
[[ -s "$REPOSITORY_ROOT/crates/sdk/wasm/pkg/pir_sdk_wasm_bg.wasm" ]] \
  || die "pir-sdk-wasm offline build did not produce the expected package"

run_bounded_command "$BITCOIND" -help 2>&1 | grep -- 'regtest' >/dev/null \
  || die "the selected bitcoind does not advertise regtest support"
run_bounded_command "$LIGHTNINGD" --help 2>&1 | grep -- '--network' >/dev/null \
  || die "the selected lightningd does not advertise an explicit network option"

# macOS commonly provides a very long per-user TMPDIR. CLN's own CLI can use a
# relative RPC path, but payment-issuer deliberately opens the verified socket
# by absolute path; keep that path below the strictest common AF_UNIX limit.
TEMP_PARENT="$(cd /tmp && pwd -P)"
readonly TEMP_PARENT
RUNTIME_ROOT="$(mktemp -d "$TEMP_PARENT/bitcoinpir-cln.XXXXXX")"
chmod 0700 "$RUNTIME_ROOT"
readonly RUNTIME_ROOT
readonly RUNTIME_MARKER="$RUNTIME_ROOT/.bitcoinpir-payment-v1-cln-regtest"
: >"$RUNTIME_MARKER"

# Install a marker-bound cleanup before any later validation or port allocation
# can fail. No daemon exists in this early phase; the full PID-aware cleanup
# trap replaces this one immediately after its helpers are defined.
early_cleanup() {
  local status="$?"
  local base=""
  local name=""
  trap - EXIT INT TERM HUP
  base="$(dirname "$RUNTIME_ROOT")"
  name="$(basename "$RUNTIME_ROOT")"
  if [[ "$base" == "$TEMP_PARENT" \
    && "$name" == bitcoinpir-cln.* \
    && -f "$RUNTIME_MARKER" \
    && ! -L "$RUNTIME_ROOT" ]]; then
    rm -rf -- "$RUNTIME_ROOT" || status=1
  else
    printf 'payment-v1 CLN regtest E2E: early cleanup refused unsafe path %s\n' \
      "$RUNTIME_ROOT" >&2
    status=1
  fi
  exit "$status"
}

trap early_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

readonly BITCOIN_DIR="$RUNTIME_ROOT/bitcoin"
readonly ISSUER_CLN_DIR="$RUNTIME_ROOT/cln-issuer"
readonly ROUTER_CLN_DIR="$RUNTIME_ROOT/cln-router"
readonly PAYER_CLN_DIR="$RUNTIME_ROOT/cln-payer"
readonly CLN_WALLET_FUNDING_BTC="5.0"
readonly CLN_CHANNEL_CAPACITY="1000000sat"
mkdir -m 0700 "$BITCOIN_DIR" "$ISSUER_CLN_DIR" "$ROUTER_CLN_DIR" "$PAYER_CLN_DIR"

EXPECTED_ISSUER_SOCKET="$ISSUER_CLN_DIR/regtest/lightning-rpc"
[[ "$($PYTHON3 - "$EXPECTED_ISSUER_SOCKET" <<'PY'
import os
import sys

# 103 bytes plus NUL is the macOS sockaddr_un limit; use a conservative bound
# that also leaves room for implementation-specific handling.
print("yes" if len(os.fsencode(sys.argv[1])) <= 96 else "no")
PY
)" == "yes" ]] || die "temporary path is too long for a portable CLN Unix RPC socket"
readonly EXPECTED_ISSUER_SOCKET

BITCOIND_PID=""
ISSUER_CLN_PID=""
ROUTER_CLN_PID=""
PAYER_CLN_PID=""
ALLOCATED_PORTS=" "
ALLOCATED_PORT=""

allocate_loopback_port() {
  local attempt=0
  local candidate=""
  while [[ "$attempt" -lt 32 ]]; do
    candidate="$($PYTHON3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
)"
    if [[ "$candidate" =~ ^[0-9]+$ \
      && "$candidate" -ge 20000 \
      && "$candidate" -le 65535 \
      && "$ALLOCATED_PORTS" != *" $candidate "* ]]; then
      ALLOCATED_PORTS="${ALLOCATED_PORTS}${candidate} "
      ALLOCATED_PORT="$candidate"
      return 0
    fi
    attempt=$((attempt + 1))
  done
  die "could not allocate a unique high loopback port"
}

allocate_loopback_port
readonly BITCOIN_RPC_PORT="$ALLOCATED_PORT"
allocate_loopback_port
readonly ISSUER_CLN_PORT="$ALLOCATED_PORT"
allocate_loopback_port
readonly ROUTER_CLN_PORT="$ALLOCATED_PORT"
allocate_loopback_port
readonly PAYER_CLN_PORT="$ALLOCATED_PORT"
allocate_loopback_port
readonly REGTEST_WEB_PORT="$ALLOCATED_PORT"
allocate_loopback_port
readonly JOINED_WEB_PORT="$ALLOCATED_PORT"

process_is_live() {
  local pid="$1"
  local process_state=""
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" >/dev/null 2>&1 || return 1
  process_state="$(ps -p "$pid" -o stat= 2>/dev/null || true)"
  [[ -n "$process_state" && "$process_state" != Z* ]]
}

process_is_owned() {
  local pid="$1"
  local command_line=""
  process_is_live "$pid" || return 1
  command_line="$(ps -ww -p "$pid" -o command= 2>/dev/null || true)"
  [[ "$command_line" == *"$RUNTIME_ROOT"* ]]
}

wait_for_process_exit() {
  local pid="$1"
  local attempts=0
  while process_is_live "$pid" && [[ "$attempts" -lt 100 ]]; do
    sleep 0.05
    attempts=$((attempts + 1))
  done
  ! process_is_live "$pid"
}

cln_cli() {
  local directory="$1"
  shift
  run_bounded_command "$LIGHTNING_CLI" \
    --lightning-dir="$directory" \
    --network=regtest \
    --notifications=none \
    -R \
    "$@"
}

bitcoin_cli() {
  run_bounded_command "$BITCOIN_CLI" \
    -datadir="$BITCOIN_DIR" \
    -regtest \
    -rpcconnect=127.0.0.1 \
    -rpcport="$BITCOIN_RPC_PORT" \
    "$@"
}

bitcoin_wallet_cli() {
  bitcoin_cli -rpcwallet=miner "$@"
}

stop_cln() {
  local directory="$1"
  local pid="$2"
  [[ -n "$pid" ]] || return 0
  process_is_live "$pid" || {
    wait "$pid" >/dev/null 2>&1 || true
    return 0
  }
  if ! process_is_owned "$pid"; then
    printf 'payment-v1 CLN regtest E2E: refusing to signal non-owned PID %s\n' "$pid" >&2
    return 1
  fi
  cln_cli "$directory" stop >/dev/null 2>&1 || kill -TERM "$pid" >/dev/null 2>&1 || true
  if ! wait_for_process_exit "$pid"; then
    process_is_owned "$pid" && kill -KILL "$pid" >/dev/null 2>&1 || true
    wait_for_process_exit "$pid" || return 1
  fi
  wait "$pid" >/dev/null 2>&1 || true
}

stop_bitcoind() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  process_is_live "$pid" || {
    wait "$pid" >/dev/null 2>&1 || true
    return 0
  }
  if ! process_is_owned "$pid"; then
    printf 'payment-v1 CLN regtest E2E: refusing to signal non-owned PID %s\n' "$pid" >&2
    return 1
  fi
  bitcoin_cli stop >/dev/null 2>&1 || kill -TERM "$pid" >/dev/null 2>&1 || true
  if ! wait_for_process_exit "$pid"; then
    process_is_owned "$pid" && kill -KILL "$pid" >/dev/null 2>&1 || true
    wait_for_process_exit "$pid" || return 1
  fi
  wait "$pid" >/dev/null 2>&1 || true
}

safe_remove_runtime() {
  local base=""
  local name=""
  base="$(dirname "$RUNTIME_ROOT")"
  name="$(basename "$RUNTIME_ROOT")"
  [[ "$base" == "$TEMP_PARENT" \
    && "$name" == bitcoinpir-cln.* \
    && -f "$RUNTIME_MARKER" \
    && ! -L "$RUNTIME_ROOT" ]] \
    || return 1
  rm -rf -- "$RUNTIME_ROOT"
}

cleanup() {
  local status="$?"
  local cleanup_ok=0
  trap - EXIT INT TERM HUP
  set +e
  stop_cln "$PAYER_CLN_DIR" "$PAYER_CLN_PID" || cleanup_ok=1
  stop_cln "$ROUTER_CLN_DIR" "$ROUTER_CLN_PID" || cleanup_ok=1
  stop_cln "$ISSUER_CLN_DIR" "$ISSUER_CLN_PID" || cleanup_ok=1
  stop_bitcoind "$BITCOIND_PID" || cleanup_ok=1
  if [[ "$cleanup_ok" -eq 0 ]]; then
    safe_remove_runtime || cleanup_ok=1
  fi
  if [[ "$cleanup_ok" -ne 0 ]]; then
    printf 'payment-v1 CLN regtest E2E: cleanup was incomplete; inspect %s without executing it\n' \
      "$RUNTIME_ROOT" >&2
    [[ "$status" -ne 0 ]] || status=1
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

wait_until() {
  local description="$1"
  local timeout_seconds="$2"
  shift 2
  local deadline=$((SECONDS + timeout_seconds))
  while [[ "$SECONDS" -lt "$deadline" ]]; do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.10
  done
  die "timed out waiting for $description"
}

bitcoin_is_ready() {
  process_is_owned "$BITCOIND_PID" \
    && [[ "$(bitcoin_cli getblockchaininfo 2>/dev/null | "$JQ" -r '.chain // empty')" == "regtest" ]]
}

cln_is_ready() {
  local directory="$1"
  local pid="$2"
  process_is_owned "$pid" \
    && [[ "$(cln_cli "$directory" getinfo 2>/dev/null | "$JQ" -r '.network // empty')" == "regtest" ]]
}

nodes_are_at_bitcoin_tip() {
  local bitcoin_height=""
  local issuer_height=""
  local router_height=""
  local payer_height=""
  bitcoin_height="$(bitcoin_cli getblockcount 2>/dev/null)" || return 1
  issuer_height="$(cln_cli "$ISSUER_CLN_DIR" getinfo 2>/dev/null | "$JQ" -r '.blockheight // empty')" \
    || return 1
  router_height="$(cln_cli "$ROUTER_CLN_DIR" getinfo 2>/dev/null | "$JQ" -r '.blockheight // empty')" \
    || return 1
  payer_height="$(cln_cli "$PAYER_CLN_DIR" getinfo 2>/dev/null | "$JQ" -r '.blockheight // empty')" \
    || return 1
  [[ "$bitcoin_height" =~ ^[0-9]+$ \
    && "$issuer_height" == "$bitcoin_height" \
    && "$router_height" == "$bitcoin_height" \
    && "$payer_height" == "$bitcoin_height" ]]
}

channel_is_usable() {
  local directory="$1"
  local peer_id="$2"
  # `$peer` below is a jq variable, not a shell variable.
  # shellcheck disable=SC2016
  cln_cli "$directory" listpeerchannels 2>/dev/null \
    | "$JQ" -e --arg peer "$peer_id" \
      '.channels | any(.peer_id == $peer and .state == "CHANNELD_NORMAL" and .peer_connected == true)' \
      >/dev/null
}

announced_direction_is_visible() {
  local directory="$1"
  local source="$2"
  local destination="$3"
  # `$source` and `$destination` below are jq variables, not shell variables.
  # shellcheck disable=SC2016
  cln_cli "$directory" -k listchannels source="$source" 2>/dev/null \
    | "$JQ" -e --arg source "$source" --arg destination "$destination" \
      '.channels | any(.source == $source and .destination == $destination and .public == true and .active == true)' \
      >/dev/null
}

check_owner_only_socket() {
  local socket_path="$1"
  "$PYTHON3" - "$socket_path" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
metadata = os.lstat(path)
if not stat.S_ISSOCK(metadata.st_mode):
    raise SystemExit("CLN RPC path is not a Unix socket")
if stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("CLN RPC socket is not mode 0600")
if metadata.st_uid != os.getuid():
    raise SystemExit("CLN RPC socket is not owned by the current user")
PY
}

printf 'payment-v1 CLN regtest E2E: starting isolated local regtest\n'

"$BITCOIND" \
  -datadir="$BITCOIN_DIR" \
  -regtest=1 \
  -server=1 \
  -listen=0 \
  -discover=0 \
  -dnsseed=0 \
  -listenonion=0 \
  -onion=0 \
  -connect=0 \
  -rpcbind=127.0.0.1 \
  -rpcallowip=127.0.0.1 \
  -rpcport="$BITCOIN_RPC_PORT" \
  -fallbackfee=0.0002 \
  -txindex=1 \
  -pid="$RUNTIME_ROOT/bitcoind.pid" \
  -printtoconsole=0 \
  >"$RUNTIME_ROOT/bitcoind-stdio.log" 2>&1 &
BITCOIND_PID="$!"
wait_until "the temporary Bitcoin Core regtest" 30 bitcoin_is_ready

[[ "$(bitcoin_cli getblockchaininfo | "$JQ" -r '.chain')" == "regtest" ]] \
  || die "Bitcoin Core reported a non-regtest chain"
bitcoin_cli -named createwallet \
  wallet_name=miner \
  descriptors=true \
  load_on_startup=true \
  >/dev/null
MINER_ADDRESS="$(bitcoin_wallet_cli getnewaddress mining bech32)"
[[ "$MINER_ADDRESS" == bcrt1* ]] || die "Bitcoin Core returned a non-regtest mining address"
bitcoin_wallet_cli generatetoaddress 101 "$MINER_ADDRESS" >/dev/null

readonly CLN_COMMON=(
  --network=regtest
  --developer
  --dev-allow-localhost
  --dev-fast-gossip
  --dev-bitcoind-poll=1
  --disable-plugin=cln-grpc
  --bitcoin-cli="$BITCOIN_CLI"
  --bitcoin-datadir="$BITCOIN_DIR"
  --bitcoin-rpcconnect=127.0.0.1
  --bitcoin-rpcport="$BITCOIN_RPC_PORT"
)

"$LIGHTNINGD" \
  "${CLN_COMMON[@]}" \
  --lightning-dir="$ISSUER_CLN_DIR" \
  --addr="127.0.0.1:$ISSUER_CLN_PORT" \
  --alias=BitcoinPIR-regtest-issuer \
  --pid-file="$RUNTIME_ROOT/cln-issuer.pid" \
  --log-file="$RUNTIME_ROOT/cln-issuer.log" \
  >"$RUNTIME_ROOT/cln-issuer-stdio.log" 2>&1 &
ISSUER_CLN_PID="$!"

"$LIGHTNINGD" \
  "${CLN_COMMON[@]}" \
  --lightning-dir="$PAYER_CLN_DIR" \
  --addr="127.0.0.1:$PAYER_CLN_PORT" \
  --alias=BitcoinPIR-regtest-payer \
  --pid-file="$RUNTIME_ROOT/cln-payer.pid" \
  --log-file="$RUNTIME_ROOT/cln-payer.log" \
  >"$RUNTIME_ROOT/cln-payer-stdio.log" 2>&1 &
PAYER_CLN_PID="$!"

"$LIGHTNINGD" \
  "${CLN_COMMON[@]}" \
  --lightning-dir="$ROUTER_CLN_DIR" \
  --addr="127.0.0.1:$ROUTER_CLN_PORT" \
  --alias=BitcoinPIR-regtest-router \
  --pid-file="$RUNTIME_ROOT/cln-router.pid" \
  --log-file="$RUNTIME_ROOT/cln-router.log" \
  >"$RUNTIME_ROOT/cln-router-stdio.log" 2>&1 &
ROUTER_CLN_PID="$!"

wait_until "the temporary issuer CLN regtest node" 45 \
  cln_is_ready "$ISSUER_CLN_DIR" "$ISSUER_CLN_PID"
wait_until "the temporary payer CLN regtest node" 45 \
  cln_is_ready "$PAYER_CLN_DIR" "$PAYER_CLN_PID"
wait_until "the temporary router CLN regtest node" 45 \
  cln_is_ready "$ROUTER_CLN_DIR" "$ROUTER_CLN_PID"

readonly ISSUER_RPC_SOCKET="$EXPECTED_ISSUER_SOCKET"
check_owner_only_socket "$ISSUER_RPC_SOCKET" \
  || die "issuer CLN RPC socket failed owner/type/mode validation"

ISSUER_NODE_ID="$(cln_cli "$ISSUER_CLN_DIR" getinfo \
  | "$JQ" -er '.id | select(test("^(02|03)[0-9a-f]{64}$"))')"
PAYER_NODE_ID="$(cln_cli "$PAYER_CLN_DIR" getinfo \
  | "$JQ" -er '.id | select(test("^(02|03)[0-9a-f]{64}$"))')"
ROUTER_NODE_ID="$(cln_cli "$ROUTER_CLN_DIR" getinfo \
  | "$JQ" -er '.id | select(test("^(02|03)[0-9a-f]{64}$"))')"
[[ "$ISSUER_NODE_ID" != "$PAYER_NODE_ID" \
  && "$ISSUER_NODE_ID" != "$ROUTER_NODE_ID" \
  && "$PAYER_NODE_ID" != "$ROUTER_NODE_ID" ]] \
  || die "CLN nodes unexpectedly share one identity"

cln_cli "$PAYER_CLN_DIR" help \
  | "$JQ" -e '.help | any(.command | startswith("xpay "))' >/dev/null \
  || die "the selected CLN payer lacks xpay support (Core Lightning v24.11 or newer is required)"

cln_cli "$PAYER_CLN_DIR" -k connect \
  id="$ROUTER_NODE_ID" \
  host=127.0.0.1 \
  port="$ROUTER_CLN_PORT" \
  >/dev/null
cln_cli "$ROUTER_CLN_DIR" -k connect \
  id="$ISSUER_NODE_ID" \
  host=127.0.0.1 \
  port="$ISSUER_CLN_PORT" \
  >/dev/null

PAYER_ADDRESS="$(cln_cli "$PAYER_CLN_DIR" newaddr \
  | "$JQ" -er '(.bech32 // .p2tr) | select(startswith("bcrt1"))')"
ROUTER_ADDRESS="$(cln_cli "$ROUTER_CLN_DIR" newaddr \
  | "$JQ" -er '(.bech32 // .p2tr) | select(startswith("bcrt1"))')"
bitcoin_wallet_cli sendtoaddress "$PAYER_ADDRESS" "$CLN_WALLET_FUNDING_BTC" >/dev/null
bitcoin_wallet_cli sendtoaddress "$ROUTER_ADDRESS" "$CLN_WALLET_FUNDING_BTC" >/dev/null
bitcoin_wallet_cli generatetoaddress 6 "$MINER_ADDRESS" >/dev/null
wait_until "all CLN nodes to reach the local Bitcoin tip" 30 nodes_are_at_bitcoin_tip

cln_cli "$PAYER_CLN_DIR" -k fundchannel \
  id="$ROUTER_NODE_ID" \
  amount="$CLN_CHANNEL_CAPACITY" \
  announce=true \
  minconf=1 \
  >/dev/null
cln_cli "$ROUTER_CLN_DIR" -k fundchannel \
  id="$ISSUER_NODE_ID" \
  amount="$CLN_CHANNEL_CAPACITY" \
  announce=true \
  minconf=1 \
  >/dev/null
bitcoin_wallet_cli generatetoaddress 6 "$MINER_ADDRESS" >/dev/null
wait_until "all CLN nodes to confirm the announced regtest channels" 45 nodes_are_at_bitcoin_tip
wait_until "the payer-to-router regtest channel" 45 \
  channel_is_usable "$PAYER_CLN_DIR" "$ROUTER_NODE_ID"
wait_until "the router-to-payer regtest channel" 45 \
  channel_is_usable "$ROUTER_CLN_DIR" "$PAYER_NODE_ID"
wait_until "the router-to-issuer regtest channel" 45 \
  channel_is_usable "$ROUTER_CLN_DIR" "$ISSUER_NODE_ID"
wait_until "the issuer-to-router regtest channel" 45 \
  channel_is_usable "$ISSUER_CLN_DIR" "$ROUTER_NODE_ID"
wait_until "payer gossip to learn the router-to-issuer direction" 45 \
  announced_direction_is_visible "$PAYER_CLN_DIR" "$ROUTER_NODE_ID" "$ISSUER_NODE_ID"

export BITCOINPIR_PAYMENT_CLN_ACKNOWLEDGE_LOCAL_REGTEST_ONLY=1
export BITCOINPIR_PAYMENT_CLN_RPC_SOCKET="$ISSUER_RPC_SOCKET"
export BITCOINPIR_PAYMENT_CLN_PAYEE_PUBKEY="$ISSUER_NODE_ID"
export BITCOINPIR_PAYMENT_CLN_PAYER_DIR="$PAYER_CLN_DIR"
export BITCOINPIR_PAYMENT_CLN_CLI="$LIGHTNING_CLI"
export BITCOINPIR_PAYMENT_CLN_REGTEST_WEB_PORT="$REGTEST_WEB_PORT"
export BITCOINPIR_PAYMENT_CLN_JOINED_WEB_PORT="$JOINED_WEB_PORT"
export CARGO_NET_OFFLINE=true
export NO_PROXY=127.0.0.1,localhost
export no_proxy=127.0.0.1,localhost

printf 'payment-v1 CLN regtest E2E: two-hop route ready; running acquisition and joined provider-query tests\n'
(
  cd "$REPOSITORY_ROOT/web"
  npm run test:e2e:payment-cln-regtest
)
printf 'payment-v1 CLN regtest E2E: PASS (temporary regtest only; no real funds)\n'
