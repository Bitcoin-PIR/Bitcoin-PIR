#!/usr/bin/env bash
set -euo pipefail

# Disposable, fake-wallet-only NUT-03/NUT-07 interoperability test for standard Cashu.
# This never connects to Lightning, never uses real funds, and never relaxes
# the production WebPKI/HTTPS mint transport. The ignored Rust test receives a
# loopback-only token and public keyset through owner-only temporary files.

CDK_MINTD_BIN="${BITCOINPIR_CDK_MINTD:-$(command -v cdk-mintd || true)}"
CDK_CLI_BIN="${BITCOINPIR_CDK_CLI:-$(command -v cdk-cli || true)}"
if [[ -z "$CDK_MINTD_BIN" || -z "$CDK_CLI_BIN" ]]; then
  echo "set BITCOINPIR_CDK_MINTD and BITCOINPIR_CDK_CLI to CDK 0.17.3 binaries" >&2
  exit 2
fi
if [[ "$("$CDK_MINTD_BIN" --version 2>&1)" != "cdk-mintd 0.17.3" ]]; then
  echo "BITCOINPIR_CDK_MINTD must be cdk-mintd 0.17.3" >&2
  exit 2
fi
if [[ "$("$CDK_CLI_BIN" --version 2>&1)" != "cdk-cli 0.17.3" ]]; then
  echo "BITCOINPIR_CDK_CLI must be cdk-cli 0.17.3" >&2
  exit 2
fi

task_tmp_root="${TMPDIR:-/tmp}"
runtime_dir="$(mktemp -d "${task_tmp_root%/}/bitcoinpir-cdk.XXXXXX")"
chmod 700 "$runtime_dir"
mint_pid=""

cleanup() {
  if [[ -n "$mint_pid" ]]; then
    kill "$mint_pid" 2>/dev/null || true
    wait "$mint_pid" 2>/dev/null || true
  fi
  case "$runtime_dir" in
    "${task_tmp_root%/}"/bitcoinpir-cdk.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to remove unexpected runtime directory: $runtime_dir" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM

port="${BITCOINPIR_CDK_PORT:-}"
if [[ -z "$port" ]]; then
  port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
fi
if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1024 || port > 65535 )); then
  echo "BITCOINPIR_CDK_PORT must be an unprivileged TCP port" >&2
  exit 2
fi
mint_endpoint="http://127.0.0.1:${port}"
config_path="$runtime_dir/config.toml"
mint_log="$runtime_dir/mintd.log"
wallet_dir="$runtime_dir/wallet"
mint_output="$runtime_dir/mint.log"
send_output="$runtime_dir/send.out"
token_file="$runtime_dir/token.cashub"
keys_file="$runtime_dir/keys.json"
expected_amount=8

umask 077
{
  echo '[info]'
  echo "url = \"$mint_endpoint\""
  echo 'listen_host = "127.0.0.1"'
  echo "listen_port = $port"
  echo 'mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"'
  echo 'use_keyset_v2 = true'
  echo
  echo '[info.quote_ttl]'
  echo 'mint_ttl = 600'
  echo 'melt_ttl = 120'
  echo
  echo '[info.http_cache]'
  echo 'backend = "memory"'
  echo 'ttl = 60'
  echo 'tti = 60'
  echo
  echo '[mint_management_rpc]'
  echo 'enabled = false'
  echo
  echo '[mint_info]'
  echo 'name = "BitcoinPIR disposable CDK interop mint"'
  echo 'description = "Local fakewallet tokens only"'
  echo
  echo '[database]'
  echo 'engine = "sqlite"'
  echo
  echo '[ln]'
  echo 'ln_backend = "fakewallet"'
  echo 'unit = "sat"'
  echo 'min_mint = 1'
  echo 'max_mint = 100000'
  echo 'min_melt = 1'
  echo 'max_melt = 100000'
  echo
  echo '[onchain]'
  echo 'onchain_backend = "fakewallet"'
  echo 'min_mint = 1'
  echo 'max_mint = 100000'
  echo 'min_melt = 1'
  echo 'max_melt = 100000'
} > "$config_path"

"$CDK_MINTD_BIN" --work-dir "$runtime_dir" --config "$config_path" > "$mint_log" 2>&1 &
mint_pid=$!
ready=false
for _ in $(seq 1 100); do
  if curl --fail --silent "$mint_endpoint/v1/info" >/dev/null 2>&1; then
    ready=true
    break
  fi
  if ! kill -0 "$mint_pid" 2>/dev/null; then
    echo "disposable cdk-mintd exited during startup; inspect $mint_log before cleanup" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  echo "disposable cdk-mintd did not become ready" >&2
  exit 1
fi

install -d -m 700 "$wallet_dir"
"$CDK_CLI_BIN" --work-dir "$wallet_dir" --unit sat --non-interactive \
  mint "$mint_endpoint" "$expected_amount" > "$mint_output"
"$CDK_CLI_BIN" --work-dir "$wallet_dir" --unit sat --non-interactive \
  send --amount "$expected_amount" --mint-url "$mint_endpoint" > "$send_output"
tail -n 1 "$send_output" > "$token_file"
chmod 600 "$token_file"
if ! grep -Eq '^cashuB[A-Za-z0-9_-]+={0,2}$' "$token_file"; then
  echo "cdk-cli did not emit one cashuB token" >&2
  exit 1
fi
curl --fail --silent --show-error "$mint_endpoint/v1/keys" > "$keys_file"
chmod 600 "$keys_file"

BITCOINPIR_CDK_CASHUB_TOKEN_FILE="$token_file" \
BITCOINPIR_CDK_KEYS_FILE="$keys_file" \
BITCOINPIR_CDK_MINT_ENDPOINT="$mint_endpoint" \
BITCOINPIR_CDK_EXPECTED_AMOUNT="$expected_amount" \
  cargo test --offline -p pir-sdk-wasm --lib \
    standard_cashu::tests::real_cdk_cashub_interop -- --ignored --exact

BITCOINPIR_CDK_CASHUB_TOKEN_FILE="$token_file" \
BITCOINPIR_CDK_KEYS_FILE="$keys_file" \
BITCOINPIR_CDK_MINT_ENDPOINT="$mint_endpoint" \
BITCOINPIR_CDK_EXPECTED_AMOUNT="$expected_amount" \
  cargo test --offline -p pir-cashu-client \
    --features insecure-dev-sqlite-store \
    --test cdk_nut03_interop \
    real_cdk_nut03_swap_verifies_dleq_and_commits_custody -- --ignored --exact

# Fixed cdk-cli 0.17.3 accepts `receive` bearer tokens only as positional
# arguments, not from stdin or a private file. Do not expose provider custody
# in process argv. The Rust test therefore proves original inputs SPENT and
# fresh provider custody UNSPENT against real CDK NUT-07, but intentionally
# does not exercise the provider-custody UNSPENT -> SPENT transition.
echo "CDK 0.17.3 fakewallet NUT-03 plus input-SPENT/custody-UNSPENT NUT-07 interoperability: PASS"
echo "provider-custody UNSPENT -> SPENT is not exercised: cdk-cli 0.17.3 receive is argv-only"
