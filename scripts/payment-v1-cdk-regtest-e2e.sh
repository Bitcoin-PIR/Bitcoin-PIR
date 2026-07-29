#!/usr/bin/env bash
set -euo pipefail

# Disposable, fake-wallet-only browser/provider/NUT-03/NUT-07 interoperability
# test for standard Cashu. This never connects to Lightning, never uses real
# funds, and never relaxes the production WebPKI/HTTPS mint transport. Default
# mode uses two independent notes: Chromium feeds the first through a real
# Standard Cashu provider plus independent Free peer and verified DPF/Merkle
# query; the native custody lifecycle uses the second. All fixtures are
# owner-only temporary files.

usage() {
  cat <<'EOF'
Usage:
  scripts/payment-v1-cdk-regtest-e2e.sh
  scripts/payment-v1-cdk-regtest-e2e.sh --check-binaries
  scripts/payment-v1-cdk-regtest-e2e.sh --browser-only

The optional check mode verifies the exact CDK version and SHA-256 pins, then
exits without starting a mint, creating a token, or running Cargo.
Browser-only mode runs the real generated JS/WASM import in Chromium and
exits without running Cargo. It accepts only explicitly acknowledged, SHA-256
pinned prebuilt bpir-admin and WASM runtime artifacts; it is not current-tree
build evidence. The default mode builds current bpir-admin and WASM artifacts
with Cargo locked/offline before starting the mint, runs the browser evidence,
then runs the real two-provider query/restart boundary and the independent
native custody interoperability checks.
EOF
}

cdk_mode="run"
case "${1:-}" in
  "") [[ "$#" -eq 0 ]] || { usage >&2; exit 2; } ;;
  --check-binaries) [[ "$#" -eq 1 ]] || { usage >&2; exit 2; }; cdk_mode="check" ;;
  --browser-only) [[ "$#" -eq 1 ]] || { usage >&2; exit 2; }; cdk_mode="browser" ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

for required_command in python3 curl ps uname date cmp; do
  command -v "$required_command" >/dev/null 2>&1 || {
    echo "missing required command: $required_command" >&2
    exit 2
  }
done
PYTHON3_BIN="$(command -v python3)"
readonly PYTHON3_BIN
readonly NATIVE_CALL_TIMEOUT_SECONDS="30"
script_dir="$(cd "$(dirname "$0")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
readonly script_dir repo_root

run_bounded_command() {
  "$PYTHON3_BIN" - "$NATIVE_CALL_TIMEOUT_SECONDS" "$@" <<'PY'
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

CDK_MINTD_BIN="${BITCOINPIR_CDK_MINTD:-$(command -v cdk-mintd || true)}"
CDK_CLI_BIN="${BITCOINPIR_CDK_CLI:-$(command -v cdk-cli || true)}"
if [[ -z "$CDK_MINTD_BIN" || -z "$CDK_CLI_BIN" ]]; then
  echo "set BITCOINPIR_CDK_MINTD and BITCOINPIR_CDK_CLI to CDK 0.17.3 binaries" >&2
  exit 2
fi
if [[ "$(run_bounded_command "$CDK_MINTD_BIN" --version 2>&1)" != "cdk-mintd 0.17.3" ]]; then
  echo "BITCOINPIR_CDK_MINTD must be cdk-mintd 0.17.3" >&2
  exit 2
fi
if [[ "$(run_bounded_command "$CDK_CLI_BIN" --version 2>&1)" != "cdk-cli 0.17.3" ]]; then
  echo "BITCOINPIR_CDK_CLI must be cdk-cli 0.17.3" >&2
  exit 2
fi

sha256_file() {
  "$PYTHON3_BIN" - "$1" <<'PY'
import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], "rb") as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
}

expected_mintd_sha256="${BITCOINPIR_CDK_MINTD_SHA256:-}"
expected_cli_sha256="${BITCOINPIR_CDK_CLI_SHA256:-}"
if [[ -z "$expected_mintd_sha256" && -z "$expected_cli_sha256" \
  && "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
  expected_mintd_sha256="05b2e8cb01c2500a0200264947eb5b41cb82fcfc02263de6c0c1af7d531b89ab"
  expected_cli_sha256="78390b850e6e24f11af1848f54004bdf7439771d81970b115241922435e944b9"
fi
if [[ ! "$expected_mintd_sha256" =~ ^[0-9a-f]{64}$ \
  || ! "$expected_cli_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "set both BITCOINPIR_CDK_MINTD_SHA256 and BITCOINPIR_CDK_CLI_SHA256 for this platform" >&2
  exit 2
fi
if [[ "$(sha256_file "$CDK_MINTD_BIN")" != "$expected_mintd_sha256" \
  || "$(sha256_file "$CDK_CLI_BIN")" != "$expected_cli_sha256" ]]; then
  echo "CDK 0.17.3 binary SHA-256 pin mismatch" >&2
  exit 2
fi
if [[ "$cdk_mode" == "check" ]]; then
  echo "CDK 0.17.3 binary version/hash pins: PASS"
  exit 0
fi
command -v npm >/dev/null 2>&1 || {
  echo "missing required browser command: npm" >&2
  exit 2
}

wasm_package_dir="$repo_root/crates/sdk/wasm/pkg"
wasm_package_json="$wasm_package_dir/package.json"
wasm_js="$wasm_package_dir/pir_sdk_wasm.js"
wasm_binary="$wasm_package_dir/pir_sdk_wasm_bg.wasm"

require_pinned_artifact() {
  local label="$1"
  local path="$2"
  local expected_sha256="$3"
  local actual_sha256=""
  if [[ "$path" != /* || ! -f "$path" ]]; then
    echo "$label must be an existing regular file at an absolute path: $path" >&2
    exit 2
  fi
  if [[ ! "$expected_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "$label requires an explicit lowercase SHA-256 provenance pin" >&2
    exit 2
  fi
  actual_sha256="$(sha256_file "$path")"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    echo "$label SHA-256 provenance pin mismatch" >&2
    exit 2
  fi
}

if [[ "$cdk_mode" == "run" ]]; then
  for build_command in cargo wasm-pack; do
    command -v "$build_command" >/dev/null 2>&1 || {
      echo "missing required default-mode build command: $build_command" >&2
      exit 2
    }
  done
  if [[ "$(wasm-pack --version 2>&1)" != "wasm-pack 0.14.0" ]]; then
    echo "default mode requires wasm-pack 0.14.0" >&2
    exit 2
  fi
  build_target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
  if [[ "$build_target_dir" != /* ]]; then
    build_target_dir="$repo_root/$build_target_dir"
  fi
  (
    cd "$repo_root"
    CARGO_TARGET_DIR="$build_target_dir" \
      cargo build --locked --offline -p bpir-admin
    CARGO_TARGET_DIR="$build_target_dir" CARGO_NET_OFFLINE=true \
      wasm-pack build crates/sdk/wasm \
        --target web --out-dir pkg --mode no-install --no-opt \
        -- --locked --offline
  )
  bpir_admin_bin="$build_target_dir/debug/bpir-admin"
  if [[ ! -x "$bpir_admin_bin" || ! -f "$wasm_package_json" \
    || ! -f "$wasm_js" || ! -f "$wasm_binary" ]]; then
    echo "default mode did not produce the required current-tree browser artifacts" >&2
    exit 2
  fi
  echo "current bpir-admin sha256=$(sha256_file "$bpir_admin_bin")"
  echo "current WASM package.json sha256=$(sha256_file "$wasm_package_json")"
  echo "current WASM JS sha256=$(sha256_file "$wasm_js")"
  echo "current WASM binary sha256=$(sha256_file "$wasm_binary")"
else
  if [[ "${BITCOINPIR_CDK_BROWSER_ONLY_ACKNOWLEDGE_PREBUILT:-}" != "1" ]]; then
    echo "--browser-only requires BITCOINPIR_CDK_BROWSER_ONLY_ACKNOWLEDGE_PREBUILT=1" >&2
    exit 2
  fi
  bpir_admin_bin="${BITCOINPIR_BPIR_ADMIN:-}"
  require_pinned_artifact \
    "BITCOINPIR_BPIR_ADMIN" \
    "$bpir_admin_bin" \
    "${BITCOINPIR_BPIR_ADMIN_SHA256:-}"
  require_pinned_artifact \
    "generated WASM package.json" \
    "$wasm_package_json" \
    "${BITCOINPIR_WASM_PACKAGE_JSON_SHA256:-}"
  require_pinned_artifact \
    "generated WASM JavaScript" \
    "$wasm_js" \
    "${BITCOINPIR_WASM_JS_SHA256:-}"
  require_pinned_artifact \
    "generated WASM binary" \
    "$wasm_binary" \
    "${BITCOINPIR_WASM_BINARY_SHA256:-}"
  if [[ ! -x "$bpir_admin_bin" ]]; then
    echo "BITCOINPIR_BPIR_ADMIN must be executable" >&2
    exit 2
  fi
  echo "browser-only prebuilt bpir-admin and WASM provenance pins: PASS"
fi
readonly wasm_package_dir wasm_package_json wasm_js wasm_binary bpir_admin_bin
if [[ ! -x "$repo_root/web/node_modules/.bin/tsc" \
  || ! -x "$repo_root/web/node_modules/.bin/playwright" ]]; then
  echo "install the pinned web dependencies before running CDK browser evidence" >&2
  exit 2
fi

task_tmp_root="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
runtime_dir="$(mktemp -d "$task_tmp_root/bitcoinpir-cdk.XXXXXX")"
chmod 700 "$runtime_dir"
runtime_marker="$runtime_dir/.bitcoinpir-payment-v1-cdk-regtest"
: > "$runtime_marker"
mint_pid=""

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
  [[ "$command_line" == *"$runtime_dir"* ]]
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

safe_remove_runtime() {
  local base=""
  local name=""
  base="$(dirname "$runtime_dir")"
  name="$(basename "$runtime_dir")"
  [[ "$base" == "$task_tmp_root" \
    && "$name" == bitcoinpir-cdk.* \
    && -f "$runtime_marker" \
    && ! -L "$runtime_dir" ]] \
    || return 1
  rm -rf -- "$runtime_dir"
}

cleanup() {
  local status="$?"
  local cleanup_ok=0
  trap - EXIT INT TERM HUP
  set +e
  if [[ -n "$mint_pid" ]]; then
    if process_is_live "$mint_pid"; then
      if process_is_owned "$mint_pid"; then
        kill -TERM "$mint_pid" >/dev/null 2>&1 || true
        if ! wait_for_process_exit "$mint_pid"; then
          process_is_owned "$mint_pid" && kill -KILL "$mint_pid" >/dev/null 2>&1 || true
          wait_for_process_exit "$mint_pid" || cleanup_ok=1
        fi
      else
        echo "refusing to signal non-owned PID $mint_pid" >&2
        cleanup_ok=1
      fi
    fi
    process_is_live "$mint_pid" || wait "$mint_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$cleanup_ok" -eq 0 ]]; then
    safe_remove_runtime || cleanup_ok=1
  fi
  if [[ "$cleanup_ok" -ne 0 ]]; then
    echo "cleanup was incomplete; inspect $runtime_dir without executing it" >&2
    [[ "$status" -ne 0 ]] || status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

expected_amount=8
total_mint_amount=$((expected_amount * 2))
test_leaf_spki_sha256="e91550521f8e17b21d99f7e00b99c08be1b1f31fe57772ac8f904ea50c6a609b"
synthetic_mint_endpoint="https://cdk-loopback.invalid"
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
if [[ "$cdk_mode" == "run" ]]; then
  provider_tls_port="${BITCOINPIR_CDK_PROVIDER_TLS_PORT:-}"
  if [[ -z "$provider_tls_port" ]]; then
    provider_tls_port="$("$PYTHON3_BIN" - "$port" <<'PY'
import socket
import sys

excluded = int(sys.argv[1])
while True:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        candidate = sock.getsockname()[1]
    if candidate != excluded:
        print(candidate)
        break
PY
)"
  fi
  if [[ ! "$provider_tls_port" =~ ^[0-9]+$ ]] \
    || (( provider_tls_port < 1024 || provider_tls_port > 65535 )) \
    || [[ "$provider_tls_port" == "$port" ]]; then
    echo "BITCOINPIR_CDK_PROVIDER_TLS_PORT must be a distinct unprivileged port" >&2
    exit 2
  fi
  signed_mint_endpoint="https://localhost:${provider_tls_port}"
  signed_leaf_spki_sha256="$test_leaf_spki_sha256"
else
  provider_tls_port=""
  signed_mint_endpoint="$synthetic_mint_endpoint"
  signed_leaf_spki_sha256="$("$PYTHON3_BIN" - "$signed_mint_endpoint" <<'PY'
import hashlib
import sys

print(hashlib.sha256(
    b"BitcoinPIR/payment-v1/test-only-cdk-loopback-leaf-spki/v1\x00"
    + sys.argv[1].encode("ascii")
).hexdigest())
PY
)"
fi
export NO_PROXY=127.0.0.1,localhost
export no_proxy=127.0.0.1,localhost
config_path="$runtime_dir/config.toml"
mint_log="$runtime_dir/mintd.log"
wallet_dir="$runtime_dir/wallet"
mint_output="$runtime_dir/mint.log"
browser_send_output="$runtime_dir/send-browser.out"
native_send_output="$runtime_dir/send-native.out"
browser_source_token_file="$runtime_dir/token-browser-source.cashub"
native_token_file="$runtime_dir/token-native.cashub"
keys_file="$runtime_dir/keys.json"
info_file="$runtime_dir/info.json"
browser_token_file="$runtime_dir/token-browser.cashub"
browser_fixture_file="$runtime_dir/browser-fixture.json"
browser_spend_file="$runtime_dir/browser-spend.bin"
manifest_config="$runtime_dir/cashu-manifest.toml"
manifest_file="$runtime_dir/cashu-manifest-v1.bin"
manifest_output="$runtime_dir/cashu-manifest.out"
policy_config="$runtime_dir/service-policy.toml"
policy_file="$runtime_dir/service-policy-v1.bin"
policy_output="$runtime_dir/service-policy.out"
operator_key="$runtime_dir/operator-ed25519.key"
policy_key="$runtime_dir/policy-ed25519.key"
database_fixture_root="$runtime_dir/provider-database-fixture"
database_fixture_metadata="$database_fixture_root/fixture.json"

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
  if ! process_is_owned "$mint_pid"; then
    echo "disposable cdk-mintd exited or changed identity during startup; inspect $mint_log before cleanup" >&2
    exit 1
  fi
  if curl --fail --silent --connect-timeout 1 --max-time 2 \
    "$mint_endpoint/v1/info" > "$info_file" 2>/dev/null \
    && "$PYTHON3_BIN" - "$info_file" <<'PY'
import json
import sys

with open(sys.argv[1], "rb") as source:
    value = json.load(source)
if not isinstance(value, dict) or value.get("name") != "BitcoinPIR disposable CDK interop mint":
    raise SystemExit(1)
PY
  then
    if process_is_owned "$mint_pid"; then
      ready=true
      break
    fi
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  echo "disposable cdk-mintd did not become ready" >&2
  exit 1
fi

install -d -m 700 "$wallet_dir"
run_bounded_command "$CDK_CLI_BIN" --work-dir "$wallet_dir" --unit sat --non-interactive \
  mint "$mint_endpoint" "$total_mint_amount" > "$mint_output"
run_bounded_command "$CDK_CLI_BIN" --work-dir "$wallet_dir" --unit sat --non-interactive \
  send --amount "$expected_amount" --mint-url "$mint_endpoint" > "$browser_send_output"
run_bounded_command "$CDK_CLI_BIN" --work-dir "$wallet_dir" --unit sat --non-interactive \
  send --amount "$expected_amount" --mint-url "$mint_endpoint" > "$native_send_output"
tail -n 1 "$browser_send_output" > "$browser_source_token_file"
tail -n 1 "$native_send_output" > "$native_token_file"
chmod 600 "$browser_source_token_file" "$native_token_file"
for token_path in "$browser_source_token_file" "$native_token_file"; do
  if ! grep -Eq '^cashuB[A-Za-z0-9_-]+={0,2}$' "$token_path"; then
    echo "cdk-cli did not emit two independent cashuB tokens" >&2
    exit 1
  fi
done
if cmp -s "$browser_source_token_file" "$native_token_file"; then
  echo "cdk-cli emitted duplicate browser and native Cashu notes" >&2
  exit 1
fi
rm -f -- "$browser_send_output" "$native_send_output"
curl --fail --silent --show-error --connect-timeout 2 --max-time 10 \
  "$mint_endpoint/v1/keys" > "$keys_file"
chmod 600 "$keys_file"

# Production policy correctly forbids the disposable mint's HTTP loopback URL.
# Cashu proofs do not commit to the NUT-00 wallet mint URL, so this owner-only
# test fixture changes only that CBOR text field to the signed HTTPS identity.
# Default mode terminates strict private-CA TLS at a feature-gated test proxy;
# browser-only mode retains the non-routable synthetic identity. Chromium must
# reject the untouched HTTP token and accept the relabelled first token only
# against a manifest built from the exact CDK keyset. The second token is never
# imported by Chromium and remains reserved for native custody lifecycle tests.
"$PYTHON3_BIN" - \
  "$browser_source_token_file" "$browser_token_file" "$mint_endpoint" "$signed_mint_endpoint" <<'PY'
import base64
import pathlib
import sys

source_path, destination_path, actual_endpoint, signed_endpoint = sys.argv[1:]
token = pathlib.Path(source_path).read_text(encoding="ascii").strip()
if not token.startswith("cashuB"):
    raise SystemExit("CDK token is not cashuB")
encoded = token[len("cashuB"):]
padding = "=" * ((4 - len(encoded) % 4) % 4)
raw = base64.urlsafe_b64decode(encoded + padding)

def cbor_text(value: str) -> bytes:
    payload = value.encode("utf-8")
    length = len(payload)
    if length < 24:
        head = bytes([0x60 | length])
    elif length <= 0xff:
        head = bytes([0x78, length])
    elif length <= 0xffff:
        head = bytes([0x79]) + length.to_bytes(2, "big")
    else:
        raise SystemExit("mint endpoint exceeds the bounded CBOR relabel helper")
    return head + payload

needle = cbor_text(actual_endpoint)
if raw.count(needle) != 1:
    raise SystemExit("cashuB CBOR does not contain exactly one expected mint endpoint")
relabelled = raw.replace(needle, cbor_text(signed_endpoint), 1)
browser_encoded = base64.urlsafe_b64encode(relabelled).decode("ascii")
if "=" not in encoded:
    browser_encoded = browser_encoded.rstrip("=")
pathlib.Path(destination_path).write_text("cashuB" + browser_encoded + "\n", encoding="ascii")
PY
chmod 600 "$browser_token_file"

manifest_root_hex=""
if [[ "$cdk_mode" == "run" ]]; then
  install -d -m 700 "$database_fixture_root"
  BITCOINPIR_CDK_DATABASE_FIXTURE_ROOT="$database_fixture_root" \
  BITCOINPIR_CDK_DATABASE_FIXTURE_METADATA="$database_fixture_metadata" \
  CARGO_TARGET_DIR="$build_target_dir" \
    cargo test --locked --offline \
      -p runtime \
      --features standard-cashu-process-e2e \
      --test payment_v1_standard_cashu_process_e2e \
      standard_cashu_prepare_real_cdk_database_fixture -- --ignored --exact
  manifest_root_hex="$("$PYTHON3_BIN" - "$database_fixture_metadata" <<'PY'
import json
import pathlib
import re
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if set(value) != {"databasePath", "manifestRootHex", "bucketSuperRootHex"}:
    raise SystemExit("prepared database metadata has an unexpected schema")
for field in ("manifestRootHex", "bucketSuperRootHex"):
    if not isinstance(value[field], str) or not re.fullmatch(r"[0-9a-f]{64}", value[field]):
        raise SystemExit(f"prepared database {field} is invalid")
database = pathlib.Path(value["databasePath"])
if not database.is_absolute() or database.parent != pathlib.Path(sys.argv[1]).parent:
    raise SystemExit("prepared database escaped the owner-only fixture root")
print(value["manifestRootHex"])
PY
)"
  if [[ ! "$manifest_root_hex" =~ ^[0-9a-f]{64}$ ]]; then
    echo "runtime fixture prepare did not emit an exact manifest root" >&2
    exit 1
  fi
fi

now_unix="$(date +%s)"
issued_at=$((now_unix - 60))
expires_at=$((now_unix + 3600))
active_output_valid_through=$((expires_at + 3600))
"$PYTHON3_BIN" - \
  "$keys_file" "$manifest_config" "$signed_mint_endpoint" \
  "$signed_leaf_spki_sha256" "$expires_at" "$active_output_valid_through" <<'PY'
import json
import pathlib
import re
import sys

keys_path, output_path, endpoint, leaf_pin, accepted_through, output_through = sys.argv[1:]
value = json.loads(pathlib.Path(keys_path).read_text(encoding="utf-8"))
keysets = value.get("keysets")
if not isinstance(keysets, list):
    raise SystemExit("CDK /v1/keys has no keysets array")
active = [entry for entry in keysets
          if isinstance(entry, dict) and entry.get("active") is True and entry.get("unit") == "sat"]
if len(active) != 1:
    raise SystemExit("CDK /v1/keys must contain exactly one active sat keyset")
keyset = active[0]
keys = keyset.get("keys")
if not isinstance(keys, dict) or not keys:
    raise SystemExit("active CDK keyset has no denomination keys")
rows = []
for amount_text, public_key in keys.items():
    if not isinstance(amount_text, str) or not amount_text.isdigit() or int(amount_text) <= 0:
        raise SystemExit("CDK denomination amount is invalid")
    if not isinstance(public_key, str) or not re.fullmatch(r"[0-9a-f]{66}", public_key):
        raise SystemExit("CDK denomination key is not canonical compressed-point hex")
    rows.append((int(amount_text), public_key))
rows.sort()
fee = keyset.get("input_fee_ppk", 0)
if not isinstance(fee, int) or fee < 0 or fee > 2**32 - 1:
    raise SystemExit("CDK input_fee_ppk is invalid")
final_expiry = keyset.get("final_expiry")
if final_expiry is not None and (not isinstance(final_expiry, int) or final_expiry <= 0):
    raise SystemExit("CDK final_expiry is invalid")
if not re.fullmatch(r"[0-9a-f]{64}", leaf_pin):
    raise SystemExit("signed mint leaf SPKI pin is invalid")
lines = [
    "manifest_epoch = 1",
    f'mint_endpoint = "{endpoint}"',
    # Default mode gives the real provider this exact private-CA pin through
    # the production strict-HTTPS transport. Browser-only keeps a deterministic
    # non-routable identity. Neither mode introduces a pinless fallback.
    f'leaf_spki_sha256_pins_hex = ["{leaf_pin}"]',
    'unit = "sat"',
    f"accepted_inputs_valid_through = {accepted_through}",
    f"active_output_valid_through = {output_through}",
    "",
    "[[keysets]]",
    "active = true",
    f"input_fee_ppk = {fee}",
]
if final_expiry is not None:
    lines.append(f"final_expiry = {final_expiry}")
for amount, public_key in rows:
    lines.extend([
        "",
        "[[keysets.keys]]",
        f"amount = {amount}",
        f'public_key_hex = "{public_key}"',
    ])
pathlib.Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
chmod 600 "$manifest_config"
run_bounded_command "$bpir_admin_bin" payment-artifact cashu-manifest \
  --config "$manifest_config" --out "$manifest_file" > "$manifest_output"
chmod 600 "$manifest_file" "$manifest_output"
mint_id="$(sed -n 's/^mint_id=//p' "$manifest_output")"
manifest_digest="$(sed -n 's/^manifest_digest=//p' "$manifest_output")"
if [[ ! "$mint_id" =~ ^[0-9a-f]{64}$ || ! "$manifest_digest" =~ ^[0-9a-f]{64}$ ]]; then
  echo "bpir-admin did not emit canonical Cashu manifest bindings" >&2
  exit 1
fi

operator_pubkey="$(run_bounded_command "$bpir_admin_bin" keygen --out "$operator_key")"
policy_pubkey="$(run_bounded_command "$bpir_admin_bin" keygen --out "$policy_key")"
if [[ ! "$operator_pubkey" =~ ^[0-9a-f]{64}$ \
  || ! "$policy_pubkey" =~ ^[0-9a-f]{64}$ \
  || "$operator_pubkey" == "$policy_pubkey" ]]; then
  echo "bpir-admin did not emit two independent Ed25519 test keys" >&2
  exit 1
fi

"$PYTHON3_BIN" - \
  "$policy_config" "$operator_pubkey" "$issued_at" "$expires_at" \
  "$mint_id" "$manifest_digest" "$signed_mint_endpoint" "$expected_amount" \
  "$manifest_root_hex" <<'PY'
import pathlib
import re
import sys

(output_path, operator_key, issued_at, expires_at, mint_id,
 manifest_digest, endpoint, amount, manifest_root) = sys.argv[1:]
if manifest_root:
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_root):
        raise SystemExit("exact provider manifest root is invalid")
    dataset = f'''kind = "manifest-root"
root_hex = "{manifest_root}"'''
else:
    dataset = '''kind = "class"
class_id = 2'''
config = f'''operator_pubkey_hex = "{operator_key}"
stable_server_id = "payment-cdk-cashu-browser"
policy_epoch = 1
issued_at = {issued_at}
expires_at = {expires_at}
auth_padding_class = "16-kib"

[[scopes]]
backend = "dpf-pir-v1"
workload = "dpf-evaluate-job-v1"
protocol_version = 1
operation_profile = 1
entitlement_profile = 8

[scopes.dataset]
{dataset}

[scopes.limits]
max_logical_inputs = 1
max_frames = 64
max_request_bytes = 2097152
max_response_bytes = 2097152
max_wall_time_ms = 20000
max_concurrent_sockets = 1
max_hint_groups = 0
max_work_units = 10000

[[scopes.offers]]
offer_id = 17
acquisition = "cashu-ecash"
free_mode = "not-free"
priority_class = 10
authorization = "cashu-ecash"
verification = "standard-cashu-mint-online"
deployment_status = "stable"
issuer_id_hex = "{mint_id}"
key_id_hex = "{manifest_digest}"
cashu_mint_manifest_path = "cashu-manifest-v1.bin"
endpoint = "{endpoint}"
minimum_credential_validity_seconds = 1
retired_policy_grace_seconds = 0
credential_count = 1
credential_presentation_limit = 1
privacy_leakage_bits = 24

[scopes.offers.price]
kind = "cashu"
unit = "sat"
amount = {amount}
'''
pathlib.Path(output_path).write_text(config, encoding="utf-8")
PY
chmod 600 "$policy_config"
run_bounded_command "$bpir_admin_bin" service-policy sign \
  --config "$policy_config" --policy-signing-key "$policy_key" --out "$policy_file" \
  > "$policy_output"
chmod 600 "$policy_file" "$policy_output"
provider_id="$(sed -n 's/^provider_id=//p' "$policy_output")"
signed_policy_pubkey="$(sed -n 's/^policy_signing_key_ed25519=//p' "$policy_output")"
if [[ ! "$provider_id" =~ ^[0-9a-f]{64}$ || "$signed_policy_pubkey" != "$policy_pubkey" ]]; then
  echo "bpir-admin did not emit the expected signed Cashu policy bindings" >&2
  exit 1
fi

"$PYTHON3_BIN" - \
  "$browser_fixture_file" "$policy_file" "$browser_source_token_file" "$browser_token_file" \
  "$provider_id" "$policy_pubkey" "$mint_endpoint" "$signed_mint_endpoint" \
  "$expected_amount" <<'PY'
import json
import pathlib
import sys

(output_path, policy_path, original_path, browser_path, provider_id,
 policy_key, actual_endpoint, signed_endpoint, expected_amount) = sys.argv[1:]
fixture = {
    "providerIdHex": provider_id,
    "policySigningPubkeyHex": policy_key,
    "policyBytes": list(pathlib.Path(policy_path).read_bytes()),
    "originalToken": pathlib.Path(original_path).read_text(encoding="ascii").strip(),
    "browserToken": pathlib.Path(browser_path).read_text(encoding="ascii").strip(),
    "actualMintEndpoint": actual_endpoint,
    "signedMintEndpoint": signed_endpoint,
    "expectedAmount": int(expected_amount),
}
pathlib.Path(output_path).write_text(json.dumps(fixture, separators=(",", ":")), encoding="utf-8")
PY
chmod 600 "$browser_fixture_file"

(
  cd "$repo_root/web"
  BITCOINPIR_CDK_BROWSER_FIXTURE_FILE="$browser_fixture_file" \
  BITCOINPIR_CDK_BROWSER_SPEND_FILE="$browser_spend_file" \
    npm run test:e2e:payment-cdk-cashu
)
if [[ ! -s "$browser_spend_file" ]]; then
  echo "Chromium did not emit one canonical standard-Cashu spend" >&2
  exit 1
fi
chmod 600 "$browser_spend_file"

if [[ "$cdk_mode" == "browser" ]]; then
  echo "CDK 0.17.3 cashuB -> hash-pinned prebuilt JS/WASM Chromium import -> encrypted-vault retirement: PASS"
  echo "Evidence boundary: --browser-only does not prove current source-to-artifact correspondence."
  echo "Boundary: the untouched HTTP token is rejected; only owner-only test metadata is relabelled to the signed synthetic HTTPS identity."
  exit 0
fi

BITCOINPIR_CDK_DATABASE_FIXTURE_ROOT="$database_fixture_root" \
BITCOINPIR_CDK_DATABASE_FIXTURE_METADATA="$database_fixture_metadata" \
BITCOINPIR_CDK_SIGNED_MINT_ENDPOINT="$signed_mint_endpoint" \
BITCOINPIR_CDK_MINT_ENDPOINT="$mint_endpoint" \
BITCOINPIR_CDK_EXPECTED_AMOUNT="$expected_amount" \
BITCOINPIR_CDK_POLICY_FILE="$policy_file" \
BITCOINPIR_CDK_PROVIDER_ID_HEX="$provider_id" \
BITCOINPIR_CDK_POLICY_SIGNING_PUBKEY_HEX="$policy_pubkey" \
BITCOINPIR_CDK_BROWSER_SPEND_FILE="$browser_spend_file" \
CARGO_TARGET_DIR="$build_target_dir" \
  cargo test --locked --offline \
    -p runtime \
    --features standard-cashu-process-e2e \
    --test payment_v1_standard_cashu_process_e2e \
    standard_cashu_real_cdk_browser_provider_two_server_e2e -- --ignored --exact

BITCOINPIR_CDK_CASHUB_TOKEN_FILE="$native_token_file" \
BITCOINPIR_CDK_KEYS_FILE="$keys_file" \
BITCOINPIR_CDK_MINT_ENDPOINT="$mint_endpoint" \
BITCOINPIR_CDK_EXPECTED_AMOUNT="$expected_amount" \
CARGO_TARGET_DIR="$build_target_dir" \
  cargo test --locked --offline -p pir-sdk-wasm --lib \
    standard_cashu::tests::real_cdk_cashub_interop -- --ignored --exact

BITCOINPIR_CDK_CASHUB_TOKEN_FILE="$native_token_file" \
BITCOINPIR_CDK_KEYS_FILE="$keys_file" \
BITCOINPIR_CDK_MINT_ENDPOINT="$mint_endpoint" \
BITCOINPIR_CDK_SIGNED_MINT_ENDPOINT="$signed_mint_endpoint" \
BITCOINPIR_CDK_SIGNED_MINT_LEAF_SPKI_SHA256_HEX="$signed_leaf_spki_sha256" \
BITCOINPIR_CDK_EXPECTED_AMOUNT="$expected_amount" \
BITCOINPIR_CDK_POLICY_FILE="$policy_file" \
BITCOINPIR_CDK_PROVIDER_ID_HEX="$provider_id" \
BITCOINPIR_CDK_POLICY_SIGNING_PUBKEY_HEX="$policy_pubkey" \
BITCOINPIR_CDK_NOW_UNIX="$now_unix" \
BITCOINPIR_CDK_BROWSER_SPEND_FILE="$browser_spend_file" \
CARGO_TARGET_DIR="$build_target_dir" \
  cargo test --locked --offline -p pir-cashu-client \
    --features insecure-dev-sqlite-store \
    --test cdk_nut03_interop \
    real_cdk_nut03_swap_verifies_dleq_and_commits_custody -- --ignored --exact

# Fixed cdk-cli 0.17.3 accepts `receive` bearer tokens only as positional
# arguments, not from stdin or a private file. The Rust client therefore
# performs the successor NUT-03 directly from authenticated custody memory.
# This keeps the second token and custody bearer out of process argv while
# proving the first custody lot transitions UNSPENT -> SPENT and independent
# successor custody is UNSPENT.
for cdk_log_path in "$mint_log" "$runtime_dir"/logs/*; do
  [[ -f "$cdk_log_path" && ! -L "$cdk_log_path" ]] || continue
  if grep -Eqi \
    'cashuB[A-Za-z0-9_-]+={0,2}|payment[_-]?hash|preimage|ln(bc|tb|bcrt)[0-9a-z]{20,}' \
    "$cdk_log_path"; then
    echo "CDK daemon log contained forbidden bearer, hash, preimage or invoice value" >&2
    exit 1
  fi
done
echo "CDK 0.17.3 fakewallet NUT-03/NUT-07 input-SPENT, custody-UNSPENT->SPENT, successor-UNSPENT interoperability: PASS"
