#!/usr/bin/env bash
set -euo pipefail

# End-to-end local smoke for the TEE ORAM backend:
#   1. build a tiny INDEX+CHUNK cuckoo DB fixture,
#   2. build split-store Circuit ORAM images with oramctl,
#   3. start unified_server with --features cuckoo-oram,
#   4. verify cleartext ORAM lookup is rejected,
#   5. verify encrypted-channel ORAM lookup returns found / missing / whale.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ORAM_REPO="${ORAM_REPO:-${HOME}/bitcoin-pir/oram}"
SMOKE_ROOT="${SMOKE_ROOT:-$(mktemp -d /tmp/bpir-oram-smoke.XXXXXX)}"
PORT="${PORT:-}"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  if [[ "${KEEP_SMOKE_ROOT:-0}" != "1" ]]; then
    rm -rf "${SMOKE_ROOT}"
  else
    printf 'keeping_smoke_root=%s\n' "${SMOKE_ROOT}"
  fi
}
trap cleanup EXIT

choose_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

require_path() {
  local path="$1"
  local label="$2"
  if [[ ! -e "${path}" ]]; then
    printf 'missing_%s=%s\n' "${label}" "${path}" >&2
    exit 2
  fi
}

require_contains() {
  local haystack="$1"
  local needle="$2"
  if ! grep -Fq "${needle}" <<< "${haystack}"; then
    printf 'missing_expected_output=%s\n' "${needle}" >&2
    exit 1
  fi
}

if [[ -z "${PORT}" ]]; then
  PORT="$(choose_port)"
fi

DB_DIR="${SMOKE_ROOT}/db"
ORAM_DIR="${SMOKE_ROOT}/oram"
SERVER_LOG="${SMOKE_ROOT}/unified_server.log"
mkdir -p "${DB_DIR}" "${ORAM_DIR}"

require_path "${ORAM_REPO}/Cargo.toml" "oram_repo"

printf 'repo_root=%s\n' "${REPO_ROOT}"
printf 'oram_repo=%s\n' "${ORAM_REPO}"
printf 'smoke_root=%s\n' "${SMOKE_ROOT}"
printf 'port=%s\n' "${PORT}"

cd "${REPO_ROOT}"

fixture_output="$(
  cargo run -q -p pir-sdk-client --example oram_make_fixture -- --out-dir "${DB_DIR}"
)"
printf '%s\n' "${fixture_output}" | tee "${SMOKE_ROOT}/fixture.env"
FOUND_HASH="$(awk -F= '/^found_script_hash=/{print $2}' <<< "${fixture_output}")"
MISSING_HASH="$(awk -F= '/^missing_script_hash=/{print $2}' <<< "${fixture_output}")"
WHALE_HASH="$(awk -F= '/^whale_script_hash=/{print $2}' <<< "${fixture_output}")"

(
  cd "${ORAM_REPO}"
  cargo run -q --bin oramctl -- build-circuit \
    --db-dir "${DB_DIR}" \
    --out-dir "${ORAM_DIR}" \
    --pack 4 \
    --leaf-divisor 4 \
    --bucket-size 2 \
    --stash-capacity 128
  cargo run -q --bin oramctl -- verify-circuit-bins \
    --db-dir "${DB_DIR}" \
    --oram-dir "${ORAM_DIR}" \
    --pack 4 \
    --bins 32
)

cd "${REPO_ROOT}"
cargo build -q -p runtime --features cuckoo-oram --bin unified_server

./target/debug/unified_server \
  --port "${PORT}" \
  --data-dir "${DB_DIR}" \
  --serve-queries \
  --disable-onion \
  --cuckoo-oram-dir "${ORAM_DIR}" \
  --cuckoo-oram-pack 4 \
  --cuckoo-oram-no-save \
  >"${SERVER_LOG}" 2>&1 &
SERVER_PID="$!"

for _ in $(seq 1 100); do
  if grep -Fq "Listening on" "${SERVER_LOG}"; then
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    cat "${SERVER_LOG}" >&2 || true
    exit 1
  fi
  sleep 0.1
done

if ! grep -Fq "Listening on" "${SERVER_LOG}"; then
  cat "${SERVER_LOG}" >&2 || true
  printf 'server_failed_to_start=true\n' >&2
  exit 1
fi

SERVER_URL="ws://127.0.0.1:${PORT}"
cleartext_output="$(
  cargo run -q -p pir-sdk-client --example oram_local_smoke -- \
    --server "${SERVER_URL}" \
    --expect-cleartext-reject \
    "${FOUND_HASH}"
)"
printf '%s\n' "${cleartext_output}"
require_contains "${cleartext_output}" "cleartext_reject=ok"

encrypted_output="$(
  cargo run -q -p pir-sdk-client --example oram_local_smoke -- \
    --server "${SERVER_URL}" \
    "${FOUND_HASH}" \
    "${MISSING_HASH}" \
    "${WHALE_HASH}"
)"
printf '%s\n' "${encrypted_output}"
require_contains "${encrypted_output}" "secure_channel=established"
require_contains "${encrypted_output}" "result[0].found=true"
require_contains "${encrypted_output}" "result[0].utxo_count=1"
require_contains "${encrypted_output}" "result[0].total_balance=50000"
require_contains "${encrypted_output}" "result[1].found=false"
require_contains "${encrypted_output}" "result[2].is_whale=true"

require_contains "$(cat "${SERVER_LOG}")" "[oram-lookup] db=0 3 scripthash(es)"

printf 'oram_local_smoke=ok\n'
