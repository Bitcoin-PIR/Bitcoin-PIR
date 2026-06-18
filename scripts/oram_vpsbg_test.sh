#!/usr/bin/env bash
set -euo pipefail

# Non-TEE ORAM test runner for VPSBG/Slice-2 style environments.
#
# Modes:
#   tiny-smoke   Build a tiny fixture and run the existing end-to-end smoke.
#   preflight    Print host/service/DB/ORAM-dir readiness checks.
#   real-build   Build authenticated Circuit ORAM images from a real DB dir.
#   real-verify  Verify random cuckoo bins through existing ORAM images.
#   real-bench   Benchmark existing ORAM images, optionally against DB bytes.
#   real-all     preflight + real-build + real-verify.
#   server-smoke Start a local ORAM-enabled unified_server against one DB dir
#                or CONFIG_PATH plus per-db ORAM specs.
#
# Build/verify/bench modes deliberately avoid --config/databases.toml so they
# do not mmap every checkpoint/delta. Point DB_DIR at one checkpoint or delta.
# server-smoke may use CONFIG_PATH for production-shaped multi-db plumbing.

MODE="${1:-tiny-smoke}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -d "${HOME}/bitcoin-pir/oram" ]]; then
  DEFAULT_ORAM_REPO="${HOME}/bitcoin-pir/oram"
elif [[ -d /home/pir/bitcoin-pir/oram ]]; then
  DEFAULT_ORAM_REPO="/home/pir/bitcoin-pir/oram"
elif [[ -d /home/pir/oram ]]; then
  DEFAULT_ORAM_REPO="/home/pir/oram"
else
  DEFAULT_ORAM_REPO="${HOME}/bitcoin-pir/oram"
fi

ORAM_REPO="${ORAM_REPO:-${DEFAULT_ORAM_REPO}}"
if ! command -v cargo >/dev/null 2>&1 && [[ -x /home/pir/.cargo/bin/cargo ]]; then
  PATH="/home/pir/.cargo/bin:${PATH}"
fi
DB_DIR="${DB_DIR:-/home/pir/data/checkpoints/940611}"
CONFIG_PATH="${CONFIG_PATH:-}"
ORAM_DIR="${ORAM_DIR:-/home/pir/data/oram-test/$(basename "${DB_DIR}")-pack16-z2-div2-stash128-auth}"
ORAM_DB_SPECS="${ORAM_DB_SPECS:-}"
ORAM_DB0_DIR="${ORAM_DB0_DIR:-}"
ORAM_DB1_DIR="${ORAM_DB1_DIR:-}"
LOG_DIR="${LOG_DIR:-${ORAM_DIR}/logs}"
PORT="${PORT:-}"

PACK="${PACK:-16}"
LEAF_DIVISOR="${LEAF_DIVISOR:-2}"
BUCKET_SIZE="${BUCKET_SIZE:-2}"
STASH_CAPACITY="${STASH_CAPACITY:-128}"
DRAIN_PER_ACCESS="${DRAIN_PER_ACCESS:-2}"
CACHE_LEVELS="${CACHE_LEVELS:-0}"
LEVEL="${LEVEL:-all}"

AUTH_STORE="${AUTH_STORE:-1}"
AUTH_TRUSTED_LEVELS="${AUTH_TRUSTED_LEVELS:-1}"
AUTH_HASH_PAGE_SIZE="${AUTH_HASH_PAGE_SIZE:-4096}"
ENCRYPTED="${ENCRYPTED:-0}"
PAGE_KEY_HEX="${PAGE_KEY_HEX:-4242424242424242424242424242424242424242424242424242424242424242}"
STATE_KEY_HEX="${STATE_KEY_HEX:-7373737373737373737373737373737373737373737373737373737373737373}"

VERIFY_BINS="${VERIFY_BINS:-1000}"
BENCH_OPS="${BENCH_OPS:-1000}"
CARGO_JOBS="${CARGO_JOBS:-1}"
REAL_MIN_FREE_GIB="${REAL_MIN_FREE_GIB:-80}"
SERVER_MIN_MEM_GIB="${SERVER_MIN_MEM_GIB:-16}"
SERVER_STARTUP_WAIT_SECS="${SERVER_STARTUP_WAIT_SECS:-180}"
REAL_MIN_MEM_GIB="${REAL_MIN_MEM_GIB:-12}"
ALLOW_PIR_SERVICE_ACTIVE="${ALLOW_PIR_SERVICE_ACTIVE:-0}"
ALLOW_LOW_MEMORY="${ALLOW_LOW_MEMORY:-0}"
ALLOW_LOW_DISK="${ALLOW_LOW_DISK:-0}"
PATCH_LOCAL_ORAM="${PATCH_LOCAL_ORAM:-0}"
NO_SAVE="${NO_SAVE:-0}"
SCRIPT_HASHES="${SCRIPT_HASHES:-4242424242424242424242424242424242424242}"
SMOKE_DB_IDS="${SMOKE_DB_IDS:-0}"

SERVER_SMOKE_PID=""
LOCAL_ORAM_PATCH_CONFIG_BACKUP=""
LOCAL_ORAM_PATCH_LOCK_BACKUP=""

usage() {
  sed -n '1,34p' "$0" >&2
  cat >&2 <<EOF

Important env:
  DB_DIR=/home/pir/data/checkpoints/940611
  CONFIG_PATH=/home/pir/data/databases.toml
  ORAM_DIR=/home/pir/data/oram-test/940611-pack16-z2-div2-stash128-auth
  ORAM_DB_SPECS='0=/home/pir/data/oram/full 1=/home/pir/data/oram/delta'
  SMOKE_DB_IDS='0 1'
  ORAM_REPO=/home/pir/bitcoin-pir/oram
  PACK=16 LEAF_DIVISOR=2 BUCKET_SIZE=2 STASH_CAPACITY=128
  PATCH_LOCAL_ORAM=1          temporarily patch runtime to ORAM_REPO for server-smoke
  AUTH_STORE=1 AUTH_TRUSTED_LEVELS=1
  ENCRYPTED=0 PAGE_KEY_HEX=<32-byte hex> STATE_KEY_HEX=<32-byte hex>
  VERIFY_BINS=1000 BENCH_OPS=1000 CARGO_JOBS=1

Safety overrides:
  ALLOW_PIR_SERVICE_ACTIVE=1  permit real modes while pir-vpsbg is active
  ALLOW_LOW_MEMORY=1          warn instead of failing low-memory preflight
  ALLOW_LOW_DISK=1            warn instead of failing low-disk preflight
EOF
}

log() {
  printf '[oram-vpsbg-test] %s\n' "$*"
}

die() {
  printf '[oram-vpsbg-test] ERROR: %s\n' "$*" >&2
  exit 1
}

server_smoke_cleanup() {
  if [[ -n "${SERVER_SMOKE_PID}" ]]; then
    kill "${SERVER_SMOKE_PID}" 2>/dev/null || true
    wait "${SERVER_SMOKE_PID}" 2>/dev/null || true
    SERVER_SMOKE_PID=""
  fi
  if [[ -n "${LOCAL_ORAM_PATCH_CONFIG_BACKUP}" ]]; then
    cp "${LOCAL_ORAM_PATCH_CONFIG_BACKUP}" "${REPO_ROOT}/.cargo/config.toml" 2>/dev/null || true
    rm -f "${LOCAL_ORAM_PATCH_CONFIG_BACKUP}" 2>/dev/null || true
    LOCAL_ORAM_PATCH_CONFIG_BACKUP=""
  fi
  if [[ -n "${LOCAL_ORAM_PATCH_LOCK_BACKUP}" ]]; then
    cp "${LOCAL_ORAM_PATCH_LOCK_BACKUP}" "${REPO_ROOT}/Cargo.lock" 2>/dev/null || true
    rm -f "${LOCAL_ORAM_PATCH_LOCK_BACKUP}" 2>/dev/null || true
    LOCAL_ORAM_PATCH_LOCK_BACKUP=""
  fi
}

require_file() {
  [[ -f "$1" ]] || die "missing file: $1"
}

require_dir() {
  [[ -d "$1" ]] || die "missing directory: $1"
}

available_mem_gib() {
  if [[ -r /proc/meminfo ]]; then
    awk '/MemAvailable:/ { printf "%.0f\n", $2 / 1024 / 1024 }' /proc/meminfo
  else
    printf '0\n'
  fi
}

free_disk_gib_for() {
  local path="$1"
  local probe="$path"
  while [[ ! -e "$probe" && "$probe" != "/" ]]; do
    probe="$(dirname "$probe")"
  done
  df -Pk "$probe" | awk 'NR==2 { printf "%.0f\n", $4 / 1024 / 1024 }'
}

check_threshold() {
  local label="$1"
  local actual="$2"
  local required="$3"
  local allow="$4"
  if (( actual < required )); then
    if [[ "$allow" == "1" ]]; then
      log "WARNING: ${label} ${actual} GiB < requested ${required} GiB; continuing by override"
    else
      die "${label} ${actual} GiB < requested ${required} GiB"
    fi
  fi
}

pir_service_active() {
  command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet pir-vpsbg
}

check_pir_service_inactive() {
  if pir_service_active; then
    if [[ "$ALLOW_PIR_SERVICE_ACTIVE" == "1" ]]; then
      log "WARNING: pir-vpsbg is active; continuing by override"
    else
      die "pir-vpsbg is active. Stop it first, or set ALLOW_PIR_SERVICE_ACTIVE=1"
    fi
  fi
}

print_host_state() {
  log "mode=${MODE}"
  log "repo_root=${REPO_ROOT}"
  log "oram_repo=${ORAM_REPO}"
  log "db_dir=${DB_DIR}"
  log "config_path=${CONFIG_PATH:-<unset>}"
  log "oram_dir=${ORAM_DIR}"
  log "oram_db_specs=${ORAM_DB_SPECS:-<unset>}"
  log "oram_db0_dir=${ORAM_DB0_DIR:-<unset>}"
  log "oram_db1_dir=${ORAM_DB1_DIR:-<unset>}"
  log "smoke_db_ids=${SMOKE_DB_IDS}"
  log "pack=${PACK} leaf_divisor=${LEAF_DIVISOR} bucket_size=${BUCKET_SIZE} stash_capacity=${STASH_CAPACITY}"
  log "auth_store=${AUTH_STORE} encrypted=${ENCRYPTED} cache_levels=${CACHE_LEVELS} drain_per_access=${DRAIN_PER_ACCESS}"
  log "cargo_jobs=${CARGO_JOBS}"
  log "mem_available_gib=$(available_mem_gib)"
  log "disk_free_gib_for_oram_dir=$(free_disk_gib_for "${ORAM_DIR}")"
  if pir_service_active; then
    log "pir_vpsbg_active=1"
  else
    log "pir_vpsbg_active=0"
  fi
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -af 'unified_server' || true
  fi
}

require_oram_repo() {
  require_file "${ORAM_REPO}/Cargo.toml"
}

require_db_dir() {
  require_dir "${DB_DIR}"
  require_file "${DB_DIR}/batch_pir_cuckoo.bin"
  require_file "${DB_DIR}/chunk_pir_cuckoo.bin"
}

require_runtime_source() {
  if [[ -n "${CONFIG_PATH}" ]]; then
    require_file "${CONFIG_PATH}"
  else
    require_db_dir
  fi
}

cargo_oramctl() {
  (
    cd "${ORAM_REPO}"
    cargo run -j "${CARGO_JOBS}" --release --bin oramctl -- "$@"
  )
}

warn_if_no_save() {
  if [[ "${NO_SAVE}" == "1" ]]; then
    log "WARNING: --no-save leaves mutated ORAM page images without matching state; use only with disposable ORAM_DIR"
  fi
}

preflight_real() {
  require_oram_repo
  require_db_dir
  check_pir_service_inactive
  mkdir -p "${ORAM_DIR}" "${LOG_DIR}"
  local mem_gib
  mem_gib="$(available_mem_gib)"
  if (( mem_gib > 0 )); then
    check_threshold "available memory" "${mem_gib}" "${REAL_MIN_MEM_GIB}" "${ALLOW_LOW_MEMORY}"
  fi
  check_threshold "free disk near ORAM_DIR" "$(free_disk_gib_for "${ORAM_DIR}")" "${REAL_MIN_FREE_GIB}" "${ALLOW_LOW_DISK}"
}

preflight_server() {
  require_oram_repo
  require_runtime_source
  check_pir_service_inactive
  mkdir -p "${LOG_DIR}"
  local mem_gib
  mem_gib="$(available_mem_gib)"
  if (( mem_gib > 0 )); then
    check_threshold "available memory" "${mem_gib}" "${SERVER_MIN_MEM_GIB}" "${ALLOW_LOW_MEMORY}"
  fi
  log "server_startup_wait_secs=${SERVER_STARTUP_WAIT_SECS}"
}

enable_local_oram_patch() {
  [[ "${PATCH_LOCAL_ORAM}" == "1" ]] || return 0
  require_dir "${ORAM_REPO}"
  require_file "${REPO_ROOT}/.cargo/config.toml"
  require_file "${REPO_ROOT}/Cargo.lock"
  if grep -Fq '[patch."https://github.com/Bitcoin-PIR/oram.git"]' "${REPO_ROOT}/.cargo/config.toml"; then
    log "local ORAM Cargo patch already present"
    return 0
  fi
  LOCAL_ORAM_PATCH_CONFIG_BACKUP="$(mktemp)"
  LOCAL_ORAM_PATCH_LOCK_BACKUP="$(mktemp)"
  cp "${REPO_ROOT}/.cargo/config.toml" "${LOCAL_ORAM_PATCH_CONFIG_BACKUP}"
  cp "${REPO_ROOT}/Cargo.lock" "${LOCAL_ORAM_PATCH_LOCK_BACKUP}"
  cat >> "${REPO_ROOT}/.cargo/config.toml" <<EOF

# Temporary ORAM smoke override; restored by scripts/oram_vpsbg_test.sh.
[patch."https://github.com/Bitcoin-PIR/oram.git"]
bitcoinpir-oram = { path = "${ORAM_REPO}" }
EOF
  log "temporarily patched bitcoinpir-oram to ${ORAM_REPO}"
}

tiny_smoke() {
  require_oram_repo
  log "running tiny smoke through scripts/oram_local_smoke.sh"
  (
    cd "${REPO_ROOT}"
    if [[ -n "${PORT}" ]]; then
      ORAM_REPO="${ORAM_REPO}" PORT="${PORT}" scripts/oram_local_smoke.sh
    else
      ORAM_REPO="${ORAM_REPO}" scripts/oram_local_smoke.sh
    fi
  )
}

real_build() {
  preflight_real
  log "running size-cuckoo"
  cargo_oramctl size-cuckoo \
    --db-dir "${DB_DIR}" \
    --packs "${PACK}" \
    --leaf-divisors "${LEAF_DIVISOR}" \
    --bucket-size "${BUCKET_SIZE}" \
    --stash-capacity "${STASH_CAPACITY}" \
    --cache-levels "${CACHE_LEVELS}" | tee "${LOG_DIR}/size-cuckoo.log"

  local build_cmd=(
    build-circuit
    --db-dir "${DB_DIR}" \
    --out-dir "${ORAM_DIR}" \
    --level "${LEVEL}" \
    --pack "${PACK}" \
    --leaf-divisor "${LEAF_DIVISOR}" \
    --bucket-size "${BUCKET_SIZE}" \
    --stash-capacity "${STASH_CAPACITY}" \
    --cache-levels "${CACHE_LEVELS}"
  )
  if [[ "${AUTH_STORE}" == "1" ]]; then
    build_cmd+=(--auth-store --auth-trusted-levels "${AUTH_TRUSTED_LEVELS}" --auth-hash-page-size "${AUTH_HASH_PAGE_SIZE}")
  fi
  if [[ "${ENCRYPTED}" == "1" ]]; then
    build_cmd+=(--encrypted --key-hex "${PAGE_KEY_HEX}" --state-key-hex "${STATE_KEY_HEX}")
  fi

  log "building Circuit ORAM images"
  cargo_oramctl "${build_cmd[@]}" | tee "${LOG_DIR}/build-circuit.log"

  du -sh "${ORAM_DIR}" | tee "${LOG_DIR}/du-after-build.log"
}

real_verify() {
  preflight_real
  warn_if_no_save
  local verify_cmd=(
    verify-circuit-bins
    --db-dir "${DB_DIR}"
    --oram-dir "${ORAM_DIR}"
    --level "${LEVEL}"
    --pack "${PACK}"
    --bins "${VERIFY_BINS}"
    --drain-per-access "${DRAIN_PER_ACCESS}"
    --cache-levels "${CACHE_LEVELS}"
  )
  if [[ "${AUTH_STORE}" == "1" ]]; then
    verify_cmd+=(--auth-store)
  fi
  if [[ "${ENCRYPTED}" == "1" ]]; then
    verify_cmd+=(--encrypted --key-hex "${PAGE_KEY_HEX}" --state-key-hex "${STATE_KEY_HEX}")
  fi
  if [[ "${NO_SAVE}" == "1" ]]; then
    verify_cmd+=(--no-save)
  fi

  log "verifying ${VERIFY_BINS} random cuckoo bins per selected level"
  cargo_oramctl "${verify_cmd[@]}" | tee "${LOG_DIR}/verify-circuit-bins.log"
}

real_bench() {
  preflight_real
  warn_if_no_save
  local bench_cmd=(
    bench-circuit
    --db-dir "${DB_DIR}"
    --oram-dir "${ORAM_DIR}"
    --level "${LEVEL}"
    --pack "${PACK}"
    --ops "${BENCH_OPS}"
    --drain-per-access "${DRAIN_PER_ACCESS}"
    --cache-levels "${CACHE_LEVELS}"
  )
  if [[ "${AUTH_STORE}" == "1" ]]; then
    bench_cmd+=(--auth-store)
  fi
  if [[ "${ENCRYPTED}" == "1" ]]; then
    bench_cmd+=(--encrypted --key-hex "${PAGE_KEY_HEX}" --state-key-hex "${STATE_KEY_HEX}")
  fi
  if [[ "${NO_SAVE}" == "1" ]]; then
    bench_cmd+=(--no-save)
  fi

  log "benchmarking ${BENCH_OPS} random ORAM reads per selected level"
  cargo_oramctl "${bench_cmd[@]}" | tee "${LOG_DIR}/bench-circuit.log"
}

server_smoke() {
  preflight_server
  enable_local_oram_patch
  trap server_smoke_cleanup EXIT
  if [[ -z "${PORT}" ]]; then
    PORT=18091
  fi

  local server_log="${LOG_DIR}/server-smoke.log"
  mkdir -p "${LOG_DIR}"
  log "building ORAM-enabled unified_server"
  (
    cd "${REPO_ROOT}"
    cargo build -j "${CARGO_JOBS}" --release -p runtime --features cuckoo-oram --bin unified_server
  )

  local server_args=(
    --port "${PORT}"
    --role secondary
    --serve-queries
    --disable-onion
    --cuckoo-oram-pack "${PACK}"
    --cuckoo-oram-drain-per-access "${DRAIN_PER_ACCESS}"
    --cuckoo-oram-cache-levels "${CACHE_LEVELS}"
  )
  if [[ -n "${CONFIG_PATH}" ]]; then
    server_args+=(--config "${CONFIG_PATH}")
  else
    server_args+=(--data-dir "${DB_DIR}")
  fi

  local oram_specs=()
  if [[ -n "${ORAM_DB_SPECS}" ]]; then
    # shellcheck disable=SC2206
    oram_specs=(${ORAM_DB_SPECS})
  fi
  if [[ -n "${ORAM_DB0_DIR}" ]]; then
    oram_specs+=("0=${ORAM_DB0_DIR}")
  fi
  if [[ -n "${ORAM_DB1_DIR}" ]]; then
    oram_specs+=("1=${ORAM_DB1_DIR}")
  fi
  if (( ${#oram_specs[@]} == 0 )); then
    oram_specs+=("0=${ORAM_DIR}")
  fi
  for spec in "${oram_specs[@]}"; do
    server_args+=(--cuckoo-oram-db "${spec}")
  done

  if [[ "${AUTH_STORE}" == "1" ]]; then
    server_args+=(--cuckoo-oram-auth-store)
  fi
  if [[ "${ENCRYPTED}" == "1" ]]; then
    server_args+=(--cuckoo-oram-encrypted --cuckoo-oram-key-hex "${PAGE_KEY_HEX}" --cuckoo-oram-state-key-hex "${STATE_KEY_HEX}")
  fi
  if [[ "${NO_SAVE}" == "1" ]]; then
    server_args+=(--cuckoo-oram-no-save)
  fi

  log "starting local unified_server on ws://127.0.0.1:${PORT}"
  (
    cd "${REPO_ROOT}"
    ./target/release/unified_server "${server_args[@]}"
  ) >"${server_log}" 2>&1 &
  SERVER_SMOKE_PID=$!

  local startup_checks=$((SERVER_STARTUP_WAIT_SECS * 10))
  for _ in $(seq 1 "${startup_checks}"); do
    if grep -Fq "Listening on" "${server_log}"; then
      break
    fi
    if ! kill -0 "${SERVER_SMOKE_PID}" 2>/dev/null; then
      cat "${server_log}" >&2 || true
      die "unified_server exited before listening"
    fi
    sleep 0.1
  done
  grep -Fq "Listening on" "${server_log}" || {
    cat "${server_log}" >&2 || true
    die "unified_server did not start listening"
  }

  local server_url="ws://127.0.0.1:${PORT}"
  local first_hash
  first_hash="$(awk '{print $1}' <<< "${SCRIPT_HASHES}")"
  local smoke_db_ids=()
  # shellcheck disable=SC2206
  smoke_db_ids=(${SMOKE_DB_IDS})
  if (( ${#smoke_db_ids[@]} == 0 )); then
    smoke_db_ids=(0)
  fi
  local first_db_id="${smoke_db_ids[0]}"
  log "checking cleartext ORAM rejection"
  (
    cd "${REPO_ROOT}"
    cargo run -q -p pir-sdk-client --example oram_local_smoke -- \
      --server "${server_url}" \
      --db-id "${first_db_id}" \
      --expect-cleartext-reject \
      "${first_hash}"
  ) | tee "${LOG_DIR}/server-smoke-cleartext-db${first_db_id}.log"

  for db_id in "${smoke_db_ids[@]}"; do
    log "checking encrypted-channel ORAM query for db_id=${db_id}"
    (
      cd "${REPO_ROOT}"
      cargo run -q -p pir-sdk-client --example oram_local_smoke -- \
        --server "${server_url}" \
        --db-id "${db_id}" \
        ${SCRIPT_HASHES}
    ) | tee "${LOG_DIR}/server-smoke-encrypted-db${db_id}.log"
  done

  log "server_smoke=ok"
  server_smoke_cleanup
  trap - EXIT
}

case "${MODE}" in
  tiny-smoke)
    tiny_smoke
    ;;
  preflight)
    print_host_state
    preflight_real
    ;;
  real-build)
    real_build
    ;;
  real-verify)
    real_verify
    ;;
  real-bench)
    real_bench
    ;;
  real-all)
    print_host_state
    real_build
    real_verify
    ;;
  server-smoke)
    server_smoke
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    die "unknown mode: ${MODE}"
    ;;
esac
