#!/usr/bin/env bash
set -euo pipefail

# Non-TEE ORAM test runner for VPSBG/Slice-2 style environments.
#
# Modes:
#   tiny-smoke   Build a tiny fixture and run the existing end-to-end smoke.
#   preflight    Print host/service/DB/ORAM-dir readiness checks.
#   real-build   Build authenticated ORAM images from a real DB dir.
#   real-extract-direct-chunks
#                Reconstruct direct utxo_chunks_nodust.bin from chunk_pir_cuckoo.bin.
#   real-verify  Verify existing ORAM images. Direct layout does structural checks;
#                cuckoo layout verifies random cuckoo bins.
#   real-bench   Benchmark existing ORAM images, optionally against DB bytes.
#   pos-map-bench
#                Benchmark branchless trusted position-map scans.
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
ORAM_LAYOUT="${ORAM_LAYOUT:-direct}"
DEFAULT_DIRECT_SOURCE_DIR="${DB_DIR}"
if [[ ! -f "${DB_DIR}/utxo_chunks_index_nodust.bin" && ! -f "${DB_DIR}/utxo_chunks_nodust.bin" ]]; then
  case "${DB_DIR}" in
    */checkpoints/*)
      DATA_ROOT="${DB_DIR%/checkpoints/*}"
      DEFAULT_DIRECT_SOURCE_DIR="${DATA_ROOT}/oram-inputs/checkpoints/$(basename "${DB_DIR}")"
      ;;
    */deltas/*)
      DATA_ROOT="${DB_DIR%/deltas/*}"
      DEFAULT_DIRECT_SOURCE_DIR="${DATA_ROOT}/oram-inputs/deltas/$(basename "${DB_DIR}")"
      ;;
  esac
fi
DIRECT_SOURCE_DIR="${DIRECT_SOURCE_DIR:-${DEFAULT_DIRECT_SOURCE_DIR}}"
DIRECT_INDEX_FILE="${DIRECT_INDEX_FILE:-${DIRECT_SOURCE_DIR}/utxo_chunks_index_nodust.bin}"
DIRECT_CHUNKS_FILE="${DIRECT_CHUNKS_FILE:-${DIRECT_SOURCE_DIR}/utxo_chunks_nodust.bin}"
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
DIRECT_ACCESS_BUDGET="${DIRECT_ACCESS_BUDGET:-75}"
PADDED_SLOTS="${PADDED_SLOTS:-}"
CACHE_LEVELS="${CACHE_LEVELS:-0}"
LEVEL="${LEVEL:-all}"
DIRECT_INDEX_SLOTS_PER_BIN="${DIRECT_INDEX_SLOTS_PER_BIN:-4}"
DIRECT_INDEX_HASH_FNS="${DIRECT_INDEX_HASH_FNS:-2}"
DIRECT_INDEX_LOAD_FACTOR="${DIRECT_INDEX_LOAD_FACTOR:-0.95}"
DIRECT_INDEX_SEED="${DIRECT_INDEX_SEED:-8030603977422561841}"
DIRECT_INPUTS_SHA256_FILE="${DIRECT_INPUTS_SHA256_FILE:-${DIRECT_SOURCE_DIR}/direct-inputs.sha256}"
DB_BUILD_EVIDENCE="${DB_BUILD_EVIDENCE:-}"
ROOT_BUNDLE_PAYLOAD="${ROOT_BUNDLE_PAYLOAD:-}"
EXPECTED_MUHASH="${EXPECTED_MUHASH:-}"
EXPECTED_FROM_MUHASH="${EXPECTED_FROM_MUHASH:-}"
EXPECTED_INDEX_SHA256="${EXPECTED_INDEX_SHA256:-}"
EXPECTED_CHUNKS_SHA256="${EXPECTED_CHUNKS_SHA256:-}"
STRICT_SOURCE_BINDING="${STRICT_SOURCE_BINDING:-0}"

AUTH_STORE="${AUTH_STORE:-1}"
AUTH_TRUSTED_LEVELS="${AUTH_TRUSTED_LEVELS:-1}"
AUTH_HASH_PAGE_SIZE="${AUTH_HASH_PAGE_SIZE:-4096}"
ENCRYPTED="${ENCRYPTED:-0}"
PAGE_KEY_HEX="${PAGE_KEY_HEX:-4242424242424242424242424242424242424242424242424242424242424242}"
STATE_KEY_HEX="${STATE_KEY_HEX:-7373737373737373737373737373737373737373737373737373737373737373}"

VERIFY_BINS="${VERIFY_BINS:-1000}"
BENCH_OPS="${BENCH_OPS:-1000}"
POS_MAP_SIZES="${POS_MAP_SIZES:-3370000,5070000}"
POS_MAP_WARMUP_OPS="${POS_MAP_WARMUP_OPS:-50}"
CARGO_JOBS="${CARGO_JOBS:-1}"
CARGO_TOOLCHAIN="${CARGO_TOOLCHAIN:-stable}"
ORAMCTL_BIN="${ORAMCTL_BIN:-}"
ORAMCTL_BUILD="${ORAMCTL_BUILD:-1}"
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
  ORAM_LAYOUT=direct          direct (default, non-PBC) or cuckoo (legacy PBC table wrapper)
  DIRECT_SOURCE_DIR=/path/to/oram-inputs/checkpoints/940611
  DIRECT_INDEX_FILE=/path/to/utxo_chunks_index_nodust.bin
  DIRECT_CHUNKS_FILE=/path/to/utxo_chunks_nodust.bin
  DB_BUILD_EVIDENCE=/path/to/build-evidence.bin ROOT_BUNDLE_PAYLOAD=/path/to/root-bundle-payload.bin
  STRICT_SOURCE_BINDING=1 EXPECTED_MUHASH=<Core-display-muhash>
  PACK=16 LEAF_DIVISOR=2 BUCKET_SIZE=2 STASH_CAPACITY=128
  DIRECT_ACCESS_BUDGET=75
  PATCH_LOCAL_ORAM=1          temporarily patch runtime to ORAM_REPO for server-smoke
  AUTH_STORE=1 AUTH_TRUSTED_LEVELS=1
  ENCRYPTED=0 PAGE_KEY_HEX=<32-byte hex> STATE_KEY_HEX=<32-byte hex>
  VERIFY_BINS=1000 BENCH_OPS=1000 CARGO_JOBS=1
  POS_MAP_SIZES=3370000,5070000 POS_MAP_WARMUP_OPS=50
  CARGO_TOOLCHAIN=stable          use CARGO_TOOLCHAIN=none for a non-rustup cargo
  ORAMCTL_BIN=/path/to/oramctl   optional prebuilt oramctl binary
  ORAMCTL_BUILD=1                build oramctl before running it

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
  log "oram_layout=${ORAM_LAYOUT}"
  log "db_dir=${DB_DIR}"
  log "direct_source_dir=${DIRECT_SOURCE_DIR}"
  log "direct_index_file=${DIRECT_INDEX_FILE}"
  log "direct_chunks_file=${DIRECT_CHUNKS_FILE}"
  log "direct_inputs_sha256_file=${DIRECT_INPUTS_SHA256_FILE}"
  log "db_build_evidence=${DB_BUILD_EVIDENCE:-<unset>}"
  log "root_bundle_payload=${ROOT_BUNDLE_PAYLOAD:-<unset>}"
  log "strict_source_binding=${STRICT_SOURCE_BINDING}"
  log "config_path=${CONFIG_PATH:-<unset>}"
  log "oram_dir=${ORAM_DIR}"
  log "oram_db_specs=${ORAM_DB_SPECS:-<unset>}"
  log "oram_db0_dir=${ORAM_DB0_DIR:-<unset>}"
  log "oram_db1_dir=${ORAM_DB1_DIR:-<unset>}"
  log "smoke_db_ids=${SMOKE_DB_IDS}"
  log "pack=${PACK} leaf_divisor=${LEAF_DIVISOR} bucket_size=${BUCKET_SIZE} stash_capacity=${STASH_CAPACITY}"
  log "direct_access_budget=${DIRECT_ACCESS_BUDGET} direct_index_hash_fns=${DIRECT_INDEX_HASH_FNS} direct_index_load_factor=${DIRECT_INDEX_LOAD_FACTOR}"
  log "auth_store=${AUTH_STORE} encrypted=${ENCRYPTED} cache_levels=${CACHE_LEVELS} drain_per_access=${DRAIN_PER_ACCESS}"
  log "bench_ops=${BENCH_OPS} pos_map_sizes=${POS_MAP_SIZES} pos_map_warmup_ops=${POS_MAP_WARMUP_OPS}"
  log "cargo_jobs=${CARGO_JOBS} cargo_toolchain=${CARGO_TOOLCHAIN} oramctl_build=${ORAMCTL_BUILD} oramctl_bin=${ORAMCTL_BIN:-<auto>}"
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

require_cuckoo_db_dir() {
  require_dir "${DB_DIR}"
  require_file "${DB_DIR}/batch_pir_cuckoo.bin"
  require_file "${DB_DIR}/chunk_pir_cuckoo.bin"
}

require_direct_sources() {
  require_file "${DIRECT_INDEX_FILE}"
  require_file "${DIRECT_CHUNKS_FILE}"
}

require_direct_oram_image() {
  require_dir "${ORAM_DIR}"
  for prefix in direct-index direct-chunk; do
    require_file "${ORAM_DIR}/${prefix}.meta.oram"
    require_file "${ORAM_DIR}/${prefix}.payload.oram"
    require_file "${ORAM_DIR}/${prefix}.state"
    require_file "${ORAM_DIR}/${prefix}.metadata"
    if [[ "${AUTH_STORE}" == "1" ]]; then
      require_file "${ORAM_DIR}/${prefix}.meta.hash.oram"
      require_file "${ORAM_DIR}/${prefix}.payload.hash.oram"
      require_file "${ORAM_DIR}/${prefix}.auth.state"
    fi
  done
}

require_cuckoo_oram_image() {
  require_dir "${ORAM_DIR}"
  for prefix in index chunk; do
    require_file "${ORAM_DIR}/${prefix}.meta.oram"
    require_file "${ORAM_DIR}/${prefix}.payload.oram"
    require_file "${ORAM_DIR}/${prefix}.state"
    if [[ "${AUTH_STORE}" == "1" ]]; then
      require_file "${ORAM_DIR}/${prefix}.meta.hash.oram"
      require_file "${ORAM_DIR}/${prefix}.payload.hash.oram"
      require_file "${ORAM_DIR}/${prefix}.auth.state"
    fi
  done
}

require_runtime_source() {
  if [[ -n "${CONFIG_PATH}" ]]; then
    require_file "${CONFIG_PATH}"
  else
    require_cuckoo_db_dir
  fi
}

cargo_oramctl() {
  (
    cd "${ORAM_REPO}"
    local target_root="${CARGO_TARGET_DIR:-${ORAM_REPO}/target}"
    local oramctl_bin="${ORAMCTL_BIN:-${target_root}/release/oramctl}"
    local cargo_toolchain_arg=()
    if [[ -n "${CARGO_TOOLCHAIN}" && "${CARGO_TOOLCHAIN}" != "none" ]]; then
      cargo_toolchain_arg=("+${CARGO_TOOLCHAIN}")
    fi
    if [[ "${ORAMCTL_BUILD}" == "1" || ! -x "${oramctl_bin}" ]]; then
      cargo "${cargo_toolchain_arg[@]}" build -j "${CARGO_JOBS}" --release --bin oramctl
    fi
    "${oramctl_bin}" "$@"
  )
}

pos_map_bench() {
  require_oram_repo
  check_pir_service_inactive
  mkdir -p "${LOG_DIR}"
  log "benchmarking position-map scan sizes=${POS_MAP_SIZES} ops=${BENCH_OPS} warmup_ops=${POS_MAP_WARMUP_OPS}"
  cargo_oramctl bench-pos-map \
    --sizes "${POS_MAP_SIZES}" \
    --ops "${BENCH_OPS}" \
    --warmup-ops "${POS_MAP_WARMUP_OPS}" | tee "${LOG_DIR}/bench-pos-map.log"
}

warn_if_no_save() {
  if [[ "${NO_SAVE}" == "1" ]]; then
    log "WARNING: --no-save leaves mutated ORAM page images without matching state; use only with disposable ORAM_DIR"
  fi
}

preflight_real() {
  require_oram_repo
  case "${ORAM_LAYOUT}" in
    direct)
      require_direct_sources
      ;;
    cuckoo)
      require_cuckoo_db_dir
      ;;
    *)
      die "ORAM_LAYOUT must be direct or cuckoo, got ${ORAM_LAYOUT}"
      ;;
  esac
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
  local build_cmd=()
  if [[ "${ORAM_LAYOUT}" == "direct" ]]; then
    log "running size-direct"
    cargo_oramctl size-direct \
      --index-file "${DIRECT_INDEX_FILE}" \
      --chunks-file "${DIRECT_CHUNKS_FILE}" \
      --packs "${PACK}" \
      --leaf-divisors "${LEAF_DIVISOR}" \
      --bucket-size "${BUCKET_SIZE}" \
      --stash-capacity "${STASH_CAPACITY}" \
      --cache-levels "${CACHE_LEVELS}" \
      --index-slots-per-bin "${DIRECT_INDEX_SLOTS_PER_BIN}" \
      --index-hash-fns "${DIRECT_INDEX_HASH_FNS}" \
      --index-load-factor "${DIRECT_INDEX_LOAD_FACTOR}" \
      --index-seed "${DIRECT_INDEX_SEED}" | tee "${LOG_DIR}/size-direct.log"

    build_cmd=(
      build-direct
      --index-file "${DIRECT_INDEX_FILE}"
      --chunks-file "${DIRECT_CHUNKS_FILE}"
      --out-dir "${ORAM_DIR}"
      --level "${LEVEL}"
      --pack "${PACK}"
      --leaf-divisor "${LEAF_DIVISOR}"
      --bucket-size "${BUCKET_SIZE}"
      --stash-capacity "${STASH_CAPACITY}"
      --cache-levels "${CACHE_LEVELS}"
      --index-slots-per-bin "${DIRECT_INDEX_SLOTS_PER_BIN}"
      --index-hash-fns "${DIRECT_INDEX_HASH_FNS}"
      --index-load-factor "${DIRECT_INDEX_LOAD_FACTOR}"
      --index-seed "${DIRECT_INDEX_SEED}"
    )
    if [[ -f "${DIRECT_INPUTS_SHA256_FILE}" ]]; then
      EXPECTED_INDEX_SHA256="${EXPECTED_INDEX_SHA256:-$(awk '$2 == "utxo_chunks_index_nodust.bin" || $2 == "./utxo_chunks_index_nodust.bin" { print $1; exit }' "${DIRECT_INPUTS_SHA256_FILE}")}"
      EXPECTED_CHUNKS_SHA256="${EXPECTED_CHUNKS_SHA256:-$(awk '$2 == "utxo_chunks_nodust.bin" || $2 == "./utxo_chunks_nodust.bin" { print $1; exit }' "${DIRECT_INPUTS_SHA256_FILE}")}"
    fi
    [[ -n "${DB_BUILD_EVIDENCE}" ]] && build_cmd+=(--db-build-evidence "${DB_BUILD_EVIDENCE}")
    [[ -n "${ROOT_BUNDLE_PAYLOAD}" ]] && build_cmd+=(--root-bundle-payload "${ROOT_BUNDLE_PAYLOAD}")
    [[ -n "${EXPECTED_MUHASH}" ]] && build_cmd+=(--expected-muhash "${EXPECTED_MUHASH}")
    [[ -n "${EXPECTED_FROM_MUHASH}" ]] && build_cmd+=(--expected-from-muhash "${EXPECTED_FROM_MUHASH}")
    [[ -n "${EXPECTED_INDEX_SHA256}" ]] && build_cmd+=(--expected-index-sha256 "${EXPECTED_INDEX_SHA256}")
    [[ -n "${EXPECTED_CHUNKS_SHA256}" ]] && build_cmd+=(--expected-chunks-sha256 "${EXPECTED_CHUNKS_SHA256}")
    [[ "${STRICT_SOURCE_BINDING}" == "1" ]] && build_cmd+=(--strict-source-binding)
  else
    log "running size-cuckoo"
    cargo_oramctl size-cuckoo \
      --db-dir "${DB_DIR}" \
      --packs "${PACK}" \
      --leaf-divisors "${LEAF_DIVISOR}" \
      --bucket-size "${BUCKET_SIZE}" \
      --stash-capacity "${STASH_CAPACITY}" \
      --cache-levels "${CACHE_LEVELS}" | tee "${LOG_DIR}/size-cuckoo.log"

    build_cmd=(
      build-circuit
      --db-dir "${DB_DIR}"
      --out-dir "${ORAM_DIR}"
      --level "${LEVEL}"
      --pack "${PACK}"
      --leaf-divisor "${LEAF_DIVISOR}"
      --bucket-size "${BUCKET_SIZE}"
      --stash-capacity "${STASH_CAPACITY}"
      --cache-levels "${CACHE_LEVELS}"
    )
  fi
  if [[ "${AUTH_STORE}" == "1" ]]; then
    build_cmd+=(--auth-store --auth-trusted-levels "${AUTH_TRUSTED_LEVELS}" --auth-hash-page-size "${AUTH_HASH_PAGE_SIZE}")
  fi
  if [[ "${ENCRYPTED}" == "1" ]]; then
    build_cmd+=(--encrypted --key-hex "${PAGE_KEY_HEX}" --state-key-hex "${STATE_KEY_HEX}")
  fi

  log "building ${ORAM_LAYOUT} Circuit ORAM images"
  cargo_oramctl "${build_cmd[@]}" | tee "${LOG_DIR}/build-${ORAM_LAYOUT}.log"

  du -sh "${ORAM_DIR}" | tee "${LOG_DIR}/du-after-build.log"
}

real_extract_direct_chunks() {
  require_oram_repo
  require_cuckoo_db_dir
  check_pir_service_inactive
  mkdir -p "${DIRECT_SOURCE_DIR}" "${LOG_DIR}"
  check_threshold "free disk near direct source dir" "$(free_disk_gib_for "${DIRECT_SOURCE_DIR}")" "${REAL_MIN_FREE_GIB}" "${ALLOW_LOW_DISK}"
  log "extracting direct CHUNK source from ${DB_DIR}/chunk_pir_cuckoo.bin"
  cargo_oramctl extract-direct-chunks \
    --chunk-cuckoo-file "${DB_DIR}/chunk_pir_cuckoo.bin" \
    --out-file "${DIRECT_CHUNKS_FILE}" | tee "${LOG_DIR}/extract-direct-chunks.log"
}

real_verify() {
  preflight_real
  warn_if_no_save
  if [[ "${ORAM_LAYOUT}" == "direct" ]]; then
    require_direct_oram_image
    log "direct ORAM image structure verified; use server-smoke for behavioral direct lookup verification"
    {
      echo "verify_direct_structure=true"
      ls "${ORAM_DIR}"/direct-index.* "${ORAM_DIR}"/direct-chunk.* 2>/dev/null | sort
    } | tee "${LOG_DIR}/verify-direct-structure.log"
    return 0
  fi

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
  if [[ "${ORAM_LAYOUT}" == "direct" ]]; then
    pos_map_bench
    return 0
  fi
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
  )
  if [[ "${ORAM_LAYOUT}" == "direct" ]]; then
    server_args+=(
      --direct-oram-drain-per-access "${DRAIN_PER_ACCESS}"
      --direct-oram-access-budget "${DIRECT_ACCESS_BUDGET}"
      --direct-oram-cache-levels "${CACHE_LEVELS}"
    )
  elif [[ "${ORAM_LAYOUT}" == "cuckoo" ]]; then
    server_args+=(
      --cuckoo-oram-pack "${PACK}"
      --cuckoo-oram-drain-per-access "${DRAIN_PER_ACCESS}"
      --cuckoo-oram-cache-levels "${CACHE_LEVELS}"
    )
  else
    die "ORAM_LAYOUT must be direct or cuckoo, got ${ORAM_LAYOUT}"
  fi
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
    if [[ "${ORAM_LAYOUT}" == "direct" ]]; then
      server_args+=(--direct-oram-db "${spec}")
    else
      server_args+=(--cuckoo-oram-db "${spec}")
    fi
  done

  if [[ "${AUTH_STORE}" == "1" ]]; then
    if [[ "${ORAM_LAYOUT}" == "direct" ]]; then
      server_args+=(--direct-oram-auth-store)
    else
      server_args+=(--cuckoo-oram-auth-store)
    fi
  fi
  if [[ "${ENCRYPTED}" == "1" ]]; then
    if [[ "${ORAM_LAYOUT}" == "direct" ]]; then
      server_args+=(--direct-oram-encrypted --direct-oram-key-hex "${PAGE_KEY_HEX}" --direct-oram-state-key-hex "${STATE_KEY_HEX}")
    else
      server_args+=(--cuckoo-oram-encrypted --cuckoo-oram-key-hex "${PAGE_KEY_HEX}" --cuckoo-oram-state-key-hex "${STATE_KEY_HEX}")
    fi
  fi
  if [[ "${NO_SAVE}" == "1" ]]; then
    if [[ "${ORAM_LAYOUT}" == "direct" ]]; then
      server_args+=(--direct-oram-no-save)
    else
      server_args+=(--cuckoo-oram-no-save)
    fi
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
  local padded_args=()
  if [[ -n "${PADDED_SLOTS}" ]]; then
    padded_args=(--padded-slots "${PADDED_SLOTS}")
    log "encrypted ORAM smoke will use padded_slots=${PADDED_SLOTS}"
  fi
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
        "${padded_args[@]}" \
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
  real-extract-direct-chunks)
    real_extract_direct_chunks
    ;;
  real-verify)
    real_verify
    ;;
  real-bench)
    real_bench
    ;;
  pos-map-bench)
    pos_map_bench
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
