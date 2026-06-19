#!/usr/bin/env bash
# Runtime wrapper for the one-shot attested-builder Tier 3 UKI.

set -Eeuo pipefail

PATH=/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
export PATH

BAKED_ENV=/etc/bpir-builder/baked.env
CONFIG=${BPIR_BUILDER_CONFIG:-/home/pir/data/attested-builder/config.env}
BIN=/usr/local/bin/pir-attested-builder
PIPELINE=/usr/local/lib/attested-builder/scripts/build-snapshot-database.sh

fail() {
    printf '[bpir-builder-run] FATAL: %s\n' "$*" >&2
    exit 1
}

trim() {
    local value=$1
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

load_kv_file() {
    local file=$1
    local allowed_keys=$2
    local line key value

    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line%$'\r'}
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || fail "$file contains a non KEY=VALUE line: $line"

        key=$(trim "${line%%=*}")
        value=$(trim "${line#*=}")
        [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] ||
            fail "$file contains an invalid key: $key"
        case " $allowed_keys " in
            *" $key "*) ;;
            *) fail "$file contains unsupported key: $key" ;;
        esac
        printf -v "$key" '%s' "$value"
    done < "$file"
}

require_env() {
    local name=$1
    if [[ -z "${!name:-}" ]]; then
        fail "$name is required in $CONFIG"
    fi
}

require_data_path() {
    local name=$1
    local value=${!name:-}
    [[ -n "$value" ]] || return 0
    case "$value" in
        /home/pir/data/*) ;;
        *) fail "$name must live under /home/pir/data inside the builder UKI: $value" ;;
    esac
}

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|y|Y) return 0 ;;
        *) return 1 ;;
    esac
}

[[ -r "$BAKED_ENV" ]] || fail "missing baked metadata: $BAKED_ENV"
load_kv_file "$BAKED_ENV" \
    "BAKED_BUILDER_REPO BAKED_BUILDER_GIT_COMMIT BAKED_BUILDER_BIN_SHA256"

[[ -r "$CONFIG" ]] || fail "missing runtime config: $CONFIG"
load_kv_file "$CONFIG" \
    "SNAPSHOT EXPECTED_MUHASH NETWORK_MAGIC ANCHOR_HEIGHT ANCHOR_HASH CORE_VERSION OUT_BASE OUT_DIR RUN_ID MIN_FREE_KB REFERENCE_DATABASE_MANIFEST REFERENCE_ALL_ARTIFACTS_MANIFEST ONION_ENTRY_SIZE PARTITIONS ISSUED_AT PUSH_BATCH_ENTRIES ORAM_DIRECT_INPUT_DIR KEEP_ORAM_DIRECT_INPUTS"

require_env SNAPSHOT
require_env EXPECTED_MUHASH
require_env NETWORK_MAGIC
require_env ANCHOR_HEIGHT
require_env CORE_VERSION

require_data_path SNAPSHOT
require_data_path REFERENCE_DATABASE_MANIFEST
require_data_path REFERENCE_ALL_ARTIFACTS_MANIFEST

[[ -f "$SNAPSHOT" ]] || fail "snapshot not found: $SNAPSHOT"
[[ "$EXPECTED_MUHASH" =~ ^[0-9a-fA-F]{64}$ ]] || fail "EXPECTED_MUHASH must be 64 hex chars"
[[ "$NETWORK_MAGIC" =~ ^[0-9a-fA-F]{8}$ ]] || fail "NETWORK_MAGIC must be 8 hex chars"
[[ "$ANCHOR_HEIGHT" =~ ^[0-9]+$ ]] || fail "ANCHOR_HEIGHT must be an integer"
[[ -x "$BIN" ]] || fail "builder binary missing or not executable: $BIN"
[[ -x "$PIPELINE" ]] || fail "pipeline script missing or not executable: $PIPELINE"
[[ -c /dev/sev-guest ]] || fail "/dev/sev-guest missing"

OUT_BASE=${OUT_BASE:-/home/pir/data/attested-builder-runs}
require_data_path OUT_BASE
mkdir -p "$OUT_BASE"

RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
[[ "$RUN_ID" =~ ^[A-Za-z0-9._=-]+$ ]] || fail "RUN_ID contains unsafe characters: $RUN_ID"

OUT_DIR=${OUT_DIR:-"$OUT_BASE/mainnet_${ANCHOR_HEIGHT}_${RUN_ID}"}
require_data_path OUT_DIR
case "$OUT_DIR" in
    "$OUT_BASE"/*) ;;
    *) fail "OUT_DIR must be under OUT_BASE ($OUT_BASE): $OUT_DIR" ;;
esac
[[ ! -e "$OUT_DIR" ]] || fail "OUT_DIR already exists; refusing to reuse: $OUT_DIR"

ORAM_DIRECT_INPUT_DIR=${ORAM_DIRECT_INPUT_DIR:-"$OUT_DIR/oram-direct-inputs"}
require_data_path ORAM_DIRECT_INPUT_DIR
case "$ORAM_DIRECT_INPUT_DIR" in
    "$OUT_DIR"/*) ;;
    *) fail "ORAM_DIRECT_INPUT_DIR must be under OUT_DIR ($OUT_DIR): $ORAM_DIRECT_INPUT_DIR" ;;
esac

STATUS_FILE="$OUT_BASE/builder-tier3-$RUN_ID.status"
{
    printf 'status=running\n'
    printf 'run_id=%s\n' "$RUN_ID"
    printf 'out_dir=%s\n' "$OUT_DIR"
    printf 'snapshot=%s\n' "$SNAPSHOT"
    printf 'oram_direct_input_dir=%s\n' "$ORAM_DIRECT_INPUT_DIR"
    printf 'anchor_height=%s\n' "$ANCHOR_HEIGHT"
    printf 'baked_builder_git_commit=%s\n' "${BAKED_BUILDER_GIT_COMMIT:-unknown}"
    printf 'baked_builder_bin_sha256=%s\n' "${BAKED_BUILDER_BIN_SHA256:-unknown}"
    printf 'started_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$STATUS_FILE"

on_exit() {
    local status=$?
    if [[ "$status" -ne 0 ]]; then
        {
            printf 'status=failed\n'
            printf 'exit_code=%s\n' "$status"
            printf 'finished_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        } >> "$STATUS_FILE" || true
    fi
}
trap on_exit EXIT

MIN_FREE_KB=${MIN_FREE_KB:-50000000}
if [[ "$MIN_FREE_KB" =~ ^[0-9]+$ && "$MIN_FREE_KB" -gt 0 ]]; then
    free_kb=$(df -Pk "$OUT_BASE" | awk 'NR == 2 {print $4}')
    if [[ -n "$free_kb" && "$free_kb" -lt "$MIN_FREE_KB" ]]; then
        fail "not enough free space under $OUT_BASE: ${free_kb} KiB < ${MIN_FREE_KB} KiB"
    fi
fi

export SNAPSHOT EXPECTED_MUHASH NETWORK_MAGIC ANCHOR_HEIGHT CORE_VERSION
export OUT_DIR
export SKIP_CARGO_BUILD=1
export BIN
export RELEASE=1
export RUN_ONION_FFI=0
export ROOTS_ONLY=1
export STAGE_SERVER_DB=0
export KEEP_ORAM_DIRECT_INPUTS=1
export ORAM_DIRECT_INPUT_DIR
export WRITE_BUILD_EVIDENCE=1
export EMIT_SEV_SNP_QUOTE=1
export TEE_PLATFORM=sev-snp
export TEE_IMAGE_MEASUREMENT=none
export BUILDER_GIT_COMMIT=${BAKED_BUILDER_GIT_COMMIT:-unknown}
export ONION_ENTRY_SIZE=${ONION_ENTRY_SIZE:-3328}
export PARTITIONS=${PARTITIONS:-4}
export ISSUED_AT=${ISSUED_AT:-0}
export PUSH_BATCH_ENTRIES=${PUSH_BATCH_ENTRIES:-256}

if [[ -n "${REFERENCE_DATABASE_MANIFEST:-}" ]]; then
    export REFERENCE_DATABASE_MANIFEST
fi
if [[ -n "${REFERENCE_ALL_ARTIFACTS_MANIFEST:-}" ]]; then
    export REFERENCE_ALL_ARTIFACTS_MANIFEST
fi

echo "[bpir-builder-run] running attested-builder pipeline"
echo "[bpir-builder-run] out_dir=$OUT_DIR"
/bin/bash "$PIPELINE"

VERIFY_ARGS=(
    "$OUT_DIR/build-evidence.bin"
    --snapshot "$SNAPSHOT"
    --builder-bin "$BIN"
    --payload "$OUT_DIR/root-bundle-payload.bin"
    --database-manifest "$OUT_DIR/database.manifest.sha256"
    --all-artifacts-manifest "$OUT_DIR/all-artifacts.manifest.sha256"
    --server-db-manifest "$OUT_DIR/server-db/MANIFEST.toml"
    --expected-muhash "$EXPECTED_MUHASH"
    --expected-anchor-height "$ANCHOR_HEIGHT"
    --sev-snp-report "$OUT_DIR/build-evidence.sev-snp-report.bin"
)
if [[ -n "${ANCHOR_HASH:-}" ]]; then
    VERIFY_ARGS+=(--expected-anchor-hash "$ANCHOR_HASH")
fi

echo "[bpir-builder-run] verifying build evidence and SEV-SNP report_data"
"$BIN" verify-build-evidence "${VERIFY_ARGS[@]}" | tee "$OUT_DIR/build-evidence.verify.txt"

ln -sfn "$OUT_DIR" "$OUT_BASE/latest"
{
    printf 'status=ok\n'
    printf 'exit_code=0\n'
    printf 'out_dir=%s\n' "$OUT_DIR"
    printf 'summary=%s\n' "$OUT_DIR/build-summary.txt"
    printf 'evidence=%s\n' "$OUT_DIR/build-evidence.bin"
    printf 'sev_snp_report=%s\n' "$OUT_DIR/build-evidence.sev-snp-report.bin"
    printf 'oram_direct_input_dir=%s\n' "$ORAM_DIRECT_INPUT_DIR"
    printf 'finished_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >> "$STATUS_FILE"

trap - EXIT
echo "[bpir-builder-run] completed successfully"
