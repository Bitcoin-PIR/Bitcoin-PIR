#!/usr/bin/env bash
# Runtime wrapper for the one-shot attested-builder Tier 3 UKI.

set -Eeuo pipefail

PATH=/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
export PATH

BAKED_ENV=/etc/bpir-builder/baked.env
CONFIG=${BPIR_BUILDER_CONFIG:-/home/pir/data/attested-builder/config.env}
BIN=/usr/local/bin/pir-attested-builder
ONIONFFI_BIN=/usr/local/bin/onionffi
PIPELINE_DIR=/usr/local/lib/attested-builder/scripts
SNAPSHOT_PIPELINE=$PIPELINE_DIR/build-snapshot-database.sh
DELTA_PIPELINE=$PIPELINE_DIR/build-delta-database.sh

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

require_unsigned_integer() {
    local name=$1
    local value=${!name:-}
    [[ "$value" =~ ^[0-9]+$ ]] || fail "$name must be an unsigned integer"
}

verified_evidence_field() {
    local report=$1
    local field=$2
    awk -F= -v field="$field" '
        $1 == field {
            count++
            value = substr($0, index($0, "=") + 1)
        }
        END {
            if (count == 1) print value
        }
    ' "$report"
}

run_reattest_v2_job() {
    local job=$1
    local predecessor_name="V2_DB${job}_PREDECESSOR_PROOF_DIR"
    local artifact_name="V2_DB${job}_ARTIFACT_DIR"
    local output_name="V2_DB${job}_OUT_DIR"
    local predecessor=${!predecessor_name:-}
    local artifact=${!artifact_name:-}
    local output=${!output_name:-}
    local attest_log="$OUT_BASE/v2-db${job}-$RUN_ID.attest.log"

    [[ -n "$predecessor" ]] || fail "$predecessor_name is required"
    [[ -n "$artifact" ]] || fail "$artifact_name is required"
    [[ -n "$output" ]] || fail "$output_name is required"
    require_data_path "$predecessor_name"
    require_data_path "$artifact_name"
    require_data_path "$output_name"
    [[ -d "$predecessor" ]] || fail "$predecessor_name not found: $predecessor"
    [[ -d "$artifact" ]] || fail "$artifact_name not found: $artifact"
    [[ ! -e "$output" ]] || fail "$output_name already exists: $output"
    mkdir -p "$(dirname "$output")"

    echo "[bpir-builder-run] re-attesting v2 db${job}"
    echo "[bpir-builder-run] WARNING: reattest-existing-v2 cannot add a Direct ORAM manifest commitment; db${job} remains ineligible for production TEE-ORAM"
    echo "[bpir-builder-run] predecessor=$predecessor"
    echo "[bpir-builder-run] artifacts=$artifact"
    echo "[bpir-builder-run] output=$output"
    "$BIN" attest-existing-layout \
        "$predecessor" \
        "$artifact" \
        "${BAKED_BUILDER_GIT_COMMIT:-unknown}" \
        "$BIN" \
        sev-snp \
        none \
        "$ISSUED_AT" \
        "$output" | tee "$attest_log"
    mv "$attest_log" "$output/attest-existing-layout.txt"

    "$BIN" emit-sev-snp-quote \
        "$output/build-evidence.bin" \
        "$output/build-evidence.sev-snp-report.bin" \
        "$output/build-evidence.report-data"

    "$BIN" verify-build-evidence \
        "$output/build-evidence.bin" \
        --builder-bin "$BIN" \
        --payload "$output/root-bundle-payload.bin" \
        --database-manifest "$output/database.manifest.sha256" \
        --all-artifacts-manifest "$output/all-artifacts.manifest.sha256" \
        --server-db-manifest "$output/server-db/MANIFEST.toml" \
        --sev-snp-report "$output/build-evidence.sev-snp-report.bin" \
        | tee "$output/build-evidence.verify.txt"

    (
        cd "$output"
        find . -type f ! -name SHA256SUMS -print \
            | sort \
            | while IFS= read -r file; do sha256sum "$file"; done \
            > SHA256SUMS
    )
    ln -sfn "$output" "$OUT_BASE/v2-db${job}-latest"
    {
        printf 'db%s_status=ok\n' "$job"
        printf 'db%s_out_dir=%s\n' "$job" "$output"
        printf 'db%s_evidence=%s\n' "$job" "$output/build-evidence.bin"
        printf 'db%s_sev_snp_report=%s\n' "$job" "$output/build-evidence.sev-snp-report.bin"
        printf 'db%s_direct_oram_eligible=no\n' "$job"
        printf 'db%s_direct_oram_blocker=reattest-existing-cannot-add-pre-evidence-direct-oram-manifest\n' "$job"
    } >> "$STATUS_FILE"
}

run_reattest_v2() {
    OUT_BASE=${OUT_BASE:-/home/pir/data/attested-builder-runs}
    require_data_path OUT_BASE
    mkdir -p "$OUT_BASE"
    RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
    [[ "$RUN_ID" =~ ^[A-Za-z0-9._=-]+$ ]] || fail "RUN_ID contains unsafe characters: $RUN_ID"
    ISSUED_AT=${ISSUED_AT:-$(date -u +%s)}
    [[ "$ISSUED_AT" =~ ^[0-9]+$ ]] || fail "ISSUED_AT must be an integer"
    V2_JOB_COUNT=${V2_JOB_COUNT:-2}
    [[ "$V2_JOB_COUNT" == 1 || "$V2_JOB_COUNT" == 2 ]] ||
        fail "V2_JOB_COUNT must be 1 or 2"

    STATUS_FILE="$OUT_BASE/builder-tier3-v2-$RUN_ID.status"
    {
        printf 'status=running\n'
        printf 'mode=reattest-existing-v2\n'
        printf 'direct_oram_eligible=no\n'
        printf 'direct_oram_blocker=requires-new-measured-snapshot-or-delta-build-with-typed-manifest-before-evidence\n'
        printf 'run_id=%s\n' "$RUN_ID"
        printf 'issued_at=%s\n' "$ISSUED_AT"
        printf 'baked_builder_git_commit=%s\n' "${BAKED_BUILDER_GIT_COMMIT:-unknown}"
        printf 'baked_builder_bin_sha256=%s\n' "${BAKED_BUILDER_BIN_SHA256:-unknown}"
        printf 'started_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$STATUS_FILE"

    local status=0
    trap 'status=$?; if [[ $status -ne 0 ]]; then printf "status=failed\nexit_code=%s\nfinished_at=%s\n" "$status" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$STATUS_FILE"; fi' EXIT
    local job
    for ((job = 0; job < V2_JOB_COUNT; job++)); do
        run_reattest_v2_job "$job"
    done
    {
        printf 'status=ok\n'
        printf 'exit_code=0\n'
        printf 'finished_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >> "$STATUS_FILE"
    trap - EXIT
    echo "[bpir-builder-run] v2 re-attestation completed successfully"
}

[[ -r "$BAKED_ENV" ]] || fail "missing baked metadata: $BAKED_ENV"
load_kv_file "$BAKED_ENV" \
    "BAKED_BUILDER_REPO BAKED_BUILDER_GIT_COMMIT BAKED_BUILDER_REQUIRED_GIT_COMMIT BAKED_BUILDER_BIN_SHA256"
[[ "${BAKED_BUILDER_REQUIRED_GIT_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]] ||
    fail "baked builder required commit is missing or malformed"
[[ "${BAKED_BUILDER_GIT_COMMIT:-}" == "$BAKED_BUILDER_REQUIRED_GIT_COMMIT" ]] ||
    fail "baked builder commit does not match required native-full-build-v2 pin"

[[ -r "$CONFIG" ]] || fail "missing runtime config: $CONFIG"
load_kv_file "$CONFIG" \
    "MODE SNAPSHOT EXPECTED_MUHASH NETWORK_MAGIC ANCHOR_HEIGHT ANCHOR_HASH FROM_SNAPSHOT FROM_EXPECTED_MUHASH FROM_ANCHOR_HEIGHT FROM_ANCHOR_HASH TO_SNAPSHOT TO_EXPECTED_MUHASH TO_ANCHOR_HEIGHT TO_ANCHOR_HASH CORE_VERSION OUT_BASE OUT_DIR RUN_ID MIN_FREE_KB REFERENCE_DATABASE_MANIFEST REFERENCE_ALL_ARTIFACTS_MANIFEST ONION_ENTRY_SIZE PARTITIONS ISSUED_AT PUSH_BATCH_ENTRIES ORAM_DIRECT_INPUT_DIR DIRECT_ORAM_INDEX_SLOTS_PER_BIN DIRECT_ORAM_INDEX_HASH_FNS DIRECT_ORAM_INDEX_LOAD_FACTOR_PPB DIRECT_ORAM_INDEX_SEED V2_JOB_COUNT V2_DB0_PREDECESSOR_PROOF_DIR V2_DB0_ARTIFACT_DIR V2_DB0_OUT_DIR V2_DB1_PREDECESSOR_PROOF_DIR V2_DB1_ARTIFACT_DIR V2_DB1_OUT_DIR"

[[ -x "$BIN" ]] || fail "builder binary missing or not executable: $BIN"
[[ -x "$ONIONFFI_BIN" ]] || fail "onionffi binary missing or not executable: $ONIONFFI_BIN"
[[ -c /dev/sev-guest ]] || fail "/dev/sev-guest missing"

MODE=${MODE:-}
if [[ "$MODE" == reattest-existing-v2 ]]; then
    run_reattest_v2
    exit 0
fi
case "$MODE" in
    native-full-build-v2-snapshot)
        BUILD_KIND=snapshot
        PIPELINE=$SNAPSHOT_PIPELINE
        require_env SNAPSHOT
        require_env EXPECTED_MUHASH
        require_env NETWORK_MAGIC
        require_env ANCHOR_HEIGHT
        require_data_path SNAPSHOT
        [[ -f "$SNAPSHOT" ]] || fail "snapshot not found: $SNAPSHOT"
        [[ "$EXPECTED_MUHASH" =~ ^[0-9a-fA-F]{64}$ ]] || fail "EXPECTED_MUHASH must be 64 hex chars"
        [[ "$NETWORK_MAGIC" =~ ^[0-9a-fA-F]{8}$ ]] || fail "NETWORK_MAGIC must be 8 hex chars"
        [[ "$ANCHOR_HEIGHT" =~ ^[0-9]+$ ]] || fail "ANCHOR_HEIGHT must be an integer"
        ;;
    native-full-build-v2-delta)
        BUILD_KIND=delta
        PIPELINE=$DELTA_PIPELINE
        require_env FROM_SNAPSHOT
        require_env FROM_EXPECTED_MUHASH
        require_env FROM_ANCHOR_HEIGHT
        require_env TO_SNAPSHOT
        require_env TO_EXPECTED_MUHASH
        require_env TO_ANCHOR_HEIGHT
        require_env NETWORK_MAGIC
        require_data_path FROM_SNAPSHOT
        require_data_path TO_SNAPSHOT
        [[ -f "$FROM_SNAPSHOT" ]] || fail "from snapshot not found: $FROM_SNAPSHOT"
        [[ -f "$TO_SNAPSHOT" ]] || fail "to snapshot not found: $TO_SNAPSHOT"
        [[ "$FROM_EXPECTED_MUHASH" =~ ^[0-9a-fA-F]{64}$ ]] || fail "FROM_EXPECTED_MUHASH must be 64 hex chars"
        [[ "$TO_EXPECTED_MUHASH" =~ ^[0-9a-fA-F]{64}$ ]] || fail "TO_EXPECTED_MUHASH must be 64 hex chars"
        [[ "$NETWORK_MAGIC" =~ ^[0-9a-fA-F]{8}$ ]] || fail "NETWORK_MAGIC must be 8 hex chars"
        [[ "$FROM_ANCHOR_HEIGHT" =~ ^[0-9]+$ && "$TO_ANCHOR_HEIGHT" =~ ^[0-9]+$ ]] ||
            fail "delta anchor heights must be integers"
        ((FROM_ANCHOR_HEIGHT < TO_ANCHOR_HEIGHT)) || fail "FROM_ANCHOR_HEIGHT must be < TO_ANCHOR_HEIGHT"
        SNAPSHOT=$TO_SNAPSHOT
        EXPECTED_MUHASH=$TO_EXPECTED_MUHASH
        ANCHOR_HEIGHT=$TO_ANCHOR_HEIGHT
        ANCHOR_HASH=${TO_ANCHOR_HASH:-}
        ;;
    *) fail "MODE must be native-full-build-v2-snapshot, native-full-build-v2-delta, or reattest-existing-v2" ;;
esac

require_env CORE_VERSION

require_data_path REFERENCE_DATABASE_MANIFEST
require_data_path REFERENCE_ALL_ARTIFACTS_MANIFEST
[[ -x "$PIPELINE" ]] || fail "pipeline script missing or not executable: $PIPELINE"

OUT_BASE=${OUT_BASE:-/home/pir/data/attested-builder-runs}
require_data_path OUT_BASE
mkdir -p "$OUT_BASE"

RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
[[ "$RUN_ID" =~ ^[A-Za-z0-9._=-]+$ ]] || fail "RUN_ID contains unsafe characters: $RUN_ID"

if [[ "$BUILD_KIND" == delta ]]; then
    OUT_DIR=${OUT_DIR:-"$OUT_BASE/delta_${FROM_ANCHOR_HEIGHT}_${TO_ANCHOR_HEIGHT}_${RUN_ID}"}
else
    OUT_DIR=${OUT_DIR:-"$OUT_BASE/mainnet_${ANCHOR_HEIGHT}_${RUN_ID}"}
fi
require_data_path OUT_DIR
case "$OUT_DIR" in
    "$OUT_BASE"/*) ;;
    *) fail "OUT_DIR must be under OUT_BASE ($OUT_BASE): $OUT_DIR" ;;
esac
[[ ! -e "$OUT_DIR" ]] || fail "OUT_DIR already exists; refusing to reuse: $OUT_DIR"

ORAM_DIRECT_INPUT_DIR=${ORAM_DIRECT_INPUT_DIR:-"$OUT_DIR/oram-direct-inputs"}
require_data_path ORAM_DIRECT_INPUT_DIR
[[ "$ORAM_DIRECT_INPUT_DIR" == "$OUT_DIR/oram-direct-inputs" ]] ||
    fail "ORAM_DIRECT_INPUT_DIR must be the native pipeline path $OUT_DIR/oram-direct-inputs"

DIRECT_ORAM_INDEX_SLOTS_PER_BIN=${DIRECT_ORAM_INDEX_SLOTS_PER_BIN:-4}
DIRECT_ORAM_INDEX_HASH_FNS=${DIRECT_ORAM_INDEX_HASH_FNS:-2}
DIRECT_ORAM_INDEX_LOAD_FACTOR_PPB=${DIRECT_ORAM_INDEX_LOAD_FACTOR_PPB:-950000000}
DIRECT_ORAM_INDEX_SEED=${DIRECT_ORAM_INDEX_SEED:-8030603977422561841}
require_unsigned_integer DIRECT_ORAM_INDEX_SLOTS_PER_BIN
require_unsigned_integer DIRECT_ORAM_INDEX_HASH_FNS
require_unsigned_integer DIRECT_ORAM_INDEX_LOAD_FACTOR_PPB
require_unsigned_integer DIRECT_ORAM_INDEX_SEED
((DIRECT_ORAM_INDEX_SLOTS_PER_BIN > 0)) || fail "DIRECT_ORAM_INDEX_SLOTS_PER_BIN must be > 0"
((DIRECT_ORAM_INDEX_HASH_FNS > 0)) || fail "DIRECT_ORAM_INDEX_HASH_FNS must be > 0"
((DIRECT_ORAM_INDEX_LOAD_FACTOR_PPB > 0 && DIRECT_ORAM_INDEX_LOAD_FACTOR_PPB < 1000000000)) ||
    fail "DIRECT_ORAM_INDEX_LOAD_FACTOR_PPB must be in 1..999999999"

STATUS_FILE="$OUT_BASE/builder-tier3-$RUN_ID.status"
{
    printf 'status=running\n'
    printf 'mode=%s\n' "$MODE"
    printf 'build_kind=%s\n' "$BUILD_KIND"
    printf 'direct_oram_eligible=pending\n'
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
export ONIONFFI_BIN
export RELEASE=1
export RUN_ONION_FFI=1
export ROOTS_ONLY=0
export STAGE_SERVER_DB=1
export BUILD_EVIDENCE_VERSION=2
export WRITE_BUILD_EVIDENCE=1
export EMIT_SEV_SNP_QUOTE=1
export TEE_PLATFORM=sev-snp
export TEE_IMAGE_MEASUREMENT=none
export BUILDER_GIT_COMMIT=${BAKED_BUILDER_GIT_COMMIT:-unknown}
export ONION_ENTRY_SIZE=${ONION_ENTRY_SIZE:-3328}
export PARTITIONS=${PARTITIONS:-4}
export ISSUED_AT=${ISSUED_AT:-0}
export PUSH_BATCH_ENTRIES=${PUSH_BATCH_ENTRIES:-256}
export DIRECT_ORAM_INDEX_SLOTS_PER_BIN DIRECT_ORAM_INDEX_HASH_FNS
export DIRECT_ORAM_INDEX_LOAD_FACTOR_PPB DIRECT_ORAM_INDEX_SEED

if [[ "$BUILD_KIND" == delta ]]; then
    export FROM_SNAPSHOT FROM_EXPECTED_MUHASH FROM_ANCHOR_HEIGHT
    export TO_SNAPSHOT TO_EXPECTED_MUHASH TO_ANCHOR_HEIGHT
fi

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

# Production Direct ORAM requires the native pipeline to have emitted
# predecessor-free full-build-v2 evidence. Fail closed before publishing
# `latest` or an eligibility claim.
evidence_version=$(verified_evidence_field "$OUT_DIR/build-evidence.verify.txt" evidence_version)
evidence_mode=$(verified_evidence_field "$OUT_DIR/build-evidence.verify.txt" evidence_mode)
predecessor_evidence=$(verified_evidence_field \
    "$OUT_DIR/build-evidence.verify.txt" predecessor_evidence_sha256)
predecessor_report=$(verified_evidence_field \
    "$OUT_DIR/build-evidence.verify.txt" predecessor_report_sha256)
if [[ "$evidence_version" != 2 || "$evidence_mode" != full_build ||
      "$predecessor_evidence" != none || "$predecessor_report" != none ]]; then
    {
        printf 'direct_oram_eligible=no\n'
        printf 'direct_oram_blocker=attested-builder-full-build-v2-required\n'
        printf 'observed_evidence_version=%s\n' "${evidence_version:-missing-or-ambiguous}"
        printf 'observed_evidence_mode=%s\n' "${evidence_mode:-missing-or-ambiguous}"
    } >> "$STATUS_FILE"
    fail "attested-builder did not emit predecessor-free full-build-v2 evidence"
fi

ln -sfn "$OUT_DIR" "$OUT_BASE/latest"
{
    printf 'status=ok\n'
    printf 'exit_code=0\n'
    printf 'mode=%s\n' "$MODE"
    printf 'build_kind=%s\n' "$BUILD_KIND"
    printf 'direct_oram_eligible=yes\n'
    printf 'out_dir=%s\n' "$OUT_DIR"
    printf 'summary=%s\n' "$OUT_DIR/build-summary.txt"
    printf 'evidence=%s\n' "$OUT_DIR/build-evidence.bin"
    printf 'sev_snp_report=%s\n' "$OUT_DIR/build-evidence.sev-snp-report.bin"
    printf 'oram_direct_input_dir=%s\n' "$ORAM_DIRECT_INPUT_DIR"
    printf 'finished_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >> "$STATUS_FILE"

trap - EXIT
echo "[bpir-builder-run] completed successfully"
