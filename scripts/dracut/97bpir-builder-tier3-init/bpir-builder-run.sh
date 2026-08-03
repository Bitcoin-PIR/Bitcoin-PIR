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

augment_server_db_manifest_with_direct_oram() {
    local manifest=$1
    local index_source=$2
    local chunk_source=$3
    local index_sha chunk_sha index_bytes chunk_bytes index_records chunk_records
    local files_sections manifest_tmp section_tmp

    [[ -f "$manifest" ]] || fail "server DB manifest missing before Direct ORAM binding: $manifest"
    [[ -f "$index_source" ]] || fail "Direct ORAM INDEX source missing: $index_source"
    [[ -f "$chunk_source" ]] || fail "Direct ORAM CHUNK source missing: $chunk_source"
    if grep -Eq '^\[direct_oram\][[:space:]]*$' "$manifest"; then
        fail "server DB manifest already contains [direct_oram]; refusing ambiguous rewrite: $manifest"
    fi
    files_sections=$(awk '$0 == "[files]" { count++ } END { print count + 0 }' "$manifest")
    [[ "$files_sections" == 1 ]] ||
        fail "server DB manifest must contain exactly one [files] section: $manifest"

    index_sha=$(sha256sum "$index_source" | awk '{print $1}')
    chunk_sha=$(sha256sum "$chunk_source" | awk '{print $1}')
    index_bytes=$(wc -c < "$index_source" | tr -d ' ')
    chunk_bytes=$(wc -c < "$chunk_source" | tr -d ' ')
    ((index_bytes > 0 && index_bytes % 25 == 0)) ||
        fail "Direct ORAM INDEX source size must be a positive multiple of 25 bytes"
    ((chunk_bytes > 0 && chunk_bytes % 40 == 0)) ||
        fail "Direct ORAM CHUNK source size must be a positive multiple of 40 bytes"
    index_records=$((index_bytes / 25))
    chunk_records=$((chunk_bytes / 40))

    manifest_tmp=$(mktemp "${manifest}.tmp.XXXXXX")
    section_tmp=$(mktemp "${manifest}.direct-oram.XXXXXX")
    if ! {
        printf '[direct_oram]\n'
        printf 'version = 1\n'
        printf 'index_sha256 = "%s"\n' "$index_sha"
        printf 'index_bytes = %s\n' "$index_bytes"
        printf 'index_records = %s\n' "$index_records"
        printf 'chunk_sha256 = "%s"\n' "$chunk_sha"
        printf 'chunk_bytes = %s\n' "$chunk_bytes"
        printf 'chunk_records = %s\n' "$chunk_records"
        printf 'index_slots_per_bin = %s\n' "$DIRECT_ORAM_INDEX_SLOTS_PER_BIN"
        printf 'index_hash_fns = %s\n' "$DIRECT_ORAM_INDEX_HASH_FNS"
        printf 'index_load_factor_ppb = %s\n' "$DIRECT_ORAM_INDEX_LOAD_FACTOR_PPB"
        printf 'index_seed = %s\n\n' "$DIRECT_ORAM_INDEX_SEED"
    } > "$section_tmp"; then
        rm -f -- "$manifest_tmp" "$section_tmp"
        fail "could not render Direct ORAM manifest section"
    fi
    if ! awk -v section="$section_tmp" '
        $0 == "[files]" && !inserted {
            while ((getline line < section) > 0) print line
            close(section)
            inserted = 1
        }
        { print }
        END { if (!inserted) exit 42 }
    ' "$manifest" > "$manifest_tmp"; then
        rm -f -- "$manifest_tmp" "$section_tmp"
        fail "could not atomically augment server DB manifest"
    fi
    rm -f -- "$section_tmp"
    chmod 0644 "$manifest_tmp"
    mv -f -- "$manifest_tmp" "$manifest"

    printf 'server_db_direct_oram_bound=1\n' >> "$OUT_DIR/build-summary.txt"
    printf 'server_db_manifest_bound_sha256=%s\n' \
        "$(sha256sum "$manifest" | awk '{print $1}')" >> "$OUT_DIR/build-summary.txt"
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
    "BAKED_BUILDER_REPO BAKED_BUILDER_GIT_COMMIT BAKED_BUILDER_BIN_SHA256"

[[ -r "$CONFIG" ]] || fail "missing runtime config: $CONFIG"
load_kv_file "$CONFIG" \
    "MODE SNAPSHOT EXPECTED_MUHASH NETWORK_MAGIC ANCHOR_HEIGHT ANCHOR_HASH CORE_VERSION OUT_BASE OUT_DIR RUN_ID MIN_FREE_KB REFERENCE_DATABASE_MANIFEST REFERENCE_ALL_ARTIFACTS_MANIFEST ONION_ENTRY_SIZE PARTITIONS ISSUED_AT PUSH_BATCH_ENTRIES ORAM_DIRECT_INPUT_DIR KEEP_ORAM_DIRECT_INPUTS DIRECT_ORAM_INDEX_SLOTS_PER_BIN DIRECT_ORAM_INDEX_HASH_FNS DIRECT_ORAM_INDEX_LOAD_FACTOR_PPB DIRECT_ORAM_INDEX_SEED V2_JOB_COUNT V2_DB0_PREDECESSOR_PROOF_DIR V2_DB0_ARTIFACT_DIR V2_DB0_OUT_DIR V2_DB1_PREDECESSOR_PROOF_DIR V2_DB1_ARTIFACT_DIR V2_DB1_OUT_DIR"

[[ -x "$BIN" ]] || fail "builder binary missing or not executable: $BIN"
[[ -c /dev/sev-guest ]] || fail "/dev/sev-guest missing"

MODE=${MODE:-full-build}
if [[ "$MODE" == reattest-existing-v2 ]]; then
    run_reattest_v2
    exit 0
fi
[[ "$MODE" == full-build ]] || fail "unsupported MODE: $MODE"

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
[[ -x "$PIPELINE" ]] || fail "pipeline script missing or not executable: $PIPELINE"

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
    printf 'mode=full-snapshot-build\n'
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
export RELEASE=1
export RUN_ONION_FFI=0
export ROOTS_ONLY=0
export STAGE_SERVER_DB=1
export KEEP_ORAM_DIRECT_INPUTS=1
export ORAM_DIRECT_INPUT_DIR
# BuildEvidence must commit the final typed server-db manifest. The pipeline
# stages the exact server-loadable tree first; this wrapper adds [direct_oram]
# and only then writes evidence/report_data and asks /dev/sev-guest for a quote.
export WRITE_BUILD_EVIDENCE=0
export EMIT_SEV_SNP_QUOTE=0
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

augment_server_db_manifest_with_direct_oram \
    "$OUT_DIR/server-db/MANIFEST.toml" \
    "$ORAM_DIRECT_INPUT_DIR/utxo_chunks_index_nodust.bin" \
    "$ORAM_DIRECT_INPUT_DIR/utxo_chunks_nodust.bin"

echo "[bpir-builder-run] writing evidence after Direct ORAM manifest binding"
"$BIN" write-build-evidence \
    "$OUT_DIR" \
    "$SNAPSHOT" \
    "$CORE_VERSION" \
    "$BUILDER_GIT_COMMIT" \
    "$BIN" \
    "$TEE_PLATFORM" \
    "$TEE_IMAGE_MEASUREMENT" \
    "$OUT_DIR/build-evidence.bin"
"$BIN" write-tee-report-data \
    "$OUT_DIR/build-evidence.bin" \
    "$OUT_DIR/build-evidence.report-data"
"$BIN" emit-sev-snp-quote \
    "$OUT_DIR/build-evidence.bin" \
    "$OUT_DIR/build-evidence.sev-snp-report.bin" \
    "$OUT_DIR/build-evidence.report-data"

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

# Production Direct ORAM requires a native full-build-v2 producer.  Merely
# augmenting a v1 pipeline's manifest and asking its legacy
# `write-build-evidence` command for another quote does not upgrade the root
# payload or params domain to v2.  Fail closed before publishing `latest` or an
# eligibility claim.  The predecessor checks also prevent re-attestation from
# being mistaken for a fresh measured build.
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
    printf 'mode=full-snapshot-build\n'
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
