#!/usr/bin/env bash
# Runtime wrapper for the one-shot attested-builder Tier 3 UKI.

set -Eeuo pipefail

PATH=/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
export PATH

BAKED_ENV=/etc/bpir-builder/baked.env
CONFIG=${BPIR_BUILDER_CONFIG:-/home/pir/data/attested-builder/config.env}
BIN=/usr/local/bin/pir-attested-builder
PIPELINE=/usr/local/lib/attested-builder/scripts/build-snapshot-database.sh
LOG_FILE=${BPIR_BUILDER_LOG:-/home/pir/data/attested-builder-runs/builder-tier3-init.log}
PROGRESS_ROOT=/run/bpir-builder-progress
PROGRESS_WWW=$PROGRESS_ROOT/www
PROGRESS_STATE=$PROGRESS_ROOT/state.env
PROGRESS_HTTP_PID=
PROGRESS_HEARTBEAT_PID=
PROGRESS_HTTP_PORT=18080
PROGRESS_INTERVAL_SECONDS=15
PROGRESS_LOG_LINES=120
RUN_STATUS=initializing
RUN_STAGE=boot
RUN_STAGE_INDEX=0
RUN_STAGE_TOTAL=5
RUN_DETAIL=
EXIT_CODE=
FINISHED_AT=

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

json_escape() {
    local value=${1:-}
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    printf '%s' "$value"
}

now_utc() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

write_status_file() {
    local tmp="$STATUS_FILE.tmp"
    mkdir -p "$PROGRESS_ROOT"
    {
        printf 'status=%s\n' "$RUN_STATUS"
        printf 'stage=%s\n' "$RUN_STAGE"
        printf 'stage_index=%s\n' "$RUN_STAGE_INDEX"
        printf 'stage_total=%s\n' "$RUN_STAGE_TOTAL"
        printf 'detail=%s\n' "$RUN_DETAIL"
        printf 'run_id=%s\n' "$RUN_ID"
        printf 'out_dir=%s\n' "$OUT_DIR"
        printf 'snapshot=%s\n' "$SNAPSHOT"
        printf 'anchor_height=%s\n' "$ANCHOR_HEIGHT"
        printf 'baked_builder_git_commit=%s\n' "${BAKED_BUILDER_GIT_COMMIT:-unknown}"
        printf 'baked_builder_bin_sha256=%s\n' "${BAKED_BUILDER_BIN_SHA256:-unknown}"
        printf 'started_at=%s\n' "$STARTED_AT"
        printf 'updated_at=%s\n' "$(now_utc)"
        if [[ -n "$EXIT_CODE" ]]; then
            printf 'exit_code=%s\n' "$EXIT_CODE"
        fi
        if [[ -n "$FINISHED_AT" ]]; then
            printf 'finished_at=%s\n' "$FINISHED_AT"
        fi
        if [[ "$RUN_STATUS" == "ok" ]]; then
            printf 'summary=%s\n' "$OUT_DIR/build-summary.txt"
            printf 'evidence=%s\n' "$OUT_DIR/build-evidence.bin"
            printf 'sev_snp_report=%s\n' "$OUT_DIR/build-evidence.sev-snp-report.bin"
        fi
    } > "$tmp"
    mv "$tmp" "$STATUS_FILE"

    {
        declare -p RUN_STATUS RUN_STAGE RUN_STAGE_INDEX RUN_STAGE_TOTAL
        declare -p RUN_DETAIL EXIT_CODE FINISHED_AT STARTED_AT STARTED_EPOCH
        declare -p RUN_ID OUT_DIR SNAPSHOT ANCHOR_HEIGHT OUT_BASE LOG_FILE
        declare -p PROGRESS_HTTP_PORT PROGRESS_LOG_LINES
    } > "$PROGRESS_STATE.tmp"
    mv "$PROGRESS_STATE.tmp" "$PROGRESS_STATE"
}

progress_write_files() {
    mkdir -p "$PROGRESS_WWW"

    local now uptime free_kb out_kb log_bytes last_log_line log_lines
    now=$(now_utc)
    uptime=0
    if [[ "${STARTED_EPOCH:-0}" =~ ^[0-9]+$ && "$STARTED_EPOCH" -gt 0 ]]; then
        uptime=$(( $(date -u +%s) - STARTED_EPOCH ))
    fi
    free_kb=$(df -Pk "$OUT_BASE" 2>/dev/null | awk 'NR == 2 {print $4}')
    free_kb=${free_kb:-0}
    out_kb=0
    if [[ -d "$OUT_DIR" ]]; then
        out_kb=$(du -sk "$OUT_DIR" 2>/dev/null | awk '{print $1}')
        out_kb=${out_kb:-0}
    fi
    log_bytes=0
    last_log_line=
    if [[ -f "$LOG_FILE" ]]; then
        log_bytes=$(wc -c < "$LOG_FILE" 2>/dev/null || printf 0)
        last_log_line=$(tail -n 1 "$LOG_FILE" 2>/dev/null || true)
        log_lines=${PROGRESS_LOG_LINES:-120}
        [[ "$log_lines" =~ ^[0-9]+$ ]] || log_lines=120
        tail -n "$log_lines" "$LOG_FILE" > "$PROGRESS_WWW/log-tail.txt.tmp" 2>/dev/null || true
        mv "$PROGRESS_WWW/log-tail.txt.tmp" "$PROGRESS_WWW/log-tail.txt" 2>/dev/null || true
    else
        : > "$PROGRESS_WWW/log-tail.txt"
    fi

    {
        printf '{\n'
        printf '  "status": "%s",\n' "$(json_escape "$RUN_STATUS")"
        printf '  "stage": "%s",\n' "$(json_escape "$RUN_STAGE")"
        printf '  "stage_index": %s,\n' "$RUN_STAGE_INDEX"
        printf '  "stage_total": %s,\n' "$RUN_STAGE_TOTAL"
        printf '  "detail": "%s",\n' "$(json_escape "$RUN_DETAIL")"
        printf '  "run_id": "%s",\n' "$(json_escape "$RUN_ID")"
        printf '  "anchor_height": %s,\n' "$ANCHOR_HEIGHT"
        printf '  "out_dir": "%s",\n' "$(json_escape "$OUT_DIR")"
        printf '  "started_at": "%s",\n' "$(json_escape "$STARTED_AT")"
        printf '  "updated_at": "%s",\n' "$now"
        printf '  "uptime_seconds": %s,\n' "$uptime"
        printf '  "free_kb": %s,\n' "$free_kb"
        printf '  "out_dir_kb": %s,\n' "$out_kb"
        printf '  "log_bytes": %s,\n' "$log_bytes"
        printf '  "last_log_line": "%s",\n' "$(json_escape "$last_log_line")"
        printf '  "progress_http_port": %s\n' "${PROGRESS_HTTP_PORT:-18080}"
        printf '}\n'
    } > "$PROGRESS_WWW/status.json.tmp"
    mv "$PROGRESS_WWW/status.json.tmp" "$PROGRESS_WWW/status.json"

    {
        printf 'status=%s\n' "$RUN_STATUS"
        printf 'stage=%s\n' "$RUN_STAGE"
        printf 'stage_index=%s\n' "$RUN_STAGE_INDEX"
        printf 'stage_total=%s\n' "$RUN_STAGE_TOTAL"
        printf 'detail=%s\n' "$RUN_DETAIL"
        printf 'run_id=%s\n' "$RUN_ID"
        printf 'anchor_height=%s\n' "$ANCHOR_HEIGHT"
        printf 'out_dir=%s\n' "$OUT_DIR"
        printf 'updated_at=%s\n' "$now"
        printf 'uptime_seconds=%s\n' "$uptime"
        printf 'free_kb=%s\n' "$free_kb"
        printf 'out_dir_kb=%s\n' "$out_kb"
        printf 'log_bytes=%s\n' "$log_bytes"
        printf 'last_log_line=%s\n' "$last_log_line"
    } > "$PROGRESS_WWW/status.txt.tmp"
    mv "$PROGRESS_WWW/status.txt.tmp" "$PROGRESS_WWW/status.txt"

    cat > "$PROGRESS_WWW/index.html.tmp" <<HTML
<!doctype html>
<meta charset="utf-8">
<title>BitcoinPIR attested-builder progress</title>
<pre>
status: $RUN_STATUS
stage:  $RUN_STAGE ($RUN_STAGE_INDEX/$RUN_STAGE_TOTAL)
detail: $RUN_DETAIL
run:    $RUN_ID
height: $ANCHOR_HEIGHT
out:    $OUT_DIR
time:   $now

Endpoints:
  /status.json
  /status.txt
  /log-tail.txt
</pre>
HTML
    mv "$PROGRESS_WWW/index.html.tmp" "$PROGRESS_WWW/index.html"
}

progress_set_stage() {
    RUN_STAGE=$1
    RUN_STAGE_INDEX=$2
    RUN_DETAIL=${3:-}
    write_status_file || true
    progress_write_files || true
    printf '[bpir-builder-progress] stage=%s index=%s/%s detail=%s\n' \
        "$RUN_STAGE" "$RUN_STAGE_INDEX" "$RUN_STAGE_TOTAL" "$RUN_DETAIL"
}

progress_setup_network() {
    local iface path ip

    modprobe virtio_net 2>/dev/null || true
    modprobe virtio_pci 2>/dev/null || true

    /usr/bin/busybox ip link set lo up 2>/dev/null || true
    iface=
    for path in /sys/class/net/*; do
        iface=$(basename "$path")
        [[ "$iface" != "lo" ]] || continue
        break
    done
    [[ -n "$iface" && -e "/sys/class/net/$iface" ]] || return 1

    /usr/bin/busybox ip link set "$iface" up 2>/dev/null || return 1
    /usr/bin/busybox udhcpc -i "$iface" -n -q -t 5 -T 3 \
        -s /usr/local/bin/bpir-udhcpc-script >/tmp/bpir-udhcpc.log 2>&1 || return 1

    ip=$(/usr/bin/busybox ip -4 addr show dev "$iface" 2>/dev/null |
        awk '/inet / {print $2; exit}')
    {
        printf 'iface=%s\n' "$iface"
        printf 'ipv4=%s\n' "$ip"
        printf 'port=%s\n' "${PROGRESS_HTTP_PORT:-18080}"
    } > "$PROGRESS_WWW/network.txt"
    printf '[bpir-builder-progress] read-only HTTP status on %s:%s (%s)\n' \
        "${ip:-unknown}" "${PROGRESS_HTTP_PORT:-18080}" "$iface"
}

start_progress_services() {
    PROGRESS_INTERVAL_SECONDS=${PROGRESS_INTERVAL_SECONDS:-15}
    PROGRESS_LOG_LINES=${PROGRESS_LOG_LINES:-120}
    PROGRESS_HTTP_PORT=${PROGRESS_HTTP_PORT:-18080}

    [[ "$PROGRESS_INTERVAL_SECONDS" =~ ^[0-9]+$ ]] || PROGRESS_INTERVAL_SECONDS=15
    [[ "$PROGRESS_INTERVAL_SECONDS" -ge 5 ]] || PROGRESS_INTERVAL_SECONDS=5
    [[ "$PROGRESS_LOG_LINES" =~ ^[0-9]+$ ]] || PROGRESS_LOG_LINES=120
    [[ "$PROGRESS_HTTP_PORT" =~ ^[0-9]+$ ]] || PROGRESS_HTTP_PORT=18080

    mkdir -p "$PROGRESS_WWW"
    progress_write_files || true

    (
        while true; do
            sleep "$PROGRESS_INTERVAL_SECONDS"
            # This loop runs in a subshell, so reload the parent-written state.
            # shellcheck disable=SC1090
            source "$PROGRESS_STATE" 2>/dev/null || true
            progress_write_files || true
            printf '[bpir-builder-progress] heartbeat status=%s stage=%s updated_at=%s\n' \
                "$RUN_STATUS" "$RUN_STAGE" "$(now_utc)"
        done
    ) &
    PROGRESS_HEARTBEAT_PID=$!

    if is_truthy "${PROGRESS_HTTP:-0}"; then
        if progress_setup_network; then
            /usr/bin/busybox httpd -f -p "0.0.0.0:$PROGRESS_HTTP_PORT" \
                -h "$PROGRESS_WWW" &
            PROGRESS_HTTP_PID=$!
        else
            printf '[bpir-builder-progress] WARN: progress HTTP requested but network setup failed\n' >&2
        fi
    fi
}

stop_progress_services() {
    if [[ -n "${PROGRESS_HTTP_PID:-}" ]]; then
        kill "$PROGRESS_HTTP_PID" 2>/dev/null || true
    fi
    if [[ -n "${PROGRESS_HEARTBEAT_PID:-}" ]]; then
        kill "$PROGRESS_HEARTBEAT_PID" 2>/dev/null || true
    fi
}

[[ -r "$BAKED_ENV" ]] || fail "missing baked metadata: $BAKED_ENV"
load_kv_file "$BAKED_ENV" \
    "BAKED_BUILDER_REPO BAKED_BUILDER_GIT_COMMIT BAKED_BUILDER_BIN_SHA256"

[[ -r "$CONFIG" ]] || fail "missing runtime config: $CONFIG"
load_kv_file "$CONFIG" \
    "SNAPSHOT EXPECTED_MUHASH NETWORK_MAGIC ANCHOR_HEIGHT ANCHOR_HASH CORE_VERSION OUT_BASE OUT_DIR RUN_ID MIN_FREE_KB REFERENCE_DATABASE_MANIFEST REFERENCE_ALL_ARTIFACTS_MANIFEST ONION_ENTRY_SIZE PARTITIONS ISSUED_AT PUSH_BATCH_ENTRIES PROGRESS_HTTP PROGRESS_HTTP_PORT PROGRESS_INTERVAL_SECONDS PROGRESS_LOG_LINES"

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

STATUS_FILE="$OUT_BASE/builder-tier3-$RUN_ID.status"
STARTED_AT=$(now_utc)
STARTED_EPOCH=$(date -u +%s)
RUN_STATUS=running
progress_set_stage "preflight" 1 "runtime inputs validated"
start_progress_services || true

on_exit() {
    local status=$?
    if [[ "$status" -ne 0 ]]; then
        RUN_STATUS=failed
        EXIT_CODE=$status
        FINISHED_AT=$(now_utc)
        RUN_DETAIL="exit_code=$status"
        write_status_file || true
        progress_write_files || true
    fi
    stop_progress_services
}
trap on_exit EXIT

MIN_FREE_KB=${MIN_FREE_KB:-50000000}
progress_set_stage "space-check" 2 "checking free space"
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
progress_set_stage "pipeline" 3 "running roots-only snapshot pipeline"
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
progress_set_stage "verify-evidence" 4 "verifying build evidence and SEV-SNP report_data"
"$BIN" verify-build-evidence "${VERIFY_ARGS[@]}" | tee "$OUT_DIR/build-evidence.verify.txt"

ln -sfn "$OUT_DIR" "$OUT_BASE/latest"
RUN_STATUS=ok
RUN_STAGE=completed
RUN_STAGE_INDEX=5
RUN_DETAIL="completed successfully"
EXIT_CODE=0
FINISHED_AT=$(now_utc)
write_status_file || true
progress_write_files || true

trap - EXIT
stop_progress_services
echo "[bpir-builder-run] completed successfully"
