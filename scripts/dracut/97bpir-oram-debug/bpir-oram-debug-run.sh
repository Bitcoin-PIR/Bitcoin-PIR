#!/bin/bash
# Bounded encrypted Direct ORAM fixture build inside the SEV-SNP debug UKI.

set -Eeuo pipefail

PATH=/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
export PATH

# shellcheck disable=SC1091
source /etc/bpir-oram-debug/baked.env

RUN_DIR=${BPIR_ORAM_DEBUG_RUN_DIR:?BPIR_ORAM_DEBUG_RUN_DIR is required}
INPUT_DIR=/run/bitcoinpir-oram-debug-inputs
STATE_DIR=/run/bitcoinpir-oram-debug-state
BULK_DIR="$RUN_DIR/bulk"
LOG_FILE="$RUN_DIR/oramctl.log"
PROGRESS_FILE="$RUN_DIR/progress.log"
HEARTBEAT_FILE="$RUN_DIR/heartbeat.env"
STATUS_FILE="$RUN_DIR/status.env"
ORAMCTL=/usr/local/bin/oramctl
INDEX_BAKED=/usr/share/bitcoinpir/oram-debug/utxo_chunks_index_nodust.bin
CHUNK_BAKED=/usr/share/bitcoinpir/oram-debug/utxo_chunks_nodust.bin
MAX_BUILD_SECONDS=300

phase=prepare
heartbeat_pid=
watchdog_pid=
build_pid=

timestamp() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

progress() {
    phase=$1
    printf '%s phase=%s\n' "$(timestamp)" "$phase" >>"$PROGRESS_FILE"
}

write_status() {
    local status=$1
    local reason=${2:-none}
    {
        printf 'status=%s\n' "$status"
        printf 'phase=%s\n' "$phase"
        printf 'reason=%s\n' "$reason"
        printf 'run_id=%s\n' "$BAKED_RUN_ID"
        printf 'updated_at=%s\n' "$(timestamp)"
        printf 'sev_device=present\n'
        printf 'oramctl_sha256=%s\n' "$BAKED_ORAMCTL_SHA256"
        printf 'index_sha256=%s\n' "$BAKED_INDEX_SHA256"
        printf 'chunk_sha256=%s\n' "$BAKED_CHUNK_SHA256"
        printf 'max_build_seconds=%s\n' "$MAX_BUILD_SECONDS"
    } >"$STATUS_FILE.tmp"
    mv "$STATUS_FILE.tmp" "$STATUS_FILE"
}

cleanup() {
    local status=$?
    [ -n "$heartbeat_pid" ] && kill "$heartbeat_pid" 2>/dev/null || true
    [ -n "$watchdog_pid" ] && kill "$watchdog_pid" 2>/dev/null || true
    unset PAGE_KEY_HEX || true
    if [ "$status" -ne 0 ]; then
        progress failed
        write_status failed "runner-exit-$status"
    fi
    return "$status"
}
trap cleanup EXIT

progress prepare
write_status running
mkdir -p "$INPUT_DIR" "$STATE_DIR" "$BULK_DIR"

[ "$(sha256sum "$ORAMCTL" | awk '{print $1}')" = "$BAKED_ORAMCTL_SHA256" ]
[ "$(sha256sum "$INDEX_BAKED" | awk '{print $1}')" = "$BAKED_INDEX_SHA256" ]
[ "$(sha256sum "$CHUNK_BAKED" | awk '{print $1}')" = "$BAKED_CHUNK_SHA256" ]
cp "$INDEX_BAKED" "$INPUT_DIR/utxo_chunks_index_nodust.bin"
cp "$CHUNK_BAKED" "$INPUT_DIR/utxo_chunks_nodust.bin"
cmp "$INDEX_BAKED" "$INPUT_DIR/utxo_chunks_index_nodust.bin"
cmp "$CHUNK_BAKED" "$INPUT_DIR/utxo_chunks_nodust.bin"

PAGE_KEY_HEX=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -An -tx1 -v | tr -d ' \n')
[ "${#PAGE_KEY_HEX}" -eq 64 ]

progress build-direct
write_status running
started_epoch=$(date -u +%s)

"$ORAMCTL" build-direct \
    --index-file "$INPUT_DIR/utxo_chunks_index_nodust.bin" \
    --chunks-file "$INPUT_DIR/utxo_chunks_nodust.bin" \
    --out-dir "$BULK_DIR" \
    --trusted-state-dir "$STATE_DIR" \
    --level all \
    --pack 4 \
    --leaf-divisor 2 \
    --bucket-size 2 \
    --stash-capacity 128 \
    --cache-levels 0 \
    --index-slots-per-bin 4 \
    --index-hash-fns 2 \
    --index-load-factor 0.8 \
    --index-seed 8030603977422561841 \
    --encrypted \
    --key-hex "$PAGE_KEY_HEX" \
    --auth-store \
    --auth-layout sidecar \
    --auth-trusted-levels 1 \
    --auth-hash-page-size 64 \
    >"$LOG_FILE" 2>&1 &
build_pid=$!

(
    max_rss_kib=0
    while kill -0 "$build_pid" 2>/dev/null; do
        rss_kib=$(awk '/^VmRSS:/ {print $2; exit}' "/proc/$build_pid/status" 2>/dev/null || echo 0)
        case "$rss_kib" in ''|*[!0-9]*) rss_kib=0 ;; esac
        [ "$rss_kib" -gt "$max_rss_kib" ] && max_rss_kib=$rss_kib
        output_bytes=$(du -sb "$BULK_DIR" 2>/dev/null | awk '{print $1}' || echo 0)
        {
            printf 'phase=build-direct\n'
            printf 'updated_at=%s\n' "$(timestamp)"
            printf 'elapsed_seconds=%s\n' "$(( $(date -u +%s) - started_epoch ))"
            printf 'output_bytes=%s\n' "$output_bytes"
            printf 'rss_kib=%s\n' "$rss_kib"
            printf 'max_rss_kib=%s\n' "$max_rss_kib"
        } >"$HEARTBEAT_FILE.tmp"
        mv "$HEARTBEAT_FILE.tmp" "$HEARTBEAT_FILE"
        sleep 5
    done
    printf '%s\n' "$max_rss_kib" >"$RUN_DIR/max-rss-kib"
) &
heartbeat_pid=$!

(
    sleep "$MAX_BUILD_SECONDS"
    if kill -0 "$build_pid" 2>/dev/null; then
        printf '%s\n' timed-out >"$RUN_DIR/watchdog.result"
        kill -TERM "$build_pid" 2>/dev/null || true
        sleep 5
        kill -KILL "$build_pid" 2>/dev/null || true
    fi
) &
watchdog_pid=$!

set +e
wait "$build_pid"
build_status=$?
set -e
unset PAGE_KEY_HEX
kill "$heartbeat_pid" "$watchdog_pid" 2>/dev/null || true
wait "$heartbeat_pid" 2>/dev/null || true
wait "$watchdog_pid" 2>/dev/null || true
heartbeat_pid=
watchdog_pid=
build_pid=

[ ! -e "$RUN_DIR/watchdog.result" ] || {
    progress timed-out
    write_status failed build-timeout
    exit 124
}
[ "$build_status" -eq 0 ] || {
    tail -80 "$LOG_FILE" >&2 || true
    exit "$build_status"
}

progress verify-output
write_status running
for level in direct-index direct-chunk; do
    for suffix in meta.oram payload.oram meta.hash.oram payload.hash.oram; do
        [ -s "$BULK_DIR/$level.$suffix" ]
    done
    for suffix in state auth.state metadata; do
        [ -s "$STATE_DIR/$level.$suffix" ]
    done
done
[ -s "$BULK_DIR/oram-build-evidence.json" ]
[ -s "$BULK_DIR/oram-build-evidence.bin" ]
grep -Fq 'direct_auth_built level=index' "$LOG_FILE"
grep -Fq 'direct_auth_built level=chunk' "$LOG_FILE"
grep -Fq 'built_direct level=index' "$LOG_FILE"
grep -Fq 'built_direct level=chunk' "$LOG_FILE"

finished_epoch=$(date -u +%s)
output_bytes=$(du -sb "$BULK_DIR" | awk '{print $1}')
max_rss_kib=$(cat "$RUN_DIR/max-rss-kib" 2>/dev/null || echo 0)
phase=complete
progress complete
{
    printf 'status=success\n'
    printf 'phase=complete\n'
    printf 'reason=none\n'
    printf 'run_id=%s\n' "$BAKED_RUN_ID"
    printf 'updated_at=%s\n' "$(timestamp)"
    printf 'sev_device=present\n'
    printf 'oramctl_sha256=%s\n' "$BAKED_ORAMCTL_SHA256"
    printf 'index_sha256=%s\n' "$BAKED_INDEX_SHA256"
    printf 'chunk_sha256=%s\n' "$BAKED_CHUNK_SHA256"
    printf 'elapsed_seconds=%s\n' "$((finished_epoch - started_epoch))"
    printf 'output_bytes=%s\n' "$output_bytes"
    printf 'max_rss_kib=%s\n' "$max_rss_kib"
    printf 'page_key_source=guest-urandom-not-recorded\n'
    printf 'source_binding_mode=minimal-fixture-nonstrict\n'
} >"$STATUS_FILE.tmp"
mv "$STATUS_FILE.tmp" "$STATUS_FILE"
sync
trap - EXIT
exit 0
