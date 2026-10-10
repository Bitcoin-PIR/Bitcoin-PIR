#!/bin/sh
# Runit finish hook for unified_server.
#
# Stop supervising after three exits within ten minutes. A long stable interval
# starts a new failure sequence. State in /run is per boot; the status copy on
# /home/pir/data is only for operator visibility after returning to stock mode.

# shellcheck shell=sh

umask 077

MAX_FAILURES=3
FAILURE_WINDOW_SECONDS=600
STATE_DIR=${BPIR_RUNIT_GUARD_STATE_DIR:-/run/bitcoinpir-runit/unified_server}
STATUS_DIR=${BPIR_RUNIT_GUARD_STATUS_DIR:-/home/pir/data/oram-boot-logs}
SV_BIN=${BPIR_RUNIT_GUARD_SV_BIN:-/usr/bin/sv}
SERVICE_DIR=${BPIR_RUNIT_GUARD_SERVICE_DIR:-/etc/service/unified_server}
ORAM_BOOT_ID_FILE=${BPIR_ORAM_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}
ORAM_PUBLISHED_MARKER=${BPIR_ORAM_PUBLISHED_MARKER:-/home/pir/data/oram-boot-logs/oram-published.boot-id.env}

published_marker_matches_current_boot() {
    [ -r "$ORAM_PUBLISHED_MARKER" ] || return 1
    boot_id=$(cat "$ORAM_BOOT_ID_FILE" 2>/dev/null || true)
    case "$boot_id" in
        ????????-????-????-????-????????????) ;;
        *) return 1 ;;
    esac
    marker_boot_id=$(awk -F= '$1 == "boot_id" { if (++seen == 1) print $2; else exit 2 } END { if (seen != 1) exit 1 }' "$ORAM_PUBLISHED_MARKER") \
        || return 1
    marker_status=$(awk -F= '$1 == "status" { if (++seen == 1) print $2; else exit 2 } END { if (seen != 1) exit 1 }' "$ORAM_PUBLISHED_MARKER") \
        || return 1
    [ "$marker_status" = published ] && [ "$marker_boot_id" = "$boot_id" ]
}

mkdir -p "$STATE_DIR" || exit 0

now=$(date +%s 2>/dev/null || echo 0)
last=0
count=0
[ -r "$STATE_DIR/last_failure_at" ] && last=$(cat "$STATE_DIR/last_failure_at" 2>/dev/null || echo 0)
[ -r "$STATE_DIR/failure_count" ] && count=$(cat "$STATE_DIR/failure_count" 2>/dev/null || echo 0)
case "$now:$last:$count" in
    *[!0-9:]*|::*|*::*) now=0; last=0; count=0 ;;
esac

if [ "$now" -gt 0 ] && [ "$last" -gt 0 ] && [ $((now - last)) -le "$FAILURE_WINDOW_SECONDS" ]; then
    count=$((count + 1))
else
    count=1
fi

printf '%s\n' "$now" >"$STATE_DIR/last_failure_at.tmp"
mv "$STATE_DIR/last_failure_at.tmp" "$STATE_DIR/last_failure_at"
printf '%s\n' "$count" >"$STATE_DIR/failure_count.tmp"
mv "$STATE_DIR/failure_count.tmp" "$STATE_DIR/failure_count"

status=retrying
action=restart
reason=failure-threshold-not-reached
if published_marker_matches_current_boot; then
    status=restart_suppressed
    action=down
    reason=oram-published-same-boot
elif [ "$count" -ge "$MAX_FAILURES" ]; then
    status=restart_suppressed
    action=down
    reason=failure-threshold-reached
fi

if mkdir -p "$STATUS_DIR" 2>/dev/null; then
    {
        printf 'status=%s\n' "$status"
        printf 'failure_count=%s\n' "$count"
        printf 'max_failures=%s\n' "$MAX_FAILURES"
        printf 'failure_window_seconds=%s\n' "$FAILURE_WINDOW_SECONDS"
        printf 'last_failure_at_epoch=%s\n' "$now"
        printf 'exit_code=%s\n' "${1:-unknown}"
        printf 'signal=%s\n' "${2:-unknown}"
        printf 'action=%s\n' "$action"
        printf 'reason=%s\n' "$reason"
    } >"$STATUS_DIR/unified-server-runit.status.tmp"
    mv "$STATUS_DIR/unified-server-runit.status.tmp" "$STATUS_DIR/unified-server-runit.status"
fi

if [ "$action" = down ]; then
    echo "[unified-server-finish] suppressing restart: $reason" >&2
    # `sv down` sends the control byte immediately. The one-second wait may
    # expire because this finish hook must return before runsv becomes down.
    "$SV_BIN" -w 1 down "$SERVICE_DIR" >/dev/null 2>&1 || true
else
    echo "[unified-server-finish] failure $count/$MAX_FAILURES; runit may retry" >&2
fi

exit 0
