#!/bin/sh
# Run one Direct ORAM build with persistent progress, heartbeat, and hard stops.

# shellcheck shell=sh

set -u
umask 077

usage() {
    echo "usage: direct-oram-supervisor LABEL TIMEOUT HEARTBEAT_INTERVAL HEARTBEAT_DEADLINE KILL_GRACE STATUS_DIR OUTPUT_DIR LOG_FILE -- COMMAND [ARG ...]" >&2
    exit 2
}

[ "$#" -ge 10 ] || usage
label=$1
timeout_seconds=$2
heartbeat_interval_seconds=$3
heartbeat_deadline_seconds=$4
kill_grace_seconds=$5
status_dir=$6
output_dir=$7
log_file=$8
shift 8
[ "${1:-}" = -- ] || usage
shift
[ "$#" -gt 0 ] || usage

case "$label" in
    ''|*[!A-Za-z0-9._-]*) usage ;;
esac
for value in "$timeout_seconds" "$heartbeat_interval_seconds" \
    "$heartbeat_deadline_seconds" "$kill_grace_seconds"; do
    case "$value" in
        ''|*[!0-9]*) usage ;;
    esac
done
[ "$timeout_seconds" -gt 0 ] || usage
[ "$heartbeat_interval_seconds" -gt 0 ] || usage
[ "$heartbeat_deadline_seconds" -gt "$heartbeat_interval_seconds" ] || usage

log_dir=${log_file%/*}
[ "$log_dir" = "$log_file" ] && log_dir=.
mkdir -p "$status_dir" "$output_dir" "$log_dir" || exit 1

status_file="$status_dir/$label.status.env"
heartbeat_file="$status_dir/$label.heartbeat.env"
progress_file="$status_dir/direct-oram.progress.log"
reason_file="$status_dir/$label.watchdog-reason"
rm -f "$reason_file"

worker_pid=
heartbeat_pid=
watchdog_pid=
final_written=0
started_at_epoch=$(date -u +%s)

timestamp() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

output_kib() {
    du -sk "$output_dir" 2>/dev/null | awk '{ print $1; exit }'
}

write_status() {
    status=$1
    reason=$2
    elapsed=$(( $(date -u +%s) - started_at_epoch ))
    kib=$(output_kib)
    case "$kib" in ''|*[!0-9]*) kib=0 ;; esac
    {
        printf 'status=%s\n' "$status"
        printf 'phase=build-direct\n'
        printf 'database=%s\n' "$label"
        printf 'reason=%s\n' "$reason"
        printf 'updated_at=%s\n' "$(timestamp)"
        printf 'updated_at_epoch=%s\n' "$(date -u +%s)"
        printf 'elapsed_seconds=%s\n' "$elapsed"
        printf 'output_kib=%s\n' "$kib"
        printf 'timeout_seconds=%s\n' "$timeout_seconds"
        printf 'heartbeat_interval_seconds=%s\n' "$heartbeat_interval_seconds"
        printf 'heartbeat_deadline_seconds=%s\n' "$heartbeat_deadline_seconds"
    } >"$status_file.tmp"
    mv "$status_file.tmp" "$status_file"
}

cleanup() {
    cleanup_status=$?
    trap - EXIT HUP INT TERM
    [ -n "$heartbeat_pid" ] && kill "$heartbeat_pid" 2>/dev/null || true
    [ -n "$watchdog_pid" ] && kill "$watchdog_pid" 2>/dev/null || true
    if [ -n "$worker_pid" ] && kill -0 "$worker_pid" 2>/dev/null; then
        kill -TERM "$worker_pid" 2>/dev/null || true
        sleep "$kill_grace_seconds"
        kill -KILL "$worker_pid" 2>/dev/null || true
    fi
    [ -n "$worker_pid" ] && wait "$worker_pid" 2>/dev/null || true
    [ -n "$heartbeat_pid" ] && wait "$heartbeat_pid" 2>/dev/null || true
    [ -n "$watchdog_pid" ] && wait "$watchdog_pid" 2>/dev/null || true
    if [ "$cleanup_status" -ne 0 ] && [ "$final_written" -eq 0 ]; then
        write_status failed "supervisor-exit-$cleanup_status"
    fi
    exit "$cleanup_status"
}

handle_signal() {
    signal_name=$1
    write_status failed "supervisor-signal-$signal_name"
    final_written=1
    exit 143
}

trap cleanup EXIT
trap 'handle_signal HUP' HUP
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM

printf '%s database=%s phase=starting timeout_seconds=%s\n' \
    "$(timestamp)" "$label" "$timeout_seconds" >>"$progress_file"
: >"$log_file"
"$@" >"$log_file" 2>&1 &
worker_pid=$!
write_status running none

(
    max_rss_kib=0
    while kill -0 "$worker_pid" 2>/dev/null; do
        now_epoch=$(date -u +%s)
        rss_kib=$(awk '/^VmRSS:/ { print $2; exit }' "/proc/$worker_pid/status" 2>/dev/null || echo 0)
        kib=$(output_kib)
        case "$rss_kib" in ''|*[!0-9]*) rss_kib=0 ;; esac
        case "$kib" in ''|*[!0-9]*) kib=0 ;; esac
        [ "$rss_kib" -gt "$max_rss_kib" ] && max_rss_kib=$rss_kib
        {
            printf 'status=running\n'
            printf 'phase=build-direct\n'
            printf 'database=%s\n' "$label"
            printf 'updated_at=%s\n' "$(timestamp)"
            printf 'updated_at_epoch=%s\n' "$now_epoch"
            printf 'elapsed_seconds=%s\n' "$((now_epoch - started_at_epoch))"
            printf 'output_kib=%s\n' "$kib"
            printf 'rss_kib=%s\n' "$rss_kib"
            printf 'max_rss_kib=%s\n' "$max_rss_kib"
        } >"$heartbeat_file.tmp"
        mv "$heartbeat_file.tmp" "$heartbeat_file"
        sleep "$heartbeat_interval_seconds"
    done
) </dev/null >/dev/null 2>&1 &
heartbeat_pid=$!

(
    while kill -0 "$worker_pid" 2>/dev/null; do
        sleep 1
        kill -0 "$worker_pid" 2>/dev/null || exit 0
        now_epoch=$(date -u +%s)
        reason=
        if [ $((now_epoch - started_at_epoch)) -ge "$timeout_seconds" ]; then
            reason=build-timeout
        else
            heartbeat_epoch=$(awk -F= '$1 == "updated_at_epoch" { print $2; exit }' "$heartbeat_file" 2>/dev/null || echo 0)
            case "$heartbeat_epoch" in ''|*[!0-9]*) heartbeat_epoch=0 ;; esac
            if [ "$heartbeat_epoch" -eq 0 ]; then
                [ $((now_epoch - started_at_epoch)) -ge "$heartbeat_deadline_seconds" ] \
                    && reason=heartbeat-missing
            elif [ $((now_epoch - heartbeat_epoch)) -ge "$heartbeat_deadline_seconds" ]; then
                reason=heartbeat-stale
            fi
        fi
        [ -n "$reason" ] || continue
        printf '%s\n' "$reason" >"$reason_file.tmp"
        mv "$reason_file.tmp" "$reason_file"
        kill -TERM "$worker_pid" 2>/dev/null || true
        sleep "$kill_grace_seconds"
        kill -KILL "$worker_pid" 2>/dev/null || true
        exit 0
    done
) </dev/null >/dev/null 2>&1 &
watchdog_pid=$!

wait "$worker_pid"
worker_status=$?
worker_pid=
kill "$heartbeat_pid" "$watchdog_pid" 2>/dev/null || true
wait "$heartbeat_pid" 2>/dev/null || true
wait "$watchdog_pid" 2>/dev/null || true
heartbeat_pid=
watchdog_pid=

reason=none
[ -r "$reason_file" ] && reason=$(cat "$reason_file")
case "$reason" in
    build-timeout|heartbeat-missing|heartbeat-stale)
        write_status timed_out "$reason"
        printf '%s database=%s phase=timed-out reason=%s\n' \
            "$(timestamp)" "$label" "$reason" >>"$progress_file"
        final_written=1
        exit 124
        ;;
esac
if [ "$worker_status" -ne 0 ]; then
    write_status failed "worker-exit-$worker_status"
    printf '%s database=%s phase=failed worker_exit=%s\n' \
        "$(timestamp)" "$label" "$worker_status" >>"$progress_file"
    final_written=1
    exit "$worker_status"
fi

write_status success none
printf '%s database=%s phase=complete\n' "$(timestamp)" "$label" >>"$progress_file"
final_written=1
exit 0
