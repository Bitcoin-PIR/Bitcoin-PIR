#!/bin/sh
# Read-only startup watchdog for the measured unified_server.
#
# It never opens ORAM files, sends requests, or controls the server. If the
# current attempt has not published a valid ready marker at 30/60/180 seconds,
# it persists a bounded /proc snapshot outside all database/ORAM directories.

# shellcheck shell=sh

umask 077
BB=${BPIR_BUSYBOX:-/usr/bin/busybox}
RUN_ROOT=${BPIR_RUN_ROOT:-/run/bpir}
DIAG_ROOT=${BPIR_DIAG_ROOT:-/home/pir/data/.runtime/tier3}
CURRENT_FILE=$RUN_ROOT/unified-server.current
READY_CHECK=${BPIR_READY_CHECK:-/usr/local/bin/bpir-ready-check}
PROC_ROOT=${BPIR_PROC_ROOT:-/proc}
SERVER_EXE=${BPIR_SERVER_EXE:-/usr/local/bin/unified_server}
WATCHDOG_DELAYS=${BPIR_WATCHDOG_DELAYS:-"30 60 180"}
WATCHDOG_ONCE=${BPIR_WATCHDOG_ONCE:-0}
LAST_CURRENT=

uptime_seconds() {
    value=$($BB cat "$PROC_ROOT/uptime" 2>/dev/null) || return 1
    value=${value%%.*}
    case "$value" in ''|*[!0-9]*) return 1 ;; esac
    printf '%s\n' "$value"
}

process_start_matches() {
    pid=$1
    expected_start_ticks=$2
    stat_line=$($BB cat "$PROC_ROOT/$pid/stat" 2>/dev/null) || return 1
    stat_suffix=${stat_line##*) }
    # shellcheck disable=SC2086 # intentional split of proc stat fields
    set -- $stat_suffix
    [ "$#" -ge 20 ] || return 1
    shift 19
    [ "$1" = "$expected_start_ticks" ]
}

process_exe_state() {
    pid=$1
    expected=$($BB readlink -f "$SERVER_EXE" 2>/dev/null) || {
        printf 'unavailable\n'
        return
    }
    actual=$($BB readlink -f "$PROC_ROOT/$pid/exe" 2>/dev/null) || {
        printf 'unavailable\n'
        return
    }
    if [ "$actual" = "$expected" ]; then
        printf 'unified_server\n'
    else
        # Do not persist either path: a pre-exec runner is useful evidence,
        # while a foreign path could disclose unmeasured host information.
        printf 'other\n'
    fi
}

current_is() {
    expected=$1
    actual=$($BB cat "$CURRENT_FILE" 2>/dev/null) || return 1
    [ "$actual" = "$expected" ]
}

proc_section() {
    label=$1
    file=$2
    printf '\n[%s]\n' "$label"
    $BB timeout 2 $BB cat "$file" 2>&1 || printf 'unavailable\n'
}

persist_snapshot() {
    delay=$1
    current=$2
    attempt_dir=$3
    pid=$4
    start_ticks=$5
    final=$attempt_dir/watchdog-$(printf '%04d' "$delay").txt
    raw=$final.raw.$$
    synced=$final.tmp.$$

    current_is "$current" || return 0
    process_start_matches "$pid" "$start_ticks" || return 0
    {
        printf 'schema=bpir-watchdog-v1 delay_s=%s pid=%s start_ticks=%s\n' \
            "$delay" "$pid" "$start_ticks"
        now=$(uptime_seconds 2>/dev/null || printf 'unknown')
        printf 'uptime_s=%s\n' "$now"
        printf 'process_exe=%s\n' "$(process_exe_state "$pid")"
        printf '\n[last_startup_events]\n'
        $BB tail -n 16 "$attempt_dir/events.log" 2>&1 || printf 'unavailable\n'

        proc_section process_status "$PROC_ROOT/$pid/status"
        proc_section process_stat "$PROC_ROOT/$pid/stat"
        proc_section process_io "$PROC_ROOT/$pid/io"
        proc_section process_wchan "$PROC_ROOT/$pid/wchan"
        proc_section process_syscall "$PROC_ROOT/$pid/syscall"
        proc_section process_stack "$PROC_ROOT/$pid/stack"

        printf '\n[threads]\n'
        thread_count=0
        for task in "$PROC_ROOT/$pid"/task/[0-9]*; do
            [ -d "$task" ] || continue
            thread_count=$((thread_count + 1))
            [ "$thread_count" -le 128 ] || {
                printf 'thread_limit_reached=128\n'
                break
            }
            tid=${task##*/}
            printf '\n[thread tid=%s]\n' "$tid"
            $BB timeout 2 $BB cat "$task/comm" "$task/status" "$task/wchan" \
                "$task/syscall" "$task/stack" 2>&1 || printf 'thread_data_incomplete\n'
        done

        proc_section meminfo "$PROC_ROOT/meminfo"
        proc_section pressure_cpu "$PROC_ROOT/pressure/cpu"
        proc_section pressure_memory "$PROC_ROOT/pressure/memory"
        proc_section pressure_io "$PROC_ROOT/pressure/io"
        proc_section entropy_avail "$PROC_ROOT/sys/kernel/random/entropy_avail"

        printf '\n[port_8091_tcp]\n'
        $BB head -n 1 "$PROC_ROOT/net/tcp" 2>/dev/null || true
        $BB grep -i ':1F9B ' "$PROC_ROOT/net/tcp" 2>/dev/null || printf 'none\n'
        printf '\n[port_8091_tcp6]\n'
        $BB head -n 1 "$PROC_ROOT/net/tcp6" 2>/dev/null || true
        $BB grep -i ':1F9B ' "$PROC_ROOT/net/tcp6" 2>/dev/null || printf 'none\n'

        printf '\n[data_mount]\n'
        $BB grep ' /home/pir/data ' "$PROC_ROOT/self/mountinfo" 2>/dev/null || printf 'unavailable\n'
        printf '\n[kernel_filtered]\n'
        $BB dmesg 2>/dev/null \
            | $BB grep -Ei 'out of memory|killed process|segfault|i/o error|ext4-fs error|hung task|random:|crng|rng' \
            | $BB tail -n 200 || true
        printf '\nSNAPSHOT_COMPLETE=1\n'
    } > "$raw"

    current_is "$current" || {
        $BB rm -f "$raw"
        return 0
    }
    process_start_matches "$pid" "$start_ticks" || {
        $BB rm -f "$raw"
        return 0
    }
    # dd conv=fsync gives a file-level durability point without globally
    # flushing the filesystem that also contains the ORAM images.
    $BB dd if="$raw" of="$synced" bs=4096 conv=fsync 2>/dev/null || {
        $BB rm -f "$raw" "$synced"
        return 1
    }
    $BB mv -f "$synced" "$final" || return 1
    $BB sync -d "$attempt_dir" || return 1
    $BB rm -f "$raw"
    return 0
}

monitor_attempt() {
    current=$1
    # shellcheck disable=SC2086 # intentional split of fixed control tuple
    set -- $current
    [ "$#" -eq 6 ] && [ "$1" = bpir-current-v1 ] || return 0
    boot_id=$2
    attempt=$3
    pid=$4
    start_ticks=$5
    case "$boot_id" in
        ????????-????-????-????-????????????) ;;
        *) return 0 ;;
    esac
    case "$boot_id" in *[!0-9a-f-]*) return 0 ;; esac
    for value in "$attempt" "$pid" "$start_ticks"; do
        case "$value" in ''|*[!0-9]*) return 0 ;; esac
    done
    attempt_dir=$DIAG_ROOT/$boot_id/attempt-$attempt
    [ -d "$attempt_dir" ] && [ ! -L "$attempt_dir" ] || return 0

    started=$(uptime_seconds) || return 0
    for delay in $WATCHDOG_DELAYS; do
        case "$delay" in ''|*[!0-9]*) return 0 ;; esac
        deadline=$((started + delay))
        while :; do
            if "$READY_CHECK"; then
                printf 'schema=bpir-watchdog-ready-v1 delay_limit_s=%s\n' "$delay" \
                    > "$attempt_dir/watchdog-ready.meta"
                $BB sync -d "$attempt_dir/watchdog-ready.meta" 2>/dev/null || true
                return 0
            fi
            current_is "$current" || return 0
            process_start_matches "$pid" "$start_ticks" || return 0
            now=$(uptime_seconds) || return 0
            [ "$now" -ge "$deadline" ] && break
            $BB sleep 1
        done
        persist_snapshot "$delay" "$current" "$attempt_dir" "$pid" "$start_ticks" \
            || echo "[startup-watchdog] WARN: snapshot at ${delay}s failed" >&2
    done
    return 0
}

while :; do
    current=$($BB cat "$CURRENT_FILE" 2>/dev/null || true)
    if [ -n "$current" ] && [ "$current" != "$LAST_CURRENT" ]; then
        LAST_CURRENT=$current
        monitor_attempt "$current"
        [ "$WATCHDOG_ONCE" = 1 ] && exit 0
    fi
    $BB sleep 1
done
