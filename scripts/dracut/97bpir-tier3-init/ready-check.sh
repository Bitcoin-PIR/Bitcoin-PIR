#!/bin/sh
# Validate the complete measured-server readiness tuple.
#
# The Rust server publishes the ready marker only after startup and bind. This
# checker additionally binds it to the current runit attempt and live process,
# preventing stale files, PID reuse, or an unrelated listener from releasing
# cloudflared.

# shellcheck shell=sh

BB=${BPIR_BUSYBOX:-/usr/bin/busybox}
RUN_ROOT=${BPIR_RUN_ROOT:-/run/bpir}
PROC_ROOT=${BPIR_PROC_ROOT:-/proc}
SERVER_EXE=${BPIR_SERVER_EXE:-/usr/local/bin/unified_server}
CURRENT_FILE=$RUN_ROOT/unified-server.current
READY_FILE=$RUN_ROOT/unified-server.ready

read_tuple() {
    file=$1
    expected_schema=$2
    [ -r "$file" ] || return 1
    # shellcheck disable=SC2046 # fixed six-field, root-owned control file
    set -- $($BB cat "$file" 2>/dev/null) || return 1
    [ "$#" -eq 6 ] || return 1
    [ "$1" = "$expected_schema" ] || return 1
    T_BOOT_ID=$2
    T_ATTEMPT=$3
    T_PID=$4
    T_START_TICKS=$5
    T_PORT=$6
    case "$T_BOOT_ID" in
        ????????-????-????-????-????????????) ;;
        *) return 1 ;;
    esac
    case "$T_BOOT_ID" in *[!0-9a-f-]*) return 1 ;; esac
    for value in "$T_ATTEMPT" "$T_PID" "$T_START_TICKS" "$T_PORT"; do
        case "$value" in ''|*[!0-9]*) return 1 ;; esac
    done
    [ "$T_ATTEMPT" -gt 0 ] && [ "$T_PID" -gt 0 ] && [ "$T_START_TICKS" -gt 0 ] || return 1
    [ "$T_PORT" -eq 8091 ] || return 1
    return 0
}

read_tuple "$CURRENT_FILE" bpir-current-v1 || exit 1
C_BOOT_ID=$T_BOOT_ID
C_ATTEMPT=$T_ATTEMPT
C_PID=$T_PID
C_START_TICKS=$T_START_TICKS
C_PORT=$T_PORT

read_tuple "$READY_FILE" bpir-ready-v1 || exit 1
[ "$T_BOOT_ID" = "$C_BOOT_ID" ] || exit 1
[ "$T_ATTEMPT" = "$C_ATTEMPT" ] || exit 1
[ "$T_PID" = "$C_PID" ] || exit 1
[ "$T_START_TICKS" = "$C_START_TICKS" ] || exit 1
[ "$T_PORT" = "$C_PORT" ] || exit 1

[ -r "$PROC_ROOT/$C_PID/stat" ] || exit 1
stat_line=$($BB cat "$PROC_ROOT/$C_PID/stat" 2>/dev/null) || exit 1
stat_suffix=${stat_line##*) }
# Fields after comm begin at field 3; process starttime is field 22, hence 20.
# shellcheck disable=SC2086 # intentional split of proc stat numeric fields
set -- $stat_suffix
[ "$#" -ge 20 ] || exit 1
shift 19
[ "$1" = "$C_START_TICKS" ] || exit 1

# Nix assembles /usr/local/bin/unified_server as a symlink into /nix/store,
# while /proc/<pid>/exe exposes the resolved store path. Compare canonical
# targets so both the Nix and dracut initramfs layouts pass, but a foreign
# executable with the same PID tuple cannot release the tunnel.
expected_exe=$($BB readlink -f "$SERVER_EXE" 2>/dev/null) || exit 1
actual_exe=$($BB readlink -f "$PROC_ROOT/$C_PID/exe" 2>/dev/null) || exit 1
[ "$actual_exe" = "$expected_exe" ] || exit 1

exit 0
