#!/bin/sh
# runit finish hook for unified_server. Arguments follow runsv(8):
#   $1 = exit code, or -1 when signalled
#   $2 = wait status low byte (signal number for signal termination)

# shellcheck shell=sh

umask 077
BB=${BPIR_BUSYBOX:-/usr/bin/busybox}
RUN_ROOT=${BPIR_RUN_ROOT:-/run/bpir}
DIAG_ROOT=${BPIR_DIAG_ROOT:-/home/pir/data/.runtime/tier3}
SV=${BPIR_SV:-/usr/bin/sv}
BACKOFF_SECONDS=${BPIR_FINISH_BACKOFF_SECONDS:-5}
CURRENT_FILE=$RUN_ROOT/unified-server.current
READY_FILE=$RUN_ROOT/unified-server.ready
EXIT_CODE=${1:--1}
EXIT_SIGNAL=${2:-0}

atomic_line() {
    target=$1
    line=$2
    tmp=$target.tmp.$$
    printf '%s\n' "$line" > "$tmp" || return 1
    $BB sync -d "$tmp" || return 1
    $BB mv -f "$tmp" "$target" || return 1
    $BB sync -d "${target%/*}" || return 1
}

if [ -r "$CURRENT_FILE" ]; then
    current_line=$($BB cat "$CURRENT_FILE" 2>/dev/null) || current_line=
    # shellcheck disable=SC2046 # fixed six-field, root-owned control file
    set -- $current_line
    if [ "$#" -eq 6 ] && [ "$1" = bpir-current-v1 ]; then
        boot_id=$2
        attempt=$3
        pid=$4
        start_ticks=$5
        case "$boot_id" in
            ????????-????-????-????-????????????) ;;
            *) boot_id= ;;
        esac
        case "$boot_id" in *[!0-9a-f-]*) boot_id= ;; esac
        case "$attempt" in ''|*[!0-9]*) attempt= ;; esac
        if [ -n "$boot_id" ] && [ -n "$attempt" ]; then
            attempt_dir=$DIAG_ROOT/$boot_id/attempt-$attempt
            if [ -d "$attempt_dir" ] && [ ! -L "$attempt_dir" ]; then
                atomic_line "$attempt_dir/exit.meta" \
                    "schema=bpir-exit-v1 code=$EXIT_CODE signal=$EXIT_SIGNAL pid=$pid start_ticks=$start_ticks" \
                    || echo "[unified-server-finish] WARN: could not persist exit metadata" >&2
            fi
        fi

        if [ -r "$READY_FILE" ]; then
            # Remove ready only when it belongs to the process that just exited.
            # shellcheck disable=SC2046 # fixed six-field, root-owned control file
            set -- $($BB cat "$READY_FILE" 2>/dev/null)
            if [ "$#" -eq 6 ] && [ "$1" = bpir-ready-v1 ] && \
                [ "$2" = "$boot_id" ] && [ "$3" = "$attempt" ] && \
                [ "$4" = "$pid" ] && [ "$5" = "$start_ticks" ]; then
                $BB rm -f "$READY_FILE"
            fi
        fi

        # A subsequent run can fail before publishing its own current tuple.
        # Remove this tuple only if it still belongs to the attempt we just
        # handled, so such a pre-publish failure cannot overwrite exit.meta for
        # the previous attempt.
        if [ "$($BB cat "$CURRENT_FILE" 2>/dev/null || true)" = "$current_line" ]; then
            $BB rm -f "$CURRENT_FILE"
        fi
    fi
fi

# Force cloudflared back through its readiness gate on the next server attempt.
"$SV" term cloudflared >/dev/null 2>&1 || true

# Prevent a panic/abort/configuration failure from creating a one-second loop.
if [ "$EXIT_CODE" != 0 ] || [ "$EXIT_SIGNAL" != 0 ]; then
    case "$BACKOFF_SECONDS" in ''|*[!0-9]*) BACKOFF_SECONDS=5 ;; esac
    $BB sleep "$BACKOFF_SECONDS"
fi

exit 0
