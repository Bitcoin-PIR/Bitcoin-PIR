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
PIR2_SEALED_ATTEMPT_DIR=${BPIR_PIR2_SNP_SEALED_ATTEMPT_ROOT:-/run/bitcoinpir-pir2-sealed}
PIR2_SEALED_INERT_SUCCESS_EXIT_CODE=42

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

read_exact_attempt_token_value() {
    token_path=$1
    token_key=$2
    awk -F= -v key="$token_key" '
        $1 == key { if (++seen == 1) value = substr($0, length(key) + 2); else exit 2 }
        END { if (seen != 1 || value == "") exit 1; print value }
    ' "$token_path"
}

canonical_nonzero_lower_hex() {
    token_hex=$1
    token_hex_length=$2
    case "$token_hex" in *[!0-9a-f]*|'') return 1 ;; esac
    [ "${#token_hex}" -eq "$token_hex_length" ] || return 1
    case "$token_hex" in *[1-9a-f]*) ;; *) return 1 ;; esac
}

sealed_terminal_token_matches_current_boot() {
    [ "${1:-}" = "$PIR2_SEALED_INERT_SUCCESS_EXIT_CODE" ] || return 1
    boot_id=$(cat "$ORAM_BOOT_ID_FILE" 2>/dev/null || true)
    case "$boot_id" in
        ????????-????-????-????-????????????) ;;
        *) return 1 ;;
    esac
    case "$boot_id" in *[!0-9a-f-]*) return 1 ;; esac
    boot_id_hex=$(printf '%s' "$boot_id" | tr -d -)
    [ -d "$PIR2_SEALED_ATTEMPT_DIR" ] && [ ! -L "$PIR2_SEALED_ATTEMPT_DIR" ] || return 1
    token="$PIR2_SEALED_ATTEMPT_DIR/terminal-$boot_id_hex.env"
    [ -f "$token" ] && [ ! -L "$token" ] && [ -r "$token" ] || return 1
    token_lines=$(wc -l <"$token" | tr -d '[:space:]')
    [ "$token_lines" = 11 ] || return 1
    token_schema=$(read_exact_attempt_token_value "$token" schema) || return 1
    token_kind=$(read_exact_attempt_token_value "$token" kind) || return 1
    token_phase=$(read_exact_attempt_token_value "$token" phase) || return 1
    token_boot_id=$(read_exact_attempt_token_value "$token" boot_id) || return 1
    token_ordinal=$(read_exact_attempt_token_value "$token" ordinal) || return 1
    token_nonce=$(read_exact_attempt_token_value "$token" verifier_nonce_hex) || return 1
    token_policy=$(read_exact_attempt_token_value "$token" current_policy_digest_hex) || return 1
    token_class=$(read_exact_attempt_token_value "$token" class_digest_hex) || return 1
    token_minimum_epoch=$(read_exact_attempt_token_value "$token" minimum_authorization_epoch) || return 1
    token_receipt_digest=$(read_exact_attempt_token_value "$token" receipt_protocol_digest) || return 1
    token_receipt_sha256=$(read_exact_attempt_token_value "$token" receipt_file_sha256) || return 1
    [ "$token_schema" = bitcoinpir-pir2-sealed-authoritative-attempt-v1 ] || return 1
    [ "$token_kind" = terminal ] || return 1
    case "$token_phase" in observe|enroll|probe) ;; *) return 1 ;; esac
    [ "$token_boot_id" = "$boot_id_hex" ] || return 1
    case "$token_ordinal:$token_minimum_epoch" in
        *[!0-9:]*|0:*|*:0) return 1 ;;
    esac
    canonical_nonzero_lower_hex "$token_nonce" 64 || return 1
    canonical_nonzero_lower_hex "$token_policy" 64 || return 1
    canonical_nonzero_lower_hex "$token_class" 64 || return 1
    canonical_nonzero_lower_hex "$token_receipt_digest" 64 || return 1
    canonical_nonzero_lower_hex "$token_receipt_sha256" 64 || return 1
}

mkdir -p "$STATE_DIR" || exit 0

# Observe/enroll/probe exit 42 is terminal only when the run script published a
# distinct current-boot authoritative token in trusted /run after the measured
# child succeeded. Persistent audit markers never authorize this branch; an
# unbound/spoofed exit 42 follows the ordinary bounded failure counter.
if sealed_terminal_token_matches_current_boot "${1:-}"; then
    if mkdir -p "$STATUS_DIR" 2>/dev/null; then
        {
            printf 'status=restart_suppressed\n'
            printf 'failure_count=0\n'
            printf 'max_failures=%s\n' "$MAX_FAILURES"
            printf 'failure_window_seconds=%s\n' "$FAILURE_WINDOW_SECONDS"
            printf 'last_failure_at_epoch=0\n'
            printf 'exit_code=%s\n' "$PIR2_SEALED_INERT_SUCCESS_EXIT_CODE"
            printf 'signal=%s\n' "${2:-unknown}"
            printf 'action=down\n'
            printf 'reason=pir2-sealed-inert-success\n'
        } >"$STATUS_DIR/unified-server-runit.status.tmp"
        mv "$STATUS_DIR/unified-server-runit.status.tmp" "$STATUS_DIR/unified-server-runit.status"
    fi
    echo "[unified-server-finish] suppressing restart: pir2-sealed-inert-success" >&2
    "$SV_BIN" -w 1 down "$SERVICE_DIR" >/dev/null 2>&1 || true
    exit 0
fi

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
