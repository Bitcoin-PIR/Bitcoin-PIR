#!/bin/sh
# runit service: BitcoinPIR unified_server.
#
# Lives at /etc/sv/unified_server/run inside the initramfs. runsvdir
# starts this; runit restarts on exit (1s default backoff).
#
# Flags mirror deploy/systemd/pir-vpsbg.service:
#   --port 8091
#   --role secondary   (DPF queries + HarmonyPIR query phase, no OnionPIR)
#   --serve-queries    (pir2 is queries-only per the production topology
#                       — see memory: project_pir1_hint_pir2_query_split.md.
#                       No --serve-hints, no --pool-size: hints come from
#                       pir1/Hetzner instead. Required by the startup
#                       validation in unified_server::main since 2026-05-13;
#                       without it the binary exits code 2 → runit crash-loop.)
#   --config /home/pir/data/databases.toml   (loaded from rootfs via
#                                             bpir-tier3-init's bind mount)
#   --direct-oram-db 0=... / 1=...
#                       direct ORAM images stay on the bind-mounted rootfs, but
#                       these paths and ORAM runtime parameters are baked into
#                       the measured UKI run script.
#   --admin-pubkey-hex <op key>   (auth for REQ_ADMIN_DB_UPLOAD etc.)
#
# Runs as root — Tier 3 initramfs has no /etc/passwd, so dropping
# privs to a `pir` user via chpst -u would need an `/etc/passwd`
# file with a numeric UID. Punted to a future hardening pass.
# /dev/sev-guest is owned root:root 0600 by default, so root access
# is required to read attestation reports anyway.

# shellcheck shell=sh

umask 077
BB=/usr/bin/busybox
RUN_ROOT=/run/bpir
DIAG_ROOT=/home/pir/data/.runtime/tier3
CURRENT_FILE=$RUN_ROOT/unified-server.current
READY_FILE=$RUN_ROOT/unified-server.ready
ATTEMPT_COUNTER=$RUN_ROOT/unified-server.attempt
MAX_ATTEMPTS=16

atomic_line() {
    target=$1
    line=$2
    tmp=$target.tmp.$$
    printf '%s\n' "$line" > "$tmp" || return 1
    # BusyBox `sync -d` maps to fdatasync(2) for this one path. Never use
    # `sync -f` here: that maps to syncfs(2) and would flush the filesystem
    # containing the large ORAM images while we are trying to diagnose it.
    $BB sync -d "$tmp" || return 1
    $BB mv -f "$tmp" "$target" || return 1
    $BB sync -d "${target%/*}" || return 1
}

fatal() {
    echo "[unified-server-run] FATAL: $1" >&2
    $BB sleep 5
    exit 1
}

[ -d "$RUN_ROOT" ] && [ ! -L "$RUN_ROOT" ] || fatal "$RUN_ROOT unavailable or unsafe"
[ -d "$DIAG_ROOT" ] && [ ! -L "$DIAG_ROOT" ] || fatal "$DIAG_ROOT unavailable or unsafe"

BOOT_ID=$($BB cat "$RUN_ROOT/boot-id" 2>/dev/null) || fatal "boot ID unavailable"
case "$BOOT_ID" in
    ????????-????-????-????-????????????) ;;
    *) fatal "boot ID has invalid shape" ;;
esac
case "$BOOT_ID" in *[!0-9a-f-]*) fatal "boot ID contains invalid characters" ;; esac

previous_attempt=0
if [ -r "$ATTEMPT_COUNTER" ]; then
    previous_attempt=$($BB cat "$ATTEMPT_COUNTER" 2>/dev/null) || fatal "attempt counter unreadable"
    case "$previous_attempt" in ''|*[!0-9]*) fatal "attempt counter invalid" ;; esac
fi
ATTEMPT=$((previous_attempt + 1))
if [ "$ATTEMPT" -gt "$MAX_ATTEMPTS" ]; then
    echo "[unified-server-run] FATAL: more than $MAX_ATTEMPTS attempts in one boot; preserving evidence" >&2
    while :; do $BB sleep 300; done
fi
atomic_line "$ATTEMPT_COUNTER" "$ATTEMPT" || fatal "attempt counter could not be persisted"

BOOT_DIR=$DIAG_ROOT/$BOOT_ID
[ -d "$BOOT_DIR" ] && [ ! -L "$BOOT_DIR" ] || fatal "boot diagnostics directory unavailable"
ATTEMPT_DIR=$BOOT_DIR/attempt-$ATTEMPT
$BB mkdir "$ATTEMPT_DIR" || fatal "attempt diagnostics directory already exists or cannot be created"
$BB chmod 0700 "$ATTEMPT_DIR" || fatal "attempt diagnostics permissions could not be set"
$BB sync -d "$BOOT_DIR" || fatal "attempt diagnostics directory could not be synced"

# `exec` preserves both this shell's PID and process starttime. Publish them
# before any database/ORAM operation so the sibling watchdog can bind itself to
# exactly this runit attempt, including failures before Rust starts.
stat_line=$($BB cat "/proc/$$/stat" 2>/dev/null) || fatal "process stat unavailable"
stat_suffix=${stat_line##*) }
# shellcheck disable=SC2086 # intentional split of proc stat numeric fields
set -- $stat_suffix
[ "$#" -ge 20 ] || fatal "process stat is truncated"
shift 19
START_TICKS=$1
case "$START_TICKS" in ''|*[!0-9]*) fatal "process starttime invalid" ;; esac

$BB rm -f "$READY_FILE" "$RUN_ROOT"/.unified-server.ready.tmp.*
CURRENT="bpir-current-v1 $BOOT_ID $ATTEMPT $$ $START_TICKS 8091"
atomic_line "$CURRENT_FILE" "$CURRENT" || fatal "current attempt could not be published"
atomic_line "$ATTEMPT_DIR/runner.meta" \
    "schema=bpir-runner-v1 boot_id=$BOOT_ID attempt=$ATTEMPT pid=$$ start_ticks=$START_TICKS port=8091" \
    || fatal "runner metadata could not be persisted"

# Wait for the bind-mounted /home/pir/data to actually be available.
# The takeover init mounts it before starting runsvdir, but runit
# might race on cold-start. Give it a few seconds.
i=0
while [ ! -r /home/pir/data/databases.toml ] && [ "$i" -lt 30 ]; do
    sleep 0.5
    i=$((i + 1))
done
if [ ! -r /home/pir/data/databases.toml ]; then
    fatal "/home/pir/data/databases.toml missing — bind mount failed?"
fi

ORAM_FULL_DIR=/home/pir/data/oram/checkpoints/948454-direct-pack16-z2-div2-stash128-auth
ORAM_DELTA_DIR=/home/pir/data/oram/deltas/940611_948454_canonical-direct-pack16-z2-div2-stash128-auth

for dir in "$ORAM_FULL_DIR" "$ORAM_DELTA_DIR"; do
    if [ ! -d "$dir" ]; then
        fatal "direct ORAM image directory missing"
    fi
done

exec /usr/local/bin/unified_server \
    --port 8091 \
    --role secondary \
    --serve-queries \
    --config /home/pir/data/databases.toml \
    --direct-oram-db "0=$ORAM_FULL_DIR" \
    --direct-oram-db "1=$ORAM_DELTA_DIR" \
    --direct-oram-drain-per-access 2 \
    --direct-oram-access-budget 75 \
    --direct-oram-cache-levels 0 \
    --direct-oram-auth-store \
    --admin-pubkey-hex 87d454db85266e10e55ed8b68417de9d79ceb1d5d944bae831a7877627efdad3 \
    --vcek-dir /home/pir/data/vcek \
    --identity-key-path /home/pir/data/pir2-identity.key \
    --identity-cert-path /home/pir/data/pir2.cert \
    --identity-server-id pir2 \
    --startup-diagnostics-file "$ATTEMPT_DIR/events.log" \
    --startup-attempt "$ATTEMPT" \
    --ready-file "$READY_FILE" \
    2>&1
# --identity-* (operator-signed identity / REQ_ANNOUNCE): key + cert live
# in the bind-mounted rootfs /home/pir/data — NOT baked into the measured
# initramfs (only this run script + the binary are measured). Missing or
# inconsistent files are non-fatal (unified_server logs "Identity
# announce: DISABLED" and serves everything else), so this is safe to ship
# ahead of provisioning the files. server_id MUST be "pir2" to match the
# operator-signed cert.
