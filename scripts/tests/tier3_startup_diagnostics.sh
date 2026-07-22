#!/bin/sh
# Portable fixture tests for Tier 3 readiness and token parsing. Linux CI runs
# the same scripts against real /proc and the extracted initramfs as a second
# gate; this fixture covers tuple parsing and hostile input deterministically.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
READY_CHECK=$REPO_ROOT/scripts/dracut/97bpir-tier3-init/ready-check.sh
TOKEN_READER=$REPO_ROOT/scripts/dracut/97bpir-tier3-init/read-tunnel-token.sh
FINISH=$REPO_ROOT/scripts/dracut/97bpir-tier3-init/unified-server-finish.sh

TMP=$(mktemp -d "${TMPDIR:-/tmp}/bpir-tier3-diag.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

expect_fail() {
    if "$@"; then
        fail "command unexpectedly succeeded: $*"
    fi
}

cat > "$TMP/busybox" <<'EOF'
#!/bin/sh
applet=$1
shift
if [ "$applet" = readlink ] && [ "${1:-}" = -f ]; then
    shift
    exec realpath "$@"
fi
if [ "$applet" = sync ] && [ "${1:-}" = -d ]; then
    # macOS' fixture shim lacks BusyBox sync -d. Linux CI exercises the real
    # applet; this portable harness only models successful single-path sync.
    exit 0
fi
exec "$applet" "$@"
EOF
chmod 0755 "$TMP/busybox"

RUN_ROOT=$TMP/run
PROC_ROOT=$TMP/proc
SERVER_EXE=$TMP/unified_server
SERVER_REAL=$TMP/nix/store/unified_server
PID=4321
START_TICKS=987654
BOOT_ID=01234567-89ab-cdef-0123-456789abcdef
ATTEMPT=1
mkdir -p "$RUN_ROOT" "$PROC_ROOT/$PID" "${SERVER_REAL%/*}"
printf '#!/bin/sh\nexit 0\n' > "$SERVER_REAL"
chmod 0755 "$SERVER_REAL"
ln -s "$SERVER_REAL" "$SERVER_EXE"

# Fields after comm begin at field 3. S + 18 numeric fields precede field 22
# (starttime), which the production parser reads as suffix field 20.
printf '%s (unified server) S' "$PID" > "$PROC_ROOT/$PID/stat"
i=1
while [ "$i" -le 18 ]; do
    printf ' %s' "$i" >> "$PROC_ROOT/$PID/stat"
    i=$((i + 1))
done
printf ' %s 20 21\n' "$START_TICKS" >> "$PROC_ROOT/$PID/stat"
# /proc/<pid>/exe reports the canonical target even when the process was
# invoked through /usr/local/bin/unified_server, as in the Nix UKI.
ln -s "$SERVER_REAL" "$PROC_ROOT/$PID/exe"

write_current() {
    printf 'bpir-current-v1 %s %s %s %s 8091\n' \
        "$BOOT_ID" "$ATTEMPT" "$PID" "$START_TICKS" > "$RUN_ROOT/unified-server.current"
}
write_ready() {
    ready_attempt=$1
    ready_start=$2
    printf 'bpir-ready-v1 %s %s %s %s 8091\n' \
        "$BOOT_ID" "$ready_attempt" "$PID" "$ready_start" > "$RUN_ROOT/unified-server.ready"
}
run_ready_check() {
    BPIR_BUSYBOX=$TMP/busybox \
    BPIR_RUN_ROOT=$RUN_ROOT \
    BPIR_PROC_ROOT=$PROC_ROOT \
    BPIR_SERVER_EXE=$SERVER_EXE \
        "$READY_CHECK"
}

write_current
write_ready "$ATTEMPT" "$START_TICKS"
run_ready_check || fail "valid ready tuple was rejected"

write_ready 2 "$START_TICKS"
expect_fail run_ready_check
write_ready "$ATTEMPT" 999999
expect_fail run_ready_check
printf 'bpir-current-v1 %s %s %s %s 8091\n' \
    "$BOOT_ID" "$ATTEMPT" "$PID" 999999 > "$RUN_ROOT/unified-server.current"
write_ready "$ATTEMPT" 999999
expect_fail run_ready_check
write_current
printf 'bpir-ready-v1 truncated\n' > "$RUN_ROOT/unified-server.ready"
expect_fail run_ready_check
write_ready "$ATTEMPT" "$START_TICKS"
rm "$PROC_ROOT/$PID/exe"
ln -s "$TMP/foreign_server" "$PROC_ROOT/$PID/exe"
expect_fail run_ready_check
rm "$PROC_ROOT/$PID/exe"
ln -s "$SERVER_REAL" "$PROC_ROOT/$PID/exe"
run_ready_check || fail "restored executable tuple was rejected"

TOKEN_FILE=$TMP/tunnel.env
printf '# comment\n\nTUNNEL_TOKEN=abc.DEF_123-xyz=\n' > "$TOKEN_FILE"
token=$(BPIR_BUSYBOX=$TMP/busybox "$TOKEN_READER" "$TOKEN_FILE")
[ "$token" = 'abc.DEF_123-xyz=' ] || fail "valid token parsed incorrectly"

printf 'TUNNEL_TOKEN=one\nTUNNEL_TOKEN=two\n' > "$TOKEN_FILE"
expect_fail env BPIR_BUSYBOX=$TMP/busybox "$TOKEN_READER" "$TOKEN_FILE"
printf 'TUNNEL_TOKEN=$(touch /tmp/pwned)\n' > "$TOKEN_FILE"
expect_fail env BPIR_BUSYBOX=$TMP/busybox "$TOKEN_READER" "$TOKEN_FILE"
printf 'OTHER=value\nTUNNEL_TOKEN=valid\n' > "$TOKEN_FILE"
expect_fail env BPIR_BUSYBOX=$TMP/busybox "$TOKEN_READER" "$TOKEN_FILE"
printf 'TUNNEL_TOKEN=\n' > "$TOKEN_FILE"
expect_fail env BPIR_BUSYBOX=$TMP/busybox "$TOKEN_READER" "$TOKEN_FILE"

if grep -q 'nc -z' "$REPO_ROOT/scripts/dracut/97bpir-tier3-init/cloudflared-run.sh"; then
    fail "obsolete nc -z probe remains"
fi
if grep -q '^\. .*TUNNEL_ENV' "$REPO_ROOT/scripts/dracut/97bpir-tier3-init/cloudflared-run.sh"; then
    fail "tunnel environment is still sourced as shell"
fi

DIAG_ROOT=$TMP/diagnostics
mkdir -p "$DIAG_ROOT/$BOOT_ID/attempt-$ATTEMPT"
write_current
write_ready "$ATTEMPT" "$START_TICKS"
cat > "$TMP/sv" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "$TMP/sv"
BPIR_BUSYBOX=$TMP/busybox \
BPIR_RUN_ROOT=$RUN_ROOT \
BPIR_DIAG_ROOT=$DIAG_ROOT \
BPIR_SV=$TMP/sv \
BPIR_FINISH_BACKOFF_SECONDS=0 \
    "$FINISH" -1 6
[ ! -e "$RUN_ROOT/unified-server.ready" ] || fail "finish left matching ready marker"
[ ! -e "$RUN_ROOT/unified-server.current" ] || fail "finish left stale current tuple"
exit_meta=$DIAG_ROOT/$BOOT_ID/attempt-$ATTEMPT/exit.meta
[ -r "$exit_meta" ] || fail "finish did not persist exit metadata"
grep -q 'code=-1 signal=6' "$exit_meta" || fail "finish persisted wrong exit status"
exit_meta_before=$(cat "$exit_meta")
BPIR_BUSYBOX=$TMP/busybox \
BPIR_RUN_ROOT=$RUN_ROOT \
BPIR_DIAG_ROOT=$DIAG_ROOT \
BPIR_SV=$TMP/sv \
BPIR_FINISH_BACKOFF_SECONDS=0 \
    "$FINISH" 2 0
[ "$(cat "$exit_meta")" = "$exit_meta_before" ] \
    || fail "pre-current failure overwrote the previous attempt metadata"

# Linux-only real-/proc smoke test for the read-only watchdog snapshot path.
if [ -r /proc/uptime ] && command -v busybox >/dev/null 2>&1; then
    WATCHDOG=$REPO_ROOT/scripts/dracut/97bpir-tier3-init/startup-watchdog-run.sh
    sleep 30 &
    watched_pid=$!
    watched_stat=$(cat "/proc/$watched_pid/stat")
    watched_suffix=${watched_stat##*) }
    # shellcheck disable=SC2086 # intentional proc stat split
    set -- $watched_suffix
    shift 19
    watched_start=$1
    WATCH_RUN=$TMP/watch-run
    WATCH_DIAG=$TMP/watch-diag
    mkdir -p "$WATCH_RUN" "$WATCH_DIAG/$BOOT_ID/attempt-1"
    printf 'bpir-current-v1 %s 1 %s %s 8091\n' \
        "$BOOT_ID" "$watched_pid" "$watched_start" > "$WATCH_RUN/unified-server.current"
    BPIR_BUSYBOX=$(command -v busybox) \
    BPIR_RUN_ROOT=$WATCH_RUN \
    BPIR_DIAG_ROOT=$WATCH_DIAG \
    BPIR_READY_CHECK=/bin/false \
    BPIR_WATCHDOG_DELAYS=0 \
    BPIR_WATCHDOG_ONCE=1 \
        "$WATCHDOG"
    snapshot=$WATCH_DIAG/$BOOT_ID/attempt-1/watchdog-0000.txt
    [ -r "$snapshot" ] || fail "watchdog did not create snapshot"
    grep -q 'SNAPSHOT_COMPLETE=1' "$snapshot" || fail "watchdog snapshot is incomplete"
    if grep -qE '/(cmdline|environ)|TUNNEL_TOKEN|identity.*key' "$snapshot"; then
        fail "watchdog snapshot contains forbidden data source"
    fi

    rm "$snapshot"
    printf 'bpir-current-v1 %s 1 %s %s 8091\n' \
        "$BOOT_ID" "$watched_pid" "$((watched_start + 1))" \
        > "$WATCH_RUN/unified-server.current"
    BPIR_BUSYBOX=$(command -v busybox) \
    BPIR_RUN_ROOT=$WATCH_RUN \
    BPIR_DIAG_ROOT=$WATCH_DIAG \
    BPIR_READY_CHECK=/bin/false \
    BPIR_WATCHDOG_DELAYS=0 \
    BPIR_WATCHDOG_ONCE=1 \
        "$WATCHDOG"
    [ ! -e "$snapshot" ] || fail "watchdog sampled a mismatched process starttime"
    kill "$watched_pid" 2>/dev/null || true
    wait "$watched_pid" 2>/dev/null || true
fi

echo "Tier 3 startup diagnostics shell fixtures passed"
