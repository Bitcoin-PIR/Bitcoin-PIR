#!/bin/sh
# runit service: cloudflared tunnel (Phase 3.1).
#
# Lives at /etc/sv/cloudflared/run inside the initramfs. runsvdir
# (started by /sbin/bpir-tier3-init) execs this; if cloudflared exits,
# runit restarts it after a 1s delay.
#
# The token is parsed from /home/pir/data/cloudflared/tunnel.env on
# the rootfs partition, NOT from the initramfs cpio. The bind mount
# of /sysroot/home/pir/data → /home/pir/data is set up by
# /sbin/bpir-tier3-init before runsvdir takes over, so by the time
# this script runs the path is reachable (or the mount failed and
# we FATAL out — runit will keep restart-looping until the operator
# fixes it). tunnel.env contains TUNNEL_TOKEN=<base64-jwt>, treated strictly
# as data and never evaluated as shell.
#
# Why runtime-sourced: keeping the token out of the cpio means the
# UKI bytes (and therefore MEASUREMENT) are operator-agnostic — see
# docs/PHASE3_SLICE3_REPRO_PLAN.md sub-task 3 (option b). Trade-off
# vs the old in-cpio path: if the rootfs mount fails we lose the
# tunnel entirely (vs the old "tunnel up to dead origin → 502
# observable" failure mode), but unified_server can't run without
# the rootfs anyway, so the box is broken either way and the
# observability difference is moot.

# shellcheck shell=sh

umask 077
BB=/usr/bin/busybox
READY_CHECK=/usr/local/bin/bpir-ready-check
TOKEN_READER=/usr/local/bin/bpir-read-tunnel-token

# Wait for the exact measured unified_server attempt to finish all startup
# work and publish its ready tuple. There is deliberately no timeout path that
# starts a tunnel to a dead or foreign origin: the sibling watchdog preserves
# diagnostics at 30/60/180 seconds while this service remains closed.
while ! "$READY_CHECK"; do
    $BB sleep 1
done

# The token lives on the unmeasured writable rootfs. Treat the file strictly as
# data; sourcing it as shell would grant arbitrary root code execution to any
# rootfs writer. Read it only after server readiness, accept exactly one
# TUNNEL_TOKEN line, and reject all other non-comment content.
TUNNEL_ENV=/home/pir/data/cloudflared/tunnel.env
if [ ! -r "$TUNNEL_ENV" ]; then
    echo "[cloudflared-run] FATAL: $TUNNEL_ENV not readable" >&2
    echo "[cloudflared-run]   provision via Slice 2 SSH:" >&2
    echo "[cloudflared-run]   mkdir -p /home/pir/data/cloudflared && \\" >&2
    echo "[cloudflared-run]     cp /etc/cloudflared/tunnel.env /home/pir/data/cloudflared/" >&2
    $BB sleep 5
    exit 1
fi
TUNNEL_TOKEN=$("$TOKEN_READER" "$TUNNEL_ENV") || {
    echo "[cloudflared-run] FATAL: $TUNNEL_ENV must contain exactly one valid TUNNEL_TOKEN line" >&2
    $BB sleep 5
    exit 1
}
[ -n "$TUNNEL_TOKEN" ] || {
    echo "[cloudflared-run] FATAL: parsed tunnel token is empty" >&2
    $BB sleep 5
    exit 1
}
export TUNNEL_TOKEN

# Match the systemd-canonical invocation form (deploy/systemd/cloudflared.service):
# rely on TUNNEL_TOKEN env var, NOT a `--token` CLI flag. cloudflared 2026.3.0's
# parser bails to `tunnel run --help` if `--token <value>` is placed between
# `tunnel` and `run` — the visible failure mode in the Phase 3.1 first attempt.
exec /usr/local/bin/cloudflared --no-autoupdate tunnel run 2>&1
