#!/bin/sh
# runit service: cloudflared tunnel (Phase 3.1).
#
# Lives at /etc/sv/cloudflared/run inside the initramfs. runsvdir
# (started by /sbin/bpir-tier3-init) execs this; if cloudflared exits,
# runit restarts it after a 1s delay.
#
# The token is sourced from /home/pir/data/cloudflared/tunnel.env on
# the rootfs partition, NOT from the initramfs cpio. The bind mount
# of /sysroot/home/pir/data → /home/pir/data is set up by
# /sbin/bpir-tier3-init before runsvdir takes over, so by the time
# this script runs the path is reachable (or the mount failed and
# we FATAL out — runit will keep restart-looping until the operator
# fixes it). tunnel.env defines TUNNEL_TOKEN=<base64-jwt>.
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

# Source then explicitly export — `. /file` populates the shell's
# vars but does NOT export them, so a child process (cloudflared)
# launched via exec would not inherit TUNNEL_TOKEN unless we export.
TUNNEL_ENV=/home/pir/data/cloudflared/tunnel.env
if [ ! -r "$TUNNEL_ENV" ]; then
    echo "[cloudflared-run] FATAL: $TUNNEL_ENV not readable" >&2
    echo "[cloudflared-run]   provision via Slice 2 SSH:" >&2
    echo "[cloudflared-run]   mkdir -p /home/pir/data/cloudflared && \\" >&2
    echo "[cloudflared-run]     cp /etc/cloudflared/tunnel.env /home/pir/data/cloudflared/" >&2
    sleep 5
    exit 1
fi
. "$TUNNEL_ENV"
export TUNNEL_TOKEN

if [ -z "$TUNNEL_TOKEN" ]; then
    echo "[cloudflared-run] FATAL: TUNNEL_TOKEN not set after sourcing $TUNNEL_ENV" >&2
    sleep 5
    exit 1
fi

# Wait for unified_server to listen on 8091 before starting cloudflared.
# Without this gate, the tunnel comes up to a dead origin and we serve
# 502s for the first ~10s of every boot. busybox nc supports -z (port
# scan, no data) — exit 0 if open, non-zero otherwise.
i=0
while ! nc -z 127.0.0.1 8091 2>/dev/null; do
    if [ "$i" -ge 60 ]; then
        echo "[cloudflared-run] WARN: unified_server still not listening on 8091 after 60s — starting cloudflared anyway" >&2
        break
    fi
    sleep 1
    i=$((i + 1))
done

# Match the systemd-canonical invocation form (deploy/systemd/cloudflared.service):
# rely on TUNNEL_TOKEN env var, NOT a `--token` CLI flag. cloudflared 2026.3.0's
# parser bails to `tunnel run --help` if `--token <value>` is placed between
# `tunnel` and `run` — the visible failure mode in the Phase 3.1 first attempt.
exec /usr/local/bin/cloudflared --no-autoupdate tunnel run 2>&1
