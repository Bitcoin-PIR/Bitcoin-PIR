#!/bin/sh
# runit service: cloudflared tunnel (Phase 3.1).
#
# Lives at /etc/sv/cloudflared/run inside the initramfs. runsvdir
# (started by /sbin/bpir-tier3-init) execs this; if cloudflared exits,
# runit restarts it after a 1s delay.
#
# The token is sourced from /etc/cloudflared/tunnel.env, which the
# 96bpir-cloudflared dracut module bakes in from the build host's
# matching file. tunnel.env defines TUNNEL_TOKEN=<base64-jwt>.

# shellcheck shell=sh

# Source then explicitly export — `. /file` populates the shell's
# vars but does NOT export them, so a child process (cloudflared)
# launched via exec would not inherit TUNNEL_TOKEN unless we export.
. /etc/cloudflared/tunnel.env
export TUNNEL_TOKEN

if [ -z "$TUNNEL_TOKEN" ]; then
    echo "[cloudflared-run] FATAL: TUNNEL_TOKEN not set after sourcing tunnel.env" >&2
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
