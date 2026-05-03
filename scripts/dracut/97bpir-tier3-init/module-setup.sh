#!/bin/bash
# dracut module-setup for bpir-tier3-init
#
# Bakes a runit-based PID 1 takeover into the initramfs. The kernel's
# `rdinit=/sbin/bpir-tier3-init` cmdline parameter (set by
# scripts/build_uki_tier3.sh) makes the kernel exec OUR script as PID
# 1 from the initramfs, completely bypassing dracut's /init script.
#
# Why bypass dracut's /init: Tier 3's whole point is to live entirely
# in the initramfs — no pivot to a rootfs, no /sysroot mount. Dracut's
# /init expects to find a real rootfs via cmdline `root=...` and
# switch_root into it. We want the opposite: stay here, bring up
# devices ourselves, supervise our long-lived processes, never pivot.
# `rdinit=` is the kernel-level escape hatch that gives us this.
#
# This module installs:
#   /sbin/bpir-tier3-init       — the takeover script (rdinit target)
#   /usr/bin/runit, runsvdir,   — runit supervisor binaries
#   runsv, sv, chpst
#   /etc/sv/cloudflared/run     — cloudflared service definition
#
# Plus dracut's standard `busybox` deps for ip / udhcpc / mount /
# modprobe etc.
#
# Phase 3.1 scope: only cloudflared. Phase 3.2 will add unified_server
# under /etc/sv/unified_server/ and a port-probe wait so cloudflared
# starts after unified_server is listening on 8091.
#
# Build-host prereq: `apt install runit` on pir2.

# shellcheck shell=bash

check() {
    # Module is opt-in via `--add bpir-tier3-init`. Refuse to install
    # if runit isn't on the build host — the alternative is silently
    # baking a UKI that won't boot.
    for b in runit runsvdir runsv sv chpst; do
        if ! command -v "$b" >/dev/null 2>&1; then
            derror "bpir-tier3-init: $b not in \$PATH on build host"
            derror "  install with: apt install runit"
            return 1
        fi
    done
    return 0
}

depends() {
    # busybox gives us udhcpc, ip, mount, modprobe, sleep, ln, mkdir,
    # and the udhcpc default.script that configures the interface
    # after a DHCP lease. base provides /bin/sh.
    echo "busybox base"
    return 0
}

install() {
    # ── runit binaries ──────────────────────────────────────────
    # Ubuntu's `runit` package puts these at /usr/bin/. inst_simple
    # follows the canonical path so they end up at the same location
    # in the initramfs (where /sbin/bpir-tier3-init expects them).
    for b in runit runsvdir runsv sv chpst; do
        path=$(command -v "$b")
        inst_simple "$path"
    done

    # ── Tools the init script invokes ───────────────────────────
    # ip / modprobe / mount / sleep / ln / mkdir / cat / sh come from
    # the busybox dependency or are baked in by base. Listing them
    # explicitly is idempotent (inst_multiple no-ops if already there).
    # nc is needed by cloudflared-run.sh's port-wait gate (Phase 3.2);
    # blkid for the FATAL-path diagnostic when rootfs mount fails.
    inst_multiple ip modprobe mount sleep ln mkdir cat sh nc blkid

    # udhcpc is a busybox applet, NOT a standalone binary on Ubuntu.
    # Bake busybox itself in (statically linked, ~1.5 MB) and create
    # a /sbin/udhcpc symlink to it. busybox dispatches based on argv[0].
    if [ -x /usr/bin/busybox ]; then
        inst_simple /usr/bin/busybox
        ln_r /usr/bin/busybox /sbin/udhcpc
    else
        derror "bpir-tier3-init: /usr/bin/busybox not found"
        derror "  install with: apt install busybox-static"
        return 1
    fi

    # Our own default.script — busybox's example simple.script has a
    # netmask-format bug (passes dotted-decimal to `ip addr add`).
    inst_simple "$moddir/udhcpc-default.script" /etc/udhcpc/default.script
    chmod 0755 "${initdir}/etc/udhcpc/default.script"

    # ── Takeover init (rdinit= target) ──────────────────────────
    inst_simple "$moddir/bpir-tier3-init.sh" /sbin/bpir-tier3-init

    # ── Service tree ────────────────────────────────────────────
    # /etc/sv/<service>/run is the runit convention. The takeover
    # init symlinks each /etc/sv/<service> into /etc/service/ at boot,
    # which is what runsvdir watches.
    inst_dir /etc/sv/cloudflared
    inst_simple "$moddir/cloudflared-run.sh" /etc/sv/cloudflared/run

    # Phase 3.2: unified_server service. Depends on the binary at
    # /usr/local/bin/unified_server which the 96bpir-unified-server
    # module bakes in. The run script gates on /home/pir/data/
    # databases.toml (bind-mounted by bpir-tier3-init) and exec's
    # the same flag set as deploy/systemd/pir-vpsbg.service.
    inst_dir /etc/sv/unified_server
    inst_simple "$moddir/unified-server-run.sh" /etc/sv/unified_server/run
}
