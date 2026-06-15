#!/bin/bash
# dracut module-setup for the one-shot attested-builder Tier 3 init.
#
# This installs a tiny PID 1 takeover plus the shell/coreutils needed by
# scripts/build-snapshot-database.sh. There is intentionally no sshd,
# cloudflared, or runit service tree in this UKI.

# shellcheck shell=bash

check() {
    local b
    for b in bash awk sort find tee date sed diff wc tr dirname basename \
        mktemp mv chmod rm mkdir cp ln sha256sum df sync blkid grep cut cat \
        sleep mount modprobe ls; do
        if ! command -v "$b" >/dev/null 2>&1; then
            derror "bpir-builder-tier3-init: $b not in PATH on build host"
            return 1
        fi
    done
    if [ ! -x /usr/bin/busybox ]; then
        derror "bpir-builder-tier3-init: /usr/bin/busybox not found"
        derror "  install with: apt install busybox-static"
        return 1
    fi
    return 0
}

depends() {
    echo "busybox base"
    return 0
}

install() {
    inst_multiple bash env awk sort find tee date sed diff wc tr dirname \
        basename mktemp mv chmod rm mkdir cp ln sha256sum df sync blkid grep \
        cut cat sleep mount modprobe ls sh

    # Use busybox for the hard-stop path; systemd poweroff is not available in
    # this no-systemd initramfs.
    inst_simple /usr/bin/busybox
    ln_r /usr/bin/busybox /sbin/poweroff
    ln_r /usr/bin/busybox /sbin/reboot

    inst_simple "$moddir/bpir-builder-tier3-init.sh" /sbin/bpir-builder-tier3-init
    inst_simple "$moddir/bpir-builder-run.sh" /usr/local/bin/bpir-builder-run
    chmod 0755 "${initdir}/sbin/bpir-builder-tier3-init"
    chmod 0755 "${initdir}/usr/local/bin/bpir-builder-run"
}
