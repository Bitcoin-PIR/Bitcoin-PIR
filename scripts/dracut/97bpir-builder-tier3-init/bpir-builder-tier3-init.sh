#!/bin/bash
# One-shot Tier 3 PID 1 for attested-builder.
#
# This UKI is not the production pir2 service image. It mounts the existing
# rootfs only to read snapshot/config inputs and to write build artifacts, then
# powers the VM off. Recovery path: switch VPSBG Measured Boot back to "None"
# and boot the normal rootfs.

set -u

PATH=/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
export PATH

halt_vm() {
    local status=${1:-0}
    sync || true
    echo "[bpir-builder-tier3-init] powering off with status $status"
    poweroff -f 2>/dev/null || /usr/bin/busybox poweroff -f 2>/dev/null ||
        reboot -f 2>/dev/null || /usr/bin/busybox reboot -f 2>/dev/null || true
    while true; do
        sleep 3600
    done
}

mount_pseudo_fs() {
    mount -t proc proc /proc 2>/dev/null || true
    mount -t sysfs sysfs /sys 2>/dev/null || true
    mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
    mkdir -p /dev/pts /run /tmp
    mount -t devpts devpts /dev/pts 2>/dev/null || true
    mount -t tmpfs tmpfs /run 2>/dev/null || true
    mount -t tmpfs -o size=512m tmpfs /tmp 2>/dev/null || true
}

mount_rootfs_data() {
    echo "--- mounting rootfs for /home/pir/data ---"
    modprobe virtio_blk 2>/dev/null || true
    modprobe ext4 2>/dev/null || true

    local i=0
    while [ "$i" -lt 30 ] && ! grep -qE "(vda|sda|nvme)" /proc/partitions; do
        sleep 0.2
        i=$((i + 1))
    done

    echo "--- /proc/partitions ---"
    cat /proc/partitions 2>/dev/null || true
    echo "--- blkid ---"
    blkid 2>&1 || true

    mkdir -p /sysroot
    local mounted=false
    local src flag
    for src in "LABEL=cloudimg-rootfs" /dev/vda1 /dev/sda1 /dev/vda /dev/sda; do
        case "$src" in
            LABEL=*) flag="-L ${src#LABEL=}" ;;
            *) flag="$src" ;;
        esac
        if mount $flag -o rw /sysroot 2>/dev/null; then
            echo "[bpir-builder-tier3-init] rootfs mounted at /sysroot via $src"
            mounted=true
            break
        fi
    done

    if [ "$mounted" != "true" ]; then
        echo "[bpir-builder-tier3-init] FATAL: rootfs mount failed" >&2
        halt_vm 1
    fi

    mkdir -p /home/pir/data
    if ! mount --bind /sysroot/home/pir/data /home/pir/data 2>&1; then
        echo "[bpir-builder-tier3-init] FATAL: bind mount /home/pir/data failed" >&2
        halt_vm 1
    fi
    mkdir -p /home/pir/data/attested-builder-runs
    echo "[bpir-builder-tier3-init] /home/pir/data bind-mounted rw"
}

load_sev_snp() {
    echo "--- loading SEV-SNP kernel modules ---"
    modprobe ccp 2>/dev/null || echo "[bpir-builder-tier3-init] WARN: modprobe ccp failed"
    modprobe sev-guest 2>/dev/null || echo "[bpir-builder-tier3-init] WARN: modprobe sev-guest failed"
    modprobe tsm_report 2>/dev/null || true

    echo "--- sev modules + device ---"
    grep -E "sev|ccp|tsm" /proc/modules 2>/dev/null ||
        echo "[bpir-builder-tier3-init] WARN: no sev/ccp modules in /proc/modules"
    if [ -c /dev/sev-guest ]; then
        ls -la /dev/sev-guest
        echo "[bpir-builder-tier3-init] /dev/sev-guest ready"
    else
        echo "[bpir-builder-tier3-init] FATAL: /dev/sev-guest missing" >&2
        halt_vm 1
    fi
}

mount_pseudo_fs
echo 0 > /proc/sys/kernel/sysrq 2>/dev/null || true
echo 0 > /proc/sys/kernel/ctrl-alt-del 2>/dev/null || true

mount_rootfs_data
load_sev_snp

LOG=/home/pir/data/attested-builder-runs/builder-tier3-init.log
echo "[bpir-builder-tier3-init] starting builder runner; log=$LOG"
set +e
/usr/local/bin/bpir-builder-run 2>&1 | tee -a "$LOG"
runner_status=${PIPESTATUS[0]}
set -e

if [ "$runner_status" -eq 0 ]; then
    echo "[bpir-builder-tier3-init] builder completed successfully"
else
    echo "[bpir-builder-tier3-init] builder failed with status $runner_status" >&2
fi

halt_vm "$runner_status"
