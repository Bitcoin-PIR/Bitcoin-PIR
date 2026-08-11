#!/bin/bash
# One-shot PID 1 for the Direct ORAM TEE debug UKI.

set -u

PATH=/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
export PATH

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts /run /tmp
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
mount -t tmpfs -o size=512m tmpfs /tmp 2>/dev/null || true
echo 0 >/proc/sys/kernel/sysrq 2>/dev/null || true
echo 0 >/proc/sys/kernel/ctrl-alt-del 2>/dev/null || true

modprobe virtio_net 2>/dev/null || true
modprobe virtio_pci 2>/dev/null || true
modprobe virtio_blk 2>/dev/null || true
modprobe ext4 2>/dev/null || true

ip link set lo up 2>/dev/null || true
i=0
while [ ! -d /sys/class/net/eth0 ] && [ "$i" -lt 60 ]; do
    sleep 0.2
    i=$((i + 1))
done
if [ -d /sys/class/net/eth0 ]; then
    ip link set eth0 up || true
    ip addr add 87.120.8.198/32 dev eth0 || true
    ip route add default via 172.16.0.1 dev eth0 onlink || true
fi

i=0
while [ "$i" -lt 30 ] && ! grep -qE '(vda|sda|nvme)' /proc/partitions; do
    sleep 0.2
    i=$((i + 1))
done
mkdir -p /sysroot
mounted=false
for src in "LABEL=cloudimg-rootfs" /dev/vda1 /dev/sda1 /dev/vda /dev/sda; do
    case "$src" in LABEL=*) flag="-L ${src#LABEL=}" ;; *) flag="$src" ;; esac
    if mount $flag -o rw /sysroot 2>/dev/null; then
        mounted=true
        break
    fi
done
if [ "$mounted" != true ]; then
    echo '[bpir-oram-debug-init] FATAL: rootfs mount failed' >&2
    while true; do sleep 3600; done
fi
mkdir -p /home/pir/data
if ! mount --bind /sysroot/home/pir/data /home/pir/data; then
    echo '[bpir-oram-debug-init] FATAL: data bind mount failed' >&2
    while true; do sleep 3600; done
fi

# shellcheck disable=SC1091
source /etc/bpir-oram-debug/baked.env
STATUS_ROOT=/home/pir/data/oram-tee-debug
RUN_DIR="$STATUS_ROOT/$BAKED_RUN_ID"
if [ -e "$RUN_DIR" ]; then
    echo "[bpir-oram-debug-init] FATAL: run directory already exists: $RUN_DIR" >&2
    while true; do sleep 3600; done
fi
mkdir -p "$RUN_DIR"
ln -sfn "$RUN_DIR" "$STATUS_ROOT/current"
printf 'status=booting\nphase=network-and-sev\nrun_id=%s\nupdated_at=%s\n' \
    "$BAKED_RUN_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$RUN_DIR/status.env"

# Public, credential-free debug status only. Port 22 is used because it is the
# one VPSBG ingress port already known to be reachable in stock mode. No shell
# or file upload endpoint exists in this image.
/usr/bin/busybox httpd -f -p 0.0.0.0:22 -h "$STATUS_ROOT" \
    >"$RUN_DIR/httpd.log" 2>&1 &
httpd_pid=$!
sleep 1
if ! kill -0 "$httpd_pid" 2>/dev/null; then
    printf 'status=failed\nphase=http-status\nreason=httpd-not-running\nupdated_at=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$RUN_DIR/status.env"
    while true; do sleep 3600; done
fi

write_boot_status() {
    {
        printf 'status=booting\n'
        printf 'phase=%s\n' "$1"
        printf 'run_id=%s\n' "$BAKED_RUN_ID"
        printf 'updated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >"$RUN_DIR/status.env.tmp"
    mv "$RUN_DIR/status.env.tmp" "$RUN_DIR/status.env"
}

# Some VPSBG kernels expose the device before PID 1 runs. Do not reload the
# SEV stack in that case. Otherwise bound every module probe independently so
# a wedged driver can never hide the useful HTTP status endpoint indefinitely.
write_boot_status sev-device-probe
if [ ! -c /dev/sev-guest ]; then
    for module in ccp sev-guest tsm_report; do
        write_boot_status "sev-modprobe-$module"
        if ! /usr/bin/busybox timeout -k 2 10 modprobe "$module" \
            >>"$RUN_DIR/sev-modprobe.log" 2>&1; then
            printf '%s module=%s result=failed-or-timed-out\n' \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$module" \
                >>"$RUN_DIR/sev-modprobe.log"
        fi
    done
fi
write_boot_status sev-device-validate
if [ ! -c /dev/sev-guest ]; then
    printf 'status=failed\nphase=sev\nreason=sev-guest-missing\nupdated_at=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$RUN_DIR/status.env"
    while true; do sleep 3600; done
fi

echo "[bpir-oram-debug-init] starting runner; status URL: http://87.120.8.198:22/current/status.env"
write_boot_status runner-start
set +e
BPIR_ORAM_DEBUG_RUN_DIR="$RUN_DIR" /usr/local/bin/bpir-oram-debug-run \
    >>"$RUN_DIR/runner.log" 2>&1
runner_status=$?
set -e
printf 'runner_exit=%s\n' "$runner_status" >>"$RUN_DIR/init.env"
if [ "$runner_status" -ne 0 ] && ! grep -Fq 'status=failed' "$RUN_DIR/status.env"; then
    printf 'status=failed\nphase=runner-bootstrap\nreason=runner-exit-%s\nrun_id=%s\nupdated_at=%s\n' \
        "$runner_status" "$BAKED_RUN_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >"$RUN_DIR/status.env.tmp"
    mv "$RUN_DIR/status.env.tmp" "$RUN_DIR/status.env"
fi
sync || true
echo "[bpir-oram-debug-init] runner exited $runner_status; retaining live status endpoint"
while true; do sleep 3600; done
