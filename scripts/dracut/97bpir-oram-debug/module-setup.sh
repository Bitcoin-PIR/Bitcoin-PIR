#!/bin/bash
# Dracut module for the one-shot Direct ORAM SEV-SNP debug image.

# shellcheck shell=bash

check() {
    for name in BPIR_ORAM_DEBUG_ORAMCTL_BIN BPIR_ORAM_DEBUG_INDEX_FIXTURE \
        BPIR_ORAM_DEBUG_CHUNK_FIXTURE BPIR_ORAM_DEBUG_ORAMCTL_SHA256 \
        BPIR_ORAM_DEBUG_INDEX_SHA256 BPIR_ORAM_DEBUG_CHUNK_SHA256 \
        BPIR_ORAM_DEBUG_RUN_ID; do
        [ -n "${!name:-}" ] || {
            derror "bpir-oram-debug: missing build variable $name"
            return 1
        }
    done
    [ -x "$BPIR_ORAM_DEBUG_ORAMCTL_BIN" ] || return 1
    [ -r "$BPIR_ORAM_DEBUG_INDEX_FIXTURE" ] || return 1
    [ -r "$BPIR_ORAM_DEBUG_CHUNK_FIXTURE" ] || return 1
    [ -x /usr/bin/busybox ] || return 1
    [ -x /usr/bin/time ] || return 1
    return 0
}

depends() {
    echo "busybox base"
    return 0
}

install() {
    inst_multiple bash env ip modprobe mount sleep ln mkdir cat sh blkid awk \
        cmp dd od tr tail mv cp date sha256sum du sync grep stat tee
    inst_simple /usr/bin/busybox
    inst_simple /usr/bin/time
    ln_r /usr/bin/busybox /sbin/poweroff
    ln_r /usr/bin/busybox /sbin/reboot

    inst_simple "$BPIR_ORAM_DEBUG_ORAMCTL_BIN" /usr/local/bin/oramctl
    inst_simple "$BPIR_ORAM_DEBUG_INDEX_FIXTURE" \
        /usr/share/bitcoinpir/oram-debug/utxo_chunks_index_nodust.bin
    inst_simple "$BPIR_ORAM_DEBUG_CHUNK_FIXTURE" \
        /usr/share/bitcoinpir/oram-debug/utxo_chunks_nodust.bin
    inst_simple "$moddir/bpir-oram-debug-init.sh" /sbin/bpir-oram-debug-init
    inst_simple "$moddir/bpir-oram-debug-run.sh" /usr/local/bin/bpir-oram-debug-run
    chmod 0755 "${initdir}/sbin/bpir-oram-debug-init"
    chmod 0755 "${initdir}/usr/local/bin/bpir-oram-debug-run"

    inst_dir /etc/bpir-oram-debug
    {
        printf 'BAKED_RUN_ID=%q\n' "$BPIR_ORAM_DEBUG_RUN_ID"
        printf 'BAKED_ORAMCTL_SHA256=%q\n' "$BPIR_ORAM_DEBUG_ORAMCTL_SHA256"
        printf 'BAKED_INDEX_SHA256=%q\n' "$BPIR_ORAM_DEBUG_INDEX_SHA256"
        printf 'BAKED_CHUNK_SHA256=%q\n' "$BPIR_ORAM_DEBUG_CHUNK_SHA256"
    } >"${initdir}/etc/bpir-oram-debug/baked.env"
    chmod 0444 "${initdir}/etc/bpir-oram-debug/baked.env"
}
