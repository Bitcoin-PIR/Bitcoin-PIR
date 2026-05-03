#!/bin/bash
# dracut module-setup for bpir-cloudflared
#
# Bakes the cloudflared static binary into the initramfs. The
# 97bpir-tier3-init module's runit service tree invokes cloudflared
# at boot; this module ships only the binary.
#
# Cloudflared is statically linked (verified via `ldd cloudflared` →
# "not a dynamic executable"), so no library dependencies need to be
# pulled in. Just the binary itself (~36 MB).
#
# The tunnel token does NOT live in the initramfs (and therefore is
# not in MEASUREMENT). At runtime cloudflared-run.sh sources it from
# /home/pir/data/cloudflared/tunnel.env on the rootfs partition,
# which is bind-mounted by 97bpir-tier3-init/bpir-tier3-init.sh
# before runsvdir takes over. This makes the UKI operator-agnostic —
# two operators with the same git commit produce byte-identical UKI
# bytes regardless of their cloudflared tokens. See
# docs/PHASE3_SLICE3_REPRO_PLAN.md sub-task 3 (option b).
#
# Operator one-time setup before deploying Tier 3: copy
# /etc/cloudflared/tunnel.env → /home/pir/data/cloudflared/tunnel.env
# on the rootfs partition (via Slice 2 SSH access).
#
# Installed at /usr/lib/dracut/modules.d/96bpir-cloudflared/ by
# scripts/build_uki_tier3.sh and pulled in via `--add bpir-cloudflared`.

# shellcheck shell=bash

check() {
    return 0
}

depends() {
    echo "busybox"
    return 0
}

install() {
    local cf_bin=/usr/local/bin/cloudflared

    if [ ! -x "$cf_bin" ]; then
        derror "bpir-cloudflared: $cf_bin not found or not executable"
        return 1
    fi

    # cloudflared is statically linked; inst_simple copies just the
    # one file (no library walk needed). The token is loaded at
    # runtime from the rootfs — see header comment.
    inst_simple "$cf_bin"
}
