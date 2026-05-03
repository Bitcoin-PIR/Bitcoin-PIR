#!/bin/bash
# dracut module-setup for bpir-cloudflared
#
# Bakes the cloudflared static binary + the tunnel token into the
# initramfs. The 97bpir-tier3-init module's runit service tree is
# what actually invokes cloudflared at boot; this module only ships
# the inputs (binary + token).
#
# Cloudflared is statically linked (verified via `ldd cloudflared` →
# "not a dynamic executable"), so no library dependencies need to be
# pulled in. Just the binary itself (~36 MB) and the env file.
#
# The tunnel token is read from the build host's
# /etc/cloudflared/tunnel.env (i.e., pir2's actual production token,
# NOT the deploy/cloudflared_tunnel.env in the repo — that one is
# Hetzner's). Token bytes end up inside the initramfs cpio and
# therefore inside MEASUREMENT, so the operator-published MEASUREMENT
# is one-to-one with a specific (binary, token, kernel) triple.
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
    local cf_env=/etc/cloudflared/tunnel.env

    if [ ! -x "$cf_bin" ]; then
        derror "bpir-cloudflared: $cf_bin not found or not executable"
        return 1
    fi
    if [ ! -r "$cf_env" ]; then
        derror "bpir-cloudflared: $cf_env not readable (need TUNNEL_TOKEN)"
        return 1
    fi

    # cloudflared is statically linked; inst_simple copies just the
    # one file (no library walk needed).
    inst_simple "$cf_bin"

    # Token env file at the same path as on the host so the runit
    # service-run script can `. /etc/cloudflared/tunnel.env`.
    inst_simple "$cf_env"
}
