#!/bin/bash
# dracut module-setup for bpir-unified-server
#
# Bakes the BitcoinPIR `unified_server` binary + its .so dependencies
# into the initramfs. Phase 3.2's whole point: the binary's bytes are
# directly inside the UKI (and therefore directly in MEASUREMENT) —
# not just transitively pinned via a cmdline hash like Slice 2.
#
# Source binary: /home/pir/BitcoinPIR/target/release/unified_server
# (the same path scripts/build_uki.sh picks up). Dest in initramfs:
# /usr/local/bin/unified_server.
#
# .so deps (from `ldd` on a fresh build, 2026-05-03):
#   libgomp.so.1, libstdc++.so.6, libgcc_s.so.1, libm.so.6, libc.so.6,
#   /lib64/ld-linux-x86-64.so.2  (linker)
# dracut's `inst` helper auto-walks ldd output, so we don't enumerate
# them manually here — `inst <bin> <dst>` does the right thing.
#
# Together with 97bpir-tier3-init's runit service tree (which adds
# /etc/sv/unified_server/run pointing at /usr/local/bin/unified_server),
# this gives us a Tier 3 boot where unified_server is a first-class
# initramfs-resident service.

# shellcheck shell=bash

check() {
    return 0
}

depends() {
    # We only need busybox / base for sh, mount, etc — those come via
    # the 97bpir-tier3-init module's depends. Kept this list explicit
    # so the module is self-describing.
    echo "busybox base"
    return 0
}

install() {
    local bin=/home/pir/BitcoinPIR/target/release/unified_server

    if [ ! -x "$bin" ]; then
        derror "bpir-unified-server: $bin not executable on build host"
        derror "  run: cargo build --release -p unified_server"
        return 1
    fi

    # `inst` is dracut's smart installer: copies the file AND walks
    # its ldd output, copying every required .so + the dynamic linker.
    # Result: /usr/local/bin/unified_server in the initramfs, with all
    # its libs at /usr/lib/x86_64-linux-gnu/* and the linker at
    # /lib64/ld-linux-x86-64.so.2.
    inst "$bin" /usr/local/bin/unified_server
}
