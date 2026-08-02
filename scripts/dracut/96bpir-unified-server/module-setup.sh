#!/bin/bash
# dracut module-setup for bpir-unified-server
#
# Bakes the BitcoinPIR `unified_server` binary, the ORAM image builder
# `oramctl`, and their .so dependencies into the initramfs. Phase 3.2's whole
# point: the binary bytes are directly inside the UKI (and therefore directly
# in MEASUREMENT), not just transitively pinned via a cmdline hash like Slice 2.
#
# Source binaries:
#   /home/pir/BitcoinPIR/target/release/unified_server
#   /home/pir/bitcoin-pir/oram/target/release/oramctl
# Destinations in initramfs:
#   /usr/local/bin/unified_server
#   /usr/local/bin/oramctl
#
# .so deps (from `ldd` on a fresh build, 2026-05-03):
#   libgomp.so.1, libstdc++.so.6, libgcc_s.so.1, libm.so.6, libc.so.6,
#   /lib64/ld-linux-x86-64.so.2  (linker)
# dracut's `inst` helper auto-walks ldd output, so we don't enumerate
# them manually here — `inst <bin> <dst>` does the right thing.
#
# Together with 97bpir-tier3-init's runit service tree, this gives us a Tier 3
# boot where the measured startup path regenerates disposable ORAM images from
# proof-bound direct inputs before exec'ing unified_server.

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
    local bin=${BPIR_UNIFIED_SERVER_BIN:-${BINARY:-/home/pir/BitcoinPIR/target/release/unified_server}}
    local oramctl=${BPIR_ORAMCTL_BIN:-${ORAMCTL:-/home/pir/bitcoin-pir/oram/target/release/oramctl}}
    local bhtm_from_leaf_proof=${BPIR_BHTM_FROM_LEAF_PROOF:-/home/pir/BitcoinPIR/web/public/proofs/trust-chain/delta_940611_948454/bhtm/height-940611.leaf-proof.json}
    local identity_key=${BPIR_TIER3_IDENTITY_KEY:-}
    local identity_cert=${BPIR_TIER3_IDENTITY_CERT:-}

    if [ ! -x "$bin" ]; then
        derror "bpir-unified-server: $bin not executable on build host"
        derror "  run: cargo build --release -p runtime --features cuckoo-oram --bin unified_server"
        return 1
    fi
    if [ ! -x "$oramctl" ]; then
        derror "bpir-unified-server: $oramctl not executable on build host"
        derror "  run: cd /home/pir/bitcoin-pir/oram && cargo build --release --bin oramctl"
        return 1
    fi
    if [ ! -r "$bhtm_from_leaf_proof" ]; then
        derror "bpir-unified-server: BHTM from-leaf proof not readable: $bhtm_from_leaf_proof"
        return 1
    fi

    # `inst` is dracut's smart installer: copies the file AND walks
    # its ldd output, copying every required .so + the dynamic linker.
    # Result: /usr/local/bin/unified_server in the initramfs, with all
    # its libs at /usr/lib/x86_64-linux-gnu/* and the linker at
    # /lib64/ld-linux-x86-64.so.2.
    inst "$bin" /usr/local/bin/unified_server
    inst "$oramctl" /usr/local/bin/oramctl
    inst_simple "$bhtm_from_leaf_proof" \
        /usr/share/bitcoinpir/proofs/height-940611.leaf-proof.json

    # Optional measured fallback for the server identity. Tier 3 normally
    # reads identity material from the mutable data mount. A fresh rootfs can
    # lack that pair, which leaves REQ_ANNOUNCE disabled even while attestation
    # and the secure channel succeed. When both explicit build inputs are
    # supplied, place only the server key + public certificate in the UKI;
    # never the operator signing key.
    if [ -n "$identity_key" ] || [ -n "$identity_cert" ]; then
        if [ -z "$identity_key" ] || [ -z "$identity_cert" ]; then
            derror "bpir-unified-server: BPIR_TIER3_IDENTITY_KEY and BPIR_TIER3_IDENTITY_CERT must be supplied together"
            return 1
        fi
        if [ ! -r "$identity_key" ] || [ ! -r "$identity_cert" ]; then
            derror "bpir-unified-server: measured identity input is not readable"
            return 1
        fi
        if [ "$(wc -c < "$identity_key")" -ne 32 ]; then
            derror "bpir-unified-server: measured identity key must be exactly 32 bytes"
            return 1
        fi
        inst_dir /etc/bitcoinpir/identity
        inst_simple "$identity_key" /etc/bitcoinpir/identity/server.key
        inst_simple "$identity_cert" /etc/bitcoinpir/identity/server.cert
        chmod 0600 "$initdir/etc/bitcoinpir/identity/server.key"
        chmod 0644 "$initdir/etc/bitcoinpir/identity/server.cert"
    fi
}
