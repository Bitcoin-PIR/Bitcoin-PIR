#!/bin/bash
# dracut module-setup for the one-shot attested-builder Tier 3 UKI.
#
# Bakes the standalone attested-builder binary and its host/TEE boundary
# pipeline script into the initramfs. Runtime input state still comes from the
# mounted rootfs under /home/pir/data/attested-builder/config.env.

# shellcheck shell=bash

builder_repo() {
    printf '%s\n' "${ATTESTED_BUILDER_REPO:-/home/pir/bitcoin-pir/attested-builder}"
}

builder_bin() {
    local repo
    repo=$(builder_repo)
    printf '%s\n' "${ATTESTED_BUILDER_BIN:-$repo/target/release/pir-attested-builder}"
}

onionffi_bin() {
    local repo
    repo=$(builder_repo)
    printf '%s\n' "${ATTESTED_BUILDER_ONIONFFI_BIN:-$repo/target/release/onionffi}"
}

check() {
    local repo bin onionffi
    repo=$(builder_repo)
    bin=$(builder_bin)
    onionffi=$(onionffi_bin)

    if [ ! -x "$bin" ]; then
        derror "bpir-attested-builder: $bin not executable on build host"
        derror "  run: cargo build --release -p pir-attested-builder in $repo"
        return 1
    fi
    if [ ! -f "$repo/scripts/build-snapshot-database.sh" ] ||
        [ ! -f "$repo/scripts/build-delta-database.sh" ]; then
        derror "bpir-attested-builder: missing snapshot or delta pipeline script under $repo/scripts"
        return 1
    fi
    if [ ! -x "$onionffi" ]; then
        derror "bpir-attested-builder: $onionffi not executable"
        derror "  run: cargo build --release -p onionffi --features ffi in $repo"
        return 1
    fi
    command -v sha256sum >/dev/null 2>&1 || {
        derror "bpir-attested-builder: sha256sum not in PATH"
        return 1
    }
    return 0
}

depends() {
    echo "base"
    return 0
}

install() {
    local repo bin onionffi git_commit required_git_commit bin_sha
    repo=$(builder_repo)
    bin=$(builder_bin)
    onionffi=$(onionffi_bin)
    git_commit=${ATTESTED_BUILDER_GIT_COMMIT:-unknown}
    required_git_commit=${ATTESTED_BUILDER_REQUIRED_GIT_COMMIT:-unknown}
    bin_sha=${ATTESTED_BUILDER_BIN_SHA256:-$(sha256sum "$bin" | awk '{print $1}')}

    # `inst` copies the binary plus all dynamic library dependencies.
    inst "$bin" /usr/local/bin/pir-attested-builder
    inst "$onionffi" /usr/local/bin/onionffi

    inst_dir /usr/local/lib/attested-builder/scripts
    inst_simple "$repo/scripts/build-snapshot-database.sh" \
        /usr/local/lib/attested-builder/scripts/build-snapshot-database.sh
    inst_simple "$repo/scripts/build-delta-database.sh" \
        /usr/local/lib/attested-builder/scripts/build-delta-database.sh
    chmod 0755 "${initdir}/usr/local/lib/attested-builder/scripts/build-snapshot-database.sh"
    chmod 0755 "${initdir}/usr/local/lib/attested-builder/scripts/build-delta-database.sh"

    inst_dir /etc/bpir-builder
    {
        printf 'BAKED_BUILDER_REPO=%s\n' "$repo"
        printf 'BAKED_BUILDER_GIT_COMMIT=%s\n' "$git_commit"
        printf 'BAKED_BUILDER_REQUIRED_GIT_COMMIT=%s\n' "$required_git_commit"
        printf 'BAKED_BUILDER_BIN_SHA256=%s\n' "$bin_sha"
    } > "${initdir}/etc/bpir-builder/baked.env"
    chmod 0644 "${initdir}/etc/bpir-builder/baked.env"
}
