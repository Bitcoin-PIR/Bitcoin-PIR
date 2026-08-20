#!/bin/bash
# One-shot, offline pir2 sealed-state provisioner.  It deliberately contains
# no network, SSH, service manager, ORAM, builder, or SEV component.

check() {
    local name
    for name in BPIR_PIR2_SEALED_PROVISIONER_PAYLOAD_DIR \
        BPIR_PIR2_SEALED_PROVISIONER_MANIFEST; do
        [ -n "${!name:-}" ] || {
            derror "bpir-pir2-sealed-provisioner: missing $name"
            return 1
        }
    done
    [ -d "$BPIR_PIR2_SEALED_PROVISIONER_PAYLOAD_DIR" ] || return 1
    [ -r "$BPIR_PIR2_SEALED_PROVISIONER_MANIFEST" ] || return 1
    [ -x /usr/bin/busybox ] || return 1
    return 0
}

depends() {
    echo "busybox base"
    return 0
}

install() {
    local payload=$BPIR_PIR2_SEALED_PROVISIONER_PAYLOAD_DIR
    local manifest_path=$BPIR_PIR2_SEALED_PROVISIONER_MANIFEST

    inst_multiple awk basename cat chmod cmp dirname find ln mkdir mount modprobe mv \
        rm sha256sum sleep sync
    inst_simple /usr/bin/busybox
    ln_r /usr/bin/busybox /sbin/poweroff
    inst_simple "$moddir/bpir-pir2-sealed-provisioner-init.sh" \
        /sbin/bpir-pir2-sealed-provisioner-init
    inst_dir /usr/share/bitcoinpir/pir2-sealed-provisioner/payload
    local tab action rel expected extra source destination
    tab=$(printf '\t')
    while IFS="$tab" read -r action rel expected extra; do
        [ -n "$action" ] || continue
        [ -z "$extra" ] || {
            derror "bpir-pir2-sealed-provisioner: invalid manifest fields"
            return 1
        }
        case "$rel" in ''|/*|..|../*|*/../*|*/..) derror "bpir-pir2-sealed-provisioner: unsafe manifest path"; return 1 ;; esac
        source="$payload/$rel"
        [ -f "$source" ] && [ ! -L "$source" ] && [ -r "$source" ] || {
            derror "bpir-pir2-sealed-provisioner: unreadable regular payload source: $rel"
            return 1
        }
        destination="/usr/share/bitcoinpir/pir2-sealed-provisioner/payload/$rel"
        inst_dir "$(dirname "$destination")"
        inst_simple "$source" "$destination"
    done < "$manifest_path"
    inst_simple "$manifest_path" \
        /usr/share/bitcoinpir/pir2-sealed-provisioner/manifest.tsv
    chmod 0755 "$initdir/sbin/bpir-pir2-sealed-provisioner-init"
    chmod 0444 "$initdir/usr/share/bitcoinpir/pir2-sealed-provisioner/manifest.tsv"
}
