#!/bin/sh
# Offline one-shot installer for the pre-validated sealed release payload.
# The manifest is the complete write plan: action<TAB>relative path<TAB>sha256.

set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

payload=${BPIR_SEALED_PROVISIONER_TEST_PAYLOAD:-/usr/share/bitcoinpir/pir2-sealed-provisioner/payload}
manifest=${BPIR_SEALED_PROVISIONER_TEST_MANIFEST:-/usr/share/bitcoinpir/pir2-sealed-provisioner/manifest.tsv}
test_root=${BPIR_SEALED_PROVISIONER_TEST_ROOT:-}

fail() {
    echo "[pir2-sealed-provisioner] FATAL: $*" >&2
    if [ -n "$test_root" ]; then
        return 1
    fi
    sync || true
    poweroff -f
    while :; do sleep 1; done
}

allowed() {
    case "$1:$2" in
        replace:startup.env) return 0 ;;
        replay:release.bin|replay:public-artifact-set.env|replay:identity.cert|\
        replay:provider-accounting-authorization.bin|replay:issuer-accounting-approval.bin) return 0 ;;
        replay:public/classes/*)
            class=${2#public/classes/}
            stem=${class%.bin}
            [ "$class" = "$stem.bin" ] && [ "${#stem}" -eq 64 ] || return 1
            case "$stem" in *[!0123456789abcdef]*|'') return 1 ;; esac
            return 0
            ;;
    esac
    return 1
}

sha256() { sha256sum "$1" | awk '{print $1}'; }

if [ -n "$test_root" ]; then
    target="$test_root/home/pir/data/pir2-sealed"
else
    mount -t proc proc /proc 2>/dev/null || true
    mount -t sysfs sysfs /sys 2>/dev/null || true
    mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
    modprobe virtio_blk 2>/dev/null || true
    modprobe ext4 2>/dev/null || true
    mkdir -p /sysroot
    root_label=${BPIR_PIR2_SEALED_PROVISIONER_ROOT_LABEL:-cloudimg-rootfs}
    mount -L "$root_label" -o rw /sysroot || fail "cannot mount rootfs label $root_label"
    target=/sysroot/home/pir/data/pir2-sealed
fi

[ -r "$manifest" ] || fail "manifest unavailable"
[ -d "$payload" ] || fail "payload unavailable"
mkdir -p "$target"
chmod 0700 "$target"

# First validate every line and every embedded byte.  No destination write is
# attempted until the payload is complete and matches the baked manifest.
tab=$(printf '\t')
while IFS="$tab" read -r action rel expected extra; do
    [ -n "$action" ] || continue
    [ -z "$extra" ] || fail "invalid manifest fields"
    allowed "$action" "$rel" || fail "manifest path is not allowlisted: $action $rel"
    case "$expected" in [0123456789abcdef][0123456789abcdef][0123456789abcdef][0123456789abcdef][0123456789abcdef][0123456789abcdef][0123456789abcdef][0123456789abcdef]*) ;; *) fail "invalid manifest sha256" ;; esac
    [ "${#expected}" -eq 64 ] || fail "invalid manifest sha256 length"
    src="$payload/$rel"
    [ -f "$src" ] && [ ! -L "$src" ] || fail "payload file missing: $rel"
    [ "$(sha256 "$src")" = "$expected" ] || fail "payload hash mismatch: $rel"
done < "$manifest"

while IFS="$tab" read -r action rel expected extra; do
    [ -n "$action" ] || continue
    dest="$target/$rel"
    src="$payload/$rel"
    mkdir -p "$(dirname "$dest")"
    chmod 0700 "$(dirname "$dest")"
    case "$action" in
        replace)
            tmp="$dest.tmp.$$"
            rm -f "$tmp"
            cp "$src" "$tmp" || fail "cannot stage replacement: $rel"
            chmod 0600 "$tmp"
            mv -f "$tmp" "$dest" || fail "cannot replace: $rel"
            ;;
        replay)
            if [ -e "$dest" ] || [ -L "$dest" ]; then
                [ ! -L "$dest" ] && [ -f "$dest" ] || fail "replay destination is not a regular file: $rel"
                cmp -s "$src" "$dest" || fail "replay conflict: $rel"
            else
                tmp="$dest.tmp.$$"
                rm -f "$tmp"
                cp "$src" "$tmp" || fail "cannot stage replay: $rel"
                chmod 0600 "$tmp"
                if ! ln "$tmp" "$dest" 2>/dev/null; then
                    rm -f "$tmp"
                    [ -e "$dest" ] && cmp -s "$src" "$dest" || fail "replay conflict: $rel"
                else
                    rm -f "$tmp"
                fi
            fi
            ;;
        *) fail "unsupported manifest action" ;;
    esac
done < "$manifest"

manifest_sha=$(sha256 "$manifest")
markers="$target/markers"
mkdir -p "$markers"
chmod 0700 "$markers"
marker="$markers/provision-$manifest_sha.env"
marker_tmp="$marker.tmp.$$"
printf 'sealed-provisioner-manifest-sha256=%s\n' "$manifest_sha" > "$marker_tmp"
chmod 0600 "$marker_tmp"
if ! ln "$marker_tmp" "$marker" 2>/dev/null; then
    rm -f "$marker_tmp"
    [ -f "$marker" ] && [ ! -L "$marker" ] \
        && [ "$(cat "$marker")" = "sealed-provisioner-manifest-sha256=$manifest_sha" ] \
        || fail "marker conflict"
else
    rm -f "$marker_tmp"
fi
sync
echo "[pir2-sealed-provisioner] complete"
[ -n "$test_root" ] && exit 0
poweroff -f
while :; do sleep 1; done
