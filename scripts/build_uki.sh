#!/usr/bin/env bash
# Build a Unified Kernel Image (UKI) for BitcoinPIR's Phase 3 deployment.
#
# A UKI is a single PE/EFI file containing kernel + initrd + cmdline.
# When uploaded to a SEV-SNP host (e.g., via VPSBG's "Advanced: Measured
# Boot" UI), the entire UKI bytes get hashed into the launch MEASUREMENT
# the AMD chip signs in every attestation report. That extends the
# attested-boot chain from "OVMF only" to "OVMF + kernel + initrd + cmdline".
#
# This first iteration is Phase 3 SLICE 1 — it bakes the *binary's
# SHA-256 hash* into the kernel cmdline (`bpir.expected_binary_sha256=...`).
# Because the cmdline is part of the UKI, that hash is in MEASUREMENT.
# An attacker can't swap the binary on disk without either:
#   (a) also rebuilding + reuploading a new UKI (operator-controlled,
#       and the new MEASUREMENT diverges from what the operator
#       publishes), or
#   (b) modifying the binary in-place at runtime (defeated by SEV-SNP
#       memory encryption + the ProtectSystem= sandbox in pir-vpsbg.service).
#
# Slice 2+ will add a dracut hook that verifies the disk binary against
# the cmdline-pinned hash before systemd starts pir-vpsbg.service —
# that's the "honest" check, since right now nothing on the box
# enforces the equality.
#
# Operator usage:
#   ssh vpsbg-pir 'sudo -u pir /home/pir/BitcoinPIR/scripts/build_uki.sh'
# then upload the printed .efi path via VPSBG dashboard → Confidentiality
# & Protection → Advanced: Measured Boot → UKI → Upload, then Save & Reboot.
#
# After the reboot, run from your laptop:
#   bpir-admin attest wss://pir2.chenweikeng.com
# and capture the new MEASUREMENT — that's what you publish for verifiers.

set -euo pipefail

# ─── Defaults (override via env) ───────────────────────────────────────────
KERNEL=${KERNEL:-/boot/vmlinuz-7.0.0-15-generic}
INITRD=${INITRD:-/boot/initrd.img-7.0.0-15-generic}
BINARY=${BINARY:-/home/pir/BitcoinPIR/target/release/unified_server}
ROOT_LABEL=${ROOT_LABEL:-cloudimg-rootfs}
OUT=${OUT:-/tmp/bpir.efi}

# ─── Sanity checks ─────────────────────────────────────────────────────────
for f in "$KERNEL" "$INITRD" "$BINARY"; do
    [ -r "$f" ] || { echo "error: $f not readable" >&2; exit 1; }
done
command -v ukify >/dev/null 2>&1 || {
    echo "error: ukify not installed (apt install systemd-ukify)" >&2
    exit 1
}

# ─── Compute the binary's SHA-256 (the value that ends up in cmdline) ────
if command -v sha256sum >/dev/null 2>&1; then
    BIN_HASH=$(sha256sum "$BINARY" | awk '{print $1}')
else
    BIN_HASH=$(shasum -a 256 "$BINARY" | awk '{print $1}')
fi
echo "binary:                   $BINARY"
echo "binary sha256:            $BIN_HASH"
echo "kernel:                   $KERNEL"
echo "initrd:                   $INITRD ($(du -h "$INITRD" | cut -f1))"

# ─── Build the cmdline ─────────────────────────────────────────────────────
# Standard Linux boot params + our BPIR-specific params. The bpir.* keys
# are inert today (no consumer) but get committed to MEASUREMENT and
# parsed by future initramfs hooks (Slice 2+).
CMDLINE="root=LABEL=${ROOT_LABEL} ro console=ttyS0,115200 console=tty1 \
bpir.expected_binary_sha256=${BIN_HASH} \
bpir.uki_built_at=$(date -u +%Y%m%dT%H%M%SZ)"

echo "cmdline:                  $CMDLINE"
echo

# ─── Build the UKI ─────────────────────────────────────────────────────────
ukify build \
    --linux="$KERNEL" \
    --initrd="$INITRD" \
    --cmdline="$CMDLINE" \
    --output="$OUT"

# ─── Report ────────────────────────────────────────────────────────────────
SIZE=$(du -h "$OUT" | cut -f1)
UKI_SHA=$(sha256sum "$OUT" 2>/dev/null | awk '{print $1}' \
       || shasum -a 256 "$OUT" | awk '{print $1}')
echo
echo "wrote UKI:                $OUT (${SIZE})"
echo "uki sha256:               $UKI_SHA"
echo
echo "Next steps (operator):"
echo "  1. Download $OUT to your laptop:"
echo "       scp vpsbg-pir:$OUT ./bpir.efi"
echo "  2. VPSBG dashboard → Confidentiality & Protection →"
echo "     Advanced: Measured Boot → UKI → Upload bpir.efi → Save & Reboot"
echo "  3. After reboot, fetch the new MEASUREMENT:"
echo "       bpir-admin attest wss://pir2.chenweikeng.com"
echo "  4. Publish the new MEASUREMENT alongside this UKI's sha256:"
echo "       UKI sha256:   $UKI_SHA"
echo "       Binary sha256: $BIN_HASH"
echo "       MEASUREMENT:  <captured from step 3>"
echo "  5. Verifiers run:"
echo "       bpir-admin attest wss://pir2.chenweikeng.com \\"
echo "           --expect-measurement <published MEASUREMENT> \\"
echo "           --expect-binary $BIN_HASH"
