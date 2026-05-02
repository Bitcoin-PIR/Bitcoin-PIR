#!/bin/sh
# Pre-pivot dracut hook: verify the on-disk unified_server binary
# matches the SHA-256 pinned into the UKI's kernel cmdline.
#
# Threat model: an attacker with pir-user privileges can overwrite
# /home/pir/BitcoinPIR/target/release/unified_server while the system
# is up. SEV-SNP memory encryption protects the running process from
# the host but not from a co-located attacker on the guest. This hook
# closes the loop by failing the next boot if the on-disk bytes don't
# match what the operator signed off on (the cmdline hash → in
# MEASUREMENT → in the chip-signed attestation report).
#
# Failure modes:
#   - cmdline missing the pin → log, skip (preserves rollback path: a
#     vanilla UKI without the pin boots fine).
#   - binary unreadable → emergency_shell. Operator investigates via
#     VPSBG VNC console.
#   - hash mismatch → emergency_shell. Same recovery path.
#
# emergency_shell shows the FATAL message at a maintenance prompt.
# The operator can `reboot` to retry, fix the issue from VNC, or in
# the worst case roll back to a vanilla UKI via the VPSBG portal.

# shellcheck shell=sh

EXPECTED=$(grep -oE 'bpir\.expected_binary_sha256=[0-9a-f]+' /proc/cmdline 2>/dev/null | cut -d= -f2)
if [ -z "$EXPECTED" ]; then
    echo "[bpir-verify] no bpir.expected_binary_sha256 in cmdline; skipping"
    exit 0
fi

BINARY=/sysroot/home/pir/BitcoinPIR/target/release/unified_server
if [ ! -r "$BINARY" ]; then
    echo "[bpir-verify] FATAL: $BINARY not readable" >&2
    type emergency_shell >/dev/null 2>&1 && emergency_shell "bpir-verify: binary missing"
    exit 1
fi

ACTUAL=$(sha256sum "$BINARY" | awk '{print $1}')
if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "[bpir-verify] FATAL: binary hash mismatch" >&2
    echo "[bpir-verify]   expected: $EXPECTED" >&2
    echo "[bpir-verify]   got:      $ACTUAL" >&2
    type emergency_shell >/dev/null 2>&1 && emergency_shell "bpir-verify: binary tamper detected"
    exit 1
fi

echo "[bpir-verify] binary hash verified: $ACTUAL"
exit 0
