/**
 * Operator-pinned 32-byte SHA-256 fingerprint of the AMD ARK (Root
 * Key) certificate.
 *
 * This is the trust anchor for browser-side AMD VCEK chain validation
 * (Slice D). When the adapter calls `verifyVcekChain`, it computes
 * SHA-256(ARK_DER) and compares to this constant; mismatch = the
 * server's bundled cert chain doesn't actually root at AMD's ARK.
 *
 * Pinned 2026-05-03 by the operator from the Turin family ARK at
 * https://kdsintf.amd.com/vcek/v1/Turin/cert_chain (second PEM block).
 *
 * To rotate (very rare — AMD ARKs have ~25-year validity):
 *   1. Re-fetch cert_chain.pem from AMD KDS.
 *   2. Run on the operator's laptop:
 *        # Split, then SHA-256 the ARK DER:
 *        csplit -z -f cert_ -b "%d.pem" cert_chain.pem '/-----BEGIN CERT/' '{*}'
 *        openssl x509 -in cert_1.pem -outform DER | sha256sum
 *   3. Replace the hex below + rebuild + redeploy the web bundle.
 *
 * Same fingerprint applies to all Turin-family chips. (Genoa, Milan,
 * etc. would have different ARKs and need their own pins; we only
 * deploy on Turin so far.)
 */
export const AMD_TURIN_ARK_FINGERPRINT_HEX =
  '1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a';

/** Same as `AMD_TURIN_ARK_FINGERPRINT_HEX` but as Uint8Array — the
 *  shape `WasmAttestVerification.verifyVcekChain` expects. */
export const AMD_TURIN_ARK_FINGERPRINT: Uint8Array = (() => {
  const hex = AMD_TURIN_ARK_FINGERPRINT_HEX;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
})();

/**
 * Per-server build-time pins for values the SEV-SNP report surfaces.
 * Defense in depth on top of the ARK chain validation: even with a
 * verified chain, mismatches on these self-reported (but in Tier 3
 * MEASUREMENT-covered) values trip state to `'mismatch'` and the
 * adapter refuses to upgrade to the encrypted channel.
 *
 * - `measurementHex`: 96-char hex (48 bytes) — the launch
 *   MEASUREMENT AMD's PSP signs into every report. For Tier 3 this
 *   covers OVMF + UKI bytes (kernel + initramfs + cmdline) and
 *   therefore the unified_server binary itself, since it lives
 *   inside the initramfs. Any binary substitution flips this value.
 * - `binarySha256Hex`: 64-char hex — SHA-256 of the running
 *   unified_server binary, server-self-reported. Cross-checkable
 *   against MEASUREMENT (transitively, for Tier 3) and against
 *   the cmdline pin (for Slice 2 with bpir-verify hook).
 *
 * Operator publishes both in `docs/PHASE3_ROADMAP.md::Attested
 * values published`. Update here whenever you re-bake + republish
 * the UKI on pir2 (every binary change).
 */
export interface ServerAttestPin {
  measurementHex?: string;
  binarySha256Hex?: string;
  /** Human-readable description shown in the badge tooltip. */
  description?: string;
}

/**
 * pir2.chenweikeng.com — VPSBG Tier 3 (Slice 3 lockdown).
 * Pinned 2026-05-03 from the post-Slice-3 deploy (UKI sha
 * `afbc07f8…f8b8fe90`).
 */
export const PIR2_TIER3_PIN: ServerAttestPin = {
  measurementHex:
    '2ad9490a64a48d7ab9af1045c5a5abe2b8308edcb13f966a9c95eea3709c4018faf161f52eb3c6063c1e241f19fd6fe5',
  binarySha256Hex:
    '324c3883510c56a344221ec379a6466c3089099f51e566e7ad9b1356156eee7e',
  description: 'pir2.chenweikeng.com (VPSBG, SEV-SNP, Tier 3 UKI)',
};

/**
 * pir1.chenweikeng.com — Hetzner i7-8700, Intel chip, NO SEV-SNP.
 * No MEASUREMENT to pin (no SEV report). binary_sha256 IS pinnable —
 * the value isn't hardware-backed without SEV, but pinning still
 * detects accidental drift between what the operator claims is
 * deployed and what's actually running.
 */
export const PIR1_PIN: ServerAttestPin = {
  // No measurementHex — Hetzner has no SEV.
  binarySha256Hex:
    '8fec274b9089a5defaec5825920e662af771a3cbd542968c6fdba93ab3f7d0f6',
  description: 'pir1.chenweikeng.com (Hetzner i7-8700, no SEV)',
};
