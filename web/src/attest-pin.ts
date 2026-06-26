import { requireSdkWasm } from './sdk-bridge.js';
import type { DatabaseProofPin } from './db-proof.js';

/**
 * Operator-pinned 32-byte SHA-256 fingerprint of the AMD ARK (Root
 * Key) certificate, as a human-readable hex string.
 *
 * This constant is **documentation** — the live runtime value used by
 * the verifier comes from the WASM module (`turinArkFingerprint()`,
 * exported from `pir-attest-verify::TURIN_ARK_FINGERPRINT_SHA256`).
 * Keeping the hex here gives operators a searchable, auditable copy
 * of the pinned value AND a build-time cross-check (see
 * [`getAmdTurinArkFingerprint`] below) that catches drift if anyone
 * ever rotates one without the other.
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
 *   3. Replace the hex below AND the Rust constant
 *      `pir-attest-verify::TURIN_ARK_FINGERPRINT_SHA256`, then rebuild
 *      the WASM bundle.
 *
 * Same fingerprint applies to all Turin-family chips. (Genoa, Milan,
 * etc. would have different ARKs and need their own pins; we only
 * deploy on Turin so far.)
 */
export const AMD_TURIN_ARK_FINGERPRINT_HEX =
  '1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a';

/** Decode the hex constant once at module load. Used as the
 *  authoritative *human-readable* source — the runtime value comes
 *  from WASM and is checked against this at [`getAmdTurinArkFingerprint`]
 *  call time. */
const HEX_AS_BYTES: Uint8Array = (() => {
  const hex = AMD_TURIN_ARK_FINGERPRINT_HEX;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
})();

/**
 * Return the 32-byte ARK fingerprint sourced from the WASM module
 * (which mirrors the Rust constant
 * `pir-attest-verify::TURIN_ARK_FINGERPRINT_SHA256`).
 *
 * Throws if [`initSdkWasm`] hasn't resolved yet — the WASM module is
 * the single source of truth, so this function intentionally has no
 * pure-TS fallback. Callers that need the value before WASM init can
 * use [`AMD_TURIN_ARK_FINGERPRINT_HEX`] for display purposes only
 * (never as the value passed to `verifyVcekChain` / `verifyFull` —
 * that would defeat the cross-check).
 *
 * On first call after WASM init, cross-checks the WASM-exported bytes
 * against the hex constant and throws on mismatch (build-time drift
 * between Rust + TS). Subsequent calls return the cached Uint8Array.
 */
let cachedArkFingerprint: Uint8Array | null = null;
export function getAmdTurinArkFingerprint(): Uint8Array {
  if (cachedArkFingerprint) return cachedArkFingerprint;
  const sdk = requireSdkWasm();
  const fromWasm = sdk.turinArkFingerprint();
  if (fromWasm.length !== 32) {
    throw new Error(
      `attest-pin: WASM turinArkFingerprint returned ${fromWasm.length} bytes (expected 32)`,
    );
  }
  for (let i = 0; i < 32; i++) {
    if (fromWasm[i] !== HEX_AS_BYTES[i]) {
      throw new Error(
        `attest-pin: ARK fingerprint mismatch between WASM (${bytesToHex(fromWasm)}) ` +
          `and AMD_TURIN_ARK_FINGERPRINT_HEX (${AMD_TURIN_ARK_FINGERPRINT_HEX}). ` +
          `One was rotated without the other — fix and rebuild.`,
      );
    }
  }
  cachedArkFingerprint = fromWasm;
  return fromWasm;
}

/**
 * @deprecated Use [`getAmdTurinArkFingerprint`] instead. This eager
 * Uint8Array is kept for back-compat with pre-Slice-D.4 callers; new
 * code should source from WASM so the cross-check fires. Will be
 * removed once `dpf-adapter.ts` / `harmonypir-adapter.ts` migrate.
 */
export const AMD_TURIN_ARK_FINGERPRINT: Uint8Array = HEX_AS_BYTES;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

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
 * weikeng2.bitcoinpir.org — VPSBG Tier 3 ORAM UKI, pinned 2026-06-27.
 * Built by `scripts/build_uki_tier3.sh` on the Hetzner build host:
 * VPSBG kernel 7.0.0-15 + the ORAM-enabled `unified_server`
 * binary baked into the initramfs.
 */
export const PIR2_TIER3_PIN: ServerAttestPin = {
  // Tier 3 ORAM UKI — 2026-06-27. Built from BitcoinPIR commit
  // f402466af1ee21d02e0a65b457ad338ceb1216c0:
  // unified_server serves db-proof query traffic and direct ORAM lookup
  // for db_id 0/1 as pir2 query-only (`--serve-queries`, no hint pool,
  // no OnionPIR) plus `--identity-*` (operator-signed identity,
  // server_id=pir2). MEASUREMENT captured from the live Tier 3 deploy via
  // `bpir-admin attest wss://weikeng2.bitcoinpir.org` after uploading
  // UKI sha256 `3ef8249b...` (SEV-SNP REPORT_DATA binding verified on
  // real hardware).
  measurementHex:
    'f0d449e04c27ba2bf5b96790d58d9b1d5b789c7c560f16bc9d3f8bb26c78391ae7d3bb55deeea1bf7ef07c1671ad8da0',
  binarySha256Hex:
    '233541886714f1eec9ca90cf876c33774b9fd07cae2d6e3a2c9d555ef5e53fb3',
  description: 'weikeng2.bitcoinpir.org (VPSBG, SEV-SNP, Tier 3 ORAM UKI)',
};

/**
 * weikeng1.bitcoinpir.org — Hetzner i7-8700, Intel chip, NO SEV-SNP.
 * No MEASUREMENT to pin (no SEV report). binary_sha256 IS pinnable —
 * the value isn't hardware-backed without SEV, but pinning still
 * detects accidental drift between what the operator claims is
 * deployed and what's actually running.
 */
export const PIR1_PIN: ServerAttestPin = {
  // No measurementHex — Hetzner has no SEV.
  // Bumped 2026-06-16: pir1 redeployed to the db-proof-enabled
  // unified_server (`git_rev` reported as 1c21d341...-dirty), serving
  // the delta_940611_948454 proof sidecar. This is intentionally
  // independent from the pir2 ORAM Tier 3 UKI pin above.
  binarySha256Hex:
    'd01e5b7aab2b3075eed4dd154ffc2079aae394b418a40155128166a50ace750a',
  description: 'weikeng1.bitcoinpir.org (Hetzner i7-8700, no SEV)',
};

/**
 * Production database proof pins.
 *
 * These are not server-binary pins. They are the public chain/database anchor
 * the browser expects the attested-builder proof to reproduce. The live proof
 * must first verify in WASM, then match these exact values before the frontend
 * marks the DB/MuHash binding as verified.
 */
export const DELTA_940611_948454_DB_PROOF_PIN: DatabaseProofPin = {
  dbId: 1,
  buildKind: 'delta',
  fromHeight: 940611,
  height: 948454,
  fromBlockHashHex:
    '000000000000000000002c41243b3d74d135942031ef15f547bca1ce8f85eb99',
  blockHashHex:
    '00000000000000000001ef683c02c383315db7e917c69d20f79e05985560a4e4',
  muhashHex:
    'cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee',
  bucketSuperRootHex:
    'e2ba2eee6788424309a95f771893d5401cc8e3ceec6188dc2708900e211a910a',
  onionSuperRootHex:
    'f86baa3966a61cdcd70d8c0ad9bed233f591806eb351db2ae35ac0192a3fe997',
  paramsHashHex:
    '2b3e488c04433ed8bd293fd3adab72b49bf52346b81160365486d76f9b4d4e39',
  networkMagicHex: 'f9beb4d9',
  builderBinarySha256Hex:
    '34a677847b9be6580385c73f163279c81561772f8d3ad782d0ca08f1c01fad4a',
  builderGitCommit: '01e8db91d76037cd5562fce85c40e832ad156431',
  description:
    'delta_940611_948454: Bitcoin Core MuHash and PIR Merkle roots from the SEV-SNP attested builder',
};

export const MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN: DatabaseProofPin = {
  dbId: 0,
  buildKind: 'snapshot',
  fromHeight: 0,
  height: 948454,
  fromBlockHashHex:
    '0000000000000000000000000000000000000000000000000000000000000000',
  blockHashHex:
    '00000000000000000001ef683c02c383315db7e917c69d20f79e05985560a4e4',
  muhashHex:
    'cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee',
  bucketSuperRootHex:
    '45def9b3c191cd28e630dae51f32d3e2f85f4d8ccf38c0712a23136967f2ec0b',
  onionSuperRootHex:
    'e83efa5730c47b94e8e6af09b1cb76a9e006634645fd39c939bd7b8ea554f8b4',
  paramsHashHex:
    'ac364eb24e24ba025e2dcfdd50b9ccf65ffd556488afc076b70b557084c5318e',
  networkMagicHex: 'f9beb4d9',
  builderBinarySha256Hex:
    'd4da29807e806c8a16eec94b86119bd16df7805a66fa4ff1c187a26832a36427',
  builderGitCommit: 'b692aec18b9c20ac92cb9fe22588e96ff96ad27d',
  description:
    'mainnet_948454 ORAM source proof: roots-only snapshot inputs preserved by the SEV-SNP attested builder for strict direct ORAM rebuild',
};

export const PRODUCTION_DB_PROOF_PINS: DatabaseProofPin[] = [
  DELTA_940611_948454_DB_PROOF_PIN,
];

/**
 * Operator identity pin (Tier-1) for the REQ_ANNOUNCE operator-signed
 * identity flow.
 *
 * The operator's long-term Ed25519 key (generated OFFLINE via
 * `bpir-admin generate-identity --purpose operator`, secret never on a
 * server) signs each server's `IdentityCert`. A client pins the
 * operator's *public* key here and rejects any announce bundle whose
 * cert isn't signed by it. One operator key signs the whole fleet; the
 * per-server `IdentityCert.server_id` (pir1 / pir2) distinguishes them,
 * so this single pin covers both.
 *
 * Pass the decoded bytes to `WasmAnnounceVerification.checkPinnedOperator`
 * (operator pubkey match + cert signature + validity + chain check) —
 * NOT a bare `operatorPubkeyHex` string-compare, which would miss the
 * cert's operator signature.
 *
 * Pinned 2026-05-25. Operator key generated offline via
 * `bpir-admin generate-identity --purpose operator`; the SECRET lives
 * only on the operator's workstation (`~/.config/bpir-admin/operator.key`,
 * backed up out-of-band) and signs the pir1 / pir2 `IdentityCert`s
 * (`bpir-admin sign-identity`, valid_until 2029-05).
 *
 * LIVE END-TO-END (verified 2026-06-27, still used by the current
 * production binaries). pir1 + pir2 both serve REQ_ANNOUNCE on
 * announce-enabled binaries (pir1 db-proof `d01e5b7a...`, pir2 ORAM
 * `23354188...`); `announce()` against either returns an
 * operator-endorsed bundle that verifies under this pinned key
 * (operator-pin + cert signature + validity + chain + channel binding).
 * The "verified operator" badge is wired into the DPF + HarmonyPIR cards
 * (web/index.html) and the playground, gated on `state === 'verified'`.
 * See docs/OPERATOR_IDENTITY.md.
 */
export const PIR_OPERATOR_PUBKEY_HEX =
  '256fb106c039f8009d3caa431a9634ff3fe5db3b9e4d9ae7282bbde66772c97a';

/** Decoded 32-byte operator pubkey for
 *  `WasmAnnounceVerification.checkPinnedOperator`. See provenance +
 *  the live deployment note on [`PIR_OPERATOR_PUBKEY_HEX`]. */
export const PIR_OPERATOR_PUBKEY: Uint8Array = (() => {
  const hex = PIR_OPERATOR_PUBKEY_HEX;
  if (hex.length !== 64) {
    throw new Error(
      `attest-pin: PIR_OPERATOR_PUBKEY_HEX must be 64 hex chars, got ${hex.length}`,
    );
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
})();
