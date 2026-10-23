import { bytesToHex } from './hash.js';
import type { WasmPolicyRequirements } from './sdk-bridge.js';
import type { DatabaseProofPin } from './db-proof.js';

/**
 * Operator-pinned 32-byte SHA-256 fingerprint of the AMD Turin-family ARK
 * (Root Key) certificate, as hex. Same value as the Rust constant
 * `pir-attest-verify::TURIN_ARK_FINGERPRINT_SHA256`.
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
 *   3. Replace the hex below and the Rust constant.
 *
 * Same fingerprint applies to all Turin-family chips. Other generations
 * have their own ARK and pin (Milan: [`AMD_MILAN_ARK_FINGERPRINT_HEX`]).
 */
export const AMD_TURIN_ARK_FINGERPRINT_HEX =
  '1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a';

/**
 * The AMD Milan-family ARK fingerprint, for SEV hosts on Milan (EPYC 7003).
 * Pinned 2026-10-02 from https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
 * (second PEM block, CN=ARK-Milan) for the VPSBG Direct ORAM host (EPYC
 * 7713P). Same role and rotation steps as the Turin pin above (Rust:
 * `pir-attest-verify::MILAN_ARK_FINGERPRINT_SHA256`). Reports chained to it
 * must also meet [`AMD_MILAN_SEV_SNP_FLOOR`].
 */
export const AMD_MILAN_ARK_FINGERPRINT_HEX =
  '69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd';

function arkHexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Bytes of [`AMD_TURIN_ARK_FINGERPRINT_HEX`]. */
export const AMD_TURIN_ARK_FINGERPRINT: Uint8Array = arkHexToBytes(AMD_TURIN_ARK_FINGERPRINT_HEX);

/** Bytes of [`AMD_MILAN_ARK_FINGERPRINT_HEX`]. */
export const AMD_MILAN_ARK_FINGERPRINT: Uint8Array = arkHexToBytes(AMD_MILAN_ARK_FINGERPRINT_HEX);

/**
 * The TCB floor and platform checks every report chained to the Milan ARK
 * must pass ([`applySevSnpPlatformFloor`]). Zen 3 has more public SEV-SNP
 * attacks than Turin, each fixed by microcode or firmware.
 *
 * - `minTcb`: VPSBG server 26939's reported TCB, checked 2026-10-02. On
 *   2026-10-12 no Milan bulletin asks for more: it meets the TCB of every
 *   Milan fix in AMD-SB-3005, 3015, 3016, 3019, 3020, 3023, 3027, 3029 and
 *   3033. The microcode value is a Milan (B1) one; a Milan-X host reports a
 *   lower microcode SVN and would fail.
 * - `requireAliasCheckComplete`: platform_info bit 5, for AMD-SB-3015/3033.
 * - `requiredMitVectorBits`: mitigation-vector bit 1, for AMD-SB-3020.
 *   AMD-SB-3016 defines bit 2, which also needs the host kernel's IOMMU fix;
 *   server 26939 does not set it (2026-10-12), so the floor leaves it out.
 *
 * A report cannot show fixes that ship only in platform firmware
 * (AMD-SB-3030) or protect against physical attacks (AMD-SB-3028/3032).
 * Raise the floor after AMD publishes a new Milan fix.
 */
export const AMD_MILAN_SEV_SNP_FLOOR = {
  minTcb: { bootloader: 4, tee: 0, snp: 29, microcode: 222 },
  requireAliasCheckComplete: true,
  requiredMitVectorBits: 0b10,
} as const;

/**
 * Apply the TCB floor for the generation `arkFingerprint` pins: Milan gets
 * [`AMD_MILAN_SEV_SNP_FLOOR`]; Turin keeps the default policy. Call it on
 * the policy passed to every `verifyFull` with that fingerprint.
 */
export function applySevSnpPlatformFloor(
  policy: Pick<
    WasmPolicyRequirements,
    'setMinTcb' | 'setRequireAliasCheckComplete' | 'setRequiredMitVectorBits'
  >,
  arkFingerprint: Uint8Array | null | undefined,
): void {
  if (!arkFingerprint || bytesToHex(arkFingerprint) !== AMD_MILAN_ARK_FINGERPRINT_HEX) return;
  const { bootloader, tee, snp, microcode } = AMD_MILAN_SEV_SNP_FLOOR.minTcb;
  policy.setMinTcb(bootloader, tee, snp, microcode);
  policy.setRequireAliasCheckComplete(AMD_MILAN_SEV_SNP_FLOOR.requireAliasCheckComplete);
  policy.setRequiredMitVectorBits(AMD_MILAN_SEV_SNP_FLOOR.requiredMitVectorBits);
}

/**
 * Per-server build-time pins for values the SEV-SNP report surfaces.
 * Defense in depth on top of the ARK chain validation: even with a
 * verified chain, mismatches on these self-reported (but in Tier 3
 * MEASUREMENT-covered) values set the state to `'mismatch'`, which the
 * adapter reports.
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
 * This file is the pin catalog. `docs/history/PHASE3_ROADMAP.md` is
 * frozen rationale, not an identity source. Update these fields when
 * a reviewed pir2 UKI republish is accepted (every binary change).
 */
export interface ServerAttestPin {
  measurementHex?: string;
  binarySha256Hex?: string;
  /**
   * A second accepted binary while a host without a TEE switches builds
   * (docs/PRODUCTION_OPERATIONS.md Flow I): the build it runs now, next to
   * the new `binarySha256Hex`. Deploy the pin with both, switch the node
   * whenever, then deploy it again without this field. Leave it unset
   * otherwise; a TEE host's MEASUREMENT pin changes with every build anyway.
   */
  transitionBinarySha256Hex?: string;
  /** Human-readable description shown in the badge tooltip. */
  description?: string;
}

/**
 * Whether a server reporting `binarySha256Hex` satisfies the binary pin:
 * the pinned build, or the transition build while one is set.
 */
export function pinAcceptsBinary(
  pin: { binarySha256Hex?: string; transitionBinarySha256Hex?: string },
  binarySha256Hex: string,
): boolean {
  const reported = binarySha256Hex.toLowerCase();
  return [pin.binarySha256Hex, pin.transitionBinarySha256Hex].some(
    (accepted) => accepted !== undefined && accepted.trim() !== '' && accepted.toLowerCase() === reported,
  );
}

/**
 * weikeng2.bitcoinpir.org — the Direct ORAM host since 2026-10-02: VPSBG
 * server 26939, an AMD EPYC 7713P (Milan), so its reports chain to the
 * Milan ARK and must meet AMD_MILAN_SEV_SNP_FLOOR. Tier 3 runtime UKI image
 * 407 (r12, source `ce2c26ef`, kernel 6.17.0-23, built on pir1; 375 was r11
 * from `987fad2f`) with no server identity: a fresh channel key every boot, bound by the report. It
 * runs `unified_server --oram-only` (no DPF, HarmonyPIR or OnionPIR tables;
 * the attested root is the tagged ORAM-only root), builds Direct ORAM from
 * hash-checked in-memory inputs, and serves it free on a best-effort lane.
 */
export const PIR2_TIER3_PIN: ServerAttestPin = {
  // MEASUREMENT is the offline sev-snp-measure prediction for this UKI +
  // pinned OVMF on 4 Milan vCPUs, equal to the chip-signed report after the
  // switch; binary_sha256 is the stripped unified_server baked into image 407
  // (r12, source ce2c26ef, UKI tier3-20261021T065838Z-7aafdbeae91b.efi).
  measurementHex:
    '8ac1a7a596061b36fa484b34762ea6848ea12fb7a5817d8c8244b32ca3ba752353beea173025a6217781c5575e3c30cc',
  binarySha256Hex:
    '31e777ec06d55f5d9622dcfad4b44d7c4fd27b8a4bb2df146974d60abebb2d76',
  description: 'weikeng2.bitcoinpir.org (VPSBG server 26939, AMD Milan SEV-SNP, Tier 3 image 407: Direct ORAM only, best-effort free)',
};

/**
 * bitcoin-pir-weikeng-laptop.chenweikeng.com — the pir2 replacement after VPSBG pir2
 * (PIR2_TIER3_PIN above) was retired on 2026-10-02: a MacBook (macOS arm64),
 * NO TEE. It serves DPF server 1 and the HarmonyPIR query role (Direct ORAM
 * runs on the VPSBG host). As with PIR1_PIN there is no MEASUREMENT; the binary pin is not
 * hardware-backed but detects drift from the operator-published build. The
 * operator-signed identity (server id pir2-macbook-v1, pir2 operator key)
 * is checked too.
 */
export const PIR2_MACBOOK_PIN: ServerAttestPin = {
  // No measurementHex — no SEV on this host.
  // unified_server built on the MacBook from the r12 release commit ce2c26ef
  // (#443: rustls, rustls-webpki and webpki-roots bumps), `--locked
  // --release`, macOS arm64, rustc 1.94.1; the node switched to it by
  // 2026-10-23 (Flow I, 92 s to Listening; previous build ce5b4373). Access
  // policy --require-credits --access dpf=best-effort:2 --access
  // harmony=best-effort:2 (unchanged).
  binarySha256Hex:
    '22149da25de88c726d72f580e79ce5aa06897cf190876cb4bdc68fd09201bf56',
  description: 'bitcoin-pir-weikeng-laptop.chenweikeng.com (MacBook, no TEE: DPF server 1 + HarmonyPIR query, DPF and HarmonyPIR best-effort free; operator API keys)',
};

/**
 * weikeng1.bitcoinpir.org — Hetzner Intel host, NO SEV-SNP. The public
 * endpoint is independently keyed and pinned below. No MEASUREMENT to
 * pin (no SEV report). binary_sha256 IS pinnable — the value isn't
 * hardware-backed without SEV, but pinning still detects accidental
 * drift between what the operator claims is deployed and what's
 * actually running.
 */
export const PIR1_PIN: ServerAttestPin = {
  // No measurementHex — Hetzner has no SEV.
  // unified_server from the r12 Flow D rebuild of ce2c26ef (#443: rustls,
  // rustls-webpki and webpki-roots bumps), `--locked --release` + strip,
  // switched to on 2026-10-21. Access policy
  // --require-credits --access dpf=best-effort:2 --access
  // harmony=best-effort:1:1500000 --access onion=best-effort:1:3000000:
  // DPF is free while pir1 has room, HarmonyPIR hints are free up to 1.5M
  // gas per hour, OnionPIR one lookup at a time up to 3M gas per hour.
  binarySha256Hex:
    '97487ef98dc760c56a632b82be52886fe96e91903343f613a58c46f25a766558',
  description: 'weikeng1.bitcoinpir.org (Hetzner, no SEV, unified_server ce2c26ef: DPF best-effort free, HarmonyPIR hints best-effort free up to 1.5M gas/hour, OnionPIR best-effort free up to 3M gas/hour; operator API keys)',
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
  fromMuhashHex:
    'aebb29df12e045ef5279036263aba3b8f8e9e816e05b04a58f57e63b3b25756b',
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
    'historical mainnet_948454 v1 database roots; retained for DB-proof compatibility, never sufficient for paid ORAM source verification',
};

/** The same verified snapshot database bundle, named for the DPF/Harmony
 * query-root flow rather than its additional use as the direct-ORAM source. */
export const MAINNET_948454_DB_PROOF_PIN: DatabaseProofPin = {
  ...MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN,
  description:
    'mainnet_948454 full snapshot: Bitcoin Core MuHash and PIR Merkle roots from the SEV-SNP attested builder',
};

export const PRODUCTION_DB_PROOF_PINS: DatabaseProofPin[] = [
  MAINNET_948454_DB_PROOF_PIN,
  DELTA_940611_948454_DB_PROOF_PIN,
];

/** v2 pins for the Hetzner OnionPIR service. Unlike the v1 pins above
 * (retained for DPF/Harmony compatibility), these bind the complete typed
 * Onion query layout and the reviewed re-attestation producer. */
export const PRODUCTION_ONION_DB_PROOF_V2_PINS: DatabaseProofPin[] = [
  {
    dbId: 0,
    buildKind: 'snapshot',
    fromHeight: 0,
    height: 948454,
    fromBlockHashHex: MAINNET_948454_DB_PROOF_PIN.fromBlockHashHex,
    blockHashHex: MAINNET_948454_DB_PROOF_PIN.blockHashHex,
    muhashHex: MAINNET_948454_DB_PROOF_PIN.muhashHex,
    bucketSuperRootHex: MAINNET_948454_DB_PROOF_PIN.bucketSuperRootHex,
    onionSuperRootHex: MAINNET_948454_DB_PROOF_PIN.onionSuperRootHex,
    paramsHashHex: 'a600f33fa0e644aab533a050eabf9c03882aa00f1b293ddf9d7f4bf7c8142563',
    networkMagicHex: 'f9beb4d9',
    builderBinarySha256Hex: '1150d6a2d746398d9046e677e1f0d36f4c4ccb3c390265ea8cf14d7c1f23671c',
    builderGitCommit: 'd49a199e290ccbb05b6481c5ba691cb516aa76bb',
    onionEntrySize: 3_328,
    proofVersion: 2,
    onionTotalPackedEntries: 948_640,
    onionIndexBinsPerTable: 10_273,
    onionChunkBinsPerTable: 37_954,
    onionIndexSlotsPerBin: 221,
    onionIndexSlotSize: 15,
    description: 'mainnet_948454 database proof v2 with complete OnionPIR layout binding',
  },
  {
    dbId: 1,
    buildKind: 'delta',
    fromHeight: 940611,
    height: 948454,
    fromBlockHashHex: DELTA_940611_948454_DB_PROOF_PIN.fromBlockHashHex,
    fromMuhashHex: DELTA_940611_948454_DB_PROOF_PIN.fromMuhashHex,
    blockHashHex: DELTA_940611_948454_DB_PROOF_PIN.blockHashHex,
    muhashHex: DELTA_940611_948454_DB_PROOF_PIN.muhashHex,
    bucketSuperRootHex: DELTA_940611_948454_DB_PROOF_PIN.bucketSuperRootHex,
    onionSuperRootHex: DELTA_940611_948454_DB_PROOF_PIN.onionSuperRootHex,
    paramsHashHex: 'fe6f516696bafaa2226cc1bdc7888c7c69dd263a84817dd0f18cf8027123c45d',
    networkMagicHex: 'f9beb4d9',
    builderBinarySha256Hex: '1150d6a2d746398d9046e677e1f0d36f4c4ccb3c390265ea8cf14d7c1f23671c',
    builderGitCommit: 'd49a199e290ccbb05b6481c5ba691cb516aa76bb',
    onionEntrySize: 3_328,
    proofVersion: 2,
    onionTotalPackedEntries: 116_030,
    onionIndexBinsPerTable: 965,
    onionChunkBinsPerTable: 4_792,
    onionIndexSlotsPerBin: 221,
    onionIndexSlotSize: 15,
    description: 'delta_940611_948454 database proof v2 with complete OnionPIR layout binding',
  },
];

/** v2 pins for the VPSBG Direct ORAM service. The layout and database
 * roots match the Onion service; the native full-build producer has its own
 * builder identity. */
export const PRODUCTION_ORAM_DB_PROOF_V2_PINS: DatabaseProofPin[] =
  PRODUCTION_ONION_DB_PROOF_V2_PINS.map((pin) => ({
    ...pin,
    builderBinarySha256Hex: 'cf973a833f9b892743e451da4c2937c82865b12d8901c48ac4483b5e0696ba6f',
    builderGitCommit: '8d9d21a6be560236cb666269cf1f93a3de53bb1f',
    description: `${pin.description}; VPSBG native full-build producer`,
  }));
