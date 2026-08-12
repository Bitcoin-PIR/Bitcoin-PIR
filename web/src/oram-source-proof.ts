import { extractSnpMeasurement, extractSnpReportData } from './bhtm-proof.js';
import { getAmdTurinArkFingerprint } from './attest-pin.js';
import type { DatabaseProofPin, VerifiedDatabaseProof } from './db-proof.js';
import { verifyDatabaseProofAgainstPin } from './db-proof.js';
import { bytesToHex, hexToBytes, sha256 } from './hash.js';
import { fetchProofArtifactBytesV1 } from './proof-artifact-fetch.js';
import { requireSdkWasm } from './sdk-bridge.js';

const DB_EVIDENCE_V1_DOMAIN = new TextEncoder().encode(
  'BitcoinPIR/attested-builder/build-evidence/v1\0',
);
const DB_EVIDENCE_V2_DOMAIN = new TextEncoder().encode(
  'BitcoinPIR/attested-builder/build-evidence/v2\0',
);
const DB_REPORT_DATA_V1_DOMAIN = new TextEncoder().encode(
  'BitcoinPIR/attested-builder/build-evidence/report-data/v1\0',
);
const DB_REPORT_DATA_V2_DOMAIN = new TextEncoder().encode(
  'BitcoinPIR/attested-builder/build-evidence/report-data/v2\0',
);
const DB_PARAMS_V2_DOMAIN = new TextEncoder().encode('BPIR_BUILD_PARAMS_V2\0');

export const DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH =
  '/proofs/oram-source/current.json';

export interface OramSourceArtifactRef {
  path: string;
  sha256: string;
  size: number;
}

export interface OramSourceProofManifest {
  schemaVersion: number;
  proofType: string;
  id: string;
  description?: string;
  attestedBuilder: {
    /** Browser policy pin for the AMD-signed builder image. */
    measurementHex: string;
    artifacts: Record<string, OramSourceArtifactRef>;
  };
}

export interface OramSourceProofCheck {
  name: string;
  state: 'verified' | 'unverified' | 'unavailable';
  message?: string;
}

export interface VerifiedOramSourceProof {
  manifest: OramSourceProofManifest;
  buildEvidence: AttestedBuildEvidence;
  directInputs: DirectOramManifestBinding;
}

export interface OramSourceProofStatus {
  state: 'not-checked' | 'verified' | 'unverified' | 'unavailable';
  manifest?: OramSourceProofManifest;
  verified?: VerifiedOramSourceProof;
  checks: OramSourceProofCheck[];
  mismatches: string[];
  error?: string;
}

export interface VerifyOramSourceProofOptions {
  manifestPath?: string;
  artifactLoader?: (path: string) => Promise<Uint8Array>;
  expectedDbPin?: DatabaseProofPin;
  /** The proof verified on the current ORAM server connection. Required. */
  liveDatabaseProof?: VerifiedDatabaseProof;
  /** The current strict runtime attestation and its db-local manifest root. Required. */
  liveRuntime?: OramSourceLiveRuntime;
  /** Defaults to true. False is restricted to forensic/offline fixture tests. */
  verifyAmdSignature?: boolean;
}

export interface OramSourceLiveRuntime {
  state: string;
  sevStatus?: string;
  vcekChain?: string;
  pinStatus?: string;
  /** Root for this exact db, selected from the attested catalog by the caller. */
  manifestRootHex?: string;
}

export interface DirectOramManifestBinding {
  version: string;
  index_sha256: string;
  index_bytes: string;
  index_records: string;
  chunk_sha256: string;
  chunk_bytes: string;
  chunk_records: string;
  index_slots_per_bin: string;
  index_hash_fns: string;
  index_load_factor_ppb: string;
  index_seed: string;
}

export interface AttestedChainAnchor {
  blockHashHex: string;
  height: number;
}

export interface AttestedBuildEvidence {
  version: 1 | 2;
  builderGitCommit: string;
  builderBinarySha256Hex: string;
  teePlatform: string;
  teeImageMeasurementHex: string;
  coreVersion: string;
  snapshotSha256Hex: string;
  snapshotBytesDecimal: string;
  networkMagicHex: string;
  buildKind: 'snapshot' | 'delta';
  fromAnchor: AttestedChainAnchor;
  anchor: AttestedChainAnchor;
  utxoMuhashHex: string;
  dustThresholdSatsDecimal: string;
  maxUtxosPerSpk: number;
  paramsHashHex: string;
  indexBinsPerTable: number;
  chunkBinsPerTable: number;
  onionEntrySize: number;
  bucketSuperRootHex: string;
  onionSuperRootHex: string;
  rootBundlePayloadSha256Hex: string;
  signedRootBundleSha256Hex?: string;
  databaseManifestSha256Hex: string;
  allArtifactsManifestSha256Hex: string;
  serverDbManifestSha256Hex: string;
  evidenceMode: 'full-build' | 'reattest-existing';
  predecessorEvidenceSha256Hex?: string;
  predecessorReportSha256Hex?: string;
  onionLayoutV2?: {
    totalPackedEntries: number;
    indexBinsPerTable: number;
    chunkBinsPerTable: number;
  };
}

interface AttestedRootBundlePayload {
  networkMagicHex: string;
  buildKind: 'snapshot' | 'delta';
  fromAnchor: AttestedChainAnchor;
  anchor: AttestedChainAnchor;
  utxoMuhashHex: string;
  dustThresholdSatsDecimal: string;
  maxUtxosPerSpk: number;
  paramsHashHex: string;
  issuedAtDecimal: string;
  roots: Map<string, string>;
}

class StrictByteCursor {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  take(length: number, field: string): Uint8Array {
    const end = this.offset + length;
    if (!Number.isSafeInteger(length) || length < 0 || end > this.bytes.length) {
      throw new Error(`truncated ${field}`);
    }
    const value = this.bytes.slice(this.offset, end);
    this.offset = end;
    return value;
  }

  u8(field: string): number {
    return this.take(1, field)[0];
  }

  u16(field: string): number {
    return new DataView(this.take(2, field).buffer).getUint16(0, true);
  }

  u32(field: string): number {
    return new DataView(this.take(4, field).buffer).getUint32(0, true);
  }

  u64Decimal(field: string): string {
    return new DataView(this.take(8, field).buffer).getBigUint64(0, true).toString();
  }

  i64Decimal(field: string): string {
    return new DataView(this.take(8, field).buffer).getBigInt64(0, true).toString();
  }

  hex(length: number, field: string): string {
    return bytesToHex(this.take(length, field));
  }

  displayHashHex(field: string): string {
    return bytesToHex(this.take(32, field).slice().reverse());
  }

  lengthPrefixedBytes(field: string, maximum: number): Uint8Array {
    const length = this.u16(`${field} length`);
    if (length > maximum) throw new Error(`${field} exceeds ${maximum} bytes`);
    return this.take(length, field);
  }

  string(field: string): string {
    const bytes = this.lengthPrefixedBytes(field, 4096);
    let value: string;
    try {
      value = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      throw new Error(`${field} is not UTF-8`);
    }
    if (/[\0\r\n]/.test(value)) throw new Error(`${field} contains newline or NUL`);
    return value;
  }

  finish(): void {
    if (this.offset !== this.bytes.length) {
      throw new Error(`trailing bytes (${this.bytes.length - this.offset})`);
    }
  }
}

function decodeBuildKind(value: number, field: string): 'snapshot' | 'delta' {
  if (value === 0) return 'snapshot';
  if (value === 1) return 'delta';
  throw new Error(`unknown ${field} ${value}`);
}

function decodeAnchor(cursor: StrictByteCursor, field: string): AttestedChainAnchor {
  return {
    blockHashHex: cursor.displayHashHex(`${field} block hash`),
    height: cursor.u32(`${field} height`),
  };
}

function decodeOptionalHash(cursor: StrictByteCursor, field: string): string | undefined {
  const tag = cursor.u8(`${field} option tag`);
  if (tag === 0) return undefined;
  if (tag === 1) return cursor.hex(32, field);
  throw new Error(`bad ${field} option tag ${tag}`);
}

/** Strict mirror of `pir_db_attest::BuildEvidence::decode`. */
export function parseAttestedBuildEvidence(bytes: Uint8Array): AttestedBuildEvidence {
  const cursor = new StrictByteCursor(bytes);
  const rawVersion = cursor.u16('BuildEvidence version');
  if (rawVersion !== 1 && rawVersion !== 2) {
    throw new Error(`unsupported BuildEvidence version ${rawVersion}`);
  }
  const version = rawVersion as 1 | 2;
  const builderGitCommit = cursor.string('builder_git_commit');
  const builderBinarySha256Hex = cursor.hex(32, 'builder_binary_sha256');
  const teePlatform = cursor.string('tee_platform');
  const teeImageMeasurementHex = bytesToHex(
    cursor.lengthPrefixedBytes('tee_image_measurement', 4096),
  );
  const coreVersion = cursor.string('core_version');
  const snapshotSha256Hex = cursor.hex(32, 'snapshot_sha256');
  const snapshotBytesDecimal = cursor.u64Decimal('snapshot_bytes');
  const networkMagicHex = cursor.hex(4, 'network_magic');
  const buildKind = decodeBuildKind(cursor.u8('build_kind'), 'build kind');
  const fromAnchor = decodeAnchor(cursor, 'from_anchor');
  const anchor = decodeAnchor(cursor, 'anchor');
  const utxoMuhashHex = cursor.displayHashHex('utxo_muhash');
  const dustThresholdSatsDecimal = cursor.u64Decimal('dust_threshold_sats');
  const maxUtxosPerSpk = cursor.u32('max_utxos_per_spk');
  const paramsHashHex = cursor.hex(32, 'params_hash');
  const indexBinsPerTable = cursor.u32('index_bins_per_table');
  const chunkBinsPerTable = cursor.u32('chunk_bins_per_table');
  const onionEntrySize = cursor.u32('onion_entry_size');
  const bucketSuperRootHex = cursor.hex(32, 'bucket_super_root');
  const onionSuperRootHex = cursor.hex(32, 'onion_super_root');
  const rootBundlePayloadSha256Hex = cursor.hex(32, 'root_bundle_payload_sha256');
  const signedRootBundleSha256Hex = decodeOptionalHash(cursor, 'signed_root_bundle_sha256');
  const databaseManifestSha256Hex = cursor.hex(32, 'database_manifest_sha256');
  const allArtifactsManifestSha256Hex = cursor.hex(32, 'all_artifacts_manifest_sha256');
  const serverDbManifestSha256Hex = cursor.hex(32, 'server_db_manifest_sha256');

  let evidenceMode: 'full-build' | 'reattest-existing' = 'full-build';
  let predecessorEvidenceSha256Hex: string | undefined;
  let predecessorReportSha256Hex: string | undefined;
  let onionLayoutV2: AttestedBuildEvidence['onionLayoutV2'];
  if (version === 2) {
    const rawMode = cursor.u8('evidence_mode');
    if (rawMode !== 0 && rawMode !== 1) throw new Error(`unknown evidence mode ${rawMode}`);
    evidenceMode = rawMode === 0 ? 'full-build' : 'reattest-existing';
    predecessorEvidenceSha256Hex = decodeOptionalHash(cursor, 'predecessor_evidence_sha256');
    predecessorReportSha256Hex = decodeOptionalHash(cursor, 'predecessor_report_sha256');
    if (
      evidenceMode === 'reattest-existing'
      && (!predecessorEvidenceSha256Hex || !predecessorReportSha256Hex)
    ) {
      throw new Error('reattest-existing evidence is missing predecessor hashes');
    }
    onionLayoutV2 = {
      totalPackedEntries: cursor.u32('onion_total_packed_entries'),
      indexBinsPerTable: cursor.u32('onion_index_bins_per_table'),
      chunkBinsPerTable: cursor.u32('onion_chunk_bins_per_table'),
    };
    if (
      onionLayoutV2.totalPackedEntries === 0
      || onionLayoutV2.indexBinsPerTable === 0
      || onionLayoutV2.chunkBinsPerTable === 0
      || onionEntrySize === 0
      || onionEntrySize % 32 !== 0
      || Math.floor(onionEntrySize / 15) > 0xffff
      || Math.floor(onionEntrySize / 32) > 0xffff
    ) {
      throw new Error('invalid v2 Onion query dimensions');
    }
  }
  cursor.finish();

  return {
    version,
    builderGitCommit,
    builderBinarySha256Hex,
    teePlatform,
    teeImageMeasurementHex,
    coreVersion,
    snapshotSha256Hex,
    snapshotBytesDecimal,
    networkMagicHex,
    buildKind,
    fromAnchor,
    anchor,
    utxoMuhashHex,
    dustThresholdSatsDecimal,
    maxUtxosPerSpk,
    paramsHashHex,
    indexBinsPerTable,
    chunkBinsPerTable,
    onionEntrySize,
    bucketSuperRootHex,
    onionSuperRootHex,
    rootBundlePayloadSha256Hex,
    signedRootBundleSha256Hex,
    databaseManifestSha256Hex,
    allArtifactsManifestSha256Hex,
    serverDbManifestSha256Hex,
    evidenceMode,
    predecessorEvidenceSha256Hex,
    predecessorReportSha256Hex,
    onionLayoutV2,
  };
}

function appendU16Le(out: number[], value: number): void {
  out.push(value & 0xff, (value >>> 8) & 0xff);
}

function appendU32Le(out: number[], value: number): void {
  out.push(
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff,
  );
}

function appendU64Le(out: number[], value: bigint): void {
  for (let shift = 0n; shift < 64n; shift += 8n) {
    out.push(Number((value >> shift) & 0xffn));
  }
}

function directDpfBits(bins: number): number {
  if (bins <= 2) return 1;
  let remaining = bins - 1;
  let bits = 0;
  while (remaining > 0) {
    remaining = Math.floor(remaining / 2);
    bits += 1;
  }
  return bits;
}

function appendBuildTableParams(
  out: number[],
  k: number,
  bins: number,
  slots: number,
  slotSize: number,
  magic: bigint,
  headerSize: number,
  hasTagSeed: boolean,
): void {
  appendU16Le(out, k);
  appendU16Le(out, 3);
  appendU32Le(out, bins);
  appendU16Le(out, slots);
  appendU16Le(out, 2);
  appendU16Le(out, slotSize);
  out.push(directDpfBits(bins));
  appendU64Le(out, magic);
  appendU16Le(out, headerSize);
  out.push(hasTagSeed ? 1 : 0);
}

/** Strict mirror of `pir_db_attest::BuildParamsV2::params_hash`. */
export function paramsHashV2ForAttestedBuildEvidence(
  evidence: AttestedBuildEvidence,
): string {
  if (evidence.version !== 2 || !evidence.onionLayoutV2) {
    throw new Error('BuildEvidence v2 Onion layout is required');
  }
  const out: number[] = [];
  appendU16Le(out, 2);
  for (const value of [68, 20, 32, 25, 40, 1]) appendU16Le(out, value);
  appendBuildTableParams(
    out,
    75,
    evidence.indexBinsPerTable,
    4,
    13,
    0xba7cc000c0000004n,
    40,
    true,
  );
  appendBuildTableParams(
    out,
    80,
    evidence.chunkBinsPerTable,
    3,
    44,
    0xba7cc000c0000002n,
    32,
    false,
  );
  appendU32Le(out, evidence.onionEntrySize);
  for (const value of [
    27,
    15,
    Math.floor(evidence.onionEntrySize / 15),
    80,
    8,
    32,
    0,
  ]) {
    appendU16Le(out, value);
  }
  appendU32Le(out, evidence.onionLayoutV2.totalPackedEntries);
  appendU32Le(out, evidence.onionLayoutV2.indexBinsPerTable);
  appendU32Le(out, evidence.onionLayoutV2.chunkBinsPerTable);
  return bytesToHex(sha256(concatBytes(DB_PARAMS_V2_DOMAIN, Uint8Array.from(out))));
}

/** Strict mirror of `rootbundle::RootBundlePayload::decode`. */
function parseAttestedRootBundlePayload(bytes: Uint8Array): AttestedRootBundlePayload {
  const cursor = new StrictByteCursor(bytes);
  const version = cursor.u16('root bundle version');
  if (version !== 1) throw new Error(`unsupported root bundle version ${version}`);
  const networkMagicHex = cursor.hex(4, 'root bundle network magic');
  const buildKind = decodeBuildKind(cursor.u8('root bundle build kind'), 'root bundle build kind');
  const fromAnchor = decodeAnchor(cursor, 'root bundle from_anchor');
  const anchor = decodeAnchor(cursor, 'root bundle anchor');
  const utxoMuhashHex = cursor.displayHashHex('root bundle utxo_muhash');
  const dustThresholdSatsDecimal = cursor.u64Decimal('root bundle dust_threshold_sats');
  const maxUtxosPerSpk = cursor.u32('root bundle max_utxos_per_spk');
  const paramsHashHex = cursor.hex(32, 'root bundle params_hash');
  const issuedAtDecimal = cursor.i64Decimal('root bundle issued_at');
  const rootCount = cursor.u16('root bundle root count');
  if (rootCount === 0 || rootCount > 1024) throw new Error('invalid root bundle root count');
  const roots = new Map<string, string>();
  let previousLabel: string | undefined;
  for (let i = 0; i < rootCount; i += 1) {
    const labelLength = cursor.u8(`root ${i} label length`);
    if (labelLength === 0 || labelLength > 64) throw new Error(`invalid root ${i} label length`);
    const labelBytes = cursor.take(labelLength, `root ${i} label`);
    if (!labelBytes.every((byte) => byte >= 0x21 && byte <= 0x7e)) {
      throw new Error(`invalid root ${i} label bytes`);
    }
    const label = new TextDecoder().decode(labelBytes);
    if (previousLabel !== undefined && previousLabel >= label) {
      throw new Error('root bundle labels are not strictly sorted');
    }
    previousLabel = label;
    roots.set(label, cursor.hex(32, `root ${label}`));
  }
  cursor.finish();
  return {
    networkMagicHex,
    buildKind,
    fromAnchor,
    anchor,
    utxoMuhashHex,
    dustThresholdSatsDecimal,
    maxUtxosPerSpk,
    paramsHashHex,
    issuedAtDecimal,
    roots,
  };
}

export async function verifyOramSourceProof(
  options: VerifyOramSourceProofOptions = {},
): Promise<OramSourceProofStatus> {
  const checks: OramSourceProofCheck[] = [];
  const mismatches: string[] = [];
  const loader = options.artifactLoader ?? fetchProofArtifactBytesV1;
  const manifestPath = options.manifestPath ?? DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH;

  try {
    const manifest = await loadJson<OramSourceProofManifest>(manifestPath, loader);
    validateManifestShape(manifest);
    checks.push({ name: 'manifest loaded', state: 'verified', message: manifest.id });

    const artifacts = await verifyManifestArtifacts(manifest, loader, checks);
    const buildEvidenceBytes = requiredArtifact(artifacts, 'attestedBuilder.buildEvidence');
    const attestedBuildEvidence = parseAttestedBuildEvidence(buildEvidenceBytes);

    const dbBefore = mismatches.length;
    const directInputs = compareAttestedDbEvidence(
      attestedBuildEvidence,
      manifest,
      artifacts,
      mismatches,
    );
    checks.push(checkFromMismatches('AMD-attested Direct ORAM inputs matched', mismatches, dbBefore));

    const reportBefore = mismatches.length;
    const expectedReportData = reportDataForBuildEvidence(buildEvidenceBytes);
    const report = requiredArtifact(artifacts, 'attestedBuilder.sevSnpReport');
    compareHex(
      'BuildEvidence-derived REPORT_DATA',
      bytesToHex(expectedReportData),
      bytesToHex(extractSnpReportData(report)),
      mismatches,
    );
    compareHex(
      'attested-builder SNP MEASUREMENT field',
      bytesToHex(extractSnpMeasurement(report)),
      manifest.attestedBuilder.measurementHex,
      mismatches,
    );
    checks.push(checkFromMismatches('BuildEvidence REPORT_DATA matched', mismatches, reportBefore));

    if (options.verifyAmdSignature ?? true) {
      verifyStaticSnpReportSignature(artifacts, report, manifest);
      checks.push({ name: 'attested-builder SNP signature and certificate chain', state: 'verified' });
    } else {
      mismatches.push('AMD signature verification was disabled for an offline fixture');
      checks.push({
        name: 'attested-builder SNP signature and certificate chain',
        state: 'unverified',
        message: 'disabled only for an offline forensic fixture',
      });
    }

    const sourceProof = databaseProofFromAttestedBuildEvidence(
      attestedBuildEvidence,
      options.expectedDbPin?.dbId ?? options.liveDatabaseProof?.dbId ?? -1,
    );

    if (options.expectedDbPin) {
      const pinBefore = mismatches.length;
      const status = verifyDatabaseProofAgainstPin(sourceProof, options.expectedDbPin);
      if (status.state !== 'verified') {
        mismatches.push(...(status.mismatches ?? []).map((m) => `attested DB pin: ${m}`));
      }
      checks.push(checkFromMismatches('attested DB matches production v2 pin', mismatches, pinBefore));
    } else {
      mismatches.push('expectedDbPin is required before an ORAM source proof can be trusted');
      checks.push({
        name: 'attested DB matches production v2 pin',
        state: 'unverified',
        message: 'no expectedDbPin supplied',
      });
    }

    if (options.liveDatabaseProof) {
      const liveBefore = mismatches.length;
      const liveStatus = verifyDatabaseProofAgainstPin(options.liveDatabaseProof, sourceProof);
      if (liveStatus.state !== 'verified') {
        mismatches.push(
          ...(liveStatus.mismatches ?? []).map((m) => `live ORAM DB proof: ${m}`),
        );
      }
      checks.push(checkFromMismatches('live DB proof matches attested source', mismatches, liveBefore));
    } else {
      mismatches.push('liveDatabaseProof is required before an ORAM source proof can be trusted');
      checks.push({
        name: 'live DB proof matches attested source',
        state: 'unverified',
        message: 'no live verified database proof supplied',
      });
    }

    if (options.liveRuntime) {
      const runtimeBefore = mismatches.length;
      compareLiveRuntimeBinding(
        options.liveRuntime,
        options.liveDatabaseProof,
        attestedBuildEvidence.serverDbManifestSha256Hex,
        mismatches,
      );
      checks.push(checkFromMismatches('live measured runtime binds the same manifest', mismatches, runtimeBefore));
    } else {
      mismatches.push('liveRuntime is required before an ORAM source proof can be trusted');
      checks.push({
        name: 'live measured runtime binds the same manifest',
        state: 'unverified',
        message: 'no live strict runtime attestation supplied',
      });
    }

    const state = mismatches.length === 0 ? 'verified' : 'unverified';
    return {
      state,
      manifest,
      verified: state === 'verified' && directInputs
        ? { manifest, buildEvidence: attestedBuildEvidence, directInputs }
        : undefined,
      checks,
      mismatches,
    };
  } catch (err) {
    const message = (err as Error)?.message ?? String(err);
    const unavailable = /fetch|network|404|not found|no such file|ENOENT|failed to load|missing artifact/i.test(message);
    checks.push({
      name: unavailable ? 'artifact loading' : 'ORAM source-proof verification',
      state: unavailable ? 'unavailable' : 'unverified',
      message,
    });
    return {
      state: unavailable ? 'unavailable' : 'unverified',
      checks,
      mismatches,
      error: message,
    };
  }
}

function databaseProofFromAttestedBuildEvidence(
  evidence: AttestedBuildEvidence,
  dbId: number,
): DatabaseProofPin & VerifiedDatabaseProof {
  return {
    dbId,
    manifestRootHex: evidence.serverDbManifestSha256Hex,
    buildKind: evidence.buildKind,
    fromHeight: evidence.fromAnchor.height,
    fromBlockHashHex: evidence.fromAnchor.blockHashHex,
    height: evidence.anchor.height,
    blockHashHex: evidence.anchor.blockHashHex,
    muhashHex: evidence.utxoMuhashHex,
    bucketSuperRootHex: evidence.bucketSuperRootHex,
    onionSuperRootHex: evidence.onionSuperRootHex,
    paramsHashHex: evidence.paramsHashHex,
    networkMagicHex: evidence.networkMagicHex,
    builderBinarySha256Hex: evidence.builderBinarySha256Hex,
    builderGitCommit: evidence.builderGitCommit,
    onionEntrySize: evidence.onionEntrySize,
    proofVersion: evidence.version,
    onionTotalPackedEntries: evidence.onionLayoutV2?.totalPackedEntries,
    onionIndexBinsPerTable: evidence.onionLayoutV2?.indexBinsPerTable,
    onionChunkBinsPerTable: evidence.onionLayoutV2?.chunkBinsPerTable,
    onionIndexSlotsPerBin: evidence.version === 2
      ? Math.floor(evidence.onionEntrySize / 15)
      : undefined,
    onionIndexSlotSize: evidence.version === 2 ? 15 : undefined,
  };
}

function compareLiveRuntimeBinding(
  runtime: OramSourceLiveRuntime,
  liveProof: VerifiedDatabaseProof | undefined,
  attestedManifestRootHex: string,
  mismatches: string[],
): void {
  compareString('live runtime attestation state', runtime.state, 'verified-vcek', mismatches);
  compareString('live runtime REPORT_DATA', runtime.sevStatus ?? '', 'reportDataMatch', mismatches);
  compareString('live runtime VCEK chain', runtime.vcekChain ?? '', 'pass', mismatches);
  compareString('live runtime production pin', runtime.pinStatus ?? '', 'match', mismatches);
  compareHex(
    'live runtime manifest root',
    runtime.manifestRootHex ?? '',
    attestedManifestRootHex,
    mismatches,
  );
  if (liveProof) {
    compareHex(
      'live DB proof/runtime manifest root',
      liveProof.manifestRootHex ?? '',
      runtime.manifestRootHex ?? '',
      mismatches,
    );
  }
}

/**
 * Reproduce `pir_db_attest::report_data_for_evidence_bytes` exactly.
 * The low half commits to the domain-separated binary BuildEvidence bytes;
 * the high half commits to that digest under a second domain. This check is
 * what turns the SNP report's REPORT_DATA from a manifest assertion into a
 * binding to the actual `build-evidence.bin` artifact.
 */
export function reportDataForBuildEvidence(evidenceBytes: Uint8Array): Uint8Array {
  const { version } = parseAttestedBuildEvidence(evidenceBytes);
  const evidenceDomain = version === 1 ? DB_EVIDENCE_V1_DOMAIN : DB_EVIDENCE_V2_DOMAIN;
  const reportDomain = version === 1
    ? DB_REPORT_DATA_V1_DOMAIN
    : DB_REPORT_DATA_V2_DOMAIN;
  const evidenceHash = sha256(concatBytes(evidenceDomain, evidenceBytes));
  const high = sha256(concatBytes(reportDomain, evidenceHash));
  return concatBytes(evidenceHash, high);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function verifyManifestArtifacts(
  manifest: OramSourceProofManifest,
  loader: (path: string) => Promise<Uint8Array>,
  checks: OramSourceProofCheck[],
): Promise<Map<string, Uint8Array>> {
  const refs: Array<[string, OramSourceArtifactRef]> = [];
  collectRefs('attestedBuilder', manifest.attestedBuilder.artifacts, refs);

  const out = new Map<string, Uint8Array>();
  for (const [name, ref] of refs) {
    const bytes = await loader(ref.path);
    if (bytes.length !== ref.size) {
      throw new Error(`${name}: artifact size mismatch for ${ref.path}: expected ${ref.size}, got ${bytes.length}`);
    }
    const digest = bytesToHex(sha256(bytes));
    if (normalizeHex(digest) !== normalizeHex(ref.sha256)) {
      throw new Error(`${name}: artifact sha256 mismatch for ${ref.path}: expected ${ref.sha256}, got ${digest}`);
    }
    checks.push({ name: `artifact ${name}`, state: 'verified', message: ref.path });
    out.set(name, bytes);
  }
  return out;
}

function collectRefs(
  prefix: string,
  refs: Record<string, OramSourceArtifactRef>,
  out: Array<[string, OramSourceArtifactRef]>,
): void {
  for (const [name, ref] of Object.entries(refs)) {
    out.push([`${prefix}.${name}`, ref]);
  }
}

function verifyStaticSnpReportSignature(
  artifacts: Map<string, Uint8Array>,
  sevSnpReport: Uint8Array,
  manifest: OramSourceProofManifest,
): void {
  // Resolve the certificate artifacts before loading the WASM verifier.  A
  // proof bundle that omitted its chain is unavailable regardless of whether
  // the local SDK happened to initialize, and must fail with that precise
  // reason.
  const arkPem = decodeUtf8(requiredArtifact(artifacts, 'attestedBuilder.arkPem'));
  const askPem = decodeUtf8(requiredArtifact(artifacts, 'attestedBuilder.askPem'));
  const vcekPem = decodeUtf8(requiredArtifact(artifacts, 'attestedBuilder.vcekPem'));
  const sdk = requireSdkWasm();
  const policy = new sdk.WasmPolicyRequirements();
  policy.setExpectedMeasurement(hexToBytes(normalizeHex(manifest.attestedBuilder.measurementHex)));
  sdk.verifyRawSnpReport(
    sevSnpReport,
    arkPem,
    askPem,
    vcekPem,
    getAmdTurinArkFingerprint(),
    policy,
  );
}

function compareAttestedDbEvidence(
  attested: AttestedBuildEvidence,
  manifest: OramSourceProofManifest,
  artifacts: Map<string, Uint8Array>,
  mismatches: string[],
): DirectOramManifestBinding | undefined {
  if (attested.version !== 2) {
    mismatches.push(`production ORAM source proof requires BuildEvidence v2, got v${attested.version}`);
  }
  compareString('attested evidence mode', attested.evidenceMode, 'full-build', mismatches);
  if (
    attested.predecessorEvidenceSha256Hex !== undefined
    || attested.predecessorReportSha256Hex !== undefined
  ) {
    mismatches.push('production ORAM source proof must not use reattestation predecessor hashes');
  }
  if (attested.version === 2) {
    compareHex(
      'attested v2 build-params hash recomputation',
      attested.paramsHashHex,
      paramsHashV2ForAttestedBuildEvidence(attested),
      mismatches,
    );
  }
  if (attested.teeImageMeasurementHex) {
    compareHex(
      'attested TEE image measurement',
      attested.teeImageMeasurementHex,
      manifest.attestedBuilder.measurementHex,
      mismatches,
    );
  }

  const rootBundleBytes = requiredArtifact(artifacts, 'attestedBuilder.rootBundlePayload');
  compareHex(
    'attested root bundle payload bytes sha256',
    attested.rootBundlePayloadSha256Hex,
    bytesToHex(sha256(rootBundleBytes)),
    mismatches,
  );
  compareHex(
    'attested root bundle payload artifact pin',
    attested.rootBundlePayloadSha256Hex,
    manifest.attestedBuilder.artifacts.rootBundlePayload.sha256,
    mismatches,
  );
  compareAttestedRootBundle(attested, rootBundleBytes, mismatches);
  if (attested.signedRootBundleSha256Hex !== undefined) {
    mismatches.push(
      'attested BuildEvidence references a signed root bundle, but this proof has no signed-root-bundle artifact',
    );
  }

  compareAttestedManifestArtifact(
    'database manifest',
    attested.databaseManifestSha256Hex,
    manifest.attestedBuilder.artifacts.databaseManifest,
    requiredArtifact(artifacts, 'attestedBuilder.databaseManifest'),
    mismatches,
  );
  compareAttestedManifestArtifact(
    'all-artifacts manifest',
    attested.allArtifactsManifestSha256Hex,
    manifest.attestedBuilder.artifacts.allArtifactsManifest,
    requiredArtifact(artifacts, 'attestedBuilder.allArtifactsManifest'),
    mismatches,
  );
  const manifestRef = manifest.attestedBuilder.artifacts.serverDbManifest;
  const manifestBytes = requiredArtifact(artifacts, 'attestedBuilder.serverDbManifest');
  compareAttestedManifestArtifact(
    'server DB manifest',
    attested.serverDbManifestSha256Hex,
    manifestRef,
    manifestBytes,
    mismatches,
  );

  try {
    return parseDirectOramManifestBinding(decodeUtf8(manifestBytes));
  } catch (err) {
    mismatches.push(`server DB manifest direct_oram: ${(err as Error).message}`);
    return undefined;
  }
}

function compareAttestedAnchor(
  name: string,
  actual: AttestedChainAnchor,
  expectedHash: string,
  expectedHeight: number,
  mismatches: string[],
): void {
  compareHex(`${name} block hash`, actual.blockHashHex, expectedHash, mismatches);
  compareNumber(`${name} height`, actual.height, expectedHeight, mismatches);
}

function compareAttestedManifestArtifact(
  name: string,
  attestedHash: string,
  artifactRef: OramSourceArtifactRef | undefined,
  bytes: Uint8Array,
  mismatches: string[],
): void {
  compareHex(`attested ${name} bytes sha256`, attestedHash, bytesToHex(sha256(bytes)), mismatches);
  if (!artifactRef) {
    mismatches.push(`${name}: missing manifest artifact reference`);
  } else {
    compareHex(`attested ${name} artifact ref`, attestedHash, artifactRef.sha256, mismatches);
  }
}

function compareAttestedRootBundle(
  attested: AttestedBuildEvidence,
  payloadBytes: Uint8Array,
  mismatches: string[],
): void {
  let payload: AttestedRootBundlePayload;
  try {
    payload = parseAttestedRootBundlePayload(payloadBytes);
  } catch (err) {
    mismatches.push(`attested root bundle payload: ${(err as Error).message}`);
    return;
  }
  compareHex('root bundle network magic', payload.networkMagicHex, attested.networkMagicHex, mismatches);
  compareString('root bundle build kind', payload.buildKind, attested.buildKind, mismatches);
  compareAttestedAnchor(
    'root bundle from anchor',
    payload.fromAnchor,
    attested.fromAnchor.blockHashHex,
    attested.fromAnchor.height,
    mismatches,
  );
  compareAttestedAnchor(
    'root bundle anchor',
    payload.anchor,
    attested.anchor.blockHashHex,
    attested.anchor.height,
    mismatches,
  );
  compareHex('root bundle UTXO MuHash', payload.utxoMuhashHex, attested.utxoMuhashHex, mismatches);
  compareString(
    'root bundle dust threshold',
    payload.dustThresholdSatsDecimal,
    attested.dustThresholdSatsDecimal,
    mismatches,
  );
  compareNumber('root bundle max UTXOs per script', payload.maxUtxosPerSpk, attested.maxUtxosPerSpk, mismatches);
  compareHex('root bundle params hash', payload.paramsHashHex, attested.paramsHashHex, mismatches);
  compareHex(
    'root bundle bucket super-root',
    payload.roots.get('merkle/bucket/super_root') ?? '',
    attested.bucketSuperRootHex,
    mismatches,
  );
  compareHex(
    'root bundle Onion super-root',
    payload.roots.get('merkle/onion/super_root') ?? '',
    attested.onionSuperRootHex,
    mismatches,
  );
}

const DIRECT_ORAM_MANIFEST_KEYS = [
  'version',
  'index_sha256',
  'index_bytes',
  'index_records',
  'chunk_sha256',
  'chunk_bytes',
  'chunk_records',
  'index_slots_per_bin',
  'index_hash_fns',
  'index_load_factor_ppb',
  'index_seed',
] as const;

/**
 * Parse only the security-critical `[direct_oram]` table. The measured build
 * emits this deliberately narrow TOML subset, so accepting broader TOML here
 * would create unnecessary parser-differential risk in the browser verifier.
 */
export function parseDirectOramManifestBinding(text: string): DirectOramManifestBinding {
  const values = new Map<string, string>();
  let inDirectOram = false;
  let sectionCount = 0;

  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    if (line.startsWith('[')) {
      if (line === '[direct_oram]') {
        sectionCount += 1;
        if (sectionCount > 1) {
          throw new Error('duplicate [direct_oram] section');
        }
        inDirectOram = true;
      } else {
        if (!/^\[[^\[\]\r\n]+\]$/.test(line)) {
          throw new Error(`malformed TOML section header on line ${index + 1}`);
        }
        inDirectOram = false;
      }
      continue;
    }

    if (!inDirectOram) continue;
    const assignment = /^([a-z0-9_]+)\s*=\s*(.+)$/.exec(line);
    if (!assignment) {
      throw new Error(`unsupported [direct_oram] assignment on line ${index + 1}`);
    }
    const key = assignment[1];
    if (!(DIRECT_ORAM_MANIFEST_KEYS as readonly string[]).includes(key)) {
      throw new Error(`unknown [direct_oram] key ${key}`);
    }
    if (values.has(key)) {
      throw new Error(`duplicate [direct_oram] key ${key}`);
    }
    const rawValue = assignment[2];
    if (key === 'index_sha256' || key === 'chunk_sha256') {
      const hash = /^"([0-9a-fA-F]{64})"$/.exec(rawValue);
      if (!hash) throw new Error(`[direct_oram] ${key} must be quoted 32-byte hex`);
      values.set(key, hash[1]);
    } else {
      if (!/^(?:0|[1-9][0-9]*)$/.test(rawValue)) {
        throw new Error(`[direct_oram] ${key} must be canonical unquoted decimal`);
      }
      values.set(key, rawValue);
    }
  }

  if (sectionCount === 0) {
    throw new Error('missing [direct_oram] section');
  }
  for (const key of DIRECT_ORAM_MANIFEST_KEYS) {
    if (!values.has(key)) {
      throw new Error(`missing [direct_oram] key ${key}`);
    }
  }
  for (const key of ['index_sha256', 'chunk_sha256'] as const) {
    if (/^0{64}$/.test(values.get(key)!)) {
      throw new Error(`[direct_oram] ${key} must not be all-zero`);
    }
  }
  const u32Max = 0xffff_ffffn;
  // TOML 1.0 integer values are signed 64-bit even when the Rust destination
  // field is `u64`. Match the server's TOML parser exactly.
  const tomlI64Max = 0x7fff_ffff_ffff_ffffn;
  for (const key of DIRECT_ORAM_MANIFEST_KEYS) {
    if (key === 'index_sha256' || key === 'chunk_sha256') continue;
    const value = BigInt(values.get(key)!);
    const maximum = [
      'version',
      'index_slots_per_bin',
      'index_hash_fns',
      'index_load_factor_ppb',
    ].includes(key) ? u32Max : tomlI64Max;
    if (value > maximum) throw new Error(`[direct_oram] ${key} exceeds its integer range`);
  }
  if (values.get('version') !== '1') {
    throw new Error(`unsupported [direct_oram] version ${values.get('version')}`);
  }
  const indexRecords = BigInt(values.get('index_records')!);
  const chunkRecords = BigInt(values.get('chunk_records')!);
  if (indexRecords * 25n !== BigInt(values.get('index_bytes')!)) {
    throw new Error('[direct_oram] INDEX bytes/records mismatch');
  }
  if (chunkRecords * 40n !== BigInt(values.get('chunk_bytes')!)) {
    throw new Error('[direct_oram] CHUNK bytes/records mismatch');
  }
  const slots = BigInt(values.get('index_slots_per_bin')!);
  const hashFunctions = BigInt(values.get('index_hash_fns')!);
  const loadFactorPpb = BigInt(values.get('index_load_factor_ppb')!);
  if (slots === 0n || hashFunctions === 0n || loadFactorPpb === 0n || loadFactorPpb >= 1_000_000_000n) {
    throw new Error('[direct_oram] INDEX layout is invalid');
  }

  return Object.fromEntries(values) as unknown as DirectOramManifestBinding;
}

async function loadJson<T>(path: string, loader: (path: string) => Promise<Uint8Array>): Promise<T> {
  return JSON.parse(decodeUtf8(await loader(path))) as T;
}

function validateManifestShape(manifest: OramSourceProofManifest): void {
  if (manifest.schemaVersion !== 2) {
    throw new Error(`unsupported ORAM source-proof manifest schemaVersion ${manifest.schemaVersion}`);
  }
  if (manifest.proofType !== 'BitcoinPIR/oram-source-binding/v2') {
    throw new Error(`unsupported ORAM source-proof manifest proofType ${manifest.proofType}`);
  }
  if (!manifest.attestedBuilder?.measurementHex || !manifest.attestedBuilder.artifacts) {
    throw new Error('ORAM source-proof manifest missing attested builder policy/artifacts');
  }
  const expectedArtifacts = [
    'allArtifactsManifest',
    'arkPem',
    'askPem',
    'buildEvidence',
    'databaseManifest',
    'rootBundlePayload',
    'serverDbManifest',
    'sevSnpReport',
    'vcekPem',
  ];
  const actualArtifacts = Object.keys(manifest.attestedBuilder.artifacts).sort();
  if (actualArtifacts.join('\0') !== expectedArtifacts.join('\0')) {
    throw new Error(
      `ORAM source-proof artifact set must be closed: expected ${expectedArtifacts.join(', ')}`,
    );
  }
}

function requiredArtifact(artifacts: Map<string, Uint8Array>, name: string): Uint8Array {
  const bytes = artifacts.get(name);
  if (!bytes) throw new Error(`missing artifact ${name}`);
  return bytes;
}

function compareNumber(name: string, actual: number, expected: number, mismatches: string[]): void {
  if (actual !== expected) {
    mismatches.push(`${name}: expected ${expected}, got ${actual}`);
  }
}

function compareString(name: string, actual: string, expected: string, mismatches: string[]): void {
  if (actual !== expected) {
    mismatches.push(`${name}: expected ${expected}, got ${actual}`);
  }
}

function compareHex(name: string, actual: string, expected: string, mismatches: string[]): void {
  if (normalizeHex(actual) !== normalizeHex(expected)) {
    mismatches.push(`${name}: expected ${expected}, got ${actual}`);
  }
}

function checkFromMismatches(name: string, mismatches: string[], start = 0): OramSourceProofCheck {
  const own = mismatches.slice(start);
  return own.length === 0
    ? { name, state: 'verified' }
    : { name, state: 'unverified', message: own.join('; ') };
}

function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function normalizeHex(hex: string): string {
  return hex.trim().toLowerCase().replace(/^0x/, '');
}
