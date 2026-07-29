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
  anchor: {
    network: string;
    dbId: number;
    buildKind: 'snapshot' | 'delta' | string;
    fromHeight: number;
    fromBlockHashHex: string;
    height: number;
    blockHashHex: string;
    muhashHex: string;
    bucketSuperRootHex: string;
    onionSuperRootHex: string;
    paramsHashHex: string;
    networkMagicHex: string;
  };
  attestedBuilder: {
    builderGitCommit: string;
    builderBinarySha256Hex: string;
    coreVersion: string;
    snapshotSha256: string;
    snapshotBytes: number;
    teePlatform: string;
    uki: {
      fileName: string;
      sha256: string;
      archivePath: string;
      reproducibleBuild: string;
    };
    sevSnp: {
      reportDataHex: string;
      measurementHex: string;
      reportSha256: string;
    };
    manifests: {
      databaseManifestSha256: string;
      allArtifactsManifestSha256: string;
      serverDbManifestSha256: string;
    };
    artifacts: Record<string, OramSourceArtifactRef>;
  };
  directInputs: {
    archivePath: string;
    rootsOnlySha256: Record<string, string>;
    index: OramDirectSourcePin;
    chunks: OramDirectSourcePin;
    artifacts: Record<string, OramSourceArtifactRef>;
  };
  oramBuild: {
    repository: string;
    commit: string;
    oramctlSha256Hex: string;
    outputArchivePath: string;
    sha256SumsSha256: string;
    strictSourceBinding: boolean;
    params: OramBuildParamsPin;
    outputArtifacts: OramOutputArtifactPin[];
    controllerAuthRoots: Record<string, OramControllerAuthRootPin>;
    artifacts: Record<string, OramSourceArtifactRef>;
  };
  liveDeployment: {
    status: string;
    verifiedAtUtc: string;
    currentPir2RuntimeBitcoinPirCommit: string;
    currentPir2RuntimeOramCommit: string;
    strictRebuildOramCommit: string;
    pir2UkiSha256: string;
    pir2BinarySha256: string;
    pir2MeasurementHex: string;
    pir2ChannelPubkeyHex: string;
    hetznerArchivePath: string;
    note?: string;
  };
}

export interface OramDirectSourcePin {
  fileName: string;
  sha256: string;
  bytes: number;
  records: number;
  recordSize: number;
}

export interface OramBuildParamsPin {
  pack: number;
  leafDivisor: number;
  bucketSize: number;
  stashCapacity: number;
  cacheLevels: number;
  authStore: boolean;
  authLayout: string;
  authTrustedLevels: number;
  authHashPageSize: number;
  indexSlotsPerBin: number;
  indexHashFns: number;
  indexLoadFactor: number;
  indexSeedDecimal: string;
  indexSeedHex: string;
  /** Legacy v1 reproducible evidence only. Never present for strict v2 builds. */
  oramRngSeedHex?: string;
  /** Strict v2 evidence records only the non-secret entropy source. */
  oramRngSeedSource?: string;
}

export interface OramOutputArtifactPin {
  fileName: string;
  sha256: string;
  size: number;
}

export interface OramControllerAuthRootPin {
  controllerStateSha256: string;
  controllerStateBytes: number;
  layout: string;
  metaRootHex: string;
  payloadRootHex: string;
  metaTrustedHashesSha256: string;
  payloadTrustedHashesSha256: string;
}

export interface OramSourceProofCheck {
  name: string;
  state: 'verified' | 'unverified' | 'unavailable';
  message?: string;
}

export interface VerifiedOramSourceProof {
  manifest: OramSourceProofManifest;
  evidence: OramBuildEvidenceJson;
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
  /** Defaults to true. False is restricted to forensic/offline fixture tests. */
  verifyAmdSignature?: boolean;
}

interface OramBuildEvidenceJson {
  version: number;
  build: string;
  strict_source_binding: boolean;
  db_certification: {
    build_kind: string;
    network_magic_hex: string;
    from_anchor: {
      height: number;
      block_hash_hex: string;
    };
    anchor: {
      height: number;
      block_hash_hex: string;
    };
    from_muhash_hex: string | null;
    to_muhash_hex: string;
  };
  db_build_evidence: EvidenceFileRef;
  root_bundle_payload: EvidenceFileRef;
  server_db_manifest?: EvidenceFileRef;
  source_files: {
    index: EvidenceSourceFile;
    chunks: EvidenceSourceFile;
  };
  oram_params: Record<string, unknown>;
  output_artifacts: EvidenceFileRef[];
  controller_states: EvidenceControllerState[];
}

interface EvidenceFileRef {
  path: string;
  file_name: string;
  sha256: string;
  bytes: number;
}

interface EvidenceSourceFile {
  level: string;
  path: string;
  sha256: string;
  bytes: number;
  records: number;
  record_size: number;
}

interface EvidenceControllerState {
  level: string;
  state_path: string;
  controller_state_bincode_sha256: string;
  controller_state_bincode_bytes: number;
  auth_roots: {
    layout: string;
    meta: EvidenceAuthRoot;
    payload: EvidenceAuthRoot;
  };
}

interface EvidenceAuthRoot {
  root_hash_hex: string;
  trusted_hashes_sha256: string;
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
    const evidenceJsonText = decodeUtf8(requiredArtifact(artifacts, 'oram.evidenceJson'));
    const evidence = JSON.parse(evidenceJsonText) as OramBuildEvidenceJson;
    const rawIndexSeed = extractRawJsonInteger(evidenceJsonText, 'index_seed');
    const buildEvidenceBytes = requiredArtifact(artifacts, 'attestedBuilder.buildEvidence');
    const attestedBuildEvidence = parseAttestedBuildEvidence(buildEvidenceBytes);

    const structureBefore = mismatches.length;
    compareEvidenceStructure(evidence, manifest, rawIndexSeed, mismatches);
    checks.push(checkFromMismatches('ORAM evidence matches manifest', mismatches, structureBefore));

    const dbBefore = mismatches.length;
    compareAttestedDbEvidence(
      evidence,
      attestedBuildEvidence,
      manifest,
      artifacts,
      mismatches,
    );
    checks.push(checkFromMismatches('attested DB source binding matched', mismatches, dbBefore));

    const sourceBefore = mismatches.length;
    compareDirectSourceHashes(evidence, manifest, artifacts, mismatches);
    checks.push(checkFromMismatches('direct input hashes matched', mismatches, sourceBefore));

    const outputBefore = mismatches.length;
    compareOutputArtifacts(evidence, manifest, artifacts, mismatches);
    checks.push(checkFromMismatches('ORAM output hashes matched', mismatches, outputBefore));

    const stateBefore = mismatches.length;
    compareControllerAuthRoots(evidence, manifest, mismatches);
    checks.push(checkFromMismatches('controller auth roots matched', mismatches, stateBefore));

    const logsBefore = mismatches.length;
    compareBuildLogs(manifest, artifacts, mismatches);
    checks.push(checkFromMismatches('build logs matched manifest', mismatches, logsBefore));

    const reportBefore = mismatches.length;
    const expectedReportData = reportDataForBuildEvidence(buildEvidenceBytes);
    const report = requiredArtifact(artifacts, 'attestedBuilder.sevSnpReport');
    compareHex(
      'BuildEvidence-derived REPORT_DATA',
      bytesToHex(expectedReportData),
      manifest.attestedBuilder.sevSnp.reportDataHex,
      mismatches,
    );
    compareHex(
      'attested-builder SNP REPORT_DATA field',
      bytesToHex(extractSnpReportData(report)),
      manifest.attestedBuilder.sevSnp.reportDataHex,
      mismatches,
    );
    compareHex(
      'attested-builder SNP MEASUREMENT field',
      bytesToHex(extractSnpMeasurement(report)),
      manifest.attestedBuilder.sevSnp.measurementHex,
      mismatches,
    );
    compareHex(
      'attested-builder report-data artifact',
      bytesToHex(requiredArtifact(artifacts, 'attestedBuilder.reportData')),
      manifest.attestedBuilder.sevSnp.reportDataHex,
      mismatches,
    );
    checks.push(checkFromMismatches('attested-builder SNP fields matched', mismatches, reportBefore));

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

    if (options.liveDatabaseProof) {
      const liveBefore = mismatches.length;
      const livePin: DatabaseProofPin = {
        ...oramSourcePinFromManifest(manifest),
        manifestRootHex: attestedBuildEvidence.serverDbManifestSha256Hex,
        onionEntrySize: attestedBuildEvidence.onionEntrySize,
        proofVersion: attestedBuildEvidence.version,
        onionTotalPackedEntries: attestedBuildEvidence.onionLayoutV2?.totalPackedEntries,
        onionIndexBinsPerTable: attestedBuildEvidence.onionLayoutV2?.indexBinsPerTable,
        onionChunkBinsPerTable: attestedBuildEvidence.onionLayoutV2?.chunkBinsPerTable,
        onionIndexSlotsPerBin: attestedBuildEvidence.version === 2
          ? Math.floor(attestedBuildEvidence.onionEntrySize / 15)
          : undefined,
        onionIndexSlotSize: attestedBuildEvidence.version === 2 ? 15 : undefined,
      };
      const liveStatus = verifyDatabaseProofAgainstPin(options.liveDatabaseProof, livePin);
      if (liveStatus.state !== 'verified') {
        mismatches.push(
          ...(liveStatus.mismatches ?? []).map((m) => `live ORAM DB proof: ${m}`),
        );
      }
      checks.push(checkFromMismatches('live ORAM DB proof matches attested image', mismatches, liveBefore));
    } else {
      mismatches.push('liveDatabaseProof is required before an ORAM source proof can be trusted');
      checks.push({
        name: 'live ORAM DB proof matches attested image',
        state: 'unverified',
        message: 'no live verified database proof supplied',
      });
    }

    if (options.expectedDbPin) {
      const pinBefore = mismatches.length;
      const status = verifyDatabaseProofAgainstPin(
        oramSourcePinFromManifest(manifest),
        options.expectedDbPin,
      );
      if (status.state !== 'verified') {
        mismatches.push(...(status.mismatches ?? []).map((m) => `manifest DB pin: ${m}`));
      }
      checks.push(checkFromMismatches('manifest matches ORAM DB pin', mismatches, pinBefore));
    } else {
      mismatches.push('expectedDbPin is required before an ORAM source proof can be trusted');
      checks.push({
        name: 'manifest matches ORAM DB pin',
        state: 'unverified',
        message: 'no expectedDbPin supplied',
      });
    }

    checks.push({
      name: 'live deployment claim (informational)',
      state: 'unverified',
      message: `${manifest.liveDeployment.status}; verify the live runtime attestation separately`,
    });

    const state = mismatches.length === 0 ? 'verified' : 'unverified';
    return {
      state,
      manifest,
      verified: state === 'verified' ? { manifest, evidence } : undefined,
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

export function oramSourcePinFromManifest(manifest: OramSourceProofManifest): DatabaseProofPin {
  return {
    dbId: manifest.anchor.dbId,
    buildKind: manifest.anchor.buildKind as 'snapshot' | 'delta',
    fromHeight: manifest.anchor.fromHeight,
    height: manifest.anchor.height,
    fromBlockHashHex: manifest.anchor.fromBlockHashHex,
    blockHashHex: manifest.anchor.blockHashHex,
    muhashHex: manifest.anchor.muhashHex,
    bucketSuperRootHex: manifest.anchor.bucketSuperRootHex,
    onionSuperRootHex: manifest.anchor.onionSuperRootHex,
    paramsHashHex: manifest.anchor.paramsHashHex,
    networkMagicHex: manifest.anchor.networkMagicHex,
    builderBinarySha256Hex: manifest.attestedBuilder.builderBinarySha256Hex,
    builderGitCommit: manifest.attestedBuilder.builderGitCommit,
    description: manifest.description,
  };
}

async function verifyManifestArtifacts(
  manifest: OramSourceProofManifest,
  loader: (path: string) => Promise<Uint8Array>,
  checks: OramSourceProofCheck[],
): Promise<Map<string, Uint8Array>> {
  const refs: Array<[string, OramSourceArtifactRef]> = [];
  collectRefs('attestedBuilder', manifest.attestedBuilder.artifacts, refs);
  collectRefs('directInputs', manifest.directInputs.artifacts, refs);
  collectRefs('oram', manifest.oramBuild.artifacts, refs);

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
  policy.setExpectedMeasurement(hexToBytes(normalizeHex(manifest.attestedBuilder.sevSnp.measurementHex)));
  sdk.verifyRawSnpReport(
    sevSnpReport,
    arkPem,
    askPem,
    vcekPem,
    getAmdTurinArkFingerprint(),
    policy,
  );
}

function compareEvidenceStructure(
  evidence: OramBuildEvidenceJson,
  manifest: OramSourceProofManifest,
  rawIndexSeed: string,
  mismatches: string[],
): void {
  if (evidence.version !== 2) {
    mismatches.push(
      `production ORAM source proof requires evidence v2; legacy v1 disclosed the ORAM RNG seed (got version ${evidence.version})`,
    );
  }
  compareString('ORAM evidence build', evidence.build, 'bitcoinpir-oram/direct-build', mismatches);
  compareBoolean('ORAM strict source binding', evidence.strict_source_binding, true, mismatches);
  compareBoolean('manifest strict source binding', manifest.oramBuild.strictSourceBinding, true, mismatches);

  compareString('DB certification build kind', evidence.db_certification.build_kind, manifest.anchor.buildKind, mismatches);
  compareHex('DB certification network magic', evidence.db_certification.network_magic_hex, manifest.anchor.networkMagicHex, mismatches);
  compareNumber('DB certification from height', evidence.db_certification.from_anchor.height, manifest.anchor.fromHeight, mismatches);
  compareHex('DB certification from block hash', evidence.db_certification.from_anchor.block_hash_hex, manifest.anchor.fromBlockHashHex, mismatches);
  compareNumber('DB certification height', evidence.db_certification.anchor.height, manifest.anchor.height, mismatches);
  compareHex('DB certification block hash', evidence.db_certification.anchor.block_hash_hex, manifest.anchor.blockHashHex, mismatches);
  compareHex('DB certification MuHash', evidence.db_certification.to_muhash_hex, manifest.anchor.muhashHex, mismatches);

  const params = manifest.oramBuild.params;
  compareScalar('ORAM param pack', evidence.oram_params.pack, params.pack, mismatches);
  compareScalar('ORAM param leaf_divisor', evidence.oram_params.leaf_divisor, params.leafDivisor, mismatches);
  compareScalar('ORAM param bucket_size', evidence.oram_params.bucket_size, params.bucketSize, mismatches);
  compareScalar('ORAM param stash_capacity', evidence.oram_params.stash_capacity, params.stashCapacity, mismatches);
  compareScalar('ORAM param cache_levels', evidence.oram_params.cache_levels, params.cacheLevels, mismatches);
  compareScalar('ORAM param auth_store', evidence.oram_params.auth_store, params.authStore, mismatches);
  compareString('ORAM param auth_layout', String(evidence.oram_params.auth_layout ?? ''), params.authLayout, mismatches);
  compareScalar('ORAM param auth_trusted_levels', evidence.oram_params.auth_trusted_levels, params.authTrustedLevels, mismatches);
  compareScalar('ORAM param auth_hash_page_size', evidence.oram_params.auth_hash_page_size, params.authHashPageSize, mismatches);
  compareScalar('ORAM param index_slots_per_bin', evidence.oram_params.index_slots_per_bin, params.indexSlotsPerBin, mismatches);
  compareScalar('ORAM param index_hash_fns', evidence.oram_params.index_hash_fns, params.indexHashFns, mismatches);
  compareScalar('ORAM param index_load_factor', evidence.oram_params.index_load_factor, params.indexLoadFactor, mismatches);
  compareString('ORAM param index_seed decimal', rawIndexSeed, params.indexSeedDecimal, mismatches);
  if (evidence.version === 2) {
    compareString(
      'ORAM RNG seed source',
      String(evidence.oram_params.oram_rng_seed_source ?? ''),
      'os_rng',
      mismatches,
    );
    if (Object.prototype.hasOwnProperty.call(evidence.oram_params, 'oram_rng_seed_hex')) {
      mismatches.push('strict ORAM evidence v2 must not disclose oram_rng_seed_hex');
    }
    if (params.oramRngSeedSource !== undefined) {
      compareString('manifest ORAM RNG seed source', params.oramRngSeedSource, 'os_rng', mismatches);
    }
    if (params.oramRngSeedHex !== undefined) {
      mismatches.push('strict ORAM proof manifest v2 must not disclose oramRngSeedHex');
    }
  }
}

function compareAttestedDbEvidence(
  evidence: OramBuildEvidenceJson,
  attested: AttestedBuildEvidence,
  manifest: OramSourceProofManifest,
  artifacts: Map<string, Uint8Array>,
  mismatches: string[],
): void {
  compareEvidenceFile('DB build evidence', evidence.db_build_evidence, manifest.attestedBuilder.artifacts.buildEvidence, mismatches);
  compareEvidenceFile('root bundle payload', evidence.root_bundle_payload, manifest.attestedBuilder.artifacts.rootBundlePayload, mismatches);

  compareString('attested builder git commit', attested.builderGitCommit, manifest.attestedBuilder.builderGitCommit, mismatches);
  compareHex('attested builder binary sha256', attested.builderBinarySha256Hex, manifest.attestedBuilder.builderBinarySha256Hex, mismatches);
  compareString('attested builder TEE platform', attested.teePlatform, manifest.attestedBuilder.teePlatform, mismatches);
  compareString('attested Bitcoin Core version', attested.coreVersion, manifest.attestedBuilder.coreVersion, mismatches);
  compareHex('attested snapshot sha256', attested.snapshotSha256Hex, manifest.attestedBuilder.snapshotSha256, mismatches);
  if (!Number.isSafeInteger(manifest.attestedBuilder.snapshotBytes)) {
    mismatches.push('manifest snapshotBytes is not a safe integer');
  } else {
    compareString(
      'attested snapshot bytes',
      attested.snapshotBytesDecimal,
      String(manifest.attestedBuilder.snapshotBytes),
      mismatches,
    );
  }
  compareHex('attested network magic', attested.networkMagicHex, manifest.anchor.networkMagicHex, mismatches);
  compareString('attested build kind', attested.buildKind, manifest.anchor.buildKind, mismatches);
  compareAttestedAnchor(
    'attested from anchor',
    attested.fromAnchor,
    manifest.anchor.fromBlockHashHex,
    manifest.anchor.fromHeight,
    mismatches,
  );
  compareAttestedAnchor(
    'attested anchor',
    attested.anchor,
    manifest.anchor.blockHashHex,
    manifest.anchor.height,
    mismatches,
  );
  compareHex('attested UTXO MuHash', attested.utxoMuhashHex, manifest.anchor.muhashHex, mismatches);
  compareHex('attested params hash', attested.paramsHashHex, manifest.anchor.paramsHashHex, mismatches);
  if (attested.version === 2) {
    compareHex(
      'attested v2 build-params hash recomputation',
      attested.paramsHashHex,
      paramsHashV2ForAttestedBuildEvidence(attested),
      mismatches,
    );
  }
  compareHex('attested bucket super-root', attested.bucketSuperRootHex, manifest.anchor.bucketSuperRootHex, mismatches);
  compareHex('attested Onion super-root', attested.onionSuperRootHex, manifest.anchor.onionSuperRootHex, mismatches);
  if (attested.teeImageMeasurementHex) {
    compareHex(
      'attested TEE image measurement',
      attested.teeImageMeasurementHex,
      manifest.attestedBuilder.sevSnp.measurementHex,
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
    manifest.attestedBuilder.manifests.databaseManifestSha256,
    manifest.attestedBuilder.artifacts.databaseManifest,
    requiredArtifact(artifacts, 'attestedBuilder.databaseManifest'),
    mismatches,
  );
  compareAttestedManifestArtifact(
    'all-artifacts manifest',
    attested.allArtifactsManifestSha256Hex,
    manifest.attestedBuilder.manifests.allArtifactsManifestSha256,
    manifest.attestedBuilder.artifacts.allArtifactsManifest,
    requiredArtifact(artifacts, 'attestedBuilder.allArtifactsManifest'),
    mismatches,
  );
  const manifestRef = manifest.attestedBuilder.artifacts.serverDbManifest;
  const manifestBytes = requiredArtifact(artifacts, 'attestedBuilder.serverDbManifest');
  compareAttestedManifestArtifact(
    'server DB manifest',
    attested.serverDbManifestSha256Hex,
    manifest.attestedBuilder.manifests.serverDbManifestSha256,
    manifestRef,
    manifestBytes,
    mismatches,
  );

  if (evidence.version !== 2) return;

  if (attested.version !== 2) {
    mismatches.push(`production ORAM proof requires attested BuildEvidence v2, got v${attested.version}`);
  }
  compareString('attested evidence mode', attested.evidenceMode, 'full-build', mismatches);
  if (
    attested.predecessorEvidenceSha256Hex !== undefined
    || attested.predecessorReportSha256Hex !== undefined
  ) {
    mismatches.push('production ORAM proof must not use reattestation predecessor hashes');
  }

  if (!evidence.server_db_manifest) {
    mismatches.push('ORAM evidence v2 is missing server_db_manifest');
  } else {
    compareEvidenceFile(
      'server DB manifest',
      evidence.server_db_manifest,
      manifestRef,
      mismatches,
    );
  }
  mismatches.push(
    ...directOramManifestBindingMismatches(decodeUtf8(manifestBytes), manifest),
  );
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
  outerHash: string,
  artifactRef: OramSourceArtifactRef | undefined,
  bytes: Uint8Array,
  mismatches: string[],
): void {
  compareHex(`attested ${name} bytes sha256`, attestedHash, bytesToHex(sha256(bytes)), mismatches);
  compareHex(`attested ${name} outer manifest pin`, attestedHash, outerHash, mismatches);
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

/** Compare the measured server manifest's typed Direct ORAM binding to all pins. */
export function directOramManifestBindingMismatches(
  text: string,
  manifest: OramSourceProofManifest,
): string[] {
  const mismatches: string[] = [];
  let binding: DirectOramManifestBinding;
  try {
    binding = parseDirectOramManifestBinding(text);
  } catch (err) {
    return [`server DB manifest direct_oram: ${(err as Error).message}`];
  }

  compareString('server DB direct_oram version', binding.version, '1', mismatches);
  compareHex(
    'server DB direct_oram index sha256',
    binding.index_sha256,
    manifest.directInputs.index.sha256,
    mismatches,
  );
  compareString(
    'server DB direct_oram index bytes',
    binding.index_bytes,
    String(manifest.directInputs.index.bytes),
    mismatches,
  );
  compareString(
    'server DB direct_oram index records',
    binding.index_records,
    String(manifest.directInputs.index.records),
    mismatches,
  );
  compareHex(
    'server DB direct_oram chunk sha256',
    binding.chunk_sha256,
    manifest.directInputs.chunks.sha256,
    mismatches,
  );
  compareString(
    'server DB direct_oram chunk bytes',
    binding.chunk_bytes,
    String(manifest.directInputs.chunks.bytes),
    mismatches,
  );
  compareString(
    'server DB direct_oram chunk records',
    binding.chunk_records,
    String(manifest.directInputs.chunks.records),
    mismatches,
  );
  compareString(
    'server DB direct_oram index slots per bin',
    binding.index_slots_per_bin,
    String(manifest.oramBuild.params.indexSlotsPerBin),
    mismatches,
  );
  compareString(
    'server DB direct_oram index hash functions',
    binding.index_hash_fns,
    String(manifest.oramBuild.params.indexHashFns),
    mismatches,
  );
  compareString(
    'server DB direct_oram index load factor ppb',
    binding.index_load_factor_ppb,
    String(Math.round(manifest.oramBuild.params.indexLoadFactor * 1_000_000_000)),
    mismatches,
  );
  compareString(
    'server DB direct_oram index seed',
    binding.index_seed,
    manifest.oramBuild.params.indexSeedDecimal,
    mismatches,
  );
  return mismatches;
}

function compareDirectSourceHashes(
  evidence: OramBuildEvidenceJson,
  manifest: OramSourceProofManifest,
  artifacts: Map<string, Uint8Array>,
  mismatches: string[],
): void {
  const directInputs = parseSha256List(decodeUtf8(requiredArtifact(artifacts, 'directInputs.directInputsSha256')));
  compareHex('direct-inputs index sha256', directInputs[manifest.directInputs.index.fileName] ?? '', manifest.directInputs.index.sha256, mismatches);
  compareHex('direct-inputs chunks sha256', directInputs[manifest.directInputs.chunks.fileName] ?? '', manifest.directInputs.chunks.sha256, mismatches);
  compareSourceFile('index source file', evidence.source_files.index, manifest.directInputs.index, mismatches);
  compareSourceFile('chunks source file', evidence.source_files.chunks, manifest.directInputs.chunks, mismatches);
}

function compareOutputArtifacts(
  evidence: OramBuildEvidenceJson,
  manifest: OramSourceProofManifest,
  artifacts: Map<string, Uint8Array>,
  mismatches: string[],
): void {
  const shaSums = parseSha256List(decodeUtf8(requiredArtifact(artifacts, 'oram.sha256Sums')));
  compareHex('SHA256SUMS manifest digest', manifest.oramBuild.sha256SumsSha256, manifest.oramBuild.artifacts.sha256Sums.sha256, mismatches);
  compareHex('SHA256SUMS evidence JSON', shaSums['oram-build-evidence.json'] ?? '', manifest.oramBuild.artifacts.evidenceJson.sha256, mismatches);
  compareHex('SHA256SUMS evidence bin', shaSums['oram-build-evidence.bin'] ?? '', manifest.oramBuild.artifacts.evidenceBin.sha256, mismatches);

  const evidenceOutputs = new Map(evidence.output_artifacts.map((artifact) => [artifact.file_name, artifact]));
  if (evidenceOutputs.size !== manifest.oramBuild.outputArtifacts.length) {
    mismatches.push(`ORAM output artifact count: expected ${manifest.oramBuild.outputArtifacts.length}, got ${evidenceOutputs.size}`);
  }
  for (const artifact of manifest.oramBuild.outputArtifacts) {
    const fromEvidence = evidenceOutputs.get(artifact.fileName);
    if (!fromEvidence) {
      mismatches.push(`ORAM output artifact missing from evidence: ${artifact.fileName}`);
      continue;
    }
    compareHex(`ORAM output ${artifact.fileName} sha256`, fromEvidence.sha256, artifact.sha256, mismatches);
    compareNumber(`ORAM output ${artifact.fileName} size`, fromEvidence.bytes, artifact.size, mismatches);
    compareHex(`SHA256SUMS ${artifact.fileName}`, shaSums[artifact.fileName] ?? '', artifact.sha256, mismatches);
  }
}

function compareControllerAuthRoots(
  evidence: OramBuildEvidenceJson,
  manifest: OramSourceProofManifest,
  mismatches: string[],
): void {
  const states = new Map(evidence.controller_states.map((state) => [state.level.toLowerCase(), state]));
  for (const [level, root] of Object.entries(manifest.oramBuild.controllerAuthRoots)) {
    const state = states.get(level);
    if (!state) {
      mismatches.push(`controller auth state missing from evidence: ${level}`);
      continue;
    }
    compareHex(`${level} controller state sha256`, state.controller_state_bincode_sha256, root.controllerStateSha256, mismatches);
    compareNumber(`${level} controller state size`, state.controller_state_bincode_bytes, root.controllerStateBytes, mismatches);
    compareString(`${level} auth layout`, state.auth_roots.layout, root.layout, mismatches);
    compareHex(`${level} meta auth root`, state.auth_roots.meta.root_hash_hex, root.metaRootHex, mismatches);
    compareHex(`${level} payload auth root`, state.auth_roots.payload.root_hash_hex, root.payloadRootHex, mismatches);
    compareHex(`${level} meta trusted hashes`, state.auth_roots.meta.trusted_hashes_sha256, root.metaTrustedHashesSha256, mismatches);
    compareHex(`${level} payload trusted hashes`, state.auth_roots.payload.trusted_hashes_sha256, root.payloadTrustedHashesSha256, mismatches);
  }
}

function compareBuildLogs(
  manifest: OramSourceProofManifest,
  artifacts: Map<string, Uint8Array>,
  mismatches: string[],
): void {
  const metadata = parseKeyValues(decodeUtf8(requiredArtifact(artifacts, 'oram.buildRunMetadata')));
  const buildLog = parseKeyValues(decodeUtf8(requiredArtifact(artifacts, 'oram.buildLog')));
  compareString('ORAM metadata commit', metadata.oram_commit ?? '', manifest.oramBuild.commit, mismatches);
  compareHex('ORAM metadata oramctl sha256', metadata.oramctl_sha256 ?? '', manifest.oramBuild.oramctlSha256Hex, mismatches);
  compareHex('ORAM metadata expected index sha256', metadata.expected_index_sha256 ?? '', manifest.directInputs.index.sha256, mismatches);
  compareHex('ORAM metadata expected chunks sha256', metadata.expected_chunks_sha256 ?? '', manifest.directInputs.chunks.sha256, mismatches);
  compareHex('ORAM metadata expected MuHash', metadata.expected_muhash ?? '', manifest.anchor.muhashHex, mismatches);
  compareHex('ORAM build log index sha256', buildLog.index_sha256 ?? '', manifest.directInputs.index.sha256, mismatches);
  compareHex('ORAM build log chunks sha256', buildLog.chunks_sha256 ?? '', manifest.directInputs.chunks.sha256, mismatches);
  compareHex('ORAM build log certified MuHash', buildLog.certified_muhash ?? '', manifest.anchor.muhashHex, mismatches);
  compareString('ORAM build log index seed hex', buildLog.index_seed ?? '', manifest.oramBuild.params.indexSeedHex, mismatches);
}

function compareEvidenceFile(
  name: string,
  evidenceRef: EvidenceFileRef,
  manifestRef: OramSourceArtifactRef | undefined,
  mismatches: string[],
): void {
  if (!manifestRef) {
    mismatches.push(`${name}: missing manifest artifact reference`);
    return;
  }
  if (!manifestRef.path.endsWith(`/${evidenceRef.file_name}`)) {
    mismatches.push(`${name}: expected manifest path ending in ${evidenceRef.file_name}, got ${manifestRef.path}`);
  }
  compareHex(`${name} sha256`, evidenceRef.sha256, manifestRef.sha256, mismatches);
  compareNumber(`${name} size`, evidenceRef.bytes, manifestRef.size, mismatches);
}

function compareSourceFile(
  name: string,
  evidenceSource: EvidenceSourceFile,
  pin: OramDirectSourcePin,
  mismatches: string[],
): void {
  compareHex(`${name} sha256`, evidenceSource.sha256, pin.sha256, mismatches);
  compareNumber(`${name} bytes`, evidenceSource.bytes, pin.bytes, mismatches);
  compareNumber(`${name} records`, evidenceSource.records, pin.records, mismatches);
  compareNumber(`${name} record size`, evidenceSource.record_size, pin.recordSize, mismatches);
}

async function loadJson<T>(path: string, loader: (path: string) => Promise<Uint8Array>): Promise<T> {
  return JSON.parse(decodeUtf8(await loader(path))) as T;
}

function validateManifestShape(manifest: OramSourceProofManifest): void {
  if (manifest.schemaVersion !== 1) {
    throw new Error(`unsupported ORAM source-proof manifest schemaVersion ${manifest.schemaVersion}`);
  }
  if (manifest.proofType !== 'BitcoinPIR/oram-source-binding/v1') {
    throw new Error(`unsupported ORAM source-proof manifest proofType ${manifest.proofType}`);
  }
  if (!manifest.anchor || !manifest.attestedBuilder || !manifest.directInputs || !manifest.oramBuild) {
    throw new Error('ORAM source-proof manifest missing anchor/attestedBuilder/directInputs/oramBuild');
  }
}

function requiredArtifact(artifacts: Map<string, Uint8Array>, name: string): Uint8Array {
  const bytes = artifacts.get(name);
  if (!bytes) throw new Error(`missing artifact ${name}`);
  return bytes;
}

function parseKeyValues(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    const idx = line.indexOf('=');
    if (idx === -1) continue;
    out[line.slice(0, idx)] = line.slice(idx + 1);
  }
  return out;
}

function parseSha256List(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const match = /^([0-9a-fA-F]{64})\s+(.+)$/.exec(trimmed);
    if (!match) continue;
    out[match[2].replace(/^\.\//, '')] = match[1].toLowerCase();
  }
  return out;
}

function extractRawJsonInteger(json: string, key: string): string {
  const match = new RegExp(`"${key}"\\s*:\\s*(\\d+)`).exec(json);
  if (!match) {
    throw new Error(`missing raw JSON integer ${key}`);
  }
  return match[1];
}

function compareScalar(name: string, actual: unknown, expected: string | number | boolean, mismatches: string[]): void {
  if (actual !== expected) {
    mismatches.push(`${name}: expected ${String(expected)}, got ${String(actual)}`);
  }
}

function compareBoolean(name: string, actual: boolean, expected: boolean, mismatches: string[]): void {
  if (actual !== expected) {
    mismatches.push(`${name}: expected ${expected}, got ${actual}`);
  }
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
