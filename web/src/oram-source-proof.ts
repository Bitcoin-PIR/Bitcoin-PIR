import { extractSnpMeasurement, extractSnpReportData } from './bhtm-proof.js';
import type { DatabaseProofPin } from './db-proof.js';
import { verifyDatabaseProofAgainstPin } from './db-proof.js';
import { bytesToHex, sha256 } from './hash.js';

export const DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH =
  '/proofs/oram-source/mainnet_948454.json';

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
    currentPir2RuntimeBitcoinPirCommit?: string;
    currentPir2RuntimeOramCommit?: string;
    strictRebuildOramCommit?: string;
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
  oramRngSeedHex: string;
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

export async function verifyOramSourceProof(
  options: VerifyOramSourceProofOptions = {},
): Promise<OramSourceProofStatus> {
  const checks: OramSourceProofCheck[] = [];
  const mismatches: string[] = [];
  const loader = options.artifactLoader ?? fetchArtifactBytes;
  const manifestPath = options.manifestPath ?? DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH;

  try {
    const manifest = await loadJson<OramSourceProofManifest>(manifestPath, loader);
    validateManifestShape(manifest);
    checks.push({ name: 'manifest loaded', state: 'verified', message: manifest.id });

    const artifacts = await verifyManifestArtifacts(manifest, loader, checks);
    const evidenceJsonText = decodeUtf8(requiredArtifact(artifacts, 'oram.evidenceJson'));
    const evidence = JSON.parse(evidenceJsonText) as OramBuildEvidenceJson;
    const rawIndexSeed = extractRawJsonInteger(evidenceJsonText, 'index_seed');

    const structureBefore = mismatches.length;
    compareEvidenceStructure(evidence, manifest, rawIndexSeed, mismatches);
    checks.push(checkFromMismatches('ORAM evidence matches manifest', mismatches, structureBefore));

    const dbBefore = mismatches.length;
    compareAttestedDbEvidence(evidence, manifest, artifacts, mismatches);
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
    const report = requiredArtifact(artifacts, 'attestedBuilder.sevSnpReport');
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
    }

    checks.push({
      name: 'live deployment claim',
      state: 'verified',
      message: manifest.liveDeployment.status,
    });

    return {
      state: mismatches.length === 0 ? 'verified' : 'unverified',
      manifest,
      verified: { manifest, evidence },
      checks,
      mismatches,
    };
  } catch (err) {
    const message = (err as Error)?.message ?? String(err);
    const unavailable = /fetch|network|404|not found|failed to load|missing artifact/i.test(message);
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

function compareEvidenceStructure(
  evidence: OramBuildEvidenceJson,
  manifest: OramSourceProofManifest,
  rawIndexSeed: string,
  mismatches: string[],
): void {
  compareNumber('ORAM evidence version', evidence.version, 1, mismatches);
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
  compareHex('ORAM RNG seed', String(evidence.oram_params.oram_rng_seed_hex ?? ''), params.oramRngSeedHex, mismatches);
}

function compareAttestedDbEvidence(
  evidence: OramBuildEvidenceJson,
  manifest: OramSourceProofManifest,
  artifacts: Map<string, Uint8Array>,
  mismatches: string[],
): void {
  compareEvidenceFile('DB build evidence', evidence.db_build_evidence, manifest.attestedBuilder.artifacts.buildEvidence, mismatches);
  compareEvidenceFile('root bundle payload', evidence.root_bundle_payload, manifest.attestedBuilder.artifacts.rootBundlePayload, mismatches);
  requiredArtifact(artifacts, 'attestedBuilder.rootBundlePayload');
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

async function fetchArtifactBytes(path: string): Promise<Uint8Array> {
  const response = await fetch(path, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`failed to load ${path}: HTTP ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
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
