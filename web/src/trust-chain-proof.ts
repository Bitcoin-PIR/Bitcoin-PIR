import { getAmdTurinArkFingerprint } from './attest-pin.js';
import {
  BHTM_REPORT_DATA_DOMAIN_V2,
  computeBhtmReportData,
  extractSnpMeasurement,
  extractSnpReportData,
  parseBhtmAttestationV2,
  verifyBhtmLeafProofJson,
  type BhtmAttestationV2,
  type VerifiedBhtmLeafProof,
} from './bhtm-proof.js';
import type { DatabaseProofPin, VerifiedDatabaseProof } from './db-proof.js';
import { verifyDatabaseProofAgainstPin } from './db-proof.js';
import { bytesToHex, hexToBytes, sha256 } from './hash.js';
import { requireSdkWasm } from './sdk-bridge.js';

export const DEFAULT_TRUST_CHAIN_MANIFEST_PATH = '/proofs/trust-chain/delta_940611_948454.json';

export interface TrustChainArtifactRef {
  path: string;
  sha256: string;
  size: number;
}

export interface TrustChainManifest {
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
  };
  databaseProof: {
    builderBinarySha256Hex: string;
    builderGitCommit: string;
    paramsHashHex: string;
    networkMagicHex: string;
    artifacts: Record<string, TrustChainArtifactRef>;
  };
  bhtmProof: {
    chunk: string;
    leafIndex: number;
    treeSize: number;
    leafHashHex: string;
    treeRootHex: string;
    attestationVersion: number;
    jobVersion: number;
    jobSha256Hex: string;
    streamingUkiMeasurementHex: string;
    reportDataDomain: string;
    reportDataScheme: string;
    artifacts: Record<string, TrustChainArtifactRef>;
  };
}

export interface TrustChainCheck {
  name: string;
  state: 'verified' | 'unverified' | 'unavailable';
  message?: string;
}

export interface VerifiedTrustChain {
  manifest: TrustChainManifest;
  leaf: VerifiedBhtmLeafProof;
  attestation: BhtmAttestationV2;
}

export interface DatabaseTrustChainStatus {
  state: 'not-checked' | 'verified' | 'unverified' | 'unavailable';
  manifest?: TrustChainManifest;
  verified?: VerifiedTrustChain;
  checks: TrustChainCheck[];
  mismatches: string[];
  error?: string;
}

export interface VerifyTrustChainOptions {
  manifestPath?: string;
  artifactLoader?: (path: string) => Promise<Uint8Array>;
  expectedDbPin?: DatabaseProofPin;
  liveDatabaseProof?: VerifiedDatabaseProof;
  verifyAmdSignature?: boolean;
}

export async function verifyProductionTrustChain(
  options: VerifyTrustChainOptions = {},
): Promise<DatabaseTrustChainStatus> {
  const checks: TrustChainCheck[] = [];
  const mismatches: string[] = [];
  const loader = options.artifactLoader ?? fetchArtifactBytes;
  const manifestPath = options.manifestPath ?? DEFAULT_TRUST_CHAIN_MANIFEST_PATH;

  try {
    const manifest = await loadJson<TrustChainManifest>(manifestPath, loader);
    validateManifestShape(manifest);
    checks.push({ name: 'manifest loaded', state: 'verified', message: manifest.id });

    const dbArtifactBytes = await verifyArtifactGroup(manifest.databaseProof.artifacts, loader, checks);
    const bhtmArtifactBytes = await verifyArtifactGroup(manifest.bhtmProof.artifacts, loader, checks);

    if (options.expectedDbPin) {
      const before = mismatches.length;
      compareManifestToDbPin(manifest, options.expectedDbPin, mismatches);
      checks.push(checkFromMismatches('manifest matches DB pin', mismatches, before));
    }

    if (options.liveDatabaseProof && options.expectedDbPin) {
      const dbStatus = verifyDatabaseProofAgainstPin(options.liveDatabaseProof, options.expectedDbPin);
      if (dbStatus.state === 'verified') {
        checks.push({ name: 'live DB proof matches pin', state: 'verified' });
      } else {
        const dbMismatches = dbStatus.mismatches ?? [dbStatus.error ?? 'live DB proof did not match pin'];
        mismatches.push(...dbMismatches.map((m) => `live DB proof: ${m}`));
        checks.push({
          name: 'live DB proof matches pin',
          state: 'unverified',
          message: dbMismatches.join('; '),
        });
      }
    }

    const leaf = verifyBhtmLeafProofJson(
      JSON.parse(decodeUtf8(requiredArtifact(bhtmArtifactBytes, 'leafProof'))),
    );
    checks.push({ name: 'BHTM leaf proof verified', state: 'verified' });

    const attestationBytes = requiredArtifact(bhtmArtifactBytes, 'attestation');
    const attestation = parseBhtmAttestationV2(attestationBytes);
    const attestationBefore = mismatches.length;
    compareBhtmAttestationToManifest(attestation, manifest, mismatches);
    checks.push(checkFromMismatches('BHTM attestation matches manifest', mismatches, attestationBefore));

    const expectedReportData = computeBhtmReportData(
      attestationBytes,
      manifest.bhtmProof.reportDataDomain || BHTM_REPORT_DATA_DOMAIN_V2,
    );
    const reportData = requiredArtifact(bhtmArtifactBytes, 'reportData');
    const reportBefore = mismatches.length;
    compareBytes('BHTM report-data artifact', reportData, expectedReportData, mismatches);

    const sevSnpReport = requiredArtifact(bhtmArtifactBytes, 'sevSnpReport');
    compareBytes('BHTM SNP REPORT_DATA field', extractSnpReportData(sevSnpReport), reportData, mismatches);
    compareHex(
      'BHTM SNP MEASUREMENT field',
      bytesToHex(extractSnpMeasurement(sevSnpReport)),
      manifest.bhtmProof.streamingUkiMeasurementHex,
      mismatches,
    );
    checks.push(checkFromMismatches('BHTM report-data and measurement matched', mismatches, reportBefore));

    const leafBefore = mismatches.length;
    compareLeafToManifestAndDbAnchor(leaf, manifest, mismatches);
    checks.push(checkFromMismatches('DB anchor matches BHTM leaf', mismatches, leafBefore));

    const statsBefore = mismatches.length;
    compareStatsAndJobToManifest(bhtmArtifactBytes, manifest, mismatches);
    checks.push(checkFromMismatches('BHTM stats/job matched', mismatches, statsBefore));

    if (dbArtifactBytes.size === 0) {
      mismatches.push('database proof artifacts missing from manifest');
    }

    if (options.verifyAmdSignature) {
      verifyStaticSnpReportSignature(bhtmArtifactBytes, sevSnpReport, manifest);
      checks.push({ name: 'BHTM AMD VCEK/report signature verified', state: 'verified' });
    }

    return {
      state: mismatches.length === 0 ? 'verified' : 'unverified',
      manifest,
      verified: { manifest, leaf, attestation },
      checks,
      mismatches,
    };
  } catch (err) {
    const message = (err as Error)?.message ?? String(err);
    const unavailable = /fetch|network|404|not found|failed to load|missing artifact/i.test(message);
    checks.push({
      name: unavailable ? 'artifact loading' : 'trust-chain verification',
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

export function trustChainPinFromManifest(manifest: TrustChainManifest): DatabaseProofPin {
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
    paramsHashHex: manifest.databaseProof.paramsHashHex,
    networkMagicHex: manifest.databaseProof.networkMagicHex,
    builderBinarySha256Hex: manifest.databaseProof.builderBinarySha256Hex,
    builderGitCommit: manifest.databaseProof.builderGitCommit,
    description: manifest.description,
  };
}

async function verifyArtifactGroup(
  artifacts: Record<string, TrustChainArtifactRef>,
  loader: (path: string) => Promise<Uint8Array>,
  checks: TrustChainCheck[],
): Promise<Map<string, Uint8Array>> {
  const out = new Map<string, Uint8Array>();
  for (const [name, ref] of Object.entries(artifacts)) {
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

function verifyStaticSnpReportSignature(
  artifacts: Map<string, Uint8Array>,
  sevSnpReport: Uint8Array,
  manifest: TrustChainManifest,
): void {
  const sdk = requireSdkWasm();
  const policy = new sdk.WasmPolicyRequirements();
  policy.setExpectedMeasurement(hexToBytes(normalizeHex(manifest.bhtmProof.streamingUkiMeasurementHex)));
  sdk.verifyRawSnpReport(
    sevSnpReport,
    decodeUtf8(requiredArtifact(artifacts, 'arkPem')),
    decodeUtf8(requiredArtifact(artifacts, 'askPem')),
    decodeUtf8(requiredArtifact(artifacts, 'vcekPem')),
    getAmdTurinArkFingerprint(),
    policy,
  );
}

function compareManifestToDbPin(
  manifest: TrustChainManifest,
  pin: DatabaseProofPin,
  mismatches: string[],
): void {
  const pinFromManifest = trustChainPinFromManifest(manifest);
  const status = verifyDatabaseProofAgainstPin(pinFromManifest, pin);
  if (status.state !== 'verified') {
    mismatches.push(...(status.mismatches ?? []).map((m) => `manifest DB pin: ${m}`));
  }
}

function compareBhtmAttestationToManifest(
  attestation: BhtmAttestationV2,
  manifest: TrustChainManifest,
  mismatches: string[],
): void {
  if (attestation.version !== manifest.bhtmProof.attestationVersion) {
    mismatches.push(`BHTM attestation version: expected ${manifest.bhtmProof.attestationVersion}, got ${attestation.version}`);
  }
  if (attestation.jobVersion !== manifest.bhtmProof.jobVersion) {
    mismatches.push(`BHTM job version: expected ${manifest.bhtmProof.jobVersion}, got ${attestation.jobVersion}`);
  }
  compareHex('BHTM attestation job_sha256', attestation.jobSha256Hex, manifest.bhtmProof.jobSha256Hex, mismatches);
  compareHex('BHTM attestation tree_root', attestation.treeRootHex, manifest.bhtmProof.treeRootHex, mismatches);
  if (attestation.treeSize !== BigInt(manifest.bhtmProof.treeSize)) {
    mismatches.push(`BHTM attestation tree_size: expected ${manifest.bhtmProof.treeSize}, got ${attestation.treeSize}`);
  }
}

function compareLeafToManifestAndDbAnchor(
  leaf: VerifiedBhtmLeafProof,
  manifest: TrustChainManifest,
  mismatches: string[],
): void {
  if (leaf.height !== manifest.anchor.height) {
    mismatches.push(`BHTM leaf height: expected ${manifest.anchor.height}, got ${leaf.height}`);
  }
  if (leaf.leafIndex !== manifest.bhtmProof.leafIndex) {
    mismatches.push(`BHTM leaf index: expected ${manifest.bhtmProof.leafIndex}, got ${leaf.leafIndex}`);
  }
  if (leaf.treeSize !== manifest.bhtmProof.treeSize) {
    mismatches.push(`BHTM tree size: expected ${manifest.bhtmProof.treeSize}, got ${leaf.treeSize}`);
  }
  compareHex('BHTM leaf block hash', leaf.blockHashDisplayHex, manifest.anchor.blockHashHex, mismatches);
  compareHex('BHTM leaf Core MuHash', leaf.coreMuhashDisplayHex, manifest.anchor.muhashHex, mismatches);
  compareHex('BHTM leaf hash', leaf.leafHashHex, manifest.bhtmProof.leafHashHex, mismatches);
  compareHex('BHTM leaf tree_root', leaf.treeRootHex, manifest.bhtmProof.treeRootHex, mismatches);
}

function compareStatsAndJobToManifest(
  artifacts: Map<string, Uint8Array>,
  manifest: TrustChainManifest,
  mismatches: string[],
): void {
  const stats = JSON.parse(decodeUtf8(requiredArtifact(artifacts, 'stats'))) as Record<string, unknown>;
  const job = JSON.parse(decodeUtf8(requiredArtifact(artifacts, 'job'))) as Record<string, unknown>;
  compareHex('BHTM stats tree_root', String(stats.tree_root ?? ''), manifest.bhtmProof.treeRootHex, mismatches);
  compareHex('BHTM stats job_sha256', String(stats.job_sha256 ?? ''), manifest.bhtmProof.jobSha256Hex, mismatches);
  compareHex('BHTM stats tee_report_data', String(stats.tee_report_data ?? ''), bytesToHex(requiredArtifact(artifacts, 'reportData')), mismatches);
  if (stats.job_chunk !== manifest.bhtmProof.chunk) {
    mismatches.push(`BHTM stats job_chunk: expected ${manifest.bhtmProof.chunk}, got ${String(stats.job_chunk ?? '')}`);
  }
  if (job.chunk !== manifest.bhtmProof.chunk) {
    mismatches.push(`BHTM job chunk: expected ${manifest.bhtmProof.chunk}, got ${String(job.chunk ?? '')}`);
  }
}

function compareBytes(name: string, actual: Uint8Array, expected: Uint8Array, mismatches: string[]): void {
  compareHex(name, bytesToHex(actual), bytesToHex(expected), mismatches);
}

function compareHex(name: string, actual: string, expected: string, mismatches: string[]): void {
  if (normalizeHex(actual) !== normalizeHex(expected)) {
    mismatches.push(`${name}: expected ${expected}, got ${actual}`);
  }
}

function checkFromMismatches(name: string, mismatches: string[], start = 0): TrustChainCheck {
  const own = mismatches.slice(start);
  return own.length === 0
    ? { name, state: 'verified' }
    : { name, state: 'unverified', message: own.join('; ') };
}

function requiredArtifact(artifacts: Map<string, Uint8Array>, name: string): Uint8Array {
  const bytes = artifacts.get(name);
  if (!bytes) throw new Error(`missing artifact ${name}`);
  return bytes;
}

function validateManifestShape(manifest: TrustChainManifest): void {
  if (manifest.schemaVersion !== 1) {
    throw new Error(`unsupported trust-chain manifest schemaVersion ${manifest.schemaVersion}`);
  }
  if (manifest.proofType !== 'BitcoinPIR/database-authenticity/trust-chain/v1') {
    throw new Error(`unsupported trust-chain manifest proofType ${manifest.proofType}`);
  }
  if (!manifest.anchor || !manifest.databaseProof || !manifest.bhtmProof) {
    throw new Error('trust-chain manifest missing anchor/databaseProof/bhtmProof');
  }
}

function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function normalizeHex(hex: string): string {
  return hex.trim().toLowerCase().replace(/^0x/, '');
}
