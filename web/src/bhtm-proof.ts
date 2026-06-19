import { bytesToHex, hexToBytes, sha256, sha512 } from './hash.js';

export const BHTM_LEAF_PROOF_TYPE = 'BitcoinPIR/blockhash-to-muhash/leaf-proof/v1';
export const BHTM_REPORT_DATA_DOMAIN_V2 = 'BitcoinPIR/blockhash-to-muhash/report-data/v2';
export const SEV_SNP_REPORT_DATA_OFFSET = 0x50;
export const SEV_SNP_REPORT_DATA_LEN = 64;
export const SEV_SNP_MEASUREMENT_OFFSET = 0x90;
export const SEV_SNP_MEASUREMENT_LEN = 48;

export interface BhtmLeafProofStep {
  level?: number;
  side: 'left' | 'right';
  hash: string;
}

export interface BhtmLeafProofJson {
  schema_version: number;
  proof_type: string;
  height: number;
  block_hash_internal: string;
  block_hash_display: string;
  muhash: string;
  core_muhash_internal: string;
  core_muhash_display: string;
  leaf_hash: string;
  leaf_index: number;
  tree_size: number;
  tree_root: string;
  proof: BhtmLeafProofStep[];
  verified_against_tree_root?: boolean;
  chunk?: {
    anchor_height?: number;
    anchor_block_hash_internal?: string;
    anchor_block_hash_display?: string;
    first_block_height?: number;
    end_height?: number;
    end_block_hash_internal?: string;
    end_block_hash_display?: string;
    end_muhash_core_display?: string;
  };
}

export interface VerifiedBhtmLeafProof {
  height: number;
  blockHashInternalHex: string;
  blockHashDisplayHex: string;
  muhashHex: string;
  coreMuhashInternalHex: string;
  coreMuhashDisplayHex: string;
  leafHashHex: string;
  leafIndex: number;
  treeSize: number;
  treeRootHex: string;
  proofSteps: number;
}

export interface BhtmAttestationV2 {
  version: number;
  jobVersion: number;
  startHeight: number;
  endHeight: number;
  startBlockHashInternalHex: string;
  startBlockHashDisplayHex: string;
  endBlockHashInternalHex: string;
  endBlockHashDisplayHex: string;
  jobSha256Hex: string;
  treeRootHex: string;
  treeSize: bigint;
  startMuhashHex: string;
  endMuhashHex: string;
}

export function verifyBhtmLeafProofJson(value: unknown): VerifiedBhtmLeafProof {
  if (!isRecord(value)) {
    throw new Error('BHTM leaf proof must be an object');
  }
  const schemaVersion = expectNumber(value, 'schema_version');
  if (schemaVersion !== 1) {
    throw new Error(`unsupported BHTM leaf proof schema_version ${schemaVersion}`);
  }
  const proofType = expectString(value, 'proof_type');
  if (proofType !== BHTM_LEAF_PROOF_TYPE) {
    throw new Error(`unsupported BHTM leaf proof_type ${proofType}`);
  }

  const height = expectNumber(value, 'height');
  const blockHashInternal = expectHexBytes(expectString(value, 'block_hash_internal'), 32, 'block_hash_internal');
  const muhash = expectHexBytes(expectString(value, 'muhash'), 384, 'muhash');
  const coreMuhash = sha256(muhash);
  const leafHash = bhtmLeafHash(height, blockHashInternal, muhash);
  const treeRoot = expectHexBytes(expectString(value, 'tree_root'), 32, 'tree_root');
  const leafIndex = expectNumber(value, 'leaf_index');
  const treeSize = expectNumber(value, 'tree_size');

  expectEqualHex(expectString(value, 'block_hash_display'), displayOrderHex(blockHashInternal), 'block_hash_display');
  expectEqualHex(expectString(value, 'core_muhash_internal'), bytesToHex(coreMuhash), 'core_muhash_internal');
  expectEqualHex(expectString(value, 'core_muhash_display'), displayOrderHex(coreMuhash), 'core_muhash_display');
  expectEqualHex(expectString(value, 'leaf_hash'), bytesToHex(leafHash), 'leaf_hash');

  const proofValue = value.proof;
  if (!Array.isArray(proofValue)) {
    throw new Error('BHTM leaf proof field proof must be an array');
  }
  const proof = proofValue.map((step, idx) => parseProofStep(step, idx));
  const computedRoot = verifyInclusionProof(leafHash, leafIndex, treeSize, proof);
  expectEqualHex(bytesToHex(computedRoot), bytesToHex(treeRoot), 'tree_root');

  return {
    height,
    blockHashInternalHex: bytesToHex(blockHashInternal),
    blockHashDisplayHex: displayOrderHex(blockHashInternal),
    muhashHex: bytesToHex(muhash),
    coreMuhashInternalHex: bytesToHex(coreMuhash),
    coreMuhashDisplayHex: displayOrderHex(coreMuhash),
    leafHashHex: bytesToHex(leafHash),
    leafIndex,
    treeSize,
    treeRootHex: bytesToHex(treeRoot),
    proofSteps: proof.length,
  };
}

export function bhtmLeafHash(height: number, blockHashInternal: Uint8Array, muhash: Uint8Array): Uint8Array {
  if (!Number.isInteger(height) || height < 0 || height > 0xffffffff) {
    throw new Error(`height must be a u32, got ${height}`);
  }
  if (blockHashInternal.length !== 32) {
    throw new Error(`block_hash must be 32 bytes, got ${blockHashInternal.length}`);
  }
  if (muhash.length !== 384) {
    throw new Error(`muhash must be 384 bytes, got ${muhash.length}`);
  }
  const domain = new TextEncoder().encode('muhash-leaf');
  const data = new Uint8Array(domain.length + 4 + 32 + 384);
  data.set(domain, 0);
  new DataView(data.buffer, data.byteOffset + domain.length, 4).setUint32(0, height, true);
  data.set(blockHashInternal, domain.length + 4);
  data.set(muhash, domain.length + 4 + 32);
  return sha256(data);
}

export function verifyInclusionProof(
  leafHash: Uint8Array,
  leafIndex: number,
  treeSize: number,
  proof: Array<{ side: 'left' | 'right'; hash: Uint8Array }>,
): Uint8Array {
  if (leafHash.length !== 32) {
    throw new Error(`leaf hash must be 32 bytes, got ${leafHash.length}`);
  }
  if (!Number.isInteger(treeSize) || treeSize <= 0) {
    throw new Error(`tree_size must be positive, got ${treeSize}`);
  }
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) {
    throw new Error(`leaf_index ${leafIndex} out of range for tree_size ${treeSize}`);
  }
  const proofIndex = { value: 0 };
  const root = verifyInclusionRange(leafHash, leafIndex, treeSize, proof, proofIndex);
  if (proofIndex.value !== proof.length) {
    throw new Error(`unused BHTM proof steps: consumed ${proofIndex.value}, got ${proof.length}`);
  }
  return root;
}

export function parseBhtmAttestationV2(attestation: Uint8Array): BhtmAttestationV2 {
  if (attestation.length !== 916) {
    throw new Error(`BHTM attestation v2 must be 916 bytes, got ${attestation.length}`);
  }
  const view = new DataView(attestation.buffer, attestation.byteOffset, attestation.byteLength);
  const version = view.getUint16(0, true);
  if (version !== 2) {
    throw new Error(`unsupported BHTM attestation version ${version}`);
  }
  const jobVersion = view.getUint16(2, true);
  const startHeight = view.getUint32(4, true);
  const endHeight = view.getUint32(8, true);
  const startBlockHash = attestation.slice(12, 44);
  const endBlockHash = attestation.slice(44, 76);
  const jobSha256 = attestation.slice(76, 108);
  const treeRoot = attestation.slice(108, 140);
  const treeSize = view.getBigUint64(140, true);
  const startMuhash = attestation.slice(148, 532);
  const endMuhash = attestation.slice(532, 916);
  return {
    version,
    jobVersion,
    startHeight,
    endHeight,
    startBlockHashInternalHex: bytesToHex(startBlockHash),
    startBlockHashDisplayHex: displayOrderHex(startBlockHash),
    endBlockHashInternalHex: bytesToHex(endBlockHash),
    endBlockHashDisplayHex: displayOrderHex(endBlockHash),
    jobSha256Hex: bytesToHex(jobSha256),
    treeRootHex: bytesToHex(treeRoot),
    treeSize,
    startMuhashHex: bytesToHex(startMuhash),
    endMuhashHex: bytesToHex(endMuhash),
  };
}

export function computeBhtmReportData(attestation: Uint8Array, domain = BHTM_REPORT_DATA_DOMAIN_V2): Uint8Array {
  const domainBytes = new TextEncoder().encode(domain);
  const data = new Uint8Array(domainBytes.length + attestation.length);
  data.set(domainBytes, 0);
  data.set(attestation, domainBytes.length);
  return sha512(data);
}

export function extractSnpReportData(report: Uint8Array): Uint8Array {
  return sliceReportField(report, SEV_SNP_REPORT_DATA_OFFSET, SEV_SNP_REPORT_DATA_LEN, 'REPORT_DATA');
}

export function extractSnpMeasurement(report: Uint8Array): Uint8Array {
  return sliceReportField(report, SEV_SNP_MEASUREMENT_OFFSET, SEV_SNP_MEASUREMENT_LEN, 'MEASUREMENT');
}

export function displayOrderHex(bytes: Uint8Array): string {
  return bytesToHex(new Uint8Array(bytes).reverse());
}

function verifyInclusionRange(
  node: Uint8Array,
  leafIndex: number,
  treeSize: number,
  proof: Array<{ side: 'left' | 'right'; hash: Uint8Array }>,
  proofIndex: { value: number },
): Uint8Array {
  if (treeSize === 1) {
    return node;
  }
  const split = largestPowerOfTwoLessThan(treeSize);
  if (leafIndex < split) {
    const left = verifyInclusionRange(node, leafIndex, split, proof, proofIndex);
    const step = proof[proofIndex.value];
    if (!step) throw new Error('BHTM proof ended before right sibling');
    proofIndex.value += 1;
    if (step.side !== 'right') {
      throw new Error(`BHTM proof step ${proofIndex.value - 1} should be a right sibling`);
    }
    return hashPair(left, step.hash);
  }

  const right = verifyInclusionRange(node, leafIndex - split, treeSize - split, proof, proofIndex);
  const step = proof[proofIndex.value];
  if (!step) throw new Error('BHTM proof ended before left sibling');
  proofIndex.value += 1;
  if (step.side !== 'left') {
    throw new Error(`BHTM proof step ${proofIndex.value - 1} should be a left sibling`);
  }
  return hashPair(step.hash, right);
}

function hashPair(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length !== 32 || right.length !== 32) {
    throw new Error(`BHTM Merkle nodes must be 32 bytes, got ${left.length} and ${right.length}`);
  }
  const data = new Uint8Array(64);
  data.set(left, 0);
  data.set(right, 32);
  return sha256(data);
}

function largestPowerOfTwoLessThan(n: number): number {
  if (!Number.isInteger(n) || n < 2) {
    throw new Error(`largestPowerOfTwoLessThan needs n >= 2, got ${n}`);
  }
  let p = 1;
  while (p * 2 < n) p *= 2;
  return p;
}

function parseProofStep(value: unknown, idx: number): { side: 'left' | 'right'; hash: Uint8Array } {
  if (!isRecord(value)) {
    throw new Error(`BHTM proof[${idx}] must be an object`);
  }
  const side = expectString(value, 'side');
  if (side !== 'left' && side !== 'right') {
    throw new Error(`BHTM proof[${idx}].side must be left|right, got ${side}`);
  }
  return {
    side,
    hash: expectHexBytes(expectString(value, 'hash'), 32, `proof[${idx}].hash`),
  };
}

function sliceReportField(report: Uint8Array, offset: number, len: number, name: string): Uint8Array {
  if (report.length < offset + len) {
    throw new Error(`SEV-SNP report too short for ${name}: got ${report.length} bytes`);
  }
  return report.slice(offset, offset + len);
}

function expectHexBytes(hex: string, bytes: number, field: string): Uint8Array {
  const normalized = normalizeHex(hex);
  if (normalized.length !== bytes * 2) {
    throw new Error(`${field} must be ${bytes} bytes of hex, got ${normalized.length / 2}`);
  }
  return hexToBytes(normalized);
}

function expectEqualHex(actual: string, expected: string, field: string): void {
  if (normalizeHex(actual) !== normalizeHex(expected)) {
    throw new Error(`${field} mismatch: expected ${expected}, got ${actual}`);
  }
}

function expectString(value: Record<string, unknown>, key: string): string {
  const v = value[key];
  if (typeof v !== 'string') {
    throw new Error(`${key} must be a string`);
  }
  return v;
}

function expectNumber(value: Record<string, unknown>, key: string): number {
  const v = value[key];
  if (typeof v !== 'number' || !Number.isInteger(v)) {
    throw new Error(`${key} must be an integer`);
  }
  return v;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizeHex(hex: string): string {
  return hex.trim().toLowerCase().replace(/^0x/, '');
}
