import type { WasmDatabaseProof } from './sdk-bridge.js';

export interface VerifiedDatabaseProof {
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
  builderBinarySha256Hex: string;
  builderGitCommit: string;
  onionEntrySize?: number;
  proofVersion?: number;
  onionTotalPackedEntries?: number;
  onionIndexBinsPerTable?: number;
  onionChunkBinsPerTable?: number;
  onionIndexSlotsPerBin?: number;
  onionIndexSlotSize?: number;
}

export interface DatabaseProofPin {
  dbId: number;
  buildKind: 'snapshot' | 'delta';
  fromHeight: number;
  height: number;
  fromBlockHashHex: string;
  /** Starting-state MuHash for a delta. It is authenticated by the separate
   * BHTM from-leaf proof, not by database-proof v1 itself. */
  fromMuhashHex?: string;
  blockHashHex: string;
  muhashHex: string;
  bucketSuperRootHex: string;
  onionSuperRootHex: string;
  paramsHashHex: string;
  networkMagicHex: string;
  builderBinarySha256Hex: string;
  builderGitCommit: string;
  /** Present in current attested-builder evidence; optional for older/static
   * manifest-derived pins that predate this field. */
  onionEntrySize?: number;
  description?: string;
}

export interface DatabaseProofStatus {
  state: 'not-checked' | 'verified' | 'unverified' | 'unavailable';
  dbId: number;
  pin?: DatabaseProofPin;
  proof?: VerifiedDatabaseProof;
  mismatches?: string[];
  error?: string;
}

export interface DatabaseAnchorPoint {
  role: 'from' | 'latest';
  height: number;
  blockHashHex: string;
}

export function verifiedDatabaseProofFromWasm(proof: WasmDatabaseProof): VerifiedDatabaseProof {
  return {
    dbId: proof.dbId,
    buildKind: proof.buildKind,
    fromHeight: proof.fromHeight,
    fromBlockHashHex: proof.fromBlockHashHex,
    height: proof.height,
    blockHashHex: proof.blockHashHex,
    muhashHex: proof.muhashHex,
    bucketSuperRootHex: proof.bucketSuperRootHex,
    onionSuperRootHex: proof.onionSuperRootHex,
    paramsHashHex: proof.paramsHashHex,
    networkMagicHex: proof.networkMagicHex,
    builderBinarySha256Hex: proof.builderBinarySha256Hex,
    builderGitCommit: proof.builderGitCommit,
    onionEntrySize: proof.onionEntrySize,
    proofVersion: proof.proofVersion,
    onionTotalPackedEntries: proof.onionTotalPackedEntries,
    onionIndexBinsPerTable: proof.onionIndexBinsPerTable,
    onionChunkBinsPerTable: proof.onionChunkBinsPerTable,
    onionIndexSlotsPerBin: proof.onionIndexSlotsPerBin,
    onionIndexSlotSize: proof.onionIndexSlotSize,
  };
}

export function verifyDatabaseProofAgainstPin(
  proof: VerifiedDatabaseProof,
  pin: DatabaseProofPin,
): DatabaseProofStatus {
  const mismatches: string[] = [];
  const cmp = (field: keyof DatabaseProofPin & keyof VerifiedDatabaseProof, hex = false) => {
    const expected = pin[field];
    const actual = proof[field];
    if (hex) {
      if (normalizeHex(String(expected)) !== normalizeHex(String(actual))) {
        mismatches.push(`${field}: expected ${expected}, got ${actual}`);
      }
      return;
    }
    if (expected !== actual) {
      mismatches.push(`${field}: expected ${expected}, got ${actual}`);
    }
  };

  cmp('dbId');
  cmp('buildKind');
  cmp('fromHeight');
  cmp('height');
  cmp('fromBlockHashHex', true);
  cmp('blockHashHex', true);
  cmp('muhashHex', true);
  cmp('bucketSuperRootHex', true);
  cmp('onionSuperRootHex', true);
  cmp('paramsHashHex', true);
  cmp('networkMagicHex', true);
  cmp('builderBinarySha256Hex', true);
  cmp('builderGitCommit');
  if (pin.onionEntrySize !== undefined) cmp('onionEntrySize');

  return {
    state: mismatches.length === 0 ? 'verified' : 'unverified',
    dbId: pin.dbId,
    pin,
    proof,
    mismatches,
  };
}

export function databaseProofUnavailable(
  pin: DatabaseProofPin,
  error: unknown,
): DatabaseProofStatus {
  const message = (error as Error)?.message ?? String(error);
  const unavailable = /not configured|server returned error|db proof/i.test(message);
  return {
    state: unavailable ? 'unavailable' : 'unverified',
    dbId: pin.dbId,
    pin,
    error: message,
  };
}

export function databaseProofAnchorLabel(proof: VerifiedDatabaseProof | DatabaseProofPin): string {
  if (proof.buildKind === 'delta') {
    return `${proof.fromHeight.toLocaleString()} to ${proof.height.toLocaleString()}`;
  }
  return proof.height.toLocaleString();
}

/**
 * Return every Bitcoin block hash that is an explicit input to the build.
 * A delta has two independently meaningful endpoints; the latest header alone
 * does not authenticate the claimed `from` hash unless the verifier also has
 * the intervening headers or a Merkle inclusion proof for that earlier leaf.
 */
export function databaseProofAnchorPoints(
  proof: VerifiedDatabaseProof | DatabaseProofPin,
): DatabaseAnchorPoint[] {
  const points: DatabaseAnchorPoint[] = [];
  if (proof.buildKind === 'delta') {
    points.push({
      role: 'from',
      height: proof.fromHeight,
      blockHashHex: normalizeHex(proof.fromBlockHashHex),
    });
  }
  points.push({
    role: 'latest',
    height: proof.height,
    blockHashHex: normalizeHex(proof.blockHashHex),
  });
  return points;
}

/** Build a safe mainnet mempool.space URL for a server-provided block hash. */
export function mempoolSpaceBlockUrl(blockHashHex: string): string | undefined {
  const hash = normalizeHex(blockHashHex);
  if (!/^[0-9a-f]{64}$/.test(hash)) return undefined;
  return `https://mempool.space/block/${hash}`;
}

function normalizeHex(hex: string): string {
  return hex.trim().toLowerCase().replace(/^0x/, '');
}
