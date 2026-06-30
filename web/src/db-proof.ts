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
}

export interface DatabaseProofPin {
  dbId: number;
  buildKind: 'snapshot' | 'delta';
  fromHeight: number;
  height: number;
  fromBlockHashHex: string;
  blockHashHex: string;
  muhashHex: string;
  bucketSuperRootHex: string;
  onionSuperRootHex: string;
  paramsHashHex: string;
  networkMagicHex: string;
  builderBinarySha256Hex: string;
  builderGitCommit: string;
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

function normalizeHex(hex: string): string {
  return hex.trim().toLowerCase().replace(/^0x/, '');
}
