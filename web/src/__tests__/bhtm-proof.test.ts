import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import {
  computeBhtmReportData,
  extractSnpMeasurement,
  extractSnpReportData,
  parseBhtmAttestationV2,
  verifyBhtmLeafProofJson,
} from '../bhtm-proof.js';
import { bytesToHex } from '../hash.js';

const fixtureRoot = new URL('../../public/proofs/trust-chain/delta_940611_948454/bhtm/', import.meta.url);

async function readFixture(name: string): Promise<Uint8Array> {
  return new Uint8Array(await readFile(new URL(name, fixtureRoot)));
}

async function readJsonFixture<T>(name: string): Promise<T> {
  return JSON.parse(new TextDecoder().decode(await readFixture(name))) as T;
}

describe('BHTM proof verification', () => {
  it('verifies the height 948454 leaf proof against the BHTM tree root', async () => {
    const leaf = verifyBhtmLeafProofJson(await readJsonFixture('height-948454.leaf-proof.json'));

    expect(leaf.height).toBe(948454);
    expect(leaf.leafIndex).toBe(48454);
    expect(leaf.treeSize).toBe(54921);
    expect(leaf.blockHashDisplayHex).toBe(
      '00000000000000000001ef683c02c383315db7e917c69d20f79e05985560a4e4',
    );
    expect(leaf.coreMuhashDisplayHex).toBe(
      'cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee',
    );
    expect(leaf.treeRootHex).toBe(
      'babeea635812c3b1a2d5f352ab0a5d1ee8a4e9c668c43c05d6603ef3c3766ba6',
    );
  });

  it('rejects a mutated leaf proof field', async () => {
    const proof = await readJsonFixture<any>('height-948454.leaf-proof.json');
    proof.core_muhash_display =
      '00' + proof.core_muhash_display.slice(2);

    expect(() => verifyBhtmLeafProofJson(proof)).toThrow(/core_muhash_display mismatch/);
  });

  it('parses BHTM attestation v2 and checks report-data/measurement offsets', async () => {
    const attestation = await readFixture('attestation.bin');
    const reportData = await readFixture('report-data.bin');
    const sevSnpReport = await readFixture('sev-snp-report.bin');
    const parsed = parseBhtmAttestationV2(attestation);

    expect(parsed.version).toBe(2);
    expect(parsed.jobVersion).toBe(1);
    expect(parsed.startHeight).toBe(899999);
    expect(parsed.endHeight).toBe(954920);
    expect(parsed.jobSha256Hex).toBe(
      '19e03b71ea9150b1c64d4a0069469384420a22dd4bcffd0ae1300a7121331e52',
    );
    expect(parsed.treeRootHex).toBe(
      'babeea635812c3b1a2d5f352ab0a5d1ee8a4e9c668c43c05d6603ef3c3766ba6',
    );
    expect(bytesToHex(computeBhtmReportData(attestation))).toBe(bytesToHex(reportData));
    expect(bytesToHex(extractSnpReportData(sevSnpReport))).toBe(bytesToHex(reportData));
    expect(bytesToHex(extractSnpMeasurement(sevSnpReport))).toBe(
      '652f8c813382abb0c09a7bdc6528e6a3494f9f0833eb087349ad5dac76dec140532763fec8eeaf3fa52723b6a5de8279',
    );
  });
});
