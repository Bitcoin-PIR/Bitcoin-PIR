import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { DELTA_940611_948454_DB_PROOF_PIN } from '../attest-pin.js';
import {
  DEFAULT_TRUST_CHAIN_MANIFEST_PATH,
  verifyProductionTrustChain,
} from '../trust-chain-proof.js';

const publicRoot = new URL('../../public/', import.meta.url);

async function publicArtifactLoader(path: string): Promise<Uint8Array> {
  const clean = path.startsWith('/') ? path.slice(1) : path;
  return new Uint8Array(await readFile(new URL(clean, publicRoot)));
}

describe('database trust-chain proof', () => {
  it('verifies the published delta_940611_948454 manifest and artifacts', async () => {
    const status = await verifyProductionTrustChain({
      artifactLoader: publicArtifactLoader,
      expectedDbPin: DELTA_940611_948454_DB_PROOF_PIN,
    });

    expect(status.state).toBe('verified');
    expect(status.mismatches).toEqual([]);
    expect(status.verified?.leaf.height).toBe(948454);
    expect(status.verified?.leaf.coreMuhashDisplayHex).toBe(
      DELTA_940611_948454_DB_PROOF_PIN.muhashHex,
    );
    expect(status.verified?.attestation.treeRootHex).toBe(
      'babeea635812c3b1a2d5f352ab0a5d1ee8a4e9c668c43c05d6603ef3c3766ba6',
    );
  });

  it('reports unverified when manifest and BHTM leaf disagree', async () => {
    const original = JSON.parse(
      new TextDecoder().decode(await publicArtifactLoader(DEFAULT_TRUST_CHAIN_MANIFEST_PATH)),
    );
    original.anchor.muhashHex =
      '00' + original.anchor.muhashHex.slice(2);
    const mutatedManifest = new TextEncoder().encode(JSON.stringify(original));

    const status = await verifyProductionTrustChain({
      manifestPath: DEFAULT_TRUST_CHAIN_MANIFEST_PATH,
      expectedDbPin: DELTA_940611_948454_DB_PROOF_PIN,
      artifactLoader: async (path) => (
        path === DEFAULT_TRUST_CHAIN_MANIFEST_PATH ? mutatedManifest : publicArtifactLoader(path)
      ),
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => m.includes('BHTM leaf Core MuHash'))).toBe(true);
    expect(status.mismatches.some((m) => m.includes('manifest DB pin'))).toBe(true);
  });
});
