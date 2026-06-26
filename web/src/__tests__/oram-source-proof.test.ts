import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN } from '../attest-pin.js';
import {
  DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH,
  verifyOramSourceProof,
} from '../oram-source-proof.js';

const publicRoot = new URL('../../public/', import.meta.url);

async function publicArtifactLoader(path: string): Promise<Uint8Array> {
  const clean = path.startsWith('/') ? path.slice(1) : path;
  return new Uint8Array(await readFile(new URL(clean, publicRoot)));
}

describe('ORAM source-binding proof', () => {
  it('verifies the published mainnet_948454 strict direct ORAM manifest and artifacts', async () => {
    const status = await verifyOramSourceProof({
      artifactLoader: publicArtifactLoader,
      expectedDbPin: MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN,
    });

    expect(status.state).toBe('verified');
    expect(status.mismatches).toEqual([]);
    expect(status.verified?.manifest.anchor.height).toBe(948454);
    expect(status.verified?.manifest.oramBuild.commit).toBe(
      '5f366492504d8e853cbd60d25a6adbf021a78746',
    );
    expect(status.verified?.manifest.oramBuild.params.indexSeedDecimal).toBe(
      '8030603977422561841',
    );
    expect(status.verified?.manifest.liveDeployment.status).toBe(
      'strict-source-bound-live-on-pir2',
    );
  });

  it('reports unverified when the manifest MuHash is changed', async () => {
    const original = JSON.parse(
      new TextDecoder().decode(await publicArtifactLoader(DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH)),
    );
    original.anchor.muhashHex =
      '00' + original.anchor.muhashHex.slice(2);
    const mutatedManifest = new TextEncoder().encode(JSON.stringify(original));

    const status = await verifyOramSourceProof({
      manifestPath: DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH,
      expectedDbPin: MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN,
      artifactLoader: async (path) => (
        path === DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH ? mutatedManifest : publicArtifactLoader(path)
      ),
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => m.includes('DB certification MuHash'))).toBe(true);
    expect(status.mismatches.some((m) => m.includes('manifest DB pin'))).toBe(true);
  });

  it('keeps the 64-bit ORAM index seed exact instead of rounding in JavaScript', async () => {
    const original = JSON.parse(
      new TextDecoder().decode(await publicArtifactLoader(DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH)),
    );
    original.oramBuild.params.indexSeedDecimal = '8030603977422561842';
    const mutatedManifest = new TextEncoder().encode(JSON.stringify(original));

    const status = await verifyOramSourceProof({
      manifestPath: DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH,
      artifactLoader: async (path) => (
        path === DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH ? mutatedManifest : publicArtifactLoader(path)
      ),
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => m.includes('index_seed decimal'))).toBe(true);
  });
});
