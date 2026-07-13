import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { DELTA_940611_948454_DB_PROOF_PIN } from '../attest-pin.js';
import {
  DEFAULT_TRUST_CHAIN_MANIFEST_PATH,
  trustChainPinFromManifest,
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
      verifyAmdSignature: false,
    });

    expect(status.state).toBe('verified');
    expect(status.mismatches).toEqual([]);
    expect(status.verified?.fromLeaf?.height).toBe(940611);
    expect(status.verified?.fromLeaf?.leafIndex).toBe(40611);
    expect(status.verified?.fromLeaf?.blockHashDisplayHex).toBe(
      DELTA_940611_948454_DB_PROOF_PIN.fromBlockHashHex,
    );
    expect(status.verified?.leaf.height).toBe(948454);
    expect(status.verified?.leaf.coreMuhashDisplayHex).toBe(
      DELTA_940611_948454_DB_PROOF_PIN.muhashHex,
    );
    expect(status.verified?.attestation.treeRootHex).toBe(
      'babeea635812c3b1a2d5f352ab0a5d1ee8a4e9c668c43c05d6603ef3c3766ba6',
    );
    expect(status.verified?.fromLeaf?.treeRootHex).toBe(status.verified?.leaf.treeRootHex);
    expect(status.checks).toContainEqual({
      name: 'BHTM delta from leaf proof verified',
      state: 'verified',
    });
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
      verifyAmdSignature: false,
      artifactLoader: async (path) => (
        path === DEFAULT_TRUST_CHAIN_MANIFEST_PATH ? mutatedManifest : publicArtifactLoader(path)
      ),
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => m.includes('BHTM leaf Core MuHash'))).toBe(true);
    expect(status.mismatches.some((m) => m.includes('manifest DB pin'))).toBe(true);
  });

  it('directly verifies both live delta endpoints against the manifest', async () => {
    const manifest = JSON.parse(
      new TextDecoder().decode(await publicArtifactLoader(DEFAULT_TRUST_CHAIN_MANIFEST_PATH)),
    );
    const liveProof = trustChainPinFromManifest(manifest);
    liveProof.fromBlockHashHex = `${liveProof.fromBlockHashHex.slice(0, -1)}0`;

    const status = await verifyProductionTrustChain({
      artifactLoader: publicArtifactLoader,
      liveDatabaseProof: liveProof,
      verifyAmdSignature: false,
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => (
      m.includes('live DB proof vs manifest: fromBlockHashHex')
    ))).toBe(true);
    expect(status.checks.some((check) => (
      check.name === 'live DB proof matches manifest anchors and roots'
      && check.state === 'unverified'
    ))).toBe(true);
  });

  it('reports unverified when the delta from block hash disagrees with its BHTM leaf', async () => {
    const original = JSON.parse(
      new TextDecoder().decode(await publicArtifactLoader(DEFAULT_TRUST_CHAIN_MANIFEST_PATH)),
    );
    original.anchor.fromBlockHashHex = `${original.anchor.fromBlockHashHex.slice(0, -1)}0`;
    const mutatedManifest = new TextEncoder().encode(JSON.stringify(original));

    const status = await verifyProductionTrustChain({
      manifestPath: DEFAULT_TRUST_CHAIN_MANIFEST_PATH,
      artifactLoader: async (path) => (
        path === DEFAULT_TRUST_CHAIN_MANIFEST_PATH ? mutatedManifest : publicArtifactLoader(path)
      ),
      verifyAmdSignature: false,
    });

    expect(status.state).toBe('unverified');
    expect(status.verified).toBeUndefined();
    expect(status.mismatches.some((m) => m.includes('BHTM from leaf block hash'))).toBe(true);
  });

  it('fails closed when a delta manifest omits the from leaf proof', async () => {
    const original = JSON.parse(
      new TextDecoder().decode(await publicArtifactLoader(DEFAULT_TRUST_CHAIN_MANIFEST_PATH)),
    );
    delete original.bhtmProof.artifacts.fromLeafProof;
    const mutatedManifest = new TextEncoder().encode(JSON.stringify(original));

    const status = await verifyProductionTrustChain({
      manifestPath: DEFAULT_TRUST_CHAIN_MANIFEST_PATH,
      artifactLoader: async (path) => (
        path === DEFAULT_TRUST_CHAIN_MANIFEST_PATH ? mutatedManifest : publicArtifactLoader(path)
      ),
      verifyAmdSignature: false,
    });

    expect(status.state).toBe('unverified');
    expect(status.error).toContain('missing BHTM fromLeafProof artifact');
  });

  it('rejects substituting the latest leaf proof for the delta from leaf proof', async () => {
    const original = JSON.parse(
      new TextDecoder().decode(await publicArtifactLoader(DEFAULT_TRUST_CHAIN_MANIFEST_PATH)),
    );
    original.bhtmProof.artifacts.fromLeafProof = original.bhtmProof.artifacts.leafProof;
    const mutatedManifest = new TextEncoder().encode(JSON.stringify(original));

    const status = await verifyProductionTrustChain({
      manifestPath: DEFAULT_TRUST_CHAIN_MANIFEST_PATH,
      artifactLoader: async (path) => (
        path === DEFAULT_TRUST_CHAIN_MANIFEST_PATH ? mutatedManifest : publicArtifactLoader(path)
      ),
      verifyAmdSignature: false,
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => m.includes('BHTM from leaf height'))).toBe(true);
  });

  it('binds the published job bytes to the attested job hash', async () => {
    const original = JSON.parse(
      new TextDecoder().decode(await publicArtifactLoader(DEFAULT_TRUST_CHAIN_MANIFEST_PATH)),
    );
    const jobRef = original.bhtmProof.artifacts.job;
    const job = JSON.parse(new TextDecoder().decode(await publicArtifactLoader(jobRef.path)));
    job.chain = 'testnet';
    const mutatedJob = new TextEncoder().encode(JSON.stringify(job));
    jobRef.size = mutatedJob.length;
    jobRef.sha256 = createHash('sha256').update(mutatedJob).digest('hex');
    const mutatedManifest = new TextEncoder().encode(JSON.stringify(original));

    const status = await verifyProductionTrustChain({
      manifestPath: DEFAULT_TRUST_CHAIN_MANIFEST_PATH,
      artifactLoader: async (path) => {
        if (path === DEFAULT_TRUST_CHAIN_MANIFEST_PATH) return mutatedManifest;
        if (path === jobRef.path) return mutatedJob;
        return publicArtifactLoader(path);
      },
      verifyAmdSignature: false,
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => m.includes('BHTM job artifact sha256'))).toBe(true);
    expect(status.mismatches.some((m) => m.includes('BHTM job chain'))).toBe(true);
  });

  it('rejects an unknown build kind instead of bypassing delta checks', async () => {
    const original = JSON.parse(
      new TextDecoder().decode(await publicArtifactLoader(DEFAULT_TRUST_CHAIN_MANIFEST_PATH)),
    );
    original.anchor.buildKind = 'unknown';
    const mutatedManifest = new TextEncoder().encode(JSON.stringify(original));

    const status = await verifyProductionTrustChain({
      manifestPath: DEFAULT_TRUST_CHAIN_MANIFEST_PATH,
      artifactLoader: async (path) => (
        path === DEFAULT_TRUST_CHAIN_MANIFEST_PATH ? mutatedManifest : publicArtifactLoader(path)
      ),
      verifyAmdSignature: false,
    });

    expect(status.state).toBe('unverified');
    expect(status.error).toContain('unsupported trust-chain buildKind unknown');
  });
});
