import { readFile } from 'node:fs/promises';
import { beforeAll, describe, expect, it, vi } from 'vitest';

const { requireSdkWasm } = vi.hoisted(() => ({ requireSdkWasm: vi.fn() }));
vi.mock('../sdk-bridge.js', () => ({ requireSdkWasm }));
import { PRODUCTION_ORAM_DB_PROOF_V2_PINS } from '../attest-pin.js';
import { trustChainManifestPathForDatabase, verifyProductionTrustChain } from '../trust-chain-proof.js';

const pin = PRODUCTION_ORAM_DB_PROOF_V2_PINS[0];
const manifestPath = '/proofs/trust-chain/snapshot_976083.json';
async function load(path: string): Promise<Uint8Array> {
  return new Uint8Array(await readFile(new URL(`../../public/${path.replace(/^\//, '')}`, import.meta.url)));
}

describe('published snapshot Bitcoin anchor', () => {
  beforeAll(async () => {
    const sdk = await import('pir-sdk-wasm');
    sdk.initSync({ module: await readFile(new URL('../../../crates/sdk/wasm/pkg/pir_sdk_wasm_bg.wasm', import.meta.url)) });
    requireSdkWasm.mockReturnValue(sdk);
  });

  it('verifies the 976083 leaf, report binding, AMD signature and Milan platform floor', async () => {
    expect(trustChainManifestPathForDatabase(pin)).toBe(manifestPath);
    const status = await verifyProductionTrustChain({ manifestPath, artifactLoader: load, expectedDbPin: pin });
    expect(status.error).toBeUndefined();
    expect(status.mismatches).toEqual([]);
    expect(status.state).toBe('verified');
    expect(status.manifestPath).toBe(manifestPath);
    expect(status.verified?.leaf.height).toBe(976083);
    expect(status.verified?.leaf.coreMuhashDisplayHex).toBe(pin.muhashHex);
    expect(status.verified?.fromLeaf).toBeUndefined();
    expect(status.checks).toContainEqual({ name: 'BHTM AMD VCEK/report signature verified', state: 'verified' });
  });

  it('rejects the Milan proof when its manifest selects the historical Turin default', async () => {
    const manifest = JSON.parse(new TextDecoder().decode(await load(manifestPath)));
    delete manifest.bhtmProof.amdProduct;
    const status = await verifyProductionTrustChain({ manifestPath, expectedDbPin: pin,
      artifactLoader: path => path === manifestPath
        ? Promise.resolve(new TextEncoder().encode(JSON.stringify(manifest))) : load(path) });
    expect(status.state).toBe('unverified');
    expect(status.checks).not.toContainEqual({ name: 'BHTM AMD VCEK/report signature verified', state: 'verified' });
  });
});
