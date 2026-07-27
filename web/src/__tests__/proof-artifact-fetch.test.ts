import { describe, expect, it, vi } from 'vitest';

import {
  fetchProofArtifactBytesV1,
  resolveProofArtifactUrlV1,
} from '../proof-artifact-fetch.js';

const BASE_HREF = 'https://bitcoinpir.example/app/index.html';

describe('same-origin proof artifact fetch', () => {
  it('accepts only canonical paths below the same-origin /proofs/ namespace', () => {
    expect(resolveProofArtifactUrlV1(
      '/proofs/trust-chain/example/artifact.bin',
      BASE_HREF,
    ).href).toBe('https://bitcoinpir.example/proofs/trust-chain/example/artifact.bin');

    for (const path of [
      'https://attacker.example/proofs/a',
      '//attacker.example/proofs/a',
      '/api/private',
      '/proofs/../api/private',
      '/proofs/%2e%2e/api/private',
      '/proofs/a?leak=1',
      '/proofs/a#fragment',
      '/proofs//a',
      '/proofs\\a',
    ]) {
      expect(() => resolveProofArtifactUrlV1(path, BASE_HREF)).toThrow();
    }
  });

  it('omits ambient authority and rejects redirects when fetching', async () => {
    const body = new Uint8Array([1, 2, 3]);
    const fetchImpl = vi.fn(async () => new Response(body, {
      status: 200,
      headers: { 'content-length': String(body.length) },
    })) as unknown as typeof fetch;

    await expect(fetchProofArtifactBytesV1('/proofs/a.bin', {
      baseHref: BASE_HREF,
      fetchImpl,
    })).resolves.toEqual(body);
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://bitcoinpir.example/proofs/a.bin',
      {
        method: 'GET',
        mode: 'same-origin',
        credentials: 'omit',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        cache: 'no-store',
      },
    );
  });

  it('rejects oversized or redirected responses and never fetches an invalid path', async () => {
    const invalidFetch = vi.fn() as unknown as typeof fetch;
    await expect(fetchProofArtifactBytesV1('https://attacker.example/a', {
      baseHref: BASE_HREF,
      fetchImpl: invalidFetch,
    })).rejects.toThrow(/canonical absolute/);
    expect(invalidFetch).not.toHaveBeenCalled();

    const oversizedFetch = vi.fn(async () => new Response(new Uint8Array([1]), {
      status: 200,
      headers: { 'content-length': '65' },
    })) as unknown as typeof fetch;
    await expect(fetchProofArtifactBytesV1('/proofs/a.bin', {
      baseHref: BASE_HREF,
      fetchImpl: oversizedFetch,
      maxBytes: 64,
    })).rejects.toThrow(/fetch limit/);

    const redirectedFetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      redirected: true,
      url: 'https://bitcoinpir.example/proofs/elsewhere.bin',
      headers: new Headers(),
      arrayBuffer: async () => new Uint8Array([1]).buffer,
    } as Response)) as unknown as typeof fetch;
    await expect(fetchProofArtifactBytesV1('/proofs/a.bin', {
      baseHref: BASE_HREF,
      fetchImpl: redirectedFetch,
    })).rejects.toThrow(/redirect rejected/);
  });
});
