import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import bundledFunctionalBetaBootstrap from '../functional-beta-trusted-bootstrap.json';
import {
  assertIndependentProviderDialPairV1,
  parseProductTrustedBootstrapV1,
} from '../product-provider-bootstrap.js';

describe('bundled functional-beta trusted bootstrap', () => {
  it('pins the live Hetzner and VPSBG providers as an independent Signet pair', () => {
    const parsed = parseProductTrustedBootstrapV1(
      JSON.stringify(bundledFunctionalBetaBootstrap),
    );

    expect(parsed.network).toBe('signet');
    expect(parsed.providers).toHaveLength(2);
    expect(parsed.providers.map((provider) => provider.endpoint)).toEqual([
      'wss://weikeng1.bitcoinpir.org',
      'wss://weikeng2.bitcoinpir.org',
    ]);
    expect(parsed.providers[1].hardwareAttestation).toBe('required');
    expect(parsed.providers[1].operatorSigningKeyHex).toBe(
      '256fb106c039f8009d3caa431a9634ff3fe5db3b9e4d9ae7282bbde66772c97a',
    );
    expect(parsed.providers[1].serverPin.measurementHex).toBe(
      'b8b9e724b244a52a2f87dfcde3edb895cbf5eec1c9b08f964eaefc8160c8be4988c7814fe424cbbd3158ff2e7928db53',
    );
    expect(parsed.providers[1].serverPin.binarySha256Hex).toBe(
      '8aa6928c866aaed396c8d2ffe70520ba1dd7e650c4e5bfdaea87f38eb42ea355',
    );
    expect(parsed.providers[0].supportedWorkloads).toEqual([
      'dpf-query', 'harmony-hint', 'onion-session',
    ]);
    expect(parsed.providers[1].supportedWorkloads).toEqual([
      'dpf-query', 'harmony-query', 'tee-oram-query',
    ]);
    expect(() => assertIndependentProviderDialPairV1(
      parsed.providers[0],
      parsed.providers[1],
    )).not.toThrow();
    expect(parsed.providers.flatMap((provider) => provider.databaseProofPins)).not.toHaveLength(0);
  });

  it('rejects a provider without an explicit pre-connection workload allowlist', () => {
    const replacement = structuredClone(bundledFunctionalBetaBootstrap) as {
      providers: Array<Record<string, unknown>>;
    };
    delete replacement.providers[0].supportedWorkloads;
    expect(() => parseProductTrustedBootstrapV1(JSON.stringify(replacement))).toThrow(
      /must declare supported workloads/,
    );
  });

  it('routes strict OnionPIR through the reviewed v2 proof pins', () => {
    const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
    const start = html.indexOf('async function opConnect(provider)');
    const end = html.indexOf('function opDisconnect', start);
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);

    const onionConnect = html.slice(start, end);
    expect(onionConnect).toContain('databaseProofPins: PRODUCTION_ONION_DB_PROOF_V2_PINS');
    expect(onionConnect).not.toContain('databaseProofPins: provider.databaseProofPins');
  });

  it('routes strict Direct ORAM through the reviewed full-build v2 proof pins', () => {
    const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
    const start = html.indexOf('async function oramConnect(provider)');
    const end = html.indexOf('function oramDisconnect', start);
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);

    const oramConnect = html.slice(start, end);
    expect(oramConnect).toContain('databaseProofPins: PRODUCTION_ORAM_DB_PROOF_V2_PINS');
    expect(oramConnect).not.toContain('databaseProofPins: PRODUCTION_ONION_DB_PROOF_V2_PINS');
    expect(oramConnect).not.toContain('databaseProofPins: provider.databaseProofPins');
  });
});
