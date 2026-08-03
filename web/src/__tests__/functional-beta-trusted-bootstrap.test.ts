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
      'cfae85d99232010a028b4dd820b0da67069c0685a1b8cb72520b0d884f678f3def19febe5cc18b0af3c976821791b897',
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
});
