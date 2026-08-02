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
      'b5f559816fe655507f37d57259cb3c1a162c8670971c1c30e079904e9e2c7ccd988b2b69080a3672048c75e46e236afa',
    );
    expect(() => assertIndependentProviderDialPairV1(
      parsed.providers[0],
      parsed.providers[1],
    )).not.toThrow();
    expect(parsed.providers.flatMap((provider) => provider.databaseProofPins)).not.toHaveLength(0);
  });
});
