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
    expect(parsed.providers[1].serverPin.measurementHex).toBe(
      '3564465a167bcc8d406041f296ecce12749a151bebc996371ebbea35b3947ad85011d99777562ff8b53bfd314846de21',
    );
    expect(() => assertIndependentProviderDialPairV1(
      parsed.providers[0],
      parsed.providers[1],
    )).not.toThrow();
    expect(parsed.providers.flatMap((provider) => provider.databaseProofPins)).not.toHaveLength(0);
  });
});
