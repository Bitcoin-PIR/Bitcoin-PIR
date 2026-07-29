import { describe, expect, it } from 'vitest';

import { assertIndependentProviderDialPairV1 } from '../product-provider-bootstrap.js';

const provider = (providerIdHex: string, endpoint: string) => ({ providerIdHex, endpoint });

describe('pre-dial provider independence', () => {
  it('accepts distinct provider identities at distinct WebSocket origins', () => {
    expect(() => assertIndependentProviderDialPairV1(
      provider('01', 'wss://pir0.example'),
      provider('02', 'wss://pir1.example'),
    )).not.toThrow();
  });

  it('rejects one provider identity before the second dial', () => {
    expect(() => assertIndependentProviderDialPairV1(
      provider('01', 'wss://pir0.example'),
      provider('01', 'wss://pir1.example'),
    )).toThrow(/distinct provider identities/);
  });

  it('rejects a shared ingress even when URL paths differ', () => {
    expect(() => assertIndependentProviderDialPairV1(
      provider('01', 'wss://shared.example/hint'),
      provider('02', 'wss://shared.example/query'),
    )).toThrow(/one WebSocket origin/);
  });

  it('fails closed for a malformed trusted endpoint', () => {
    expect(() => assertIndependentProviderDialPairV1(
      provider('01', 'wss://pir0.example'),
      provider('02', 'https://pir1.example'),
    )).toThrow(/wss/);
  });
});
