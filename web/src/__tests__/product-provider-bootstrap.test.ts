import { describe, expect, it } from 'vitest';

import { assertIndependentProviderDialPairV1 } from '../product-provider-bootstrap.js';

const provider = (providerIdHex: string, endpoint: string) => ({
  providerIdHex,
  endpoint,
  policySigningKeyHex: `policy-${providerIdHex}`,
  operatorSigningKeyHex: `operator-${providerIdHex}`,
  stableServerId: `server-${providerIdHex}`,
});

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

  it.each([
    ['operatorSigningKeyHex', 'operator signing key'],
    ['policySigningKeyHex', 'policy signing key'],
    ['stableServerId', 'stable server identity'],
  ] as const)('rejects a shared trusted %s before the second dial', (field, reason) => {
    const first = provider('01', 'wss://pir0.example');
    const second = provider('02', 'wss://pir1.example');
    second[field] = first[field];
    expect(() => assertIndependentProviderDialPairV1(first, second)).toThrow(reason);
  });
});
