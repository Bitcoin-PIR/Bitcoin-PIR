import { describe, expect, it } from 'vitest';

import {
  assertIndependentProviderDialPairV1,
  expectedLightningPayeeForOfferV1,
  parseProductTrustedBootstrapV1,
  providerLightningPayeeTrustV1,
} from '../product-provider-bootstrap.js';
import type { ServiceOfferViewV1 } from '../sdk-bridge.js';
import { hexToBytes } from '../hash.js';

const ISSUER_ID = '11'.repeat(32);
const OTHER_ISSUER_ID = '22'.repeat(32);
const PAYEE = `02${'33'.repeat(32)}`;
const OTHER_PAYEE = `03${'44'.repeat(32)}`;

const provider = (providerIdHex: string, endpoint: string) => ({
  providerIdHex,
  endpoint,
  policySigningKeyHex: `policy-${providerIdHex}`,
  operatorSigningKeyHex: `operator-${providerIdHex}`,
  stableServerId: `server-${providerIdHex}`,
});

const databaseProofPin = {
  dbId: 0,
  buildKind: 'snapshot',
  fromHeight: 1,
  height: 2,
  fromBlockHashHex: '11'.repeat(32),
  blockHashHex: '12'.repeat(32),
  muhashHex: '13'.repeat(32),
  bucketSuperRootHex: '14'.repeat(32),
  onionSuperRootHex: '15'.repeat(32),
  paramsHashHex: '16'.repeat(32),
  networkMagicHex: 'f9beb4d9',
  builderBinarySha256Hex: '17'.repeat(32),
  builderGitCommit: 'trusted-builder',
};

function bootstrapProvider() {
  return {
    label: 'Provider 0',
    endpoint: 'wss://pir0.example',
    providerIdHex: '21'.repeat(32),
    policySigningKeyHex: '22'.repeat(32),
    operatorSigningKeyHex: '23'.repeat(32),
    stableServerId: 'pir0',
    serverPin: { binarySha256Hex: '24'.repeat(32) },
    hardwareAttestation: 'unavailable-accepted',
    databaseProofPins: [databaseProofPin],
    lightningPayeeTrust: [{
      issuerIdHex: ISSUER_ID,
      issuerOrigin: 'https://issuer.example',
      network: 'signet' as const,
      expectedPayeePubkeyHex: PAYEE,
    }],
  };
}

function parseProvider(overrides: Record<string, unknown> = {}) {
  return parseProductTrustedBootstrapV1(JSON.stringify({
    version: 1,
    network: 'signet',
    providers: [{ ...bootstrapProvider(), ...overrides }],
  })).providers[0];
}

function offer(overrides: Partial<ServiceOfferViewV1> = {}): ServiceOfferViewV1 {
  return {
    offerId: 7,
    acquisition: 'bolt11',
    authorization: 'cashu-bat',
    freeMode: 'not-free',
    verification: 'provider-local',
    deploymentStatus: 'stable',
    priorityClass: 1,
    price: { kind: 'msat', amount: '1000' },
    issuerIdHex: ISSUER_ID,
    keyIdHex: '31'.repeat(32),
    batVerificationKeyFingerprintHex: '32'.repeat(32),
    arcVerificationKeyFingerprintHex: '',
    endpoint: 'https://issuer.example',
    credentialCount: 1,
    credentialPresentationLimit: 1,
    privacyLeakageBits: 0,
    ...overrides,
  };
}

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

describe('exact Lightning payee bootstrap', () => {
  it('parses a bounded trust table and returns an owned copy', () => {
    const parsed = parseProvider({
      lightningPayeeTrust: [
        bootstrapProvider().lightningPayeeTrust[0],
        {
          issuerIdHex: OTHER_ISSUER_ID,
          issuerOrigin: 'https://other-issuer.example/',
          network: 'regtest',
          expectedPayeePubkeyHex: OTHER_PAYEE,
        },
      ],
    });
    expect(parsed.lightningPayeeTrust[1].issuerOrigin).toBe('https://other-issuer.example');
    const copy = providerLightningPayeeTrustV1(parsed);
    copy[0].expectedPayeePubkeyHex = OTHER_PAYEE;
    expect(parsed.lightningPayeeTrust[0].expectedPayeePubkeyHex).toBe(PAYEE);
  });

  it('resolves only an exact signed BOLT11 issuer/origin/network tuple', () => {
    const trust = parseProvider().lightningPayeeTrust;
    expect(Array.from(expectedLightningPayeeForOfferV1(trust, offer(), 'signet') ?? []))
      .toEqual(Array.from(hexToBytes(PAYEE)));
    for (const [changedOffer, network] of [
      [offer({ issuerIdHex: OTHER_ISSUER_ID }), 'signet'],
      [offer({ endpoint: 'https://other-issuer.example' }), 'signet'],
      [offer(), 'regtest'],
    ] as const) {
      expect(() => expectedLightningPayeeForOfferV1(trust, changedOffer, network))
        .toThrow(/no exact trusted Lightning payee/);
    }
  });

  it('returns no payee for every non-BOLT11 acquisition method', () => {
    for (const acquisition of ['free', 'cashu-ecash'] as const) {
      expect(expectedLightningPayeeForOfferV1([], offer({ acquisition }), 'signet'))
        .toBeUndefined();
    }
  });

  it('rejects provider-wide payee trust and requires an explicit table', () => {
    expect(() => parseProvider({
      expectedLightningPayeePubkeyHex: PAYEE,
    })).toThrow(/provider-wide Lightning payee trust/);
    expect(() => parseProvider({ lightningPayeeTrust: undefined }))
      .toThrow(/lightningPayeeTrust/);
  });

  it('rejects duplicate issuer/origin/network tuples regardless of payee', () => {
    const first = bootstrapProvider().lightningPayeeTrust[0];
    for (const expectedPayeePubkeyHex of [PAYEE, OTHER_PAYEE]) {
      expect(() => parseProvider({
        lightningPayeeTrust: [first, { ...first, expectedPayeePubkeyHex }],
      })).toThrow(/duplicate provider 0 Lightning payee trust tuple/);
    }
    expect(() => expectedLightningPayeeForOfferV1(
      [first, { ...first, expectedPayeePubkeyHex: OTHER_PAYEE }],
      offer(),
      'signet',
    )).toThrow(/duplicate Lightning payee trust tuple/);
  });

  it('rejects an oversized table and malformed trust fields', () => {
    const first = bootstrapProvider().lightningPayeeTrust[0];
    expect(() => parseProvider({ lightningPayeeTrust: Array(65).fill(first) }))
      .toThrow(/at most 64/);
    for (const invalid of [
      { ...first, issuerIdHex: '00'.repeat(32) },
      { ...first, issuerOrigin: 'http://issuer.example' },
      { ...first, issuerOrigin: 'https://user@issuer.example' },
      { ...first, issuerOrigin: 'https://issuer.example/path' },
      { ...first, network: 'mainnet' },
      { ...first, expectedPayeePubkeyHex: `04${'33'.repeat(32)}` },
    ]) {
      expect(() => parseProvider({ lightningPayeeTrust: [invalid] })).toThrow();
    }
  });

  it('fails closed on malformed signed BOLT11 issuer context', () => {
    const trust = parseProvider().lightningPayeeTrust;
    expect(() => expectedLightningPayeeForOfferV1(
      trust,
      offer({ endpoint: 'https://issuer.example/path' }),
      'signet',
    )).toThrow(/credential-free https/);
    expect(() => expectedLightningPayeeForOfferV1(
      trust,
      offer({ issuerIdHex: '00'.repeat(32) }),
      'signet',
    )).toThrow(/non-zero lowercase hex/);
  });
});

describe('database proof bootstrap anchors', () => {
  it('accepts the explicit zero predecessor only for a height-zero snapshot', () => {
    const initialSnapshot = {
      ...databaseProofPin,
      fromHeight: 0,
      fromBlockHashHex: '00'.repeat(32),
    };
    expect(parseProvider({ databaseProofPins: [initialSnapshot] }).databaseProofPins[0]
      .fromBlockHashHex).toBe(initialSnapshot.fromBlockHashHex);
    expect(() => parseProvider({
      databaseProofPins: [{ ...initialSnapshot, fromHeight: 1 }],
    })).toThrow(/fromBlockHashHex must be non-zero/);
  });
});
