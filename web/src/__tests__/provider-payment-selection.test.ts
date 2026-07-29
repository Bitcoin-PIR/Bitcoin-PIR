import { describe, expect, it } from 'vitest';

import { assertIndependentProviderOfferPairV1 } from '../provider-payment-selection.js';
import type { ProviderTrustAnchorV1 } from '../service-admission.js';
import type { ServiceOfferViewV1 } from '../sdk-bridge.js';

function trust(providerByte: number, policyByte: number, operatorByte: number): ProviderTrustAnchorV1 {
  return {
    providerId: new Uint8Array(32).fill(providerByte),
    policySigningKey: new Uint8Array(32).fill(policyByte),
    directoryAssertion: {
      operatorSigningKeyEd25519: new Uint8Array(32).fill(operatorByte),
      stableServerId: `pir-${providerByte}`,
      policyEpoch: 1n,
      policyDigest: new Uint8Array(32).fill(providerByte + 1),
    },
  };
}

function offer(overrides: Partial<ServiceOfferViewV1> = {}): ServiceOfferViewV1 {
  return {
    offerId: 1,
    acquisition: 'bolt11',
    authorization: 'cashu-bat',
    freeMode: 'not-free',
    verification: 'provider-local',
    deploymentStatus: 'stable',
    priorityClass: 1,
    price: { kind: 'msat', amount: '1000' },
    issuerIdHex: '31'.repeat(32),
    keyIdHex: '41'.repeat(32),
    batVerificationKeyFingerprintHex: '51'.repeat(32),
    arcVerificationKeyFingerprintHex: '',
    endpoint: 'https://issuer-a.example',
    credentialCount: 1,
    credentialPresentationLimit: 1,
    privacyLeakageBits: 0,
    ...overrides,
  };
}

describe('local independent-provider payment selection', () => {
  it('accepts independent providers, issuers, origins, and BAT raw keys', () => {
    expect(() => assertIndependentProviderOfferPairV1(
      { trust: trust(1, 11, 21), offer: offer() },
      { trust: trust(2, 12, 22), offer: offer({
        issuerIdHex: '32'.repeat(32),
        keyIdHex: '42'.repeat(32),
        endpoint: 'https://issuer-b.example',
        batVerificationKeyFingerprintHex: '52'.repeat(32),
      }) },
    )).not.toThrow();
  });

  it('rejects a copied raw BAT key even if shared issuer correlation is explicitly allowed', () => {
    expect(() => assertIndependentProviderOfferPairV1(
      { trust: trust(1, 11, 21), offer: offer() },
      { trust: trust(2, 12, 22), offer: offer() },
      { allowSharedIssuerCorrelation: true },
    )).toThrow(/raw Cashu BAT verification key/);
  });

  it('rejects a copied raw ARC key even if shared issuer correlation is explicitly allowed', () => {
    const arcOffer = offer({
      authorization: 'arc-experimental',
      deploymentStatus: 'experimental',
      batVerificationKeyFingerprintHex: '',
      arcVerificationKeyFingerprintHex: '61'.repeat(32),
      credentialPresentationLimit: 10,
    });
    expect(() => assertIndependentProviderOfferPairV1(
      { trust: trust(1, 11, 21), offer: arcOffer },
      { trust: trust(2, 12, 22), offer: { ...arcOffer, offerId: 2 } },
      { allowSharedIssuerCorrelation: true },
    )).toThrow(/raw ARC verification key/);
  });

  it('accepts two ARC raw keys after explicit shared-issuer correlation opt-in', () => {
    const first = offer({
      authorization: 'arc-experimental',
      deploymentStatus: 'experimental',
      batVerificationKeyFingerprintHex: '',
      arcVerificationKeyFingerprintHex: '61'.repeat(32),
      credentialPresentationLimit: 10,
    });
    expect(() => assertIndependentProviderOfferPairV1(
      { trust: trust(1, 11, 21), offer: first },
      { trust: trust(2, 12, 22), offer: {
        ...first,
        offerId: 2,
        arcVerificationKeyFingerprintHex: '62'.repeat(32),
      } },
      { allowSharedIssuerCorrelation: true },
    )).not.toThrow();
  });

  it('fails closed when a non-ARC offer exposes an ARC raw-key fingerprint', () => {
    expect(() => assertIndependentProviderOfferPairV1(
      { trust: trust(1, 11, 21), offer: offer({
        arcVerificationKeyFingerprintHex: '61'.repeat(32),
      }) },
      { trust: trust(2, 12, 22), offer: offer({
        issuerIdHex: '32'.repeat(32),
        endpoint: 'https://issuer-b.example',
        batVerificationKeyFingerprintHex: '52'.repeat(32),
      }) },
    )).toThrow(/non-ARC offer/);
  });

  it('rejects one paid issuer or origin by default and requires explicit opt-in', () => {
    const first = { trust: trust(1, 11, 21), offer: offer() };
    const second = { trust: trust(2, 12, 22), offer: offer({
      batVerificationKeyFingerprintHex: '52'.repeat(32),
    }) };
    expect(() => assertIndependentProviderOfferPairV1(first, second)).toThrow(/one issuer/);
    expect(() => assertIndependentProviderOfferPairV1(
      first,
      second,
      { allowSharedIssuerCorrelation: true },
    )).not.toThrow();
  });

  it('also rejects free anonymous tickets verified by one shared issuer', () => {
    const anonymousTicket = offer({
      acquisition: 'free',
      authorization: 'free',
      freeMode: 'anonymous-ticket',
      verification: 'shared-issuer-online',
      price: { kind: 'free' },
      batVerificationKeyFingerprintHex: '',
      endpoint: 'https://tickets.example',
      issuerIdHex: '61'.repeat(32),
    });
    const first = { trust: trust(1, 11, 21), offer: anonymousTicket };
    const second = { trust: trust(2, 12, 22), offer: { ...anonymousTicket, offerId: 2 } };
    expect(() => assertIndependentProviderOfferPairV1(first, second)).toThrow(/one issuer/);
    expect(() => assertIndependentProviderOfferPairV1(
      first,
      second,
      { allowSharedIssuerCorrelation: true },
    )).not.toThrow();
  });

  it('guards a paid plus free-ticket pair and accepts two external issuers', () => {
    const paid = { trust: trust(1, 11, 21), offer: offer() };
    const freeTicket = (issuer: string, endpoint: string) => ({
      trust: trust(2, 12, 22),
      offer: offer({
        acquisition: 'free', authorization: 'free', freeMode: 'anonymous-ticket',
        verification: 'shared-issuer-online', price: { kind: 'free' },
        issuerIdHex: issuer, endpoint, batVerificationKeyFingerprintHex: '',
      }),
    });
    expect(() => assertIndependentProviderOfferPairV1(
      paid,
      freeTicket(paid.offer.issuerIdHex, paid.offer.endpoint),
    )).toThrow(/one issuer/);
    expect(() => assertIndependentProviderOfferPairV1(
      paid,
      {
        ...freeTicket('72'.repeat(32), 'https://tickets-b.example'),
        offer: {
          ...freeTicket('72'.repeat(32), 'https://tickets-b.example').offer,
          keyIdHex: '73'.repeat(32),
        },
      },
    )).not.toThrow();
  });

  it('rejects a shared delegated receipt key even with the issuer override', () => {
    const first = {
      trust: trust(1, 11, 21),
      offer: offer({
        authorization: 'bolt11-direct-receipt',
        keyIdHex: '41'.repeat(16),
        batVerificationKeyFingerprintHex: '',
      }),
    };
    const second = { trust: trust(2, 12, 22), offer: offer({
      authorization: 'bolt11-direct-receipt',
      issuerIdHex: '32'.repeat(32),
      endpoint: 'https://issuer-b.example',
      batVerificationKeyFingerprintHex: '',
      keyIdHex: '41'.repeat(16),
    }) };
    expect(() => assertIndependentProviderOfferPairV1(first, second))
      .toThrow(/receipt verification key/);
    expect(() => assertIndependentProviderOfferPairV1(
      first, second, { allowSharedIssuerCorrelation: true },
    )).toThrow(/receipt verification key/);
  });

  it('rejects one Lightning payee observing both purchases', () => {
    const payee = new Uint8Array([2, ...new Uint8Array(32).fill(9)]);
    const first = {
      trust: trust(1, 11, 21), offer: offer(),
      expectedLightningPayeePubkey: payee,
    };
    const second = {
      trust: trust(2, 12, 22),
      offer: offer({
        issuerIdHex: '32'.repeat(32), keyIdHex: '42'.repeat(32),
        endpoint: 'https://issuer-b.example',
        batVerificationKeyFingerprintHex: '52'.repeat(32),
      }),
      expectedLightningPayeePubkey: payee.slice(),
    };
    expect(() => assertIndependentProviderOfferPairV1(
      first,
      second,
      { allowSharedIssuerCorrelation: true },
    ))
      .toThrow(/Lightning payee/);
  });

  it('rejects two PIR roles on one WebSocket origin even with different paths', () => {
    const first = {
      trust: trust(1, 11, 21), offer: offer(),
      providerEndpoint: 'wss://pir.example/provider-a',
    };
    const second = {
      trust: trust(2, 12, 22),
      offer: offer({
        issuerIdHex: '32'.repeat(32), keyIdHex: '42'.repeat(32),
        endpoint: 'https://issuer-b.example',
        batVerificationKeyFingerprintHex: '52'.repeat(32),
      }),
      providerEndpoint: 'wss://pir.example/provider-b',
    };
    expect(() => assertIndependentProviderOfferPairV1(
      first,
      second,
      { allowSharedIssuerCorrelation: true },
    ))
      .toThrow(/WebSocket origin/);
  });
});
