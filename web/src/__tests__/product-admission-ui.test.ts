import { describe, expect, it } from 'vitest';

import { privacyLabelForOfferV1 } from '../product-admission-ui.js';
import type { ServiceOfferViewV1 } from '../sdk-bridge.js';

function offer(overrides: Partial<ServiceOfferViewV1>): ServiceOfferViewV1 {
  return {
    offerId: 1,
    acquisition: 'free',
    authorization: 'free',
    freeMode: 'open-best-effort',
    verification: 'provider-local',
    deploymentStatus: 'stable',
    priorityClass: 0,
    price: { kind: 'free' },
    issuerIdHex: '00'.repeat(32),
    keyIdHex: '',
    batVerificationKeyFingerprintHex: '',
    arcVerificationKeyFingerprintHex: '',
    endpoint: '',
    credentialCount: 0,
    credentialPresentationLimit: 0,
    privacyLeakageBits: 0,
    ...overrides,
  };
}

describe('signed offer privacy wording', () => {
  it('warns that a direct BOLT11 receipt is payment-to-spend linkable', () => {
    expect(privacyLabelForOfferV1(offer({
      acquisition: 'bolt11',
      authorization: 'bolt11-direct-receipt',
      freeMode: 'not-free',
      price: { kind: 'msat', amount: '1000' },
      privacyLeakageBits: 1 << 1,
    }))).toMatch(/DIRECT BOLT11.*links payment acquisition.*not.*anonymous/i);
  });

  it('surfaces issuer timing for free shared-issuer tickets', () => {
    expect(privacyLabelForOfferV1(offer({
      freeMode: 'anonymous-ticket',
      verification: 'shared-issuer-online',
      privacyLeakageBits: (1 << 2) | (1 << 3) | (1 << 4),
    }))).toMatch(/issuer observes redemption timing.*cross-leg timing/i);
  });

  it('distinguishes provider-local BAT, standard Cashu, and experimental ARC', () => {
    expect(privacyLabelForOfferV1(offer({
      acquisition: 'bolt11', authorization: 'cashu-bat', freeMode: 'not-free',
      privacyLeakageBits: (1 << 2) | (1 << 4) | (1 << 5),
    }))).toMatch(/blinded provider-local BAT.*not invoice\/hash/i);
    expect(privacyLabelForOfferV1(offer({
      acquisition: 'cashu-ecash', authorization: 'cashu-ecash', freeMode: 'not-free',
      verification: 'standard-cashu-mint-online', privacyLeakageBits: (1 << 3) | (1 << 4),
    }))).toMatch(/mint is online at redemption.*not invoice\/hash/i);
    expect(privacyLabelForOfferV1(offer({
      acquisition: 'bolt11', authorization: 'arc-experimental', freeMode: 'not-free',
      deploymentStatus: 'experimental', arcVerificationKeyFingerprintHex: '91'.repeat(32),
      privacyLeakageBits: (1 << 2) | (1 << 5),
    }))).toMatch(/EXPERIMENTAL ARC.*not independently reviewed/i);
  });
});
