import { describe, expect, it } from 'vitest';

import {
  canBootstrapNextProviderV1,
  credentialActionsReadyV1,
  pairAuthorizationReadyV1,
  privacyLabelForOfferV1,
} from '../product-admission-ui.js';
import type { ProductAdmissionSnapshotV1 } from '../product-admission-controller.js';
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

function stagedSnapshot(
  statuses: Array<'offer-selection-required' | 'ready'>,
  selected: boolean[],
): ProductAdmissionSnapshotV1 {
  return {
    phase: 'selecting',
    topology: 'independent-pair',
    allowSharedIssuerCorrelationOnce: false,
    errorCode: null,
    legs: statuses.map((status, index) => ({
      role: `server${index}`,
      label: `Server ${index}`,
      providerIdHex: `${index + 1}`.repeat(64),
      policyDigestHex: `${index + 3}`.repeat(64),
      status,
      offers: [],
      selected: selected[index] ? { scopeIdHex: '11'.repeat(32), offerId: index + 1 } : null,
      retainedCapabilities: [],
      retainedSelected: null,
      retainedRecoveries: [],
      inventory: null,
      invoice: null,
      invoiceExpiresAtUnix: null,
      quoteStatus: null,
      recoveryIds: [],
      errorCode: null,
    })),
  };
}

describe('staged provider UI ordering', () => {
  it('enables the second provider after first offer selection but keeps payment actions hidden', () => {
    const firstSelected = stagedSnapshot(['ready'], [true]);
    expect(canBootstrapNextProviderV1(firstSelected)).toBe(true);
    expect(credentialActionsReadyV1(firstSelected)).toBe(false);
  });

  it('enables credential actions only after both exact offers are selected', () => {
    expect(canBootstrapNextProviderV1(
      stagedSnapshot(['offer-selection-required'], [false]),
    )).toBe(false);
    expect(credentialActionsReadyV1(
      stagedSnapshot(['ready', 'offer-selection-required'], [true, false]),
    )).toBe(false);
    expect(credentialActionsReadyV1(
      stagedSnapshot(['ready', 'ready'], [true, true]),
    )).toBe(true);
  });

  it('holds pair authorization while a paid peer has no local capability', () => {
    const snapshot = stagedSnapshot(['ready', 'ready'], [true, true]);
    snapshot.legs[0].offers = [{
      scopeIdHex: snapshot.legs[0].selected!.scopeIdHex,
      offerId: snapshot.legs[0].selected!.offerId,
      scope: {
        scopeIdHex: snapshot.legs[0].selected!.scopeIdHex,
        backend: 'dpf-pir',
        workload: 'dpf-query',
        protocolVersion: 1,
        operationProfile: 1,
        entitlementProfile: 1,
        offers: [],
      },
      offer: offer({}),
    }];
    snapshot.legs[1].offers = [{
      ...snapshot.legs[0].offers[0],
      scopeIdHex: snapshot.legs[1].selected!.scopeIdHex,
      offerId: snapshot.legs[1].selected!.offerId,
      offer: offer({
        acquisition: 'bolt11',
        authorization: 'cashu-bat',
        freeMode: 'not-free',
        price: { kind: 'msat', amount: '1000' },
      }),
    }];
    expect(pairAuthorizationReadyV1(snapshot)).toBe(false);
    snapshot.legs[1].inventory = 1;
    expect(pairAuthorizationReadyV1(snapshot)).toBe(true);
  });
});
