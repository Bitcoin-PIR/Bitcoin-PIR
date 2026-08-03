import { describe, expect, it } from 'vitest';

import {
  canBootstrapNextProviderV1,
  credentialActionsReadyV1,
  offerChoiceLabelForOfferV1,
  pairAuthorizationReadyV1,
  partitionOfferOptionsForDisplayV1,
  privacyLabelForOfferV1,
  publicAdmissionError,
  retainedCapabilityLabelV1,
  retainedRecoveryLabelV1,
} from '../product-admission-ui.js';
import type {
  ProductAdmissionSnapshotV1,
  ProductOfferOptionV1,
} from '../product-admission-controller.js';
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
  it('labels free capacity and premium authorization methods distinctly', () => {
    const free = offerChoiceLabelForOfferV1({ offer: offer({}) } as ProductOfferOptionV1);
    const bolt11 = offerChoiceLabelForOfferV1({ offer: offer({
      acquisition: 'bolt11',
      authorization: 'bolt11-direct-receipt',
      freeMode: 'not-free',
      price: { kind: 'msat', amount: '1000' },
    }) } as ProductOfferOptionV1);
    const bat = offerChoiceLabelForOfferV1({ offer: offer({
      acquisition: 'bolt11',
      authorization: 'cashu-bat',
      freeMode: 'not-free',
      price: { kind: 'msat', amount: '1000' },
    }) } as ProductOfferOptionV1);
    const arc = offerChoiceLabelForOfferV1({ offer: offer({
      acquisition: 'bolt11',
      authorization: 'arc-experimental',
      freeMode: 'not-free',
      price: { kind: 'msat', amount: '1000' },
    }) } as ProductOfferOptionV1);

    expect(free).toMatch(/Free access.*best effort, may queue.*no charge/i);
    expect(bolt11).toMatch(/Premium access.*BOLT11 direct receipt.*1000 msat/i);
    expect(bat).toMatch(/Premium access.*Cashu BAT.*acquire with BOLT11/i);
    expect(arc).toMatch(/Premium access.*ARC.*EXPERIMENTAL.*acquire with BOLT11/i);
  });

  it('puts Free offers before Premium offers without dropping either exact offer', () => {
    const free = { offer: offer({ offerId: 11 }) } as ProductOfferOptionV1;
    const premium = { offer: offer({
      offerId: 12,
      acquisition: 'bolt11',
      authorization: 'cashu-bat',
      freeMode: 'not-free',
      price: { kind: 'msat', amount: '1000' },
    }) } as ProductOfferOptionV1;

    const grouped = partitionOfferOptionsForDisplayV1([premium, free]);
    expect(grouped.free).toEqual([free]);
    expect(grouped.premium).toEqual([premium]);
  });

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

describe('admission failure wording', () => {
  it('does not mislabel a post-verification access failure as a verification failure', () => {
    expect(publicAdmissionError(new Error('connection closed'))).toBe(
      'Free or Premium access could not be granted on the verified connection. Start a new provider verification attempt.',
    );
  });
});

describe('retained capability labels', () => {
  const binding = {
    providerIdHex: '11'.repeat(32),
    policyDigestHex: '22'.repeat(32),
    scopeIdHex: '33'.repeat(32),
    offerId: 7,
    scheme: 'cashu-bat' as const,
    count: 2,
  };

  it('distinguishes duplicate bindings with different BOLT11 contexts', () => {
    const first = retainedCapabilityLabelV1({
      ...binding,
      acquisitionContext: {
        kind: 'bolt11',
        issuerIdHex: '44'.repeat(32),
        issuerEndpoint: 'https://issuer-a.example',
        network: 'signet',
        expectedPayeePubkeyHex: `02${'55'.repeat(32)}`,
      },
    });
    const second = retainedCapabilityLabelV1({
      ...binding,
      acquisitionContext: {
        kind: 'bolt11',
        issuerIdHex: '66'.repeat(32),
        issuerEndpoint: 'https://issuer-b.example',
        network: 'regtest',
        expectedPayeePubkeyHex: `03${'77'.repeat(32)}`,
      },
    });
    expect(first).toContain('BOLT11 signet');
    expect(first).toContain('issuer 4444444444…44444444');
    expect(first).toContain('origin https://issuer-a.example');
    expect(first).toContain('payee 0255555555…55555555');
    expect(second).toContain('BOLT11 regtest');
    expect(second).toContain('issuer 6666666666…66666666');
    expect(second).toContain('origin https://issuer-b.example');
    expect(second).toContain('payee 0377777777…77777777');
    expect(first).not.toBe(second);
  });

  it('distinguishes contexts that differ only by canonical issuer origin', () => {
    const acquisitionContext = {
      kind: 'bolt11' as const,
      issuerIdHex: '44'.repeat(32),
      issuerEndpoint: 'https://issuer-a.example',
      network: 'signet' as const,
      expectedPayeePubkeyHex: `02${'55'.repeat(32)}`,
    };
    const first = retainedCapabilityLabelV1({ ...binding, acquisitionContext });
    const second = retainedCapabilityLabelV1({
      ...binding,
      acquisitionContext: {
        ...acquisitionContext,
        issuerEndpoint: 'https://issuer-b.example',
      },
    });
    expect(first).not.toBe(second);
    expect(first).toContain('origin https://issuer-a.example');
    expect(second).toContain('origin https://issuer-b.example');
  });

  it('uses the same exact BOLT11 context suffix for encrypted recovery', () => {
    const acquisitionContext = {
      kind: 'bolt11' as const,
      issuerIdHex: '44'.repeat(32),
      issuerEndpoint: 'https://issuer-a.example',
      network: 'signet' as const,
      expectedPayeePubkeyHex: `02${'55'.repeat(32)}`,
    };
    const retained = retainedCapabilityLabelV1({ ...binding, acquisitionContext });
    const recovery = retainedRecoveryLabelV1({
      id: 'recovery-id',
      binding,
      acquisitionContext,
    });
    const suffix = 'BOLT11 signet · issuer 4444444444…44444444 · origin https://issuer-a.example · payee 0255555555…55555555';
    expect(retained).toContain(suffix);
    expect(recovery).toContain(suffix);
  });

  it('marks a contextless legacy direct BOLT11 capability unusable', () => {
    expect(retainedCapabilityLabelV1({
      ...binding,
      scheme: 'bolt11-direct-receipt',
    })).toMatch(/legacy BOLT11 context missing · unusable/);
  });
});

function stagedSnapshot(
  statuses: Array<'offer-selection-required' | 'ready'>,
  selected: boolean[],
): ProductAdmissionSnapshotV1 {
  return {
    phase: 'selecting',
    topology: 'independent-pair',
    allowSharedInfrastructureCorrelationOnce: false,
    homogeneousPairLimits: null,
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
      queryShape: null,
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
        dataset: { kind: 'manifest-root', rootHex: '5a'.repeat(32) },
        limits: {
          maxLogicalInputs: 1,
          maxFrames: 64,
          maxRequestBytes: '1048576',
          maxResponseBytes: '2097152',
          maxWallTimeMs: 30_000,
          maxConcurrentSockets: 1,
          maxHintGroups: 0,
          maxWorkUnits: '10000',
        },
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

  it('allows a Free access choice on both providers without Premium inventory', () => {
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
        dataset: { kind: 'manifest-root', rootHex: '5a'.repeat(32) },
        limits: {
          maxLogicalInputs: 1,
          maxFrames: 64,
          maxRequestBytes: '1048576',
          maxResponseBytes: '2097152',
          maxWallTimeMs: 30_000,
          maxConcurrentSockets: 1,
          maxHintGroups: 0,
          maxWorkUnits: '10000',
        },
        offers: [],
      },
      offer: offer({}),
    }];
    snapshot.legs[1].offers = [{
      ...snapshot.legs[0].offers[0],
      scopeIdHex: snapshot.legs[1].selected!.scopeIdHex,
      offerId: snapshot.legs[1].selected!.offerId,
      scope: {
        ...snapshot.legs[0].offers[0].scope,
        scopeIdHex: snapshot.legs[1].selected!.scopeIdHex,
      },
      offer: offer({ offerId: snapshot.legs[1].selected!.offerId }),
    }];

    expect(pairAuthorizationReadyV1(snapshot)).toBe(true);
  });
});
