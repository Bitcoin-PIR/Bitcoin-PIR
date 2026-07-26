import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../sdk-bridge.js', async () => {
  return {
    requireSdkWasm: () => ({
      initialServicePolicyCheckpointV1: () => new Uint8Array([1, 0]),
      WasmArcPresentationState: { deserialize: () => { throw new Error('unused'); } },
    }),
  };
});

import {
  AmbiguousCapabilitySpendErrorV1,
  ProviderAdmissionSessionV1,
  VerifiedIndependentProviderPairV1,
  VerifiedSingleProviderOfferV1,
  type ServiceAdmissionPortV1,
  type ServiceAdmissionVaultV1,
} from '../service-admission.js';
import type {
  ServiceOfferViewV1,
  ServicePolicyViewV1,
  RetainedServiceRedemptionViewV1,
  WasmAcceptedRetainedServiceRedemptionV1,
  WasmAcceptedServicePolicyV1,
} from '../sdk-bridge.js';

const providerHex = '11'.repeat(32);
const scopeHex = '22'.repeat(32);
const providerId = new Uint8Array(32).fill(0x11);
const policyKey = new Uint8Array(32).fill(0x33);
const secondProviderHex = '12'.repeat(32);
const secondScopeHex = '23'.repeat(32);
const secondProviderId = new Uint8Array(32).fill(0x12);
const secondPolicyKey = new Uint8Array(32).fill(0x34);

function policy(
  offer: ServiceOfferViewV1,
  selectedProviderHex = providerHex,
  selectedScopeHex = scopeHex,
): ServicePolicyViewV1 {
  return {
    providerIdHex: selectedProviderHex,
    policyDigestHex: '44'.repeat(32),
    policyEpoch: '7',
    expiresAtUnix: String(Math.floor(Date.now() / 1000) + 300),
    scopes: [{
      scopeIdHex: selectedScopeHex,
      backend: 'dpf-pir',
      workload: 'dpf-query',
      protocolVersion: 1,
      operationProfile: 2,
      entitlementProfile: 3,
      offers: [offer],
    }],
  };
}

function accepted(view: ServicePolicyViewV1) {
  let acknowledged = false;
  return {
    free: vi.fn(),
    providerIdHex: view.providerIdHex,
    policyDigestHex: view.policyDigestHex,
    policyEpoch: view.policyEpoch,
    expiresAtUnix: view.expiresAtUnix,
    checkpointBytes: () => new Uint8Array([9, 9]),
    acknowledgeCheckpointPersisted: () => { acknowledged = true; },
    validateAuthorizationProof: (_scope: Uint8Array, _offer: number, proof: Uint8Array) => {
      if (!acknowledged) throw new Error('checkpoint not acknowledged');
      if (proof.length === 0 && view.scopes[0].offers[0].authorization !== 'free') {
        throw new Error('empty paid proof');
      }
    },
    importStandardCashuToken: () => new Uint8Array([7, 7]),
    offersJson: () => view,
    beginBolt11Acquisition: () => { throw new Error('unused'); },
  } satisfies WasmAcceptedServicePolicyV1;
}

function retainedAccepted(
  offer: ServiceOfferViewV1,
): WasmAcceptedRetainedServiceRedemptionV1 {
  const view: RetainedServiceRedemptionViewV1 = {
    providerIdHex: providerHex,
    policyDigestHex: '44'.repeat(32),
    scope: {
      scopeIdHex: scopeHex,
      backend: 'dpf-pir',
      workload: 'dpf-query',
      protocolVersion: 1,
      operationProfile: 2,
      entitlementProfile: 3,
      limits: {
        maxLogicalInputs: 1,
        maxFrames: 1,
        maxRequestBytes: '4096',
        maxResponseBytes: '4096',
        maxWallTimeMs: 1000,
        maxConcurrentSockets: 1,
        maxHintGroups: 0,
        maxWorkUnits: '1',
      },
      offers: [],
    },
    offer,
  };
  return {
    free: vi.fn(),
    providerIdHex: providerHex,
    policyDigestHex: view.policyDigestHex,
    scopeIdHex: scopeHex,
    offerId: offer.offerId,
    assertRedemptionReady: vi.fn(),
    validateAuthorizationProof: vi.fn(),
    redemptionJson: () => structuredClone(view),
  };
}

describe('provider admission orchestration', () => {
  let checkpointCommitted: boolean;
  let retiredBinding: unknown;
  let vault: ServiceAdmissionVaultV1;

  beforeEach(() => {
    checkpointCommitted = false;
    retiredBinding = null;
    vault = {
      advancePolicyCheckpoint: async (_provider, initial, advance) => {
        const result = await advance(initial);
        checkpointCommitted = true;
        return result.value;
      },
      takeSingleUseCapability: async (binding, validate) => {
        retiredBinding = binding;
        const payload = new Uint8Array([1, 2, 3]);
        validate?.(payload);
        return { ...binding, payload };
      },
      advanceArcCredential: async () => { throw new Error('unused'); },
    };
  });

  async function independentFreeSession(): Promise<ProviderAdmissionSessionV1> {
    const view = policy({
      offerId: 91,
      acquisition: 'free',
      authorization: 'free',
      freeMode: 'open-best-effort',
      verification: 'provider-local',
      deploymentStatus: 'stable',
      priorityClass: 1,
      price: { kind: 'free' },
      issuerIdHex: '00'.repeat(32),
      keyIdHex: '',
      batVerificationKeyFingerprintHex: '',
      endpoint: '',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 0,
    }, secondProviderHex, secondScopeHex);
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      assertSessionBinding: vi.fn(),
      fetchPolicy: async () => accepted(view),
      authorize: async () => ({
        scopeIdHex: secondScopeHex,
        enforcedProfile: 3,
        expiresInMs: 1000,
        hasHarmonyAttach: false,
      }),
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId: secondProviderId, policySigningKey: secondPolicyKey },
      { backend: 'dpf-pir', workload: 'dpf-query' },
    );
    await session.refreshPolicy();
    return session;
  }

  it('commits the provider checkpoint before free authorization', async () => {
    const view = policy({
      offerId: 1,
      acquisition: 'free',
      authorization: 'free',
      freeMode: 'open-best-effort',
      verification: 'provider-local',
      deploymentStatus: 'stable',
      priorityClass: 1,
      price: { kind: 'free' },
      issuerIdHex: '00'.repeat(32),
      keyIdHex: '',
      batVerificationKeyFingerprintHex: '',
      endpoint: '',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 0,
    });
    const handle = accepted(view);
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      assertSessionBinding: vi.fn(),
      fetchPolicy: async () => handle,
      authorize: async (_policy, _scope, _offer, proof) => {
        expect(checkpointCommitted).toBe(true);
        expect(proof).toHaveLength(0);
        return { scopeIdHex: scopeHex, enforcedProfile: 3, expiresInMs: 1000, hasHarmonyAttach: false };
      },
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      { backend: 'dpf-pir', workload: 'dpf-query' },
    );
    await session.refreshPolicy();
    const second = await independentFreeSession();
    const pair = VerifiedIndependentProviderPairV1.create(
      { session, scopeIdHex: scopeHex, offerId: 1 },
      { session: second, scopeIdHex: secondScopeHex, offerId: 91 },
    );
    await expect(pair.authorize('first')).resolves.toMatchObject({ enforcedProfile: 3 });
    expect((session as unknown as { authorize?: unknown }).authorize).toBeUndefined();
  });

  it('authorizes a genuine single-provider backend without inventing a peer', async () => {
    const view = policy({
      offerId: 2,
      acquisition: 'free',
      authorization: 'free',
      freeMode: 'open-best-effort',
      verification: 'provider-local',
      deploymentStatus: 'stable',
      priorityClass: 1,
      price: { kind: 'free' },
      issuerIdHex: '00'.repeat(32),
      keyIdHex: '',
      batVerificationKeyFingerprintHex: '',
      endpoint: '',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 0,
    });
    const authorize = vi.fn(async () => ({
      scopeIdHex: scopeHex,
      enforcedProfile: 3,
      expiresInMs: 1000,
      hasHarmonyAttach: false,
    }));
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      assertSessionBinding: vi.fn(),
      fetchPolicy: async () => accepted(view),
      authorize,
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      { backend: 'dpf-pir', workload: 'dpf-query' },
    );
    await session.refreshPolicy();
    const selected = VerifiedSingleProviderOfferV1.create({
      session,
      scopeIdHex: scopeHex,
      offerId: 2,
    });

    await expect(selected.authorize()).resolves.toMatchObject({ enforcedProfile: 3 });
    expect(authorize).toHaveBeenCalledTimes(1);
  });

  it('rejects a stale single-provider channel before starting invoice acquisition', async () => {
    const view = policy({
      offerId: 3,
      acquisition: 'bolt11',
      authorization: 'bolt11-direct-receipt',
      freeMode: 'not-free',
      verification: 'provider-local',
      deploymentStatus: 'stable',
      priorityClass: 1,
      price: { kind: 'msat', amount: '1000' },
      issuerIdHex: '59'.repeat(32),
      keyIdHex: '6a'.repeat(16),
      batVerificationKeyFingerprintHex: '',
      endpoint: 'https://issuer-e.invalid',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 1,
    });
    const assertSessionBinding = vi.fn(() => {
      throw new Error('accepted policy belongs to a different secure-channel session');
    });
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      assertSessionBinding,
      fetchPolicy: async () => accepted(view),
      authorize: async () => { throw new Error('unused'); },
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      { backend: 'dpf-pir', workload: 'dpf-query' },
    );
    await session.refreshPolicy();
    const selected = VerifiedSingleProviderOfferV1.create({
      session,
      scopeIdHex: scopeHex,
      offerId: 3,
    });

    await expect(selected.startBolt11Acquisition({
      vault: {} as never,
      network: 'bitcoin',
      expectedPayeePubkey: new Uint8Array(33).fill(2),
    })).rejects.toThrow(/different secure-channel session/);
    expect(assertSessionBinding).toHaveBeenCalledTimes(1);
  });

  it('imports standard Cashu only through a frozen offer and stores its exact policy binding', async () => {
    const view = policy({
      offerId: 4,
      acquisition: 'cashu-ecash',
      authorization: 'cashu-ecash',
      freeMode: 'not-free',
      verification: 'standard-cashu-mint-online',
      deploymentStatus: 'stable',
      priorityClass: 1,
      price: { kind: 'cashu', amount: '1', unit: 'sat' },
      issuerIdHex: '59'.repeat(32),
      keyIdHex: '6a'.repeat(32),
      batVerificationKeyFingerprintHex: '',
      endpoint: 'https://mint.example',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 3,
    });
    const handle = accepted(view);
    const importToken = vi.fn(() => new Uint8Array([7, 7]));
    handle.importStandardCashuToken = importToken;
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      assertSessionBinding: vi.fn(),
      fetchPolicy: async () => handle,
      authorize: async () => { throw new Error('unused'); },
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      { backend: 'dpf-pir', workload: 'dpf-query' },
    );
    await session.refreshPolicy();
    const selected = VerifiedSingleProviderOfferV1.create({
      session,
      scopeIdHex: scopeHex,
      offerId: 4,
    });
    const putCapability = vi.fn(async () => 'vault-record-id');

    await expect(selected.importStandardCashuToken({
      vault: { putCapability } as never,
      serializedToken: 'cashuBfixture',
    })).resolves.toBe('vault-record-id');
    expect(importToken).toHaveBeenCalledOnce();
    expect(putCapability).toHaveBeenCalledWith({
      providerIdHex: providerHex,
      policyDigestHex: '44'.repeat(32),
      scopeIdHex: scopeHex,
      offerId: 4,
      scheme: 'cashu-ecash',
      payload: new Uint8Array([7, 7]),
    });
    expect((session as unknown as { importStandardCashuToken?: unknown })
      .importStandardCashuToken).toBeUndefined();
  });

  it('retires an exact provider-bound paid proof and never retries ambiguity', async () => {
    const view = policy({
      offerId: 7,
      acquisition: 'bolt11',
      authorization: 'bolt11-direct-receipt',
      freeMode: 'not-free',
      verification: 'provider-local',
      deploymentStatus: 'stable',
      priorityClass: 1,
      price: { kind: 'msat', amount: '1000' },
      issuerIdHex: '55'.repeat(32),
      keyIdHex: '66'.repeat(16),
      batVerificationKeyFingerprintHex: '',
      endpoint: 'https://issuer.invalid',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 1,
    });
    const authorize = vi.fn(async () => { throw new Error('connection lost'); });
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      assertSessionBinding: vi.fn(),
      fetchPolicy: async () => accepted(view),
      authorize,
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      { backend: 'dpf-pir', workload: 'dpf-query' },
    );
    await session.refreshPolicy();
    const second = await independentFreeSession();
    const pair = VerifiedIndependentProviderPairV1.create(
      { session, scopeIdHex: scopeHex, offerId: 7 },
      { session: second, scopeIdHex: secondScopeHex, offerId: 91 },
    );
    await expect(pair.authorize('first')).rejects.toBeInstanceOf(
      AmbiguousCapabilitySpendErrorV1,
    );
    expect(authorize).toHaveBeenCalledTimes(1);
    expect(retiredBinding).toEqual({
      providerIdHex: providerHex,
      policyDigestHex: '44'.repeat(32),
      scopeIdHex: scopeHex,
      offerId: 7,
      scheme: 'bolt11-direct-receipt',
    });
  });

  it('rejects a stale secure-channel session before retiring a paid proof', async () => {
    const view = policy({
      offerId: 9,
      acquisition: 'bolt11',
      authorization: 'bolt11-direct-receipt',
      freeMode: 'not-free',
      verification: 'provider-local',
      deploymentStatus: 'stable',
      priorityClass: 1,
      price: { kind: 'msat', amount: '1000' },
      issuerIdHex: '58'.repeat(32),
      keyIdHex: '69'.repeat(16),
      batVerificationKeyFingerprintHex: '',
      endpoint: 'https://issuer-d.invalid',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 1,
    });
    const take = vi.spyOn(vault, 'takeSingleUseCapability');
    const authorize = vi.fn();
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      assertSessionBinding: vi.fn(() => {
        throw new Error('accepted policy belongs to a different secure-channel session');
      }),
      fetchPolicy: async () => accepted(view),
      authorize,
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const first = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      { backend: 'dpf-pir', workload: 'dpf-query' },
    );
    await first.refreshPolicy();
    const second = await independentFreeSession();
    const pair = VerifiedIndependentProviderPairV1.create(
      { session: first, scopeIdHex: scopeHex, offerId: 9 },
      { session: second, scopeIdHex: secondScopeHex, offerId: 91 },
    );

    await expect(pair.authorize('first')).rejects.toThrow(/different secure-channel session/);
    expect(take).not.toHaveBeenCalled();
    expect(authorize).not.toHaveBeenCalled();
  });

  it('invalidates a verified pair after either provider policy is refreshed', async () => {
    const view = policy({
      offerId: 5,
      acquisition: 'free',
      authorization: 'free',
      freeMode: 'open-best-effort',
      verification: 'provider-local',
      deploymentStatus: 'stable',
      priorityClass: 1,
      price: { kind: 'free' },
      issuerIdHex: '00'.repeat(32),
      keyIdHex: '',
      batVerificationKeyFingerprintHex: '',
      endpoint: '',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 0,
    });
    const authorize = vi.fn(async () => ({
      scopeIdHex: scopeHex,
      enforcedProfile: 3,
      expiresInMs: 1000,
      hasHarmonyAttach: false,
    }));
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      assertSessionBinding: vi.fn(),
      fetchPolicy: async () => accepted(view),
      authorize,
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const first = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      { backend: 'dpf-pir', workload: 'dpf-query' },
    );
    await first.refreshPolicy();
    const second = await independentFreeSession();
    const pair = VerifiedIndependentProviderPairV1.create(
      { session: first, scopeIdHex: scopeHex, offerId: 5 },
      { session: second, scopeIdHex: secondScopeHex, offerId: 91 },
    );

    await first.refreshPolicy();
    await expect(pair.authorize('first')).rejects.toThrow(/policy changed/);
    expect(authorize).not.toHaveBeenCalled();
  });

  it('prevents refresh or close from racing a burn-before-send authorization', async () => {
    const view = policy({
      offerId: 8,
      acquisition: 'bolt11',
      authorization: 'bolt11-direct-receipt',
      freeMode: 'not-free',
      verification: 'provider-local',
      deploymentStatus: 'stable',
      priorityClass: 1,
      price: { kind: 'msat', amount: '1000' },
      issuerIdHex: '57'.repeat(32),
      keyIdHex: '68'.repeat(16),
      batVerificationKeyFingerprintHex: '',
      endpoint: 'https://issuer-c.invalid',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 1,
    });
    let releaseRetirement!: () => void;
    let markRetirementEntered!: () => void;
    const retirementGate = new Promise<void>((resolve) => { releaseRetirement = resolve; });
    const retirementEntered = new Promise<void>((resolve) => { markRetirementEntered = resolve; });
    vault.takeSingleUseCapability = async (binding, validate) => {
      const payload = new Uint8Array([1, 2, 3]);
      validate?.(payload);
      markRetirementEntered();
      await retirementGate;
      return { ...binding, payload };
    };
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      assertSessionBinding: vi.fn(),
      fetchPolicy: async () => accepted(view),
      authorize: async () => ({
        scopeIdHex: scopeHex,
        enforcedProfile: 3,
        expiresInMs: 1000,
        hasHarmonyAttach: false,
      }),
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const first = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      { backend: 'dpf-pir', workload: 'dpf-query' },
    );
    await first.refreshPolicy();
    const second = await independentFreeSession();
    const pair = VerifiedIndependentProviderPairV1.create(
      { session: first, scopeIdHex: scopeHex, offerId: 8 },
      { session: second, scopeIdHex: secondScopeHex, offerId: 91 },
    );

    const authorization = pair.authorize('first');
    await retirementEntered;
    await expect(first.refreshPolicy()).rejects.toThrow(/already in flight/);
    expect(() => first.close()).toThrow(/during authorize/);
    releaseRetirement();
    await expect(authorization).resolves.toMatchObject({ enforcedProfile: 3 });
  });

  it('redeems one retained capability only against its exact historical selector', async () => {
    const offer: ServiceOfferViewV1 = {
      offerId: 17,
      acquisition: 'bolt11',
      authorization: 'cashu-bat',
      freeMode: 'not-free',
      verification: 'provider-local',
      deploymentStatus: 'stable',
      priorityClass: 1,
      price: { kind: 'msat', amount: '1000' },
      issuerIdHex: '57'.repeat(32),
      keyIdHex: '68'.repeat(16),
      batVerificationKeyFingerprintHex: '78'.repeat(32),
      endpoint: 'https://issuer.invalid',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 0,
    };
    const retained = retainedAccepted(offer);
    const authorizeRetained = vi.fn(async () => ({
      scopeIdHex: scopeHex,
      enforcedProfile: 3,
      expiresInMs: 1000,
      hasHarmonyAttach: false,
    }));
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      fetchPolicy: async () => { throw new Error('current policy must not be fetched'); },
      fetchRetainedRedemption: async () => retained,
      assertSessionBinding: vi.fn(),
      assertRetainedSessionBinding: vi.fn(),
      authorize: async () => { throw new Error('current authorization must not be used'); },
      authorizeRetained,
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      { backend: 'dpf-pir', workload: 'dpf-query' },
    );
    const binding = {
      providerIdHex: providerHex,
      policyDigestHex: '44'.repeat(32),
      scopeIdHex: scopeHex,
      offerId: 17,
      scheme: 'cashu-bat' as const,
    };

    await expect(session.inspectRetainedCapability(binding)).resolves.toMatchObject({
      policyDigestHex: binding.policyDigestHex,
      offer: { authorization: 'cashu-bat' },
    });
    await expect(session.authorizeRetainedCapability(binding)).resolves.toMatchObject({
      scopeIdHex: scopeHex,
      enforcedProfile: 3,
    });
    expect(retiredBinding).toEqual(binding);
    expect(authorizeRetained).toHaveBeenCalledOnce();
  });

  it('rejects a retained scheme mismatch before retiring proof bytes', async () => {
    const offer: ServiceOfferViewV1 = {
      offerId: 18,
      acquisition: 'bolt11',
      authorization: 'bolt11-direct-receipt',
      freeMode: 'not-free',
      verification: 'provider-local',
      deploymentStatus: 'stable',
      priorityClass: 1,
      price: { kind: 'msat', amount: '1000' },
      issuerIdHex: '58'.repeat(32),
      keyIdHex: '69'.repeat(16),
      batVerificationKeyFingerprintHex: '',
      endpoint: 'https://issuer.invalid',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 0,
    };
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      fetchPolicy: async () => { throw new Error('unused'); },
      fetchRetainedRedemption: async () => retainedAccepted(offer),
      assertSessionBinding: vi.fn(),
      assertRetainedSessionBinding: vi.fn(),
      authorize: async () => { throw new Error('unused'); },
      authorizeRetained: async () => { throw new Error('must not send'); },
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      { backend: 'dpf-pir', workload: 'dpf-query' },
    );
    await expect(session.authorizeRetainedCapability({
      providerIdHex: providerHex,
      policyDigestHex: '44'.repeat(32),
      scopeIdHex: scopeHex,
      offerId: 18,
      scheme: 'cashu-bat',
    })).rejects.toThrow(/does not match capability scheme/);
    expect(retiredBinding).toBeNull();
  });
});
