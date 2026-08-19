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
  VerifiedIndependentProviderBatV2PairV2,
  VerifiedIndependentProviderPairV1,
  VerifiedSingleProviderOfferV1,
  VerifiedSingleProviderRetainedOfferV1,
  type ServiceAdmissionPortV1,
  type ServiceAdmissionTargetV1,
  type ServiceAdmissionVaultV1,
  type BatV2AdmissionVaultV2,
} from '../service-admission.js';
import type { AdmissionCapabilityV1 } from '../admission-vault.js';
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
const manifestRootHex = '5a'.repeat(32);
const limits = {
  maxLogicalInputs: 4,
  maxFrames: 64,
  maxRequestBytes: '1048576',
  maxResponseBytes: '2097152',
  maxWallTimeMs: 30_000,
  maxConcurrentSockets: 1,
  maxHintGroups: 0,
  maxWorkUnits: '10000',
};
const DPF_TARGET: ServiceAdmissionTargetV1 = {
  backend: 'dpf-pir',
  workload: 'dpf-query',
  protocolVersion: 1,
  expectedDatasetManifestRootHex: manifestRootHex,
};

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
      dataset: { kind: 'manifest-root', rootHex: manifestRootHex },
      limits: { ...limits },
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
    verifyBatV2Redemption: (scopeId: Uint8Array, offerId: number) => {
      const selected = view.scopes[0].offers[0];
      if (selected.authorization !== 'cashu-bat-v2'
          || offerId !== selected.offerId
          || Buffer.from(scopeId).toString('hex') !== view.scopes[0].scopeIdHex) {
        throw new Error('wrong BAT V2 member');
      }
      return {
        free: vi.fn(),
        providerIdHex: view.providerIdHex,
        policyDigestHex: view.policyDigestHex,
        scopeIdHex: view.scopes[0].scopeIdHex,
        offerId,
        classIdHex: selected.keyIdHex,
        classBindingJson: () => ({
          issuerIdHex: selected.issuerIdHex,
          classIdHex: selected.keyIdHex,
          classDigestHex: '73'.repeat(32),
          classKeyEpoch: '4',
          batKeyIdHex: '74'.repeat(32),
        }),
        assertRedemptionReady: vi.fn(),
      };
    },
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
      dataset: { kind: 'manifest-root', rootHex: manifestRootHex },
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

function batV2Offer(): ServiceOfferViewV1 {
  return {
    offerId: 101,
    acquisition: 'bolt11',
    authorization: 'cashu-bat-v2',
    freeMode: 'not-free',
    verification: 'shared-issuer-online',
    deploymentStatus: 'stable',
    priorityClass: 1,
    price: { kind: 'msat', amount: '1000' },
    issuerIdHex: '71'.repeat(32),
    keyIdHex: '72'.repeat(32),
    batVerificationKeyFingerprintHex: '',
    arcVerificationKeyFingerprintHex: '',
    endpoint: 'https://shared-issuer.example',
    credentialCount: 2,
    credentialPresentationLimit: 1,
    privacyLeakageBits: 0,
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
      arcVerificationKeyFingerprintHex: '',
      endpoint: '',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 0,
    }, secondProviderHex, secondScopeHex);
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      providerEndpoint: () => 'wss://provider-b.example',
      operatorSigningKey: () => secondProviderId.slice(),
      assertSessionBinding: vi.fn(),
      captureReadinessGuard: () => vi.fn(),
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
      DPF_TARGET,
    );
    await session.refreshPolicy();
    return session;
  }

  function sessionForOffer(offer: ServiceOfferViewV1): ProviderAdmissionSessionV1 {
    return sessionForPolicyView(policy(offer));
  }

  function sessionForPolicyView(
    view: ServicePolicyViewV1,
    target: ServiceAdmissionTargetV1 = DPF_TARGET,
  ): ProviderAdmissionSessionV1 {
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      providerEndpoint: () => 'wss://provider-a.example',
      operatorSigningKey: () => providerId.slice(),
      assertSessionBinding: vi.fn(),
      captureReadinessGuard: () => vi.fn(),
      fetchPolicy: async () => accepted(view),
      authorize: async () => { throw new Error('unused'); },
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    return new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      target,
    );
  }

  function arcOffer(fingerprint = '79'.repeat(32)): ServiceOfferViewV1 {
    return {
      offerId: 92,
      acquisition: 'bolt11',
      authorization: 'arc-experimental',
      freeMode: 'not-free',
      verification: 'provider-local',
      deploymentStatus: 'experimental',
      priorityClass: 1,
      price: { kind: 'msat', amount: '1000' },
      issuerIdHex: '57'.repeat(32),
      keyIdHex: '68'.repeat(16),
      batVerificationKeyFingerprintHex: '',
      arcVerificationKeyFingerprintHex: fingerprint,
      endpoint: 'https://issuer.invalid',
      credentialCount: 1,
      credentialPresentationLimit: 10,
      privacyLeakageBits: 0,
    };
  }

  it('strictly accepts only a non-zero lowercase ARC raw-key fingerprint', async () => {
    await expect(sessionForOffer(arcOffer()).refreshPolicy()).resolves.toMatchObject({
      scopes: [{ offers: [{ arcVerificationKeyFingerprintHex: '79'.repeat(32) }] }],
    });
    await expect(sessionForOffer(arcOffer('')).refreshPolicy()).rejects.toThrow(/lowercase/);
    await expect(sessionForOffer(arcOffer('ab'.repeat(32).toUpperCase())).refreshPolicy())
      .rejects.toThrow(/lowercase/);
    await expect(sessionForOffer(arcOffer('00'.repeat(32))).refreshPolicy())
      .rejects.toThrow(/lowercase/);
  });

  it('exposes only the unique scope for the exact protocol and verified manifest root', async () => {
    const view = policy(arcOffer());
    view.scopes.push({
      ...structuredClone(view.scopes[0]),
      scopeIdHex: '24'.repeat(32),
      dataset: { kind: 'manifest-root', rootHex: '6a'.repeat(32) },
    });
    await expect(sessionForPolicyView(view).refreshPolicy()).resolves.toMatchObject({
      scopes: [{ scopeIdHex: scopeHex, dataset: { rootHex: manifestRootHex } }],
    });

    const ambiguous = structuredClone(view);
    ambiguous.scopes[1].dataset = { kind: 'manifest-root', rootHex: manifestRootHex };
    ambiguous.scopes[1].entitlementProfile = 9;
    await expect(sessionForPolicyView(ambiguous).refreshPolicy())
      .rejects.toThrow(/exactly one scope/);
    await expect(sessionForPolicyView(ambiguous, {
      ...DPF_TARGET,
      entitlementProfile: 3,
    }).refreshPolicy()).rejects.toThrow(/exactly one scope/);

    const wrongProtocol = policy(arcOffer());
    wrongProtocol.scopes[0].protocolVersion = 2;
    await expect(sessionForPolicyView(wrongProtocol).refreshPolicy())
      .rejects.toThrow(/exactly one scope/);
  });

  it('rejects malformed live signed limits before any offer can be selected', async () => {
    const view = policy(arcOffer());
    view.scopes[0].limits.maxRequestBytes = '01';
    await expect(sessionForPolicyView(view).refreshPolicy())
      .rejects.toThrow(/canonical decimal u64/);
  });

  it('rejects an ARC raw-key fingerprint on a non-ARC policy offer', async () => {
    const polluted = {
      ...arcOffer(),
      authorization: 'bolt11-direct-receipt' as const,
      deploymentStatus: 'stable' as const,
      credentialPresentationLimit: 1,
    };
    await expect(sessionForOffer(polluted).refreshPolicy()).rejects.toThrow(/non-ARC/);
  });

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
      arcVerificationKeyFingerprintHex: '',
      endpoint: '',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 0,
    });
    const handle = accepted(view);
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      providerEndpoint: () => 'wss://provider-a.example',
      operatorSigningKey: () => providerId.slice(),
      assertSessionBinding: vi.fn(),
      captureReadinessGuard: () => vi.fn(),
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
      DPF_TARGET,
    );
    await session.refreshPolicy();
    const second = await independentFreeSession();
    const pair = VerifiedIndependentProviderPairV1.create(
      {
        session, scopeIdHex: scopeHex, offerId: 1,
        providerEndpoint: 'wss://provider-a.example/v1',
      },
      {
        session: second, scopeIdHex: secondScopeHex, offerId: 91,
        providerEndpoint: 'wss://provider-b.example/v1',
      },
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
      arcVerificationKeyFingerprintHex: '',
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
      providerEndpoint: () => 'wss://provider-a.example',
      operatorSigningKey: () => providerId.slice(),
      assertSessionBinding: vi.fn(),
      captureReadinessGuard: () => vi.fn(),
      fetchPolicy: async () => accepted(view),
      authorize,
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      DPF_TARGET,
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

  it('binds a single-provider BOLT11 capability retirement to its frozen context', async () => {
    const offer: ServiceOfferViewV1 = {
      offerId: 18,
      acquisition: 'bolt11',
      authorization: 'cashu-bat',
      freeMode: 'not-free',
      verification: 'provider-local',
      deploymentStatus: 'stable',
      priorityClass: 1,
      price: { kind: 'msat', amount: '1000' },
      issuerIdHex: '58'.repeat(32),
      keyIdHex: '69'.repeat(32),
      batVerificationKeyFingerprintHex: '79'.repeat(32),
      arcVerificationKeyFingerprintHex: '',
      endpoint: 'https://issuer-single.invalid',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 1,
    };
    const payee = new Uint8Array([2, ...new Uint8Array(32).fill(6)]);
    const expectedContext = {
      kind: 'bolt11' as const,
      issuerEndpoint: offer.endpoint,
      issuerIdHex: offer.issuerIdHex,
      network: 'bitcoin' as const,
      expectedPayeePubkeyHex: Array.from(
        payee,
        (byte) => byte.toString(16).padStart(2, '0'),
      ).join(''),
    };
    vault.takeSingleUseCapability = async (binding, validate, context) => {
      expect(context).toEqual(expectedContext);
      const payload = new Uint8Array([1, 2, 3]);
      validate?.(payload);
      return { ...binding, payload };
    };
    const authorize = vi.fn(async () => ({
      scopeIdHex: scopeHex,
      enforcedProfile: 3,
      expiresInMs: 1000,
      hasHarmonyAttach: false,
    }));
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      assertSessionBinding: vi.fn(),
      captureReadinessGuard: () => vi.fn(),
      fetchPolicy: async () => accepted(policy(offer)),
      authorize,
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      DPF_TARGET,
    );
    await session.refreshPolicy();
    expect(() => VerifiedSingleProviderOfferV1.create({
      session,
      scopeIdHex: scopeHex,
      offerId: offer.offerId,
    })).toThrow(/trusted compressed Lightning payee/);
    const selected = VerifiedSingleProviderOfferV1.create({
      session,
      scopeIdHex: scopeHex,
      offerId: offer.offerId,
      lightningNetwork: 'bitcoin',
      expectedLightningPayeePubkey: payee,
    });

    await expect(selected.authorize()).resolves.toMatchObject({ enforcedProfile: 3 });
    expect(authorize).toHaveBeenCalledOnce();
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
      arcVerificationKeyFingerprintHex: '',
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
      captureReadinessGuard: () => vi.fn(),
      fetchPolicy: async () => accepted(view),
      authorize: async () => { throw new Error('unused'); },
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      DPF_TARGET,
    );
    await session.refreshPolicy();
    const payee = new Uint8Array([2, ...new Uint8Array(32).fill(2)]);
    const selected = VerifiedSingleProviderOfferV1.create({
      session,
      scopeIdHex: scopeHex,
      offerId: 3,
      lightningNetwork: 'bitcoin',
      expectedLightningPayeePubkey: payee,
    });

    await expect(selected.startBolt11Acquisition({
      vault: {} as never,
      network: 'bitcoin',
      expectedPayeePubkey: payee,
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
      arcVerificationKeyFingerprintHex: '',
      endpoint: 'https://mint.example',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 3,
    });
    const handle = accepted(view);
    const importedPayloads: Uint8Array[] = [];
    const importToken = vi.fn(() => {
      const payload = new Uint8Array([7, 7]);
      importedPayloads.push(payload);
      return payload;
    });
    handle.importStandardCashuToken = importToken;
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      assertSessionBinding: vi.fn(),
      captureReadinessGuard: () => vi.fn(),
      fetchPolicy: async () => handle,
      authorize: async () => { throw new Error('unused'); },
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      DPF_TARGET,
    );
    await session.refreshPolicy();
    const selected = VerifiedSingleProviderOfferV1.create({
      session,
      scopeIdHex: scopeHex,
      offerId: 4,
    });
    let releasePut!: () => void;
    let markPutEntered!: () => void;
    const putGate = new Promise<void>((resolve) => { releasePut = resolve; });
    const putEntered = new Promise<void>((resolve) => { markPutEntered = resolve; });
    let persistedCapability: Record<string, unknown> | undefined;
    const putCapability = vi.fn(async (capability: AdmissionCapabilityV1) => {
      expect(capability.payload).toEqual(new Uint8Array([7, 7]));
      markPutEntered();
      await putGate;
      expect(capability.payload).toEqual(new Uint8Array([7, 7]));
      persistedCapability = { ...capability, payload: capability.payload.slice() };
      return 'vault-record-id';
    });

    const pendingImport = selected.importStandardCashuToken({
      vault: { putCapability } as never,
      serializedToken: 'cashuBfixture',
    });
    await putEntered;
    expect(importedPayloads[0]).toEqual(new Uint8Array([7, 7]));
    await expect(selected.importStandardCashuToken({
      vault: { putCapability } as never,
      serializedToken: 'cashuBfixture',
    })).rejects.toThrow(/already in flight/);
    releasePut();
    await expect(pendingImport).resolves.toBe('vault-record-id');
    expect(importToken).toHaveBeenCalledOnce();
    expect(persistedCapability).toEqual({
      providerIdHex: providerHex,
      policyDigestHex: '44'.repeat(32),
      scopeIdHex: scopeHex,
      offerId: 4,
      scheme: 'cashu-ecash',
      payload: new Uint8Array([7, 7]),
    });
    expect(importedPayloads[0]).toEqual(new Uint8Array(2));

    const rejectCapability = vi.fn(async (capability: AdmissionCapabilityV1) => {
      expect(capability.payload).toEqual(new Uint8Array([7, 7]));
      await Promise.resolve();
      expect(capability.payload).toEqual(new Uint8Array([7, 7]));
      throw new Error('vault write failed');
    });
    await expect(selected.importStandardCashuToken({
      vault: { putCapability: rejectCapability } as never,
      serializedToken: 'cashuBfixture',
    })).rejects.toThrow(/vault write failed/);
    expect(importedPayloads[1]).toEqual(new Uint8Array(2));
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
      arcVerificationKeyFingerprintHex: '',
      endpoint: 'https://issuer.invalid',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 1,
    });
    let retiredProof: Uint8Array | undefined;
    const authorize = vi.fn(async (
      _policy: WasmAcceptedServicePolicyV1,
      _scope: Uint8Array,
      _offer: number,
      proof: Uint8Array,
    ) => {
      retiredProof = proof;
      expect(proof).toEqual(new Uint8Array([1, 2, 3]));
      throw new Error('connection lost');
    });
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      providerEndpoint: () => 'wss://provider-a.example',
      operatorSigningKey: () => providerId.slice(),
      assertSessionBinding: vi.fn(),
      captureReadinessGuard: () => vi.fn(),
      fetchPolicy: async () => accepted(view),
      authorize,
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      DPF_TARGET,
    );
    await session.refreshPolicy();
    const second = await independentFreeSession();
    const pair = VerifiedIndependentProviderPairV1.create(
      {
        session, scopeIdHex: scopeHex, offerId: 7,
        providerEndpoint: 'wss://provider-a.example/v1',
        lightningNetwork: 'bitcoin',
        expectedLightningPayeePubkey: new Uint8Array([2, ...new Uint8Array(32).fill(1)]),
      },
      {
        session: second, scopeIdHex: secondScopeHex, offerId: 91,
        providerEndpoint: 'wss://provider-b.example/v1',
      },
    );
    expect(() => pair.startBolt11Acquisition('first', {
      vault: {} as never,
      network: 'bitcoin',
      expectedPayeePubkey: new Uint8Array([2, ...new Uint8Array(32).fill(2)]),
    })).toThrow(/differs from the independently frozen provider context/);
    await expect(pair.authorize('first')).rejects.toBeInstanceOf(
      AmbiguousCapabilitySpendErrorV1,
    );
    expect(authorize).toHaveBeenCalledTimes(1);
    expect(retiredProof).toEqual(new Uint8Array(3));
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
      arcVerificationKeyFingerprintHex: '',
      endpoint: 'https://issuer-d.invalid',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 1,
    });
    const take = vi.spyOn(vault, 'takeSingleUseCapability');
    const authorize = vi.fn();
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      providerEndpoint: () => 'wss://provider-a.example',
      operatorSigningKey: () => providerId.slice(),
      assertSessionBinding: vi.fn(() => {
        throw new Error('accepted policy belongs to a different secure-channel session');
      }),
      captureReadinessGuard: () => vi.fn(),
      fetchPolicy: async () => accepted(view),
      authorize,
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const first = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      DPF_TARGET,
    );
    await first.refreshPolicy();
    const second = await independentFreeSession();
    const pair = VerifiedIndependentProviderPairV1.create(
      {
        session: first, scopeIdHex: scopeHex, offerId: 9,
        providerEndpoint: 'wss://provider-a.example/v1',
        lightningNetwork: 'bitcoin',
        expectedLightningPayeePubkey: new Uint8Array([2, ...new Uint8Array(32).fill(1)]),
      },
      {
        session: second, scopeIdHex: secondScopeHex, offerId: 91,
        providerEndpoint: 'wss://provider-b.example/v1',
      },
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
      arcVerificationKeyFingerprintHex: '',
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
      providerEndpoint: () => 'wss://provider-a.example',
      operatorSigningKey: () => providerId.slice(),
      assertSessionBinding: vi.fn(),
      captureReadinessGuard: () => vi.fn(),
      fetchPolicy: async () => accepted(view),
      authorize,
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const first = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      DPF_TARGET,
    );
    await first.refreshPolicy();
    const second = await independentFreeSession();
    const pair = VerifiedIndependentProviderPairV1.create(
      {
        session: first, scopeIdHex: scopeHex, offerId: 5,
        providerEndpoint: 'wss://provider-a.example/v1',
      },
      {
        session: second, scopeIdHex: secondScopeHex, offerId: 91,
        providerEndpoint: 'wss://provider-b.example/v1',
      },
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
      arcVerificationKeyFingerprintHex: '',
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
      providerEndpoint: () => 'wss://provider-a.example',
      operatorSigningKey: () => providerId.slice(),
      assertSessionBinding: vi.fn(),
      captureReadinessGuard: () => vi.fn(),
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
      DPF_TARGET,
    );
    await first.refreshPolicy();
    const second = await independentFreeSession();
    const pair = VerifiedIndependentProviderPairV1.create(
      {
        session: first, scopeIdHex: scopeHex, offerId: 8,
        providerEndpoint: 'wss://provider-a.example/v1',
        lightningNetwork: 'bitcoin',
        expectedLightningPayeePubkey: new Uint8Array([2, ...new Uint8Array(32).fill(1)]),
      },
      {
        session: second, scopeIdHex: secondScopeHex, offerId: 91,
        providerEndpoint: 'wss://provider-b.example/v1',
      },
    );

    const authorization = pair.authorize('first');
    await retirementEntered;
    await expect(first.refreshPolicy()).rejects.toThrow(/already in flight/);
    expect(() => first.close()).toThrow(/during authorize/);
    releaseRetirement();
    await expect(authorization).resolves.toMatchObject({ enforcedProfile: 3 });
  });

  it('rejects retained ARC metadata without its canonical raw-key fingerprint', async () => {
    const offer = arcOffer('');
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      fetchPolicy: async () => { throw new Error('unused'); },
      fetchRetainedRedemption: async () => retainedAccepted(offer),
      assertSessionBinding: vi.fn(),
      captureReadinessGuard: () => vi.fn(),
      assertRetainedSessionBinding: vi.fn(),
      authorize: async () => { throw new Error('unused'); },
      authorizeRetained: async () => { throw new Error('must not send'); },
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      DPF_TARGET,
    );
    await expect(session.inspectRetainedCapability({
      providerIdHex: providerHex,
      policyDigestHex: '44'.repeat(32),
      scopeIdHex: scopeHex,
      offerId: offer.offerId,
      scheme: 'arc-experimental',
    })).rejects.toThrow(/lowercase/);
    expect(retiredBinding).toBeNull();
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
      arcVerificationKeyFingerprintHex: '',
      endpoint: 'https://issuer.invalid',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 0,
    };
    const retained = retainedAccepted(offer);
    let retiredProof: Uint8Array | undefined;
    const authorizeRetained = vi.fn(async (
      _policy: WasmAcceptedRetainedServiceRedemptionV1,
      proof: Uint8Array,
    ) => {
      retiredProof = proof;
      expect(proof).toEqual(new Uint8Array([1, 2, 3]));
      return {
        scopeIdHex: scopeHex,
        enforcedProfile: 3,
        expiresInMs: 1000,
        hasHarmonyAttach: false,
      };
    });
    const port: ServiceAdmissionPortV1 = {
      assertTrustAnchor: vi.fn(),
      fetchPolicy: async () => { throw new Error('current policy must not be fetched'); },
      fetchRetainedRedemption: async () => retained,
      assertSessionBinding: vi.fn(),
      captureReadinessGuard: () => vi.fn(),
      assertRetainedSessionBinding: vi.fn(),
      authorize: async () => { throw new Error('current authorization must not be used'); },
      authorizeRetained,
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      DPF_TARGET,
    );
    const binding = {
      providerIdHex: providerHex,
      policyDigestHex: '44'.repeat(32),
      scopeIdHex: scopeHex,
      offerId: 17,
      scheme: 'cashu-bat' as const,
    };

    const inspected = await session.inspectRetainedCapability(binding);
    expect(inspected).toMatchObject({
      policyDigestHex: binding.policyDigestHex,
      offer: { authorization: 'cashu-bat' },
    });
    const payee = new Uint8Array([2, ...new Uint8Array(32).fill(7)]);
    const acquisitionContext = {
      kind: 'bolt11' as const,
      issuerEndpoint: offer.endpoint,
      issuerIdHex: offer.issuerIdHex,
      network: 'bitcoin' as const,
      expectedPayeePubkeyHex: Array.from(
        payee,
        (byte) => byte.toString(16).padStart(2, '0'),
      ).join(''),
    };
    vault.takeSingleUseCapability = async (selectedBinding, validate, expectedContext) => {
      retiredBinding = selectedBinding;
      expect(expectedContext).toEqual(acquisitionContext);
      const payload = new Uint8Array([1, 2, 3]);
      validate?.(payload);
      return { ...selectedBinding, payload };
    };
    expect(() => VerifiedSingleProviderRetainedOfferV1.create({
      session,
      binding,
      redemption: inspected,
      lightningNetwork: 'bitcoin',
      expectedLightningPayeePubkey: payee,
    })).toThrow(/lacks authenticated historical payment context/);
    const selected = VerifiedSingleProviderRetainedOfferV1.create({
      session,
      binding,
      redemption: inspected,
      lightningNetwork: 'bitcoin',
      expectedLightningPayeePubkey: payee,
      acquisitionContext,
    });
    await expect(selected.authorize()).resolves.toMatchObject({
      scopeIdHex: scopeHex,
      enforcedProfile: 3,
    });
    expect(retiredBinding).toEqual(binding);
    expect(authorizeRetained).toHaveBeenCalledOnce();
    expect(retiredProof).toEqual(new Uint8Array(3));
  });

  it('freezes mixed retained pair order and exact historical BOLT11 context', async () => {
    const makeRetained = (
      selectedProviderHex: string,
      selectedProviderId: Uint8Array,
      selectedPolicyKey: Uint8Array,
      selectedScopeHex: string,
      providerEndpoint: string,
      issuerByte: string,
      payeeFill: number,
      offerId: number,
    ) => {
      const offer: ServiceOfferViewV1 = {
        offerId,
        acquisition: 'bolt11',
        authorization: 'cashu-bat',
        freeMode: 'not-free',
        verification: 'provider-local',
        deploymentStatus: 'stable',
        priorityClass: 1,
        price: { kind: 'msat', amount: '1000' },
        issuerIdHex: issuerByte.repeat(32),
        keyIdHex: issuerByte.repeat(16),
        batVerificationKeyFingerprintHex: issuerByte.repeat(32),
        arcVerificationKeyFingerprintHex: '',
        endpoint: `https://issuer-${issuerByte}.example`,
        credentialCount: 1,
        credentialPresentationLimit: 1,
        privacyLeakageBits: 0,
      };
      const redemption: RetainedServiceRedemptionViewV1 = {
        providerIdHex: selectedProviderHex,
        policyDigestHex: '44'.repeat(32),
        scope: {
          scopeIdHex: selectedScopeHex,
          backend: 'dpf-pir',
          workload: 'dpf-query',
          protocolVersion: 1,
          operationProfile: 2,
          entitlementProfile: 3,
          dataset: { kind: 'manifest-root', rootHex: manifestRootHex },
          limits: { ...limits },
          offers: [],
        },
        offer,
      };
      const retainedHandle = (): WasmAcceptedRetainedServiceRedemptionV1 => ({
        free: vi.fn(),
        providerIdHex: selectedProviderHex,
        policyDigestHex: redemption.policyDigestHex,
        scopeIdHex: selectedScopeHex,
        offerId,
        assertRedemptionReady: vi.fn(),
        validateAuthorizationProof: vi.fn(),
        redemptionJson: () => structuredClone(redemption),
      });
      const port: ServiceAdmissionPortV1 = {
        providerEndpoint: () => providerEndpoint,
        operatorSigningKey: () => selectedProviderId.slice(),
        assertTrustAnchor: vi.fn(),
        fetchPolicy: async () => { throw new Error('current policy must not be fetched'); },
        fetchRetainedRedemption: async () => retainedHandle(),
        assertSessionBinding: vi.fn(),
        captureReadinessGuard: () => vi.fn(),
        assertRetainedSessionBinding: vi.fn(),
        authorize: async () => { throw new Error('current authorization must not be used'); },
        authorizeRetained: async () => ({
          scopeIdHex: selectedScopeHex,
          enforcedProfile: 3,
          expiresInMs: 1000,
          hasHarmonyAttach: false,
        }),
        requestPowChallenge: async () => { throw new Error('unused'); },
      };
      const payee = new Uint8Array([2, ...new Uint8Array(32).fill(payeeFill)]);
      const context = {
        kind: 'bolt11' as const,
        issuerEndpoint: offer.endpoint,
        issuerIdHex: offer.issuerIdHex,
        network: 'bitcoin' as const,
        expectedPayeePubkeyHex: Array.from(payee, (byte) =>
          byte.toString(16).padStart(2, '0')).join(''),
      };
      return {
        session: new ProviderAdmissionSessionV1(
          vault,
          port,
          { providerId: selectedProviderId, policySigningKey: selectedPolicyKey },
          DPF_TARGET,
        ),
        binding: {
          providerIdHex: selectedProviderHex,
          policyDigestHex: redemption.policyDigestHex,
          scopeIdHex: selectedScopeHex,
          offerId,
          scheme: 'cashu-bat' as const,
        },
        redemption,
        providerEndpoint,
        lightningNetwork: 'bitcoin' as const,
        expectedLightningPayeePubkey: payee,
        acquisitionContext: context,
      };
    };

    const first = makeRetained(
      providerHex, providerId, policyKey, scopeHex,
      'wss://provider-a.example', '57', 7, 71,
    );
    const second = makeRetained(
      secondProviderHex, secondProviderId, secondPolicyKey, secondScopeHex,
      'wss://provider-b.example', '58', 8, 72,
    );
    let consumedContext: unknown = null;
    vault.takeSingleUseCapability = async (binding, validate, context) => {
      consumedContext = context;
      const payload = new Uint8Array([1, 2, 3]);
      validate?.(payload);
      return { ...binding, payload };
    };
    const currentSecond = await independentFreeSession();
    const retainedCurrent = VerifiedIndependentProviderPairV1.createSelections(
      { kind: 'retained', value: first },
      { kind: 'current', value: {
        session: currentSecond,
        scopeIdHex: secondScopeHex,
        offerId: 91,
        providerEndpoint: 'wss://provider-b.example',
      } },
    );
    await expect(retainedCurrent.authorize('first')).resolves.toMatchObject({
      scopeIdHex: scopeHex,
    });
    expect(consumedContext).toEqual(first.acquisitionContext);

    const freeFirst = sessionForOffer({
      offerId: 90,
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
      arcVerificationKeyFingerprintHex: '',
      endpoint: '',
      credentialCount: 1,
      credentialPresentationLimit: 1,
      privacyLeakageBits: 0,
    });
    await freeFirst.refreshPolicy();
    expect(() => VerifiedIndependentProviderPairV1.createSelections(
      { kind: 'current', value: {
        session: freeFirst,
        scopeIdHex: scopeHex,
        offerId: 90,
        providerEndpoint: 'wss://provider-a.example',
        lightningNetwork: 'bitcoin',
      } },
      { kind: 'retained', value: second },
    )).not.toThrow();
    expect(() => VerifiedIndependentProviderPairV1.createSelections(
      { kind: 'retained', value: first },
      { kind: 'retained', value: second },
    )).not.toThrow();

    expect(() => VerifiedIndependentProviderPairV1.createSelections(
      { kind: 'retained', value: { ...first, acquisitionContext: undefined } },
      { kind: 'retained', value: second },
    )).toThrow(/lacks authenticated historical payment context/);
    expect(() => VerifiedIndependentProviderPairV1.createSelections(
      { kind: 'retained', value: {
        ...first,
        acquisitionContext: { ...first.acquisitionContext, issuerIdHex: '59'.repeat(32) },
      } },
      { kind: 'retained', value: second },
    )).toThrow(/differs from trusted offer context/);
    expect(() => VerifiedIndependentProviderPairV1.createSelections(
      { kind: 'retained', value: first },
      { kind: 'retained', value: {
        ...second,
        expectedLightningPayeePubkey: first.expectedLightningPayeePubkey,
        acquisitionContext: {
          ...second.acquisitionContext,
          expectedPayeePubkeyHex: first.acquisitionContext.expectedPayeePubkeyHex,
        },
      } },
    )).toThrow(/one Lightning payee observing both purchases/);
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
      arcVerificationKeyFingerprintHex: '',
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
      captureReadinessGuard: () => vi.fn(),
      assertRetainedSessionBinding: vi.fn(),
      authorize: async () => { throw new Error('unused'); },
      authorizeRetained: async () => { throw new Error('must not send'); },
      requestPowChallenge: async () => { throw new Error('unused'); },
    };
    const session = new ProviderAdmissionSessionV1(
      vault,
      port,
      { providerId, policySigningKey: policyKey },
      DPF_TARGET,
    );
    await expect(session.inspectRetainedCapability({
      providerIdHex: providerHex,
      policyDigestHex: '44'.repeat(32),
      scopeIdHex: scopeHex,
      offerId: 18,
      scheme: 'cashu-bat',
    })).rejects.toThrow(/does not match capability scheme/);
    expect(retiredBinding).toBeNull();
  });

  it('reserves two class-only BAT V2 proofs before either typed adapter call', async () => {
    const events: string[] = [];
    const dispositions: string[] = [];
    let firstSendGate: Promise<void> | null = null;
    const classBinding = {
      issuerIdHex: '71'.repeat(32),
      classIdHex: '72'.repeat(32),
      classDigestHex: '73'.repeat(32),
      classKeyEpoch: '4',
      batKeyIdHex: '74'.repeat(32),
    };
    const artifact = { classBytes: new Uint8Array([1, 2, 3]), binding: classBinding };
    const reservationId = 'reservation-v2';
    const lease = (recordId: string, spendByte: number) => ({
      ...classBinding,
      proof: new Uint8Array(210).fill(spendByte),
      globalSpendKeyHex: spendByte.toString(16).padStart(2, '0').repeat(32),
      recordId,
      reservationId,
    });
    const batVault: BatV2AdmissionVaultV2 = {
      reserveDistinctPair: vi.fn(async (_first, _second, validate) => {
        events.push('reserve');
        const first = lease('record-a', 0x31);
        const second = lease('record-b', 0x32);
        validate?.(first);
        validate?.(second);
        return { reservationId, first, second };
      }),
      finishReservation: vi.fn(async (_lease, disposition) => {
        dispositions.push(disposition);
      }),
    };
    const firstView = policy(batV2Offer(), providerHex, scopeHex);
    const secondView = policy(batV2Offer(), secondProviderHex, secondScopeHex);
    const makePort = (
      label: string,
      view: ServicePolicyViewV1,
      endpoint: string,
      operator: Uint8Array,
    ): ServiceAdmissionPortV1 => ({
      assertTrustAnchor: vi.fn(),
      providerEndpoint: () => endpoint,
      operatorSigningKey: () => operator.slice(),
      fetchPolicy: async () => accepted(view),
      assertSessionBinding: vi.fn(),
      captureReadinessGuard: () => vi.fn(),
      authorize: async () => { throw new Error('V1 must not send'); },
      authorizeBatV2: async () => {
        events.push(label);
        if (label === 'send-a') await firstSendGate;
        return {
          kind: 'granted',
          grant: {
            scopeIdHex: view.scopes[0].scopeIdHex,
            enforcedProfile: 3,
            expiresInMs: 1000,
            hasHarmonyAttach: false,
          },
        };
      },
      requestPowChallenge: async () => { throw new Error('unused'); },
    });
    const firstSession = new ProviderAdmissionSessionV1(
      vault,
      makePort('send-a', firstView, 'wss://provider-a.example', providerId),
      { providerId, policySigningKey: policyKey },
      DPF_TARGET,
    );
    const secondSession = new ProviderAdmissionSessionV1(
      vault,
      makePort('send-b', secondView, 'wss://provider-b.example', secondProviderId),
      { providerId: secondProviderId, policySigningKey: secondPolicyKey },
      DPF_TARGET,
    );
    await firstSession.refreshPolicy();
    await secondSession.refreshPolicy();
    const payee = new Uint8Array([2, ...new Uint8Array(32).fill(8)]);
    const createPair = () => VerifiedIndependentProviderBatV2PairV2.create(
      {
        session: firstSession,
        scopeIdHex: scopeHex,
        offerId: 101,
        providerEndpoint: 'wss://provider-a.example',
        lightningNetwork: 'bitcoin',
        expectedLightningPayeePubkey: payee,
        classArtifact: artifact,
      },
      {
        session: secondSession,
        scopeIdHex: secondScopeHex,
        offerId: 101,
        providerEndpoint: 'wss://provider-b.example',
        lightningNetwork: 'bitcoin',
        expectedLightningPayeePubkey: payee,
        classArtifact: artifact,
      },
      batVault,
      {
        allowSharedIssuerCorrelation: true,
        allowSharedLightningPayeeCorrelation: true,
      },
    );
    const pair = createPair();
    await expect(pair.authorize('first')).resolves.toMatchObject({ kind: 'granted' });
    await expect(pair.authorize('second')).resolves.toMatchObject({ kind: 'granted' });
    expect(events).toEqual(['reserve', 'send-a', 'send-b']);
    expect(dispositions).toEqual(['burn', 'burn']);
    await pair.close();

    events.length = 0;
    dispositions.length = 0;
    let releaseFirstSend!: () => void;
    firstSendGate = new Promise<void>((resolve) => { releaseFirstSend = resolve; });
    const closingPair = createPair();
    const authorization = closingPair.authorize('first');
    await vi.waitFor(() => expect(events).toEqual(['reserve', 'send-a']));
    const closing = closingPair.close();
    await Promise.resolve();
    expect(dispositions).toEqual([]);

    releaseFirstSend();
    await expect(authorization).resolves.toMatchObject({ kind: 'granted' });
    await closing;
    expect(dispositions).toEqual(['burn', 'recover-safe']);
    firstSession.close();
    secondSession.close();
  });

  it('performs zero sends for missing or duplicate BAT V2 pair inventory', async () => {
    const send = vi.fn();
    const classBinding = {
      issuerIdHex: '71'.repeat(32),
      classIdHex: '72'.repeat(32),
      classDigestHex: '73'.repeat(32),
      classKeyEpoch: '4',
      batKeyIdHex: '74'.repeat(32),
    };
    const viewA = policy(batV2Offer(), providerHex, scopeHex);
    const viewB = policy(batV2Offer(), secondProviderHex, secondScopeHex);
    const port = (
      view: ServicePolicyViewV1,
      endpoint: string,
      operator: Uint8Array,
      withBatV2 = true,
    ): ServiceAdmissionPortV1 => {
      const value: ServiceAdmissionPortV1 = {
        assertTrustAnchor: vi.fn(),
        providerEndpoint: () => endpoint,
        operatorSigningKey: () => operator.slice(),
        fetchPolicy: async () => accepted(view),
        assertSessionBinding: vi.fn(),
        captureReadinessGuard: () => vi.fn(),
        authorize: async () => { throw new Error('unused'); },
        requestPowChallenge: async () => { throw new Error('unused'); },
      };
      if (withBatV2) {
        value.authorizeBatV2 = async () => {
          send();
          return { kind: 'burn-terminal' };
        };
      }
      return value;
    };
    const first = new ProviderAdmissionSessionV1(
      vault, port(viewA, 'wss://a.example', providerId),
      { providerId, policySigningKey: policyKey }, DPF_TARGET,
    );
    const second = new ProviderAdmissionSessionV1(
      vault, port(viewB, 'wss://b.example', secondProviderId),
      { providerId: secondProviderId, policySigningKey: secondPolicyKey }, DPF_TARGET,
    );
    await first.refreshPolicy();
    await second.refreshPolicy();
    const artifact = { classBytes: new Uint8Array([1]), binding: classBinding };
    const payee = new Uint8Array([2, ...new Uint8Array(32).fill(8)]);
    const create = (
      batVault: BatV2AdmissionVaultV2,
      firstSession = first,
    ) =>
      VerifiedIndependentProviderBatV2PairV2.create(
        { session: firstSession, scopeIdHex: scopeHex, offerId: 101,
          providerEndpoint: 'wss://a.example', lightningNetwork: 'bitcoin',
          expectedLightningPayeePubkey: payee,
          classArtifact: artifact },
        { session: second, scopeIdHex: secondScopeHex, offerId: 101,
          providerEndpoint: 'wss://b.example', lightningNetwork: 'bitcoin',
          expectedLightningPayeePubkey: payee,
          classArtifact: artifact },
        batVault,
        { allowSharedIssuerCorrelation: true, allowSharedLightningPayeeCorrelation: true },
      );
    const missing = create({
      reserveDistinctPair: async () => null,
      finishReservation: vi.fn(),
    });
    await expect(missing.authorize('first')).rejects.toThrow(/two distinct BAT V2 proofs/);
    expect(send).not.toHaveBeenCalled();
    await missing.close();

    const duplicateLease = {
      ...classBinding,
      proof: new Uint8Array(210).fill(5),
      globalSpendKeyHex: '75'.repeat(32),
      recordId: 'record-a',
      reservationId: 'reservation-duplicate',
    };
    const duplicate = create({
      reserveDistinctPair: async () => ({
        reservationId: 'reservation-duplicate',
        first: duplicateLease,
        second: { ...duplicateLease, proof: duplicateLease.proof.slice(), recordId: 'record-b' },
      }),
      finishReservation: vi.fn(async () => {}),
    });
    await expect(duplicate.authorize('first')).rejects.toThrow(/non-distinct/);
    expect(send).not.toHaveBeenCalled();
    await duplicate.close();

    const mismatchedFirst = {
      ...duplicateLease,
      recordId: 'record-c',
      reservationId: 'reservation-mismatch',
      classDigestHex: '76'.repeat(32),
      proof: new Uint8Array(210).fill(6),
    };
    const mismatchedSecond = {
      ...duplicateLease,
      recordId: 'record-d',
      reservationId: 'reservation-mismatch',
      globalSpendKeyHex: '77'.repeat(32),
      proof: new Uint8Array(210).fill(7),
    };
    const finishMismatch = vi.fn(async (
      reserved: typeof mismatchedFirst,
      _disposition: 'recover-safe' | 'burn',
    ) => {
      reserved.proof.fill(0);
    });
    const mismatched = create({
      reserveDistinctPair: async () => ({
        reservationId: 'reservation-mismatch',
        first: mismatchedFirst,
        second: mismatchedSecond,
      }),
      finishReservation: finishMismatch,
    });
    await expect(mismatched.authorize('first')).rejects.toThrow(/exact verified class/);
    expect(finishMismatch).toHaveBeenCalledTimes(2);
    expect(finishMismatch.mock.calls.every(([, disposition]) =>
      disposition === 'recover-safe')).toBe(true);
    expect(mismatchedFirst.proof.every((byte) => byte === 0)).toBe(true);
    expect(mismatchedSecond.proof.every((byte) => byte === 0)).toBe(true);
    expect(send).not.toHaveBeenCalled();
    await mismatched.close();

    const unsupportedFirst = new ProviderAdmissionSessionV1(
      vault, port(viewA, 'wss://a.example', providerId, false),
      { providerId, policySigningKey: policyKey }, DPF_TARGET,
    );
    await unsupportedFirst.refreshPolicy();
    const reserveDistinctPair = vi.fn(async () => null);
    const unsupported = create({
      reserveDistinctPair,
      finishReservation: vi.fn(),
    }, unsupportedFirst);
    await expect(unsupported.authorize('first')).rejects.toThrow(/does not expose typed BAT V2/);
    expect(reserveDistinctPair).not.toHaveBeenCalled();
    expect(send).not.toHaveBeenCalled();
    await unsupported.close();
    unsupportedFirst.close();
    first.close();
    second.close();
  });
});
