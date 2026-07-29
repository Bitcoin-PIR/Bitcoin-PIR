import { beforeEach, describe, expect, it, vi } from 'vitest';

const acquisitionMock = vi.hoisted(() => ({
  startMode: 'success' as 'success' | 'lost',
  resume: vi.fn(),
}));

vi.mock('../sdk-bridge.js', async () => ({
  requireSdkWasm: () => ({
    initialServicePolicyCheckpointV1: () => new Uint8Array([1]),
    WasmArcPresentationState: { deserialize: () => { throw new Error('unused'); } },
  }),
}));

vi.mock('../service-acquisition.js', () => {
  class RecoveryRequired extends Error {
    name = 'Bolt11RecoveryRequiredErrorV1';
    constructor(readonly recoveryId: string) { super('lost quote response'); }
  }
  const handle = () => ({
    recoveryId: '99'.repeat(32),
    ensureQuote: vi.fn(async () => 'lnbc1fixture'),
    invoice: () => 'lnbc1fixture',
    status: () => 'invoice-open',
    invoiceExpiresAtUnix: () => 9_999_999_999n,
    claimDeadlineUnix: () => 9_999_999_999n,
    pollStatus: vi.fn(async () => 'payment-settled'),
    claim: vi.fn(async () => 1),
    close: vi.fn(),
  });
  return {
    Bolt11RecoveryRequiredErrorV1: RecoveryRequired,
    Bolt11AcquisitionControllerV1: {
      start: vi.fn(async () => {
        if (acquisitionMock.startMode === 'lost') throw new RecoveryRequired('88'.repeat(32));
        return handle();
      }),
    },
    resumeBolt11AcquisitionV1: acquisitionMock.resume,
  };
});

import { AdmissionCredentialVaultV1 } from '../admission-vault.js';
import {
  ProductAdmissionControllerV1,
  ProductAdmissionErrorV1,
} from '../product-admission-controller.js';
import {
  ProviderAdmissionSessionV1,
  type ProviderTrustAnchorV1,
  type ServiceAdmissionPortV1,
  type ServiceAdmissionTargetV1,
  type ServiceAdmissionVaultV1,
} from '../service-admission.js';
import type {
  ServiceOfferViewV1,
  ServicePolicyViewV1,
  RetainedServiceRedemptionViewV1,
  WasmAcceptedRetainedServiceRedemptionV1,
  WasmAcceptedServicePolicyV1,
} from '../sdk-bridge.js';

const HEX = {
  provider0: '11'.repeat(32),
  provider1: '12'.repeat(32),
  scope0: '21'.repeat(32),
  scope1: '22'.repeat(32),
  policy0: '31'.repeat(32),
  policy1: '32'.repeat(32),
  key0: '41'.repeat(32),
  key1: '42'.repeat(32),
  dataset: '51'.repeat(32),
};

interface FakeVaultState {
  inventory: Map<string, number>;
  takes: number;
  recoveries: any[];
}

function freeOffer(offerId: number): ServiceOfferViewV1 {
  return {
    offerId,
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
  };
}

function paidOffer(
  offerId: number,
  authorization: 'cashu-bat' | 'arc-experimental' | 'cashu-ecash' | 'bolt11-direct-receipt',
): ServiceOfferViewV1 {
  const standard = authorization === 'cashu-ecash';
  return {
    offerId,
    acquisition: standard ? 'cashu-ecash' : 'bolt11',
    authorization,
    freeMode: 'not-free',
    verification: standard ? 'standard-cashu-mint-online' : 'provider-local',
    deploymentStatus: authorization === 'arc-experimental' ? 'experimental' : 'stable',
    priorityClass: 1,
    price: { kind: 'msat', amount: '1000' },
    issuerIdHex: `${offerId.toString(16).padStart(2, '0')}`.repeat(32),
    keyIdHex: '71'.repeat(16),
    batVerificationKeyFingerprintHex: authorization === 'cashu-bat' ? '81'.repeat(32) : '',
    arcVerificationKeyFingerprintHex: authorization === 'arc-experimental'
      ? `${(offerId + 0x80).toString(16).padStart(2, '0')}`.repeat(32)
      : '',
    endpoint: 'https://issuer.example',
    credentialCount: 1,
    credentialPresentationLimit: authorization === 'arc-experimental' ? 10 : 1,
    privacyLeakageBits: 1,
  };
}

function policy(
  providerIdHex: string,
  policyDigestHex: string,
  scopeIdHex: string,
  target: ServiceAdmissionTargetV1,
  offers: ServiceOfferViewV1[],
): ServicePolicyViewV1 {
  return {
    providerIdHex,
    policyDigestHex,
    policyEpoch: '1',
    expiresAtUnix: String(Math.floor(Date.now() / 1000) + 600),
    scopes: [{
      scopeIdHex,
      backend: target.backend,
      workload: target.workload,
      protocolVersion: 1,
      operationProfile: 1,
      entitlementProfile: 2,
      offers,
    }],
  };
}

function retainedView(
  providerIdHex: string,
  policyDigestHex: string,
  scopeIdHex: string,
  target: ServiceAdmissionTargetV1,
  offer: ServiceOfferViewV1,
): RetainedServiceRedemptionViewV1 {
  return {
    providerIdHex,
    policyDigestHex,
    scope: {
      scopeIdHex,
      backend: target.backend,
      workload: target.workload,
      protocolVersion: target.backend === 'harmony-pir' ? 2 : 1,
      operationProfile: 1,
      entitlementProfile: 2,
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
}

function accepted(view: ServicePolicyViewV1): WasmAcceptedServicePolicyV1 {
  let acknowledged = false;
  return {
    free: vi.fn(),
    providerIdHex: view.providerIdHex,
    policyDigestHex: view.policyDigestHex,
    policyEpoch: view.policyEpoch,
    expiresAtUnix: view.expiresAtUnix,
    checkpointBytes: () => new Uint8Array([9]),
    acknowledgeCheckpointPersisted: () => { acknowledged = true; },
    validateAuthorizationProof: (_scope, _offer, proof) => {
      if (!acknowledged) throw new Error('checkpoint not durable');
      if (proof.length === 0 && view.scopes[0].offers[0].authorization !== 'free') {
        throw new Error('paid proof missing');
      }
    },
    importStandardCashuToken: () => new Uint8Array([7, 7]),
    offersJson: () => structuredClone(view),
    beginBolt11Acquisition: () => { throw new Error('mocked at controller boundary'); },
  };
}

function fakeVault(): { vault: AdmissionCredentialVaultV1; state: FakeVaultState } {
  const state: FakeVaultState = { inventory: new Map(), takes: 0, recoveries: [] };
  const key = (binding: any) => [
    binding.providerIdHex,
    binding.policyDigestHex,
    binding.scopeIdHex,
    binding.offerId,
    binding.scheme,
  ].join(':');
  const vault = {
    advancePolicyCheckpoint: async (_provider: string, initial: Uint8Array, advance: Function) => {
      const result = await advance(initial);
      return result.value;
    },
    takeSingleUseCapability: async (binding: any, validate?: Function) => {
      const id = key(binding);
      const count = state.inventory.get(id) ?? 0;
      if (count === 0) return null;
      const payload = new Uint8Array([1, 2, 3]);
      validate?.(payload);
      state.inventory.set(id, count - 1);
      state.takes += 1;
      return { ...binding, payload };
    },
    advanceArcCredential: async () => null,
    countCapabilities: async (binding: any) => state.inventory.get(key(binding)) ?? 0,
    listCapabilityInventory: async (providerIdHex?: string) => [...state.inventory]
      .filter(([serialized, count]) => count > 0
        && (!providerIdHex || serialized.startsWith(`${providerIdHex}:`)))
      .map(([serialized, count]) => {
        const [providerIdHex, policyDigestHex, scopeIdHex, offerId, scheme] = serialized.split(':');
        return {
          providerIdHex,
          policyDigestHex,
          scopeIdHex,
          offerId: Number(offerId),
          scheme,
          count,
        };
      }),
    putCapability: async (capability: any) => {
      const id = key(capability);
      state.inventory.set(id, (state.inventory.get(id) ?? 0) + 1);
      return 'aa'.repeat(32);
    },
    listBolt11Recoveries: async () => state.recoveries,
    getBolt11Recovery: async (id: string) => state.recoveries.find((r) => r.id === id) ?? null,
  } as unknown as AdmissionCredentialVaultV1;
  return { vault, state };
}

function session(
  vault: AdmissionCredentialVaultV1,
  views: ServicePolicyViewV1[],
  providerIdHex: string,
  policyKeyHex: string,
  target: ServiceAdmissionTargetV1,
  authorizeImpl: ServiceAdmissionPortV1['authorize'] = async (_p, scope) => ({
    scopeIdHex: Array.from(scope, (v) => v.toString(16).padStart(2, '0')).join(''),
    enforcedProfile: 2,
    expiresInMs: 1000,
    hasHarmonyAttach: target.workload === 'harmony-hint',
  }),
  retainedView?: RetainedServiceRedemptionViewV1,
): { session: ProviderAdmissionSessionV1; authorize: ReturnType<typeof vi.fn> } {
  let refresh = 0;
  const authorize = vi.fn(authorizeImpl);
  const retainedHandle = (): WasmAcceptedRetainedServiceRedemptionV1 => {
    if (!retainedView) throw new Error('unused');
    return {
      free: vi.fn(),
      providerIdHex: retainedView.providerIdHex,
      policyDigestHex: retainedView.policyDigestHex,
      scopeIdHex: retainedView.scope.scopeIdHex,
      offerId: retainedView.offer.offerId,
      assertRedemptionReady: vi.fn(),
      validateAuthorizationProof: vi.fn(),
      redemptionJson: () => structuredClone(retainedView),
    };
  };
  const port: ServiceAdmissionPortV1 = {
    assertTrustAnchor: vi.fn(),
    fetchPolicy: async () => accepted(views[Math.min(refresh++, views.length - 1)]),
    fetchRetainedRedemption: async () => retainedHandle(),
    assertSessionBinding: vi.fn(),
    assertRetainedSessionBinding: vi.fn(),
    authorize,
    authorizeRetained: async () => {
      if (!retainedView) throw new Error('unused');
      return {
        scopeIdHex: retainedView.scope.scopeIdHex,
        enforcedProfile: retainedView.scope.entitlementProfile,
        expiresInMs: 1000,
        hasHarmonyAttach: target.workload === 'harmony-hint',
      };
    },
    requestPowChallenge: async () => { throw new Error('unused'); },
  };
  const trust: ProviderTrustAnchorV1 = {
    providerId: Uint8Array.from(Buffer.from(providerIdHex, 'hex')),
    policySigningKey: Uint8Array.from(Buffer.from(policyKeyHex, 'hex')),
  };
  return {
    session: new ProviderAdmissionSessionV1(
      vault as unknown as ServiceAdmissionVaultV1,
      port,
      trust,
      target,
    ),
    authorize,
  };
}

function inventoryKey(
  provider: string,
  digest: string,
  scope: string,
  offer: ServiceOfferViewV1,
): string {
  return [provider, digest, scope, offer.offerId, offer.authorization].join(':');
}

describe('product admission lifecycle', () => {
  beforeEach(() => {
    acquisitionMock.startMode = 'success';
    acquisitionMock.resume.mockReset();
  });

  it('supports mixed Free and Cashu BAT methods on independent DPF legs', async () => {
    const { vault, state } = fakeVault();
    const target = { backend: 'dpf-pir', workload: 'dpf-query' } as const;
    const free = freeOffer(1);
    const bat = paidOffer(2, 'cashu-bat');
    const first = session(vault, [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [free])], HEX.provider0, HEX.key0, target);
    const second = session(vault, [policy(HEX.provider1, HEX.policy1, HEX.scope1, target, [bat])], HEX.provider1, HEX.key1, target);
    state.inventory.set(inventoryKey(HEX.provider1, HEX.policy1, HEX.scope1, bat), 1);
    const controller = new ProductAdmissionControllerV1({
      topology: 'independent-pair', vault,
    });
    await controller.prepare(async () => ({
      legs: [
        { role: 'server0', label: 'Server 0', session: first.session, ...target },
        { role: 'server1', label: 'Server 1', session: second.session, ...target },
      ],
      close: vi.fn(),
    }));
    await controller.selectOffer('server0', { scopeIdHex: HEX.scope0, offerId: 1 });
    await controller.selectOffer('server1', { scopeIdHex: HEX.scope1, offerId: 2 });
    await controller.authorize('server0');
    await controller.authorize('server1');
    expect(controller.canQuery()).toBe(true);
    const query = vi.fn(async () => 'ok');
    await expect(controller.executeQuery(query)).resolves.toBe('ok');
    await expect(controller.executeQuery(query)).rejects.toThrow(/must be authorized/);
    expect(query).toHaveBeenCalledOnce();
    expect(state.takes).toBe(1);
  });

  it('stages provider legs and permits first-leg acquisition before the peer is known', async () => {
    const { vault } = fakeVault();
    const target = { backend: 'dpf-pir', workload: 'dpf-query' } as const;
    const firstOffer = paidOffer(21, 'bolt11-direct-receipt');
    const secondOffer = freeOffer(22);
    const first = session(
      vault,
      [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [firstOffer])],
      HEX.provider0,
      HEX.key0,
      target,
    );
    const second = session(
      vault,
      [policy(HEX.provider1, HEX.policy1, HEX.scope1, target, [secondOffer])],
      HEX.provider1,
      HEX.key1,
      target,
    );
    const controller = new ProductAdmissionControllerV1({ topology: 'independent-pair', vault });
    await controller.prepareLeg(async () => ({
      leg: {
        role: 'server0', label: 'Server 0', session: first.session, ...target,
        expectedLightningPayeePubkey: new Uint8Array([2, ...new Uint8Array(32).fill(1)]),
      },
      close: vi.fn(),
    }));
    await controller.selectOffer('server0', { scopeIdHex: HEX.scope0, offerId: 21 });
    await controller.startBolt11('server0');
    expect(controller.snapshot().legs).toHaveLength(1);
    expect(controller.snapshot().legs[0].invoice).toBe('lnbc1fixture');

    await controller.prepareLeg(async () => ({
      leg: { role: 'server1', label: 'Server 1', session: second.session, ...target },
      close: vi.fn(),
    }));
    await controller.selectOffer('server1', { scopeIdHex: HEX.scope1, offerId: 22 });
    expect(controller.snapshot().legs[0].invoice).toBe('lnbc1fixture');
    expect(controller.canQuery()).toBe(false);
    await controller.close();
  });

  it('keeps the authorized first leg when strict bootstrap of the second leg fails', async () => {
    const { vault } = fakeVault();
    const target = { backend: 'dpf-pir', workload: 'dpf-query' } as const;
    const firstOffer = freeOffer(27);
    const first = session(
      vault,
      [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [firstOffer])],
      HEX.provider0,
      HEX.key0,
      target,
    );
    const closeFirst = vi.fn(async () => {});
    const controller = new ProductAdmissionControllerV1({ topology: 'independent-pair', vault });
    await controller.prepareLeg(async () => ({
      leg: { role: 'server0', label: 'Server 0', session: first.session, ...target },
      close: closeFirst,
    }));
    await controller.selectOffer('server0', { scopeIdHex: HEX.scope0, offerId: 27 });
    await controller.authorize('server0');

    await expect(controller.prepareLeg(async () => {
      throw new Error('second provider attestation failed');
    })).rejects.toMatchObject({ code: 'strict-bootstrap-failed' });

    const snapshot = controller.snapshot();
    expect(snapshot.phase).toBe('selecting');
    expect(snapshot.legs).toHaveLength(1);
    expect(snapshot.legs[0].status).toBe('authorized');
    expect(first.authorize).toHaveBeenCalledOnce();
    expect(closeFirst).not.toHaveBeenCalled();
    expect(controller.canQuery()).toBe(false);
    await controller.close();
  });

  it('runs the staged pair finalizer exactly once after both legs authorize', async () => {
    const { vault } = fakeVault();
    const target = { backend: 'dpf-pir', workload: 'dpf-query' } as const;
    const offer0 = freeOffer(41);
    const offer1 = freeOffer(42);
    const first = session(
      vault,
      [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [offer0])],
      HEX.provider0,
      HEX.key0,
      target,
    );
    const second = session(
      vault,
      [policy(HEX.provider1, HEX.policy1, HEX.scope1, target, [offer1])],
      HEX.provider1,
      HEX.key1,
      target,
    );
    const finalizeAfterAuthorization = vi.fn(async () => {});
    const controller = new ProductAdmissionControllerV1({ topology: 'independent-pair', vault });

    await controller.prepareLeg(async () => ({
      leg: { role: 'server0', label: 'Server 0', session: first.session, ...target },
      close: async () => {},
    }));
    await controller.selectOffer('server0', { scopeIdHex: HEX.scope0, offerId: offer0.offerId });
    await controller.authorize('server0');
    expect(finalizeAfterAuthorization).not.toHaveBeenCalled();
    expect(controller.canQuery()).toBe(false);

    await controller.prepareLeg(async () => ({
      leg: { role: 'server1', label: 'Server 1', session: second.session, ...target },
      finalizeAfterAuthorization,
      close: async () => {},
    }));
    expect(finalizeAfterAuthorization).not.toHaveBeenCalled();
    await controller.selectOffer('server1', { scopeIdHex: HEX.scope1, offerId: offer1.offerId });
    expect(finalizeAfterAuthorization).not.toHaveBeenCalled();

    const ready = await controller.authorize('server1');

    expect(finalizeAfterAuthorization).toHaveBeenCalledOnce();
    expect(ready.phase).toBe('ready-to-query');
    expect(controller.canQuery()).toBe(true);
    const query = vi.fn(async () => 'verified');
    await expect(controller.executeQuery(query)).resolves.toBe('verified');
    expect(query).toHaveBeenCalledOnce();
    expect(finalizeAfterAuthorization).toHaveBeenCalledOnce();
    await controller.close();
  });

  it('does not preflight or query when either provider authorization fails', async () => {
    const { vault } = fakeVault();
    const target = { backend: 'dpf-pir', workload: 'dpf-query' } as const;
    const offer0 = freeOffer(43);
    const offer1 = freeOffer(44);
    const first = session(
      vault,
      [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [offer0])],
      HEX.provider0,
      HEX.key0,
      target,
    );
    const second = session(
      vault,
      [policy(HEX.provider1, HEX.policy1, HEX.scope1, target, [offer1])],
      HEX.provider1,
      HEX.key1,
      target,
      async () => { throw new Error('capability rejected'); },
    );
    const finalizeAfterAuthorization = vi.fn(async () => {});
    const controller = new ProductAdmissionControllerV1({ topology: 'independent-pair', vault });
    await controller.prepareLeg(async () => ({
      leg: { role: 'server0', label: 'Server 0', session: first.session, ...target },
      close: async () => {},
    }));
    await controller.selectOffer('server0', { scopeIdHex: HEX.scope0, offerId: offer0.offerId });
    await controller.authorize('server0');
    await controller.prepareLeg(async () => ({
      leg: { role: 'server1', label: 'Server 1', session: second.session, ...target },
      finalizeAfterAuthorization,
      close: async () => {},
    }));
    await controller.selectOffer('server1', { scopeIdHex: HEX.scope1, offerId: offer1.offerId });

    await expect(controller.authorize('server1')).rejects.toThrow('capability rejected');

    expect(finalizeAfterAuthorization).not.toHaveBeenCalled();
    expect(controller.canQuery()).toBe(false);
    const query = vi.fn(async () => 'must not run');
    await expect(controller.executeQuery(query)).rejects.toMatchObject({ code: 'operation-failed' });
    expect(query).not.toHaveBeenCalled();
    await controller.close();
  });

  it('fails closed without retry when post-authorization preflight fails', async () => {
    const { vault } = fakeVault();
    const target = { backend: 'harmony-pir', workload: 'harmony-query' } as const;
    const offer0 = freeOffer(45);
    const offer1 = freeOffer(46);
    const first = session(
      vault,
      [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [offer0])],
      HEX.provider0,
      HEX.key0,
      target,
    );
    const second = session(
      vault,
      [policy(HEX.provider1, HEX.policy1, HEX.scope1, target, [offer1])],
      HEX.provider1,
      HEX.key1,
      target,
    );
    const finalizeAfterAuthorization = vi.fn(async () => {
      throw new Error('tree-top root mismatch');
    });
    const controller = new ProductAdmissionControllerV1({ topology: 'independent-pair', vault });
    await controller.prepareLeg(async () => ({
      leg: { role: 'hint', label: 'Hint', session: first.session, ...target },
      close: async () => {},
    }));
    await controller.selectOffer('hint', { scopeIdHex: HEX.scope0, offerId: offer0.offerId });
    await controller.authorize('hint');
    await controller.prepareLeg(async () => ({
      leg: { role: 'query', label: 'Query', session: second.session, ...target },
      finalizeAfterAuthorization,
      close: async () => {},
    }));
    await controller.selectOffer('query', { scopeIdHex: HEX.scope1, offerId: offer1.offerId });

    await expect(controller.authorize('query'))
      .rejects.toMatchObject({ code: 'strict-finalization-failed' });

    expect(finalizeAfterAuthorization).toHaveBeenCalledOnce();
    expect(controller.snapshot().phase).toBe('failed');
    expect(controller.snapshot().legs[1].status).toBe('authorized');
    expect(controller.canQuery()).toBe(false);
    const query = vi.fn(async () => 'must not run');
    await expect(controller.executeQuery(query)).rejects.toMatchObject({ code: 'operation-failed' });
    expect(query).not.toHaveBeenCalled();
    await expect(controller.authorize('query')).rejects.toMatchObject({
      code: 'offer-selection-invalidated',
    });
    expect(finalizeAfterAuthorization).toHaveBeenCalledOnce();
    await controller.close();
  });

  it('does not roll back a first-leg invoice when the later offer reveals a shared issuer', async () => {
    const { vault } = fakeVault();
    const target = { backend: 'dpf-pir', workload: 'dpf-query' } as const;
    const firstOffer = paidOffer(23, 'bolt11-direct-receipt');
    const secondOffer = {
      ...paidOffer(24, 'bolt11-direct-receipt'),
      issuerIdHex: firstOffer.issuerIdHex,
      endpoint: firstOffer.endpoint,
    };
    const first = session(vault, [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [firstOffer])], HEX.provider0, HEX.key0, target);
    const second = session(vault, [policy(HEX.provider1, HEX.policy1, HEX.scope1, target, [secondOffer])], HEX.provider1, HEX.key1, target);
    const controller = new ProductAdmissionControllerV1({ topology: 'independent-pair', vault });
    await controller.prepareLeg(async () => ({
      leg: {
        role: 'server0', label: 'Server 0', session: first.session, ...target,
        expectedLightningPayeePubkey: new Uint8Array([2, ...new Uint8Array(32).fill(1)]),
      }, close: vi.fn(),
    }));
    await controller.selectOffer('server0', { scopeIdHex: HEX.scope0, offerId: 23 });
    await controller.startBolt11('server0');
    await controller.prepareLeg(async () => ({
      leg: { role: 'server1', label: 'Server 1', session: second.session, ...target },
      close: vi.fn(),
    }));
    await expect(controller.selectOffer('server1', {
      scopeIdHex: HEX.scope1,
      offerId: 24,
    })).rejects.toMatchObject({ code: 'pair-correlation-rejected' });
    expect(controller.snapshot().legs[0].invoice).toBe('lnbc1fixture');
    expect(controller.canQuery()).toBe(false);
    await controller.close();
  });

  it('keeps an authorized first selection frozen while allowing a later peer and opt-in', async () => {
    const { vault, state } = fakeVault();
    const target = { backend: 'dpf-pir', workload: 'dpf-query' } as const;
    const firstOffer = paidOffer(25, 'bolt11-direct-receipt');
    const secondOffer = {
      ...paidOffer(26, 'bolt11-direct-receipt'),
      issuerIdHex: firstOffer.issuerIdHex,
      endpoint: firstOffer.endpoint,
    };
    state.inventory.set(
      inventoryKey(HEX.provider0, HEX.policy0, HEX.scope0, firstOffer),
      1,
    );
    state.inventory.set(
      inventoryKey(HEX.provider1, HEX.policy1, HEX.scope1, secondOffer),
      1,
    );
    const first = session(
      vault,
      [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [firstOffer])],
      HEX.provider0,
      HEX.key0,
      target,
    );
    const second = session(
      vault,
      [policy(HEX.provider1, HEX.policy1, HEX.scope1, target, [secondOffer])],
      HEX.provider1,
      HEX.key1,
      target,
    );
    const controller = new ProductAdmissionControllerV1({ topology: 'independent-pair', vault });
    await controller.prepareLeg(async () => ({
      leg: { role: 'server0', label: 'Server 0', session: first.session, ...target },
      close: vi.fn(),
    }));
    await controller.selectOffer('server0', { scopeIdHex: HEX.scope0, offerId: 25 });
    await controller.authorize('server0');
    await expect(controller.selectOffer('server0', {
      scopeIdHex: HEX.scope0,
      offerId: 25,
    })).rejects.toMatchObject({ code: 'offer-selection-invalidated' });

    await controller.prepareLeg(async () => ({
      leg: { role: 'server1', label: 'Server 1', session: second.session, ...target },
      close: vi.fn(),
    }));
    await expect(controller.selectOffer('server1', {
      scopeIdHex: HEX.scope1,
      offerId: 26,
    })).rejects.toMatchObject({ code: 'pair-correlation-rejected' });
    expect(second.authorize).not.toHaveBeenCalled();

    controller.setAllowSharedIssuerCorrelationOnce(true);
    await controller.authorize('server1');
    expect(first.authorize).toHaveBeenCalledOnce();
    expect(second.authorize).toHaveBeenCalledOnce();
    expect(controller.canQuery()).toBe(true);
    await controller.executeQuery(async () => 'ok');
    await controller.close();
  });

  it('uses an exact Harmony hint cache without authorization and authorizes before a fresh download', async () => {
    for (const cached of [true, false]) {
      const { vault } = fakeVault();
      const hintTarget = { backend: 'harmony-pir', workload: 'harmony-hint' } as const;
      const queryTarget = { backend: 'harmony-pir', workload: 'harmony-query' } as const;
      const hint = session(vault, [policy(HEX.provider0, HEX.policy0, HEX.scope0, hintTarget, [freeOffer(3)])], HEX.provider0, HEX.key0, hintTarget);
      const query = session(vault, [policy(HEX.provider1, HEX.policy1, HEX.scope1, queryTarget, [freeOffer(4)])], HEX.provider1, HEX.key1, queryTarget);
      const restore = vi.fn(async () => cached);
      const acquire = vi.fn(async () => {});
      const controller = new ProductAdmissionControllerV1({ topology: 'independent-pair', vault });
      await controller.prepare(async () => ({
        legs: [
          {
            role: 'hint', label: 'Hint', session: hint.session, ...hintTarget,
            resource: { restore, acquireAfterAuthorization: acquire, datasetIdHex: HEX.dataset, variant: 1 },
          },
          { role: 'query', label: 'Query', session: query.session, ...queryTarget },
        ],
        close: vi.fn(),
      }));
      await controller.selectOffer('hint', { scopeIdHex: HEX.scope0, offerId: 3 });
      await controller.selectOffer('query', { scopeIdHex: HEX.scope1, offerId: 4 });
      await controller.authorize('hint');
      await controller.authorize('query');
      expect(hint.authorize).toHaveBeenCalledTimes(cached ? 0 : 1);
      expect(acquire).toHaveBeenCalledTimes(cached ? 0 : 1);
      expect(controller.canQuery()).toBe(true);
      await controller.close();
    }
  });

  it('prevents policy, quote, authorization, and query after strict bootstrap failure', async () => {
    const { vault } = fakeVault();
    const controller = new ProductAdmissionControllerV1({ topology: 'single-provider', vault });
    await expect(controller.prepare(async () => { throw new Error('binary pin mismatch'); }))
      .rejects.toMatchObject({ code: 'strict-bootstrap-failed' });
    expect(() => controller.snapshot()).not.toThrow();
    await expect(controller.authorize('single')).rejects.toMatchObject({
      code: 'commercial-admission-unconfigured',
    });
    await expect(controller.executeQuery(vi.fn())).rejects.toThrow(/must be authorized/);
  });

  it('invalidates exact selection after a live policy refresh', async () => {
    const { vault } = fakeVault();
    const target = { backend: 'onion-pir', workload: 'onion-session' } as const;
    const first = policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [freeOffer(5)]);
    const second = policy(HEX.provider0, '33'.repeat(32), HEX.scope0, target, [freeOffer(6)]);
    const leg = session(vault, [first, second], HEX.provider0, HEX.key0, target);
    const controller = new ProductAdmissionControllerV1({ topology: 'single-provider', vault });
    await controller.prepare(async () => ({
      legs: [{ role: 'onion', label: 'Onion', session: leg.session, ...target }], close: vi.fn(),
    }));
    await controller.selectOffer('onion', { scopeIdHex: HEX.scope0, offerId: 5 });
    await controller.refreshPolicies();
    expect(controller.snapshot().legs[0].selected).toBeNull();
    await expect(controller.authorize('onion')).rejects.toMatchObject({
      code: 'offer-selection-invalidated',
    });
  });

  it('surfaces lost BOLT11 response recovery without creating another invoice', async () => {
    const { vault } = fakeVault();
    const target = { backend: 'tee-oram', workload: 'tee-oram-query' } as const;
    const bolt = paidOffer(7, 'bolt11-direct-receipt');
    const leg = session(vault, [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [bolt])], HEX.provider0, HEX.key0, target);
    const controller = new ProductAdmissionControllerV1({ topology: 'single-provider', vault });
    await controller.prepare(async () => ({
      legs: [{
        role: 'oram', label: 'ORAM', session: leg.session, ...target,
        expectedLightningPayeePubkey: new Uint8Array([2, ...new Uint8Array(32).fill(1)]),
      }],
      close: vi.fn(),
    }));
    await controller.selectOffer('oram', { scopeIdHex: HEX.scope0, offerId: 7 });
    acquisitionMock.startMode = 'lost';
    await expect(controller.startBolt11('oram')).rejects.toMatchObject({
      code: 'bolt11-recovery-required',
    });
    expect(controller.snapshot().legs[0].recoveryIds).toEqual(['88'.repeat(32)]);
  });

  it('imports standard Cashu and reports BAT/ARC missing inventory honestly', async () => {
    const { vault } = fakeVault();
    const target = { backend: 'onion-pir', workload: 'onion-session' } as const;
    const cashu = paidOffer(8, 'cashu-ecash');
    const leg = session(vault, [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [cashu])], HEX.provider0, HEX.key0, target);
    const controller = new ProductAdmissionControllerV1({ topology: 'single-provider', vault });
    await controller.prepare(async () => ({
      legs: [{ role: 'onion', label: 'Onion', session: leg.session, ...target }], close: vi.fn(),
    }));
    await controller.selectOffer('onion', { scopeIdHex: HEX.scope0, offerId: 8 });
    expect(controller.snapshot().legs[0].inventory).toBe(0);
    await controller.importStandardCashu('onion', 'cashuAfixture');
    expect(controller.snapshot().legs[0].inventory).toBe(1);
    await controller.close();

    for (const authorization of ['cashu-bat', 'arc-experimental'] as const) {
      const local = fakeVault();
      const offer = paidOffer(authorization === 'cashu-bat' ? 9 : 10, authorization);
      const current = session(local.vault, [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [offer])], HEX.provider0, HEX.key0, target);
      const missing = new ProductAdmissionControllerV1({ topology: 'single-provider', vault: local.vault });
      await missing.prepare(async () => ({
        legs: [{ role: 'onion', label: 'Onion', session: current.session, ...target }], close: vi.fn(),
      }));
      await missing.selectOffer('onion', { scopeIdHex: HEX.scope0, offerId: offer.offerId });
      await expect(missing.authorize('onion')).rejects.toMatchObject({
        code: 'capability-inventory-empty',
      });
      expect(current.authorize).not.toHaveBeenCalled();
      await missing.close();
    }
  });

  it('never retries an ambiguous one-shot capability spend', async () => {
    const { vault, state } = fakeVault();
    const target = { backend: 'tee-oram', workload: 'tee-oram-query' } as const;
    const bat = paidOffer(11, 'cashu-bat');
    state.inventory.set(inventoryKey(HEX.provider0, HEX.policy0, HEX.scope0, bat), 1);
    const leg = session(
      vault,
      [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [bat])],
      HEX.provider0,
      HEX.key0,
      target,
      async () => { throw new Error('response lost'); },
    );
    const controller = new ProductAdmissionControllerV1({ topology: 'single-provider', vault });
    await controller.prepare(async () => ({
      legs: [{ role: 'oram', label: 'ORAM', session: leg.session, ...target }], close: vi.fn(),
    }));
    await controller.selectOffer('oram', { scopeIdHex: HEX.scope0, offerId: 11 });
    await expect(controller.authorize('oram')).rejects.toMatchObject({
      code: 'ambiguous-capability-spend',
    });
    await expect(controller.authorize('oram')).rejects.toMatchObject({
      code: 'capability-inventory-empty',
    });
    expect(leg.authorize).toHaveBeenCalledOnce();
  });

  it('supports genuine single-provider Onion and ORAM attempts without peer metadata', async () => {
    for (const target of [
      { backend: 'onion-pir', workload: 'onion-session', role: 'onion' },
      { backend: 'tee-oram', workload: 'tee-oram-query', role: 'oram' },
    ] as const) {
      const { vault } = fakeVault();
      const offer = freeOffer(12);
      const current = session(
        vault,
        [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [offer])],
        HEX.provider0,
        HEX.key0,
        target,
      );
      const controller = new ProductAdmissionControllerV1({ topology: 'single-provider', vault });
      await controller.prepare(async () => ({
        legs: [{ label: target.role, session: current.session, ...target }],
        close: vi.fn(),
      }));
      await controller.selectOffer(target.role, { scopeIdHex: HEX.scope0, offerId: 12 });
      await controller.authorize(target.role);
      expect(controller.canQuery()).toBe(true);
      expect(current.authorize).toHaveBeenCalledOnce();
      await controller.close();
    }
  });

  it('does not touch localStorage or console with invoice, token, or query data', async () => {
    const storage = { setItem: vi.fn(() => { throw new Error('forbidden'); }) };
    vi.stubGlobal('localStorage', storage);
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const { vault } = fakeVault();
      const target = { backend: 'onion-pir', workload: 'onion-session' } as const;
      const offer = freeOffer(13);
      const current = session(vault, [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [offer])], HEX.provider0, HEX.key0, target);
      const controller = new ProductAdmissionControllerV1({ topology: 'single-provider', vault });
      await controller.prepare(async () => ({
        legs: [{ role: 'onion', label: 'Onion', session: current.session, ...target }],
        close: vi.fn(),
      }));
      await controller.selectOffer('onion', { scopeIdHex: HEX.scope0, offerId: 13 });
      await controller.authorize('onion');
      await controller.executeQuery(async () => ({ address: 'secret', result: 'secret' }));
      expect(storage.setItem).not.toHaveBeenCalled();
      expect(consoleSpy).not.toHaveBeenCalled();
    } finally {
      consoleSpy.mockRestore();
      vi.unstubAllGlobals();
    }
  });

  it('lists and redeems an exact capability from a retained signed policy', async () => {
    const { vault, state } = fakeVault();
    const target = { backend: 'tee-oram', workload: 'tee-oram-query' } as const;
    const currentOffer = freeOffer(31);
    const historicalOffer = paidOffer(32, 'cashu-bat');
    const oldDigest = '61'.repeat(32);
    state.inventory.set(
      inventoryKey(HEX.provider0, oldDigest, HEX.scope0, historicalOffer),
      1,
    );
    const current = session(
      vault,
      [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [currentOffer])],
      HEX.provider0,
      HEX.key0,
      target,
      undefined,
      retainedView(HEX.provider0, oldDigest, HEX.scope0, target, historicalOffer),
    );
    const controller = new ProductAdmissionControllerV1({ topology: 'single-provider', vault });
    await controller.prepare(async () => ({
      legs: [{ role: 'oram', label: 'ORAM', session: current.session, ...target }],
      close: vi.fn(),
    }));
    const retained = controller.snapshot().legs[0].retainedCapabilities[0];
    expect(retained).toMatchObject({ policyDigestHex: oldDigest, count: 1 });
    await controller.selectRetainedCapability('oram', retained);
    expect(controller.snapshot().legs[0].retainedSelected).toMatchObject({
      binding: { policyDigestHex: oldDigest, scheme: 'cashu-bat' },
    });
    await controller.authorize('oram');
    expect(state.takes).toBe(1);
    expect(controller.canQuery()).toBe(true);
  });

  it('resumes an encrypted BOLT11 recovery under its historical signed selector', async () => {
    const { vault, state } = fakeVault();
    const target = { backend: 'onion-pir', workload: 'onion-session' } as const;
    const currentOffer = freeOffer(33);
    const historicalOffer = paidOffer(34, 'bolt11-direct-receipt');
    const oldDigest = '62'.repeat(32);
    const recoveryId = '91'.repeat(32);
    state.recoveries.push({
      id: recoveryId,
      issuerEndpoint: historicalOffer.endpoint,
      providerIdHex: HEX.provider0,
      policyDigestHex: oldDigest,
      scopeIdHex: HEX.scope0,
      offerId: historicalOffer.offerId,
      expectedScheme: 'bolt11-direct-receipt',
      state: new Uint8Array([1]),
    });
    acquisitionMock.resume.mockResolvedValueOnce({
      recoveryId,
      ensureQuote: vi.fn(async () => 'lnbc1fixture'),
      invoice: () => 'lnbc1fixture',
      status: () => 'invoice-open',
      invoiceExpiresAtUnix: () => 9_999_999_999n,
      claimDeadlineUnix: () => 9_999_999_999n,
      pollStatus: vi.fn(async () => 'payment-settled'),
      claim: vi.fn(async () => 1),
      close: vi.fn(),
    });
    const current = session(
      vault,
      [policy(HEX.provider0, HEX.policy0, HEX.scope0, target, [currentOffer])],
      HEX.provider0,
      HEX.key0,
      target,
      undefined,
      retainedView(HEX.provider0, oldDigest, HEX.scope0, target, historicalOffer),
    );
    const controller = new ProductAdmissionControllerV1({ topology: 'single-provider', vault });
    await controller.prepare(async () => ({
      legs: [{ role: 'onion', label: 'Onion', session: current.session, ...target }],
      close: vi.fn(),
    }));
    await controller.selectRetainedRecovery('onion', recoveryId);
    await controller.resumeBolt11('onion', recoveryId);
    expect(acquisitionMock.resume).toHaveBeenCalledWith({ vault, recoveryId });
    expect(controller.snapshot().legs[0].invoice).toBe('lnbc1fixture');
  });
});
