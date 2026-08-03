import {
  AdmissionCredentialVaultV1,
  type AdmissionCapabilityBindingV1,
} from '../src/admission-vault.js';
import { Bolt11AcquisitionControllerV1 } from '../src/service-acquisition.js';
import type {
  ServiceOfferViewV1,
  ServiceScopeViewV1,
  WasmAcceptedServicePolicyV1,
} from '../src/sdk-bridge.js';
import { FakeBolt11AcquisitionV1 } from './payment-sdk-fake.js';

const PROVIDER_ID = '11'.repeat(32);
const POLICY_DIGEST = '22'.repeat(32);
const SCOPE_ID = '33'.repeat(32);
const ISSUER_ID = '44'.repeat(32);
const PAYEE = new Uint8Array([2, ...new Uint8Array(32).fill(5)]);
const OFFER_ID = 7;

const binding: AdmissionCapabilityBindingV1 = {
  providerIdHex: PROVIDER_ID,
  policyDigestHex: POLICY_DIGEST,
  scopeIdHex: SCOPE_ID,
  offerId: OFFER_ID,
  scheme: 'bolt11-direct-receipt',
};

const arcBinding: AdmissionCapabilityBindingV1 = {
  ...binding,
  offerId: OFFER_ID + 1,
  scheme: 'arc-experimental',
};

const offer: ServiceOfferViewV1 = {
  offerId: OFFER_ID,
  acquisition: 'bolt11',
  authorization: 'bolt11-direct-receipt',
  freeMode: 'not-free',
  verification: 'provider-local',
  deploymentStatus: 'stable',
  priorityClass: 1,
  price: { kind: 'msat', amount: '1000' },
  issuerIdHex: ISSUER_ID,
  keyIdHex: '55'.repeat(16),
  batVerificationKeyFingerprintHex: '',
  arcVerificationKeyFingerprintHex: '',
  endpoint: location.origin,
  credentialCount: 1,
  credentialPresentationLimit: 1,
  privacyLeakageBits: 1,
};

const scope: ServiceScopeViewV1 = {
  scopeIdHex: SCOPE_ID,
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
  offers: [offer],
};

const policy: WasmAcceptedServicePolicyV1 = {
  providerIdHex: PROVIDER_ID,
  policyDigestHex: POLICY_DIGEST,
  policyEpoch: '1',
  expiresAtUnix: '9999999999',
  free: () => undefined,
  checkpointBytes: () => new Uint8Array([1]),
  acknowledgeCheckpointPersisted: () => undefined,
  validateAuthorizationProof: () => undefined,
  importStandardCashuToken: () => new Uint8Array([1]),
  offersJson: () => ({
    providerIdHex: PROVIDER_ID,
    policyDigestHex: POLICY_DIGEST,
    policyEpoch: '1',
    expiresAtUnix: '9999999999',
    scopes: [scope],
  }),
  beginBolt11Acquisition: () => new FakeBolt11AcquisitionV1(),
};

let vaultPromise: Promise<AdmissionCredentialVaultV1> | null = null;
let activeAcquisition: Bolt11AcquisitionControllerV1 | null = null;

function vault(): Promise<AdmissionCredentialVaultV1> {
  vaultPromise ??= AdmissionCredentialVaultV1.open();
  return vaultPromise;
}

const api = {
  async putCapability(payload: number[]): Promise<void> {
    await (await vault()).putCapability({
      ...binding,
      payload: Uint8Array.from(payload),
    });
  },

  async countCapabilities(): Promise<number> {
    return (await vault()).countCapabilities(binding);
  },

  async putArcCredential(remaining: number): Promise<void> {
    await (await vault()).putCapability({
      ...arcBinding,
      payload: new Uint8Array([remaining]),
    });
  },

  async countArcCredentials(): Promise<number> {
    return (await vault()).countCapabilities(arcBinding);
  },

  async advanceArcCredential(): Promise<number[] | null> {
    const presentation = await (await vault()).advanceArcCredential(
      arcBinding,
      (state) => {
        if (state.length !== 1 || state[0] === 0) {
          throw new Error('invalid ARC fixture state');
        }
        const current = state[0];
        const remaining = current - 1;
        let terminal = false;
        return {
          nextState: new Uint8Array([remaining]),
          remaining,
          releaseAfterPersisted: () => {
            if (terminal) throw new Error('ARC fixture transition is terminal');
            terminal = true;
            return new Uint8Array([current]);
          },
          discard: () => { terminal = true; },
        };
      },
    );
    return presentation ? Array.from(presentation) : null;
  },

  async takeCapability(): Promise<number[] | null> {
    const capability = await (await vault()).takeSingleUseCapability(
      binding,
      (payload) => {
        if (payload.length === 0) throw new Error('empty capability');
      },
    );
    return capability ? Array.from(capability.payload) : null;
  },

  async rejectReservedCapability(): Promise<string> {
    try {
      await (await vault()).takeSingleUseCapability(binding, () => {
        throw new Error('fixture validation rejected before commit');
      });
      return 'unexpected success';
    } catch (error) {
      return (error as Error).message;
    }
  },

  async startSettledAcquisition(): Promise<{
    recoveryId: string;
    invoice: string;
    status: string;
  }> {
    activeAcquisition?.close();
    activeAcquisition = await Bolt11AcquisitionControllerV1.start({
      vault: await vault(),
      policy,
      scope,
      offer,
      network: 'bitcoin',
      expectedPayeePubkey: PAYEE,
      allowInsecureLoopback: true,
      assertReady: () => {},
    });
    await activeAcquisition.pollStatus();
    return {
      recoveryId: activeAcquisition.recoveryId,
      invoice: activeAcquisition.invoice(),
      status: activeAcquisition.status(),
    };
  },

  async claimActive(): Promise<{ ok: true; count: number } | { ok: false; error: string }> {
    if (!activeAcquisition) return { ok: false, error: 'no active acquisition' };
    try {
      return { ok: true, count: await activeAcquisition.claim() };
    } catch (error) {
      return { ok: false, error: (error as Error).message };
    }
  },

  async resumeAndClaim(
    recoveryId: string,
  ): Promise<{ ok: true; count: number } | { ok: false; error: string }> {
    try {
      const acquisition = await Bolt11AcquisitionControllerV1.resume({
        vault: await vault(),
        recoveryId,
        issuerEndpoint: offer.endpoint,
        issuerIdHex: offer.issuerIdHex,
        network: 'bitcoin',
        expectedPayeePubkey: PAYEE,
        allowInsecureLoopback: true,
        assertReady: () => {},
      });
      try {
        return { ok: true, count: await acquisition.claim() };
      } finally {
        acquisition.close();
      }
    } catch (error) {
      return { ok: false, error: (error as Error).message };
    }
  },

  async recoveryCount(): Promise<number> {
    return (await vault()).listBolt11Recoveries().then((rows) => rows.length);
  },

  localStorageSnapshot(): Record<string, string> {
    return Object.fromEntries(
      Array.from({ length: localStorage.length }, (_, index) => localStorage.key(index))
        .filter((key): key is string => key !== null)
        .map((key) => [key, localStorage.getItem(key) ?? '']),
    );
  },
};

declare global {
  interface Window {
    paymentVaultTest: typeof api;
    __paymentLocalStorageWrites?: Array<[string, string]>;
  }
}

window.paymentVaultTest = api;
window.addEventListener('pagehide', () => {
  activeAcquisition?.close();
  activeAcquisition = null;
  void vaultPromise?.then((opened) => opened.close());
  vaultPromise = null;
});
document.documentElement.dataset.paymentVaultReady = 'true';
