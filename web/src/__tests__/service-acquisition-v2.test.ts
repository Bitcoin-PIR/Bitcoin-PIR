import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({ sdk: {} as Record<string, unknown> }));

vi.mock('../sdk-bridge.js', () => ({
  requireSdkWasm: () => mocked.sdk,
}));

import type {
  BatV2RecoveryRecordV2,
  BatV2WalletRecordV2,
  LockedBatV2RecoveryV2,
} from '../bat-v2-vault.js';
import {
  BatV2AcquisitionControllerV2,
  BatV2RecoveryRequiredErrorV2,
} from '../service-acquisition-v2.js';
import type {
  ServiceOfferViewV1,
  ServiceScopeViewV1,
  WasmAcceptedServicePolicyV1,
  WasmBolt11BatV2AcquisitionV2,
} from '../sdk-bridge.js';

const issuerIdHex = '11'.repeat(32);
const scopeIdHex = '22'.repeat(32);
const classIdHex = '33'.repeat(32);
const classDigestHex = '44'.repeat(32);
const batKeyIdHex = '55'.repeat(32);
const recoveryId = '66'.repeat(32);
const payee = new Uint8Array([2, ...new Uint8Array(32).fill(7)]);
const delegationType = 'application/vnd.bitcoinpir.bolt11-quote-key-delegation-v1';
const quoteType = 'application/vnd.bitcoinpir.bolt11-quote-v1';
const quoteIntentType = 'application/vnd.bitcoinpir.bat-v2-bolt11-quote-intent-v2';
const statusType = 'application/vnd.bitcoinpir.bolt11-quote-status-request-v1';
const claimType = 'application/vnd.bitcoinpir.bat-v2-bolt11-quote-claim-envelope-v2';
const issuanceType = 'application/vnd.bitcoinpir.bat-v2-issuance-response-v2';

class FakeBatV2Acquisition implements WasmBolt11BatV2AcquisitionV2 {
  hasQuote: boolean;
  settled: boolean;
  claimPrepared: boolean;
  free = vi.fn();

  constructor(state: Uint8Array = new Uint8Array([0, 0, 0])) {
    this.hasQuote = state[0] === 1;
    this.settled = state[1] === 1;
    this.claimPrepared = state[2] === 1;
  }

  quoteIntentBytes = () => new Uint8Array([1, 2, 3]);
  quoteKeyCheckpointBytes = () => new Uint8Array([8, 8]);
  recoveryStateBytes = () => new Uint8Array([
    this.hasQuote ? 1 : 0,
    this.settled ? 1 : 0,
    this.claimPrepared ? 1 : 0,
  ]);
  acceptInitialQuote = () => { this.hasQuote = true; };
  invoice = () => {
    if (!this.hasQuote) throw new Error('no quote');
    return 'lnbc1batv2';
  };
  quoteIdHex = () => '77'.repeat(32);
  quoteStatus = () => this.settled ? 'payment-settled' as const : 'invoice-open' as const;
  invoiceExpiresAtUnix = () => '9999999999';
  claimDeadlineUnix = () => '9999999999';
  buildStatusRequest = () => new Uint8Array([4, 5]);
  acceptStatus = () => { this.settled = true; };
  prepareClaim = () => {
    this.claimPrepared = true;
    return new Uint8Array([6, 7]);
  };
  finishClaim = () => ({
    free: vi.fn(),
    count: () => 1,
    proof: () => new Uint8Array(210).fill(9),
    globalSpendKeyHex: () => '88'.repeat(32),
    classBindingJson: () => ({
      issuerIdHex,
      classIdHex,
      classDigestHex,
      classKeyEpoch: '4',
      batKeyIdHex,
    }),
  });
}

class FakeVault {
  recovery: BatV2RecoveryRecordV2 | null = null;
  completed: BatV2WalletRecordV2[] | null = null;
  createdWithoutProviderCoordinates = false;
  advanceQuoteKeyCheckpoint = vi.fn(async (
    _issuerIdHex: string,
    _network: string,
    _payeeHex: string,
    initial: Uint8Array,
    advance: (checkpoint: Uint8Array) => {
      nextCheckpoint: Uint8Array;
      value: WasmBolt11BatV2AcquisitionV2;
    },
  ) => advance(initial).value);

  createRecovery = vi.fn(async (value: Omit<BatV2RecoveryRecordV2, 'id'>) => {
    this.createdWithoutProviderCoordinates = !('providerIdHex' in value)
      && !('policyDigestHex' in value)
      && !('scopeIdHex' in value)
      && !('offerId' in value);
    this.recovery = { ...value, id: recoveryId, state: value.state.slice() };
    return cloneRecovery(this.recovery);
  });

  getRecovery = vi.fn(async (id: string) =>
    this.recovery?.id === id ? cloneRecovery(this.recovery) : null);

  async withRecovery<T>(
    id: string,
    operation: (
      recovery: BatV2RecoveryRecordV2,
      locked: LockedBatV2RecoveryV2,
    ) => Promise<T>,
  ): Promise<T> {
    if (!this.recovery || this.recovery.id !== id) throw new Error('recovery missing');
    const exposed = cloneRecovery(this.recovery);
    let terminal = false;
    const locked: LockedBatV2RecoveryV2 = {
      persistState: async (state) => {
        if (terminal || !this.recovery) throw new Error('terminal');
        this.recovery.state.fill(0);
        this.recovery.state = state.slice();
        exposed.state.fill(0);
        exposed.state = state.slice();
      },
      complete: async (records) => {
        if (terminal) throw new Error('terminal');
        terminal = true;
        this.completed = records.map((record) => ({ ...record, proof: record.proof.slice() }));
        this.recovery = null;
        return records.map((_record, index) => (index + 1).toString(16).padStart(64, '0'));
      },
    };
    return operation(exposed, locked);
  }
}

beforeEach(() => {
  mocked.sdk = {
    initial_bolt11_quote_key_checkpoint_v1: () => new Uint8Array([1]),
    WasmBolt11BatV2AcquisitionV2: {
      restore: (state: Uint8Array) => new FakeBatV2Acquisition(state),
    },
  };
});

describe('BAT V2 class-bound acquisition and recovery', () => {
  it('uses the verified member entry and exactly one request per quote/status/claim method', async () => {
    const vault = new FakeVault();
    const offer = signedOffer();
    const scope = signedScope(offer);
    const classBytes = new Uint8Array([10, 11, 12]);
    const begin = vi.fn((
      scopeBytes: Uint8Array,
      offerId: number,
      receivedClass: Uint8Array,
    ) => {
      expect(bytesToHex(scopeBytes)).toBe(scopeIdHex);
      expect(offerId).toBe(7);
      expect(receivedClass).toEqual(classBytes);
      return new FakeBatV2Acquisition();
    });
    const requests: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = vi.fn(async (url: string, init: RequestInit = {}) => {
      requests.push({ url, init });
      if (url.endsWith('/v1/quote-keys/current')) {
        return binaryResponse(delegationType, [1]);
      }
      if (url.endsWith('/v2/quotes/bolt11')) return binaryResponse(quoteType, [2]);
      if (url.endsWith('/status')) return binaryResponse(quoteType, [3]);
      if (url.endsWith('/claim')) return binaryResponse(issuanceType, [4]);
      throw new Error(`unexpected URL ${url}`);
    }) as unknown as typeof fetch;

    const controller = await BatV2AcquisitionControllerV2.start({
      vault: vault as never,
      policy: signedPolicy(begin),
      scope,
      offer,
      classBytes,
      network: 'signet',
      expectedPayeePubkey: payee,
      fetchImpl,
      assertReady: () => undefined,
    });

    expect(begin).toHaveBeenCalledOnce();
    expect(vault.createdWithoutProviderCoordinates).toBe(true);
    expect(requests).toHaveLength(2);
    expect(requests[1].url).toBe('https://issuer.example/v2/quotes/bolt11');
    expect(contentType(requests[1].init)).toBe(quoteIntentType);
    expect(acceptType(requests[1].init)).toBe(quoteType);
    await expect(controller.ensureQuote()).resolves.toBe('lnbc1batv2');
    expect(requests).toHaveLength(2);

    await expect(controller.pollStatus()).resolves.toBe('payment-settled');
    expect(requests).toHaveLength(3);
    expect(requests[2].url).toBe(`https://issuer.example/v2/quotes/${'77'.repeat(32)}/status`);
    expect(contentType(requests[2].init)).toBe(statusType);
    expect(acceptType(requests[2].init)).toBe(quoteType);

    await expect(controller.claim()).resolves.toBe(1);
    expect(requests).toHaveLength(4);
    expect(requests[3].url).toBe(`https://issuer.example/v2/quotes/${'77'.repeat(32)}/claim`);
    expect(contentType(requests[3].init)).toBe(claimType);
    expect(acceptType(requests[3].init)).toBe(issuanceType);
    expect(vault.recovery).toBeNull();
    expect(vault.completed).toEqual([{
      issuerIdHex,
      classIdHex,
      classDigestHex,
      classKeyEpoch: '4',
      batKeyIdHex,
      proof: new Uint8Array(210).fill(9),
      globalSpendKeyHex: '88'.repeat(32),
    }]);
    controller.close();
  });

  it('returns the exact durable recovery after a lost quote response and resumes without I/O', async () => {
    const vault = new FakeVault();
    const firstFetch = vi.fn(async (url: string, init: RequestInit = {}) => {
      if (url.endsWith('/v1/quote-keys/current')) return binaryResponse(delegationType, [1]);
      expect(contentType(init)).toBe(quoteIntentType);
      throw new Error('response lost');
    }) as unknown as typeof fetch;
    const offer = signedOffer();

    const failure = await BatV2AcquisitionControllerV2.start({
      vault: vault as never,
      policy: signedPolicy(() => new FakeBatV2Acquisition()),
      scope: signedScope(offer),
      offer,
      classBytes: new Uint8Array([1]),
      network: 'signet',
      expectedPayeePubkey: payee,
      fetchImpl: firstFetch,
      assertReady: () => undefined,
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(BatV2RecoveryRequiredErrorV2);
    expect((failure as BatV2RecoveryRequiredErrorV2).recoveryId).toBe(recoveryId);
    expect(firstFetch).toHaveBeenCalledTimes(2);
    expect(vault.recovery?.id).toBe(recoveryId);

    const resumeFetch = vi.fn(async (url: string) => {
      expect(url).toBe('https://issuer.example/v2/quotes/bolt11');
      return binaryResponse(quoteType, [2]);
    }) as unknown as typeof fetch;
    const resumed = await BatV2AcquisitionControllerV2.resume({
      vault: vault as never,
      recoveryId,
      issuerEndpoint: 'https://issuer.example',
      issuerIdHex,
      network: 'signet',
      expectedPayeePubkey: payee,
      fetchImpl: resumeFetch,
      assertReady: () => undefined,
    });
    expect(resumeFetch).not.toHaveBeenCalled();
    await expect(resumed.ensureQuote()).resolves.toBe('lnbc1batv2');
    expect(resumeFetch).toHaveBeenCalledOnce();
    resumed.close();
  });

  it('rechecks strict-session readiness after delegation and sends no quote POST', async () => {
    const vault = new FakeVault();
    let ready = true;
    const fetchImpl = vi.fn(async (url: string) => {
      expect(url).toBe('https://issuer.example/v1/quote-keys/current');
      ready = false;
      return binaryResponse(delegationType, [1]);
    }) as unknown as typeof fetch;
    const offer = signedOffer();

    await expect(BatV2AcquisitionControllerV2.start({
      vault: vault as never,
      policy: signedPolicy(() => new FakeBatV2Acquisition()),
      scope: signedScope(offer),
      offer,
      classBytes: new Uint8Array([1]),
      network: 'signet',
      expectedPayeePubkey: payee,
      fetchImpl,
      assertReady: () => {
        if (!ready) throw new Error('strict pair rotated');
      },
    })).rejects.toThrow(/strict pair rotated/);
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(vault.createRecovery).not.toHaveBeenCalled();
  });
});

function signedOffer(): ServiceOfferViewV1 {
  return {
    offerId: 7,
    acquisition: 'bolt11',
    authorization: 'cashu-bat-v2',
    freeMode: 'not-free',
    verification: 'shared-issuer-online',
    deploymentStatus: 'stable',
    priorityClass: 1,
    price: { kind: 'msat', amount: '1000' },
    issuerIdHex,
    keyIdHex: '99'.repeat(16),
    batVerificationKeyFingerprintHex: 'aa'.repeat(32),
    arcVerificationKeyFingerprintHex: '',
    endpoint: 'https://issuer.example',
    credentialCount: 2,
    credentialPresentationLimit: 1,
    privacyLeakageBits: 1,
  };
}

function signedScope(offer: ServiceOfferViewV1): ServiceScopeViewV1 {
  return {
    scopeIdHex,
    backend: 'dpf-pir',
    workload: 'dpf-query',
    protocolVersion: 1,
    operationProfile: 1,
    entitlementProfile: 1,
    dataset: { kind: 'manifest-root', rootHex: 'ab'.repeat(32) },
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
}

function signedPolicy(
  begin: NonNullable<WasmAcceptedServicePolicyV1['beginBatV2Acquisition']>,
): WasmAcceptedServicePolicyV1 {
  return {
    free: vi.fn(),
    providerIdHex: 'bc'.repeat(32),
    policyDigestHex: 'cd'.repeat(32),
    policyEpoch: '1',
    expiresAtUnix: '9999999999',
    checkpointBytes: () => new Uint8Array([1]),
    acknowledgeCheckpointPersisted: vi.fn(),
    validateAuthorizationProof: vi.fn(),
    importStandardCashuToken: vi.fn(),
    offersJson: vi.fn(),
    beginBolt11Acquisition: () => { throw new Error('wrong acquisition path'); },
    beginBatV2Acquisition: begin,
  };
}

function binaryResponse(contentTypeValue: string, bytes: number[]): Response {
  return new Response(new Uint8Array(bytes), {
    headers: { 'Content-Type': contentTypeValue },
  });
}

function contentType(init: RequestInit): string | null {
  return new Headers(init.headers).get('Content-Type');
}

function acceptType(init: RequestInit): string | null {
  return new Headers(init.headers).get('Accept');
}

function cloneRecovery(value: BatV2RecoveryRecordV2): BatV2RecoveryRecordV2 {
  return { ...value, state: value.state.slice() };
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
