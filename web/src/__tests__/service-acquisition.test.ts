import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({ sdk: {} as Record<string, unknown> }));

vi.mock('../sdk-bridge.js', () => ({
  requireSdkWasm: () => mocked.sdk,
}));

import type { AdmissionCredentialVaultV1 } from '../admission-vault.js';
import {
  Bolt11AcquisitionControllerV1,
  fetchQuoteKeyDelegationV1,
} from '../service-acquisition.js';
import type {
  ServiceOfferViewV1,
  ServiceScopeViewV1,
  WasmAcceptedServicePolicyV1,
} from '../sdk-bridge.js';

const providerHex = '11'.repeat(32);
const issuerHex = '22'.repeat(32);
const scopeHex = '33'.repeat(32);
const payee = new Uint8Array([2, ...new Uint8Array(32).fill(4)]);
const recoveryId = '55'.repeat(32);

class FakeAcquisition {
  hasQuote: boolean;
  status: string;
  claimMarker: number;
  free = vi.fn();

  constructor(state?: Uint8Array) {
    this.hasQuote = state?.[0] === 2;
    this.status = state?.[1] === 2 ? 'payment-settled' : 'invoice-open';
    this.claimMarker = state?.[2] ?? 0;
  }

  quote_intent_bytes = () => new Uint8Array([1, 2]);
  quote_key_checkpoint_bytes = () => new Uint8Array([7, 7]);
  recovery_state_bytes = () => new Uint8Array([
    this.hasQuote ? 2 : 1,
    this.status === 'payment-settled' ? 2 : 1,
    this.claimMarker,
  ]);
  accept_initial_quote = () => { this.hasQuote = true; };
  invoice = () => {
    if (!this.hasQuote) throw new Error('no quote');
    return 'lnbc1verified';
  };
  quote_id_hex = () => '66'.repeat(32);
  quote_status = () => this.status;
  invoice_expires_at_unix = () => '9999999999';
  claim_deadline_unix = () => '9999999999';
  build_status_request = () => new Uint8Array([3, 4]);
  accept_status = () => { this.status = 'payment-settled'; };
  prepare_claim = () => {
    if (this.claimMarker === 0) this.claimMarker = 9;
    return new Uint8Array([8, this.claimMarker]);
  };
  finish_claim = () => ({
    free: vi.fn(),
    scheme: 'bolt11-direct-receipt',
    count: () => 1,
    capability: () => new Uint8Array([10, 11]),
  });
}

function signedOffer(): ServiceOfferViewV1 {
  return {
    offerId: 7,
    acquisition: 'bolt11',
    authorization: 'bolt11-direct-receipt',
    freeMode: 'not-free',
    verification: 'provider-local',
    deploymentStatus: 'stable',
    priorityClass: 1,
    price: { kind: 'msat', amount: '1000' },
    issuerIdHex: issuerHex,
    keyIdHex: '44'.repeat(16),
    batVerificationKeyFingerprintHex: '',
    endpoint: 'https://issuer.example',
    credentialCount: 1,
    credentialPresentationLimit: 1,
    privacyLeakageBits: 1,
  };
}

function signedScope(offer: ServiceOfferViewV1): ServiceScopeViewV1 {
  return {
    scopeIdHex: scopeHex,
    backend: 'dpf-pir',
    workload: 'dpf-query',
    protocolVersion: 1,
    operationProfile: 1,
    entitlementProfile: 1,
    offers: [offer],
  };
}

describe('BOLT11 acquisition HTTP and recovery ordering', () => {
  beforeEach(() => {
    mocked.sdk = {
      initial_bolt11_quote_key_checkpoint_v1: () => new Uint8Array([1]),
      WasmBolt11AcquisitionV1: { restore: (state: Uint8Array) => new FakeAcquisition(state) },
    };
  });

  it('fetches current and retained delegations without cookies and rejects a wrong type', async () => {
    const fetchMock = vi.fn(async (url: string, init: RequestInit) => {
      expect(init.credentials).toBe('omit');
      expect(init.redirect).toBe('error');
      expect(init.referrerPolicy).toBe('no-referrer');
      return new Response(new Uint8Array([1, 2, 3]), {
        headers: { 'Content-Type':
          'application/vnd.bitcoinpir.bolt11-quote-key-delegation-v1' },
      });
    });
    const fetchImpl = fetchMock as unknown as typeof fetch;

    await expect(fetchQuoteKeyDelegationV1(
      'https://issuer.example', undefined, fetchImpl,
    )).resolves.toEqual(new Uint8Array([1, 2, 3]));
    await expect(fetchQuoteKeyDelegationV1(
      'https://issuer.example', 'aa'.repeat(16), fetchImpl,
    )).resolves.toEqual(new Uint8Array([1, 2, 3]));
    expect(fetchMock.mock.calls[0][0]).toBe('https://issuer.example/v1/quote-keys/current');
    expect(fetchMock.mock.calls[1][0]).toBe(
      `https://issuer.example/v1/quote-keys/${'aa'.repeat(16)}`,
    );

    const bad = vi.fn(async () => new Response(new Uint8Array([1]), {
      headers: { 'Content-Type': 'application/octet-stream' },
    })) as unknown as typeof fetch;
    await expect(fetchQuoteKeyDelegationV1('https://issuer.example', undefined, bad))
      .rejects.toThrow(/content type/);
  });

  it('enforces the canonical response bound while streaming without Content-Length', async () => {
    const oversized = vi.fn(async () => new Response(new Uint8Array(257), {
      headers: {
        'Content-Type': 'application/vnd.bitcoinpir.bolt11-quote-key-delegation-v1',
      },
    })) as unknown as typeof fetch;
    await expect(fetchQuoteKeyDelegationV1(
      'https://issuer.example', undefined, oversized,
    )).rejects.toThrow(/exceeds its V1 bound/);

    const compressed = vi.fn(async () => new Response(new Uint8Array([1]), {
      headers: {
        'Content-Type': 'application/vnd.bitcoinpir.bolt11-quote-key-delegation-v1',
        'Content-Encoding': 'gzip',
      },
    })) as unknown as typeof fetch;
    await expect(fetchQuoteKeyDelegationV1(
      'https://issuer.example', undefined, compressed,
    )).rejects.toThrow(/content encoding/);
  });

  it('aborts a stalled issuer request at the configured hard deadline', async () => {
    vi.useFakeTimers();
    try {
      const stalled = vi.fn((_url: string, init: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => {
            reject(new DOMException('aborted', 'AbortError'));
          }, { once: true });
        })) as unknown as typeof fetch;
      const pending = fetchQuoteKeyDelegationV1(
        'https://issuer.example', undefined, stalled, false, 1_000,
      );
      const rejected = expect(pending).rejects.toThrow(/aborted/);
      await vi.advanceTimersByTimeAsync(1_000);
      await rejected;
      expect(stalled).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });

  it('persists rollback/recovery before invoice and persists exact claim before POST', async () => {
    const events: string[] = [];
    const acquisition = new FakeAcquisition();
    const offer = signedOffer();
    const scope = signedScope(offer);
    const policy = {
      free: vi.fn(),
      providerIdHex: providerHex,
      policyDigestHex: '77'.repeat(32),
      policyEpoch: '1',
      expiresAtUnix: '9999999999',
      checkpointBytes: () => new Uint8Array([1]),
      acknowledgeCheckpointPersisted: vi.fn(),
      validateAuthorizationProof: vi.fn(),
      offersJson: vi.fn(),
      beginBolt11Acquisition: () => acquisition,
    } as unknown as WasmAcceptedServicePolicyV1;
    let storedRecovery: Record<string, any> | null = null;
    let lockTail = Promise.resolve<unknown>(undefined);
    const vault = {
      advanceQuoteKeyCheckpoint: async (
        _issuer: string,
        _network: string,
        _payee: string,
        initial: Uint8Array,
        advance: (checkpoint: Uint8Array) => Promise<unknown> | unknown,
      ) => {
        const result = await advance(initial) as {
          nextCheckpoint: Uint8Array;
          value: FakeAcquisition;
        };
        expect(result.nextCheckpoint).toEqual(new Uint8Array([7, 7]));
        events.push('quote-key-checkpoint');
        return result.value;
      },
      createBolt11Recovery: async (record: Record<string, unknown>) => {
        events.push('create-recovery');
        storedRecovery = { ...record, id: recoveryId };
        return { ...storedRecovery };
      },
      withBolt11Recovery: async (_id: string, operation: Function) => {
        const run = async () => {
          if (!storedRecovery) throw new Error('recovery complete');
          const exposed = { ...storedRecovery, state: storedRecovery.state.slice() };
          return operation(exposed, {
            persistState: async (state: Uint8Array) => {
              events.push('update-recovery');
              exposed.state = state.slice();
              storedRecovery!.state = state.slice();
            },
            complete: async (capabilities: unknown[]) => {
              events.push('complete-atomic');
              expect(capabilities).toHaveLength(1);
              storedRecovery = null;
              return ['88'.repeat(32)];
            },
          });
        };
        const result = lockTail.then(run, run);
        lockTail = result.then(() => undefined, () => undefined);
        return result;
      },
    } as unknown as AdmissionCredentialVaultV1;
    const fetchImpl = vi.fn(async (url: string, init: RequestInit) => {
      if (url.endsWith('/v1/quote-keys/current')) {
        events.push('get-delegation');
        return binaryResponse(
          [1], 'application/vnd.bitcoinpir.bolt11-quote-key-delegation-v1',
        );
      }
      if (url.endsWith('/v1/quotes/bolt11')) {
        events.push('post-quote');
        expect(new Uint8Array(init.body as ArrayBuffer)).toEqual(new Uint8Array([1, 2]));
        return binaryResponse([2], 'application/vnd.bitcoinpir.bolt11-quote-v1');
      }
      if (url.endsWith('/status')) {
        events.push('post-status');
        return binaryResponse([3], 'application/vnd.bitcoinpir.bolt11-quote-v1');
      }
      if (url.endsWith('/claim')) {
        events.push('post-claim');
        expect(new Uint8Array(init.body as ArrayBuffer)).toEqual(new Uint8Array([8, 9]));
        expect(events.at(-2)).toBe('update-recovery');
        return binaryResponse(
          [4], 'application/vnd.bitcoinpir.credential-issuance-response-v1',
        );
      }
      throw new Error(`unexpected URL ${url}`);
    }) as unknown as typeof fetch;

    const controller = await Bolt11AcquisitionControllerV1.start({
      vault,
      policy,
      scope,
      offer,
      network: 'bitcoin',
      expectedPayeePubkey: payee,
      fetchImpl,
    });
    expect(controller.invoice()).toBe('lnbc1verified');
    expect(events.indexOf('quote-key-checkpoint')).toBeLessThan(events.indexOf('post-quote'));
    expect(events.indexOf('create-recovery')).toBeLessThan(events.indexOf('post-quote'));
    await expect(controller.pollStatus()).resolves.toBe('payment-settled');
    await expect(controller.claim()).resolves.toBe(1);
    expect(events.at(-1)).toBe('complete-atomic');
  });

  it('replays the exact claim after response loss and prevents a queued stale poll overwrite', async () => {
    const acquisition = new FakeAcquisition();
    const selectedOffer = signedOffer();
    const selectedScope = signedScope(selectedOffer);
    const policy = {
      free: vi.fn(),
      providerIdHex: providerHex,
      policyDigestHex: '77'.repeat(32),
      policyEpoch: '1',
      expiresAtUnix: '9999999999',
      checkpointBytes: () => new Uint8Array([1]),
      acknowledgeCheckpointPersisted: vi.fn(),
      validateAuthorizationProof: vi.fn(),
      offersJson: vi.fn(),
      beginBolt11Acquisition: () => acquisition,
    } as unknown as WasmAcceptedServicePolicyV1;
    let storedRecovery: Record<string, any> | null = null;
    let lockTail = Promise.resolve<unknown>(undefined);
    const vault = {
      advanceQuoteKeyCheckpoint: async (
        _issuer: string,
        _network: string,
        _payee: string,
        initial: Uint8Array,
        advance: (checkpoint: Uint8Array) => Promise<unknown> | unknown,
      ) => (await advance(initial) as { value: FakeAcquisition }).value,
      createBolt11Recovery: async (record: Record<string, unknown>) => {
        storedRecovery = { ...record, id: recoveryId };
        return { ...storedRecovery, state: storedRecovery.state.slice() };
      },
      getBolt11Recovery: async () => storedRecovery
        ? { ...storedRecovery, state: storedRecovery.state.slice() }
        : null,
      withBolt11Recovery: async (_id: string, operation: Function) => {
        const run = async () => {
          if (!storedRecovery) throw new Error('BOLT11 recovery record was not found');
          const exposed = { ...storedRecovery, state: storedRecovery.state.slice() };
          return operation(exposed, {
            persistState: async (state: Uint8Array) => {
              exposed.state = state.slice();
              storedRecovery!.state = state.slice();
            },
            complete: async () => {
              storedRecovery = null;
              return ['88'.repeat(32)];
            },
          });
        };
        const result = lockTail.then(run, run);
        lockTail = result.then(() => undefined, () => undefined);
        return result;
      },
    } as unknown as AdmissionCredentialVaultV1;

    const claimBodies: Uint8Array[] = [];
    let claimAttempt = 0;
    let statusRequests = 0;
    let releaseSecondClaim!: () => void;
    let markSecondClaimEntered!: () => void;
    const secondClaimGate = new Promise<void>((resolve) => { releaseSecondClaim = resolve; });
    const secondClaimEntered = new Promise<void>((resolve) => { markSecondClaimEntered = resolve; });
    const fetchImpl = vi.fn(async (url: string, init: RequestInit) => {
      if (url.endsWith('/v1/quote-keys/current')) {
        return binaryResponse(
          [1], 'application/vnd.bitcoinpir.bolt11-quote-key-delegation-v1',
        );
      }
      if (url.endsWith('/v1/quotes/bolt11')) {
        return binaryResponse([2], 'application/vnd.bitcoinpir.bolt11-quote-v1');
      }
      if (url.endsWith('/status')) {
        statusRequests += 1;
        return binaryResponse([3], 'application/vnd.bitcoinpir.bolt11-quote-v1');
      }
      if (url.endsWith('/claim')) {
        claimAttempt += 1;
        claimBodies.push(new Uint8Array(init.body as ArrayBuffer));
        if (claimAttempt === 1) throw new Error('response lost after issuer commit');
        markSecondClaimEntered();
        await secondClaimGate;
        return binaryResponse(
          [4], 'application/vnd.bitcoinpir.credential-issuance-response-v1',
        );
      }
      throw new Error(`unexpected URL ${url}`);
    }) as unknown as typeof fetch;

    const started = await Bolt11AcquisitionControllerV1.start({
      vault,
      policy,
      scope: selectedScope,
      offer: selectedOffer,
      network: 'bitcoin',
      expectedPayeePubkey: payee,
      fetchImpl,
    });
    await started.pollStatus();
    await expect(started.claim()).rejects.toThrow(/response lost/);

    const resumedClaim = await Bolt11AcquisitionControllerV1.resume({
      vault,
      recoveryId,
      fetchImpl,
    });
    const stalePoll = await Bolt11AcquisitionControllerV1.resume({
      vault,
      recoveryId,
      fetchImpl,
    });
    const claim = resumedClaim.claim();
    await secondClaimEntered;
    const poll = stalePoll.pollStatus();
    await Promise.resolve();
    expect(statusRequests).toBe(1);
    releaseSecondClaim();
    await expect(claim).resolves.toBe(1);
    await expect(poll).rejects.toThrow(/not found/);
    expect(claimBodies).toHaveLength(2);
    expect(claimBodies[1]).toEqual(claimBodies[0]);
    expect(statusRequests).toBe(1);
  });
});

function binaryResponse(bytes: number[], contentType: string): Response {
  return new Response(new Uint8Array(bytes), { headers: { 'Content-Type': contentType } });
}
