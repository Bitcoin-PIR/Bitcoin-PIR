import {
  AdmissionCredentialVaultV1,
  type AdmissionCapabilityBindingV1,
} from '../src/admission-vault.js';
import { hexToBytes } from '../src/hash.js';
import {
  Bolt11AcquisitionControllerV1,
  type Bolt11AcquisitionHandleV1,
} from '../src/service-acquisition.js';
import {
  initSdkWasm,
  requireSdkWasm,
  type ServiceOfferViewV1,
  type ServicePolicyViewV1,
  type ServiceScopeViewV1,
  type WasmAcceptedServicePolicyV1,
} from '../src/sdk-bridge.js';

const CT_FAKE_SETTLEMENT = 'application/vnd.bitcoinpir.fake-settlement-v1';
const SERVICE_POLICY_RESPONSE_OPCODE = 0x0d;
const SERVICE_PROTOCOL_VERSION = 1;

export interface RealIssuerHarnessFixtureV1 {
  providerIdHex: string;
  policySigningPubkeyHex: string;
  expectedPayeePubkeyHex: string;
  policyBytes: number[];
  issuerOrigin: string;
  settlementMode: 'fake' | 'external';
}

let vaultPromise: Promise<AdmissionCredentialVaultV1> | null = null;
let acceptedPolicy: WasmAcceptedServicePolicyV1 | null = null;
let selectedScope: ServiceScopeViewV1 | null = null;
let selectedOffer: ServiceOfferViewV1 | null = null;
let expectedPayee: Uint8Array | null = null;
let issuerOrigin = '';
let settlementMode: RealIssuerHarnessFixtureV1['settlementMode'] = 'fake';
let activeAcquisition: Bolt11AcquisitionHandleV1 | null = null;
let loseNextClaimResponse = false;
const settledQuotes = new Set<string>();

function vault(): Promise<AdmissionCredentialVaultV1> {
  vaultPromise ??= AdmissionCredentialVaultV1.open();
  return vaultPromise;
}

async function initialize(
  fixture: RealIssuerHarnessFixtureV1,
  authorization: 'bolt11-direct-receipt' | 'cashu-bat' | 'arc-experimental' =
    'bolt11-direct-receipt',
): Promise<{
  providerIdHex: string;
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  offerEndpoint: string;
}> {
  if (!await initSdkWasm()) throw new Error('real pir-sdk-wasm failed to initialize');
  const sdk = requireSdkWasm();
  const providerId = exactHexBytes('providerIdHex', fixture.providerIdHex, 32);
  const policySigningKey = exactHexBytes(
    'policySigningPubkeyHex',
    fixture.policySigningPubkeyHex,
    32,
  );
  expectedPayee = exactHexBytes(
    'expectedPayeePubkeyHex',
    fixture.expectedPayeePubkeyHex,
    33,
  );
  issuerOrigin = canonicalLoopbackOrigin(fixture.issuerOrigin);
  settlementMode = fixture.settlementMode;
  const policyFrame = frameSignedPolicy(Uint8Array.from(fixture.policyBytes));
  const channel = new sdk.WasmStandaloneOnionServiceAdmissionV1(
    0,
    new Uint8Array(32).fill(0xa7),
  );
  acceptedPolicy?.free();
  acceptedPolicy = null;
  try {
    acceptedPolicy = await (await vault()).advancePolicyCheckpoint(
      fixture.providerIdHex,
      sdk.initialServicePolicyCheckpointV1(),
      (checkpoint) => {
        const accepted = channel.acceptPolicyResponse(
          policyFrame,
          providerId,
          policySigningKey,
          nowUnix(),
          checkpoint,
        );
        return {
          nextCheckpoint: accepted.checkpointBytes(),
          value: accepted,
          discard: () => accepted.free(),
        };
      },
    );
    acceptedPolicy.acknowledgeCheckpointPersisted();
    channel.verifyPolicySession(acceptedPolicy);
  } finally {
    channel.free();
  }

  const rawView: unknown = acceptedPolicy.offersJson();
  if (!rawView
      || typeof rawView !== 'object'
      || !Array.isArray((rawView as { scopes?: unknown }).scopes)) {
    throw new Error(`real WASM returned an invalid policy view: ${JSON.stringify(rawView)}`);
  }
  const view = rawView as ServicePolicyViewV1;
  selectedScope = view.scopes.find((scope) => scope.workload === 'dpf-query') ?? null;
  selectedOffer = selectedScope?.offers.find(
    (offer) => offer.acquisition === 'bolt11'
      && offer.authorization === authorization,
  ) ?? null;
  if (!selectedScope || !selectedOffer) {
    throw new Error(`verified fixture policy has no DPF ${authorization} offer`);
  }
  if (view.providerIdHex !== fixture.providerIdHex.toLowerCase()
      || selectedOffer.issuerIdHex.length !== 64
      || selectedOffer.price.kind !== 'msat') {
    throw new Error('verified fixture policy metadata differs from its inventory');
  }
  return {
    providerIdHex: view.providerIdHex,
    policyDigestHex: view.policyDigestHex,
    scopeIdHex: selectedScope.scopeIdHex,
    offerId: selectedOffer.offerId,
    offerEndpoint: selectedOffer.endpoint,
  };
}

async function startAcquisition(): Promise<{
  recoveryId: string;
  invoice: string;
  status: string;
}> {
  const policy = requirePolicy();
  const scope = requireScope();
  const offer = requireOffer();
  activeAcquisition?.close();
  activeAcquisition = await Bolt11AcquisitionControllerV1.start({
    vault: await vault(),
    policy,
    scope,
    offer,
    network: 'regtest',
    expectedPayeePubkey: requirePayee(),
    fetchImpl: issuerFetch,
  });
  return {
    recoveryId: activeAcquisition.recoveryId,
    invoice: activeAcquisition.invoice(),
    status: activeAcquisition.status(),
  };
}

async function settleAndPoll(): Promise<string> {
  if (!activeAcquisition) throw new Error('no active acquisition');
  return activeAcquisition.pollStatus();
}

async function claimWithLostResponse(): Promise<string> {
  if (!activeAcquisition) throw new Error('no active acquisition');
  loseNextClaimResponse = true;
  const deadline = performance.now() + 3_000;
  for (;;) {
    try {
      await activeAcquisition.claim();
      return 'unexpected success';
    } catch (error) {
      const message = (error as Error).message;
      if (message.includes('HTTP 503') && performance.now() < deadline) {
        // The issuer's lifecycle clock has one-second precision.  Retry once
        // the next second can exist instead of burning the mutation rate
        // budget with a tight loop at the same impossible timestamp.
        const nextSecond = (Math.floor(Date.now() / 1_000) + 1) * 1_000 + 10;
        await new Promise((resolveWait) => setTimeout(
          resolveWait,
          Math.max(25, nextSecond - Date.now()),
        ));
        continue;
      }
      return message;
    }
  }
}

async function resumeAndClaim(
  recoveryId: string,
): Promise<{ ok: true; count: number } | { ok: false; error: string }> {
  try {
    const acquisition = await Bolt11AcquisitionControllerV1.resume({
      vault: await vault(),
      recoveryId,
      fetchImpl: issuerFetch,
    });
    try {
      return { ok: true, count: await acquisition.claim() };
    } finally {
      acquisition.close();
    }
  } catch (error) {
    return { ok: false, error: (error as Error).message };
  }
}

async function recoveryCount(): Promise<number> {
  return (await vault()).listBolt11Recoveries().then((rows) => rows.length);
}

async function capabilityCount(): Promise<number> {
  return (await vault()).countCapabilities(binding());
}

async function capabilityInventory(): Promise<Array<{
  providerIdHex: string;
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  scheme: string;
  count: number;
}>> {
  return (await vault()).listCapabilityInventory();
}

function capabilityBinding(): AdmissionCapabilityBindingV1 {
  return binding();
}

async function takeAndVerifyCapability(): Promise<number | null> {
  const policy = requirePolicy();
  const scope = requireScope();
  const offer = requireOffer();
  const exactBinding = binding();
  if (exactBinding.scheme === 'arc-experimental') {
    const sdk = requireSdkWasm();
    const presentation = await (await vault()).advanceArcCredential(
      exactBinding,
      (serializedState) => {
        const state = sdk.WasmArcPresentationState.deserialize(serializedState);
        let prepared: ReturnType<typeof state.prepare_presentation> | null = null;
        try {
          prepared = state.prepare_presentation();
          const nextState = prepared.successor_state_bytes();
          const remaining = Number(prepared.remaining());
          if (!Number.isSafeInteger(remaining) || remaining < 0) {
            throw new Error('ARC successor returned an invalid remaining count');
          }
          let terminal = false;
          return {
            nextState,
            remaining,
            releaseAfterPersisted: () => {
              if (!prepared || terminal) throw new Error('ARC transition is already terminal');
              terminal = true;
              try {
                return prepared.release_after_persisted();
              } finally {
                prepared.free();
                prepared = null;
              }
            },
            discard: () => {
              if (!prepared || terminal) return;
              terminal = true;
              prepared.free();
              prepared = null;
            },
          };
        } finally {
          state.free();
        }
      },
    );
    if (!presentation) return null;
    policy.validateAuthorizationProof(
      hexToBytes(scope.scopeIdHex),
      offer.offerId,
      presentation,
    );
    return presentation.length;
  }
  const capability = await (await vault()).takeSingleUseCapability(
    exactBinding,
    (proof) => policy.validateAuthorizationProof(
      hexToBytes(scope.scopeIdHex),
      offer.offerId,
      proof,
    ),
  );
  return capability?.payload.length ?? null;
}

function localStorageSnapshot(): Record<string, string> {
  return Object.fromEntries(
    Array.from({ length: localStorage.length }, (_, index) => localStorage.key(index))
      .filter((key): key is string => key !== null)
      .map((key) => [key, localStorage.getItem(key) ?? '']),
  );
}

async function issuerFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const requested = requestUrl(input);
  const offer = requireOffer();
  if (requested.origin !== new URL(offer.endpoint).origin) {
    throw new Error('test fetch refused a non-fixture issuer origin');
  }
  const target = new URL(`${requested.pathname}${requested.search}`, `${issuerOrigin}/`);
  if (settlementMode === 'fake' && requested.pathname.endsWith('/status')) {
    await settleQuoteBeforeStatus(requested.pathname);
  }

  const isClaim = requested.pathname.endsWith('/claim');
  const response = await fetch(target, init);
  if (isClaim && !response.ok) {
    const problem = await response.clone().text();
    throw new Error(`real issuer claim failed with HTTP ${response.status}: ${problem}`);
  }
  if (isClaim && loseNextClaimResponse && response.ok) {
    // Model the exact ambiguity boundary: the real issuer returned success
    // after its durable commit, but the browser never receives those bytes.
    await response.arrayBuffer();
    loseNextClaimResponse = false;
    throw new TypeError('simulated claim response loss after issuer commit');
  }
  return response;
}

async function settleQuoteBeforeStatus(pathname: string): Promise<void> {
  const match = /^\/v1\/quotes\/([0-9a-f]{64})\/status$/.exec(pathname);
  if (!match) throw new Error('status URL did not carry one canonical quote ID');
  const quoteId = match[1];
  if (settledQuotes.has(quoteId)) return;
  const offer = requireOffer();
  if (offer.price.kind !== 'msat') throw new Error('direct fixture price is not millisatoshi');
  const amount = BigInt(offer.price.amount);
  const body = new Uint8Array(48);
  body.set(hexToBytes(quoteId), 0);
  const view = new DataView(body.buffer);
  view.setBigUint64(32, amount, true);
  const settledAt = nowUnix();
  view.setBigUint64(40, settledAt, true);
  const response = await fetch(`${issuerOrigin}/__test/fake/settle`, {
    method: 'POST',
    headers: { 'Content-Type': CT_FAKE_SETTLEMENT },
    body,
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  if (!response.ok) throw new Error(`fake settlement failed with HTTP ${response.status}`);
  settledQuotes.add(quoteId);
  // The deterministic route injects settlement immediately before polling.
  // Advance beyond that event's whole-second timestamp so the real issuer's
  // strictly monotonic PaymentSettled -> CredentialClaimed clock invariant
  // models a payment that the wallet completed before the browser observed it.
  const monotonicDeadline = performance.now() + 2_000;
  while (nowUnix() <= settledAt) {
    if (performance.now() >= monotonicDeadline) {
      throw new Error('test clock did not advance beyond fake settlement before its deadline');
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 25));
  }
}

function binding(): AdmissionCapabilityBindingV1 {
  const policy = requirePolicy();
  const scope = requireScope();
  const offer = requireOffer();
  const scheme = offer.authorization;
  if (scheme !== 'bolt11-direct-receipt'
      && scheme !== 'cashu-bat'
      && scheme !== 'arc-experimental') {
    throw new Error('selected fixture offer is not a BOLT11 capability scheme');
  }
  return {
    providerIdHex: policy.providerIdHex,
    policyDigestHex: policy.policyDigestHex,
    scopeIdHex: scope.scopeIdHex,
    offerId: offer.offerId,
    scheme,
  };
}

function frameSignedPolicy(policy: Uint8Array): Uint8Array {
  if (policy.length === 0 || policy.length > 128 * 1024) {
    throw new Error('fixture signed policy has an invalid size');
  }
  const payloadLength = 1 + 1 + 4 + policy.length;
  const frame = new Uint8Array(4 + payloadLength);
  const view = new DataView(frame.buffer);
  view.setUint32(0, payloadLength, true);
  frame[4] = SERVICE_POLICY_RESPONSE_OPCODE;
  frame[5] = SERVICE_PROTOCOL_VERSION;
  view.setUint32(6, policy.length, true);
  frame.set(policy, 10);
  return frame;
}

function exactHexBytes(field: string, value: string, length: number): Uint8Array {
  if (!new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)) {
    throw new Error(`${field} is not canonical lowercase ${length}-byte hex`);
  }
  const bytes = hexToBytes(value);
  if (bytes.every((byte) => byte === 0)) throw new Error(`${field} must be non-zero`);
  return bytes;
}

function canonicalLoopbackOrigin(value: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== 'http:'
      || parsed.hostname !== '127.0.0.1'
      || parsed.pathname !== '/'
      || parsed.search
      || parsed.hash
      || parsed.username
      || parsed.password) {
    throw new Error('real issuer E2E accepts only an exact HTTP 127.0.0.1 origin');
  }
  return parsed.origin;
}

function requestUrl(input: RequestInfo | URL): URL {
  if (typeof input === 'string') return new URL(input);
  if (input instanceof URL) return new URL(input.toString());
  return new URL(input.url);
}

function nowUnix(): bigint {
  return BigInt(Math.floor(Date.now() / 1000));
}

function requirePolicy(): WasmAcceptedServicePolicyV1 {
  if (!acceptedPolicy) throw new Error('verified policy is not initialized');
  return acceptedPolicy;
}

function requireScope(): ServiceScopeViewV1 {
  if (!selectedScope) throw new Error('verified DPF scope is not initialized');
  return selectedScope;
}

function requireOffer(): ServiceOfferViewV1 {
  if (!selectedOffer) throw new Error('verified direct-receipt offer is not initialized');
  return selectedOffer;
}

function requirePayee(): Uint8Array {
  if (!expectedPayee) throw new Error('verified fake-Lightning payee is not initialized');
  return expectedPayee;
}

const api = {
  initialize,
  startAcquisition,
  settleAndPoll,
  claimWithLostResponse,
  resumeAndClaim,
  recoveryCount,
  capabilityCount,
  capabilityInventory,
  capabilityBinding,
  takeAndVerifyCapability,
  localStorageSnapshot,
};

declare global {
  interface Window {
    paymentRealIssuerTest: typeof api;
    __paymentRealLocalStorageWrites?: Array<[string, string]>;
  }
}

window.paymentRealIssuerTest = api;
window.addEventListener('pagehide', () => {
  activeAcquisition?.close();
  activeAcquisition = null;
  acceptedPolicy?.free();
  acceptedPolicy = null;
  void vaultPromise?.then((opened) => opened.close());
  vaultPromise = null;
});

void initSdkWasm().then((ready) => {
  if (!ready) throw new Error('real pir-sdk-wasm failed to initialize');
  document.documentElement.dataset.paymentRealIssuerReady = 'true';
});
