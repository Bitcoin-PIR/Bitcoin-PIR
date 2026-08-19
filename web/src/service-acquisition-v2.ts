/**
 * Restart-safe, class-bound BOLT11 acquisition for issuer-wide BAT V2.
 *
 * Every method performs at most one issuer request. Recovery is encrypted in
 * the independent BAT V2 vault and contains no provider/policy/scope/offer
 * coordinates. Lost responses are resumed only by an explicit caller action.
 */

import {
  BatV2CredentialVaultV2,
  type BatV2ClassBindingV2,
  type BatV2RecoveryRecordV2,
  type BatV2WalletRecordV2,
  type LightningNetworkNameV2,
  type LockedBatV2RecoveryV2,
} from './bat-v2-vault.js';
import { hexToBytes } from './hash.js';
import {
  requireSdkWasm,
  type ServiceOfferViewV1,
  type ServiceScopeViewV1,
  type WasmAcceptedServicePolicyV1,
  type WasmBolt11BatV2AcquisitionV2,
  type WasmBolt11QuoteStatusV1,
  type WasmIssuedBatV2ProofsV2,
} from './sdk-bridge.js';
import { fetchQuoteKeyDelegationV1 } from './service-acquisition.js';
import { trustedNowUnixV1 } from './trusted-time.js';

const CT_BAT_V2_QUOTE_INTENT =
  'application/vnd.bitcoinpir.bat-v2-bolt11-quote-intent-v2';
const CT_QUOTE = 'application/vnd.bitcoinpir.bolt11-quote-v1';
const CT_STATUS_REQUEST = 'application/vnd.bitcoinpir.bolt11-quote-status-request-v1';
const CT_BAT_V2_CLAIM_ENVELOPE =
  'application/vnd.bitcoinpir.bat-v2-bolt11-quote-claim-envelope-v2';
const CT_BAT_V2_ISSUANCE_RESPONSE =
  'application/vnd.bitcoinpir.bat-v2-issuance-response-v2';
const MAX_QUOTE_BYTES = 12 * 1024;
const MAX_ISSUANCE_RESPONSE_BYTES = 128 * 1024;
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;

export type BatV2QuoteStatusNameV2 = WasmBolt11QuoteStatusV1;

export interface BatV2AcquisitionHandleV2 {
  readonly recoveryId: string;
  ensureQuote(): Promise<string>;
  invoice(): string;
  status(): BatV2QuoteStatusNameV2;
  invoiceExpiresAtUnix(): bigint;
  claimDeadlineUnix(): bigint;
  pollStatus(): Promise<BatV2QuoteStatusNameV2>;
  claim(): Promise<number>;
  close(): void;
}

export interface StartBatV2AcquisitionV2 {
  vault: BatV2CredentialVaultV2;
  policy: WasmAcceptedServicePolicyV1;
  scope: ServiceScopeViewV1;
  offer: ServiceOfferViewV1;
  /** Canonical issuer-signed class artifact injected by the trusted release. */
  classBytes: Uint8Array;
  network: LightningNetworkNameV2;
  expectedPayeePubkey: Uint8Array;
  fetchImpl?: typeof fetch;
  requestTimeoutMs?: number;
  allowInsecureLoopback?: boolean;
  /** Revalidates the selected current strict pair before any invoice escape. */
  assertReady: () => void;
}

export interface ResumeBatV2AcquisitionV2 {
  vault: BatV2CredentialVaultV2;
  recoveryId: string;
  issuerEndpoint: string;
  issuerIdHex: string;
  network: LightningNetworkNameV2;
  expectedPayeePubkey: Uint8Array;
  fetchImpl?: typeof fetch;
  requestTimeoutMs?: number;
  allowInsecureLoopback?: boolean;
  assertReady: () => void;
}

export class BatV2RecoveryRequiredErrorV2 extends Error {
  constructor(
    readonly recoveryId: string,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'BatV2RecoveryRequiredErrorV2';
  }
}

export class BatV2AcquisitionControllerV2 implements BatV2AcquisitionHandleV2 {
  private completed = false;
  private closed = false;

  private constructor(
    private readonly vault: BatV2CredentialVaultV2,
    private readonly recovery: BatV2RecoveryRecordV2,
    private wasm: WasmBolt11BatV2AcquisitionV2 | null,
    private readonly fetchImpl: typeof fetch,
    private readonly allowInsecureLoopback: boolean,
    private readonly requestTimeoutMs: number,
    private readonly assertReadyForInvoice: () => void,
  ) {}

  static async start(options: StartBatV2AcquisitionV2): Promise<BatV2AcquisitionControllerV2> {
    validateStart(options);
    options.assertReady();
    const allowInsecure = options.allowInsecureLoopback ?? false;
    const endpoint = canonicalIssuerEndpoint(options.offer.endpoint, allowInsecure);
    const issuerIdHex = canonicalHex32('offer.issuerIdHex', options.offer.issuerIdHex);
    const payee = fixedBytes('expectedPayeePubkey', options.expectedPayeePubkey, 33);
    const payeeHex = bytesToHex(payee);
    const fetchImpl = options.fetchImpl ?? fetch;
    const timeout = requestTimeout(options.requestTimeoutMs);
    const delegation = await fetchQuoteKeyDelegationV1(
      endpoint,
      undefined,
      fetchImpl,
      allowInsecure,
      timeout,
    );
    options.assertReady();
    const sdk = requireSdkWasm();
    const initial = sdk.initial_bolt11_quote_key_checkpoint_v1(
      hexToBytes32('offer.issuerIdHex', issuerIdHex),
      options.network,
      payee,
    );
    const acquisition = await options.vault.advanceQuoteKeyCheckpoint(
      issuerIdHex,
      options.network,
      payeeHex,
      initial,
      (checkpoint) => {
        options.assertReady();
        const begin = options.policy.beginBatV2Acquisition;
        if (typeof begin !== 'function') {
          throw new Error('loaded SDK does not support verified BAT V2 acquisition');
        }
        const handle = begin.call(
          options.policy,
          hexToBytes32('scope.scopeIdHex', options.scope.scopeIdHex),
          options.offer.offerId,
          options.classBytes,
          delegation,
          checkpoint,
          trustedNowUnixV1(),
        );
        return {
          nextCheckpoint: handle.quoteKeyCheckpointBytes(),
          value: handle,
          discard: () => handle.free(),
        };
      },
    );
    let recovery: BatV2RecoveryRecordV2;
    try {
      options.assertReady();
      recovery = await options.vault.createRecovery({
        issuerEndpoint: endpoint,
        issuerIdHex,
        network: options.network,
        expectedPayeePubkeyHex: payeeHex,
        state: acquisition.recoveryStateBytes(),
      });
    } catch (error) {
      acquisition.free();
      throw error;
    }
    const controller = new BatV2AcquisitionControllerV2(
      options.vault,
      recovery,
      acquisition,
      fetchImpl,
      allowInsecure,
      timeout,
      options.assertReady,
    );
    try {
      await controller.ensureQuote();
      options.assertReady();
      return controller;
    } catch (cause) {
      controller.close();
      throw new BatV2RecoveryRequiredErrorV2(
        recovery.id,
        'BAT V2 quote response may be lost; resume this exact encrypted recovery',
        { cause },
      );
    }
  }

  static async resume(options: ResumeBatV2AcquisitionV2): Promise<BatV2AcquisitionControllerV2> {
    options.assertReady();
    const recovery = await options.vault.getRecovery(options.recoveryId);
    options.assertReady();
    if (!recovery) throw new Error('BAT V2 recovery was not found (it may be complete)');
    const allowInsecure = options.allowInsecureLoopback ?? false;
    const endpoint = canonicalIssuerEndpoint(options.issuerEndpoint, allowInsecure);
    const issuerIdHex = canonicalHex32('issuerIdHex', options.issuerIdHex);
    const payee = fixedBytes('expectedPayeePubkey', options.expectedPayeePubkey, 33);
    if (recovery.issuerEndpoint !== endpoint
        || recovery.issuerIdHex !== issuerIdHex
        || recovery.network !== options.network
        || recovery.expectedPayeePubkeyHex !== bytesToHex(payee)) {
      throw new Error('BAT V2 recovery does not match issuer/network/payee context');
    }
    let wasm: WasmBolt11BatV2AcquisitionV2 | null = requireSdkWasm()
      .WasmBolt11BatV2AcquisitionV2.restore(recovery.state, trustedNowUnixV1());
    try {
      options.assertReady();
      const controller = new BatV2AcquisitionControllerV2(
        options.vault,
        recovery,
        wasm,
        options.fetchImpl ?? fetch,
        allowInsecure,
        requestTimeout(options.requestTimeoutMs),
        options.assertReady,
      );
      wasm = null;
      return controller;
    } finally {
      wasm?.free();
    }
  }

  get recoveryId(): string {
    return this.recovery.id;
  }

  async ensureQuote(): Promise<string> {
    this.assertReadyForInvoice();
    return this.withLockedRecovery(async (wasm, recovery, locked) => {
      this.assertReadyForInvoice();
      try {
        const invoice = wasm.invoice();
        this.assertReadyForInvoice();
        return invoice;
      } catch {
        // A pre-quote recovery intentionally has no invoice yet.
      }
      const body = wasm.quoteIntentBytes();
      this.assertReadyForInvoice();
      const response = await requestBinary(
        this.fetchImpl,
        issuerUrl(recovery.issuerEndpoint, 'v2/quotes/bolt11', this.allowInsecureLoopback),
        CT_BAT_V2_QUOTE_INTENT,
        CT_QUOTE,
        body,
        MAX_QUOTE_BYTES,
        this.requestTimeoutMs,
      );
      let staleAfterPost: unknown = null;
      try {
        this.assertReadyForInvoice();
      } catch (error) {
        staleAfterPost = error;
      }
      wasm.acceptInitialQuote(response, trustedNowUnixV1());
      await locked.persistState(wasm.recoveryStateBytes());
      if (staleAfterPost) throw staleAfterPost;
      this.assertReadyForInvoice();
      return wasm.invoice();
    });
  }

  invoice(): string {
    this.assertReadyForInvoice();
    return this.requireHandle().invoice();
  }

  status(): BatV2QuoteStatusNameV2 {
    return this.requireHandle().quoteStatus();
  }

  invoiceExpiresAtUnix(): bigint {
    return BigInt(this.requireHandle().invoiceExpiresAtUnix());
  }

  claimDeadlineUnix(): bigint {
    return BigInt(this.requireHandle().claimDeadlineUnix());
  }

  async pollStatus(): Promise<BatV2QuoteStatusNameV2> {
    return this.withLockedRecovery(async (wasm, recovery, locked) => {
      const quoteId = canonicalHex32('quoteId', wasm.quoteIdHex());
      const response = await requestBinary(
        this.fetchImpl,
        issuerUrl(
          recovery.issuerEndpoint,
          `v2/quotes/${quoteId}/status`,
          this.allowInsecureLoopback,
        ),
        CT_STATUS_REQUEST,
        CT_QUOTE,
        wasm.buildStatusRequest(trustedNowUnixV1()),
        MAX_QUOTE_BYTES,
        this.requestTimeoutMs,
      );
      wasm.acceptStatus(response, trustedNowUnixV1());
      await locked.persistState(wasm.recoveryStateBytes());
      return wasm.quoteStatus();
    });
  }

  async claim(): Promise<number> {
    return this.withLockedRecovery(async (wasm, recovery, locked) => {
      const quoteId = canonicalHex32('quoteId', wasm.quoteIdHex());
      const body = wasm.prepareClaim(trustedNowUnixV1());
      await locked.persistState(wasm.recoveryStateBytes());
      const response = await requestBinary(
        this.fetchImpl,
        issuerUrl(
          recovery.issuerEndpoint,
          `v2/quotes/${quoteId}/claim`,
          this.allowInsecureLoopback,
        ),
        CT_BAT_V2_CLAIM_ENVELOPE,
        CT_BAT_V2_ISSUANCE_RESPONSE,
        body,
        MAX_ISSUANCE_RESPONSE_BYTES,
        this.requestTimeoutMs,
      );
      const issued = wasm.finishClaim(response, trustedNowUnixV1());
      const records: BatV2WalletRecordV2[] = [];
      try {
        const binding = validateClassBinding(issued.classBindingJson());
        if (binding.issuerIdHex !== recovery.issuerIdHex) {
          throw new Error('issued BAT V2 class does not match the recovery issuer');
        }
        const count = issued.count();
        if (!Number.isSafeInteger(count) || count <= 0 || count > 65_535) {
          throw new Error('issuer returned an invalid BAT V2 proof count');
        }
        for (let index = 0; index < count; index += 1) {
          records.push({
            ...binding,
            proof: issued.proof(index),
            globalSpendKeyHex: issued.globalSpendKeyHex(index),
          });
        }
        await locked.complete(records);
        this.completed = true;
        return count;
      } finally {
        for (const record of records) record.proof.fill(0);
        issued.free();
      }
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.wasm?.free();
    this.wasm = null;
    this.recovery.state.fill(0);
  }

  private async withLockedRecovery<T>(
    operation: (
      wasm: WasmBolt11BatV2AcquisitionV2,
      recovery: BatV2RecoveryRecordV2,
      locked: LockedBatV2RecoveryV2,
    ) => Promise<T>,
  ): Promise<T> {
    this.requireActive();
    return this.vault.withRecovery(this.recovery.id, async (recovery, locked) => {
      this.requireActive();
      const working = requireSdkWasm().WasmBolt11BatV2AcquisitionV2.restore(
        recovery.state,
        trustedNowUnixV1(),
      );
      try {
        return await operation(working, recovery, locked);
      } finally {
        working.free();
        if (!this.closed) {
          this.wasm?.free();
          this.wasm = null;
          this.recovery.state.fill(0);
          if (!this.completed) {
            this.wasm = requireSdkWasm().WasmBolt11BatV2AcquisitionV2.restore(
              recovery.state,
              trustedNowUnixV1(),
            );
          }
        }
        recovery.state.fill(0);
      }
    });
  }

  private requireActive(): void {
    if (this.closed) throw new Error('BAT V2 acquisition controller is closed');
    if (this.completed) throw new Error('BAT V2 acquisition is already complete');
  }

  private requireHandle(): WasmBolt11BatV2AcquisitionV2 {
    this.requireActive();
    if (!this.wasm) throw new Error('BAT V2 acquisition state is unavailable');
    return this.wasm;
  }
}

export function resumeBatV2AcquisitionV2(
  options: ResumeBatV2AcquisitionV2,
): Promise<BatV2AcquisitionHandleV2> {
  return BatV2AcquisitionControllerV2.resume(options);
}

function validateStart(options: StartBatV2AcquisitionV2): void {
  requestTimeout(options.requestTimeoutMs);
  if (typeof options.assertReady !== 'function') {
    throw new Error('BAT V2 acquisition requires a strict-session readiness guard');
  }
  if (!(options.classBytes instanceof Uint8Array) || options.classBytes.length === 0) {
    throw new Error('BAT V2 acquisition requires canonical signed class bytes');
  }
  if (options.offer.acquisition !== 'bolt11'
      || options.offer.authorization !== 'cashu-bat-v2'
      || options.offer.verification !== 'shared-issuer-online') {
    throw new Error('selected signed offer is not storeless BAT V2');
  }
  if (!options.scope.offers.some((offer) =>
    offer === options.offer
      || (offer.offerId === options.offer.offerId
        && offer.authorization === 'cashu-bat-v2'
        && offer.issuerIdHex === options.offer.issuerIdHex
        && offer.endpoint === options.offer.endpoint))) {
    throw new Error('selected BAT V2 offer is not from this verified scope');
  }
  canonicalHex32('offer.issuerIdHex', options.offer.issuerIdHex);
  fixedBytes('expectedPayeePubkey', options.expectedPayeePubkey, 33);
}

function validateClassBinding(value: unknown): BatV2ClassBindingV2 {
  if (value === null || typeof value !== 'object') {
    throw new Error('WASM returned an invalid BAT V2 class binding');
  }
  const record = value as Record<string, unknown>;
  return {
    issuerIdHex: canonicalHex32('class.issuerIdHex', record.issuerIdHex),
    classIdHex: canonicalHex32('class.classIdHex', record.classIdHex),
    classDigestHex: canonicalHex32('class.classDigestHex', record.classDigestHex),
    classKeyEpoch: canonicalPositiveDecimal('class.classKeyEpoch', record.classKeyEpoch),
    batKeyIdHex: canonicalHex32('class.batKeyIdHex', record.batKeyIdHex),
  };
}

async function requestBinary(
  fetchImpl: typeof fetch,
  url: string,
  requestContentType: string,
  expectedContentType: string,
  body: Uint8Array,
  maxResponseBytes: number,
  timeoutMs: number,
): Promise<Uint8Array> {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort('BAT V2 issuer request timed out'), timeoutMs);
  try {
    const response = await fetchImpl(url, {
      method: 'POST',
      headers: {
        Accept: expectedContentType,
        'Content-Type': requestContentType,
      },
      body: ownedArrayBuffer(body),
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal: abort.signal,
    });
    if (!response.ok) {
      throw new Error(`BAT V2 issuer rejected POST with HTTP ${response.status}`);
    }
    const contentType = response.headers.get('Content-Type')?.split(';', 1)[0]?.trim().toLowerCase();
    if (contentType !== expectedContentType) {
      throw new Error('BAT V2 issuer returned an unexpected content type');
    }
    const encoding = response.headers.get('Content-Encoding');
    if (encoding !== null && encoding.trim().toLowerCase() !== 'identity') {
      throw new Error('BAT V2 issuer returned an unsupported content encoding');
    }
    const declared = response.headers.get('Content-Length');
    if (declared !== null) {
      const length = Number(declared);
      if (!Number.isSafeInteger(length) || length <= 0 || length > maxResponseBytes) {
        throw new Error('BAT V2 issuer response exceeds its bound');
      }
    }
    const bytes = await readBodyBounded(response, maxResponseBytes);
    if (bytes.length === 0 || bytes.length > maxResponseBytes) {
      throw new Error('BAT V2 issuer returned an empty or oversized response');
    }
    if (declared !== null && bytes.length !== Number(declared)) {
      throw new Error('BAT V2 issuer response length differs from Content-Length');
    }
    return bytes;
  } finally {
    clearTimeout(timer);
  }
}

async function readBodyBounded(response: Response, max: number): Promise<Uint8Array> {
  if (!response.body) throw new Error('BAT V2 issuer returned no response body');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error('invalid BAT V2 response stream');
      total += value.length;
      if (!Number.isSafeInteger(total) || total > max) {
        await reader.cancel().catch(() => undefined);
        throw new Error('BAT V2 issuer response exceeds its bound');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

function requestTimeout(value: number | undefined): number {
  const timeout = value ?? DEFAULT_REQUEST_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeout) || timeout < 1_000 || timeout > 60_000) {
    throw new Error('BAT V2 issuer timeout must be in 1000..=60000 ms');
  }
  return timeout;
}

function issuerUrl(endpoint: string, relative: string, allowInsecure: boolean): string {
  return new URL(relative, `${canonicalIssuerEndpoint(endpoint, allowInsecure)}/`).toString();
}

function canonicalIssuerEndpoint(value: string, allowInsecure: boolean): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('BAT V2 issuer endpoint must be an absolute URL');
  }
  const loopback = url.hostname === '127.0.0.1'
    || url.hostname === 'localhost'
    || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(allowInsecure && loopback && url.protocol === 'http:')) {
    throw new Error('BAT V2 issuer endpoint must use HTTPS');
  }
  if (url.username || url.password || url.search || url.hash
      || (url.pathname !== '' && url.pathname !== '/')) {
    throw new Error('BAT V2 issuer endpoint must be a credential-free origin');
  }
  return url.origin;
}

function canonicalHex32(field: string, value: unknown): string {
  if (typeof value !== 'string'
      || !/^[0-9a-fA-F]{64}$/.test(value)
      || /^0{64}$/i.test(value)) {
    throw new Error(`${field} must be non-zero 32-byte hex`);
  }
  return value.toLowerCase();
}

function canonicalPositiveDecimal(field: string, value: unknown): string {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${field} must be a positive decimal`);
  }
  const parsed = BigInt(value);
  if (parsed > 0xffff_ffff_ffff_ffffn) throw new Error(`${field} exceeds u64`);
  return parsed.toString();
}

function fixedBytes(field: string, value: Uint8Array, length: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`${field} must be exactly ${length} bytes`);
  }
  if (value.every((byte) => byte === 0)) throw new Error(`${field} must be non-zero`);
  return value.slice();
}

function hexToBytes32(field: string, value: string): Uint8Array {
  return fixedBytes(field, hexToBytes(canonicalHex32(field, value)), 32);
}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}
