/**
 * Restart-safe BOLT11 -> anonymous provider capability acquisition.
 *
 * This controller performs one HTTP request per explicit call. It never
 * retries a PIR query or a capability presentation. Lost quote/claim HTTP
 * responses are recovered by replaying the exact signed idempotent request
 * from the encrypted vault.
 */

import {
  type AdmissionCapabilityV1,
  AdmissionCredentialVaultV1,
  type AdmissionSchemeV1,
  type Bolt11RecoveryRecordV1,
  type LockedBolt11RecoveryV1,
  type LightningNetworkNameV1,
} from './admission-vault.js';
import { hexToBytes } from './hash.js';
import {
  requireSdkWasm,
  type ServiceOfferViewV1,
  type ServiceScopeViewV1,
  type WasmAcceptedServicePolicyV1,
  type WasmBolt11AcquisitionV1,
  type WasmBolt11QuoteStatusV1,
  type WasmIssuedCapabilitiesV1,
} from './sdk-bridge.js';

const CT_QUOTE_INTENT = 'application/vnd.bitcoinpir.bolt11-quote-intent-v1';
const CT_QUOTE = 'application/vnd.bitcoinpir.bolt11-quote-v1';
const CT_QUOTE_KEY_DELEGATION =
  'application/vnd.bitcoinpir.bolt11-quote-key-delegation-v1';
const CT_STATUS_REQUEST = 'application/vnd.bitcoinpir.bolt11-quote-status-request-v1';
const CT_CLAIM_ENVELOPE = 'application/vnd.bitcoinpir.bolt11-quote-claim-envelope-v1';
const CT_ISSUANCE_RESPONSE =
  'application/vnd.bitcoinpir.credential-issuance-response-v1';

// Keep these transport limits identical to the canonical Rust V1 bounds.
// The WASM decoder remains authoritative, but the browser must reject an
// oversized response before buffering it in memory.
const MAX_DELEGATION_BYTES = 256;
const MAX_QUOTE_BYTES = 12 * 1024;
const MAX_ISSUANCE_RESPONSE_BYTES = 128 * 1024;
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;

export type Bolt11QuoteStatusNameV1 = WasmBolt11QuoteStatusV1;

export interface Bolt11AcquisitionHandleV1 {
  readonly recoveryId: string;
  ensureQuote(): Promise<string>;
  invoice(): string;
  status(): Bolt11QuoteStatusNameV1;
  invoiceExpiresAtUnix(): bigint;
  claimDeadlineUnix(): bigint;
  pollStatus(): Promise<Bolt11QuoteStatusNameV1>;
  claim(): Promise<number>;
  close(): void;
}

export interface StartBolt11AcquisitionV1 {
  vault: AdmissionCredentialVaultV1;
  policy: WasmAcceptedServicePolicyV1;
  scope: ServiceScopeViewV1;
  offer: ServiceOfferViewV1;
  network: LightningNetworkNameV1;
  expectedPayeePubkey: Uint8Array;
  fetchImpl?: typeof fetch;
  /** Hard deadline covering response headers and the bounded body stream. */
  requestTimeoutMs?: number;
  /** Development-only support for apps/payment-issuer serve-fake. */
  allowInsecureLoopback?: boolean;
}

export interface ResumeBolt11AcquisitionV1 {
  vault: AdmissionCredentialVaultV1;
  recoveryId: string;
  fetchImpl?: typeof fetch;
  requestTimeoutMs?: number;
  allowInsecureLoopback?: boolean;
}

/** Carries the durable recovery ID when an HTTP response may have been lost. */
export class Bolt11RecoveryRequiredErrorV1 extends Error {
  constructor(
    readonly recoveryId: string,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'Bolt11RecoveryRequiredErrorV1';
  }
}

export class Bolt11AcquisitionControllerV1 implements Bolt11AcquisitionHandleV1 {
  private completed = false;
  private closed = false;

  private constructor(
    private readonly vault: AdmissionCredentialVaultV1,
    private readonly recovery: Bolt11RecoveryRecordV1,
    private wasm: WasmBolt11AcquisitionV1 | null,
    private readonly fetchImpl: typeof fetch,
    private readonly allowInsecureLoopback: boolean,
    private readonly requestTimeoutMs: number,
  ) {}

  /**
   * Verify the current delegated quote key, durably advance its rollback
   * checkpoint, create encrypted recovery, then make one quote POST.
   */
  static async start(options: StartBolt11AcquisitionV1): Promise<Bolt11AcquisitionControllerV1> {
    validateStart(options);
    const endpoint = canonicalIssuerEndpoint(
      options.offer.endpoint,
      options.allowInsecureLoopback ?? false,
    );
    const fetchImpl = options.fetchImpl ?? fetch;
    const delegation = await fetchQuoteKeyDelegationV1(
      endpoint,
      undefined,
      fetchImpl,
      options.allowInsecureLoopback ?? false,
      requestTimeout(options.requestTimeoutMs),
    );
    const sdk = bolt11Sdk();
    const issuerId = hexToBytes32('offer.issuerIdHex', options.offer.issuerIdHex);
    const payee = fixedBytes('expectedPayeePubkey', options.expectedPayeePubkey, 33);
    const initial = sdk.initial_bolt11_quote_key_checkpoint_v1(
      issuerId,
      options.network,
      payee,
    );
    const acquisition = await options.vault.advanceQuoteKeyCheckpoint(
      options.offer.issuerIdHex,
      options.network,
      bytesToHex(payee),
      initial,
      (checkpoint) => {
        const handle = options.policy.beginBolt11Acquisition(
          hexToBytes32('scope.scopeIdHex', options.scope.scopeIdHex),
          options.offer.offerId,
          delegation,
          checkpoint,
          trustedNowUnix(),
        );
        return {
          nextCheckpoint: handle.quote_key_checkpoint_bytes(),
          value: handle,
        };
      },
    );
    let recovery: Bolt11RecoveryRecordV1;
    try {
      recovery = await options.vault.createBolt11Recovery({
        issuerEndpoint: endpoint,
        providerIdHex: canonicalHex32('policy.providerIdHex', options.policy.providerIdHex),
        policyDigestHex: canonicalHex32(
          'policy.policyDigestHex',
          options.policy.policyDigestHex,
        ),
        scopeIdHex: canonicalHex32('scope.scopeIdHex', options.scope.scopeIdHex),
        offerId: options.offer.offerId,
        expectedScheme: expectedBolt11Scheme(options.offer.authorization),
        state: acquisition.recovery_state_bytes(),
      });
    } catch (error) {
      acquisition.free();
      throw error;
    }
    const controller = new Bolt11AcquisitionControllerV1(
      options.vault,
      recovery,
      acquisition,
      fetchImpl,
      options.allowInsecureLoopback ?? false,
      requestTimeout(options.requestTimeoutMs),
    );
    try {
      await controller.ensureQuote();
      return controller;
    } catch (cause) {
      controller.close();
      throw new Bolt11RecoveryRequiredErrorV1(
        recovery.id,
        'BOLT11 quote request did not complete; resume the encrypted acquisition',
        { cause },
      );
    }
  }

  /** Restore without making a network request. */
  static async resume(options: ResumeBolt11AcquisitionV1): Promise<Bolt11AcquisitionControllerV1> {
    const recovery = await options.vault.getBolt11Recovery(options.recoveryId);
    if (!recovery) throw new Error('BOLT11 recovery record was not found (it may be complete)');
    canonicalIssuerEndpoint(recovery.issuerEndpoint, options.allowInsecureLoopback ?? false);
    const wasm = bolt11Sdk().WasmBolt11AcquisitionV1.restore(
      recovery.state,
      trustedNowUnix(),
    );
    return new Bolt11AcquisitionControllerV1(
      options.vault,
      recovery,
      wasm,
      options.fetchImpl ?? fetch,
      options.allowInsecureLoopback ?? false,
      requestTimeout(options.requestTimeoutMs),
    );
  }

  get recoveryId(): string {
    return this.recovery.id;
  }

  /** One exact quote POST. Replays the intent's signed idempotency key. */
  async ensureQuote(): Promise<string> {
    return this.withLockedRecovery(async (wasm, recovery, locked) => {
      try {
        return wasm.invoice();
      } catch {
        // A pre-quote recovery is expected to have no invoice yet.
      }
      const body = wasm.quote_intent_bytes();
      const response = await requestBinary(
        this.fetchImpl,
        issuerUrl(recovery.issuerEndpoint, 'v1/quotes/bolt11', this.allowInsecureLoopback),
        'POST',
        CT_QUOTE_INTENT,
        CT_QUOTE,
        body,
        MAX_QUOTE_BYTES,
        this.requestTimeoutMs,
      );
      wasm.accept_initial_quote(response, trustedNowUnix());
      await locked.persistState(wasm.recovery_state_bytes());
      return wasm.invoice();
    });
  }

  invoice(): string {
    return this.requireHandle().invoice();
  }

  status(): Bolt11QuoteStatusNameV1 {
    return this.requireHandle().quote_status();
  }

  invoiceExpiresAtUnix(): bigint {
    return BigInt(this.requireHandle().invoice_expires_at_unix());
  }

  claimDeadlineUnix(): bigint {
    return BigInt(this.requireHandle().claim_deadline_unix());
  }

  /** One authenticated status POST; callers choose their own polling cadence. */
  async pollStatus(): Promise<Bolt11QuoteStatusNameV1> {
    return this.withLockedRecovery(async (wasm, recovery, locked) => {
      const quoteId = canonicalHex32('quoteId', wasm.quote_id_hex());
      const body = wasm.build_status_request(trustedNowUnix());
      const response = await requestBinary(
        this.fetchImpl,
        issuerUrl(
          recovery.issuerEndpoint,
          `v1/quotes/${quoteId}/status`,
          this.allowInsecureLoopback,
        ),
        'POST',
        CT_STATUS_REQUEST,
        CT_QUOTE,
        body,
        MAX_QUOTE_BYTES,
        this.requestTimeoutMs,
      );
      wasm.accept_status(response, trustedNowUnix());
      await locked.persistState(wasm.recovery_state_bytes());
      return wasm.quote_status();
    });
  }

  /**
   * Persist the exact signed claim before one POST, verify the response, then
   * atomically store all capabilities and delete invoice recovery.
   */
  async claim(): Promise<number> {
    return this.withLockedRecovery(async (wasm, recovery, locked) => {
      const quoteId = canonicalHex32('quoteId', wasm.quote_id_hex());
      // prepare_claim is replay-stable. Persist its exact blinded requests and
      // signature before the POST so response loss can replay byte-for-byte.
      const body = wasm.prepare_claim(trustedNowUnix());
      await locked.persistState(wasm.recovery_state_bytes());
      const response = await requestBinary(
        this.fetchImpl,
        issuerUrl(
          recovery.issuerEndpoint,
          `v1/quotes/${quoteId}/claim`,
          this.allowInsecureLoopback,
        ),
        'POST',
        CT_CLAIM_ENVELOPE,
        CT_ISSUANCE_RESPONSE,
        body,
        MAX_ISSUANCE_RESPONSE_BYTES,
        this.requestTimeoutMs,
      );
      const issued = wasm.finish_claim(response, trustedNowUnix());
      const capabilities: AdmissionCapabilityV1[] = [];
      try {
        const scheme = validateIssuedScheme(issued.scheme);
        const count = issued.count();
        if (!Number.isSafeInteger(count) || count <= 0 || count > 65_535) {
          throw new Error('issuer returned an invalid capability count');
        }
        for (let index = 0; index < count; index += 1) {
          capabilities.push({
            providerIdHex: recovery.providerIdHex,
            policyDigestHex: recovery.policyDigestHex,
            scopeIdHex: recovery.scopeIdHex,
            offerId: recovery.offerId,
            scheme,
            payload: issued.capability(index),
          });
        }
        await locked.complete(capabilities);
        this.completed = true;
        return count;
      } finally {
        for (const capability of capabilities) capability.payload.fill(0);
        issued.free();
      }
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.wasm?.free();
    this.wasm = null;
  }

  private async withLockedRecovery<T>(
    operation: (
      wasm: WasmBolt11AcquisitionV1,
      recovery: Bolt11RecoveryRecordV1,
      locked: LockedBolt11RecoveryV1,
    ) => Promise<T>,
  ): Promise<T> {
    this.requireActive();
    return this.vault.withBolt11Recovery(this.recovery.id, async (recovery, locked) => {
      this.requireActive();
      const working = bolt11Sdk().WasmBolt11AcquisitionV1.restore(
        recovery.state,
        trustedNowUnix(),
      );
      try {
        return await operation(working, recovery, locked);
      } finally {
        // Refresh the local, synchronous UI snapshot only from bytes that the
        // locked vault reports as durably persisted. Never retain an in-memory
        // state transition whose IndexedDB write failed.
        working.free();
        if (!this.closed) {
          this.wasm?.free();
          this.wasm = null;
          this.recovery.state = recovery.state.slice();
          if (!this.completed) {
            this.wasm = bolt11Sdk().WasmBolt11AcquisitionV1.restore(
              recovery.state,
              trustedNowUnix(),
            );
          }
        }
      }
    });
  }

  private requireActive(): void {
    if (this.closed) throw new Error('BOLT11 acquisition controller is closed');
    if (this.completed) throw new Error('BOLT11 acquisition is already complete');
  }

  private requireHandle(): WasmBolt11AcquisitionV1 {
    this.requireActive();
    if (!this.wasm) throw new Error('BOLT11 acquisition state is unavailable');
    return this.wasm;
  }
}

/** Resume never creates a new invoice and therefore needs no new pair check. */
export function resumeBolt11AcquisitionV1(
  options: ResumeBolt11AcquisitionV1,
): Promise<Bolt11AcquisitionHandleV1> {
  return Bolt11AcquisitionControllerV1.resume(options);
}

/** Fetch current delegation, or an exact retained 16-byte key ID. */
export async function fetchQuoteKeyDelegationV1(
  issuerEndpoint: string,
  quoteKeyIdHex?: string,
  fetchImpl: typeof fetch = fetch,
  allowInsecureLoopback = false,
  requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
): Promise<Uint8Array> {
  const endpoint = canonicalIssuerEndpoint(issuerEndpoint, allowInsecureLoopback);
  const suffix = quoteKeyIdHex === undefined
    ? 'current'
    : canonicalHex16('quoteKeyIdHex', quoteKeyIdHex);
  return requestBinary(
    fetchImpl,
    issuerUrl(endpoint, `v1/quote-keys/${suffix}`, allowInsecureLoopback),
    'GET',
    undefined,
    CT_QUOTE_KEY_DELEGATION,
    undefined,
    MAX_DELEGATION_BYTES,
    requestTimeout(requestTimeoutMs),
  );
}

async function requestBinary(
  fetchImpl: typeof fetch,
  url: string,
  method: 'GET' | 'POST',
  requestContentType: string | undefined,
  expectedContentType: string,
  body: Uint8Array | undefined,
  maxResponseBytes: number,
  timeoutMs: number,
): Promise<Uint8Array> {
  const headers = new Headers({ Accept: expectedContentType });
  if (requestContentType) headers.set('Content-Type', requestContentType);
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort('payment issuer request timed out'), timeoutMs);
  try {
    const response = await fetchImpl(url, {
      method,
      headers,
      body: body ? ownedArrayBuffer(body) : undefined,
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal: abort.signal,
    });
    if (!response.ok) {
      throw new Error(`payment issuer rejected ${method} with HTTP ${response.status}`);
    }
    const contentType = response.headers.get('Content-Type')?.split(';', 1)[0]?.trim().toLowerCase();
    if (contentType !== expectedContentType) {
      throw new Error('payment issuer returned an unexpected content type');
    }
    const contentEncoding = response.headers.get('Content-Encoding');
    if (contentEncoding !== null && contentEncoding.trim().toLowerCase() !== 'identity') {
      throw new Error('payment issuer returned an unsupported content encoding');
    }
    const declared = response.headers.get('Content-Length');
    let declaredLength: number | null = null;
    if (declared !== null) {
      const length = Number(declared);
      if (!Number.isSafeInteger(length) || length < 0 || length > maxResponseBytes) {
        throw new Error('payment issuer response exceeds its V1 bound');
      }
      declaredLength = length;
    }
    const bytes = await readResponseBodyBoundedV1(response, maxResponseBytes);
    if (bytes.length === 0 || bytes.length > maxResponseBytes) {
      throw new Error('payment issuer returned an empty or oversized response');
    }
    if (declaredLength !== null && bytes.length !== declaredLength) {
      throw new Error('payment issuer response length does not match Content-Length');
    }
    return bytes;
  } finally {
    clearTimeout(timer);
  }
}

async function readResponseBodyBoundedV1(
  response: Response,
  maxResponseBytes: number,
): Promise<Uint8Array> {
  const body = response.body;
  if (!body) throw new Error('payment issuer returned no response body');
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        throw new Error('payment issuer returned an invalid response stream');
      }
      total += value.length;
      if (!Number.isSafeInteger(total) || total > maxResponseBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error('payment issuer response exceeds its V1 bound');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}

function validateStart(options: StartBolt11AcquisitionV1): void {
  requestTimeout(options.requestTimeoutMs);
  if (options.offer.acquisition !== 'bolt11') {
    throw new Error('selected signed offer is not acquired with BOLT11');
  }
  if (![
    'bolt11-direct-receipt',
    'cashu-bat',
    'arc-experimental',
  ].includes(options.offer.authorization)) {
    throw new Error('selected signed offer is not a supported BOLT11 credential scheme');
  }
  if (options.offer.authorization === 'arc-experimental'
      && options.offer.deploymentStatus !== 'experimental') {
    throw new Error('ARC BOLT11 issuance must remain explicitly experimental');
  }
  if (!options.scope.offers.some((offer) =>
    offer.offerId === options.offer.offerId
      && offer.authorization === options.offer.authorization
      && offer.issuerIdHex === options.offer.issuerIdHex
      && offer.endpoint === options.offer.endpoint)) {
    throw new Error('selected offer is not the exact object from this verified scope');
  }
  canonicalHex32('offer.issuerIdHex', options.offer.issuerIdHex);
  fixedBytes('expectedPayeePubkey', options.expectedPayeePubkey, 33);
}

function requestTimeout(value: number | undefined): number {
  const timeout = value ?? DEFAULT_REQUEST_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeout) || timeout < 1_000 || timeout > 60_000) {
    throw new Error('payment issuer request timeout must be in 1000..=60000 ms');
  }
  return timeout;
}

function validateIssuedScheme(value: string): AdmissionSchemeV1 {
  if (value === 'bolt11-direct-receipt'
      || value === 'cashu-bat'
      || value === 'arc-experimental') return value;
  throw new Error('WASM returned a non-BOLT11 capability scheme');
}

function expectedBolt11Scheme(
  value: ServiceOfferViewV1['authorization'],
): Bolt11RecoveryRecordV1['expectedScheme'] {
  if (value === 'bolt11-direct-receipt'
      || value === 'cashu-bat'
      || value === 'arc-experimental') return value;
  throw new Error('selected signed offer has no BOLT11 recovery capability family');
}

function bolt11Sdk(): ReturnType<typeof requireSdkWasm> {
  return requireSdkWasm();
}

function issuerUrl(endpoint: string, relative: string, allowInsecureLoopback: boolean): string {
  const base = canonicalIssuerEndpoint(endpoint, allowInsecureLoopback);
  return new URL(relative, `${base}/`).toString();
}

function canonicalIssuerEndpoint(value: string, allowInsecureLoopback: boolean): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('issuer endpoint must be an absolute URL');
  }
  const loopback = parsed.hostname === '127.0.0.1'
    || parsed.hostname === 'localhost'
    || parsed.hostname === '[::1]';
  if (parsed.protocol !== 'https:'
      && !(allowInsecureLoopback && loopback && parsed.protocol === 'http:')) {
    throw new Error('issuer endpoint must use HTTPS');
  }
  if (parsed.username || parsed.password || parsed.hash || parsed.search
      || (parsed.pathname !== '/' && parsed.pathname !== '')) {
    throw new Error('issuer endpoint must be a credential-free origin URL');
  }
  return parsed.origin;
}

function trustedNowUnix(): bigint {
  const now = Date.now();
  if (!Number.isFinite(now) || now <= 0) throw new Error('trusted wall clock is unavailable');
  return BigInt(Math.floor(now / 1000));
}

function canonicalHex32(field: string, value: string): string {
  if (!/^[0-9a-fA-F]{64}$/.test(value) || /^0{64}$/i.test(value)) {
    throw new Error(`${field} must be non-zero 32-byte hex`);
  }
  return value.toLowerCase();
}

function canonicalHex16(field: string, value: string): string {
  if (!/^[0-9a-f]{32}$/.test(value) || /^0{32}$/.test(value)) {
    throw new Error(`${field} must be non-zero lowercase 16-byte hex`);
  }
  return value;
}

function hexToBytes32(field: string, value: string): Uint8Array {
  return fixedBytes(field, hexToBytes(canonicalHex32(field, value)), 32);
}

function fixedBytes(field: string, value: Uint8Array, length: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`${field} must be exactly ${length} bytes`);
  }
  if (value.every((byte) => byte === 0)) throw new Error(`${field} must be non-zero`);
  return value.slice();
}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}
