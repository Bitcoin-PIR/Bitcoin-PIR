/**
 * Session grants (paid queries), browser side.
 *
 * A cashier — operator-run, outside the PIR hosts — sells Ed25519-signed
 * session grants for Cashu ecash; the PIR server verifies them offline and
 * spends one credit per query-bearing request frame. Design and server
 * flags: `docs/SESSION_GRANTS.md`; cashier HTTP contract:
 * `docs/CASHIER_API.md`.
 *
 * Everything here works without a payment library: the cashier HTTP client,
 * the grant store, the presentation frame codec, and the outcome classifier
 * the four PIR clients share. Lightning → ecash lives in `cashu-purchase.ts`.
 *
 * A grant is a bearer token: present it only inside the encrypted channel
 * (after attest + handshake), never in cleartext through cloudflared.
 */

import {
  REQ_SESSION_GRANT_PRESENT,
  RESP_SESSION_GRANT_OK,
  SESSION_GRANT_LEN,
} from './constants.js';

const RESP_ERROR = 0xff;
const SESSION_GRANT_VERSION = 1;
export const CASHIER_API_VERSION = 1;
export const SESSION_GRANT_STORAGE_KEY = 'bitcoinpir.session-grant.v1';

/** One purchasable pack: `amount` of `unit` buys `credits`. */
export interface CashierOffer {
  credits: number;
  amount: number;
  unit: string;
}

/** `GET /v1/info` — what the cashier sells and which mints it accepts. */
export interface CashierInfo {
  service: string;
  version: number;
  cashierPubkeyHex: string;
  mints: string[];
  offers: CashierOffer[];
  grantTtlSecs: number;
}

/** Fields of a version-1 grant, decoded without signature verification. */
export interface SessionGrantFields {
  version: number;
  issuerPubkeyHex: string;
  grantIdHex: string;
  issuedAt: number;
  expiresAt: number;
  credits: number;
}

/** `POST /v1/grants` — a freshly issued grant plus its decoded fields. */
export interface IssuedGrant {
  grantBase64: string;
  grantIdHex: string;
  credits: number;
  issuedAt: number;
  expiresAt: number;
}

/** What `SessionGrantStore` persists. */
export interface StoredSessionGrant extends IssuedGrant {
  version: 1;
  cashierUrl: string;
}

/** Outcome of presenting a grant on one connection. */
export type SessionGrantPresentation =
  | { state: 'accepted'; remaining: number }
  | { state: 'not-enabled' }
  | { state: 'refused'; error: string };

/**
 * Supplies the grant a client should present on each new connection, or
 * `null` for the free path. Evaluated per connection so a purchase made
 * while connected is picked up on the next connect.
 */
export type SessionGrantProvider = () => Uint8Array | null;

export class CashierError extends Error {
  readonly status: number | null;
  readonly code: string | null;

  constructor(message: string, status: number | null = null, code: string | null = null) {
    super(message);
    this.name = 'CashierError';
    this.status = status;
    this.code = code;
  }
}

// ─── Encoding helpers ───────────────────────────────────────────────────────

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(text: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(text.trim());
  } catch {
    throw new Error('invalid base64');
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function hex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

const HEX_64 = /^[0-9a-f]{64}$/i;
const HEX_32 = /^[0-9a-f]{32}$/i;

// ─── Grant fields ───────────────────────────────────────────────────────────

/**
 * Decode the public fields of a version-1 grant. Structural checks only —
 * the server is the verifier; the browser never needs the cashier key.
 */
export function decodeSessionGrantFields(bytes: Uint8Array): SessionGrantFields {
  if (bytes.length !== SESSION_GRANT_LEN) {
    throw new Error(`session grant must be ${SESSION_GRANT_LEN} bytes, got ${bytes.length}`);
  }
  const version = bytes[0];
  if (version !== SESSION_GRANT_VERSION) {
    throw new Error(`unknown session grant version ${version}`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const issuedAt = Number(view.getBigUint64(49, true));
  const expiresAt = Number(view.getBigUint64(57, true));
  const credits = view.getUint32(65, true);
  if (credits === 0) throw new Error('session grant carries no credits');
  if (issuedAt >= expiresAt) throw new Error('session grant expires before it is issued');
  return {
    version,
    issuerPubkeyHex: hex(bytes.subarray(1, 33)),
    grantIdHex: hex(bytes.subarray(33, 49)),
    issuedAt,
    expiresAt,
    credits,
  };
}

// ─── Wire codec ─────────────────────────────────────────────────────────────

/** `[u32 LE len][REQ_SESSION_GRANT_PRESENT][grant]` for a raw socket. */
export function encodeSessionGrantPresentFrame(grant: Uint8Array): Uint8Array {
  if (grant.length !== SESSION_GRANT_LEN) {
    throw new Error(`session grant must be ${SESSION_GRANT_LEN} bytes, got ${grant.length}`);
  }
  const frame = new Uint8Array(4 + 1 + grant.length);
  new DataView(frame.buffer).setUint32(0, 1 + grant.length, true);
  frame[4] = REQ_SESSION_GRANT_PRESENT;
  frame.set(grant, 5);
  return frame;
}

/**
 * Parse a response payload (starting at the variant byte) into the
 * remaining-credit count. A server `RESP_ERROR` throws with the server's
 * text so `classifySessionGrantFailure` can read it.
 */
export function parseSessionGrantResponsePayload(payload: Uint8Array): number {
  if (payload.length === 0) throw new Error('empty session grant response');
  const variant = payload[0];
  if (variant === RESP_ERROR) throw new Error(decodeErrorEnvelope(payload));
  if (variant !== RESP_SESSION_GRANT_OK) {
    throw new Error(
      `unexpected response variant 0x${variant.toString(16)} for session grant presentation`,
    );
  }
  if (payload.length !== 5) {
    throw new Error(`session grant response must be 5 bytes, got ${payload.length}`);
  }
  return new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(1, true);
}

function decodeErrorEnvelope(payload: Uint8Array): string {
  if (payload.length >= 5) {
    const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    const length = view.getUint32(1, true);
    if (5 + length <= payload.length) {
      return new TextDecoder().decode(payload.subarray(5, 5 + length));
    }
    return '<truncated error message>';
  }
  return new TextDecoder().decode(payload.subarray(1));
}

/**
 * Map a presentation failure to a UI state. "not enabled" is the free
 * path (no cashier key pinned on that server); everything else means the
 * grant itself was refused.
 */
export function classifySessionGrantFailure(message: string): SessionGrantPresentation {
  if (/not enabled/i.test(message)) return { state: 'not-enabled' };
  return { state: 'refused', error: message };
}

// ─── Grant store ────────────────────────────────────────────────────────────

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

function defaultStorage(): StorageLike | null {
  try {
    return (globalThis as { localStorage?: StorageLike }).localStorage ?? null;
  } catch {
    return null;
  }
}

/**
 * Persists the one grant the page currently spends. Expired grants are
 * dropped on load; remaining-credit counts are not persisted because every
 * server meters independently and reports the balance on presentation.
 */
export class SessionGrantStore {
  private readonly storage: StorageLike | null;
  private readonly key: string;

  constructor(storage: StorageLike | null = defaultStorage(), key = SESSION_GRANT_STORAGE_KEY) {
    this.storage = storage;
    this.key = key;
  }

  load(nowUnixSeconds = Math.floor(Date.now() / 1000)): StoredSessionGrant | null {
    if (!this.storage) return null;
    let raw: string | null;
    try {
      raw = this.storage.getItem(this.key);
    } catch {
      return null;
    }
    if (!raw) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      this.clear();
      return null;
    }
    const grant = readStoredGrant(parsed);
    if (!grant || grant.expiresAt <= nowUnixSeconds) {
      this.clear();
      return null;
    }
    return grant;
  }

  /** The grant bytes to present, or `null` when nothing valid is stored. */
  grantBytes(nowUnixSeconds?: number): Uint8Array | null {
    const grant = this.load(nowUnixSeconds);
    if (!grant) return null;
    try {
      const bytes = base64ToBytes(grant.grantBase64);
      decodeSessionGrantFields(bytes);
      return bytes;
    } catch {
      this.clear();
      return null;
    }
  }

  save(grant: StoredSessionGrant): void {
    if (!this.storage) return;
    try {
      this.storage.setItem(this.key, JSON.stringify(grant));
    } catch {
      // Storage may be unavailable (private mode); the grant still works
      // for this page lifetime through the caller's in-memory copy.
    }
  }

  clear(): void {
    if (!this.storage) return;
    try {
      this.storage.removeItem(this.key);
    } catch {
      // ignore
    }
  }
}

function readStoredGrant(value: unknown): StoredSessionGrant | null {
  if (!isRecord(value) || value.version !== 1) return null;
  const { grantBase64, grantIdHex, credits, issuedAt, expiresAt, cashierUrl } = value;
  if (
    typeof grantBase64 !== 'string'
    || typeof grantIdHex !== 'string'
    || !isPositiveInteger(credits)
    || !isNonNegativeInteger(issuedAt)
    || !isPositiveInteger(expiresAt)
    || typeof cashierUrl !== 'string'
  ) {
    return null;
  }
  return { version: 1, grantBase64, grantIdHex, credits, issuedAt, expiresAt, cashierUrl };
}

// ─── Cashier HTTP client ────────────────────────────────────────────────────

/**
 * Minimal client for the cashier contract in `docs/CASHIER_API.md`. The
 * cashier URL is a build-time pin (`PRODUCTION_CASHIER_URL`); no cookies,
 * no referrer, no cache.
 */
export class CashierClient {
  readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(baseUrl: string, fetchImpl?: typeof fetch) {
    if (!/^https:\/\/[^/]+/.test(baseUrl) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?/.test(baseUrl)) {
      throw new Error('cashier URL must be https:// (or a loopback http:// for development)');
    }
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    const impl = fetchImpl ?? (globalThis as { fetch?: typeof fetch }).fetch;
    if (!impl) throw new Error('fetch is unavailable in this environment');
    this.fetchImpl = impl;
  }

  async info(): Promise<CashierInfo> {
    return parseCashierInfo(await this.request('GET', '/v1/info'));
  }

  /**
   * Hand a Cashu token worth exactly `offer.amount` `offer.unit` to the
   * cashier and receive a grant for `offer.credits`. Re-sending the same
   * token after a network failure is safe: the cashier is idempotent per
   * token until the grant expires.
   */
  async redeem(offer: CashierOffer, token: string): Promise<IssuedGrant> {
    const trimmed = token.trim();
    if (!trimmed.startsWith('cashu')) throw new CashierError('not a Cashu token');
    const body = await this.request('POST', '/v1/grants', { offer, token: trimmed });
    return parseIssuedGrant(body, offer);
  }

  private async request(method: 'GET' | 'POST', path: string, json?: unknown): Promise<unknown> {
    const headers: Record<string, string> = { accept: 'application/json' };
    if (json !== undefined) headers['content-type'] = 'application/json';
    let response: Response;
    try {
      response = await this.fetchImpl(this.baseUrl + path, {
        method,
        headers,
        body: json === undefined ? undefined : JSON.stringify(json),
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
      });
    } catch (error) {
      throw new CashierError(`cashier unreachable: ${(error as Error)?.message ?? error}`);
    }
    const text = await response.text();
    let parsed: unknown = null;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = null;
      }
    }
    if (!response.ok) {
      const detail = isRecord(parsed) ? parsed : {};
      throw new CashierError(
        typeof detail.message === 'string' ? detail.message : `cashier responded ${response.status}`,
        response.status,
        typeof detail.error === 'string' ? detail.error : null,
      );
    }
    if (parsed === null) throw new CashierError('cashier returned no JSON body', response.status);
    return parsed;
  }
}

export function parseCashierOffer(value: unknown): CashierOffer {
  if (!isRecord(value)) throw new CashierError('cashier offer is not an object');
  const { credits, amount, unit } = value;
  if (!isPositiveInteger(credits) || !isPositiveInteger(amount) || typeof unit !== 'string' || !unit) {
    throw new CashierError('cashier offer has invalid fields');
  }
  return { credits, amount, unit };
}

export function parseCashierInfo(value: unknown): CashierInfo {
  if (!isRecord(value)) throw new CashierError('cashier info is not an object');
  if (value.version !== CASHIER_API_VERSION) {
    throw new CashierError(`unsupported cashier API version ${String(value.version)}`);
  }
  const { service, cashier_pubkey_hex: pubkey, mints, offers, grant_ttl_secs: ttl } = value;
  if (typeof service !== 'string' || typeof pubkey !== 'string' || !HEX_64.test(pubkey)) {
    throw new CashierError('cashier info has an invalid service or public key');
  }
  if (!Array.isArray(mints) || mints.length === 0
      || !mints.every((m) => typeof m === 'string' && /^https:\/\//.test(m))) {
    throw new CashierError('cashier info lists no https mint');
  }
  if (!Array.isArray(offers) || offers.length === 0) {
    throw new CashierError('cashier info lists no offers');
  }
  if (!isPositiveInteger(ttl)) throw new CashierError('cashier info has an invalid grant TTL');
  return {
    service,
    version: CASHIER_API_VERSION,
    cashierPubkeyHex: pubkey.toLowerCase(),
    mints: mints as string[],
    offers: offers.map(parseCashierOffer),
    grantTtlSecs: ttl,
  };
}

/**
 * Validate a `POST /v1/grants` body against the offer that was paid for:
 * the grant must decode, and its embedded fields must agree with both the
 * response metadata and the offer.
 */
export function parseIssuedGrant(value: unknown, offer: CashierOffer): IssuedGrant {
  if (!isRecord(value)) throw new CashierError('cashier grant response is not an object');
  const { grant_base64: grantBase64, grant_id_hex: grantIdHex, credits, expires_at: expiresAt } = value;
  if (typeof grantBase64 !== 'string') throw new CashierError('cashier response lacks grant_base64');
  let fields: SessionGrantFields;
  try {
    fields = decodeSessionGrantFields(base64ToBytes(grantBase64));
  } catch (error) {
    throw new CashierError(`cashier returned a malformed grant: ${(error as Error).message}`);
  }
  if (fields.credits !== offer.credits) {
    throw new CashierError(`cashier issued ${fields.credits} credits, offer was ${offer.credits}`);
  }
  if (typeof grantIdHex === 'string' && (!HEX_32.test(grantIdHex) || grantIdHex.toLowerCase() !== fields.grantIdHex)) {
    throw new CashierError('cashier grant_id_hex disagrees with the grant');
  }
  if (credits !== undefined && credits !== fields.credits) {
    throw new CashierError('cashier credits disagree with the grant');
  }
  if (expiresAt !== undefined && expiresAt !== fields.expiresAt) {
    throw new CashierError('cashier expires_at disagrees with the grant');
  }
  return {
    grantBase64: bytesToBase64(base64ToBytes(grantBase64)),
    grantIdHex: fields.grantIdHex,
    credits: fields.credits,
    issuedAt: fields.issuedAt,
    expiresAt: fields.expiresAt,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}
