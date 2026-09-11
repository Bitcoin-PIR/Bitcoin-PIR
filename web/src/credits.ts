/**
 * Credits (paid queries, v2), browser side. Design: `docs/CREDITS.md`.
 *
 * - `IssuerClient`: the issuer's `/v2/` contract (`info`, `credentials`).
 * - `CreditStore`: ARC credentials and the in-flight purchase in
 *   `localStorage`, so a reload never loses paid sats or a nonce.
 * - Frame codec for `REQ_CREDIT_PRESENT` / `RESP_CREDIT_OK`.
 * - `serverGasCardFromInfo` and `ConnectionCreditMeter`: price a frame the
 *   way the server does and decide when a top-up is due.
 * - `CreditWallet`: turn credentials into kind-2 payloads, persisting the
 *   nonce before the payload leaves (a reused nonce is a double spend).
 * - `purchaseCredential`: Lightning → ecash → blinded request → credential.
 *
 * The ARC cryptography lives in the wasm SDK (`WasmArcCredentialRequest`,
 * `WasmArcCredential`); this module takes those as injected factories so
 * everything here is testable without wasm.
 */

import {
  MAX_CREDIT_PRESENT_PAYLOAD_LEN,
  REQ_CREDIT_PRESENT,
  RESP_CREDIT_OK,
} from './constants.js';
import type { StorageLike } from './session-grant.js';
import { mintTokenForQuote, requestLightningQuote, waitForQuotePayment } from './cashu-purchase.js';

const RESP_ERROR = 0xff;
export const CREDITS_API_VERSION = 2;
export const CREDIT_PRESENT_KIND_CASHU = 1;
export const CREDIT_PRESENT_KIND_ARC = 2;
export const CREDIT_STORAGE_KEY = 'bitcoinpir.credits.v1';
export const PENDING_CREDENTIAL_STORAGE_KEY = 'bitcoinpir.credits.pending-credential.v1';

// ─── Issuer contract ────────────────────────────────────────────────────────

export interface GasParams {
  creditSat: number;
  gasPerCredit: number;
  baseGasPerFrame: number;
  egressGasPerMb: number;
}

export interface ArcInfo {
  epoch: number;
  presentationLimit: number;
  issuerPublicKeyHex: string;
  presentationContextHex: string;
  validUntil: number;
}

export interface CreditOffer {
  credits: number;
  sat: number;
}

export interface IssuerInfo {
  service: string;
  version: number;
  gas: GasParams;
  mints: string[];
  offers: CreditOffer[];
  arc: ArcInfo | null;
  rateCard: { flow: string; credits: number }[];
}

/** `POST /v2/credentials` answer, decoded. */
export interface IssuedCredential {
  responseHex: string;
  epoch: number;
  presentationLimit: number;
  issuerPublicKeyHex: string;
  validUntil: number;
}

export class IssuerError extends Error {
  readonly status: number | null;
  readonly code: string | null;

  constructor(message: string, status: number | null = null, code: string | null = null) {
    super(message);
    this.name = 'IssuerError';
    this.status = status;
    this.code = code;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function positiveInt(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new IssuerError(`issuer info: ${what} is not a non-negative integer`);
  }
  return value;
}

export function parseGasParams(raw: unknown): GasParams {
  if (!isRecord(raw)) throw new IssuerError('issuer info: gas parameters missing');
  const params = {
    creditSat: positiveInt(raw.credit_sat, 'credit_sat'),
    gasPerCredit: positiveInt(raw.gas_per_credit, 'gas_per_credit'),
    baseGasPerFrame: positiveInt(raw.base_gas_per_frame, 'base_gas_per_frame'),
    egressGasPerMb: positiveInt(raw.egress_gas_per_mb, 'egress_gas_per_mb'),
  };
  if (params.creditSat === 0 || params.gasPerCredit === 0) {
    throw new IssuerError('issuer info: credit_sat and gas_per_credit must be positive');
  }
  return params;
}

export function parseIssuerInfo(raw: unknown): IssuerInfo {
  if (!isRecord(raw)) throw new IssuerError('issuer info is not an object');
  if (raw.version !== CREDITS_API_VERSION) {
    throw new IssuerError(`issuer speaks version ${String(raw.version)}, this client ${CREDITS_API_VERSION}`);
  }
  const gas = parseGasParams(raw);
  const mints = Array.isArray(raw.mints) ? raw.mints.filter((m): m is string => typeof m === 'string') : [];
  const offers: CreditOffer[] = [];
  if (Array.isArray(raw.offers)) {
    for (const offer of raw.offers) {
      if (!isRecord(offer)) continue;
      const credits = positiveInt(offer.credits, 'offer credits');
      const sat = positiveInt(offer.sat, 'offer sat');
      if (credits > 0 && sat > 0) offers.push({ credits, sat });
    }
  }
  let arc: ArcInfo | null = null;
  if (isRecord(raw.arc)) {
    const a = raw.arc;
    if (typeof a.issuer_public_key_hex !== 'string' || !/^[0-9a-f]{198}$/i.test(a.issuer_public_key_hex)) {
      throw new IssuerError('issuer info: arc.issuer_public_key_hex must be 99 bytes of hex');
    }
    arc = {
      epoch: positiveInt(a.epoch, 'arc.epoch'),
      presentationLimit: positiveInt(a.presentation_limit, 'arc.presentation_limit'),
      issuerPublicKeyHex: a.issuer_public_key_hex.toLowerCase(),
      presentationContextHex: typeof a.presentation_context_hex === 'string' ? a.presentation_context_hex : '',
      validUntil: positiveInt(a.valid_until, 'arc.valid_until'),
    };
    if (arc.presentationLimit === 0) throw new IssuerError('issuer info: arc.presentation_limit is zero');
  }
  const rateCard: { flow: string; credits: number }[] = [];
  if (Array.isArray(raw.rate_card)) {
    for (const entry of raw.rate_card) {
      if (isRecord(entry) && typeof entry.flow === 'string' && typeof entry.credits === 'number') {
        rateCard.push({ flow: entry.flow, credits: entry.credits });
      }
    }
  }
  return {
    service: typeof raw.service === 'string' ? raw.service : '',
    version: CREDITS_API_VERSION,
    gas,
    mints,
    offers,
    arc,
    rateCard,
  };
}

export function parseIssuedCredential(raw: unknown): IssuedCredential {
  if (!isRecord(raw)) throw new IssuerError('credential response is not an object');
  if (typeof raw.response_hex !== 'string' || !/^([0-9a-f]{2})+$/i.test(raw.response_hex)) {
    throw new IssuerError('credential response: response_hex is not hex');
  }
  if (typeof raw.issuer_public_key_hex !== 'string' || !/^[0-9a-f]{198}$/i.test(raw.issuer_public_key_hex)) {
    throw new IssuerError('credential response: issuer_public_key_hex must be 99 bytes of hex');
  }
  return {
    responseHex: raw.response_hex.toLowerCase(),
    epoch: positiveInt(raw.epoch, 'epoch'),
    presentationLimit: positiveInt(raw.presentation_limit, 'presentation_limit'),
    issuerPublicKeyHex: raw.issuer_public_key_hex.toLowerCase(),
    validUntil: positiveInt(raw.valid_until, 'valid_until'),
  };
}

export class IssuerClient {
  readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(baseUrl: string, fetchImpl?: typeof fetch) {
    if (!/^https:\/\/[^/]+/.test(baseUrl) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?/.test(baseUrl)) {
      throw new Error('issuer URL must be https:// (or a loopback http:// for development)');
    }
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    const native = (globalThis as { fetch?: typeof fetch }).fetch;
    if (!fetchImpl && !native) throw new Error('fetch is unavailable in this environment');
    this.fetchImpl = fetchImpl ?? ((input, init) => native!.call(globalThis, input, init));
  }

  async info(): Promise<IssuerInfo> {
    return parseIssuerInfo(await this.request('GET', '/v2/info'));
  }

  /** Pay `offer` with `token` for the blinded `requestBytes`. */
  async buyCredential(offer: CreditOffer, token: string, requestBytes: Uint8Array): Promise<IssuedCredential> {
    return parseIssuedCredential(
      await this.request('POST', '/v2/credentials', {
        credits: offer.credits,
        sat: offer.sat,
        token,
        request_hex: bytesToHex(requestBytes),
      }),
    );
  }

  private async request(method: 'GET' | 'POST', path: string, json?: unknown): Promise<unknown> {
    const headers: Record<string, string> = { accept: 'application/json' };
    if (json !== undefined) headers['content-type'] = 'application/json';
    let response: Response;
    const fetchImpl = this.fetchImpl;
    try {
      response = await fetchImpl(this.baseUrl + path, {
        method,
        headers,
        body: json === undefined ? undefined : JSON.stringify(json),
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
      });
    } catch (error) {
      throw new IssuerError(`issuer unreachable: ${(error as Error)?.message ?? error}`);
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
      throw new IssuerError(
        typeof detail.message === 'string' ? detail.message : `issuer responded ${response.status}`,
        response.status,
        typeof detail.error === 'string' ? detail.error : null,
      );
    }
    return parsed;
  }
}

// ─── Encoding helpers ───────────────────────────────────────────────────────

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(text: string): Uint8Array {
  const clean = text.trim();
  if (clean.length % 2 !== 0 || !/^([0-9a-f]{2})*$/i.test(clean)) throw new Error('invalid hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** `[len u32 LE][0x12][kind][payload len u32 LE][payload]`, ready to send. */
export function encodeCreditPresentFrame(kind: number, payload: Uint8Array): Uint8Array {
  if (kind !== CREDIT_PRESENT_KIND_CASHU && kind !== CREDIT_PRESENT_KIND_ARC) {
    throw new Error(`unknown credit presentation kind ${kind}`);
  }
  if (payload.length === 0) throw new Error('empty credit presentation');
  if (payload.length > MAX_CREDIT_PRESENT_PAYLOAD_LEN) {
    throw new Error(`credit presentation is ${payload.length} bytes, the limit is ${MAX_CREDIT_PRESENT_PAYLOAD_LEN}`);
  }
  const frame = new Uint8Array(4 + 1 + 1 + 4 + payload.length);
  const view = new DataView(frame.buffer);
  view.setUint32(0, 1 + 1 + 4 + payload.length, true);
  frame[4] = REQ_CREDIT_PRESENT;
  frame[5] = kind;
  view.setUint32(6, payload.length, true);
  frame.set(payload, 10);
  return frame;
}

export interface CreditReceipt {
  gasAdded: number;
  gasBalance: number;
}

/** Parse a response payload (starting at the variant byte). */
export function parseCreditResponsePayload(payload: Uint8Array): CreditReceipt {
  if (payload.length === 0) throw new Error('empty credit response');
  const variant = payload[0];
  if (variant === RESP_ERROR) throw new Error(decodeErrorEnvelope(payload));
  if (variant !== RESP_CREDIT_OK) {
    throw new Error(`unexpected response variant 0x${variant.toString(16)} for credit presentation`);
  }
  if (payload.length !== 17) throw new Error(`credit response must be 17 bytes, got ${payload.length}`);
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  return {
    gasAdded: Number(view.getBigUint64(1, true)),
    gasBalance: Number(view.getBigInt64(9, true)),
  };
}

function decodeErrorEnvelope(payload: Uint8Array): string {
  if (payload.length >= 5) {
    const len = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(1, true);
    if (5 + len <= payload.length) return new TextDecoder().decode(payload.subarray(5, 5 + len));
    return '<truncated error message>';
  }
  return new TextDecoder().decode(payload.subarray(1));
}

/** "insufficient gas: this frame needs N and the connection has M; …" */
export function parseInsufficientGas(message: string): { needed: number; balance: number } | null {
  const match = /^insufficient gas: this frame needs (\d+) and the connection has (-?\d+);/.exec(message);
  if (!match) return null;
  return { needed: Number(match[1]), balance: Number(match[2]) };
}

// ─── Gas card and meter ─────────────────────────────────────────────────────

export interface DatabaseGasCard {
  dpfIndexRound?: number;
  dpfChunkRound?: number;
  dpfIndexSiblingPass: number[];
  dpfChunkSiblingPass: number[];
  treeTops?: number;
  onionRegisterKeys?: number;
  onionIndexQuery?: number;
  onionChunkQuery?: number;
  onionSiblingQuery?: number;
  harmonyPoolEntry?: number;
  harmonyIndexSiblingSet: number[];
  harmonyChunkSiblingSet: number[];
  harmonyQueryIndex?: number;
  harmonyQueryChunk?: number;
  oramLookup?: number;
}

export interface ServerGasCard {
  unit: string;
  params: GasParams;
  databases: Record<string, DatabaseGasCard>;
}

export type MeteredOp =
  | { kind: 'dpf_index_round' }
  | { kind: 'dpf_chunk_round' }
  | { kind: 'dpf_sibling_pass'; table: 'index' | 'chunk'; level: number }
  | { kind: 'tree_tops' }
  | { kind: 'onion_register_keys' }
  | { kind: 'onion_index_query' }
  | { kind: 'onion_chunk_query' }
  | { kind: 'onion_sibling_query' }
  | { kind: 'onion_tree_tops' }
  | { kind: 'harmony_pool_entry' }
  | { kind: 'harmony_continuation' }
  | { kind: 'harmony_hint_set'; level: number }
  | { kind: 'harmony_query'; level: number; subQueries: number }
  | { kind: 'oram_lookup' };

function optionalNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : undefined;
}

function numberList(value: unknown): number[] {
  return Array.isArray(value) ? value.filter((v): v is number => typeof v === 'number' && v >= 0) : [];
}

/** The `"gas"` section of a server's info JSON, or `null` on older servers. */
export function serverGasCardFromInfo(info: unknown): ServerGasCard | null {
  if (!isRecord(info) || !isRecord(info.gas)) return null;
  const gas = info.gas;
  const params = parseGasParams(gas.params);
  const databases: Record<string, DatabaseGasCard> = {};
  if (isRecord(gas.databases)) {
    for (const [dbId, raw] of Object.entries(gas.databases)) {
      if (!isRecord(raw)) continue;
      databases[dbId] = {
        dpfIndexRound: optionalNumber(raw.dpf_index_round),
        dpfChunkRound: optionalNumber(raw.dpf_chunk_round),
        dpfIndexSiblingPass: numberList(raw.dpf_index_sibling_pass),
        dpfChunkSiblingPass: numberList(raw.dpf_chunk_sibling_pass),
        treeTops: optionalNumber(raw.tree_tops),
        onionRegisterKeys: optionalNumber(raw.onion_register_keys),
        onionIndexQuery: optionalNumber(raw.onion_index_query),
        onionChunkQuery: optionalNumber(raw.onion_chunk_query),
        onionSiblingQuery: optionalNumber(raw.onion_sibling_query),
        harmonyPoolEntry: optionalNumber(raw.harmony_pool_entry),
        harmonyIndexSiblingSet: numberList(raw.harmony_index_sibling_set),
        harmonyChunkSiblingSet: numberList(raw.harmony_chunk_sibling_set),
        harmonyQueryIndex: optionalNumber(raw.harmony_query_index),
        harmonyQueryChunk: optionalNumber(raw.harmony_query_chunk),
        oramLookup: optionalNumber(raw.oram_lookup),
      };
    }
  }
  return { unit: typeof gas.unit === 'string' ? gas.unit : '', params, databases };
}

/** Work gas of `op` on one database, `null` when that backend is not served there. */
export function workGas(card: DatabaseGasCard, op: MeteredOp): number | null {
  const pick = (value: number | undefined) => (value === undefined ? null : value);
  switch (op.kind) {
    case 'dpf_index_round':
      return pick(card.dpfIndexRound);
    case 'dpf_chunk_round':
      return pick(card.dpfChunkRound);
    case 'dpf_sibling_pass': {
      const passes = op.table === 'index' ? card.dpfIndexSiblingPass : card.dpfChunkSiblingPass;
      return op.level < passes.length ? passes[op.level] : null;
    }
    case 'tree_tops':
      return pick(card.treeTops);
    case 'onion_register_keys':
      return pick(card.onionRegisterKeys);
    case 'onion_index_query':
      return pick(card.onionIndexQuery);
    case 'onion_chunk_query':
      return pick(card.onionChunkQuery);
    case 'onion_sibling_query':
      return pick(card.onionSiblingQuery);
    case 'onion_tree_tops':
      return card.onionIndexQuery === undefined ? null : (card.treeTops ?? 5);
    case 'harmony_pool_entry':
      return pick(card.harmonyPoolEntry);
    case 'harmony_continuation':
      return card.harmonyPoolEntry === undefined ? null : 0;
    case 'harmony_hint_set': {
      if (op.level === 0) return card.harmonyPoolEntry === undefined ? null : Math.floor(card.harmonyPoolEntry / 3);
      if (op.level === 1) return card.harmonyPoolEntry === undefined ? null : card.harmonyPoolEntry - Math.floor(card.harmonyPoolEntry / 3);
      const sets = op.level >= 20 ? card.harmonyChunkSiblingSet : op.level >= 10 ? card.harmonyIndexSiblingSet : null;
      if (!sets) return null;
      const index = op.level >= 20 ? op.level - 20 : op.level - 10;
      return index < sets.length ? sets[index] : null;
    }
    case 'harmony_query': {
      const single = op.level === 1 || op.level >= 20 ? card.harmonyQueryChunk : card.harmonyQueryIndex;
      return single === undefined ? null : single * Math.max(1, op.subQueries);
    }
    case 'oram_lookup':
      return pick(card.oramLookup);
  }
}

export function egressGas(params: GasParams, responseBytes: number): number {
  return Math.floor((responseBytes * params.egressGasPerMb) / 1_000_000);
}

export function creditsToCover(params: GasParams, gas: number): number {
  return gas <= 0 ? 0 : Math.ceil(gas / params.gasPerCredit);
}

/** The client's view of one connection's gas balance. */
export class ConnectionCreditMeter {
  readonly card: ServerGasCard;
  private gas = 0;

  constructor(card: ServerGasCard) {
    this.card = card;
  }

  get balance(): number {
    return this.gas;
  }

  /** Work plus base fee the server charges before dispatch, `null` when unmetered. */
  frameGas(dbId: number, op: MeteredOp): number | null {
    const db = this.card.databases[String(dbId)];
    if (!db) return null;
    const work = workGas(db, op);
    return work === null ? null : work + this.card.params.baseGasPerFrame;
  }

  /** Credits to present so the balance covers `frameGas` plus the expected egress. */
  creditsToPresent(frameGas: number, expectedResponseBytes = 0): number {
    const needed = frameGas + egressGas(this.card.params, expectedResponseBytes);
    return creditsToCover(this.card.params, needed - this.gas);
  }

  recordReceipt(receipt: CreditReceipt): void {
    this.gas = receipt.gasBalance;
  }

  recordFrame(frameGas: number): void {
    this.gas -= frameGas;
  }

  recordResponse(responseBytes: number): void {
    this.gas -= egressGas(this.card.params, responseBytes);
  }

  /** The server refused a frame and named its numbers: adopt them. */
  recordRefusal(message: string): number | null {
    const parsed = parseInsufficientGas(message);
    if (!parsed) return null;
    this.gas = parsed.balance;
    return parsed.needed;
  }
}

// ─── Store ──────────────────────────────────────────────────────────────────

export interface StoredCredential {
  version: 1;
  issuerUrl: string;
  epoch: number;
  presentationLimit: number;
  /** 131 bytes from `WasmArcCredentialRequest.finalize`, hex. */
  credentialHex: string;
  nextNonce: number;
  issuerPublicKeyHex: string;
  validUntil: number;
  boughtAt: number;
}

/** A purchase in flight, persisted step by step. */
export interface PendingCredential {
  version: 1;
  issuerUrl: string;
  mintUrl: string;
  offer: CreditOffer;
  epoch: number;
  /** `WasmArcCredentialRequest.secretsBytes()` / `.requestBytes()`, hex. */
  secretsHex: string;
  requestHex: string;
  quoteId: string | null;
  invoice: string | null;
  quoteExpiry: number | null;
  token: string | null;
  createdAt: number;
}

function defaultStorage(): StorageLike | null {
  try {
    return (globalThis as { localStorage?: StorageLike }).localStorage ?? null;
  } catch {
    return null;
  }
}

export class CreditStore {
  private readonly storage: StorageLike | null;
  private readonly key: string;
  private readonly pendingKey: string;

  constructor(
    storage: StorageLike | null = defaultStorage(),
    key = CREDIT_STORAGE_KEY,
    pendingKey = PENDING_CREDENTIAL_STORAGE_KEY,
  ) {
    this.storage = storage;
    this.key = key;
    this.pendingKey = pendingKey;
  }

  list(): StoredCredential[] {
    const raw = this.read(this.key);
    if (!Array.isArray(raw)) return [];
    return raw.filter(isStoredCredential);
  }

  /** Credentials with presentations left, most nearly exhausted first. */
  usable(now: number): StoredCredential[] {
    return this.list()
      .filter((c) => c.nextNonce < c.presentationLimit && c.validUntil > now)
      .sort((a, b) => a.presentationLimit - a.nextNonce - (b.presentationLimit - b.nextNonce));
  }

  add(credential: StoredCredential): void {
    const list = this.list().filter((c) => c.credentialHex !== credential.credentialHex);
    list.push(credential);
    this.write(this.key, list);
  }

  /** Persist a new nonce; returns false if the credential is unknown. */
  advance(credentialHex: string, nextNonce: number): boolean {
    const list = this.list();
    const entry = list.find((c) => c.credentialHex === credentialHex);
    if (!entry) return false;
    if (nextNonce < entry.nextNonce) throw new Error('credential nonce cannot move backwards');
    entry.nextNonce = nextNonce;
    this.write(this.key, list);
    return true;
  }

  remove(credentialHex: string): void {
    this.write(this.key, this.list().filter((c) => c.credentialHex !== credentialHex));
  }

  /** Credits left across every usable credential. */
  remainingCredits(now: number): number {
    return this.usable(now).reduce((sum, c) => sum + (c.presentationLimit - c.nextNonce), 0);
  }

  pending(): PendingCredential | null {
    const raw = this.read(this.pendingKey);
    return isPendingCredential(raw) ? raw : null;
  }

  setPending(pending: PendingCredential | null): void {
    if (pending === null) {
      try {
        this.storage?.removeItem(this.pendingKey);
      } catch {
        /* storage unavailable */
      }
      return;
    }
    this.write(this.pendingKey, pending);
  }

  private read(key: string): unknown {
    try {
      const text = this.storage?.getItem(key);
      return text ? JSON.parse(text) : null;
    } catch {
      return null;
    }
  }

  private write(key: string, value: unknown): void {
    try {
      this.storage?.setItem(key, JSON.stringify(value));
    } catch {
      /* storage unavailable: the caller keeps working from memory */
    }
  }
}

function isStoredCredential(value: unknown): value is StoredCredential {
  return (
    isRecord(value) &&
    value.version === 1 &&
    typeof value.issuerUrl === 'string' &&
    typeof value.epoch === 'number' &&
    typeof value.presentationLimit === 'number' &&
    typeof value.credentialHex === 'string' &&
    typeof value.nextNonce === 'number' &&
    typeof value.issuerPublicKeyHex === 'string' &&
    typeof value.validUntil === 'number' &&
    typeof value.boughtAt === 'number'
  );
}

function isPendingCredential(value: unknown): value is PendingCredential {
  return (
    isRecord(value) &&
    value.version === 1 &&
    typeof value.issuerUrl === 'string' &&
    typeof value.mintUrl === 'string' &&
    isRecord(value.offer) &&
    typeof value.epoch === 'number' &&
    typeof value.secretsHex === 'string' &&
    typeof value.requestHex === 'string' &&
    typeof value.createdAt === 'number'
  );
}

// ─── Frame classification (the OnionPIR web client) ─────────────────────────

const REQ_REGISTER_KEYS = 0x50;
const REQ_ONIONPIR_INDEX_QUERY = 0x51;
const REQ_ONIONPIR_CHUNK_QUERY = 0x52;
const REQ_ONIONPIR_MERKLE_INDEX_SIBLING = 0x53;
const REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP = 0x54;
const REQ_ONIONPIR_MERKLE_DATA_SIBLING = 0x55;
const REQ_ONIONPIR_MERKLE_DATA_TREE_TOP = 0x56;

/**
 * The metered kind and database of an outgoing OnionPIR frame
 * (`[len u32][variant][body]`), mirroring the server's classifier; `null`
 * for unmetered variants and frames the server would not decode. The
 * wasm-backed clients classify inside the SDK; only the standalone
 * OnionPIR client sends frames from TypeScript.
 */
export function classifyOnionFrame(frame: Uint8Array): { op: MeteredOp; dbId: number } | null {
  if (frame.length < 5) return null;
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  if (view.getUint32(0, true) !== frame.length - 4) return null;
  const variant = frame[4];
  let pos = 5;
  const trailingDbId = (): number | null => {
    const left = frame.length - pos;
    return left === 0 ? 0 : left === 1 ? frame[pos] : null;
  };
  switch (variant) {
    case REQ_REGISTER_KEYS: {
      for (let i = 0; i < 2; i++) {
        if (pos + 4 > frame.length) return null;
        const len = view.getUint32(pos, true);
        pos += 4 + len;
        if (pos > frame.length) return null;
      }
      const dbId = trailingDbId();
      return dbId === null ? null : { op: { kind: 'onion_register_keys' }, dbId };
    }
    case REQ_ONIONPIR_INDEX_QUERY:
    case REQ_ONIONPIR_CHUNK_QUERY:
    case REQ_ONIONPIR_MERKLE_INDEX_SIBLING:
    case REQ_ONIONPIR_MERKLE_DATA_SIBLING: {
      if (pos + 3 > frame.length) return null;
      pos += 2; // round_id
      const queries = frame[pos++];
      for (let i = 0; i < queries; i++) {
        if (pos + 4 > frame.length) return null;
        const len = view.getUint32(pos, true);
        pos += 4 + len;
        if (pos > frame.length) return null;
      }
      const dbId = trailingDbId();
      if (dbId === null) return null;
      const op: MeteredOp =
        variant === REQ_ONIONPIR_INDEX_QUERY
          ? { kind: 'onion_index_query' }
          : variant === REQ_ONIONPIR_CHUNK_QUERY
            ? { kind: 'onion_chunk_query' }
            : { kind: 'onion_sibling_query' };
      return { op, dbId };
    }
    case REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP:
    case REQ_ONIONPIR_MERKLE_DATA_TREE_TOP: {
      const dbId = trailingDbId();
      return dbId === null ? null : { op: { kind: 'onion_tree_tops' }, dbId };
    }
    default:
      return null;
  }
}

/** Response bytes pre-funded before a metered frame (see the SDK's `credit_frames`). */
export function expectedResponseBytes(op: MeteredOp): number {
  const KB = 1024;
  const MB = 1024 * 1024;
  switch (op.kind) {
    case 'onion_register_keys':
      return KB;
    case 'onion_index_query':
      return 2 * MB;
    case 'onion_chunk_query':
    case 'onion_sibling_query':
      return MB;
    case 'onion_tree_tops':
      return 2 * MB;
    case 'tree_tops':
      return 12 * MB;
    case 'harmony_pool_entry':
      return 20 * MB;
    case 'harmony_continuation':
      return 16 * MB;
    case 'harmony_hint_set':
    case 'harmony_query': {
      if (op.level === 0) return 5 * MB;
      if (op.level === 1) return 16 * MB;
      const sibling = op.level >= 20 ? op.level - 20 : op.level - 10;
      const table = op.level >= 20 ? [12 * MB, 4 * MB, 2 * MB, 2 * MB] : [8 * MB, 3 * MB, MB, MB];
      return table[Math.min(sibling, 3)];
    }
    case 'dpf_index_round':
      return 16 * KB;
    case 'oram_lookup':
      return 64 * KB;
    default:
      return 32 * KB;
  }
}

// ─── Credited channel (one connection's balance, round-trip flows) ──────────

/** Hands over up to `credits` credits as one presentation, or `null` when empty. */
export type CreditProvider = (credits: number) => Presentation | null;

/** Sends a whole frame (`[len u32][payload]`) and returns the whole response frame. */
export type FrameExchange = (frame: Uint8Array) => Promise<Uint8Array>;

/** What enabling credits on one connection came to. */
export interface CreditEnablement {
  state: 'not-enabled' | 'not-required' | 'required' | 'error';
  error?: string;
}

/**
 * Keeps one round-trip connection funded: price a frame like the server
 * does, present credits first when the balance would not cover it, charge
 * egress when the response arrives, resynchronise from receipts and from a
 * refusal's own numbers (retrying once).
 */
export class CreditedChannel {
  readonly meter: ConnectionCreditMeter;
  private readonly observed = new Map<string, number>();
  private presented = 0;

  constructor(
    card: ServerGasCard,
    private readonly provider: CreditProvider,
    private readonly exchange: FrameExchange,
  ) {
    this.meter = new ConnectionCreditMeter(card);
  }

  get presentedCredits(): number {
    return this.presented;
  }

  private reserve(op: MeteredOp): number {
    const seen = this.observed.get(op.kind);
    const bytes = seen === undefined ? expectedResponseBytes(op) : seen + Math.floor(seen / 8);
    return egressGas(this.meter.card.params, bytes);
  }

  private async topUp(needed: number): Promise<void> {
    for (let attempt = 0; this.meter.balance < needed; attempt++) {
      if (attempt >= 4) throw new Error('credits: the balance did not reach the frame price after four presentations');
      const credits = Math.max(1, this.meter.creditsToPresent(needed, 0));
      const presentation = this.provider(credits);
      if (!presentation) {
        throw new Error(`credits required: this frame needs ${credits} more credit(s) and the wallet has none`);
      }
      const response = await this.exchange(encodeCreditPresentFrame(presentation.kind, presentation.payload));
      const receipt = parseCreditResponsePayload(response.subarray(4));
      this.presented += presentation.credits;
      this.meter.recordReceipt(receipt);
    }
  }

  /**
   * Send `frame` through `exchange`, funding it first when it is metered
   * and retrying once when the server still refuses it for gas.
   */
  async roundtrip(frame: Uint8Array): Promise<Uint8Array> {
    const classified = classifyOnionFrame(frame);
    const gas = classified ? this.meter.frameGas(classified.dbId, classified.op) : null;
    if (classified === null || gas === null) return this.exchange(frame);
    await this.topUp(gas + this.reserve(classified.op));
    this.meter.recordFrame(gas);
    let response = await this.exchange(frame);
    const refusal = response[4] === 0xff ? parseInsufficientGas(errorMessage(response.subarray(4))) : null;
    if (refusal) {
      this.meter.recordRefusal(errorMessage(response.subarray(4)));
      await this.topUp(refusal.needed + this.reserve(classified.op));
      this.meter.recordFrame(refusal.needed);
      response = await this.exchange(frame);
    }
    this.meter.recordResponse(response.length);
    const seen = this.observed.get(classified.op.kind) ?? 0;
    this.observed.set(classified.op.kind, Math.max(seen, response.length));
    return response;
  }
}

function errorMessage(payload: Uint8Array): string {
  if (payload.length >= 5) {
    const len = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(1, true);
    if (5 + len <= payload.length) return new TextDecoder().decode(payload.subarray(5, 5 + len));
  }
  return new TextDecoder().decode(payload.subarray(1));
}

// ─── Wallet: credentials → presentations ────────────────────────────────────

/** What the wasm SDK's `WasmArcCredential` provides. */
export interface ArcCredentialLike {
  remaining(): number;
  nextNonce(): number;
  present(count: number): Uint8Array;
  free?(): void;
}

export interface ArcCredentialFactory {
  open(credential: Uint8Array, epoch: number, presentationLimit: number, nextNonce: number): ArcCredentialLike;
}

export interface Presentation {
  kind: number;
  payload: Uint8Array;
  credits: number;
  epoch: number;
}

export class CreditWallet {
  constructor(
    private readonly store: CreditStore,
    private readonly arc: ArcCredentialFactory,
    private readonly now: () => number = () => Math.floor(Date.now() / 1000),
  ) {}

  remainingCredits(): number {
    return this.store.remainingCredits(this.now());
  }

  /**
   * A kind-2 payload worth up to `count` credits from one credential (a
   * payload carries one epoch). The nonce is persisted before the payload
   * is returned. `null` when nothing is left.
   */
  present(count: number): Presentation | null {
    if (count < 1) throw new Error('present: count must be at least 1');
    const candidates = this.store.usable(this.now());
    if (candidates.length === 0) return null;
    // Prefer a credential that covers the whole request; else the fullest.
    const covering = candidates.find((c) => c.presentationLimit - c.nextNonce >= count);
    const chosen = covering ?? candidates.reduce((a, b) => (a.presentationLimit - a.nextNonce >= b.presentationLimit - b.nextNonce ? a : b));
    const credits = Math.min(count, chosen.presentationLimit - chosen.nextNonce);
    const holder = this.arc.open(hexToBytes(chosen.credentialHex), chosen.epoch, chosen.presentationLimit, chosen.nextNonce);
    try {
      const payload = holder.present(credits);
      this.store.advance(chosen.credentialHex, holder.nextNonce());
      return { kind: CREDIT_PRESENT_KIND_ARC, payload, credits, epoch: chosen.epoch };
    } finally {
      holder.free?.();
    }
  }
}

// ─── Purchase flow ──────────────────────────────────────────────────────────

/** What the wasm SDK's `WasmArcCredentialRequest` provides. */
export interface ArcRequestLike {
  requestBytes(): Uint8Array;
  secretsBytes(): Uint8Array;
  finalize(issuerPublicKeyHex: string, response: Uint8Array): Uint8Array;
  free?(): void;
}

export interface ArcRequestFactory {
  create(epoch: number): ArcRequestLike;
  restore(epoch: number, secrets: Uint8Array, request: Uint8Array): ArcRequestLike;
}

/** Lightning → ecash, as `cashu-purchase.ts` implements it. */
export interface LightningRail {
  quote(mintUrl: string, amountSat: number, memo: string): Promise<{ quoteId: string; invoice: string; expiry: number | null }>;
  waitPaid(mintUrl: string, quoteId: string, signal?: AbortSignal): Promise<void>;
  mint(mintUrl: string, amountSat: number, quoteId: string): Promise<string>;
}

/**
 * The Lightning → ecash rail of `cashu-purchase.ts` (cashu-ts loaded on
 * demand) in the shape `purchaseCredential` takes.
 */
export function cashuLightningRail(): LightningRail {
  const offer = (amountSat: number, credits = 0) => ({ credits, amount: amountSat, unit: 'sat' });
  return {
    quote: async (mintUrl, amountSat, memo) => {
      const credits = Number(/(\d+) credits/.exec(memo)?.[1] ?? 0);
      const quote = await requestLightningQuote(mintUrl, offer(amountSat, credits));
      return { quoteId: quote.quoteId, invoice: quote.invoice, expiry: quote.expiry };
    },
    waitPaid: async (mintUrl, quoteId, signal) => {
      await waitForQuotePayment(mintUrl, 'sat', quoteId, { signal });
    },
    mint: (mintUrl, amountSat, quoteId) => mintTokenForQuote(mintUrl, offer(amountSat), quoteId),
  };
}

export interface PurchaseHooks {
  onInvoice?: (invoice: string, expiry: number | null) => void;
  onStatus?: (status: 'quoting' | 'awaiting-payment' | 'minting' | 'issuing' | 'finalizing' | 'stored') => void;
  signal?: AbortSignal;
}

/**
 * Buy one credential: pick the issuer's epoch, persist the blinded request
 * first, pay the pack over Lightning at `mintUrl`, hand token and request
 * to the issuer, finish the credential, store it. Resumable: a stored
 * pending purchase is continued from its last completed step.
 */
export async function purchaseCredential(
  issuer: IssuerClient,
  store: CreditStore,
  arc: ArcRequestFactory,
  rail: LightningRail,
  offer: CreditOffer,
  mintUrl: string,
  hooks: PurchaseHooks = {},
  now: () => number = () => Math.floor(Date.now() / 1000),
): Promise<StoredCredential> {
  let pending = store.pending();
  let info: IssuerInfo | null = null;
  if (!pending || pending.issuerUrl !== issuer.baseUrl) {
    info = await issuer.info();
    if (!info.arc) throw new IssuerError('this issuer sells no credentials');
    if (!info.offers.some((o) => o.credits === offer.credits && o.sat === offer.sat)) {
      throw new IssuerError('offer is not listed by the issuer');
    }
    if (!info.mints.includes(mintUrl)) throw new IssuerError('mint is not accepted by the issuer');
    const request = arc.create(info.arc.epoch);
    try {
      pending = {
        version: 1,
        issuerUrl: issuer.baseUrl,
        mintUrl,
        offer,
        epoch: info.arc.epoch,
        secretsHex: bytesToHex(request.secretsBytes()),
        requestHex: bytesToHex(request.requestBytes()),
        quoteId: null,
        invoice: null,
        quoteExpiry: null,
        token: null,
        createdAt: now(),
      };
    } finally {
      request.free?.();
    }
    store.setPending(pending);
  }
  if (!pending.token) {
    if (!pending.quoteId || !pending.invoice || (pending.quoteExpiry !== null && pending.quoteExpiry <= now())) {
      hooks.onStatus?.('quoting');
      const quote = await rail.quote(pending.mintUrl, pending.offer.sat, `Bitcoin PIR: ${pending.offer.credits} credits`);
      pending = { ...pending, quoteId: quote.quoteId, invoice: quote.invoice, quoteExpiry: quote.expiry };
      store.setPending(pending);
    }
    hooks.onInvoice?.(pending.invoice!, pending.quoteExpiry);
    hooks.onStatus?.('awaiting-payment');
    await rail.waitPaid(pending.mintUrl, pending.quoteId!, hooks.signal);
    hooks.onStatus?.('minting');
    const token = await rail.mint(pending.mintUrl, pending.offer.sat, pending.quoteId!);
    pending = { ...pending, token };
    store.setPending(pending);
  }
  hooks.onStatus?.('issuing');
  const token = pending.token;
  if (!token) throw new IssuerError('purchase has no token to redeem');
  const request = arc.restore(pending.epoch, hexToBytes(pending.secretsHex), hexToBytes(pending.requestHex));
  try {
    const issued = await issuer.buyCredential(pending.offer, token, request.requestBytes());
    hooks.onStatus?.('finalizing');
    if (issued.epoch !== pending.epoch) {
      throw new IssuerError(`issuer answered for epoch ${issued.epoch}, the request was for ${pending.epoch}`);
    }
    const credential = request.finalize(issued.issuerPublicKeyHex, hexToBytes(issued.responseHex));
    const stored: StoredCredential = {
      version: 1,
      issuerUrl: issuer.baseUrl,
      epoch: issued.epoch,
      presentationLimit: issued.presentationLimit,
      credentialHex: bytesToHex(credential),
      nextNonce: 0,
      issuerPublicKeyHex: issued.issuerPublicKeyHex,
      validUntil: issued.validUntil,
      boughtAt: now(),
    };
    store.add(stored);
    store.setPending(null);
    hooks.onStatus?.('stored');
    return stored;
  } finally {
    request.free?.();
  }
}
