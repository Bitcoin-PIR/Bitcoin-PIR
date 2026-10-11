/**
 * Credits (paid queries, v2), browser side. Design: `docs/CREDITS.md`.
 *
 * - `IssuerClient`: the issuer's `/v2/` contract (`info`, raw requests for
 *   x402 in `x402.ts`).
 * - Frame codec for `REQ_CREDIT_PRESENT` / `RESP_CREDIT_OK`.
 * - `serverGasCardFromInfo` and `ConnectionCreditMeter`: price a frame the
 *   way the server does and decide when a top-up is due.
 * - `CreditedChannel`: keep one OnionPIR connection funded.
 *
 * The wallet that pays, Cashu ecash presented as kind 1, is
 * `cashu-wallet.ts`.
 */

import {
  MAX_API_KEY_LEN,
  MAX_CREDIT_PRESENT_PAYLOAD_LEN,
  REQ_API_KEY,
  REQ_CREDIT_PRESENT,
  RESP_API_KEY_OK,
  RESP_CREDIT_OK,
} from './constants.js';

const RESP_ERROR = 0xff;
export const CREDITS_API_VERSION = 2;
export const CREDIT_PRESENT_KIND_CASHU = 1;

// ─── Issuer contract ────────────────────────────────────────────────────────

export interface GasParams {
  creditSat: number;
  gasPerCredit: number;
  baseGasPerFrame: number;
  egressGasPerMb: number;
}

export interface IssuerInfo {
  service: string;
  version: number;
  gas: GasParams;
  mints: string[];
  rateCard: { flow: string; credits: number }[];
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
    rateCard,
  };
}

export class IssuerClient {
  readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(baseUrl: string, fetchImpl?: typeof fetch) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    const native = (globalThis as { fetch?: typeof fetch }).fetch;
    if (!fetchImpl && !native) throw new Error('fetch is unavailable in this environment');
    this.fetchImpl = fetchImpl ?? ((input, init) => native!.call(globalThis, input, init));
  }

  async info(): Promise<IssuerInfo> {
    return parseIssuerInfo(await this.request('GET', '/v2/info'));
  }

  /** Raw POST with a caller-controlled body string and headers (x402 needs the exact bytes and the response headers). */
  async postRaw(path: string, body: string, extraHeaders: Record<string, string> = {}): Promise<Response> {
    return this.raw(path, {
      method: 'POST',
      headers: { accept: 'application/json', 'content-type': 'application/json', ...extraHeaders },
      body,
    });
  }

  /** Raw GET returning the response (status and headers included). */
  async getRaw(path: string): Promise<Response> {
    return this.raw(path, { method: 'GET', headers: { accept: 'application/json' } });
  }

  private async raw(path: string, init: { method: string; headers: Record<string, string>; body?: string }): Promise<Response> {
    try {
      return await this.fetchImpl(this.baseUrl + path, {
        ...init,
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
      });
    } catch (error) {
      throw new IssuerError(`issuer unreachable: ${(error as Error)?.message ?? error}`);
    }
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
  if (kind !== CREDIT_PRESENT_KIND_CASHU) throw new Error(`unknown credit presentation kind ${kind}`);
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

/** `[len u32 LE][0x13][key bytes]`, ready to send (docs/CREDITS.md "API keys"). */
export function encodeApiKeyFrame(key: string): Uint8Array {
  const bytes = new TextEncoder().encode(key);
  if (bytes.length === 0 || bytes.length > MAX_API_KEY_LEN) {
    throw new Error(`an API key is 1 to ${MAX_API_KEY_LEN} bytes, got ${bytes.length}`);
  }
  const frame = new Uint8Array(4 + 1 + bytes.length);
  new DataView(frame.buffer).setUint32(0, 1 + bytes.length, true);
  frame[4] = REQ_API_KEY;
  frame.set(bytes, 5);
  return frame;
}

/** Check the answer to an API key presentation (starting at the variant byte). */
export function parseApiKeyResponsePayload(payload: Uint8Array): void {
  if (payload.length === 0) throw new Error('empty API key response');
  const variant = payload[0];
  if (variant === RESP_ERROR) throw new Error(decodeErrorEnvelope(payload));
  if (variant !== RESP_API_KEY_OK || payload.length !== 1) {
    throw new Error(`unexpected response variant 0x${variant.toString(16)} for an API key presentation`);
  }
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
      return card.harmonyPoolEntry === undefined ? null : Math.floor(card.harmonyPoolEntry / 2);
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

/** A `REQ_CREDIT_PRESENT` payload and the credits it is worth. */
export interface Presentation {
  kind: number;
  payload: Uint8Array;
  credits: number;
}

/** Hands over a presentation worth at least `credits` credits, or `null` when the wallet falls short. */
export type CreditProvider = (credits: number) => Presentation | null;

/** Sends a whole frame (`[len u32][payload]`) and returns the whole response frame. */
export type FrameExchange = (frame: Uint8Array) => Promise<Uint8Array>;

/** What enabling credits on one connection came to. */
export interface CreditEnablement {
  /**
   * `best-effort`: the server serves this backend free while it has room and
   * the connection pays only when told the free lane is busy. `api-key`: the
   * server accepted the operator API key, so the connection is unmetered.
   */
  state: 'not-enabled' | 'not-required' | 'required' | 'best-effort' | 'api-key' | 'error';
  error?: string;
}

/** The WASM client methods that enable an API key or credits on one server. */
export interface CreditLegClient {
  presentApiKey(serverIndex: number, key: string): Promise<void>;
  enableCredits(serverIndex: number, provider: (credits: number) => unknown): Promise<string>;
}

/** Present `apiKey`, or else enable credits from `provider`, on one server.
 * Bearer material, so only over the encrypted channel. `null` when there is
 * neither a key nor a provider. */
export async function enableCreditsOnLeg(
  client: CreditLegClient,
  serverIndex: number,
  options: { apiKey?: string; provider?: CreditProvider; secureChannel: boolean },
): Promise<CreditEnablement | null> {
  const apiKey = options.apiKey?.trim();
  if (!apiKey && !options.provider) return null;
  if (!options.secureChannel) {
    return { state: 'error', error: `${apiKey ? 'API key' : 'credits'} withheld: the channel is cleartext` };
  }
  try {
    if (apiKey) {
      await client.presentApiKey(serverIndex, apiKey);
      return { state: 'api-key' };
    }
    return { state: (await client.enableCredits(serverIndex, options.provider!)) as CreditEnablement['state'] };
  } catch (error) {
    return { state: 'error', error: (error as Error)?.message ?? String(error) };
  }
}

// ─── Access policy (docs/CREDITS.md "Access policy") ───────────────────────

export type AccessBackend = 'dpf' | 'harmony' | 'onion' | 'oram';

/** One backend's setting on one server. */
export type AccessMode =
  | { mode: 'free' }
  | { mode: 'paid' }
  | { mode: 'best-effort'; free_concurrency: number; free_gas_per_hour?: number };

/** Prefix of a server's refusal when a best-effort free lane is busy. */
export const FREE_LANE_BUSY_PREFIX = 'free capacity busy';

export function isFreeLaneBusy(message: string): boolean {
  return message.startsWith(FREE_LANE_BUSY_PREFIX);
}

function parseAccessMode(value: unknown): AccessMode | null {
  if (!value || typeof value !== 'object') return null;
  const v = value as Record<string, unknown>;
  if (v.mode === 'free') return { mode: 'free' };
  if (v.mode === 'paid') return { mode: 'paid' };
  if (v.mode === 'best-effort' && Number.isInteger(v.free_concurrency) && (v.free_concurrency as number) >= 1) {
    const out: AccessMode = { mode: 'best-effort', free_concurrency: v.free_concurrency as number };
    if (Number.isInteger(v.free_gas_per_hour)) out.free_gas_per_hour = v.free_gas_per_hour as number;
    return out;
  }
  return null;
}

/**
 * The access a client should assume for `backend` on a server: the entry
 * the server published, else paid when it says credits are required, free
 * otherwise (servers that predate the access policy).
 */
export function resolveAccess(
  credits: { enabled?: boolean; required?: boolean; access?: unknown } | undefined,
  backend: AccessBackend,
): AccessMode {
  const published =
    credits?.access && typeof credits.access === 'object'
      ? parseAccessMode((credits.access as Record<string, unknown>)[backend])
      : null;
  if (published) return published;
  return credits?.enabled === true && credits.required === true ? { mode: 'paid' } : { mode: 'free' };
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

  /**
   * `access` is the server's setting for the backend this channel carries
   * (docs/CREDITS.md "Access policy"); `canPay` is whether the server takes
   * presentations at all.
   */
  constructor(
    card: ServerGasCard,
    private readonly provider: CreditProvider,
    private readonly exchange: FrameExchange,
    private readonly access: AccessMode = { mode: 'paid' },
    private readonly canPay = true,
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
    if (await this.topUpIfPossible(needed)) return;
    const credits = Math.max(1, this.meter.creditsToPresent(needed, 0));
    throw new Error(`credits required: this frame needs ${credits} more credit(s) and the wallet has none`);
  }

  /** Present credits until the balance covers `needed`; false when the wallet runs out. */
  private async topUpIfPossible(needed: number): Promise<boolean> {
    for (let attempt = 0; this.meter.balance < needed; attempt++) {
      if (attempt >= 4) throw new Error('credits: the balance did not reach the frame price after four presentations');
      const credits = Math.max(1, this.meter.creditsToPresent(needed, 0));
      const presentation = this.provider(credits);
      if (!presentation) return false;
      const response = await this.exchange(encodeCreditPresentFrame(presentation.kind, presentation.payload));
      const receipt = parseCreditResponsePayload(response.subarray(4));
      this.presented += presentation.credits;
      this.meter.recordReceipt(receipt);
    }
    return true;
  }

  /**
   * Send `frame` through `exchange` as the server's access policy says: a
   * free backend's frames go as they are; a paid frame is funded first and
   * retried once when the server still refuses it for gas; a best-effort
   * frame the balance does not cover goes out unpaid, and only if the
   * server answers that its free lane is busy is it paid for and sent again
   * — when the wallet can; otherwise the busy refusal is returned.
   */
  async roundtrip(frame: Uint8Array): Promise<Uint8Array> {
    const classified = classifyOnionFrame(frame);
    const gas = classified ? this.meter.frameGas(classified.dbId, classified.op) : null;
    if (classified === null || gas === null || this.access.mode === 'free') return this.exchange(frame);
    if (this.access.mode === 'best-effort') {
      // Covered by the balance, the server charges the frame and serves it
      // first; otherwise it goes out unpaid for the free lane.
      const covered = this.meter.balance >= gas;
      if (covered) this.meter.recordFrame(gas);
      const response = await this.exchange(frame);
      if (!(response[4] === 0xff && isFreeLaneBusy(errorMessage(response.subarray(4))))) {
        if (covered) this.recordPaidResponse(classified.op, response);
        return response;
      }
      // The lane refused the frame and charged nothing: the server's balance
      // did not cover it, whatever this mirror expected (it counts egress a
      // little behind the server). Pay for priority if the wallet can —
      // presenting at least once when the mirror was wrong, so the receipt
      // resynchronises it — otherwise the refusal stands.
      if (covered) this.meter.recordFrame(-gas);
      if (!this.canPay) return response;
      const needed = Math.max(gas + this.reserve(classified.op), covered ? this.meter.balance + 1 : 0);
      if (!(await this.topUpIfPossible(needed))) return response;
    } else {
      await this.topUp(gas + this.reserve(classified.op));
    }
    this.meter.recordFrame(gas);
    let response = await this.exchange(frame);
    const refusal = response[4] === 0xff ? parseInsufficientGas(errorMessage(response.subarray(4))) : null;
    if (refusal) {
      this.meter.recordRefusal(errorMessage(response.subarray(4)));
      await this.topUp(refusal.needed + this.reserve(classified.op));
      this.meter.recordFrame(refusal.needed);
      response = await this.exchange(frame);
    }
    this.recordPaidResponse(classified.op, response);
    return response;
  }

  private recordPaidResponse(op: MeteredOp, response: Uint8Array): void {
    this.meter.recordResponse(response.length);
    const seen = this.observed.get(op.kind) ?? 0;
    this.observed.set(op.kind, Math.max(seen, response.length));
  }
}

function errorMessage(payload: Uint8Array): string {
  if (payload.length >= 5) {
    const len = new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(1, true);
    if (5 + len <= payload.length) return new TextDecoder().decode(payload.subarray(5, 5 + len));
  }
  return new TextDecoder().decode(payload.subarray(1));
}
