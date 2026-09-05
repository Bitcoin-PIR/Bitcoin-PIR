import { describe, expect, it, vi } from 'vitest';
import {
  REQ_SESSION_GRANT_PRESENT,
  RESP_SESSION_GRANT_OK,
  SESSION_GRANT_LEN,
} from '../constants.js';
import {
  CashierClient,
  CashierError,
  SessionGrantStore,
  base64ToBytes,
  bytesToBase64,
  classifySessionGrantFailure,
  decodeSessionGrantFields,
  encodeSessionGrantPresentFrame,
  parseCashierInfo,
  parseIssuedGrant,
  parseSessionGrantResponsePayload,
  type StoredSessionGrant,
} from '../session-grant.js';
import { PendingPurchaseStore } from '../cashu-purchase.js';

const NOW = 1_800_000_000;

/** A structurally valid version-1 grant (signature bytes are arbitrary). */
function syntheticGrant(opts: { credits?: number; issuedAt?: number; expiresAt?: number } = {}): Uint8Array {
  const bytes = new Uint8Array(SESSION_GRANT_LEN);
  bytes[0] = 1;
  bytes.fill(0xaa, 1, 33);
  bytes.fill(0x11, 33, 49);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(49, BigInt(opts.issuedAt ?? NOW - 10), true);
  view.setBigUint64(57, BigInt(opts.expiresAt ?? NOW + 3600), true);
  view.setUint32(65, opts.credits ?? 100, true);
  bytes.fill(0x5c, 69);
  return bytes;
}

function memoryStorage() {
  const map = new Map<string, string>();
  return {
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => { map.set(key, value); },
    removeItem: (key: string) => { map.delete(key); },
    size: () => map.size,
  };
}

function errorEnvelope(message: string): Uint8Array {
  const text = new TextEncoder().encode(message);
  const payload = new Uint8Array(5 + text.length);
  payload[0] = 0xff;
  new DataView(payload.buffer).setUint32(1, text.length, true);
  payload.set(text, 5);
  return payload;
}

describe('session grant fields', () => {
  it('decodes the public fields of a version-1 grant', () => {
    const fields = decodeSessionGrantFields(syntheticGrant({ credits: 7 }));
    expect(fields).toEqual({
      version: 1,
      issuerPubkeyHex: 'aa'.repeat(32),
      grantIdHex: '11'.repeat(16),
      issuedAt: NOW - 10,
      expiresAt: NOW + 3600,
      credits: 7,
    });
  });

  it('rejects wrong length, version, zero credits, and inverted windows', () => {
    expect(() => decodeSessionGrantFields(new Uint8Array(10))).toThrow(/133 bytes/);
    const badVersion = syntheticGrant();
    badVersion[0] = 2;
    expect(() => decodeSessionGrantFields(badVersion)).toThrow(/version 2/);
    expect(() => decodeSessionGrantFields(syntheticGrant({ credits: 0 }))).toThrow(/no credits/);
    expect(() => decodeSessionGrantFields(syntheticGrant({ issuedAt: NOW, expiresAt: NOW })))
      .toThrow(/expires before/);
  });

  it('round-trips base64', () => {
    const grant = syntheticGrant();
    expect(base64ToBytes(bytesToBase64(grant))).toEqual(grant);
    expect(() => base64ToBytes('%%%')).toThrow(/base64/);
  });
});

describe('presentation wire codec', () => {
  it('frames the grant behind the 0x0b opcode', () => {
    const grant = syntheticGrant();
    const frame = encodeSessionGrantPresentFrame(grant);
    expect(frame.length).toBe(4 + 1 + SESSION_GRANT_LEN);
    expect(new DataView(frame.buffer).getUint32(0, true)).toBe(1 + SESSION_GRANT_LEN);
    expect(frame[4]).toBe(REQ_SESSION_GRANT_PRESENT);
    expect(frame.subarray(5)).toEqual(grant);
    expect(() => encodeSessionGrantPresentFrame(new Uint8Array(3))).toThrow(/133 bytes/);
  });

  it('parses the remaining-credit response and surfaces server errors', () => {
    const ok = new Uint8Array([RESP_SESSION_GRANT_OK, 0x04, 0x03, 0x02, 0x01]);
    expect(parseSessionGrantResponsePayload(ok)).toBe(0x01020304);
    expect(() => parseSessionGrantResponsePayload(new Uint8Array())).toThrow(/empty/);
    expect(() => parseSessionGrantResponsePayload(new Uint8Array([RESP_SESSION_GRANT_OK, 1])))
      .toThrow(/5 bytes/);
    expect(() => parseSessionGrantResponsePayload(new Uint8Array([0x42, 0, 0, 0, 0])))
      .toThrow(/0x42/);
    expect(() => parseSessionGrantResponsePayload(errorEnvelope('session grant: session grant has expired')))
      .toThrow(/expired/);
  });

  it('classifies "not enabled" as the free path and everything else as refused', () => {
    expect(classifySessionGrantFailure('session grants not enabled on this server'))
      .toEqual({ state: 'not-enabled' });
    expect(classifySessionGrantFailure('session grant: session grant credits are exhausted'))
      .toEqual({ state: 'refused', error: 'session grant: session grant credits are exhausted' });
  });
});

describe('SessionGrantStore', () => {
  const stored: StoredSessionGrant = {
    version: 1,
    grantBase64: bytesToBase64(syntheticGrant()),
    grantIdHex: '11'.repeat(16),
    credits: 100,
    issuedAt: NOW - 10,
    expiresAt: NOW + 3600,
    cashierUrl: 'https://cashier.example',
  };

  it('round-trips a grant and returns its bytes', () => {
    const storage = memoryStorage();
    const store = new SessionGrantStore(storage);
    expect(store.load(NOW)).toBeNull();
    store.save(stored);
    expect(store.load(NOW)).toEqual(stored);
    expect(store.grantBytes(NOW)).toEqual(syntheticGrant());
    store.clear();
    expect(store.load(NOW)).toBeNull();
  });

  it('drops expired, corrupt, and foreign entries', () => {
    const storage = memoryStorage();
    const store = new SessionGrantStore(storage);
    store.save(stored);
    expect(store.load(NOW + 3600)).toBeNull();
    expect(storage.size()).toBe(0);
    storage.setItem('bitcoinpir.session-grant.v1', '{not json');
    expect(store.load(NOW)).toBeNull();
    storage.setItem('bitcoinpir.session-grant.v1', JSON.stringify({ version: 2 }));
    expect(store.load(NOW)).toBeNull();
    storage.setItem('bitcoinpir.session-grant.v1', JSON.stringify({ ...stored, grantBase64: 'AAAA' }));
    expect(store.grantBytes(NOW)).toBeNull();
    expect(storage.size()).toBe(0);
  });

  it('is inert without storage', () => {
    const store = new SessionGrantStore(null);
    store.save(stored);
    expect(store.load(NOW)).toBeNull();
  });
});

describe('CashierClient', () => {
  const info = {
    service: 'bitcoinpir-cashier',
    version: 1,
    cashier_pubkey_hex: 'AB'.repeat(32),
    mints: ['https://mint.example'],
    offers: [{ credits: 100, amount: 21, unit: 'sat' }],
    grant_ttl_secs: 86400,
  };

  function jsonResponse(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  }

  it('requires an https URL and normalises the base', () => {
    expect(() => new CashierClient('http://cashier.example', vi.fn())).toThrow(/https/);
    expect(new CashierClient('https://cashier.example///', vi.fn()).baseUrl).toBe('https://cashier.example');
    expect(new CashierClient('http://localhost:8080', vi.fn()).baseUrl).toBe('http://localhost:8080');
  });

  it('fetches and validates /v1/info', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(200, info));
    const client = new CashierClient('https://cashier.example', fetchImpl as unknown as typeof fetch);
    const parsed = await client.info();
    expect(parsed.cashierPubkeyHex).toBe('ab'.repeat(32));
    expect(parsed.offers).toEqual([{ credits: 100, amount: 21, unit: 'sat' }]);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://cashier.example/v1/info');
    expect(init.credentials).toBe('omit');
    expect(init.referrerPolicy).toBe('no-referrer');
  });

  it('rejects malformed info documents', () => {
    expect(() => parseCashierInfo({ ...info, version: 2 })).toThrow(/version/);
    expect(() => parseCashierInfo({ ...info, mints: ['http://mint.example'] })).toThrow(/https mint/);
    expect(() => parseCashierInfo({ ...info, offers: [] })).toThrow(/offers/);
    expect(() => parseCashierInfo({ ...info, offers: [{ credits: 0, amount: 1, unit: 'sat' }] }))
      .toThrow(/invalid fields/);
    expect(() => parseCashierInfo({ ...info, cashier_pubkey_hex: 'zz' })).toThrow(/public key/);
  });

  it('redeems a token and cross-checks the issued grant against the offer', async () => {
    const grant = syntheticGrant({ credits: 100 });
    const body = {
      grant_base64: bytesToBase64(grant),
      grant_id_hex: '11'.repeat(16),
      credits: 100,
      expires_at: NOW + 3600,
    };
    const fetchImpl = vi.fn(async () => jsonResponse(200, body));
    const client = new CashierClient('https://cashier.example', fetchImpl as unknown as typeof fetch);
    const issued = await client.redeem({ credits: 100, amount: 21, unit: 'sat' }, ' cashuBabc ');
    expect(issued).toEqual({
      grantBase64: bytesToBase64(grant),
      grantIdHex: '11'.repeat(16),
      credits: 100,
      issuedAt: NOW - 10,
      expiresAt: NOW + 3600,
    });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://cashier.example/v1/grants');
    expect(JSON.parse(String(init.body))).toEqual({
      offer: { credits: 100, amount: 21, unit: 'sat' },
      token: 'cashuBabc',
    });

    await expect(client.redeem({ credits: 100, amount: 21, unit: 'sat' }, 'nope')).rejects.toThrow(/Cashu token/);
    expect(() => parseIssuedGrant(body, { credits: 50, amount: 21, unit: 'sat' })).toThrow(/offer was 50/);
    expect(() => parseIssuedGrant({ ...body, grant_id_hex: '22'.repeat(16) }, { credits: 100, amount: 21, unit: 'sat' }))
      .toThrow(/grant_id_hex/);
    expect(() => parseIssuedGrant({ ...body, expires_at: 1 }, { credits: 100, amount: 21, unit: 'sat' }))
      .toThrow(/expires_at/);
  });

  it('surfaces cashier error bodies and unreachable hosts', async () => {
    const failing = vi.fn(async () => jsonResponse(402, { error: 'token_rejected', message: 'mint rejected the token' }));
    const client = new CashierClient('https://cashier.example', failing as unknown as typeof fetch);
    const error = await client.info().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CashierError);
    expect((error as CashierError).status).toBe(402);
    expect((error as CashierError).code).toBe('token_rejected');
    expect((error as CashierError).message).toBe('mint rejected the token');

    const down = vi.fn(async () => { throw new TypeError('Failed to fetch'); });
    const offline = new CashierClient('https://cashier.example', down as unknown as typeof fetch);
    await expect(offline.info()).rejects.toThrow(/unreachable/);
  });
});

describe('PendingPurchaseStore', () => {
  it('round-trips and validates pending purchases', () => {
    const storage = memoryStorage();
    const store = new PendingPurchaseStore(storage);
    expect(store.load()).toBeNull();
    const pending = {
      version: 1 as const,
      cashierUrl: 'https://cashier.example',
      mintUrl: 'https://mint.example',
      offer: { credits: 100, amount: 21, unit: 'sat' },
      quoteId: 'q1',
      invoice: 'lnbc1...',
      quoteExpiry: null,
      token: null,
      createdAt: NOW,
    };
    store.save(pending);
    expect(store.load()).toEqual(pending);
    store.save({ ...pending, token: 'cashuB...' });
    expect(store.load()?.token).toBe('cashuB...');
    storage.setItem('bitcoinpir.session-grant.pending-purchase.v1', JSON.stringify({ version: 1 }));
    expect(store.load()).toBeNull();
    expect(storage.size()).toBe(0);
  });
});
