import { describe, expect, it, vi } from 'vitest';
import { CreditStore, IssuerClient, type ArcRequestFactory, type ArcRequestLike } from '../credits.js';
import {
  headerValue,
  http1Binding,
  jcs,
  parseHeader,
  purchaseCredentialX402,
  requestChallenge,
  settle,
  validateChallenge,
  X402_NETWORK_MAINNET,
  type PaymentRequired,
} from '../x402.js';
import { FIXTURE_INVOICE, FIXTURE_PAYMENT_HASH, FIXTURE_PREIMAGE, FIXTURE_REQUEST_HASH } from './bolt11.test.js';

const ISSUER = 'https://issuer.example';
const KEY_ONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const PUBKEY_HEX = 'ab'.repeat(99);
const NOW = 1_800_000_005;
const OFFER = { credits: 4, sat: 40 };
/** 226 bytes of 0x11: the fixture body's `request_hex`. */
const REQUEST_HEX = '11'.repeat(226);
const BODY = JSON.stringify({ credits: 4, sat: 40, request_hex: REQUEST_HEX });

function memoryStorage() {
  const map = new Map<string, string>();
  return {
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
  };
}

function requirement(overrides: Partial<PaymentRequired['accepts'][number]> = {}, extra: Record<string, unknown> = {}) {
  return {
    scheme: 'exact',
    network: X402_NETWORK_MAINNET,
    amount: '40000',
    asset: 'BTC',
    payTo: KEY_ONE,
    maxTimeoutSeconds: 900,
    ...overrides,
    extra: {
      assetTransferMethod: 'bolt11',
      paymentFlow: 'upfront',
      requestHash: FIXTURE_REQUEST_HASH,
      requestBindingProfile: 'http:1',
      requestBindingParams: { headers: ['content-type'] },
      invoice: FIXTURE_INVOICE,
      ...extra,
    },
  };
}

function required(overrides: Partial<PaymentRequired['accepts'][number]> = {}, extra: Record<string, unknown> = {}): PaymentRequired {
  return {
    x402Version: 2,
    error: 'payment required',
    resource: { url: `${ISSUER}/v2/credentials`, description: 'pack' },
    accepts: [requirement(overrides, extra)],
  };
}

describe('request binding (http:1)', () => {
  it('canonicalises like RFC 8785 and matches the specification vector', async () => {
    expect(jcs({ b: '1', a: ['x', { d: 'y', c: 'z' }] })).toBe('{"a":["x",{"c":"z","d":"y"}],"b":"1"}');
    const b = await http1Binding('GET', 'https://api.example.com/article/A', new Uint8Array(), []);
    expect(b.description).toBe(
      '{"bodyHash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"x402:exact:lnbtc:bolt11:http:1","headers":[],"method":"GET","url":"https://api.example.com/article/A"}',
    );
    expect(b.requestHashHex).toBe('0d6623f775e025501fa7f0a30b54da25aad62b6ccfe35c85da38016711e6c018');
  });

  it('binds the fixture body with its content-type header to the fixture hash', async () => {
    const b = await http1Binding('POST', `${ISSUER}/v2/credentials`, new TextEncoder().encode(BODY), [
      { name: 'content-type', value: 'application/json' },
    ]);
    expect(b.requestHashHex).toBe(FIXTURE_REQUEST_HASH);
    const absent = await http1Binding('POST', `${ISSUER}/v2/credentials`, new TextEncoder().encode(BODY), [
      { name: 'content-type', value: null },
    ]);
    expect(absent.requestHashHex).not.toBe(FIXTURE_REQUEST_HASH);
  });

  it('round-trips base64 JSON headers', () => {
    const v = { x402Version: 2, payload: { preimage: FIXTURE_PREIMAGE } };
    expect(parseHeader(headerValue(v))).toEqual(v);
  });
});

describe('validateChallenge', () => {
  it('accepts the fixture challenge and extracts the payment hash', async () => {
    const c = await validateChallenge(ISSUER, BODY, required(), OFFER, NOW);
    expect(c.paymentHash).toBe(FIXTURE_PAYMENT_HASH);
    expect(c.expiresAt).toBe(1_800_000_900);
    expect(c.invoice).toBe(FIXTURE_INVOICE);
    expect(c.accepted.payTo).toBe(KEY_ONE);
  });

  it('refuses challenges that do not bind our request or terms', async () => {
    await expect(validateChallenge(ISSUER, BODY, required(), { credits: 4, sat: 41 }, NOW)).rejects.toThrow(/msat/);
    await expect(validateChallenge(ISSUER, BODY, required({}, { requestHash: 'ab'.repeat(32) }), OFFER, NOW)).rejects.toThrow(/requestHash/);
    await expect(validateChallenge(ISSUER, BODY.replace('40', '41'), required(), OFFER, NOW)).rejects.toThrow(/requestHash/);
    const other = required();
    other.resource = { url: 'https://cashier.example/v2/credentials' };
    await expect(validateChallenge(ISSUER, BODY, other, OFFER, NOW)).rejects.toThrow(/resource\.url/);
    await expect(validateChallenge(ISSUER, BODY, required({ payTo: '02' + 'c6'.repeat(32) }), OFFER, NOW)).rejects.toThrow(/payTo/);
    await expect(validateChallenge(ISSUER, BODY, required({ maxTimeoutSeconds: 300 }), OFFER, NOW)).rejects.toThrow(/expiry/);
    await expect(validateChallenge(ISSUER, BODY, required(), OFFER, 1_800_001_000)).rejects.toThrow(/expired/);
    await expect(validateChallenge(ISSUER, BODY, required({}, { paymentFlow: 'deferred' }), OFFER, NOW)).rejects.toThrow(/upfront/);
    await expect(
      validateChallenge(ISSUER, BODY, required({}, { requestBindingParams: { headers: ['payment-signature'] } }), OFFER, NOW),
    ).rejects.toThrow(/header/);
  });
});

/** A scripted issuer: 402 challenge, invoice status polling, settlement. */
function fakeIssuer(options: { paidAfterPolls?: number; settleStatus?: number } = {}) {
  const calls: { method: string; path: string; headers: Record<string, string>; body: string | undefined }[] = [];
  let polls = 0;
  const paidAfter = options.paidAfterPolls ?? 1;
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const headers = Object.fromEntries(Object.entries((init?.headers as Record<string, string>) ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    const body = typeof init?.body === 'string' ? init.body : undefined;
    calls.push({ method: init?.method ?? 'GET', path: url.pathname, headers, body });
    const json = (status: number, value: unknown, extra: Record<string, string> = {}) =>
      new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json', ...extra } });
    if (url.pathname === '/v2/info') {
      return json(200, {
        service: 'bitcoinpir-issuer',
        version: 2,
        credit_sat: 10,
        gas_per_credit: 72_000,
        base_gas_per_frame: 20,
        egress_gas_per_mb: 1_000,
        mints: [],
        offers: [OFFER],
        arc: { epoch: 231, presentation_limit: 4, issuer_public_key_hex: PUBKEY_HEX, presentation_context_hex: '00', valid_until: NOW + 86_400 },
        rate_card: [],
      });
    }
    if (url.pathname === '/v2/credentials' && !headers['payment-signature']) {
      if (body !== BODY) return json(400, { error: 'unexpected body' });
      const r = required();
      return json(402, r, { 'payment-required': headerValue(r) });
    }
    if (url.pathname === '/v2/credentials') {
      const payload = parseHeader(headers['payment-signature']) as { payload: { preimage: string }; accepted: { extra: { invoice: string } } };
      if (body !== BODY || payload.payload.preimage !== FIXTURE_PREIMAGE || payload.accepted.extra.invoice !== FIXTURE_INVOICE) {
        return json(402, { error: 'payment_failed' }, {
          'payment-response': headerValue({ success: false, errorReason: 'invalid_exact_lnbtc_preimage_hash_mismatch', transaction: '', network: X402_NETWORK_MAINNET }),
        });
      }
      if (options.settleStatus && options.settleStatus !== 200) {
        return json(options.settleStatus, { error: 'payment_failed' }, {
          'payment-response': headerValue({ success: false, errorReason: 'duplicate_settlement', transaction: '', network: X402_NETWORK_MAINNET }),
        });
      }
      return json(
        200,
        { response_hex: 'cd'.repeat(454), epoch: 231, presentation_limit: 4, issuer_public_key_hex: PUBKEY_HEX, valid_until: NOW + 86_400 },
        { 'payment-response': headerValue({ success: true, transaction: FIXTURE_PAYMENT_HASH, network: X402_NETWORK_MAINNET }) },
      );
    }
    if (url.pathname === `/v2/x402/invoices/${FIXTURE_PAYMENT_HASH}`) {
      polls += 1;
      return polls > paidAfter
        ? json(200, { payment_hash: FIXTURE_PAYMENT_HASH, status: 'paid', bolt11: FIXTURE_INVOICE, preimage: FIXTURE_PREIMAGE })
        : json(200, { payment_hash: FIXTURE_PAYMENT_HASH, status: 'unpaid', bolt11: FIXTURE_INVOICE, preimage: null });
    }
    return json(404, { error: 'not_found' });
  };
  return { client: new IssuerClient(ISSUER, fetchImpl), calls };
}

function fakeArc(): { factory: ArcRequestFactory; finalize: ReturnType<typeof vi.fn> } {
  const finalize = vi.fn(() => new Uint8Array(131).fill(7));
  const like = (): ArcRequestLike => ({
    requestBytes: () => new Uint8Array(226).fill(0x11),
    secretsBytes: () => Uint8Array.of(1, 2, 3),
    finalize,
  });
  return { factory: { create: () => like(), restore: () => like() }, finalize };
}

describe('purchaseCredentialX402', () => {
  it('challenges, waits for the payment, settles with the identical body, and stores the credential', async () => {
    const { client, calls } = fakeIssuer({ paidAfterPolls: 2 });
    const store = new CreditStore(memoryStorage());
    const { factory, finalize } = fakeArc();
    const statuses: string[] = [];
    const invoices: string[] = [];
    const stored = await purchaseCredentialX402(
      client,
      store,
      factory,
      OFFER,
      { onStatus: (s) => statuses.push(s), onInvoice: (i) => invoices.push(i) },
      () => NOW,
      { pollIntervalMs: 1, webln: null },
    );
    expect(stored.presentationLimit).toBe(4);
    expect(stored.credentialHex).toBe('07'.repeat(131));
    expect(store.pending()).toBeNull();
    expect(store.list()).toHaveLength(1);
    expect(invoices).toEqual([FIXTURE_INVOICE]);
    expect(statuses).toEqual(['quoting', 'awaiting-payment', 'issuing', 'finalizing', 'stored']);
    expect(finalize).toHaveBeenCalledWith(PUBKEY_HEX, expect.any(Uint8Array));
    const posts = calls.filter((c) => c.path === '/v2/credentials');
    expect(posts).toHaveLength(2);
    expect(posts[0].body).toBe(BODY);
    expect(posts[1].body).toBe(BODY);
    expect(posts[0].headers['payment-signature']).toBeUndefined();
    expect(typeof posts[1].headers['payment-signature']).toBe('string');
    expect(calls.filter((c) => c.path.startsWith('/v2/x402/invoices/'))).toHaveLength(3);
  });

  it('takes the preimage from WebLN without polling', async () => {
    const { client, calls } = fakeIssuer();
    const store = new CreditStore(memoryStorage());
    const webln = { enable: vi.fn(async () => undefined), sendPayment: vi.fn(async () => ({ preimage: FIXTURE_PREIMAGE })) };
    await purchaseCredentialX402(client, store, fakeArc().factory, OFFER, {}, () => NOW, { webln });
    expect(webln.sendPayment).toHaveBeenCalledWith(FIXTURE_INVOICE);
    expect(calls.some((c) => c.path.startsWith('/v2/x402/invoices/'))).toBe(false);
    expect(store.list()).toHaveLength(1);
  });

  it('resumes a paid purchase by settling only, and refuses a wrong WebLN preimage', async () => {
    const { client, calls } = fakeIssuer();
    const store = new CreditStore(memoryStorage());
    const challenge = await validateChallenge(ISSUER, BODY, required(), OFFER, NOW);
    store.setPending({
      version: 1,
      issuerUrl: ISSUER,
      mintUrl: '',
      offer: OFFER,
      epoch: 231,
      secretsHex: '010203',
      requestHex: REQUEST_HEX,
      quoteId: FIXTURE_PAYMENT_HASH,
      invoice: FIXTURE_INVOICE,
      quoteExpiry: challenge.expiresAt,
      token: null,
      createdAt: NOW,
      x402: { body: BODY, resource: challenge.resource, accepted: challenge.accepted, paymentHash: FIXTURE_PAYMENT_HASH, invoice: FIXTURE_INVOICE, expiresAt: challenge.expiresAt, preimage: FIXTURE_PREIMAGE },
    });
    await purchaseCredentialX402(client, store, fakeArc().factory, OFFER, {}, () => NOW, { webln: null });
    expect(calls.map((c) => c.path)).toEqual(['/v2/credentials']);
    expect(store.pending()).toBeNull();

    const bad = { enable: async () => undefined, sendPayment: async () => ({ preimage: 'ff'.repeat(32) }) };
    const { client: client2 } = fakeIssuer({ paidAfterPolls: 0 });
    const store2 = new CreditStore(memoryStorage());
    // A wrong WebLN preimage is ignored and polling takes over.
    await purchaseCredentialX402(client2, store2, fakeArc().factory, OFFER, {}, () => NOW, { webln: bad, pollIntervalMs: 1 });
    expect(store2.list()).toHaveLength(1);
  });

  it('surfaces the facilitator reason when settlement is refused', async () => {
    const { client } = fakeIssuer({ settleStatus: 402 });
    const store = new CreditStore(memoryStorage());
    await expect(
      purchaseCredentialX402(client, store, fakeArc().factory, OFFER, {}, () => NOW, { webln: null, pollIntervalMs: 1 }),
    ).rejects.toThrow(/duplicate_settlement/);
    // The paid state is kept so Resume can retry.
    expect(store.pending()?.x402?.preimage).toBe(FIXTURE_PREIMAGE);
  });

  it('requestChallenge and settle report unexpected statuses', async () => {
    const { client } = fakeIssuer();
    await expect(requestChallenge(client, 'not the body')).rejects.toThrow(/expected a 402/);
    const c = await validateChallenge(ISSUER, BODY, required(), OFFER, NOW);
    await expect(settle(client, BODY, c.resource, c.accepted, 'ff'.repeat(32))).rejects.toThrow(/preimage_hash_mismatch/);
  });
});
