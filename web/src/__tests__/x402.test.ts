import { createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { decodeBolt11 } from '../bolt11.js';
import { CashuStore, type PendingX402TopUp } from '../cashu-wallet.js';
import { IssuerClient } from '../credits.js';
import {
  headerValue,
  http1Binding,
  jcs,
  parseHeader,
  requestChallenge,
  settle,
  topUpX402,
  validateChallenge,
  X402_NETWORK_MAINNET,
  type PaymentRequired,
} from '../x402.js';
import { fakeMint, json, routeFetch, type FakeBlindSignature, type FetchHandler } from './fake-mint.js';

const ISSUER = 'https://issuer.example';
const ECASH_URL = `${ISSUER}/v2/x402/ecash`;
const KEY_ONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const NOW = 1_800_000_005;
const PREIMAGE = '42'.repeat(32);
const PAYMENT_HASH = createHash('sha256').update(Buffer.from(PREIMAGE, 'hex')).digest('hex');
const KEYSET_ID = '00ad268c4d1f5826';
/** A fixed request body: 10 sat as 8 + 2. */
const BODY = JSON.stringify({
  sat: 10,
  outputs: [
    { amount: 8, id: KEYSET_ID, B_: `02${'aa'.repeat(32)}` },
    { amount: 2, id: KEYSET_ID, B_: `03${'bb'.repeat(32)}` },
  ],
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function memoryStorage() {
  const map = new Map<string, string>();
  return {
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => void map.set(k, v),
  };
}

// ─── A BOLT11 signer for the fake issuer (key 1, like the issuer's test helper) ───

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function polymod(values: number[]): number {
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ generators[i]) >>> 0;
  }
  return chk;
}

/** Regroups `from`-bit values into `to`-bit values, zero-padding the tail. */
function regroup(values: Iterable<number>, from: number, to: number): number[] {
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const v of values) {
    acc = ((acc << from) | v) & 0xffff;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >>> bits) & ((1 << to) - 1));
    }
  }
  if (bits > 0) out.push((acc << (to - bits)) & ((1 << to) - 1));
  return out;
}

function bigEndianWords(value: number, length: number): number[] {
  return Array.from({ length }, (_, i) => Math.floor(value / 32 ** (length - 1 - i)) % 32);
}

function tagged(type: number, words: number[]): number[] {
  return [type, words.length >> 5, words.length & 31, ...words];
}

/** A mainnet invoice for `sat` with a 900 s expiry, signed by key 1 and bound to `descriptionHashHex`. */
function signInvoice(sat: number, descriptionHashHex: string): string {
  const hrp = `lnbc${sat * 10}n`;
  const data = [
    ...bigEndianWords(NOW - 5, 7),
    ...tagged(1, regroup(Buffer.from(PAYMENT_HASH, 'hex'), 8, 5)),
    ...tagged(23, regroup(Buffer.from(descriptionHashHex, 'hex'), 8, 5)),
    ...tagged(6, bigEndianWords(900, 2)),
  ];
  const keyOne = new Uint8Array(32);
  keyOne[31] = 1;
  const digest = sha256(Uint8Array.from([...Buffer.from(hrp), ...regroup(data, 5, 8)]));
  const recovered = secp256k1.sign(digest, keyOne, { prehash: false, format: 'recovered' });
  const words = [...data, ...regroup([...recovered.subarray(1), recovered[0]], 8, 5)];
  const hrpWords = [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];
  const checksum = polymod([...hrpWords, ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  const check = Array.from({ length: 6 }, (_, i) => (checksum >>> (5 * (5 - i))) & 31);
  return `${hrp}1${[...words, ...check].map((w) => CHARSET[w]).join('')}`;
}

async function bodyHash(body: string, contentType: string | null = 'application/json'): Promise<string> {
  const binding = await http1Binding('POST', ECASH_URL, new TextEncoder().encode(body), [{ name: 'content-type', value: contentType }]);
  return binding.requestHashHex;
}

function required(
  sat: number,
  requestHash: string,
  invoice: string,
  overrides: Partial<PaymentRequired['accepts'][number]> = {},
  extra: Record<string, unknown> = {},
): PaymentRequired {
  return {
    x402Version: 2,
    error: 'payment required',
    resource: { url: ECASH_URL, description: 'ecash' },
    accepts: [
      {
        scheme: 'exact',
        network: X402_NETWORK_MAINNET,
        amount: String(sat * 1000),
        asset: 'BTC',
        payTo: KEY_ONE,
        maxTimeoutSeconds: 900,
        ...overrides,
        extra: {
          assetTransferMethod: 'bolt11',
          paymentFlow: 'upfront',
          requestHash,
          requestBindingProfile: 'http:1',
          requestBindingParams: { headers: ['content-type'] },
          invoice,
          ...extra,
        },
      },
    ],
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

  it('covers every byte of the body and the content-type header', async () => {
    const hash = await bodyHash(BODY);
    expect(await bodyHash(BODY.replace('aa', 'ab'))).not.toBe(hash);
    expect(await bodyHash(BODY.replace('"sat":10', '"sat":11'))).not.toBe(hash);
    expect(await bodyHash(BODY, null)).not.toBe(hash);
  });

  it('round-trips base64 JSON headers', () => {
    const v = { x402Version: 2, payload: { preimage: PREIMAGE } };
    expect(parseHeader(headerValue(v))).toEqual(v);
  });
});

describe('validateChallenge', () => {
  it('accepts a challenge bound to our exact body and extracts the payment hash', async () => {
    const hash = await bodyHash(BODY);
    const c = await validateChallenge(ISSUER, BODY, required(10, hash, signInvoice(10, hash)), 10, NOW);
    expect(c.paymentHash).toBe(PAYMENT_HASH);
    expect(c.expiresAt).toBe(NOW - 5 + 900);
    expect(c.accepted.payTo).toBe(KEY_ONE);
  });

  it('refuses challenges that do not bind our request or terms', async () => {
    const hash = await bodyHash(BODY);
    const ok = (overrides = {}, extra = {}) => required(10, hash, signInvoice(10, hash), overrides, extra);
    // The issuer bound another body (one blinded output differs).
    const other = await bodyHash(BODY.replace('aa', 'ab'));
    await expect(validateChallenge(ISSUER, BODY, required(10, other, signInvoice(10, other)), 10, NOW)).rejects.toThrow(/requestHash/);
    await expect(validateChallenge(ISSUER, BODY, required(10, hash, signInvoice(10, other)), 10, NOW)).rejects.toThrow(/not bound/);
    await expect(validateChallenge(ISSUER, BODY.replace('aa', 'ab'), ok(), 10, NOW)).rejects.toThrow(/requestHash/);
    await expect(validateChallenge(ISSUER, BODY, ok(), 11, NOW)).rejects.toThrow(/msat/);
    await expect(validateChallenge(ISSUER, BODY, required(11, hash, signInvoice(10, hash)), 11, NOW)).rejects.toThrow(/amount/);
    const elsewhere = ok();
    elsewhere.resource = { url: 'https://cashier.example/v2/x402/ecash' };
    await expect(validateChallenge(ISSUER, BODY, elsewhere, 10, NOW)).rejects.toThrow(/resource\.url/);
    await expect(validateChallenge(ISSUER, BODY, ok({ payTo: `02${'c6'.repeat(32)}` }), 10, NOW)).rejects.toThrow(/payTo/);
    await expect(validateChallenge(ISSUER, BODY, ok({ maxTimeoutSeconds: 300 }), 10, NOW)).rejects.toThrow(/expiry/);
    await expect(validateChallenge(ISSUER, BODY, ok(), 10, NOW + 1000)).rejects.toThrow(/expired/);
    await expect(validateChallenge(ISSUER, BODY, ok({}, { paymentFlow: 'deferred' }), 10, NOW)).rejects.toThrow(/upfront/);
    await expect(
      validateChallenge(ISSUER, BODY, ok({}, { requestBindingParams: { headers: ['payment-signature'] } }), 10, NOW),
    ).rejects.toThrow(/header/);
  });
});

/**
 * A scripted issuer: info naming `mint`, the 402 challenge bound to the
 * request it received, invoice polling, and a settlement that signs the
 * request's outputs with the mint's keys (DLEQ included).
 */
function fakeIssuer(
  mint: ReturnType<typeof fakeMint>,
  options: { paidAfterPolls?: number; settleStatuses?: number[]; tamper?: (signatures: FakeBlindSignature[]) => void } = {},
) {
  const calls: { path: string; headers: Record<string, string>; body: string | undefined }[] = [];
  const settleStatuses = [...(options.settleStatuses ?? [])];
  let polls = 0;
  let challenged: string | undefined;
  const handle: FetchHandler = async (input, init) => {
    const path = new URL(String(input)).pathname;
    const headers = Object.fromEntries(Object.entries((init?.headers as Record<string, string>) ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    const body = typeof init?.body === 'string' ? init.body : undefined;
    calls.push({ path, headers, body });
    if (path === '/v2/info') {
      return json(200, {
        service: 'bitcoinpir-issuer',
        version: 2,
        credit_sat: 10,
        gas_per_credit: 72_000,
        base_gas_per_frame: 20,
        egress_gas_per_mb: 1_000,
        mints: [mint.url],
        rate_card: [],
      });
    }
    if (path === '/v2/x402/ecash' && !headers['payment-signature']) {
      const { sat } = JSON.parse(body!);
      const hash = await bodyHash(body!, headers['content-type'] ?? null);
      const challenge = required(sat, hash, signInvoice(sat, hash));
      challenged = body;
      return json(402, challenge, { 'payment-required': headerValue(challenge) });
    }
    if (path === '/v2/x402/ecash') {
      const payment = parseHeader(headers['payment-signature']) as { payload: { preimage: string } };
      if (body !== challenged || payment.payload.preimage !== PREIMAGE) {
        return json(402, { error: 'payment_failed' }, {
          'payment-response': headerValue({ success: false, errorReason: 'invalid_exact_lnbtc_preimage_hash_mismatch', transaction: '', network: X402_NETWORK_MAINNET }),
        });
      }
      const status = settleStatuses.shift() ?? 200;
      if (status !== 200) return json(status, { error: 'retry', message: 'mint outcome unknown' });
      const signatures = JSON.parse(body!).outputs.map(mint.sign);
      options.tamper?.(signatures);
      return json(200, { signatures }, {
        'payment-response': headerValue({ success: true, transaction: PAYMENT_HASH, network: X402_NETWORK_MAINNET }),
      });
    }
    if (path === `/v2/x402/invoices/${PAYMENT_HASH}`) {
      polls += 1;
      return polls > (options.paidAfterPolls ?? 1)
        ? json(200, { payment_hash: PAYMENT_HASH, status: 'paid', preimage: PREIMAGE })
        : json(200, { payment_hash: PAYMENT_HASH, status: 'unpaid', preimage: null });
    }
    return json(404, { error: 'not_found' });
  };
  return { client: new IssuerClient(ISSUER, routeFetch({ [ISSUER]: handle })), calls };
}

/** A fake mint at a fresh URL, served through the global `fetch` cashu-ts uses. */
function stubMint(name: string) {
  const mint = fakeMint(`https://${name}.example`);
  vi.stubGlobal('fetch', routeFetch({ [mint.url]: mint.handle }));
  return mint;
}

describe('topUpX402', () => {
  it('challenges, waits for the payment, retries the identical body, and unblinds the signatures', async () => {
    const mint = stubMint('mint-x402-flow');
    const { client, calls } = fakeIssuer(mint, { paidAfterPolls: 2 });
    const store = new CashuStore(memoryStorage());
    const statuses: string[] = [];
    const invoices: string[] = [];
    const hooks = { onStatus: (s: string) => statuses.push(s), onInvoice: (i: string) => invoices.push(i) };
    expect(await topUpX402(client, store, 30, hooks, () => NOW, { pollIntervalMs: 1, webln: null })).toBe(30);
    const proofs = store.state().proofs;
    expect(proofs.map((p) => p.amount)).toEqual([8, 2, 8, 2, 8, 2]);
    expect(proofs.every(mint.verify)).toBe(true);
    expect(store.state().creditSat).toBe(10);
    expect(store.pending()).toBeNull();
    expect(statuses).toEqual(['quoting', 'awaiting-payment', 'minting', 'stored']);
    expect(decodeBolt11(invoices[0]).paymentHashHex).toBe(PAYMENT_HASH);
    const posts = calls.filter((c) => c.path === '/v2/x402/ecash');
    expect(posts).toHaveLength(2);
    expect(posts[1].body).toBe(posts[0].body);
    expect(posts[0].headers['payment-signature']).toBeUndefined();
    expect(typeof posts[1].headers['payment-signature']).toBe('string');
    const body = JSON.parse(posts[0].body!);
    expect(body.sat).toBe(30);
    expect(Object.keys(body.outputs[0])).toEqual(['amount', 'id', 'B_']);
    expect(body.outputs.map((o: { amount: number }) => o.amount)).toEqual([8, 2, 8, 2, 8, 2]);
    expect(body.outputs.every((o: { id: string; B_: string }) => o.id === mint.keysetId && /^0[23][0-9a-f]{64}$/.test(o.B_))).toBe(true);
    expect(calls.filter((c) => c.path.startsWith('/v2/x402/invoices/'))).toHaveLength(3);
  });

  it('takes the preimage from WebLN without polling', async () => {
    const mint = stubMint('mint-x402-webln');
    const { client, calls } = fakeIssuer(mint);
    const store = new CashuStore(memoryStorage());
    const webln = { enable: vi.fn(async () => undefined), sendPayment: vi.fn(async () => ({ preimage: PREIMAGE })) };
    expect(await topUpX402(client, store, 10, {}, () => NOW, { webln })).toBe(10);
    expect(webln.sendPayment).toHaveBeenCalledTimes(1);
    expect(calls.some((c) => c.path.startsWith('/v2/x402/invoices/'))).toBe(false);
    expect(store.balance()).toBe(10);
  });

  it('resumes a paid top-up after a reload with the identical request when the issuer answered 503', async () => {
    const mint = stubMint('mint-x402-resume');
    const { client, calls } = fakeIssuer(mint, { settleStatuses: [503] });
    const storage = memoryStorage();
    const webln = { enable: async () => undefined, sendPayment: async () => ({ preimage: PREIMAGE }) };
    await expect(topUpX402(client, new CashuStore(storage), 20, {}, () => NOW, { webln })).rejects.toThrow(/503/);
    const pending = new CashuStore(storage).pending() as PendingX402TopUp;
    expect(pending).toMatchObject({ rail: 'x402', sat: 20, mintUrl: mint.url, keysetId: mint.keysetId, preimage: PREIMAGE });
    expect(JSON.parse(pending.body).outputs.map((o: { B_: string }) => o.B_)).toEqual(pending.outputs.map((o) => o.blindedMessage.B_));
    expect(pending.outputs.every((o) => /^[1-9][0-9]*$/.test(o.blindingFactor) && o.secret.length > 0)).toBe(true);
    const before = calls.length;
    const store = new CashuStore(storage);
    expect(await topUpX402(client, store, 20, {}, () => NOW, { webln: null })).toBe(20);
    expect(calls.slice(before).map((c) => c.path)).toEqual(['/v2/x402/ecash']);
    expect(calls.at(-1)!.body).toBe(pending.body);
    expect(store.pending()).toBeNull();
    expect(store.state().proofs.every(mint.verify)).toBe(true);
  });

  it('settles with an invoice paid before it expired instead of asking for a second payment', async () => {
    const mint = stubMint('mint-x402-expired-paid');
    const { client, calls } = fakeIssuer(mint, { paidAfterPolls: 0 });
    const storage = memoryStorage();
    const controller = new AbortController();
    const hooks = { onInvoice: () => controller.abort(), signal: controller.signal };
    await expect(topUpX402(client, new CashuStore(storage), 10, hooks, () => NOW, { webln: null, pollIntervalMs: 1 })).rejects.toThrow(/cancelled/);
    const pending = new CashuStore(storage).pending() as PendingX402TopUp;
    expect(pending.paymentHash).toBe(PAYMENT_HASH);
    const store = new CashuStore(storage);
    expect(await topUpX402(client, store, 10, {}, () => pending.expiresAt! + 1, { webln: null })).toBe(10);
    expect(calls.filter((c) => c.path === '/v2/x402/ecash' && !c.headers['payment-signature'])).toHaveLength(1);
    expect(store.state().proofs.every(mint.verify)).toBe(true);
  });

  it('refuses signatures whose DLEQ proof or amount does not match, keeping the paid top-up', async () => {
    const mint = stubMint('mint-x402-tamper');
    const webln = { enable: async () => undefined, sendPayment: async () => ({ preimage: PREIMAGE }) };
    const swapDleq = (s: FakeBlindSignature[]) => ([s[0].dleq, s[1].dleq] = [s[1].dleq, s[0].dleq]);
    const store = new CashuStore(memoryStorage());
    await expect(topUpX402(fakeIssuer(mint, { tamper: swapDleq }).client, store, 10, {}, () => NOW, { webln })).rejects.toThrow(/DLEQ/);
    expect(store.pending()).toMatchObject({ rail: 'x402', preimage: PREIMAGE });
    expect(store.balance()).toBe(0);
    const relabel = (s: FakeBlindSignature[]) => void (s[0].amount = 2);
    const other = new CashuStore(memoryStorage());
    await expect(topUpX402(fakeIssuer(mint, { tamper: relabel }).client, other, 10, {}, () => NOW, { webln })).rejects.toThrow(/another amount/);
  });

  it('requestChallenge and settle report unexpected answers', async () => {
    const mint = stubMint('mint-x402-errors');
    const { client } = fakeIssuer(mint);
    const busy = new IssuerClient(ISSUER, routeFetch({ [ISSUER]: async () => json(503, { error: 'float_exhausted', message: 'try later' }) }));
    await expect(requestChallenge(busy, BODY)).rejects.toThrow(/expected a 402.*float_exhausted/);
    const hash = await bodyHash(BODY);
    const challenge = await validateChallenge(ISSUER, BODY, required(10, hash, signInvoice(10, hash)), 10, NOW);
    await expect(settle(client, BODY, challenge.resource, challenge.accepted, 'ff'.repeat(32))).rejects.toThrow(/preimage_hash_mismatch/);
  });
});
