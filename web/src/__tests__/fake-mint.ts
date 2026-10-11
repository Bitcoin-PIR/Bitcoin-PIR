/**
 * A Cashu mint for tests, built on cashu-ts's crypto helpers: one active
 * `sat` keyset, NUT-04 bolt11 quotes (the test marks them paid), blind
 * signatures with NUT-12 DLEQ proofs, NUT-07 states and NUT-09 restore.
 * `handle` answers `fetch` for the mint's origin.
 */

import {
  createBlindSignature,
  createDLEQProof,
  createNewMintKeys,
  hashToCurve,
  pointFromHex,
  serializeMintKeys,
  verifyUnblindedSignature,
} from '@cashu/cashu-ts';

export type FetchHandler = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface FakeBlindSignature {
  amount: number;
  id: string;
  C_: string;
  dleq: { e: string; s: string };
}

interface FakeQuote {
  quote: string;
  request: string;
  amount: number;
  unit: string;
  state: 'UNPAID' | 'PAID' | 'ISSUED';
  expiry: number;
}

export function json(status: number, value: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json', ...headers } });
}

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

export function fakeMint(url: string, expiry = 2_000_000_000) {
  const pair = createNewMintKeys(16, undefined, { unit: 'sat' });
  const keys = serializeMintKeys(pair.pubKeys);
  const signed = new Map<string, FakeBlindSignature>();
  const spent = new Set<string>();
  const quotes = new Map<string, FakeQuote>();
  const calls: string[] = [];
  const state = { dropNextMintAnswer: false };

  /** Sign one output with the key for its amount, remembering it for NUT-09. */
  function sign(output: { amount: number; B_: string }): FakeBlindSignature {
    const B_ = pointFromHex(output.B_);
    const key = pair.privKeys[String(output.amount)];
    const dleq = createDLEQProof(B_, key);
    const signature = {
      amount: output.amount,
      id: pair.keysetId,
      C_: createBlindSignature(B_, key, pair.keysetId).C_.toHex(true),
      dleq: { e: hex(dleq.e), s: hex(dleq.s) },
    };
    signed.set(output.B_, signature);
    return signature;
  }

  const handle: FetchHandler = async (input, init) => {
    const path = new URL(String(input)).pathname;
    const body = typeof init?.body === 'string' ? JSON.parse(init.body) : null;
    calls.push(path);
    if (path === '/v1/info') {
      return json(200, {
        name: 'fake mint',
        version: 'cdk-mintd/0.17.3',
        nuts: {
          4: { methods: [{ method: 'bolt11', unit: 'sat', options: { description: true } }], disabled: false },
          7: { supported: true },
          9: { supported: true },
          12: { supported: true },
        },
      });
    }
    if (path === '/v1/keysets') return json(200, { keysets: [{ id: pair.keysetId, unit: 'sat', active: true, input_fee_ppk: 0 }] });
    if (path === '/v1/keys' || path === `/v1/keys/${pair.keysetId}`) {
      return json(200, { keysets: [{ id: pair.keysetId, unit: 'sat', active: true, keys }] });
    }
    if (path === '/v1/mint/quote/bolt11') {
      // cashu-ts checks the invoice amount against the quote (sat × 10 in units of 100 msat).
      const quote: FakeQuote = { quote: `q${quotes.size + 1}`, request: `lnbc${body.amount * 10}n1fake`, amount: body.amount, unit: 'sat', state: 'UNPAID', expiry };
      quotes.set(quote.quote, quote);
      return json(200, quote);
    }
    if (path.startsWith('/v1/mint/quote/bolt11/')) return json(200, quotes.get(path.split('/').pop()!));
    if (path === '/v1/mint/bolt11') {
      const quote = quotes.get(body.quote);
      if (quote?.state !== 'PAID') return json(400, { code: 20002, detail: 'quote not paid or already issued' });
      quote.state = 'ISSUED';
      const signatures = body.outputs.map(sign);
      if (state.dropNextMintAnswer) {
        state.dropNextMintAnswer = false;
        return json(502, { detail: 'bad gateway' });
      }
      return json(200, { signatures });
    }
    if (path === '/v1/restore') {
      const outputs = body.outputs.filter((o: { B_: string }) => signed.has(o.B_));
      return json(200, { outputs, signatures: outputs.map((o: { B_: string }) => signed.get(o.B_)) });
    }
    if (path === '/v1/checkstate') {
      return json(200, { states: body.Ys.map((Y: string) => ({ Y, state: spent.has(Y) ? 'SPENT' : 'UNSPENT', witness: null })) });
    }
    return json(404, { detail: 'not found' });
  };

  return {
    url,
    keysetId: pair.keysetId,
    quotes,
    calls,
    state,
    sign,
    handle,
    /** Mark the quote of `invoice` paid. */
    pay(invoice: string): void {
      for (const quote of quotes.values()) if (quote.request === invoice) quote.state = 'PAID';
    },
    /** Mark a proof spent (NUT-07), as a swap of it would. */
    spend(secret: string): void {
      spent.add(hashToCurve(new TextEncoder().encode(secret)).toHex(true));
    },
    /** Whether `proof` carries this mint's signature on its secret. */
    verify(proof: { amount: number; secret: string; C: string }): boolean {
      const unblinded = { C: pointFromHex(proof.C), secret: new TextEncoder().encode(proof.secret), id: pair.keysetId };
      return verifyUnblindedSignature(unblinded, pair.privKeys[String(proof.amount)]);
    },
  };
}

/** `fetch` routed by origin. */
export function routeFetch(handlers: Record<string, FetchHandler>): typeof fetch {
  return ((input: string | URL | Request, init?: RequestInit) => {
    const handler = handlers[new URL(String(input)).origin];
    if (!handler) throw new Error(`no fake serves ${String(input)}`);
    return handler(input, init);
  }) as typeof fetch;
}
