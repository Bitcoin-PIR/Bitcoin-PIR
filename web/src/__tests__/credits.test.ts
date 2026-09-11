import { describe, expect, it, vi } from 'vitest';
import { MAX_CREDIT_PRESENT_PAYLOAD_LEN, REQ_CREDIT_PRESENT, RESP_CREDIT_OK } from '../constants.js';
import {
  CREDIT_PRESENT_KIND_ARC,
  CREDIT_PRESENT_KIND_CASHU,
  ConnectionCreditMeter,
  CreditStore,
  CreditWallet,
  IssuerClient,
  IssuerError,
  bytesToHex,
  creditsToCover,
  encodeCreditPresentFrame,
  hexToBytes,
  parseCreditResponsePayload,
  parseInsufficientGas,
  parseIssuedCredential,
  parseIssuerInfo,
  purchaseCredential,
  serverGasCardFromInfo,
  workGas,
  classifyOnionFrame,
  expectedResponseBytes,
  CreditedChannel,
  type ArcCredentialLike,
  type ArcRequestLike,
  type LightningRail,
  type StoredCredential,
} from '../credits.js';

const NOW = 1_800_000_000;
const PUBKEY_HEX = 'ab'.repeat(99);

function memoryStorage() {
  const map = new Map<string, string>();
  return {
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
  };
}

const INFO_V2 = {
  service: 'bitcoinpir-cashier',
  version: 2,
  credit_sat: 10,
  gas_per_credit: 72_000,
  base_gas_per_frame: 20,
  egress_gas_per_mb: 1_000,
  mints: ['https://mint.example'],
  offers: [{ credits: 100, sat: 1000 }],
  arc: {
    epoch: 231,
    presentation_limit: 100,
    issuer_public_key_hex: PUBKEY_HEX,
    presentation_context_hex: '00',
    valid_until: NOW + 86_400 * 100,
  },
  rate_card: [{ flow: 'onion_single_address', credits: 10 }],
};

const SERVER_INFO = {
  role: 'primary',
  gas: {
    unit: 'cpu_ms_pir1',
    params: { credit_sat: 10, gas_per_credit: 72_000, base_gas_per_frame: 20, egress_gas_per_mb: 1_000 },
    databases: {
      '0': {
        dpf_index_round: 1380,
        dpf_chunk_round: 4550,
        dpf_index_sibling_pass: [456, 57, 7],
        dpf_chunk_sibling_pass: [914, 114, 14],
        tree_tops: 5,
        onion_register_keys: 200,
        onion_index_query: 197_506,
        onion_chunk_query: 403_260,
        onion_sibling_query: 21_000,
        harmony_pool_entry: 129_970,
        harmony_index_sibling_set: [3780, 470, 60],
        harmony_chunk_sibling_set: [7570, 950, 120],
        harmony_query_index: 8,
        harmony_query_chunk: 12,
      },
      '1': { oram_lookup: 512 },
    },
  },
};

describe('credit frame codec', () => {
  it('encodes the present frame with a length prefix and parses receipts', () => {
    const frame = encodeCreditPresentFrame(CREDIT_PRESENT_KIND_ARC, new Uint8Array([1, 2, 3]));
    expect(Array.from(frame)).toEqual([9, 0, 0, 0, REQ_CREDIT_PRESENT, 2, 3, 0, 0, 0, 1, 2, 3]);
    expect(() => encodeCreditPresentFrame(3, new Uint8Array([1]))).toThrow(/kind/);
    expect(() => encodeCreditPresentFrame(CREDIT_PRESENT_KIND_CASHU, new Uint8Array())).toThrow(/empty/);
    expect(() =>
      encodeCreditPresentFrame(CREDIT_PRESENT_KIND_CASHU, new Uint8Array(MAX_CREDIT_PRESENT_PAYLOAD_LEN + 1)),
    ).toThrow(/limit/);

    const ok = new Uint8Array(17);
    ok[0] = RESP_CREDIT_OK;
    const view = new DataView(ok.buffer);
    view.setBigUint64(1, 72_000n, true);
    view.setBigInt64(9, -15n, true);
    expect(parseCreditResponsePayload(ok)).toEqual({ gasAdded: 72_000, gasBalance: -15 });
    expect(() => parseCreditResponsePayload(ok.subarray(0, 16))).toThrow(/17 bytes/);
    const message = new TextEncoder().encode('double spend');
    const error = new Uint8Array(5 + message.length);
    error[0] = 0xff;
    new DataView(error.buffer).setUint32(1, message.length, true);
    error.set(message, 5);
    expect(() => parseCreditResponsePayload(error)).toThrow('double spend');
    expect(() => parseCreditResponsePayload(new Uint8Array([0x11]))).toThrow(/unexpected/);
  });

  it('parses the server refusal exactly', () => {
    expect(
      parseInsufficientGas(
        'insufficient gas: this frame needs 1400 and the connection has -7; present credits with REQ_CREDIT_PRESENT',
      ),
    ).toEqual({ needed: 1400, balance: -7 });
    expect(parseInsufficientGas('credits not enabled on this server')).toBeNull();
  });

  it('hex helpers round trip', () => {
    expect(bytesToHex(new Uint8Array([0, 255, 16]))).toBe('00ff10');
    expect(Array.from(hexToBytes('00FF10'))).toEqual([0, 255, 16]);
    expect(() => hexToBytes('abc')).toThrow(/hex/);
  });
});

describe('gas card and meter', () => {
  it('prices frames like the server and tops up exactly the shortfall', () => {
    const card = serverGasCardFromInfo(SERVER_INFO)!;
    expect(card.unit).toBe('cpu_ms_pir1');
    expect(card.params.gasPerCredit).toBe(72_000);
    const meter = new ConnectionCreditMeter(card);
    expect(meter.frameGas(0, { kind: 'dpf_index_round' })).toBe(1400);
    expect(meter.frameGas(0, { kind: 'dpf_sibling_pass', table: 'chunk', level: 2 })).toBe(34);
    expect(meter.frameGas(0, { kind: 'dpf_sibling_pass', table: 'chunk', level: 3 })).toBeNull();
    expect(meter.frameGas(0, { kind: 'onion_chunk_query' })).toBe(403_280);
    expect(meter.frameGas(0, { kind: 'harmony_hint_set', level: 21 })).toBe(970);
    expect(meter.frameGas(0, { kind: 'harmony_query', level: 1, subQueries: 3 })).toBe(56);
    expect(meter.frameGas(0, { kind: 'harmony_continuation' })).toBe(20);
    expect(meter.frameGas(0, { kind: 'onion_tree_tops' })).toBe(25);
    expect(meter.frameGas(1, { kind: 'oram_lookup' })).toBe(532);
    expect(meter.frameGas(0, { kind: 'oram_lookup' })).toBeNull();
    expect(meter.frameGas(2, { kind: 'oram_lookup' })).toBeNull();
    expect(workGas(card.databases['1'], { kind: 'dpf_index_round' })).toBeNull();
    expect(serverGasCardFromInfo({ role: 'primary' })).toBeNull();

    expect(meter.creditsToPresent(1400, 8192)).toBe(1);
    meter.recordReceipt({ gasAdded: 72_000, gasBalance: 72_000 });
    expect(meter.creditsToPresent(1400, 8192)).toBe(0);
    meter.recordFrame(1400);
    meter.recordResponse(8192);
    expect(meter.balance).toBe(72_000 - 1400 - 8);
    expect(meter.creditsToPresent(403_280, 1_000_000)).toBe(5);
    expect(
      meter.recordRefusal(
        'insufficient gas: this frame needs 403280 and the connection has 100; present credits with REQ_CREDIT_PRESENT',
      ),
    ).toBe(403_280);
    expect(meter.balance).toBe(100);
    expect(creditsToCover(card.params, 0)).toBe(0);
    expect(creditsToCover(card.params, 72_001)).toBe(2);
  });
});

describe('issuer client', () => {
  it('parses v2 info and refuses other versions', () => {
    const info = parseIssuerInfo(INFO_V2);
    expect(info.gas.creditSat).toBe(10);
    expect(info.offers).toEqual([{ credits: 100, sat: 1000 }]);
    expect(info.arc?.epoch).toBe(231);
    expect(info.rateCard[0].credits).toBe(10);
    expect(() => parseIssuerInfo({ ...INFO_V2, version: 1 })).toThrow(/version/);
    expect(() => parseIssuerInfo({ ...INFO_V2, gas_per_credit: 0 })).toThrow(/positive/);
    expect(parseIssuerInfo({ ...INFO_V2, arc: undefined }).arc).toBeNull();
    expect(() => parseIssuerInfo({ ...INFO_V2, arc: { ...INFO_V2.arc, issuer_public_key_hex: 'ab' } })).toThrow(/99 bytes/);
  });

  it('buys a credential with hex request bytes and maps issuer errors', async () => {
    const calls: { url: string; body: unknown }[] = [];
    const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, body: init?.body ? JSON.parse(String(init.body)) : null });
      if (url.endsWith('/v2/credentials')) {
        return new Response(
          JSON.stringify({
            response_hex: 'cd'.repeat(454),
            epoch: 231,
            presentation_limit: 100,
            issuer_public_key_hex: PUBKEY_HEX,
            valid_until: NOW + 1,
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({ error: 'token_rejected', message: 'already spent' }), { status: 402 });
    }) as unknown as typeof fetch;
    const client = new IssuerClient('https://cashier.example/', fetchImpl);
    const issued = await client.buyCredential({ credits: 100, sat: 1000 }, 'cashuB', new Uint8Array([1, 2]));
    expect(issued.responseHex).toBe('cd'.repeat(454));
    expect(calls[0].url).toBe('https://cashier.example/v2/credentials');
    expect(calls[0].body).toEqual({ credits: 100, sat: 1000, token: 'cashuB', request_hex: '0102' });
    await expect(client.info()).rejects.toMatchObject({ status: 402, code: 'token_rejected' } satisfies Partial<IssuerError>);
    expect(() => new IssuerClient('ws://x')).toThrow(/https/);
    expect(() => parseIssuedCredential({ response_hex: 'zz' })).toThrow(/hex/);
  });
});

function fakeCredential(limit: number, nextNonce: number): ArcCredentialLike {
  let nonce = nextNonce;
  return {
    remaining: () => limit - nonce,
    nextNonce: () => nonce,
    present: (count: number) => {
      if (count > limit - nonce) throw new Error('too many');
      nonce += count;
      return new Uint8Array([count]);
    },
  };
}

function stored(credentialHex: string, limit: number, nextNonce: number, validUntil = NOW + 1000): StoredCredential {
  return {
    version: 1,
    issuerUrl: 'https://cashier.example',
    epoch: 231,
    presentationLimit: limit,
    credentialHex,
    nextNonce,
    issuerPublicKeyHex: PUBKEY_HEX,
    validUntil,
    boughtAt: NOW,
  };
}

describe('credit store and wallet', () => {
  it('persists credentials, advances nonces monotonically, and counts remaining credits', () => {
    const store = new CreditStore(memoryStorage());
    store.add(stored('aa', 100, 0));
    store.add(stored('bb', 100, 98));
    store.add(stored('cc', 100, 100));
    store.add(stored('dd', 100, 0, NOW - 1));
    expect(store.list()).toHaveLength(4);
    expect(store.usable(NOW).map((c) => c.credentialHex)).toEqual(['bb', 'aa']);
    expect(store.remainingCredits(NOW)).toBe(102);
    expect(store.advance('aa', 5)).toBe(true);
    expect(() => store.advance('aa', 4)).toThrow(/backwards/);
    expect(store.advance('zz', 1)).toBe(false);
    store.remove('cc');
    expect(store.list()).toHaveLength(3);
    expect(store.pending()).toBeNull();
    expect(new CreditStore(null).list()).toEqual([]);
  });

  it('presents from one credential and persists the nonce before returning', () => {
    const store = new CreditStore(memoryStorage());
    store.add(stored('aa', 100, 97));
    store.add(stored('bb', 100, 0));
    const opened: string[] = [];
    const wallet = new CreditWallet(
      store,
      {
        open: (credential, _epoch, limit, nextNonce) => {
          opened.push(bytesToHex(credential));
          return fakeCredential(limit, nextNonce);
        },
      },
      () => NOW,
    );
    expect(wallet.remainingCredits()).toBe(103);
    // Three credits fit on 'aa' (the nearly exhausted one goes first).
    const p1 = wallet.present(3)!;
    expect(p1).toMatchObject({ kind: CREDIT_PRESENT_KIND_ARC, credits: 3, epoch: 231 });
    expect(Array.from(p1.payload)).toEqual([3]);
    expect(opened).toEqual(['aa']);
    expect(store.list().find((c) => c.credentialHex === 'aa')?.nextNonce).toBe(100);
    // Ten credits: 'aa' is exhausted, 'bb' covers it.
    const p2 = wallet.present(10)!;
    expect(p2.credits).toBe(10);
    expect(opened).toEqual(['aa', 'bb']);
    // More than any single credential holds: as many as the fullest has.
    const p3 = wallet.present(500)!;
    expect(p3.credits).toBe(90);
    expect(wallet.present(1)).toBeNull();
    expect(() => wallet.present(0)).toThrow(/at least 1/);
  });

  it('buys a credential step by step and resumes from the persisted state', async () => {
    const storage = memoryStorage();
    const store = new CreditStore(storage);
    const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/v2/info')) return new Response(JSON.stringify(INFO_V2), { status: 200 });
      const body = JSON.parse(String(init?.body));
      expect(body.request_hex).toBe('0102');
      expect(body.token).toBe('cashuB-token');
      return new Response(
        JSON.stringify({
          response_hex: 'cd'.repeat(454),
          epoch: 231,
          presentation_limit: 100,
          issuer_public_key_hex: PUBKEY_HEX,
          valid_until: NOW + 100,
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;
    const issuer = new IssuerClient('https://cashier.example', fetchImpl);
    const finalize = vi.fn(() => new Uint8Array(131).fill(7));
    const request: ArcRequestLike = {
      requestBytes: () => new Uint8Array([1, 2]),
      secretsBytes: () => new Uint8Array([9, 9]),
      finalize,
    };
    const arc = { create: vi.fn(() => request), restore: vi.fn(() => request) };
    let paid = false;
    const rail: LightningRail = {
      quote: vi.fn(async () => ({ quoteId: 'q1', invoice: 'lnbc1', expiry: NOW + 600 })),
      waitPaid: vi.fn(async () => {
        if (!paid) {
          paid = true;
          throw new Error('wallet closed');
        }
      }),
      mint: vi.fn(async () => 'cashuB-token'),
    };
    const statuses: string[] = [];
    const attempt = () =>
      purchaseCredential(issuer, store, arc, rail, { credits: 100, sat: 1000 }, 'https://mint.example', {
        onStatus: (s) => statuses.push(s),
      }, () => NOW);
    // The first attempt persists request and quote, then the payment wait fails.
    await expect(attempt()).rejects.toThrow('wallet closed');
    const pending = store.pending()!;
    expect(pending.quoteId).toBe('q1');
    expect(pending.secretsHex).toBe('0909');
    expect(pending.token).toBeNull();
    // The second attempt resumes: no new request, no new quote, the invoice is now paid.
    const credential = await attempt();
    expect(arc.create).toHaveBeenCalledTimes(1);
    expect(rail.quote).toHaveBeenCalledTimes(1);
    expect(arc.restore).toHaveBeenCalledWith(231, new Uint8Array([9, 9]), new Uint8Array([1, 2]));
    expect(finalize).toHaveBeenCalledWith(PUBKEY_HEX, hexToBytes('cd'.repeat(454)));
    expect(credential.credentialHex).toBe('07'.repeat(131));
    expect(credential.nextNonce).toBe(0);
    expect(store.pending()).toBeNull();
    expect(store.list()).toHaveLength(1);
    expect(statuses).toEqual(['quoting', 'awaiting-payment', 'awaiting-payment', 'minting', 'issuing', 'finalizing', 'stored']);
  });
});

function onionFrame(variant: number, body: number[]): Uint8Array {
  const frame = new Uint8Array(5 + body.length);
  new DataView(frame.buffer).setUint32(0, 1 + body.length, true);
  frame[4] = variant;
  frame.set(body, 5);
  return frame;
}

describe('OnionPIR frame classification', () => {
  it('reads the metered kind and database like the server does', () => {
    // register keys: [galois_len u32][galois][gsw_len u32][gsw][db_id?]
    expect(classifyOnionFrame(onionFrame(0x50, [2, 0, 0, 0, 1, 2, 1, 0, 0, 0, 3, 1]))).toEqual({
      op: { kind: 'onion_register_keys' },
      dbId: 1,
    });
    expect(classifyOnionFrame(onionFrame(0x50, [2, 0, 0, 0, 1, 2, 1, 0, 0, 0, 3]))).toEqual({
      op: { kind: 'onion_register_keys' },
      dbId: 0,
    });
    // batch query: [round_id u16][n u8] n × [len u32][query] [db_id?]
    const query = [0, 0, 2, 1, 0, 0, 0, 9, 0, 0, 0, 0];
    expect(classifyOnionFrame(onionFrame(0x51, query))).toEqual({ op: { kind: 'onion_index_query' }, dbId: 0 });
    expect(classifyOnionFrame(onionFrame(0x52, [...query, 2]))).toEqual({ op: { kind: 'onion_chunk_query' }, dbId: 2 });
    expect(classifyOnionFrame(onionFrame(0x53, query))).toEqual({ op: { kind: 'onion_sibling_query' }, dbId: 0 });
    expect(classifyOnionFrame(onionFrame(0x55, query))).toEqual({ op: { kind: 'onion_sibling_query' }, dbId: 0 });
    expect(classifyOnionFrame(onionFrame(0x54, []))).toEqual({ op: { kind: 'onion_tree_tops' }, dbId: 0 });
    expect(classifyOnionFrame(onionFrame(0x56, [1]))).toEqual({ op: { kind: 'onion_tree_tops' }, dbId: 1 });
    // Truncated, over-long, unmetered, or mis-prefixed frames are not priced.
    expect(classifyOnionFrame(onionFrame(0x51, [0, 0, 2, 1, 0, 0, 0]))).toBeNull();
    expect(classifyOnionFrame(onionFrame(0x51, [...query, 1, 1]))).toBeNull();
    expect(classifyOnionFrame(onionFrame(0x03, []))).toBeNull();
    expect(classifyOnionFrame(onionFrame(0x12, [1, 0, 0, 0, 0]))).toBeNull();
    const bad = onionFrame(0x54, []);
    bad[0] = 9;
    expect(classifyOnionFrame(bad)).toBeNull();
    expect(expectedResponseBytes({ kind: 'onion_index_query' })).toBeGreaterThan(1_690_208);
    expect(expectedResponseBytes({ kind: 'tree_tops' })).toBeGreaterThan(9_155_389);
  });
});

/** A fake OnionPIR server: charges frames like the real gate, answers presentations with receipts. */
function fakeOnionServer(card: ReturnType<typeof serverGasCardFromInfo>) {
  const state = { balance: 0, sent: [] as number[], responseBytes: 100 };
  const exchange = async (frame: Uint8Array): Promise<Uint8Array> => {
    const variant = frame[4];
    state.sent.push(variant);
    const framed = (payload: Uint8Array) => {
      const out = new Uint8Array(4 + payload.length);
      new DataView(out.buffer).setUint32(0, payload.length, true);
      out.set(payload, 4);
      return out;
    };
    if (variant === 0x12) {
      const credits = frame[10];
      state.balance += credits * 72_000;
      const receipt = new Uint8Array(17);
      receipt[0] = 0x12;
      const view = new DataView(receipt.buffer);
      view.setBigUint64(1, BigInt(credits * 72_000), true);
      view.setBigInt64(9, BigInt(state.balance), true);
      return framed(receipt);
    }
    const classified = classifyOnionFrame(frame);
    const gas = classified && card ? workGas(card.databases[String(classified.dbId)] ?? { dpfIndexSiblingPass: [], dpfChunkSiblingPass: [], harmonyIndexSiblingSet: [], harmonyChunkSiblingSet: [] }, classified.op) : null;
    if (classified && gas !== null && card) {
      const needed = gas + card.params.baseGasPerFrame;
      if (state.balance < needed) {
        const message = new TextEncoder().encode(
          `insufficient gas: this frame needs ${needed} and the connection has ${state.balance}; present credits with REQ_CREDIT_PRESENT`,
        );
        const error = new Uint8Array(5 + message.length);
        error[0] = 0xff;
        new DataView(error.buffer).setUint32(1, message.length, true);
        error.set(message, 5);
        return framed(error);
      }
      state.balance -= needed;
      const response = new Uint8Array(state.responseBytes).fill(variant);
      state.balance -= Math.floor(((response.length + 4) * card.params.egressGasPerMb) / 1_000_000);
      return framed(response);
    }
    return framed(new Uint8Array([variant]));
  };
  return { state, exchange };
}

describe('credited channel', () => {
  const info = {
    role: 'primary',
    gas: {
      unit: 'cpu_ms_pir1',
      params: { credit_sat: 10, gas_per_credit: 72_000, base_gas_per_frame: 20, egress_gas_per_mb: 1_000 },
      databases: {
        '0': { onion_register_keys: 200, onion_index_query: 197_506, onion_chunk_query: 403_260, onion_sibling_query: 21_000, tree_tops: 5 },
      },
    },
    credits: { enabled: true, required: true },
  };

  it('funds metered frames before sending them and leaves free frames alone', async () => {
    const card = serverGasCardFromInfo(info)!;
    const server = fakeOnionServer(card);
    const calls: number[] = [];
    let left = 20;
    const channel = new CreditedChannel(
      card,
      (credits) => {
        calls.push(credits);
        const give = Math.min(credits, left, 255);
        if (give === 0) return null;
        left -= give;
        return { kind: CREDIT_PRESENT_KIND_ARC, payload: new Uint8Array([give]), credits: give, epoch: 1 };
      },
      server.exchange,
    );
    await channel.roundtrip(onionFrame(0x03, []));
    expect(calls).toEqual([]);
    // Register keys: 220 gas plus a 1 KiB reserve → one credit.
    const keys = onionFrame(0x50, [1, 0, 0, 0, 7, 1, 0, 0, 0, 8]);
    expect((await channel.roundtrip(keys))[4]).toBe(0x50);
    expect(calls).toEqual([1]);
    expect(server.state.sent).toEqual([0x03, 0x12, 0x50]);
    // An INDEX query needs 197,526 gas plus a 2 MiB reserve; 71,780 gas are
    // left from the first credit, so two more cover it.
    const query = onionFrame(0x51, [0, 0, 1, 1, 0, 0, 0, 9]);
    server.state.responseBytes = 1_690_208;
    expect((await channel.roundtrip(query))[4]).toBe(0x51);
    expect(calls).toEqual([1, 2]);
    expect(channel.presentedCredits).toBe(3);
    // The client's balance tracks the server's exactly after the egress charge.
    expect(channel.meter.balance).toBe(server.state.balance);
    // A second INDEX query is priced from the observed response size.
    expect((await channel.roundtrip(query))[4]).toBe(0x51);
    expect(channel.meter.balance).toBe(server.state.balance);
  });

  it('retries once with the server numbers when refused, and reports an empty wallet', async () => {
    const card = serverGasCardFromInfo(info)!;
    const server = fakeOnionServer(card);
    let left = 3;
    const channel = new CreditedChannel(
      card,
      (credits) => {
        const give = Math.min(credits, left);
        if (give === 0) return null;
        left -= give;
        return { kind: CREDIT_PRESENT_KIND_CASHU, payload: new Uint8Array([give]), credits: give, epoch: 1 };
      },
      server.exchange,
    );
    const keys = onionFrame(0x50, [1, 0, 0, 0, 7, 1, 0, 0, 0, 8]);
    await channel.roundtrip(keys);
    // The server drained the balance behind the client's back.
    server.state.balance = 10;
    expect((await channel.roundtrip(keys))[4]).toBe(0x50);
    expect(server.state.sent.filter((v) => v === 0xff).length).toBe(0);
    expect(server.state.sent.slice(-3)).toEqual([0x50, 0x12, 0x50]);
    // The wallet is now empty: a chunk query cannot be funded.
    server.state.balance = 0;
    channel.meter.recordRefusal('insufficient gas: this frame needs 403280 and the connection has 0; x');
    await expect(channel.roundtrip(onionFrame(0x52, [0, 0, 1, 1, 0, 0, 0, 9]))).rejects.toThrow(/credits required/);
  });
});
