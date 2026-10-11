import { describe, expect, it, vi } from 'vitest';
import {
  MAX_API_KEY_LEN,
  MAX_CREDIT_PRESENT_PAYLOAD_LEN,
  REQ_API_KEY,
  REQ_CREDIT_PRESENT,
  RESP_API_KEY_OK,
  RESP_CREDIT_OK,
} from '../constants.js';
import {
  CREDIT_PRESENT_KIND_CASHU,
  ConnectionCreditMeter,
  IssuerClient,
  IssuerError,
  bytesToHex,
  creditsToCover,
  encodeApiKeyFrame,
  encodeCreditPresentFrame,
  hexToBytes,
  parseApiKeyResponsePayload,
  parseCreditResponsePayload,
  parseInsufficientGas,
  parseIssuerInfo,
  serverGasCardFromInfo,
  workGas,
  classifyOnionFrame,
  expectedResponseBytes,
  CreditedChannel,
  FREE_LANE_BUSY_PREFIX,
  isFreeLaneBusy,
  resolveAccess,
} from '../credits.js';

const INFO_V2 = {
  service: 'bitcoinpir-issuer',
  version: 2,
  credit_sat: 10,
  gas_per_credit: 72_000,
  base_gas_per_frame: 20,
  egress_gas_per_mb: 1_000,
  mints: ['https://mint.example'],
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

describe('API key frame codec', () => {
  it('frames the key after the opcode and accepts only the empty OK answer', () => {
    expect(Array.from(encodeApiKeyFrame('bpk_1'))).toEqual(
      [6, 0, 0, 0, REQ_API_KEY, ...new TextEncoder().encode('bpk_1')],
    );
    expect(() => encodeApiKeyFrame('')).toThrow(/1 to 128 bytes/);
    expect(() => encodeApiKeyFrame('k'.repeat(MAX_API_KEY_LEN + 1))).toThrow(/1 to 128 bytes/);

    expect(() => parseApiKeyResponsePayload(new Uint8Array([RESP_API_KEY_OK]))).not.toThrow();
    expect(() => parseApiKeyResponsePayload(new Uint8Array([RESP_API_KEY_OK, 0]))).toThrow(/unexpected/);
    expect(() => parseApiKeyResponsePayload(new Uint8Array([RESP_CREDIT_OK]))).toThrow(/unexpected/);
    const message = new TextEncoder().encode('unknown API key');
    const error = new Uint8Array(5 + message.length);
    error[0] = 0xff;
    new DataView(error.buffer).setUint32(1, message.length, true);
    error.set(message, 5);
    expect(() => parseApiKeyResponsePayload(error)).toThrow('unknown API key');
  });
});

describe('credit frame codec', () => {
  it('encodes the present frame with a length prefix and parses receipts', () => {
    const frame = encodeCreditPresentFrame(CREDIT_PRESENT_KIND_CASHU, new Uint8Array([1, 2, 3]));
    expect(Array.from(frame)).toEqual([9, 0, 0, 0, REQ_CREDIT_PRESENT, 1, 3, 0, 0, 0, 1, 2, 3]);
    expect(() => encodeCreditPresentFrame(2, new Uint8Array([1]))).toThrow(/kind/);
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
    expect(meter.frameGas(0, { kind: 'harmony_continuation' })).toBe(20 + 64_985);
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
  it('parses v2 info, refuses other versions, and maps issuer errors', async () => {
    const info = parseIssuerInfo(INFO_V2);
    expect(info.gas.creditSat).toBe(10);
    expect(info.mints).toEqual(['https://mint.example']);
    expect(info.rateCard[0].credits).toBe(10);
    expect(() => parseIssuerInfo({ ...INFO_V2, version: 1 })).toThrow(/version/);
    expect(() => parseIssuerInfo({ ...INFO_V2, gas_per_credit: 0 })).toThrow(/positive/);
    const fetchImpl = vi.fn(async (url: string) => {
      expect(url).toBe('https://issuer.example/v2/info');
      return new Response(JSON.stringify({ error: 'rate_limited', message: 'slow down' }), { status: 429 });
    }) as unknown as typeof fetch;
    const client = new IssuerClient('https://issuer.example/', fetchImpl);
    await expect(client.info()).rejects.toMatchObject({ status: 429, code: 'rate_limited' } satisfies Partial<IssuerError>);
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
  const state = {
    balance: 0,
    sent: [] as number[],
    responseBytes: 100,
    /** `true`/`false`: best-effort — an uncovered frame is refused as busy / served free. */
    bestEffortBusy: undefined as boolean | undefined,
  };
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
      if (state.balance < needed && state.bestEffortBusy === false) {
        return framed(new Uint8Array(state.responseBytes).fill(variant));
      }
      if (state.balance < needed && state.bestEffortBusy === true) {
        const message = new TextEncoder().encode(
          'free capacity busy: onion serves 1 free frame(s) at a time and none was free within 10s; present credits for priority or retry later',
        );
        const error = new Uint8Array(5 + message.length);
        error[0] = 0xff;
        new DataView(error.buffer).setUint32(1, message.length, true);
        error.set(message, 5);
        return framed(error);
      }
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
        return { kind: CREDIT_PRESENT_KIND_CASHU, payload: new Uint8Array([give]), credits: give };
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
        return { kind: CREDIT_PRESENT_KIND_CASHU, payload: new Uint8Array([give]), credits: give };
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

describe('access policy', () => {
  it('resolves a published entry, else falls back to the legacy flag', () => {
    const credits = {
      enabled: true,
      required: true,
      access: {
        dpf: { mode: 'best-effort', free_concurrency: 2 },
        onion: { mode: 'paid' },
        oram: { mode: 'best-effort', free_concurrency: 1, free_gas_per_hour: 7200 },
      },
    };
    expect(resolveAccess(credits, 'dpf')).toEqual({ mode: 'best-effort', free_concurrency: 2 });
    expect(resolveAccess(credits, 'oram')).toEqual({ mode: 'best-effort', free_concurrency: 1, free_gas_per_hour: 7200 });
    expect(resolveAccess(credits, 'onion')).toEqual({ mode: 'paid' });
    // Not published: paid because the server says credits are required.
    expect(resolveAccess(credits, 'harmony')).toEqual({ mode: 'paid' });
    expect(resolveAccess({ enabled: true, required: false }, 'dpf')).toEqual({ mode: 'free' });
    expect(resolveAccess(undefined, 'onion')).toEqual({ mode: 'free' });
    // A malformed entry is ignored, not trusted.
    expect(resolveAccess({ enabled: true, required: true, access: { dpf: { mode: 'best-effort', free_concurrency: 0 } } }, 'dpf')).toEqual({ mode: 'paid' });
  });

  it('recognises busy refusals by their prefix', () => {
    expect(isFreeLaneBusy(`${FREE_LANE_BUSY_PREFIX}: dpf serves 2 free frame(s) at a time`)).toBe(true);
    expect(isFreeLaneBusy('insufficient gas: this frame needs 25')).toBe(false);
  });
});

describe('credited channel with a best-effort server', () => {
  const info = {
    role: 'primary',
    gas: {
      unit: 'cpu_ms_pir1',
      params: { credit_sat: 10, gas_per_credit: 72_000, base_gas_per_frame: 20, egress_gas_per_mb: 1_000 },
      databases: { '0': { onion_register_keys: 200, onion_index_query: 197_506, onion_chunk_query: 403_260, onion_sibling_query: 21_000, tree_tops: 5 } },
    },
  };
  const bestEffort = { mode: 'best-effort', free_concurrency: 1 } as const;
  const keys = onionFrame(0x50, [1, 0, 0, 0, 7, 1, 0, 0, 0, 8]);

  function wallet(credits: number) {
    const calls: number[] = [];
    let left = credits;
    const provider = (asked: number) => {
      calls.push(asked);
      const give = Math.min(asked, left, 255);
      if (give === 0) return null;
      left -= give;
      return { kind: CREDIT_PRESENT_KIND_CASHU, payload: new Uint8Array([give]), credits: give };
    };
    return { calls, provider };
  }

  it('sends an uncovered frame unpaid and takes the free answer', async () => {
    const card = serverGasCardFromInfo(info)!;
    const server = fakeOnionServer(card);
    server.state.bestEffortBusy = false;
    const w = wallet(10);
    const channel = new CreditedChannel(card, w.provider, server.exchange, bestEffort, true);
    expect((await channel.roundtrip(keys))[4]).toBe(0x50);
    expect(w.calls).toEqual([]);
    expect(server.state.sent).toEqual([0x50]);
  });

  it('pays for priority when the free lane is busy and the wallet can', async () => {
    const card = serverGasCardFromInfo(info)!;
    const server = fakeOnionServer(card);
    server.state.bestEffortBusy = true;
    const w = wallet(10);
    const channel = new CreditedChannel(card, w.provider, server.exchange, bestEffort, true);
    expect((await channel.roundtrip(keys))[4]).toBe(0x50);
    expect(w.calls).toEqual([1]);
    expect(server.state.sent).toEqual([0x50, 0x12, 0x50]);
    expect(channel.meter.balance).toBe(server.state.balance);
  });

  it('pays for a frame the mirror thought covered when the server lanes it and the lane is busy', async () => {
    const card = serverGasCardFromInfo(info)!;
    const server = fakeOnionServer(card);
    server.state.bestEffortBusy = true;
    const w = wallet(10);
    const channel = new CreditedChannel(card, w.provider, server.exchange, bestEffort, true);
    await channel.roundtrip(keys);
    // The mirror counts egress a little behind the server: the server's
    // balance has fallen just below the next frame's price (220 gas) while
    // the mirror still sees tens of thousands. Present once, pay, resend.
    server.state.balance = 219;
    expect((await channel.roundtrip(keys))[4]).toBe(0x50);
    expect(w.calls).toEqual([1, 1]);
    expect(server.state.sent).toEqual([0x50, 0x12, 0x50, 0x50, 0x12, 0x50]);
    expect(channel.meter.balance).toBe(server.state.balance);
  });

  it('hands the busy refusal back when the wallet is empty or nobody can pay', async () => {
    const card = serverGasCardFromInfo(info)!;
    for (const [credits, canPay] of [[0, true], [10, false]] as const) {
      const server = fakeOnionServer(card);
      server.state.bestEffortBusy = true;
      const w = wallet(credits);
      const channel = new CreditedChannel(card, w.provider, server.exchange, bestEffort, canPay);
      const response = await channel.roundtrip(keys);
      expect(response[4]).toBe(0xff);
      expect(server.state.sent).toEqual([0x50]);
      expect(w.calls.length).toBe(canPay ? 1 : 0);
    }
  });

  it('never funds a backend the server serves free', async () => {
    const card = serverGasCardFromInfo(info)!;
    const server = fakeOnionServer(card);
    server.state.bestEffortBusy = false;
    const w = wallet(10);
    const channel = new CreditedChannel(card, w.provider, server.exchange, { mode: 'free' }, true);
    expect((await channel.roundtrip(keys))[4]).toBe(0x50);
    expect(w.calls).toEqual([]);
  });
});
