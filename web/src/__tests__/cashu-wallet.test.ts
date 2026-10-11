import { getDecodedToken } from '@cashu/cashu-ts';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CASHU_WALLET_STORAGE_KEY,
  CashuStore,
  IN_FLIGHT_GRACE_SECS,
  openCashuWallet,
  planDenominations,
  selectProofs,
  sumSat,
  topUpFromMint,
  type StoredProof,
} from '../cashu-wallet.js';
import { CREDIT_PRESENT_KIND_CASHU, IssuerClient } from '../credits.js';
import { fakeMint, json, routeFetch } from './fake-mint.js';

const NOW = 1_800_000_000;
const ISSUER = 'https://issuer.example';
const KEYSET_ID = '00ad268c4d1f5826';

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

function proof(amount: number, n: number): StoredProof {
  return { id: KEYSET_ID, amount, secret: `secret-${n}`, C: `02${n.toString(16).padStart(64, '0')}` };
}

/** A wallet of the mint at `mintUrl` holding `amounts`, priced at 10 sat per credit. */
function storeWith(mintUrl: string, amounts: number[]): CashuStore {
  const store = new CashuStore(memoryStorage());
  store.update((s) => {
    s.mintUrl = mintUrl;
    s.creditSat = 10;
  });
  store.receive(amounts.map(proof));
  return store;
}

/** An issuer that only answers `GET /v2/info`, naming `mintUrl`. */
function infoIssuer(mintUrl: string): IssuerClient {
  const info = {
    service: 'bitcoinpir-issuer',
    version: 2,
    credit_sat: 10,
    gas_per_credit: 72_000,
    base_gas_per_frame: 20,
    egress_gas_per_mb: 1_000,
    mints: [mintUrl],
    rate_card: [],
  };
  return new IssuerClient(ISSUER, routeFetch({ [ISSUER]: async () => json(200, info) }));
}

describe('cashu store', () => {
  it('persists in one entry, survives a reload, and keeps working in memory when storage fails', () => {
    const storage = memoryStorage();
    const store = new CashuStore(storage);
    expect(store.state()).toEqual({ version: 1, mintUrl: '', creditSat: 0, proofs: [], inFlight: [], pending: null });
    store.receive([proof(8, 1), proof(2, 2)]);
    store.receive([proof(8, 1)]);
    expect(new CashuStore(storage).balance()).toBe(10);
    expect(JSON.parse(storage.getItem(CASHU_WALLET_STORAGE_KEY)!).proofs).toHaveLength(2);
    storage.setItem(CASHU_WALLET_STORAGE_KEY, '{not json');
    expect(new CashuStore(storage).balance()).toBe(0);
    const refusing = {
      getItem: () => null,
      setItem: () => {
        throw new Error('quota exceeded');
      },
    };
    const volatile = new CashuStore(refusing);
    volatile.receive([proof(4, 3)]);
    expect(volatile.balance()).toBe(4);
  });
});

describe('denominations and selection', () => {
  it('stocks credit-sized 8 + 2 groups and spreads the rest in powers of two', () => {
    expect(planDenominations(25, 10)).toEqual([8, 2, 8, 2, 4, 1]);
    const plan = planDenominations(1000, 10);
    expect(plan.slice(0, 64)).toEqual(Array.from({ length: 32 }, () => [8, 2]).flat());
    expect(plan.slice(64)).toEqual([512, 128, 32, 8]);
    expect(plan.reduce((a, b) => a + b, 0)).toBe(1000);
    expect(planDenominations(40, 20)).toEqual([16, 4, 16, 4]);
  });

  it('pays whole credits exactly from the 8 + 2 stock and overpays as little as possible otherwise', () => {
    const stock = planDenominations(30, 10).map(proof);
    expect(selectProofs(stock, 10)!.map((p) => p.amount)).toEqual([8, 2]);
    expect(selectProofs(stock, 20)!.map((p) => p.amount)).toEqual([8, 8, 2, 2]);
    expect(selectProofs(stock, 30)!.map((p) => p.amount)).toEqual([8, 8, 8, 2, 2, 2]);
    expect(selectProofs(stock, 40)).toBeNull();
    expect(selectProofs([proof(32, 1), proof(16, 2)], 10)!.map((p) => p.amount)).toEqual([16]);
    expect(selectProofs([proof(4, 1), proof(4, 2), proof(4, 3)], 10)!.map((p) => p.amount)).toEqual([4, 4, 4]);
  });
});

describe('presenting (kind 1)', () => {
  it('hands over a cashuB token for the selected proofs and moves them in flight first', async () => {
    const mintUrl = 'https://mint.example';
    const store = storeWith(mintUrl, [8, 2, 8, 2, 8, 2]);
    const wallet = await openCashuWallet(store, () => NOW);
    const presentation = wallet.present(2)!;
    expect(presentation.kind).toBe(CREDIT_PRESENT_KIND_CASHU);
    expect(presentation.credits).toBe(2);
    const text = new TextDecoder().decode(presentation.payload);
    expect(text.startsWith('cashuB')).toBe(true);
    const token = getDecodedToken(text, [KEYSET_ID]);
    expect(token.mint).toBe(mintUrl);
    expect(token.unit).toBe('sat');
    expect(token.proofs.map((p) => p.amount.toNumber())).toEqual([8, 8, 2, 2]);
    expect(token.proofs.every((p) => p.dleq === undefined)).toBe(true);
    const state = store.state();
    expect(sumSat(state.proofs)).toBe(10);
    expect(state.inFlight).toHaveLength(1);
    expect(state.inFlight[0].at).toBe(NOW);
    expect(state.inFlight[0].proofs.map((p) => p.secret).sort()).toEqual(token.proofs.map((p) => p.secret).sort());
    // 10 sat cannot pay two credits: nothing moves.
    expect(wallet.present(2)).toBeNull();
    expect(store.balance()).toBe(10);
    // With no exact subset the smallest overpay goes, and counts as what it is worth.
    store.receive([proof(32, 7)]);
    const overpaid = wallet.present(2)!;
    expect(overpaid.credits).toBe(3);
    expect(store.balance()).toBe(10);
  });

  it('returns unredeemed proofs from flight and drops spent ones, after the grace period', async () => {
    const mint = fakeMint('https://mint-reconcile.example');
    vi.stubGlobal('fetch', routeFetch({ [mint.url]: mint.handle }));
    const store = storeWith(mint.url, [8, 2, 8, 2]);
    let now = NOW;
    const wallet = await openCashuWallet(store, () => now);
    wallet.present(1);
    now += 60;
    wallet.present(1);
    // The server redeemed the first presentation: the mint reports it spent.
    for (const p of store.state().inFlight[0].proofs) mint.spend(p.secret);
    now = NOW + IN_FLIGHT_GRACE_SECS;
    expect(await wallet.reconcile()).toEqual({ returned: 0, spent: 10 });
    expect(store.state().inFlight.map((f) => f.at)).toEqual([NOW + 60]);
    // The second was never redeemed: it returns to the wallet.
    now += 60;
    expect(await wallet.reconcile()).toEqual({ returned: 10, spent: 0 });
    expect(store.state().inFlight).toEqual([]);
    expect(store.balance()).toBe(10);
  });
});

describe('top-up through the mint invoice', () => {
  it('quotes, resumes after a reload, and mints into the planned denominations', async () => {
    const mint = fakeMint('https://mint-topup.example');
    vi.stubGlobal('fetch', routeFetch({ [mint.url]: mint.handle }));
    const issuer = infoIssuer(mint.url);
    const storage = memoryStorage();
    const controller = new AbortController();
    const statuses: string[] = [];
    // The user leaves before paying.
    await expect(
      topUpFromMint(issuer, new CashuStore(storage), 30, {
        onStatus: (s) => statuses.push(s),
        onInvoice: () => controller.abort(),
        signal: controller.signal,
      }, () => NOW),
    ).rejects.toThrow(/cancelled/);
    const pending = new CashuStore(storage).pending()!;
    expect(pending).toMatchObject({ rail: 'mint', mintUrl: mint.url, sat: 30, outputs: null });
    // Paid from a phone; the reloaded page resumes the stored quote.
    mint.pay(pending.invoice!);
    const store = new CashuStore(storage);
    expect(await topUpFromMint(issuer, store, 30, { onStatus: (s) => statuses.push(s) }, () => NOW)).toBe(30);
    expect(store.state().proofs.map((p) => p.amount)).toEqual([8, 2, 8, 2, 8, 2]);
    expect(store.state().creditSat).toBe(10);
    expect(store.pending()).toBeNull();
    expect(statuses).toEqual(['quoting', 'awaiting-payment', 'awaiting-payment', 'minting', 'stored']);
    expect(mint.calls.filter((c) => c === '/v1/mint/quote/bolt11')).toHaveLength(1);
  });

  it('recovers outputs the mint signed when its answer was lost (NUT-09)', async () => {
    const mint = fakeMint('https://mint-restore.example');
    vi.stubGlobal('fetch', routeFetch({ [mint.url]: mint.handle }));
    const issuer = infoIssuer(mint.url);
    const store = new CashuStore(memoryStorage());
    mint.state.dropNextMintAnswer = true;
    await expect(topUpFromMint(issuer, store, 12, { onInvoice: (invoice) => mint.pay(invoice) }, () => NOW)).rejects.toThrow();
    expect(store.pending()).toMatchObject({ rail: 'mint', outputs: expect.any(Array) });
    expect(await topUpFromMint(issuer, store, 12, {}, () => NOW)).toBe(12);
    expect(store.state().proofs.map((p) => p.amount)).toEqual([8, 2, 2]);
    expect(mint.calls.filter((c) => c === '/v1/mint/bolt11')).toHaveLength(1);
    expect(mint.calls.filter((c) => c === '/v1/restore')).toHaveLength(1);
  });
});
