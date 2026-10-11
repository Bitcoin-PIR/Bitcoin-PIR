/**
 * The browser's Cashu wallet (docs/CREDITS.md): ecash of the issuer's mint
 * (unit sat) in `localStorage`, spent as `REQ_CREDIT_PRESENT` kind 1, a
 * `cashuB…` token.
 *
 * - `CashuStore`: spendable proofs, presentations in flight (proofs handed
 *   to a server and not yet known spent) and the pending top-up, in one
 *   `localStorage` entry so every change is a single write.
 * - `planDenominations` / `selectProofs`: a top-up stocks credit-sized
 *   groups (10 sat = 8 + 2) so whole credits are paid exactly; selection is
 *   exact when the proofs allow it and overpays as little as possible
 *   otherwise (the server keeps the surplus as connection gas).
 * - `CashuWallet.present`: the synchronous credit provider; `reconcile`
 *   later asks the mint (NUT-07) which proofs in flight were spent.
 * - `topUpFromMint`: top-up through the mint's Lightning invoice (NUT-04).
 *   The other rail, x402 from the issuer, is `topUpX402` in `x402.ts`. Both
 *   persist the wallet's own blinded outputs before minting, so a reload
 *   resumes, and nobody else learns the secrets of the proofs.
 */

import type { SerializedOutputData } from '@cashu/cashu-ts';
import {
  checkQuoteStatus,
  createOutputs,
  loadCashu,
  mintKeyset,
  mintProofsForQuote,
  openWallet,
  requestLightningQuote,
  restoreProofs,
  waitForQuotePayment,
} from './cashu-purchase.js';
import { CREDIT_PRESENT_KIND_CASHU, IssuerError, type IssuerClient, type Presentation } from './credits.js';

export const CASHU_WALLET_STORAGE_KEY = 'bitcoinpir.cashu-wallet.v1';
/** Presentations younger than this are left alone: the server may still be redeeming them. */
export const IN_FLIGHT_GRACE_SECS = 120;
/** Credits a top-up stocks as credit-sized groups of proofs (8 + 2 sat at 10 sat per credit). */
export const STOCK_CREDITS = 32;

/** One proof (NUT-00), amount in sat. Kept without its DLEQ proof, whose blinding factor would link it to its issuance. */
export interface StoredProof {
  id: string;
  amount: number;
  secret: string;
  C: string;
}

/** Proofs handed to a server at `at` (unix seconds), not yet known spent. */
export interface InFlightPresentation {
  at: number;
  proofs: StoredProof[];
}

/** A top-up through the mint's Lightning invoice; `outputs` are set once the invoice is paid, before minting. */
export interface PendingMintTopUp {
  rail: 'mint';
  mintUrl: string;
  sat: number;
  quoteId: string;
  invoice: string;
  expiry: number | null;
  outputs: SerializedOutputData[] | null;
  createdAt: number;
}

/** A top-up over x402 (`x402.ts`): the exact request body and its outputs, persisted before the invoice is requested. */
export interface PendingX402TopUp {
  rail: 'x402';
  issuerUrl: string;
  mintUrl: string;
  sat: number;
  keysetId: string;
  body: string;
  outputs: SerializedOutputData[];
  resource: unknown;
  accepted: unknown;
  paymentHash: string | null;
  invoice: string | null;
  expiresAt: number | null;
  preimage: string | null;
  createdAt: number;
}

export type PendingTopUp = PendingMintTopUp | PendingX402TopUp;

export interface CashuWalletState {
  version: 1;
  /** The mint the proofs belong to; empty until the first top-up. */
  mintUrl: string;
  /** Sat per credit at the issuer, recorded at each top-up; 0 until known. */
  creditSat: number;
  proofs: StoredProof[];
  inFlight: InFlightPresentation[];
  pending: PendingTopUp | null;
}

export interface PurchaseHooks {
  onInvoice?: (invoice: string, expiry: number | null) => void;
  onStatus?: (status: 'quoting' | 'awaiting-payment' | 'minting' | 'stored') => void;
  signal?: AbortSignal;
}

/** The part of `localStorage` the store uses. */
export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

function defaultStorage(): StorageLike | null {
  try {
    return (globalThis as { localStorage?: StorageLike }).localStorage ?? null;
  } catch {
    return null;
  }
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function sumSat(proofs: StoredProof[]): number {
  return proofs.reduce((sum, proof) => sum + proof.amount, 0);
}

// ─── Store ──────────────────────────────────────────────────────────────────

export class CashuStore {
  /** The wallet when storage refused a write: kept for this page rather than lost. */
  private memory: CashuWalletState | null = null;

  constructor(
    private readonly storage: StorageLike | null = defaultStorage(),
    private readonly key = CASHU_WALLET_STORAGE_KEY,
  ) {}

  /** The stored wallet, empty when nothing readable is stored. */
  state(): CashuWalletState {
    if (this.memory) return structuredClone(this.memory);
    try {
      const raw = JSON.parse(this.storage?.getItem(this.key) ?? 'null');
      if (raw?.version === 1 && Array.isArray(raw.proofs) && Array.isArray(raw.inFlight)) return raw;
    } catch {
      /* unreadable: an empty wallet */
    }
    return { version: 1, mintUrl: '', creditSat: 0, proofs: [], inFlight: [], pending: null };
  }

  /** Apply `change` to the current state and write it back in one step. */
  update(change: (state: CashuWalletState) => void): CashuWalletState {
    const state = this.state();
    change(state);
    try {
      if (!this.storage) throw new Error('no storage');
      this.storage.setItem(this.key, JSON.stringify(state));
      this.memory = null;
    } catch {
      this.memory = state;
    }
    return state;
  }

  /** Spendable sat. */
  balance(): number {
    return sumSat(this.state().proofs);
  }

  pending(): PendingTopUp | null {
    return this.state().pending;
  }

  setPending(pending: PendingTopUp | null): void {
    this.update((state) => {
      state.pending = pending;
    });
  }

  /** Add minted proofs (skipping any already held) and clear the pending top-up, in one write. */
  receive(proofs: StoredProof[]): void {
    this.update((state) => {
      const held = new Set([...state.proofs, ...state.inFlight.flatMap((f) => f.proofs)].map((p) => p.secret));
      state.proofs.push(...proofs.filter((p) => !held.has(p.secret)));
      state.pending = null;
    });
  }
}

// ─── Denominations and selection ────────────────────────────────────────────

/** Powers of two summing to `n`, largest first. */
function binarySplit(n: number): number[] {
  const out: number[] = [];
  let bit = 1;
  while (bit * 2 <= n) bit *= 2;
  for (; n > 0; bit /= 2) {
    if (n >= bit) {
      out.push(bit);
      n -= bit;
    }
  }
  return out;
}

/**
 * Denominations for a top-up of `sat`: up to `STOCK_CREDITS` credit-sized
 * groups (the binary split of `creditSat`, 8 + 2 for 10 sat) so whole
 * credits can be paid exactly, then a binary spread of the rest.
 */
export function planDenominations(sat: number, creditSat: number): number[] {
  const credits = Math.min(Math.floor(sat / creditSat), STOCK_CREDITS);
  const credit = binarySplit(creditSat);
  return [...Array.from({ length: credits }, () => credit).flat(), ...binarySplit(sat - credits * creditSat)];
}

/**
 * Proofs worth exactly `sat` when some subset is, else the smallest
 * overpay; `null` when the balance falls short. Taking the largest proof
 * that fits finds an exact subset whenever one exists, since amounts are
 * powers of two.
 */
export function selectProofs(proofs: StoredProof[], sat: number): StoredProof[] | null {
  const sorted = [...proofs].sort((a, b) => b.amount - a.amount);
  const total = sumSat(sorted);
  for (let target = sat; target <= total; target++) {
    const picked: StoredProof[] = [];
    let left = target;
    for (const proof of sorted) {
      if (proof.amount <= left) {
        picked.push(proof);
        left -= proof.amount;
      }
    }
    if (left === 0) return picked;
  }
  return null;
}

// ─── Presenting ─────────────────────────────────────────────────────────────

/** Encodes a `cashuB…` token (cashu-ts `getEncodedToken`). */
export type TokenEncoder = (token: { mint: string; unit: string; proofs: StoredProof[] }) => string;

export class CashuWallet {
  constructor(
    readonly store: CashuStore,
    private readonly encodeToken: TokenEncoder,
    private readonly now: () => number = nowSeconds,
  ) {}

  /**
   * The credit provider: a kind-1 presentation worth at least `credits`
   * credits, or `null` when the balance falls short. The proofs move to
   * "in flight" before the token is returned.
   */
  present(credits: number): Presentation | null {
    const state = this.store.state();
    const proofs = state.mintUrl && state.creditSat ? selectProofs(state.proofs, credits * state.creditSat) : null;
    if (!proofs?.length) return null;
    const token = this.encodeToken({ mint: state.mintUrl, unit: 'sat', proofs });
    const presented = new Set(proofs.map((p) => p.secret));
    this.store.update((s) => {
      s.proofs = s.proofs.filter((p) => !presented.has(p.secret));
      s.inFlight.push({ at: this.now(), proofs });
    });
    return {
      kind: CREDIT_PRESENT_KIND_CASHU,
      payload: new TextEncoder().encode(token),
      credits: Math.floor(sumSat(proofs) / state.creditSat),
    };
  }

  /**
   * Ask the mint (NUT-07) about presentations at least `graceSecs` old:
   * unspent proofs go back to the spendable store (no server redeemed
   * them), spent ones are dropped, pending ones stay in flight.
   */
  async reconcile(graceSecs = IN_FLIGHT_GRACE_SECS): Promise<{ returned: number; spent: number }> {
    const state = this.store.state();
    const due = state.inFlight.filter((f) => this.now() - f.at >= graceSecs).flatMap((f) => f.proofs);
    if (due.length === 0) return { returned: 0, spent: 0 };
    const wallet = await openWallet(state.mintUrl, 'sat');
    const states = (await wallet.checkProofsStates(due)).map((s) => s.state);
    const unspent = due.filter((_, i) => states[i] === 'UNSPENT');
    const spent = due.filter((_, i) => states[i] === 'SPENT');
    const settled = new Set([...unspent, ...spent].map((p) => p.secret));
    this.store.update((s) => {
      s.inFlight = s.inFlight
        .map((f) => ({ at: f.at, proofs: f.proofs.filter((p) => !settled.has(p.secret)) }))
        .filter((f) => f.proofs.length > 0);
      const held = new Set(s.proofs.map((p) => p.secret));
      s.proofs.push(...unspent.filter((p) => !held.has(p.secret)));
    });
    return { returned: sumSat(unspent), spent: sumSat(spent) };
  }
}

/** A wallet over `store` with cashu-ts loaded, so `present` encodes tokens synchronously. */
export async function openCashuWallet(store: CashuStore, now?: () => number): Promise<CashuWallet> {
  const { getEncodedToken, normalizeProofAmounts } = await loadCashu();
  return new CashuWallet(
    store,
    (token) => getEncodedToken({ ...token, proofs: normalizeProofAmounts(token.proofs) }, { removeDleq: true }),
    now,
  );
}

// ─── Top-up through the mint's Lightning invoice ────────────────────────────

/** The issuer's mint for a new top-up; records it and the credit price in the wallet. */
export async function issuerMint(issuer: IssuerClient, store: CashuStore): Promise<{ mintUrl: string; creditSat: number }> {
  const info = await issuer.info();
  const mintUrl = info.mints[0];
  if (!mintUrl) throw new IssuerError('the issuer lists no mint');
  const state = store.update((s) => {
    if (s.proofs.length === 0 && s.inFlight.length === 0) s.mintUrl = mintUrl;
    s.creditSat = info.gas.creditSat;
  });
  if (state.mintUrl !== mintUrl) throw new IssuerError(`the wallet holds ecash of ${state.mintUrl}; the issuer now takes ${mintUrl}`);
  return { mintUrl, creditSat: info.gas.creditSat };
}

/**
 * Top up `sat` through the mint's Lightning invoice: quote, wait for the
 * payment, persist fresh outputs, mint into them, store the proofs.
 * Resumable: a pending top-up continues from its last step, and outputs
 * the mint signed while its answer was lost are recovered (NUT-09).
 * Returns the sat added.
 */
export async function topUpFromMint(
  issuer: IssuerClient,
  store: CashuStore,
  sat: number,
  hooks: PurchaseHooks = {},
  now: () => number = nowSeconds,
): Promise<number> {
  let pending = store.pending();
  if (pending && pending.rail !== 'mint') throw new IssuerError('finish or cancel the pending top-up first');
  if (!pending) {
    const { mintUrl, creditSat } = await issuerMint(issuer, store);
    hooks.onStatus?.('quoting');
    const quote = await requestLightningQuote(mintUrl, { credits: Math.floor(sat / creditSat), amount: sat, unit: 'sat' });
    pending = { rail: 'mint', mintUrl, sat, quoteId: quote.quoteId, invoice: quote.invoice, expiry: quote.expiry, outputs: null, createdAt: now() };
    store.setPending(pending);
  }
  let outputs = pending.outputs;
  if (!outputs) {
    hooks.onInvoice?.(pending.invoice, pending.expiry);
    hooks.onStatus?.('awaiting-payment');
    await waitForQuotePayment(pending.mintUrl, 'sat', pending.quoteId, {
      signal: hooks.signal,
      timeoutMs: pending.expiry === null ? undefined : Math.max(0, pending.expiry - now()) * 1000 + 60_000,
    });
    outputs = await createOutputs(await mintKeyset(pending.mintUrl), planDenominations(pending.sat, store.state().creditSat));
    store.setPending({ ...pending, outputs });
  }
  hooks.onStatus?.('minting');
  const issued = (await checkQuoteStatus(pending.mintUrl, 'sat', pending.quoteId)) === 'ISSUED';
  const proofs = issued
    ? await restoreProofs(pending.mintUrl, outputs)
    : await mintProofsForQuote(pending.mintUrl, pending.sat, pending.quoteId, outputs);
  store.receive(proofs);
  hooks.onStatus?.('stored');
  return sumSat(proofs);
}
