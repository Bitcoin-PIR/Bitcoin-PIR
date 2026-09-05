/**
 * Lightning → Cashu ecash → session grant.
 *
 * `@cashu/cashu-ts` is imported on demand, so the free path never loads it.
 * A purchase is persisted step by step (`PendingPurchaseStore`): a reload
 * after paying the invoice, or a cashier outage after minting, loses nothing
 * — the page resumes from the stored quote or token.
 *
 * Flow (all against a mint the cashier lists in `GET /v1/info`):
 *   1. `requestLightningQuote` — bolt11 invoice for `offer.amount` `unit`.
 *   2. The user pays the invoice with any Lightning wallet.
 *   3. `waitForQuotePayment` — polls the mint until the quote is PAID.
 *   4. `mintTokenForQuote` — mints proofs and encodes a `cashuB…` token.
 *   5. `CashierClient.redeem(offer, token)` — the cashier swaps the token
 *      at the mint and issues the grant.
 */

import type { Wallet } from '@cashu/cashu-ts';
import type { CashierOffer, StorageLike } from './session-grant.js';

export const PENDING_PURCHASE_STORAGE_KEY = 'bitcoinpir.session-grant.pending-purchase.v1';

export type MintQuoteStatus = 'UNPAID' | 'PAID' | 'ISSUED';

/** One in-flight purchase, persisted until the grant is stored. */
export interface PendingPurchase {
  version: 1;
  cashierUrl: string;
  mintUrl: string;
  offer: CashierOffer;
  quoteId: string;
  invoice: string;
  /** Mint-side invoice expiry (Unix seconds) or `null` when unknown. */
  quoteExpiry: number | null;
  /** Set once proofs were minted; the token is then the only thing to redeem. */
  token: string | null;
  createdAt: number;
}

export interface LightningQuote {
  quoteId: string;
  invoice: string;
  expiry: number | null;
}

export interface WaitForPaymentOptions {
  signal?: AbortSignal;
  pollIntervalMs?: number;
  timeoutMs?: number;
  onStatus?: (status: MintQuoteStatus) => void;
}

type CashuModule = typeof import('@cashu/cashu-ts');

let cashuModule: Promise<CashuModule> | null = null;

/** Load cashu-ts once; the chunk is fetched only when a purchase starts. */
export function loadCashu(): Promise<CashuModule> {
  cashuModule ??= import('@cashu/cashu-ts');
  return cashuModule;
}

const wallets = new Map<string, Promise<Wallet>>();

/** One loaded wallet per mint + unit for the page lifetime. */
export function openWallet(mintUrl: string, unit: string): Promise<Wallet> {
  const key = `${unit}@${mintUrl}`;
  let pending = wallets.get(key);
  if (!pending) {
    pending = (async () => {
      const { Wallet } = await loadCashu();
      const wallet = new Wallet(mintUrl, { unit });
      await wallet.loadMint();
      return wallet;
    })();
    pending.catch(() => wallets.delete(key));
    wallets.set(key, pending);
  }
  return pending;
}

export async function requestLightningQuote(
  mintUrl: string,
  offer: CashierOffer,
): Promise<LightningQuote> {
  const wallet = await openWallet(mintUrl, offer.unit);
  const quote = await wallet.createMintQuoteBolt11(
    offer.amount,
    `Bitcoin PIR: ${offer.credits} query credits`,
  );
  if (!quote.quote || !quote.request) throw new Error('mint returned an incomplete quote');
  return { quoteId: quote.quote, invoice: quote.request, expiry: quote.expiry ?? null };
}

export async function checkQuoteStatus(
  mintUrl: string,
  unit: string,
  quoteId: string,
): Promise<MintQuoteStatus> {
  const wallet = await openWallet(mintUrl, unit);
  const status = await wallet.checkMintQuoteBolt11(quoteId);
  return status.state;
}

/** Poll the mint until the invoice is paid (or already issued). */
export async function waitForQuotePayment(
  mintUrl: string,
  unit: string,
  quoteId: string,
  options: WaitForPaymentOptions = {},
): Promise<MintQuoteStatus> {
  const interval = options.pollIntervalMs ?? 2_000;
  const deadline = Date.now() + (options.timeoutMs ?? 15 * 60_000);
  for (;;) {
    if (options.signal?.aborted) throw new Error('payment wait cancelled');
    const status = await checkQuoteStatus(mintUrl, unit, quoteId);
    options.onStatus?.(status);
    if (status === 'PAID' || status === 'ISSUED') return status;
    if (Date.now() >= deadline) throw new Error('timed out waiting for the invoice to be paid');
    await sleep(interval, options.signal);
  }
}

/** Mint the paid quote into proofs and encode them as one Cashu token. */
export async function mintTokenForQuote(
  mintUrl: string,
  offer: CashierOffer,
  quoteId: string,
): Promise<string> {
  const wallet = await openWallet(mintUrl, offer.unit);
  const proofs = await wallet.mintProofsBolt11(offer.amount, quoteId);
  const { getEncodedToken } = await loadCashu();
  return getEncodedToken({ mint: mintUrl, proofs, unit: offer.unit });
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    function onAbort() {
      clearTimeout(timer);
      reject(new Error('payment wait cancelled'));
    }
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

// ─── Pending purchase persistence ───────────────────────────────────────────

function defaultStorage(): StorageLike | null {
  try {
    return (globalThis as { localStorage?: StorageLike }).localStorage ?? null;
  } catch {
    return null;
  }
}

export class PendingPurchaseStore {
  private readonly storage: StorageLike | null;
  private readonly key: string;

  constructor(storage: StorageLike | null = defaultStorage(), key = PENDING_PURCHASE_STORAGE_KEY) {
    this.storage = storage;
    this.key = key;
  }

  load(): PendingPurchase | null {
    if (!this.storage) return null;
    let raw: string | null;
    try {
      raw = this.storage.getItem(this.key);
    } catch {
      return null;
    }
    if (!raw) return null;
    try {
      const pending = readPendingPurchase(JSON.parse(raw));
      if (!pending) this.clear();
      return pending;
    } catch {
      this.clear();
      return null;
    }
  }

  save(pending: PendingPurchase): void {
    if (!this.storage) return;
    try {
      this.storage.setItem(this.key, JSON.stringify(pending));
    } catch {
      // Storage unavailable: the purchase still completes in memory.
    }
  }

  clear(): void {
    if (!this.storage) return;
    try {
      this.storage.removeItem(this.key);
    } catch {
      // ignore
    }
  }
}

function readPendingPurchase(value: unknown): PendingPurchase | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (record.version !== 1) return null;
  const offer = record.offer;
  if (
    typeof record.cashierUrl !== 'string'
    || typeof record.mintUrl !== 'string'
    || typeof record.quoteId !== 'string'
    || typeof record.invoice !== 'string'
    || typeof offer !== 'object' || offer === null
    || (record.quoteExpiry !== null && typeof record.quoteExpiry !== 'number')
    || (record.token !== null && typeof record.token !== 'string')
    || typeof record.createdAt !== 'number'
  ) {
    return null;
  }
  const { credits, amount, unit } = offer as Record<string, unknown>;
  if (typeof credits !== 'number' || typeof amount !== 'number' || typeof unit !== 'string') return null;
  return {
    version: 1,
    cashierUrl: record.cashierUrl,
    mintUrl: record.mintUrl,
    offer: { credits, amount, unit },
    quoteId: record.quoteId,
    invoice: record.invoice,
    quoteExpiry: record.quoteExpiry as number | null,
    token: record.token as string | null,
    createdAt: record.createdAt,
  };
}
