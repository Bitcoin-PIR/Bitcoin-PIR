/**
 * Lightning → Cashu ecash: the rail `purchaseCredential` (credits.ts) buys
 * credentials with.
 *
 * `@cashu/cashu-ts` is imported on demand, so the free path never loads it.
 *
 * Flow (against a mint the issuer lists in `GET /v2/info`):
 *   1. `requestLightningQuote` — bolt11 invoice for `purchase.amount` `unit`.
 *   2. The user pays the invoice with any Lightning wallet.
 *   3. `waitForQuotePayment` — polls the mint until the quote is PAID.
 *   4. `mintTokenForQuote` — mints proofs and encodes a `cashuB…` token.
 */

import type { Wallet } from '@cashu/cashu-ts';

/** What a mint quote pays for: `amount` of `unit`, which buys `credits`. */
export interface MintPurchase {
  credits: number;
  amount: number;
  unit: string;
}

export type MintQuoteStatus = 'UNPAID' | 'PAID' | 'ISSUED';

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
  purchase: MintPurchase,
): Promise<LightningQuote> {
  const wallet = await openWallet(mintUrl, purchase.unit);
  const quote = await wallet.createMintQuoteBolt11(
    purchase.amount,
    `Bitcoin PIR: ${purchase.credits} query credits`,
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
  purchase: MintPurchase,
  quoteId: string,
): Promise<string> {
  const wallet = await openWallet(mintUrl, purchase.unit);
  const proofs = await wallet.mintProofsBolt11(purchase.amount, quoteId);
  const { getEncodedToken } = await loadCashu();
  return getEncodedToken({ mint: mintUrl, proofs, unit: purchase.unit });
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
