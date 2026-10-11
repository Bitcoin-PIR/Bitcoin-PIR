/**
 * Buying Cashu ecash into the wallet's own outputs (`cashu-wallet.ts`):
 * NUT-04 Lightning quotes at the mint, the mint's active `sat` keyset,
 * fresh blinded outputs, minting into them (NUT-09 restore when a mint
 * answer was lost), and unblinding blind signatures with the NUT-12 DLEQ
 * proof checked when present.
 *
 * `@cashu/cashu-ts` is imported on demand, so the free path never loads it.
 *
 * The mint's Lightning rail (`topUpFromMint`):
 *   1. `requestLightningQuote` — bolt11 invoice for `purchase.amount` `unit`.
 *   2. The user pays the invoice with any Lightning wallet.
 *   3. `waitForQuotePayment` — polls the mint until the quote is PAID.
 *   4. `mintProofsForQuote` — mints into outputs the wallet persisted first.
 */

import type { HasKeysetKeys, SerializedOutputData, Wallet } from '@cashu/cashu-ts';
import type { StoredProof } from './cashu-wallet.js';

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

/** A blind signature as the mint or the issuer returns it (NUT-00, NUT-12). */
export interface BlindSignatureJson {
  amount: number;
  id: string;
  C_: string;
  dleq?: { e: string; s: string };
}

type CashuModule = typeof import('@cashu/cashu-ts');

let cashuModule: Promise<CashuModule> | null = null;

/** Load cashu-ts once; the chunk is fetched only when the wallet is used. */
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

/** The mint's active `sat` keyset, or keyset `id`; cashu-ts checks the keys derive the id. */
export async function mintKeyset(mintUrl: string, id?: string): Promise<HasKeysetKeys> {
  const wallet = await openWallet(mintUrl, 'sat');
  if (id) await wallet.ensureOperableKeysets([id]);
  return wallet.getKeyset(id);
}

/** Fresh random outputs (a secret and a blinding factor each) for `denominations`, ready to persist. */
export async function createOutputs(keyset: HasKeysetKeys, denominations: number[]): Promise<SerializedOutputData[]> {
  const { OutputData } = await loadCashu();
  const total = denominations.reduce((sum, amount) => sum + amount, 0);
  return OutputData.createRandomData(total, keyset, denominations).map((output) => OutputData.serialize(output));
}

/** Mint the paid quote into the wallet's own `outputs`. */
export async function mintProofsForQuote(
  mintUrl: string,
  amount: number,
  quoteId: string,
  outputs: SerializedOutputData[],
): Promise<StoredProof[]> {
  const { OutputData } = await loadCashu();
  const wallet = await openWallet(mintUrl, 'sat');
  const proofs = await wallet.mintProofsBolt11(amount, quoteId, undefined, {
    type: 'custom',
    data: outputs.map((output) => OutputData.deserialize(output)),
  });
  return proofs.map((p) => ({ id: p.id, amount: p.amount.toNumber(), secret: p.secret, C: p.C }));
}

/** NUT-09: the signatures the mint already made on `outputs` (its mint answer never arrived), unblinded. */
export async function restoreProofs(mintUrl: string, outputs: SerializedOutputData[]): Promise<StoredProof[]> {
  const { Amount } = await loadCashu();
  const wallet = await openWallet(mintUrl, 'sat');
  const restored = await wallet.mint.restore({
    outputs: outputs.map((o) => ({ ...o.blindedMessage, amount: Amount.from(o.blindedMessage.amount) })),
  });
  const signed = new Map(restored.outputs.map((o, i) => [o.B_, restored.signatures[i]]));
  const signatures = outputs.map((o) => {
    const s = signed.get(o.blindedMessage.B_);
    if (!s) throw new Error('the mint has not signed these outputs: the quote was issued elsewhere');
    return { amount: s.amount.toNumber(), id: s.id, C_: s.C_, dleq: s.dleq };
  });
  return unblindSignatures(mintUrl, outputs, signatures);
}

/**
 * Unblind `signatures` (one per output, in order) with each output's
 * blinding factor and the keyset key for its amount, verifying the DLEQ
 * proof when present. Throws on any mismatch.
 */
export async function unblindSignatures(
  mintUrl: string,
  outputs: SerializedOutputData[],
  signatures: BlindSignatureJson[],
): Promise<StoredProof[]> {
  if (signatures.length !== outputs.length) {
    throw new Error(`expected ${outputs.length} blind signatures, got ${signatures.length}`);
  }
  const { Amount, OutputData } = await loadCashu();
  const keyset = await mintKeyset(mintUrl, outputs[0]?.blindedMessage.id);
  return outputs.map((output, i) => {
    const sig = signatures[i];
    if (String(sig.amount) !== output.blindedMessage.amount) throw new Error(`blind signature ${i} is for another amount`);
    const proof = OutputData.deserialize(output).toProof({ ...sig, amount: Amount.from(sig.amount) }, keyset);
    return { id: proof.id, amount: proof.amount.toNumber(), secret: proof.secret, C: proof.C };
  });
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
