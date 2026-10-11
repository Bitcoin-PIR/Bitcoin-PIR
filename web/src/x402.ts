/**
 * x402 `exact` on Lightning (`lnbtc`) as the issuer's way to sell ecash:
 * x402-foundation/x402 `specs/schemes/exact/scheme_exact_lnbtc.md` and the
 * HTTP transport (`PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` /
 * `PAYMENT-RESPONSE`). The issuer's contract is "Issuer API" in
 * `docs/CREDITS.md`.
 *
 * Flow: `POST /v2/x402/ecash` with `{ sat, outputs }`, blinded outputs for
 * the mint's active `sat` keyset → `402` with a fresh invoice bound to that
 * exact request → the user pays it from any wallet (WebLN pays it in place
 * when present) → the page learns the preimage (WebLN, or
 * `GET /v2/x402/invoices/{payment_hash}`) → the byte-identical request is
 * repeated with `PAYMENT-SIGNATURE` → the issuer swaps its own proofs into
 * exactly those outputs at the mint and returns the blind signatures, which
 * the wallet unblinds (the issuer never sees the proofs).
 *
 * Before paying, the client performs the scheme's mandatory checks: the
 * requirement's terms, the request binding it recomputes itself, and the
 * decoded invoice (amount, expiry, payee, description hash).
 */

import { checkQuoteStatus, createOutputs, mintKeyset, unblindSignatures, type BlindSignatureJson } from './cashu-purchase.js';
import { issuerMint, planDenominations, sumSat, type CashuStore, type PurchaseHooks } from './cashu-wallet.js';
import { bytesToHex, hexToBytes, IssuerError, type IssuerClient } from './credits.js';

export const X402_VERSION = 2;
export const X402_NETWORK_MAINNET = 'lnbtc:000000000019d6689c085ae165831e93';
export const X402_DOMAIN_HTTP1 = 'x402:exact:lnbtc:bolt11:http:1';
export const ECASH_PATH = '/v2/x402/ecash';
/** Tolerated clock difference for the invoice creation time (spec default). */
export const CLOCK_SKEW_SECS = 60;

export interface PaymentRequirements {
  scheme: string;
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra: Record<string, unknown>;
}

export interface PaymentRequired {
  x402Version: number;
  error?: string;
  resource: { url: string } & Record<string, unknown>;
  accepts: PaymentRequirements[];
}

export interface BoundHeader {
  name: string;
  value: string | null;
}

export interface ValidatedChallenge {
  resource: PaymentRequired['resource'];
  accepted: PaymentRequirements;
  invoice: string;
  paymentHash: string;
  expiresAt: number;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function isLowerHex(s: string, len: number): boolean {
  return s.length === len && /^[0-9a-f]*$/.test(s);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle) {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);
    return bytesToHex(new Uint8Array(await subtle.digest('SHA-256', copy)));
  }
  const { sha256 } = await import('@noble/hashes/sha2.js');
  return bytesToHex(sha256(bytes));
}

/** JCS (RFC 8785) for the binding object: only strings, arrays, and objects with string members. */
export function jcs(value: unknown): string {
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (isRecord(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(',')}}`;
  }
  throw new Error('jcs: unsupported value in the binding object');
}

/**
 * The `http:1` binding: description bytes (JCS of the binding object) and
 * their SHA-256, the request hash.
 */
export async function http1Binding(
  method: string,
  url: string,
  body: Uint8Array,
  headers: BoundHeader[],
): Promise<{ description: string; requestHashHex: string }> {
  const encoder = new TextEncoder();
  const boundHeaders = [];
  for (const h of headers) {
    const valueHash =
      h.value === null
        ? await sha256Hex(Uint8Array.of(0x00))
        : await sha256Hex(concat(Uint8Array.of(0x01), encoder.encode(h.value)));
    boundHeaders.push({ name: h.name, valueHash });
  }
  const binding = {
    domain: X402_DOMAIN_HTTP1,
    method,
    url,
    bodyHash: await sha256Hex(body),
    headers: boundHeaders,
  };
  const description = jcs(binding);
  return { description, requestHashHex: await sha256Hex(encoder.encode(description)) };
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Validates `requestBindingParams` for `http:1` and returns the bound header names. */
export function http1HeaderNames(params: unknown): string[] {
  if (!isRecord(params) || Object.keys(params).length !== 1 || !Array.isArray(params.headers)) {
    throw new IssuerError('x402: requestBindingParams must be exactly { headers: [...] }');
  }
  const names: string[] = [];
  for (const raw of params.headers) {
    if (typeof raw !== 'string' || raw === '' || raw === 'payment-signature' || !/^[a-z0-9._-]+$/.test(raw)) {
      throw new IssuerError('x402: malformed bound header name');
    }
    if (names.length && raw <= names[names.length - 1]) throw new IssuerError('x402: bound headers must ascend without duplicates');
    names.push(raw);
  }
  return names;
}

export function parsePaymentRequired(raw: unknown): PaymentRequired {
  if (!isRecord(raw) || raw.x402Version !== X402_VERSION) throw new IssuerError('x402: unsupported PaymentRequired');
  if (!isRecord(raw.resource) || typeof raw.resource.url !== 'string') throw new IssuerError('x402: resource.url missing');
  if (!Array.isArray(raw.accepts)) throw new IssuerError('x402: accepts missing');
  const accepts: PaymentRequirements[] = [];
  for (const a of raw.accepts) {
    if (
      !isRecord(a) ||
      typeof a.scheme !== 'string' ||
      typeof a.network !== 'string' ||
      typeof a.amount !== 'string' ||
      typeof a.asset !== 'string' ||
      typeof a.payTo !== 'string' ||
      typeof a.maxTimeoutSeconds !== 'number'
    ) {
      throw new IssuerError('x402: malformed payment requirement');
    }
    accepts.push({
      scheme: a.scheme,
      network: a.network,
      amount: a.amount,
      asset: a.asset,
      payTo: a.payTo,
      maxTimeoutSeconds: a.maxTimeoutSeconds,
      extra: isRecord(a.extra) ? a.extra : {},
    });
  }
  return {
    x402Version: X402_VERSION,
    error: typeof raw.error === 'string' ? raw.error : undefined,
    resource: raw.resource as PaymentRequired['resource'],
    accepts,
  };
}

/** Base64 of a JSON value, the header encoding of the HTTP transport. */
export function headerValue(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function parseHeader(header: string): unknown {
  const binary = atob(header.trim());
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

/**
 * The client-side checks before paying (scheme spec, "Client Payment
 * Construction"): terms, our own recomputation of the request binding, and
 * the decoded invoice.
 */
export async function validateChallenge(
  issuerBaseUrl: string,
  body: string,
  required: PaymentRequired,
  sat: number,
  now: number,
  network: string = X402_NETWORK_MAINNET,
): Promise<ValidatedChallenge> {
  const url = issuerBaseUrl + ECASH_PATH;
  if (required.resource.url !== url) throw new IssuerError(`x402: resource.url is ${required.resource.url}, expected ${url}`);
  const accepted = required.accepts.find((a) => a.scheme === 'exact' && a.network === network && a.asset === 'BTC');
  if (!accepted) throw new IssuerError('x402: issuer offers no exact/lnbtc requirement for this network');
  const extra = accepted.extra;
  if (extra.paymentFlow !== 'upfront') throw new IssuerError('x402: paymentFlow must be upfront');
  if (extra.assetTransferMethod !== undefined && extra.assetTransferMethod !== 'bolt11') {
    throw new IssuerError('x402: assetTransferMethod must be bolt11');
  }
  if (!/^[1-9][0-9]*$/.test(accepted.amount)) throw new IssuerError('x402: amount is not a positive integer');
  const expectedMsat = BigInt(sat) * 1000n;
  if (BigInt(accepted.amount) !== expectedMsat) {
    throw new IssuerError(`x402: issuer asks ${accepted.amount} msat for ${sat} sat of ecash`);
  }
  if (!Number.isInteger(accepted.maxTimeoutSeconds) || accepted.maxTimeoutSeconds <= 0) {
    throw new IssuerError('x402: maxTimeoutSeconds must be a positive integer');
  }
  if (!isLowerHex(accepted.payTo, 66) || !/^0[23]/.test(accepted.payTo)) throw new IssuerError('x402: payTo is not a compressed key');
  if (extra.requestBindingProfile !== 'http:1') throw new IssuerError('x402: unsupported request binding profile');
  const names = http1HeaderNames(extra.requestBindingParams);
  const bound: BoundHeader[] = names.map((name) => ({ name, value: name === 'content-type' ? 'application/json' : null }));
  const binding = await http1Binding('POST', url, new TextEncoder().encode(body), bound);
  if (extra.requestHash !== binding.requestHashHex) throw new IssuerError('x402: requestHash does not match our request');
  const invoice = typeof extra.invoice === 'string' ? extra.invoice.trim() : '';
  if (!invoice) throw new IssuerError('x402: no invoice in the challenge');
  const { decodeBolt11 } = await import('./bolt11.js');
  const decoded = decodeBolt11(invoice);
  const currency = network === X402_NETWORK_MAINNET ? 'bc' : 'tb';
  if (decoded.currency !== currency) throw new IssuerError('x402: invoice currency does not match the network');
  if (decoded.description !== null || decoded.descriptionHashHex === null) throw new IssuerError('x402: invoice must carry a description hash only');
  if (decoded.descriptionHashHex !== binding.requestHashHex) throw new IssuerError('x402: invoice is not bound to our request');
  if (decoded.payeeHex !== accepted.payTo) throw new IssuerError('x402: invoice is not signed by payTo');
  if (decoded.amountMsat !== expectedMsat) throw new IssuerError('x402: invoice amount differs from the requirement');
  if (decoded.expirySecs !== accepted.maxTimeoutSeconds) throw new IssuerError('x402: invoice expiry differs from maxTimeoutSeconds');
  if (decoded.timestamp > now + CLOCK_SKEW_SECS) throw new IssuerError('x402: invoice is dated in the future');
  const expiresAt = decoded.timestamp + decoded.expirySecs;
  if (now > expiresAt) throw new IssuerError('x402: invoice already expired');
  return { resource: required.resource, accepted, invoice, paymentHash: decoded.paymentHashHex, expiresAt };
}

/** `POST /v2/x402/ecash` without `PAYMENT-SIGNATURE`: the 402 challenge. */
export async function requestChallenge(issuer: IssuerClient, body: string): Promise<PaymentRequired> {
  const response = await issuer.postRaw(ECASH_PATH, body);
  if (response.status !== 402) {
    const text = await response.text().catch(() => '');
    throw new IssuerError(`x402: expected a 402 challenge, got ${response.status}${text ? `: ${text.slice(0, 200)}` : ''}`);
  }
  const header = response.headers.get('payment-required');
  const raw = header ? parseHeader(header) : await response.json();
  return parsePaymentRequired(raw);
}

export interface WebLnLike {
  enable(): Promise<unknown>;
  sendPayment(invoice: string): Promise<{ preimage: string }>;
}

async function verifyPreimage(preimage: string, paymentHash: string): Promise<string> {
  const clean = preimage.trim().toLowerCase();
  if (!isLowerHex(clean, 64)) throw new IssuerError('x402: preimage is not 32 bytes of hex');
  if ((await sha256Hex(hexToBytes(clean))) !== paymentHash) throw new IssuerError('x402: preimage does not match the payment hash');
  return clean;
}

/**
 * Drop the pending top-up unless it may already be paid, in which case it
 * stays so Resume can finish it: an x402 top-up whose preimage the page
 * holds or whose invoice the issuer reports paid, or a mint top-up whose
 * outputs are persisted or whose quote the mint reports paid or issued.
 * Returns whether it was dropped. A failed check throws and keeps it.
 */
export async function cancelPendingTopUp(issuer: IssuerClient, store: CashuStore): Promise<boolean> {
  const pending = store.pending();
  if (!pending) return true;
  let paid: boolean;
  if (pending.rail === 'x402') {
    paid = pending.preimage !== null || (pending.paymentHash !== null && (await x402InvoiceStatus(issuer, pending.paymentHash)) === 'paid');
  } else {
    paid = pending.outputs !== null || (await checkQuoteStatus(pending.mintUrl, 'sat', pending.quoteId)) !== 'UNPAID';
  }
  if (paid) return false;
  store.setPending(null);
  return true;
}

/** The issuer node's view of an x402 invoice; `unknown` when the issuer has no such invoice. */
async function x402InvoiceStatus(issuer: IssuerClient, paymentHash: string): Promise<string> {
  const response = await issuer.getRaw(`/v2/x402/invoices/${paymentHash}`);
  if (response.status === 404) return 'unknown';
  if (!response.ok) throw new IssuerError(`x402: invoice status ${response.status}`);
  return ((await response.json()) as { status?: string }).status ?? 'unknown';
}

/** The preimage of an invoice the issuer's node reports paid, else `null`. */
async function paidPreimage(issuer: IssuerClient, paymentHash: string): Promise<string | null> {
  const response = await issuer.getRaw(`/v2/x402/invoices/${paymentHash}`);
  if (!response.ok) return null;
  const state = (await response.json()) as { status?: string; preimage?: string | null };
  return state.status === 'paid' && typeof state.preimage === 'string' ? verifyPreimage(state.preimage, paymentHash) : null;
}

/**
 * Obtains the preimage: through WebLN when a browser wallet is present,
 * otherwise by polling the issuer until the node reports the invoice paid
 * (the user paid from another device).
 */
export async function waitForPayment(
  issuer: IssuerClient,
  challenge: ValidatedChallenge,
  options: { signal?: AbortSignal; intervalMs?: number; webln?: WebLnLike | null; now?: () => number } = {},
): Promise<string> {
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const webln = options.webln === undefined ? ((globalThis as { webln?: WebLnLike }).webln ?? null) : options.webln;
  if (webln) {
    try {
      await webln.enable();
      const paid = await webln.sendPayment(challenge.invoice);
      return await verifyPreimage(paid.preimage, challenge.paymentHash);
    } catch {
      /* fall through to polling: the user may pay from elsewhere */
    }
  }
  const interval = options.intervalMs ?? 3000;
  for (;;) {
    if (options.signal?.aborted) throw new IssuerError('x402: purchase cancelled');
    const response = await issuer.getRaw(`/v2/x402/invoices/${challenge.paymentHash}`);
    if (response.ok) {
      const state = (await response.json()) as { status?: string; preimage?: string | null };
      if (state.status === 'paid' && typeof state.preimage === 'string') {
        return await verifyPreimage(state.preimage, challenge.paymentHash);
      }
      if (state.status === 'expired' || now() > challenge.expiresAt + CLOCK_SKEW_SECS) {
        throw new IssuerError('x402: invoice expired before it was paid');
      }
    } else if (response.status !== 404 && response.status !== 503) {
      throw new IssuerError(`x402: invoice status ${response.status}`);
    }
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, interval);
      options.signal?.addEventListener('abort', () => {
        clearTimeout(timer);
        resolve();
      }, { once: true });
    });
  }
}

/** The `200` answer: one NUT-00 blind signature per output, in the order of `outputs`. */
export function parseEcashSignatures(raw: unknown): BlindSignatureJson[] {
  if (!isRecord(raw) || !Array.isArray(raw.signatures)) throw new IssuerError('x402: the answer carries no signatures');
  return raw.signatures.map((s: unknown) => {
    if (!isRecord(s) || typeof s.amount !== 'number' || typeof s.id !== 'string' || typeof s.C_ !== 'string') {
      throw new IssuerError('x402: malformed blind signature');
    }
    const dleq = isRecord(s.dleq) && typeof s.dleq.e === 'string' && typeof s.dleq.s === 'string' ? { e: s.dleq.e, s: s.dleq.s } : undefined;
    return { amount: s.amount, id: s.id, C_: s.C_, dleq };
  });
}

/** The paid retry: the same body with `PAYMENT-SIGNATURE`; the answer signs the request's outputs. */
export async function settle(
  issuer: IssuerClient,
  body: string,
  resource: unknown,
  accepted: PaymentRequirements,
  preimage: string,
): Promise<BlindSignatureJson[]> {
  const payload = { x402Version: X402_VERSION, resource, accepted, payload: { preimage } };
  const response = await issuer.postRaw(ECASH_PATH, body, { 'payment-signature': headerValue(payload) });
  if (response.ok) return parseEcashSignatures(await response.json());
  const settlement = response.headers.get('payment-response');
  let reason: string | null = null;
  if (settlement) {
    try {
      const parsed = parseHeader(settlement) as { errorReason?: string };
      reason = parsed.errorReason ?? null;
    } catch {
      reason = null;
    }
  }
  const text = await response.text().catch(() => '');
  throw new IssuerError(`x402: settlement refused (${response.status})${reason ? `: ${reason}` : text ? `: ${text.slice(0, 200)}` : ''}`);
}

/**
 * Top up `sat` of ecash over x402: fresh outputs for the mint's active
 * keyset go to the issuer, which swaps its own proofs into exactly those
 * outputs once the invoice is paid; the wallet unblinds the answer.
 * Resumable like `topUpFromMint`: the pending record (the exact body, each
 * output's secret and blinding factor, the challenge, and the preimage once
 * known) is persisted before the invoice is requested, so a reload
 * continues from the last completed step. Returns the sat added.
 */
export async function topUpX402(
  issuer: IssuerClient,
  store: CashuStore,
  sat: number,
  hooks: PurchaseHooks = {},
  now: () => number = () => Math.floor(Date.now() / 1000),
  options: { webln?: WebLnLike | null; pollIntervalMs?: number; network?: string } = {},
): Promise<number> {
  let pending = store.pending();
  if (pending && (pending.rail !== 'x402' || pending.issuerUrl !== issuer.baseUrl)) {
    throw new IssuerError('finish or cancel the pending top-up first');
  }
  if (!pending) {
    const { mintUrl, creditSat } = await issuerMint(issuer, store);
    const keyset = await mintKeyset(mintUrl);
    const outputs = await createOutputs(keyset, planDenominations(sat, creditSat));
    const body = JSON.stringify({
      sat,
      outputs: outputs.map((o) => ({ amount: Number(o.blindedMessage.amount), id: o.blindedMessage.id, B_: o.blindedMessage.B_ })),
    });
    pending = {
      rail: 'x402',
      issuerUrl: issuer.baseUrl,
      mintUrl,
      sat,
      keysetId: keyset.id,
      body,
      outputs,
      resource: null,
      accepted: null,
      paymentHash: null,
      invoice: null,
      expiresAt: null,
      preimage: null,
      createdAt: now(),
    };
    store.setPending(pending);
  }
  if (!pending.preimage && pending.paymentHash && pending.expiresAt !== null && pending.expiresAt <= now()) {
    // The invoice may have been paid before it expired (and the page reloaded
    // since): settle with that payment rather than ask for a second one.
    const preimage = await paidPreimage(issuer, pending.paymentHash);
    if (preimage) {
      pending = { ...pending, preimage };
      store.setPending(pending);
    }
  }
  if (!pending.preimage) {
    if (!pending.invoice || !pending.accepted || !pending.paymentHash || (pending.expiresAt !== null && pending.expiresAt <= now())) {
      hooks.onStatus?.('quoting');
      const required = await requestChallenge(issuer, pending.body);
      const challenge = await validateChallenge(issuer.baseUrl, pending.body, required, pending.sat, now(), options.network);
      pending = {
        ...pending,
        resource: challenge.resource,
        accepted: challenge.accepted,
        paymentHash: challenge.paymentHash,
        invoice: challenge.invoice,
        expiresAt: challenge.expiresAt,
      };
      store.setPending(pending);
    }
    hooks.onInvoice?.(pending.invoice!, pending.expiresAt);
    hooks.onStatus?.('awaiting-payment');
    const preimage = await waitForPayment(
      issuer,
      {
        resource: pending.resource as PaymentRequired['resource'],
        accepted: pending.accepted as PaymentRequirements,
        invoice: pending.invoice!,
        paymentHash: pending.paymentHash!,
        expiresAt: pending.expiresAt ?? now() + 3600,
      },
      { signal: hooks.signal, intervalMs: options.pollIntervalMs, webln: options.webln, now },
    );
    pending = { ...pending, preimage };
    store.setPending(pending);
  }
  hooks.onStatus?.('minting');
  const signatures = await settle(issuer, pending.body, pending.resource, pending.accepted as PaymentRequirements, pending.preimage!);
  const proofs = await unblindSignatures(pending.mintUrl, pending.outputs, signatures);
  store.receive(proofs);
  hooks.onStatus?.('stored');
  return sumSat(proofs);
}
