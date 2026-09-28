/**
 * Minimal BOLT11 decoder for the x402 client checks (`x402.ts`): currency,
 * amount, creation time, expiry, payment hash, description hash or inline
 * description, and the payee key (the `n` field, else recovered from the
 * signature, which also proves the signature is valid for that key).
 * Only what the checks need; no routing hints, no features.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const MSAT_PER_BTC = 100_000_000_000n;

export interface DecodedInvoice {
  /** `bc`, `tb`, `bcrt`, `tbs`, or `sb`. */
  currency: string;
  amountMsat: bigint | null;
  timestamp: number;
  expirySecs: number;
  paymentHashHex: string;
  descriptionHashHex: string | null;
  description: string | null;
  /** Compressed key, 66 lowercase hex. */
  payeeHex: string;
  /** True when the invoice carried an `n` field (then also checked against the signature). */
  payeeFromField: boolean;
}

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ GENERATORS[i]) >>> 0;
  }
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >>> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function bech32Decode(text: string): { hrp: string; words: number[] } {
  const lower = text.toLowerCase();
  if (lower !== text && text.toUpperCase() !== text) throw new Error('bolt11: mixed case');
  const split = lower.lastIndexOf('1');
  if (split < 1 || split + 7 > lower.length) throw new Error('bolt11: no separator');
  const hrp = lower.slice(0, split);
  const data: number[] = [];
  for (const ch of lower.slice(split + 1)) {
    const v = CHARSET.indexOf(ch);
    if (v < 0) throw new Error('bolt11: invalid character');
    data.push(v);
  }
  if (polymod(hrpExpand(hrp).concat(data)) !== 1) throw new Error('bolt11: bad checksum');
  return { hrp, words: data.slice(0, -6) };
}

function wordsToBytes(words: number[]): Uint8Array {
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const w of words) {
    acc = (acc << 5) | w;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  if (bits > 0) out.push((acc << (8 - bits)) & 0xff);
  return Uint8Array.from(out);
}

function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

function parseAmount(digits: string, multiplier: string): bigint | null {
  if (digits === '') return null;
  const n = BigInt(digits);
  switch (multiplier) {
    case '':
      return n * MSAT_PER_BTC;
    case 'm':
      return n * 100_000_000n;
    case 'u':
      return n * 100_000n;
    case 'n':
      return n * 100n;
    case 'p':
      if (n % 10n !== 0n) throw new Error('bolt11: sub-millisatoshi amount');
      return n / 10n;
    default:
      throw new Error('bolt11: unknown multiplier');
  }
}

/** Decodes and checks the checksum and signature; throws on any defect. */
export function decodeBolt11(invoice: string): DecodedInvoice {
  const { hrp, words } = bech32Decode(invoice.trim());
  const m = /^ln(bcrt|bc|tbs|tb|sb)(\d*)([munp]?)$/.exec(hrp);
  if (!m) throw new Error('bolt11: unknown prefix');
  const currency = m[1];
  const amountMsat = parseAmount(m[2], m[3]);
  if (words.length < 7 + 104) throw new Error('bolt11: too short');
  const sigWords = words.slice(-104);
  const body = words.slice(0, -104);
  let timestamp = 0;
  for (let i = 0; i < 7; i++) timestamp = timestamp * 32 + body[i];
  let expirySecs = 3600;
  let paymentHashHex: string | null = null;
  let descriptionHashHex: string | null = null;
  let description: string | null = null;
  let payeeField: string | null = null;
  let i = 7;
  while (i + 3 <= body.length) {
    const type = body[i];
    const len = body[i + 1] * 32 + body[i + 2];
    const data = body.slice(i + 3, i + 3 + len);
    if (data.length !== len) throw new Error('bolt11: truncated tagged field');
    i += 3 + len;
    switch (type) {
      case 1:
        if (len === 52) paymentHashHex = toHex(wordsToBytes(data).subarray(0, 32));
        break;
      case 23:
        if (len === 52) descriptionHashHex = toHex(wordsToBytes(data).subarray(0, 32));
        break;
      case 13:
        description = new TextDecoder('utf-8', { fatal: true }).decode(wordsToBytes(data).subarray(0, Math.floor((len * 5) / 8)));
        break;
      case 6: {
        let v = 0;
        for (const w of data) v = v * 32 + w;
        expirySecs = v;
        break;
      }
      case 19:
        if (len === 53) payeeField = toHex(wordsToBytes(data).subarray(0, 33));
        break;
      default:
        break;
    }
  }
  if (!paymentHashHex) throw new Error('bolt11: no payment hash');
  const signature = wordsToBytes(sigWords);
  if (signature.length !== 65) throw new Error('bolt11: bad signature length');
  const message = new Uint8Array(hrp.length + Math.ceil((body.length * 5) / 8));
  message.set(new TextEncoder().encode(hrp), 0);
  message.set(wordsToBytes(body), hrp.length);
  const digest = sha256(message);
  const recovered = secp256k1.Signature.fromBytes(signature.subarray(0, 64), 'compact')
    .addRecoveryBit(signature[64])
    .recoverPublicKey(digest);
  const payeeHex = toHex(recovered.toBytes(true));
  if (payeeField !== null && payeeField !== payeeHex) throw new Error('bolt11: signature does not match the payee field');
  return {
    currency,
    amountMsat,
    timestamp,
    expirySecs,
    paymentHashHex,
    descriptionHashHex,
    description,
    payeeHex,
    payeeFromField: payeeField !== null,
  };
}
