/**
 * TypeScript port of `pir-core::onion_unpack` (Rust). Bit-pack /
 * unpack the OnionPIRv2 plaintext byte-stream format used after the
 * SEAL-free upstream port (onionpir rev 92fceb01+).
 *
 * The Rust reference is `crates/protocol/core/src/onion_unpack.rs`. Both
 * implementations operate on the same algorithm (rolling-buffer bit
 * concatenation, per upstream INTEGRATION.md §1.4 / §1.5) and
 * **must** stay byte-identical so the web client (which goes through
 * the upstream Emscripten WASM binding) and the native Rust client
 * (which goes through the onionpir crate's FFI binding) produce the
 * same query plan + decoded payload for any given scripthash.
 *
 * BigInt math is used because the algorithm carries up to
 * `bits_per_coeff + 7 < 64` bits of "pending" state at any moment;
 * a JS `number` can safely hold 53 bits and would silently corrupt
 * the bit stream on `CONFIG_N4096_K2_MP` (39 bits/coeff). BigInt is
 * slower than `number` but the unpacker only runs once per response
 * (a few KiB) so the overhead is negligible.
 */

/**
 * Derive the bit width packed into each plaintext coefficient.
 *
 * For `CONFIG_N2048_K1` (default): `entrySize=3328`, `polyDegree=2048`
 * → 13 bits/coeff (matches upstream `PlainMod - 1 = 14 - 1`).
 *
 * Returns `null` if the params are inconsistent (`entrySize * 8` not
 * divisible by `polyDegree`).
 */
export function bitsPerCoeff(entrySize: number, polyDegree: number): number | null {
  if (polyDegree <= 0) return null;
  const totalBits = entrySize * 8;
  if (totalBits % polyDegree !== 0) return null;
  return Math.floor(totalBits / polyDegree);
}

/**
 * Decode the raw `decryptResponse` bytes into the original packed
 * payload.
 *
 * Input wire format (per upstream `Client::decrypt_response`):
 *
 * ```text
 * [u32 N (LE)][u64 coeff_0 (LE)]…[u64 coeff_{N-1} (LE)]
 * ```
 *
 * Returns the first `entrySize` payload bytes — i.e. what was
 * originally packed into the coefficients. Returns `null` on:
 *
 * * Truncated input (length < `4 + 8 * polyDegree`)
 * * Leading `u32 N` does not equal `polyDegree`
 * * `bitsPerCoeff(entrySize, polyDegree)` is null
 */
export function unpackOnionPlaintext(
  plaintextBytes: Uint8Array,
  polyDegree: number,
  entrySize: number,
): Uint8Array | null {
  const bpc = bitsPerCoeff(entrySize, polyDegree);
  if (bpc === null) return null;

  const headerLen = 4;
  const bodyLen = polyDegree * 8;
  if (plaintextBytes.length < headerLen + bodyLen) return null;

  // Read u32 LE N. Must match polyDegree — upstream emits exactly
  // `polyDegree` coefficients, no fewer.
  const dv = new DataView(
    plaintextBytes.buffer,
    plaintextBytes.byteOffset,
    plaintextBytes.byteLength,
  );
  const nInBlob = dv.getUint32(0, true);
  if (nInBlob !== polyDegree) return null;

  const bpcBig = BigInt(bpc);
  const coeffMask: bigint =
    bpc === 64 ? (1n << 64n) - 1n : (1n << bpcBig) - 1n;
  const out = new Uint8Array(entrySize);
  let outIdx = 0;

  let buffer = 0n;
  let offset = 0n;
  for (let i = 0; i < polyDegree; i++) {
    const off = headerLen + i * 8;
    // DataView.getBigUint64 reads 8 LE bytes into a BigInt.
    const c = dv.getBigUint64(off, true);
    const payloadBits = c & coeffMask;
    buffer |= payloadBits << offset;
    offset += bpcBig;
    while (offset >= 8n && outIdx < entrySize) {
      out[outIdx] = Number(buffer & 0xFFn);
      outIdx += 1;
      buffer >>= 8n;
      offset -= 8n;
    }
    if (outIdx === entrySize) break;
  }
  return out;
}
