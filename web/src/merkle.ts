/**
 * Client-side Merkle tree hashing primitives for PIR responses.
 *
 * Uses SHA-256 from hash.js (same as the rest of the web client).
 * Implements the same N-ary Merkle tree logic as pir-core/src/merkle.rs.
 *
 * Only the hashing helpers live here. The actual proof walks are
 * backend-specific: DPF / HarmonyPIR verify in Rust via the WASM
 * `verifyBucketMerkleItem`; the standalone OnionPIR TS client walks tree
 * tops to root in `onionpir_client.ts::walkTreeTopToRoot`. Both correctly
 * splice the verified child into its parent at `idx % arity` — a property
 * the previously-exported `verifyMerkleProof` did not have, so it was
 * removed (it never bound the leaf into the recomputed root). See
 * docs/CODE_REVIEW_2026-06.md W1.
 */

import { sha256 } from './hash.js';

/** 32-byte zero hash (padding for incomplete groups). */
export const ZERO_HASH = new Uint8Array(32);

/**
 * Compute data hash: SHA256(chunkData).
 */
export function computeDataHash(chunkData: Uint8Array): Uint8Array {
  return sha256(chunkData);
}

/**
 * Per-bucket bin Merkle: leaf = SHA256(binIndex_u32_LE || binContent).
 *
 * Each leaf in a per-PBC-group Merkle tree commits to the bin index and
 * all slot data at that bin.
 */
export function computeBinLeafHash(binIndex: number, binContent: Uint8Array): Uint8Array {
  const preimage = new Uint8Array(4 + binContent.length);
  new DataView(preimage.buffer).setUint32(0, binIndex, true);
  preimage.set(binContent, 4);
  return sha256(preimage);
}

/**
 * Compute an N-ary parent hash: SHA256(child_0 || child_1 || ... || child_{N-1}).
 *
 * @param children - Array of 32-byte child hashes (length = arity)
 */
export function computeParentN(children: Uint8Array[]): Uint8Array {
  const preimage = new Uint8Array(children.length * 32);
  for (let i = 0; i < children.length; i++) {
    preimage.set(children[i], i * 32);
  }
  return sha256(preimage);
}
