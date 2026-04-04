/**
 * Batch DPF-based Merkle verification.
 *
 * Packs multiple addresses' sibling groupIds into PBC batches per level,
 * reducing N×L round-trips to ~L rounds. Shared by BatchPirClient and
 * HarmonyPirClient.
 */

import {
  deriveIntBuckets3, deriveCuckooKeyGeneric, cuckooHashInt, sha256,
} from './hash.js';
import { genDpfKeysN } from './dpf.js';
import { encodeRequest, decodeResponse } from './protocol.js';
import { findGroupInSiblingResult } from './scan.js';
import { planRounds } from './pbc.js';
import { DummyRng } from './codec.js';
import {
  computeDataHash, computeLeafHash, computeParentN,
  parseTreeTopCache, ZERO_HASH,
  type TreeTopCache,
} from './merkle.js';
import { REQ_MERKLE_TREE_TOP, RESP_MERKLE_TREE_TOP } from './constants.js';
import type { ManagedWebSocket } from './ws.js';
import type { MerkleInfoJson } from './server-info.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function xorBuffers(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(Math.max(a.length, b.length));
  for (let i = 0; i < result.length; i++) {
    result[i] = (a[i] || 0) ^ (b[i] || 0);
  }
  return result;
}

// ─── Tree-top cache (shared across calls) ───────────────────────────────────

let cachedTreeTop: { rawBytes: Uint8Array; parsed: TreeTopCache } | null = null;

async function fetchTreeTopCache(
  ws: ManagedWebSocket,
): Promise<{ rawBytes: Uint8Array; parsed: TreeTopCache }> {
  if (cachedTreeTop) return cachedTreeTop;

  const req = new Uint8Array([1, 0, 0, 0, REQ_MERKLE_TREE_TOP]);
  const raw = await ws.sendRaw(req);

  const variant = raw[4];
  if (variant !== RESP_MERKLE_TREE_TOP) {
    throw new Error(`Unexpected tree-top response variant: 0x${variant.toString(16)}`);
  }
  const treeTopBytes = raw.slice(5);
  const parsed = parseTreeTopCache(treeTopBytes);

  cachedTreeTop = { rawBytes: treeTopBytes, parsed };
  return cachedTreeTop;
}

/** Clear the cached tree-top (call on disconnect). */
export function clearTreeTopCache(): void {
  cachedTreeTop = null;
}

// ─── Batch verification ─────────────────────────────────────────────────────

export interface MerkleVerifyItem {
  scriptHash: Uint8Array;
  rawChunkData: Uint8Array;
  treeLoc: number;
}

/**
 * Batch-verify Merkle proofs using 2-server DPF sibling queries.
 *
 * Packs all addresses' groupIds into PBC batches at each sibling level,
 * deduplicating shared groupIds. Returns one boolean per item.
 */
export async function verifyMerkleBatchDpf(
  ws0: ManagedWebSocket,
  ws1: ManagedWebSocket,
  merkle: MerkleInfoJson,
  items: MerkleVerifyItem[],
  onProgress?: (step: string, detail: string) => void,
  onLog?: (msg: string, level: 'info' | 'success' | 'error') => void,
): Promise<boolean[]> {
  const N = items.length;
  if (N === 0) return [];

  const progress = onProgress || (() => {});
  const log = onLog || (() => {});
  const rng = new DummyRng();

  // ── Fetch tree-top cache ─────────────────────────────────────────
  progress('Merkle', 'Fetching tree-top cache...');
  const treeTop = await fetchTreeTopCache(ws0);
  const expectedRoot = hexToBytes(merkle.root);

  // Verify tree-top cache integrity
  const treeTopHash = sha256(treeTop.rawBytes);
  const expectedTopHash = hexToBytes(merkle.tree_top_hash);
  if (!treeTopHash.every((b, i) => b === expectedTopHash[i])) {
    log('Tree-top cache integrity check FAILED', 'error');
    return new Array(N).fill(false);
  }
  log('Tree-top cache integrity: OK', 'success');

  // ── Initialize per-address state ───────────────────────────────────
  const currentHash: Uint8Array[] = new Array(N);
  const nodeIdx: number[] = new Array(N);
  const failed: boolean[] = new Array(N).fill(false);

  for (let i = 0; i < N; i++) {
    const dataHash = computeDataHash(items[i].rawChunkData);
    currentHash[i] = computeLeafHash(items[i].scriptHash, items[i].treeLoc, dataHash);
    nodeIdx[i] = items[i].treeLoc;
  }

  // ── Sibling PIR rounds (batched DPF) ───────────────────────────────
  for (let level = 0; level < merkle.sibling_levels; level++) {
    const levelInfo = merkle.levels[level];
    const levelSeed = BigInt('0xBA7C51B100000000') + BigInt(level);

    // Step 1: Compute groupId per address, deduplicate
    const groupToAddrs = new Map<number, number[]>(); // groupId → addr indices
    for (let i = 0; i < N; i++) {
      if (failed[i]) continue;
      const gid = Math.floor(nodeIdx[i] / merkle.arity);
      const arr = groupToAddrs.get(gid);
      if (arr) arr.push(i);
      else groupToAddrs.set(gid, [i]);
    }
    const uniqueGroupIds = [...groupToAddrs.keys()];
    if (uniqueGroupIds.length === 0) break;

    progress('Merkle', `L${level + 1}/${merkle.sibling_levels}: ${uniqueGroupIds.length} unique groups from ${N} addresses...`);

    // Step 2: PBC-place unique groupIds
    const candidateBuckets = uniqueGroupIds.map(gid => deriveIntBuckets3(gid, merkle.sibling_k));
    const pbcRounds = planRounds(candidateBuckets, merkle.sibling_k, 3);

    // Step 3: Query each PBC round
    const siblingResults = new Map<number, Uint8Array[]>(); // groupId → children

    for (let ri = 0; ri < pbcRounds.length; ri++) {
      const round = pbcRounds[ri];
      progress('Merkle', `L${level + 1}/${merkle.sibling_levels}: PBC round ${ri + 1}/${pbcRounds.length} (${round.length} groups)...`);

      // Map: bucket → uniqueGroupIndex
      const bucketToUgi = new Map<number, number>();
      for (const [ugi, bucket] of round) {
        bucketToUgi.set(bucket, ugi);
      }

      // Generate K×2 DPF keys
      const s0Keys: Uint8Array[][] = [];
      const s1Keys: Uint8Array[][] = [];
      for (let b = 0; b < merkle.sibling_k; b++) {
        const s0B: Uint8Array[] = [];
        const s1B: Uint8Array[] = [];
        const ugi = bucketToUgi.get(b);
        for (let h = 0; h < 2; h++) {
          let alpha: number;
          if (ugi !== undefined) {
            const gid = uniqueGroupIds[ugi];
            const ck = deriveCuckooKeyGeneric(levelSeed, b, h);
            alpha = cuckooHashInt(gid, ck, levelInfo.bins_per_table);
          } else {
            alpha = Number(rng.nextU64() % BigInt(levelInfo.bins_per_table));
          }
          const keys = await genDpfKeysN(alpha, levelInfo.dpf_n);
          s0B.push(keys.key0);
          s1B.push(keys.key1);
        }
        s0Keys.push(s0B);
        s1Keys.push(s1B);
      }

      // Send to both servers
      const roundId = level * 100 + ri;
      const mReq0 = encodeRequest({ type: 'MerkleSiblingBatch', query: { level: 2, roundId, keys: s0Keys } });
      const mReq1 = encodeRequest({ type: 'MerkleSiblingBatch', query: { level: 2, roundId, keys: s1Keys } });

      const [mraw0, mraw1] = await Promise.all([
        ws0.sendRaw(mReq0),
        ws1.sendRaw(mReq1),
      ]);
      const mresp0 = decodeResponse(mraw0.slice(4));
      const mresp1 = decodeResponse(mraw1.slice(4));

      if (mresp0.type !== 'MerkleSiblingBatch' || mresp1.type !== 'MerkleSiblingBatch') {
        log(`Merkle L${level}: unexpected response`, 'error');
        // Mark all addresses in this round as failed
        for (const [ugi] of round) {
          const gid = uniqueGroupIds[ugi];
          for (const ai of groupToAddrs.get(gid)!) failed[ai] = true;
        }
        continue;
      }

      // Extract results for real buckets
      for (const [ugi, bucket] of round) {
        const gid = uniqueGroupIds[ugi];
        const mr0 = mresp0.result.results[bucket];
        const mr1 = mresp1.result.results[bucket];
        let children: Uint8Array[] | null = null;
        for (let h = 0; h < 2; h++) {
          const xored = xorBuffers(mr0[h], mr1[h]);
          children = findGroupInSiblingResult(xored, gid, merkle.arity, merkle.sibling_bucket_size, merkle.sibling_slot_size);
          if (children) break;
        }
        if (children) {
          siblingResults.set(gid, children);
        } else {
          log(`Merkle L${level}: group ${gid} not found in sibling result`, 'error');
          for (const ai of groupToAddrs.get(gid)!) failed[ai] = true;
        }
      }
    }

    // Step 4: Update each address's state
    for (const [gid, addrIndices] of groupToAddrs) {
      const children = siblingResults.get(gid);
      if (!children) continue; // already marked failed
      const parentHash = computeParentN(children);
      for (const ai of addrIndices) {
        if (failed[ai]) continue;
        currentHash[ai] = parentHash;
        nodeIdx[ai] = gid;
      }
    }
  }

  // ── Walk tree-top cache per address ────────────────────────────────
  progress('Merkle', 'Walking tree-top cache to root...');
  const cache = treeTop.parsed;
  const results: boolean[] = new Array(N).fill(false);

  for (let i = 0; i < N; i++) {
    if (failed[i]) continue;

    let hash = currentHash[i];
    let idx = nodeIdx[i];

    for (let ci = 0; ci < cache.levels.length - 1; ci++) {
      const levelNodes = cache.levels[ci];
      const parentStart = Math.floor(idx / merkle.arity) * merkle.arity;
      const childHashes: Uint8Array[] = [];
      for (let c = 0; c < merkle.arity; c++) {
        const childIdx = parentStart + c;
        childHashes.push(childIdx < levelNodes.length ? levelNodes[childIdx] : ZERO_HASH);
      }
      hash = computeParentN(childHashes);
      idx = Math.floor(idx / merkle.arity);
    }

    results[i] = hash.length === expectedRoot.length &&
      hash.every((b, j) => b === expectedRoot[j]);
  }

  const verified = results.filter(Boolean).length;
  if (verified === N) {
    log(`Merkle VERIFIED: all ${N} proofs valid (root=${merkle.root.substring(0, 16)}…)`, 'success');
  } else {
    log(`Merkle: ${verified}/${N} verified, ${N - verified} failed`, verified > 0 ? 'info' : 'error');
  }

  return results;
}
