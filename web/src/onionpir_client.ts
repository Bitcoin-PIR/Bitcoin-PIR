/**
 * OnionPIR v2 WebSocket client for browser.
 *
 * Single-server FHE-based PIR using OnionPIRv2 WASM module.
 * Two-level query: index PIR → chunk PIR → decode UTXO data.
 * Multi-address batching via PBC cuckoo placement.
 */

import {
  K_CHUNK, NUM_HASHES, INDEX_CUCKOO_NUM_HASHES,
  CHUNK_MASTER_SEED, MASTER_SEED,
  REQ_ONIONPIR_MERKLE_INDEX_SIBLING, RESP_ONIONPIR_MERKLE_INDEX_SIBLING,
  REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP, RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP,
  REQ_ONIONPIR_MERKLE_DATA_SIBLING, RESP_ONIONPIR_MERKLE_DATA_SIBLING,
  REQ_ONIONPIR_MERKLE_DATA_TREE_TOP, RESP_ONIONPIR_MERKLE_DATA_TREE_TOP,
} from './constants.js';

import {
  deriveGroups, deriveCuckooKeyGeneric, cuckooHash,
  deriveChunkGroups,
  splitmix64, computeTag,
  sha256,
} from './hash.js';

import { planRounds } from './pbc.js';
import { decodeUtxoData, DummyRng } from './codec.js';
import { unpackOnionPlaintext } from './onion-unpack.js';
import { findEntryInOnionPirIndexResult } from './scan.js';
import { ManagedWebSocket } from './ws.js';
import { fetchServerInfoJson } from './server-info.js';
import {
  requireSdkWasm,
  type WasmAnnounceVerification,
  type WasmAttestVerification,
  type WasmDatabaseProof,
  type WasmStandaloneSecureChannelV1,
} from './sdk-bridge.js';
import { computeParentN, ZERO_HASH } from './merkle.js';
import {
  arkFingerprint,
  checkOperatorIdentity,
  summariseAttestation,
  verifyDatabaseProofs,
  type OperatorIdentity,
  type ServerAttestation,
} from './verification.js';
import type { ServerAttestPin } from './attest-pin.js';

import type { UtxoEntry, QueryResult, ConnectionState } from './types.js';
import type { DatabaseProofPin, DatabaseProofStatus } from './db-proof.js';
import type {
  DatabaseCatalog,
  OnionPirMerkleInfoJson,
  ServerInfoJson,
} from './server-info.js';
import { fetchDatabaseCatalog } from './server-info.js';

import type { LeakageRecorder, RoundProfile } from './leakage.js';
import {
  CreditedChannel,
  encodeApiKeyFrame,
  parseApiKeyResponsePayload,
  resolveAccess,
  serverGasCardFromInfo,
  type CreditEnablement,
  type CreditProvider,
} from './credits.js';

// ─── Constants for OnionPIR v2 layout ─────────────────────────────────────

// Post-port (commit 7): the byte count per decrypted bin is no longer a
// hardcoded 3840 — it equals `params_info().entry_size` (3328 for
// CONFIG_N2048_K1, 19968 for CONFIG_N4096_K2_MP). The TS port of the
// Rust `pir-core::onion_unpack` helper at `./onion-unpack.ts` returns
// exactly `entry_size` bytes from `decryptResponse`. The legacy
// constant is kept as a defensive upper-bound fallback only; the
// runtime `params.entrySize` is the source of truth at each call site.
const PACKED_ENTRY_SIZE = 3840;

/** Chunk cuckoo: 6 hash functions, group_size=1 */
const CHUNK_CUCKOO_NUM_HASHES = 6;

const MASK64 = 0xFFFFFFFFFFFFFFFFn;

// ─── OnionPIR wire protocol constants ─────────────────────────────────────

// Protocol constants still used for OnionPIR-specific requests
// (Ping/pong/info handled by ManagedWebSocket + fetchServerInfoJson)

// Operator-signed identity (shared across all backends; 0x07).
const REQ_ANNOUNCE              = 0x07;
const REQ_GET_DB_PROOF_V2       = 0x0C;

/** Exact v2-only request frame. Kept as a pure helper so no-fallback wire
 * behavior is covered without a live socket. */
export function databaseProofV2Request(dbId: number): Uint8Array {
  if (!Number.isInteger(dbId) || dbId < 0 || dbId > 0xff) {
    throw new Error(`database proof v2 db id must be a byte, got ${dbId}`);
  }
  return new Uint8Array([2, 0, 0, 0, REQ_GET_DB_PROOF_V2, dbId]);
}

// NOTE: moved from 0x30-0x32 to 0x50-0x52 to avoid collision with
// REQ_MERKLE_SIBLING_BATCH (0x31) and REQ_MERKLE_TREE_TOP (0x32).
const REQ_REGISTER_KEYS         = 0x50;
const REQ_ONIONPIR_INDEX_QUERY  = 0x51;
const REQ_ONIONPIR_CHUNK_QUERY  = 0x52;

const RESP_KEYS_ACK             = 0x50;
const RESP_ONIONPIR_INDEX_RESULT  = 0x51;
const RESP_ONIONPIR_CHUNK_RESULT  = 0x52;

// ─── WASM module types ────────────────────────────────────────────────────
//
// Post-port surface (onionpir rev 2402b16, upstream's wasm/bindings.cpp +
// hand-written .d.ts at web/public/wasm/onionpir_client.d.ts). The
// onionpir_client.wasm in web/public/wasm/ is rebuilt from this rev:
//
//   * `OnionPirClient(numEntries)`, `createClientFromSecretKey(numEntries,
//     clientId, secretKey)` and `paramsInfo(numEntries)` each take the
//     per-database `numEntries` (un-padded entry count): the FHE query
//     hypercube is sized from it, so INDEX / CHUNK / Merkle-sibling
//     clients each pass their own database's size.
//     `createClientFromSecretKey` returns `OnionPirClient | null` (per
//     upstream Rust: `from_secret_key -> Option<Self>`).
//   * Method renames: `generateGaloisKeys` → `galoisKeys`,
//     `generateGswKeys` → `gswKey`, `decryptResponse(idx, resp)` →
//     `decryptResponse(resp)` (caller now bit-unpacks via
//     `unpackOnionPlaintext`).
//   * Cuckoo helper key encoding flipped from `Uint32Array` lo/hi pairs
//     to `Float64Array` treated as u64-bytes (see
//     `buildCuckooKeysFloat64Array` below).

interface OnionPirParamsInfo {
  numEntries:     number;
  entrySize:      number;
  numPlaintexts:  number;
  fstDimSz:       number;
  otherDimSz:     number;
  polyDegree:     number;
  rnsModCount:    number;
  coeffValCnt:    number;
  dbSizeMB:       number;
  physicalSizeMB: number;
}

interface OnionPirModule {
  OnionPirClient: { new(numEntries: number): WasmPirClient };
  createClientFromSecretKey(numEntries: number, clientId: number, secretKey: Uint8Array): WasmPirClient | null;
  paramsInfo(numEntries: number): OnionPirParamsInfo;
  splitmix64(x: number): number;
  cuckooHashInt(entryId: number, key: number, numBins: number): number;
  buildCuckooBs1(entries: Uint32Array, keys: Uint32Array, numBins: number): Uint32Array;
}

interface WasmPirClient {
  id(): number;
  exportSecretKey(): Uint8Array;
  galoisKeys(): Uint8Array;
  gswKey(): Uint8Array;
  generateQuery(entryIndex: number): Uint8Array;
  decryptResponse(response: Uint8Array): Uint8Array;
  delete(): void;
}

// ─── WASM module loader ───────────────────────────────────────────────────
//
// Post-port the upstream WASM is emitted as an ES module
// (`onionpir_client.mjs`) with a default-exported async factory. The
// pre-port `<script>` tag + `globalThis.createOnionPirModule` global
// is gone — the browser HTML no longer ships the script tag (see
// commit 7 of the onionpir-port branch). Node tests dynamically
// `await import(...)` the same path; see
// `web/src/__tests__/onion_leakage_diff.test.ts` for the test-side
// loader.
//
// `globalThis.__onionpirWasmFactory` is a test-time escape hatch: when
// running under Node / vitest, the test harness can pre-install the
// factory there (resolved off the local filesystem) to avoid the
// browser-only `/wasm/onionpir_client.mjs` URL resolution path.

type OnionPirFactory = (moduleArg?: object) => Promise<OnionPirModule>;

let wasmModulePromise: Promise<OnionPirModule> | null = null;

async function loadWasmModule(): Promise<OnionPirModule> {
  if (!wasmModulePromise) {
    wasmModulePromise = (async () => {
      const installed = (globalThis as { __onionpirWasmFactory?: OnionPirFactory }).__onionpirWasmFactory;
      let factory: OnionPirFactory;
      if (installed) {
        factory = installed;
      } else {
        // The path is built at runtime so `tsc --noEmit` doesn't try to
        // resolve the .mjs module under web/public/wasm/ at type-check
        // time. The browser fetches it from /wasm/onionpir_client.mjs
        // (Vite serves the public/ tree verbatim); node tests install
        // a factory via `globalThis.__onionpirWasmFactory`.
        // A fully-resolved URL keeps Vite's dev server from treating this
        // public asset as source (`/wasm/...?...import`), while production
        // browsers still import the exact same static module.
        const wasmModuleUrl = new URL('/wasm/onionpir_client.mjs', globalThis.location.href).href;
        const mod = await import(/* @vite-ignore */ /* webpackIgnore: true */ wasmModuleUrl);
        factory = (mod as { default: OnionPirFactory }).default;
      }
      return await factory();
    })();
  }
  return wasmModulePromise;
}

// ─── Main-thread yield that bypasses background-tab timer throttling ─────
//
// In background/hidden tabs Chromium throttles `setTimeout(..., 0)` callbacks
// to ≥1000ms (sometimes tens of seconds), which turns a 150-iter generation
// loop into a multi-minute stall. `MessageChannel.postMessage` is scheduled as
// a task rather than a timer and is not subject to that throttling, giving us
// a stable ~sub-ms yield point in both foreground and background tabs.
function yieldToMain(): Promise<void> {
  return new Promise<void>(resolve => {
    const ch = new MessageChannel();
    ch.port1.onmessage = () => { ch.port1.close(); resolve(); };
    ch.port2.postMessage(null);
  });
}

// ─── Chunk cuckoo hash functions (BigInt for 64-bit precision) ────────────

function chunkDeriveCuckooKey(masterSeed: bigint, groupId: number, hashFn: number): bigint {
  return splitmix64(
    (masterSeed
      + ((BigInt(groupId) * 0x9e3779b97f4a7c15n) & MASK64)
      + ((BigInt(hashFn) * 0x517cc1b727220a95n) & MASK64)
    ) & MASK64
  );
}

function chunkCuckooHash(entryId: number, key: bigint, numBins: number): number {
  return Number(splitmix64((BigInt(entryId) ^ key) & MASK64) % BigInt(numBins));
}

// ─── Chunk reverse index: group → entry_ids (precomputed once) ────────────

let chunkReverseIndex: Map<number, number[]> | null = null;
let chunkReverseIndexTotalEntries = 0;

/**
 * Build reverse index mapping each chunk group to its entry_ids.
 * Single pass over all entries — 80× faster than per-group scanning.
 * Cached: only rebuilt if totalEntries changes.
 */
async function ensureChunkReverseIndex(
  totalEntries: number,
  onProgress?: (msg: string) => void,
): Promise<Map<number, number[]>> {
  if (chunkReverseIndex && chunkReverseIndexTotalEntries === totalEntries) {
    return chunkReverseIndex;
  }

  const index = new Map<number, number[]>();
  for (let g = 0; g < K_CHUNK; g++) {
    index.set(g, []);
  }

  for (let eid = 0; eid < totalEntries; eid++) {
    const groups = deriveChunkGroups(eid);
    for (const g of groups) {
      index.get(g)!.push(eid);
    }
    // Yield periodically — 815K iterations with BigInt hashing
    if (eid % 50000 === 49999) {
      onProgress?.(`Building chunk reverse index: ${eid + 1}/${totalEntries}...`);
      await yieldToMain();
    }
  }

  chunkReverseIndex = index;
  chunkReverseIndexTotalEntries = totalEntries;
  return index;
}

/**
 * Build the chunk cuckoo table for a specific group (deterministic).
 * Uses precomputed reverse index for the entry list, WASM for cuckoo insertion.
 */
function buildChunkCuckooForGroup(
  wasmModule: OnionPirModule,
  groupId: number,
  reverseIndex: Map<number, number[]>,
  binsPerTable: number,
  chunkMasterSeed: bigint,
): Uint32Array {
  const entries = reverseIndex.get(groupId) ?? [];
  // entries are already sorted since the reverse index is built in eid order

  // onionpir 2402b16's `buildCuckooBs1` embind wrapper expects the cuckoo
  // keys as a `Uint32Array` of `numHashes * 2` consecutive (lo32, hi32)
  // pairs — see wasm/hash_utils.cpp `hash_build_cuckoo_bs1_embind`. (The
  // pre-2402b16 WASM took a `Float64Array` of u64 bit-patterns; the fork
  // switched the key ABI to avoid double-precision loss.)
  const keys: bigint[] = [];
  for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
    keys.push(chunkDeriveCuckooKey(chunkMasterSeed, groupId, h));
  }
  return wasmModule.buildCuckooBs1(
    new Uint32Array(entries),
    packCuckooKeysU32(keys),
    binsPerTable,
  );
}

/**
 * Pack u64 cuckoo-hash keys into the `Uint32Array` layout the onionpir
 * 2402b16 `buildCuckooBs1` embind wrapper expects: `keys.length * 2`
 * elements, each key as a consecutive (lo32, hi32) pair.
 */
function packCuckooKeysU32(keys: bigint[]): Uint32Array {
  const out = new Uint32Array(keys.length * 2);
  for (let i = 0; i < keys.length; i++) {
    out[i * 2] = Number(keys[i] & 0xFFFFFFFFn);
    out[i * 2 + 1] = Number((keys[i] >> 32n) & 0xFFFFFFFFn);
  }
  return out;
}

function findEntryInCuckoo(
  table: Uint32Array,
  entryId: number,
  keys: bigint[],
  binsPerTable: number,
): number | null {
  for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
    const bin = chunkCuckooHash(entryId, keys[h], binsPerTable);
    if (table[bin] === entryId) return bin;
  }
  return null;
}

// ─── PBC batch placement (uses shared pbc.ts) ───────────────────────────────

function planPbcRounds(
  candidateGroups: number[][],
  k: number,
): [number, number][][] {
  return planRounds(candidateGroups, k, NUM_HASHES);
}

// DummyRng imported from codec.ts

// ─── Wire protocol helpers ────────────────────────────────────────────────

function encodeRegisterKeys(galoisKeys: Uint8Array, gswKeys: Uint8Array, dbId: number = 0): Uint8Array {
  // Trailing db_id byte: only appended when non-zero for backward compatibility.
  const trailing = dbId !== 0 ? 1 : 0;
  const payloadLen = 1 + 4 + galoisKeys.length + 4 + gswKeys.length + trailing;
  const msg = new Uint8Array(4 + payloadLen);
  const dv = new DataView(msg.buffer);
  dv.setUint32(0, payloadLen, true);
  let pos = 4;
  msg[pos++] = REQ_REGISTER_KEYS;
  dv.setUint32(pos, galoisKeys.length, true); pos += 4;
  msg.set(galoisKeys, pos); pos += galoisKeys.length;
  dv.setUint32(pos, gswKeys.length, true); pos += 4;
  msg.set(gswKeys, pos); pos += gswKeys.length;
  if (dbId !== 0) {
    msg[pos] = dbId & 0xFF;
  }
  return msg;
}

function encodeBatchQuery(variant: number, roundId: number, queries: Uint8Array[], dbId: number = 0): Uint8Array {
  let payloadSize = 1 + 2 + 1; // variant + round_id + num_groups
  for (const q of queries) payloadSize += 4 + q.length;
  // Trailing db_id byte: only appended when non-zero for backward compatibility.
  if (dbId !== 0) payloadSize += 1;
  const msg = new Uint8Array(4 + payloadSize);
  const dv = new DataView(msg.buffer);
  dv.setUint32(0, payloadSize, true);
  let pos = 4;
  msg[pos++] = variant;
  dv.setUint16(pos, roundId, true); pos += 2;
  msg[pos++] = queries.length;
  for (const q of queries) {
    dv.setUint32(pos, q.length, true); pos += 4;
    msg.set(q, pos); pos += q.length;
  }
  if (dbId !== 0) {
    msg[pos] = dbId & 0xFF;
  }
  return msg;
}

/** Validate one exact length-prefixed response record and return its payload. */
export function responsePayloadFromFrame(frame: Uint8Array, expectedVariant?: number): Uint8Array {
  if (frame.length < 5) {
    throw new Error(`Response frame too short: ${frame.length} bytes`);
  }
  const declared = new DataView(frame.buffer, frame.byteOffset, frame.byteLength)
    .getUint32(0, true);
  if (declared !== frame.length - 4) {
    throw new Error(
      `Response frame length mismatch: declared ${declared}, got ${frame.length - 4}`,
    );
  }
  const payload = frame.slice(4);
  if (expectedVariant !== undefined && payload[0] !== expectedVariant) {
    throw new Error(
      `Unexpected response variant: expected 0x${expectedVariant.toString(16)}, ` +
      `got 0x${(payload[0] ?? 0).toString(16)}`,
    );
  }
  return payload;
}

export function decodeBatchResult(
  data: Uint8Array,
  pos: number,
  expectedRoundId: number,
  expectedGroups: number,
): { roundId: number; results: Uint8Array[]; pos: number } {
  if (pos < 0 || pos + 3 > data.length) {
    throw new Error('OnionPIR batch response header truncated');
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const roundId = dv.getUint16(pos, true); pos += 2;
  const numGroups = data[pos++];
  if (roundId !== expectedRoundId) {
    throw new Error(
      `OnionPIR batch response round mismatch: expected ${expectedRoundId}, got ${roundId}`,
    );
  }
  if (numGroups !== expectedGroups) {
    throw new Error(
      `OnionPIR batch response group count mismatch: expected ${expectedGroups}, got ${numGroups}`,
    );
  }
  const results: Uint8Array[] = [];
  for (let i = 0; i < numGroups; i++) {
    if (pos + 4 > data.length) {
      throw new Error(`OnionPIR batch response truncated before group ${i} length`);
    }
    const len = dv.getUint32(pos, true); pos += 4;
    if (pos + len > data.length) {
      throw new Error(
        `OnionPIR batch response group ${i} truncated: claimed ${len}, have ${data.length - pos}`,
      );
    }
    results.push(data.slice(pos, pos + len));
    pos += len;
  }
  if (pos !== data.length) {
    throw new Error(`OnionPIR batch response has ${data.length - pos} trailing bytes`);
  }
  return { roundId, results, pos };
}

// ─── Per-group OnionPIR Merkle: tree-top blob + trust anchor ──────────────
//
// SOUNDNESS-CRITICAL module section — the standalone-TS mirror of the Rust
// verifier `crates/sdk/client/src/onion_merkle.rs` (Phase 3d, commit 79e422b4).
//
// Since the Phase-3 per-group redesign (see docs/plans/README.md /
// MERKLE_COLOCATION_REVIEW.md §2-§6) OnionPIR has one independent
// arity-`arity` Merkle tree per PBC group — 75 INDEX trees + 80 DATA trees
// — anchored by a single `super_root` = SHA256 of the 155 concatenated
// per-group roots. The old flat per-table trees, and the gid-cuckoo +
// `planRounds`-over-gids sibling machinery they needed, are gone.
//
// The 155 per-group roots ride in the *untrusted*, server-supplied tree-top
// blob. They are checked against the verified database proof's
// `onion_super_root` when there is one, else against the advertised
// `server-info.super_root`. `checkTreeTopAnchor` is the load-bearing binding
// check. Skip or weaken it
// and a malicious server can fabricate a self-consistent blob + sibling
// responses, and every leaf "verifies" against forged roots.

/**
 * One parsed per-group Merkle tree-top. `levels[0]` is the first cached
 * level (the level-1 nodes — the leaf level is the single PIR sibling
 * level and is never cached); `levels[last]` is `[root]`. Mirrors the
 * Rust `OnionTreeTopCache`.
 */
interface OnionTreeTopCache {
  cacheFromLevel: number;
  arity: number;
  levels: Uint8Array[][];
}

/** The per-group root = the single hash in the last cached level. */
function onionTreeTopRoot(top: OnionTreeTopCache): Uint8Array | null {
  const last = top.levels[top.levels.length - 1];
  return last && last.length > 0 ? last[0] : null;
}

/** Constant-length byte-array equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Parse the consolidated 155-tree tree-top blob `merkle_onion_tree_tops.bin`.
 * Mirrors the Rust `parse_onion_tree_top_cache`.
 *
 * The whole blob is served on either TREE_TOP opcode (0x54 / 0x56); the
 * caller parses all 155 trees — 75 INDEX trees first, then 80 DATA trees
 * (the order `gen_4_build_merkle_onion` writes them).
 *
 * Wire format:
 * ```text
 * [4B num_trees LE]
 * per tree:
 *   [1B cache_from_level][4B total_nodes LE][2B arity LE][1B num_cached_levels]
 *   per cached level: [4B num_nodes LE][num_nodes × 32B hashes]
 * ```
 *
 * Throws on truncation / arity=0 — SOUNDNESS-CRITICAL: a malformed blob
 * must abort verification, never silently parse as garbage.
 */
function parseOnionTreeTopCache(data: Uint8Array): OnionTreeTopCache[] {
  if (data.length < 4) {
    throw new Error('onionpir tree-tops blob too short (need 4B num_trees)');
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const numTrees = dv.getUint32(0, true);
  let off = 4;
  const out: OnionTreeTopCache[] = [];

  for (let t = 0; t < numTrees; t++) {
    if (off + 8 > data.length) {
      throw new Error(`onionpir tree-tops: truncated header for tree ${t}`);
    }
    const cacheFromLevel = data[off]; off += 1;
    off += 4; // total_nodes — informational, ignored
    const arity = dv.getUint16(off, true); off += 2;
    const numLevels = data[off]; off += 1;
    if (arity === 0) {
      throw new Error(`onionpir tree-tops: tree ${t} has arity=0`);
    }

    const levels: Uint8Array[][] = [];
    for (let l = 0; l < numLevels; l++) {
      if (off + 4 > data.length) {
        throw new Error(
          `onionpir tree-tops: truncated level-${l} count for tree ${t}`,
        );
      }
      const n = dv.getUint32(off, true); off += 4;
      if (off + n * 32 > data.length) {
        throw new Error(
          `onionpir tree-tops: truncated hashes for tree ${t} level ${l}`,
        );
      }
      const nodes: Uint8Array[] = [];
      for (let i = 0; i < n; i++) {
        nodes.push(data.slice(off, off + 32));
        off += 32;
      }
      levels.push(nodes);
    }
    out.push({ cacheFromLevel, arity, levels });
  }
  if (off !== data.length) {
    throw new Error(`onionpir tree-tops blob has ${data.length - off} trailing bytes`);
  }
  return out;
}

/**
 * Bind the fetched 155-tree tree-top blob to the pinned `super_root`.
 *
 * **SOUNDNESS-CRITICAL** — mirrors the Rust `check_tree_top_anchor`. The
 * 155 per-group roots ride in the (untrusted, server-supplied) blob;
 * `info.super_root` is the pinned anchor. If this check is skipped or
 * weakened, a malicious server can fabricate a self-consistent tree-top
 * blob + sibling responses and every leaf "verifies" against forged roots.
 *
 * Returns true iff all four checks pass:
 *  1. the blob has exactly `index.k + data.k` trees;
 *  2. the blob length + SHA256 match the JSON-declared `tree_tops_size` /
 *     `tree_tops_hash` (integrity — clearer diagnostic on corruption);
 *  3. every per-tree arity matches the JSON `arity` (build/JSON drift);
 *  4. **SHA256(concat of the 155 per-group roots) == super_root** — the
 *     load-bearing cryptographic anchor check.
 */
function checkTreeTopAnchor(
  info: OnionPirMerkleInfoJson,
  blob: Uint8Array,
  allTops: OnionTreeTopCache[],
  logErr: (msg: string) => void,
): boolean {
  const expectedTrees = info.index.k + info.data.k;
  if (allTops.length !== expectedTrees) {
    logErr(
      `[PIR-AUDIT] OnionPIR Merkle: tree-top blob has ${allTops.length} ` +
      `trees, expected ${expectedTrees} (index_k=${info.index.k} + ` +
      `data_k=${info.data.k}) — REJECTING ALL LEAVES`,
    );
    return false;
  }

  // Integrity: blob size + hash vs the JSON-declared values.
  if (blob.length !== info.tree_tops_size) {
    logErr(
      `[PIR-AUDIT] OnionPIR Merkle: tree-top blob is ${blob.length} B, ` +
      `JSON declared tree_tops_size=${info.tree_tops_size} — ` +
      `REJECTING ALL LEAVES`,
    );
    return false;
  }
  if (!bytesEqual(sha256(blob), hexToBytes(info.tree_tops_hash))) {
    logErr(
      '[PIR-AUDIT] OnionPIR Merkle: tree-top blob hash != JSON ' +
      'tree_tops_hash — REJECTING ALL LEAVES (blob corrupt or server lied)',
    );
    return false;
  }

  // Per-tree arity must match the JSON arity (build/JSON drift guard).
  for (let t = 0; t < allTops.length; t++) {
    if (allTops[t].arity !== info.arity) {
      logErr(
        `[PIR-AUDIT] OnionPIR Merkle: tree ${t} arity ${allTops[t].arity} ` +
        `!= JSON arity ${info.arity} — REJECTING ALL LEAVES`,
      );
      return false;
    }
  }

  // SOUNDNESS-CRITICAL: the 155 per-group roots must hash to super_root.
  const preimage = new Uint8Array(allTops.length * 32);
  for (let t = 0; t < allTops.length; t++) {
    const r = onionTreeTopRoot(allTops[t]);
    if (!r) {
      logErr(
        `[PIR-AUDIT] OnionPIR Merkle: tree-top ${t} has no root level — ` +
        'REJECTING ALL LEAVES',
      );
      return false;
    }
    preimage.set(r, t * 32);
  }
  if (!bytesEqual(sha256(preimage), hexToBytes(info.super_root))) {
    logErr(
      `[PIR-AUDIT] OnionPIR Merkle: SUPER-ROOT MISMATCH — computed from ` +
      `${allTops.length} per-group roots != pinned anchor — ` +
      'REJECTING ALL LEAVES (blob corrupt or server lied)',
    );
    return false;
  }
  return true;
}

/**
 * Walk a per-group tree-top from a reconstructed level-1 node up to the
 * group root. Mirrors the Rust `walk_tree_top_to_root`.
 *
 * `startHash` is the hash of the level-1 node the FHE sibling pass
 * reconstructed; `startIdx` is its index within that level. At each step
 * the running hash replaces the child at `idx % arity` of its parent (the
 * rest read from the cached level), the parent is recomputed, and `idx`
 * advances. Returns the reconstructed root.
 */
function walkTreeTopToRoot(
  startHash: Uint8Array,
  startIdx: number,
  top: OnionTreeTopCache,
  arity: number,
): Uint8Array {
  let hash = startHash;
  let idx = startIdx;
  // Walk every cached level except the last (which IS the root).
  for (let ci = 0; ci < top.levels.length - 1; ci++) {
    const levelNodes = top.levels[ci];
    const parentStart = Math.floor(idx / arity) * arity;
    const childPos = idx % arity;
    const children: Uint8Array[] = [];
    for (let c = 0; c < arity; c++) {
      const nodeI = parentStart + c;
      if (c === childPos) children.push(hash);
      else if (nodeI < levelNodes.length) children.push(levelNodes[nodeI]);
      else children.push(ZERO_HASH);
    }
    hash = computeParentN(children);
    idx = Math.floor(idx / arity);
  }
  return hash;
}

// ─── Client config ────────────────────────────────────────────────────────

export interface OnionPirClientConfig {
  serverUrl: string;
  /** Upgrade to the encrypted channel after attesting (default `true`). */
  useSecureChannel?: boolean;
  /** `undefined` uses the Turin ARK; `null` skips the VCEK chain check. */
  expectedArkFingerprint?: Uint8Array | null;
  expectedServerPin?: ServerAttestPin;
  /** Operator key; the announce bundle is checked when it is set. */
  pinnedOperatorPubkey?: Uint8Array;
  maxAnnounceAgeSeconds?: number;
  onAttestation?: (status: ServerAttestation) => void;
  onOperatorIdentity?: (status: OperatorIdentity) => void;
  /**
   * Credits (`docs/CREDITS.md`): called with the number of credits the next
   * frame needs whenever the connection's balance runs short; return a
   * presentation or `null`. Only used where the server charges for
   * OnionPIR. Outcomes arrive via `onCredits`.
   */
  creditProvider?: CreditProvider;
  onCredits?: (status: CreditEnablement) => void;
  /**
   * Operator-issued API key (docs/CREDITS.md "API keys"), presented once the
   * secure channel is open. When the server accepts it the connection is
   * unmetered and credits are not enabled; the outcome arrives via
   * `onCredits` as `api-key` or `error`.
   */
  apiKey?: string;
  databaseProofPins?: readonly DatabaseProofPin[];
  onDatabaseProof?: (dbId: number, status: DatabaseProofStatus) => void;
  onConnectionStateChange?: (state: ConnectionState, message?: string) => void;
  onLog?: (message: string, level: 'info' | 'success' | 'error') => void;
}

// ─── CHUNK Round-Presence Symmetry: per-slot classifier ───────────────────
//
// Mirrors the Rust helper `classify_chunk_slots` in
// `crates/sdk/client/src/onion.rs`. Pure (no side effects, no RNG, no DOM
// access) so it can be exercised by unit tests in node without
// instantiating the WASM module.
//
// CHUNK Round-Presence Symmetry (CLAUDE.md): every per-query slot
// produces exactly one action — `AppendReal` if the INDEX scan
// returned a non-whale match, `AppendDummy` otherwise (not-found or
// whale). The pre-fix bug skipped not-found / whale slots entirely,
// so CHUNK round count was a binary side channel for found vs
// not-found. The classifier captures the structural fix: the
// per-slot action list has length equal to the input list, with no
// "skip" branch.

/**
 * Per-slot input shape — projection of the relevant fields of the
 * IndexResult-like objects produced by the INDEX scan loop. Used by
 * the classifier; the OnionPirWebClient also emits this shape when
 * delegating to `classifyChunkSlots`.
 */
export interface ChunkSlotInput {
  entryId: number;
  numEntries: number;
}

/**
 * Per-slot action emitted by the classifier. The `queryBatch` chunk
 * loop dispatches on this discriminator: `append_real` adds
 * `numEntries` real entry_ids to the unique-fetch list,
 * `append_dummy` injects one uniformly random dummy entry_id (with
 * up to 32 dedup retries).
 */
export type ChunkSlotAction =
  | { kind: 'append_real'; entryId: number; numEntries: number }
  | { kind: 'append_dummy' };

/**
 * Classify each per-query slot for the OnionPIR CHUNK round.
 *
 * Postconditions (verified by the unit tests in
 * `web/src/__tests__/onion_chunk_slot_classifier.test.ts`):
 *
 * - **P1** (round-count uniformity) — `result.length === slots.length`.
 *   Combined with the call-site loop in `queryBatch`, this gives
 *   `uniqueEntryIds.length >= slots.length` (modulo dedup
 *   collisions on the dummy path, probabilistically negligible).
 * - **P2** (no-skip) — every slot maps to either `append_real` or
 *   `append_dummy`. There is no third "skip" branch — the pre-fix
 *   bug.
 *
 * Mirrors `classify_chunk_slots` in `crates/sdk/client/src/onion.rs`.
 * Cross-language consistency is enforced by the cross-language diff
 * test (`onion_leakage_diff.test.ts`) — same RoundProfile shape on
 * the wire requires same per-slot decisions here.
 */
export function classifyChunkSlots(slots: readonly ChunkSlotInput[]): ChunkSlotAction[] {
  return slots.map((s) => {
    if (s.numEntries > 0) {
      return { kind: 'append_real' as const, entryId: s.entryId, numEntries: s.numEntries };
    }
    return { kind: 'append_dummy' as const };
  });
}

/**
 * Pure model of the per-slot classify-then-dedup logic, parameterised on
 * the dummy source so it's deterministic under test.
 *
 * This is a test-friendly analog, not a byte-for-byte mirror of the
 * production CHUNK path. Production `queryBatch` collects only the *real*
 * chunk entry_ids into its `uniqueEntryIds` list (an all-not-found batch
 * yields an empty list and substitutes the `[[]]` empty round); the
 * K_CHUNK dummy padding is then injected later, per group, as random
 * cuckoo *bin indices* drawn from `this.rng` (a `DummyRng` seeded from
 * `splitmix64(Date.now())`), and every query — real or dummy — is
 * FHE-encrypted via `generateQuery`. The bin-index RNG is NOT a privacy
 * boundary: SEAL re-randomises each ciphertext with its own CSPRNG, so a
 * dummy query is computationally unlinkable to its bin index regardless
 * of how that index was chosen. This helper instead takes an explicit
 * `dummyGen` so the dedup behaviour can be exercised without SEAL.
 *
 * **Returns** `{ unique, dummiesAdded }` where `unique` is the
 * deduplicated entry_id list and `dummiesAdded` is the count of
 * successful dummy appends.
 *
 * **Property** verified by tests: when the dummy generator yields
 * fresh values (no dedup collisions), `unique.length === slots.length`
 * for any input — every slot contributes one entry, real or dummy.
 */
export function selectChunkUniqueFetches(
  slots: readonly ChunkSlotInput[],
  dummyGen: () => number,
): { unique: number[]; dummiesAdded: number } {
  const actions = classifyChunkSlots(slots);
  const unique: number[] = [];
  const seen = new Set<number>();
  let dummiesAdded = 0;

  for (const action of actions) {
    if (action.kind === 'append_real') {
      for (let i = 0; i < action.numEntries; i++) {
        const eid = action.entryId + i;
        if (!seen.has(eid)) {
          seen.add(eid);
          unique.push(eid);
        }
      }
    } else {
      // Up to 32 retries to dodge dedup collisions — same bound as
      // the production code.
      for (let attempt = 0; attempt < 32; attempt++) {
        const cand = dummyGen();
        if (!seen.has(cand)) {
          seen.add(cand);
          unique.push(cand);
          dummiesAdded++;
          break;
        }
      }
    }
  }

  return { unique, dummiesAdded };
}

// ─── Client class ─────────────────────────────────────────────────────────

/** One connection's FHE keys, registered per database on first use (the
 * server keeps one key set per connection). Mirrors the Rust `FheState`. */
interface FheKeys {
  clientId: number;
  secretKey: Uint8Array;
  galoisKeys: Uint8Array;
  gswKeys: Uint8Array;
}

export class OnionPirWebClient {
  private ws: ManagedWebSocket | null = null;
  private secureChannel: WasmStandaloneSecureChannelV1 | null = null;
  /** Funds metered frames when the server requires credits (docs/CREDITS.md). */
  private credited: CreditedChannel | null = null;
  private config: OnionPirClientConfig;
  private connectionState: ConnectionState = 'disconnected';
  private rng = new DummyRng();

  // Server info (fetched via JSON)
  private serverInfo: ServerInfoJson | null = null;
  private indexK = 0;
  private chunkK = 0;
  private indexBins = 0;
  private chunkBins = 0;
  private tagSeed = 0n;
  private indexMasterSeed = MASTER_SEED;
  private chunkMasterSeed = CHUNK_MASTER_SEED;
  private totalPacked = 0;
  private indexSlotsPerBin = 0;
  private indexSlotSize = 0;

  // WASM module
  private wasmModule: OnionPirModule | null = null;

  private fhe: FheKeys | null = null;
  /** Databases this connection has registered `fhe` for. */
  private registeredDbs: Set<number> = new Set();

  // Active database ID (0 = main). Switch with setDbId().
  private dbId: number = 0;

  // Database catalog (populated after connect). Used by the UI selector.
  private catalog: DatabaseCatalog | null = null;

  /** Onion super-roots of verified database proofs, by dbId. */
  private provenRoots = new Map<number, string>();
  private databaseProofStatuses = new Map<number, DatabaseProofStatus>();
  attestation: ServerAttestation = { state: 'unattested' };
  operatorIdentity: OperatorIdentity = { state: 'not-checked' };

  // Test hook: one-shot override of the computed scripthashes for the next
  // queryBatch() call. Consumed on use and then cleared. Used by harnesses
  // that need to drive a query at a specific scripthash without reversing
  // HASH160. Production UI never sets this.
  private _scriptHashOverride: Uint8Array[] | undefined = undefined;

  // Optional leakage recorder. When installed, every transport-level
  // roundtrip emits a structured `RoundProfile` matching what the Rust
  // `OnionClient` emits — see docs/VERIFICATION_OVERVIEW.md
  // diff-tests Rust against TS using these profiles. `null` = no
  // recording (zero overhead in the no-recorder case).
  private leakageRecorder: LeakageRecorder | null = null;

  /**
   * Set a one-shot scripthash override for the NEXT queryBatch call.
   * The override[] replaces the computed scripthashes 1:1 (same length).
   * Cleared after consumption.
   */
  setScriptHashOverrideForNextQuery(hashes: Uint8Array[]): void {
    this._scriptHashOverride = hashes;
  }

  constructor(config: OnionPirClientConfig) {
    this.config = config;
  }

  /** Drop everything tied to the current connection. */
  private resetSession(): void {
    this.credited = null;
    this.secureChannel?.free();
    this.secureChannel = null;
    this.fhe = null;
    this.registeredDbs.clear();
    this.provenRoots.clear();
    this.databaseProofStatuses.clear();
    this.catalog = null;
    this.serverInfo = null;
    this.attestation = { state: 'unattested' };
    this.operatorIdentity = { state: 'not-checked' };
  }

  private catalogToSdkHandle(): any {
    if (!this.catalog) throw new Error('Database catalog unavailable');
    const json = {
      databases: this.catalog.databases.map((db) => ({
        dbId: db.dbId,
        dbType: db.dbType,
        name: db.name,
        baseHeight: db.baseHeight,
        height: db.height,
        indexBins: db.indexBinsPerTable,
        chunkBins: db.chunkBinsPerTable,
        indexK: db.indexK,
        chunkK: db.chunkK,
        tagSeed: `0x${db.tagSeed.toString(16)}`,
        dpfNIndex: db.dpfNIndex,
        dpfNChunk: db.dpfNChunk,
        hasBucketMerkle: db.hasBucketMerkle,
        indexMasterSeed: `0x${db.indexMasterSeed.toString(16)}`,
        chunkMasterSeed: `0x${db.chunkMasterSeed.toString(16)}`,
        anchorKind: db.anchorKind,
        anchorHex: db.anchorHex,
      })),
    };
    return requireSdkWasm().WasmDatabaseCatalog.fromJson(json);
  }

  getDatabaseProofStatus(dbId: number): DatabaseProofStatus | undefined {
    return this.databaseProofStatuses.get(dbId);
  }

  /**
   * Install (or replace) a leakage recorder. Pass `null` to uninstall.
   * Mirrors `OnionClient::set_leakage_recorder` on the Rust side — same
   * trait shape, same `server_id = 0` (single-server) convention. Used
   * by the cross-language diff harness in Phase 2.3.
   */
  setLeakageRecorder(recorder: LeakageRecorder | null): void {
    this.leakageRecorder = recorder;
  }

  /** Internal: emit a `RoundProfile` to the installed recorder, if any. */
  private recordRound(round: RoundProfile): void {
    this.leakageRecorder?.recordRound('onion', round);
  }

  /** Return the currently active database ID (0 = main). */
  getDbId(): number { return this.dbId; }

  /** Switch to a different database (updates the BFV parameters). */
  setDbId(newDbId: number): void {
    if (newDbId === this.dbId) return;
    const oldDbId = this.dbId;
    this.dbId = newDbId;
    this.updateParamsForActiveDb();
    this.log(`Switched dbId=${oldDbId} -> dbId=${newDbId} (bins=${this.indexBins}/${this.chunkBins})`);
  }

  /** Return the parsed database catalog (fetched after connect). */
  getCatalog(): DatabaseCatalog | null { return this.catalog; }

  /** Internal: resolve per-DB OnionPIR params from serverInfo. */
  private getOnionPirForDb(dbId: number) {
    if (dbId === 0) return this.serverInfo?.onionpir;
    return this.serverInfo?.databases?.find(d => d.db_id === dbId)?.onionpir;
  }

  /** Internal: resolve per-DB OnionPIR Merkle info from serverInfo. */
  private getOnionPirMerkleForDb(dbId: number): OnionPirMerkleInfoJson | undefined {
    if (dbId === 0) return this.serverInfo?.onionpir_merkle;
    return this.serverInfo?.databases?.find(d => d.db_id === dbId)?.onionpir_merkle;
  }

  /**
   * Re-populate BFV params (indexBins, chunkBins, tagSeed, etc.) from the
   * active database's info, falling back to the main database's.
   */
  private updateParamsForActiveDb(): void {
    const opi = this.getOnionPirForDb(this.dbId) ?? this.serverInfo?.onionpir;
    if (!opi) return;
    // Some servers report absent master seeds as 0 in the per-DB info; the
    // catalog carries the chain-derived seeds.
    const entry = this.catalog?.databases.find((db) => db.dbId === this.dbId);
    this.indexK = opi.index_k;
    this.chunkK = opi.chunk_k;
    this.indexBins = opi.index_bins_per_table;
    this.chunkBins = opi.chunk_bins_per_table;
    this.tagSeed = opi.tag_seed;
    this.indexMasterSeed = opi.index_master_seed || entry?.indexMasterSeed || MASTER_SEED;
    this.chunkMasterSeed = opi.chunk_master_seed || entry?.chunkMasterSeed || CHUNK_MASTER_SEED;
    this.totalPacked = opi.total_packed_entries;
    this.indexSlotsPerBin = opi.index_slots_per_bin;
    this.indexSlotSize = opi.index_slot_size;
  }

  /**
   * Whether this database has per-group OnionPIR Merkle data. A missing or
   * malformed `super_root` means no verification rather than verifying
   * against a zero anchor (mirrors the Rust `parse_onionpir_merkle`).
   */
  hasMerkleForDb(dbId: number): boolean {
    const info = this.getOnionPirMerkleForDb(dbId);
    return !!(
      info &&
      info.arity > 0 &&
      /^[0-9a-f]{64}$/.test(info.super_root) &&
      info.index?.k > 0 &&
      info.data?.k > 0
    );
  }

  /** The Merkle root queries on `dbId` are verified against: the verified
   * database proof's root when there is one, else the advertised root. */
  getMerkleRootHexForDb(dbId: number): string | undefined {
    return this.provenRoots.get(dbId) ?? this.getOnionPirMerkleForDb(dbId)?.super_root;
  }

  private log(message: string, level: 'info' | 'success' | 'error' = 'info'): void {
    this.config.onLog?.(message, level);
    console.log(`[OnionPIR] ${message}`);
  }

  private setState(state: ConnectionState, msg?: string): void {
    this.connectionState = state;
    this.config.onConnectionStateChange?.(state, msg);
  }

  getConnectionState(): ConnectionState { return this.connectionState; }
  isConnected(): boolean { return this.ws?.isOpen() ?? false; }

  // ─── Connection (delegates to shared ws.ts) ───────────────────────────

  /** Connect, attest, open the encrypted channel, fetch the catalog and check
   * the pinned database proofs. Each check's outcome goes to its callback. */
  async connect(): Promise<void> {
    if (this.ws) this.disconnect();
    this.setState('connecting', 'Loading WASM + connecting...');
    this.wasmModule = await loadWasmModule();
    this.log('WASM module loaded');

    const socket = new ManagedWebSocket({
      url: this.config.serverUrl,
      label: 'onionpir',
      onLog: (msg, level) => this.log(msg, level),
      onClose: () => {
        if (this.ws !== socket) return;
        this.ws = null;
        this.resetSession();
        this.setState('disconnected');
      },
    });
    this.ws = socket;

    try {
      await socket.connect();
      if (this.config.useSecureChannel !== false) await this.attestAndUpgrade(socket);
      await this.fetchServerInfo();
      await verifyDatabaseProofs(this, this.config.databaseProofPins ?? [], (dbId, status) => {
        this.databaseProofStatuses.set(dbId, status);
        this.config.onDatabaseProof?.(dbId, status);
      });
      this.setState('connected', 'Connected');
      this.log('Connected to server', 'success');
    } catch (error) {
      if (this.ws === socket) {
        this.ws = null;
        this.resetSession();
        this.setState('disconnected', 'Connection failed');
      }
      socket.disconnect();
      throw error;
    }
  }

  disconnect(): void {
    const socket = this.ws;
    this.ws = null;
    this.resetSession();
    socket?.disconnect();
    this.setState('disconnected', 'Disconnected');
  }

  // ─── Raw send/receive (delegates to shared ws.ts) ─────────────────────

  /** One round trip, funded first when the server requires credits. */
  private sendRaw(msg: Uint8Array): Promise<Uint8Array> {
    if (!this.ws) throw new Error('Not connected');
    return this.credited ? this.credited.roundtrip(msg) : this.ws.sendRaw(msg);
  }

  /**
   * Read the server's credits flags and, when it requires credits, route
   * every metered frame through a `CreditedChannel` fed by
   * `config.creditProvider`. Never throws; the outcome goes to `onCredits`.
   */
  private async enableCredits(socket: ManagedWebSocket): Promise<void> {
    const apiKey = this.config.apiKey?.trim();
    if (apiKey) {
      let outcome: CreditEnablement;
      try {
        parseApiKeyResponsePayload((await socket.sendRaw(encodeApiKeyFrame(apiKey))).subarray(4));
        outcome = { state: 'api-key' };
        this.log('OnionPIR: API key accepted; this connection is unmetered', 'info');
      } catch (error) {
        outcome = { state: 'error', error: (error as Error)?.message ?? String(error) };
        this.log(`OnionPIR: API key refused — ${outcome.error}`, 'error');
      }
      this.config.onCredits?.(outcome);
      return;
    }
    const provider = this.config.creditProvider;
    if (!provider) return;
    let outcome: CreditEnablement;
    try {
      const info = await fetchServerInfoJson(socket);
      const access = resolveAccess(info.credits, 'onion');
      if (access.mode === 'free') {
        outcome = { state: info.credits?.enabled ? 'not-required' : 'not-enabled' };
      } else {
        const card = serverGasCardFromInfo(info);
        if (!card) throw new Error('server meters frames but publishes no gas card');
        if (this.ws !== socket) return;
        this.credited = new CreditedChannel(
          card,
          provider,
          (frame) => socket.sendRaw(frame),
          access,
          info.credits?.enabled === true,
        );
        outcome = { state: access.mode === 'paid' ? 'required' : 'best-effort' };
      }
    } catch (error) {
      outcome = { state: 'error', error: (error as Error)?.message ?? String(error) };
    }
    if (outcome.state === 'required') {
      this.log('OnionPIR: credits required here; metered frames are funded from the wallet', 'info');
    } else if (outcome.state === 'best-effort') {
      this.log('OnionPIR: free while the server has room; paid from the wallet only when it is busy', 'info');
    } else if (outcome.state === 'error') {
      this.log(`OnionPIR: credits could not be enabled — ${outcome.error}`, 'error');
    }
    this.config.onCredits?.(outcome);
  }

  /** Attest the server, upgrade this socket to the encrypted channel when the
   * server has a channel key, then check the operator identity (when a key is
   * pinned) and enable credits. Outcomes go to the callbacks. */
  private async attestAndUpgrade(socket: ManagedWebSocket): Promise<void> {
    const channel = new (requireSdkWasm().WasmStandaloneSecureChannelV1)();
    let att: WasmAttestVerification | null = null;
    try {
      try {
        att = channel.verifyAttestation(await socket.sendRaw(channel.attestRequest()));
      } catch (error) {
        this.log(`OnionPIR attest failed: ${(error as Error)?.message ?? String(error)}`, 'error');
      }
      this.attestation = summariseAttestation(
        att,
        this.config.expectedServerPin,
        arkFingerprint(this.config.expectedArkFingerprint),
      );
      this.config.onAttestation?.(this.attestation);
      if (!att || att.serverStaticPub.every((byte) => byte === 0)) {
        this.log('OnionPIR channel left in cleartext: no channel key', 'info');
        return;
      }

      channel.completeHandshake(await socket.sendRaw(channel.handshakeRequest()), att.serverStaticPub);
      socket.setFrameCodec({
        encode: (frame) => channel.sealFrame(frame),
        decode: (frame) => channel.openFrame(frame),
      });
      this.secureChannel = channel;
      this.log('OnionPIR same-socket secure channel established', 'success');

      if (this.config.pinnedOperatorPubkey) {
        this.operatorIdentity = await checkOperatorIdentity(
          () => this.announce(),
          att,
          this.config.pinnedOperatorPubkey,
          this.config.maxAnnounceAgeSeconds ?? 0,
        );
        this.config.onOperatorIdentity?.(this.operatorIdentity);
      }
      await this.enableCredits(socket);
    } finally {
      if (this.secureChannel !== channel) channel.free();
      att?.free();
    }
  }

  // ─── Operator-signed identity (REQ_ANNOUNCE) ──────────────────────────

  /**
   * Fetch + verify this server's operator-signed identity bundle.
   * Reuses the audited Rust parsing + in-bundle chain check via the WASM
   * `verifyAnnounceResponse` binding (SEAL doesn't compile to wasm32, but
   * Ed25519 verification does). Layer operator-pubkey pinning on the
   * result with `v.checkPinnedOperator(pinnedOperatorPubkey, nowSecs)`.
   *
   * Throws on a server `RESP_ERROR` (e.g. "announce not configured" when
   * the server lacks `--identity-*`) or a wire-format error.
   */
  async announce(): Promise<WasmAnnounceVerification> {
    if (!this.ws) throw new Error('Not connected');
    // REQ_ANNOUNCE (0x07), empty body. Frame: [u32 LE payloadLen=1][opcode].
    const msg = new Uint8Array(5);
    new DataView(msg.buffer).setUint32(0, 1, true);
    msg[4] = REQ_ANNOUNCE;
    const resp = await this.sendRaw(msg);
    return requireSdkWasm().verifyAnnounceResponse(
      responsePayloadFromFrame(resp),
    );
  }

  /** Fetch and verify one v2 DB proof. */
  async verifyDatabaseProof(
    dbId: number,
    expectedParamsHashHex?: string | null,
    allowedBuilderBinarySha256Hex?: string | null,
    allowedBuilderGitCommit?: string | null,
  ): Promise<WasmDatabaseProof> {
    const request = databaseProofV2Request(dbId);
    const response = await this.sendRaw(request);
    this.recordRound({
      kind: 'info',
      server_id: 0,
      db_id: dbId,
      request_bytes: request.length,
      response_bytes: response.length,
      items: [],
    });
    const catalogHandle = this.catalogToSdkHandle();
    try {
      return requireSdkWasm().verifyDatabaseProofV2Response(
        response,
        catalogHandle,
        dbId,
        expectedParamsHashHex,
        allowedBuilderBinarySha256Hex,
        allowedBuilderGitCommit,
      );
    } finally {
      catalogHandle.free();
    }
  }

  /** Take a pin-matched v2 proof's Onion root as the database's Merkle root.
   * Throws, consuming `proof`, when the proof's layout does not match the
   * server's query metadata. */
  installVerifiedDatabaseProof(proof: WasmDatabaseProof): void {
    try {
      const catalogEntry = this.catalog?.databases.find((db) => db.dbId === proof.dbId);
      const advertised = this.getOnionPirForDb(proof.dbId);
      const merkle = this.getOnionPirMerkleForDb(proof.dbId);
      if (!catalogEntry || !advertised || !merkle) {
        throw new Error(`OnionPIR install has no catalog/query/Merkle entry for db ${proof.dbId}`);
      }
      const typed = {
        totalPackedEntries: proof.onionTotalPackedEntries,
        indexBinsPerTable: proof.onionIndexBinsPerTable,
        chunkBinsPerTable: proof.onionChunkBinsPerTable,
        indexSlotsPerBin: proof.onionIndexSlotsPerBin,
        indexSlotSize: proof.onionIndexSlotSize,
      };
      if (proof.proofVersion !== 2 || Object.values(typed).some(
        (value) => !Number.isInteger(value) || (value ?? 0) <= 0,
      )) {
        throw new Error(`db ${proof.dbId} proof is missing a valid v2 Onion layout`);
      }
      if (proof.height !== catalogEntry.height || proof.fromHeight !== catalogEntry.baseHeight) {
        throw new Error(`db ${proof.dbId} proof/catalog height changed during install`);
      }
      const totalPackedEntries = typed.totalPackedEntries!;
      const indexBinsPerTable = typed.indexBinsPerTable!;
      const chunkBinsPerTable = typed.chunkBinsPerTable!;
      const indexSlotsPerBin = typed.indexSlotsPerBin!;
      const indexSlotSize = typed.indexSlotSize!;
      const indexK = 75;
      const chunkK = 80;
      const merkleArity = proof.onionEntrySize / 32;
      const merkleIndexNumPt = Math.ceil(indexBinsPerTable / merkleArity);
      const merkleDataNumPt = Math.ceil(chunkBinsPerTable / merkleArity);
      const mismatches: string[] = [];
      const check = (field: string, actual: unknown, expected: unknown) => {
        if (actual !== expected) mismatches.push(`${field}: expected ${String(expected)}, got ${String(actual)}`);
      };
      // The standard proof catalog carries the shared DPF table bins. Onion
      // has separately packed tables, so its bins are bound by the v2 layout
      // and checked against the Onion query metadata below, not against the
      // standard catalog's indexBinsPerTable/chunkBinsPerTable.
      check('catalog.index_k', catalogEntry.indexK, indexK);
      check('catalog.chunk_k', catalogEntry.chunkK, chunkK);
      check('onion.total_packed_entries', advertised.total_packed_entries, totalPackedEntries);
      check('onion.index_bins', advertised.index_bins_per_table, indexBinsPerTable);
      check('onion.chunk_bins', advertised.chunk_bins_per_table, chunkBinsPerTable);
      check('onion.index_k', advertised.index_k, indexK);
      check('onion.chunk_k', advertised.chunk_k, chunkK);
      check('onion.tag_seed', advertised.tag_seed, catalogEntry.tagSeed);
      // Per-DB server-info predates the catalog extension on some production
      // nodes and reports absent master seeds as 0. Query placement uses the
      // chain-derived, proof-verified catalog values stored below. If the
      // diagnostic JSON does publish a seed, require it to agree as well.
      if (advertised.index_master_seed !== 0n) {
        check('onion.index_master_seed', advertised.index_master_seed, catalogEntry.indexMasterSeed);
      }
      if (advertised.chunk_master_seed !== 0n) {
        check('onion.chunk_master_seed', advertised.chunk_master_seed, catalogEntry.chunkMasterSeed);
      }
      check('onion.index_slots_per_bin', advertised.index_slots_per_bin, indexSlotsPerBin);
      check('onion.index_slot_size', advertised.index_slot_size, indexSlotSize);
      check('merkle.arity', merkle.arity, merkleArity);
      check('merkle.index.k', merkle.index.k, indexK);
      check('merkle.data.k', merkle.data.k, chunkK);
      check('merkle.index.num_pt', merkle.index.num_pt, merkleIndexNumPt);
      check('merkle.data.num_pt', merkle.data.num_pt, merkleDataNumPt);
      check('local index entry_size', this.wasmModule!.paramsInfo(indexBinsPerTable).entrySize, proof.onionEntrySize);
      check('local chunk entry_size', this.wasmModule!.paramsInfo(chunkBinsPerTable).entrySize, proof.onionEntrySize);
      check('Merkle sibling entry_size', merkleArity * 32, proof.onionEntrySize);
      if (mismatches.length > 0) {
        throw new Error(`db ${proof.dbId} proof-v2 query-layout mismatch: ${mismatches.join('; ')}`);
      }
      const root = proof.onionSuperRootHex.toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(root)) {
        throw new Error(`db ${proof.dbId} proof has malformed Onion root`);
      }
      this.provenRoots.set(proof.dbId, root);
    } finally {
      proof.free();
    }
  }

  /** Check the server's tree-tops against the proven root of `dbId`. */
  async preflightDatabase(dbId: number): Promise<void> {
    const root = this.provenRoots.get(dbId);
    const advertised = this.getOnionPirMerkleForDb(dbId);
    if (!root || !advertised) throw new Error(`db ${dbId} has no proven root or Onion tree-top metadata`);
    if (!await this.fetchTreeTops(dbId, 'index', { ...advertised, super_root: root })) {
      throw new Error(`db ${dbId} Onion tree-tops do not match the proven root`);
    }
  }

  // ─── Server info (delegates to shared server-info.ts) ──────────────────

  private async fetchServerInfo(): Promise<void> {
    const info = await fetchServerInfoJson(this.ws!, (req, resp) => {
      this.recordRound({
        kind: 'info',
        server_id: 0,
        db_id: null,
        request_bytes: req,
        response_bytes: resp,
        items: [],
      });
    });
    this.serverInfo = info;

    // Fetch the database catalog so the UI can populate a selector.
    try {
      this.catalog = await fetchDatabaseCatalog(this.ws!, (req, resp) => {
        this.recordRound({
          kind: 'info',
          server_id: 0,
          db_id: null,
          request_bytes: req,
          response_bytes: resp,
          items: [],
        });
      });
      this.log(`Catalog: ${this.catalog.databases.length} database(s)`);
    } catch (e: any) {
      this.catalog = null;
      this.log(`Catalog fetch failed: ${e.message}`, 'error');
    }

    // Default to main-DB params (active dbId defaults to 0). Fall back to
    // top-level DPF params if the server has no OnionPIR data at all.
    if (info.onionpir) {
      this.updateParamsForActiveDb();
    } else {
      this.indexK = info.index_k;
      this.chunkK = info.chunk_k;
      this.indexBins = info.index_bins_per_table;
      this.chunkBins = info.chunk_bins_per_table;
      this.tagSeed = info.tag_seed;
      this.totalPacked = 0;
      this.indexSlotsPerBin = info.index_slots_per_bin;
      this.indexSlotSize = info.index_slot_size;
    }

    this.log(`Server (JSON): index K=${this.indexK} bins=${this.indexBins} slots_per_bin=${this.indexSlotsPerBin}, chunk K=${this.chunkK} bins=${this.chunkBins}, total_packed=${this.totalPacked}`);
  }

  // ─── UTXO decoder (delegates to shared codec.ts) ────────────────────────

  private decodeUtxoData(fullData: Uint8Array): { entries: UtxoEntry[]; totalSats: bigint } {
    return decodeUtxoData(fullData, (msg) => this.log(msg, 'error'));
  }

  // ═══════════════════════════════════════════════════════════════════════
  // BATCH QUERY
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Query `scriptHashes` (20-byte HASH160s) against `dbIdOverride`, which
   * becomes the active database, or the active database.
   *
   * When the database has Merkle data the batch is verified before this
   * returns, as in the Rust `OnionClient`: each result carries
   * `merkleVerified`, and a result whose proof fails comes back with no
   * entries and `merkleVerified: false`.
   */
  async queryBatch(
    scriptHashes: Uint8Array[],
    onProgress?: (step: string, detail: string) => void,
    dbIdOverride?: number,
  ): Promise<(QueryResult | null)[]> {
    if (!this.isConnected()) throw new Error('Not connected');
    if (!this.wasmModule) throw new Error('WASM not loaded');
    if (dbIdOverride !== undefined) this.setDbId(dbIdOverride);
    const dbId = this.dbId;
    const override = this._scriptHashOverride;
    this._scriptHashOverride = undefined;
    if (override && override.length === scriptHashes.length) scriptHashes = override;
    if (scriptHashes.length === 0) return [];

    const progress = onProgress ?? (() => {});
    this.log(`=== Batch query: ${scriptHashes.length} script hashes (dbId=${dbId}, bins=${this.indexBins}/${this.chunkBins}) ===`);
    this.log(`[PIR-AUDIT] Query parameters: K=${this.indexK} index groups, K_CHUNK=${this.chunkK} chunk groups, INDEX_CUCKOO_NUM_HASHES=${INDEX_CUCKOO_NUM_HASHES}`);

    progress('Setup', 'Creating PIR client...');
    const fhe = this.fheKeys(this.wasmModule);
    await this.registerKeys(dbId, fhe, progress);
    const results = await this.runPir(scriptHashes, dbId, fhe, progress);
    if (this.hasMerkleForDb(dbId)) {
      await this.verifyMerkle(results, dbId, fhe, progress);
    } else {
      this.log(`[PIR-AUDIT] OnionPIR Merkle verification skipped: db ${dbId} has no Merkle data`);
    }
    return results;
  }

  /** This connection's FHE keys, generated on first use. The keygen client
   * is sized to the INDEX database; the exported secret key is size-
   * independent and seeds a client for every level and database. */
  private fheKeys(wasm: OnionPirModule): FheKeys {
    if (this.fhe) return this.fhe;
    // try/finally reclaims the keygen client's WASM heap even if an
    // accessor throws.
    const keygen = new wasm.OnionPirClient(this.indexBins);
    try {
      this.fhe = {
        clientId: keygen.id(),
        galoisKeys: keygen.galoisKeys(),
        gswKeys: keygen.gswKey(),
        secretKey: keygen.exportSecretKey(),
      };
    } finally {
      keygen.delete();
    }
    return this.fhe;
  }

  /** Register `fhe` for `dbId` once per connection: each database has its
   * own OnionPIR worker and key store. */
  private async registerKeys(
    dbId: number,
    fhe: FheKeys,
    progress: (step: string, detail: string) => void,
  ): Promise<void> {
    if (this.registeredDbs.has(dbId)) return;
    progress('Setup', `Registering keys (dbId=${dbId})...`);
    const regMsg = encodeRegisterKeys(fhe.galoisKeys, fhe.gswKeys, dbId);
    const ack = await this.sendRaw(regMsg);
    this.recordRound({
      kind: 'onion_key_register',
      server_id: 0,
      db_id: dbId,
      request_bytes: regMsg.length,
      response_bytes: ack.length,
      items: [],
    });
    const ackPayload = responsePayloadFromFrame(ack, RESP_KEYS_ACK);
    if (ackPayload.length !== 1) throw new Error('Key registration response has trailing data');
    this.registeredDbs.add(dbId);
    this.log(`Keys registered for dbId=${dbId}`);
  }

  /** The INDEX and CHUNK PIR levels, then result assembly. */
  private async runPir(
    scriptHashes: Uint8Array[],
    dbId: number,
    fhe: FheKeys,
    progress: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    const wasm = this.wasmModule!;
    const N = scriptHashes.length;
    const clientId = fhe.clientId;
    const secretKey = fhe.secretKey;
    const indexClient = wasm.createClientFromSecretKey(this.indexBins, clientId, secretKey);
    if (!indexClient) {
      // Upstream's `from_secret_key` returns `Option<Self>` and the WASM
      // binding maps None → null. None can only fire on size/format
      // mismatch — for a freshly-exported secret key this should be
      // unreachable. Throw to surface the inconsistency.
      throw new Error(
        `OnionPIR createClientFromSecretKey returned null for freshly-exported sk ` +
        `(clientId=${clientId}, sk.len=${secretKey.length}). ` +
        `Likely cause: WASM module / .d.ts drift.`
      );
    }
    let chunkClient: WasmPirClient | null = null;

    try {
      // ════════════════════════════════════════════════════════════════
      // LEVEL 1: Index PIR
      // ════════════════════════════════════════════════════════════════
      progress('Level 1', `Planning index batch for ${N} queries...`);

      // Prepare per-address info
      const addrInfos = scriptHashes.map(sh => ({
        tag: computeTag(this.tagSeed, sh),
        groups: deriveGroups(sh),
      }));

      interface IndexResult {
        entryId: number;
        byteOffset: number;
        numEntries: number;
      }
      const indexResults: (IndexResult | null)[] = new Array(N).fill(null);
      // Per-group OnionPIR Merkle: SHA256 of the first probed INDEX bin
      // per address. Retained only as the UI's "this result is
      // Merkle-verifiable" marker (index.html filters on
      // `indexBinHash !== undefined`); the verifier itself walks
      // `allBinsChecked`, keyed by (pbcGroup, bin).
      const indexBinHashes: (Uint8Array | null)[] = new Array(N).fill(null);
      // Every probed INDEX cuckoo bin as a per-group Merkle leaf —
      // always INDEX_CUCKOO_NUM_HASHES per address (found / not-found /
      // whale alike, per the INDEX item-count symmetry invariant).
      // `pbcGroup` selects the per-group INDEX tree; `bin` is the leaf
      // index within that group's tree.
      const allBinsChecked: Map<number, { hash: Uint8Array; pbcGroup: number; bin: number }[]> = new Map();
      let totalIndexRounds = 0;

      // PBC place all addresses into groups (same logic as DPF-PIR)
      const allGroups = addrInfos.map(a => a.groups);
      const indexRounds = planPbcRounds(allGroups, this.indexK);
      this.log(`Level 1: ${N} queries → ${indexRounds.length} round(s)`);
      this.log(`[PIR-AUDIT] PADDING: Each index round sends exactly ${this.indexK} queries (real + empty groups for privacy)`);

      // Each round: 2 queries per group (hash0 + hash1 bins), matching DPF approach.
      // Groups without a real address send empty queries (server skips them).
      for (const round of indexRounds) {
        const roundNum = totalIndexRounds + 1;
        const totalRounds = indexRounds.length;
        progress('Level 1', `Round ${roundNum}/${totalRounds}: generating ${round.length * 2} FHE queries...`);

        const groupMap = new Map<number, number>(); // group → addrIdx
        for (const [addrIdx, group] of round) {
          groupMap.set(group, addrIdx);
        }

        // Generate 2*K queries: [g0_h0, g0_h1, g1_h0, g1_h1, ...]
        // ALL groups get real FHE queries (dummy groups use random bins)
        // so the server cannot distinguish real from dummy.
        const queries: Uint8Array[] = [];
        const queryBins: number[] = [];
        for (let g = 0; g < this.indexK; g++) {
          const addrIdx = groupMap.get(g);
          for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
            let bin: number;
            if (addrIdx !== undefined) {
              const key = deriveCuckooKeyGeneric(this.indexMasterSeed, g, h);
              bin = cuckooHash(scriptHashes[addrIdx], key, this.indexBins);
            } else {
              bin = Number(this.rng.nextU64() % BigInt(this.indexBins));
            }
            queries.push(indexClient.generateQuery(bin));
            queryBins.push(bin);
          }
          // Yield after every group — each generateQuery is ~20-50ms of WASM FHE work
          if (g % 3 === 2) {
            progress('Level 1', `Round ${roundNum}/${totalRounds}: ${(g + 1) * 2}/${this.indexK * 2} queries...`);
            await yieldToMain();
          }
        }

        progress('Level 1', `Round ${roundNum}/${totalRounds}: querying server (${queries.length} FHE queries)...`);
        const batchMsg = encodeBatchQuery(REQ_ONIONPIR_INDEX_QUERY, totalIndexRounds, queries, dbId);
        const respRaw = await this.sendRaw(batchMsg);
        // Per-group item count: every group sends INDEX_CUCKOO_NUM_HASHES
        // FHE queries — matches the Rust shape (and DPF's INDEX shape).
        // The Merkle INDEX item-count symmetry invariant lives in this
        // uniform 2-per-group payload.
        this.recordRound({
          kind: 'index',
          server_id: 0,
          db_id: dbId,
          request_bytes: batchMsg.length,
          response_bytes: respRaw.length,
          items: new Array(this.indexK).fill(INDEX_CUCKOO_NUM_HASHES),
        });
        totalIndexRounds++;

        const respPayload = responsePayloadFromFrame(respRaw, RESP_ONIONPIR_INDEX_RESULT);
        const { results } = decodeBatchResult(
          respPayload,
          1,
          totalIndexRounds - 1,
          queries.length,
        );

        // Decrypt all INDEX_CUCKOO_NUM_HASHES responses per address — even
        // after a match — so the Merkle item count is uniform across
        // found/not-found (closes the side channel where pass count leaks
        // presence). Cost: ~100ms of WASM FHE work per extra decrypt on
        // found@h=0 queries. See CLAUDE.md "Merkle INDEX item-count symmetry".
        let decrypted = 0;
        const totalDecrypts = round.length * INDEX_CUCKOO_NUM_HASHES;
        for (const [addrIdx, group] of round) {
          // Track ALL bins probed for this address as per-group leaves.
          const binsForAddr: { hash: Uint8Array; pbcGroup: number; bin: number }[] = [];
          let foundMatch = false;
          // Post-port (commit 7): query `paramsInfo()` once per
          // round; we need polyDegree + entrySize to unpack the
          // raw plaintext bytes.
          const wasmParams = wasm.paramsInfo(this.indexBins);
          for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
            const qi = group * 2 + h;
            const bin = queryBins[qi];
            // Post-port: `decryptResponse(response)` returns the raw
            // plaintext as `[u32 N][u64 coeff_0]...`; the TS port of
            // pir-core::onion_unpack handles the inverse-bit-pack.
            const rawPt = indexClient.decryptResponse(results[qi]);
            const entryBytes = unpackOnionPlaintext(
              rawPt, wasmParams.polyDegree, wasmParams.entrySize,
            );
            if (!entryBytes) {
              throw new Error(
                `onion_unpack rejected INDEX plaintext (raw.len=${rawPt.length} ` +
                `N=${wasmParams.polyDegree} es=${wasmParams.entrySize})`
              );
            }
            decrypted++;
            // Hash the full unpacked bin (entry_size bytes). The
            // legacy `PACKED_ENTRY_SIZE = 3840` slice would overshoot
            // the new 3328-byte bin and read past the end; bound the
            // slice by the actual unpack length.
            const hashLen = Math.min(entryBytes.length, PACKED_ENTRY_SIZE);
            const binHash = sha256(entryBytes.slice(0, hashLen));
            // Per-group OnionPIR Merkle leaf key: `group` selects the
            // per-group INDEX tree, `bin` is the leaf index within it.
            binsForAddr.push({ hash: binHash, pbcGroup: group, bin });

            // Only capture the first match; later iterations still decrypt
            // and track their bin but don't overwrite the matched-bin record.
            if (!foundMatch) {
              const found = findEntryInOnionPirIndexResult(entryBytes, addrInfos[addrIdx].tag, this.indexSlotsPerBin, this.indexSlotSize);
              if (found) {
                indexResults[addrIdx] = found;
                indexBinHashes[addrIdx] = binHash;
                foundMatch = true;
              }
            }
            // Yield after every decrypt — each is ~100ms+ of WASM FHE work
            progress('Level 1', `Round ${roundNum}/${totalRounds}: decrypted ${decrypted}/${totalDecrypts}...`);
            await yieldToMain();
          }

          allBinsChecked.set(addrIdx, binsForAddr);
          if (!foundMatch) {
            // Not found: set the `indexBinHash` marker from the first
            // probed bin so the UI still treats this result as
            // Merkle-verifiable (the verifier walks `allBinsChecked`).
            const firstBin = binsForAddr[0];
            if (firstBin) {
              indexBinHashes[addrIdx] = firstBin.hash;
            }
            this.log(`[PIR-AUDIT] Query ${addrIdx}: NOT FOUND (checked ${binsForAddr.length} bins)`);
          } else {
            const ir = indexResults[addrIdx];
            this.log(`[PIR-AUDIT] Query ${addrIdx}: FOUND at entryId=${ir?.entryId}, numEntries=${ir?.numEntries} (tracking ${binsForAddr.length} bins for Merkle)`);
          }
        }
      }

      const foundCount = indexResults.filter(r => r !== null).length;
      this.log(`Level 1 complete: ${foundCount}/${N} found in ${totalIndexRounds} rounds`);

      // ════════════════════════════════════════════════════════════════
      // LEVEL 2: Chunk PIR
      // ════════════════════════════════════════════════════════════════

      // Collect each query's *real* chunk entry_ids. Phase 3 / WS-A
      // removed the M=16 chunk-Merkle padding (see docs/VERIFICATION_OVERVIEW.md):
      // a query now fetches its real chunk count — found-with-N → N
      // reals, not-found / whale → 0. The newly-admitted leak (per-query
      // real chunk count is observable) is intended and tracked in the
      // leakage spec; ~99% of addresses have exactly 1 chunk. This
      // mirrors the Rust `OnionClient::query_chunk_level` (commit
      // `79e422b4`, which dropped `pad_chunk_ids_to_m`).
      //
      // Round-presence is preserved *separately* from M-padding:
      //   - CHUNK PIR round-presence — every non-empty batch issues ≥1
      //     K_CHUNK CHUNK PIR round even when all-not-found (the
      //     `chunkRounds` empty-round fallback below).
      //   - CHUNK-Merkle round-presence — the per-group verifier always
      //     issues ≥1 all-dummy DATA sibling pass (`verifySubTree`).
      // Together they keep found-vs-not-found hidden without M=16.
      const whaleQueries = new Set<number>();
      const chunkOwnedPerQuery: number[][] = new Array(N);
      const uniqueEntryIds: number[] = [];
      const seen = new Set<number>();

      for (let i = 0; i < N; i++) {
        const ir = indexResults[i];
        if (ir && ir.numEntries === 0) {
          whaleQueries.add(i);
        }
        const realChunks: number[] = [];
        if (ir && ir.numEntries > 0) {
          const end = ir.entryId + ir.numEntries;
          if (
            !Number.isSafeInteger(ir.entryId) || !Number.isSafeInteger(ir.numEntries) ||
            ir.entryId < 0 || ir.numEntries < 0 || end > this.totalPacked ||
            !Number.isSafeInteger(ir.byteOffset) || ir.byteOffset < 0 ||
            ir.byteOffset >= PACKED_ENTRY_SIZE
          ) {
            throw new Error(`OnionPIR INDEX result ${i} describes an invalid CHUNK range`);
          }
          for (let j = 0; j < ir.numEntries; j++) {
            realChunks.push(ir.entryId + j);
          }
        }
        for (const eid of realChunks) {
          if (eid < this.totalPacked && !seen.has(eid)) {
            seen.add(eid);
            uniqueEntryIds.push(eid);
          }
        }
        chunkOwnedPerQuery[i] = realChunks;
      }

      if (whaleQueries.size > 0) {
        this.log(`${whaleQueries.size} whale address(es) excluded`);
      }

      this.log(
        `[PIR-AUDIT] CHUNK: ${N} queries, ${uniqueEntryIds.length} unique real chunk entry_ids`,
      );

      const decryptedEntries = new Map<number, Uint8Array>();
      // entry_id → per-group OnionPIR Merkle DATA leaf. `pbcGroup`
      // selects the per-group DATA tree; `bin` is the leaf index within
      // it. Mirrors the Rust `data_merkle: HashMap<u32,(Hash256,usize,u32)>`.
      const dataMerkle = new Map<number, { hash: Uint8Array; pbcGroup: number; bin: number }>();
      let chunkRoundsCount = 0;

      // CHUNK Round-Presence Symmetry (CLAUDE.md / docs/VERIFICATION_OVERVIEW.md
      // cross-cutting invariant C.1). A genuinely empty batch (no
      // scripthashes, N === 0) has nothing to hide → no CHUNK round. But
      // a batch whose scripthashes are *all* not-found / whale
      // (`uniqueEntryIds` empty) MUST still issue exactly one all-dummy
      // K_CHUNK CHUNK PIR round — skipping it would leak found-vs-not-found
      // via CHUNK round absence. Mirrors the Rust `query_chunk_level`.
      if (N > 0) {
        // Create chunk client from same secret key (no extra registration needed).
        // Post-port (commit 7): no `numEntries` arg; null check on stale-key.
        progress('Level 2', 'Setting up chunk phase...');
        await yieldToMain();
        chunkClient = wasm.createClientFromSecretKey(this.chunkBins, clientId, secretKey);
        if (!chunkClient) {
          throw new Error(
            `OnionPIR chunk createClientFromSecretKey returned null ` +
            `(clientId=${clientId}, sk.len=${secretKey.length})`
          );
        }

        // Plan PBC rounds over the real chunk entry_ids. An all-not-found
        // batch has `uniqueEntryIds` empty → substitute a single empty
        // round so exactly one all-dummy K_CHUNK CHUNK PIR round still
        // goes out (round-presence, above). The round body handles an
        // empty `round` natively — every group falls through to a random
        // dummy and no real cuckoo lookup runs.
        const chunkRounds: [number, number][][] = uniqueEntryIds.length === 0
          ? [[]]
          : planPbcRounds(uniqueEntryIds.map(eid => deriveChunkGroups(eid)), this.chunkK);
        chunkRoundsCount = chunkRounds.length;
        this.log(`Level 2: ${uniqueEntryIds.length} entries → ${chunkRounds.length} round(s)`);

        // The reverse index only locates *real* entries; an all-not-found
        // batch never indexes it, so skip the (total-entries-scale) build.
        const reverseIndex = uniqueEntryIds.length === 0
          ? null
          : await ensureChunkReverseIndex(
              this.totalPacked,
              (msg) => progress('Level 2', msg),
            );

        const cuckooCache = new Map<number, Uint32Array>();

        for (let ri = 0; ri < chunkRounds.length; ri++) {
          const round = chunkRounds[ri];
          progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length} (building cuckoo tables)...`);

          const queryInfos: { entryId: number; group: number; bin: number }[] = [];
          const groupToQi = new Map<number, number>();

          let tablesBuilt = 0;
          for (const [ei, group] of round) {
            const eid = uniqueEntryIds[ei];
            if (!cuckooCache.has(group)) {
              // A non-empty `round` implies `uniqueEntryIds.length > 0`,
              // so `reverseIndex` was built (non-null) above.
              cuckooCache.set(group, buildChunkCuckooForGroup(wasm, group, reverseIndex!, this.chunkBins, this.chunkMasterSeed));
              tablesBuilt++;
              progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: built ${tablesBuilt} cuckoo tables...`);
              await yieldToMain();
            }

            const keys: bigint[] = [];
            for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
              keys.push(chunkDeriveCuckooKey(this.chunkMasterSeed, group, h));
            }
            const bin = findEntryInCuckoo(cuckooCache.get(group)!, eid, keys, this.chunkBins);
            if (bin === null) throw new Error(`Entry ${eid} not in cuckoo table for group ${group}`);

            const qi = queryInfos.length;
            queryInfos.push({ entryId: eid, group, bin });
            groupToQi.set(group, qi);
          }

          progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: generating ${this.chunkK} FHE queries...`);

          const queries: Uint8Array[] = [];
          for (let g = 0; g < this.chunkK; g++) {
            const qi = groupToQi.get(g);
            const idx = qi !== undefined
              ? queryInfos[qi].bin
              : Number(this.rng.nextU64() % BigInt(this.chunkBins));
            queries.push(chunkClient!.generateQuery(idx));
            // Yield frequently — each generateQuery is expensive WASM FHE work
            if (g % 3 === 2) {
              progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: ${g + 1}/${this.chunkK} queries...`);
              await yieldToMain();
            }
          }

          progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: querying server...`);
          const batchMsg = encodeBatchQuery(REQ_ONIONPIR_CHUNK_QUERY, ri, queries, dbId);
          const respRaw = await this.sendRaw(batchMsg);
          // OnionPIR CHUNK shape: 1 FHE query per group, K_CHUNK groups.
          // Differs from DPF/Harmony CHUNK (which send 2 per group); the
          // Rust `OnionClient::query_chunk_level` pin matches this.
          this.recordRound({
            kind: 'chunk',
            server_id: 0,
            db_id: dbId,
            request_bytes: batchMsg.length,
            response_bytes: respRaw.length,
            items: new Array(this.chunkK).fill(1),
          });

          const respPayload = responsePayloadFromFrame(respRaw, RESP_ONIONPIR_CHUNK_RESULT);
          const { results } = decodeBatchResult(respPayload, 1, ri, this.chunkK);

          let chunkDecrypted = 0;
          // Post-port (commit 7): unpack the raw plaintext exactly as
          // in the INDEX block above.
          const chunkWasmParams = wasm.paramsInfo(this.chunkBins);
          for (const qi of queryInfos) {
            const rawPt = chunkClient!.decryptResponse(results[qi.group]);
            const entryBytes = unpackOnionPlaintext(
              rawPt, chunkWasmParams.polyDegree, chunkWasmParams.entrySize,
            );
            if (!entryBytes) {
              throw new Error(
                `onion_unpack rejected CHUNK plaintext (raw.len=${rawPt.length} ` +
                `N=${chunkWasmParams.polyDegree} es=${chunkWasmParams.entrySize})`
              );
            }
            const hashLen = Math.min(entryBytes.length, PACKED_ENTRY_SIZE);
            decryptedEntries.set(qi.entryId, entryBytes.slice(0, hashLen));
            // Per-group OnionPIR Merkle DATA leaf — `qi.group` selects
            // the per-group DATA tree, `qi.bin` is the leaf index. The
            // leaf hash is OnionPIR's no-prefix SHA256(decrypted_bin).
            dataMerkle.set(qi.entryId, {
              hash: sha256(entryBytes.slice(0, hashLen)),
              pbcGroup: qi.group,
              bin: qi.bin,
            });
            chunkDecrypted++;
            progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: decrypted ${chunkDecrypted}/${queryInfos.length}...`);
            await yieldToMain();
          }
        }
      }

      this.log(`Level 2 complete: ${decryptedEntries.size} entries recovered in ${chunkRoundsCount} rounds`);

      // ════════════════════════════════════════════════════════════════
      // Reassemble results
      // ════════════════════════════════════════════════════════════════
      progress('Decode', 'Decoding UTXO data...');

      const results: (QueryResult | null)[] = new Array(N).fill(null);

      // The Merkle root this batch is verified against, surfaced on each
      // result for display.
      const resultMerkleRoot = this.getMerkleRootHexForDb(dbId);

      // Helper: collect the per-group DATA Merkle leaves owned by query
      // `qi` — one per real chunk entry_id (so 0 for not-found / whale).
      // Phase 3 / WS-A removed the M=16 pad, so the leaf count now varies
      // with UTXO count (an admitted, documented leak); CHUNK-Merkle
      // round-presence is kept by `verifySubTree`'s ≥1 all-dummy DATA
      // sibling pass, not by padding.
      const collectOwnedDataLeaves = (
        qi: number,
      ): { hash: Uint8Array; pbcGroup: number; bin: number }[] => {
        const leaves: { hash: Uint8Array; pbcGroup: number; bin: number }[] = [];
        for (const eid of chunkOwnedPerQuery[qi]) {
          const leaf = dataMerkle.get(eid);
          if (leaf) leaves.push(leaf);
        }
        return leaves;
      };

      for (let qi = 0; qi < N; qi++) {
        const ownedLeaves = collectOwnedDataLeaves(qi);

        if (whaleQueries.has(qi)) {
          // Whale: matched INDEX entry but `numEntries == 0` → 0 DATA
          // leaves. The whale's INDEX entry is committed to the per-group
          // INDEX Merkle root, so its probed INDEX bins still verify
          // (whale-exclusion is a verifiable property). DATA round-
          // presence is handled by `verifySubTree`'s all-dummy pass.
          results[qi] = {
            entries: [],
            totalSats: 0n,
            startChunkId: 0,
            numChunks: 0,
            numRounds: chunkRoundsCount,
            isWhale: true,
            merkleSuperRoot: resultMerkleRoot,
            indexBinHash: indexBinHashes[qi] ?? undefined,
            indexBinLeaves: allBinsChecked.get(qi),
            dataBinLeaves: ownedLeaves,
            scriptHash: scriptHashes[qi],
            rawChunkData: new Uint8Array(0),
          };
          continue;
        }

        const ir = indexResults[qi];
        if (!ir) {
          // Not-found in INDEX — every probed cuckoo bin is committed for
          // the absence proof. Post-M=16-removal a not-found query owns
          // 0 DATA leaves; found-vs-not-found stays hidden because
          // `verifySubTree` always issues ≥1 all-dummy DATA sibling pass
          // (CHUNK-Merkle round-presence).
          const binHash = indexBinHashes[qi];
          const allBins = allBinsChecked.get(qi);
          if (binHash) {
            results[qi] = {
              entries: [],
              totalSats: 0n,
              startChunkId: 0,
              numChunks: 0,
              numRounds: chunkRoundsCount,
              isWhale: false,
              merkleSuperRoot: resultMerkleRoot,
              indexBinHash: binHash,
              indexBinLeaves: allBins,
              dataBinLeaves: ownedLeaves,
              scriptHash: scriptHashes[qi],
              rawChunkData: new Uint8Array(0),
              };
          }
          continue;
        }

        // Found path — every INDEX-declared CHUNK is mandatory. Silently
        // concatenating only the bins a provider returned would authenticate
        // a truncated/empty result under otherwise-valid Merkle leaves.
        const fullData = reassembleCompleteOnionChunks(
          ir.entryId,
          ir.numEntries,
          ir.byteOffset,
          decryptedEntries,
        );

        const { entries, totalSats } = this.decodeUtxoData(fullData);
        results[qi] = {
          entries,
          totalSats,
          startChunkId: ir.entryId,
          numChunks: ir.numEntries,
          numRounds: chunkRoundsCount,
          isWhale: false,
          merkleSuperRoot: resultMerkleRoot,
          indexBinHash: indexBinHashes[qi] ?? undefined,
          // ALL probed cuckoo positions (always INDEX_CUCKOO_NUM_HASHES bins —
          // see CLAUDE.md "Merkle INDEX Item-Count Symmetry"); one per-group
          // INDEX Merkle leaf each.
          indexBinLeaves: allBinsChecked.get(qi),
          // One per-group DATA Merkle leaf per real chunk entry_id.
          dataBinLeaves: ownedLeaves,
          scriptHash: scriptHashes[qi],
          // Preserve raw bytes so delta-DB queries can be re-decoded via
          // decodeDeltaData in the sync-merge flow. For main DB this is just
          // the same bytes that decodeUtxoData already consumed above.
          rawChunkData: fullData,
        };
      }

      const matched = results.filter(
        r => r !== null && !r.isWhale && r.entries.length > 0,
      ).length;
      this.log(`=== Batch complete: ${matched}/${N} matched ===`, 'success');
      return results;
    } finally {
      // Free WASM clients
      indexClient.delete();
      if (chunkClient) chunkClient.delete();
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // MERKLE VERIFICATION
  // ═══════════════════════════════════════════════════════════════════════

  /** Check if the ACTIVE database supports OnionPIR per-bin Merkle verification */
  hasMerkle(): boolean {
    return this.hasMerkleForDb(this.dbId);
  }

  /** The Merkle root hex for the active database (for display). */
  getMerkleRootHex(): string | undefined {
    return this.getMerkleRootHexForDb(this.dbId);
  }

  /**
   * Verify the batch's per-group OnionPIR Merkle leaves and record each
   * result's verdict. SOUNDNESS-CRITICAL — mirrors the Rust
   * `run_merkle_verification` / `verify_onion_merkle_batch`.
   *
   * Two per-group forests: 75 INDEX trees + 80 DATA trees, anchored by one
   * `super_root`. Each leaf carried on a `QueryResult` (`indexBinLeaves` /
   * `dataBinLeaves`) is keyed by `(pbcGroup, bin)`.
   *
   * **Both** sub-trees are always verified, even when one has no leaves —
   * `verifySubTree` issues one all-dummy K-padded sibling pass for an empty
   * sub-tree so a not-found / whale batch (0 DATA leaves) is
   * wire-indistinguishable from a found batch (CHUNK-Merkle round-presence).
   */
  private async verifyMerkle(
    results: (QueryResult | null)[],
    dbId: number,
    fhe: FheKeys,
    progress: (step: string, detail: string) => void,
  ): Promise<void> {
    const info: OnionPirMerkleInfoJson = {
      ...this.getOnionPirMerkleForDb(dbId)!,
      super_root: this.getMerkleRootHexForDb(dbId)!,
    };
    type Leaf = { pbcGroup: number; bin: number; hash: Uint8Array; resultIdx: number };
    const indexLeaves: Leaf[] = [];
    const dataLeaves: Leaf[] = [];
    results.forEach((result, resultIdx) => {
      // INDEX: always INDEX_CUCKOO_NUM_HASHES per query (the INDEX
      // item-count symmetry invariant). DATA: one per real chunk entry_id
      // (0 for not-found / whale) — the admitted UTXO-count leak.
      for (const leaf of result?.indexBinLeaves ?? []) indexLeaves.push({ ...leaf, resultIdx });
      for (const leaf of result?.dataBinLeaves ?? []) dataLeaves.push({ ...leaf, resultIdx });
    });
    if (indexLeaves.length + dataLeaves.length === 0) return;

    const indexVerdicts = await this.verifySubTree('index', info, indexLeaves, dbId, fhe, progress);
    const dataVerdicts = await this.verifySubTree('data', info, dataLeaves, dbId, fhe, progress);

    // A result passes iff it has leaves and ALL of them verified.
    const ok = results.map((result) => (result?.indexBinLeaves?.length ?? 0) > 0);
    for (const leaf of indexLeaves) {
      if (!indexVerdicts.get(`${leaf.pbcGroup}:${leaf.bin}`)) ok[leaf.resultIdx] = false;
    }
    for (const leaf of dataLeaves) {
      if (!dataVerdicts.get(`${leaf.pbcGroup}:${leaf.bin}`)) ok[leaf.resultIdx] = false;
    }

    let verified = 0;
    let total = 0;
    results.forEach((result, i) => {
      if (!result) return;
      total++;
      if (ok[i]) {
        result.merkleVerified = true;
        verified++;
      } else {
        // As in Rust: a failed result carries no entries.
        results[i] = {
          entries: [],
          totalSats: 0n,
          startChunkId: 0,
          numChunks: 0,
          numRounds: result.numRounds,
          isWhale: false,
          merkleVerified: false,
          scriptHash: result.scriptHash,
        };
      }
    });
    this.log(
      `Merkle: ${verified}/${total} results verified (per-group index+data trees)`,
      verified === total ? 'success' : 'error',
    );
  }

  /** Fetch the consolidated tree-top blob for `dbId` and check it against
   * `info.super_root`; `null` when it does not match. */
  private async fetchTreeTops(
    dbId: number,
    treeName: 'index' | 'data',
    info: OnionPirMerkleInfoJson,
  ): Promise<OnionTreeTopCache[] | null> {
    const payloadLen = dbId !== 0 ? 2 : 1;
    const request = new Uint8Array(4 + payloadLen);
    new DataView(request.buffer).setUint32(0, payloadLen, true);
    request[4] = treeName === 'index' ? REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP : REQ_ONIONPIR_MERKLE_DATA_TREE_TOP;
    if (dbId !== 0) request[5] = dbId;
    const response = await this.sendRaw(request);
    this.recordRound({
      kind: 'merkle_tree_tops',
      server_id: 0,
      db_id: dbId,
      request_bytes: request.length,
      response_bytes: response.length,
      items: [],
    });
    const blob = responsePayloadFromFrame(
      response,
      treeName === 'index' ? RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP : RESP_ONIONPIR_MERKLE_DATA_TREE_TOP,
    ).slice(1);
    const allTops = parseOnionTreeTopCache(blob);
    this.log(
      `[PIR-AUDIT] OnionPIR Merkle ${treeName} tree-top: ${allTops.length} ` +
      `trees parsed (arity=${info.arity})`,
    );
    return checkTreeTopAnchor(info, blob, allTops, (m) => this.log(m, 'error')) ? allTops : null;
  }

  /**
   * Verify a set of per-group OnionPIR Merkle leaves against one
   * sub-tree (INDEX or DATA). Mirrors the Rust
   * `onion_merkle::verify_sub_tree`.
   *
   * Per-group walk: fetch + anchor-check the consolidated 155-tree
   * tree-top blob, then for each "pass" issue one K-padded FHE sibling
   * round (one query per PBC group — real row for a group with a leaf,
   * random-row dummy for the rest), fold the decrypted sibling row into
   * the leaf's running hash, and walk the cached per-group tree-top to
   * the group root.
   *
   * `max(1, maxItemsPerGroup)` passes run: ≥1 even for an empty
   * sub-tree (CHUNK-Merkle round-presence) and one extra per
   * within-group collision (e.g. the two INDEX cuckoo positions of a
   * not-found query landing in the same group).
   *
   * Returns map: `"<pbcGroup>:<bin>"` → verified boolean.
   *
   * On a protocol / parse error this throws (the verdict is "could not
   * verify"); on a super-root mismatch every probed leaf is recorded
   * `false` and the sibling rounds are skipped (they would prove
   * nothing against forged roots).
   */
  private async verifySubTree(
    treeName: 'index' | 'data',
    info: OnionPirMerkleInfoJson,
    leaves: { pbcGroup: number; bin: number; hash: Uint8Array }[],
    dbId: number,
    fhe: FheKeys,
    progress: (step: string, detail: string) => void,
  ): Promise<Map<string, boolean>> {
    const out = new Map<string, boolean>();
    const arity = info.arity;
    const kind = treeName === 'index' ? info.index : info.data;
    const k = kind.k;
    const numPt = kind.num_pt;
    const sibReq = treeName === 'index'
      ? REQ_ONIONPIR_MERKLE_INDEX_SIBLING : REQ_ONIONPIR_MERKLE_DATA_SIBLING;
    const sibResp = treeName === 'index'
      ? RESP_ONIONPIR_MERKLE_INDEX_SIBLING : RESP_ONIONPIR_MERKLE_DATA_SIBLING;

    progress('Merkle', `Fetching ${treeName} tree-top blob...`);
    const allTops = await this.fetchTreeTops(dbId, treeName, info);
    if (!allTops) {
      for (const lf of leaves) out.set(`${lf.pbcGroup}:${lf.bin}`, false);
      return out;
    }

    // ── 3. Deduplicate leaves by (pbcGroup, bin) ───────────────────────
    const uniqueMap = new Map<string, { pbcGroup: number; bin: number; hash: Uint8Array }>();
    for (const lf of leaves) {
      const key = `${lf.pbcGroup}:${lf.bin}`;
      const previous = uniqueMap.get(key);
      if (previous && !bytesEqual(previous.hash, lf.hash)) {
        throw new Error(`OnionPIR conflicting hashes for ${treeName} Merkle leaf ${key}`);
      }
      if (!previous) uniqueMap.set(key, lf);
    }
    const keys = [...uniqueMap.keys()];
    const n = keys.length;
    // Per-leaf running state.
    const currentHash: Uint8Array[] = keys.map(key => uniqueMap.get(key)!.hash);
    const nodeIdx: number[] = keys.map(key => uniqueMap.get(key)!.bin);
    const failed: boolean[] = new Array(n).fill(false);

    this.log(
      `[PIR-AUDIT] OnionPIR Merkle ${treeName}: verifying ${n} unique ` +
      `leaves (k=${k})`,
    );

    // ── 4. Group leaves by PBC group ───────────────────────────────────
    // Multiple leaves share a group only for the INDEX-not-found case
    // (both cuckoo positions) or batch collisions; each surplus leaf
    // becomes one extra pass, each pass itself fully K-padded.
    const itemsByGroup = new Map<number, number[]>();
    for (let i = 0; i < n; i++) {
      const g = uniqueMap.get(keys[i])!.pbcGroup;
      const arr = itemsByGroup.get(g);
      if (arr) arr.push(i);
      else itemsByGroup.set(g, [i]);
    }
    // ≥1: an empty sub-tree still issues one all-dummy pass (round-presence).
    let maxItemsPerGroup = 1;
    for (const arr of itemsByGroup.values()) {
      if (arr.length > maxItemsPerGroup) maxItemsPerGroup = arr.length;
    }

    // ── 5. FHE sibling client (one per sub-tree — fixed num_pt) ────────
    const sibClient = this.wasmModule!.createClientFromSecretKey(
      numPt, fhe.clientId, fhe.secretKey,
    );
    if (!sibClient) {
      throw new Error(
        `OnionPIR Merkle ${treeName}: sib createClientFromSecretKey ` +
        `returned null (clientId=${fhe.clientId}, num_pt=${numPt}, ` +
        `sk.len=${fhe.secretKey.length})`,
      );
    }
    try {
      const pinfo = this.wasmModule!.paramsInfo(numPt);
      if (pinfo.entrySize !== arity * 32) {
        throw new Error(
          `OnionPIR Merkle ${treeName}: sibling DB entry_size ` +
          `${pinfo.entrySize} != arity*32 (${arity * 32}) — onionpir ` +
          `rev / build-shape drift`,
        );
      }

      // ── 6. Sibling passes: one K-padded FHE round per pass ───────────
      // There is exactly ONE PIR sibling level (leaf → level-1). Each
      // pass handles at most one leaf per group, and every leaf is in
      // exactly one pass, so per-pass updates of nodeIdx / currentHash
      // never interfere.
      for (let pass = 0; pass < maxItemsPerGroup; pass++) {
        progress('Merkle', `${treeName} sibling pass ${pass + 1}/${maxItemsPerGroup}...`);

        // Which leaf (if any) each group contributes at this pass.
        const passGroupToItem = new Map<number, number>();
        for (const [g, arr] of itemsByGroup) {
          if (pass < arr.length) passGroupToItem.set(g, arr[pass]);
        }

        // K FHE queries — real row for a group with a pass-`pass` leaf,
        // random-row dummy for the rest. K-padding: the server sees K
        // indistinguishable FHE queries every pass, regardless of how
        // many leaves are real (CLAUDE.md "Query Padding").
        const queries: Uint8Array[] = [];
        for (let g = 0; g < k; g++) {
          const item = passGroupToItem.get(g);
          const row = item !== undefined
            ? Math.floor(nodeIdx[item] / arity)
            : Number(this.rng.nextU64() % BigInt(numPt));
          queries.push(sibClient.generateQuery(row));
          if (g % 5 === 4) await yieldToMain();
        }

        // round_id is vestigial under the per-group design — send 0.
        const batchMsg = encodeBatchQuery(sibReq, 0, queries, dbId);
        const respRaw = await this.sendRaw(batchMsg);
        // One PIR sibling level ⇒ level is always 0. K FHE queries, one
        // per PBC group — items[g] = 1 each. Matches the Rust
        // `verify_sub_tree`'s `Index/ChunkMerkleSiblings { level: 0 }`.
        this.recordRound({
          kind: treeName === 'index' ? 'index_merkle_siblings' : 'chunk_merkle_siblings',
          level: 0,
          server_id: 0,
          db_id: dbId,
          request_bytes: batchMsg.length,
          response_bytes: respRaw.length,
          items: new Array(k).fill(1),
        });
        const respPayload = responsePayloadFromFrame(respRaw, sibResp);
        const { results: batch } = decodeBatchResult(respPayload, 1, 0, k);

        // Fold each real group's decrypted sibling row into its leaf.
        for (const [g, item] of passGroupToItem) {
          if (failed[item]) continue;
          if (g >= batch.length) {
            this.log(
              `[PIR-AUDIT] OnionPIR Merkle ${treeName} pass ${pass}: result ` +
              `batch truncated at group ${g} (len ${batch.length})`,
              'error',
            );
            failed[item] = true;
            continue;
          }
          const rawPt = sibClient.decryptResponse(batch[g]);
          const row = unpackOnionPlaintext(rawPt, pinfo.polyDegree, pinfo.entrySize);
          if (!row) {
            throw new Error(
              `onion_unpack rejected ${treeName} sibling plaintext ` +
              `(raw.len=${rawPt.length} N=${pinfo.polyDegree} ` +
              `es=${pinfo.entrySize})`,
            );
          }
          // Recompute the level-1 parent of bin `nodeIdx[item]`: the
          // decrypted row holds that parent's `arity` leaf children;
          // replace the child at `bin % arity` with the leaf's own
          // committed hash, then hash the `arity` children. If the
          // server lied about any sibling, the parent — and hence the
          // root — will not match.
          const childPos = nodeIdx[item] % arity;
          const children: Uint8Array[] = [];
          for (let c = 0; c < arity; c++) {
            if (c === childPos) {
              children.push(currentHash[item]);
            } else {
              const off = c * 32;
              children.push(off + 32 <= row.length ? row.slice(off, off + 32) : ZERO_HASH);
            }
          }
          currentHash[item] = computeParentN(children);
          nodeIdx[item] = Math.floor(nodeIdx[item] / arity);
        }
      }
    } finally {
      sibClient.delete();
    }

    // ── 7. Walk each leaf's cached tree-top to its per-group root ──────
    for (let i = 0; i < n; i++) {
      const { pbcGroup, bin } = uniqueMap.get(keys[i])!;
      if (failed[i]) {
        out.set(keys[i], false);
        continue;
      }
      // 75 INDEX trees first, then 80 DATA trees.
      const topIdx = treeName === 'index' ? pbcGroup : info.index.k + pbcGroup;
      const top = allTops[topIdx];
      if (!top) {
        this.log(
          `[PIR-AUDIT] OnionPIR Merkle ${treeName}: no tree-top for group ` +
          `${pbcGroup} (leaf bin ${bin})`,
          'error',
        );
        out.set(keys[i], false);
        continue;
      }
      const walked = walkTreeTopToRoot(currentHash[i], nodeIdx[i], top, arity);
      // `onionTreeTopRoot` is non-null — `checkTreeTopAnchor` already
      // rejected any tree-top without a root level.
      const expected = onionTreeTopRoot(top);
      const ok = expected !== null && bytesEqual(walked, expected);
      if (!ok) {
        this.log(
          `[PIR-AUDIT] OnionPIR Merkle ${treeName} group ${pbcGroup} bin ` +
          `${bin}: root MISMATCH`,
          'error',
        );
      }
      out.set(keys[i], ok);
    }

    const verified = [...out.values()].filter(Boolean).length;
    this.log(`[PIR-AUDIT] OnionPIR Merkle ${treeName}: ${verified}/${n} leaves verified`);
    return out;
  }
}

export function reassembleCompleteOnionChunks(
  startChunkId: number,
  numChunks: number,
  byteOffset: number,
  decryptedEntries: ReadonlyMap<number, Uint8Array>,
): Uint8Array {
  if (!Number.isSafeInteger(startChunkId) || startChunkId < 0
      || !Number.isSafeInteger(numChunks) || numChunks <= 0
      || !Number.isSafeInteger(byteOffset) || byteOffset < 0) {
    throw new Error('OnionPIR INDEX result has invalid CHUNK coordinates');
  }
  const parts: Uint8Array[] = [];
  let chunkSize: number | null = null;
  for (let offset = 0; offset < numChunks; offset += 1) {
    const entryId = startChunkId + offset;
    const entry = decryptedEntries.get(entryId);
    if (!entry) {
      throw new Error(`OnionPIR provider omitted expected CHUNK entry ${entryId}`);
    }
    if (entry.length === 0 || (chunkSize !== null && entry.length !== chunkSize)) {
      throw new Error(`OnionPIR provider returned malformed CHUNK entry ${entryId}`);
    }
    chunkSize ??= entry.length;
    if (offset === 0) {
      if (byteOffset >= entry.length) {
        throw new Error('OnionPIR INDEX byte offset exceeds the first CHUNK');
      }
      parts.push(entry.slice(byteOffset));
    } else {
      parts.push(entry);
    }
  }
  const totalLen = parts.reduce((sum, part) => sum + part.length, 0);
  const fullData = new Uint8Array(totalLen);
  let position = 0;
  for (const part of parts) {
    fullData.set(part, position);
    position += part.length;
  }
  return fullData;
}

// ─── Hex helper ─────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
