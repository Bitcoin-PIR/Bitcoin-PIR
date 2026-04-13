/**
 * Bridge between the existing web client and pir-sdk-wasm.
 *
 * This module provides a migration path from the pure-TS implementation
 * to the Rust SDK via WASM. Functions check if the WASM module is loaded
 * and fall back to the TS implementation if not.
 */

import type { DatabaseCatalog, DatabaseCatalogEntry } from './server-info.js';
import type { SyncPlan, SyncStep } from './sync.js';
import { computeSyncPlan as computeSyncPlanTS } from './sync.js';

// ─── WASM module type ───────────────────────────────────────────────────────

interface PirSdkWasm {
  WasmDatabaseCatalog: {
    new(): WasmDatabaseCatalog;
    fromJson(json: any): WasmDatabaseCatalog;
  };
  WasmSyncPlan: WasmSyncPlan;
  WasmQueryResult: {
    new(): WasmQueryResult;
    fromJson(json: any): WasmQueryResult;
  };
  computeSyncPlan(catalog: WasmDatabaseCatalog, lastSyncedHeight?: number | null): WasmSyncPlan;
  mergeDelta(snapshot: WasmQueryResult, deltaRaw: Uint8Array): WasmQueryResult;
  decodeDeltaData(raw: Uint8Array): DeltaDataJson;
  // Hash functions
  splitmix64(xHi: number, xLo: number): Uint8Array;
  computeTag(tagSeedHi: number, tagSeedLo: number, scriptHash: Uint8Array): Uint8Array;
  deriveGroups(scriptHash: Uint8Array, k: number): Uint32Array;
  deriveCuckooKey(masterSeedHi: number, masterSeedLo: number, groupId: number, hashFn: number): Uint8Array;
  cuckooHash(scriptHash: Uint8Array, keyHi: number, keyLo: number, numBins: number): number;
  deriveChunkGroups(chunkId: number, k: number): Uint32Array;
  cuckooHashInt(chunkId: number, keyHi: number, keyLo: number, numBins: number): number;
  // PBC
  cuckooPlace(candGroupsFlat: Uint32Array, numItems: number, numGroups: number, maxKicks: number, numHashes: number): Int32Array;
  planRounds(itemGroupsFlat: Uint32Array, itemsPer: number, numGroups: number, numHashes: number, maxKicks: number): [number, number][][];
  // Codec
  readVarint(data: Uint8Array, offset: number): Uint32Array;
  decodeUtxoData(data: Uint8Array): UtxoEntryRaw[];
}

interface WasmDatabaseCatalog {
  free(): void;
  readonly count: number;
  readonly latestTip: number | undefined;
  getDatabase(index: number): any;
  toJson(): any;
}

interface WasmSyncPlan {
  free(): void;
  readonly stepsCount: number;
  readonly isFreshSync: boolean;
  readonly targetHeight: number;
  readonly isEmpty: boolean;
  getStep(index: number): any;
  toJson(): any;
}

interface WasmQueryResult {
  free(): void;
  readonly entryCount: number;
  readonly totalBalance: bigint;
  readonly isWhale: boolean;
  getEntry(index: number): any;
  toJson(): any;
}

interface DeltaDataJson {
  spent: string[];
  newUtxos: UtxoEntryRaw[];
}

interface UtxoEntryRaw {
  txid: string;
  vout: number;
  amount?: number;
  amountSats?: number;
}

// ─── State ──────────────────────────────────────────────────────────────────

let sdkWasm: PirSdkWasm | null = null;
let sdkInitPromise: Promise<boolean> | null = null;

// ─── Initialization ─────────────────────────────────────────────────────────

/**
 * Initialize the PIR SDK WASM module.
 * Returns true if successful, false if WASM is not available.
 */
export async function initSdkWasm(): Promise<boolean> {
  if (sdkWasm) return true;
  if (sdkInitPromise) return sdkInitPromise;

  sdkInitPromise = (async () => {
    try {
      // Dynamic import - the bundler resolves the WASM package
      // @ts-ignore - pir-sdk-wasm may not be installed
      const mod = await import('pir-sdk-wasm');
      // wasm-pack generates a default export that initializes the module
      if (typeof (mod as any).default === 'function') {
        await (mod as any).default();
      }
      sdkWasm = mod as unknown as PirSdkWasm;
      console.log('[PIR-SDK] WASM module loaded successfully');
      return true;
    } catch (e) {
      console.warn('[PIR-SDK] Failed to load WASM module, using pure-TS fallback:', e);
      return false;
    }
  })();

  return sdkInitPromise;
}

/**
 * Check if SDK WASM is loaded and ready.
 */
export function isSdkWasmReady(): boolean {
  return sdkWasm !== null;
}

// ─── Catalog Conversion ─────────────────────────────────────────────────────

/**
 * Convert web client DatabaseCatalog to SDK format.
 */
function catalogToSdkFormat(catalog: DatabaseCatalog): any {
  return {
    databases: catalog.databases.map(db => ({
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
    })),
  };
}

/**
 * Convert SDK SyncPlan to web client format.
 */
function sdkPlanToWebFormat(plan: WasmSyncPlan): SyncPlan {
  const steps: SyncStep[] = [];
  for (let i = 0; i < plan.stepsCount; i++) {
    const step = plan.getStep(i);
    if (step) {
      steps.push({
        dbId: step.dbId,
        dbType: step.dbType,
        name: step.name,
        baseHeight: step.baseHeight,
        tipHeight: step.tipHeight,
      });
    }
  }
  return {
    steps,
    isFreshSync: plan.isFreshSync,
    targetHeight: plan.targetHeight,
  };
}

// ─── SDK-backed Functions ───────────────────────────────────────────────────

/**
 * Compute sync plan using SDK WASM if available, otherwise fall back to TS.
 *
 * This is a drop-in replacement for the TS computeSyncPlan function.
 */
export function computeSyncPlanSdk(
  catalog: DatabaseCatalog,
  lastSyncedHeight?: number,
): SyncPlan {
  // Try WASM first
  if (sdkWasm) {
    try {
      const sdkCatalog = sdkWasm.WasmDatabaseCatalog.fromJson(catalogToSdkFormat(catalog));
      const sdkPlan = sdkWasm.computeSyncPlan(sdkCatalog, lastSyncedHeight ?? null);
      const result = sdkPlanToWebFormat(sdkPlan);
      // Free WASM objects
      sdkPlan.free();
      sdkCatalog.free();
      return result;
    } catch (e) {
      console.warn('[PIR-SDK] WASM computeSyncPlan failed, falling back to TS:', e);
    }
  }

  // Fall back to TypeScript implementation
  return computeSyncPlanTS(catalog, lastSyncedHeight);
}

// ─── Hash Function Wrappers ─────────────────────────────────────────────────

/**
 * Convert 8-byte LE array to BigInt.
 */
function leBytes8ToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 7; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Split BigInt into [hi, lo] u32 pair.
 */
function bigintToHiLo(v: bigint): [number, number] {
  const lo = Number(v & 0xFFFFFFFFn);
  const hi = Number((v >> 32n) & 0xFFFFFFFFn);
  return [hi, lo];
}

/**
 * SDK-backed splitmix64.
 */
export function sdkSplitmix64(x: bigint): bigint | undefined {
  if (!sdkWasm) return undefined;
  const [hi, lo] = bigintToHiLo(x);
  const result = sdkWasm.splitmix64(hi, lo);
  return leBytes8ToBigint(result);
}

/**
 * SDK-backed computeTag.
 */
export function sdkComputeTag(tagSeed: bigint, scriptHash: Uint8Array): bigint | undefined {
  if (!sdkWasm) return undefined;
  const [hi, lo] = bigintToHiLo(tagSeed);
  const result = sdkWasm.computeTag(hi, lo, scriptHash);
  return leBytes8ToBigint(result);
}

/**
 * SDK-backed deriveGroups.
 */
export function sdkDeriveGroups(scriptHash: Uint8Array, k: number): number[] | undefined {
  if (!sdkWasm) return undefined;
  const result = sdkWasm.deriveGroups(scriptHash, k);
  return Array.from(result);
}

/**
 * SDK-backed deriveCuckooKey.
 */
export function sdkDeriveCuckooKey(
  masterSeed: bigint,
  groupId: number,
  hashFn: number,
): bigint | undefined {
  if (!sdkWasm) return undefined;
  const [hi, lo] = bigintToHiLo(masterSeed);
  const result = sdkWasm.deriveCuckooKey(hi, lo, groupId, hashFn);
  return leBytes8ToBigint(result);
}

/**
 * SDK-backed cuckooHash.
 */
export function sdkCuckooHash(
  scriptHash: Uint8Array,
  key: bigint,
  numBins: number,
): number | undefined {
  if (!sdkWasm) return undefined;
  const [hi, lo] = bigintToHiLo(key);
  return sdkWasm.cuckooHash(scriptHash, hi, lo, numBins);
}

/**
 * SDK-backed deriveChunkGroups.
 */
export function sdkDeriveChunkGroups(chunkId: number, k: number): number[] | undefined {
  if (!sdkWasm) return undefined;
  const result = sdkWasm.deriveChunkGroups(chunkId, k);
  return Array.from(result);
}

/**
 * SDK-backed cuckooHashInt.
 */
export function sdkCuckooHashInt(
  chunkId: number,
  key: bigint,
  numBins: number,
): number | undefined {
  if (!sdkWasm) return undefined;
  const [hi, lo] = bigintToHiLo(key);
  return sdkWasm.cuckooHashInt(chunkId, hi, lo, numBins);
}

// ─── Re-exports for convenience ─────────────────────────────────────────────

export { computeSyncPlanTS };
export type { SyncPlan, SyncStep } from './sync.js';
