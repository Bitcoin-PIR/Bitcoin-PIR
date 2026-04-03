/**
 * WASM bridge for pir-core-wasm.
 *
 * Provides TypeScript-friendly wrappers around the WASM module's (hi, lo)
 * u32-pair API, converting to/from BigInt. WASM is initialized eagerly
 * and is required — there is no pure-TS fallback.
 */

// ─── WASM module type ────────────────────────────────────────────────────

interface PirCoreWasm {
  splitmix64(x_hi: number, x_lo: number): Uint8Array;
  compute_tag(tag_seed_hi: number, tag_seed_lo: number, script_hash: Uint8Array): Uint8Array;
  derive_buckets(script_hash: Uint8Array, k: number): Uint32Array;
  derive_cuckoo_key(master_seed_hi: number, master_seed_lo: number, bucket_id: number, hash_fn: number): Uint8Array;
  cuckoo_hash(script_hash: Uint8Array, key_hi: number, key_lo: number, num_bins: number): number;
  derive_chunk_buckets(chunk_id: number, k: number): Uint32Array;
  derive_chunk_cuckoo_key(master_seed_hi: number, master_seed_lo: number, bucket_id: number, hash_fn: number): Uint8Array;
  cuckoo_hash_int(chunk_id: number, key_hi: number, key_lo: number, num_bins: number): number;
}

// ─── State ───────────────────────────────────────────────────────────────

let wasmModule: PirCoreWasm | null = null;
let wasmInitPromise: Promise<void> | null = null;

function wasm(): PirCoreWasm {
  if (!wasmModule) throw new Error('WASM not initialized — call initWasm() first');
  return wasmModule;
}

// ─── Conversion helpers ─────────────────────────────────────────────────

function bigintToHiLo(v: bigint): [number, number] {
  const lo = Number(v & 0xFFFFFFFFn);
  const hi = Number((v >> 32n) & 0xFFFFFFFFn);
  return [hi, lo];
}

function leBytes8ToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 7; i >= 0; i--) result = (result << 8n) | BigInt(bytes[i]);
  return result;
}

// ─── Initialization ─────────────────────────────────────────────────────

/**
 * Load and initialize the WASM module. Must be called (and awaited)
 * before using any hash functions. Safe to call multiple times.
 */
export async function initWasm(): Promise<void> {
  if (wasmModule) return;
  if (wasmInitPromise) return wasmInitPromise;

  wasmInitPromise = (async () => {
    const mod = await import('pir-core-wasm');
    // For bundler target, vite-plugin-wasm handles WASM instantiation.
    // For web target, call init() if present.
    if (typeof (mod as any).default === 'function') {
      await (mod as any).default();
    }
    wasmModule = mod as unknown as PirCoreWasm;
    console.log('[PIR-WASM] WASM module loaded');
  })();

  return wasmInitPromise;
}

/** Returns true if the WASM module has been successfully loaded. */
export function isWasmReady(): boolean {
  return wasmModule !== null;
}

// ─── WASM functions ─────────────────────────────────────────────────────

export function wasmSplitmix64(x: bigint): bigint {
  const [hi, lo] = bigintToHiLo(x);
  return leBytes8ToBigint(wasm().splitmix64(hi, lo));
}

export function wasmComputeTag(tagSeed: bigint, scriptHash: Uint8Array): bigint {
  const [hi, lo] = bigintToHiLo(tagSeed);
  return leBytes8ToBigint(wasm().compute_tag(hi, lo, scriptHash));
}

export function wasmDeriveBuckets(scriptHash: Uint8Array, k: number): number[] {
  return Array.from(wasm().derive_buckets(scriptHash, k));
}

export function wasmDeriveCuckooKey(masterSeed: bigint, bucketId: number, hashFn: number): bigint {
  const [hi, lo] = bigintToHiLo(masterSeed);
  return leBytes8ToBigint(wasm().derive_cuckoo_key(hi, lo, bucketId, hashFn));
}

export function wasmCuckooHash(scriptHash: Uint8Array, key: bigint, numBins: number): number {
  const [hi, lo] = bigintToHiLo(key);
  return wasm().cuckoo_hash(scriptHash, hi, lo, numBins);
}

export function wasmDeriveChunkBuckets(chunkId: number, k: number): number[] {
  return Array.from(wasm().derive_chunk_buckets(chunkId, k));
}

export function wasmDeriveChunkCuckooKey(masterSeed: bigint, bucketId: number, hashFn: number): bigint {
  const [hi, lo] = bigintToHiLo(masterSeed);
  return leBytes8ToBigint(wasm().derive_chunk_cuckoo_key(hi, lo, bucketId, hashFn));
}

export function wasmCuckooHashInt(chunkId: number, key: bigint, numBins: number): number {
  const [hi, lo] = bigintToHiLo(key);
  return wasm().cuckoo_hash_int(chunkId, hi, lo, numBins);
}

// ─── Utility ────────────────────────────────────────────────────────────

/** Compute minimum DPF domain exponent such that 2^n >= bins_per_table. */
export function computeDpfN(binsPerTable: number): number {
  if (binsPerTable <= 1) return 1;
  let n = 0;
  let v = 1;
  while (v < binsPerTable) { v <<= 1; n++; }
  return n;
}
