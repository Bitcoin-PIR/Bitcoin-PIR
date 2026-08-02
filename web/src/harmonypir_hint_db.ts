/**
 * IndexedDB persistence for complete HarmonyPIR hint state (v4 schema).
 *
 * Stores the opaque byte blob produced by `WasmHarmonyClient.saveHints()`
 * (self-describing, fingerprinted — see `crates/sdk/client/src/hint_cache.rs`)
 * together with the effective master PRP key and backend selected during
 * hint setup. A page reload throws away the in-memory `WasmHarmonyClient`,
 * so this binding has to be persisted next to the hint blob — otherwise a
 * restored hint bundle can't be replayed.
 *
 * Records are keyed by the exact verified admission binding plus dataset and
 * PRP backend. Endpoint-only v2 records are deliberately discarded: they do
 * not prove which provider, signed policy, scope, and offer paid for the
 * expensive hint download. The 16-byte
 * `fingerprintHex` is an integrity/debug field; the authoritative
 * cross-check happens inside `WasmHarmonyClient.loadHints(bytes, catalog, db_id)`
 * which re-derives and compares the fingerprint before accepting the blob.
 * A fingerprint mismatch surfaces as a thrown `JsError` from the WASM
 * boundary — the caller treats that as "cache stale" and re-fetches.
 *
 * Schema version is bumped to 2 when migrating from the old per-group
 * `Map<number, Uint8Array>` layout. IndexedDB's `onupgradeneeded`
 * handler deletes the store and re-creates it, so pre-Session-6
 * entries are discarded cleanly on first load.
 */

const DB_NAME = 'harmonypir-hints';
const DB_VERSION = 4;
const STORE = 'hints';
const SCHEMA_VERSION = 4;

export interface HarmonyHintCacheBindingV1 {
  providerIdHex: string;
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  datasetIdHex: string;
  prpBackend: number;
}

/** Generic product resources call their backend-specific variant `variant`.
 * Harmony hint persistence names that same value `prpBackend` so it is part
 * of the exact cache key. Keep this conversion explicit at the boundary. */
export interface HarmonyHintResourceBindingV1
  extends Omit<HarmonyHintCacheBindingV1, 'prpBackend'> {
  variant: number;
}

export function resourceBindingToHarmonyHintCacheBindingV1(
  binding: HarmonyHintResourceBindingV1,
): HarmonyHintCacheBindingV1 {
  return {
    providerIdHex: binding.providerIdHex,
    policyDigestHex: binding.policyDigestHex,
    scopeIdHex: binding.scopeIdHex,
    offerId: binding.offerId,
    datasetIdHex: binding.datasetIdHex,
    prpBackend: binding.variant,
  };
}

/** Stored IndexedDB record containing a complete main+sibling hint bundle. */
export interface StoredHints {
  cacheKey: string;
  dbId: number;
  providerIdHex: string;
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  datasetIdHex: string;
  prpBackend: number;
  /** Effective backend selected by V2 hint setup. */
  backend: number;
  /** Effective 16-byte master PRP key bound to the hint bytes. */
  masterKey: Uint8Array;
  /** Self-describing hint blob from `WasmHarmonyClient.saveHints()`. */
  bytes: Uint8Array;
  /** 16-byte fingerprint (hex) — informational; authoritative check is in WASM. */
  fingerprintHex: string;
  savedAt: number;
  schemaVersion: number;
}

export function buildCacheKey(binding: HarmonyHintCacheBindingV1, dbId: number): string {
  const provider = canonicalHex32('providerIdHex', binding.providerIdHex);
  const policy = canonicalHex32('policyDigestHex', binding.policyDigestHex);
  const scope = canonicalHex32('scopeIdHex', binding.scopeIdHex);
  const dataset = canonicalHex32('datasetIdHex', binding.datasetIdHex);
  if (!Number.isSafeInteger(binding.offerId) || binding.offerId <= 0) {
    throw new Error('Harmony hint offerId must be a positive safe integer');
  }
  if (!Number.isSafeInteger(binding.prpBackend) || binding.prpBackend < 0
      || binding.prpBackend > 0xffff_ffff) {
    throw new Error('Harmony hint PRP backend is invalid');
  }
  if (!Number.isSafeInteger(dbId) || dbId < 0 || dbId > 0xffff_ffff) {
    throw new Error('Harmony hint dbId is invalid');
  }
  return `${provider}|${policy}|${scope}|${binding.offerId}|${dataset}|${dbId}|${binding.prpBackend}`;
}

function idbAvailable(): boolean {
  return typeof indexedDB !== 'undefined';
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      // Endpoint-only v2 records and older layouts cannot prove the exact
      // admission binding. Drop them rather than silently treating an old
      // hint purchase as valid under a rotated policy or different provider.
      if (db.objectStoreNames.contains(STORE)) {
        db.deleteObjectStore(STORE);
      }
      db.createObjectStore(STORE, { keyPath: 'cacheKey' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB open failed'));
    req.onblocked = () => reject(new Error('IndexedDB open blocked'));
  });
}

export async function putHints(record: StoredHints): Promise<void> {
  if (!idbAvailable()) throw new Error('IndexedDB not available');
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error('IndexedDB put failed'));
      tx.onabort = () => reject(tx.error ?? new Error('IndexedDB put aborted'));
      tx.objectStore(STORE).put(record);
    });
  } finally {
    db.close();
  }
}

export async function getHints(cacheKey: string): Promise<StoredHints | undefined> {
  if (!idbAvailable()) return undefined;
  const db = await openDb();
  try {
    return await new Promise<StoredHints | undefined>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(cacheKey);
      req.onsuccess = () => {
        const rec = req.result as StoredHints | undefined;
        // Defensive check: if something older than v2 survived the
        // upgrade handler (e.g. a browser that delivered onupgradeneeded
        // for a different reason), reject it silently so callers
        // re-download.
        if (rec && rec.schemaVersion !== SCHEMA_VERSION) resolve(undefined);
        else resolve(rec);
      };
      req.onerror = () => reject(req.error ?? new Error('IndexedDB get failed'));
    });
  } finally {
    db.close();
  }
}

export async function deleteHints(cacheKey: string): Promise<void> {
  if (!idbAvailable()) return;
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error('IndexedDB delete failed'));
      tx.objectStore(STORE).delete(cacheKey);
    });
  } finally {
    db.close();
  }
}

export const HINT_SCHEMA_VERSION = SCHEMA_VERSION;

/** Format a 16-byte fingerprint as a hex string for storage/debug. */
export function fingerprintToHex(fp: Uint8Array): string {
  let out = '';
  for (const b of fp) out += b.toString(16).padStart(2, '0');
  return out;
}

function canonicalHex32(field: string, value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value) || /^0{64}$/.test(value)) {
    throw new Error(`${field} must be non-zero lowercase 32-byte hex`);
  }
  return value;
}
