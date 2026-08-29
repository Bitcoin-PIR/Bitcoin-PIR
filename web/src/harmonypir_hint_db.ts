/**
 * IndexedDB persistence for complete HarmonyPIR hint state (v5 schema).
 *
 * Stores the opaque byte blob produced by `WasmHarmonyClient.saveHints()`
 * (self-describing, fingerprinted — see `crates/sdk/client/src/hint_cache.rs`)
 * together with the effective master PRP key and backend selected during
 * hint setup. A page reload throws away the in-memory `WasmHarmonyClient`,
 * so this binding has to be persisted next to the hint blob — otherwise a
 * restored hint bundle can't be replayed.
 *
 * Records are keyed by the verified dataset root, database id, and PRP
 * backend. The dataset root (`bucketSuperRootHex` from the verified database
 * proof) already pins the exact database content; the blob's self-describing
 * `fingerprintHex` is re-derived and compared inside
 * `WasmHarmonyClient.loadHints(bytes, catalog, db_id)` before the blob is
 * accepted, so a record bound to a different database can never replay.
 * A fingerprint mismatch surfaces as a thrown `JsError` from the WASM
 * boundary — the caller treats that as "cache stale" and re-fetches.
 *
 * Schema version is bumped whenever the record layout changes. IndexedDB's
 * `onupgradeneeded` handler deletes the store and re-creates it, so
 * older entries are discarded cleanly on first load.
 */

const DB_NAME = 'harmonypir-hints';
const DB_VERSION = 5;
const STORE = 'hints';
const SCHEMA_VERSION = 5;

export interface HarmonyHintCacheBindingV1 {
  datasetIdHex: string;
  prpBackend: number;
}

/** Stored IndexedDB record containing a complete main+sibling hint bundle. */
export interface StoredHints {
  cacheKey: string;
  dbId: number;
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
  const dataset = canonicalHex32('datasetIdHex', binding.datasetIdHex);
  if (!Number.isSafeInteger(binding.prpBackend) || binding.prpBackend < 0
      || binding.prpBackend > 0xffff_ffff) {
    throw new Error('Harmony hint PRP backend is invalid');
  }
  if (!Number.isSafeInteger(dbId) || dbId < 0 || dbId > 0xffff_ffff) {
    throw new Error('Harmony hint dbId is invalid');
  }
  return `${dataset}|${dbId}|${binding.prpBackend}`;
}

function idbAvailable(): boolean {
  return typeof indexedDB !== 'undefined';
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      // Records from older schema versions are discarded rather than
      // migrated: a hint blob is only ever a cache of bytes the server
      // can stream again, and an old-layout record cannot prove it was
      // built for this dataset.
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
        // Defensive check: if something older than the current schema
        // survived the upgrade handler (e.g. a browser that delivered
        // onupgradeneeded for a different reason), reject it silently so
        // callers re-download.
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
