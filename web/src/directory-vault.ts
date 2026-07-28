/**
 * Encrypted, cross-tab-safe rollback storage for the public Nostr directory.
 *
 * The directory data is public, but encrypting these floors avoids leaving a
 * plaintext browser-history index of previously seen providers. The
 * non-extractable key does not protect against same-origin script compromise.
 */

import type { WasmDirectoryCatalogCandidateV1 } from './sdk-bridge.js';

const DB_NAME = 'bitcoinpir-directory-v1';
const DB_VERSION = 1;
const META_STORE = 'meta';
const STATE_STORE = 'rollback-state';
const KEY_ID = 'non-extractable-aes-gcm-v1';
const STATE_AAD_DOMAIN = 'BitcoinPIR/directory-rollback-state/v1';
const STATE_ID_DOMAIN = 'BitcoinPIR/directory-rollback-key/v1';

interface KeyRecordV1 {
  id: string;
  key: CryptoKey;
}

interface CipherStateRecordV1 {
  id: string;
  /** Public SHA-256 CAS tag; the state itself remains encrypted. */
  stateDigestHex: string;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
}

interface DirectoryStateKeysV1 {
  version: 1;
  directoryPubkeyHex: string;
  entries: string[];
  checkpoints: number[];
}

interface StateEnvelopeV1 {
  version: 1;
  directoryPubkeyHex: string;
  entries: Array<{ providerIdHex: string; state: number[] }>;
  checkpoints: Array<{ shard: number; state: number[] }>;
}

interface RollbackPlanV1 {
  version: 1;
  directoryPubkeyHex: string;
  entries: Array<{
    providerIdHex: string;
    expected: number[] | null;
    successor: number[];
  }>;
  checkpoints: Array<{
    shard: number;
    expected: number[] | null;
    successor: number[];
  }>;
}

interface PreparedCasWriteV1 {
  id: string;
  expectedDigestHex: string | null;
  successorDigestHex: string;
  successor: CipherStateRecordV1;
}

export interface DirectoryDiscoveryEntryJsonV1 {
  v: 1;
  provider_id: string;
  directory_sequence: number;
  directory_valid_until: number;
  status: 'active';
  operator_assertion: unknown;
  catalog_hints: unknown[];
  health: unknown;
}

export interface SelectableDirectoryEntryV1 {
  providerIdHex: string;
  eventIdHex: string;
  directorySequence: string;
  directoryValidUntil: string;
  operatorPubkeyEd25519Hex: string;
  stableServerId: string;
  policySigningKeyEd25519Hex: string;
  assertionEpoch: string;
  policyEpoch: string;
  policyDigestHex: string;
  entry: DirectoryDiscoveryEntryJsonV1;
}

export interface SelectableDirectoryShardV1 {
  shard: number;
  checkpointEpoch: string;
  checkpointRootHex: string;
  entries: SelectableDirectoryEntryV1[];
}

export interface SelectableDirectoryCatalogV1 {
  version: 1;
  directoryPubkeyHex: string;
  shards: SelectableDirectoryShardV1[];
}

export class DirectoryRollbackVaultV1 {
  private constructor(
    private readonly db: IDBDatabase,
    private readonly key: CryptoKey,
  ) {}

  static async open(): Promise<DirectoryRollbackVaultV1> {
    requireBrowserPrimitives();
    return withExclusiveLock('bitcoinpir:directory-vault:init', async () => {
      const db = await openDb();
      let key = await getValue<KeyRecordV1>(db, META_STORE, KEY_ID).then((row) => row?.key);
      if (!key) {
        key = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt'],
        );
        await putValue(db, META_STORE, { id: KEY_ID, key } satisfies KeyRecordV1);
      }
      if (key.extractable || key.algorithm.name !== 'AES-GCM') {
        db.close();
        throw new Error('directory vault key is not a non-extractable AES-GCM key');
      }
      return new DirectoryRollbackVaultV1(db, key);
    });
  }

  close(): void {
    this.db.close();
  }

  /**
   * Execute load -> Rust transition -> atomic CAS -> Rust acknowledgement
   * under one directory-wide Web Lock. No catalog bytes are returned before
   * every entry and all 16 checkpoint floors commit together.
   */
  async acceptCatalog(
    candidate: WasmDirectoryCatalogCandidateV1,
  ): Promise<SelectableDirectoryCatalogV1> {
    const keys = parseStateKeys(candidate.stateKeysJson());
    return withExclusiveLock(`bitcoinpir:directory:${keys.directoryPubkeyHex}`, async () => {
      const current = await this.loadStateEnvelope(keys);
      const plan = parseRollbackPlan(candidate.prepareRollback(encodeJson(current)), keys);
      const writes = await this.prepareCasWrites(plan);
      await applyAtomicCas(this.db, writes);
      const durable = successorEnvelope(plan);
      candidate.acknowledgePersisted(encodeJson(durable));
      return parseSelectableCatalog(candidate.selectableCatalogJson(), keys.directoryPubkeyHex);
    });
  }

  private async loadStateEnvelope(keys: DirectoryStateKeysV1): Promise<StateEnvelopeV1> {
    const entries: StateEnvelopeV1['entries'] = [];
    const checkpoints: StateEnvelopeV1['checkpoints'] = [];
    for (const providerIdHex of keys.entries) {
      const id = await stateId(keys.directoryPubkeyHex, 'entry', providerIdHex);
      const state = await this.loadState(id);
      if (state) entries.push({ providerIdHex, state: Array.from(state) });
    }
    for (const shard of keys.checkpoints) {
      const id = await stateId(keys.directoryPubkeyHex, 'checkpoint', shard.toString(16));
      const state = await this.loadState(id);
      if (state) checkpoints.push({ shard, state: Array.from(state) });
    }
    return { version: 1, directoryPubkeyHex: keys.directoryPubkeyHex, entries, checkpoints };
  }

  private async loadState(id: string): Promise<Uint8Array | null> {
    const row = await getValue<CipherStateRecordV1>(this.db, STATE_STORE, id);
    if (!row) return null;
    validateCipherRow(row, id);
    try {
      const plaintext = new Uint8Array(await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: row.iv,
          additionalData: aad(STATE_AAD_DOMAIN, id),
        },
        this.key,
        row.ciphertext,
      ));
      if (await sha256Hex(plaintext) !== row.stateDigestHex) throw new Error('digest');
      return plaintext;
    } catch {
      throw new Error('directory rollback state authentication failed');
    }
  }

  private async prepareCasWrites(plan: RollbackPlanV1): Promise<PreparedCasWriteV1[]> {
    const pending = [
      ...plan.entries.map((row) => ({
        kind: 'entry' as const,
        key: row.providerIdHex,
        expected: row.expected,
        successor: row.successor,
      })),
      ...plan.checkpoints.map((row) => ({
        kind: 'checkpoint' as const,
        key: row.shard.toString(16),
        expected: row.expected,
        successor: row.successor,
      })),
    ];
    const writes: PreparedCasWriteV1[] = [];
    for (const row of pending) {
      const expected = row.expected === null ? null : fixedStateBytes(row.expected);
      const successor = fixedStateBytes(row.successor);
      const id = await stateId(plan.directoryPubkeyHex, row.kind, row.key);
      const successorDigestHex = await sha256Hex(successor);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: ownedArrayBuffer(iv),
          additionalData: aad(STATE_AAD_DOMAIN, id),
        },
        this.key,
        ownedArrayBuffer(successor),
      );
      writes.push({
        id,
        expectedDigestHex: expected === null ? null : await sha256Hex(expected),
        successorDigestHex,
        successor: {
          id,
          stateDigestHex: successorDigestHex,
          iv: iv.buffer.slice(0),
          ciphertext,
        },
      });
    }
    return writes;
  }
}

function parseStateKeys(json: string): DirectoryStateKeysV1 {
  let value: DirectoryStateKeysV1;
  try {
    value = JSON.parse(json) as DirectoryStateKeysV1;
  } catch {
    throw new Error('WASM returned malformed directory state keys');
  }
  const directory = canonicalHex32('directoryPubkeyHex', value.directoryPubkeyHex);
  if (value.version !== 1 || !Array.isArray(value.entries) || !Array.isArray(value.checkpoints)) {
    throw new Error('WASM returned an unsupported directory state-key envelope');
  }
  const entries = value.entries.map((entry) => canonicalHex32('providerIdHex', entry));
  if (new Set(entries).size !== entries.length) throw new Error('duplicate directory state key');
  const checkpoints = value.checkpoints.map(canonicalShard);
  if (checkpoints.length !== 16 || new Set(checkpoints).size !== 16
      || checkpoints.some((shard, index) => shard !== index)) {
    throw new Error('directory state keys must contain all 16 ordered shards');
  }
  return { version: 1, directoryPubkeyHex: directory, entries, checkpoints };
}

function parseRollbackPlan(json: string, keys: DirectoryStateKeysV1): RollbackPlanV1 {
  let value: RollbackPlanV1;
  try {
    value = JSON.parse(json) as RollbackPlanV1;
  } catch {
    throw new Error('WASM returned malformed directory rollback plan');
  }
  if (value.version !== 1
      || canonicalHex32('directoryPubkeyHex', value.directoryPubkeyHex) !== keys.directoryPubkeyHex
      || !Array.isArray(value.entries) || !Array.isArray(value.checkpoints)) {
    throw new Error('WASM returned a directory rollback plan for the wrong namespace');
  }
  const entryKeys = value.entries.map((row) => canonicalHex32('providerIdHex', row.providerIdHex));
  if (entryKeys.length !== keys.entries.length
      || entryKeys.some((entry, index) => entry !== keys.entries[index])) {
    throw new Error('directory rollback plan entry keys do not match the verified catalog');
  }
  const shards = value.checkpoints.map((row) => canonicalShard(row.shard));
  if (shards.length !== 16 || shards.some((shard, index) => shard !== index)) {
    throw new Error('directory rollback plan is missing an ordered shard checkpoint');
  }
  for (const row of [...value.entries, ...value.checkpoints]) {
    if (row.expected !== null) fixedStateBytes(row.expected);
    fixedStateBytes(row.successor);
  }
  return value;
}

function successorEnvelope(plan: RollbackPlanV1): StateEnvelopeV1 {
  return {
    version: 1,
    directoryPubkeyHex: plan.directoryPubkeyHex,
    entries: plan.entries.map((row) => ({
      providerIdHex: row.providerIdHex,
      state: row.successor.slice(),
    })),
    checkpoints: plan.checkpoints.map((row) => ({
      shard: row.shard,
      state: row.successor.slice(),
    })),
  };
}

function parseSelectableCatalog(
  json: string,
  expectedDirectoryPubkeyHex: string,
): SelectableDirectoryCatalogV1 {
  let value: SelectableDirectoryCatalogV1;
  try {
    value = JSON.parse(json) as SelectableDirectoryCatalogV1;
  } catch {
    throw new Error('WASM returned malformed selectable directory catalog');
  }
  if (value.version !== 1
      || canonicalHex32('directoryPubkeyHex', value.directoryPubkeyHex)
        !== expectedDirectoryPubkeyHex
      || !Array.isArray(value.shards) || value.shards.length !== 16) {
    throw new Error('selectable directory catalog has the wrong namespace or shard count');
  }
  const providers = new Set<string>();
  value.shards.forEach((shard, index) => {
    if (canonicalShard(shard.shard) !== index
        || !isPositiveDecimal(shard.checkpointEpoch)
        || canonicalHex32('checkpointRootHex', shard.checkpointRootHex).length !== 64
        || !Array.isArray(shard.entries)) {
      throw new Error('selectable directory shard is malformed');
    }
    for (const item of shard.entries) {
      const provider = canonicalHex32('providerIdHex', item.providerIdHex);
      if (providers.has(provider)) throw new Error('provider appears in multiple directory shards');
      providers.add(provider);
      if (provider[0] !== index.toString(16)
          || canonicalHex32('eventIdHex', item.eventIdHex).length !== 64
          || !isPositiveDecimal(item.directorySequence)
          || !isPositiveDecimal(item.directoryValidUntil)
          || canonicalHex32('operatorPubkeyEd25519Hex', item.operatorPubkeyEd25519Hex).length !== 64
          || typeof item.stableServerId !== 'string' || item.stableServerId.length === 0
          || canonicalHex32(
            'policySigningKeyEd25519Hex',
            item.policySigningKeyEd25519Hex,
          ).length !== 64
          || item.policySigningKeyEd25519Hex === item.operatorPubkeyEd25519Hex
          || !isPositiveDecimal(item.assertionEpoch)
          || !isPositiveDecimal(item.policyEpoch)
          || canonicalHex32('policyDigestHex', item.policyDigestHex).length !== 64
          || item.entry?.v !== 1 || item.entry.status !== 'active'
          || item.entry.provider_id !== provider
          || String(item.entry.directory_sequence) !== item.directorySequence
          || String(item.entry.directory_valid_until) !== item.directoryValidUntil) {
        throw new Error('selectable directory entry is malformed or inconsistent');
      }
    }
  });
  return value;
}

function fixedStateBytes(value: unknown): Uint8Array {
  if (!Array.isArray(value) || value.length === 0 || value.length > 4096
      || value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) {
    throw new Error('directory rollback state is not a bounded byte array');
  }
  return Uint8Array.from(value);
}

function canonicalHex32(field: string, value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value) || /^0{64}$/.test(value)) {
    throw new Error(`${field} must be non-zero lowercase 32-byte hex`);
  }
  return value;
}

function canonicalShard(value: unknown): number {
  if (!Number.isInteger(value) || Number(value) < 0 || Number(value) >= 16) {
    throw new Error('directory shard must be an integer in [0, 15]');
  }
  return Number(value);
}

function isPositiveDecimal(value: unknown): value is string {
  return typeof value === 'string' && /^[1-9][0-9]*$/.test(value);
}

function validateCipherRow(row: CipherStateRecordV1, expectedId: string): void {
  if (row.id !== expectedId || !/^[0-9a-f]{64}$/.test(row.stateDigestHex)
      || !(row.iv instanceof ArrayBuffer) || row.iv.byteLength !== 12
      || !(row.ciphertext instanceof ArrayBuffer) || row.ciphertext.byteLength === 0) {
    throw new Error('directory rollback ciphertext record is malformed');
  }
}

function requireBrowserPrimitives(): void {
  if (typeof indexedDB === 'undefined') throw new Error('IndexedDB is required for directory state');
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('WebCrypto is required for directory state');
  }
  if (typeof navigator === 'undefined' || !navigator.locks) {
    throw new Error('Web Locks are required for directory rollback CAS');
  }
}

async function withExclusiveLock<T>(name: string, body: () => Promise<T>): Promise<T> {
  if (typeof navigator === 'undefined' || !navigator.locks) {
    throw new Error('Web Locks are required for directory rollback CAS');
  }
  return navigator.locks.request(name, { mode: 'exclusive' }, body);
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(META_STORE)) {
        db.createObjectStore(META_STORE, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STATE_STORE)) {
        db.createObjectStore(STATE_STORE, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('failed to open directory IndexedDB'));
    request.onblocked = () => reject(new Error('directory IndexedDB upgrade is blocked'));
  });
}

function getValue<T>(db: IDBDatabase, store: string, key: IDBValidKey): Promise<T | undefined> {
  return requestInTransaction<T | undefined>(db, store, 'readonly', (objectStore) =>
    objectStore.get(key));
}

function putValue(db: IDBDatabase, store: string, value: unknown): Promise<void> {
  return requestInTransaction(db, store, 'readwrite', (objectStore) =>
    objectStore.put(value)).then(() => undefined);
}

function requestInTransaction<T>(
  db: IDBDatabase,
  storeName: string,
  mode: IDBTransactionMode,
  start: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, mode);
    const request = start(tx.objectStore(storeName));
    let result: T;
    request.onsuccess = () => { result = request.result; };
    request.onerror = () => reject(new Error(`IndexedDB ${storeName} request failed`));
    tx.oncomplete = () => resolve(result!);
    tx.onerror = () => reject(new Error(`IndexedDB ${storeName} transaction failed`));
    tx.onabort = () => reject(new Error(`IndexedDB ${storeName} transaction aborted`));
  });
}

function applyAtomicCas(db: IDBDatabase, writes: PreparedCasWriteV1[]): Promise<void> {
  if (writes.length < 16 || new Set(writes.map((write) => write.id)).size !== writes.length) {
    throw new Error('directory CAS plan is incomplete or contains duplicate keys');
  }
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STATE_STORE, 'readwrite');
    const store = tx.objectStore(STATE_STORE);
    let remaining = writes.length;
    let conflict = false;
    for (const write of writes) {
      const request = store.get(write.id) as IDBRequest<CipherStateRecordV1 | undefined>;
      request.onerror = () => tx.abort();
      request.onsuccess = () => {
        if (conflict) return;
        const current = request.result;
        const currentDigest = current?.stateDigestHex ?? null;
        if (currentDigest !== write.expectedDigestHex
            && currentDigest !== write.successorDigestHex) {
          conflict = true;
          tx.abort();
          return;
        }
        remaining -= 1;
        if (remaining === 0) {
          for (const pending of writes) store.put(pending.successor);
        }
      };
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error('directory rollback CAS transaction failed'));
    tx.onabort = () => reject(new Error(
      conflict
        ? 'directory rollback CAS conflict; restart the catalog refresh'
        : 'directory rollback CAS transaction aborted',
    ));
  });
}

async function stateId(
  directoryPubkeyHex: string,
  kind: 'entry' | 'checkpoint',
  key: string,
): Promise<string> {
  return sha256Hex(new TextEncoder().encode(
    `${STATE_ID_DOMAIN}\0${directoryPubkeyHex}\0${kind}\0${key}`,
  ));
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', ownedArrayBuffer(bytes));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function aad(domain: string, id: string): ArrayBuffer {
  return ownedArrayBuffer(new TextEncoder().encode(`${domain}\0${id}`));
}

function encodeJson(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function ownedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
