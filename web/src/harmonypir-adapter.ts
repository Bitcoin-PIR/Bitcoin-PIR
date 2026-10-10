/**
 * Browser HarmonyPIR client: a thin wrapper around `WasmHarmonyClient` (the
 * native Rust `HarmonyClient`) that connects the hint and query servers, runs
 * the connection checks in `verification.ts`, manages hints (download and
 * IndexedDB cache), and translates results into `HarmonyQueryResult`.
 *
 * The PIR work, the padding invariants and per-query Merkle verification all
 * live in native code: `queryBatchVerified` verifies each result and
 * reports its verdict in `merkleVerified`.
 *
 * Hint caching: the native client keys its hints with a 16-byte master PRP
 * key. `saveHintsToCache` stores that key next to the hint blob and
 * `restoreHintsFromCache` re-applies it before loading, so a page reload can
 * reuse downloaded hints; the native fingerprint check rejects a stale blob.
 */

import {
  addressToScriptPubKey,
  bytesToHex,
  hexToBytes,
  scriptHash as computeScriptHash,
} from './hash.js';
import {
  databaseCatalogFromWasmJson,
  type DatabaseCatalog,
  type DatabaseCatalogEntry,
} from './server-info.js';
import {
  initSdkWasm,
  isSdkWasmReady,
  requireSdkWasm,
  type WasmHarmonyClient,
  type WasmQueryResult,
} from './sdk-bridge.js';
import type { DatabaseProofPin, DatabaseProofStatus } from './db-proof.js';
import type { ServerAttestPin } from './attest-pin.js';
import {
  arkFingerprint,
  attestPair,
  verifyDatabaseProofs,
  type OperatorIdentity,
  type ServerAttestation,
} from './verification.js';
import type { HarmonyQueryResult, HarmonyUtxoEntry, QueryInspectorData } from './harmony-types.js';
import {
  buildCacheKey,
  deleteHints as idbDeleteHints,
  fingerprintToHex,
  getHints as idbGetHints,
  putHints as idbPutHints,
  HINT_SCHEMA_VERSION,
  type HarmonyHintCacheBindingV1,
  type StoredHints,
} from './harmonypir_hint_db.js';
import { enableCreditsOnLeg, type CreditEnablement, type CreditProvider } from './credits.js';

export interface HarmonyPirClientConfig {
  hintServerUrl: string;
  queryServerUrl: string;
  onProgress?: (msg: string) => void;
  /** PRP backend: 0 = HMR12 (default), 1 = FastPRP. */
  prpBackend?: number;
  /** Upgrade both connections to the encrypted channel after attesting
   * (default `true`). */
  useSecureChannel?: boolean;
  /** Server 0 is the hint server, 1 the query server. */
  onAttestation?: (serverIndex: 0 | 1, info: ServerAttestation) => void;
  /** `undefined` uses the Turin ARK; `null` skips the VCEK chain check. */
  expectedArkFingerprint?: Uint8Array | null;
  expectedServer0Pin?: ServerAttestPin;
  expectedServer1Pin?: ServerAttestPin;
  /** Operator keys; a server's announce bundle is checked when its key is set. */
  pinnedHintOperatorPubkey?: Uint8Array;
  pinnedQueryOperatorPubkey?: Uint8Array;
  maxAnnounceAgeSeconds?: number;
  onOperatorIdentity?: (serverIndex: 0 | 1, info: OperatorIdentity) => void;
  creditProvider?: CreditProvider;
  onCredits?: (serverIndex: 0 | 1, status: CreditEnablement) => void;
  apiKey?: string;
  databaseProofPins?: DatabaseProofPin[];
  onDatabaseProof?: (dbId: number, info: DatabaseProofStatus) => void;
}

export class HarmonyPirClientAdapter {
  private readonly config: HarmonyPirClientConfig;
  private wasmClient: WasmHarmonyClient | null = null;
  private catalog: DatabaseCatalog | null = null;
  private dbId = 0;
  private connected = false;
  private secureChannel = false;
  /** Whether hints for the active database are loaded. */
  hintsLoaded = false;

  attestation: { hint: ServerAttestation; query: ServerAttestation } = {
    hint: { state: 'unattested' },
    query: { state: 'unattested' },
  };
  operatorIdentity: { hint: OperatorIdentity; query: OperatorIdentity } = {
    hint: { state: 'not-checked' },
    query: { state: 'not-checked' },
  };
  databaseProofs: Map<number, DatabaseProofStatus> = new Map();
  /** Inspector data from the latest `queryBatch` (built from the result's bins). */
  lastInspectorData: Map<number, QueryInspectorData> | null = null;

  constructor(config: HarmonyPirClientConfig) {
    this.config = { ...config };
  }

  async connect(): Promise<void> {
    try {
      if (!isSdkWasmReady() && !(await initSdkWasm())) {
        throw new Error('PIR SDK WASM failed to load');
      }
      const client = new (requireSdkWasm().WasmHarmonyClient)(
        this.config.hintServerUrl,
        this.config.queryServerUrl,
      );
      this.wasmClient = client;
      client.setPrpBackend(this.config.prpBackend ?? 0);
      // Fix the master PRP key before any hints exist; hints are keyed by it.
      const masterKey = new Uint8Array(16);
      crypto.getRandomValues(masterKey);
      client.setMasterKey(masterKey);

      await client.connect();
      if (this.config.useSecureChannel !== false) await this.attestAndUpgrade(client);

      const catalog = await client.fetchCatalog();
      try {
        this.catalog = databaseCatalogFromWasmJson(catalog.toJson());
      } finally {
        catalog.free();
      }
      await verifyDatabaseProofs(client, this.config.databaseProofPins ?? [], (dbId, status) => {
        this.databaseProofs.set(dbId, status);
        this.config.onDatabaseProof?.(dbId, status);
      });
      this.connected = true;
      this.log('Connected to the HarmonyPIR servers');
    } catch (error) {
      await this.teardown().catch(() => {});
      throw error;
    }
  }

  disconnect(): void {
    void this.teardown().catch(() => {});
  }

  isConnected(): boolean {
    return this.connected && !!this.wasmClient?.isConnected;
  }

  getDbId(): number {
    return this.dbId;
  }

  /** Switch the active database; its hints must be loaded before a query. */
  setDbId(dbId: number): void {
    if (dbId === this.dbId) return;
    this.dbId = dbId;
    this.hintsLoaded = false;
    this.wasmClient?.setDbId(dbId);
  }

  getCatalog(): DatabaseCatalog | null {
    return this.catalog;
  }

  getCatalogEntry(dbId: number): DatabaseCatalogEntry | undefined {
    return this.catalog?.databases.find((d) => d.dbId === dbId);
  }

  getDatabaseProofStatus(dbId: number): DatabaseProofStatus | undefined {
    return this.databaseProofs.get(dbId);
  }

  hasMerkleForDb(dbId: number): boolean {
    return this.getCatalogEntry(dbId)?.hasBucketMerkle ?? false;
  }

  /** The active database's verified bucket Merkle root, if any. */
  getMerkleRootHex(): string | undefined {
    return this.databaseProofs.get(this.dbId)?.proof?.bucketSuperRootHex;
  }

  /** Download the hints (main and Merkle-sibling groups) for the active
   * database, reporting per-group progress through `onProgress`. */
  async fetchHints(): Promise<void> {
    const client = this.requireClient();
    this.log('Hints: downloading…');
    client.setDbId(this.dbId);
    const catalog = this.catalogHandle();
    try {
      await client.fetchCompleteHintsWithProgress(catalog, this.dbId, ({ done, total }) => {
        const pct = total > 0 ? Math.round((done / total) * 100) : 0;
        this.log(`Hints: ${done}/${total} (${pct}%)`);
      });
    } finally {
      catalog.free();
    }
    this.hintsLoaded = true;
    this.log('Hints: ready');
  }

  /** Query `addresses` (addresses or scriptPubKey hex) against `dbId`, or the
   * active database. Invalid inputs are skipped; the map is keyed by input
   * index. */
  async queryBatch(
    addresses: string[],
    progress?: (phase: string, detail: string) => void,
    dbId?: number,
  ): Promise<Map<number, HarmonyQueryResult>> {
    const client = this.requireClient();
    if (dbId !== undefined) this.setDbId(dbId);

    const inputs: { index: number; address: string; scriptHash: Uint8Array }[] = [];
    addresses.forEach((input, index) => {
      const spkHex = /^[0-9a-fA-F]+$/.test(input) && input.length % 2 === 0
        ? input.toLowerCase()
        : addressToScriptPubKey(input);
      if (!spkHex) {
        this.log(`Invalid input ${index}: ${input}`);
        return;
      }
      inputs.push({ index, address: input, scriptHash: computeScriptHash(hexToBytes(spkHex)) });
    });
    if (inputs.length === 0) return new Map();

    if (!this.hintsLoaded) {
      progress?.('setup', 'downloading hints');
      await this.fetchHints();
    }

    progress?.('index', `submitting ${inputs.length} queries`);
    const packed = new Uint8Array(inputs.length * 20);
    inputs.forEach((input, i) => packed.set(input.scriptHash, i * 20));
    const handles = await client.queryBatchVerified(packed, this.dbId);
    progress?.('decode', `translating ${handles.length} results`);

    const out = new Map<number, HarmonyQueryResult>();
    const inspector = new Map<number, QueryInspectorData>();
    const merkleRootHex = this.getMerkleRootHex();
    handles.forEach((handle, j) => {
      try {
        const { index, address, scriptHash } = inputs[j];
        const shHex = bytesToHex(scriptHash);
        const result = translateWasmResult(handle, address, shHex, scriptHash, merkleRootHex);
        out.set(index, result);
        inspector.set(index, buildInspectorShim(address, shHex, result));
      } finally {
        handle.free();
      }
    });
    this.lastInspectorData = inspector;
    return out;
  }

  /** Persist the loaded hints to IndexedDB under `binding`. Only a complete
   * set (main and sibling groups) is saved. */
  async saveHintsToCache(binding: HarmonyHintCacheBindingV1): Promise<void> {
    const client = this.wasmClient;
    if (!client || !this.catalog) return;
    const catalog = this.catalogHandle();
    let fingerprint: Uint8Array;
    try {
      if (!client.hasCompleteHints(catalog, this.dbId)) return;
      fingerprint = client.fingerprint(catalog, this.dbId);
    } finally {
      catalog.free();
    }
    const bytes = client.saveHints();
    if (!bytes) return;
    // Store the effective native key and backend: a V2 hint server may assign
    // them, replacing the ones set at connect.
    const record: StoredHints = {
      cacheKey: buildCacheKey(binding, this.dbId),
      dbId: this.dbId,
      datasetIdHex: binding.datasetIdHex,
      prpBackend: binding.prpBackend,
      backend: client.cachePrpBackend(),
      masterKey: client.cacheMasterKey(),
      bytes,
      fingerprintHex: fingerprintToHex(fingerprint),
      savedAt: Date.now(),
      schemaVersion: HINT_SCHEMA_VERSION,
    };
    try {
      await idbPutHints(record);
      this.log(`Hints cached (${(bytes.length / (1024 * 1024)).toFixed(1)} MB)`);
    } catch (error) {
      this.log(`Failed to cache hints: ${(error as Error).message}`);
    }
  }

  /** Load hints saved under `binding`, if any. A stale entry is deleted. */
  async restoreHintsFromCache(binding: HarmonyHintCacheBindingV1): Promise<boolean> {
    const client = this.wasmClient;
    if (!client || !this.catalog) return false;
    const key = buildCacheKey(binding, this.dbId);
    const record = await idbGetHints(key);
    if (!record || record.schemaVersion !== HINT_SCHEMA_VERSION) return false;
    try {
      client.setMasterKey(record.masterKey);
      client.setPrpBackend(record.backend);
      const catalog = this.catalogHandle();
      try {
        client.loadCompleteHints(record.bytes, catalog, this.dbId);
      } finally {
        catalog.free();
      }
      this.hintsLoaded = true;
      this.log(`Hints restored from cache (${(record.bytes.length / (1024 * 1024)).toFixed(1)} MB)`);
      return true;
    } catch (error) {
      this.log(`Cache stale (${(error as Error).message}); re-downloading`);
      await idbDeleteHints(key).catch(() => {});
      return false;
    }
  }

  /** Lowest remaining per-group query budget of the loaded hints. */
  async getMinQueriesRemaining(): Promise<number> {
    return this.wasmClient?.minQueriesRemaining() ?? 0;
  }

  /** Loaded hint size in MB, one decimal place. */
  estimateHintSize(): string {
    const bytes = this.wasmClient?.estimateHintSizeBytes() ?? 0;
    return (bytes / (1024 * 1024)).toFixed(1);
  }

  /** Present the API key, or enable credits, on one server. */
  async enableCredits(serverIndex: 0 | 1): Promise<CreditEnablement | null> {
    if (!this.wasmClient) return null;
    const outcome = await enableCreditsOnLeg(this.wasmClient, serverIndex, {
      apiKey: this.config.apiKey,
      provider: this.config.creditProvider,
      secureChannel: this.secureChannel,
    });
    if (outcome) this.config.onCredits?.(serverIndex, outcome);
    return outcome;
  }

  private async attestAndUpgrade(client: WasmHarmonyClient): Promise<void> {
    const checks = await attestPair(client, {
      pins: [this.config.expectedServer0Pin, this.config.expectedServer1Pin],
      operatorPins: [this.config.pinnedHintOperatorPubkey, this.config.pinnedQueryOperatorPubkey],
      arkFingerprint: arkFingerprint(this.config.expectedArkFingerprint),
      maxAnnounceAgeSeconds: this.config.maxAnnounceAgeSeconds,
      log: (msg) => this.log(msg),
    });
    this.attestation = { hint: checks.attestation[0], query: checks.attestation[1] };
    this.operatorIdentity = { hint: checks.operatorIdentity[0], query: checks.operatorIdentity[1] };
    this.secureChannel = checks.secureChannel;
    for (const idx of [0, 1] as const) {
      this.config.onAttestation?.(idx, checks.attestation[idx]);
      if (checks.operatorIdentity[idx].state !== 'not-checked') {
        this.config.onOperatorIdentity?.(idx, checks.operatorIdentity[idx]);
      }
    }
    if (this.secureChannel) {
      await this.enableCredits(0);
      await this.enableCredits(1);
    }
  }

  private requireClient(): WasmHarmonyClient {
    if (!this.wasmClient || !this.isConnected()) throw new Error('Not connected');
    return this.wasmClient;
  }

  /** The cached catalog as a `WasmDatabaseCatalog` handle (caller frees). */
  private catalogHandle(): any {
    const json = {
      databases: (this.catalog?.databases ?? []).map((db) => ({
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

  private async teardown(): Promise<void> {
    this.connected = false;
    this.secureChannel = false;
    this.hintsLoaded = false;
    this.catalog = null;
    this.databaseProofs.clear();
    const client = this.wasmClient;
    if (!client) return;
    this.wasmClient = null;
    // `disconnect()` borrows the native value; await it before `free()`.
    try {
      await client.disconnect();
    } catch {
      /* already closed */
    }
    client.free();
  }

  private log(msg: string): void {
    this.config.onProgress?.(msg);
  }
}

/** Translate a verified `WasmQueryResult` into a `HarmonyQueryResult` (txid
 * hex in display byte order, value in sats as a number). */
function translateWasmResult(
  wqr: WasmQueryResult,
  address: string,
  scriptHashHex: string,
  scriptHashBytes: Uint8Array,
  merkleRootHex: string | undefined,
): HarmonyQueryResult {
  const utxos: HarmonyUtxoEntry[] = [];
  for (let i = 0; i < wqr.entryCount; i++) {
    const e = wqr.getEntry(i);
    if (!e) continue;
    utxos.push({
      txid: bytesToHex(hexToBytes(e.txid).reverse()),
      vout: Number(e.vout),
      value: Number(e.amountSats ?? e.amount ?? 0),
    });
  }

  type WireBin = { pbcGroup: number; binIndex: number; binContent: string };
  const indexBins = ((wqr.indexBins() as WireBin[]) ?? []).map((b) => ({
    pbcGroup: b.pbcGroup,
    binIndex: b.binIndex,
    binContent: hexToBytes(b.binContent),
  }));
  const chunkBins = (wqr.chunkBins() as WireBin[]) ?? [];
  const matchedIdx = wqr.matchedIndexIdx();
  const primary = typeof matchedIdx === 'number' ? indexBins[matchedIdx] : indexBins[0];
  const rawChunkData = wqr.rawChunkData();

  return {
    address,
    scriptHash: scriptHashHex,
    utxos,
    whale: wqr.isWhale,
    merkleVerified: wqr.merkleVerified,
    merkleRootHex,
    rawChunkData: rawChunkData instanceof Uint8Array ? rawChunkData : undefined,
    scriptHashBytes,
    indexPbcGroup: primary?.pbcGroup,
    indexBinIndex: primary?.binIndex,
    indexBinContent: primary?.binContent,
    allIndexBins: indexBins.length > 0 ? indexBins : undefined,
    chunkPbcGroups: chunkBins.length > 0 ? chunkBins.map((b) => b.pbcGroup) : undefined,
    chunkBinIndices: chunkBins.length > 0 ? chunkBins.map((b) => b.binIndex) : undefined,
    chunkBinContents: chunkBins.length > 0 ? chunkBins.map((b) => hexToBytes(b.binContent)) : undefined,
  };
}

/** Reduced inspector data: the native client does not expose placement
 * rounds or timings. */
function buildInspectorShim(
  address: string,
  scriptHashHex: string,
  qr: HarmonyQueryResult,
): QueryInspectorData {
  return {
    address,
    scriptPubKeyHex: '',
    scriptHashHex,
    candidateIndexGroups: [],
    assignedIndexGroup: qr.indexPbcGroup ?? -1,
    indexPlacementRound: -1,
    indexBinIndex: qr.indexBinIndex,
    isWhale: qr.whale,
    numChunks: qr.chunkPbcGroups?.length ?? 0,
    roundTimings: [],
    totalMs: 0,
  };
}
