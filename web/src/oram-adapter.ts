/**
 * WASM-backed adapter for the single-server TEE ORAM backend.
 *
 * This is intentionally not a DPF/Harmony wrapper. ORAM queries send
 * plaintext script hashes only inside the attested encrypted channel, and the
 * server performs direct INDEX+CHUNK lookup over ORAM images built from
 * `utxo_chunks_index_nodust.bin` and `utxo_chunks_nodust.bin`. There are no
 * PBC groups, no per-bucket Merkle inspector bins, and no browser-side PBC
 * proof verifier on this path.
 */

import type { ServerAttestPin } from './attest-pin.js';
import type { DatabaseProofPin, DatabaseProofStatus } from './db-proof.js';
import { hexToBytes } from './hash.js';
import { attestedRootBindsManifest } from './oram-source-proof.js';
import {
  databaseCatalogFromWasmJson,
  type DatabaseCatalog,
  type DatabaseCatalogEntry,
} from './server-info.js';
import {
  initSdkWasm,
  isSdkWasmReady,
  requireSdkWasm,
  type WasmAtomicMetrics,
  type WasmOramClient,
} from './sdk-bridge.js';
import type { ConnectionState, QueryResult, UtxoEntry } from './types.js';
import {
  arkFingerprint,
  checkOperatorIdentity,
  summariseAttestation,
  verifyDatabaseProofs,
  type OperatorIdentity,
  type ServerAttestation,
} from './verification.js';
import { enableCreditsOnLeg, type CreditEnablement, type CreditProvider } from './credits.js';

export interface OramLayoutInfo {
  backend: 'oram-direct';
  usesPbc: false;
  serverCount: 1;
  merkleModel: 'server-authenticated-oram';
}

export const DEFAULT_ORAM_SCRIPT_HASHES_PER_REQUEST = 1;
export const DEFAULT_ORAM_ACCESS_BUDGET = 50;
export const DEFAULT_ORAM_INDEX_READS_PER_SCRIPT_HASH = 2;

export interface OramBatchPlannerConfig {
  /**
   * Fixed server-side direct ORAM access budget for one lookup frame.
   */
  accessBudget?: number;
  /**
   * Direct INDEX ORAM reads needed for one script hash. This is the direct
   * index cuckoo hash count in the deployed image metadata.
   */
  indexReadsPerScriptHash?: number;
  /**
   * Expected CHUNK ORAM reads per script hash. Use 0 for mostly-not-found
   * scans, 1 for ordinary small UTXO lookups, and a higher value for known
   * dense wallets.
   */
  expectedChunkReadsPerScriptHash?: number;
  /**
   * Extra CHUNK reads to leave unused by the planner in each fixed-budget
   * request. This gives the server room for unexpectedly found chunks.
   */
  chunkReadReserve?: number;
  /**
   * Optional operator/client cap after applying the access-budget model.
   */
  maxScriptHashesPerRequest?: number;
  /**
   * Fixed script-hash slot width sent to the TEE. Empty slots are explicit,
   * so the server can spend dummy INDEX ORAM accesses instead of treating
   * padding as real keys. If omitted, it is derived from the access budget and
   * expected chunk count.
   */
  paddedSlotCount?: number;
}

export interface OramBatchPlan {
  accessBudget: number;
  indexReadsPerScriptHash: number;
  expectedChunkReadsPerScriptHash: number;
  chunkReadReserve: number;
  paddedSlotCount: number;
  maxScriptHashesPerRequest: number;
  chunkReadsAvailableAtMax: number;
}

export interface OramPirClientConfig {
  serverUrl: string;
  onConnectionStateChange?: (state: ConnectionState, message?: string) => void;
  onLog?: (msg: string, level: 'info' | 'success' | 'error') => void;
  /** Upgrade to the encrypted channel after attesting (default `true`). ORAM
   * lookups reveal script hashes to the server process, so privacy rests on
   * the attestation and the channel. */
  useSecureChannel?: boolean;
  onAttestation?: (info: ServerAttestation) => void;
  /** `undefined` uses the Turin ARK; `null` skips the VCEK chain check. */
  expectedArkFingerprint?: Uint8Array | null;
  expectedServerPin?: ServerAttestPin;
  /** Operator key; the announce bundle is checked when it is set. */
  pinnedOperatorPubkey?: Uint8Array;
  maxAnnounceAgeSeconds?: number;
  onOperatorIdentity?: (info: OperatorIdentity) => void;
  creditProvider?: CreditProvider;
  onCredits?: (status: CreditEnablement) => void;
  apiKey?: string;
  databaseProofPins?: DatabaseProofPin[];
  onDatabaseProof?: (dbId: number, info: DatabaseProofStatus) => void;
  /** Script hashes per lookup request; a larger batch is split. */
  maxScriptHashesPerRequest?: number;
  /** Fixed-budget planner: when set, every request carries explicit padded
   * empty slots. */
  batchPlanner?: OramBatchPlannerConfig;
}

export class OramPirClientAdapter {
  private readonly config: OramPirClientConfig;
  private wasmClient: WasmOramClient | null = null;
  private catalog: DatabaseCatalog | null = null;
  private connected = false;
  private secureChannel = false;
  private readonly databaseProofs = new Map<number, DatabaseProofStatus>();

  attestation: ServerAttestation = { state: 'unattested' };
  operatorIdentity: OperatorIdentity = { state: 'not-checked' };

  constructor(config: OramPirClientConfig) {
    this.config = config;
  }

  static layout(): OramLayoutInfo {
    return {
      backend: 'oram-direct',
      usesPbc: false,
      serverCount: 1,
      merkleModel: 'server-authenticated-oram',
    };
  }

  layout(): OramLayoutInfo {
    return OramPirClientAdapter.layout();
  }

  async connect(): Promise<void> {
    await this.teardown().catch(() => {});
    this.setState('connecting');
    try {
      if (!isSdkWasmReady() && !(await initSdkWasm())) {
        throw new Error('PIR SDK WASM failed to load');
      }
      const client = new (requireSdkWasm().WasmOramClient)(this.config.serverUrl);
      this.wasmClient = client;
      await client.connect();
      if (this.config.useSecureChannel !== false) await this.attestAndUpgrade(client);

      const catalog = await client.fetchCatalog();
      try {
        this.catalog = databaseCatalogFromWasmJson(catalog.toJson());
      } finally {
        catalog.free();
      }
      await verifyDatabaseProofs(client, this.config.databaseProofPins ?? [], (dbId, status) => {
        const error = status.state === 'verified' ? this.manifestBindingError(dbId, status) : null;
        const reported: DatabaseProofStatus = error ? { ...status, state: 'unverified', error } : status;
        this.databaseProofs.set(dbId, reported);
        this.config.onDatabaseProof?.(dbId, reported);
      });
      this.connected = true;
      this.setState('connected');
      this.log('Connected to ORAM server', 'success');
    } catch (error) {
      this.log(`ORAM connect failed: ${(error as Error)?.message ?? error}`, 'error');
      await this.teardown().catch(() => {});
      this.setState('disconnected', (error as Error)?.message);
      throw error;
    }
  }

  disconnect(): void {
    void this.teardown().catch(() => {});
    this.setState('disconnected');
  }

  isConnected(): boolean {
    return this.connected && !!this.wasmClient?.isConnected;
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

  /** Direct ORAM has no client-verifiable bucket Merkle trees; the page store
   * is authenticated inside the TEE. */
  hasMerkleForDb(_dbId: number): boolean {
    return false;
  }

  async queryBatch(
    scriptHashes: Uint8Array[],
    onProgress?: (step: string, detail: string) => void,
    dbId: number = 0,
  ): Promise<(QueryResult | null)[]> {
    const client = this.wasmClient;
    if (!client || !this.isConnected()) throw new Error('Not connected');
    const plan = this.config.batchPlanner
      ? resolveOramBatchPlan({
          ...this.config.batchPlanner,
          maxScriptHashesPerRequest:
            this.config.batchPlanner.maxScriptHashesPerRequest ?? this.config.maxScriptHashesPerRequest,
        })
      : null;
    const perRequest = plan?.maxScriptHashesPerRequest
      ?? resolveMaxScriptHashesPerRequest(this.config.maxScriptHashesPerRequest);
    const batches = splitOramScriptHashBatches(scriptHashes, perRequest);
    const results: (QueryResult | null)[] = [];
    for (const [i, batch] of batches.entries()) {
      onProgress?.('ORAM', `lookup ${i + 1}/${batches.length} (${batch.length} script hash${batch.length === 1 ? '' : 'es'})`);
      const packed = packScriptHashes(batch);
      const raw = plan
        ? await client.queryBatchPadded(packed, dbId, plan.paddedSlotCount)
        : await client.queryBatch(packed, dbId);
      raw.forEach((value, j) => {
        const result = oramJsonResultToQueryResult(value);
        if (result) result.scriptHash = batch[j];
        results.push(result);
      });
    }
    onProgress?.('Decode', `translated ${results.length} result(s)`);
    return results;
  }

  async queryDelta(
    scriptHashes: Uint8Array[],
    dbId: number = 1,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    return this.queryBatch(scriptHashes, onProgress, dbId);
  }

  setMetricsRecorder(metrics: WasmAtomicMetrics): void {
    this.wasmClient?.setMetricsRecorder(metrics);
  }

  clearMetricsRecorder(): void {
    this.wasmClient?.clearMetricsRecorder();
  }

  /** Present the API key, or enable credits. */
  async enableCredits(): Promise<CreditEnablement | null> {
    const client = this.wasmClient;
    if (!client) return null;
    const outcome = await enableCreditsOnLeg(
      {
        presentApiKey: (_idx, key) => client.presentApiKey(key),
        enableCredits: (_idx, provider) => client.enableCredits(provider),
      },
      0,
      { apiKey: this.config.apiKey, provider: this.config.creditProvider, secureChannel: this.secureChannel },
    );
    if (outcome) this.config.onCredits?.(outcome);
    return outcome;
  }

  private async attestAndUpgrade(client: WasmOramClient): Promise<void> {
    let att = null;
    try {
      att = await client.attest();
    } catch (error) {
      this.log(`ORAM attest failed: ${(error as Error)?.message ?? error}`, 'error');
    }
    try {
      this.attestation = summariseAttestation(
        att,
        this.config.expectedServerPin,
        arkFingerprint(this.config.expectedArkFingerprint),
      );
      this.config.onAttestation?.(this.attestation);
      if (att && att.serverStaticPub.some((b) => b !== 0)) {
        try {
          await client.upgradeToSecureChannel(att.serverStaticPub);
          this.secureChannel = true;
          this.log('ORAM upgraded to the encrypted channel', 'success');
        } catch (error) {
          this.log(`ORAM upgradeToSecureChannel failed: ${(error as Error)?.message ?? error}`, 'error');
        }
      } else {
        this.log('ORAM channel left in cleartext: no channel key', 'info');
      }
      if (this.config.pinnedOperatorPubkey) {
        this.operatorIdentity = await checkOperatorIdentity(
          () => client.announce(),
          att,
          this.config.pinnedOperatorPubkey,
          this.config.maxAnnounceAgeSeconds ?? 0,
        );
        this.config.onOperatorIdentity?.(this.operatorIdentity);
      }
      if (this.secureChannel) await this.enableCredits();
    } finally {
      att?.free();
    }
  }

  /** Whether the attested server's manifest roots bind this proof. `null` when
   * they do, or when the attestation carried no roots. */
  private manifestBindingError(dbId: number, status: DatabaseProofStatus): string | null {
    const roots = this.attestation.manifestRootsHex;
    const position = this.catalog?.databases.findIndex((database) => database.dbId === dbId) ?? -1;
    if (!roots || position < 0) return null;
    const attested = roots[position] ?? '';
    return attestedRootBindsManifest(attested, status.proof?.manifestRootHex ?? '')
      ? null
      : `the attested manifest root does not bind database ${dbId}`;
  }

  private async teardown(): Promise<void> {
    this.connected = false;
    this.secureChannel = false;
    this.catalog = null;
    this.databaseProofs.clear();
    this.attestation = { state: 'unattested' };
    this.operatorIdentity = { state: 'not-checked' };
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

  private setState(state: ConnectionState, message?: string): void {
    this.config.onConnectionStateChange?.(state, message);
  }

  private log(msg: string, level: 'info' | 'success' | 'error' = 'info'): void {
    this.config.onLog?.(msg, level);
  }
}

export function splitOramScriptHashBatches<T>(
  items: readonly T[],
  maxPerRequest: number = DEFAULT_ORAM_SCRIPT_HASHES_PER_REQUEST,
): T[][] {
  const max = resolveMaxScriptHashesPerRequest(maxPerRequest);
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += max) {
    out.push(items.slice(i, i + max));
  }
  return out;
}

export function planOramScriptHashBatches<T>(
  items: readonly T[],
  config: OramBatchPlannerConfig = {},
): T[][] {
  const plan = resolveOramBatchPlan(config);
  return splitOramScriptHashBatches(items, plan.maxScriptHashesPerRequest);
}

export function resolveOramBatchPlan(config: OramBatchPlannerConfig = {}): OramBatchPlan {
  const accessBudget = resolvePositiveInteger(
    'accessBudget',
    config.accessBudget,
    DEFAULT_ORAM_ACCESS_BUDGET,
  );
  const indexReadsPerScriptHash = resolvePositiveInteger(
    'indexReadsPerScriptHash',
    config.indexReadsPerScriptHash,
    DEFAULT_ORAM_INDEX_READS_PER_SCRIPT_HASH,
  );
  const expectedChunkReadsPerScriptHash = resolveNonNegativeInteger(
    'expectedChunkReadsPerScriptHash',
    config.expectedChunkReadsPerScriptHash,
    0,
  );
  const chunkReadReserve = resolveNonNegativeInteger(
    'chunkReadReserve',
    config.chunkReadReserve,
    0,
  );
  const explicitPaddedSlotCount =
    config.paddedSlotCount === undefined
      ? undefined
      : resolvePositiveInteger('paddedSlotCount', config.paddedSlotCount, 1);
  const paddedSlotCount =
    explicitPaddedSlotCount ??
    Math.floor(
      (accessBudget - chunkReadReserve) /
        (indexReadsPerScriptHash + expectedChunkReadsPerScriptHash),
    );
  if (paddedSlotCount < 1) {
    throw new Error(
      `ORAM batch planner cannot fit one padded slot in access budget ${accessBudget}`,
    );
  }

  const indexBudget = paddedSlotCount * indexReadsPerScriptHash;
  if (indexBudget + chunkReadReserve > accessBudget) {
    throw new Error(
      `ORAM padded slot count ${paddedSlotCount} needs ${indexBudget} INDEX reads plus ${chunkReadReserve} reserved CHUNK reads, exceeding access budget ${accessBudget}`,
    );
  }

  const chunkBudgetAfterReserve = accessBudget - indexBudget - chunkReadReserve;
  const chunkLimitedMax =
    expectedChunkReadsPerScriptHash === 0
      ? paddedSlotCount
      : Math.min(
          paddedSlotCount,
          Math.floor(chunkBudgetAfterReserve / expectedChunkReadsPerScriptHash),
        );
  const cappedMax = config.maxScriptHashesPerRequest === undefined
    ? chunkLimitedMax
    : Math.min(
        chunkLimitedMax,
        resolveMaxScriptHashesPerRequest(config.maxScriptHashesPerRequest),
      );
  if (cappedMax < 1) {
    throw new Error(
      `ORAM batch planner cannot fit one real script hash in access budget ${accessBudget}`,
    );
  }

  return {
    accessBudget,
    indexReadsPerScriptHash,
    expectedChunkReadsPerScriptHash,
    chunkReadReserve,
    paddedSlotCount,
    maxScriptHashesPerRequest: cappedMax,
    chunkReadsAvailableAtMax: accessBudget - paddedSlotCount * indexReadsPerScriptHash,
  };
}

function resolveMaxScriptHashesPerRequest(value?: number): number {
  const max = value ?? DEFAULT_ORAM_SCRIPT_HASHES_PER_REQUEST;
  if (!Number.isInteger(max) || max < 1) {
    throw new Error(`maxScriptHashesPerRequest must be a positive integer, got ${value}`);
  }
  return max;
}

function resolvePositiveInteger(name: string, value: number | undefined, fallback: number): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved < 1) {
    throw new Error(`${name} must be a positive integer, got ${value}`);
  }
  return resolved;
}

function resolveNonNegativeInteger(
  name: string,
  value: number | undefined,
  fallback: number,
): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved < 0) {
    throw new Error(`${name} must be a non-negative integer, got ${value}`);
  }
  return resolved;
}

export function oramJsonResultToQueryResult(value: any): QueryResult | null {
  if (value == null) return null;
  const entries: UtxoEntry[] = Array.isArray(value.entries)
    ? value.entries.map((e: any) => ({
        txid: typeof e.txid === 'string' ? hexToBytes(e.txid) : new Uint8Array(e.txid ?? []),
        vout: Number(e.vout ?? 0),
        amount: BigInt(e.amountSats ?? e.amount ?? 0),
      }))
    : [];
  const rawChunkData = parseMaybeBytes(value.rawChunkData);
  const total =
    value.totalBalance !== undefined
      ? BigInt(value.totalBalance)
      : entries.reduce((acc, e) => acc + e.amount, 0n);

  return {
    entries,
    totalSats: total,
    startChunkId: Number(value.startChunkId ?? 0),
    numChunks: Number(value.numChunks ?? 0),
    numRounds: 1,
    isWhale: Boolean(value.isWhale ?? value.whale ?? false),
    merkleVerified: value.merkleVerified,
    rawChunkData,
  };
}

function packScriptHashes(hashes: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(hashes.length * 20);
  for (let i = 0; i < hashes.length; i++) {
    if (hashes[i].length !== 20) {
      throw new Error(`scriptHash[${i}] must be 20 bytes, got ${hashes[i].length}`);
    }
    out.set(hashes[i], i * 20);
  }
  return out;
}

function parseMaybeBytes(value: any): Uint8Array | undefined {
  if (value == null) return undefined;
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string') return hexToBytes(value);
  if (Array.isArray(value)) return new Uint8Array(value);
  return undefined;
}
