/**
 * Browser DPF client: a thin wrapper around `WasmDpfClient` (the native Rust
 * `DpfClient`) that connects both servers, runs the connection checks in
 * `verification.ts`, and translates results into the `QueryResult` shape the
 * UI and `sync-merge.ts` use.
 *
 * The PIR work, the padding invariants and per-query Merkle verification all
 * live in native code: `queryBatchVerified` verifies each result and
 * reports its verdict in `merkleVerified`.
 */

import { hexToBytes } from './hash.js';
import {
  databaseCatalogFromWasmJson,
  type DatabaseCatalog,
  type DatabaseCatalogEntry,
} from './server-info.js';
import {
  initSdkWasm,
  isSdkWasmReady,
  requireSdkWasm,
  type WasmDpfClient,
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
import type { ConnectionState, QueryResult, UtxoEntry } from './types.js';
import { enableCreditsOnLeg, type CreditEnablement, type CreditProvider } from './credits.js';

export { gateOperatorIdentity, type OperatorIdentity, type ServerAttestation } from './verification.js';

export interface BatchPirClientConfig {
  server0Url: string;
  server1Url: string;
  onConnectionStateChange?: (state: ConnectionState, message?: string) => void;
  onLog?: (msg: string, level: 'info' | 'success' | 'error') => void;
  /** Upgrade both connections to the encrypted channel after attesting
   * (default `true`). */
  useSecureChannel?: boolean;
  /** AMD ARK fingerprint for the VCEK chain check. `undefined` uses the
   * Turin ARK; `null` skips the chain check. */
  expectedArkFingerprint?: Uint8Array | null;
  expectedServer0Pin?: ServerAttestPin;
  expectedServer1Pin?: ServerAttestPin;
  onAttestation?: (serverIndex: 0 | 1, info: ServerAttestation) => void;
  /** Operator keys; a server's announce bundle is checked when its key is set. */
  pinnedOperatorPubkey0?: Uint8Array;
  pinnedOperatorPubkey1?: Uint8Array;
  /** Staleness cap on the announce bundle's `issuedAt` (0 = none). */
  maxAnnounceAgeSeconds?: number;
  onOperatorIdentity?: (serverIndex: 0 | 1, info: OperatorIdentity) => void;
  /** Credits (`docs/CREDITS.md`) for servers that charge for DPF. */
  creditProvider?: CreditProvider;
  onCredits?: (serverIndex: 0 | 1, status: CreditEnablement) => void;
  /** Operator-issued API key, presented instead of credits. */
  apiKey?: string;
  databaseProofPins?: DatabaseProofPin[];
  onDatabaseProof?: (dbId: number, info: DatabaseProofStatus) => void;
}

export class BatchPirClientAdapter {
  private readonly config: BatchPirClientConfig;
  private wasmClient: WasmDpfClient | null = null;
  private catalog: DatabaseCatalog | null = null;
  private connected = false;
  private secureChannel = false;

  attestation: { server0: ServerAttestation; server1: ServerAttestation } = {
    server0: { state: 'unattested' },
    server1: { state: 'unattested' },
  };
  operatorIdentity: { server0: OperatorIdentity; server1: OperatorIdentity } = {
    server0: { state: 'not-checked' },
    server1: { state: 'not-checked' },
  };
  databaseProofs: Map<number, DatabaseProofStatus> = new Map();

  constructor(config: BatchPirClientConfig) {
    this.config = { ...config };
  }

  async connect(): Promise<void> {
    this.setState('connecting');
    try {
      if (!isSdkWasmReady() && !(await initSdkWasm())) {
        throw new Error('PIR SDK WASM failed to load');
      }
      const client = new (requireSdkWasm().WasmDpfClient)(
        this.config.server0Url,
        this.config.server1Url,
      );
      this.wasmClient = client;
      client.onStateChange((state: string) => {
        if (this.wasmClient !== client) return;
        if (state === 'connected' || state === 'disconnected' || state === 'connecting' || state === 'reconnecting') {
          this.setState(state);
        }
      });
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
      this.setState('connected');
    } catch (error) {
      this.log(`Connect failed: ${(error as Error)?.message ?? error}`, 'error');
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

  hasMerkleForDb(dbId: number): boolean {
    return this.getCatalogEntry(dbId)?.hasBucketMerkle ?? false;
  }

  /** The verified database proof's bucket Merkle root, if any. */
  getMerkleRootHexForDb(dbId: number): string | undefined {
    return this.databaseProofs.get(dbId)?.proof?.bucketSuperRootHex;
  }

  /** Query `scriptHashes` (20-byte HASH160s) against `dbId`. A slot is `null`
   * when nothing was probed for it. */
  async queryBatch(
    scriptHashes: Uint8Array[],
    onProgress?: (step: string, detail: string) => void,
    dbId: number = 0,
  ): Promise<(QueryResult | null)[]> {
    const client = this.wasmClient;
    if (!client || !this.isConnected()) throw new Error('Not connected');
    onProgress?.('Level 1', 'sending batched INDEX queries');
    const handles = await client.queryBatchVerified(packScriptHashes(scriptHashes), dbId);
    onProgress?.('Decode', `translating ${handles.length} results`);
    return handles.map((handle) => {
      try {
        const result = translateWasmResult(handle);
        const probed = (result.allIndexBins?.length ?? 0) > 0 || result.isWhale || result.entries.length > 0;
        return probed ? result : null;
      } finally {
        handle.free();
      }
    });
  }

  /** Same as `queryBatch`; delta results carry their encoded delta in
   * `rawChunkData` for `sync-merge.ts`. */
  async queryDelta(
    scriptHashes: Uint8Array[],
    dbId: number = 1,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    return this.queryBatch(scriptHashes, onProgress, dbId);
  }

  /** Present the API key, or enable credits, on one server. The outcome goes
   * to `onCredits`. */
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

  private async attestAndUpgrade(client: WasmDpfClient): Promise<void> {
    const checks = await attestPair(client, {
      pins: [this.config.expectedServer0Pin, this.config.expectedServer1Pin],
      operatorPins: [this.config.pinnedOperatorPubkey0, this.config.pinnedOperatorPubkey1],
      arkFingerprint: arkFingerprint(this.config.expectedArkFingerprint),
      maxAnnounceAgeSeconds: this.config.maxAnnounceAgeSeconds,
      log: (msg, level) => this.log(msg, level),
    });
    this.attestation = { server0: checks.attestation[0], server1: checks.attestation[1] };
    this.operatorIdentity = { server0: checks.operatorIdentity[0], server1: checks.operatorIdentity[1] };
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

  private async teardown(): Promise<void> {
    this.connected = false;
    this.secureChannel = false;
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

  private setState(state: ConnectionState, message?: string): void {
    this.config.onConnectionStateChange?.(state, message);
  }

  private log(msg: string, level: 'info' | 'success' | 'error' = 'info'): void {
    this.config.onLog?.(msg, level);
  }
}

/** Pack 20-byte HASH160s into one `Uint8Array(20 * N)`. */
function packScriptHashes(hashes: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(hashes.length * 20);
  hashes.forEach((hash, i) => {
    if (hash.length !== 20) throw new Error(`scriptHash[${i}] must be 20 bytes, got ${hash.length}`);
    out.set(hash, i * 20);
  });
  return out;
}

/** Translate a verified `WasmQueryResult` into the UI's `QueryResult`. */
function translateWasmResult(wqr: WasmQueryResult): QueryResult {
  const entries: UtxoEntry[] = [];
  for (let i = 0; i < wqr.entryCount; i++) {
    const e = wqr.getEntry(i);
    if (!e) continue;
    entries.push({
      txid: hexToBytes(e.txid),
      vout: Number(e.vout),
      amount: BigInt(e.amountSats ?? e.amount ?? 0),
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
    entries,
    totalSats: wqr.totalBalance,
    startChunkId: 0,
    numChunks: chunkBins.length,
    numRounds: 0,
    isWhale: wqr.isWhale,
    merkleVerified: wqr.merkleVerified,
    rawChunkData: rawChunkData instanceof Uint8Array ? rawChunkData : undefined,
    indexPbcGroup: primary?.pbcGroup,
    indexBinIndex: primary?.binIndex,
    indexBinContent: primary?.binContent,
    allIndexBins: indexBins.length > 0 ? indexBins : undefined,
    chunkPbcGroups: chunkBins.length > 0 ? chunkBins.map((b) => b.pbcGroup) : undefined,
    chunkBinIndices: chunkBins.length > 0 ? chunkBins.map((b) => b.binIndex) : undefined,
    chunkBinContents: chunkBins.length > 0 ? chunkBins.map((b) => hexToBytes(b.binContent)) : undefined,
  };
}
