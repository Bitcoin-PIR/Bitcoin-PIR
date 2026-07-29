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

import { getAmdTurinArkFingerprint, PIR_OPERATOR_PUBKEY } from './attest-pin.js';
import type { ServerAttestPin } from './attest-pin.js';
import {
  databaseProofUnavailable,
  verifiedDatabaseProofFromWasm,
  verifyDatabaseProofAgainstPin,
  type DatabaseProofPin,
  type DatabaseProofStatus,
} from './db-proof.js';
import {
  gateOperatorIdentity,
  type OperatorIdentity,
  type ServerAttestation,
} from './dpf-adapter.js';
import { hexToBytes } from './hash.js';
import {
  databaseCatalogFromWasmJson,
  type DatabaseCatalog,
  type DatabaseCatalogEntry,
} from './server-info.js';
import {
  requireSdkWasm,
  type WasmAnnounceVerification,
  type WasmAtomicMetrics,
  type WasmAttestVerification,
  type WasmPolicyRequirements,
  type WasmOramClient,
} from './sdk-bridge.js';
import type { ConnectionState, QueryResult, UtxoEntry } from './types.js';
import type { ProductQueryShapeV1 } from './service-entitlement.js';
import {
  assertLiveOperatorIdentityV1,
  type ServiceAdmissionPortV1,
} from './service-admission.js';
import {
  assertStrictDatabasePinCoverage,
  assertStrictSingleTransportReady,
} from './strict-verification.js';

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
  /**
   * Default true. ORAM lookups reveal script hashes to the server process, so
   * production callers should leave this enabled and require the server to
   * reject cleartext ORAM frames.
   */
  useSecureChannel?: boolean;
  /** Production enables the complete attestation/identity/root fail-closed gate. */
  strictVerification?: boolean;
  onAttestation?: (info: ServerAttestation) => void;
  expectedArkFingerprint?: Uint8Array | null;
  expectedServerPin?: ServerAttestPin;
  verifyOperatorIdentity?: boolean;
  /** Expected operator-endorsed runtime identity. Required for V1 admission. */
  expectedServerId?: string;
  pinnedOperatorPubkey?: Uint8Array;
  maxAnnounceAgeSeconds?: number;
  onOperatorIdentity?: (info: OperatorIdentity) => void;
  databaseProofPins?: DatabaseProofPin[];
  onDatabaseProof?: (dbId: number, info: DatabaseProofStatus) => void;
  /**
   * Number of script hashes to send in one fixed-budget ORAM lookup request.
   * The default is deliberately conservative: one script hash gets the full
   * server access budget after its fixed INDEX probes. Operators can raise
   * this after measuring their direct-index hash count and chunk overflow rate.
   */
  maxScriptHashesPerRequest?: number;
  /**
   * Opt-in direct ORAM fixed-budget planner. When unset, the adapter preserves
   * the conservative `maxScriptHashesPerRequest` split behavior.
   * When set, every request is sent with explicit padded empty slots.
   */
  batchPlanner?: OramBatchPlannerConfig;
}

export class OramPirClientAdapter {
  private readonly config: OramPirClientConfig;
  private wasmClient: WasmOramClient | null = null;
  private catalog: DatabaseCatalog | null = null;
  private connected = false;
  private strictReady = false;
  private secureChannelEstablished = false;
  private readonly databaseProofs = new Map<number, DatabaseProofStatus>();
  private sessionGeneration = 0;

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
    await this.teardown().catch(() => { /* start from an empty native session */ });
    const generation = ++this.sessionGeneration;
    let client: WasmOramClient | null = null;
    this.resetSessionTrust();
    this.setState('connecting');
    try {
      if (this.isStrictVerification() && this.config.useSecureChannel === false) {
        throw new Error('strict ORAM requires the secure channel');
      }

      const sdk = requireSdkWasm();
      client = new sdk.WasmOramClient(this.config.serverUrl);
      this.wasmClient = client;
      await client.connect();
      this.assertCurrentSession(generation, client, 'connect');

      if (this.config.useSecureChannel !== false) {
        await this.attestAndUpgrade();
      }
      this.assertCurrentSession(generation, client, 'secure-channel upgrade');
      if (this.isStrictVerification()) {
        assertStrictSingleTransportReady({
          secureChannelEstablished: this.secureChannelEstablished,
          attestation: this.attestation,
          expectedPin: this.config.expectedServerPin,
          expectedServerId: this.config.expectedServerId,
          operatorIdentity: this.operatorIdentity,
        });
      }

      // This native catalog is fetched over the exact transport that was just
      // upgraded. A second clear diagnostic WebSocket is deliberately absent:
      // it cannot add, remove, or rewrite databases used by query routing.
      const wasmCatalog = await client.fetchCatalog();
      try {
        this.assertCurrentSession(generation, client, 'catalog fetch');
        this.catalog = databaseCatalogFromWasmJson(wasmCatalog.toJson());
      } finally {
        wasmCatalog.free();
      }
      if (this.isStrictVerification()) {
        assertStrictDatabasePinCoverage(
          this.catalog.databases.map((database) => database.dbId),
          this.config.databaseProofPins ?? [],
        );
      }
      await this.verifyConfiguredDatabaseProofs(generation, client);
      this.assertCurrentSession(generation, client, 'database-proof verification');
      if (this.isStrictVerification()) {
        for (const database of this.catalog.databases) {
          if (this.databaseProofs.get(database.dbId)?.state !== 'verified') {
            throw new Error(
              `strict ORAM requires a verified database proof for db ${database.dbId}`,
            );
          }
        }
      }

      this.connected = true;
      this.strictReady = this.isStrictVerification();
      this.setState('connected');
      this.log('Connected to ORAM server', 'success');
    } catch (e) {
      this.log(`ORAM connect failed: ${(e as Error)?.message ?? e}`, 'error');
      if (
        generation === this.sessionGeneration
        && (client === null || this.wasmClient === client)
      ) {
        await this.teardown().catch(() => { /* preserve original error */ });
        this.setState('disconnected', (e as Error)?.message);
      }
      throw e;
    }
  }

  disconnect(): void {
    void this.teardown().catch(() => { /* best-effort close */ });
    this.setState('disconnected');
  }

  isConnected(): boolean {
    const nativeConnected = this.connected && !!this.wasmClient?.isConnected;
    return this.isStrictVerification() ? nativeConnected && this.strictReady : nativeConnected;
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

  /** Strict provider-local admission for the single ORAM provider. */
  serviceAdmissionPort(dbId: number): ServiceAdmissionPortV1 {
    const client = (): WasmOramClient => {
      if (!this.wasmClient) throw new Error('Not connected');
      if (!this.isStrictVerification() || !this.strictReady) {
        throw new Error('V1 service admission requires completed strict ORAM verification');
      }
      if (!this.secureChannelEstablished) {
        throw new Error('V1 service admission requires a verified secure channel');
      }
      if (!this.config.expectedServerPin?.binarySha256Hex || this.attestation.pinStatus !== 'match') {
        throw new Error('V1 service admission requires a matching binary pin');
      }
      if (
        this.config.verifyOperatorIdentity !== true
        || !this.config.expectedServerId
        || this.operatorIdentity.state !== 'verified'
        || this.operatorIdentity.serverId !== this.config.expectedServerId
      ) {
        throw new Error('V1 service admission requires the expected verified operator identity');
      }
      if (this.databaseProofs.get(dbId)?.state !== 'verified') {
        throw new Error(`V1 service admission requires a verified database proof for db ${dbId}`);
      }
      return this.wasmClient;
    };
    return {
      assertTrustAnchor: (trust) => {
        client();
        assertLiveOperatorIdentityV1(trust, this.operatorIdentity);
      },
      fetchPolicy: (providerId, policyKey, nowUnix, checkpoint) =>
        client().fetchServicePolicy(dbId, providerId, policyKey, nowUnix, checkpoint),
      fetchRetainedRedemption: (
        providerId, policyKey, policyDigest, scopeId, offerId, nowUnix,
      ) => client().fetchRetainedServiceRedemption(
        dbId, providerId, policyKey, policyDigest, scopeId, offerId, nowUnix,
      ),
      assertSessionBinding: (policy) => client().verifyServicePolicySession(policy),
      captureReadinessGuard: () => {
        const expectedClient = client();
        const expectedGeneration = this.sessionGeneration;
        const assertReady = () => {
          this.assertCurrentSession(
            expectedGeneration,
            expectedClient,
            'service admission readiness',
          );
          client();
        };
        assertReady();
        return assertReady;
      },
      assertRetainedSessionBinding: (policy, nowUnix) =>
        client().verifyRetainedServiceSession(policy, nowUnix),
      authorize: (policy, scopeId, offerId, proof) =>
        client().authorizeService(dbId, policy, scopeId, offerId, proof),
      authorizeRetained: (policy, proof, nowUnix) =>
        client().authorizeRetainedService(dbId, policy, proof, nowUnix),
      requestPowChallenge: (policy, scopeId, offerId, nowUnix) =>
        client().requestServicePowChallenge(dbId, policy, scopeId, offerId, nowUnix),
    };
  }

  /**
   * ORAM does not publish client-verifiable per-PBC bucket trees. The direct
   * ORAM page store is authenticated server-side against trusted state.
   */
  hasMerkle(): boolean {
    return false;
  }

  hasMerkleForDb(_dbId: number): boolean {
    return false;
  }

  getMerkleRootHex(): undefined {
    return undefined;
  }

  getMerkleRootHexForDb(_dbId: number): undefined {
    return undefined;
  }

  async queryBatch(
    scriptHashes: Uint8Array[],
    onProgress?: (step: string, detail: string) => void,
    dbId: number = 0,
  ): Promise<(QueryResult | null)[]> {
    return this.queryBatchInternal(scriptHashes, dbId, onProgress);
  }

  async queryDelta(
    scriptHashes: Uint8Array[],
    dbId: number = 1,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    return this.queryBatchInternal(scriptHashes, dbId, onProgress);
  }

  /** Exact zero-wire accounting for the single atomic ORAM request frame. */
  planServiceQuery(
    scriptHashes: Uint8Array[],
    dbId: number = 0,
  ): ProductQueryShapeV1 {
    if (!this.wasmClient) throw new Error('Not connected');
    if (this.isStrictVerification()
        && (!this.strictReady || this.databaseProofs.get(dbId)?.state !== 'verified')) {
      throw new Error(`strict ORAM service planning requires verified db_id ${dbId}`);
    }
    const plannerConfig = this.config.batchPlanner
      ? {
          ...this.config.batchPlanner,
          maxScriptHashesPerRequest:
            this.config.batchPlanner.maxScriptHashesPerRequest
            ?? this.config.maxScriptHashesPerRequest,
        }
      : null;
    const plan = plannerConfig ? resolveOramBatchPlan(plannerConfig) : null;
    const maxRealInputs = plan
      ? plan.maxScriptHashesPerRequest
      : resolveMaxScriptHashesPerRequest(this.config.maxScriptHashesPerRequest);
    const batch = requireAtomicOramRequest(scriptHashes, maxRealInputs);
    if (batch.length === 0) throw new Error('ORAM service plan requires an input');
    const chargedSlots = plan?.paddedSlotCount ?? batch.length;
    return {
      backend: 'tee-oram',
      workload: 'tee-oram-query',
      lowerBounds: {
        logicalInputs: chargedSlots,
        frames: 1,
        concurrentSockets: 1,
        workUnits: chargedSlots.toString(),
      },
    };
  }

  /**
   * There is no browser-side PBC Merkle verifier on direct ORAM. Kept as an
   * explicit method so UI code can fail closed if it accidentally routes ORAM
   * results into the DPF/Harmony verification path.
   */
  async verifyMerkleBatch(
    _results: QueryResult[],
    _onProgress?: (step: string, detail: string) => void,
    _dbId: number = 0,
  ): Promise<boolean[]> {
    throw new Error('Direct ORAM does not expose PBC bucket Merkle proofs');
  }

  setMetricsRecorder(metrics: WasmAtomicMetrics): void {
    this.wasmClient?.setMetricsRecorder(metrics);
  }

  clearMetricsRecorder(): void {
    this.wasmClient?.clearMetricsRecorder();
  }

  private async queryBatchInternal(
    scriptHashes: Uint8Array[],
    dbId: number,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    if (!this.wasmClient) throw new Error('Not connected');
    const client = this.wasmClient;
    const generation = this.sessionGeneration;
    this.assertLiveQuerySession(generation, client, dbId, 'start');
    const plannerConfig = this.config.batchPlanner
      ? {
          ...this.config.batchPlanner,
          maxScriptHashesPerRequest:
            this.config.batchPlanner.maxScriptHashesPerRequest ??
            this.config.maxScriptHashesPerRequest,
        }
      : null;
    const plan = plannerConfig ? resolveOramBatchPlan(plannerConfig) : null;
    const maxRealInputs = plan
      ? plan.maxScriptHashesPerRequest
      : resolveMaxScriptHashesPerRequest(this.config.maxScriptHashesPerRequest);
    const batch = requireAtomicOramRequest(scriptHashes, maxRealInputs);
    if (batch.length === 0) return [];

    // One service authorization grants exactly one REQ_ORAM_LOOKUP frame. Do
    // not silently split a product query: the first frame would complete the
    // grant and a second frame would either fail or tempt cross-query reuse.
    onProgress?.(
      'ORAM',
      plan
        ? `one atomic fixed-budget lookup (${batch.length}/${plan.paddedSlotCount} real slot${batch.length === 1 ? '' : 's'})`
        : `one atomic fixed-budget lookup (${batch.length} script hash${batch.length === 1 ? '' : 'es'})`,
    );
    const packed = packScriptHashes(batch);
    const raw = plan
      ? await client.queryBatchPadded(packed, dbId, plan.paddedSlotCount)
      : await client.queryBatch(packed, dbId);
    this.assertLiveQuerySession(generation, client, dbId, 'response');
    if (raw.length !== batch.length) {
      throw new Error(
        `ORAM response length ${raw.length} does not match request length ${batch.length}`,
      );
    }
    onProgress?.('Decode', `translating ${raw.length} direct result(s)`);
    const results: (QueryResult | null)[] = [];
    for (let i = 0; i < raw.length; i++) {
      const qr = oramJsonResultToQueryResult(raw[i]);
      if (qr) qr.scriptHash = batch[i];
      results.push(qr);
    }

    return results;
  }

  private async teardown(): Promise<void> {
    ++this.sessionGeneration;
    this.strictReady = false;
    this.secureChannelEstablished = false;
    this.connected = false;
    this.catalog = null;
    this.databaseProofs.clear();
    this.attestation = { state: 'unattested' };
    this.operatorIdentity = { state: 'not-checked' };
    const client = this.wasmClient;
    if (client) {
      this.wasmClient = null;
      try {
        await client.disconnect();
      } catch {
        /* already closed */
      }
      client.free();
    }
  }

  private async verifyConfiguredDatabaseProofs(
    generation: number,
    client: WasmOramClient,
  ): Promise<void> {
    this.assertCurrentSession(generation, client, 'database-proof start');
    this.databaseProofs.clear();
    const pins = this.config.databaseProofPins ?? [];
    for (const pin of pins) {
      let status: DatabaseProofStatus;
      let proofHandle: Awaited<ReturnType<WasmOramClient['verifyDatabaseProof']>> | null = null;
      try {
        proofHandle = await client.verifyDatabaseProof(
          pin.dbId,
          pin.paramsHashHex,
          pin.builderBinarySha256Hex,
          pin.builderGitCommit,
        );
        if (generation !== this.sessionGeneration || this.wasmClient !== client) {
          proofHandle.free();
          proofHandle = null;
          throw new Error(`stale ORAM database-proof result for db ${pin.dbId}`);
        }
        const proof = verifiedDatabaseProofFromWasm(proofHandle);
        status = verifyDatabaseProofAgainstPin(proof, pin);
        if (status.state === 'verified') {
          const moved = proofHandle;
          proofHandle = null;
          client.installVerifiedDatabaseProof(moved);
        }
      } catch (e) {
        if (generation !== this.sessionGeneration || this.wasmClient !== client) throw e;
        status = databaseProofUnavailable(pin, e);
      } finally {
        proofHandle?.free();
      }
      this.assertCurrentSession(generation, client, `database-proof db ${pin.dbId}`);
      this.databaseProofs.set(pin.dbId, status);
      this.config.onDatabaseProof?.(pin.dbId, status);
      if (status.state === 'verified') {
        this.log(
          `ORAM DB proof db ${pin.dbId}: verified MuHash ${status.proof?.muhashHex.slice(0, 16)}...`,
          'success',
        );
      } else if (status.state === 'unavailable') {
        this.log(`ORAM DB proof db ${pin.dbId}: unavailable (${status.error})`, 'info');
      } else {
        this.log(
          `ORAM DB proof db ${pin.dbId}: unverified (${status.mismatches?.[0] ?? status.error ?? 'check failed'})`,
          'error',
        );
      }
    }
  }

  private isStrictVerification(): boolean {
    return this.config.strictVerification === true;
  }

  private resetSessionTrust(): void {
    this.connected = false;
    this.strictReady = false;
    this.secureChannelEstablished = false;
    this.catalog = null;
    this.databaseProofs.clear();
    this.attestation = { state: 'unattested' };
    this.operatorIdentity = { state: 'not-checked' };
  }

  private assertCurrentSession(
    generation: number,
    client: WasmOramClient,
    operation: string,
  ): void {
    if (generation !== this.sessionGeneration || this.wasmClient !== client) {
      throw new Error(`stale ORAM ${operation} result`);
    }
  }

  private assertLiveQuerySession(
    generation: number,
    client: WasmOramClient,
    dbId: number,
    operation: string,
  ): void {
    this.assertCurrentSession(generation, client, `query ${operation}`);
    if (!this.isStrictVerification()) return;
    if (!this.strictReady || !this.connected || !client.isConnected) {
      throw new Error('strict ORAM query requires the live verified native session');
    }
    if (this.databaseProofs.get(dbId)?.state !== 'verified') {
      throw new Error(`strict ORAM query requires a verified database proof for db ${dbId}`);
    }
  }

  private async attestAndUpgrade(): Promise<void> {
    if (!this.wasmClient) return;

    let att: WasmAttestVerification | null = null;
    try {
      att = await this.wasmClient.attest();
    } catch (e) {
      this.log(`ORAM attest failed: ${(e as Error)?.message ?? e}`, 'error');
    }

    let expectedArkFp: Uint8Array | null;
    if (this.config.expectedArkFingerprint === null) {
      expectedArkFp = null;
    } else if (this.config.expectedArkFingerprint !== undefined) {
      expectedArkFp = this.config.expectedArkFingerprint;
    } else {
      try {
        expectedArkFp = getAmdTurinArkFingerprint();
      } catch (e) {
        this.log(
          `ORAM default ARK fingerprint unavailable: ${(e as Error)?.message ?? e}`,
          'info',
        );
        expectedArkFp = null;
      }
    }

    const sdk = requireSdkWasm();
    const policyReqs = new sdk.WasmPolicyRequirements();
    try {
      const summary = this.summariseAttestation(att, expectedArkFp, policyReqs);
      this.attestation = summary;
      this.config.onAttestation?.(summary);

      const channelReady = summary.state === 'verified' || summary.state === 'verified-vcek';
      if (channelReady && att) {
        try {
          await this.wasmClient.upgradeToSecureChannel(att.serverStaticPub);
          this.secureChannelEstablished = true;
          this.log('ORAM upgraded to encrypted channel', 'success');
        } catch (e) {
          this.log(`ORAM upgradeToSecureChannel failed: ${(e as Error)?.message ?? e}`, 'error');
          this.attestation = { ...summary, state: 'mismatch' };
          this.config.onAttestation?.(this.attestation);
        }
      } else {
        this.log(`ORAM channel left in cleartext (${summary.state})`, 'info');
      }

      if (this.config.verifyOperatorIdentity && this.secureChannelEstablished && att) {
        const pin = this.config.pinnedOperatorPubkey ?? PIR_OPERATOR_PUBKEY;
        const oid = await this.verifyOperatorIdentity(att, pin);
        this.operatorIdentity = oid;
        this.config.onOperatorIdentity?.(oid);
      } else if (this.config.verifyOperatorIdentity) {
        const oid: OperatorIdentity = {
          state: 'error',
          error: 'secure channel unavailable; operator identity was not requested',
        };
        this.operatorIdentity = oid;
        this.config.onOperatorIdentity?.(oid);
      }
    } finally {
      policyReqs.free();
      att?.free();
    }
  }

  private summariseAttestation(
    att: WasmAttestVerification | null,
    expectedArkFp: Uint8Array | null,
    policyReqs: WasmPolicyRequirements,
  ): ServerAttestation {
    if (!att) return { state: 'mismatch' };

    const allZero = att.serverStaticPub.every((b) => b === 0);
    const matched = att.sevStatus === 'reportDataMatch';
    const noSev = att.sevStatus === 'noSevHost';
    const channelOk = matched || noSev;
    let state: ServerAttestation['state'];
    if (allZero) state = 'plaintext';
    else if (!channelOk) state = 'mismatch';
    else state = 'verified';

    const result: ServerAttestation = {
      state,
      sevStatus: att.sevStatus,
      serverStaticPubHex: att.serverStaticPubHex,
      binarySha256Hex: att.binarySha256Hex,
      gitRev: att.gitRev,
      launchMeasurementHex: att.launchMeasurementHex,
    };

    if (state === 'verified' && matched && att.hasVcekChain) {
      if (expectedArkFp) {
        try {
          att.verifyFull(expectedArkFp, policyReqs);
          result.state = 'verified-vcek';
          result.vcekChain = 'pass';
        } catch (e) {
          result.vcekChain = 'fail';
          result.vcekChainError = (e as Error)?.message ?? String(e);
          result.state = 'mismatch';
          this.log(`ORAM verifyFull failed: ${result.vcekChainError}`, 'error');
        }
      } else {
        result.vcekChain = 'skipped';
      }
    } else if (state === 'verified' && matched && !att.hasVcekChain) {
      result.vcekChain = 'skipped';
    }

    const pin = this.config.expectedServerPin;
    if (pin) {
      const stateOk = result.state === 'verified' || result.state === 'verified-vcek';
      if (stateOk) {
        if (pin.measurementHex && !att.launchMeasurementHex) {
          result.pinStatus = 'measurement-mismatch';
          result.pinError = 'attestation omitted the configured launch measurement claim';
          result.state = 'mismatch';
        } else if (
          pin.measurementHex
          && pin.measurementHex.toLowerCase() !== att.launchMeasurementHex.toLowerCase()
        ) {
          result.pinStatus = 'measurement-mismatch';
          result.pinError = `MEASUREMENT pin mismatch: expected ${pin.measurementHex.slice(0, 16)}..., got ${att.launchMeasurementHex.slice(0, 16)}...`;
          result.state = 'mismatch';
        } else if (pin.binarySha256Hex && !att.binarySha256Hex) {
          result.pinStatus = 'binary-mismatch';
          result.pinError = 'attestation omitted the configured binary sha256 claim';
          result.state = 'mismatch';
        } else if (
          pin.binarySha256Hex
          && pin.binarySha256Hex.toLowerCase() !== att.binarySha256Hex.toLowerCase()
        ) {
          result.pinStatus = 'binary-mismatch';
          result.pinError = `binary_sha256 pin mismatch: expected ${pin.binarySha256Hex.slice(0, 16)}..., got ${att.binarySha256Hex.slice(0, 16)}...`;
          result.state = 'mismatch';
        } else if (pin.measurementHex || pin.binarySha256Hex) {
          result.pinStatus = 'match';
        } else {
          result.pinStatus = 'no-pin';
        }
      }
    } else {
      result.pinStatus = 'no-pin';
    }
    return result;
  }

  private async verifyOperatorIdentity(
    att: WasmAttestVerification | null,
    pin: Uint8Array,
  ): Promise<OperatorIdentity> {
    if (!this.wasmClient) {
      return { state: 'error', error: 'wasm client not initialised' };
    }
    if (!att) {
      return { state: 'error', error: 'attestation unavailable; cannot bind channel key' };
    }
    let v: WasmAnnounceVerification;
    try {
      v = await this.wasmClient.announce();
    } catch (e) {
      const msg = (e as Error)?.message ?? String(e);
      if (/not configured/i.test(msg)) {
        this.log('ORAM operator identity not configured', 'info');
        return { state: 'unconfigured' };
      }
      this.log(`ORAM announce failed: ${msg}`, 'error');
      return { state: 'error', error: msg };
    }
    try {
      const nowSecs = BigInt(Math.floor(Date.now() / 1000));
      const maxAge = BigInt(this.config.maxAnnounceAgeSeconds ?? 0);
      const result = gateOperatorIdentity(v, pin, att.serverStaticPub, nowSecs, maxAge);
      if (result.state === 'verified') {
        this.log(`ORAM operator identity verified (${result.serverId})`, 'success');
      } else {
        this.log(`ORAM operator identity UNVERIFIED: ${result.error}`, 'error');
      }
      return result;
    } finally {
      v.free();
    }
  }

  private setState(state: ConnectionState, message?: string): void {
    this.config.onConnectionStateChange?.(state, message);
  }

  private log(msg: string, level: 'info' | 'success' | 'error' = 'info'): void {
    this.config.onLog?.(msg, level);
  }
}

export function createOramPirClientAdapter(
  config: OramPirClientConfig,
): OramPirClientAdapter {
  return new OramPirClientAdapter(config);
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

/**
 * Admission-safe product boundary: one user query must fit one ORAM wire
 * frame. This is checked before the SDK sends anything; callers should acquire
 * a separate capability/connection for another atomic query, never split one
 * authorized attempt behind the user's back.
 */
export function requireAtomicOramRequest<T>(
  items: readonly T[],
  maxPerRequest: number = DEFAULT_ORAM_SCRIPT_HASHES_PER_REQUEST,
): T[] {
  const max = resolveMaxScriptHashesPerRequest(maxPerRequest);
  if (items.length > max) {
    throw new Error(
      `atomic ORAM query has ${items.length} real inputs but this signed/deployment profile permits at most ${max} in one authorization; reduce the query or acquire a separate capability`,
    );
  }
  return items.slice();
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
