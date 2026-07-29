/**
 * WASM-backed adapter that mimics the legacy `HarmonyPirClient` API shape.
 *
 * The old `web/src/harmonypir_client.ts` carried ~2150 LOC of
 * HarmonyPIR-specific wire-format logic (PRP-based hint replay, per-group
 * relocation tracking, K-padded INDEX/CHUNK query batching, worker-pool
 * lifecycle, per-bucket Merkle verification). Session 6 of the TS
 * retirement plan replaces all of that with this adapter, which
 * delegates the actual PIR work to `WasmHarmonyClient` from
 * `pir-sdk-wasm` (which in turn wraps the native Rust `HarmonyClient`
 * via the `wasm_transport` layer in `pir-sdk-client`).
 *
 * What stays in TypeScript:
 *   * A side-channel `ManagedWebSocket` to the query server — the WASM
 *     client owns its own transport sockets internally, but those
 *     aren't exposed to JS. The side-channel carries
 *     `REQ_GET_INFO_JSON` for diagnostic details only. The canonical catalog,
 *     sync plan, Merkle availability, and roots come from the post-upgrade
 *     native connection and installed proof handles.
 *   * IndexedDB plumbing — the native `HarmonyClient`'s `save_hints` /
 *     `load_hints` API produces opaque byte blobs; this adapter
 *     persists them through `harmonypir_hint_db.ts` keyed on
 *     `(serverUrl, dbId, prpBackend)` together with the random 16-byte
 *     master PRP key that the WASM client generates at construction
 *     time. See "Cross-reload key persistence" below.
 *   * Address-to-scripthash conversion (HASH160 / scriptPubKey parsing).
 *     The WASM client takes 20-byte scripthashes as input; converting
 *     Bitcoin addresses to those bytes stays in JS because the native
 *     side has no address parser.
 *   * Translation between `WasmQueryResult` and `HarmonyQueryResult`
 *     (the UI-facing shape with hex-string `txid` + number `value`).
 *
 * What moves to WASM:
 *   * All PIR wire-format logic (INDEX + CHUNK K-padded queries, PRP
 *     hint replay, group relocation tracking).
 *   * Per-bucket bin-Merkle verification before any result handle crosses
 *     the WASM boundary (`queryBatchVerified`).
 *   * Padding invariants (K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE) —
 *     owned by the native `HarmonyClient`, not re-implementable here.
 *
 * Cross-reload key persistence: the native `HarmonyClient` seeds a fresh
 * random 16-byte master PRP key at construction. A page reload throws
 * that instance away, so to restore hints across reloads the key must
 * be persisted alongside the hint blob. `saveHintsToCache` stores the
 * key next to the blob; `restoreHintsFromCache` reads the key out,
 * calls `setMasterKey(key)` before `loadHints(...)`, and the native
 * client's fingerprint cross-check will confirm the pair matches.
 *
 * 🔒 Privacy: the adapter cannot bypass padding, cannot short-circuit the
 * symmetric INDEX bin probing (`INDEX_CUCKOO_NUM_HASHES = 2`), and cannot
 * turn off Merkle verification — those live in native Rust code below
 * the WASM boundary.
 */

import {
  addressToScriptPubKey,
  bytesToHex,
  hexToBytes,
  scriptHash as computeScriptHash,
} from './hash.js';
import {
  databaseCatalogFromWasmJson,
  fetchServerInfoJson,
  type BucketMerkleInfoJson,
  type DatabaseCatalog,
  type DatabaseCatalogEntry,
  type ServerInfoJson,
} from './server-info.js';
import {
  requireSdkWasm,
  type WasmAnnounceVerification,
  type WasmAttestVerification,
  type WasmHarmonyClient,
  type WasmQueryResult,
} from './sdk-bridge.js';
import {
  type DatabaseProofPin,
  type DatabaseProofStatus,
} from './db-proof.js';
import { getAmdTurinArkFingerprint, PIR_OPERATOR_PUBKEY } from './attest-pin.js';
import {
  gateOperatorIdentity,
  type OperatorIdentity,
  type ServerAttestation,
} from './dpf-adapter.js';
import {
  assertIndependentOperatorPinsV1,
  assertStrictDatabasePinCoverage,
  assertStrictServerLegReady,
  assertStrictTransportReady,
  exactOperatorPinV1,
  preflightInstalledDatabaseProofs,
  resolveIndependentOperatorPinsV1,
  verifyAndInstallDatabaseProofs,
  verifyInstallAndPreflightDatabaseProofs,
  type InstalledDatabaseProof,
} from './strict-verification.js';
import type {
  HarmonyQueryResult,
  HarmonyUtxoEntry,
  QueryInspectorData,
} from './harmony-types.js';
import { ManagedWebSocket } from './ws.js';
import {
  assertLiveOperatorIdentityV1,
  verifiedLiveOperatorSigningKeyV1,
  type ServiceAdmissionPortV1,
} from './service-admission.js';
import {
  canonicalProductQueryShapeV1,
  type ProductQueryShapeV1,
} from './service-entitlement.js';
import { trustedNowUnixV1 } from './trusted-time.js';
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

// ─── Config ──────────────────────────────────────────────────────────────────

export interface HarmonyPirClientConfig {
  hintServerUrl: string;
  queryServerUrl: string;
  onProgress?: (msg: string) => void;
  /** PRP backend: 0=HMR12 (default), 1=FastPRP. (PRP_ALF=2 was
   * retired 2026-05-12 — see attest-pin.ts v13 notes.) */
  prpBackend?: number;
  /**
   * If `true` (default), the adapter automatically attests both servers
   * (hint + query) after `connectQueryServer()` and, when both report
   * a valid X25519 channel pubkey, upgrades both connections so
   * subsequent PIR traffic flows through `pir_channel`'s AEAD-sealed
   * frames. cloudflared sees only ciphertext.
   *
   * Set `false` to keep the connection in cleartext for debugging.
   */
  useSecureChannel?: boolean;
  /** Fail closed on the complete transport, operator, database-proof, and
   * tree-top gate before hints or address queries. Production enables this
   * explicitly; the library default remains advisory. */
  strictVerification?: boolean;
  /** Fires once per server after `connectQueryServer()` resolves the
   *  per-server attestation. `serverIndex` 0 = hint server, 1 = query
   *  server (matches `serverUrls()` order). */
  onAttestation?: (serverIndex: 0 | 1, info: ServerAttestation) => void;
  /**
   * Operator-pinned 32-byte SHA-256 fingerprint of the AMD ARK
   * (Root Key) certificate. See
   * `BatchPirClientConfig.expectedArkFingerprint` for the full
   * doc-comment. When set + server bundles a chain, the adapter
   * flips state to `'verified-vcek'` on chain validation success.
   */
  expectedArkFingerprint?: Uint8Array | null;
  /**
   * Slice 3 build-time pins for the per-server attested values.
   * See `BatchPirClientConfig.expectedServer{0,1}Pin` for full doc.
   * Index 0 = hint server, 1 = query server. For the production
   * topology (pir1 hint, pir2 query): set hint=PIR1_PIN,
   * query=PIR2_TIER3_PIN.
   */
  expectedServer0Pin?: import('./attest-pin.js').ServerAttestPin;
  expectedServer1Pin?: import('./attest-pin.js').ServerAttestPin;
  /** Expected operator-endorsed identity for each transport endpoint.
   * Strict mode requires both non-empty IDs and rejects duplicate endpoint
   * identities. Production uses hint=`pir1`, query=`pir2`. */
  expectedServer0Id?: string;
  expectedServer1Id?: string;
  /**
   * Opt-in operator-signed identity (REQ_ANNOUNCE) verification, mirroring
   * `BatchPirClientConfig`. When `true`, after attesting both servers the
   * adapter fetches each server's announce bundle and verifies it against
   * its per-leg operator pin + the attested channel key, populating
   * `operatorIdentity`. Default `false`.
   */
  verifyOperatorIdentity?: boolean;
  /** Legacy shared operator pin for advisory compatibility only.
   * @deprecated Strict mode requires the two per-leg fields below. */
  pinnedOperatorPubkey?: Uint8Array;
  /** Exact Tier-1 key for the hint provider. */
  pinnedHintOperatorPubkey?: Uint8Array;
  /** Exact Tier-1 key for the query provider. Strict mode requires it to
   * differ from `pinnedHintOperatorPubkey`. */
  pinnedQueryOperatorPubkey?: Uint8Array;
  /** Replay/staleness cap (seconds) on the bundle's `issued_at`. Default
   *  `0` = no cap (issued_at is the server's boot time, so a staleness cap
   *  would wrongly reject long-uptime servers). */
  maxAnnounceAgeSeconds?: number;
  /** Fires once per server after attest resolves the operator-identity
   *  check (only when `verifyOperatorIdentity`). Index 0 = hint, 1 = query.
   *  Gate any "verified operator" badge on `state === 'verified'`. */
  onOperatorIdentity?: (serverIndex: 0 | 1, info: OperatorIdentity) => void;
  /** Database proof pins the frontend should fetch and verify after the
   * catalog is loaded. Empty/default means no db-proof UI check. */
  databaseProofPins?: DatabaseProofPin[];
  /** Fires once per configured database proof pin after verification,
   * mismatch, or "not configured" is known. */
  onDatabaseProof?: (dbId: number, info: DatabaseProofStatus) => void;
}

export interface HarmonyProviderLegConfig {
  url: string;
  expectedPin?: import('./attest-pin.js').ServerAttestPin;
  expectedServerId?: string;
  pinnedOperatorPubkey?: Uint8Array;
}

interface HarmonyLegOwnerV1 {
  generation: number;
  client: WasmHarmonyClient | null;
  url: string;
  configSignature: string;
}

interface HarmonyVerifiedResultBindingV1 {
  handle: WasmQueryResult;
  batchId: number;
  batchSize: number;
  slot: number;
  dbId: number;
  pairGeneration: number;
  inputIndex: number;
  address: string;
  scriptHashHex: string;
  scriptHashBytes: Uint8Array;
  merkleRootHex: string | undefined;
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

/**
 * Drop-in replacement for the pre-Session-6 `HarmonyPirClient`. Same
 * constructor config, same method names, same return shapes —
 * `web/index.html` changes its `new HarmonyPirClient(...)` call site to
 * `new HarmonyPirClientAdapter(...)` and nothing else.
 */
export class HarmonyPirClientAdapter {
  private config: HarmonyPirClientConfig;
  private wasmClient: WasmHarmonyClient | null = null;
  private queryWs: ManagedWebSocket | null = null;
  private serverInfo: ServerInfoJson | null = null;
  private catalog: DatabaseCatalog | null = null;
  private dbId = 0;
  private secureChannelEstablished = false;
  private secureChannelLegs: [boolean, boolean] = [false, false];
  private strictReady = false;
  private strictLegReady: [boolean, boolean] = [false, false];
  private installedProofsByLeg: [InstalledDatabaseProof[] | null, InstalledDatabaseProof[] | null] = [null, null];
  private pairConsistencyReady = false;
  private pairPreflightState: 'not-ready' | 'pending' | 'in-flight' | 'complete' | 'failed' = 'not-ready';
  private pairPreflightPromise: Promise<void> | null = null;
  private pairGeneration = 0;
  private pairPreflightDbId: number | null = null;
  private admissionDbId: number | null = null;
  private legGenerations: [number, number] = [0, 0];
  private legOwners: [HarmonyLegOwnerV1 | null, HarmonyLegOwnerV1 | null] = [null, null];
  private legDisconnects: [Promise<void> | null, Promise<void> | null] = [null, null];
  /** Whether any hints are loaded (main or restored from cache). */
  hintsLoaded = false;
  /**
   * Per-server attestation snapshot. Filled in by `connectQueryServer()`
   * if `useSecureChannel` is enabled (default). Default `'unattested'`
   * until the post-connect attest call resolves. UI consumers should
   * read this after `connectQueryServer()` returns or via the
   * `onAttestation` callback for live updates. Index 0 = hint server,
   * 1 = query server.
   */
  attestation: { hint: ServerAttestation; query: ServerAttestation } = {
    hint: { state: 'unattested' },
    query: { state: 'unattested' },
  };
  /**
   * Per-server operator-signed-identity snapshot, mirroring
   * `BatchPirClientAdapter.operatorIdentity`. Populated by
   * `attestAndUpgrade()` only when `verifyOperatorIdentity` is set; stays
   * `'not-checked'` otherwise. Index 0 = hint, 1 = query. Gate any
   * "verified operator" badge on `state === 'verified'`.
   */
  operatorIdentity: { hint: OperatorIdentity; query: OperatorIdentity } = {
    hint: { state: 'not-checked' },
    query: { state: 'not-checked' },
  };
  /** Per-database attested-builder proof status, keyed by db_id. */
  databaseProofs: Map<number, DatabaseProofStatus> = new Map();
  /**
   * Inspector data populated by the most recent `queryBatch`. The native
   * `HarmonyClient` doesn't surface placement-round / per-chunk timing
   * internals across the WASM boundary, so this is a thin shim built
   * from `WasmQueryResult`'s inspector fields (INDEX + CHUNK bin probes,
   * whale flag). The Query Inspector UI still renders, with reduced
   * fidelity for the "Placement" and "Timing" panels.
   */
  lastInspectorData: Map<number, QueryInspectorData> | null = null;
  private externalCloseCallback: (() => void) | null = null;

  /** Native-verified handles awaiting the legacy UI's one-shot release
   * boundary. Persisted or caller-constructed JSON can never enter it. */
  private readonly verifiedHandles: WeakMap<
    HarmonyQueryResult,
    HarmonyVerifiedResultBindingV1
  > = new WeakMap();
  private verifiedBatchGeneration = 0;
  private activeVerifiedBatchId: number | null = null;

  constructor(config: HarmonyPirClientConfig) {
    this.config = {
      ...config,
      expectedArkFingerprint: config.expectedArkFingerprint?.slice() ?? config.expectedArkFingerprint,
      expectedServer0Pin: config.expectedServer0Pin ? { ...config.expectedServer0Pin } : undefined,
      expectedServer1Pin: config.expectedServer1Pin ? { ...config.expectedServer1Pin } : undefined,
      pinnedOperatorPubkey: config.pinnedOperatorPubkey?.slice(),
      pinnedHintOperatorPubkey: config.pinnedHintOperatorPubkey?.slice(),
      pinnedQueryOperatorPubkey: config.pinnedQueryOperatorPubkey?.slice(),
      databaseProofPins: config.databaseProofPins?.map((pin) => ({ ...pin })),
    };
  }

  /** Configure one role without selecting or disclosing its peer provider. */
  configureProviderLeg(providerIndex: 0 | 1, leg: HarmonyProviderLegConfig): void {
    if (!leg.url.trim()) throw new Error(`Harmony provider ${providerIndex} URL is required`);
    if (this.legDisconnects[providerIndex]) {
      throw new Error(`Harmony provider ${providerIndex} disconnect is still in flight`);
    }
    if (this.legOwners[providerIndex]
        || this.strictLegReady[providerIndex]
        || this.wasmClient?.isProviderConnected(providerIndex)) {
      throw new Error(`Harmony provider ${providerIndex} is already connected`);
    }
    const configuredOperatorPin = providerIndex === 0
      ? this.config.pinnedHintOperatorPubkey
      : this.config.pinnedQueryOperatorPubkey;
    const operatorPin = this.isStrictVerification()
      ? exactOperatorPinV1(
        `Harmony provider ${providerIndex} operator pin`,
        leg.pinnedOperatorPubkey ?? configuredOperatorPin,
      )
      : (leg.pinnedOperatorPubkey ?? configuredOperatorPin)?.slice();
    ++this.legGenerations[providerIndex];
    if (providerIndex === 0) {
      this.config.hintServerUrl = leg.url;
      this.config.expectedServer0Pin = leg.expectedPin
        ? { ...leg.expectedPin }
        : this.config.expectedServer0Pin;
      this.config.expectedServer0Id = leg.expectedServerId ?? this.config.expectedServer0Id;
      this.config.pinnedHintOperatorPubkey = operatorPin;
    } else {
      this.config.queryServerUrl = leg.url;
      this.config.expectedServer1Pin = leg.expectedPin
        ? { ...leg.expectedPin }
        : this.config.expectedServer1Pin;
      this.config.expectedServer1Id = leg.expectedServerId ?? this.config.expectedServer1Id;
      this.config.pinnedQueryOperatorPubkey = operatorPin;
      this.queryWs?.disconnect();
      this.queryWs = null;
    }
    this.wasmClient?.setProviderUrl(providerIndex, leg.url);
  }

  /**
   * Strictly verify one independently priced role. Its signed policy may be
   * displayed before the peer is selected; capability and hint acquisition,
   * plus real PIR queries, wait for both roles and the pair preflight.
   */
  async connectLeg(providerIndex: 0 | 1): Promise<void> {
    if (this.strictLegReady[providerIndex]) return;
    if (this.legDisconnects[providerIndex]) {
      throw new Error(`Harmony provider ${providerIndex} disconnect is still in flight`);
    }
    if (this.legOwners[providerIndex]) {
      throw new Error(`Harmony provider ${providerIndex} connect is already in flight`);
    }
    let owner: HarmonyLegOwnerV1 | null = null;
    try {
      if (!this.isStrictVerification()) {
        throw new Error('staged Harmony provider admission requires strict verification');
      }
      if (this.isStrictVerification() && this.config.useSecureChannel === false) {
        throw new Error('strict verification requires the secure channel');
      }
      const url = providerIndex === 0
        ? this.config.hintServerUrl
        : this.config.queryServerUrl;
      if (!url.trim()) throw new Error(`Harmony provider ${providerIndex} is not configured`);
      this.operatorPinForLeg(providerIndex);
      const peerIndex = providerIndex === 0 ? 1 : 0;
      if (this.legDisconnects[peerIndex]) {
        throw new Error(`Harmony provider ${peerIndex} disconnect is still in flight`);
      }
      if (this.legOwners[peerIndex] && !this.strictLegReady[peerIndex]) {
        throw new Error(`Harmony provider ${peerIndex} connect is still in flight`);
      }
      if (this.strictLegReady[peerIndex] || this.wasmClient?.isProviderConnected(peerIndex)) {
        this.assertIndependentOperatorPins();
      }
      owner = {
        generation: ++this.legGenerations[providerIndex],
        client: this.wasmClient,
        url,
        configSignature: this.legConfigSignature(providerIndex),
      };
      this.legOwners[providerIndex] = owner;
      await this.loadWasm();
      owner.client = this.wasmClient;
      this.assertLegOwner(providerIndex, owner);
      const client = this.wasmClient!;
      await client.connectProvider(providerIndex);
      this.assertLegOwner(providerIndex, owner);
      if (this.config.useSecureChannel !== false) {
        await this.attestAndUpgradeLeg(providerIndex, owner);
        this.assertLegOwner(providerIndex, owner);
      }
      if (this.isStrictVerification()) this.assertStrictLegReady(providerIndex);

      const catalogHandle = await client.fetchCatalogFromProvider(providerIndex);
      let stagedCatalog: DatabaseCatalog;
      try {
        this.assertLegOwner(providerIndex, owner);
        // Rust has already enforced query-compatible db_id/kind/height,
        // geometry, seed, anchor and Merkle fields against the first role.
        stagedCatalog = databaseCatalogFromWasmJson(catalogHandle.toJson());
      } finally {
        catalogHandle.free();
      }
      this.assertLegOwner(providerIndex, owner);
      this.catalog ??= stagedCatalog;
      if (this.isStrictVerification()) this.assertPinsCoverCatalog();
      const installedProofs = await this.verifyConfiguredDatabaseProofsForLeg(
        providerIndex,
        () => this.assertLegOwner(providerIndex, owner!),
      );
      this.assertLegOwner(providerIndex, owner);
      this.installedProofsByLeg[providerIndex] = installedProofs;
      if (providerIndex === 0) {
        for (const installed of this.installedProofsByLeg[0] ?? []) {
          // The hint cache is independently bound to the hint provider's
          // verified dataset. Query execution still waits for the peer proof.
          this.recordDatabaseProofStatus(installed.pin.dbId, installed.status);
        }
      }
      this.strictLegReady[providerIndex] = this.isStrictVerification();

      if (this.strictLegReady[0] && this.strictLegReady[1]) {
        this.assertIndependentOperatorPins();
        assertStrictTransportReady({
          secureChannelEstablished: this.secureChannelLegs.every(Boolean),
          attestations: [this.attestation.hint, this.attestation.query],
          expectedPins: [this.config.expectedServer0Pin, this.config.expectedServer1Pin],
          expectedServerIds: [this.config.expectedServer0Id, this.config.expectedServer1Id],
          requireOperatorIdentity: this.config.verifyOperatorIdentity === true,
          operatorIdentities: [this.operatorIdentity.hint, this.operatorIdentity.query],
          operatorPins: [
            this.config.pinnedHintOperatorPubkey,
            this.config.pinnedQueryOperatorPubkey,
          ],
        });
        this.assertLegProofsMatch();
        this.secureChannelEstablished = true;
        this.pairGeneration += 1;
        this.pairConsistencyReady = true;
        this.pairPreflightState = 'pending';
        this.pairPreflightPromise = null;
        this.pairPreflightDbId = null;
        this.admissionDbId = null;
        const pairGeneration = this.pairGeneration;
        await this.connectDiagnosticSocket(
          () => this.assertCurrentStrictPair(client, pairGeneration),
        );
        this.assertCurrentStrictPair(client, pairGeneration);
        this.log('HarmonyPIR: pair consistency verified; awaiting pre-authorization preflight');
      } else {
        this.log(
          providerIndex === 0
            ? 'HarmonyPIR hint role strictly ready; query provider not selected'
            : 'HarmonyPIR query role strictly ready; hint provider not selected',
        );
      }
    } catch (error) {
      this.log(
        `HarmonyPIR ${providerIndex === 0 ? 'hint' : 'query'} connect failed: `
        + `${(error as Error)?.message ?? error}`,
      );
      if (owner && this.legOwners[providerIndex] === owner) {
        await this.disconnectLeg(providerIndex).catch(() => { /* preserve primary failure */ });
      }
      throw error;
    }
  }

  /** Close one role only. A paid/authorized peer transport is not retried or
   * re-authorized, and loaded hint state survives a query-leg failure. */
  async disconnectLeg(providerIndex: 0 | 1): Promise<void> {
    const existing = this.legDisconnects[providerIndex];
    if (existing) return existing;
    const operation = this.disconnectLegOwned(providerIndex);
    this.legDisconnects[providerIndex] = operation;
    try {
      await operation;
    } finally {
      if (this.legDisconnects[providerIndex] === operation) {
        this.legDisconnects[providerIndex] = null;
      }
    }
  }

  private async disconnectLegOwned(providerIndex: 0 | 1): Promise<void> {
    const generation = ++this.legGenerations[providerIndex];
    const configSignature = this.legConfigSignature(providerIndex);
    this.legOwners[providerIndex] = null;
    this.strictReady = false;
    this.secureChannelEstablished = false;
    this.pairGeneration += 1;
    this.verifiedBatchGeneration += 1;
    this.activeVerifiedBatchId = null;
    this.pairConsistencyReady = false;
    this.pairPreflightState = 'not-ready';
    this.pairPreflightPromise = null;
    this.pairPreflightDbId = null;
    this.admissionDbId = null;
    this.secureChannelLegs[providerIndex] = false;
    this.strictLegReady[providerIndex] = false;
    this.installedProofsByLeg[providerIndex] = null;
    if (providerIndex === 0) {
      this.attestation.hint = { state: 'unattested' };
      this.operatorIdentity.hint = { state: 'not-checked' };
    } else {
      this.queryWs?.disconnect();
      this.queryWs = null;
      this.attestation.query = { state: 'unattested' };
      this.operatorIdentity.query = { state: 'not-checked' };
    }
    let hasSurvivingLeg = false;
    const client = this.wasmClient;
    if (client) {
      await client.disconnectProvider(providerIndex);
      this.assertLegDisconnectedOwner(providerIndex, generation, client, configSignature);
      hasSurvivingLeg = client.isProviderConnected(providerIndex === 0 ? 1 : 0);
    }
    if (!hasSurvivingLeg) {
      // The final native transport invalidates session-bound catalog, roots,
      // tree tops and in-memory hints. Keep the browser mirror in lock-step;
      // persisted hint bytes may still be restored through the normal bind.
      this.catalog = null;
      this.serverInfo = null;
      this.databaseProofs.clear();
      this.hintsLoaded = false;
      this.secureChannelLegs = [false, false];
      this.strictLegReady = [false, false];
      this.installedProofsByLeg = [null, null];
    }
  }

  isLegReady(providerIndex: 0 | 1): boolean {
    return this.strictLegReady[providerIndex];
  }

  /** Authenticate the selected tree-tops before either Harmony capability is
   * acquired or authorized. The one-shot result is bound to this exact pair. */
  async prepareStrictAdmission(dbId: number): Promise<void> {
    if (!Number.isInteger(dbId) || dbId < 0 || dbId > 255) {
      throw new Error('Harmony pre-authorization preflight requires an exact u8 db_id');
    }
    if (!this.pairConsistencyReady
        || !this.strictLegReady.every(Boolean)
        || !this.secureChannelLegs.every(Boolean)
        || !this.wasmClient) {
      throw new Error('Harmony pair consistency is not ready for pre-authorization preflight');
    }
    if (this.pairPreflightState === 'complete') {
      if (this.admissionDbId !== dbId) {
        throw new Error(`Harmony admission is already prepared for db_id ${this.admissionDbId}`);
      }
      return;
    }
    if (this.pairPreflightState === 'failed') {
      throw new Error('Harmony pre-authorization preflight already failed; retry is disabled');
    }
    if (this.pairPreflightState === 'in-flight') {
      if (this.pairPreflightDbId !== dbId) {
        throw new Error(`Harmony preflight is already in flight for db_id ${this.pairPreflightDbId}`);
      }
      const client = this.wasmClient;
      const generation = this.pairGeneration;
      await this.pairPreflightPromise;
      this.assertCurrentStrictPair(client, generation);
      if (!this.isPairPreflightComplete()) {
        throw new Error('Harmony pre-authorization preflight was invalidated while in flight');
      }
      return;
    }

    const client = this.wasmClient;
    const generation = this.pairGeneration;
    this.assertCurrentStrictPair(client, generation);
    const installed = this.installedProofsByLeg[0]?.find((item) => item.pin.dbId === dbId);
    if (!installed || !this.installedProofsByLeg[1]?.some((item) => item.pin.dbId === dbId)) {
      throw new Error(`Harmony pair has no matching installed proof for db_id ${dbId}`);
    }
    this.pairPreflightState = 'in-flight';
    this.pairPreflightDbId = dbId;
    const attempt = preflightInstalledDatabaseProofs(
      client,
      [installed],
      (dbId, status) => {
        this.recordDatabaseProofStatus(dbId, status);
      },
      () => this.assertCurrentStrictPair(client, generation),
    ).then(() => undefined);
    this.pairPreflightPromise = attempt;
    try {
      await attempt;
      this.assertCurrentStrictPair(client, generation);
      if (this.pairPreflightState !== 'in-flight') {
        throw new Error('Harmony pre-authorization preflight was invalidated while in flight');
      }
      this.pairPreflightState = 'complete';
      this.admissionDbId = dbId;
      this.strictReady = true;
      this.log('HarmonyPIR: pre-authorization tree-top preflight complete');
    } catch (error) {
      if (this.pairGeneration === generation && this.wasmClient === client) {
        this.pairPreflightState = 'failed';
        this.strictReady = false;
      }
      throw error;
    }
  }

  private log(msg: string): void {
    this.config.onProgress?.(msg);
  }

  private expectedArkFingerprint(): Uint8Array | null {
    if (this.config.expectedArkFingerprint === null) return null;
    if (this.config.expectedArkFingerprint !== undefined) {
      return this.config.expectedArkFingerprint;
    }
    try {
      return getAmdTurinArkFingerprint();
    } catch (error) {
      this.log(`HarmonyPIR default ARK fingerprint unavailable: ${(error as Error)?.message ?? error}`);
      return null;
    }
  }

  private operatorPinForLeg(providerIndex: 0 | 1): Uint8Array {
    const configured = providerIndex === 0
      ? this.config.pinnedHintOperatorPubkey
      : this.config.pinnedQueryOperatorPubkey;
    const value = configured ?? (this.isStrictVerification()
      ? undefined
      : this.config.pinnedOperatorPubkey ?? PIR_OPERATOR_PUBKEY);
    return exactOperatorPinV1(`Harmony provider ${providerIndex} operator pin`, value);
  }

  private assertIndependentOperatorPins(): readonly [Uint8Array, Uint8Array] {
    return assertIndependentOperatorPinsV1({
      first: this.config.pinnedHintOperatorPubkey,
      second: this.config.pinnedQueryOperatorPubkey,
    });
  }

  private legConfigSignature(providerIndex: 0 | 1): string {
    const pin = providerIndex === 0
      ? this.config.pinnedHintOperatorPubkey
      : this.config.pinnedQueryOperatorPubkey;
    return JSON.stringify({
      url: providerIndex === 0 ? this.config.hintServerUrl : this.config.queryServerUrl,
      expectedPin: providerIndex === 0
        ? this.config.expectedServer0Pin
        : this.config.expectedServer1Pin,
      expectedServerId: providerIndex === 0
        ? this.config.expectedServer0Id
        : this.config.expectedServer1Id,
      operatorPin: pin instanceof Uint8Array ? bytesToHex(pin) : null,
      databaseProofPins: this.config.databaseProofPins ?? [],
      prpBackend: this.config.prpBackend ?? 0,
    });
  }

  private assertLegOwner(providerIndex: 0 | 1, owner: HarmonyLegOwnerV1): void {
    if (!owner.client
        || this.legGenerations[providerIndex] !== owner.generation
        || this.legOwners[providerIndex] !== owner
        || this.wasmClient !== owner.client
        || (providerIndex === 0
          ? this.config.hintServerUrl
          : this.config.queryServerUrl) !== owner.url
        || this.legConfigSignature(providerIndex) !== owner.configSignature) {
      throw new Error(`Harmony provider ${providerIndex} connection attempt was invalidated`);
    }
  }

  private assertLegDisconnectedOwner(
    providerIndex: 0 | 1,
    generation: number,
    client: WasmHarmonyClient,
    configSignature: string,
  ): void {
    if (this.legGenerations[providerIndex] !== generation
        || this.legOwners[providerIndex] !== null
        || this.wasmClient !== client
        || this.legConfigSignature(providerIndex) !== configSignature) {
      throw new Error(`Harmony provider ${providerIndex} disconnect was invalidated`);
    }
  }

  private assertCurrentStrictPair(client: WasmHarmonyClient, generation: number): void {
    if (this.pairGeneration !== generation
        || this.wasmClient !== client
        || !this.pairConsistencyReady
        || !this.strictLegReady.every(Boolean)
        || !this.secureChannelLegs.every(Boolean)) {
      throw new Error('Harmony strict pair attempt was invalidated');
    }
    const hint = this.legOwners[0];
    const query = this.legOwners[1];
    if (!hint || !query) throw new Error('Harmony strict pair has no current leg owners');
    this.assertLegOwner(0, hint);
    this.assertLegOwner(1, query);
    this.assertIndependentOperatorPins();
    assertStrictTransportReady({
      secureChannelEstablished: true,
      attestations: [this.attestation.hint, this.attestation.query],
      expectedPins: [this.config.expectedServer0Pin, this.config.expectedServer1Pin],
      expectedServerIds: [this.config.expectedServer0Id, this.config.expectedServer1Id],
      requireOperatorIdentity: this.config.verifyOperatorIdentity === true,
      operatorIdentities: [this.operatorIdentity.hint, this.operatorIdentity.query],
      operatorPins: [
        this.config.pinnedHintOperatorPubkey,
        this.config.pinnedQueryOperatorPubkey,
      ],
    });
    this.assertLegProofsMatch();
  }

  private summariseAttestationLeg(
    providerIndex: 0 | 1,
    attestation: WasmAttestVerification,
  ): ServerAttestation {
    const matched = attestation.sevStatus === 'reportDataMatch';
    const noSev = attestation.sevStatus === 'noSevHost';
    const allZero = attestation.serverStaticPub.every((byte) => byte === 0);
    const result: ServerAttestation = {
      state: allZero ? 'plaintext' : (matched || noSev ? 'verified' : 'mismatch'),
      sevStatus: attestation.sevStatus,
      serverStaticPubHex: attestation.serverStaticPubHex,
      binarySha256Hex: attestation.binarySha256Hex,
      gitRev: attestation.gitRev,
      launchMeasurementHex: attestation.launchMeasurementHex,
    };
    const policyRequirements = new (requireSdkWasm().WasmPolicyRequirements)();
    try {
      const arkFingerprint = this.expectedArkFingerprint();
      if (result.state === 'verified' && matched && attestation.hasVcekChain) {
        if (arkFingerprint) {
          try {
            attestation.verifyFull(arkFingerprint, policyRequirements);
            result.state = 'verified-vcek';
            result.vcekChain = 'pass';
          } catch (error) {
            result.state = 'mismatch';
            result.vcekChain = 'fail';
            result.vcekChainError = (error as Error)?.message ?? String(error);
            this.log(`HarmonyPIR verifyFull failed: ${result.vcekChainError}`);
          }
        } else {
          result.vcekChain = 'skipped';
        }
      } else if (result.state === 'verified' && matched && !attestation.hasVcekChain) {
        result.vcekChain = 'skipped';
      }

      const pin = providerIndex === 0
        ? this.config.expectedServer0Pin
        : this.config.expectedServer1Pin;
      if (!pin) {
        result.pinStatus = 'no-pin';
        return result;
      }
      if (result.state !== 'verified' && result.state !== 'verified-vcek') return result;
      if (pin.measurementHex && !attestation.launchMeasurementHex) {
        result.pinStatus = 'measurement-mismatch';
        result.pinError = 'MEASUREMENT pin required but server report omitted launch MEASUREMENT';
      } else if (
        pin.measurementHex
        && pin.measurementHex.toLowerCase() !== attestation.launchMeasurementHex!.toLowerCase()
      ) {
        result.pinStatus = 'measurement-mismatch';
        result.pinError = 'MEASUREMENT pin mismatch';
      } else if (pin.binarySha256Hex && !attestation.binarySha256Hex) {
        result.pinStatus = 'binary-mismatch';
        result.pinError = 'binary_sha256 pin required but server report omitted binary_sha256';
      } else if (
        pin.binarySha256Hex
        && pin.binarySha256Hex.toLowerCase() !== attestation.binarySha256Hex.toLowerCase()
      ) {
        result.pinStatus = 'binary-mismatch';
        result.pinError = 'binary_sha256 pin mismatch';
      } else {
        result.pinStatus = 'match';
      }
      if (result.pinStatus !== 'match') {
        result.state = 'mismatch';
        this.log(
          `HarmonyPIR ${providerIndex === 0 ? 'hint' : 'query'}: ${result.pinError}`,
        );
      }
      return result;
    } finally {
      policyRequirements.free();
    }
  }

  private async attestAndUpgradeLeg(
    providerIndex: 0 | 1,
    owner: HarmonyLegOwnerV1,
  ): Promise<void> {
    const client = this.wasmClient;
    if (!client) throw new Error('WASM client not initialised');
    this.assertLegOwner(providerIndex, owner);
    this.secureChannelLegs[providerIndex] = false;
    let attestation: WasmAttestVerification | null = null;
    try {
      try {
        attestation = await client.attest(providerIndex);
        this.assertLegOwner(providerIndex, owner);
      } catch (error) {
        this.assertLegOwner(providerIndex, owner);
        const failed: ServerAttestation = { state: 'mismatch' };
        if (providerIndex === 0) this.attestation.hint = failed;
        else this.attestation.query = failed;
        this.config.onAttestation?.(providerIndex, failed);
        throw new Error(
          `HarmonyPIR attest(${providerIndex === 0 ? 'hint' : 'query'}) failed: `
          + `${(error as Error)?.message ?? error}`,
          { cause: error },
        );
      }

      let summary = this.summariseAttestationLeg(providerIndex, attestation);
      if (providerIndex === 0) this.attestation.hint = summary;
      else this.attestation.query = summary;
      this.config.onAttestation?.(providerIndex, summary);
      if (summary.state !== 'verified' && summary.state !== 'verified-vcek') {
        throw new Error('HarmonyPIR attestation did not satisfy the secure-channel gate');
      }
      try {
        this.assertLegOwner(providerIndex, owner);
        await client.upgradeProviderToSecureChannel(
          providerIndex,
          attestation.serverStaticPub,
        );
        this.assertLegOwner(providerIndex, owner);
        this.secureChannelLegs[providerIndex] = true;
      } catch (error) {
        this.assertLegOwner(providerIndex, owner);
        summary = { ...summary, state: 'mismatch' };
        if (providerIndex === 0) this.attestation.hint = summary;
        else this.attestation.query = summary;
        this.config.onAttestation?.(providerIndex, summary);
        throw new Error(
          `HarmonyPIR secure-channel upgrade failed: ${(error as Error)?.message ?? error}`,
          { cause: error },
        );
      }

      if (this.config.verifyOperatorIdentity) {
        this.assertLegOwner(providerIndex, owner);
        const identity = await this.verifyOperatorIdentityOne(
          providerIndex,
          attestation,
          this.operatorPinForLeg(providerIndex),
          () => this.assertLegOwner(providerIndex, owner),
        );
        this.assertLegOwner(providerIndex, owner);
        if (providerIndex === 0) this.operatorIdentity.hint = identity;
        else this.operatorIdentity.query = identity;
        this.config.onOperatorIdentity?.(providerIndex, identity);
      }
    } finally {
      attestation?.free();
    }
  }

  /**
   * Attest both servers (hint + query) and upgrade to the encrypted
   * channel if both report a valid V2 channel pubkey. Mirrors the
   * `BatchPirClientAdapter.attestAndUpgrade` flow on the DPF side; see
   * that doc-comment for failure-mode semantics. Failures leave the
   * connection alive in cleartext mode and log a warning.
   */
  private async attestAndUpgrade(): Promise<void> {
    if (!this.wasmClient) return;
    this.secureChannelEstablished = false;
    this.secureChannelLegs = [false, false];
    const operatorPins = this.config.verifyOperatorIdentity
      ? resolveIndependentOperatorPinsV1({
        strictVerification: this.isStrictVerification(),
        first: this.config.pinnedHintOperatorPubkey,
        second: this.config.pinnedQueryOperatorPubkey,
        legacyShared: this.config.pinnedOperatorPubkey ?? PIR_OPERATOR_PUBKEY,
      })
      : null;

    const attestOne = async (idx: 0 | 1): Promise<WasmAttestVerification | null> => {
      try {
        return await this.wasmClient!.attest(idx);
      } catch (e) {
        const which = idx === 0 ? 'hint' : 'query';
        this.log(`HarmonyPIR attest(${which}) failed: ${(e as Error)?.message ?? e}`);
        return null;
      }
    };

    let hintAtt: WasmAttestVerification | null = null;
    let queryAtt: WasmAttestVerification | null = null;
    try {
      // Sequential — same reasoning as dpf-adapter::attestAndUpgrade:
      // both calls target the same WasmHarmonyClient and the underlying
      // `&mut self` borrow serializes them. Promise.all wedges.
      hintAtt = await attestOne(0);
      queryAtt = await attestOne(1);

      // Same default-to-WASM-export logic as the DPF adapter — see
      // dpf-adapter.ts::attestAndUpgrade for rationale.
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
            `HarmonyPIR default ARK fingerprint unavailable: ${(e as Error)?.message ?? e}`,
          );
          expectedArkFp = null;
        }
      }

      const sdk = requireSdkWasm();
      const policyReqs = new sdk.WasmPolicyRequirements();
      try {

        const summarise = (
          idx: 0 | 1,
          att: WasmAttestVerification | null,
        ): ServerAttestation => {
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
          // Slice D.3+ chain + policy validation. Same gating logic as
          // the DPF adapter — see dpf-adapter.ts::attestAndUpgrade.
          if (state === 'verified' && matched && att.hasVcekChain) {
            if (expectedArkFp) {
              try {
                att.verifyFull(expectedArkFp, policyReqs);
                result.state = 'verified-vcek';
                result.vcekChain = 'pass';
              } catch (e) {
                result.vcekChain = 'fail';
                result.vcekChainError = (e as Error)?.message ?? String(e);
                this.log(
                  `HarmonyPIR verifyFull failed: ${result.vcekChainError}`,
                );
                result.state = 'mismatch';
              }
            } else {
              result.vcekChain = 'skipped';
            }
          } else if (state === 'verified' && matched && !att.hasVcekChain) {
            result.vcekChain = 'skipped';
          }
          // Slice 3 build-time pin enforcement. See dpf-adapter.ts::summarise
          // for the rationale + same shape.
          const pin =
            idx === 0 ? this.config.expectedServer0Pin : this.config.expectedServer1Pin;
          if (pin) {
            const stateOk = result.state === 'verified' || result.state === 'verified-vcek';
            if (stateOk) {
              if (pin.measurementHex && !att.launchMeasurementHex) {
                result.pinStatus = 'measurement-mismatch';
                result.pinError = `MEASUREMENT pin required (${pin.measurementHex.slice(0, 16)}…) but server report omitted launch MEASUREMENT`;
                result.state = 'mismatch';
                this.log(`HarmonyPIR ${idx === 0 ? 'hint' : 'query'}: ${result.pinError}`);
              } else if (
                pin.measurementHex &&
                pin.measurementHex.toLowerCase() !== att.launchMeasurementHex!.toLowerCase()
              ) {
                result.pinStatus = 'measurement-mismatch';
                result.pinError = `MEASUREMENT pin mismatch — expected ${pin.measurementHex.slice(0, 16)}…, got ${att.launchMeasurementHex.slice(0, 16)}…`;
                result.state = 'mismatch';
                this.log(`HarmonyPIR ${idx === 0 ? 'hint' : 'query'}: ${result.pinError}`);
              } else if (
                pin.binarySha256Hex &&
                !att.binarySha256Hex
              ) {
                result.pinStatus = 'binary-mismatch';
                result.pinError = `binary_sha256 pin required (${pin.binarySha256Hex.slice(0, 16)}…) but server report omitted binary_sha256`;
                result.state = 'mismatch';
                this.log(`HarmonyPIR ${idx === 0 ? 'hint' : 'query'}: ${result.pinError}`);
              } else if (
                pin.binarySha256Hex &&
                att.binarySha256Hex &&
                pin.binarySha256Hex.toLowerCase() !== att.binarySha256Hex.toLowerCase()
              ) {
                result.pinStatus = 'binary-mismatch';
                result.pinError = `binary_sha256 pin mismatch — expected ${pin.binarySha256Hex.slice(0, 16)}…, got ${att.binarySha256Hex.slice(0, 16)}…`;
                result.state = 'mismatch';
                this.log(`HarmonyPIR ${idx === 0 ? 'hint' : 'query'}: ${result.pinError}`);
              } else {
                result.pinStatus = 'match';
              }
            }
          } else {
            result.pinStatus = 'no-pin';
          }
          return result;
        };

        this.attestation.hint = summarise(0, hintAtt);
        this.attestation.query = summarise(1, queryAtt);
        this.config.onAttestation?.(0, this.attestation.hint);
        this.config.onAttestation?.(1, this.attestation.query);

        const channelReady = (s: ServerAttestation['state']) =>
          s === 'verified' || s === 'verified-vcek';
        if (
          channelReady(this.attestation.hint.state)
          && channelReady(this.attestation.query.state)
          && hintAtt
          && queryAtt
        ) {
          try {
            await this.wasmClient.upgradeToSecureChannel(
              hintAtt.serverStaticPub,
              queryAtt.serverStaticPub,
            );
            this.secureChannelEstablished = true;
            this.secureChannelLegs = [true, true];
            this.log('HarmonyPIR: upgraded to encrypted channel (cloudflared blind)');
          } catch (e) {
            this.log(`HarmonyPIR upgradeToSecureChannel failed: ${(e as Error)?.message ?? e}`);
            this.attestation.hint = { ...this.attestation.hint, state: 'mismatch' };
            this.attestation.query = { ...this.attestation.query, state: 'mismatch' };
            this.config.onAttestation?.(0, this.attestation.hint);
            this.config.onAttestation?.(1, this.attestation.query);
          }
        } else {
          this.log(
            `HarmonyPIR channel left in cleartext (hint=${this.attestation.hint.state},`
            + ` query=${this.attestation.query.state})`,
          );
        }

        // Operator-signed identity (REQ_ANNOUNCE), opt-in. After the channel
        // decision so announce() rides the encrypted channel when it came up;
        // binds against the attested serverStaticPub from hintAtt/queryAtt
        // (still alive here — freed just below). Mirrors the DPF adapter.
        if (this.config.verifyOperatorIdentity) {
          this.operatorIdentity.hint = await this.verifyOperatorIdentityOne(
            0,
            hintAtt,
            operatorPins![0],
          );
          this.operatorIdentity.query = await this.verifyOperatorIdentityOne(
            1,
            queryAtt,
            operatorPins![1],
          );
          this.config.onOperatorIdentity?.(0, this.operatorIdentity.hint);
          this.config.onOperatorIdentity?.(1, this.operatorIdentity.query);
        }

      } finally {
        policyReqs.free();
      }
    } finally {
      // Keep the attestation allocations scoped to this bootstrap even when
      // a UI callback, field projection, identity check, or upgrade throws.
      try {
        hintAtt?.free();
      } finally {
        queryAtt?.free();
      }
    }
  }

  /**
   * Fetch + verify one server's operator-signed identity. Never throws;
   * returns an `OperatorIdentity` snapshot. `att` supplies the attested
   * `serverStaticPub` the bundle's `channel_pub` is bound against, so a
   * `null` att (attest failed) yields `state: 'error'`. Mirrors
   * `dpf-adapter.ts::verifyOperatorIdentityOne`.
   */
  private async verifyOperatorIdentityOne(
    idx: 0 | 1,
    att: WasmAttestVerification | null,
    pin: Uint8Array,
    assertCurrent?: () => void,
  ): Promise<OperatorIdentity> {
    const which = idx === 0 ? 'hint' : 'query';
    const client = this.wasmClient;
    if (!client) {
      return { state: 'error', error: 'wasm client not initialised' };
    }
    if (!att) {
      return { state: 'error', error: 'attestation unavailable; cannot bind channel key' };
    }
    let v: WasmAnnounceVerification;
    try {
      v = await client.announce(idx);
      assertCurrent?.();
    } catch (e) {
      assertCurrent?.();
      const msg = (e as Error)?.message ?? String(e);
      // A server started without --identity-* answers RESP_ERROR
      // "announce not configured" — an expected, benign state.
      if (/not configured/i.test(msg)) {
        this.log(`HarmonyPIR ${which}: operator identity not configured`);
        return { state: 'unconfigured' };
      }
      this.log(`HarmonyPIR announce(${which}) failed: ${msg}`);
      return { state: 'error', error: msg };
    }
    try {
      const nowSecs = trustedNowUnixV1();
      const maxAge = BigInt(this.config.maxAnnounceAgeSeconds ?? 0);
      const result = gateOperatorIdentity(v, pin, att.serverStaticPub, nowSecs, maxAge);
      if (result.state === 'verified') {
        this.log(`HarmonyPIR ${which}: operator identity verified (${result.serverId})`);
      } else {
        this.log(`HarmonyPIR ${which}: operator identity UNVERIFIED — ${result.error}`);
      }
      return result;
    } finally {
      v.free();
    }
  }

  // ══ Setup / WASM loading ════════════════════════════════════════════════

  /**
   * Load the WASM module + construct the `WasmHarmonyClient`.
   *
   * Kept as a distinct method from `connectQueryServer` for API
   * compatibility with `web/index.html`'s setup sequence. The WASM
   * client's actual transport sockets open in `connect()`, so "load"
   * here is a lightweight constructor call — no network I/O yet.
   */
  async loadWasm(): Promise<void> {
    if (this.wasmClient) return;
    const sdk = requireSdkWasm();
    this.wasmClient = new sdk.WasmHarmonyClient(
      this.config.hintServerUrl,
      this.config.queryServerUrl,
    );
    this.wasmClient.setRequireVerifiedDatabaseRoots(this.isStrictVerification());
    const backend = this.config.prpBackend ?? 0;
    this.wasmClient.setPrpBackend(backend);
    // Pin the adapter's master PRP key NOW, before any hints are fetched.
    // `setMasterKey` invalidates any already-loaded hint groups on the
    // native side; deferring this call until `saveHintsToCache` (the old
    // lazy path) would swap the key mid-session and leave the persisted
    // blob / fingerprint / masterKey triple mutually inconsistent on the
    // very next `restoreHintsFromCache`.
    const masterKey = new Uint8Array(16);
    crypto.getRandomValues(masterKey);
    this.wasmClient.setMasterKey(masterKey);
    const backendName = ['HMR12', 'FastPRP'][backend] ?? 'HMR12';
    this.log(`WASM loaded: ${backendName}`);
  }

  /**
   * Open the two WebSocket connections (hint + query) inside the WASM
   * client + the TS-side side-channel to the query server (for
   * diagnostic frames).
   */
  async connectQueryServer(): Promise<void> {
    if (!this.wasmClient) throw new Error('loadWasm() must be called first');
    try {
      this.resetVerificationState();
      if (this.isStrictVerification() && this.config.useSecureChannel === false) {
        throw new Error('strict verification requires the secure channel');
      }
      await this.establishNativeSession();
      await this.connectDiagnosticSocket();
      this.log('Connected to HarmonyPIR servers');
    } catch (error) {
      this.strictReady = false;
      this.secureChannelEstablished = false;
      this.disconnectQueryServer();
      await this.freeWasmClient().catch(() => { /* keep original error */ });
      throw error;
    }
  }

  /**
   * Populate server-info JSON and catalog. Matches the legacy client's
   * two-call setup so `web/index.html` can keep calling
   * `loadWasm` → `connectQueryServer` → `fetchServerInfo` in order.
   */
  async fetchServerInfo(): Promise<void> {
    if (!this.queryWs) throw new Error('connectQueryServer() must be called first');
    try {
      this.serverInfo = await fetchServerInfoJson(this.queryWs);
    } catch (error) {
      this.serverInfo = null;
      this.log(
        `HarmonyPIR server diagnostics unavailable: ${(error as Error)?.message ?? error}`,
      );
    }
  }

  /**
   * No-op for API compatibility. The legacy client reserved and
   * allocated per-group WASM state here; the native `HarmonyClient`
   * does this lazily inside `queryBatchVerified`, so there's
   * nothing to do up front.
   */
  async initGroups(): Promise<void> {
    // Intentionally empty — native client initialises on demand.
  }

  /**
   * Download the complete restart-safe hint resource for the active `dbId`
   * (main groups plus every authenticated Merkle-sibling group) and emit main
   * per-group
   * progress as `"Hints: N/total (X%)"` log lines so the UI progress
   * bar can fill incrementally as INDEX (75 groups) and CHUNK (80
   * groups) responses arrive — a total of 155 groups in production.
   *
   * Uses the native `fetchCompleteHintsWithProgress` entry point rather than
   * issuing a dummy query, so no per-group query budget is consumed
   * just to warm the hint state.
   */
  async fetchHints(): Promise<void> {
    if (!this.wasmClient) throw new Error('loadWasm() must be called first');
    if (this.isStrictVerification() && !this.isPreparedAdmissionDb(this.dbId)) {
      throw new Error(
        `Harmony hint acquisition requires prepared strict admission for db_id ${this.dbId}`,
      );
    }
    this.log('Hints: downloading…');
    this.wasmClient.setDbId(this.dbId);
    const sdkCatalog = this.catalogToSdkHandle();
    try {
      await this.wasmClient.fetchCompleteHintsWithProgress(
        sdkCatalog,
        this.dbId,
        ({ done, total }) => {
          const pct = total > 0 ? Math.round((done / total) * 100) : 0;
          this.log(`Hints: ${done}/${total} (${pct}%)`);
        },
      );
    } finally {
      sdkCatalog.free();
    }
    this.hintsLoaded = true;
    this.log('Hints: complete main+sibling bundle ready');
  }

  // ══ Database switching + catalog ══════════════════════════════════════

  getDbId(): number {
    return this.dbId;
  }

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

  /** Independent, separately priced admission for the expensive hint phase. */
  hintServiceAdmissionPort(dbId: number): ServiceAdmissionPortV1 {
    const client = (): WasmHarmonyClient => this.requireStrictAdmissionClient(0);
    const authorizedClient = (): WasmHarmonyClient =>
      this.requirePreparedAdmissionClient(0, dbId);
    return {
      providerEndpoint: () => this.config.hintServerUrl,
      operatorSigningKey: () => verifiedLiveOperatorSigningKeyV1(this.operatorIdentity.hint),
      assertTrustAnchor: (trust) => {
        client();
        assertLiveOperatorIdentityV1(trust, this.operatorIdentity.hint);
      },
      fetchPolicy: (providerId, policyKey, nowUnix, checkpoint) =>
        client().fetchServicePolicy(0, dbId, providerId, policyKey, nowUnix, checkpoint),
      fetchRetainedRedemption: (
        providerId, policyKey, policyDigest, scopeId, offerId, nowUnix,
      ) => client().fetchRetainedServiceRedemption(
        0, dbId, providerId, policyKey, policyDigest, scopeId, offerId, nowUnix,
      ),
      assertSessionBinding: (policy) => authorizedClient().verifyServicePolicySession(0, policy),
      captureReadinessGuard: () => this.captureServiceReadinessGuard(0, dbId),
      assertRetainedSessionBinding: (policy, nowUnix) =>
        authorizedClient().verifyRetainedServiceSession(0, policy, nowUnix),
      authorize: (policy, scopeId, offerId, proof) =>
        authorizedClient().authorizeHintService(dbId, policy, scopeId, offerId, proof),
      authorizeRetained: (policy, proof, nowUnix) =>
        authorizedClient().dangerousUnpairedAuthorizeRetainedHintService(
          dbId,
          policy,
          proof,
          nowUnix,
        ),
      requestPowChallenge: (policy, scopeId, offerId, nowUnix) =>
        authorizedClient().requestHintPowChallenge(dbId, policy, scopeId, offerId, nowUnix),
    };
  }

  /** Independent admission for the lower-cost Harmony query phase. */
  queryServiceAdmissionPort(dbId: number): ServiceAdmissionPortV1 {
    const client = (): WasmHarmonyClient => this.requireStrictAdmissionClient(1);
    const authorizedClient = (): WasmHarmonyClient =>
      this.requirePreparedAdmissionClient(1, dbId);
    return {
      providerEndpoint: () => this.config.queryServerUrl,
      operatorSigningKey: () => verifiedLiveOperatorSigningKeyV1(this.operatorIdentity.query),
      assertTrustAnchor: (trust) => {
        client();
        assertLiveOperatorIdentityV1(trust, this.operatorIdentity.query);
      },
      fetchPolicy: (providerId, policyKey, nowUnix, checkpoint) =>
        client().fetchServicePolicy(1, dbId, providerId, policyKey, nowUnix, checkpoint),
      fetchRetainedRedemption: (
        providerId, policyKey, policyDigest, scopeId, offerId, nowUnix,
      ) => client().fetchRetainedServiceRedemption(
        1, dbId, providerId, policyKey, policyDigest, scopeId, offerId, nowUnix,
      ),
      assertSessionBinding: (policy) => authorizedClient().verifyServicePolicySession(1, policy),
      captureReadinessGuard: () => this.captureServiceReadinessGuard(1, dbId),
      assertRetainedSessionBinding: (policy, nowUnix) =>
        authorizedClient().verifyRetainedServiceSession(1, policy, nowUnix),
      authorize: (policy, scopeId, offerId, proof) =>
        authorizedClient().authorizeQueryService(dbId, policy, scopeId, offerId, proof),
      authorizeRetained: (policy, proof, nowUnix) =>
        authorizedClient().dangerousUnpairedAuthorizeRetainedQueryService(
          dbId,
          policy,
          proof,
          nowUnix,
        ),
      requestPowChallenge: (policy, scopeId, offerId, nowUnix) =>
        authorizedClient().requestQueryPowChallenge(dbId, policy, scopeId, offerId, nowUnix),
    };
  }

  private requireStrictAdmissionClient(providerIndex: 0 | 1): WasmHarmonyClient {
    if (!this.wasmClient) throw new Error('Not connected');
    if (!this.isStrictVerification() || !this.strictLegReady[providerIndex]) {
      throw new Error(
        `V1 service admission requires strict verification of Harmony provider ${providerIndex}`,
      );
    }
    return this.wasmClient;
  }

  private requirePreparedAdmissionClient(
    providerIndex: 0 | 1,
    dbId: number,
  ): WasmHarmonyClient {
    const client = this.requireStrictAdmissionClient(providerIndex);
    if (!this.isPreparedAdmissionDb(dbId)) {
      throw new Error(
        `Harmony capability use requires prepared strict admission for db_id ${dbId}`,
      );
    }
    return client;
  }

  private captureServiceReadinessGuard(
    providerIndex: 0 | 1,
    dbId: number,
  ): () => void {
    const expectedClient = this.requirePreparedAdmissionClient(providerIndex, dbId);
    const expectedGeneration = this.pairGeneration;
    const assertReady = () => {
      if (!expectedClient.isProviderConnected(0)
          || !expectedClient.isProviderConnected(1)) {
        throw new Error('Harmony strict pair transport is no longer connected');
      }
      this.assertCurrentStrictPair(expectedClient, expectedGeneration);
      this.requirePreparedAdmissionClient(providerIndex, dbId);
    };
    assertReady();
    return assertReady;
  }

  private async verifyConfiguredDatabaseProofs(): Promise<void> {
    if (!this.wasmClient) return;
    const pins = this.config.databaseProofPins ?? [];
    if (pins.length === 0 && !this.isStrictVerification()) return;
    try {
      await verifyInstallAndPreflightDatabaseProofs({
        client: this.wasmClient,
        pins,
        onStatus: (dbId, status) => {
          this.databaseProofs.set(dbId, status);
          this.config.onDatabaseProof?.(dbId, status);
          if (status.state === 'verified') {
            this.log(
              `DB proof db ${dbId}: verified MuHash ${status.proof?.muhashHex.slice(0, 16)}...`,
            );
          } else if (status.state === 'unavailable') {
            this.log(`DB proof db ${dbId}: unavailable (${status.error})`);
          } else {
            this.log(
              `DB proof db ${dbId}: unverified (${status.mismatches?.[0] ?? status.error ?? 'check failed'})`,
            );
          }
        },
      });
    } catch (error) {
      if (this.isStrictVerification()) throw error;
      this.log(
        `Advisory database verification did not complete: ${(error as Error)?.message ?? error}`,
      );
    }
  }

  private async verifyConfiguredDatabaseProofsForLeg(
    providerIndex: 0 | 1,
    assertCurrent: () => void,
  ): Promise<InstalledDatabaseProof[]> {
    if (!this.wasmClient) throw new Error('Not connected');
    const client = this.wasmClient;
    return verifyAndInstallDatabaseProofs({
      client: {
        verifyDatabaseProof: (dbId, params, binary, commit) =>
          client.verifyDatabaseProofFromProvider(
            providerIndex,
            dbId,
            params,
            binary,
            commit,
          ),
        installVerifiedDatabaseProof: (proof) => client.installVerifiedDatabaseProof(proof),
        preflightDatabase: (dbId) => client.preflightDatabase(dbId),
      },
      pins: this.config.databaseProofPins ?? [],
      onStatus: (dbId, status) => this.recordDatabaseProofStatus(dbId, status),
      assertCurrent,
    });
  }

  private assertLiveQueryPair(
    client: WasmHarmonyClient,
    generation: number,
    dbId: number,
    operation: string,
  ): void {
    if (this.pairGeneration !== generation || this.wasmClient !== client) {
      throw new Error(`stale Harmony ${operation} result`);
    }
    if (!this.isStrictVerification()) return;
    this.assertCurrentStrictPair(client, generation);
    if (!this.isPreparedAdmissionDb(dbId)) {
      throw new Error(
        `strict Harmony ${operation} requires prepared admission for db_id ${dbId}`,
      );
    }
  }

  private recordDatabaseProofStatus(dbId: number, status: DatabaseProofStatus): void {
    this.databaseProofs.set(dbId, status);
    this.config.onDatabaseProof?.(dbId, status);
    if (status.state === 'verified') {
      this.log(
        `DB proof db ${dbId}: verified MuHash ${status.proof?.muhashHex.slice(0, 16)}...`,
      );
    } else if (status.state === 'unavailable') {
      this.log(`DB proof db ${dbId}: unavailable (${status.error})`);
    } else {
      this.log(
        `DB proof db ${dbId}: unverified (${status.mismatches?.[0] ?? status.error ?? 'check failed'})`,
      );
    }
  }

  private assertLegProofsMatch(): void {
    const hint = this.installedProofsByLeg[0];
    const query = this.installedProofsByLeg[1];
    if (!hint || !query || hint.length !== query.length) {
      throw new Error('Harmony roles did not authenticate the same database proof set');
    }
    for (let index = 0; index < hint.length; index += 1) {
      if (JSON.stringify(hint[index].proof) !== JSON.stringify(query[index].proof)) {
        throw new Error(
          `Harmony role database proof mismatch for db ${hint[index].pin.dbId}`,
        );
      }
    }
  }

  private assertStrictLegReady(providerIndex: 0 | 1): void {
    assertStrictServerLegReady({
      serverIndex: providerIndex,
      secureChannelEstablished: this.secureChannelLegs[providerIndex],
      attestation: providerIndex === 0 ? this.attestation.hint : this.attestation.query,
      expectedPin:
        providerIndex === 0 ? this.config.expectedServer0Pin : this.config.expectedServer1Pin,
      expectedServerId:
        providerIndex === 0 ? this.config.expectedServer0Id : this.config.expectedServer1Id,
      requireOperatorIdentity: this.config.verifyOperatorIdentity === true,
      operatorIdentity:
        providerIndex === 0 ? this.operatorIdentity.hint : this.operatorIdentity.query,
      operatorPin: providerIndex === 0
        ? this.config.pinnedHintOperatorPubkey
        : this.config.pinnedQueryOperatorPubkey,
    });
  }

  // ══ Query path ═══════════════════════════════════════════════════════

  /** Zero-network query-provider demand from the native PBC planner. */
  planServiceQuery(
    scriptHashes: Uint8Array[],
    dbId: number = this.dbId,
  ): ProductQueryShapeV1 {
    if (!this.wasmClient) throw new Error('Not connected');
    const plan = this.wasmClient.planServiceQuery(packScriptHashes(scriptHashes), dbId);
    return canonicalProductQueryShapeV1(plan, 'Harmony planned query shape');
  }

  /**
   * Separate cold-cache hint-provider lower bound. It covers catalog-known
   * main groups; authenticated sibling groups remain explicitly unknown.
   */
  planServiceHint(dbId: number = this.dbId): ProductQueryShapeV1 {
    if (!this.wasmClient) throw new Error('Not connected');
    const plan = this.wasmClient.planServiceHint(dbId);
    return canonicalProductQueryShapeV1(plan, 'Harmony planned hint shape');
  }

  /**
   * Batch query. Accepts Bitcoin addresses or raw-hex scriptPubKeys,
   * converts them to 20-byte HASH160 scripthashes, and issues a single
   * WASM `queryBatchVerified`. Returns a `Map<qi, HarmonyQueryResult>` keyed
   * by the input index (matching the legacy UI contract — failed
   * conversions / not-found slots are omitted from the map).
   */
  async queryBatch(
    addresses: string[],
    progress?: (phase: string, detail: string) => void,
    dbId?: number,
  ): Promise<Map<number, HarmonyQueryResult>> {
    if (!this.wasmClient) throw new Error('Not connected');
    if (this.isStrictVerification() && !this.strictReady) {
      throw new Error('strict verification is not ready');
    }
    if (this.isStrictVerification()
        && this.pairPreflightDbId !== null
        && this.admissionDbId !== this.dbId) {
      throw new Error(
        `strict Harmony admission is bound to db_id ${this.admissionDbId}, not db_id ${this.dbId}`,
      );
    }
    const client = this.wasmClient;
    const generation = this.pairGeneration;
    this.assertLiveQueryPair(client, generation, this.dbId, 'query start');
    if (dbId !== undefined && dbId !== this.dbId) {
      throw new Error(
        `queryBatch dbId=${dbId} does not match active dbId=${this.dbId}; ` +
          `call setDbId() + fetchHints() before querying a different database.`,
      );
    }

    // ── Resolve inputs to scripthashes ──
    const scriptHashes: Uint8Array[] = [];
    const shHexes: string[] = [];
    const addressesOut: string[] = [];
    const inputIndex: number[] = [];
    for (let i = 0; i < addresses.length; i++) {
      const input = addresses[i];
      let spkHex: string | null;
      if (/^[0-9a-fA-F]+$/.test(input) && input.length % 2 === 0) {
        spkHex = input.toLowerCase();
      } else {
        spkHex = addressToScriptPubKey(input);
      }
      if (!spkHex) {
        this.log(`Invalid input ${i}: ${input}`);
        continue;
      }
      const sh = computeScriptHash(hexToBytes(spkHex));
      scriptHashes.push(sh);
      shHexes.push(bytesToHex(sh));
      addressesOut.push(input);
      inputIndex.push(i);
    }
    if (scriptHashes.length === 0) return new Map();

    // ── Warm-up hints if needed ──
    if (!this.hintsLoaded) {
      progress?.('setup', 'downloading hints');
      await this.fetchHints();
      this.assertLiveQueryPair(client, generation, this.dbId, 'hint response');
    }

    // ── Submit batch ──
    progress?.('index', `submitting ${scriptHashes.length} queries`);
    const batchId = ++this.verifiedBatchGeneration;
    this.activeVerifiedBatchId = null;
    const packed = packScriptHashes(scriptHashes);
    const wqrs = await client.queryBatchVerified(packed, this.dbId);
    this.assertLiveQueryPair(client, generation, this.dbId, 'query response');
    if (batchId !== this.verifiedBatchGeneration) {
      throw new Error('stale Harmony verified result batch was superseded by a newer query');
    }
    if (wqrs.length !== scriptHashes.length) {
      throw new Error(
        `Harmony verified query returned ${wqrs.length} results for ${scriptHashes.length} inputs`,
      );
    }
    if (wqrs.some((result) => result.merkleVerified !== true)) {
      throw new Error('Harmony native verifier returned an unverified result handle');
    }
    this.activeVerifiedBatchId = batchId;
    progress?.('decode', `translating ${wqrs.length} results`);

    // ── Translate + build inspector shim ──
    const out = new Map<number, HarmonyQueryResult>();
    const inspector = new Map<number, QueryInspectorData>();
    for (let j = 0; j < wqrs.length; j++) {
      const wqr = wqrs[j];
      const qi = inputIndex[j];
      const qr = translateWasmResult(
        wqr,
        addressesOut[j],
        shHexes[j],
        scriptHashes[j],
        this.getMerkleRootHex(),
      );
      this.verifiedHandles.set(qr, {
        handle: wqr,
        batchId,
        batchSize: wqrs.length,
        slot: j,
        dbId: this.dbId,
        pairGeneration: generation,
        inputIndex: qi,
        address: addressesOut[j],
        scriptHashHex: shHexes[j],
        scriptHashBytes: scriptHashes[j].slice(),
        merkleRootHex: this.getMerkleRootHex(),
      });
      out.set(qi, qr);
      inspector.set(qi, buildInspectorShim(addressesOut[j], shHexes[j], qr));
    }
    this.lastInspectorData = inspector;
    return out;
  }

  // ══ Merkle accessors ═══════════════════════════════════════════════════

  hasMerkle(): boolean {
    return this.catalog?.databases.some((db) => db.hasBucketMerkle) ?? false;
  }

  hasMerkleForDb(dbId: number): boolean {
    return this.getCatalogEntry(dbId)?.hasBucketMerkle ?? false;
  }

  getMerkleRootHex(): string | undefined {
    const proofRoot = this.databaseProofs.get(this.dbId)?.proof?.bucketSuperRootHex;
    if (proofRoot) return proofRoot;
    if (this.isStrictVerification()) return undefined;
    return this.getBucketMerkleForDb(this.dbId)?.super_root
      ?? this.serverInfo?.merkle_bucket?.super_root;
  }

  private getBucketMerkleForDb(dbId: number): BucketMerkleInfoJson | undefined {
    if (dbId === 0) return this.serverInfo?.merkle_bucket;
    return this.serverInfo?.databases?.find((d) => d.db_id === dbId)?.merkle_bucket;
  }

  /**
   * One-shot release boundary for a native-verified Harmony batch. Only the
   * exact live objects in their original order/database/session are accepted;
   * every public field is then reconstructed from the opaque verified handle.
   */
  async verifyMerkleBatch(
    results: HarmonyQueryResult[],
    onProgress?: (step: string, detail: string) => void,
    dbId: number = this.dbId,
  ): Promise<boolean[]> {
    if (!this.wasmClient) throw new Error('Not connected');
    if (this.isStrictVerification() && !this.strictReady) {
      throw new Error('strict verification is not ready');
    }
    if (this.isStrictVerification()
        && this.pairPreflightDbId !== null
        && this.admissionDbId !== dbId) {
      throw new Error(
        `strict Harmony Merkle verification is bound to db_id ${this.admissionDbId}, not db_id ${dbId}`,
      );
    }
    const client = this.wasmClient;
    const generation = this.pairGeneration;
    this.assertLiveQueryPair(client, generation, dbId, 'inclusion verification start');
    if (dbId !== this.dbId) {
      throw new Error(
        `Harmony inclusion verification db_id ${dbId} does not match active db_id ${this.dbId}`,
      );
    }
    onProgress?.('Merkle', `verifying ${results.length} items`);

    try {
      if (results.length === 0 || this.activeVerifiedBatchId === null) {
        throw new Error('strict Harmony inclusion verification requires a live verified batch');
      }
      const bindings = results.map((result, slot) => {
        const binding = this.verifiedHandles.get(result);
        if (!binding) {
          throw new Error(`Harmony result ${slot} has no live native verification handle`);
        }
        if (binding.batchId !== this.activeVerifiedBatchId
            || binding.batchSize !== results.length
            || binding.slot !== slot
            || binding.dbId !== dbId
            || binding.pairGeneration !== generation
            || binding.handle.merkleVerified !== true) {
          throw new Error(`Harmony result ${slot} is stale, reordered, or bound to another query`);
        }
        return binding;
      });

      for (let index = 0; index < results.length; index++) {
        const binding = bindings[index];
        const trusted = translateWasmResult(
          binding.handle,
          binding.address,
          binding.scriptHashHex,
          binding.scriptHashBytes.slice(),
          binding.merkleRootHex,
        );
        scrubUnverifiedHarmonyResult(results[index]);
        Object.assign(results[index], trusted, { merkleVerified: true });
        this.verifiedHandles.delete(results[index]);
        this.lastInspectorData?.set(
          binding.inputIndex,
          buildInspectorShim(binding.address, binding.scriptHashHex, results[index]),
        );
      }
      this.activeVerifiedBatchId = null;
    } catch (error) {
      this.activeVerifiedBatchId = null;
      for (const result of results) scrubUnverifiedHarmonyResult(result);
      throw error;
    }
    const verdicts = results.map(() => true);
    onProgress?.('Merkle', `done (${verdicts.length}/${verdicts.length} passed)`);
    return verdicts;
  }

  // ══ IndexedDB hint persistence ═════════════════════════════════════════

  /**
   * Serialise current hint state to the IndexedDB cache, keyed by the exact
   * provider/policy/scope/offer/dataset/PRP admission binding. The blob embeds a
   * fingerprint; the stored record also carries the random master PRP
   * key so a restore across page reloads can re-derive the
   * fingerprint correctly.
   *
   * The native client uses the master PRP key to encode / decrypt hint
   * parities, but the fingerprint check in `loadHints` is defence in
   * depth against stale server-side data — both must match.
   */
  async saveHintsToCache(binding: HarmonyHintCacheBindingV1): Promise<void> {
    if (!this.wasmClient || !this.catalog) return;
    this.assertHintCacheBinding(binding);
    const completenessCatalog = this.catalogToSdkHandle();
    try {
      if (!this.wasmClient.hasCompleteHints(completenessCatalog, this.dbId)) {
        this.log('Incomplete main-only hint state was not persisted');
        return;
      }
    } finally {
      completenessCatalog.free();
    }
    const bytes = this.wasmClient.saveHints();
    if (!bytes) {
      this.log('No hints loaded to persist');
      return;
    }
    // Keep the fingerprint for cache diagnostics. The restore path still
    // performs the authoritative native fingerprint check in loadHints().
    const sdkCatalog = this.catalogToSdkHandle();
    let fingerprint: Uint8Array;
    try {
      fingerprint = this.wasmClient.fingerprint(sdkCatalog, this.dbId);
    } finally {
      sdkCatalog.free();
    }
    // V2 hint setup replaces the initial client-generated PRP key with the
    // server-assigned key. Persist the effective native key, not the stale
    // value installed by loadWasm(), or the next restore fails fingerprint
    // validation even though the blob and database are otherwise identical.
    const masterKey = this.wasmClient.cacheMasterKey();
    const effectiveBackend = this.wasmClient.cachePrpBackend();
    const cacheKey = buildCacheKey(binding, this.dbId);
    const record: StoredHints = {
      cacheKey,
      dbId: this.dbId,
      providerIdHex: binding.providerIdHex,
      policyDigestHex: binding.policyDigestHex,
      scopeIdHex: binding.scopeIdHex,
      offerId: binding.offerId,
      datasetIdHex: binding.datasetIdHex,
      prpBackend: binding.prpBackend,
      // V2 servers may select a different compatible backend in the hint
      // preamble. The blob header is authoritative for later restoration.
      backend: effectiveBackend,
      masterKey,
      bytes,
      fingerprintHex: fingerprintToHex(fingerprint),
      savedAt: Date.now(),
      schemaVersion: HINT_SCHEMA_VERSION,
    };
    try {
      await idbPutHints(record);
      this.log(`Hints cached (${(bytes.length / (1024 * 1024)).toFixed(1)} MB)`);
    } catch (e) {
      this.log(`Failed to cache hints: ${(e as Error).message}`);
    }
  }

  /**
   * Restore hint state from IndexedDB, if a matching record exists.
   *
   * The master key stored alongside the blob is re-applied to the WASM
   * client via `setMasterKey` before `loadHints`. If the blob's
   * embedded fingerprint doesn't match the re-derived
   * `(masterKey, prpBackend, catalog.get(dbId))` triple, `loadHints`
   * throws and we delete the stale cache entry.
   */
  async restoreHintsFromCache(binding: HarmonyHintCacheBindingV1): Promise<boolean> {
    if (!this.wasmClient || !this.catalog) return false;
    this.assertHintCacheBinding(binding);
    const key = buildCacheKey(binding, this.dbId);
    const record = await idbGetHints(key);
    if (!record || record.schemaVersion !== HINT_SCHEMA_VERSION) return false;

    try {
      this.wasmClient.setMasterKey(record.masterKey);
      this.wasmClient.setPrpBackend(record.backend);
      const sdkCatalog = this.catalogToSdkHandle();
      try {
        this.wasmClient.loadCompleteHints(record.bytes, sdkCatalog, this.dbId);
      } finally {
        sdkCatalog.free();
      }
      this.hintsLoaded = true;
      this.log(
        `Hints restored from cache (${(record.bytes.length / (1024 * 1024)).toFixed(1)} MB)`,
      );
      return true;
    } catch (e) {
      this.log(`Cache stale (${(e as Error).message}); re-downloading`);
      // Evict the broken entry so next attempt starts clean.
      await idbDeleteHints(key).catch(() => { /* swallow */ });
      return false;
    }
  }

  /** Whether the given backend has a cached entry for the active `dbId`. */
  async hasPersistedHints(binding: HarmonyHintCacheBindingV1): Promise<boolean> {
    this.assertHintCacheBinding(binding);
    const key = buildCacheKey(binding, this.dbId);
    const record = await idbGetHints(key);
    return !!record && record.schemaVersion === HINT_SCHEMA_VERSION;
  }

  private assertHintCacheBinding(binding: HarmonyHintCacheBindingV1): void {
    const proof = this.databaseProofs.get(this.dbId)?.proof;
    if (!proof || this.databaseProofs.get(this.dbId)?.state !== 'verified') {
      throw new Error('Harmony hint cache requires a verified dataset proof');
    }
    if (binding.datasetIdHex !== proof.bucketSuperRootHex.toLowerCase()) {
      throw new Error('Harmony hint cache dataset binding does not match the verified root');
    }
    if (binding.prpBackend !== (this.config.prpBackend ?? 0)) {
      throw new Error('Harmony hint cache PRP binding does not match the active backend');
    }
  }

  // ══ Hint stats ═════════════════════════════════════════════════════════

  /**
   * Minimum remaining per-group query budget. Legacy returns
   * `number` synchronously; adapter returns a `Promise` because the
   * surface on the WASM client is synchronous but `web/index.html`
   * already `await`s it. Defaults to 0 when no hints are loaded.
   */
  async getMinQueriesRemaining(): Promise<number> {
    if (!this.wasmClient) return 0;
    return this.wasmClient.minQueriesRemaining() ?? 0;
  }

  /** Human-readable size estimate (MB, one decimal place) for the UI. */
  estimateHintSize(): string {
    if (!this.wasmClient) return '0.0';
    const bytes = this.wasmClient.estimateHintSizeBytes();
    return (bytes / (1024 * 1024)).toFixed(1);
  }

  /**
   * Re-download hints for the active `(dbId, backend)`. Convenience
   * wrapper that calls `fetchHints` after resetting the
   * `hintsLoaded` flag.
   */
  async refreshHints(): Promise<void> {
    this.hintsLoaded = false;
    await this.fetchHints();
  }

  // ══ Connection management ══════════════════════════════════════════════

  disconnectQueryServer(): void {
    this.queryWs?.disconnect();
    this.queryWs = null;
    if (this.isStrictVerification()) {
      // A later reconnect must rebuild channel and database-root trust for a
      // fresh native session before queries become available again.
      this.strictReady = false;
    }
  }

  isQueryServerConnected(): boolean {
    return this.queryWs?.isOpen() ?? false;
  }

  onQueryServerClose(callback: () => void): void {
    this.externalCloseCallback = callback;
  }

  async reconnectQueryServer(): Promise<void> {
    this.disconnectQueryServer();
    if (!this.wasmClient) throw new Error('loadWasm() must be called first');
    try {
      if (this.isStrictVerification()) {
        // Native disconnect clears installed roots, catalog, and tree-top cache.
        // Re-run the complete bootstrap so root rotation cannot reuse old state.
        if (this.wasmClient.isConnected) {
          await this.wasmClient.disconnect();
        }
        this.hintsLoaded = false;
        this.resetVerificationState();
        this.wasmClient.setRequireVerifiedDatabaseRoots(true);
        await this.establishNativeSession();
      } else if (!this.wasmClient.isConnected) {
        // Advisory compatibility path.
        await this.wasmClient.connect();
      }
      await this.connectDiagnosticSocket();
      await this.fetchServerInfo();
      this.log(
        this.hintsLoaded
          ? 'Reconnected to Query Server (hints preserved)'
          : 'Reconnected to Query Server',
      );
    } catch (error) {
      // A strict rebuild may fail after opening only part of the transport or
      // after allocating a fresh proof/catalog session. Leave no reconnectable
      // half-session behind; the caller can construct/load a fresh client.
      this.disconnectQueryServer();
      this.hintsLoaded = false;
      await this.freeWasmClient().catch(() => { /* keep original error */ });
      throw error;
    }
  }

  /**
   * Await the WASM client's `disconnect()` before `free()`, then drop the
   * handle. `disconnect()` is a wasm-bindgen `async fn(&mut self)` and holds
   * the Rust borrow until its promise resolves; calling `free()` (which takes
   * ownership) while that borrow is live throws "attempted to take ownership
   * of Rust value while it was borrowed". Awaiting also lets the WS close
   * frame go out, which `Drop`'s `detach_ws_handlers` alone would not send.
   * Nulls the handle up front so a concurrent call can't double-free.
   */
  private async freeWasmClient(): Promise<void> {
    this.legGenerations = [this.legGenerations[0] + 1, this.legGenerations[1] + 1];
    this.legOwners = [null, null];
    this.strictReady = false;
    this.secureChannelEstablished = false;
    this.pairGeneration += 1;
    this.verifiedBatchGeneration += 1;
    this.activeVerifiedBatchId = null;
    this.secureChannelLegs = [false, false];
    this.strictLegReady = [false, false];
    this.installedProofsByLeg = [null, null];
    this.pairConsistencyReady = false;
    this.pairPreflightState = 'not-ready';
    this.pairPreflightPromise = null;
    this.pairPreflightDbId = null;
    this.admissionDbId = null;
    this.catalog = null;
    this.serverInfo = null;
    this.databaseProofs.clear();
    const client = this.wasmClient;
    if (!client) return;
    this.wasmClient = null;
    try {
      await client.disconnect();
    } catch {
      /* already closed / mid-flight — proceed to free regardless */
    }
    client.free();
  }

  /** Full teardown — closes transports and frees WASM state. */
  disconnect(): void {
    this.strictReady = false;
    this.secureChannelEstablished = false;
    this.queryWs?.disconnect();
    this.queryWs = null;
    // `freeWasmClient()` is async (awaits the WASM `disconnect()` before
    // `free()`); callers invoke `disconnect()` fire-and-forget, and the
    // synchronous prefix above (socket close + handle null-out) has already
    // taken effect. Swallow any rejection from the async tail.
    void this.freeWasmClient().catch(() => { /* swallow */ });
    this.hintsLoaded = false;
  }

  /**
   * Legacy API — used to terminate the TS worker pool for a PRP
   * switch. The adapter has no worker pool; we free the WASM client
   * so `updatePrpBackend` + `loadWasm` starts fresh.
   */
  terminatePool(): void {
    void this.freeWasmClient().catch(() => { /* swallow */ });
    this.hintsLoaded = false;
  }

  /** Update the PRP backend. Call before `loadWasm()` on a PRP switch. */
  updatePrpBackend(backend: number): void {
    this.config.prpBackend = backend;
  }

  // ══ Test-only hook ═════════════════════════════════════════════════════

  /**
   * Legacy test-harness escape hatch. The native `HarmonyClient` has
   * no matching override path (query inputs go straight through the
   * wire format without client-side re-derivation), so this is a no-op
   * stub kept for API compatibility. Production UI never sets this.
   */
  setScriptHashOverrideForNextQuery(_hashes: Uint8Array[]): void {
    // No-op.
  }

  // ══ Internal ═══════════════════════════════════════════════════════════

  private isStrictVerification(): boolean {
    return this.config.strictVerification === true;
  }

  private isPairPreflightComplete(): boolean {
    return this.pairPreflightState === 'complete';
  }

  /** Exact staged binding, with a compatibility allowance for the legacy
   * bootstrap that preflights and publishes every pinned database root. */
  isPreparedAdmissionDb(dbId: number): boolean {
    if (!this.strictReady || !this.isPairPreflightComplete()) return false;
    if (this.admissionDbId !== null) return this.admissionDbId === dbId;
    return this.pairPreflightDbId === null
      && this.databaseProofs.get(dbId)?.state === 'verified';
  }

  private resetVerificationState(): void {
    this.legGenerations = [this.legGenerations[0] + 1, this.legGenerations[1] + 1];
    this.legOwners = [null, null];
    this.strictReady = false;
    this.secureChannelEstablished = false;
    this.pairGeneration += 1;
    this.verifiedBatchGeneration += 1;
    this.activeVerifiedBatchId = null;
    this.secureChannelLegs = [false, false];
    this.strictLegReady = [false, false];
    this.installedProofsByLeg = [null, null];
    this.pairConsistencyReady = false;
    this.pairPreflightState = 'not-ready';
    this.pairPreflightPromise = null;
    this.pairPreflightDbId = null;
    this.admissionDbId = null;
    this.catalog = null;
    this.serverInfo = null;
    this.databaseProofs.clear();
    this.attestation = {
      hint: { state: 'unattested' },
      query: { state: 'unattested' },
    };
    this.operatorIdentity = {
      hint: { state: 'not-checked' },
      query: { state: 'not-checked' },
    };
  }

  private async establishNativeSession(): Promise<void> {
    if (!this.wasmClient) throw new Error('loadWasm() must be called first');
    await this.wasmClient.connect();
    if (this.config.useSecureChannel !== false) {
      await this.attestAndUpgrade();
    }
    if (this.isStrictVerification()) {
      assertStrictTransportReady({
        secureChannelEstablished: this.secureChannelEstablished,
        attestations: [this.attestation.hint, this.attestation.query],
        expectedPins: [this.config.expectedServer0Pin, this.config.expectedServer1Pin],
        expectedServerIds: [this.config.expectedServer0Id, this.config.expectedServer1Id],
        requireOperatorIdentity: this.config.verifyOperatorIdentity === true,
        operatorIdentities: [this.operatorIdentity.hint, this.operatorIdentity.query],
        operatorPins: [
          this.config.pinnedHintOperatorPubkey,
          this.config.pinnedQueryOperatorPubkey,
        ],
      });
    }

    const catalogHandle = await this.wasmClient.fetchCatalog();
    try {
      this.catalog = databaseCatalogFromWasmJson(catalogHandle.toJson());
    } finally {
      catalogHandle.free();
    }
    if (this.isStrictVerification()) this.assertPinsCoverCatalog();
    await this.verifyConfiguredDatabaseProofs();
    this.strictReady = this.isStrictVerification();
    this.strictLegReady = [this.strictReady, this.strictReady];
    this.pairGeneration += 1;
    this.pairConsistencyReady = this.strictReady;
    this.pairPreflightState = this.strictReady ? 'complete' : 'not-ready';
    this.pairPreflightDbId = null;
    this.admissionDbId = null;
  }

  private assertPinsCoverCatalog(): void {
    if (!this.catalog) throw new Error('strict verification requires a database catalog');
    assertStrictDatabasePinCoverage(
      this.catalog.databases.map((db) => db.dbId),
      this.config.databaseProofPins ?? [],
    );
  }

  private async connectDiagnosticSocket(assertCurrent?: () => void): Promise<void> {
    const socket = new ManagedWebSocket({
      url: this.config.queryServerUrl,
      label: 'HarmonyPIR Query Server',
      onLog: (msg, _level) => this.log(msg),
      onClose: () => {
        // `disconnect()` closes asynchronously. Ignore the old socket's late
        // close event if a replacement diagnostic session already exists.
        if (this.queryWs !== socket) return;
        this.queryWs = null;
        if (this.isStrictVerification()) this.strictReady = false;
        this.externalCloseCallback?.();
      },
    });
    this.queryWs = socket;
    try {
      await socket.connect();
      assertCurrent?.();
    } catch (error) {
      if (this.queryWs === socket) this.queryWs = null;
      socket.disconnect();
      throw error;
    }
  }

  /** Build a `WasmDatabaseCatalog` handle from the cached catalog. */
  private catalogToSdkHandle(): any {
    const sdk = requireSdkWasm();
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
    return sdk.WasmDatabaseCatalog.fromJson(json);
  }

}

function scrubUnverifiedHarmonyResult(result: HarmonyQueryResult): void {
  result.utxos = [];
  result.rawChunkData = undefined;
  result.scriptHashBytes = undefined;
  result.indexPbcGroup = undefined;
  result.indexBinIndex = undefined;
  result.indexBinContent = undefined;
  result.allIndexBins = undefined;
  result.chunkPbcGroups = undefined;
  result.chunkBinIndices = undefined;
  result.chunkBinContents = undefined;
  result.merkleVerified = false;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function packScriptHashes(hashes: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(hashes.length * 20);
  for (let i = 0; i < hashes.length; i++) {
    if (hashes[i].length !== 20) {
      throw new Error(
        `scriptHash[${i}] must be 20 bytes, got ${hashes[i].length}`,
      );
    }
    out.set(hashes[i], i * 20);
  }
  return out;
}

/**
 * Translate a `WasmQueryResult` into a `HarmonyQueryResult`. Structurally
 * very similar to `translateWasmResult` in the DPF adapter, but the
 * UTXO shape differs (hex-string `txid` + `number value` instead of
 * `Uint8Array txid` + `bigint amount`).
 */
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
    // WASM: {txid: hexString, vout: number, amountSats: number | bigint}.
    // HarmonyPIR UI-facing: {txid: hex (internal byte order), vout, value}.
    // Legacy TS client stored txid in display byte order (reversed); the
    // WASM side already emits internal byte order.  Match the legacy
    // display by reversing here, keeping UI rendering unchanged.
    const txidBytes = hexToBytes(e.txid);
    const txidReversed = new Uint8Array(txidBytes.length);
    for (let k = 0; k < txidBytes.length; k++) {
      txidReversed[k] = txidBytes[txidBytes.length - 1 - k];
    }
    utxos.push({
      txid: bytesToHex(txidReversed),
      vout: Number(e.vout),
      value: Number(e.amountSats ?? e.amount ?? 0),
    });
  }

  type WireBin = { pbcGroup: number; binIndex: number; binContent: string };
  const indexBinsRaw = (wqr.indexBins() as WireBin[]) ?? [];
  const chunkBinsRaw = (wqr.chunkBins() as WireBin[]) ?? [];
  const matchedIdxRaw = wqr.matchedIndexIdx();
  const matchedIdx = typeof matchedIdxRaw === 'number' ? matchedIdxRaw : undefined;
  const rawChunkData = wqr.rawChunkData();

  const allIndexBins = indexBinsRaw.map((b) => ({
    pbcGroup: b.pbcGroup,
    binIndex: b.binIndex,
    binContent: hexToBytes(b.binContent),
  }));
  // Fall back to the first probed bin for NOT-FOUND queries so
  // `indexPbcGroup !== undefined` stays truthy — the Merkle-button filter
  // in `web/index.html` uses that predicate to decide whether to attach a
  // verify button for the step, and not-found queries in a sparse delta
  // would otherwise drop out entirely (absence is still provable via
  // `allIndexBins`). Matches the DPF adapter's fallback.
  const primary = matchedIdx !== undefined ? allIndexBins[matchedIdx] : allIndexBins[0];

  return {
    address,
    scriptHash: scriptHashHex,
    utxos,
    whale: wqr.isWhale,
    // Native verification has completed, but the UI-visible object remains
    // quarantined until the adapter's one-shot object/order check runs.
    merkleVerified: false,
    merkleRootHex,
    rawChunkData: rawChunkData instanceof Uint8Array ? rawChunkData : undefined,
    scriptHashBytes,
    indexPbcGroup: primary?.pbcGroup,
    indexBinIndex: primary?.binIndex,
    indexBinContent: primary?.binContent,
    allIndexBins: allIndexBins.length > 0 ? allIndexBins : undefined,
    chunkPbcGroups: chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => b.pbcGroup) : undefined,
    chunkBinIndices: chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => b.binIndex) : undefined,
    chunkBinContents:
      chunkBinsRaw.length > 0
        ? chunkBinsRaw.map((b) => hexToBytes(b.binContent))
        : undefined,
  };
}


/**
 * Build a reduced `QueryInspectorData` from the translated
 * `HarmonyQueryResult`. The UI's Query Inspector can still open; fields
 * the native client does not surface (placement round, per-chunk
 * segment/position, round timings) are left blank.
 */
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

// ─── Factory ────────────────────────────────────────────────────────────────

/** Convenience factory matching the legacy `createHarmonyPirClient`. */
export function createHarmonyPirClientAdapter(
  config: HarmonyPirClientConfig,
): HarmonyPirClientAdapter {
  return new HarmonyPirClientAdapter(config);
}
