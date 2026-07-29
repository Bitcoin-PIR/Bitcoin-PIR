/**
 * WASM-backed adapter that mimics the legacy `BatchPirClient` API shape.
 *
 * The old `web/src/client.ts` carried ~800 LOC of PIR wire-format logic
 * (encoding batched DPF queries, decoding responses, per-bucket Merkle
 * verification). Session 3 of the TS retirement plan replaced that with
 * this adapter, which delegates the actual PIR work to `WasmDpfClient`
 * from `pir-sdk-wasm` (which in turn wraps the native Rust `DpfClient`
 * via the `wasm_transport` layer in `pir-sdk-client`).
 *
 * What stays in TypeScript:
 *   * A pair of side-channel `ManagedWebSocket`s — the WASM client owns
 *     its own transport sockets internally, but those aren't exposed to
 *     the browser. The side-channel sockets are used for:
 *       - `REQ_GET_INFO_JSON` for diagnostic details only. Catalog, Merkle
 *         availability, sync planning, and trusted roots all come from the
 *         post-upgrade native connection and installed proof handles.
 *   * Translation between `WasmQueryResult` (the WASM-side opaque
 *     handle) and the legacy `QueryResult` shape consumed by the UI
 *     renderers + `sync-merge.ts`.
 *
 * What moves to WASM:
 *   * All PIR wire-format logic (INDEX + CHUNK batched queries).
 *   * Per-bucket bin-Merkle verification (`verifyMerkleBatch`).
 *   * Padding invariants (K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE) —
 *     owned by the native `DpfClient`, not re-implementable here.
 *
 * 🔒 Privacy: the adapter cannot bypass padding, cannot short-circuit the
 * symmetric INDEX bin probing (`INDEX_CUCKOO_NUM_HASHES = 2`), and cannot
 * turn off Merkle verification — those live in native Rust code below the
 * WASM boundary.
 */

import { bytesToHex, hexToBytes } from './hash.js';
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
  type WasmDpfClient,
  type WasmQueryResult,
} from './sdk-bridge.js';
import {
  type DatabaseProofPin,
  type DatabaseProofStatus,
} from './db-proof.js';
import { getAmdTurinArkFingerprint, PIR_OPERATOR_PUBKEY } from './attest-pin.js';
import {
  assertIndependentOperatorPinsV1,
  assertStrictDatabasePinCoverage,
  assertStrictServerLegReady,
  assertStrictTransportReady,
  exactOperatorPinV1,
  preflightInstalledDatabaseProofs,
  resolveIndependentOperatorPinsV1 as resolveIndependentOperatorPinsV1StrictHelper,
  verifyAndInstallDatabaseProofs,
  verifyInstallAndPreflightDatabaseProofs,
  type InstalledDatabaseProof,
} from './strict-verification.js';
import type { ConnectionState, QueryResult, UtxoEntry } from './types.js';
import { ManagedWebSocket } from './ws.js';
import {
  assertLiveOperatorIdentityV1,
  type ServiceAdmissionPortV1,
} from './service-admission.js';

// ─── Config ──────────────────────────────────────────────────────────────────

/**
 * Per-server attestation snapshot, exposed via
 * `BatchPirClientAdapter.attestation` after `connect()` returns.
 *
 * `state`:
 *   - `'unattested'`: no attest call has succeeded for this server (or
 *     it's still in progress). Treat the channel as cleartext.
 *   - `'verified'`: attest returned `'reportDataMatch'` AND the server
 *     reported a non-zero X25519 channel pubkey AND the
 *     `upgradeToSecureChannel` call succeeded. Subsequent traffic is
 *     AEAD-sealed; cloudflared sees only ciphertext. The SEV-SNP
 *     report is internally consistent but its signature has NOT been
 *     chain-validated back to AMD's root.
 *   - `'verified-vcek'`: same as `'verified'` PLUS the AMD VCEK chain
 *     (ARK→ASK→VCEK) verified AND the report's ECDSA-P384 signature
 *     verified against the VCEK pubkey. Strongest browser-side
 *     guarantee — the report is provably signed by real AMD silicon
 *     whose root we operator-pinned at web-build time.
 *   - `'plaintext'`: attest succeeded but the server has no channel
 *     pubkey (legacy server). Subsequent traffic is plaintext through
 *     cloudflared — fine for development but not for production
 *     privacy.
 *   - `'mismatch'`: attest binding check failed. Self-reported fields
 *     should not be trusted; the connection is still alive but the
 *     adapter logs a warning and falls back to cleartext.
 */
export interface ServerAttestation {
  state: 'unattested' | 'verified' | 'verified-vcek' | 'plaintext' | 'mismatch';
  /** Raw SEV-SNP REPORT_DATA binding status from the attest call.
   *  Useful for surfacing the precise reason behind `mismatch`. */
  sevStatus?: string;
  /** Hex-encoded X25519 channel pubkey reported by the server. Empty
   *  on `unattested`; all-zero hex (`'00…00'`) on `plaintext`. */
  serverStaticPubHex?: string;
  /** SHA-256 of the running server binary (server-side self-report).
   *  Hex-encoded. Trusted only when `state === 'verified'` or
   *  `'verified-vcek'`. */
  binarySha256Hex?: string;
  /** Git commit baked into the running server binary. */
  gitRev?: string;
  /** Hex-encoded launch MEASUREMENT (96 chars / 48 bytes) — the
   *  digest AMD's PSP signs into every SEV-SNP report, covering OVMF
   *  + the loaded UKI bytes. Empty when not on a SEV-SNP host.
   *  Hardware-backed iff `sevStatus === 'reportDataMatch'`. */
  launchMeasurementHex?: string;
  /** When VCEK chain validation was attempted: 'pass' / 'fail' /
   *  'skipped' (server didn't bundle a chain — pre-Slice-D.2 server
   *  or `--vcek-dir` unset). Filled in by the adapter after the
   *  attest call resolves. */
  vcekChain?: 'pass' | 'fail' | 'skipped';
  /** When `vcekChain === 'fail'`, the diagnostic from
   *  `pir_attest_verify::VerifyError`. */
  vcekChainError?: string;
  /** Slice 3 build-time pin enforcement status:
   *   - `'no-pin'`: no pin configured for this server.
   *   - `'match'`: configured pin(s) matched the attested values.
   *   - `'measurement-mismatch'`: launchMeasurementHex didn't match.
   *   - `'binary-mismatch'`: binarySha256Hex didn't match.
   * On any mismatch, `state` is demoted to `'mismatch'` and
   * `pinError` carries a human-readable diagnostic. */
  pinStatus?: 'no-pin' | 'match' | 'measurement-mismatch' | 'binary-mismatch';
  pinError?: string;
}

/**
 * Per-server operator-signed-identity snapshot, exposed via
 * `BatchPirClientAdapter.operatorIdentity` when
 * `config.verifyOperatorIdentity` is enabled. The UI gates a "verified
 * operator" badge on `state === 'verified'` ONLY — never on the bundle's
 * `chainVerified` alone (that proves consistency, not authenticity).
 *
 * States:
 *   - `'not-checked'`: verification disabled, or not yet run.
 *   - `'unconfigured'`: server has no operator identity (started without
 *     `--identity-*`). Expected for servers that haven't opted in — show
 *     nothing, not an error.
 *   - `'verified'`: REQ_ANNOUNCE returned a bundle AND operator-pin
 *     (`checkPinnedOperator`: pubkey + cert signature + validity + chain)
 *     AND channel-binding (`checkChannelBinding` vs the attested
 *     `serverStaticPub`) both passed.
 *   - `'unverified'`: a bundle came back but a check failed (wrong
 *     operator, bad signature, expired, chain mismatch, or channel
 *     mismatch). `error` carries the diagnostic — treat as a strong
 *     negative signal.
 *   - `'error'`: couldn't complete the check (no attestation to bind
 *     against, transport/protocol error). `error` carries the reason.
 */
export interface OperatorIdentity {
  state: 'not-checked' | 'unconfigured' | 'verified' | 'unverified' | 'error';
  /** `server_id` the cert is endorsed for (e.g. "pir1"). */
  serverId?: string;
  /** Hex operator (Tier-1) pubkey the cert claims. Trustworthy only
   *  when `state === 'verified'`. */
  operatorPubkeyHex?: string;
  /** Hex identity (Tier-2) pubkey the operator endorsed. */
  identityPubkeyHex?: string;
  /** Git rev the manifest self-reports. */
  gitRev?: string;
  /** Binary SHA-256 authenticated by the signed announce manifest. */
  binarySha256Hex?: string;
  /** Cert validity upper bound (unix-seconds; 0 = indefinite). */
  validUntil?: number;
  /** Diagnostic for `'unverified'` / `'error'`. */
  error?: string;
}

/**
 * Pure gating step: given a fetched `WasmAnnounceVerification`, the
 * pinned operator pubkey, the attested channel key, and a wall clock,
 * run operator-pin + channel-binding and classify. Never throws —
 * folds a failed check into `state: 'unverified'`. Extracted (and
 * exported) so it's unit-testable without a live server.
 */
export function gateOperatorIdentity(
  v: WasmAnnounceVerification,
  pinnedOperatorPubkey: Uint8Array,
  expectedChannelPub: Uint8Array,
  nowUnixSeconds: bigint,
  maxAgeSeconds: bigint = 0n,
): OperatorIdentity {
  try {
    // checkPinnedOperator already requires chainVerified internally.
    v.checkPinnedOperator(pinnedOperatorPubkey, nowUnixSeconds);
    v.checkChannelBinding(expectedChannelPub);
    // Replay/staleness guard. With maxAgeSeconds=0n only the future-dated
    // arm runs (issued_at is the server's boot time, so a default
    // staleness cap would wrongly reject long-uptime servers).
    v.checkFreshness(nowUnixSeconds, maxAgeSeconds);
    return {
      state: 'verified',
      serverId: v.serverId,
      operatorPubkeyHex: v.operatorPubkeyHex,
      identityPubkeyHex: v.identityPubkeyHex,
      binarySha256Hex: v.binarySha256Hex,
      gitRev: v.gitRev,
      validUntil: Number(v.validUntil),
    };
  } catch (e) {
    return {
      state: 'unverified',
      serverId: v.serverId,
      operatorPubkeyHex: v.operatorPubkeyHex,
      binarySha256Hex: v.binarySha256Hex,
      error: (e as Error)?.message ?? String(e),
    };
  }
}

/** Resolve two local operator pins without introducing a cross-server ID. */
export function resolveIndependentOperatorPinsV1(options: {
  strictVerification: boolean;
  first?: Uint8Array;
  second?: Uint8Array;
  legacyShared?: Uint8Array;
}): readonly [Uint8Array, Uint8Array] {
  return resolveIndependentOperatorPinsV1StrictHelper({
    ...options,
    legacyShared: options.legacyShared ?? PIR_OPERATOR_PUBKEY,
  });
}

export interface BatchPirClientConfig {
  server0Url: string;
  server1Url: string;
  /** Fires on every connection-state transition (from the adapter itself +
   * from the underlying `WasmDpfClient`). `disconnected` is also emitted on
   * errors during connect. */
  onConnectionStateChange?: (state: ConnectionState, message?: string) => void;
  /** Fires for adapter-level log events (connect messages, side-channel
   * errors). Audit events from the native client go to `console.log` —
   * we do not have an `onLog` hook on `WasmDpfClient` yet. */
  onLog?: (msg: string, level: 'info' | 'success' | 'error') => void;
  /**
   * If `true` (default), the adapter automatically attests both servers
   * after the WS connect completes and, when both report a valid
   * X25519 channel pubkey, upgrades both connections to the encrypted
   * channel. Subsequent PIR traffic flows through `pir_channel`'s
   * AEAD-sealed frames so cloudflared sees only ciphertext.
   *
   * Set `false` to keep the connection in cleartext (e.g. for
   * tcpdump-side debugging or testing against pre-V2 servers).
   */
  useSecureChannel?: boolean;
  /**
   * Fail closed unless both runtime identities, the encrypted channel, every
   * configured operator identity, and every catalog database root are
   * verified before a query. Default `false` for library compatibility;
   * production explicitly enables it.
   */
  strictVerification?: boolean;
  /** Fires once per server after `connect()` resolves the per-server
   *  attestation result. Use to surface a "verified channel" badge in
   *  the UI. `serverIndex` is 0 (first URL) or 1 (second URL). */
  onAttestation?: (serverIndex: 0 | 1, info: ServerAttestation) => void;
  /**
   * Operator-pinned 32-byte SHA-256 fingerprint of the AMD ARK
   * (Root Key) certificate. When set AND the server bundles a VCEK
   * chain, the adapter calls `verifyVcekChain` and flips
   * `attestation.serverN.state` to `'verified-vcek'` on success. When
   * `null` (default), the chain isn't validated and state caps at
   * `'verified'` (V2 binding only).
   *
   * Pin this at web-build time (e.g. read from a `.env` constant) so a
   * malicious server can't substitute a forged "ARK". Compute via
   *   sha256(DER(ARK))
   * — for AMD's published ARK at https://kdsintf.amd.com/vcek/v1/{Family}/cert_chain
   * (the second PEM block).
   */
  expectedArkFingerprint?: Uint8Array | null;
  /**
   * Slice 3 build-time pins for the per-server attested values.
   * When a pin is set for a server, the adapter enforces it after
   * the SEV-SNP / VCEK chain checks pass: any mismatch on
   * `measurementHex` or `binarySha256Hex` demotes that server's
   * `state` to `'mismatch'` and carries a `pinError` diagnostic.
   *
   * Both fields are optional per server. Skipping a field skips
   * that check (e.g. omit `measurementHex` for non-SEV servers
   * like pir1 — they have no MEASUREMENT to compare).
   *
   * Pin values come from operator-published constants in
   * [`./attest-pin.ts`] — see `PIR2_TIER3_PIN` and `PIR1_PIN`.
   * Update those constants whenever the operator re-bakes + republishes.
   */
  expectedServer0Pin?: import('./attest-pin.js').ServerAttestPin;
  expectedServer1Pin?: import('./attest-pin.js').ServerAttestPin;
  /** Expected operator-endorsed identity for each transport endpoint.
   * Strict mode requires both non-empty IDs and rejects duplicate endpoint
   * identities. Production uses server0=`pir1`, server1=`pir2`. */
  expectedServer0Id?: string;
  expectedServer1Id?: string;
  /**
   * If `true`, after attesting each server the adapter also fetches its
   * operator-signed identity (REQ_ANNOUNCE) and verifies it against
   * that server's per-leg operator pin + the attested channel key, populating
   * `operatorIdentity.serverN`. Default `false`: production servers
   * don't yet run with `--identity-*` (they'd report `'unconfigured'`)
   * and the default pin is a DEV stand-in — see `PIR_OPERATOR_PUBKEY`.
   * Requires `useSecureChannel` (needs the attested channel key to bind).
   */
  verifyOperatorIdentity?: boolean;
  /**
   * Legacy shared operator pin. Advisory mode falls back to this value (or
   * the development constant) for compatibility.
   * @deprecated It cannot satisfy strict two-provider independence; use the
   * two per-leg fields below.
   */
  pinnedOperatorPubkey?: Uint8Array;
  /** Exact Tier-1 operator key for server 0. */
  pinnedOperatorPubkey0?: Uint8Array;
  /** Exact Tier-1 operator key for server 1. Strict mode requires it to
   * differ from `pinnedOperatorPubkey0`. */
  pinnedOperatorPubkey1?: Uint8Array;
  /**
   * Replay/staleness cap (seconds) on the announce bundle's `issuedAt`.
   * `issuedAt` is the server's *boot time*, so set this generously
   * (≥ expected max uptime). Default `0` = no staleness cap (the
   * future-dated guard always runs). Only consulted when
   * `verifyOperatorIdentity`.
   */
  maxAnnounceAgeSeconds?: number;
  /** Fires once per server after `connect()` resolves the per-server
   *  operator-identity check (only when `verifyOperatorIdentity`). Use to
   *  surface a "verified operator" badge — gate it on `state === 'verified'`. */
  onOperatorIdentity?: (serverIndex: 0 | 1, info: OperatorIdentity) => void;
  /** Database proof pins the frontend should fetch and verify after the
   * catalog is loaded. Empty/default means no db-proof UI check. */
  databaseProofPins?: DatabaseProofPin[];
  /** Fires once per configured database proof pin after verification,
   * mismatch, or "not configured" is known. */
  onDatabaseProof?: (dbId: number, info: DatabaseProofStatus) => void;
}

export interface BatchPirServerLegConfig {
  url: string;
  expectedPin?: import('./attest-pin.js').ServerAttestPin;
  expectedServerId?: string;
  pinnedOperatorPubkey?: Uint8Array;
}

interface DpfLegOwnerV1 {
  generation: number;
  client: WasmDpfClient;
  diagnostic: ManagedWebSocket;
  url: string;
  configSignature: string;
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

/**
 * Drop-in replacement for the pre-Session-3 `BatchPirClient`. Same
 * constructor config, same method names, same return shapes —
 * `web/index.html` changes its `new BatchPirClient(...)` call site to
 * `new BatchPirClientAdapter(...)` and nothing else.
 */
export class BatchPirClientAdapter {
  private readonly config: BatchPirClientConfig;
  private ws0: ManagedWebSocket | null;
  private ws1: ManagedWebSocket | null;
  private wasmClient: WasmDpfClient | null = null;
  private catalog: DatabaseCatalog | null = null;
  private serverInfo: ServerInfoJson | null = null;
  /**
   * Back-reference from translated `QueryResult` to its originating
   * `WasmQueryResult` handle. `WeakMap` so the pair can be collected once
   * the caller drops the translated result. `verifyMerkleBatch` reaches
   * here to round-trip each result through `toJson()` without having to
   * re-serialise by hand.
   */
  private readonly wasmHandles: WeakMap<QueryResult, WasmQueryResult> = new WeakMap();
  private connected = false;
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
  /** Invalidates native state callbacks from a client being torn down. */
  private sessionGeneration = 0;
  /** Per-leg async ownership. A disconnect/reconfiguration invalidates every
   * late continuation before it may publish catalog/proof/readiness state. */
  private legGenerations: [number, number] = [0, 0];
  private legOwners: [DpfLegOwnerV1 | null, DpfLegOwnerV1 | null] = [null, null];
  private legDisconnects: [Promise<void> | null, Promise<void> | null] = [null, null];
  /**
   * Per-server attestation snapshot. Filled in by `connect()` if
   * `useSecureChannel` is enabled (default). Default `'unattested'`
   * until the post-connect attest call resolves. UI consumers should
   * read this after `connect()` returns or via the `onAttestation`
   * callback for live updates.
   */
  attestation: { server0: ServerAttestation; server1: ServerAttestation } = {
    server0: { state: 'unattested' },
    server1: { state: 'unattested' },
  };

  /**
   * Per-server operator-signed-identity snapshot. Populated by
   * `connect()` only when `config.verifyOperatorIdentity` is set; stays
   * `'not-checked'` otherwise. Read after `connect()` or via the
   * `onOperatorIdentity` callback. Gate any "verified operator" badge on
   * `state === 'verified'`.
   */
  operatorIdentity: { server0: OperatorIdentity; server1: OperatorIdentity } = {
    server0: { state: 'not-checked' },
    server1: { state: 'not-checked' },
  };

  /** Per-database attested-builder proof status, keyed by db_id. */
  databaseProofs: Map<number, DatabaseProofStatus> = new Map();

  constructor(config: BatchPirClientConfig) {
    this.config = {
      ...config,
      expectedArkFingerprint: config.expectedArkFingerprint?.slice() ?? config.expectedArkFingerprint,
      expectedServer0Pin: config.expectedServer0Pin ? { ...config.expectedServer0Pin } : undefined,
      expectedServer1Pin: config.expectedServer1Pin ? { ...config.expectedServer1Pin } : undefined,
      pinnedOperatorPubkey: config.pinnedOperatorPubkey?.slice(),
      pinnedOperatorPubkey0: config.pinnedOperatorPubkey0?.slice(),
      pinnedOperatorPubkey1: config.pinnedOperatorPubkey1?.slice(),
      databaseProofPins: config.databaseProofPins?.map((pin) => ({ ...pin })),
    };
    this.ws0 = config.server0Url.trim() ? this.newDiagnosticSocket(0) : null;
    this.ws1 = config.server1Url.trim() ? this.newDiagnosticSocket(1) : null;
  }

  /** Configure one provider without requiring or revealing the peer choice. */
  configureServerLeg(serverIndex: 0 | 1, leg: BatchPirServerLegConfig): void {
    if (!leg.url.trim()) throw new Error(`DPF server ${serverIndex} URL is required`);
    if (this.legDisconnects[serverIndex]) {
      throw new Error(`DPF server ${serverIndex} disconnect is still in flight`);
    }
    if (this.legOwners[serverIndex]
        || this.strictLegReady[serverIndex]
        || this.wasmClient?.isServerConnected(serverIndex)) {
      throw new Error(`DPF server ${serverIndex} is already connected`);
    }
    const configuredOperatorPin = serverIndex === 0
      ? this.config.pinnedOperatorPubkey0
      : this.config.pinnedOperatorPubkey1;
    const operatorPin = this.isStrictVerification()
      ? exactOperatorPinV1(
        `DPF server ${serverIndex} operator pin`,
        leg.pinnedOperatorPubkey ?? configuredOperatorPin,
      )
      : (leg.pinnedOperatorPubkey ?? configuredOperatorPin)?.slice();
    ++this.legGenerations[serverIndex];
    if (serverIndex === 0) {
      this.config.server0Url = leg.url;
      this.config.expectedServer0Pin = leg.expectedPin
        ? { ...leg.expectedPin }
        : this.config.expectedServer0Pin;
      this.config.expectedServer0Id = leg.expectedServerId ?? this.config.expectedServer0Id;
      this.config.pinnedOperatorPubkey0 = operatorPin;
      this.ws0?.disconnect();
      this.ws0 = this.newDiagnosticSocket(0);
    } else {
      this.config.server1Url = leg.url;
      this.config.expectedServer1Pin = leg.expectedPin
        ? { ...leg.expectedPin }
        : this.config.expectedServer1Pin;
      this.config.expectedServer1Id = leg.expectedServerId ?? this.config.expectedServer1Id;
      this.config.pinnedOperatorPubkey1 = operatorPin;
      this.ws1?.disconnect();
      this.ws1 = this.newDiagnosticSocket(1);
    }
    this.wasmClient?.setServerUrl(serverIndex, leg.url);
  }

  /**
   * Establish and strictly verify one provider transport. The first leg may
   * expose its signed policy and other read-only session metadata; capability
   * use and queries wait for the independently selected second leg and pair
   * preflight.
   */
  async connectLeg(serverIndex: 0 | 1): Promise<void> {
    if (this.strictLegReady[serverIndex]) return;
    if (this.legDisconnects[serverIndex]) {
      throw new Error(`DPF server ${serverIndex} disconnect is still in flight`);
    }
    if (this.legOwners[serverIndex]) {
      throw new Error(`DPF server ${serverIndex} connect is already in flight`);
    }
    this.setState('connecting');
    let owner: DpfLegOwnerV1 | null = null;
    try {
      if (!this.isStrictVerification()) {
        throw new Error('staged DPF provider admission requires strict verification');
      }
      if (this.isStrictVerification() && this.config.useSecureChannel === false) {
        throw new Error('strict verification requires the secure channel');
      }
      const url = serverIndex === 0 ? this.config.server0Url : this.config.server1Url;
      if (!url.trim()) throw new Error(`DPF server ${serverIndex} is not configured`);
      this.operatorPinForLeg(serverIndex);
      const peerIndex = serverIndex === 0 ? 1 : 0;
      if (this.legDisconnects[peerIndex]) {
        throw new Error(`DPF server ${peerIndex} disconnect is still in flight`);
      }
      if (this.legOwners[peerIndex] && !this.strictLegReady[peerIndex]) {
        throw new Error(`DPF server ${peerIndex} connect is still in flight`);
      }
      if (this.strictLegReady[peerIndex] || this.wasmClient?.isServerConnected(peerIndex)) {
        this.assertIndependentOperatorPins();
      }
      const diagnostic = this.diagnosticSocket(serverIndex);
      const client = this.ensureStagedWasmClient();
      owner = {
        generation: ++this.legGenerations[serverIndex],
        client,
        diagnostic,
        url,
        configSignature: this.legConfigSignature(serverIndex),
      };
      this.legOwners[serverIndex] = owner;
      await diagnostic.connect();
      try {
        this.assertLegOwner(serverIndex, owner);
      } catch (error) {
        // ManagedWebSocket cannot cancel a socket whose `open` event has not
        // fired yet. Close a late-opened socket before propagating the stale
        // owner failure; disconnectLeg() replaces this leg's diagnostic
        // object, so this cannot close a newer attempt.
        diagnostic.disconnect();
        throw error;
      }
      await client.connectServer(serverIndex);
      this.assertLegOwner(serverIndex, owner);
      if (this.config.useSecureChannel !== false) {
        await this.attestAndUpgradeLeg(serverIndex, owner);
        this.assertLegOwner(serverIndex, owner);
      }
      if (this.isStrictVerification()) this.assertStrictLegReady(serverIndex);

      const catalogHandle = await client.fetchCatalogFromServer(serverIndex);
      let stagedCatalog: DatabaseCatalog;
      try {
        this.assertLegOwner(serverIndex, owner);
        // The native call rejects before returning this handle unless every
        // first-leg db_id has matching kind/height/query geometry/seeds,
        // anchor and Merkle capability on this independently selected leg.
        stagedCatalog = databaseCatalogFromWasmJson(catalogHandle.toJson());
      } finally {
        catalogHandle.free();
      }
      this.assertLegOwner(serverIndex, owner);
      this.catalog ??= stagedCatalog;
      if (this.isStrictVerification()) this.assertPinsCoverCatalog();
      const installedProofs = await this.verifyConfiguredDatabaseProofsForLeg(
        serverIndex,
        () => this.assertLegOwner(serverIndex, owner!),
      );
      this.assertLegOwner(serverIndex, owner);
      this.installedProofsByLeg[serverIndex] = installedProofs;
      this.strictLegReady[serverIndex] = this.isStrictVerification();

      if (this.strictLegReady[0] && this.strictLegReady[1]) {
        this.assertIndependentOperatorPins();
        this.assertStrictTransportReady();
        this.assertLegProofsMatch();
        this.secureChannelEstablished = this.secureChannelLegs.every(Boolean);
        this.pairGeneration += 1;
        this.pairConsistencyReady = true;
        this.pairPreflightState = 'pending';
        this.pairPreflightPromise = null;
        this.pairPreflightDbId = null;
        this.admissionDbId = null;
        const pairGeneration = this.pairGeneration;
        try {
          const serverInfo = await fetchServerInfoJson(this.ws0 ?? diagnostic);
          this.assertCurrentStrictPair(client, pairGeneration);
          this.serverInfo = serverInfo;
        } catch (error) {
          // Diagnostics remain optional, but a peer disconnect/replacement
          // during the await must invalidate this pair completion.
          this.assertCurrentStrictPair(client, pairGeneration);
          this.log(`Server diagnostics unavailable: ${(error as Error)?.message ?? error}`, 'info');
        }
      }
    } catch (error) {
      this.log(
        `DPF server ${serverIndex} connect failed: ${(error as Error)?.message ?? error}`,
        'error',
      );
      if (owner && this.legOwners[serverIndex] === owner) {
        await this.disconnectLeg(serverIndex).catch(() => { /* preserve primary failure */ });
      }
      throw error;
    }
  }

  /** Close one provider only; an authorized peer leg remains untouched. */
  async disconnectLeg(serverIndex: 0 | 1): Promise<void> {
    const existing = this.legDisconnects[serverIndex];
    if (existing) return existing;
    const operation = this.disconnectLegOwned(serverIndex);
    this.legDisconnects[serverIndex] = operation;
    try {
      await operation;
    } finally {
      if (this.legDisconnects[serverIndex] === operation) {
        this.legDisconnects[serverIndex] = null;
      }
    }
  }

  private async disconnectLegOwned(serverIndex: 0 | 1): Promise<void> {
    const generation = ++this.legGenerations[serverIndex];
    const configSignature = this.legConfigSignature(serverIndex);
    this.legOwners[serverIndex] = null;
    this.connected = false;
    this.strictReady = false;
    this.secureChannelEstablished = false;
    this.pairGeneration += 1;
    this.pairConsistencyReady = false;
    this.pairPreflightState = 'not-ready';
    this.pairPreflightPromise = null;
    this.pairPreflightDbId = null;
    this.admissionDbId = null;
    this.secureChannelLegs[serverIndex] = false;
    this.strictLegReady[serverIndex] = false;
    this.installedProofsByLeg[serverIndex] = null;
    if (serverIndex === 0) {
      const diagnostic = this.ws0;
      this.ws0 = null;
      diagnostic?.disconnect();
      this.attestation.server0 = { state: 'unattested' };
      this.operatorIdentity.server0 = { state: 'not-checked' };
    } else {
      const diagnostic = this.ws1;
      this.ws1 = null;
      diagnostic?.disconnect();
      this.attestation.server1 = { state: 'unattested' };
      this.operatorIdentity.server1 = { state: 'not-checked' };
    }
    let hasSurvivingLeg = false;
    const client = this.wasmClient;
    if (client) {
      await client.disconnectServer(serverIndex);
      this.assertLegDisconnectedOwner(serverIndex, generation, client, configSignature);
      hasSurvivingLeg = client.isServerConnected(serverIndex === 0 ? 1 : 0);
    }
    if (!hasSurvivingLeg) {
      // The native client invalidates these bindings when its final transport
      // closes. Mirror that boundary in the adapter so a later staged attempt
      // cannot render or select against a stale catalog/proof snapshot.
      this.catalog = null;
      this.serverInfo = null;
      this.databaseProofs.clear();
      this.secureChannelLegs = [false, false];
      this.strictLegReady = [false, false];
      this.installedProofsByLeg = [null, null];
    }
  }

  isLegReady(serverIndex: 0 | 1): boolean {
    return this.strictLegReady[serverIndex];
  }

  /**
   * Authenticate the selected database tree-tops after both independently
   * pinned provider legs agree on the proof, but before capability acquisition
   * or authorization. Query and authorization methods remain fail closed until
   * this one-shot gate succeeds.
   */
  async prepareStrictAdmission(dbId: number): Promise<void> {
    if (!Number.isInteger(dbId) || dbId < 0 || dbId > 255) {
      throw new Error('DPF pre-authorization preflight requires an exact u8 db_id');
    }
    if (!this.pairConsistencyReady
        || !this.strictLegReady.every(Boolean)
        || !this.secureChannelLegs.every(Boolean)
        || !this.wasmClient) {
      throw new Error('DPF pair consistency is not ready for pre-authorization preflight');
    }
    if (this.pairPreflightState === 'complete') {
      if (this.admissionDbId !== dbId) {
        throw new Error(`DPF admission is already prepared for db_id ${this.admissionDbId}`);
      }
      return;
    }
    if (this.pairPreflightState === 'failed') {
      throw new Error('DPF pre-authorization preflight already failed; retry is disabled');
    }
    if (this.pairPreflightState === 'in-flight') {
      if (this.pairPreflightDbId !== dbId) {
        throw new Error(`DPF preflight is already in flight for db_id ${this.pairPreflightDbId}`);
      }
      const client = this.wasmClient;
      const generation = this.pairGeneration;
      await this.pairPreflightPromise;
      this.assertCurrentStrictPair(client, generation);
      if (!this.isPairPreflightComplete()) {
        throw new Error('DPF pre-authorization preflight was invalidated while in flight');
      }
      return;
    }

    const client = this.wasmClient;
    const generation = this.pairGeneration;
    this.assertCurrentStrictPair(client, generation);
    const installed = this.installedProofsByLeg[0]?.find((item) => item.pin.dbId === dbId);
    if (!installed || !this.installedProofsByLeg[1]?.some((item) => item.pin.dbId === dbId)) {
      throw new Error(`DPF pair has no matching installed proof for db_id ${dbId}`);
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
        throw new Error('DPF pre-authorization preflight was invalidated while in flight');
      }
      this.pairPreflightState = 'complete';
      this.admissionDbId = dbId;
      this.strictReady = true;
      this.connected = true;
      this.setState('connected');
    } catch (error) {
      if (this.pairGeneration === generation && this.wasmClient === client) {
        this.pairPreflightState = 'failed';
        this.strictReady = false;
        this.connected = false;
      }
      throw error;
    }
  }

  private ensureStagedWasmClient(): WasmDpfClient {
    if (this.wasmClient) return this.wasmClient;
    const generation = ++this.sessionGeneration;
    const sdk = requireSdkWasm();
    const client = new sdk.WasmDpfClient(this.config.server0Url, this.config.server1Url);
    this.wasmClient = client;
    client.setRequireVerifiedDatabaseRoots(this.isStrictVerification());
    client.onStateChange((state: string) => {
      if (generation !== this.sessionGeneration || this.wasmClient !== client) return;
      if (state === 'disconnected' && !this.strictLegReady[0] && !this.strictLegReady[1]) {
        this.setState('disconnected');
      }
    });
    return client;
  }

  private operatorPinForLeg(serverIndex: 0 | 1): Uint8Array {
    const configured = serverIndex === 0
      ? this.config.pinnedOperatorPubkey0
      : this.config.pinnedOperatorPubkey1;
    return exactOperatorPinV1(
      `DPF server ${serverIndex} operator pin`,
      configured ?? (this.isStrictVerification()
        ? undefined
        : this.config.pinnedOperatorPubkey ?? PIR_OPERATOR_PUBKEY),
    );
  }

  private assertIndependentOperatorPins(): readonly [Uint8Array, Uint8Array] {
    return assertIndependentOperatorPinsV1({
      first: this.config.pinnedOperatorPubkey0,
      second: this.config.pinnedOperatorPubkey1,
    });
  }

  private legConfigSignature(serverIndex: 0 | 1): string {
    const pin = serverIndex === 0
      ? this.config.pinnedOperatorPubkey0
      : this.config.pinnedOperatorPubkey1;
    return JSON.stringify({
      url: serverIndex === 0 ? this.config.server0Url : this.config.server1Url,
      expectedPin: serverIndex === 0
        ? this.config.expectedServer0Pin
        : this.config.expectedServer1Pin,
      expectedServerId: serverIndex === 0
        ? this.config.expectedServer0Id
        : this.config.expectedServer1Id,
      operatorPin: pin instanceof Uint8Array ? bytesToHex(pin) : null,
      databaseProofPins: this.config.databaseProofPins ?? [],
    });
  }

  private assertLegOwner(serverIndex: 0 | 1, owner: DpfLegOwnerV1): void {
    const currentDiagnostic = serverIndex === 0 ? this.ws0 : this.ws1;
    if (this.legGenerations[serverIndex] !== owner.generation
        || this.legOwners[serverIndex] !== owner
        || this.wasmClient !== owner.client
        || currentDiagnostic !== owner.diagnostic
        || (serverIndex === 0 ? this.config.server0Url : this.config.server1Url) !== owner.url
        || this.legConfigSignature(serverIndex) !== owner.configSignature) {
      throw new Error(`DPF server ${serverIndex} connection attempt was invalidated`);
    }
  }

  private assertLegDisconnectedOwner(
    serverIndex: 0 | 1,
    generation: number,
    client: WasmDpfClient,
    configSignature: string,
  ): void {
    if (this.legGenerations[serverIndex] !== generation
        || this.legOwners[serverIndex] !== null
        || this.wasmClient !== client
        || this.legConfigSignature(serverIndex) !== configSignature) {
      throw new Error(`DPF server ${serverIndex} disconnect was invalidated`);
    }
  }

  private assertCurrentStrictPair(client: WasmDpfClient, generation: number): void {
    if (this.pairGeneration !== generation
        || this.wasmClient !== client
        || !this.pairConsistencyReady
        || !this.strictLegReady.every(Boolean)
        || !this.secureChannelLegs.every(Boolean)) {
      throw new Error('DPF strict pair attempt was invalidated');
    }
    const first = this.legOwners[0];
    const second = this.legOwners[1];
    if (!first || !second) throw new Error('DPF strict pair has no current leg owners');
    this.assertLegOwner(0, first);
    this.assertLegOwner(1, second);
    this.assertIndependentOperatorPins();
    this.assertStrictTransportReady();
    this.assertLegProofsMatch();
  }

  private newDiagnosticSocket(serverIndex: 0 | 1): ManagedWebSocket {
    return new ManagedWebSocket({
      url: serverIndex === 0 ? this.config.server0Url : this.config.server1Url,
      label: `DPF server${serverIndex}`,
      onLog: this.config.onLog,
    });
  }

  private diagnosticSocket(serverIndex: 0 | 1): ManagedWebSocket {
    const existing = serverIndex === 0 ? this.ws0 : this.ws1;
    if (existing) return existing;
    const created = this.newDiagnosticSocket(serverIndex);
    if (serverIndex === 0) this.ws0 = created;
    else this.ws1 = created;
    return created;
  }

  // ── Connection lifecycle ──────────────────────────────────────────────

  async connect(): Promise<void> {
    const generation = ++this.sessionGeneration;
    this.setState('connecting');
    try {
      this.resetVerificationState();
      if (this.isStrictVerification() && this.config.useSecureChannel === false) {
        throw new Error('strict verification requires the secure channel');
      }

      // Side-channels first — these carry small diagnostic frames, so
      // they're useful even before the PIR client comes up.
      const ws0 = this.diagnosticSocket(0);
      const ws1 = this.diagnosticSocket(1);
      await Promise.all([ws0.connect(), ws1.connect()]);

      // Construct + wire the WASM client. `onStateChange` replays the
      // native-side transitions; we remap the plain-string payload onto
      // the web `ConnectionState` enum.
      const sdk = requireSdkWasm();
      const client = new sdk.WasmDpfClient(
        this.config.server0Url,
        this.config.server1Url,
      );
      this.wasmClient = client;
      client.setRequireVerifiedDatabaseRoots(this.isStrictVerification());
      client.onStateChange((state: string) => {
        if (generation !== this.sessionGeneration || this.wasmClient !== client) return;
        if (
          state === 'connected'
          || state === 'disconnected'
          || state === 'connecting'
          || state === 'reconnecting'
        ) {
          if (state === 'connected' && this.isStrictVerification() && !this.strictReady) {
            return;
          }
          this.setState(state);
        }
      });

      await this.wasmClient.connect();

      // Optionally attest both servers and upgrade to the encrypted
      // channel BEFORE fetching the catalog (so the catalog request
      // itself goes through the channel — first frame cloudflared sees
      // is the handshake, everything after is ciphertext).
      if (this.config.useSecureChannel !== false) {
        await this.attestAndUpgrade();
      }
      if (this.isStrictVerification()) {
        this.assertStrictTransportReady();
      }

      // This post-upgrade native catalog is canonical for both native query
      // routing and TypeScript sync planning. The clear diagnostic socket can
      // no longer remove a delta step or disable Merkle verification.
      const catalogHandle = await this.wasmClient.fetchCatalog();
      try {
        this.catalog = databaseCatalogFromWasmJson(catalogHandle.toJson());
      } finally {
        catalogHandle.free();
      }
      if (this.isStrictVerification()) {
        this.assertPinsCoverCatalog();
      }
      await this.verifyConfiguredDatabaseProofs();
      this.strictReady = this.isStrictVerification();
      this.strictLegReady = [this.strictReady, this.strictReady];
      this.pairGeneration += 1;
      this.pairConsistencyReady = this.strictReady;
      this.pairPreflightState = this.strictReady ? 'complete' : 'not-ready';
      this.pairPreflightDbId = null;
      this.admissionDbId = null;
      // Best-effort diagnostics only. Failure here cannot replace or weaken
      // the post-channel catalog/proof/tree-top trust gate above.
      try {
        this.serverInfo = await fetchServerInfoJson(ws0);
      } catch (error) {
        this.log(`Server diagnostics unavailable: ${(error as Error)?.message ?? error}`, 'info');
      }
      this.connected = true;
      // Emit a final `connected` in case the native client's own
      // `onStateChange` fired before we registered the listener or got
      // coalesced out.
      this.setState('connected');
    } catch (e) {
      this.log(`Connect failed: ${(e as Error)?.message ?? e}`, 'error');
      // Await teardown so the WASM client is fully freed before we rethrow,
      // but swallow any teardown failure — the original connect error `e` is
      // what the caller needs to see, not a secondary cleanup error.
      await this.teardown().catch(() => { /* swallow */ });
      this.setState('disconnected', (e as Error)?.message);
      throw e;
    }
  }

  disconnect(): void {
    // `teardown()` is async (it awaits the WASM client's `disconnect()`
    // before `free()` to avoid a wasm-bindgen borrow race). Existing
    // callers invoke this fire-and-forget; the synchronous prefix of
    // `teardown()` (socket close + handle null-out) has already run by the
    // time this returns, so the observable "disconnected" effect is
    // immediate. The async tail (WS close frame + `free()`) finishes on its
    // own; swallow any rejection so it can't surface as an unhandled one.
    void this.teardown().catch(() => { /* swallow */ });
    this.setState('disconnected');
  }

  /**
   * `true` iff every piece of the stack is up:
   *   * both side-channel sockets are open,
   *   * the WASM client holds live transport sockets.
   */
  isConnected(): boolean {
    return (
      this.connected
      && !!this.ws0?.isOpen()
      && !!this.ws1?.isOpen()
      && !!this.wasmClient?.isConnected
      && (!this.isStrictVerification() || this.strictReady)
    );
  }

  // ── Catalog accessors ─────────────────────────────────────────────────

  getCatalog(): DatabaseCatalog | null {
    return this.catalog;
  }

  getCatalogEntry(dbId: number): DatabaseCatalogEntry | undefined {
    return this.catalog?.databases.find((d) => d.dbId === dbId);
  }

  getDatabaseProofStatus(dbId: number): DatabaseProofStatus | undefined {
    return this.databaseProofs.get(dbId);
  }

  /**
   * Build an independent admission port for exactly one DPF provider. The
   * caller creates one `ProviderAdmissionSessionV1` per server; no peer ID or
   * shared capability crosses either connection.
   */
  serviceAdmissionPort(serverIndex: 0 | 1, dbId: number): ServiceAdmissionPortV1 {
    const client = (): WasmDpfClient => {
      if (!this.wasmClient) throw new Error('Not connected');
      if (!this.isStrictVerification() || !this.strictLegReady[serverIndex]) {
        throw new Error(`V1 service admission requires strict verification of server ${serverIndex}`);
      }
      return this.wasmClient;
    };
    const authorizedClient = (): WasmDpfClient => {
      const current = client();
      if (!this.isPreparedAdmissionDb(dbId)) {
        throw new Error(
          `DPF capability use requires prepared strict admission for db_id ${dbId}`,
        );
      }
      return current;
    };
    return {
      assertTrustAnchor: (trust) => {
        client();
        assertLiveOperatorIdentityV1(
          trust,
          serverIndex === 0 ? this.operatorIdentity.server0 : this.operatorIdentity.server1,
        );
      },
      fetchPolicy: (providerId, policyKey, nowUnix, checkpoint) =>
        client().fetchServicePolicy(
          serverIndex,
          dbId,
          providerId,
          policyKey,
          nowUnix,
          checkpoint,
        ),
      fetchRetainedRedemption: (
        providerId, policyKey, policyDigest, scopeId, offerId, nowUnix,
      ) => client().fetchRetainedServiceRedemption(
        serverIndex,
        dbId,
        providerId,
        policyKey,
        policyDigest,
        scopeId,
        offerId,
        nowUnix,
      ),
      assertSessionBinding: (policy) =>
        authorizedClient().verifyServicePolicySession(serverIndex, policy),
      assertRetainedSessionBinding: (policy, nowUnix) =>
        authorizedClient().verifyRetainedServiceSession(serverIndex, policy, nowUnix),
      authorize: (policy, scopeId, offerId, proof) =>
        authorizedClient().authorizeService(serverIndex, dbId, policy, scopeId, offerId, proof),
      authorizeRetained: (policy, proof, nowUnix) =>
        authorizedClient().authorizeRetainedService(
          serverIndex, dbId, policy, proof, nowUnix,
        ),
      requestPowChallenge: (policy, scopeId, offerId, nowUnix) =>
        authorizedClient().requestServicePowChallenge(
          serverIndex,
          dbId,
          policy,
          scopeId,
          offerId,
          nowUnix,
        ),
    };
  }

  // ── Merkle accessors ─────────────────────────────────────────────────

  hasMerkle(): boolean {
    return this.catalog?.databases.some((db) => db.hasBucketMerkle) ?? false;
  }

  hasMerkleForDb(dbId: number): boolean {
    return this.getCatalogEntry(dbId)?.hasBucketMerkle ?? false;
  }

  getMerkleRootHex(): string | undefined {
    return this.getMerkleRootHexForDb(0);
  }

  getMerkleRootHexForDb(dbId: number): string | undefined {
    const proofRoot = this.databaseProofs.get(dbId)?.proof?.bucketSuperRootHex;
    if (proofRoot) return proofRoot;
    // In advisory mode the server-info root remains useful diagnostics. It is
    // never treated as a trust root by strict sessions.
    if (this.isStrictVerification()) return undefined;
    return this.getMerkleInfoForDb(dbId)?.super_root;
  }

  private getMerkleInfoForDb(dbId: number): BucketMerkleInfoJson | undefined {
    // Main DB (db_id = 0) lives at the top level; non-zero DBs are under
    // the `databases` array. Mirrors the legacy `BatchPirClient` lookup.
    if (dbId === 0 && this.serverInfo?.merkle_bucket) {
      return this.serverInfo.merkle_bucket;
    }
    return this.serverInfo?.databases?.find((d) => d.db_id === dbId)?.merkle_bucket;
  }

  // ── Query paths ───────────────────────────────────────────────────────

  /**
   * Full-snapshot batch query. `scriptHashes` is an array of 20-byte
   * HASH160 outputs (as `Uint8Array`). Returns an array of the same
   * length, each slot either a `QueryResult` or `null` ("not found and
   * nothing to verify").
   *
   * The `onProgress` callback fires for step transitions only — the WASM
   * client doesn't yet expose fine-grained per-batch progress, so the
   * step names are coarser than in the pre-Session-3 client. This is an
   * accepted regression.
   */
  async queryBatch(
    scriptHashes: Uint8Array[],
    onProgress?: (step: string, detail: string) => void,
    dbId: number = 0,
  ): Promise<(QueryResult | null)[]> {
    return this.queryBatchInternal(scriptHashes, dbId, onProgress);
  }

  /**
   * Delta-database batch query. Same shape as `queryBatch` but every
   * non-null result carries `rawChunkData` — the encoded delta payload
   * that `sync-merge.ts::applyDeltaData` consumes to apply changes on
   * top of a cached snapshot.
   */
  async queryDelta(
    scriptHashes: Uint8Array[],
    dbId: number = 1,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    return this.queryBatchInternal(scriptHashes, dbId, onProgress);
  }

  private async queryBatchInternal(
    scriptHashes: Uint8Array[],
    dbId: number,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    if (!this.wasmClient) throw new Error('Not connected');
    if (this.isStrictVerification() && !this.strictReady) {
      throw new Error('strict verification is not ready');
    }
    if (this.isStrictVerification()
        && this.pairPreflightDbId !== null
        && this.admissionDbId !== dbId) {
      throw new Error(
        `strict DPF admission is bound to db_id ${this.admissionDbId}, not db_id ${dbId}`,
      );
    }
    onProgress?.('Level 1', 'sending batched INDEX queries');

    const packed = packScriptHashes(scriptHashes);
    const wqrs = await this.wasmClient.queryBatchRaw(packed, dbId);
    onProgress?.('Decode', `translating ${wqrs.length} results`);

    const out: (QueryResult | null)[] = new Array(wqrs.length);
    for (let i = 0; i < wqrs.length; i++) {
      const wqr = wqrs[i];
      const qr = translateWasmResult(wqr);
      this.wasmHandles.set(qr, wqr);
      // The legacy BatchPirClient surfaced pure "not found" queries as
      // `null`. Preserve that contract for callers that do
      // `if (result) found++`. Queries that probed INDEX bins but found
      // no entries still carry verifiable absence-proof state, so we
      // keep the `QueryResult` for those — the UI filters with
      // `r && !r.isWhale && r.indexPbcGroup !== undefined` downstream.
      const hasInspectorState =
        (qr.allIndexBins?.length ?? 0) > 0 || qr.isWhale || qr.entries.length > 0;
      out[i] = hasInspectorState ? qr : null;
    }
    return out;
  }

  /**
   * Batch-verify per-bucket bin Merkle proofs for one or more
   * inspector-populated `QueryResult`s. `dbId` selects which database's
   * Merkle roots to verify against (0 = main, 1+ = delta).
   *
   * Each `QueryResult` is serialised to JSON via the stashed
   * `WasmQueryResult.toJson()` (or, for results that came from
   * elsewhere, via a manual `queryResultToJson` reconstruction) and
   * handed to `WasmDpfClient.verifyMerkleBatch`. The native verifier
   * drives the K-padded sibling-query rounds, parses the tree-tops
   * blob, walks every proof, and returns a `boolean[]` of verdicts.
   */
  async verifyMerkleBatch(
    results: QueryResult[],
    onProgress?: (step: string, detail: string) => void,
    dbId: number = 0,
  ): Promise<boolean[]> {
    if (!this.wasmClient) throw new Error('Not connected');
    if (results.length === 0
        || results.some((result) => !result.allIndexBins || result.allIndexBins.length === 0)) {
      throw new Error('strict DPF inclusion verification requires an INDEX trace for every result');
    }
    if (this.isStrictVerification()
        && this.pairPreflightDbId !== null
        && this.admissionDbId !== dbId) {
      throw new Error(
        `strict DPF Merkle verification is bound to db_id ${this.admissionDbId}, not db_id ${dbId}`,
      );
    }
    onProgress?.('Merkle', `verifying ${results.length} items`);

    const jsonArr: any[] = results.map((r) => {
      const handle = this.wasmHandles.get(r);
      if (handle) return handle.toJson();
      return queryResultToJson(r);
    });

    const verdicts = await this.wasmClient.verifyMerkleBatch(jsonArr, dbId);
    if (verdicts.length !== results.length) {
      for (const result of results) scrubUnverifiedDpfResult(result);
      throw new Error(
        `DPF inclusion verifier returned ${verdicts.length} verdicts for ${results.length} results`,
      );
    }
    for (let index = 0; index < results.length; index++) {
      results[index].merkleVerified = verdicts[index] === true;
      if (verdicts[index] !== true) scrubUnverifiedDpfResult(results[index]);
    }
    const passed = verdicts.filter(Boolean).length;
    onProgress?.('Merkle', `done (${passed}/${verdicts.length} passed)`);
    return verdicts;
  }

  // ── Internal ──────────────────────────────────────────────────────────

  private async teardown(): Promise<void> {
    ++this.sessionGeneration;
    this.legGenerations = [this.legGenerations[0] + 1, this.legGenerations[1] + 1];
    this.legOwners = [null, null];
    this.strictReady = false;
    this.secureChannelEstablished = false;
    this.pairGeneration += 1;
    this.secureChannelLegs = [false, false];
    this.strictLegReady = [false, false];
    this.installedProofsByLeg = [null, null];
    this.pairConsistencyReady = false;
    this.pairPreflightState = 'not-ready';
    this.pairPreflightPromise = null;
    this.pairPreflightDbId = null;
    this.admissionDbId = null;
    this.connected = false;
    this.catalog = null;
    this.serverInfo = null;
    this.databaseProofs.clear();
    const ws0 = this.ws0;
    const ws1 = this.ws1;
    this.ws0 = null;
    this.ws1 = null;
    ws0?.disconnect();
    ws1?.disconnect();
    const client = this.wasmClient;
    if (client) {
      // Null the handle first so a concurrent teardown can't double-free.
      this.wasmClient = null;
      // `disconnect()` is a wasm-bindgen `async fn(&mut self)` — it holds
      // the Rust borrow until its promise resolves. We MUST await it before
      // `free()` (which takes ownership); calling `free()` while the borrow
      // is live throws "attempted to take ownership of Rust value while it
      // was borrowed". Awaiting also lets the WS close frame go out, which
      // `Drop`'s `detach_ws_handlers` alone would not send.
      try {
        await client.disconnect();
      } catch {
        /* already closed / mid-flight — proceed to free regardless */
      }
      client.free();
    }
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
              'success',
            );
          } else if (status.state === 'unavailable') {
            this.log(`DB proof db ${dbId}: unavailable (${status.error})`, 'info');
          } else {
            this.log(
              `DB proof db ${dbId}: unverified (${status.mismatches?.[0] ?? status.error ?? 'check failed'})`,
              'error',
            );
          }
        },
      });
    } catch (error) {
      if (this.isStrictVerification()) throw error;
      this.log(
        `Advisory database verification did not complete: ${(error as Error)?.message ?? error}`,
        'info',
      );
    }
  }

  private async verifyConfiguredDatabaseProofsForLeg(
    serverIndex: 0 | 1,
    assertCurrent: () => void,
  ): Promise<InstalledDatabaseProof[]> {
    if (!this.wasmClient) throw new Error('Not connected');
    const client = this.wasmClient;
    const pins = this.config.databaseProofPins ?? [];
    return verifyAndInstallDatabaseProofs({
      client: {
        verifyDatabaseProof: (dbId, params, binary, commit) =>
          client.verifyDatabaseProofFromServer(serverIndex, dbId, params, binary, commit),
        installVerifiedDatabaseProof: (proof) => client.installVerifiedDatabaseProof(proof),
        preflightDatabase: (dbId) => client.preflightDatabase(dbId),
      },
      pins,
      onStatus: (dbId, status) => this.recordDatabaseProofStatus(dbId, status),
      assertCurrent,
    });
  }

  private recordDatabaseProofStatus(dbId: number, status: DatabaseProofStatus): void {
    this.databaseProofs.set(dbId, status);
    this.config.onDatabaseProof?.(dbId, status);
    if (status.state === 'verified') {
      this.log(
        `DB proof db ${dbId}: verified MuHash ${status.proof?.muhashHex.slice(0, 16)}...`,
        'success',
      );
    } else if (status.state === 'unavailable') {
      this.log(`DB proof db ${dbId}: unavailable (${status.error})`, 'info');
    } else {
      this.log(
        `DB proof db ${dbId}: unverified (${status.mismatches?.[0] ?? status.error ?? 'check failed'})`,
        'error',
      );
    }
  }

  private assertLegProofsMatch(): void {
    const first = this.installedProofsByLeg[0];
    const second = this.installedProofsByLeg[1];
    if (!first || !second || first.length !== second.length) {
      throw new Error('strict DPF providers did not authenticate the same database proof set');
    }
    for (let index = 0; index < first.length; index += 1) {
      if (JSON.stringify(first[index].proof) !== JSON.stringify(second[index].proof)) {
        throw new Error(
          `strict DPF provider database proof mismatch for db ${first[index].pin.dbId}`,
        );
      }
    }
  }

  private isStrictVerification(): boolean {
    return this.config.strictVerification === true;
  }

  private isPairPreflightComplete(): boolean {
    return this.pairPreflightState === 'complete';
  }

  /** Staged admission binds one exact database. The legacy all-at-once path
   * preflights every pinned database, so retain compatibility only for roots
   * whose verified status was actually published by that completed gate. */
  private isPreparedAdmissionDb(dbId: number): boolean {
    if (!this.strictReady || !this.isPairPreflightComplete()) return false;
    if (this.admissionDbId !== null) return this.admissionDbId === dbId;
    return this.pairPreflightDbId === null
      && this.databaseProofs.get(dbId)?.state === 'verified';
  }

  private resetVerificationState(): void {
    this.legGenerations = [this.legGenerations[0] + 1, this.legGenerations[1] + 1];
    this.legOwners = [null, null];
    this.connected = false;
    this.strictReady = false;
    this.secureChannelEstablished = false;
    this.pairGeneration += 1;
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
      server0: { state: 'unattested' },
      server1: { state: 'unattested' },
    };
    this.operatorIdentity = {
      server0: { state: 'not-checked' },
      server1: { state: 'not-checked' },
    };
  }

  private assertPinsCoverCatalog(): void {
    if (!this.catalog) throw new Error('strict verification requires a database catalog');
    assertStrictDatabasePinCoverage(
      this.catalog.databases.map((db) => db.dbId),
      this.config.databaseProofPins ?? [],
    );
  }

  private assertStrictTransportReady(): void {
    assertStrictTransportReady({
      // Staged upgrades complete one leg at a time; the aggregate compatibility
      // flag is committed only after the final proof/tree-top gate succeeds.
      secureChannelEstablished: this.secureChannelLegs.every(Boolean),
      attestations: [this.attestation.server0, this.attestation.server1],
      expectedPins: [this.config.expectedServer0Pin, this.config.expectedServer1Pin],
      expectedServerIds: [this.config.expectedServer0Id, this.config.expectedServer1Id],
      requireOperatorIdentity: this.config.verifyOperatorIdentity === true,
      operatorIdentities: [this.operatorIdentity.server0, this.operatorIdentity.server1],
      operatorPins: [this.config.pinnedOperatorPubkey0, this.config.pinnedOperatorPubkey1],
    });
  }

  private assertStrictLegReady(serverIndex: 0 | 1): void {
    assertStrictServerLegReady({
      serverIndex,
      secureChannelEstablished: this.secureChannelLegs[serverIndex],
      attestation: serverIndex === 0 ? this.attestation.server0 : this.attestation.server1,
      expectedPin:
        serverIndex === 0 ? this.config.expectedServer0Pin : this.config.expectedServer1Pin,
      expectedServerId:
        serverIndex === 0 ? this.config.expectedServer0Id : this.config.expectedServer1Id,
      requireOperatorIdentity: this.config.verifyOperatorIdentity === true,
      operatorIdentity:
        serverIndex === 0 ? this.operatorIdentity.server0 : this.operatorIdentity.server1,
      operatorPin: serverIndex === 0
        ? this.config.pinnedOperatorPubkey0
        : this.config.pinnedOperatorPubkey1,
    });
  }

  private setState(state: ConnectionState, message?: string): void {
    this.config.onConnectionStateChange?.(state, message);
  }

  private log(msg: string, level: 'info' | 'success' | 'error' = 'info'): void {
    this.config.onLog?.(msg, level);
  }

  private expectedArkFingerprint(): Uint8Array | null {
    if (this.config.expectedArkFingerprint === null) return null;
    if (this.config.expectedArkFingerprint !== undefined) {
      return this.config.expectedArkFingerprint;
    }
    try {
      return getAmdTurinArkFingerprint();
    } catch (error) {
      this.log(
        `default ARK fingerprint unavailable (WASM not initialised?): ${(error as Error)?.message ?? error}`,
        'info',
      );
      return null;
    }
  }

  private summariseAttestationLeg(
    serverIndex: 0 | 1,
    attestation: WasmAttestVerification,
  ): ServerAttestation {
    const allZero = attestation.serverStaticPub.every((byte) => byte === 0);
    const matched = attestation.sevStatus === 'reportDataMatch';
    const noSev = attestation.sevStatus === 'noSevHost';
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
            this.log(
              `verifyFull(server${serverIndex}) failed: ${result.vcekChainError}`,
              'error',
            );
          }
        } else {
          result.vcekChain = 'skipped';
        }
      } else if (result.state === 'verified' && matched && !attestation.hasVcekChain) {
        result.vcekChain = 'skipped';
      }

      const pin = serverIndex === 0
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
        this.log(`server${serverIndex}: ${result.pinError}`, 'error');
      }
      return result;
    } finally {
      policyRequirements.free();
    }
  }

  private async attestAndUpgradeLeg(
    serverIndex: 0 | 1,
    owner: DpfLegOwnerV1,
  ): Promise<void> {
    const client = this.wasmClient;
    if (!client) throw new Error('WASM client not initialised');
    this.assertLegOwner(serverIndex, owner);
    this.secureChannelLegs[serverIndex] = false;
    let attestation: WasmAttestVerification | null = null;
    try {
      try {
        attestation = await client.attest(serverIndex);
        this.assertLegOwner(serverIndex, owner);
      } catch (error) {
        this.assertLegOwner(serverIndex, owner);
        const failed: ServerAttestation = { state: 'mismatch' };
        if (serverIndex === 0) this.attestation.server0 = failed;
        else this.attestation.server1 = failed;
        this.config.onAttestation?.(serverIndex, failed);
        throw new Error(
          `attest(server${serverIndex}) failed: ${(error as Error)?.message ?? error}`,
          { cause: error },
        );
      }

      let summary = this.summariseAttestationLeg(serverIndex, attestation);
      if (serverIndex === 0) this.attestation.server0 = summary;
      else this.attestation.server1 = summary;
      this.config.onAttestation?.(serverIndex, summary);
      if (summary.state !== 'verified' && summary.state !== 'verified-vcek') {
        throw new Error(`server${serverIndex} attestation did not satisfy the secure-channel gate`);
      }

      try {
        this.assertLegOwner(serverIndex, owner);
        await client.upgradeServerToSecureChannel(
          serverIndex,
          attestation.serverStaticPub,
        );
        this.assertLegOwner(serverIndex, owner);
        this.secureChannelLegs[serverIndex] = true;
      } catch (error) {
        this.assertLegOwner(serverIndex, owner);
        summary = { ...summary, state: 'mismatch' };
        if (serverIndex === 0) this.attestation.server0 = summary;
        else this.attestation.server1 = summary;
        this.config.onAttestation?.(serverIndex, summary);
        throw new Error(
          `upgradeServerToSecureChannel(server${serverIndex}) failed: ${(error as Error)?.message ?? error}`,
          { cause: error },
        );
      }

      if (this.config.verifyOperatorIdentity) {
        const configuredPin = serverIndex === 0
          ? this.config.pinnedOperatorPubkey0
          : this.config.pinnedOperatorPubkey1;
        const pin = exactOperatorPinV1(
          `server ${serverIndex} operator pin`,
          configuredPin ?? (this.isStrictVerification()
            ? undefined
            : this.config.pinnedOperatorPubkey ?? PIR_OPERATOR_PUBKEY),
        );
        this.assertLegOwner(serverIndex, owner);
        const identity = await this.verifyOperatorIdentityOne(
          serverIndex,
          attestation,
          pin,
          () => this.assertLegOwner(serverIndex, owner),
        );
        this.assertLegOwner(serverIndex, owner);
        if (serverIndex === 0) this.operatorIdentity.server0 = identity;
        else this.operatorIdentity.server1 = identity;
        this.config.onOperatorIdentity?.(serverIndex, identity);
      }
    } finally {
      attestation?.free();
    }
  }

  /**
   * Attest both servers and, if both report a valid V2 channel pubkey,
   * upgrade both connections to the encrypted channel. Called at the
   * tail of `connect()` when `useSecureChannel` is enabled (default).
   *
   * Failure modes (each leaves `attestation.serverN.state` set to a
   * descriptive value and logs but does NOT throw — the connection
   * stays alive in cleartext mode):
   *   - attest call rejects → state `'mismatch'` for that server
   *   - attest succeeds but `sevStatus !== 'reportDataMatch'` →
   *     state `'mismatch'`
   *   - attest succeeds but server reports all-zero pubkey (legacy
   *     server, no channel support) → state `'plaintext'`
   *   - both servers verified → call `upgradeToSecureChannel`; state
   *     becomes `'verified'` on each (or `'mismatch'` if the upgrade
   *     itself fails)
   */
  private async attestAndUpgrade(): Promise<void> {
    if (!this.wasmClient) return;
    this.secureChannelEstablished = false;
    this.secureChannelLegs = [false, false];
    const operatorPins = this.config.verifyOperatorIdentity
      ? resolveIndependentOperatorPinsV1({
        strictVerification: this.isStrictVerification(),
        first: this.config.pinnedOperatorPubkey0,
        second: this.config.pinnedOperatorPubkey1,
        legacyShared: this.config.pinnedOperatorPubkey,
      })
      : null;

    const attestOne = async (idx: 0 | 1): Promise<WasmAttestVerification | null> => {
      try {
        return await this.wasmClient!.attest(idx);
      } catch (e) {
        this.log(
          `attest(server${idx}) failed: ${(e as Error)?.message ?? e}`,
          'error',
        );
        return null;
      }
    };

    let att0: WasmAttestVerification | null = null;
    let att1: WasmAttestVerification | null = null;
    try {
      // Run sequentially: both attests target the same WasmDpfClient
      // instance and the underlying `&mut self` Rust API serializes them
      // anyway. Using Promise.all here can leave the second future
      // wedged on the borrow when wasm-bindgen's async glue races.
      att0 = await attestOne(0);
      att1 = await attestOne(1);

      // Default behaviour: source the ARK fingerprint from WASM
      // (`getAmdTurinArkFingerprint`), which mirrors the Rust constant
      // `pir-attest-verify::TURIN_ARK_FINGERPRINT_SHA256` and runs a
      // cross-check against `AMD_TURIN_ARK_FINGERPRINT_HEX` on first
      // call. Callers can still pass `null` explicitly to skip the
      // chain check (tests, pre-deploy debugging) or pass a different
      // fingerprint to override (e.g. for a future Milan migration —
      // they'd ship a custom Uint8Array).
      let expectedArkFp: Uint8Array | null;
      if (this.config.expectedArkFingerprint === null) {
        expectedArkFp = null;
      } else if (this.config.expectedArkFingerprint !== undefined) {
        expectedArkFp = this.config.expectedArkFingerprint;
      } else {
        try {
          expectedArkFp = getAmdTurinArkFingerprint();
        } catch (e) {
          // 'info' rather than 'error' because this is a fallback path
          // (skip chain validation) rather than an outright failure —
          // the connection still works, just without ARK pinning.
          this.log(
            `default ARK fingerprint unavailable (WASM not initialised?): ${(e as Error)?.message ?? e}`,
            'info',
          );
          expectedArkFp = null;
        }
      }

      // Strict production policy: VMPL 0, no debug, no migrate-MA, TCB-
      // monotonic. We deliberately do NOT pin MEASUREMENT here even when
      // a per-server pin is configured — the manual measurement check
      // below produces a more granular error message (which pin failed,
      // for which server) than the single-line WASM diagnostic.
      const sdk = requireSdkWasm();
      const policyReqs = new sdk.WasmPolicyRequirements();
      try {

        const summarise = (
          idx: 0 | 1,
          att: WasmAttestVerification | null,
        ): ServerAttestation => {
          if (!att) {
            return { state: 'mismatch' };
          }
          const allZero = att.serverStaticPub.every((b) => b === 0);
          const matched = att.sevStatus === 'reportDataMatch';
          const noSev = att.sevStatus === 'noSevHost';
          // For non-SEV hosts (e.g. Hetzner) we still allow the channel —
          // `noSevHost` means the binding can't be hardware-anchored but
          // the inner crypto is otherwise sound. Production `pir2` is on
          // SEV-SNP, so it should be `reportDataMatch`.
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

          // Slice D.3+: AMD VCEK chain + policy validation. Only attempt
          // when the V2 binding already passed (otherwise the report is
          // suspect anyway), the server bundled a chain, AND we have an
          // operator-pinned ARK fingerprint to anchor trust.
          //
          // `verifyFull` runs:
          //   1. ARK fingerprint match + ARK→ASK→VCEK chain (RSA-PSS)
          //   2. SEV-SNP report ECDSA-P384 signature against VCEK
          //   3. Policy: VMPL ≤ max, no debug, no migrate-MA, TCB
          //      monotonicity + optional minimum / measurement / id pins
          // — and throws on the FIRST failure. Error message starts with
          // "chain:", "report-sig:" or "policy:" so the operator can
          // tell which step rejected.
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
                  `verifyFull(server${idx}) failed: ${result.vcekChainError}`,
                  'error',
                );
                // Demote to 'mismatch' on any failure — the operator's
                // pinning explicitly demanded chain + policy validation
                // and it didn't pass. Treat as a strong negative signal.
                result.state = 'mismatch';
              }
            } else {
              result.vcekChain = 'skipped';
            }
          } else if (state === 'verified' && matched && !att.hasVcekChain) {
            result.vcekChain = 'skipped';
          }

          // Slice 3 build-time pin enforcement. Runs AFTER chain
          // validation so the pin only kicks in when the report is
          // already internally consistent. A mismatch demotes state to
          // 'mismatch' regardless of how clean the chain validation was —
          // the operator pinned a specific (UKI, binary), and the server
          // is reporting something else.
          const pin =
            idx === 0 ? this.config.expectedServer0Pin : this.config.expectedServer1Pin;
          if (pin) {
            // Only enforce when state is verified-ish AND the report is
            // internally consistent. Skipping pin check on a 'mismatch'
            // would be misleading anyway — the channel is already broken.
            const stateOk = result.state === 'verified' || result.state === 'verified-vcek';
            if (stateOk) {
              if (pin.measurementHex && !att.launchMeasurementHex) {
                result.pinStatus = 'measurement-mismatch';
                result.pinError = `MEASUREMENT pin required (${pin.measurementHex.slice(0, 16)}…) but server report omitted launch MEASUREMENT`;
                result.state = 'mismatch';
                this.log(`server${idx}: ${result.pinError}`, 'error');
              } else if (
                pin.measurementHex &&
                pin.measurementHex.toLowerCase() !== att.launchMeasurementHex!.toLowerCase()
              ) {
                result.pinStatus = 'measurement-mismatch';
                result.pinError = `MEASUREMENT pin mismatch — expected ${pin.measurementHex.slice(0, 16)}…, got ${att.launchMeasurementHex.slice(0, 16)}…`;
                result.state = 'mismatch';
                this.log(`server${idx}: ${result.pinError}`, 'error');
              } else if (
                pin.binarySha256Hex &&
                !att.binarySha256Hex
              ) {
                result.pinStatus = 'binary-mismatch';
                result.pinError = `binary_sha256 pin required (${pin.binarySha256Hex.slice(0, 16)}…) but server report omitted binary_sha256`;
                result.state = 'mismatch';
                this.log(`server${idx}: ${result.pinError}`, 'error');
              } else if (
                pin.binarySha256Hex &&
                att.binarySha256Hex &&
                pin.binarySha256Hex.toLowerCase() !== att.binarySha256Hex.toLowerCase()
              ) {
                result.pinStatus = 'binary-mismatch';
                result.pinError = `binary_sha256 pin mismatch — expected ${pin.binarySha256Hex.slice(0, 16)}…, got ${att.binarySha256Hex.slice(0, 16)}…`;
                result.state = 'mismatch';
                this.log(`server${idx}: ${result.pinError}`, 'error');
              } else {
                result.pinStatus = 'match';
              }
            }
          } else {
            result.pinStatus = 'no-pin';
          }
          return result;
        };

        const sum0 = summarise(0, att0);
        const sum1 = summarise(1, att1);
        this.attestation.server0 = sum0;
        this.attestation.server1 = sum1;
        this.config.onAttestation?.(0, sum0);
        this.config.onAttestation?.(1, sum1);

        // Only upgrade if BOTH servers cleared the channel-OK gate. A
        // half-encrypted setup gives no privacy benefit (the all-cleartext
        // server still leaks queries to cloudflared) and complicates UI.
        // Either 'verified' (V2 binding only) or 'verified-vcek' (full
        // AMD chain) qualifies — both prove the channel pubkey is bound
        // to a SEV-SNP report; the V2 binding is the gate that matters
        // for the channel itself.
        const channelReady = (s: ServerAttestation['state']) =>
          s === 'verified' || s === 'verified-vcek';
        if (channelReady(sum0.state) && channelReady(sum1.state) && att0 && att1) {
          try {
            await this.wasmClient.upgradeToSecureChannel(
              att0.serverStaticPub,
              att1.serverStaticPub,
            );
            this.secureChannelEstablished = true;
            this.secureChannelLegs = [true, true];
            this.log('Upgraded to encrypted channel (cloudflared sees only ciphertext)', 'success');
          } catch (e) {
            this.log(`upgradeToSecureChannel failed: ${(e as Error)?.message ?? e}`, 'error');
            // Mark both as mismatch since the channel didn't actually come
            // up despite the per-server attest being clean.
            this.attestation.server0 = { ...sum0, state: 'mismatch' };
            this.attestation.server1 = { ...sum1, state: 'mismatch' };
            this.config.onAttestation?.(0, this.attestation.server0);
            this.config.onAttestation?.(1, this.attestation.server1);
          }
        } else {
          this.log(
            `Channel left in cleartext (server0=${sum0.state}, server1=${sum1.state})`,
            'info',
          );
        }

        // Operator-signed identity (REQ_ANNOUNCE), opt-in. Runs after the
        // channel decision so announce() rides the encrypted channel when it
        // came up; binds against the attested serverStaticPub from `att*`.
        if (this.config.verifyOperatorIdentity) {
          const oid0 = await this.verifyOperatorIdentityOne(0, att0, operatorPins![0]);
          const oid1 = await this.verifyOperatorIdentityOne(1, att1, operatorPins![1]);
          this.operatorIdentity.server0 = oid0;
          this.operatorIdentity.server1 = oid1;
          this.config.onOperatorIdentity?.(0, oid0);
          this.config.onOperatorIdentity?.(1, oid1);
        }

      } finally {
        policyReqs.free();
      }
    } finally {
      // Callbacks, field projections, BigInt conversion, identity checks, and
      // secure-channel upgrade are all allowed to throw. Neither attestation
      // allocation may outlive this bootstrap attempt.
      try {
        att0?.free();
      } finally {
        att1?.free();
      }
    }
  }

  /**
   * Fetch + verify one server's operator-signed identity. Never throws;
   * returns an `OperatorIdentity` snapshot. `att` supplies the attested
   * `serverStaticPub` the bundle's `channel_pub` is bound against, so a
   * `null` att (attest failed) yields `state: 'error'`.
   */
  private async verifyOperatorIdentityOne(
    idx: 0 | 1,
    att: WasmAttestVerification | null,
    pin: Uint8Array,
    assertCurrent?: () => void,
  ): Promise<OperatorIdentity> {
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
        this.log(`server${idx}: operator identity not configured`, 'info');
        return { state: 'unconfigured' };
      }
      this.log(`announce(server${idx}) failed: ${msg}`, 'error');
      return { state: 'error', error: msg };
    }
    try {
      const nowSecs = BigInt(Math.floor(Date.now() / 1000));
      const maxAge = BigInt(this.config.maxAnnounceAgeSeconds ?? 0);
      const result = gateOperatorIdentity(v, pin, att.serverStaticPub, nowSecs, maxAge);
      if (result.state === 'verified') {
        this.log(`server${idx}: operator identity verified (${result.serverId})`, 'success');
      } else {
        this.log(`server${idx}: operator identity UNVERIFIED — ${result.error}`, 'error');
      }
      return result;
    } finally {
      v.free();
    }
  }
}

function scrubUnverifiedDpfResult(result: QueryResult): void {
  result.entries = [];
  result.totalSats = 0n;
  result.rawChunkData = undefined;
  result.scriptHash = undefined;
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

/**
 * Pack an `N`-entry `Uint8Array[]` of 20-byte HASH160 outputs into a
 * single `Uint8Array(20 * N)`, as expected by `WasmDpfClient.queryBatchRaw`.
 */
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
 * Translate a `WasmQueryResult` (opaque handle from
 * `WasmDpfClient.queryBatchRaw`) into the legacy `QueryResult` shape.
 *
 * The two shapes differ in:
 *   * `entries`: WASM uses `{txid: hex, vout, amountSats}`; web uses
 *     `{txid: Uint8Array, vout, amount: bigint}` (hash.ts-style).
 *   * Inspector fields: WASM keeps all probed bins in `indexBins()` +
 *     `chunkBins()` with a separate `matchedIndexIdx()`; web keeps
 *     `indexPbcGroup`/`indexBinIndex`/`indexBinContent` for the matched
 *     bin plus an `allIndexBins` array for absence proofs. We derive
 *     both by indexing `indexBins[matchedIdx]`.
 *   * `chunkBinContents`: WASM hex, web raw bytes.
 */
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
  // Primary match: prefer the explicitly matched bin, else fall back to
  // the first probed bin (legacy behaviour for not-found queries so
  // `indexPbcGroup !== undefined` still filters "verifiable" truthy).
  const primary = matchedIdx !== undefined ? allIndexBins[matchedIdx] : allIndexBins[0];

  return {
    entries,
    totalSats: wqr.totalBalance,
    // Display-only legacy fields — not read by any remaining consumer
    // for DPF results. Kept in the shape for type compatibility.
    startChunkId: 0,
    numChunks: chunkBinsRaw.length,
    numRounds: 0,
    isWhale: wqr.isWhale,
    // Native query decoding has not yet run the inclusion verifier. Never
    // inherit a transport/fixture default as a release verdict.
    merkleVerified: false,
    rawChunkData: rawChunkData instanceof Uint8Array ? rawChunkData : undefined,
    indexPbcGroup: primary?.pbcGroup,
    indexBinIndex: primary?.binIndex,
    indexBinContent: primary?.binContent,
    allIndexBins: allIndexBins.length > 0 ? allIndexBins : undefined,
    chunkPbcGroups: chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => b.pbcGroup) : undefined,
    chunkBinIndices: chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => b.binIndex) : undefined,
    chunkBinContents:
      chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => hexToBytes(b.binContent)) : undefined,
  };
}

/**
 * Rebuild a `WasmQueryResult`-compatible JSON object from a hand-crafted
 * `QueryResult` (one that doesn't have a stashed WASM handle, e.g.
 * persisted through localStorage). Matches the field-name contract that
 * `parse_query_result_json` accepts in `pir-sdk-wasm`.
 */
function queryResultToJson(r: QueryResult): any {
  const entries = r.entries.map((e) => ({
    txid: bytesToHex(e.txid),
    vout: e.vout,
    // `parse_query_result_json` reads via `as_u64()`, so we must pass a
    // number (not a bigint) in JSON. The hex / decimal representation
    // doesn't matter — `JSON.stringify` handles bigints by conversion.
    amountSats: Number(e.amount),
  }));
  const obj: any = {
    entries,
    isWhale: r.isWhale,
    merkleVerified: false,
  };
  if (r.allIndexBins && r.allIndexBins.length > 0) {
    obj.indexBins = r.allIndexBins.map((b) => ({
      pbcGroup: b.pbcGroup,
      binIndex: b.binIndex,
      binContent: bytesToHex(b.binContent),
    }));
    // Derive the matched-idx by scanning for the bin whose
    // (pbcGroup, binIndex) matches the primary-match fields. Only emit
    // when the result is an actual match — a not-found with
    // `indexPbcGroup === allIndexBins[0].pbcGroup` would otherwise be
    // miscategorised as a match.
    if (r.entries.length > 0 && r.indexPbcGroup !== undefined) {
      const idx = r.allIndexBins.findIndex(
        (b) => b.pbcGroup === r.indexPbcGroup && b.binIndex === r.indexBinIndex,
      );
      if (idx >= 0) obj.matchedIndexIdx = idx;
    }
  }
  if (r.chunkPbcGroups && r.chunkPbcGroups.length > 0) {
    obj.chunkBins = r.chunkPbcGroups.map((grp, i) => ({
      pbcGroup: grp,
      binIndex: r.chunkBinIndices?.[i] ?? 0,
      binContent: bytesToHex(r.chunkBinContents?.[i] ?? new Uint8Array()),
    }));
  }
  if (r.rawChunkData) {
    obj.rawChunkData = bytesToHex(r.rawChunkData);
  }
  return obj;
}
