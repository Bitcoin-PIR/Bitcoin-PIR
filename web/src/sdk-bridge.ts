/**
 * Loads `pir-sdk-wasm` and types the parts of its surface the web client
 * calls.
 */

// ─── WASM module type ───────────────────────────────────────────────────────

interface PirSdkWasm {
  WasmDatabaseCatalog: {
    fromJson(json: any): WasmDatabaseCatalog;
  };
  /** ARC credentials for credits (`docs/CREDITS.md`); see `sdkArcFactories`. */
  WasmArcCredentialRequest: {
    new(epoch: number): WasmArcCredentialRequest;
    fromBytes(epoch: number, secrets: Uint8Array, request: Uint8Array): WasmArcCredentialRequest;
  };
  WasmArcCredential: {
    new(credential: Uint8Array, epoch: number, presentationLimit: number, nextNonce: number): WasmArcCredential;
  };
  // Native-WASM DPF client — used by `dpf-adapter.ts` to retire the pure-TS
  // `BatchPirClient`. The class is constructed with two server URLs; its
  // `connect()` opens both WebSockets via the wasm32 transport layer in
  // `pir-sdk-client::wasm_transport`. The adapter owns padding invariants
  // (K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE) by delegating the query
  // machinery to the native `DpfClient` underneath — there is no way the
  // adapter could bypass them.
  WasmDpfClient: {
    new(server0Url: string, server1Url: string): WasmDpfClient;
  };
  // Native-WASM HarmonyPIR client — used by `harmonypir-adapter.ts` to
  // retire the pure-TS `HarmonyPirClient`. Constructed with two server
  // URLs (hint server + query server). Generates a fresh random master
  // PRP key at construction; callers that want to resume from a cached
  // hint blob must `setMasterKey(bytes)` before `loadHints(...)`. The
  // adapter owns HarmonyPIR's padding invariants (K=75 INDEX / K_CHUNK=80
  // CHUNK / 25-MERKLE) by delegating to the native `HarmonyClient`
  // underneath — the wrapper cannot bypass them.
  WasmHarmonyClient: {
    new(hintServerUrl: string, queryServerUrl: string): WasmHarmonyClient;
  };
  // Native-WASM ORAM client — single-server TEE backend. Constructed
  // with one attested query server URL. Unlike DPF/Harmony, this backend
  // does not expose PBC inspector results; it returns decoded direct-entry
  // ORAM query results from `queryBatch`.
  WasmOramClient: {
    new(serverUrl: string): WasmOramClient;
  };
  /** Same-socket attestation and encrypted framing for the standalone
   * C++/SEAL OnionPIR browser client. */
  WasmStandaloneSecureChannelV1: {
    new(): WasmStandaloneSecureChannelV1;
  };
  /**
   * Constructor for [`WasmPolicyRequirements`] used by
   * `WasmAttestVerification.verifyFull`. `new sdk.WasmPolicyRequirements()`
   * returns the strict production defaults; mutate via setters.
   */
  WasmPolicyRequirements: {
    new(): WasmPolicyRequirements;
  };
  /**
   * Verify a standalone SEV-SNP report plus PEM ARK/ASK/VCEK chain using
   * the same Rust verifier as live runtime attestation. Used for static
   * database-authenticity proof artifacts.
   */
  verifyRawSnpReport(
    reportBytes: Uint8Array,
    arkPem: string,
    askPem: string,
    vcekPem: string,
    expectedArkFingerprint: Uint8Array | null,
    policy: WasmPolicyRequirements,
  ): void;
  /**
   * Parse + verify a raw RESP_ANNOUNCE wire payload (the response frame
   * starting at the variant byte) into a `WasmAnnounceVerification`,
   * running the in-bundle chain check. Throws on a wire-format violation
   * or a server `RESP_ERROR` envelope (e.g. "announce not configured").
   *
   * For transports that don't go through `WasmDpfClient` — the
   * standalone `OnionPirWebClient` does its own REQ_ANNOUNCE round-trip
   * and hands the response bytes here, reusing the exact Rust parsing +
   * chain verification. Mirrors
   * `pir_sdk_client::announce::parse_announce_response`.
   */
  verifyAnnounceResponse(respPayload: Uint8Array): WasmAnnounceVerification;
  /** V2 proof verifier used by the standalone OnionPIR client. */
  verifyDatabaseProofV2Response(
    responseFrame: Uint8Array,
    catalog: WasmDatabaseCatalog,
    expectedDbId: number,
    expectedParamsHashHex?: string | null,
    allowedBuilderBinarySha256Hex?: string | null,
    allowedBuilderGitCommit?: string | null,
  ): WasmDatabaseProof;
}

interface WasmDatabaseCatalog {
  free(): void;
  toJson(): any;
}

/**
 * JS-visible result of a `WasmDpfClient.attest()` /
 * `WasmHarmonyClient.attest()` call. Mirrors the Rust struct
 * `pir_sdk_wasm::WasmAttestVerification`.
 *
 * Use the `serverStaticPub` getter (raw 32 bytes) as input to
 * `upgradeToSecureChannel`.
 */
export interface WasmAttestVerification {
  free(): void;
  /** 32-byte client nonce sent in REQ_ATTEST, hex-encoded. */
  readonly nonceHex: string;
  /** SEV-SNP REPORT_DATA binding status. One of:
   * `'noSevHost'` | `'reportDataMatch'` | `'reportDataMismatch'` | `'malformedReport'`. */
  readonly sevStatus: string;
  /** SHA-256 of the running `unified_server` binary, hex-encoded.
   *  Only trustworthy if `sevStatus === 'reportDataMatch'`. */
  readonly binarySha256Hex: string;
  /** Raw 32-byte X25519 channel pubkey. Pass directly to
   *  `upgradeToSecureChannel`. All-zero if the server hasn't enabled
   *  the encrypted channel yet. */
  readonly serverStaticPub: Uint8Array;
  /** Hex-encoded form of `serverStaticPub` for display / cross-check. */
  readonly serverStaticPubHex: string;
  /** Git rev baked into the running server binary. */
  readonly gitRev: string;
  /** Per-DB manifest roots in db_id order, each as 64-char hex. */
  readonly manifestRootsHex: string[];
  /** Raw signed SEV-SNP attestation report bytes (~1184 for v5).
   *  Empty if not on a SEV-SNP host. */
  readonly sevSnpReport: Uint8Array;
  /** Hex-encoded launch MEASUREMENT — the 48-byte hash AMD's PSP
   *  signs into every SEV-SNP report, covering OVMF + the loaded
   *  UKI bytes (kernel + initramfs + cmdline). Empty string when
   *  the server isn't on a SEV-SNP host. Compare against an
   *  operator-published value to detect substitution of the
   *  running stack. */
  readonly launchMeasurementHex: string;

  /** Raw PEM bytes of the AMD ARK (Root Key) cert, as bundled by
   *  the server. Empty if `--vcek-dir` wasn't configured server-
   *  side. */
  readonly arkPem: Uint8Array;
  /** Raw PEM bytes of the AMD ASK (per-family Signing Key) cert.
   *  Empty if not bundled. */
  readonly askPem: Uint8Array;
  /** Raw PEM bytes of the per-chip VCEK cert. Empty if not bundled. */
  readonly vcekPem: Uint8Array;
  /** True when all three cert PEMs are non-empty. */
  readonly hasVcekChain: boolean;

  /**
   * Verify the AMD chain (ARK fingerprint against the pin when one is
   * passed; ARK→ASK→VCEK) and the report signature, plus the policy
   * assertions captured in `policy` — VMPL ceiling,
   * `debug_allowed` / `migrate_ma_allowed` / `single_socket_required`
   * bits, TCB monotonicity (`reported_tcb ≤ committed_tcb`) + optional
   * minimum TCB, optional MEASUREMENT / family_id / image_id pins.
   *
   * Throws on the FIRST failing step. Caller can detect which step
   * failed by inspecting the error message ("chain: …", "report-sig: …",
   * "policy: …").
   */
  verifyFull(
    expectedArkFingerprint: Uint8Array | null,
    policy: WasmPolicyRequirements,
  ): void;
}

/** Opaque one-shot attestation-bound X25519/AEAD state. Secrets and sequence
 * counters remain in Rust/WASM; JS only transports canonical frames. */
export interface WasmStandaloneSecureChannelV1 {
  free(): void;
  attestRequest(): Uint8Array;
  verifyAttestation(responseFrame: Uint8Array): WasmAttestVerification;
  handshakeRequest(): Uint8Array;
  completeHandshake(responseFrame: Uint8Array, serverStaticPub: Uint8Array): void;
  sealFrame(frame: Uint8Array): Uint8Array;
  openFrame(frame: Uint8Array): Uint8Array;
}

/**
 * Policy requirements for [`WasmAttestVerification.verifyFull`].
 *
 * Constructed via `new sdk.WasmPolicyRequirements()` for strict
 * production defaults: VMPL 0, no debug, no MA migration, TCB-
 * monotonic, no pinned MEASUREMENT/family_id/image_id. Mutate via the
 * setters to relax (e.g. enabling debug for a local test rig) or to
 * pin MEASUREMENT.
 */
export interface WasmPolicyRequirements {
  free(): void;
  /** Raise the VMPL ceiling. Production wants 0. */
  setMaxVmpl(v: number): void;
  /** Permit guests with `policy.debug_allowed` set. Production: false. */
  setAllowDebug(v: boolean): void;
  /** Permit guests with `policy.migrate_ma_allowed` set. Production: false. */
  setAllowMigrateMa(v: boolean): void;
  /** Require `policy.single_socket_required`. Off by default. */
  setRequireSingleSocket(v: boolean): void;
  /** Require every SVN of `reported_tcb` to reach these values; `fmc`
   * only for generations that report one (Turin). */
  setMinTcb(bootloader: number, tee: number, snp: number, microcode: number, fmc?: number): void;
  /** Require `platform_info.alias_check_complete` (bit 5). Off by default. */
  setRequireAliasCheckComplete(v: boolean): void;
  /** Bits required in both the launch and current mitigation vector. 0 = off. */
  setRequiredMitVectorBits(bits: number): void;
  /** Pin the expected MEASUREMENT (must be exactly 48 bytes). */
  setExpectedMeasurement(bytes: Uint8Array): void;
  /** Pin the expected family_id (16 bytes). */
  setExpectedFamilyId(bytes: Uint8Array): void;
  /** Pin the expected image_id (16 bytes). */
  setExpectedImageId(bytes: Uint8Array): void;
}

/**
 * JS-visible result of a `WasmDpfClient.announce()` call. Mirrors
 * `pir_sdk_wasm::WasmAnnounceVerification`. Carries the parsed
 * operator-signed bundle; the caller layers verification:
 *   - `checkPinnedOperator(pin, now)` — operator pubkey match + cert
 *     signature + validity + in-bundle chain check (do NOT settle for a
 *     bare `operatorPubkeyHex` string-compare — it misses the signature),
 *   - `checkChannelBinding(expected)` — `channelPub` equals the attested
 *     `serverStaticPub` the channel handshook against.
 * Both throw on failure. `i64` fields surface as `bigint` (wasm-bindgen).
 */
export interface WasmAnnounceVerification {
  readonly serverId: string;
  readonly operatorPubkeyHex: string;
  readonly identityPubkeyHex: string;
  readonly channelPub: Uint8Array;
  readonly channelPubHex: string;
  readonly binarySha256Hex: string;
  readonly gitRev: string;
  readonly validFrom: bigint;
  readonly validUntil: bigint;
  readonly issuedAt: bigint;
  readonly chainVerified: boolean;
  readonly chainError: string;
  /** Operator pubkey match + `cert.verify()` signature + validity
   *  (skipped when `nowUnixSeconds === 0n`) + chain check. Throws on
   *  failure. */
  checkPinnedOperator(pinnedOperatorPubkey: Uint8Array, nowUnixSeconds: bigint): void;
  /** `channelPub === expectedChannelPub` (32 bytes). Throws on mismatch. */
  checkChannelBinding(expectedChannelPub: Uint8Array): void;
  /** Replay/staleness guard on `issuedAt`: throws if older than
   *  `maxAgeSeconds` before `now` (stale) or >300s after it (future).
   *  `issuedAt` is the server's boot time, so keep `maxAgeSeconds`
   *  generous; `0n` skips the staleness arm, `nowUnixSeconds === 0n`
   *  skips entirely. */
  checkFreshness(nowUnixSeconds: bigint, maxAgeSeconds: bigint): void;
  free(): void;
}

export interface WasmDatabaseProof {
  free(): void;
  readonly dbId: number;
  /** SHA-256 of the verified server database MANIFEST.toml bytes. */
  readonly manifestRootHex?: string;
  readonly buildKind: 'snapshot' | 'delta' | string;
  readonly fromHeight: number;
  readonly fromBlockHashHex: string;
  readonly height: number;
  readonly blockHashHex: string;
  readonly muhashHex: string;
  readonly bucketSuperRootHex: string;
  readonly onionSuperRootHex: string;
  readonly paramsHashHex: string;
  readonly networkMagicHex: string;
  readonly builderBinarySha256Hex: string;
  readonly builderGitCommit: string;
  readonly onionEntrySize: number;
  readonly proofVersion?: number;
  readonly onionTotalPackedEntries?: number;
  readonly onionIndexBinsPerTable?: number;
  readonly onionChunkBinsPerTable?: number;
  readonly onionIndexSlotsPerBin?: number;
  readonly onionIndexSlotSize?: number;
  toJson(): any;
}

export interface WasmDpfClient {
  free(): void;
  readonly isConnected: boolean;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  /** Send REQ_ATTEST to one of the connected servers (`serverIndex`
   *  ∈ {0, 1}) and return a verification result. The 32-byte nonce
   *  is generated browser-side via `crypto.getRandomValues`. Use the
   *  returned `serverStaticPub` (32 bytes) as input to
   *  `upgradeToSecureChannel`. */
  attest(serverIndex: number): Promise<WasmAttestVerification>;
  /** Send REQ_ANNOUNCE to one of the connected servers (`serverIndex`
   *  ∈ {0, 1}) and return the parsed operator-signed identity bundle.
   *  Rejects with "announce not configured" when the server was started
   *  without `--identity-*` flags. See `WasmAnnounceVerification` for the
   *  verification methods to run on the result. */
  announce(serverIndex: number): Promise<WasmAnnounceVerification>;
  /** Pay one leg's metered frames from `provider` when that server requires
   *  credits (`docs/CREDITS.md`): `provider(credits)` returns
   *  `{ kind, payload, credits }` or `null` and is called from inside query
   *  calls whenever the connection's balance runs short. Resolves to
   *  `"not-enabled"`, `"not-required"`, `"required"`, or
   *  `"best-effort"`. Call after
   *  `upgradeToSecureChannel`. */
  enableCredits(serverIndex: number, provider: (credits: number) => unknown): Promise<string>;
  /** Present an operator-issued API key on one leg (`docs/CREDITS.md`
   *  "API keys"); that connection is then unmetered. Bearer material: call
   *  after `upgradeToSecureChannel`. */
  presentApiKey(serverIndex: number, key: string): Promise<void>;
  /** Wrap both server connections with the encrypted-channel transport.
   *  Caller MUST first verify `pub0`/`pub1` came from a trustworthy
   *  source (call `attest` first, and check the SEV-SNP report's AMD
   *  VCEK chain where there is one). After this returns, every subsequent
   *  query is AEAD-sealed via `pir_channel`'s ChaCha20-Poly1305 frame
   *  layer; cloudflared sees only ciphertext.
   *
   *  Each pubkey arg must be exactly 32 bytes (rejects with a `Error`
   *  otherwise). On handshake failure both connections are dropped —
   *  call `connect` again to retry. */
  upgradeToSecureChannel(pub0: Uint8Array, pub1: Uint8Array): Promise<void>;
  /** Populate the native-side catalog so subsequent `queryBatchVerified` calls
   * can resolve `db_id`
   * against an in-memory catalog. Returns the freshly fetched catalog. */
  fetchCatalog(): Promise<WasmDatabaseCatalog>;
  /** Fetch and verify an attested-builder database proof against the
   * native catalog. Optional string policy pins may be `undefined` or empty.
   * Mainnet network magic is always enforced by the WASM method. */
  verifyDatabaseProof(
    dbId: number,
    expectedParamsHashHex?: string | null,
    allowedBuilderBinarySha256Hex?: string | null,
    allowedBuilderGitCommit?: string | null,
  ): Promise<WasmDatabaseProof>;
  /** Install the roots of a proof from `verifyDatabaseProof`; queries then
   * check the Merkle tree-tops against them. Takes ownership of `proof`. */
  installVerifiedDatabaseProof(proof: WasmDatabaseProof): void;
  /** Check this DB's Merkle tree-tops against the installed proof root. */
  preflightDatabase(dbId: number): Promise<void>;
  /** Query with inspector state: one result per input, each with the bins
   * it probed and its own `merkleVerified`. */
  queryBatchVerified(scriptHashes: Uint8Array, dbId: number): Promise<WasmQueryResult[]>;
  /** Register a JS callback for every `ConnectionState` transition; the
   * callback receives a single string (`"connecting"` / `"connected"` /
   * `"disconnected"`). Replaces any previously registered listener. */
  onStateChange(cb: (state: string) => void): void;
}

/**
 * Native-WASM HarmonyPIR client: the part of
 * `crates/sdk/wasm/src/client.rs::WasmHarmonyClient` that
 * `harmonypir-adapter.ts` uses.
 */
export interface WasmHarmonyClient {
  free(): void;
  readonly isConnected: boolean;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  /** Same as `WasmDpfClient.attest`. `serverIndex` 0 = hint server,
   *  1 = query server. */
  attest(serverIndex: number): Promise<WasmAttestVerification>;
  /** Same as `WasmDpfClient.announce`. `serverIndex` 0 = hint server,
   *  1 = query server. Rejects with "announce not configured" when the
   *  server was started without `--identity-*` flags. */
  announce(serverIndex: number): Promise<WasmAnnounceVerification>;
  /** Same as `WasmDpfClient.enableCredits`. */
  enableCredits(serverIndex: number, provider: (credits: number) => unknown): Promise<string>;
  /** Same as `WasmDpfClient.presentApiKey`. */
  presentApiKey(serverIndex: number, key: string): Promise<void>;
  /** Same as `WasmDpfClient.upgradeToSecureChannel`, with the arguments
   *  `(hintServerStaticPub, queryServerStaticPub)`. */
  upgradeToSecureChannel(hintServerStaticPub: Uint8Array, queryServerStaticPub: Uint8Array): Promise<void>;
  /** Fetch + cache the database catalog over the WASM client's
   *  internal connection. */
  fetchCatalog(): Promise<WasmDatabaseCatalog>;
  /** Same as `WasmDpfClient.verifyDatabaseProof`. */
  verifyDatabaseProof(
    dbId: number,
    expectedParamsHashHex?: string | null,
    allowedBuilderBinarySha256Hex?: string | null,
    allowedBuilderGitCommit?: string | null,
  ): Promise<WasmDatabaseProof>;
  /** Same as `WasmDpfClient.installVerifiedDatabaseProof`. */
  installVerifiedDatabaseProof(proof: WasmDatabaseProof): void;
  /** Same as `WasmDpfClient.preflightDatabase`. */
  preflightDatabase(dbId: number): Promise<void>;
  setDbId(dbId: number): void;
  /** Overwrite the random 16-byte master PRP key. Must happen before
   *  `loadCompleteHints(...)`. Throws on non-16-byte input. */
  setMasterKey(key: Uint8Array): void;
  /** Effective key bound to the current hint state. V2 hint setup may
   *  replace the key originally installed through `setMasterKey`. */
  cacheMasterKey(): Uint8Array;
  /** Effective PRP backend selected by V2 hint setup. */
  cachePrpBackend(): number;
  setPrpBackend(backend: number): void;
  /** Release-safe inspector query. Native code binds each result to the
   *  exact input order and db, then completes all Merkle checks before
   *  returning any handle. */
  queryBatchVerified(scriptHashes: Uint8Array, dbId: number): Promise<WasmQueryResult[]>;
  /** 16-byte fingerprint derived from `(masterKey, prpBackend, catalog.get(dbId))`.
   *  Embedded in `saveHints()` output; exposed here so the IndexedDB
   *  bridge can tag cache entries for debugging. */
  fingerprint(catalog: WasmDatabaseCatalog, dbId: number): Uint8Array;
  /** Serialize the currently-loaded hint state to a self-describing
   *  binary blob. Returns `null` / `undefined` when nothing is loaded. */
  saveHints(): Uint8Array | undefined | null;
  /** Restore a complete hint set from a `saveHints()` blob. The fingerprint
   *  is cross-checked against `(masterKey, prpBackend, catalog.get(dbId))`;
   *  a mismatch throws. Requires authenticated tree-tops and
   *  rejects/clears main-only or malformed sibling state. */
  loadCompleteHints(bytes: Uint8Array, catalog: WasmDatabaseCatalog, dbId: number): void;
  /** Whether the in-memory state exactly covers all main and authenticated
   *  sibling groups for this proof-verified database. */
  hasCompleteHints(catalog: WasmDatabaseCatalog, dbId: number): boolean;
  /** Minimum per-group query budget across every loaded HarmonyGroup.
   *  `undefined` when nothing is loaded. */
  minQueriesRemaining(): number | undefined;
  /** Size of the `saveHints()` blob that would be produced right now. */
  estimateHintSizeBytes(): number;
  /** Fetch all main and Merkle-sibling hints, so the set can be cached.
   *  `progress` receives `{ done, total, phase }` after each per-group
   *  response. */
  fetchCompleteHintsWithProgress(
    catalog: WasmDatabaseCatalog,
    dbId: number,
    progress: (event: { done: number; total: number; phase: string }) => void,
  ): Promise<void>;
}

/**
 * Native-WASM ORAM client. See `crates/sdk/wasm/src/client.rs::WasmOramClient`.
 *
 * This is the direct TEE backend surface: one server connection, one
 * attestation/channel upgrade, then fixed-budget server-side ORAM lookup.
 * `queryBatch` returns plain `QueryResult` JSON objects or `null`, matching
 * the decoded shape used by the DPF/Harmony high-level wrappers.
 * `queryBatchPadded` sends the same real script hashes padded with explicit
 * empty slots inside the TEE ORAM request, and returns only real results.
 */
export interface WasmOramClient {
  free(): void;
  readonly isConnected: boolean;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  attest(): Promise<WasmAttestVerification>;
  announce(): Promise<WasmAnnounceVerification>;
  /** Pay the server's metered frames from `provider` when it requires credits; see `WasmDpfClient.enableCredits`. */
  enableCredits(provider: (credits: number) => unknown): Promise<string>;
  /** Present an operator-issued API key; see `WasmDpfClient.presentApiKey`. */
  presentApiKey(key: string): Promise<void>;
  upgradeToSecureChannel(serverStaticPub: Uint8Array): Promise<void>;
  fetchCatalog(): Promise<WasmDatabaseCatalog>;
  verifyDatabaseProof(
    dbId: number,
    expectedParamsHashHex?: string | null,
    allowedBuilderBinarySha256Hex?: string | null,
    allowedBuilderGitCommit?: string | null,
  ): Promise<WasmDatabaseProof>;
  installVerifiedDatabaseProof(proof: WasmDatabaseProof): void;
  queryBatch(scriptHashes: Uint8Array, dbId: number): Promise<any[]>;
  queryBatchPadded(scriptHashes: Uint8Array, dbId: number, paddedSlots: number): Promise<any[]>;
}

export interface WasmQueryResult {
  free(): void;
  readonly entryCount: number;
  readonly totalBalance: bigint;
  readonly isWhale: boolean;
  /** Native per-result Merkle verdict. */
  readonly merkleVerified: boolean;
  /** Returns `{txid: hexString, vout, amountSats}` or `null`. */
  getEntry(index: number): any;
  /** The CHUNK bins fetched for this result. */
  chunkBins(): any;
  /** Raw chunk bytes for delta-database queries, else `undefined`. */
  rawChunkData(): Uint8Array | undefined;
}

// ─── State ──────────────────────────────────────────────────────────────────

let sdkWasm: PirSdkWasm | null = null;
let sdkInitPromise: Promise<boolean> | null = null;

// ─── Initialization ─────────────────────────────────────────────────────────

/**
 * Initialize the PIR SDK WASM module.
 * Returns true if successful, false if WASM is not available.
 */
export async function initSdkWasm(): Promise<boolean> {
  if (sdkWasm) return true;
  if (sdkInitPromise) return sdkInitPromise;

  sdkInitPromise = (async () => {
    try {
      // Dynamic import - the bundler resolves the WASM package
      // @ts-ignore - pir-sdk-wasm may not be installed
      const mod = await import('pir-sdk-wasm');
      // wasm-pack generates a default export that initializes the module
      if (typeof (mod as any).default === 'function') {
        await (mod as any).default();
      }
      sdkWasm = mod as unknown as PirSdkWasm;
      console.log('[PIR-SDK] WASM module loaded successfully');
      return true;
    } catch (e) {
      console.warn('[PIR-SDK] Failed to load WASM module:', e);
      return false;
    }
  })();

  return sdkInitPromise;
}

/**
 * Check if SDK WASM is loaded and ready.
 */
export function isSdkWasmReady(): boolean {
  return sdkWasm !== null;
}

/** A blinded ARC credential request held in wasm (`WasmArcCredentialRequest`). */
export interface WasmArcCredentialRequest {
  epoch(): number;
  requestBytes(): Uint8Array;
  secretsBytes(): Uint8Array;
  finalize(issuerPublicKeyHex: string, response: Uint8Array): Uint8Array;
  free(): void;
}

/** A finished ARC credential with its presentation counter (`WasmArcCredential`). */
export interface WasmArcCredential {
  epoch(): number;
  presentationLimit(): number;
  nextNonce(): number;
  remaining(): number;
  present(count: number): Uint8Array;
  free(): void;
}

/**
 * The ARC factories `credits.ts` needs (`ArcRequestFactory` and
 * `ArcCredentialFactory`), backed by the loaded wasm module. Throws when
 * the module is not loaded: call `initSdkWasm()` first.
 */
export function sdkArcFactories(): {
  request: {
    create(epoch: number): WasmArcCredentialRequest;
    restore(epoch: number, secrets: Uint8Array, request: Uint8Array): WasmArcCredentialRequest;
  };
  credential: {
    open(credential: Uint8Array, epoch: number, presentationLimit: number, nextNonce: number): WasmArcCredential;
  };
} {
  const mod = sdkWasm;
  if (!mod) throw new Error('SDK WASM is not loaded; credentials need it');
  return {
    request: {
      create: (epoch) => new mod.WasmArcCredentialRequest(epoch),
      restore: (epoch, secrets, request) => mod.WasmArcCredentialRequest.fromBytes(epoch, secrets, request),
    },
    credential: {
      open: (credential, epoch, presentationLimit, nextNonce) =>
        new mod.WasmArcCredential(credential, epoch, presentationLimit, nextNonce),
    },
  };
}

/**
 * Return the loaded `PirSdkWasm` module, throwing if `initSdkWasm()` has
 * not resolved yet.
 */
export function requireSdkWasm(): PirSdkWasm {
  if (!sdkWasm) {
    throw new Error(
      '[PIR-SDK] WASM module required. Call initSdkWasm() at app startup.',
    );
  }
  return sdkWasm;
}

// Re-export the adapter-facing interface types so `dpf-adapter.ts` can
// import them without having to reach into this module's type-only
// `PirSdkWasm` shape.
export type { WasmDatabaseCatalog };
