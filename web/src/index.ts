/**
 * Bitcoin Batch PIR Web Client
 *
 * Main entry point for the two-level Batch PIR web client library.
 */

// Polyfill Buffer for browser environment
import { Buffer } from 'buffer';
if (typeof window !== 'undefined') {
  (window as any).Buffer = Buffer;

  if (!(window as any).crypto) {
    (window as any).crypto = {};
  }
  if (!(window as any).crypto.randomBytes) {
    (window as any).crypto.randomBytes = (size: number) => {
      const bytes = new Uint8Array(size);
      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(bytes);
      } else {
        throw new Error('crypto.getRandomValues is required but not available in this browser');
      }
      return Buffer.from(bytes);
    };
  }
}

export {
  BatchPirClientAdapter,
  type BatchPirClientConfig,
  type OperatorIdentity,
  gateOperatorIdentity,
} from './dpf-adapter.js';

export type {
  ConnectionState,
  UtxoEntry,
  QueryResult,
} from './types.js';

export {
  encodeRequest,
  decodeResponse,
  type Request,
  type Response,
  type BatchQuery,
  type BatchResult,
  type ServerInfo,
} from './protocol.js';

export {
  splitmix64,
  computeTag,
  deriveGroups,
  deriveCuckooKey,
  cuckooHash,
  deriveChunkGroups,
  deriveChunkCuckooKey,
  cuckooHashInt,
  deriveIntGroups3,
  deriveCuckooKeyGeneric,
  sha256,
  ripemd160,
  scriptHash,
  scriptPubKeyToAddress,
  addressToScriptPubKey,
  decompileScript,
  decompileScriptText,
  type DecompiledOp,
  reverseBytes,
  hexToBytes,
  bytesToHex,
} from './hash.js';

export {
  K, K_CHUNK, NUM_HASHES,
  SCRIPT_HASH_SIZE, TAG_SIZE, INDEX_SLOT_SIZE,
  CHUNK_SIZE, CHUNKS_PER_UNIT, UNIT_DATA_SIZE,
  INDEX_SLOTS_PER_BIN, INDEX_CUCKOO_NUM_HASHES,
  CHUNK_SLOTS_PER_BIN, CHUNK_CUCKOO_NUM_HASHES,
  DPF_N, CHUNK_DPF_N,
  HARMONY_INDEX_W, HARMONY_CHUNK_W, HARMONY_EMPTY,
  DEFAULT_SERVER0_URL,
  DEFAULT_SERVER1_URL,
  BUCKET_MERKLE_ARITY, BUCKET_MERKLE_SIB_ROW_SIZE,
  REQ_BUCKET_MERKLE_SIB_BATCH, RESP_BUCKET_MERKLE_SIB_BATCH,
  REQ_BUCKET_MERKLE_TREE_TOPS, RESP_BUCKET_MERKLE_TREE_TOPS,
} from './constants.js';

export { PRODUCTION_CASHIER_URL, SESSION_GRANT_LEN } from './constants.js';

export {
  CashierClient,
  CashierError,
  SessionGrantStore,
  base64ToBytes,
  bytesToBase64,
  classifySessionGrantFailure,
  decodeSessionGrantFields,
  encodeSessionGrantPresentFrame,
  parseSessionGrantResponsePayload,
  type CashierInfo,
  type CashierOffer,
  type IssuedGrant,
  type SessionGrantPresentation,
  type SessionGrantProvider,
  type StoredSessionGrant,
} from './session-grant.js';

export {
  PendingPurchaseStore,
  checkQuoteStatus,
  mintTokenForQuote,
  requestLightningQuote,
  waitForQuotePayment,
  type MintQuoteStatus,
  type PendingPurchase,
} from './cashu-purchase.js';

export {
  computeDataHash,
  computeParentN,
  computeBinLeafHash,
} from './merkle.js';

export {
  OnionPirWebClient,
  createOnionPirWebClient,
  type OnionPirClientConfig,
} from './onionpir_client.js';

export {
  HarmonyPirClientAdapter,
  createHarmonyPirClientAdapter,
  type HarmonyPirClientConfig,
} from './harmonypir-adapter.js';

export {
  DEFAULT_ORAM_ACCESS_BUDGET,
  DEFAULT_ORAM_INDEX_READS_PER_SCRIPT_HASH,
  DEFAULT_ORAM_SCRIPT_HASHES_PER_REQUEST,
  OramPirClientAdapter,
  createOramPirClientAdapter,
  oramJsonResultToQueryResult,
  planOramScriptHashBatches,
  requireAtomicOramRequest,
  resolveOramBatchPlan,
  splitOramScriptHashBatches,
  type OramBatchPlan,
  type OramBatchPlannerConfig,
  type OramLayoutInfo,
  type OramPirClientConfig,
} from './oram-adapter.js';

export {
  AMD_TURIN_ARK_FINGERPRINT,
  AMD_TURIN_ARK_FINGERPRINT_HEX,
  DELTA_940611_948454_DB_PROOF_PIN,
  MAINNET_948454_DB_PROOF_PIN,
  MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN,
  PIR1_PIN,
  PIR2_TIER3_PIN,
  PRODUCTION_DB_PROOF_PINS,
  PRODUCTION_ONION_DB_PROOF_V2_PINS,
  PRODUCTION_ORAM_DB_PROOF_V2_PINS,
  type ServerAttestPin,
} from './attest-pin.js';

export {
  databaseProofAnchorLabel,
  databaseProofAnchorPoints,
  databaseProofUnavailable,
  mempoolSpaceBlockUrl,
  verifiedDatabaseProofFromWasm,
  verifyDatabaseProofAgainstPin,
  type DatabaseAnchorPoint,
  type DatabaseProofPin,
  type DatabaseProofStatus,
  type VerifiedDatabaseProof,
} from './db-proof.js';

export {
  DEFAULT_TRUST_CHAIN_MANIFEST_PATH,
  verifyProductionTrustChain,
  trustChainPinFromManifest,
  type DatabaseTrustChainStatus,
  type TrustChainManifest,
} from './trust-chain-proof.js';

export {
  DB1_ORAM_SOURCE_PROOF_MANIFEST_PATH,
  DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH,
  oramSourceProofManifestPathForDbId,
  verifyOramSourceProof,
  type OramSourceProofManifest,
  type OramSourceLiveRuntime,
  type OramSourceProofStatus,
} from './oram-source-proof.js';

export type {
  HarmonyQueryResult,
  HarmonyUtxoEntry,
  QueryInspectorData,
  RoundTimingData,
} from './harmony-types.js';

export {
  prepareQueryInspectorRenderDataV1,
  type QueryInspectorRenderDataV1,
} from './query-inspector-sanitize.js';

export {
  fetchProofArtifactBytesV1,
  resolveProofArtifactUrlV1,
  type ProofArtifactFetchOptionsV1,
} from './proof-artifact-fetch.js';

// Backwards-compat shims for the old `pir-core-wasm` bridge. The crate has
// been retired and all primitives it exposed are now served by `pir-sdk-wasm`,
// so these names forward to the SDK init. New callers should import
// `initSdkWasm` / `isSdkWasmReady` directly.
export {
  initSdkWasm as initWasm,
  isSdkWasmReady as isWasmReady,
} from './sdk-bridge.js';

export {
  cuckooPlace,
  planRounds,
} from './pbc.js';

export {
  readVarint,
  decodeUtxoData,
  decodeDeltaData,
  DummyRng,
  type UtxoEntryRaw,
  type DeltaData,
  type SpentRef,
} from './codec.js';

export {
  fetchDatabaseCatalog,
  decodeDatabaseCatalog,
  type DatabaseCatalog,
  type DatabaseCatalogEntry,
  type PerDatabaseInfoJson,
} from './server-info.js';

export {
  computeSyncPlan,
  type SyncPlan,
  type SyncStep,
} from './sync.js';

export {
  mergeDeltaIntoSnapshot,
  applyDeltaData,
  mergeDeltaBatch,
  mergeDeltaIntoHarmonySnapshot,
  mergeDeltaHarmonyBatch,
} from './sync-merge.js';

export {
  SyncController,
  describeStep,
  type SyncableResult,
  type SyncExecuteHooks,
  type SyncExecuteOutput,
  type SyncControllerConfig,
} from './sync-controller.js';

// SDK WASM bridge (optional - use pir-sdk-wasm for Rust-backed implementations)
export {
  initSdkWasm,
  isSdkWasmReady,
  computeSyncPlanSdk,
  sdkSplitmix64,
  sdkComputeTag,
  sdkDeriveGroups,
  sdkDeriveCuckooKey,
  sdkCuckooHash,
  sdkDeriveChunkGroups,
  sdkCuckooHashInt,
} from './sdk-bridge.js';

export { trustedNowUnixV1 } from './trusted-time.js';
export { renderSecurityBadgeTextRowsV1 } from './security-badge.js';
export type { SecurityBadgeTextRowV1 } from './security-badge.js';
export { type HarmonyHintCacheBindingV1 } from './harmonypir_hint_db.js';

export { requireVerifiedQueryResultsV1 } from './strict-result-release.js';
