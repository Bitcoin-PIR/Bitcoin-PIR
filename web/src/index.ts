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
  DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH,
  oramSourcePinFromManifest,
  verifyOramSourceProof,
  type OramSourceProofManifest,
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

// ARC anonymous rate limiting
export { ArcCredentialManager, ARC_LOW_WARNING } from './credential-manager.js';
export type { ArcCredentialState } from './credential-manager.js';
export { sendArcPresentation } from './arc-present.js';

// Cashu Blind Auth (NUT-22) rate limiting
export { CashuBatPool, mintBatPool } from './cashu-bat.js';
export type { Bat } from './cashu-bat.js';

// Provider-independent V1 service admission. Offer selection remains a
// product-policy decision outside the protocol orchestrator.
export {
  AmbiguousCapabilitySpendErrorV1,
  ProviderAdmissionSessionV1,
  VerifiedIndependentProviderPairV1,
  VerifiedSingleProviderOfferV1,
  VerifiedSingleProviderRetainedOfferV1,
} from './service-admission.js';
export {
  assertProductQueryShapeFitsScopeV1,
  canonicalProductQueryShapeV1,
  canonicalServiceEntitlementLimitsV1,
  intersectHomogeneousEntitlementLimitsV1,
} from './service-entitlement.js';
export type {
  ProductQueryShapeV1,
  ProductQueryShapesByRoleV1,
} from './service-entitlement.js';
export { assertIndependentProviderOfferPairV1 } from './provider-payment-selection.js';
export type {
  IndependentProviderSelectionOptionsV1,
  SelectedProviderOfferV1,
} from './provider-payment-selection.js';
export type {
  ProviderTrustAnchorV1,
  ProviderAdmissionSelectionV1,
  IndependentProviderAdmissionSelectionV1,
  IndependentRetainedProviderAdmissionSelectionV1,
  IndependentProviderPairAdmissionSelectionV1,
  SingleProviderAdmissionSelectionV1,
  SingleRetainedProviderAdmissionSelectionV1,
  ProviderPairBolt11AcquisitionOptionsV1,
  ProviderPairSideV1,
  ServiceAdmissionPortV1,
  ServiceAdmissionTargetV1,
  ServiceAdmissionVaultV1,
  ServiceAuthorizationOptionsV1,
} from './service-admission.js';
export {
  AdmissionCredentialVaultV1,
  validateBindingV1,
  validateCapabilityV1,
} from './admission-vault.js';
export type {
  AdmissionCapabilityBindingV1,
  AdmissionCapabilityV1,
  AdmissionSchemeV1,
  ArcAdvanceV1,
  Bolt11RecoveryRecordV1,
  LockedBolt11RecoveryV1,
  LightningNetworkNameV1,
  PolicyCheckpointAdvanceV1,
} from './admission-vault.js';
export {
  Bolt11RecoveryRequiredErrorV1,
  fetchQuoteKeyDelegationV1,
  resumeBolt11AcquisitionV1,
} from './service-acquisition.js';
export type {
  Bolt11AcquisitionHandleV1,
  Bolt11QuoteStatusNameV1,
  ResumeBolt11AcquisitionV1,
} from './service-acquisition.js';

// Explicit strict-multi or centralized/degraded Nostr directory refresh and
// durable rollback storage. Centralized mode never activates implicitly.
export { DirectoryRollbackVaultV1 } from './directory-vault.js';
export type {
  DirectoryDiscoveryEntryJsonV1,
  SelectableDirectoryCatalogV1,
  SelectableDirectoryEntryV1,
  SelectableDirectoryShardV1,
} from './directory-vault.js';
export {
  directoryProviderTrustAnchorV1,
  directoryProviderTrustMaterialV1,
  refreshNostrDirectoryV1,
} from './nostr-directory.js';

// Product application admission lifecycle. These controllers contain no
// address/query payloads and never persist payment material in localStorage.
export {
  ProductAdmissionControllerV1,
  ProductAdmissionErrorV1,
  ProductResourceFailedAfterAuthorizationErrorV1,
} from './product-admission-controller.js';
export type {
  ProductAdmissionControllerOptionsV1,
  ProductAdmissionErrorCodeV1,
  ProductAdmissionLegSnapshotV1,
  ProductAdmissionLegStatusV1,
  ProductAdmissionLegV1,
  ProductAdmissionResourceBindingV1,
  ProductAdmissionResourceV1,
  ProductAdmissionSnapshotV1,
  ProductAdmissionTopologyV1,
  ProductOfferChoiceV1,
  ProductOfferOptionV1,
  ProductStrictBootstrapV1,
  ProductStrictLegBootstrapV1,
} from './product-admission-controller.js';
export {
  canBootstrapNextProviderV1,
  credentialActionsReadyV1,
  pairAuthorizationReadyV1,
  ProductAdmissionPanelV1,
  privacyLabelForOfferV1,
  publicAdmissionError,
} from './product-admission-ui.js';
export type {
  ProductAdmissionPanelOptionsV1,
  ProductAdmissionPanelRoleV1,
  ProductProviderChoiceV1,
} from './product-admission-ui.js';
export { renderSecurityBadgeTextRowsV1 } from './security-badge.js';
export type { SecurityBadgeTextRowV1 } from './security-badge.js';
export {
  assertIndependentProviderDialPairV1,
  directoryBoundProviderTrustAnchorV1,
  manualProviderAdmissionTrustAnchorV1,
  parseProductTrustedBootstrapV1,
  expectedLightningPayeeForOfferV1,
  providerArkFingerprintV1,
  providerLightningPayeeTrustV1,
  providerOperatorKeyV1,
} from './product-provider-bootstrap.js';
export type {
  ProductLightningPayeeTrustV1,
  ProductTrustedBootstrapV1,
  ProductTrustedProviderV1,
} from './product-provider-bootstrap.js';
export type { HarmonyHintCacheBindingV1 } from './harmonypir_hint_db.js';
export type {
  DirectoryRelayModeV1,
  DirectoryProviderTrustMaterialV1,
  DirectoryWebSocketV1,
  NostrDirectoryRefreshOptionsV1,
} from './nostr-directory.js';

// Credential issuer HTTP client (the "obtain" leg)
export {
  getArcPubkey,
  issueArcCredential,
  getCashuKeyset,
  mintCashuBats,
  presentArc,
  presentCashu,
  ARC_PUBKEY_BYTES,
  ARC_REQUEST_BYTES,
  ARC_RESPONSE_BYTES,
  CASHU_POINT_BYTES,
} from './payment-client.js';
export type { CashuKeyset, PresentResult } from './payment-client.js';
export { requireVerifiedQueryResultsV1 } from './strict-result-release.js';
