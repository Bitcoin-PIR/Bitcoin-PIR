/**
 * Bitcoin Batch PIR Web Client
 *
 * Main entry point for the two-level Batch PIR web client library.
 */

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
  splitmix64,
  computeTag,
  deriveGroups,
  cuckooHash,
  deriveChunkGroups,
  cuckooHashInt,
  deriveCuckooKeyGeneric,
  sha256,
  ripemd160,
  scriptHash,
  scriptPubKeyToAddress,
  addressToScriptPubKey,
  decompileScript,
  type DecompiledOp,
  hexToBytes,
  bytesToHex,
} from './hash.js';

export {
  K, K_CHUNK, NUM_HASHES, INDEX_CUCKOO_NUM_HASHES,
  PRODUCTION_ISSUER_URL,
} from './constants.js';

export {
  checkQuoteStatus,
  mintTokenForQuote,
  requestLightningQuote,
  waitForQuotePayment,
  type MintPurchase,
  type MintQuoteStatus,
} from './cashu-purchase.js';

export {
  CREDIT_PRESENT_KIND_ARC,
  CREDIT_PRESENT_KIND_CASHU,
  CreditStore,
  CreditWallet,
  CreditedChannel,
  ConnectionCreditMeter,
  IssuerClient,
  IssuerError,
  cashuLightningRail,
  parseIssuerInfo,
  purchaseCredential,
  serverGasCardFromInfo,
  type CreditEnablement,
  type CreditOffer,
  type CreditProvider,
  type IssuedCredential,
  type IssuerInfo,
  type LightningRail,
  type PendingCredential,
  type Presentation,
  type PurchaseHooks,
  type StoredCredential,
} from './credits.js';

export {
  computeParentN,
} from './merkle.js';

export {
  OnionPirWebClient,
  type OnionPirClientConfig,
} from './onionpir_client.js';

export {
  HarmonyPirClientAdapter,
  type HarmonyPirClientConfig,
} from './harmonypir-adapter.js';

export {
  DEFAULT_ORAM_ACCESS_BUDGET,
  DEFAULT_ORAM_INDEX_READS_PER_SCRIPT_HASH,
  DEFAULT_ORAM_SCRIPT_HASHES_PER_REQUEST,
  OramPirClientAdapter,
  oramJsonResultToQueryResult,
  resolveOramBatchPlan,
  splitOramScriptHashBatches,
  type OramBatchPlan,
  type OramBatchPlannerConfig,
  type OramPirClientConfig,
} from './oram-adapter.js';

export {
  AMD_TURIN_ARK_FINGERPRINT,
  AMD_TURIN_ARK_FINGERPRINT_HEX,
  DELTA_940611_948454_DB_PROOF_PIN,
  MAINNET_948454_DB_PROOF_PIN,
  MAINNET_948454_ORAM_SOURCE_DB_PROOF_PIN,
  PIR1_PIN,
  PIR2_MACBOOK_PIN,
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
} from './harmony-types.js';

export { fetchProofArtifactBytesV1 } from './proof-artifact-fetch.js';

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
  mergeDeltaIntoHarmonySnapshot,
} from './sync-merge.js';

export {
  SyncController,
  describeStep,
  type SyncableResult,
  type SyncExecuteHooks,
  type SyncExecuteOutput,
  type SyncControllerConfig,
} from './sync-controller.js';

export {
  initSdkWasm,
  sdkArcFactories,
  type WasmArcCredential,
  type WasmArcCredentialRequest,
  isSdkWasmReady,
} from './sdk-bridge.js';

export { renderSecurityBadgeTextRowsV1 } from './security-badge.js';
export type { SecurityBadgeTextRowV1 } from './security-badge.js';
export { type HarmonyHintCacheBindingV1 } from './harmonypir_hint_db.js';


export {
  STALE_CHUNK_RELOAD_KEY,
  STALE_CHUNK_RELOAD_WINDOW_MS,
  claimStaleChunkReload,
  installStaleChunkReload,
  type StaleChunkReloadEnv,
} from './stale-chunk-reload.js';

export {
  ORAM_PAUSED_MESSAGE,
  ORAM_PROVIDER,
  PIR1_PROVIDER,
  PIR2_PROVIDER,
  PRODUCTION_ORAM_BATCH_PLANNER,
  type ProductionProviderPin,
} from './production-providers.js';

export {
  purchaseCredentialX402,
  requestChallenge as x402RequestChallenge,
  validateChallenge as x402ValidateChallenge,
  waitForPayment as x402WaitForPayment,
  settle as x402Settle,
  http1Binding as x402Http1Binding,
  X402_NETWORK_MAINNET,
} from './x402.js';
export type { PaymentRequired, PaymentRequirements, ValidatedChallenge, WebLnLike } from './x402.js';
