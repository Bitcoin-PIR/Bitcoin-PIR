import {
  AdmissionCredentialVaultV1,
  type AdmissionCapabilityBindingV1,
} from '../src/admission-vault.js';
import { hexToBytes } from '../src/hash.js';
import {
  Bolt11AcquisitionControllerV1,
  type Bolt11AcquisitionHandleV1,
} from '../src/service-acquisition.js';
import { AmbiguousCapabilitySpendErrorV1 } from '../src/service-admission.js';
import { assertIndependentProviderOfferPairV1 } from '../src/provider-payment-selection.js';
import {
  initSdkWasm,
  requireSdkWasm,
  type ServiceOfferViewV1,
  type ServicePolicyViewV1,
  type ServiceScopeViewV1,
  type WasmAcceptedServicePolicyV1,
  type WasmArcPresentationState,
  type WasmDpfClient,
} from '../src/sdk-bridge.js';
import type {
  PaymentTwoProviderFixtureV1,
  PaymentTwoProviderVariantV1,
} from './payment-two-provider.global-setup.js';

const CT_FAKE_SETTLEMENT = 'application/vnd.bitcoinpir.fake-settlement-v1';
// Fixed 20-byte test scripthash. It is never rendered or persisted and is
// zeroized after the real two-server query. The Playwright test uses the same
// byte pattern as a plaintext-transcript/log leakage needle.
const QUERY_SCRIPT_HASH_BYTE = 0x42;

interface LegStateV1 {
  fixture: PaymentTwoProviderFixtureV1['providers'][number];
  policy: WasmAcceptedServicePolicyV1;
  view: ServicePolicyViewV1;
  scope: ServiceScopeViewV1;
}

let fixtureState: PaymentTwoProviderFixtureV1 | null = null;
let vaultPromise: Promise<AdmissionCredentialVaultV1> | null = null;
let client: WasmDpfClient | null = null;
let legs: [LegStateV1, LegStateV1] | null = null;
let selectedVariant: PaymentTwoProviderVariantV1 | null = null;
let selectedOffers: [ServiceOfferViewV1, ServiceOfferViewV1] | null = null;
const settledQuotes = new Set<string>();
const replayProofs: Array<Uint8Array | null> = [null, null];

function vault(): Promise<AdmissionCredentialVaultV1> {
  vaultPromise ??= AdmissionCredentialVaultV1.open();
  return vaultPromise;
}

async function initialize(fixture: PaymentTwoProviderFixtureV1): Promise<{
  secureChannel: true;
  attestationBoundary: [string, string];
  databaseProofInstalled: true;
  databaseProofBoundary: string;
  providers: Array<{
    providerIdHex: string;
    policyDigestHex: string;
    scopeIdHex: string;
    methods: string[];
    arcKeyIdHex: string | null;
    issuerOrigin: string;
    payeePubkeyHex: string;
  }>;
}> {
  validateFixture(fixture);
  fixtureState = structuredClone(fixture);
  selectedVariant = null;
  selectedOffers = null;
  if (!await initSdkWasm()) throw new Error('real pir-sdk-wasm failed to initialize');
  const statuses = await connectAndFetchPolicies();
  return {
    secureChannel: true,
    attestationBoundary: statuses,
    databaseProofInstalled: true,
    databaseProofBoundary: fixture.databaseProof.boundary,
    providers: requireLegs().map((leg) => ({
      providerIdHex: leg.view.providerIdHex,
      policyDigestHex: leg.view.policyDigestHex,
      scopeIdHex: leg.scope.scopeIdHex,
      methods: leg.scope.offers.map((offer) => offer.authorization),
      arcKeyIdHex: leg.fixture.arcKeyIdHex,
      issuerOrigin: leg.fixture.issuerOrigin,
      payeePubkeyHex: leg.fixture.expectedPayeePubkeyHex,
    })),
  };
}

async function acquireLeg(index: 0 | 1): Promise<{
  invoice: string | null;
  count: number;
  binding: AdmissionCapabilityBindingV1 | null;
}> {
  const leg = requireLeg(index);
  const offer = requireSelectedOffer(index);
  if (offer.authorization === 'free') {
    if (offer.acquisition !== 'free'
        || offer.freeMode !== 'ip-rate-limited'
        || offer.privacyLeakageBits !== 1
        || offer.price.kind !== 'free'
        || offer.endpoint !== '') {
      throw new Error('selected signed Free offer is not exact IP-rate-limited mode');
    }
    return { invoice: null, count: 0, binding: null };
  }
  if (requireFixture().settlementMode !== 'fake') {
    throw new Error('external settlement requires explicit startPaidLeg/finishPaidLeg phases');
  }
  let acquisition: Bolt11AcquisitionHandleV1 | null = null;
  try {
    acquisition = await Bolt11AcquisitionControllerV1.start({
      vault: await vault(),
      policy: leg.policy,
      scope: leg.scope,
      offer,
      network: 'regtest',
      expectedPayeePubkey: exactHexBytes(
        'expectedPayeePubkeyHex',
        leg.fixture.expectedPayeePubkeyHex,
        33,
      ),
      fetchImpl: (input, init) => issuerFetch(index, input, init),
      assertReady: () => {},
    });
    const invoice = acquisition.invoice();
    await pollUntilSettled(acquisition);
    const count = await claimWhenClockAllows(acquisition);
    if (count !== 1) throw new Error(`browser harness expected one capability, received ${count}`);
    return { invoice, count, binding: bindingFor(leg, offer) };
  } finally {
    acquisition?.close();
  }
}

async function startPaidLeg(index: 0 | 1): Promise<{
  recoveryId: string;
  invoice: string;
  binding: AdmissionCapabilityBindingV1;
}> {
  const leg = requireLeg(index);
  const offer = requireSelectedOffer(index);
  if (offer.authorization === 'free' || offer.acquisition !== 'bolt11') {
    throw new Error(`provider ${index} selected an offer without paid BOLT11 acquisition`);
  }
  let acquisition: Bolt11AcquisitionHandleV1 | null = null;
  try {
    acquisition = await Bolt11AcquisitionControllerV1.start({
      vault: await vault(),
      policy: leg.policy,
      scope: leg.scope,
      offer,
      network: 'regtest',
      expectedPayeePubkey: exactHexBytes(
        'expectedPayeePubkeyHex',
        leg.fixture.expectedPayeePubkeyHex,
        33,
      ),
      fetchImpl: (input, init) => issuerFetch(index, input, init),
      assertReady: () => {},
    });
    return {
      recoveryId: acquisition.recoveryId,
      invoice: acquisition.invoice(),
      binding: bindingFor(leg, offer),
    };
  } finally {
    acquisition?.close();
  }
}

async function finishPaidLeg(
  index: 0 | 1,
  recoveryId: string,
): Promise<{
  count: number;
  binding: AdmissionCapabilityBindingV1;
}> {
  const leg = requireLeg(index);
  const offer = requireSelectedOffer(index);
  if (offer.authorization === 'free' || offer.acquisition !== 'bolt11') {
    throw new Error(`provider ${index} selected an offer without paid BOLT11 acquisition`);
  }
  const acquisition = await Bolt11AcquisitionControllerV1.resume({
    vault: await vault(),
    recoveryId,
    fetchImpl: (input, init) => issuerFetch(index, input, init),
  });
  try {
    await pollUntilSettled(acquisition);
    const count = await claimWhenClockAllows(acquisition);
    if (count !== 1) throw new Error(`browser harness expected one capability, received ${count}`);
    return { count, binding: bindingFor(leg, offer) };
  } finally {
    acquisition.close();
  }
}

async function authorizeLeg(index: 0 | 1, corruptBeforeSend = false): Promise<{
  scopeIdHex: string;
  enforcedProfile: number;
}> {
  const activeClient = requireClient();
  const leg = requireLeg(index);
  const offer = requireSelectedOffer(index);
  const scopeId = hexToBytes(leg.scope.scopeIdHex);
  const retiredOrAdvanced = offer.authorization !== 'free';
  const exactProof = await prepareAuthorizationProof(leg, offer, scopeId);
  const wireProof = exactProof.slice();
  if (!corruptBeforeSend) {
    if (retiredOrAdvanced) {
      replayProofs[index]?.fill(0);
      replayProofs[index] = exactProof.slice();
    }
  } else {
    if (!retiredOrAdvanced || wireProof.length === 0) {
      throw new Error('the browser harness corrupts only one-shot paid/ARC proofs');
    }
    wireProof[wireProof.length - 1] ^= 0x01;
  }
  try {
    try {
      const grant = await activeClient.authorizeService(
        index,
        0,
        leg.policy,
        scopeId,
        offer.offerId,
        wireProof,
      );
      if (corruptBeforeSend) {
        throw new Error('provider accepted a deliberately corrupted capability');
      }
      if (grant.scopeIdHex !== leg.scope.scopeIdHex
          || grant.enforcedProfile !== leg.fixture.entitlementProfile) {
        throw new Error('provider grant did not match its exact signed entitlement');
      }
      return {
        scopeIdHex: grant.scopeIdHex,
        enforcedProfile: grant.enforcedProfile,
      };
    } catch (cause) {
      if ((cause as Error).message.includes('accepted a deliberately corrupted capability')) {
        throw cause;
      }
      if (retiredOrAdvanced) {
        throw new AmbiguousCapabilitySpendErrorV1(
          `provider ${index} authorization failed after local capability retirement; no fallback or retry is permitted`,
          { cause },
        );
      }
      throw cause;
    }
  } finally {
    exactProof.fill(0);
    wireProof.fill(0);
  }
}

async function prepareAuthorizationProof(
  leg: LegStateV1,
  offer: ServiceOfferViewV1,
  scopeId: Uint8Array,
): Promise<Uint8Array> {
  if (offer.authorization === 'free') {
    if (offer.freeMode !== 'ip-rate-limited' || offer.privacyLeakageBits !== 1) {
      throw new Error('browser harness Free variant changed its signed free mode');
    }
    const proof = new Uint8Array();
    leg.policy.validateAuthorizationProof(scopeId, offer.offerId, proof);
    return proof;
  }

  const binding = bindingFor(leg, offer);
  if (offer.authorization === 'arc-experimental') {
    if (offer.deploymentStatus !== 'experimental') {
      throw new Error('ARC browser variant is not explicitly experimental');
    }
    const presentation = await (await vault()).advanceArcCredential(
      binding,
      (serializedState) => {
        const state = requireSdkWasm().WasmArcPresentationState.deserialize(serializedState);
        let prepared: ReturnType<WasmArcPresentationState['prepare_presentation']> | null = null;
        try {
          prepared = state.prepare_presentation();
          return {
            nextState: prepared.successor_state_bytes(),
            remaining: Number(prepared.remaining()),
            releaseAfterPersisted: () => {
              const transition = prepared!;
              let proof: Uint8Array | null = null;
              try {
                proof = transition.release_after_persisted();
                leg.policy.validateAuthorizationProof(scopeId, offer.offerId, proof);
                return proof;
              } catch (error) {
                proof?.fill(0);
                throw error;
              } finally {
                transition.free();
                prepared = null;
              }
            },
            discard: () => {
              prepared?.free();
              prepared = null;
            },
          };
        } finally {
          state.free();
        }
      },
    );
    if (!presentation) throw new Error('no ARC credential is available for this exact offer');
    return presentation;
  }

  const capability = await (await vault()).takeSingleUseCapability(
    binding,
    (candidate) => leg.policy.validateAuthorizationProof(scopeId, offer.offerId, candidate),
  );
  if (!capability) throw new Error('no capability is available for this exact offer');
  return capability.payload;
}

async function preflightAndQuery(): Promise<{
  preflightComplete: true;
  explicitMerkleVerified: true;
  entryCount: number;
  totalBalanceSats: string;
  isWhale: boolean;
}> {
  const activeClient = requireClient();
  const scriptHash = new Uint8Array(20);
  scriptHash.fill(QUERY_SCRIPT_HASH_BYTE);
  let results: Awaited<ReturnType<WasmDpfClient['queryBatchRaw']>> = [];
  const resultJson: unknown[] = [];
  try {
    // This deliberately runs only after both independent provider grants have
    // committed. It binds the server-supplied tree tops to the installed
    // synthetic proof root before either server performs the real DPF query.
    await activeClient.preflightDatabase(0);
    results = await activeClient.queryBatchRaw(scriptHash, 0);
    if (results.length !== 1 || !results[0]) {
      throw new Error(`real DPF query returned ${results.length} results instead of one`);
    }
    for (const result of results) resultJson.push(result.toJson());
    const verdicts = await activeClient.verifyMerkleBatch(resultJson, 0);
    if (verdicts.length !== 1 || verdicts[0] !== true) {
      throw new Error('proof-bound bucket-Merkle verification rejected the DPF result');
    }
    const result = results[0];
    if (result.matchedIndexIdx() !== undefined
        || result.entryCount !== 0
        || result.totalBalance !== 0n
        || result.isWhale) {
      throw new Error('all-zero synthetic database unexpectedly returned a matching UTXO');
    }
    return {
      preflightComplete: true,
      explicitMerkleVerified: true,
      entryCount: result.entryCount,
      totalBalanceSats: result.totalBalance.toString(),
      isWhale: result.isWhale,
    };
  } finally {
    scriptHash.fill(0);
    for (const result of results) result.free();
    results.length = 0;
    resultJson.length = 0;
  }
}

async function replaySpentCapability(index: 0 | 1): Promise<string> {
  const proof = replayProofs[index];
  if (!proof) throw new Error(`provider ${index} has no retained test replay proof`);
  const variant = requireSelectedVariant();
  await connectAndFetchPolicies();
  selectVariant(variant);
  const activeClient = requireClient();
  const leg = requireLeg(index);
  const offer = requireSelectedOffer(index);
  const replay = proof.slice();
  try {
    try {
      await activeClient.authorizeService(
        index,
        0,
        leg.policy,
        hexToBytes(leg.scope.scopeIdHex),
        offer.offerId,
        replay,
      );
    } catch (error) {
      return (error as Error).message;
    }
    throw new Error(`provider ${index} accepted a replayed single-use capability`);
  } finally {
    replay.fill(0);
  }
}

async function replayFreeQuota(index: 0 | 1): Promise<string> {
  const variant = requireSelectedVariant();
  await connectAndFetchPolicies();
  selectVariant(variant);
  const activeClient = requireClient();
  const leg = requireLeg(index);
  const offer = requireSelectedOffer(index);
  if (offer.authorization !== 'free'
      || offer.freeMode !== 'ip-rate-limited'
      || offer.privacyLeakageBits !== 1) {
    throw new Error(`provider ${index} did not select the signed Free/IP quota offer`);
  }
  const scopeId = hexToBytes(leg.scope.scopeIdHex);
  const proof = new Uint8Array();
  try {
    try {
      await activeClient.authorizeService(
        index,
        0,
        leg.policy,
        scopeId,
        offer.offerId,
        proof,
      );
    } catch (error) {
      return (error as Error).message;
    }
    throw new Error(`provider ${index} accepted a second connection in its durable Free/IP window`);
  } finally {
    scopeId.fill(0);
    proof.fill(0);
  }
}

async function capabilityCount(index: 0 | 1): Promise<number> {
  const leg = requireLeg(index);
  return (await vault()).countCapabilities(bindingFor(leg, requireSelectedOffer(index)));
}

function retainedReplayProofContains(index: 0 | 1, needleValues: number[]): boolean {
  const proof = replayProofs[index];
  if (!proof) throw new Error(`provider ${index} has no retained test replay proof`);
  if (!Array.isArray(needleValues)
      || needleValues.length === 0
      || needleValues.length > 16 * 1024
      || needleValues.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
    throw new Error('test needle must be a non-empty byte array');
  }
  const needle = Uint8Array.from(needleValues);
  try {
    return containsBytes(proof, needle);
  } finally {
    needle.fill(0);
  }
}

function verifiedOfferInventory(): Array<{
  index: 0 | 1;
  offerCount: number;
  hasFree: boolean;
  authorization: string;
  acquisition: string;
  freeMode: string;
  deploymentStatus: string;
}> {
  return requireLegs().map((leg, index) => ({
    index: index as 0 | 1,
    offerCount: leg.scope.offers.length,
    hasFree: leg.scope.offers.some((offer) => offer.authorization === 'free'),
    authorization: requireSelectedOffer(index as 0 | 1).authorization,
    acquisition: requireSelectedOffer(index as 0 | 1).acquisition,
    freeMode: requireSelectedOffer(index as 0 | 1).freeMode,
    deploymentStatus: requireSelectedOffer(index as 0 | 1).deploymentStatus,
  }));
}

function selectVariant(variant: PaymentTwoProviderVariantV1): ReturnType<
  typeof verifiedOfferInventory
> {
  if (variant !== 'direct-bat' && variant !== 'free-arc-experimental') {
    throw new Error('browser harness refused an unknown payment variant');
  }
  const activeLegs = requireLegs();
  const offers = activeLegs.map((leg) => {
    const fixtureOffer = leg.fixture.offers.find((candidate) => candidate.variant === variant);
    if (!fixtureOffer) throw new Error(`provider ${leg.fixture.index} omitted variant ${variant}`);
    const offer = leg.scope.offers.find((candidate) => candidate.offerId === fixtureOffer.offerId);
    if (!offer
        || offer.authorization !== fixtureOffer.method
        || offer.freeMode !== fixtureOffer.freeMode
        || offer.deploymentStatus !== fixtureOffer.deploymentStatus) {
      throw new Error(`provider ${leg.fixture.index} signed variant differs from fixture inventory`);
    }
    return offer;
  }) as [ServiceOfferViewV1, ServiceOfferViewV1];
  assertIndependentProviderOfferPairV1(
    {
      trust: {
        providerId: exactHexBytes('providerIdHex', activeLegs[0].fixture.providerIdHex, 32),
        policySigningKey: exactHexBytes(
          'policySigningPubkeyHex',
          activeLegs[0].fixture.policySigningPubkeyHex,
          32,
        ),
      },
      offer: offers[0],
    },
    {
      trust: {
        providerId: exactHexBytes('providerIdHex', activeLegs[1].fixture.providerIdHex, 32),
        policySigningKey: exactHexBytes(
          'policySigningPubkeyHex',
          activeLegs[1].fixture.policySigningPubkeyHex,
          32,
        ),
      },
      offer: offers[1],
    },
  );
  selectedVariant = variant;
  selectedOffers = offers;
  return verifiedOfferInventory();
}

function localStorageSnapshot(): Record<string, string> {
  return Object.fromEntries(
    Array.from({ length: localStorage.length }, (_, index) => localStorage.key(index))
      .filter((key): key is string => key !== null)
      .map((key) => [key, localStorage.getItem(key) ?? '']),
  );
}

async function connectAndFetchPolicies(): Promise<[string, string]> {
  const fixture = requireFixture();
  await closeClient();
  const sdk = requireSdkWasm();
  const nextClient = new sdk.WasmDpfClient(
    fixture.providers[0].serverWsUrl,
    fixture.providers[1].serverWsUrl,
  );
  nextClient.setRequireVerifiedDatabaseRoots(true);
  client = nextClient;
  await nextClient.connect();
  const att0 = await nextClient.attest(0);
  const att1 = await nextClient.attest(1);
  let statuses: [string, string];
  try {
    statuses = [att0.sevStatus, att1.sevStatus];
    for (const [index, attestation] of [att0, att1].entries()) {
      if (attestation.sevStatus !== 'noSevHost') {
        throw new Error(
          `provider ${index} left the harness's explicit NoSEV boundary: ${attestation.sevStatus}`,
        );
      }
      if (attestation.serverStaticPub.length !== 32
          || attestation.serverStaticPub.every((byte) => byte === 0)) {
        throw new Error(`provider ${index} did not expose a secure-channel key`);
      }
      if (attestation.manifestRootsHex.length !== 1
          || attestation.manifestRootsHex[0] !== fixture.manifestRootHex) {
        throw new Error(`provider ${index} served an unexpected test manifest root`);
      }
    }
    await nextClient.upgradeToSecureChannel(
      att0.serverStaticPub,
      att1.serverStaticPub,
    );
  } finally {
    att0.free();
    att1.free();
  }

  await verifyAndInstallSyntheticDatabaseProof(nextClient, fixture);

  const fetched: LegStateV1[] = [];
  for (const provider of fixture.providers) {
    const accepted = await (await vault()).advancePolicyCheckpoint(
      provider.providerIdHex,
      sdk.initialServicePolicyCheckpointV1(),
      async (checkpoint) => {
        const candidate = await nextClient.fetchServicePolicy(
          provider.index,
          0,
          exactHexBytes('providerIdHex', provider.providerIdHex, 32),
          exactHexBytes('policySigningPubkeyHex', provider.policySigningPubkeyHex, 32),
          nowUnix(),
          checkpoint,
        );
        return {
          nextCheckpoint: candidate.checkpointBytes(),
          value: candidate,
          discard: () => candidate.free(),
        };
      },
    );
    try {
      accepted.acknowledgeCheckpointPersisted();
      nextClient.verifyServicePolicySession(provider.index, accepted);
      const view = accepted.offersJson();
      const scope = view.scopes.find((candidate) => candidate.scopeIdHex === provider.scopeIdHex);
      if (!scope
          || view.providerIdHex !== provider.providerIdHex
          || scope.workload !== 'dpf-query'
          || scope.backend !== 'dpf-pir'
          || scope.entitlementProfile !== provider.entitlementProfile
          || scope.offers.length !== provider.offers.length
          || !provider.offers.every((expected) => {
            const offer = scope.offers.find((candidate) => candidate.offerId === expected.offerId);
            const isFree = expected.method === 'free';
            return offer?.authorization === expected.method
              && offer.freeMode === expected.freeMode
              && (!isFree || offer.privacyLeakageBits === 1)
              && offer.deploymentStatus === expected.deploymentStatus
              && (expected.method !== 'arc-experimental'
                || offer.arcVerificationKeyFingerprintHex === provider.arcKeyIdHex)
              && offer.acquisition === (isFree ? 'free' : 'bolt11')
              && offer.endpoint === (isFree
                ? ''
                : `https://issuer-${provider.index}.fixture.invalid`);
          })) {
        throw new Error(`provider ${provider.index} live signed policy differs from the harness`);
      }
      fetched.push({ fixture: provider, policy: accepted, view, scope });
    } catch (error) {
      accepted.free();
      throw error;
    }
  }
  if (fetched.length !== 2) throw new Error('did not fetch two independent provider policies');
  legs = fetched as [LegStateV1, LegStateV1];
  return statuses;
}

async function verifyAndInstallSyntheticDatabaseProof(
  activeClient: WasmDpfClient,
  fixture: PaymentTwoProviderFixtureV1,
): Promise<void> {
  const expected = fixture.databaseProof;
  const catalog = await activeClient.fetchCatalog();
  try {
    const entry = catalog.getEntry(expected.dbId) as Record<string, unknown> | null;
    if (catalog.count !== 1
        || catalog.latestTip !== expected.height
        || !entry
        || entry.dbId !== expected.dbId
        || entry.dbType !== 0
        || entry.baseHeight !== expected.fromHeight
        || entry.height !== expected.height
        || entry.indexBins !== 128
        || entry.chunkBins !== 128
        || entry.indexK !== 75
        || entry.chunkK !== 80
        || entry.tagSeed !== `0x${expected.tagSeedHex}`
        || entry.dpfNIndex !== 7
        || entry.dpfNChunk !== 7
        || entry.hasBucketMerkle !== true
        || entry.indexMasterSeed !== `0x${expected.indexMasterSeedHex}`
        || entry.chunkMasterSeed !== `0x${expected.chunkMasterSeedHex}`
        || entry.anchorKind !== 1
        || entry.anchorHex !== expected.anchorHex
        || entry.anchorBlockHash !== expected.anchorHex.slice(0, 64)
        || entry.anchorHeight !== expected.height
        || entry.anchorVerified !== true) {
      throw new Error('live catalog did not match every pinned synthetic fixture field');
    }
  } finally {
    catalog.free();
  }

  let proof: Awaited<ReturnType<WasmDpfClient['verifyDatabaseProof']>> | null =
    await activeClient.verifyDatabaseProof(
      expected.dbId,
      expected.paramsHashHex,
      expected.builderBinarySha256Hex,
      expected.builderGitCommit,
    );
  try {
    if (proof.dbId !== expected.dbId
        || proof.buildKind !== expected.buildKind
        || proof.fromHeight !== expected.fromHeight
        || proof.fromBlockHashHex !== expected.fromBlockHashHex
        || proof.height !== expected.height
        || proof.blockHashHex !== expected.blockHashHex
        || proof.muhashHex !== expected.muhashHex
        || proof.bucketSuperRootHex !== expected.bucketSuperRootHex
        || proof.onionSuperRootHex !== expected.onionSuperRootHex
        || proof.onionEntrySize !== expected.onionEntrySize
        || proof.paramsHashHex !== expected.paramsHashHex
        || proof.networkMagicHex !== expected.networkMagicHex
        || proof.builderBinarySha256Hex !== expected.builderBinarySha256Hex
        || proof.builderGitCommit !== expected.builderGitCommit
        || proof.proofVersion !== expected.proofVersion) {
      throw new Error('verified database proof did not match every browser fixture pin');
    }
    // Ownership transfers by value only after the explicit application-level
    // pin comparison. Do not call free() on the consumed handle.
    activeClient.installVerifiedDatabaseProof(proof);
    proof = null;
  } finally {
    proof?.free();
  }
  // Preflight is intentionally deferred until both provider-specific payment
  // capabilities have committed, immediately before the expensive query.
}

async function closeClient(): Promise<void> {
  const oldLegs = legs;
  legs = null;
  selectedOffers = null;
  if (oldLegs) for (const leg of oldLegs) leg.policy.free();
  const oldClient = client;
  client = null;
  if (!oldClient) return;
  try {
    await oldClient.disconnect();
  } catch {
    // A test deliberately leaves granted/rejected sessions mid-protocol.
  }
  oldClient.free();
}

async function issuerFetch(
  index: 0 | 1,
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const leg = requireLeg(index);
  const offer = requireSelectedOffer(index);
  const requested = requestUrl(input);
  if (offer.acquisition !== 'bolt11'
      || requested.origin !== new URL(offer.endpoint).origin) {
    throw new Error(`provider ${index} fetch refused a non-policy issuer origin`);
  }
  const issuerOrigin = canonicalLoopbackOrigin(leg.fixture.issuerOrigin);
  const target = new URL(`${requested.pathname}${requested.search}`, `${issuerOrigin}/`);
  if (requireFixture().settlementMode === 'fake'
      && requested.pathname.endsWith('/status')) {
    await settleQuoteBeforeStatus(index, requested.pathname);
  }
  return fetch(target, init);
}

async function pollUntilSettled(acquisition: Bolt11AcquisitionHandleV1): Promise<void> {
  const external = requireFixture().settlementMode === 'external';
  const deadline = performance.now() + (external ? 20_000 : 3_000);
  for (;;) {
    const status = await acquisition.pollStatus();
    if (status === 'payment-settled') return;
    if (status !== 'invoice-open') {
      throw new Error(`BOLT11 acquisition reached terminal status ${status}`);
    }
    if (performance.now() >= deadline) {
      throw new Error('timed out waiting for the paid regtest invoice to settle');
    }
    await delay(external ? 100 : 25);
  }
}

async function settleQuoteBeforeStatus(index: 0 | 1, pathname: string): Promise<void> {
  const match = /^\/v1\/quotes\/([0-9a-f]{64})\/status$/.exec(pathname);
  if (!match) throw new Error('status URL did not carry one canonical quote ID');
  const quoteId = match[1];
  const settlementKey = `${index}:${quoteId}`;
  if (settledQuotes.has(settlementKey)) return;
  const leg = requireLeg(index);
  const offer = requireSelectedOffer(index);
  if (offer.price.kind !== 'msat') throw new Error('fixture price is not millisatoshi');
  const amount = BigInt(offer.price.amount);
  const body = new Uint8Array(48);
  body.set(hexToBytes(quoteId), 0);
  const view = new DataView(body.buffer);
  view.setBigUint64(32, amount, true);
  const settledAt = nowUnix();
  view.setBigUint64(40, settledAt, true);
  const response = await fetch(`${leg.fixture.issuerOrigin}/__test/fake/settle`, {
    method: 'POST',
    headers: { 'Content-Type': CT_FAKE_SETTLEMENT },
    body,
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  body.fill(0);
  if (!response.ok) throw new Error(`provider ${index} fake settlement failed: ${response.status}`);
  settledQuotes.add(settlementKey);
  const deadline = performance.now() + 2_000;
  while (nowUnix() <= settledAt) {
    if (performance.now() >= deadline) {
      throw new Error('test clock did not advance beyond fake settlement');
    }
    await delay(25);
  }
}

async function claimWhenClockAllows(acquisition: Bolt11AcquisitionHandleV1): Promise<number> {
  const deadline = performance.now() + 3_000;
  for (;;) {
    try {
      return await acquisition.claim();
    } catch (error) {
      const message = (error as Error).message;
      if (!message.includes('HTTP 503') || performance.now() >= deadline) throw error;
      const nextSecond = (Math.floor(Date.now() / 1_000) + 1) * 1_000 + 10;
      await delay(Math.max(25, nextSecond - Date.now()));
    }
  }
}

function bindingFor(
  leg: LegStateV1,
  offer: ServiceOfferViewV1,
): AdmissionCapabilityBindingV1 {
  const scheme = offer.authorization;
  if (scheme !== 'bolt11-direct-receipt'
      && scheme !== 'cashu-bat'
      && scheme !== 'arc-experimental') {
    throw new Error('browser harness selected an offer without a vault capability');
  }
  return {
    providerIdHex: leg.view.providerIdHex,
    policyDigestHex: leg.view.policyDigestHex,
    scopeIdHex: leg.scope.scopeIdHex,
    offerId: offer.offerId,
    scheme,
  };
}

function validateFixture(fixture: PaymentTwoProviderFixtureV1): void {
  if (!fixture.testOnly
      || !fixture.deterministic
      || fixture.fundsCapable
      || fixture.network !== 'regtest'
      || (fixture.settlementMode !== 'fake' && fixture.settlementMode !== 'external')
      || !fixture.boundary.includes('explicit NoSEV')
      || fixture.providers.length !== 2
      || fixture.providers[0]?.index !== 0
      || fixture.providers[1]?.index !== 1
      || fixture.providers[0]?.offers.length !== 2
      || fixture.providers[1]?.offers.length !== 2
      || !fixture.providers[0]?.offers.some((offer) =>
        offer.variant === 'direct-bat' && offer.method === 'bolt11-direct-receipt')
      || !fixture.providers[0]?.offers.some((offer) =>
        offer.variant === 'free-arc-experimental'
          && offer.method === 'free'
          && offer.freeMode === 'ip-rate-limited')
      || !fixture.providers[1]?.offers.some((offer) =>
        offer.variant === 'direct-bat' && offer.method === 'cashu-bat')
      || !fixture.providers[1]?.offers.some((offer) =>
        offer.variant === 'free-arc-experimental'
          && offer.method === 'arc-experimental'
          && offer.deploymentStatus === 'experimental')
      || fixture.providers[0]?.arcKeyIdHex !== null
      || fixture.providers[1]?.arcKeyIdHex === null
      || fixture.providers[0]?.providerIdHex === fixture.providers[1]?.providerIdHex
      || fixture.providers[0]?.policySigningPubkeyHex
        === fixture.providers[1]?.policySigningPubkeyHex
      || fixture.providers[0]?.issuerOrigin === fixture.providers[1]?.issuerOrigin
      || (fixture.settlementMode === 'fake'
        && fixture.providers[0]?.expectedPayeePubkeyHex
          === fixture.providers[1]?.expectedPayeePubkeyHex)
      || (fixture.settlementMode === 'external'
        && fixture.providers[0]?.expectedPayeePubkeyHex
          !== fixture.providers[1]?.expectedPayeePubkeyHex)
      || !fixture.databaseProof
      || fixture.databaseProof.dbId !== 0
      || fixture.databaseProof.buildKind !== 'snapshot'
      || fixture.databaseProof.fromHeight !== 0
      || fixture.databaseProof.fromBlockHashHex !== '0'.repeat(64)
      || fixture.databaseProof.networkMagicHex !== 'f9beb4d9'
      || fixture.databaseProof.proofVersion !== 1
      || !fixture.databaseProof.boundary.includes('not AMD SEV-SNP signature')) {
    throw new Error('browser harness refused a non-independent or funds-capable fixture');
  }
  exactHexBytes('manifestRootHex', fixture.manifestRootHex, 32);
  exactHexBytes('databaseProof.blockHashHex', fixture.databaseProof.blockHashHex, 32);
  exactHexBytes('databaseProof.anchorHex', fixture.databaseProof.anchorHex, 36);
  exactHexBytes('databaseProof.indexMasterSeedHex', fixture.databaseProof.indexMasterSeedHex, 8);
  exactHexBytes('databaseProof.chunkMasterSeedHex', fixture.databaseProof.chunkMasterSeedHex, 8);
  exactHexBytes('databaseProof.tagSeedHex', fixture.databaseProof.tagSeedHex, 8);
  exactHexBytes('databaseProof.muhashHex', fixture.databaseProof.muhashHex, 32);
  exactHexBytes('databaseProof.bucketSuperRootHex', fixture.databaseProof.bucketSuperRootHex, 32);
  exactHexBytes('databaseProof.onionSuperRootHex', fixture.databaseProof.onionSuperRootHex, 32);
  exactHexBytes('databaseProof.paramsHashHex', fixture.databaseProof.paramsHashHex, 32);
  exactHexBytes(
    'databaseProof.builderBinarySha256Hex',
    fixture.databaseProof.builderBinarySha256Hex,
    32,
  );
  if (!Number.isSafeInteger(fixture.databaseProof.height)
      || fixture.databaseProof.height <= 0
      || !Number.isSafeInteger(fixture.databaseProof.onionEntrySize)
      || fixture.databaseProof.onionEntrySize <= 0
      || !fixture.databaseProof.builderGitCommit
      || fixture.databaseProof.builderGitCommit.trim()
        !== fixture.databaseProof.builderGitCommit) {
    throw new Error('browser harness database-proof scalar pins are invalid');
  }
  for (const provider of fixture.providers) {
    exactHexBytes('providerIdHex', provider.providerIdHex, 32);
    exactHexBytes('policySigningPubkeyHex', provider.policySigningPubkeyHex, 32);
    exactHexBytes('issuerIdHex', provider.issuerIdHex, 32);
    exactHexBytes('scopeIdHex', provider.scopeIdHex, 32);
    if (provider.arcKeyIdHex !== null) {
      exactHexBytes('arcKeyIdHex', provider.arcKeyIdHex, 32);
    }
    exactHexBytes('expectedPayeePubkeyHex', provider.expectedPayeePubkeyHex, 33);
    if (!/^(02|03)[0-9a-f]{64}$/.test(provider.expectedPayeePubkeyHex)) {
      throw new Error('browser harness payee is not a compressed secp256k1 public key');
    }
    for (const offer of provider.offers) {
      if (!Number.isSafeInteger(offer.offerId) || offer.offerId <= 0) {
        throw new Error('browser harness offer ID is invalid');
      }
    }
    canonicalLoopbackOrigin(provider.issuerOrigin);
    const ws = new URL(provider.serverWsUrl);
    if (ws.protocol !== 'ws:'
        || ws.hostname !== '127.0.0.1'
        || ws.pathname !== '/'
        || ws.search
        || ws.hash
        || ws.username
        || ws.password
        || provider.serverWsUrl !== ws.toString()) {
      throw new Error('browser harness accepts only exact loopback provider WebSockets');
    }
  }
}

function exactHexBytes(field: string, value: string, length: number): Uint8Array {
  if (!new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)) {
    throw new Error(`${field} is not canonical lowercase ${length}-byte hex`);
  }
  const bytes = hexToBytes(value);
  if (bytes.every((byte) => byte === 0)) throw new Error(`${field} must be non-zero`);
  return bytes;
}

function canonicalLoopbackOrigin(value: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== 'http:'
      || parsed.hostname !== '127.0.0.1'
      || parsed.pathname !== '/'
      || parsed.search
      || parsed.hash
      || parsed.username
      || parsed.password) {
    throw new Error('browser harness accepts only exact HTTP 127.0.0.1 issuer origins');
  }
  return parsed.origin;
}

function requestUrl(input: RequestInfo | URL): URL {
  if (typeof input === 'string') return new URL(input);
  if (input instanceof URL) return new URL(input.toString());
  return new URL(input.url);
}

function requireFixture(): PaymentTwoProviderFixtureV1 {
  if (!fixtureState) throw new Error('browser harness fixture is not initialized');
  return fixtureState;
}

function requireClient(): WasmDpfClient {
  if (!client) throw new Error('browser harness transport is not connected');
  return client;
}

function requireLegs(): [LegStateV1, LegStateV1] {
  if (!legs) throw new Error('browser harness policies are not initialized');
  return legs;
}

function requireLeg(index: 0 | 1): LegStateV1 {
  return requireLegs()[index];
}

function requireSelectedVariant(): PaymentTwoProviderVariantV1 {
  if (!selectedVariant) throw new Error('select an exact two-provider payment variant first');
  return selectedVariant;
}

function requireSelectedOffer(index: 0 | 1): ServiceOfferViewV1 {
  if (!selectedOffers) throw new Error('select an exact two-provider payment variant first');
  return selectedOffers[index];
}

function nowUnix(): bigint {
  return BigInt(Math.floor(Date.now() / 1_000));
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length > haystack.length) return false;
  outer: for (let offset = 0; offset <= haystack.length - needle.length; offset += 1) {
    for (let index = 0; index < needle.length; index += 1) {
      if (haystack[offset + index] !== needle[index]) continue outer;
    }
    return true;
  }
  return false;
}

const api = {
  initialize,
  selectVariant,
  acquireLeg,
  startPaidLeg,
  finishPaidLeg,
  authorizeLeg,
  preflightAndQuery,
  replaySpentCapability,
  replayFreeQuota,
  capabilityCount,
  retainedReplayProofContains,
  verifiedOfferInventory,
  localStorageSnapshot,
};

declare global {
  interface Window {
    paymentTwoProviderTest: typeof api;
    __paymentTwoProviderLocalStorageWrites?: Array<[string, string]>;
  }
}

window.paymentTwoProviderTest = api;
window.addEventListener('pagehide', () => {
  for (const proof of replayProofs) proof?.fill(0);
  replayProofs[0] = null;
  replayProofs[1] = null;
  selectedVariant = null;
  selectedOffers = null;
  void closeClient();
  void vaultPromise?.then((opened) => opened.close());
  vaultPromise = null;
});

void initSdkWasm().then((ready) => {
  if (!ready) throw new Error('real pir-sdk-wasm failed to initialize');
  document.documentElement.dataset.paymentTwoProviderReady = 'true';
});
