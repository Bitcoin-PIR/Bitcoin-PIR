/**
 * Provider-independent V1 service admission orchestration.
 *
 * Pricing/offer choice is deliberately outside this class. The caller selects
 * one exact signed `scopeId + offerId` for each provider; this class only
 * enforces trust ordering, durable rollback state, proof lifecycle, and the
 * no-retry admission wire call.
 */

import {
  type AdmissionCredentialVaultV1,
  type AdmissionCapabilityBindingV1,
  type AdmissionCapabilityV1,
  type AdmissionSchemeV1,
} from './admission-vault.js';
import { hexToBytes } from './hash.js';
import {
  requireSdkWasm,
  type ServiceGrantViewV1,
  type ServiceOfferViewV1,
  type ServicePolicyViewV1,
  type ServiceScopeViewV1,
  type RetainedServiceRedemptionViewV1,
  type WasmAcceptedServicePolicyV1,
  type WasmAcceptedRetainedServiceRedemptionV1,
  type WasmServicePowChallengeV1,
} from './sdk-bridge.js';
import {
  assertIndependentProviderOfferPairV1,
  type IndependentProviderSelectionOptionsV1,
  type SelectedProviderOfferV1,
} from './provider-payment-selection.js';
import {
  Bolt11AcquisitionControllerV1,
  type Bolt11AcquisitionHandleV1,
} from './service-acquisition.js';
import { canonicalServiceEntitlementLimitsV1 } from './service-entitlement.js';

// Unexported symbols make a verified single-provider or pair typestate the only
// public route to authorization/acquisition transitions. No symbol, peer
// identity, or pair identifier ever crosses a network boundary.
const PAIR_SELECTION_V1 = Symbol('BitcoinPIR/verified-pair-selection/v1');
const PAIR_AUTHORIZATION_V1 = Symbol('BitcoinPIR/verified-pair-authorization/v1');
const PAIR_ACQUISITION_V1 = Symbol('BitcoinPIR/verified-pair-acquisition/v1');
const PAIR_CASHU_IMPORT_V1 = Symbol('BitcoinPIR/verified-pair-cashu-import/v1');

export interface ProviderTrustAnchorV1 {
  /** Pinned 32-byte provider identity, independent of the peer PIR server. */
  providerId: Uint8Array;
  /** Pinned provider policy Ed25519 public key. Providers use distinct keys. */
  policySigningKey: Uint8Array;
  /**
   * Exact directory assertion that must be closed against the live, already
   * verified operator identity and the fetched policy. Omit only for a fully
   * manual trust anchor configured outside the directory.
   */
  directoryAssertion?: {
    operatorSigningKeyEd25519: Uint8Array;
    stableServerId: string;
    policyEpoch: bigint;
    policyDigest: Uint8Array;
  };
}

export interface ServiceAdmissionPortV1 {
  /** Fail before policy I/O unless the live strict identity closes the anchor. */
  assertTrustAnchor(trust: ProviderTrustAnchorV1): void;
  fetchPolicy(
    expectedProviderId: Uint8Array,
    policySigningKey: Uint8Array,
    nowUnix: bigint,
    checkpointBytes: Uint8Array,
  ): Promise<WasmAcceptedServicePolicyV1>;
  /** Fetch exactly one historical signed selector for redemption only. */
  fetchRetainedRedemption?(
    expectedProviderId: Uint8Array,
    policySigningKey: Uint8Array,
    expectedPolicyDigest: Uint8Array,
    scopeId: Uint8Array,
    offerId: number,
    nowUnix: bigint,
  ): Promise<WasmAcceptedRetainedServiceRedemptionV1>;
  /** Fail synchronously unless the policy came from this live channel session. */
  assertSessionBinding(policy: WasmAcceptedServicePolicyV1): void;
  /**
   * Fail synchronously unless the complete strict admission owner is still
   * current. Pair adapters include both independently verified legs and the
   * exact database/tree-top preflight in this guard.
   */
  captureReadinessGuard(): () => void;
  assertRetainedSessionBinding?(
    policy: WasmAcceptedRetainedServiceRedemptionV1,
    nowUnix: bigint,
  ): void;
  authorize(
    policy: WasmAcceptedServicePolicyV1,
    scopeId: Uint8Array,
    offerId: number,
    proofBytes: Uint8Array,
  ): Promise<ServiceGrantViewV1>;
  authorizeRetained?(
    policy: WasmAcceptedRetainedServiceRedemptionV1,
    proofBytes: Uint8Array,
    nowUnix: bigint,
  ): Promise<ServiceGrantViewV1>;
  requestPowChallenge(
    policy: WasmAcceptedServicePolicyV1,
    scopeId: Uint8Array,
    offerId: number,
    nowUnix: bigint,
  ): Promise<WasmServicePowChallengeV1>;
}

type RetainedServiceAdmissionPortV1 = Required<Pick<
  ServiceAdmissionPortV1,
  'fetchRetainedRedemption' | 'assertRetainedSessionBinding' | 'authorizeRetained'
>>;

export interface ServiceAdmissionTargetV1 {
  backend: ServiceScopeViewV1['backend'];
  workload: ServiceScopeViewV1['workload'];
  /** Exact wire version supported by this already-verified adapter. */
  protocolVersion: number;
  /** Exact manifest root established by database proof/tree-top preflight. */
  expectedDatasetManifestRootHex: string;
  /** Optional independently trusted opaque profile pins. */
  operationProfile?: number;
  entitlementProfile?: number;
}

/** Narrow vault surface makes admission orchestration testable and auditable. */
export interface ServiceAdmissionVaultV1 {
  advancePolicyCheckpoint<T>(
    providerIdHex: string,
    initialCheckpoint: Uint8Array,
    advance: (currentCheckpoint: Uint8Array) => Promise<{
      nextCheckpoint: Uint8Array;
      value: T;
      discard?: () => void;
    }> | {
      nextCheckpoint: Uint8Array;
      value: T;
      discard?: () => void;
    },
  ): Promise<T>;
  takeSingleUseCapability(
    binding: AdmissionCapabilityBindingV1,
    validateBeforeRetire?: (payload: Uint8Array) => void,
  ): Promise<AdmissionCapabilityV1 | null>;
  advanceArcCredential(
    binding: AdmissionCapabilityBindingV1,
    advance: (serializedState: Uint8Array) => {
      nextState: Uint8Array;
      remaining: number;
      releaseAfterPersisted: () => Uint8Array;
      discard: () => void;
    },
  ): Promise<Uint8Array | null>;
}

interface StrictArcPreparedPresentationV1 {
  free(): void;
  successor_state_bytes(): Uint8Array;
  remaining(): bigint;
  release_after_persisted(): Uint8Array;
}

interface StrictArcPresentationStateV1 {
  free(): void;
  prepare_presentation(): StrictArcPreparedPresentationV1;
}

export interface ServiceAuthorizationOptionsV1 {
  /** Optional cancellation for browser PoW; never triggers token retry. */
  signal?: AbortSignal;
  /** Bounded work per event-loop slice. */
  powChunkAttempts?: number;
}

export interface ProviderAdmissionSelectionV1 {
  session: ProviderAdmissionSessionV1;
  scopeIdHex: string;
  offerId: number;
}

/**
 * One provider leg plus the independently trusted network context that must be
 * frozen before a two-provider capability can be acquired or retired.
 * `expectedLightningPayeePubkey` is mandatory for a BOLT11 offer and omitted
 * for every non-BOLT11 offer.
 */
export interface IndependentProviderAdmissionSelectionV1
  extends ProviderAdmissionSelectionV1 {
  providerEndpoint: string;
  expectedLightningPayeePubkey?: Uint8Array;
}

export type ProviderPairSideV1 = 'first' | 'second';

export interface ProviderPairBolt11AcquisitionOptionsV1 {
  vault: AdmissionCredentialVaultV1;
  network: 'bitcoin' | 'testnet' | 'signet' | 'regtest';
  expectedPayeePubkey: Uint8Array;
  fetchImpl?: typeof fetch;
  requestTimeoutMs?: number;
  /** Development-only support for the loopback fake issuer. */
  allowInsecureLoopback?: boolean;
  /** Additional browser-local product generation/pair guard. */
  assertReady?: () => void;
}

export interface StandardCashuImportOptionsV1 {
  vault: AdmissionCredentialVaultV1;
  /** Standard Cashu `cashuA` (V3) or `cashuB` (V4) wallet token. */
  serializedToken: string;
}

/**
 * The proof was retired/advanced before the one-shot wire call. The caller
 * must not retry with the same bytes; obtain a fresh proof or reconnect and
 * let product policy decide what to do.
 */
export class AmbiguousCapabilitySpendErrorV1 extends Error {
  readonly capabilityMayBeSpent = true;

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AmbiguousCapabilitySpendErrorV1';
  }
}

export class ProviderAdmissionSessionV1 {
  private accepted: WasmAcceptedServicePolicyV1 | null = null;
  private view: ServicePolicyViewV1 | null = null;
  private policyRevision = 0;
  private transitionInFlight:
    | 'refresh'
    | 'acquire'
    | 'import-cashu'
    | 'authorize'
    | 'inspect-retained'
    | 'authorize-retained'
    | null = null;

  constructor(
    private readonly vault: ServiceAdmissionVaultV1,
    private readonly port: ServiceAdmissionPortV1,
    private readonly trust: ProviderTrustAnchorV1,
    private readonly target: ServiceAdmissionTargetV1,
  ) {
    requireFixedNonzero('providerId', trust.providerId, 32);
    requireFixedNonzero('policySigningKey', trust.policySigningKey, 32);
    validateDirectoryAssertion(trust);
    validateAdmissionTarget(target);
  }

  /**
   * Fetch and verify policy only after the adapter has completed strict
   * identity/channel/database-root verification. Persisting its checkpoint is
   * mandatory before the handle can authorize anything.
   */
  async refreshPolicy(nowUnix = trustedNowUnix()): Promise<ServicePolicyViewV1> {
    this.beginTransition('refresh');
    try {
    const providerIdHex = bytesToLowerHex(this.trust.providerId);
    const sdk = requireSdkWasm();
    // This check closes directory discovery to the exact live server before
    // any policy, offer, issuer endpoint, or payment metadata is requested.
    this.port.assertTrustAnchor(this.trust);
    const initial = sdk.initialServicePolicyCheckpointV1();
    const accepted = await this.vault.advancePolicyCheckpoint(
      providerIdHex,
      initial,
      async (checkpoint) => {
        let next: WasmAcceptedServicePolicyV1 | null = null;
        try {
          next = await this.port.fetchPolicy(
            this.trust.providerId.slice(),
            this.trust.policySigningKey.slice(),
            nowUnix,
            checkpoint,
          );
          if (next.providerIdHex !== providerIdHex) {
            throw new Error('verified service policy provider ID does not match trust anchor');
          }
          const view = validatePolicyView(next, next.offersJson(), this.target, nowUnix);
          validateDirectoryPolicyBinding(this.trust, view);
          const retained = next;
          return {
            nextCheckpoint: next.checkpointBytes(),
            value: { handle: next, view },
            discard: () => retained.free(),
          };
        } catch (error) {
          next?.free();
          throw error;
        }
      },
    );
    const next = accepted.handle;
    try {
      // The vault returns only after the encrypted successor checkpoint is
      // durable; until this acknowledgement the WASM handle cannot authorize.
      next.acknowledgeCheckpointPersisted();

      const previous = this.accepted;
      this.accepted = next;
      this.view = accepted.view;
      this.policyRevision += 1;
      previous?.free();
      return structuredClonePolicy(accepted.view);
    } catch (error) {
      next.free();
      throw error;
    }
    } finally {
      this.transitionInFlight = null;
    }
  }

  policy(): ServicePolicyViewV1 | null {
    return this.view ? structuredClonePolicy(this.view) : null;
  }

  /** Browser-local trust metadata for pair-correlation preflight only. */
  trustAnchor(): ProviderTrustAnchorV1 {
    return cloneTrustAnchor(this.trust);
  }

  /** List metadata only. This method never picks a price or payment method. */
  offers(scopeIdHex: string): ServiceOfferViewV1[] {
    const scope = this.requireScope(scopeIdHex);
    return scope.offers.map((offer) => ({ ...offer, price: { ...offer.price } }));
  }

  [PAIR_SELECTION_V1](scopeIdHex: string, offerId: number): SessionPairSelectionV1 {
    const scope = this.requireScope(scopeIdHex);
    const offer = scope.offers.find((candidate) => candidate.offerId === offerId);
    if (!offer) throw new Error('selected offer is not present in the verified service policy');
    return {
      trust: cloneTrustAnchor(this.trust),
      offer: cloneOffer(offer),
      policyDigestHex: canonicalHex32('policyDigestHex', this.view!.policyDigestHex),
      policyRevision: this.policyRevision,
      offerFingerprint: offerFingerprintV1(offer),
    };
  }

  /**
   * Authorize exactly one signed offer. Paid/single-use material is retired
   * (or ARC state advanced) before the request is allowed onto the network.
   * There is deliberately no automatic retry.
   */
  async [PAIR_AUTHORIZATION_V1](
    selection: SessionPairSelectionV1,
    scopeIdHex: string,
    offerId: number,
    options: ServiceAuthorizationOptionsV1 = {},
  ): Promise<ServiceGrantViewV1> {
    this.beginTransition('authorize');
    try {
      this.assertCurrentPairSelection(selection, scopeIdHex, offerId);
    const accepted = this.accepted;
    if (!accepted || !this.view) throw new Error('fetch and persist service policy first');
    this.port.assertSessionBinding(accepted);
    const nowUnix = trustedNowUnix();
    if (BigInt(this.view.expiresAtUnix) < nowUnix) {
      throw new Error('service policy expired; fetch a fresh verified policy');
    }
    const scope = this.requireScope(scopeIdHex);
    const offer = scope.offers.find((candidate) => candidate.offerId === offerId);
    if (!offer) throw new Error('selected offer is not present in the verified service policy');
    const scopeId = hexToBytes32('scopeIdHex', scope.scopeIdHex);
    let retiredOrAdvanced = false;
    let proof: Uint8Array;

    if (offer.authorization === 'free') {
      if (offer.freeMode === 'open-best-effort' || offer.freeMode === 'ip-rate-limited') {
        proof = new Uint8Array();
        accepted.validateAuthorizationProof(scopeId, offerId, proof);
      } else if (offer.freeMode === 'proof-of-work') {
        proof = await this.solvePow(accepted, scopeId, offer, options);
        // A challenge is connection-bound and one-shot even though it is free.
        retiredOrAdvanced = true;
      } else if (offer.freeMode === 'anonymous-ticket') {
        proof = await this.retireSingleUse(accepted, scope, offer, 'free-anonymous-ticket');
        retiredOrAdvanced = true;
      } else {
        throw new Error('verified free offer has an unsupported free mode');
      }
    } else if (offer.authorization === 'arc-experimental') {
      if (offer.deploymentStatus !== 'experimental') {
        throw new Error('ARC is allowed only when the signed offer marks it experimental');
      }
      const binding = capabilityBinding(
        this.view.providerIdHex,
        this.view.policyDigestHex,
        scope,
        offer,
        'arc-experimental',
      );
      const presentation = await this.vault.advanceArcCredential(binding, (serializedState) => {
        const state = requireSdkWasm().WasmArcPresentationState.deserialize(
          serializedState,
        ) as unknown as StrictArcPresentationStateV1;
        let prepared: StrictArcPreparedPresentationV1 | null = null;
        try {
          prepared = state.prepare_presentation();
          const remaining = Number(prepared.remaining());
          return {
            nextState: prepared.successor_state_bytes(),
            remaining,
            releaseAfterPersisted: () => {
              const transition = prepared!;
              let nextPresentation: Uint8Array | null = null;
              try {
                nextPresentation = transition.release_after_persisted();
                accepted.validateAuthorizationProof(scopeId, offerId, nextPresentation);
                return nextPresentation;
              } catch (error) {
                nextPresentation?.fill(0);
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
      });
      if (!presentation) throw new Error('no ARC credential is available for this exact offer');
      proof = presentation;
      retiredOrAdvanced = true;
    } else {
      proof = await this.retireSingleUse(
        accepted,
        scope,
        offer,
        schemeForPaidOffer(offer.authorization),
      );
      retiredOrAdvanced = true;
    }

    // No refresh/close can interleave while this transition is in flight.
    // Recheck immediately before the one-shot network boundary anyway, so a
    // future refactor cannot silently weaken the frozen pair binding.
    try {
      this.assertCurrentPairSelection(selection, scopeIdHex, offerId);
      this.port.assertSessionBinding(accepted);
      const grant = await this.port.authorize(accepted, scopeId, offerId, proof);
      if (
        grant.scopeIdHex !== scope.scopeIdHex
        || grant.enforcedProfile !== scope.entitlementProfile
      ) {
        throw new Error('authorization grant does not match selected scope/profile');
      }
      return { ...grant };
    } catch (cause) {
      if (retiredOrAdvanced) {
        throw new AmbiguousCapabilitySpendErrorV1(
          'service authorization failed after a one-shot proof was retired; do not retry it',
          { cause },
        );
      }
      throw cause;
    } finally {
      proof.fill(0);
    }
    } finally {
      this.transitionInFlight = null;
    }
  }

  /**
   * Redeem an already-purchased capability against its exact historical
   * signed policy. This path deliberately has no acquisition, policy
   * checkpoint, offer-selection, free/PoW, or automatic-retry surface.
   */
  async authorizeRetainedCapability(
    binding: AdmissionCapabilityBindingV1,
  ): Promise<ServiceGrantViewV1> {
    this.beginTransition('authorize-retained');
    let retained: WasmAcceptedRetainedServiceRedemptionV1 | null = null;
    try {
      const canonical = exactRetainedBinding(binding, this.trust);
      const nowUnix = trustedNowUnix();
      const retainedPort = requireRetainedServicePort(this.port);
      this.port.assertTrustAnchor(this.trust);
      retained = await retainedPort.fetchRetainedRedemption(
        this.trust.providerId.slice(),
        this.trust.policySigningKey.slice(),
        hexToBytes32('policyDigestHex', canonical.policyDigestHex),
        hexToBytes32('scopeIdHex', canonical.scopeIdHex),
        canonical.offerId,
        nowUnix,
      );
      assertRetainedHandleMatchesBinding(retained, canonical);
      retained.assertRedemptionReady(nowUnix);
      const retainedView = validateRetainedRedemptionView(
        retained.redemptionJson(nowUnix),
        canonical,
        this.target,
      );
      retainedPort.assertRetainedSessionBinding(retained, nowUnix);

      const proof = await this.retireRetainedCapability(retained, canonical);
      // Repeat the live-channel and grace check immediately after the durable
      // local retirement and before the one-shot network boundary.
      try {
        retained.assertRedemptionReady(nowUnix);
        retainedPort.assertRetainedSessionBinding(retained, nowUnix);
        const grant = await retainedPort.authorizeRetained(retained, proof, nowUnix);
        if (canonicalHex32('retained grant scopeIdHex', grant.scopeIdHex)
            !== canonical.scopeIdHex
            || grant.enforcedProfile !== retainedView.scope.entitlementProfile) {
          throw new Error('retained authorization grant does not match the exact scope/profile');
        }
        return { ...grant };
      } catch (cause) {
        throw new AmbiguousCapabilitySpendErrorV1(
          'retained service authorization failed after a one-shot proof was retired; do not retry it',
          { cause },
        );
      } finally {
        proof.fill(0);
      }
    } finally {
      retained?.free();
      this.transitionInFlight = null;
    }
  }

  /** Fetch and verify historical public metadata without touching a proof. */
  async inspectRetainedCapability(
    binding: AdmissionCapabilityBindingV1,
  ): Promise<RetainedServiceRedemptionViewV1> {
    this.beginTransition('inspect-retained');
    let retained: WasmAcceptedRetainedServiceRedemptionV1 | null = null;
    try {
      const canonical = exactRetainedBinding(binding, this.trust);
      const nowUnix = trustedNowUnix();
      const retainedPort = requireRetainedServicePort(this.port);
      this.port.assertTrustAnchor(this.trust);
      retained = await retainedPort.fetchRetainedRedemption(
        this.trust.providerId.slice(),
        this.trust.policySigningKey.slice(),
        hexToBytes32('policyDigestHex', canonical.policyDigestHex),
        hexToBytes32('scopeIdHex', canonical.scopeIdHex),
        canonical.offerId,
        nowUnix,
      );
      assertRetainedHandleMatchesBinding(retained, canonical);
      retained.assertRedemptionReady(nowUnix);
      retainedPort.assertRetainedSessionBinding(retained, nowUnix);
      return cloneRetainedRedemptionView(
        validateRetainedRedemptionView(
          retained.redemptionJson(nowUnix),
          canonical,
          this.target,
        ),
      );
    } finally {
      retained?.free();
      this.transitionInFlight = null;
    }
  }

  async [PAIR_ACQUISITION_V1](
    selection: SessionPairSelectionV1,
    scopeIdHex: string,
    offerId: number,
    options: ProviderPairBolt11AcquisitionOptionsV1,
  ): Promise<Bolt11AcquisitionHandleV1> {
    this.beginTransition('acquire');
    try {
      this.assertCurrentPairSelection(selection, scopeIdHex, offerId);
      const accepted = this.accepted;
      if (!accepted || !this.view) throw new Error('fetch and persist service policy first');
      const scope = this.requireScope(scopeIdHex);
      const offer = scope.offers.find((candidate) => candidate.offerId === offerId);
      if (!offer) throw new Error('selected offer is not present in the verified service policy');
      const assertStrictReady = this.port.captureReadinessGuard();
      // This composite guard is passed into the BOLT11 controller and re-run
      // after delegation/vault/recovery awaits, immediately before quote POST,
      // and again before a verified invoice can escape to the UI.
      const assertReady = () => {
        options.assertReady?.();
        this.assertCurrentPairSelection(selection, scopeIdHex, offerId);
        assertStrictReady();
        this.port.assertSessionBinding(accepted);
        if (!this.view || BigInt(this.view.expiresAtUnix) < trustedNowUnix()) {
          throw new Error('service policy expired; fetch a fresh verified policy');
        }
      };
      assertReady();
      return await Bolt11AcquisitionControllerV1.start({
        vault: options.vault,
        policy: accepted,
        scope,
        offer,
        network: options.network,
        expectedPayeePubkey: options.expectedPayeePubkey,
        fetchImpl: options.fetchImpl,
        requestTimeoutMs: options.requestTimeoutMs,
        allowInsecureLoopback: options.allowInsecureLoopback,
        assertReady,
      });
    } finally {
      this.transitionInFlight = null;
    }
  }

  async [PAIR_CASHU_IMPORT_V1](
    selection: SessionPairSelectionV1,
    scopeIdHex: string,
    offerId: number,
    options: StandardCashuImportOptionsV1,
  ): Promise<string> {
    this.beginTransition('import-cashu');
    try {
      this.assertCurrentPairSelection(selection, scopeIdHex, offerId);
      const accepted = this.accepted;
      if (!accepted || !this.view) throw new Error('fetch and persist service policy first');
      this.port.assertSessionBinding(accepted);
      const nowUnix = trustedNowUnix();
      if (BigInt(this.view.expiresAtUnix) < nowUnix) {
        throw new Error('service policy expired; fetch a fresh verified policy');
      }
      const scope = this.requireScope(scopeIdHex);
      const offer = scope.offers.find((candidate) => candidate.offerId === offerId);
      if (!offer
          || offer.acquisition !== 'cashu-ecash'
          || offer.authorization !== 'cashu-ecash'
          || offer.verification !== 'standard-cashu-mint-online') {
        throw new Error('selected signed offer is not standard Cashu eCash');
      }
      if (typeof options.serializedToken !== 'string' || options.serializedToken.length === 0) {
        throw new Error('serialized Cashu token must be a non-empty string');
      }
      const scopeId = hexToBytes32('scopeIdHex', scope.scopeIdHex);
      const payload = accepted.importStandardCashuToken(
        scopeId,
        offer.offerId,
        options.serializedToken,
        nowUnix,
      );
      try {
        accepted.validateAuthorizationProof(scopeId, offer.offerId, payload);
        this.assertCurrentPairSelection(selection, scopeIdHex, offerId);
        this.port.assertSessionBinding(accepted);
        return await options.vault.putCapability({
          ...capabilityBinding(
            this.view.providerIdHex,
            this.view.policyDigestHex,
            scope,
            offer,
            'cashu-ecash',
          ),
          payload,
        });
      } finally {
        payload.fill(0);
      }
    } finally {
      this.transitionInFlight = null;
    }
  }

  close(): void {
    if (this.transitionInFlight !== null) {
      throw new Error(`cannot close service admission during ${this.transitionInFlight}`);
    }
    this.accepted?.free();
    this.accepted = null;
    this.view = null;
    this.policyRevision += 1;
  }

  private beginTransition(
    kind:
      | 'refresh'
      | 'acquire'
      | 'import-cashu'
      | 'authorize'
      | 'inspect-retained'
      | 'authorize-retained',
  ): void {
    if (this.transitionInFlight !== null) {
      throw new Error(
        `service admission ${this.transitionInFlight} transition is already in flight`,
      );
    }
    this.transitionInFlight = kind;
  }

  private assertCurrentPairSelection(
    selection: SessionPairSelectionV1,
    scopeIdHex: string,
    offerId: number,
  ): void {
    if (!this.view || !this.accepted
        || selection.policyRevision !== this.policyRevision
        || selection.policyDigestHex
          !== canonicalHex32('current policy digest', this.view.policyDigestHex)) {
      throw new Error('provider policy changed after strict pair verification');
    }
    const scope = this.requireScope(scopeIdHex);
    const offer = scope.offers.find((candidate) => candidate.offerId === offerId);
    if (!offer || offerFingerprintV1(offer) !== selection.offerFingerprint) {
      throw new Error('provider offer changed after strict pair verification');
    }
  }

  private requireScope(scopeIdHex: string): ServiceScopeViewV1 {
    if (!this.view) throw new Error('fetch and persist service policy first');
    const canonical = canonicalHex32('scopeIdHex', scopeIdHex);
    const scope = this.view.scopes.find((candidate) => candidate.scopeIdHex === canonical);
    if (!scope) throw new Error('selected scope is not present in the verified service policy');
    if (!scopeMatchesTargetV1(scope, this.target)) {
      throw new Error('selected scope does not match this adapter wire/profile target');
    }
    return scope;
  }

  private async retireSingleUse(
    accepted: WasmAcceptedServicePolicyV1,
    scope: ServiceScopeViewV1,
    offer: ServiceOfferViewV1,
    scheme: AdmissionSchemeV1,
  ): Promise<Uint8Array> {
    const scopeId = hexToBytes32('scopeIdHex', scope.scopeIdHex);
    const capability = await this.vault.takeSingleUseCapability(
      capabilityBinding(
        this.view!.providerIdHex,
        this.view!.policyDigestHex,
        scope,
        offer,
        scheme,
      ),
      (candidate) => accepted.validateAuthorizationProof(scopeId, offer.offerId, candidate),
    );
    if (!capability) {
      throw new Error(`no ${scheme} capability is available for this exact provider offer`);
    }
    return capability.payload;
  }

  private async retireRetainedCapability(
    accepted: WasmAcceptedRetainedServiceRedemptionV1,
    binding: AdmissionCapabilityBindingV1,
  ): Promise<Uint8Array> {
    if (binding.scheme === 'arc-experimental') {
      const presentation = await this.vault.advanceArcCredential(binding, (serializedState) => {
        const state = requireSdkWasm().WasmArcPresentationState.deserialize(
          serializedState,
        ) as unknown as StrictArcPresentationStateV1;
        let prepared: StrictArcPreparedPresentationV1 | null = null;
        try {
          prepared = state.prepare_presentation();
          const remaining = Number(prepared.remaining());
          return {
            nextState: prepared.successor_state_bytes(),
            remaining,
            releaseAfterPersisted: () => {
              const transition = prepared!;
              let nextPresentation: Uint8Array | null = null;
              try {
                nextPresentation = transition.release_after_persisted();
                accepted.validateAuthorizationProof(nextPresentation);
                return nextPresentation;
              } catch (error) {
                nextPresentation?.fill(0);
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
      });
      if (!presentation) {
        throw new Error('no retained ARC credential is available for this exact offer');
      }
      return presentation;
    }

    const capability = await this.vault.takeSingleUseCapability(
      binding,
      (candidate) => accepted.validateAuthorizationProof(candidate),
    );
    if (!capability) {
      throw new Error(`no retained ${binding.scheme} capability is available for this exact offer`);
    }
    return capability.payload;
  }

  private async solvePow(
    accepted: WasmAcceptedServicePolicyV1,
    scopeId: Uint8Array,
    offer: ServiceOfferViewV1,
    options: ServiceAuthorizationOptionsV1,
  ): Promise<Uint8Array> {
    const attempts = options.powChunkAttempts ?? 50_000;
    if (!Number.isSafeInteger(attempts) || attempts <= 0 || attempts > 1_000_000) {
      throw new Error('powChunkAttempts must be within 1..=1000000');
    }
    const challenge = await this.port.requestPowChallenge(
      accepted,
      scopeId,
      offer.offerId,
      trustedNowUnix(),
    );
    try {
      let nonce = 0n;
      const maxNonce = 0xffff_ffff_ffff_ffffn;
      for (;;) {
        if (options.signal?.aborted) throw new DOMException('PoW cancelled', 'AbortError');
        if (trustedNowUnix() > BigInt(challenge.expiresAtUnix)) {
          throw new Error('proof-of-work challenge expired before a solution was found');
        }
        const proof = challenge.solveChunk(nonce, attempts);
        if (proof.length > 0) {
          accepted.validateAuthorizationProof(scopeId, offer.offerId, proof);
          return proof;
        }
        const next = nonce + BigInt(attempts);
        if (next > maxNonce) throw new Error('proof-of-work nonce space exhausted');
        nonce = next;
        await yieldToBrowser();
      }
    } finally {
      challenge.free();
    }
  }
}

interface SessionPairSelectionV1 extends SelectedProviderOfferV1 {
  policyDigestHex: string;
  policyRevision: number;
  offerFingerprint: string;
}

interface PairLegV1 extends IndependentProviderAdmissionSelectionV1 {
  verified: SessionPairSelectionV1;
}

interface SingleLegV1 extends ProviderAdmissionSelectionV1 {
  verified: SessionPairSelectionV1;
}

/**
 * Browser-local typestate for a backend that genuinely uses one provider
 * (currently OnionPIR and direct TEE-ORAM). It freezes one exact signed offer
 * but does not invent a peer provider or apply two-provider independence rules.
 */
export class VerifiedSingleProviderOfferV1 {
  private constructor(private readonly leg: SingleLegV1) {}

  static create(selection: ProviderAdmissionSelectionV1): VerifiedSingleProviderOfferV1 {
    validateAdmissionSelection('single provider', selection);
    const verified = selection.session[PAIR_SELECTION_V1](
      selection.scopeIdHex,
      selection.offerId,
    );
    return new VerifiedSingleProviderOfferV1({
      ...selection,
      scopeIdHex: canonicalHex32('single provider scopeIdHex', selection.scopeIdHex),
      verified,
    });
  }

  offer(): ServiceOfferViewV1 {
    return cloneOffer(this.leg.verified.offer);
  }

  trust(): ProviderTrustAnchorV1 {
    return cloneTrustAnchor(this.leg.verified.trust);
  }

  authorize(options: ServiceAuthorizationOptionsV1 = {}): Promise<ServiceGrantViewV1> {
    return this.leg.session[PAIR_AUTHORIZATION_V1](
      this.leg.verified,
      this.leg.scopeIdHex,
      this.leg.offerId,
      options,
    );
  }

  startBolt11Acquisition(
    options: ProviderPairBolt11AcquisitionOptionsV1,
  ): Promise<Bolt11AcquisitionHandleV1> {
    return this.leg.session[PAIR_ACQUISITION_V1](
      this.leg.verified,
      this.leg.scopeIdHex,
      this.leg.offerId,
      options,
    );
  }

  importStandardCashuToken(options: StandardCashuImportOptionsV1): Promise<string> {
    return this.leg.session[PAIR_CASHU_IMPORT_V1](
      this.leg.verified,
      this.leg.scopeIdHex,
      this.leg.offerId,
      options,
    );
  }
}

/**
 * Browser-local typestate proving that both independently discovered provider
 * selections passed the strict correlation checks. It deliberately exposes
 * one authorization call per leg rather than an automatic two-leg retry.
 */
export class VerifiedIndependentProviderPairV1 {
  private constructor(
    private readonly first: PairLegV1,
    private readonly second: PairLegV1,
  ) {}

  static create(
    first: IndependentProviderAdmissionSelectionV1,
    second: IndependentProviderAdmissionSelectionV1,
    options: IndependentProviderSelectionOptionsV1 = {},
  ): VerifiedIndependentProviderPairV1 {
    if (first.session === second.session) {
      throw new Error('the two PIR selections must use distinct admission sessions');
    }
    validateAdmissionSelection('first pair', first);
    validateAdmissionSelection('second pair', second);
    const firstVerified = first.session[PAIR_SELECTION_V1](first.scopeIdHex, first.offerId);
    const secondVerified = second.session[PAIR_SELECTION_V1](second.scopeIdHex, second.offerId);
    const firstPayment = freezeProviderPaymentContextV1('first pair', first, firstVerified.offer);
    const secondPayment = freezeProviderPaymentContextV1('second pair', second, secondVerified.offer);
    assertIndependentProviderOfferPairV1(
      { ...firstVerified, ...firstPayment },
      { ...secondVerified, ...secondPayment },
      options,
    );
    return new VerifiedIndependentProviderPairV1(
      {
        ...first,
        ...firstPayment,
        scopeIdHex: canonicalHex32('first scopeIdHex', first.scopeIdHex),
        verified: firstVerified,
      },
      {
        ...second,
        ...secondPayment,
        scopeIdHex: canonicalHex32('second scopeIdHex', second.scopeIdHex),
        verified: secondVerified,
      },
    );
  }

  offer(side: ProviderPairSideV1): ServiceOfferViewV1 {
    return cloneOffer(this.leg(side).verified.offer);
  }

  trust(side: ProviderPairSideV1): ProviderTrustAnchorV1 {
    return cloneTrustAnchor(this.leg(side).verified.trust);
  }

  /** Authorize one provider exactly once; callers decide ordering. */
  authorize(
    side: ProviderPairSideV1,
    options: ServiceAuthorizationOptionsV1 = {},
  ): Promise<ServiceGrantViewV1> {
    const leg = this.leg(side);
    return leg.session[PAIR_AUTHORIZATION_V1](
      leg.verified,
      leg.scopeIdHex,
      leg.offerId,
      options,
    );
  }

  /**
   * Start invoice acquisition only after both exact offers passed the strict
   * pair checks. Each leg still creates and pays its own independent invoice.
   */
  startBolt11Acquisition(
    side: ProviderPairSideV1,
    options: ProviderPairBolt11AcquisitionOptionsV1,
  ): Promise<Bolt11AcquisitionHandleV1> {
    const leg = this.leg(side);
    const frozenPayee = leg.expectedLightningPayeePubkey;
    if (leg.verified.offer.acquisition !== 'bolt11' || frozenPayee === undefined) {
      throw new Error('selected provider payment context is not a frozen BOLT11 leg');
    }
    if (!equalBytes(frozenPayee, options.expectedPayeePubkey)) {
      throw new Error('BOLT11 payee differs from the independently frozen provider context');
    }
    return leg.session[PAIR_ACQUISITION_V1](
      leg.verified,
      leg.scopeIdHex,
      leg.offerId,
      { ...options, expectedPayeePubkey: frozenPayee.slice() },
    );
  }

  /** Import one wallet token only after both exact provider offers passed the pair checks. */
  importStandardCashuToken(
    side: ProviderPairSideV1,
    options: StandardCashuImportOptionsV1,
  ): Promise<string> {
    const leg = this.leg(side);
    return leg.session[PAIR_CASHU_IMPORT_V1](
      leg.verified,
      leg.scopeIdHex,
      leg.offerId,
      options,
    );
  }

  private leg(side: ProviderPairSideV1): PairLegV1 {
    if (side === 'first') return this.first;
    if (side === 'second') return this.second;
    throw new Error('provider pair side must be first or second');
  }
}

export interface LiveOperatorIdentityV1 {
  state: string;
  serverId?: string;
  operatorPubkeyHex?: string;
}

/** Close a directory assertion to one live identity already verified by the adapter. */
export function assertLiveOperatorIdentityV1(
  trust: ProviderTrustAnchorV1,
  identity: LiveOperatorIdentityV1,
): void {
  const expected = trust.directoryAssertion;
  if (!expected) return;
  if (identity.state !== 'verified') {
    throw new Error('directory-selected provider does not have a verified live operator identity');
  }
  if (identity.serverId !== expected.stableServerId) {
    throw new Error('live operator server ID does not match the directory assertion');
  }
  const liveKey = identity.operatorPubkeyHex === undefined
    ? ''
    : canonicalHex32('live operator public key', identity.operatorPubkeyHex);
  if (liveKey !== bytesToLowerHex(expected.operatorSigningKeyEd25519)) {
    throw new Error('live operator public key does not match the directory assertion');
  }
}

function validatePolicyView(
  accepted: WasmAcceptedServicePolicyV1,
  view: ServicePolicyViewV1,
  target: ServiceAdmissionTargetV1,
  nowUnix: bigint,
): ServicePolicyViewV1 {
  if (
    view.providerIdHex !== accepted.providerIdHex
    || view.policyDigestHex !== accepted.policyDigestHex
    || view.policyEpoch !== accepted.policyEpoch
    || view.expiresAtUnix !== accepted.expiresAtUnix
  ) {
    throw new Error('service policy metadata disagrees with verified handle');
  }
  if (BigInt(view.expiresAtUnix) < nowUnix) throw new Error('verified service policy is expired');
  if (!Array.isArray(view.scopes)) throw new Error('service policy scopes are malformed');
  const canonical = structuredClonePolicy(view);
  for (const [index, scope] of canonical.scopes.entries()) {
    canonicalHex32('scopeIdHex', scope.scopeIdHex);
    for (const [field, value] of [
      ['protocolVersion', scope.protocolVersion],
      ['operationProfile', scope.operationProfile],
      ['entitlementProfile', scope.entitlementProfile],
    ] as const) {
      if (!Number.isSafeInteger(value) || value <= 0 || value > 0xffff) {
        throw new Error(`service policy scope ${index} ${field} must be a non-zero u16`);
      }
    }
    scope.dataset = canonicalDatasetBindingViewV1(
      scope.dataset,
      `service policy scope ${index} dataset`,
    );
    scope.limits = canonicalServiceEntitlementLimitsV1(
      scope.limits,
      `service policy scope ${index} entitlement limits`,
    );
    if (!Array.isArray(scope.offers)) throw new Error('service policy scope offers are malformed');
    const ids = new Set<number>();
    for (const offer of scope.offers) {
      if (!Number.isSafeInteger(offer.offerId) || offer.offerId <= 0 || ids.has(offer.offerId)) {
        throw new Error('service policy view contains an invalid or duplicate offer ID');
      }
      ids.add(offer.offerId);
      validateOfferVerificationKeyFingerprints(offer);
    }
  }
  const wireDatasetMatching = canonical.scopes.filter(
    (scope) => scopeMatchesWireDatasetTargetV1(scope, target),
  );
  if (wireDatasetMatching.length !== 1) {
    throw new Error('service policy must have exactly one scope for this adapter wire/dataset target');
  }
  const matching = wireDatasetMatching.filter((scope) => scopeMatchesTargetV1(scope, target));
  if (matching.length !== 1) {
    throw new Error('service policy scope does not match the independently pinned profile target');
  }
  // Do not expose same-workload scopes for another database/profile to the
  // product selector. The returned scope remains committed by the full signed
  // policy digest and retains its exact profile and entitlement limits.
  return { ...canonical, scopes: matching };
}

function validateAdmissionTarget(target: ServiceAdmissionTargetV1): void {
  if (!target || typeof target !== 'object') throw new Error('service admission target is missing');
  for (const [field, value] of [
    ['protocolVersion', target.protocolVersion],
    ['operationProfile', target.operationProfile],
    ['entitlementProfile', target.entitlementProfile],
  ] as const) {
    if (value === undefined) {
      if (field !== 'protocolVersion') continue;
      throw new Error('service admission target protocolVersion is required');
    }
    if (!Number.isSafeInteger(value) || value <= 0 || value > 0xffff) {
      throw new Error(`service admission target ${field} must be a non-zero u16`);
    }
  }
  canonicalLowerHex32(
    'service admission target manifest root',
    target.expectedDatasetManifestRootHex,
  );
}

function scopeMatchesTargetV1(
  scope: ServiceScopeViewV1,
  target: ServiceAdmissionTargetV1,
): boolean {
  return scopeMatchesWireDatasetTargetV1(scope, target)
    && (target.operationProfile === undefined
      || scope.operationProfile === target.operationProfile)
    && (target.entitlementProfile === undefined
      || scope.entitlementProfile === target.entitlementProfile);
}

function scopeMatchesWireDatasetTargetV1(
  scope: ServiceScopeViewV1,
  target: ServiceAdmissionTargetV1,
): boolean {
  return scope.backend === target.backend
    && scope.workload === target.workload
    && scope.protocolVersion === target.protocolVersion
    && scope.dataset?.kind === 'manifest-root'
    && scope.dataset.rootHex === target.expectedDatasetManifestRootHex;
}

function canonicalDatasetBindingViewV1(
  dataset: ServiceScopeViewV1['dataset'],
  field: string,
): ServiceScopeViewV1['dataset'] {
  if (!dataset || typeof dataset !== 'object') throw new Error(`${field} is missing`);
  if (dataset.kind === 'manifest-root') {
    return { kind: 'manifest-root', rootHex: canonicalLowerHex32(field, dataset.rootHex) };
  }
  if (dataset.kind === 'class') {
    if (!Number.isSafeInteger(dataset.classId) || dataset.classId < 0 || dataset.classId > 0xffff) {
      throw new Error(`${field} class ID must be a u16`);
    }
    return { kind: 'class', classId: dataset.classId };
  }
  if (dataset.kind === 'catalog-epoch') {
    if (!/^(0|[1-9][0-9]*)$/.test(dataset.epoch)) {
      throw new Error(`${field} epoch must be a canonical decimal u64`);
    }
    const epoch = BigInt(dataset.epoch);
    if (epoch > 0xffff_ffff_ffff_ffffn) throw new Error(`${field} epoch exceeds u64`);
    return { kind: 'catalog-epoch', epoch: epoch.toString() };
  }
  throw new Error(`${field} has an unknown binding kind`);
}

function validateDirectoryAssertion(trust: ProviderTrustAnchorV1): void {
  const assertion = trust.directoryAssertion;
  if (!assertion) return;
  requireFixedNonzero(
    'directory operatorSigningKeyEd25519',
    assertion.operatorSigningKeyEd25519,
    32,
  );
  requireFixedNonzero('directory policyDigest', assertion.policyDigest, 32);
  if (
    typeof assertion.stableServerId !== 'string'
    || assertion.stableServerId.length === 0
    || assertion.stableServerId.length > 128
    || /[\u0000-\u001f\u007f]/.test(assertion.stableServerId)
  ) {
    throw new Error('directory stableServerId is invalid');
  }
  if (assertion.policyEpoch <= 0n || assertion.policyEpoch > 0xffff_ffff_ffff_ffffn) {
    throw new Error('directory policyEpoch must be a non-zero u64');
  }
  if (bytesToLowerHex(assertion.operatorSigningKeyEd25519)
      === bytesToLowerHex(trust.policySigningKey)) {
    throw new Error('directory operator and policy signing keys must be distinct');
  }
}

function validateDirectoryPolicyBinding(
  trust: ProviderTrustAnchorV1,
  view: ServicePolicyViewV1,
): void {
  const assertion = trust.directoryAssertion;
  if (!assertion) return;
  if (BigInt(view.policyEpoch) !== assertion.policyEpoch) {
    throw new Error('verified policy epoch does not match the directory assertion');
  }
  if (canonicalHex32('verified policy digest', view.policyDigestHex)
      !== bytesToLowerHex(assertion.policyDigest)) {
    throw new Error('verified policy digest does not match the directory assertion');
  }
}

function capabilityBinding(
  providerIdHex: string,
  policyDigestHex: string,
  scope: ServiceScopeViewV1,
  offer: ServiceOfferViewV1,
  scheme: AdmissionSchemeV1,
): AdmissionCapabilityBindingV1 {
  return {
    providerIdHex: canonicalHex32('providerIdHex', providerIdHex),
    policyDigestHex: canonicalHex32('policyDigestHex', policyDigestHex),
    scopeIdHex: canonicalHex32('scopeIdHex', scope.scopeIdHex),
    offerId: offer.offerId,
    scheme,
  };
}

function schemeForPaidOffer(
  authorization: ServiceOfferViewV1['authorization'],
): AdmissionSchemeV1 {
  switch (authorization) {
    case 'bolt11-direct-receipt': return 'bolt11-direct-receipt';
    case 'cashu-ecash': return 'cashu-ecash';
    case 'cashu-bat': return 'cashu-bat';
    default: throw new Error('selected offer is not a supported single-use paid capability');
  }
}

function exactRetainedBinding(
  binding: AdmissionCapabilityBindingV1,
  trust: ProviderTrustAnchorV1,
): AdmissionCapabilityBindingV1 {
  const canonical: AdmissionCapabilityBindingV1 = {
    providerIdHex: canonicalHex32('providerIdHex', binding.providerIdHex),
    policyDigestHex: canonicalHex32('policyDigestHex', binding.policyDigestHex),
    scopeIdHex: canonicalHex32('scopeIdHex', binding.scopeIdHex),
    offerId: binding.offerId,
    scheme: binding.scheme,
  };
  if (!Number.isSafeInteger(canonical.offerId)
      || canonical.offerId <= 0
      || canonical.offerId > 0xffff_ffff) {
    throw new Error('retained offer ID must be a non-zero u32');
  }
  if (canonical.providerIdHex !== bytesToLowerHex(trust.providerId)) {
    throw new Error('retained capability provider does not match this trusted provider');
  }
  return canonical;
}

function requireRetainedServicePort(
  port: ServiceAdmissionPortV1,
): RetainedServiceAdmissionPortV1 {
  if (typeof port.fetchRetainedRedemption !== 'function'
      || typeof port.assertRetainedSessionBinding !== 'function'
      || typeof port.authorizeRetained !== 'function') {
    throw new Error('this strict adapter does not support retained-policy redemption');
  }
  return {
    fetchRetainedRedemption: port.fetchRetainedRedemption.bind(port),
    assertRetainedSessionBinding: port.assertRetainedSessionBinding.bind(port),
    authorizeRetained: port.authorizeRetained.bind(port),
  };
}

function assertRetainedHandleMatchesBinding(
  accepted: WasmAcceptedRetainedServiceRedemptionV1,
  binding: AdmissionCapabilityBindingV1,
): void {
  if (
    canonicalHex32('retained providerIdHex', accepted.providerIdHex) !== binding.providerIdHex
    || canonicalHex32('retained policyDigestHex', accepted.policyDigestHex)
      !== binding.policyDigestHex
    || canonicalHex32('retained scopeIdHex', accepted.scopeIdHex) !== binding.scopeIdHex
    || accepted.offerId !== binding.offerId
  ) {
    throw new Error('retained policy response does not match the exact capability binding');
  }
}

function validateRetainedRedemptionView(
  view: RetainedServiceRedemptionViewV1,
  binding: AdmissionCapabilityBindingV1,
  target: ServiceAdmissionTargetV1,
): RetainedServiceRedemptionViewV1 {
  if (!view || typeof view !== 'object' || !view.scope || !view.offer) {
    throw new Error('retained policy metadata is malformed');
  }
  if (canonicalHex32('retained view providerIdHex', view.providerIdHex)
      !== binding.providerIdHex
      || canonicalHex32('retained view policyDigestHex', view.policyDigestHex)
        !== binding.policyDigestHex
      || canonicalHex32('retained view scopeIdHex', view.scope.scopeIdHex)
        !== binding.scopeIdHex
      || view.offer.offerId !== binding.offerId) {
    throw new Error('retained policy metadata does not match the exact capability binding');
  }
  if (!scopeMatchesTargetV1(view.scope, target)) {
    throw new Error('retained capability scope does not match this adapter wire/profile target');
  }
  if (!Array.isArray(view.scope.offers) || view.scope.offers.length !== 0) {
    throw new Error('retained redemption metadata must expose only the selected offer');
  }
  for (const [field, value] of [
    ['protocolVersion', view.scope.protocolVersion],
    ['operationProfile', view.scope.operationProfile],
    ['entitlementProfile', view.scope.entitlementProfile],
  ] as const) {
    if (!Number.isSafeInteger(value) || value <= 0 || value > 0xffff) {
      throw new Error(`retained scope ${field} must be a non-zero u16`);
    }
  }
  if (retainedSchemeForOffer(view.offer) !== binding.scheme) {
    throw new Error('retained signed offer authorization does not match capability scheme');
  }
  if (view.offer.authorization === 'arc-experimental'
      && view.offer.deploymentStatus !== 'experimental') {
    throw new Error('retained ARC offer is not marked experimental');
  }
  validateOfferVerificationKeyFingerprints(view.offer);
  const canonical = cloneRetainedRedemptionView(view);
  canonical.scope.dataset = canonicalDatasetBindingViewV1(
    view.scope.dataset,
    'retained dataset binding',
  );
  canonical.scope.limits = canonicalServiceEntitlementLimitsV1(
    view.scope.limits,
    'retained entitlement limits',
  );
  return canonical;
}

function retainedSchemeForOffer(offer: ServiceOfferViewV1): AdmissionSchemeV1 {
  if (offer.authorization === 'free') {
    if (offer.freeMode !== 'anonymous-ticket') {
      throw new Error('non-ticket free offers cannot have retained capabilities');
    }
    return 'free-anonymous-ticket';
  }
  if (offer.authorization === 'arc-experimental') return 'arc-experimental';
  return schemeForPaidOffer(offer.authorization);
}

function cloneRetainedRedemptionView(
  view: RetainedServiceRedemptionViewV1,
): RetainedServiceRedemptionViewV1 {
  return {
    providerIdHex: view.providerIdHex,
    policyDigestHex: view.policyDigestHex,
    scope: {
      ...view.scope,
      dataset: { ...view.scope.dataset },
      limits: { ...view.scope.limits },
      offers: [],
    },
    offer: cloneOffer(view.offer),
  };
}

function trustedNowUnix(): bigint {
  const millis = Date.now();
  if (!Number.isFinite(millis) || millis <= 0) throw new Error('trusted wall clock is unavailable');
  return BigInt(Math.floor(millis / 1000));
}

function requireFixedNonzero(field: string, value: Uint8Array, length: number): void {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`${field} must be exactly ${length} bytes`);
  }
  if (value.every((byte) => byte === 0)) throw new Error(`${field} must be non-zero`);
}

function canonicalHex32(field: string, value: string): string {
  if (!/^[0-9a-fA-F]{64}$/.test(value) || /^0{64}$/i.test(value)) {
    throw new Error(`${field} must be non-zero 32-byte hex`);
  }
  return value.toLowerCase();
}

function canonicalLowerHex32(field: string, value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value) || /^0{64}$/.test(value)) {
    throw new Error(`${field} must be non-zero lowercase 32-byte hex`);
  }
  return value;
}

function validateOfferVerificationKeyFingerprints(offer: ServiceOfferViewV1): void {
  if (offer.authorization === 'cashu-bat') {
    canonicalHex32(
      'BAT verification-key fingerprint',
      offer.batVerificationKeyFingerprintHex,
    );
  } else if (offer.batVerificationKeyFingerprintHex !== '') {
    throw new Error('non-BAT offer contains a BAT verification-key fingerprint');
  }
  if (offer.authorization === 'arc-experimental') {
    canonicalLowerHex32(
      'ARC verification-key fingerprint',
      offer.arcVerificationKeyFingerprintHex,
    );
  } else if (offer.arcVerificationKeyFingerprintHex !== '') {
    throw new Error('non-ARC offer contains an ARC verification-key fingerprint');
  }
}

function hexToBytes32(field: string, value: string): Uint8Array {
  const bytes = hexToBytes(canonicalHex32(field, value));
  requireFixedNonzero(field, bytes, 32);
  return bytes;
}

function bytesToLowerHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function structuredClonePolicy(view: ServicePolicyViewV1): ServicePolicyViewV1 {
  return {
    ...view,
    scopes: view.scopes.map((scope) => ({
      ...scope,
      dataset: { ...scope.dataset },
      limits: { ...scope.limits },
      offers: scope.offers.map((offer) => ({ ...offer, price: { ...offer.price } })),
    })),
  };
}

function cloneOffer(offer: ServiceOfferViewV1): ServiceOfferViewV1 {
  return { ...offer, price: { ...offer.price } };
}

function cloneTrustAnchor(trust: ProviderTrustAnchorV1): ProviderTrustAnchorV1 {
  return {
    providerId: trust.providerId.slice(),
    policySigningKey: trust.policySigningKey.slice(),
    directoryAssertion: trust.directoryAssertion ? {
      operatorSigningKeyEd25519:
        trust.directoryAssertion.operatorSigningKeyEd25519.slice(),
      stableServerId: trust.directoryAssertion.stableServerId,
      policyEpoch: trust.directoryAssertion.policyEpoch,
      policyDigest: trust.directoryAssertion.policyDigest.slice(),
    } : undefined,
  };
}

function offerFingerprintV1(offer: ServiceOfferViewV1): string {
  // This is an in-memory equality fingerprint, not an authentication digest;
  // policy signature verification remains authoritative. An explicit tuple
  // avoids depending on object property order or ignoring a future field.
  return JSON.stringify([
    offer.offerId,
    offer.acquisition,
    offer.authorization,
    offer.freeMode,
    offer.verification,
    offer.deploymentStatus,
    offer.priorityClass,
    offer.price.kind,
    'amount' in offer.price ? offer.price.amount : '',
    offer.issuerIdHex,
    offer.keyIdHex,
    offer.batVerificationKeyFingerprintHex,
    offer.arcVerificationKeyFingerprintHex,
    offer.endpoint,
    offer.credentialCount,
    offer.credentialPresentationLimit,
    offer.privacyLeakageBits,
  ]);
}

function validateAdmissionSelection(label: string, value: ProviderAdmissionSelectionV1): void {
  if (!(value.session instanceof ProviderAdmissionSessionV1)) {
    throw new Error(`${label} selection has an invalid admission session`);
  }
  canonicalHex32(`${label} scopeIdHex`, value.scopeIdHex);
  if (!Number.isSafeInteger(value.offerId) || value.offerId <= 0) {
    throw new Error(`${label} selection has an invalid offer ID`);
  }
}

function freezeProviderPaymentContextV1(
  label: string,
  selection: IndependentProviderAdmissionSelectionV1,
  offer: ServiceOfferViewV1,
): Pick<PairLegV1, 'providerEndpoint' | 'expectedLightningPayeePubkey'> {
  let endpoint: URL;
  try {
    endpoint = new URL(selection.providerEndpoint);
  } catch {
    throw new Error(`${label} provider WebSocket endpoint is invalid`);
  }
  if ((endpoint.protocol !== 'wss:' && endpoint.protocol !== 'ws:')
      || endpoint.username !== '' || endpoint.password !== '') {
    throw new Error(`${label} provider endpoint must be a credential-free WebSocket URL`);
  }

  const payee = selection.expectedLightningPayeePubkey;
  if (offer.acquisition === 'bolt11') {
    if (!(payee instanceof Uint8Array) || payee.length !== 33
        || (payee[0] !== 0x02 && payee[0] !== 0x03)
        || payee.subarray(1).every((byte) => byte === 0)) {
      throw new Error(`${label} BOLT11 offer requires one trusted compressed Lightning payee key`);
    }
    return {
      providerEndpoint: endpoint.origin,
      expectedLightningPayeePubkey: payee.slice(),
    };
  }
  if (payee !== undefined) {
    throw new Error(`${label} non-BOLT11 offer must not carry a Lightning payee context`);
  }
  return { providerEndpoint: endpoint.origin };
}

function equalBytes(first: Uint8Array, second: Uint8Array): boolean {
  if (!(second instanceof Uint8Array) || first.length !== second.length) return false;
  let difference = 0;
  for (let index = 0; index < first.length; index += 1) {
    difference |= first[index] ^ second[index];
  }
  return difference === 0;
}

function yieldToBrowser(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}
