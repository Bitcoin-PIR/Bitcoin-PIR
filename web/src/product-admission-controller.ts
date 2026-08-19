/**
 * Product-level V1 admission state machine.
 *
 * The controller owns ordering, not pricing policy: a caller supplies a
 * strict transport/database-root bootstrap and the user explicitly
 * chooses one exact signed scope/offer per independent provider. No peer
 * provider, pair identifier, invoice, token, address, or query result is ever
 * passed to another leg or persisted by this module.
 */

import {
  AdmissionCredentialVaultV1,
  type AdmissionCapabilityBindingV1,
  type AdmissionCapabilityInventoryV1,
  type AdmissionSchemeV1,
  type Bolt11CapabilityAcquisitionContextV1,
  type Bolt11RecoveryRecordV1,
  type LightningNetworkNameV1,
} from './admission-vault.js';
import {
  BatV2CredentialVaultV2,
  validateBatV2ClassBindingV2,
  type BatV2ClassBindingV2,
} from './bat-v2-vault.js';
import {
  AmbiguousCapabilitySpendErrorV1,
  ProviderAdmissionSessionV1,
  VerifiedIndependentProviderPairV1,
  VerifiedIndependentProviderBatV2PairV2,
  VerifiedSingleProviderOfferV1,
  VerifiedSingleProviderRetainedOfferV1,
  type IndependentProviderPairAdmissionSelectionV1,
  type IndependentProviderBatV2AdmissionSelectionV2,
  type ProviderPairBolt11AcquisitionOptionsV1,
  type ProviderPairSideV1,
  type ServiceAuthorizationOptionsV1,
} from './service-admission.js';
import type { BatV2ClassArtifactV2 } from './provider-payment-selection.js';
import {
  Bolt11RecoveryRequiredErrorV1,
  resumeBolt11AcquisitionV1,
  type Bolt11AcquisitionHandleV1,
  type Bolt11QuoteStatusNameV1,
} from './service-acquisition.js';
import type {
  ServiceEntitlementLimitsViewV1,
  ServiceGrantViewV1,
  ServiceOfferViewV1,
  ServicePolicyViewV1,
  RetainedServiceRedemptionViewV1,
  ServiceScopeViewV1,
  BatV2AdmissionOutcomeV2,
} from './sdk-bridge.js';
import {
  assertProductQueryShapeFitsScopeV1,
  canonicalProductQueryShapeV1,
  intersectHomogeneousEntitlementLimitsV1,
  sameProductQueryShapeV1,
  type ProductQueryShapeV1,
  type ProductQueryShapesByRoleV1,
} from './service-entitlement.js';
import {
  expectedLightningPayeeForOfferV1,
  type ProductLightningPayeeTrustV1,
} from './product-provider-bootstrap.js';

export type ProductAdmissionTopologyV1 = 'independent-pair' | 'single-provider';

export type ProductAdmissionLegStatusV1 =
  | 'strict-bootstrap-pending'
  | 'policy-pending'
  | 'offer-selection-required'
  | 'ready'
  | 'checking-cache'
  | 'acquiring'
  | 'invoice-open'
  | 'payment-settled'
  | 'authorizing'
  | 'authorized'
  | 'cached-resource-ready'
  | 'ambiguous-spend'
  | 'failed';

export interface ProductAdmissionResourceBindingV1 {
  providerIdHex: string;
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  scheme: AdmissionSchemeV1 | 'cashu-bat-v2';
  /** Trusted dataset identifier, normally the verified bucket super-root. */
  datasetIdHex: string;
  /** Exact Harmony PRP backend, or another resource-specific variant. */
  variant: number;
}

export interface ProductAdmissionResourceV1 {
  /** Restore only an exact provider/policy/scope/offer/dataset/variant match. */
  restore(binding: ProductAdmissionResourceBindingV1): Promise<boolean>;
  /** Called only after the provider returned a valid admission grant. */
  acquireAfterAuthorization(binding: ProductAdmissionResourceBindingV1): Promise<void>;
  /** Persist post-query mutable resource state under the same exact binding. */
  persistAfterQuery?(binding: ProductAdmissionResourceBindingV1): Promise<void>;
  datasetIdHex: string;
  variant: number;
}

export interface ProductAdmissionLegV1 {
  /** Browser-local role name. It is never placed on a provider wire message. */
  role: string;
  label: string;
  session: ProviderAdmissionSessionV1;
  backend: ServiceScopeViewV1['backend'];
  workload: ServiceScopeViewV1['workload'];
  network?: LightningNetworkNameV1;
  /**
   * Independent exact-issuer trust only; never directory self-reported data.
   * Optional for non-BOLT11 legs. A selected BOLT11 offer fails closed unless
   * exactly one `(issuer ID, canonical HTTPS origin, network)` entry matches.
   */
  lightningPayeeTrust?: readonly ProductLightningPayeeTrustV1[];
  /** Required at runtime for every independent-pair leg; unused by true single-provider products. */
  providerEndpoint?: string;
  resource?: ProductAdmissionResourceV1;
  /** Optional exact planner snapshot captured during strict bootstrap. */
  queryShape?: ProductQueryShapeV1;
}

export interface ProductStrictBootstrapV1 {
  legs: ProductAdmissionLegV1[];
  /** Close every transport and dispose any backend-local state. */
  close(): void | Promise<void>;
}

/** One independently discovered/verified provider leg for staged products. */
export interface ProductStrictLegBootstrapV1 {
  leg: ProductAdmissionLegV1;
  close(): void | Promise<void>;
}

export interface ProductAdmissionControllerOptionsV1 {
  topology: ProductAdmissionTopologyV1;
  vault: AdmissionCredentialVaultV1;
  /** Test seam; production uses the restart-safe encrypted recovery adapter. */
  resumeBolt11?: typeof resumeBolt11AcquisitionV1;
  /** Required only when both independent paid legs select BAT V2. */
  batV2Vault?: BatV2CredentialVaultV2;
  /** Trusted release/class-registry resolver. It receives one exact signed
   * provider member and must return the canonical issuer-signed artifact. */
  resolveBatV2Class?: ProductBatV2ClassResolverV2;
}

export interface ProductBatV2ClassMemberSelectorV2 {
  role: string;
  providerIdHex: string;
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  offer: ServiceOfferViewV1;
}

export type ProductBatV2ClassResolverV2 = (
  selector: ProductBatV2ClassMemberSelectorV2,
) => BatV2ClassArtifactV2 | Promise<BatV2ClassArtifactV2>;

export interface ProductOfferChoiceV1 {
  scopeIdHex: string;
  offerId: number;
}

export interface ProductOfferOptionV1 extends ProductOfferChoiceV1 {
  scope: ServiceScopeViewV1;
  offer: ServiceOfferViewV1;
}

export interface ProductRetainedCapabilityOptionV1
  extends AdmissionCapabilityInventoryV1 {}

export interface ProductRetainedCapabilitySelectorV1
  extends AdmissionCapabilityBindingV1 {
  acquisitionContext?: Bolt11CapabilityAcquisitionContextV1;
}

export interface ProductRetainedSelectionV1 {
  binding: AdmissionCapabilityBindingV1;
  count: number;
  redemption: RetainedServiceRedemptionViewV1;
  recoveryId: string | null;
  acquisitionContext?: Bolt11CapabilityAcquisitionContextV1;
}

export interface ProductRetainedRecoveryOptionV1 {
  id: string;
  binding: AdmissionCapabilityBindingV1;
  acquisitionContext: Bolt11CapabilityAcquisitionContextV1;
}

export interface ProductAdmissionLegSnapshotV1 {
  role: string;
  label: string;
  providerIdHex: string;
  policyDigestHex: string;
  status: ProductAdmissionLegStatusV1;
  offers: ProductOfferOptionV1[];
  selected: ProductOfferChoiceV1 | null;
  retainedCapabilities: ProductRetainedCapabilityOptionV1[];
  retainedSelected: ProductRetainedSelectionV1 | null;
  retainedRecoveries: ProductRetainedRecoveryOptionV1[];
  inventory: number | null;
  invoice: string | null;
  invoiceExpiresAtUnix: string | null;
  quoteStatus: Bolt11QuoteStatusNameV1 | null;
  recoveryIds: string[];
  errorCode: ProductAdmissionErrorCodeV1 | null;
  /** Frozen planner lower bounds; never sent to either provider. */
  queryShape: ProductQueryShapeV1 | null;
}

export interface ProductAdmissionSnapshotV1 {
  phase: 'idle' | 'bootstrapping' | 'selecting' | 'ready-to-query' | 'querying' | 'failed';
  topology: ProductAdmissionTopologyV1;
  allowSharedInfrastructureCorrelationOnce: boolean;
  /** Present only when both selected legs use the same workload units. */
  homogeneousPairLimits: ServiceEntitlementLimitsViewV1 | null;
  legs: ProductAdmissionLegSnapshotV1[];
  errorCode: ProductAdmissionErrorCodeV1 | null;
}

export type ProductAdmissionErrorCodeV1 =
  | 'commercial-admission-unconfigured'
  | 'strict-bootstrap-failed'
  | 'policy-unavailable'
  | 'simple-free-unavailable'
  | 'query-shape-unavailable'
  | 'entitlement-limits-insufficient'
  | 'offer-selection-invalidated'
  | 'pair-correlation-rejected'
  | 'lightning-payee-untrusted'
  | 'bolt11-recovery-required'
  | 'capability-inventory-empty'
  | 'bat-v2-retry-safe'
  | 'ambiguous-capability-spend'
  | 'resource-failed-after-authorization'
  | 'operation-failed';

export class ProductAdmissionErrorV1 extends Error {
  constructor(
    readonly code: ProductAdmissionErrorCodeV1,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'ProductAdmissionErrorV1';
  }
}

export class ProductResourceFailedAfterAuthorizationErrorV1
  extends ProductAdmissionErrorV1 {
  constructor(options?: ErrorOptions) {
    super(
      'resource-failed-after-authorization',
      'resource acquisition failed after admission was authorized; do not retry automatically',
      options,
    );
    this.name = 'ProductResourceFailedAfterAuthorizationErrorV1';
  }
}

interface LegStateV1 extends Omit<ProductAdmissionLegV1, 'queryShape'> {
  policy: ServicePolicyViewV1;
  offers: ProductOfferOptionV1[];
  selected: ProductOfferOptionV1 | null;
  retainedCapabilities: ProductRetainedCapabilityOptionV1[];
  retainedSelected: ProductRetainedSelectionV1 | null;
  retainedRecoveries: ProductRetainedRecoveryOptionV1[];
  status: ProductAdmissionLegStatusV1;
  inventory: number | null;
  grant: ServiceGrantViewV1 | null;
  acquisition: Bolt11AcquisitionHandleV1 | null;
  invoice: string | null;
  invoiceExpiresAtUnix: bigint | null;
  quoteStatus: Bolt11QuoteStatusNameV1 | null;
  recoveryIds: string[];
  errorCode: ProductAdmissionErrorCodeV1 | null;
  transitionInFlight: boolean;
  /** True once this exact leg has touched credential/acquisition state. */
  credentialFlowStarted: boolean;
  queryShape: ProductQueryShapeV1 | null;
}

type FrozenSelectionV1 =
  | { kind: 'pair'; value: VerifiedIndependentProviderPairV1 }
  | {
    kind: 'single';
    value: VerifiedSingleProviderOfferV1 | VerifiedSingleProviderRetainedOfferV1;
  };

export class ProductAdmissionControllerV1 {
  private phase: ProductAdmissionSnapshotV1['phase'] = 'idle';
  private bootstraps: ProductStrictBootstrapV1[] = [];
  private legs: LegStateV1[] = [];
  private allowSharedInfrastructureCorrelationOnce = false;
  private errorCode: ProductAdmissionErrorCodeV1 | null = null;
  private queryAttempted = false;
  private queryShapesFrozen = false;
  private batV2Pair: VerifiedIndependentProviderBatV2PairV2 | null = null;
  /** Invalidated synchronously when a strict admission attempt starts closing. */
  private lifecycleGeneration = 0;
  private readonly resumeBolt11Impl: typeof resumeBolt11AcquisitionV1;

  constructor(private readonly options: ProductAdmissionControllerOptionsV1) {
    this.resumeBolt11Impl = options.resumeBolt11 ?? resumeBolt11AcquisitionV1;
  }

  /**
   * Execute the complete strict transport/proof/tree-top bootstrap before any
   * service-policy, quote or capability operation is reachable.
   */
  async prepare(
    strictBootstrap: () => Promise<ProductStrictBootstrapV1>,
  ): Promise<ProductAdmissionSnapshotV1> {
    await this.close();
    this.phase = 'bootstrapping';
    this.errorCode = null;
    let bootstrapped: ProductStrictBootstrapV1 | null = null;
    try {
      bootstrapped = await strictBootstrap();
      validateBootstrap(this.options.topology, bootstrapped);
      this.bootstraps = [bootstrapped];
      this.legs = bootstrapped.legs.map((leg) => pendingLeg(leg));
      await this.refreshPoliciesInternal();
      this.phase = 'selecting';
      return this.snapshot();
    } catch (cause) {
      this.errorCode = classifyPrepareError(cause);
      this.phase = 'failed';
      for (const leg of this.legs) {
        try { leg.session.close(); } catch { /* transport close below is authoritative */ }
      }
      this.legs = [];
      if (bootstrapped && !this.bootstraps.includes(bootstrapped)) {
        await bootstrapped.close();
      }
      await this.closeBootstrapOnly();
      throw new ProductAdmissionErrorV1(
        this.errorCode,
        this.errorCode === 'strict-bootstrap-failed'
          ? 'strict server verification failed before commercial admission'
          : 'verified V1 service policy is unavailable',
        { cause },
      );
    }
  }

  /**
   * Add one strict provider independently. Policy inspection is allowed after
   * one leg, but every acquisition/import/authorization path remains blocked
   * until both legs are connected and the second bootstrap has completed the
   * pair database/tree-top preflight.
   */
  async prepareLeg(
    strictBootstrap: () => Promise<ProductStrictLegBootstrapV1>,
  ): Promise<ProductAdmissionSnapshotV1> {
    if (this.options.topology !== 'independent-pair') {
      throw new ProductAdmissionErrorV1(
        'operation-failed',
        'staged provider legs are only valid for independent-pair products',
      );
    }
    if (this.legs.length >= 2 || this.legs.some((leg) => leg.transitionInFlight)) {
      throw new ProductAdmissionErrorV1('operation-failed', 'cannot add another provider leg now');
    }
    if (this.legs.length === 1 && !hasAdmissionSelection(this.legs[0])) {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'select the first provider exact offer before connecting the second provider',
      );
    }
    this.phase = 'bootstrapping';
    this.errorCode = null;
    let staged: ProductStrictLegBootstrapV1 | null = null;
    let wrapper: ProductStrictBootstrapV1 | null = null;
    let addedLeg: LegStateV1 | null = null;
    try {
      staged = await strictBootstrap();
      validateLegBootstrap(staged, new Set(this.legs.map((leg) => leg.role)));
      wrapper = {
        legs: [staged.leg],
        close: staged.close,
      };
      this.bootstraps.push(wrapper);
      addedLeg = pendingLeg(staged.leg);
      this.legs.push(addedLeg);
      await this.refreshLegPolicy(addedLeg);
      this.phase = 'selecting';
      return this.snapshot();
    } catch (cause) {
      if (addedLeg) {
        this.legs = this.legs.filter((candidate) => candidate !== addedLeg);
        try { addedLeg.session.close(); } catch { /* close transport below */ }
      }
      if (wrapper) {
        this.bootstraps = this.bootstraps.filter((candidate) => candidate !== wrapper);
        await wrapper.close();
      } else if (staged) {
        await staged.close();
      }
      this.errorCode = classifyPrepareError(cause);
      this.phase = this.legs.length > 0 ? 'selecting' : 'failed';
      throw new ProductAdmissionErrorV1(
        this.errorCode,
        this.errorCode === 'strict-bootstrap-failed'
          ? 'strict server verification failed before commercial admission'
          : 'verified V1 service policy is unavailable',
        { cause },
      );
    }
  }

  /** A live policy refresh invalidates every exact selection and grant. */
  async refreshPolicies(): Promise<ProductAdmissionSnapshotV1> {
    this.requirePrepared();
    if (this.queryShapesFrozen) {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'policy refresh after credential flow requires a new strict admission attempt',
      );
    }
    if (this.legs.some((leg) => leg.transitionInFlight)) {
      throw new ProductAdmissionErrorV1('operation-failed', 'an admission transition is in flight');
    }
    await this.closeBatV2Pair();
    this.closeAcquisitions();
    for (const leg of this.legs) resetLegForPolicy(leg);
    try {
      await this.refreshPoliciesInternal();
      this.phase = 'selecting';
      this.queryAttempted = false;
      return this.snapshot();
    } catch (cause) {
      this.phase = 'failed';
      this.errorCode = 'policy-unavailable';
      throw new ProductAdmissionErrorV1(
        'policy-unavailable',
        'verified V1 service policy refresh failed',
        { cause },
      );
    }
  }

  /**
   * Advanced, in-memory-only confirmation for both shared issuer/origin and
   * shared Lightning-payee correlation. It resets on close/prepare and must
   * be set before either credential flow starts.
   */
  setAllowSharedInfrastructureCorrelationOnce(allowed: boolean): ProductAdmissionSnapshotV1 {
    this.requirePrepared();
    if (this.legs.some((leg) => leg.transitionInFlight)) {
      throw new ProductAdmissionErrorV1(
        'operation-failed',
        'cannot change correlation consent during an admission transition',
      );
    }
    if (this.legs.some((leg) => leg.credentialFlowStarted)) {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'shared-infrastructure confirmation must happen before either credential flow starts',
      );
    }
    this.allowSharedInfrastructureCorrelationOnce = allowed === true;
    this.validateFrozenSelectionIfComplete();
    return this.snapshot();
  }

  /**
   * Install planner-proven demand before offer selection. Pair roles are
   * independent: Harmony hint and query shapes are intentionally not merged.
   * Once any credential flow begins, only an identical recomputation is
   * accepted; changing demand requires a new strict admission attempt.
   */
  setQueryShape(role: string, shapeValue: ProductQueryShapeV1): ProductAdmissionSnapshotV1 {
    const leg = this.requireLeg(role);
    if (this.legs.some((candidate) => candidate.transitionInFlight)) {
      throw new ProductAdmissionErrorV1(
        'operation-failed',
        'cannot change planned query demand during an admission transition',
      );
    }
    let shape: ProductQueryShapeV1;
    try {
      shape = canonicalProductQueryShapeV1(shapeValue, `${leg.label} planned query shape`);
    } catch (cause) {
      throw new ProductAdmissionErrorV1(
        'query-shape-unavailable',
        'the backend planner did not provide canonical query demand',
        { cause },
      );
    }
    if (shape.backend !== leg.backend || shape.workload !== leg.workload) {
      throw new ProductAdmissionErrorV1(
        'query-shape-unavailable',
        'planned query demand does not match this provider role',
      );
    }
    if (this.queryShapesFrozen) {
      if (leg.queryShape && sameProductQueryShapeV1(leg.queryShape, shape)) return this.snapshot();
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'planned query demand changed after credential flow began; start a new admission',
      );
    }
    if (hasAdmissionSelection(leg)) this.assertShapeFitsLeg(leg, shape);
    leg.queryShape = cloneQueryShape(shape);
    return this.snapshot();
  }

  async selectOffer(
    role: string,
    choice: ProductOfferChoiceV1,
  ): Promise<ProductAdmissionSnapshotV1> {
    const leg = this.requireLeg(role);
    return this.withLegExclusiveMutation(leg, async () => {
      if (this.pairCredentialFlowStarted()
          || leg.credentialFlowStarted
          || leg.status === 'authorized'
          || leg.status === 'cached-resource-ready'
          || leg.status === 'ambiguous-spend') {
        throw new ProductAdmissionErrorV1(
          'offer-selection-invalidated',
          'this provider offer is frozen after its credential flow starts',
        );
      }
      leg.acquisition?.close();
      leg.acquisition = null;
      leg.invoice = null;
      leg.invoiceExpiresAtUnix = null;
      leg.quoteStatus = null;
      leg.recoveryIds = [];
      leg.retainedSelected = null;
      const selected = leg.offers.find(
        (candidate) => candidate.scopeIdHex === canonicalHex32(choice.scopeIdHex)
          && candidate.offerId === choice.offerId,
      );
      if (!selected) {
        throw new ProductAdmissionErrorV1(
          'offer-selection-invalidated',
          'selected offer is not in the current verified policy',
        );
      }
      this.assertShapeFitsScope(leg, selected.scope);
      leg.selected = cloneOfferOption(selected);
      leg.status = 'ready';
      leg.errorCode = null;
      this.phase = 'selecting';
      this.validateFrozenSelectionIfComplete();
      await this.refreshLegInventory(leg);
      await this.refreshLegRecoveries(leg);
      return this.snapshot();
    });
  }

  /**
   * Select the first signed Free offer that can run without a user-supplied
   * or previously retained capability. Simple mode deliberately excludes
   * anonymous-ticket offers: those consume a single-use vault credential and
   * are not an automatic free quota.
   */
  async selectFreeOffers(): Promise<ProductAdmissionSnapshotV1> {
    this.requirePrepared();
    for (const leg of this.legs) {
      if (leg.status === 'authorized' || leg.status === 'cached-resource-ready') continue;
      if (leg.credentialFlowStarted || leg.retainedSelected) {
        throw simpleFreeUnavailable(
          `${leg.label} already has a credential flow or retained capability selected`,
        );
      }
      if (leg.selected) {
        if (!isAutomaticFreeOffer(leg.selected.offer)) {
          throw simpleFreeUnavailable(`${leg.label} does not have an automatic signed Free selection`);
        }
        continue;
      }
      if (leg.status === 'failed' || leg.status === 'ambiguous-spend') {
        throw simpleFreeUnavailable(`${leg.label} is already in a failed admission state`);
      }
      const option = leg.offers.find((candidate) => isAutomaticFreeOffer(candidate.offer));
      if (!option) {
        throw simpleFreeUnavailable(`${leg.label} does not advertise an automatic signed Free offer`);
      }
      await this.selectOffer(leg.role, {
        scopeIdHex: option.scopeIdHex,
        offerId: option.offerId,
      });
    }
    return this.snapshot();
  }

  /** Authorize only the exact automatic Free selections made by simple mode. */
  async authorizeSelectedFreeOffers(): Promise<ProductAdmissionSnapshotV1> {
    this.requirePrepared();
    for (const leg of this.legs) {
      if (leg.status === 'authorized' || leg.status === 'cached-resource-ready') continue;
      if (!leg.selected || !isAutomaticFreeOffer(leg.selected.offer)) {
        throw simpleFreeUnavailable(`${leg.label} has no automatic signed Free selection to authorize`);
      }
      if (leg.credentialFlowStarted
          || leg.status === 'failed'
          || leg.status === 'ambiguous-spend'
          || leg.status === 'invoice-open'
          || leg.status === 'payment-settled') {
        throw simpleFreeUnavailable(`${leg.label} requires manual recovery before simple mode can continue`);
      }
      await this.authorize(leg.role);
    }
    return this.snapshot();
  }

  /** Select an already-purchased proof bound to an exact historical policy. */
  async selectRetainedCapability(
    role: string,
    requested: ProductRetainedCapabilitySelectorV1,
  ): Promise<ProductAdmissionSnapshotV1> {
    const leg = this.requireLeg(role);
    if (this.pairCredentialFlowStarted()
        || leg.credentialFlowStarted
        || leg.status === 'authorized'
        || leg.status === 'cached-resource-ready'
        || leg.status === 'ambiguous-spend') {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'this provider selection is frozen after its credential flow starts',
      );
    }
    return this.withLegTransition(leg, async () => {
      await this.refreshRetainedInventory(leg);
      const binding = canonicalCapabilityBinding(requested);
      const requestedContext = cloneAcquisitionContext(requested.acquisitionContext);
      const candidates = leg.retainedCapabilities.filter((candidate) =>
        sameCapabilityBinding(candidate, binding)
          && sameOptionalAcquisitionContext(candidate.acquisitionContext, requestedContext)
          && candidate.count > 0);
      if (candidates.length > 1) {
        throw new ProductAdmissionErrorV1(
          'offer-selection-invalidated',
          'historical capability selector is ambiguous across payment contexts',
        );
      }
      const available = candidates[0];
      if (!available) {
        throw new ProductAdmissionErrorV1(
          'capability-inventory-empty',
          'no capability is available for this exact historical policy selector',
        );
      }
      const redemption = await leg.session.inspectRetainedCapability(binding);
      this.assertShapeFitsScope(leg, redemption.scope);
      leg.selected = null;
      leg.retainedSelected = {
        binding,
        count: available.count,
        redemption,
        recoveryId: null,
        acquisitionContext: cloneAcquisitionContext(available.acquisitionContext),
      };
      leg.recoveryIds = [];
      leg.status = 'ready';
      leg.inventory = available.count;
      leg.errorCode = null;
      this.phase = 'selecting';
      this.validateFrozenSelectionIfComplete();
      return this.snapshot();
    });
  }

  /** Inspect one encrypted historical quote recovery before any issuer I/O. */
  async selectRetainedRecovery(
    role: string,
    recoveryId: string,
  ): Promise<ProductAdmissionSnapshotV1> {
    const leg = this.requireLeg(role);
    if (this.pairCredentialFlowStarted() || leg.credentialFlowStarted) {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'this provider selection is frozen after its credential flow starts',
      );
    }
    return this.withLegTransition(leg, async () => {
      await this.refreshRetainedRecoveries(leg);
      const option = leg.retainedRecoveries.find((candidate) => candidate.id === recoveryId);
      if (!option) {
        throw new ProductAdmissionErrorV1(
          'operation-failed',
          'encrypted recovery does not belong to this exact trusted provider',
        );
      }
      const redemption = await leg.session.inspectRetainedCapability(option.binding);
      this.assertShapeFitsScope(leg, redemption.scope);
      leg.selected = null;
      leg.retainedSelected = {
        binding: { ...option.binding },
        count: 0,
        redemption,
        recoveryId,
        acquisitionContext: cloneAcquisitionContext(option.acquisitionContext),
      };
      leg.recoveryIds = [recoveryId];
      leg.status = 'ready';
      leg.inventory = 0;
      leg.errorCode = null;
      this.phase = 'selecting';
      this.validateFrozenSelectionIfComplete();
      return this.snapshot();
    });
  }

  async authorize(
    role: string,
    options: ServiceAuthorizationOptionsV1 = {},
  ): Promise<ProductAdmissionSnapshotV1> {
    const leg = this.requireAdmissionSelectionLeg(role);
    this.assertCredentialFlowTopologyReady();
    return this.withLegTransition(leg, async () => {
      this.freezeQueryShapesForCredentialFlow();
      if (leg.status === 'authorized' || leg.status === 'cached-resource-ready') {
        throw new ProductAdmissionErrorV1(
          'offer-selection-invalidated',
          'this exact provider leg is already authorized',
        );
      }
      this.assertSelectionPrivacyIfComplete();
      const chosenOffer = selectedOffer(leg);
      if (chosenOffer.authorization === 'cashu-bat-v2') {
        return this.authorizeBatV2Leg(role, leg);
      }
      const frozen = this.freezeSelection();
      const binding = selectedCapabilityBinding(leg);

      if (leg.resource) {
        leg.status = 'checking-cache';
        const resourceBinding = selectedResourceBinding(leg, binding);
        if (await leg.resource.restore(resourceBinding)) {
          leg.status = 'cached-resource-ready';
          leg.errorCode = null;
          this.updateReadyPhase();
          return this.snapshot();
        }
        leg.status = 'ready';
      }

      await this.assertPairAcquisitionBarrier();
      if (leg.retainedSelected || requiresVaultCapability(chosenOffer)) {
        await this.refreshLegInventory(leg);
        if ((leg.inventory ?? 0) <= 0) {
          leg.errorCode = 'capability-inventory-empty';
          throw new ProductAdmissionErrorV1(
            'capability-inventory-empty',
            missingInventoryMessage(chosenOffer),
          );
        }
      }

      leg.status = 'authorizing';
      leg.credentialFlowStarted = true;
      let grant: ServiceGrantViewV1;
      try {
        grant = await authorizeFrozen(frozen, this.sideFor(role), options);
      } catch (cause) {
        if (cause instanceof AmbiguousCapabilitySpendErrorV1) {
          leg.status = 'ambiguous-spend';
          leg.errorCode = 'ambiguous-capability-spend';
          throw new ProductAdmissionErrorV1(
            'ambiguous-capability-spend',
            'capability may be spent; do not retry this authorization',
            { cause },
          );
        }
        throw cause;
      }
      leg.grant = grant;

      if (leg.resource) {
        try {
          await leg.resource.acquireAfterAuthorization(selectedResourceBinding(leg, binding));
        } catch (cause) {
          leg.status = 'failed';
          leg.errorCode = 'resource-failed-after-authorization';
          throw new ProductResourceFailedAfterAuthorizationErrorV1({ cause });
        }
      }

      leg.status = 'authorized';
      leg.errorCode = null;
      await this.refreshLegInventory(leg);
      this.updateReadyPhase();
      return this.snapshot();
    });
  }

  private async authorizeBatV2Leg(
    role: string,
    leg: LegStateV1,
  ): Promise<ProductAdmissionSnapshotV1> {
    if (this.options.topology !== 'independent-pair'
        || this.legs.length !== 2
        || this.legs.some((candidate) => candidate.retainedSelected !== null
          || candidate.selected?.offer.authorization !== 'cashu-bat-v2')) {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'BAT V2 consumption requires two current exact class-member offers',
      );
    }
    if (!this.options.batV2Vault || !this.options.resolveBatV2Class) {
      throw new ProductAdmissionErrorV1(
        'commercial-admission-unconfigured',
        'BAT V2 requires the independent class wallet and trusted class resolver',
      );
    }

    const resourceBinding = productBatV2ResourceBinding(leg);
    if (leg.resource) {
      leg.status = 'checking-cache';
      if (await leg.resource.restore(selectedResourceBinding(leg, resourceBinding))) {
        leg.status = 'cached-resource-ready';
        leg.errorCode = null;
        this.updateReadyPhase();
        if (this.phase === 'ready-to-query') await this.closeBatV2Pair();
        return this.snapshot();
      }
      leg.status = 'ready';
    }

    // Rebuild the ordinary strict-pair guard before resolving public class
    // artifacts. Neither resolver input nor the vault contains proof bytes.
    this.freezeSelection();
    let pair: VerifiedIndependentProviderBatV2PairV2;
    try {
      pair = await this.requireBatV2Pair();
    } catch (cause) {
      if (/two distinct BAT V2 proofs/i.test(errorMessage(cause))) {
        leg.errorCode = 'capability-inventory-empty';
        throw new ProductAdmissionErrorV1(
          'capability-inventory-empty',
          'two distinct issuer-wide BAT V2 proofs are required before either provider send',
          { cause },
        );
      }
      throw cause;
    }

    leg.status = 'authorizing';
    leg.credentialFlowStarted = true;
    let outcome: BatV2AdmissionOutcomeV2;
    try {
      outcome = await pair.authorize(this.sideFor(role));
    } catch (cause) {
      if (/two distinct BAT V2 proofs/i.test(errorMessage(cause))) {
        leg.status = 'ready';
        leg.errorCode = 'capability-inventory-empty';
        throw new ProductAdmissionErrorV1(
          'capability-inventory-empty',
          'two distinct issuer-wide BAT V2 proofs are required before either provider send',
          { cause },
        );
      }
      if (cause instanceof AmbiguousCapabilitySpendErrorV1) {
        await this.closeBatV2PairAndRefresh(pair).catch(() => {
          // The proof remains reserved/burn-intended; preserve the more useful
          // may-have-been-sent error for the caller.
        });
        leg.status = 'ambiguous-spend';
        leg.errorCode = 'ambiguous-capability-spend';
        throw new ProductAdmissionErrorV1(
          'ambiguous-capability-spend',
          'BAT V2 may be spent after the one-shot admission call; do not retry it',
          { cause },
        );
      }
      await this.closeBatV2PairAndRefresh(pair).catch(() => {
        // Preserve the local exact-gate failure. Unfinished reservations stay
        // fail-closed in the V2 vault if release itself fails.
      });
      throw cause;
    }

    if (outcome.kind === 'recoverable-definitely-not-sent'
        || outcome.kind === 'recoverable-retry-safe') {
      leg.status = 'ready';
      leg.errorCode = null;
      await this.closeBatV2PairAndRefresh(pair);
      throw new ProductAdmissionErrorV1(
        'bat-v2-retry-safe',
        'BAT V2 proof was recovered safely; retry only by explicit user action',
      );
    }
    if (outcome.kind === 'burn-terminal') {
      leg.status = 'failed';
      leg.errorCode = 'operation-failed';
      await this.closeBatV2PairAndRefresh(pair);
      throw new ProductAdmissionErrorV1(
        'operation-failed',
        'BAT V2 authorization was terminal and the proof was burned',
      );
    }
    if (outcome.kind === 'burn-outcome-unknown') {
      leg.status = 'ambiguous-spend';
      leg.errorCode = 'ambiguous-capability-spend';
      await this.closeBatV2PairAndRefresh(pair);
      throw new ProductAdmissionErrorV1(
        'ambiguous-capability-spend',
        'BAT V2 authorization outcome is unknown and the proof was burned',
      );
    }

    leg.grant = { ...outcome.grant };
    if (leg.resource) {
      try {
        await leg.resource.acquireAfterAuthorization(
          selectedResourceBinding(leg, resourceBinding),
        );
      } catch (cause) {
        await this.closeBatV2PairAndRefresh(pair).catch(() => {
          // The provider grant is authoritative; keep its resource failure as
          // the surfaced recovery instruction.
        });
        leg.status = 'failed';
        leg.errorCode = 'resource-failed-after-authorization';
        throw new ProductResourceFailedAfterAuthorizationErrorV1({ cause });
      }
    }
    leg.status = 'authorized';
    leg.errorCode = null;
    await this.refreshBatV2Inventory(pair.classBinding());
    this.updateReadyPhase();
    if (this.phase === 'ready-to-query') await this.closeBatV2Pair();
    return this.snapshot();
  }

  private async requireBatV2Pair(): Promise<VerifiedIndependentProviderBatV2PairV2> {
    if (this.batV2Pair) return this.batV2Pair;
    const vault = this.options.batV2Vault!;
    const resolver = this.options.resolveBatV2Class!;
    const artifacts = await Promise.all(this.legs.map(async (leg) =>
      normalizeProductBatV2ClassArtifactV2(await resolver(batV2ResolverSelector(leg)))));
    try {
      const pair = VerifiedIndependentProviderBatV2PairV2.create(
        productBatV2Selection(this.legs[0], artifacts[0]),
        productBatV2Selection(this.legs[1], artifacts[1]),
        vault,
        {
          allowSharedIssuerCorrelation: this.allowSharedInfrastructureCorrelationOnce,
          allowSharedLightningPayeeCorrelation: this.allowSharedInfrastructureCorrelationOnce,
        },
      );
      this.batV2Pair = pair;
      await this.refreshBatV2Inventory(pair.classBinding());
      return pair;
    } finally {
      for (const artifact of artifacts) artifact.classBytes.fill(0);
    }
  }

  private async refreshBatV2Inventory(binding: BatV2ClassBindingV2): Promise<void> {
    const vault = this.options.batV2Vault;
    if (!vault) return;
    const inventory = await vault.listInventory();
    const count = inventory.find((entry) => sameBatV2ClassBindingV2(entry, binding))?.count ?? 0;
    for (const leg of this.legs) {
      if (selectedOffer(leg).authorization === 'cashu-bat-v2') leg.inventory = count;
    }
  }

  async startBolt11(role: string): Promise<ProductAdmissionSnapshotV1> {
    const leg = this.requireSelectedLeg(role);
    this.assertCredentialFlowTopologyReady();
    const lifecycleGeneration = this.lifecycleGeneration;
    return this.withLegTransition(leg, async () => {
      this.freezeQueryShapesForCredentialFlow();
      if (leg.selected!.offer.acquisition !== 'bolt11') {
        throw new ProductAdmissionErrorV1('operation-failed', 'selected offer is not BOLT11');
      }
      if (leg.selected!.offer.authorization === 'cashu-bat-v2') {
        throw new ProductAdmissionErrorV1(
          'operation-failed',
          'BAT V2 acquisition uses the independent class-wallet controller',
        );
      }
      const payee = selectedExpectedLightningPayee(leg);
      const frozen = this.freezeSelection();
      const assertReady = () => this.assertBolt11StartReady(leg, lifecycleGeneration);
      assertReady();
      leg.status = 'acquiring';
      leg.credentialFlowStarted = true;
      let acquisition: Bolt11AcquisitionHandleV1 | null = null;
      try {
        acquisition = await startBolt11Frozen(
          frozen,
          this.sideFor(role),
          {
            vault: this.options.vault,
            network: leg.network ?? 'bitcoin',
            expectedPayeePubkey: payee.slice(),
            assertReady,
          },
        );
        assertReady();
        // Keep the verified invoice out of observable controller state until
        // every remaining vault await has completed under the same pair.
        await this.refreshLegRecoveries(leg);
        assertReady();
        this.installAcquisition(leg, acquisition);
        acquisition = null;
        return this.snapshot();
      } catch (cause) {
        acquisition?.close();
        if (cause instanceof Bolt11RecoveryRequiredErrorV1) {
          leg.status = 'failed';
          leg.errorCode = 'bolt11-recovery-required';
          leg.recoveryIds = [cause.recoveryId];
          throw new ProductAdmissionErrorV1(
            'bolt11-recovery-required',
            'invoice response may have been lost; resume the encrypted acquisition',
            { cause },
          );
        }
        throw cause;
      }
    });
  }

  async resumeBolt11(role: string, recoveryId: string): Promise<ProductAdmissionSnapshotV1> {
    const leg = this.requireAdmissionSelectionLeg(role);
    this.assertCredentialFlowTopologyReady();
    const lifecycleGeneration = this.lifecycleGeneration;
    return this.withLegTransition(leg, async () => {
      this.freezeQueryShapesForCredentialFlow();
      this.freezeSelection();
      const payee = selectedExpectedLightningPayee(leg);
      const network = leg.network ?? 'bitcoin';
      const offer = selectedOffer(leg);
      const assertReady = () => this.assertBolt11StartReady(leg, lifecycleGeneration);
      assertReady();
      const recovery = await this.options.vault.getBolt11Recovery(recoveryId);
      assertReady();
      if (!recovery || !recoveryMatchesLeg(recovery, leg)) {
        throw new ProductAdmissionErrorV1(
          'operation-failed',
          'encrypted BOLT11 recovery does not match the current exact offer',
        );
      }
      leg.credentialFlowStarted = true;
      let acquisition: Bolt11AcquisitionHandleV1 | null = null;
      try {
        acquisition = await this.resumeBolt11Impl({
          vault: this.options.vault,
          recoveryId,
          issuerEndpoint: offer.endpoint,
          issuerIdHex: offer.issuerIdHex,
          network,
          expectedPayeePubkey: payee,
          assertReady,
        });
        assertReady();
        await acquisition.ensureQuote();
        assertReady();
        await this.refreshLegRecoveries(leg);
        assertReady();
        await this.refreshRetainedRecoveries(leg);
        assertReady();
        this.installAcquisition(leg, acquisition);
        acquisition = null;
        return this.snapshot();
      } catch (cause) {
        acquisition?.close();
        if (cause instanceof Bolt11RecoveryRequiredErrorV1) {
          leg.status = 'failed';
          leg.errorCode = 'bolt11-recovery-required';
          leg.recoveryIds = [cause.recoveryId];
          throw new ProductAdmissionErrorV1(
            'bolt11-recovery-required',
            'invoice response may have been lost; resume the encrypted acquisition',
            { cause },
          );
        }
        throw cause;
      }
    });
  }

  async pollBolt11(role: string): Promise<ProductAdmissionSnapshotV1> {
    const leg = this.requireLeg(role);
    return this.withLegTransition(leg, async () => {
      if (!leg.acquisition) {
        throw new ProductAdmissionErrorV1('operation-failed', 'no BOLT11 acquisition is active');
      }
      const status = await leg.acquisition.pollStatus();
      leg.quoteStatus = status;
      leg.status = status === 'payment-settled' || status === 'late-settled-reconcile'
        ? 'payment-settled'
        : 'invoice-open';
      return this.snapshot();
    });
  }

  async claimBolt11(role: string): Promise<ProductAdmissionSnapshotV1> {
    const leg = this.requireLeg(role);
    return this.withLegTransition(leg, async () => {
      this.assertShapeFitsLeg(leg);
      if (!leg.acquisition || (leg.quoteStatus !== 'payment-settled'
          && leg.quoteStatus !== 'late-settled-reconcile')) {
        throw new ProductAdmissionErrorV1(
          'operation-failed',
          'BOLT11 payment is not settled and claimable',
        );
      }
      await leg.acquisition.claim();
      leg.acquisition.close();
      leg.acquisition = null;
      leg.invoice = null;
      leg.invoiceExpiresAtUnix = null;
      leg.quoteStatus = null;
      leg.status = 'ready';
      await this.refreshLegInventory(leg);
      if (leg.retainedSelected) leg.retainedSelected.recoveryId = null;
      await this.refreshLegRecoveries(leg);
      await this.refreshRetainedRecoveries(leg);
      return this.snapshot();
    });
  }

  async importStandardCashu(
    role: string,
    serializedToken: string,
  ): Promise<ProductAdmissionSnapshotV1> {
    const leg = this.requireSelectedLeg(role);
    this.assertCredentialFlowTopologyReady();
    return this.withLegTransition(leg, async () => {
      this.freezeQueryShapesForCredentialFlow();
      const offer = leg.selected!.offer;
      if (offer.acquisition !== 'cashu-ecash'
          || offer.authorization !== 'cashu-ecash'
          || offer.verification !== 'standard-cashu-mint-online') {
        throw new ProductAdmissionErrorV1(
          'operation-failed',
          'selected offer is not standard Cashu eCash',
        );
      }
      const frozen = this.freezeSelection();
      leg.credentialFlowStarted = true;
      await importCashuFrozen(
        frozen,
        this.sideFor(role),
        this.options.vault,
        serializedToken,
      );
      leg.status = 'ready';
      leg.errorCode = null;
      await this.refreshLegInventory(leg);
      return this.snapshot();
    });
  }

  canQuery(): boolean {
    if (!(this.phase === 'ready-to-query'
      && !this.queryAttempted
      && this.legs.length > 0
      && this.legs.every((leg) => leg.status === 'authorized'
        || leg.status === 'cached-resource-ready'))) return false;
    try {
      this.assertCompleteSelectionPrivacy();
      this.assertEveryShapeFitsSelection();
      return true;
    } catch {
      return false;
    }
  }

  /** Exactly one caller-supplied query attempt; no retry and no refund logic. */
  async executeQuery<T>(
    currentShapes: ProductQueryShapesByRoleV1,
    query: () => Promise<T>,
  ): Promise<T> {
    this.assertCurrentQueryShapes(currentShapes);
    if (!this.canQuery()) {
      throw new ProductAdmissionErrorV1(
        'operation-failed',
        'every exact provider offer must be authorized before the PIR query',
      );
    }
    // Re-run the pair/privacy guard immediately before the real query. This is
    // browser-local only and never creates a pair identifier on either wire.
    this.assertCompleteSelectionPrivacy();
    this.assertEveryShapeFitsSelection();
    this.queryAttempted = true;
    this.phase = 'querying';
    const result = await query();
    for (const leg of this.legs) {
      if (leg.resource?.persistAfterQuery && hasAdmissionSelection(leg)) {
        try {
          const binding = selectedOffer(leg).authorization === 'cashu-bat-v2'
            ? productBatV2ResourceBinding(leg)
            : selectedCapabilityBinding(leg);
          await leg.resource.persistAfterQuery(
            selectedResourceBinding(leg, binding),
          );
        } catch {
          // Query/results remain valid. A missing cache write only forces the
          // next attempt to authorize and download a fresh resource.
        }
      }
    }
    return result;
  }

  snapshot(): ProductAdmissionSnapshotV1 {
    return {
      phase: this.phase,
      topology: this.options.topology,
      allowSharedInfrastructureCorrelationOnce: this.allowSharedInfrastructureCorrelationOnce,
      homogeneousPairLimits: this.homogeneousPairLimits(),
      legs: this.legs.map((leg) => ({
        role: leg.role,
        label: leg.label,
        providerIdHex: leg.policy.providerIdHex,
        policyDigestHex: leg.policy.policyDigestHex,
        status: leg.status,
        offers: leg.offers.map(cloneOfferOption),
        selected: leg.selected
          ? { scopeIdHex: leg.selected.scopeIdHex, offerId: leg.selected.offerId }
          : null,
        retainedCapabilities: leg.retainedCapabilities.map((entry) => ({
          ...entry,
          acquisitionContext: cloneAcquisitionContext(entry.acquisitionContext),
        })),
        retainedSelected: leg.retainedSelected
          ? cloneRetainedSelection(leg.retainedSelected)
          : null,
        retainedRecoveries: leg.retainedRecoveries.map((entry) => ({
          id: entry.id,
          binding: { ...entry.binding },
          acquisitionContext: cloneAcquisitionContext(entry.acquisitionContext)!,
        })),
        inventory: leg.inventory,
        invoice: leg.invoice,
        invoiceExpiresAtUnix: leg.invoiceExpiresAtUnix?.toString() ?? null,
        quoteStatus: leg.quoteStatus,
        recoveryIds: [...leg.recoveryIds],
        errorCode: leg.errorCode,
        queryShape: leg.queryShape ? cloneQueryShape(leg.queryShape) : null,
      })),
      errorCode: this.errorCode,
    };
  }

  async close(): Promise<void> {
    this.lifecycleGeneration += 1;
    this.closeAcquisitions();
    let closeFailure: unknown = null;
    try {
      await this.closeBatV2Pair();
    } catch (error) {
      closeFailure = error;
    }
    for (const leg of this.legs) {
      if (!leg.transitionInFlight) {
        try { leg.session.close(); } catch { /* closing transport below is authoritative */ }
      }
    }
    try {
      await this.closeBootstrapOnly();
    } catch (error) {
      closeFailure = closeFailure
        ? new AggregateError([closeFailure, error], 'product admission close failed')
        : error;
    } finally {
      this.legs = [];
      this.phase = 'idle';
      this.errorCode = null;
      this.allowSharedInfrastructureCorrelationOnce = false;
      this.queryAttempted = false;
      this.queryShapesFrozen = false;
    }
    if (closeFailure) throw closeFailure;
  }

  private async refreshPoliciesInternal(): Promise<void> {
    for (const leg of this.legs) {
      await this.refreshLegPolicy(leg);
    }
  }

  private async refreshLegPolicy(leg: LegStateV1): Promise<void> {
    leg.status = 'policy-pending';
    const policy = await leg.session.refreshPolicy();
    const scopes = policy.scopes.filter(
      (scope) => scope.backend === leg.backend && scope.workload === leg.workload,
    );
    const offers = scopes.flatMap((scope) => scope.offers.map((offer) => ({
      scopeIdHex: scope.scopeIdHex,
      offerId: offer.offerId,
      scope: cloneScope(scope),
      offer: cloneOffer(offer),
    })));
    if (offers.length === 0) throw new Error('policy has no exact product scope offers');
    leg.policy = clonePolicy(policy);
    leg.offers = offers;
    leg.status = 'offer-selection-required';
    leg.errorCode = null;
    await this.refreshRetainedInventory(leg);
    await this.refreshRetainedRecoveries(leg);
  }

  private validateFrozenSelectionIfComplete(): void {
    const expected = this.options.topology === 'independent-pair' ? 2 : 1;
    if (this.legs.length !== expected
        || this.legs.some((leg) => !hasAdmissionSelection(leg))) return;
    try {
      this.assertCompleteSelectionPrivacy();
      this.errorCode = null;
    } catch (cause) {
      if (cause instanceof ProductAdmissionErrorV1
          && cause.code === 'lightning-payee-untrusted') {
        this.errorCode = cause.code;
        throw cause;
      }
      this.errorCode = 'pair-correlation-rejected';
      throw new ProductAdmissionErrorV1(
        'pair-correlation-rejected',
        'selected provider offers fail the independent-provider privacy guard',
        { cause },
      );
    }
  }

  private assertCompleteSelectionPrivacy(): void {
    this.requirePrepared();
    const expected = this.options.topology === 'independent-pair' ? 2 : 1;
    if (this.legs.length !== expected
        || this.legs.some((leg) => !hasAdmissionSelection(leg))) {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'select one exact signed current or retained offer for every required provider role',
      );
    }
    // Constructing the opaque typestate is itself the authoritative local
    // privacy check, including mixed current/retained historical contexts.
    this.freezeSelection();
  }

  private assertSelectionPrivacyIfComplete(): void {
    const expected = this.options.topology === 'independent-pair' ? 2 : 1;
    if (this.legs.length === expected
        && this.legs.every((leg) => hasAdmissionSelection(leg))) {
      this.assertCompleteSelectionPrivacy();
    }
  }

  private freezeSelection(): FrozenSelectionV1 {
    this.requirePrepared();
    const expected = this.options.topology === 'independent-pair' ? 2 : 1;
    if (this.legs.length !== expected || this.legs.some((leg) => !hasAdmissionSelection(leg))) {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'select one exact signed current or retained offer for every required provider role',
      );
    }
    if (this.options.topology === 'single-provider') {
      const leg = this.legs[0];
      const expectedLightningPayeePubkey = projectedLightningPayee(leg);
      const paymentContext = {
        lightningNetwork: leg.network ?? 'bitcoin',
        expectedLightningPayeePubkey,
      };
      if (leg.retainedSelected) {
        return {
          kind: 'single',
          value: VerifiedSingleProviderRetainedOfferV1.create({
            session: leg.session,
            ...paymentContext,
            binding: { ...leg.retainedSelected.binding },
            redemption: cloneRetainedSelection(leg.retainedSelected).redemption,
            acquisitionContext: cloneAcquisitionContext(
              leg.retainedSelected.acquisitionContext,
            ),
          }),
        };
      }
      return {
        kind: 'single',
        value: VerifiedSingleProviderOfferV1.create({
          session: leg.session,
          ...paymentContext,
          scopeIdHex: leg.selected!.scopeIdHex,
          offerId: leg.selected!.offerId,
        }),
      };
    }
    const [first, second] = this.legs;
    return {
      kind: 'pair',
      value: VerifiedIndependentProviderPairV1.createSelections(
        pairSelectionForLeg(first),
        pairSelectionForLeg(second),
        {
          allowSharedIssuerCorrelation: this.allowSharedInfrastructureCorrelationOnce,
          allowSharedLightningPayeeCorrelation: this.allowSharedInfrastructureCorrelationOnce,
        },
      ),
    };
  }

  private sideFor(role: string): ProviderPairSideV1 {
    const index = this.legs.findIndex((leg) => leg.role === role);
    if (index === 0) return 'first';
    if (index === 1) return 'second';
    throw new ProductAdmissionErrorV1('operation-failed', 'unknown provider role');
  }

  private requirePrepared(): void {
    if (this.bootstraps.length === 0 || this.legs.length === 0 || this.phase === 'idle') {
      throw new ProductAdmissionErrorV1(
        'commercial-admission-unconfigured',
        'commercial admission is not prepared on a strict verified connection',
      );
    }
  }

  private assertCredentialFlowTopologyReady(): void {
    if (this.options.topology === 'independent-pair'
        && (this.legs.length !== 2
          || !this.legs.every((leg) => hasAdmissionSelection(leg)))) {
      throw new ProductAdmissionErrorV1(
        'operation-failed',
        'strictly connect and preflight both providers and select both exact offers before either credential flow',
      );
    }
  }

  /**
   * Bind first invoice exposure to this exact product attempt. The provider
   * session adds its own transport/policy guard; this layer additionally
   * prevents a late async acquisition from surviving controller close or
   * replacement of either independently selected product leg.
   */
  private assertBolt11StartReady(leg: LegStateV1, generation: number): void {
    const expected = this.options.topology === 'independent-pair' ? 2 : 1;
    if (this.lifecycleGeneration !== generation
        || this.phase === 'idle'
        || this.phase === 'failed'
        || this.bootstraps.length === 0
        || this.legs.length !== expected
        || !this.legs.includes(leg)
        || !hasAdmissionSelection(leg)) {
      throw new ProductAdmissionErrorV1(
        'strict-bootstrap-failed',
        'strict product admission was invalidated before invoice exposure',
      );
    }
    this.assertCredentialFlowTopologyReady();
    this.assertSelectionPrivacyIfComplete();
    this.assertShapeFitsLeg(leg);
  }

  private pairCredentialFlowStarted(): boolean {
    return this.options.topology === 'independent-pair'
      && this.legs.some((candidate) => candidate.credentialFlowStarted);
  }

  /** Do not start either connection-bound grant while the peer still needs a
   * wallet/mint round trip. This is a local acquisition barrier, not a
   * cross-provider transaction or shared identifier. */
  private async assertPairAcquisitionBarrier(): Promise<void> {
    if (this.options.topology !== 'independent-pair') return;
    for (const candidate of this.legs) {
      if (candidate.status === 'authorized' || candidate.status === 'cached-resource-ready') {
        continue;
      }
      const offer = selectedOffer(candidate);
      if (offer.authorization === 'cashu-bat-v2') continue;
      if (!candidate.retainedSelected && !requiresVaultCapability(offer)) continue;
      await this.refreshLegInventory(candidate);
      if ((candidate.inventory ?? 0) <= 0) {
        throw new ProductAdmissionErrorV1(
          'capability-inventory-empty',
          `prepare the exact capability for ${candidate.label} before authorizing either provider`,
        );
      }
    }
  }

  private assertShapeFitsScope(
    leg: LegStateV1,
    scope: ServiceScopeViewV1,
    shape = leg.queryShape,
  ): void {
    if (!shape) {
      throw new ProductAdmissionErrorV1(
        'query-shape-unavailable',
        `the backend planner has not frozen demand for ${leg.label}`,
      );
    }
    try {
      assertProductQueryShapeFitsScopeV1(shape, scope, `${leg.label} signed scope`);
    } catch (cause) {
      throw new ProductAdmissionErrorV1(
        'entitlement-limits-insufficient',
        `the selected signed entitlement cannot cover known demand for ${leg.label}`,
        { cause },
      );
    }
  }

  private assertShapeFitsLeg(leg: LegStateV1, shape = leg.queryShape): void {
    const scope = selectedScope(leg);
    if (!scope) {
      if (!shape) {
        throw new ProductAdmissionErrorV1(
          'query-shape-unavailable',
          `the backend planner has not frozen demand for ${leg.label}`,
        );
      }
      return;
    }
    this.assertShapeFitsScope(leg, scope, shape);
  }

  private assertEveryShapeFitsSelection(): void {
    for (const leg of this.legs) this.assertShapeFitsLeg(leg);
  }

  private freezeQueryShapesForCredentialFlow(): void {
    this.assertEveryShapeFitsSelection();
    this.queryShapesFrozen = true;
  }

  private assertCurrentQueryShapes(current: ProductQueryShapesByRoleV1): void {
    if (!current || typeof current !== 'object') {
      throw new ProductAdmissionErrorV1(
        'query-shape-unavailable',
        'current backend planner demand is required immediately before query execution',
      );
    }
    const expectedRoles = new Set(this.legs.map((leg) => leg.role));
    const actualRoles = Object.keys(current);
    if (actualRoles.length !== expectedRoles.size
        || actualRoles.some((role) => !expectedRoles.has(role))) {
      throw new ProductAdmissionErrorV1(
        'query-shape-unavailable',
        'current backend planner demand does not cover the exact provider roles',
      );
    }
    for (const leg of this.legs) {
      if (!leg.queryShape) {
        throw new ProductAdmissionErrorV1(
          'query-shape-unavailable',
          `the backend planner has not frozen demand for ${leg.label}`,
        );
      }
      let currentShape: ProductQueryShapeV1;
      try {
        currentShape = canonicalProductQueryShapeV1(
          current[leg.role],
          `${leg.label} current query shape`,
        );
      } catch (cause) {
        throw new ProductAdmissionErrorV1(
          'query-shape-unavailable',
          `current backend planner demand is malformed for ${leg.label}`,
          { cause },
        );
      }
      if (!sameProductQueryShapeV1(leg.queryShape, currentShape)) {
        throw new ProductAdmissionErrorV1(
          'offer-selection-invalidated',
          `planned demand changed after authorization for ${leg.label}; start a new admission`,
        );
      }
      this.assertShapeFitsScope(leg, selectedScope(leg)!, currentShape);
    }
  }

  private homogeneousPairLimits(): ServiceEntitlementLimitsViewV1 | null {
    if (this.options.topology !== 'independent-pair' || this.legs.length !== 2) return null;
    const scopes = this.legs.map(selectedScope);
    if (scopes.some((scope) => scope === null)) return null;
    return intersectHomogeneousEntitlementLimitsV1(scopes as ServiceScopeViewV1[]);
  }

  private requireLeg(role: string): LegStateV1 {
    this.requirePrepared();
    const leg = this.legs.find((candidate) => candidate.role === role);
    if (!leg) throw new ProductAdmissionErrorV1('operation-failed', 'unknown provider role');
    return leg;
  }

  private requireSelectedLeg(role: string): LegStateV1 {
    const leg = this.requireLeg(role);
    if (!leg.selected) {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'select an exact current offer first',
      );
    }
    return leg;
  }

  private requireAdmissionSelectionLeg(role: string): LegStateV1 {
    const leg = this.requireLeg(role);
    if (!hasAdmissionSelection(leg)) {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'select an exact current offer or retained capability first',
      );
    }
    return leg;
  }

  private async withLegTransition<T>(leg: LegStateV1, operation: () => Promise<T>): Promise<T> {
    if (leg.transitionInFlight
        || (this.options.topology === 'independent-pair'
          && this.legs.some((candidate) => candidate.transitionInFlight))) {
      throw new ProductAdmissionErrorV1('operation-failed', 'this provider action is in flight');
    }
    leg.transitionInFlight = true;
    try {
      return await operation();
    } catch (cause) {
      if (leg.status !== 'ambiguous-spend'
          && leg.errorCode !== 'bolt11-recovery-required'
          && leg.errorCode !== 'resource-failed-after-authorization'
          && leg.errorCode !== 'capability-inventory-empty'
          && leg.errorCode !== 'lightning-payee-untrusted'
          && !(cause instanceof ProductAdmissionErrorV1
            && cause.code === 'bat-v2-retry-safe')
          && !(cause instanceof ProductAdmissionErrorV1
            && cause.code === 'pair-correlation-rejected')) {
        leg.status = 'failed';
        leg.errorCode = cause instanceof ProductAdmissionErrorV1
          ? cause.code
          : 'operation-failed';
      }
      throw cause;
    } finally {
      leg.transitionInFlight = false;
    }
  }

  /** Serialize selection mutations without translating an expected selection
   * rejection into a transport/admission failure state. */
  private async withLegExclusiveMutation<T>(
    leg: LegStateV1,
    operation: () => Promise<T>,
  ): Promise<T> {
    if (leg.transitionInFlight
        || (this.options.topology === 'independent-pair'
          && this.legs.some((candidate) => candidate.transitionInFlight))) {
      throw new ProductAdmissionErrorV1('operation-failed', 'this provider action is in flight');
    }
    leg.transitionInFlight = true;
    try {
      return await operation();
    } finally {
      leg.transitionInFlight = false;
    }
  }

  private installAcquisition(leg: LegStateV1, acquisition: Bolt11AcquisitionHandleV1): void {
    // Read all guarded UI fields before replacing the currently installed
    // handle, so a stale-invoice rejection cannot leave a dangling handle.
    const invoice = acquisition.invoice();
    const invoiceExpiresAtUnix = acquisition.invoiceExpiresAtUnix();
    const quoteStatus = acquisition.status();
    leg.acquisition?.close();
    leg.acquisition = acquisition;
    leg.invoice = invoice;
    leg.invoiceExpiresAtUnix = invoiceExpiresAtUnix;
    leg.quoteStatus = quoteStatus;
    leg.status = leg.quoteStatus === 'payment-settled'
      || leg.quoteStatus === 'late-settled-reconcile'
      ? 'payment-settled'
      : 'invoice-open';
    leg.errorCode = null;
  }

  private async refreshLegInventory(leg: LegStateV1): Promise<void> {
    if (leg.retainedSelected) {
      await this.refreshRetainedInventory(leg);
      const available = leg.retainedCapabilities.find((candidate) =>
        sameCapabilityBinding(candidate, leg.retainedSelected!.binding)
          && sameOptionalAcquisitionContext(
            candidate.acquisitionContext,
            leg.retainedSelected!.acquisitionContext,
          ));
      const count = available?.count ?? 0;
      leg.retainedSelected.count = count;
      leg.inventory = count;
      return;
    }
    if (!leg.selected || !requiresVaultCapability(leg.selected.offer)) {
      leg.inventory = null;
      return;
    }
    if (leg.selected.offer.authorization === 'cashu-bat-v2') {
      if (this.batV2Pair) {
        await this.refreshBatV2Inventory(this.batV2Pair.classBinding());
      } else {
        leg.inventory = null;
      }
      return;
    }
    leg.inventory = await this.options.vault.countCapabilities(
      selectedCapabilityBinding(leg),
      currentCapabilityAcquisitionContext(leg),
    );
  }

  private async refreshRetainedInventory(leg: LegStateV1): Promise<void> {
    const list = typeof this.options.vault.listCapabilityInventory === 'function'
      ? await this.options.vault.listCapabilityInventory(leg.policy.providerIdHex)
      : [];
    leg.retainedCapabilities = list
      .filter((entry) => entry.providerIdHex === leg.policy.providerIdHex && entry.count > 0)
      .map((entry) => ({
        ...canonicalCapabilityBinding(entry),
        count: entry.count,
        acquisitionContext: cloneAcquisitionContext(entry.acquisitionContext),
      }));
  }

  private async refreshLegRecoveries(leg: LegStateV1): Promise<void> {
    if (!hasAdmissionSelection(leg)
        || selectedOffer(leg).acquisition !== 'bolt11') {
      leg.recoveryIds = [];
      return;
    }
    const recoveries = await this.options.vault.listBolt11Recoveries();
    leg.recoveryIds = recoveries
      .filter((recovery) => recoveryMatchesLeg(recovery, leg))
      .map((recovery) => recovery.id);
  }

  private async refreshRetainedRecoveries(leg: LegStateV1): Promise<void> {
    const recoveries = await this.options.vault.listBolt11Recoveries();
    leg.retainedRecoveries = recoveries
      .filter((recovery) => recovery.providerIdHex === leg.policy.providerIdHex)
      .map((recovery) => ({
        id: recovery.id,
        binding: canonicalCapabilityBinding({
          providerIdHex: recovery.providerIdHex,
          policyDigestHex: recovery.policyDigestHex,
          scopeIdHex: recovery.scopeIdHex,
          offerId: recovery.offerId,
          scheme: recovery.expectedScheme,
        }),
        acquisitionContext: recoveryAcquisitionContext(recovery),
      }));
  }

  private updateReadyPhase(): void {
    const expected = this.options.topology === 'independent-pair' ? 2 : 1;
    this.phase = this.legs.length === expected
      && this.legs.every((leg) => leg.status === 'authorized'
      || leg.status === 'cached-resource-ready')
      ? 'ready-to-query'
      : 'selecting';
  }

  private closeAcquisitions(): void {
    for (const leg of this.legs) {
      leg.acquisition?.close();
      leg.acquisition = null;
    }
  }

  private async closeBatV2Pair(): Promise<void> {
    const pair = this.batV2Pair;
    this.batV2Pair = null;
    await pair?.close();
  }

  private async closeBatV2PairAndRefresh(
    pair: VerifiedIndependentProviderBatV2PairV2,
  ): Promise<void> {
    const binding = pair.classBinding();
    await this.closeBatV2Pair();
    await this.refreshBatV2Inventory(binding);
  }

  private async closeBootstrapOnly(): Promise<void> {
    const bootstraps = this.bootstraps.splice(0);
    const outcomes = await Promise.allSettled(
      bootstraps.reverse().map((bootstrap) => Promise.resolve().then(() => bootstrap.close())),
    );
    const failures = outcomes
      .filter((outcome): outcome is PromiseRejectedResult => outcome.status === 'rejected')
      .map((outcome) => outcome.reason);
    if (failures.length > 0) {
      throw new AggregateError(failures, 'one or more strict provider transports failed to close');
    }
  }
}

function validateBootstrap(
  topology: ProductAdmissionTopologyV1,
  bootstrap: ProductStrictBootstrapV1,
): void {
  const expected = topology === 'independent-pair' ? 2 : 1;
  if (!bootstrap || !Array.isArray(bootstrap.legs) || bootstrap.legs.length !== expected
      || typeof bootstrap.close !== 'function') {
    throw new Error(`strict bootstrap must return exactly ${expected} provider leg(s)`);
  }
  const roles = new Set<string>();
  for (const leg of bootstrap.legs) {
    if (!leg || typeof leg.role !== 'string' || leg.role.length === 0
        || roles.has(leg.role) || !(leg.session instanceof ProviderAdmissionSessionV1)) {
      throw new Error('strict bootstrap returned malformed or duplicate provider roles');
    }
    roles.add(leg.role);
  }
}

function validateLegBootstrap(
  bootstrap: ProductStrictLegBootstrapV1,
  existingRoles: Set<string>,
): void {
  const leg = bootstrap?.leg;
  if (!bootstrap || typeof bootstrap.close !== 'function' || !leg
      || typeof leg.role !== 'string' || leg.role.length === 0
      || existingRoles.has(leg.role) || !(leg.session instanceof ProviderAdmissionSessionV1)) {
    throw new Error('strict staged bootstrap returned a malformed or duplicate provider leg');
  }
}

function pendingLeg(leg: ProductAdmissionLegV1): LegStateV1 {
  const queryShape = leg.queryShape === undefined
    ? null
    : canonicalProductQueryShapeV1(leg.queryShape, `${leg.label} bootstrap query shape`);
  return {
    ...leg,
    lightningPayeeTrust: leg.lightningPayeeTrust?.map((entry) => ({ ...entry })),
    policy: emptyPolicy(),
    offers: [],
    selected: null,
    retainedCapabilities: [],
    retainedSelected: null,
    retainedRecoveries: [],
    status: 'policy-pending',
    inventory: null,
    grant: null,
    acquisition: null,
    invoice: null,
    invoiceExpiresAtUnix: null,
    quoteStatus: null,
    recoveryIds: [],
    errorCode: null,
    transitionInFlight: false,
    credentialFlowStarted: false,
    queryShape,
  };
}

function resetLegForPolicy(leg: LegStateV1): void {
  leg.selected = null;
  leg.retainedSelected = null;
  leg.retainedCapabilities = [];
  leg.retainedRecoveries = [];
  leg.offers = [];
  leg.policy = emptyPolicy();
  leg.status = 'policy-pending';
  leg.inventory = null;
  leg.grant = null;
  leg.invoice = null;
  leg.invoiceExpiresAtUnix = null;
  leg.quoteStatus = null;
  leg.recoveryIds = [];
  leg.errorCode = null;
  leg.credentialFlowStarted = false;
}

function emptyPolicy(): ServicePolicyViewV1 {
  return {
    providerIdHex: '',
    policyDigestHex: '',
    policyEpoch: '0',
    expiresAtUnix: '0',
    scopes: [],
  };
}

function selectedCapabilityBinding(leg: LegStateV1): AdmissionCapabilityBindingV1 {
  if (leg.retainedSelected) return { ...leg.retainedSelected.binding };
  const selected = leg.selected!;
  return {
    providerIdHex: canonicalHex32(leg.policy.providerIdHex),
    policyDigestHex: canonicalHex32(leg.policy.policyDigestHex),
    scopeIdHex: canonicalHex32(selected.scopeIdHex),
    offerId: selected.offerId,
    scheme: schemeForOffer(selected.offer),
  };
}

function hasAdmissionSelection(leg: LegStateV1): boolean {
  return leg.selected !== null || leg.retainedSelected !== null;
}

function selectedOffer(leg: LegStateV1): ServiceOfferViewV1 {
  if (leg.retainedSelected) return leg.retainedSelected.redemption.offer;
  if (leg.selected) return leg.selected.offer;
  throw new ProductAdmissionErrorV1(
    'offer-selection-invalidated',
    'no exact current or retained provider offer is selected',
  );
}

function selectedExpectedLightningPayee(leg: LegStateV1): Uint8Array {
  const offer = selectedOffer(leg);
  if (offer.acquisition !== 'bolt11') {
    throw new ProductAdmissionErrorV1(
      'operation-failed',
      'the selected offer does not use BOLT11 acquisition',
    );
  }
  try {
    const payee = expectedLightningPayeeForOfferV1(
      leg.lightningPayeeTrust ?? [],
      offer,
      leg.network ?? 'bitcoin',
    );
    if (payee) return payee.slice();
  } catch (cause) {
    leg.errorCode = 'lightning-payee-untrusted';
    throw new ProductAdmissionErrorV1(
      'lightning-payee-untrusted',
      'BOLT11 is disabled without one exact independently trusted issuer payee',
      { cause },
    );
  }
  leg.errorCode = 'lightning-payee-untrusted';
  throw new ProductAdmissionErrorV1(
    'lightning-payee-untrusted',
    'BOLT11 is disabled without one exact independently trusted issuer payee',
  );
}

function projectedLightningPayee(leg: LegStateV1): Uint8Array | undefined {
  return selectedOffer(leg).acquisition === 'bolt11'
    ? selectedExpectedLightningPayee(leg)
    : undefined;
}

function pairSelectionForLeg(
  leg: LegStateV1,
): IndependentProviderPairAdmissionSelectionV1 {
  const expectedLightningPayeePubkey = projectedLightningPayee(leg);
  const common = {
    session: leg.session,
    providerEndpoint: leg.providerEndpoint ?? '',
    lightningNetwork: leg.network ?? 'bitcoin',
    expectedLightningPayeePubkey,
  };
  if (leg.retainedSelected) {
    return {
      kind: 'retained',
      value: {
        ...common,
        binding: { ...leg.retainedSelected.binding },
        redemption: cloneRetainedSelection(leg.retainedSelected).redemption,
        acquisitionContext: cloneAcquisitionContext(
          leg.retainedSelected.acquisitionContext,
        ),
      },
    };
  }
  if (!leg.selected) {
    throw new ProductAdmissionErrorV1(
      'offer-selection-invalidated',
      'no exact current or retained provider offer is selected',
    );
  }
  return {
    kind: 'current',
    value: {
      ...common,
      scopeIdHex: leg.selected.scopeIdHex,
      offerId: leg.selected.offerId,
    },
  };
}

function currentCapabilityAcquisitionContext(
  leg: LegStateV1,
): Bolt11CapabilityAcquisitionContextV1 | null | undefined {
  if (!leg.selected) return undefined;
  if (leg.selected.offer.acquisition !== 'bolt11') return null;
  const endpoint = new URL(leg.selected.offer.endpoint);
  return {
    kind: 'bolt11',
    issuerEndpoint: endpoint.origin,
    issuerIdHex: leg.selected.offer.issuerIdHex,
    network: leg.network ?? 'bitcoin',
    expectedPayeePubkeyHex: bytesToHex(selectedExpectedLightningPayee(leg)),
  };
}

function selectedScope(leg: LegStateV1): ServiceScopeViewV1 | null {
  if (leg.retainedSelected) return leg.retainedSelected.redemption.scope;
  return leg.selected?.scope ?? null;
}

function canonicalCapabilityBinding(
  binding: AdmissionCapabilityBindingV1,
): AdmissionCapabilityBindingV1 {
  const schemes: AdmissionSchemeV1[] = [
    'free-anonymous-ticket',
    'bolt11-direct-receipt',
    'cashu-ecash',
    'cashu-bat',
    'arc-experimental',
  ];
  if (!Number.isSafeInteger(binding.offerId)
      || binding.offerId <= 0
      || binding.offerId > 0xffff_ffff
      || !schemes.includes(binding.scheme)) {
    throw new ProductAdmissionErrorV1(
      'operation-failed',
      'retained capability binding is malformed',
    );
  }
  return {
    providerIdHex: canonicalHex32(binding.providerIdHex),
    policyDigestHex: canonicalHex32(binding.policyDigestHex),
    scopeIdHex: canonicalHex32(binding.scopeIdHex),
    offerId: binding.offerId,
    scheme: binding.scheme,
  };
}

function sameCapabilityBinding(
  left: AdmissionCapabilityBindingV1,
  right: AdmissionCapabilityBindingV1,
): boolean {
  return left.providerIdHex === right.providerIdHex
    && left.policyDigestHex === right.policyDigestHex
    && left.scopeIdHex === right.scopeIdHex
    && left.offerId === right.offerId
    && left.scheme === right.scheme;
}

function selectedResourceBinding(
  leg: LegStateV1,
  binding: Pick<
    ProductAdmissionResourceBindingV1,
    'providerIdHex' | 'policyDigestHex' | 'scopeIdHex' | 'offerId' | 'scheme'
  >,
): ProductAdmissionResourceBindingV1 {
  if (!leg.resource) throw new Error('provider leg has no bound resource');
  return {
    ...binding,
    datasetIdHex: canonicalHex32(leg.resource.datasetIdHex),
    variant: requireVariant(leg.resource.variant),
  };
}

function productBatV2ResourceBinding(
  leg: LegStateV1,
): Omit<ProductAdmissionResourceBindingV1, 'datasetIdHex' | 'variant'> {
  if (!leg.selected || leg.selected.offer.authorization !== 'cashu-bat-v2') {
    throw new ProductAdmissionErrorV1(
      'offer-selection-invalidated',
      'the selected provider offer is not BAT V2',
    );
  }
  return {
    providerIdHex: canonicalHex32(leg.policy.providerIdHex),
    policyDigestHex: canonicalHex32(leg.policy.policyDigestHex),
    scopeIdHex: canonicalHex32(leg.selected.scopeIdHex),
    offerId: leg.selected.offerId,
    scheme: 'cashu-bat-v2',
  };
}

function batV2ResolverSelector(leg: LegStateV1): ProductBatV2ClassMemberSelectorV2 {
  if (!leg.selected || leg.selected.offer.authorization !== 'cashu-bat-v2') {
    throw new ProductAdmissionErrorV1(
      'offer-selection-invalidated',
      'BAT V2 resolver requires one current exact signed offer',
    );
  }
  return {
    role: leg.role,
    providerIdHex: canonicalHex32(leg.policy.providerIdHex),
    policyDigestHex: canonicalHex32(leg.policy.policyDigestHex),
    scopeIdHex: canonicalHex32(leg.selected.scopeIdHex),
    offerId: leg.selected.offerId,
    offer: cloneOffer(leg.selected.offer),
  };
}

function productBatV2Selection(
  leg: LegStateV1,
  classArtifact: BatV2ClassArtifactV2,
): IndependentProviderBatV2AdmissionSelectionV2 {
  if (!leg.selected || leg.selected.offer.authorization !== 'cashu-bat-v2'
      || !leg.providerEndpoint) {
    throw new ProductAdmissionErrorV1(
      'offer-selection-invalidated',
      'BAT V2 requires a current exact offer on an adapter-bound provider endpoint',
    );
  }
  return {
    session: leg.session,
    scopeIdHex: leg.selected.scopeIdHex,
    offerId: leg.selected.offerId,
    providerEndpoint: leg.providerEndpoint,
    lightningNetwork: leg.network ?? 'bitcoin',
    expectedLightningPayeePubkey: selectedExpectedLightningPayee(leg),
    classArtifact,
  };
}

function normalizeProductBatV2ClassArtifactV2(value: BatV2ClassArtifactV2): BatV2ClassArtifactV2 {
  if (!value || !(value.classBytes instanceof Uint8Array) || value.classBytes.length === 0
      || !value.binding || typeof value.binding !== 'object') {
    throw new ProductAdmissionErrorV1(
      'operation-failed',
      'trusted BAT V2 resolver returned a malformed class artifact',
    );
  }
  try {
    validateBatV2ClassBindingV2(value.binding);
  } catch (cause) {
    throw new ProductAdmissionErrorV1(
      'operation-failed',
      'trusted BAT V2 resolver returned an invalid class binding',
      { cause },
    );
  }
  return {
    classBytes: value.classBytes.slice(),
    binding: { ...value.binding },
  };
}

function sameBatV2ClassBindingV2(
  left: BatV2ClassBindingV2,
  right: BatV2ClassBindingV2,
): boolean {
  return left.issuerIdHex === right.issuerIdHex
    && left.classIdHex === right.classIdHex
    && left.classDigestHex === right.classDigestHex
    && left.classKeyEpoch === right.classKeyEpoch
    && left.batKeyIdHex === right.batKeyIdHex;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function schemeForOffer(offer: ServiceOfferViewV1): AdmissionSchemeV1 {
  if (offer.authorization === 'free') {
    if (offer.freeMode !== 'anonymous-ticket') {
      // Open/IP/PoW do not touch the vault; this placeholder never reaches it.
      return 'free-anonymous-ticket';
    }
    return 'free-anonymous-ticket';
  }
  if (offer.authorization === 'cashu-bat-v2') {
    throw new Error('BAT V2 requires the class-bound admission path');
  }
  return offer.authorization;
}

function requiresVaultCapability(offer: ServiceOfferViewV1): boolean {
  return offer.authorization !== 'free' || offer.freeMode === 'anonymous-ticket';
}

function isAutomaticFreeOffer(offer: ServiceOfferViewV1): boolean {
  return offer.authorization === 'free'
    && (offer.freeMode === 'open-best-effort'
      || offer.freeMode === 'ip-rate-limited'
      || offer.freeMode === 'proof-of-work');
}

function simpleFreeUnavailable(message: string): ProductAdmissionErrorV1 {
  return new ProductAdmissionErrorV1(
    'simple-free-unavailable',
    `simple mode stopped: ${message}`,
  );
}

function missingInventoryMessage(offer: ServiceOfferViewV1): string {
  if (offer.authorization === 'cashu-bat') {
    return 'Cashu BAT inventory is empty; import or purchase a capability first';
  }
  if (offer.authorization === 'arc-experimental') {
    return 'experimental ARC inventory is empty; import or purchase a capability first';
  }
  if (offer.authorization === 'cashu-ecash') {
    return 'standard Cashu inventory is empty; paste and import a token first';
  }
  return 'capability inventory is empty; acquire a capability first';
}

async function authorizeFrozen(
  frozen: FrozenSelectionV1,
  side: ProviderPairSideV1,
  options: ServiceAuthorizationOptionsV1,
): Promise<ServiceGrantViewV1> {
  return frozen.kind === 'pair'
    ? frozen.value.authorize(side, options)
    : frozen.value.authorize(options);
}

async function startBolt11Frozen(
  frozen: FrozenSelectionV1,
  side: ProviderPairSideV1,
  options: ProviderPairBolt11AcquisitionOptionsV1,
): Promise<Bolt11AcquisitionHandleV1> {
  if (frozen.kind === 'pair') return frozen.value.startBolt11Acquisition(side, options);
  if (frozen.value instanceof VerifiedSingleProviderRetainedOfferV1) {
    throw new Error('a retained provider capability cannot start a new invoice');
  }
  return frozen.value.startBolt11Acquisition(options);
}

async function importCashuFrozen(
  frozen: FrozenSelectionV1,
  side: ProviderPairSideV1,
  vault: AdmissionCredentialVaultV1,
  serializedToken: string,
): Promise<string> {
  if (frozen.kind === 'pair') {
    return frozen.value.importStandardCashuToken(side, { vault, serializedToken });
  }
  if (frozen.value instanceof VerifiedSingleProviderRetainedOfferV1) {
    throw new Error('a retained provider capability cannot import a new Cashu token');
  }
  return frozen.value.importStandardCashuToken({ vault, serializedToken });
}

function recoveryMatchesLeg(recovery: Bolt11RecoveryRecordV1, leg: LegStateV1): boolean {
  if (!hasAdmissionSelection(leg)) return false;
  try {
    const binding = selectedCapabilityBinding(leg);
    const offer = selectedOffer(leg);
    if (offer.acquisition !== 'bolt11') return false;
    const endpoint = new URL(offer.endpoint);
    const payeeHex = bytesToHex(selectedExpectedLightningPayee(leg));
    const matches = recovery.providerIdHex === binding.providerIdHex
      && recovery.policyDigestHex === binding.policyDigestHex
      && recovery.scopeIdHex === binding.scopeIdHex
      && recovery.offerId === binding.offerId
      && recovery.expectedScheme === binding.scheme
      && recovery.issuerEndpoint === endpoint.origin
      && recovery.issuerIdHex === offer.issuerIdHex
      && recovery.network === (leg.network ?? 'bitcoin')
      && recovery.expectedPayeePubkeyHex === payeeHex;
    return matches && (leg.retainedSelected?.acquisitionContext === undefined
      || sameOptionalAcquisitionContext(
        leg.retainedSelected.acquisitionContext,
        recoveryAcquisitionContext(recovery),
      ));
  } catch {
    return false;
  }
}

function classifyPrepareError(cause: unknown): ProductAdmissionErrorCodeV1 {
  const message = (cause as Error)?.message ?? '';
  return /policy|scope|checkpoint|anchor/i.test(message)
    ? 'policy-unavailable'
    : 'strict-bootstrap-failed';
}

function clonePolicy(policy: ServicePolicyViewV1): ServicePolicyViewV1 {
  return {
    ...policy,
    scopes: policy.scopes.map(cloneScope),
  };
}

function cloneScope(scope: ServiceScopeViewV1): ServiceScopeViewV1 {
  return {
    ...scope,
    dataset: { ...scope.dataset },
    limits: { ...scope.limits },
    offers: scope.offers.map(cloneOffer),
  };
}

function cloneOffer(offer: ServiceOfferViewV1): ServiceOfferViewV1 {
  return { ...offer, price: { ...offer.price } };
}

function cloneOfferOption(option: ProductOfferOptionV1): ProductOfferOptionV1 {
  return {
    scopeIdHex: option.scopeIdHex,
    offerId: option.offerId,
    scope: cloneScope(option.scope),
    offer: cloneOffer(option.offer),
  };
}

function cloneRetainedSelection(
  selection: ProductRetainedSelectionV1,
): ProductRetainedSelectionV1 {
  return {
    binding: { ...selection.binding },
    count: selection.count,
    recoveryId: selection.recoveryId,
    acquisitionContext: cloneAcquisitionContext(selection.acquisitionContext),
    redemption: {
      providerIdHex: selection.redemption.providerIdHex,
      policyDigestHex: selection.redemption.policyDigestHex,
      scope: {
        ...selection.redemption.scope,
        dataset: { ...selection.redemption.scope.dataset },
        limits: { ...selection.redemption.scope.limits },
        offers: [],
      },
      offer: cloneOffer(selection.redemption.offer),
    },
  };
}

function cloneAcquisitionContext(
  value: Bolt11CapabilityAcquisitionContextV1 | undefined,
): Bolt11CapabilityAcquisitionContextV1 | undefined {
  if (value === undefined) return undefined;
  return {
    kind: 'bolt11',
    issuerEndpoint: value.issuerEndpoint,
    issuerIdHex: value.issuerIdHex,
    network: value.network,
    expectedPayeePubkeyHex: value.expectedPayeePubkeyHex,
  };
}

function sameOptionalAcquisitionContext(
  first: Bolt11CapabilityAcquisitionContextV1 | undefined,
  second: Bolt11CapabilityAcquisitionContextV1 | undefined,
): boolean {
  if (first === undefined || second === undefined) return first === second;
  return first.kind === second.kind
    && first.issuerEndpoint === second.issuerEndpoint
    && first.issuerIdHex === second.issuerIdHex
    && first.network === second.network
    && first.expectedPayeePubkeyHex === second.expectedPayeePubkeyHex;
}

function recoveryAcquisitionContext(
  recovery: Bolt11RecoveryRecordV1,
): Bolt11CapabilityAcquisitionContextV1 {
  return {
    kind: 'bolt11',
    issuerEndpoint: recovery.issuerEndpoint,
    issuerIdHex: recovery.issuerIdHex,
    network: recovery.network,
    expectedPayeePubkeyHex: recovery.expectedPayeePubkeyHex,
  };
}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function cloneQueryShape(shape: ProductQueryShapeV1): ProductQueryShapeV1 {
  return {
    backend: shape.backend,
    workload: shape.workload,
    lowerBounds: { ...shape.lowerBounds },
  };
}

function canonicalHex32(value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value) || /^0{64}$/.test(value)) {
    throw new ProductAdmissionErrorV1('operation-failed', 'expected non-zero lowercase 32-byte hex');
  }
  return value;
}

function requireVariant(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new ProductAdmissionErrorV1('operation-failed', 'resource variant is invalid');
  }
  return value;
}
