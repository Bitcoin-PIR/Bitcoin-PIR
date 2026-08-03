/**
 * Product-level V1 admission state machine.
 *
 * The controller owns ordering, not pricing policy: a caller supplies a
 * strict, already verified transport bootstrap and the user explicitly
 * chooses one exact signed scope/offer per independent provider. No peer
 * provider, pair identifier, invoice, token, address, or query result is ever
 * passed to another leg or persisted by this module.
 */

import {
  AdmissionCredentialVaultV1,
  type AdmissionCapabilityBindingV1,
  type AdmissionCapabilityInventoryV1,
  type AdmissionSchemeV1,
  type Bolt11RecoveryRecordV1,
  type LightningNetworkNameV1,
} from './admission-vault.js';
import {
  AmbiguousCapabilitySpendErrorV1,
  ProviderAdmissionSessionV1,
  VerifiedIndependentProviderPairV1,
  VerifiedSingleProviderOfferV1,
  type ProviderPairBolt11AcquisitionOptionsV1,
  type ProviderPairSideV1,
  type ServiceAuthorizationOptionsV1,
} from './service-admission.js';
import { assertIndependentProviderOfferPairV1 } from './provider-payment-selection.js';
import {
  Bolt11RecoveryRequiredErrorV1,
  resumeBolt11AcquisitionV1,
  type Bolt11AcquisitionHandleV1,
  type Bolt11QuoteStatusNameV1,
} from './service-acquisition.js';
import type {
  ServiceGrantViewV1,
  ServiceOfferViewV1,
  ServicePolicyViewV1,
  RetainedServiceRedemptionViewV1,
  ServiceScopeViewV1,
} from './sdk-bridge.js';

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

export interface ProductAdmissionResourceBindingV1
  extends AdmissionCapabilityBindingV1 {
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
  /** Independent trusted bootstrap only; never directory self-reported data. */
  expectedLightningPayeePubkey?: Uint8Array;
  resource?: ProductAdmissionResourceV1;
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
}

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

export interface ProductRetainedSelectionV1 {
  binding: AdmissionCapabilityBindingV1;
  count: number;
  redemption: RetainedServiceRedemptionViewV1;
  recoveryId: string | null;
}

export interface ProductRetainedRecoveryOptionV1 {
  id: string;
  binding: AdmissionCapabilityBindingV1;
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
}

export interface ProductAdmissionSnapshotV1 {
  phase: 'idle' | 'bootstrapping' | 'selecting' | 'ready-to-query' | 'querying' | 'failed';
  topology: ProductAdmissionTopologyV1;
  allowSharedIssuerCorrelationOnce: boolean;
  legs: ProductAdmissionLegSnapshotV1[];
  errorCode: ProductAdmissionErrorCodeV1 | null;
}

export type ProductAdmissionErrorCodeV1 =
  | 'commercial-admission-unconfigured'
  | 'strict-bootstrap-failed'
  | 'policy-unavailable'
  | 'simple-free-unavailable'
  | 'offer-selection-invalidated'
  | 'pair-correlation-rejected'
  | 'lightning-payee-untrusted'
  | 'bolt11-recovery-required'
  | 'capability-inventory-empty'
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

interface LegStateV1 extends ProductAdmissionLegV1 {
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
}

type FrozenSelectionV1 =
  | { kind: 'pair'; value: VerifiedIndependentProviderPairV1 }
  | { kind: 'single'; value: VerifiedSingleProviderOfferV1 };

export class ProductAdmissionControllerV1 {
  private phase: ProductAdmissionSnapshotV1['phase'] = 'idle';
  private bootstraps: ProductStrictBootstrapV1[] = [];
  private legs: LegStateV1[] = [];
  private allowSharedIssuerCorrelationOnce = false;
  private errorCode: ProductAdmissionErrorCodeV1 | null = null;
  private queryAttempted = false;
  private readonly resumeBolt11Impl: typeof resumeBolt11AcquisitionV1;

  constructor(private readonly options: ProductAdmissionControllerOptionsV1) {
    this.resumeBolt11Impl = options.resumeBolt11 ?? resumeBolt11AcquisitionV1;
  }

  /**
   * Execute the strict transport/proof bootstrap before any service-policy,
   * quote, capability, or query operation is reachable.
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
   * Add one strict provider independently. The first leg can select an offer,
   * acquire/import a capability, and authorize before the second provider is
   * known. Pair/privacy checks become mandatory once both offers are selected
   * and are repeated immediately before the final PIR query.
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
    if (this.legs.some((leg) => leg.transitionInFlight)) {
      throw new ProductAdmissionErrorV1('operation-failed', 'an admission transition is in flight');
    }
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

  /** Advanced, in-memory-only confirmation. It resets on close/prepare. */
  setAllowSharedIssuerCorrelationOnce(allowed: boolean): ProductAdmissionSnapshotV1 {
    this.requirePrepared();
    if (this.legs.filter((leg) => leg.credentialFlowStarted).length > 1) {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'shared-issuer confirmation must happen before a second credential flow starts',
      );
    }
    this.allowSharedIssuerCorrelationOnce = allowed === true;
    this.validateFrozenSelectionIfComplete();
    return this.snapshot();
  }

  async selectOffer(
    role: string,
    choice: ProductOfferChoiceV1,
  ): Promise<ProductAdmissionSnapshotV1> {
    const leg = this.requireLeg(role);
    if (leg.credentialFlowStarted
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
    leg.selected = cloneOfferOption(selected);
    leg.status = 'ready';
    leg.errorCode = null;
    this.phase = 'selecting';
    this.validateFrozenSelectionIfComplete();
    await this.refreshLegInventory(leg);
    await this.refreshLegRecoveries(leg);
    return this.snapshot();
  }

  /**
   * Select the first signed Free offer that does not require a user-supplied
   * or previously retained capability. Simple mode deliberately excludes
   * anonymous-ticket offers: those are single-use vault credentials, not a
   * direct free quota, and silently spending one would be surprising.
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
    requested: AdmissionCapabilityBindingV1,
  ): Promise<ProductAdmissionSnapshotV1> {
    const leg = this.requireLeg(role);
    if (leg.credentialFlowStarted
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
      const available = leg.retainedCapabilities.find(
        (candidate) => sameCapabilityBinding(candidate, binding) && candidate.count > 0,
      );
      if (!available) {
        throw new ProductAdmissionErrorV1(
          'capability-inventory-empty',
          'no capability is available for this exact historical policy selector',
        );
      }
      const redemption = await leg.session.inspectRetainedCapability(binding);
      leg.selected = null;
      leg.retainedSelected = {
        binding,
        count: available.count,
        redemption,
        recoveryId: null,
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
    if (leg.credentialFlowStarted) {
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
      leg.selected = null;
      leg.retainedSelected = {
        binding: { ...option.binding },
        count: 0,
        redemption,
        recoveryId,
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
    return this.withLegTransition(leg, async () => {
      if (leg.status === 'authorized' || leg.status === 'cached-resource-ready') {
        throw new ProductAdmissionErrorV1(
          'offer-selection-invalidated',
          'this exact provider leg is already authorized',
        );
      }
      this.assertSelectionPrivacyIfComplete();
      const frozen = leg.selected ? this.freezeLegSelection(leg) : null;
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
      }

      const chosenOffer = selectedOffer(leg);
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
        grant = leg.retainedSelected
          ? await leg.session.authorizeRetainedCapability(binding)
          : await frozen!.authorize(options);
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

  async startBolt11(role: string): Promise<ProductAdmissionSnapshotV1> {
    const leg = this.requireSelectedLeg(role);
    return this.withLegTransition(leg, async () => {
      if (leg.selected!.offer.acquisition !== 'bolt11') {
        throw new ProductAdmissionErrorV1('operation-failed', 'selected offer is not BOLT11');
      }
      const payee = leg.expectedLightningPayeePubkey;
      if (!(payee instanceof Uint8Array) || payee.length !== 33) {
        leg.errorCode = 'lightning-payee-untrusted';
        throw new ProductAdmissionErrorV1(
          'lightning-payee-untrusted',
          'BOLT11 is disabled without an independently trusted expected payee key',
        );
      }
      const frozen = this.freezeLegSelection(leg);
      leg.status = 'acquiring';
      leg.credentialFlowStarted = true;
      try {
        const acquisition = await frozen.startBolt11Acquisition(
          {
            vault: this.options.vault,
            network: leg.network ?? 'bitcoin',
            expectedPayeePubkey: payee.slice(),
          },
        );
        this.installAcquisition(leg, acquisition);
        await this.refreshLegRecoveries(leg);
        return this.snapshot();
      } catch (cause) {
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
    return this.withLegTransition(leg, async () => {
      const recovery = await this.options.vault.getBolt11Recovery(recoveryId);
      if (!recovery || !recoveryMatchesLeg(recovery, leg)) {
        throw new ProductAdmissionErrorV1(
          'operation-failed',
          'encrypted BOLT11 recovery does not match the current exact offer',
        );
      }
      this.assertSelectionPrivacyIfComplete();
      leg.credentialFlowStarted = true;
      const acquisition = await this.resumeBolt11Impl({
        vault: this.options.vault,
        recoveryId,
      });
      this.installAcquisition(leg, acquisition);
      await this.refreshLegRecoveries(leg);
      await this.refreshRetainedRecoveries(leg);
      return this.snapshot();
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
    return this.withLegTransition(leg, async () => {
      const offer = leg.selected!.offer;
      if (offer.acquisition !== 'cashu-ecash'
          || offer.authorization !== 'cashu-ecash'
          || offer.verification !== 'standard-cashu-mint-online') {
        throw new ProductAdmissionErrorV1(
          'operation-failed',
          'selected offer is not standard Cashu eCash',
        );
      }
      const frozen = this.freezeLegSelection(leg);
      leg.credentialFlowStarted = true;
      await frozen.importStandardCashuToken({
        vault: this.options.vault,
        serializedToken,
      });
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
      return true;
    } catch {
      return false;
    }
  }

  /** Exactly one caller-supplied query attempt; no retry and no refund logic. */
  async executeQuery<T>(query: () => Promise<T>): Promise<T> {
    if (!this.canQuery()) {
      throw new ProductAdmissionErrorV1(
        'operation-failed',
        'every exact provider offer must be authorized before the PIR query',
      );
    }
    // Re-run the pair/privacy guard immediately before the real query. This is
    // browser-local only and never creates a pair identifier on either wire.
    this.assertCompleteSelectionPrivacy();
    this.queryAttempted = true;
    this.phase = 'querying';
    const result = await query();
    for (const leg of this.legs) {
      if (leg.resource?.persistAfterQuery && hasAdmissionSelection(leg)) {
        try {
          await leg.resource.persistAfterQuery(
            selectedResourceBinding(leg, selectedCapabilityBinding(leg)),
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
      allowSharedIssuerCorrelationOnce: this.allowSharedIssuerCorrelationOnce,
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
        retainedCapabilities: leg.retainedCapabilities.map((entry) => ({ ...entry })),
        retainedSelected: leg.retainedSelected
          ? cloneRetainedSelection(leg.retainedSelected)
          : null,
        retainedRecoveries: leg.retainedRecoveries.map((entry) => ({
          id: entry.id,
          binding: { ...entry.binding },
        })),
        inventory: leg.inventory,
        invoice: leg.invoice,
        invoiceExpiresAtUnix: leg.invoiceExpiresAtUnix?.toString() ?? null,
        quoteStatus: leg.quoteStatus,
        recoveryIds: [...leg.recoveryIds],
        errorCode: leg.errorCode,
      })),
      errorCode: this.errorCode,
    };
  }

  async close(): Promise<void> {
    this.closeAcquisitions();
    for (const leg of this.legs) {
      if (!leg.transitionInFlight) {
        try { leg.session.close(); } catch { /* closing transport below is authoritative */ }
      }
    }
    await this.closeBootstrapOnly();
    this.legs = [];
    this.phase = 'idle';
    this.errorCode = null;
    this.allowSharedIssuerCorrelationOnce = false;
    this.queryAttempted = false;
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
    if (this.options.topology === 'independent-pair') {
      const [first, second] = this.legs;
      assertIndependentProviderOfferPairV1(
        { trust: first.session.trustAnchor(), offer: selectedOffer(first) },
        { trust: second.session.trustAnchor(), offer: selectedOffer(second) },
        { allowSharedIssuerCorrelation: this.allowSharedIssuerCorrelationOnce },
      );
    }
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
    if (this.legs.length !== expected || this.legs.some((leg) => !leg.selected)) {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'select one exact signed offer for every required provider role',
      );
    }
    if (this.options.topology === 'single-provider') {
      const leg = this.legs[0];
      return {
        kind: 'single',
        value: VerifiedSingleProviderOfferV1.create({
          session: leg.session,
          scopeIdHex: leg.selected!.scopeIdHex,
          offerId: leg.selected!.offerId,
        }),
      };
    }
    const [first, second] = this.legs;
    return {
      kind: 'pair',
      value: VerifiedIndependentProviderPairV1.create(
        {
          session: first.session,
          scopeIdHex: first.selected!.scopeIdHex,
          offerId: first.selected!.offerId,
        },
        {
          session: second.session,
          scopeIdHex: second.selected!.scopeIdHex,
          offerId: second.selected!.offerId,
        },
        { allowSharedIssuerCorrelation: this.allowSharedIssuerCorrelationOnce },
      ),
    };
  }

  /**
   * Freeze one exact provider leg without requiring that the user has already
   * discovered or selected the other provider. This preserves the protocol's
   * sequential "find one server, then find another" workflow. Once both legs
   * are selected, the independent-provider guard is still enforced before a
   * second action and again immediately before the PIR query.
   */
  private freezeLegSelection(leg: LegStateV1): VerifiedSingleProviderOfferV1 {
    this.requirePrepared();
    if (!leg.selected) {
      throw new ProductAdmissionErrorV1(
        'offer-selection-invalidated',
        'select one exact signed offer for this provider role',
      );
    }
    if (this.options.topology === 'independent-pair'
        && this.legs.length === 2
        && this.legs.every((candidate) => hasAdmissionSelection(candidate))) {
      this.assertCompleteSelectionPrivacy();
    }
    return VerifiedSingleProviderOfferV1.create({
      session: leg.session,
      scopeIdHex: leg.selected.scopeIdHex,
      offerId: leg.selected.offerId,
    });
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
    if (leg.transitionInFlight) {
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

  private installAcquisition(leg: LegStateV1, acquisition: Bolt11AcquisitionHandleV1): void {
    leg.acquisition?.close();
    leg.acquisition = acquisition;
    leg.invoice = acquisition.invoice();
    leg.invoiceExpiresAtUnix = acquisition.invoiceExpiresAtUnix();
    leg.quoteStatus = acquisition.status();
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
        sameCapabilityBinding(candidate, leg.retainedSelected!.binding));
      const count = available?.count ?? 0;
      leg.retainedSelected.count = count;
      leg.inventory = count;
      return;
    }
    if (!leg.selected || !requiresVaultCapability(leg.selected.offer)) {
      leg.inventory = null;
      return;
    }
    leg.inventory = await this.options.vault.countCapabilities(selectedCapabilityBinding(leg));
  }

  private async refreshRetainedInventory(leg: LegStateV1): Promise<void> {
    const list = typeof this.options.vault.listCapabilityInventory === 'function'
      ? await this.options.vault.listCapabilityInventory(leg.policy.providerIdHex)
      : [];
    leg.retainedCapabilities = list
      .filter((entry) => entry.providerIdHex === leg.policy.providerIdHex && entry.count > 0)
      .map((entry) => ({ ...canonicalCapabilityBinding(entry), count: entry.count }));
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

  private async closeBootstrapOnly(): Promise<void> {
    const bootstraps = this.bootstraps.splice(0);
    for (const bootstrap of bootstraps.reverse()) await bootstrap.close();
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
  return {
    ...leg,
    expectedLightningPayeePubkey: leg.expectedLightningPayeePubkey?.slice(),
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
  binding: AdmissionCapabilityBindingV1,
): ProductAdmissionResourceBindingV1 {
  if (!leg.resource) throw new Error('provider leg has no bound resource');
  return {
    ...binding,
    datasetIdHex: canonicalHex32(leg.resource.datasetIdHex),
    variant: requireVariant(leg.resource.variant),
  };
}

function schemeForOffer(offer: ServiceOfferViewV1): AdmissionSchemeV1 {
  if (offer.authorization === 'free') {
    if (offer.freeMode !== 'anonymous-ticket') {
      // Open/IP/PoW do not touch the vault; this placeholder never reaches it.
      return 'free-anonymous-ticket';
    }
    return 'free-anonymous-ticket';
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
  return frozen.kind === 'pair'
    ? frozen.value.startBolt11Acquisition(side, options)
    : frozen.value.startBolt11Acquisition(options);
}

async function importCashuFrozen(
  frozen: FrozenSelectionV1,
  side: ProviderPairSideV1,
  vault: AdmissionCredentialVaultV1,
  serializedToken: string,
): Promise<string> {
  return frozen.kind === 'pair'
    ? frozen.value.importStandardCashuToken(side, { vault, serializedToken })
    : frozen.value.importStandardCashuToken({ vault, serializedToken });
}

function recoveryMatchesLeg(recovery: Bolt11RecoveryRecordV1, leg: LegStateV1): boolean {
  if (!hasAdmissionSelection(leg)) return false;
  const binding = selectedCapabilityBinding(leg);
  return recovery.providerIdHex === binding.providerIdHex
    && recovery.policyDigestHex === binding.policyDigestHex
    && recovery.scopeIdHex === binding.scopeIdHex
    && recovery.offerId === binding.offerId
    && recovery.expectedScheme === binding.scheme;
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
    redemption: {
      providerIdHex: selection.redemption.providerIdHex,
      policyDigestHex: selection.redemption.policyDigestHex,
      scope: {
        ...selection.redemption.scope,
        limits: { ...selection.redemption.scope.limits },
        offers: [],
      },
      offer: cloneOffer(selection.redemption.offer),
    },
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
