/** Minimal DOM adapter for the product admission controller. */

import {
  ProductAdmissionControllerV1,
  ProductAdmissionErrorV1,
  type ProductAdmissionErrorCodeV1,
  type ProductAdmissionLegSnapshotV1,
  type ProductAdmissionSnapshotV1,
  type ProductOfferOptionV1,
  type ProductRetainedCapabilityOptionV1,
  type ProductRetainedCapabilitySelectorV1,
  type ProductRetainedRecoveryOptionV1,
} from './product-admission-controller.js';
import type { RetainedServiceRedemptionViewV1 } from './sdk-bridge.js';

export interface ProductProviderChoiceV1 {
  providerIdHex: string;
  label: string;
  source: 'directory' | 'manual';
}

export interface ProductAdmissionPanelRoleV1 {
  role: string;
  label: string;
}

export interface ProductAdmissionPanelOptionsV1 {
  root: HTMLElement;
  roles: ProductAdmissionPanelRoleV1[];
  /** Honest product-layer note for adapters that still dial a pair together. */
  transportCompatibilityNotice?: string;
  /** Fresh fail-closed trust check before offer/payment/token/auth transitions. */
  beforeSecurityTransition?: () => void | Promise<void>;
  onStateChange?: (snapshot: ProductAdmissionSnapshotV1 | null) => void;
}

interface RoleElementsV1 {
  row: HTMLElement;
  provider: HTMLSelectElement;
  identity: HTMLElement;
  offer: HTMLSelectElement;
  terms: HTMLElement;
  warning: HTMLElement;
  status: HTMLElement;
  actions: HTMLElement;
}

/** The second network dial is available after the first exact offer is
 * selected, but before any credential/payment action is allowed. */
export function canBootstrapNextProviderV1(snapshot: ProductAdmissionSnapshotV1): boolean {
  return snapshot.topology === 'independent-pair'
    && snapshot.legs.length > 0
    && snapshot.legs.every((leg) => leg.status === 'ready'
      || leg.status === 'authorized'
      || leg.status === 'cached-resource-ready');
}

/** Pair credential controls stay hidden until both exact selections exist. */
export function credentialActionsReadyV1(snapshot: ProductAdmissionSnapshotV1): boolean {
  const everyLegSelected = snapshot.legs.length > 0
    && snapshot.legs.every((leg) => leg.selected !== null || leg.retainedSelected !== null);
  return everyLegSelected && (snapshot.topology === 'single-provider' || snapshot.legs.length === 2);
}

/** Provider grants can begin only after every exact capability-requiring leg
 * has local inventory. Free/open/PoW legs do not need inventory. */
export function pairAuthorizationReadyV1(snapshot: ProductAdmissionSnapshotV1): boolean {
  if (snapshot.topology === 'single-provider') return true;
  if (!credentialActionsReadyV1(snapshot)) return false;
  return snapshot.legs.every((leg) => {
    if (leg.status === 'authorized' || leg.status === 'cached-resource-ready') return true;
    if (leg.retainedSelected) return (leg.inventory ?? 0) > 0;
    const selected = leg.offers.find((candidate) => candidate.scopeIdHex === leg.selected?.scopeIdHex
      && candidate.offerId === leg.selected?.offerId);
    if (!selected) return false;
    const needsInventory = selected.offer.authorization !== 'free'
      || selected.offer.freeMode === 'anonymous-ticket';
    return !needsInventory || (leg.inventory ?? 0) > 0;
  });
}

/**
 * Keeps provider selection visible before connection, then renders one dense
 * exact-offer row per role. It never logs or persists secret-bearing values.
 */
export class ProductAdmissionPanelV1 {
  private controller: ProductAdmissionControllerV1 | null = null;
  private snapshot: ProductAdmissionSnapshotV1 | null = null;
  private readonly rows = new Map<string, RoleElementsV1>();
  private publicError: string | null = null;
  private busy = false;

  constructor(private readonly options: ProductAdmissionPanelOptionsV1) {
    options.root.replaceChildren();
    const notice = document.createElement('p');
    notice.className = 'admission-notice';
    notice.dataset.admissionNotice = 'true';
    notice.setAttribute('role', 'status');
    notice.setAttribute('aria-live', 'polite');
    notice.textContent = 'Query access is not configured; queries are blocked.';
    options.root.appendChild(notice);

    if (options.transportCompatibilityNotice) {
      const boundary = document.createElement('p');
      boundary.className = 'admission-transport-boundary';
      boundary.dataset.transportBoundary = 'true';
      boundary.textContent = options.transportCompatibilityNotice;
      options.root.appendChild(boundary);
    }

    for (const role of options.roles) {
      const row = document.createElement('div');
      row.className = 'admission-provider-row';
      row.dataset.role = role.role;

      const heading = document.createElement('div');
      heading.className = 'admission-provider-heading';
      const title = document.createElement('strong');
      title.textContent = role.label;
      const provider = document.createElement('select');
      provider.className = 'select admission-provider-select';
      provider.setAttribute('aria-label', `${role.label} trusted provider`);
      provider.addEventListener('change', () => this.handleProviderSelection(role.role));
      heading.append(title, provider);

      const identity = textLine('admission-provider-identity', 'Provider identity: not selected');
      const offer = document.createElement('select');
      offer.className = 'select admission-offer-select';
      offer.setAttribute('aria-label', `${role.label} Free or Premium exact signed service offer`);
      offer.disabled = true;
      offer.addEventListener('change', () => void this.handleOfferSelection(role.role, offer.value));
      const terms = textLine('admission-provider-terms', 'Scope/offer: unavailable');
      const warning = textLine('admission-provider-warning', 'Access: select Free or Premium');
      const status = textLine('admission-provider-status', 'Query access: blocked');
      status.setAttribute('role', 'status');
      status.setAttribute('aria-live', 'polite');
      const actions = document.createElement('div');
      actions.className = 'admission-provider-actions';

      row.append(heading, identity, offer, terms, warning, status, actions);
      options.root.appendChild(row);
      this.rows.set(role.role, { row, provider, identity, offer, terms, warning, status, actions });
    }

    const advanced = document.createElement('label');
    advanced.className = 'admission-shared-infrastructure';
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.dataset.action = 'allow-shared-infrastructure';
    checkbox.addEventListener('change', () => void this.handleSharedInfrastructure(checkbox.checked));
    const advancedText = document.createElement('span');
    advancedText.textContent = 'Advanced: for this attempt only, allow one issuer and/or Lightning payee to correlate both provider purchases, identities and timing';
    advanced.append(checkbox, advancedText);
    if (options.roles.length < 2) advanced.hidden = true;
    options.root.appendChild(advanced);
  }

  setProviderOptions(options: ProductProviderChoiceV1[]): void {
    for (const row of this.rows.values()) {
      const previous = row.provider.value;
      row.provider.replaceChildren(optionElement('', 'Select trusted provider…'));
      for (const provider of options) {
        const suffix = provider.source === 'directory' ? ' · verified directory' : ' · manual';
        row.provider.appendChild(optionElement(provider.providerIdHex, provider.label + suffix));
      }
      if (options.some((candidate) => candidate.providerIdHex === previous)) {
        row.provider.value = previous;
      }
    }
    this.renderUnavailable(
      options.length === 0
        ? 'Query access is not configured. Load a complete trusted bootstrap before querying.'
        : this.options.roles.length > 1
          ? 'Verify the first provider’s identity, software, and database, then select Free or Premium access. The second role will then be enabled; Premium authorization remains disabled.'
          : 'Verify the provider’s identity, software, and database, then select Free or Premium access.',
    );
  }

  selectedProviderIds(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [role, row] of this.rows) {
      if (!row.provider.value) throw new Error(`select a trusted provider for ${role}`);
      out[role] = row.provider.value;
    }
    return out;
  }

  selectedProviderId(role: string): string {
    const row = this.rows.get(role);
    if (!row) throw new Error(`unknown provider role ${role}`);
    if (!row.provider.value) throw new Error(`select a trusted provider for ${role}`);
    return row.provider.value;
  }

  /** Capture and lock the exact staged provider before any asynchronous
   * bootstrap work starts. A failed bootstrap render re-enables this row. */
  freezeProviderSelection(role: string): string {
    const providerId = this.selectedProviderId(role);
    this.rows.get(role)!.provider.disabled = true;
    return providerId;
  }

  attach(controller: ProductAdmissionControllerV1): void {
    this.controller = controller;
    this.publicError = null;
    this.render(controller.snapshot());
  }

  detach(message = 'Query access is not configured; queries are blocked.'): void {
    this.controller = null;
    this.snapshot = null;
    this.busy = false;
    for (const row of this.rows.values()) row.provider.disabled = false;
    this.renderUnavailable(message);
    this.options.onStateChange?.(null);
  }

  render(snapshot = this.controller?.snapshot() ?? null): void {
    this.snapshot = snapshot;
    const notice = this.options.root.querySelector<HTMLElement>('[data-admission-notice]');
    if (notice) {
      notice.textContent = this.publicError
        ?? (snapshot?.phase === 'ready-to-query'
          ? 'All exact provider roles are authorized. The next action sends one query to every required provider role.'
          : snapshot?.phase === 'querying'
            ? 'One authorized PIR query is in flight; it will not be retried automatically.'
            : snapshot?.legs.length === 1 && canBootstrapNextProviderV1(snapshot)
              ? 'First exact offer is locked. Verify the independent second provider before any Premium acquisition or payment.'
              : snapshot?.legs.length === 2 && !credentialActionsReadyV1(snapshot)
                ? 'Both providers are verified. Choose Free access on each provider for best-effort capacity, or select a Premium method before authorization.'
                : snapshot?.legs.length === 2 && !snapshot.legs.every((leg) => leg.status === 'authorized'
                  || leg.status === 'cached-resource-ready')
                  ? 'Both access methods are selected. Request Free access directly, or complete the selected Premium authorization for each provider independently.'
                : snapshot?.legs.length === 1
                ? 'Select the first provider Free or Premium method before connecting the second.'
                : this.options.roles.length > 1
                  ? 'Verify and authorize the first independent provider.'
                  : 'Verify and authorize the provider.');
      notice.classList.toggle('error', this.publicError !== null || snapshot?.phase === 'failed');
    }
    if (!snapshot) return;
    const preparedRoles = new Set(snapshot.legs.map((leg) => leg.role));
    const previousLegsReady = snapshot.legs.length === 0
      || canBootstrapNextProviderV1(snapshot);
    const nextRole = this.options.roles[snapshot.legs.length]?.role;
    for (const [role, row] of this.rows) {
      if (preparedRoles.has(role)) {
        row.provider.disabled = true;
      } else {
        const available = role === nextRole && previousLegsReady;
        row.provider.disabled = this.busy || !available;
        this.renderPendingLeg(row, available);
      }
    }
    for (const leg of snapshot.legs) this.renderLeg(leg);
    const shared = this.options.root.querySelector<HTMLInputElement>(
      '[data-action="allow-shared-infrastructure"]',
    );
    if (shared) shared.checked = snapshot.allowSharedInfrastructureCorrelationOnce;
    this.options.onStateChange?.(snapshot);
  }

  private renderLeg(leg: ProductAdmissionLegSnapshotV1): void {
    const row = this.rows.get(leg.role);
    if (!row) return;
    row.identity.textContent = `Provider identity: ${abbreviate(leg.providerIdHex)} · policy ${abbreviate(leg.policyDigestHex)}`;
    const selectedValue = leg.retainedSelected
      ? (leg.retainedSelected.recoveryId
        ? recoveryChoiceValue(leg.retainedSelected.recoveryId)
        : retainedChoiceValue({
          ...leg.retainedSelected.binding,
          acquisitionContext: leg.retainedSelected.acquisitionContext,
        }))
      : leg.selected ? choiceValue(leg.selected.scopeIdHex, leg.selected.offerId) : '';
    row.offer.replaceChildren(optionElement('', 'Select Free or Premium access…'));
    const groupedOffers = partitionOfferOptionsForDisplayV1(leg.offers);
    appendOfferGroup(
      row.offer,
      'Free access · best effort, may queue or rate-limit',
      groupedOffers.free,
    );
    appendOfferGroup(
      row.offer,
      'Premium access · authorization required',
      groupedOffers.premium,
    );
    for (const capability of leg.retainedCapabilities) {
      row.offer.appendChild(optionElement(
        retainedChoiceValue(capability),
        retainedCapabilityLabelV1(capability),
      ));
    }
    for (const recovery of leg.retainedRecoveries) {
      row.offer.appendChild(optionElement(
        recoveryChoiceValue(recovery.id),
        retainedRecoveryLabelV1(recovery),
      ));
    }
    row.offer.value = selectedValue;
    row.offer.disabled = this.busy || leg.status === 'authorized'
      || leg.status === 'cached-resource-ready' || leg.status === 'ambiguous-spend';

    const selected = leg.retainedSelected
      ? retainedAsOfferOption(leg.retainedSelected.redemption)
      : leg.offers.find(
      (option) => choiceValue(option.scopeIdHex, option.offerId) === selectedValue,
      );
    row.terms.textContent = selected
      ? `${leg.retainedSelected ? 'Retained signed terms' : 'Scope'} ${abbreviate(selected.scopeIdHex)} · ${selected.scope.workload} · ${accessTermsLabel(selected.offer)} · ${limitsLabel(selected)}`
      : 'Scope/offer: choose Free or Premium access';
    row.warning.textContent = selected
      ? privacyLabelForOfferV1(selected.offer)
      : 'Access: no Free or Premium method selected';
    row.warning.classList.toggle(
      'experimental',
      selected?.offer.authorization === 'arc-experimental',
    );
    row.status.textContent = statusLabel(leg, selected);
    row.status.className = `admission-provider-status status-${leg.status}`;
    this.renderActions(
      row.actions,
      leg,
      selected,
      leg.retainedSelected !== null,
      this.snapshot !== null && credentialActionsReadyV1(this.snapshot),
      this.snapshot !== null && pairAuthorizationReadyV1(this.snapshot),
    );
  }

  private renderActions(
    container: HTMLElement,
    leg: ProductAdmissionLegSnapshotV1,
    selected: ProductOfferOptionV1 | undefined,
    retained: boolean,
    credentialActionsReady: boolean,
    authorizationReady: boolean,
  ): void {
    container.replaceChildren();
    if (!selected || !credentialActionsReady) return;

    if (leg.invoice) {
      const invoice = document.createElement('textarea');
      invoice.className = 'admission-invoice';
      invoice.readOnly = true;
      invoice.rows = 2;
      invoice.value = leg.invoice;
      invoice.setAttribute('aria-label', `${leg.label} BOLT11 invoice`);
      container.appendChild(invoice);
      container.appendChild(actionButton('Copy BOLT11 invoice', () => void copyText(invoice.value)));
      container.appendChild(actionButton('Check Premium payment', () => this.runAction(
        () => this.controller!.pollBolt11(leg.role),
      )));
      if (leg.status === 'payment-settled') {
        container.appendChild(actionButton('Claim Premium capability', () => this.runAction(
          () => this.controller!.claimBolt11(leg.role),
        )));
      }
      return;
    }

    if (leg.recoveryIds.length > 0) {
      container.appendChild(actionButton('Resume encrypted Premium invoice recovery', () => this.runAction(
        () => this.controller!.resumeBolt11(leg.role, leg.recoveryIds[0]),
      )));
    }

    if (!retained && selected.offer.acquisition === 'bolt11') {
      container.appendChild(actionButton('Create Premium BOLT11 invoice', () => this.runAction(
        () => this.controller!.startBolt11(leg.role),
      )));
    }

    if (!retained && selected.offer.acquisition === 'cashu-ecash') {
      const token = document.createElement('textarea');
      token.className = 'admission-cashu-token';
      token.rows = 2;
      token.placeholder = 'Paste cashuA / cashuB token';
      token.autocomplete = 'off';
      token.spellcheck = false;
      token.setAttribute('aria-label', `${leg.label} standard Cashu token`);
      container.appendChild(token);
      container.appendChild(actionButton('Import Premium Cashu token', async () => {
        const value = token.value;
        token.value = '';
        await this.runAction(() => this.controller!.importStandardCashu(leg.role, value));
      }));
    }

    if (leg.status !== 'authorized' && leg.status !== 'cached-resource-ready'
        && leg.status !== 'ambiguous-spend'
        && (!retained || (leg.inventory ?? 0) > 0)
        && (authorizationReady || selected.scope.workload === 'harmony-hint')) {
      container.appendChild(actionButton(
        selected.scope.workload === 'harmony-hint'
          ? `Use cache or ${selected.offer.authorization === 'free' ? 'request Free access' : 'authorize Premium access'}`
          : selected.offer.authorization === 'free' ? 'Request Free access' : 'Authorize Premium access',
        () => this.runAction(() => this.controller!.authorize(leg.role)),
      ));
    }
  }

  private async handleOfferSelection(role: string, value: string): Promise<void> {
    if (!this.controller || !value) return;
    if (value.startsWith('retained:')) {
      const leg = this.snapshot?.legs.find((candidate) => candidate.role === role);
      if (!leg) return;
      const selected = leg.retainedCapabilities.find(
        (candidate) => retainedChoiceValue(candidate) === value,
      );
      if (!selected) return;
      await this.runAction(() => this.controller!.selectRetainedCapability(role, selected));
      return;
    }
    if (value.startsWith('recovery:')) {
      await this.runAction(() => this.controller!.selectRetainedRecovery(
        role,
        value.slice('recovery:'.length),
      ));
      return;
    }
    const [scopeIdHex, offerIdText] = value.split(':');
    await this.runAction(() => this.controller!.selectOffer(role, {
      scopeIdHex,
      offerId: Number(offerIdText),
    }));
  }

  private async handleSharedInfrastructure(allowed: boolean): Promise<void> {
    if (!this.controller) return;
    await this.runAction(async () => this.controller!.setAllowSharedInfrastructureCorrelationOnce(allowed));
  }

  private async runAction(
    action: () => Promise<ProductAdmissionSnapshotV1> | ProductAdmissionSnapshotV1,
  ): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    this.publicError = null;
    this.render();
    try {
      await this.options.beforeSecurityTransition?.();
      const snapshot = await action();
      this.render(snapshot);
    } catch (error) {
      this.publicError = publicAdmissionError(error);
      this.render(this.controller?.snapshot() ?? null);
    } finally {
      this.busy = false;
      this.render(this.controller?.snapshot() ?? null);
    }
  }

  private invalidatePreparedAttempt(): void {
    if (!this.controller) return;
    this.publicError = 'Provider selection changed. Cancel this connection and start provider verification again.';
    this.render();
  }

  private handleProviderSelection(role: string): void {
    if (this.snapshot?.legs.some((leg) => leg.role === role)) {
      this.invalidatePreparedAttempt();
      return;
    }
    const row = this.rows.get(role);
    if (!row) return;
    row.identity.textContent = row.provider.value
      ? `Trusted bootstrap: ${abbreviate(row.provider.value)}`
      : 'Provider identity: not selected';
  }

  private renderPendingLeg(row: RoleElementsV1, available: boolean): void {
    row.identity.textContent = row.provider.value
      ? `Trusted bootstrap: ${abbreviate(row.provider.value)}`
      : 'Provider identity: not selected';
    row.offer.replaceChildren(optionElement('', available
      ? 'Connect provider to load signed offers'
      : 'Complete previous provider first'));
    row.offer.disabled = true;
    row.terms.textContent = available
      ? 'Scope/offer: connect this provider to load Free and Premium methods'
      : 'Scope/offer: waiting for the previous provider';
    row.warning.textContent = 'Access: this provider has not been contacted';
    row.warning.classList.remove('experimental');
    row.status.textContent = available ? 'Query access: ready for provider verification' : 'Query access: waiting';
    row.status.className = 'admission-provider-status status-strict-bootstrap-pending';
    row.actions.replaceChildren();
  }

  private renderUnavailable(message: string): void {
    const notice = this.options.root.querySelector<HTMLElement>('[data-admission-notice]');
    if (notice) {
      notice.textContent = message;
      notice.classList.add('error');
    }
    let roleIndex = 0;
    for (const row of this.rows.values()) {
      row.provider.disabled = roleIndex > 0;
      roleIndex += 1;
      row.identity.textContent = row.provider.value
        ? `Trusted bootstrap: ${abbreviate(row.provider.value)}`
        : 'Provider identity: not selected';
      row.offer.replaceChildren(optionElement('', 'Signed policy required'));
      row.offer.disabled = true;
      row.terms.textContent = 'Scope/offer: unavailable';
      row.warning.textContent = 'Access: no Free or Premium method selected';
      row.status.textContent = 'Query access: blocked';
      row.actions.replaceChildren();
    }
  }
}

export function publicAdmissionError(error: unknown): string {
  const code = error instanceof ProductAdmissionErrorV1 ? error.code : 'operation-failed';
  return publicErrorForCode(code);
}

function publicErrorForCode(code: ProductAdmissionErrorCodeV1): string {
  switch (code) {
    case 'commercial-admission-unconfigured': return 'Query access is not configured.';
    case 'strict-bootstrap-failed': return 'Strict server verification failed; no quote, capability, or query was sent.';
    case 'policy-unavailable': return 'A live signed V1 policy/anchor is unavailable; legacy query access is disabled.';
    case 'query-shape-unavailable': return 'The exact backend planner demand is unavailable; no offer or capability may be used.';
    case 'entitlement-limits-insufficient': return 'The signed entitlement is below the backend planner’s known demand; no payment or capability was used.';
    case 'offer-selection-invalidated': return 'The exact offer selection changed or is incomplete; restart provider verification.';
    case 'pair-correlation-rejected': return 'The selected pair shares an issuer or trust key; choose independently, or use the one-attempt advanced confirmation.';
    case 'lightning-payee-untrusted': return 'BOLT11 is blocked because no independent expected-payee key is trusted.';
    case 'bolt11-recovery-required': return 'The invoice response may have been lost. Resume the encrypted recovery; do not create another invoice.';
    case 'capability-inventory-empty': return 'No exact capability is available. Import or purchase one before authorization.';
    case 'ambiguous-capability-spend': return 'Capability spend is ambiguous. It will not be retried automatically.';
    case 'resource-failed-after-authorization': return 'Authorization succeeded but the resource failed. It will not retry automatically.';
    default: return 'Provider verification operation failed without exposing secret material.';
  }
}

function appendOfferGroup(
  select: HTMLSelectElement,
  label: string,
  offers: ProductOfferOptionV1[],
): void {
  if (offers.length === 0) return;
  const group = document.createElement('optgroup');
  group.label = label;
  for (const option of offers) {
    group.appendChild(optionElement(
      choiceValue(option.scopeIdHex, option.offerId),
      offerChoiceLabelForOfferV1(option),
    ));
  }
  select.appendChild(group);
}

export function partitionOfferOptionsForDisplayV1(options: ProductOfferOptionV1[]): {
  free: ProductOfferOptionV1[];
  premium: ProductOfferOptionV1[];
} {
  return {
    free: options.filter((option) => option.offer.authorization === 'free'),
    premium: options.filter((option) => option.offer.authorization !== 'free'),
  };
}

export function offerChoiceLabelForOfferV1(option: ProductOfferOptionV1): string {
  const offer = option.offer;
  if (offer.authorization === 'free') {
    return `#${offer.offerId} · Free access · ${freeAccessModeLabel(offer.freeMode)} · no charge`;
  }
  return `#${offer.offerId} · Premium access · ${premiumMethodLabel(offer)} · ${priceLabel(option)}`;
}

function accessTermsLabel(offer: ProductOfferOptionV1['offer']): string {
  return offer.authorization === 'free'
    ? `Free access · ${freeAccessModeLabel(offer.freeMode)} · no payment required`
    : `Premium access · ${premiumMethodLabel(offer)} · authorization required · ${priceLabelForOffer(offer)}`;
}

function freeAccessModeLabel(offerFreeMode: ProductOfferOptionV1['offer']['freeMode']): string {
  switch (offerFreeMode) {
    case 'open-best-effort': return 'best effort, may queue';
    case 'ip-rate-limited': return 'rate limited, may queue';
    case 'proof-of-work': return 'one-shot proof of work, may queue';
    case 'anonymous-ticket': return 'anonymous ticket, may queue';
    default: return 'provider-defined free policy';
  }
}

function premiumMethodLabel(offer: ProductOfferOptionV1['offer']): string {
  if (offer.authorization === 'bolt11-direct-receipt') return 'BOLT11 direct receipt';
  if (offer.authorization === 'cashu-bat') return 'Cashu BAT · acquire with BOLT11';
  if (offer.authorization === 'cashu-ecash') return 'Cashu eCash';
  if (offer.authorization === 'arc-experimental') return 'ARC · EXPERIMENTAL · acquire with BOLT11';
  return offer.authorization;
}

function priceLabel(option: ProductOfferOptionV1): string {
  return priceLabelForOffer(option.offer);
}

function priceLabelForOffer(offer: ProductOfferOptionV1['offer']): string {
  const price = offer.price;
  if (price.kind === 'free') return 'free';
  return price.kind === 'msat'
    ? `${price.amount} msat`
    : `${price.amount} ${price.unit ?? 'cashu units'}`;
}

function limitsLabel(option: ProductOfferOptionV1): string {
  const limits = option.scope.limits;
  return [
    `caps inputs=${limits.maxLogicalInputs}`,
    `frames=${limits.maxFrames}`,
    `request=${limits.maxRequestBytes}B`,
    `response=${limits.maxResponseBytes}B`,
    `wall=${limits.maxWallTimeMs}ms`,
    `sockets=${limits.maxConcurrentSockets}`,
    `hints=${limits.maxHintGroups}`,
    `work=${limits.maxWorkUnits}`,
  ].join(', ');
}

export function privacyLabelForOfferV1(offer: ProductOfferOptionV1['offer']): string {
  const flags = signedLeakageFlags(offer.privacyLeakageBits);
  if (offer.authorization === 'free') {
    if (offer.freeMode === 'ip-rate-limited') return 'Privacy: provider observes IP rate-limit bucket';
    if (offer.freeMode === 'proof-of-work') return 'Privacy: provider sees a one-shot connection-bound PoW';
    if (offer.freeMode === 'anonymous-ticket') {
      return offer.verification === 'shared-issuer-online'
        ? `Privacy: free ticket issuer observes redemption timing and provider; cross-leg timing can correlate (${flags})`
        : `Privacy: provider-local anonymous ticket; issuer sees issuance timing and provider sees a bearer proof (${flags})`;
    }
    return 'Privacy: no payer or invoice identifier';
  }
  if (offer.authorization === 'arc-experimental') {
    return `EXPERIMENTAL ARC: cryptography not independently reviewed; issuer/provider timing correlation remains possible (${flags})`;
  }
  if (offer.authorization === 'cashu-bat') {
    return offer.verification === 'provider-local'
      ? `Privacy: blinded provider-local BAT; server sees a bearer, not invoice/hash; purchase timing remains observable (${flags})`
      : `Privacy: BAT issuer is online at redemption and learns provider/timing; server does not receive invoice/hash (${flags})`;
  }
  if (offer.authorization === 'cashu-ecash') {
    return `Privacy: standard Cashu mint is online at redemption and observes provider/timing; server sees proof, not invoice/hash (${flags})`;
  }
  if (offer.authorization === 'bolt11-direct-receipt') {
    return `Privacy: DIRECT BOLT11 receipt links payment acquisition to this spend/provider; do not treat it as anonymous (${flags})`;
  }
  return `Privacy: server receives a capability, not invoice/payment hash (${flags})`;
}

function signedLeakageFlags(bits: number): string {
  const labels: string[] = [];
  if ((bits & (1 << 0)) !== 0) labels.push('IP rate bucket');
  if ((bits & (1 << 1)) !== 0) labels.push('direct payment-to-spend');
  if ((bits & (1 << 2)) !== 0) labels.push('issuer issuance timing');
  if ((bits & (1 << 3)) !== 0) labels.push('issuer redemption timing');
  if ((bits & (1 << 4)) !== 0) labels.push('issuer learns provider');
  if ((bits & (1 << 5)) !== 0) labels.push('provider-local bearer');
  return labels.length > 0 ? labels.join(', ') : 'signed leakage: none';
}

function statusLabel(
  leg: ProductAdmissionLegSnapshotV1,
  selected: ProductOfferOptionV1 | undefined,
): string {
  const access = selected?.offer.authorization === 'free' ? 'Free access' : 'Premium access';
  if (leg.status === 'ambiguous-spend') return 'Query access: ambiguous spend — no retry';
  if (leg.status === 'authorized') return selected?.offer.authorization === 'free'
    ? 'Free access: ready for one query'
    : `${access}: authorized for one query`;
  if (leg.status === 'cached-resource-ready') return `${access}: exact verified hint cache hit — no hint purchase`;
  if (leg.status === 'invoice-open') return `Invoice: open${leg.invoiceExpiresAtUnix ? ` · expires ${leg.invoiceExpiresAtUnix}` : ''}`;
  if (leg.status === 'payment-settled') return 'Invoice: payment settled · claim required';
  if (leg.status === 'failed') return 'Query access: failed closed';
  if (selected && (selected.offer.authorization === 'cashu-bat'
      || selected.offer.authorization === 'arc-experimental') && leg.inventory === 0) {
    return `Inventory: 0 · import or acquire a capability first${selected.offer.authorization === 'arc-experimental' ? ' · EXPERIMENTAL' : ''}`;
  }
  if (selected?.offer.authorization === 'free') {
    return `Free access: selected · ${freeAccessModeLabel(selected.offer.freeMode)}`;
  }
  if (leg.inventory !== null) return `Inventory: ${leg.inventory} exact capability record(s)`;
  return `Query access: ${leg.status}`;
}

function actionButton(label: string, action: () => void | Promise<void>): HTMLButtonElement {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'btn ghost sm';
  button.textContent = label;
  button.addEventListener('click', () => void action());
  return button;
}

function optionElement(value: string, label: string): HTMLOptionElement {
  const option = document.createElement('option');
  option.value = value;
  option.textContent = label;
  return option;
}

function textLine(className: string, value: string): HTMLElement {
  const element = document.createElement('div');
  element.className = className;
  element.textContent = value;
  return element;
}

function choiceValue(scopeIdHex: string, offerId: number): string {
  return `${scopeIdHex}:${offerId}`;
}

function retainedChoiceValue(binding: ProductRetainedCapabilitySelectorV1): string {
  const context = binding.acquisitionContext;
  const contextSelector = context
    ? [context.issuerIdHex, context.network, context.expectedPayeePubkeyHex,
      encodeURIComponent(context.issuerEndpoint)].join('.')
    : 'non-bolt11';
  return [
    'retained',
    binding.policyDigestHex,
    binding.scopeIdHex,
    String(binding.offerId),
    binding.scheme,
    contextSelector,
  ].join(':');
}

/**
 * Keep otherwise identical retained bindings distinguishable by their exact
 * BOLT11 acquisition context without exposing invoices or capability bytes.
 */
export function retainedCapabilityLabelV1(
  capability: ProductRetainedCapabilityOptionV1,
): string {
  const prefix = `Retained ${capability.scheme} · policy ${abbreviate(capability.policyDigestHex)} · #${capability.offerId} · ${capability.count} left`;
  const context = capability.acquisitionContext;
  if (context) {
    return `${prefix} · ${bolt11AcquisitionContextLabelV1(context)}`;
  }
  if (capability.scheme === 'bolt11-direct-receipt') {
    return `${prefix} · legacy BOLT11 context missing · unusable`;
  }
  return prefix;
}

export function retainedRecoveryLabelV1(
  recovery: ProductRetainedRecoveryOptionV1,
): string {
  return `Recover encrypted ${recovery.binding.scheme} quote · policy ${abbreviate(recovery.binding.policyDigestHex)} · #${recovery.binding.offerId} · ${bolt11AcquisitionContextLabelV1(recovery.acquisitionContext)}`;
}

function bolt11AcquisitionContextLabelV1(
  context: NonNullable<ProductRetainedCapabilitySelectorV1['acquisitionContext']>,
): string {
  const issuerOrigin = canonicalIssuerOriginForLabelV1(context.issuerEndpoint);
  return `BOLT11 ${context.network} · issuer ${abbreviate(context.issuerIdHex)} · origin ${issuerOrigin} · payee ${abbreviate(context.expectedPayeePubkeyHex)}`;
}

function canonicalIssuerOriginForLabelV1(value: string): string {
  let parsed: URL;
  try { parsed = new URL(value); } catch {
    throw new Error('retained BOLT11 issuer endpoint is invalid');
  }
  const loopback = parsed.hostname === '127.0.0.1'
    || parsed.hostname === 'localhost'
    || parsed.hostname === '[::1]';
  if ((parsed.protocol !== 'https:' && !(loopback && parsed.protocol === 'http:'))
      || parsed.username || parsed.password || parsed.search || parsed.hash
      || (parsed.pathname !== '' && parsed.pathname !== '/')) {
    throw new Error('retained BOLT11 issuer endpoint must be a credential-free origin');
  }
  return parsed.origin;
}

function recoveryChoiceValue(recoveryId: string): string {
  return `recovery:${recoveryId}`;
}

function retainedAsOfferOption(
  redemption: RetainedServiceRedemptionViewV1,
): ProductOfferOptionV1 {
  return {
    scopeIdHex: redemption.scope.scopeIdHex,
    offerId: redemption.offer.offerId,
    scope: {
      ...redemption.scope,
      dataset: { ...redemption.scope.dataset },
      limits: { ...redemption.scope.limits },
      offers: [],
    },
    offer: { ...redemption.offer, price: { ...redemption.offer.price } },
  };
}

function abbreviate(value: string): string {
  return value.length > 20 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
}

async function copyText(value: string): Promise<void> {
  if (!value) return;
  await navigator.clipboard.writeText(value);
}
