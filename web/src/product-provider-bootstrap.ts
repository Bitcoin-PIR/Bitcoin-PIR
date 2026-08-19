/** In-memory trusted product bootstrap. Nothing in this module persists it. */

import type { ServerAttestPin } from './attest-pin.js';
import type { DatabaseProofPin } from './db-proof.js';
import { hexToBytes } from './hash.js';
import type { SelectableDirectoryEntryV1 } from './directory-vault.js';
import { directoryProviderTrustAnchorV1 } from './nostr-directory.js';
import type { ProviderTrustAnchorV1 } from './service-admission.js';
import type { LightningNetworkNameV1 } from './admission-vault.js';
import type { ServiceOfferViewV1 } from './sdk-bridge.js';
import {
  parseTrustedBatV2PublicClassCatalogRefV2,
  type TrustedBatV2PublicClassCatalogRefV2,
} from './bat-v2-class-catalog.js';

const MAX_LIGHTNING_PAYEE_TRUST_ENTRIES_V1 = 64;

/**
 * Workloads that can be routed to one provider role before a connection is
 * opened. This is an operator-published routing allowlist, not a capability
 * grant: the live signed service policy remains the final authority.
 */
export type ProductAdmissionWorkloadV1 =
  | 'dpf-query'
  | 'harmony-hint'
  | 'harmony-query'
  | 'onion-session'
  | 'tee-oram-query';

export type ProductAdmissionRouteV1 = readonly [role: string, workload: ProductAdmissionWorkloadV1];

export interface ProductLightningPayeeTrustV1 {
  /** Exact issuer identity committed by the signed service offer. */
  issuerIdHex: string;
  /** Credential-free HTTPS origin committed by the signed service offer. */
  issuerOrigin: string;
  /** Exact BOLT11 network accepted for this issuer/payee tuple. */
  network: LightningNetworkNameV1;
  /** Independently trusted compressed secp256k1 Lightning node identity. */
  expectedPayeePubkeyHex: string;
}

export interface ProductTrustedProviderV1 {
  label: string;
  endpoint: string;
  providerIdHex: string;
  policySigningKeyHex: string;
  operatorSigningKeyHex: string;
  stableServerId: string;
  serverPin: ServerAttestPin;
  /** Explicitly records why a missing hardware measurement is accepted. */
  hardwareAttestation: 'required' | 'unavailable-accepted';
  expectedArkFingerprintHex?: string;
  /** Explicit pre-connection workload routing; absence is rejected. */
  supportedWorkloads: readonly ProductAdmissionWorkloadV1[];
  databaseProofPins: DatabaseProofPin[];
  /** Independent exact-offer payment trust; the Nostr directory does not supply this. */
  lightningPayeeTrust: ProductLightningPayeeTrustV1[];
}

export interface ProductTrustedBootstrapV1 {
  version: 1;
  network: LightningNetworkNameV1;
  providers: ProductTrustedProviderV1[];
  /** Independent trusted-render root. Directory catalog hints never fill it. */
  batV2ClassCatalog?: TrustedBatV2PublicClassCatalogRefV2;
}

/**
 * Reject an obvious shared network ingress before the browser opens the second
 * PIR connection.  The later offer-pair guard still checks issuer, receipt
 * key, and Lightning payee material learned from the authenticated policy.
 */
export function assertIndependentProviderDialPairV1(
  first: Pick<ProductTrustedProviderV1,
    'providerIdHex' | 'endpoint' | 'policySigningKeyHex'
    | 'operatorSigningKeyHex' | 'stableServerId'>,
  second: Pick<ProductTrustedProviderV1,
    'providerIdHex' | 'endpoint' | 'policySigningKeyHex'
    | 'operatorSigningKeyHex' | 'stableServerId'>,
): void {
  if (first.providerIdHex === second.providerIdHex) {
    throw new Error('independent PIR roles must select distinct provider identities');
  }
  if (trustedWebSocketOrigin(first.endpoint) === trustedWebSocketOrigin(second.endpoint)) {
    throw new Error('independent PIR roles must not share one WebSocket origin');
  }
  if (first.operatorSigningKeyHex === second.operatorSigningKeyHex) {
    throw new Error('independent PIR roles must not share one operator signing key');
  }
  if (first.policySigningKeyHex === second.policySigningKeyHex) {
    throw new Error('independent PIR roles must not share one policy signing key');
  }
  if (first.stableServerId === second.stableServerId) {
    throw new Error('independent PIR roles must not share one stable server identity');
  }
}

export function parseProductTrustedBootstrapV1(serialized: string): ProductTrustedBootstrapV1 {
  let parsed: unknown;
  try { parsed = JSON.parse(serialized); } catch {
    throw new Error('trusted provider bootstrap must be valid JSON');
  }
  if (!isRecord(parsed) || parsed.version !== 1
      || !isNetwork(parsed.network) || !Array.isArray(parsed.providers)
      || parsed.providers.length === 0 || parsed.providers.length > 64) {
    throw new Error('trusted provider bootstrap has an invalid V1 envelope');
  }
  const providers = parsed.providers.map((value, index) => parseProvider(value, index));
  requireUnique(providers.map((value) => value.providerIdHex), 'provider ID');
  const batV2ClassCatalog = parsed.batV2ClassCatalog === undefined
    ? undefined
    : parseTrustedBatV2PublicClassCatalogRefV2(parsed.batV2ClassCatalog);
  return { version: 1, network: parsed.network, providers, batV2ClassCatalog };
}

/** Return an owned trusted catalog ref; callers cannot mutate bootstrap state. */
export function productBatV2ClassCatalogRefV2(
  bootstrap: ProductTrustedBootstrapV1,
): TrustedBatV2PublicClassCatalogRefV2 | undefined {
  return bootstrap.batV2ClassCatalog
    ? { ...bootstrap.batV2ClassCatalog }
    : undefined;
}

/** Manual anchors cannot pre-commit an unknown live policy epoch/digest. */
export function manualProviderAdmissionTrustAnchorV1(
  provider: ProductTrustedProviderV1,
): ProviderTrustAnchorV1 {
  return {
    providerId: hexToBytes(provider.providerIdHex),
    policySigningKey: hexToBytes(provider.policySigningKeyHex),
  };
}

/**
 * Prefer the durably verified directory anchor, while requiring every
 * security-critical key/ID to agree with independent trusted bootstrap.
 * Directory health and catalog-hint pin fields are deliberately ignored.
 */
export function directoryBoundProviderTrustAnchorV1(
  entry: SelectableDirectoryEntryV1,
  provider: ProductTrustedProviderV1,
): ProviderTrustAnchorV1 {
  if (entry.providerIdHex !== provider.providerIdHex
      || entry.policySigningKeyEd25519Hex !== provider.policySigningKeyHex
      || entry.operatorPubkeyEd25519Hex !== provider.operatorSigningKeyHex
      || entry.stableServerId !== provider.stableServerId) {
    throw new Error('verified directory entry does not match independent provider bootstrap');
  }
  return directoryProviderTrustAnchorV1(entry);
}

export function providerOperatorKeyV1(provider: ProductTrustedProviderV1): Uint8Array {
  return hexToBytes(provider.operatorSigningKeyHex);
}

/** Return an owned copy so callers cannot mutate the in-memory bootstrap. */
export function providerLightningPayeeTrustV1(
  provider: ProductTrustedProviderV1,
): ProductLightningPayeeTrustV1[] {
  return provider.lightningPayeeTrust.map((entry) => ({ ...entry }));
}

/**
 * Resolve payment trust only after one exact signed offer has been selected.
 * Non-BOLT11 offers deliberately carry no Lightning payee. A BOLT11 offer
 * must match one independently bootstrapped `(issuer, origin, network)` tuple.
 * The canonical HTTPS origin comes from `offer.endpoint`; it is never the
 * provider's separately trusted WebSocket endpoint. Duplicate tuples are
 * rejected even when they repeat the same payee.
 */
export function expectedLightningPayeeForOfferV1(
  trust: readonly ProductLightningPayeeTrustV1[],
  offer: ServiceOfferViewV1,
  network: LightningNetworkNameV1,
): Uint8Array | undefined {
  if (offer.acquisition !== 'bolt11') return undefined;
  if (!Array.isArray(trust) || trust.length > MAX_LIGHTNING_PAYEE_TRUST_ENTRIES_V1
      || !isNetwork(network)) {
    throw new Error('Lightning payee trust is invalid');
  }
  const normalized = trust.map((entry, index) => parseLightningPayeeTrust(
    entry,
    `Lightning payee trust entry ${index}`,
  ));
  requireUnique(
    normalized.map(lightningPayeeTrustTupleV1),
    'Lightning payee trust tuple',
  );
  const issuerIdHex = nonzeroHex('signed offer issuer ID', offer.issuerIdHex, 64);
  const issuerOrigin = httpsOrigin('signed offer issuer endpoint', offer.endpoint);
  const matches = normalized.filter((entry) => entry.issuerIdHex === issuerIdHex
    && entry.issuerOrigin === issuerOrigin
    && entry.network === network);
  if (matches.length !== 1) {
    throw new Error('BOLT11 offer has no exact trusted Lightning payee');
  }
  return hexToBytes(matches[0].expectedPayeePubkeyHex);
}

export function providerArkFingerprintV1(
  provider: ProductTrustedProviderV1,
): Uint8Array | null {
  return provider.expectedArkFingerprintHex
    ? hexToBytes(provider.expectedArkFingerprintHex)
    : null;
}

export function providerSupportsWorkloadV1(
  provider: Pick<ProductTrustedProviderV1, 'supportedWorkloads'>,
  workload: ProductAdmissionWorkloadV1,
): boolean {
  return provider.supportedWorkloads.includes(workload);
}

/**
 * Pick deterministic defaults only from the explicitly declared workload
 * routes. A provider cannot fill two independent roles in one pair.
 */
export function defaultProviderIdsForAdmissionRoutesV1(
  providers: readonly Pick<ProductTrustedProviderV1, 'providerIdHex' | 'supportedWorkloads'>[],
  routes: readonly ProductAdmissionRouteV1[],
): Record<string, string> {
  const selected = new Set<string>();
  const defaults: Record<string, string> = {};
  for (const [role, workload] of routes) {
    const provider = providers.find((candidate) =>
      !selected.has(candidate.providerIdHex)
      && providerSupportsWorkloadV1(candidate, workload));
    if (!provider) return {};
    selected.add(provider.providerIdHex);
    defaults[role] = provider.providerIdHex;
  }
  return defaults;
}

function parseProvider(value: unknown, index: number): ProductTrustedProviderV1 {
  if (!isRecord(value)) throw new Error(`provider ${index} must be an object`);
  const label = boundedText(`provider ${index} label`, value.label, 1, 80);
  const endpoint = websocketOrigin(`provider ${index} endpoint`, value.endpoint);
  const providerIdHex = nonzeroHex(`provider ${index} ID`, value.providerIdHex, 64);
  const policySigningKeyHex = nonzeroHex(
    `provider ${index} policy key`, value.policySigningKeyHex, 64,
  );
  const operatorSigningKeyHex = nonzeroHex(
    `provider ${index} operator key`, value.operatorSigningKeyHex, 64,
  );
  if (policySigningKeyHex === operatorSigningKeyHex) {
    throw new Error(`provider ${index} must use distinct policy and operator keys`);
  }
  const stableServerId = boundedText(
    `provider ${index} stable server ID`, value.stableServerId, 1, 128,
  );
  if (value.hardwareAttestation !== 'required'
      && value.hardwareAttestation !== 'unavailable-accepted') {
    throw new Error(`provider ${index} hardwareAttestation is invalid`);
  }
  if (!isRecord(value.serverPin)) throw new Error(`provider ${index} serverPin is required`);
  const binarySha256Hex = nonzeroHex(
    `provider ${index} binary pin`, value.serverPin.binarySha256Hex, 64,
  );
  const measurementHex = value.serverPin.measurementHex === undefined
    ? undefined
    : nonzeroHex(`provider ${index} measurement pin`, value.serverPin.measurementHex, 96);
  if (value.hardwareAttestation === 'required' && !measurementHex) {
    throw new Error(`provider ${index} requires a hardware measurement pin`);
  }
  if (value.hardwareAttestation === 'unavailable-accepted' && measurementHex) {
    throw new Error(`provider ${index} cannot both pin and waive hardware measurement`);
  }
  const expectedArkFingerprintHex = value.expectedArkFingerprintHex === undefined
    ? undefined
    : nonzeroHex(`provider ${index} ARK fingerprint`, value.expectedArkFingerprintHex, 64);
  if (value.hardwareAttestation === 'required' && !expectedArkFingerprintHex) {
    throw new Error(`provider ${index} requires an independently pinned ARK fingerprint`);
  }
  if (!Array.isArray(value.supportedWorkloads)
      || value.supportedWorkloads.length === 0
      || value.supportedWorkloads.length > 8) {
    throw new Error(`provider ${index} must declare supported workloads`);
  }
  const supportedWorkloads = value.supportedWorkloads.map((workload, workloadIndex) => {
    if (!isProductAdmissionWorkload(workload)) {
      throw new Error(`provider ${index} workload ${workloadIndex} is invalid`);
    }
    return workload;
  });
  requireUnique(supportedWorkloads, `provider ${index} supported workload`);
  if (!Array.isArray(value.databaseProofPins) || value.databaseProofPins.length === 0) {
    throw new Error(`provider ${index} requires database proof pins`);
  }
  const databaseProofPins = value.databaseProofPins.map(
    (pin, pinIndex) => parseDatabasePin(pin, index, pinIndex),
  );
  requireUnique(databaseProofPins.map((pin) => String(pin.dbId)), `provider ${index} database ID`);
  if (value.expectedLightningPayeePubkeyHex !== undefined) {
    throw new Error(
      `provider ${index} provider-wide Lightning payee trust is not accepted`,
    );
  }
  if (!Array.isArray(value.lightningPayeeTrust)
      || value.lightningPayeeTrust.length > MAX_LIGHTNING_PAYEE_TRUST_ENTRIES_V1) {
    throw new Error(
      `provider ${index} lightningPayeeTrust must contain at most ${MAX_LIGHTNING_PAYEE_TRUST_ENTRIES_V1} entries`,
    );
  }
  const lightningPayeeTrust = value.lightningPayeeTrust.map((entry, trustIndex) => (
    parseLightningPayeeTrust(entry, `provider ${index} Lightning payee trust ${trustIndex}`)
  ));
  requireUnique(
    lightningPayeeTrust.map(lightningPayeeTrustTupleV1),
    `provider ${index} Lightning payee trust tuple`,
  );
  return {
    label,
    endpoint,
    providerIdHex,
    policySigningKeyHex,
    operatorSigningKeyHex,
    stableServerId,
    serverPin: { binarySha256Hex, measurementHex, description: label },
    hardwareAttestation: value.hardwareAttestation,
    expectedArkFingerprintHex,
    supportedWorkloads,
    databaseProofPins,
    lightningPayeeTrust,
  };
}

function parseLightningPayeeTrust(
  value: unknown,
  field: string,
): ProductLightningPayeeTrustV1 {
  if (!isRecord(value)) throw new Error(`${field} must be an object`);
  const issuerIdHex = nonzeroHex(`${field} issuer ID`, value.issuerIdHex, 64);
  const issuerOrigin = httpsOrigin(`${field} issuer origin`, value.issuerOrigin);
  if (!isNetwork(value.network)) throw new Error(`${field} network is invalid`);
  const expectedPayeePubkeyHex = compressedPubkeyHex(
    `${field} expected payee`,
    value.expectedPayeePubkeyHex,
  );
  return { issuerIdHex, issuerOrigin, network: value.network, expectedPayeePubkeyHex };
}

function lightningPayeeTrustTupleV1(value: ProductLightningPayeeTrustV1): string {
  return `${value.issuerIdHex}\u0000${value.issuerOrigin}\u0000${value.network}`;
}

function parseDatabasePin(value: unknown, providerIndex: number, pinIndex: number): DatabaseProofPin {
  if (!isRecord(value)) throw new Error(`provider ${providerIndex} database pin ${pinIndex} is invalid`);
  if (!Number.isSafeInteger(value.dbId) || (value.dbId as number) < 0
      || (value.buildKind !== 'snapshot' && value.buildKind !== 'delta')) {
    throw new Error(`provider ${providerIndex} database pin ${pinIndex} metadata is invalid`);
  }
  const numeric = ['fromHeight', 'height'] as const;
  for (const field of numeric) {
    if (!Number.isSafeInteger(value[field]) || (value[field] as number) < 0) {
      throw new Error(`provider ${providerIndex} database pin ${pinIndex} ${field} is invalid`);
    }
  }
  const hex32Fields = [
    'fromBlockHashHex', 'blockHashHex', 'muhashHex', 'bucketSuperRootHex',
    'onionSuperRootHex', 'paramsHashHex', 'builderBinarySha256Hex',
  ] as const;
  for (const field of hex32Fields) {
    // A full snapshot beginning at height zero has no predecessor block. The
    // production DB-proof format represents that explicit sentinel with 32
    // zero bytes; all other trust anchors remain non-zero.
    if (field === 'fromBlockHashHex'
        && value.buildKind === 'snapshot' && value.fromHeight === 0) {
      fixedHex(`database pin ${pinIndex} ${field}`, value[field], 64);
    } else {
      nonzeroHex(`database pin ${pinIndex} ${field}`, value[field], 64);
    }
  }
  nonzeroHex(`database pin ${pinIndex} networkMagicHex`, value.networkMagicHex, 8);
  boundedText(`database pin ${pinIndex} builderGitCommit`, value.builderGitCommit, 1, 128);
  if (value.fromMuhashHex !== undefined) {
    nonzeroHex(`database pin ${pinIndex} fromMuhashHex`, value.fromMuhashHex, 64);
  }
  return structuredClone(value) as unknown as DatabaseProofPin;
}

function websocketOrigin(field: string, value: unknown): string {
  if (typeof value !== 'string') throw new Error(`${field} must be wss://`);
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error(`${field} is invalid`); }
  if (parsed.protocol !== 'wss:' || parsed.username || parsed.password
      || parsed.search || parsed.hash || (parsed.pathname !== '' && parsed.pathname !== '/')) {
    throw new Error(`${field} must be a credential-free wss:// origin`);
  }
  return parsed.origin;
}

function httpsOrigin(field: string, value: unknown): string {
  if (typeof value !== 'string') throw new Error(`${field} must be https://`);
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error(`${field} is invalid`); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password
      || parsed.search || parsed.hash || (parsed.pathname !== '' && parsed.pathname !== '/')) {
    throw new Error(`${field} must be a credential-free https:// origin`);
  }
  return parsed.origin;
}

function trustedWebSocketOrigin(endpoint: string): string {
  let parsed: URL;
  try { parsed = new URL(endpoint); } catch {
    throw new Error('trusted provider endpoint is invalid');
  }
  if (parsed.protocol !== 'wss:' || parsed.username || parsed.password) {
    throw new Error('trusted provider endpoint must be a credential-free wss:// URL');
  }
  return parsed.origin;
}

function nonzeroHex(field: string, value: unknown, length: number): string {
  const hex = fixedHex(field, value, length);
  if (/^0+$/.test(hex)) {
    throw new Error(`${field} must be non-zero lowercase hex of length ${length}`);
  }
  return hex;
}

function fixedHex(field: string, value: unknown, length: number): string {
  if (typeof value !== 'string' || value.length !== length || !/^[0-9a-f]+$/.test(value)) {
    throw new Error(`${field} must be lowercase hex of length ${length}`);
  }
  return value;
}

function compressedPubkeyHex(field: string, value: unknown): string {
  const hex = nonzeroHex(field, value, 66);
  if (!hex.startsWith('02') && !hex.startsWith('03')) {
    throw new Error(`${field} must be a compressed secp256k1 public key`);
  }
  return hex;
}

function boundedText(field: string, value: unknown, min: number, max: number): string {
  if (typeof value !== 'string' || value.length < min || value.length > max
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${field} is invalid`);
  }
  return value;
}

function requireUnique(values: string[], label: string): void {
  if (new Set(values).size !== values.length) throw new Error(`duplicate ${label}`);
}

function isNetwork(value: unknown): value is LightningNetworkNameV1 {
  return value === 'bitcoin' || value === 'testnet' || value === 'signet' || value === 'regtest';
}

function isProductAdmissionWorkload(value: unknown): value is ProductAdmissionWorkloadV1 {
  return value === 'dpf-query'
    || value === 'harmony-hint'
    || value === 'harmony-query'
    || value === 'onion-session'
    || value === 'tee-oram-query';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
