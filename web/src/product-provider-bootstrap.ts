/** In-memory trusted product bootstrap. Nothing in this module persists it. */

import type { ServerAttestPin } from './attest-pin.js';
import type { DatabaseProofPin } from './db-proof.js';
import { hexToBytes } from './hash.js';
import type { SelectableDirectoryEntryV1 } from './directory-vault.js';
import { directoryProviderTrustAnchorV1 } from './nostr-directory.js';
import type { ProviderTrustAnchorV1 } from './service-admission.js';
import type { LightningNetworkNameV1 } from './admission-vault.js';

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
  databaseProofPins: DatabaseProofPin[];
  /** Independent payment trust; the Nostr directory does not supply this. */
  expectedLightningPayeePubkeyHex?: string;
}

export interface ProductTrustedBootstrapV1 {
  version: 1;
  network: LightningNetworkNameV1;
  providers: ProductTrustedProviderV1[];
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
  return { version: 1, network: parsed.network, providers };
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

export function providerExpectedPayeeV1(
  provider: ProductTrustedProviderV1,
): Uint8Array | undefined {
  return provider.expectedLightningPayeePubkeyHex
    ? hexToBytes(provider.expectedLightningPayeePubkeyHex)
    : undefined;
}

export function providerArkFingerprintV1(
  provider: ProductTrustedProviderV1,
): Uint8Array | null {
  return provider.expectedArkFingerprintHex
    ? hexToBytes(provider.expectedArkFingerprintHex)
    : null;
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
  if (!Array.isArray(value.databaseProofPins) || value.databaseProofPins.length === 0) {
    throw new Error(`provider ${index} requires database proof pins`);
  }
  const databaseProofPins = value.databaseProofPins.map(
    (pin, pinIndex) => parseDatabasePin(pin, index, pinIndex),
  );
  requireUnique(databaseProofPins.map((pin) => String(pin.dbId)), `provider ${index} database ID`);
  const expectedLightningPayeePubkeyHex = value.expectedLightningPayeePubkeyHex === undefined
    ? undefined
    : compressedPubkeyHex(
      `provider ${index} expected Lightning payee`,
      value.expectedLightningPayeePubkeyHex,
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
    databaseProofPins,
    expectedLightningPayeePubkeyHex,
  };
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
    nonzeroHex(`database pin ${pinIndex} ${field}`, value[field], 64);
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
  if (typeof value !== 'string' || value.length !== length
      || !/^[0-9a-f]+$/.test(value) || /^0+$/.test(value)) {
    throw new Error(`${field} must be non-zero lowercase hex of length ${length}`);
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
