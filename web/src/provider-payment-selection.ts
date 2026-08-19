/**
 * Pure, local checks for independently selected provider offers.
 *
 * This module never sends a peer provider, pair identifier, token, or payment
 * method to either server. It only rejects selections whose already-verified
 * public metadata would create an avoidable common correlation point.
 */

import type { ProviderTrustAnchorV1 } from './service-admission.js';
import {
  validateBatV2ClassBindingV2,
  type BatV2ClassBindingV2,
} from './bat-v2-vault.js';
import type {
  ServiceOfferViewV1,
  WasmVerifiedBatV2RedemptionV2,
} from './sdk-bridge.js';

export interface SelectedProviderOfferV1 {
  trust: ProviderTrustAnchorV1;
  offer: ServiceOfferViewV1;
  /** Browser-trusted provider WebSocket endpoint; never sent to its peer. */
  providerEndpoint?: string;
  /** Browser-trusted Lightning payee key; never sent to its peer. */
  expectedLightningPayeePubkey?: Uint8Array;
  /** Live adapter-bound operator key; never accepted from directory self-reporting alone. */
  trustedOperatorSigningKey?: Uint8Array;
}

export interface IndependentProviderSelectionOptionsV1 {
  /** Explicitly allow one issuer/origin to observe both credential flows. */
  allowSharedIssuerCorrelation?: boolean;
  /** Explicitly allow one Lightning payee to observe both purchases. */
  allowSharedLightningPayeeCorrelation?: boolean;
}

/** Canonical, issuer-signed class bytes plus the independently verified
 * wallet projection derived from those exact bytes. */
export interface BatV2ClassArtifactV2 {
  classBytes: Uint8Array;
  binding: BatV2ClassBindingV2;
}

export interface VerifiedProviderBatV2ProjectionInputV2
  extends SelectedProviderOfferV1 {
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  classArtifact: BatV2ClassArtifactV2;
  verifiedRedemption: WasmVerifiedBatV2RedemptionV2;
}

/**
 * Runtime typestate retaining the exact verified class/member handle. A plain
 * copied provider selection cannot stand in for this object, and all mutable
 * byte inputs are copied before they are retained.
 */
export class VerifiedProviderBatV2ProjectionV2 {
  private closed = false;
  private readonly selectedValue: SelectedProviderOfferV1;
  private readonly classBytesValue: Uint8Array;
  private readonly bindingValue: BatV2ClassBindingV2;

  private constructor(
    private readonly policyDigestValue: string,
    private readonly scopeIdValue: string,
    private readonly offerIdValue: number,
    private readonly redemptionValue: WasmVerifiedBatV2RedemptionV2,
    input: VerifiedProviderBatV2ProjectionInputV2,
  ) {
    this.selectedValue = cloneSelectedProviderOfferV1(input);
    this.classBytesValue = input.classArtifact.classBytes.slice();
    this.bindingValue = { ...input.classArtifact.binding };
  }

  static create(
    input: VerifiedProviderBatV2ProjectionInputV2,
  ): VerifiedProviderBatV2ProjectionV2 {
    const providerIdHex = fixedHex('BAT V2 provider ID', input.trust.providerId);
    const policyDigestHex = canonicalNonzeroHex32(
      'BAT V2 policy digest', input.policyDigestHex,
    );
    const scopeIdHex = canonicalNonzeroHex32('BAT V2 scope ID', input.scopeIdHex);
    if (!Number.isSafeInteger(input.offerId)
        || input.offerId <= 0 || input.offerId > 0xffff_ffff) {
      throw new Error('BAT V2 offer ID must be a positive u32');
    }
    if (!(input.classArtifact.classBytes instanceof Uint8Array)
        || input.classArtifact.classBytes.length === 0) {
      throw new Error('BAT V2 selection requires canonical signed class bytes');
    }
    validateBatV2ClassBindingV2(input.classArtifact.binding);
    assertBatV2OfferShape(input.offer, input.classArtifact.binding, input.offerId);
    const verified = input.verifiedRedemption;
    if (!verified || typeof verified.assertRedemptionReady !== 'function'
        || typeof verified.classBindingJson !== 'function'
        || typeof verified.free !== 'function') {
      throw new Error('BAT V2 selection requires an opaque verified redemption handle');
    }
    if (verified.providerIdHex !== providerIdHex
        || verified.policyDigestHex !== policyDigestHex
        || verified.scopeIdHex !== scopeIdHex
        || verified.offerId !== input.offerId) {
      throw new Error('BAT V2 verified class/member projection changed coordinates');
    }
    assertVerifiedBatV2ClassBindingV2(verified, input.classArtifact.binding);
    return new VerifiedProviderBatV2ProjectionV2(
      policyDigestHex,
      scopeIdHex,
      input.offerId,
      verified,
      input,
    );
  }

  selected(): SelectedProviderOfferV1 {
    this.assertOpen();
    return cloneSelectedProviderOfferV1(this.selectedValue);
  }

  coordinates(): {
    policyDigestHex: string;
    scopeIdHex: string;
    offerId: number;
  } {
    this.assertOpen();
    return {
      policyDigestHex: this.policyDigestValue,
      scopeIdHex: this.scopeIdValue,
      offerId: this.offerIdValue,
    };
  }

  classArtifact(): BatV2ClassArtifactV2 {
    this.assertOpen();
    return {
      classBytes: this.classBytesValue.slice(),
      binding: { ...this.bindingValue },
    };
  }

  verifiedRedemption(): WasmVerifiedBatV2RedemptionV2 {
    this.assertOpen();
    return this.redemptionValue;
  }

  assertRedemptionReady(nowUnix: bigint): void {
    this.assertOpen();
    this.redemptionValue.assertRedemptionReady(nowUnix);
    const selected = this.selectedValue;
    if (this.redemptionValue.providerIdHex !== fixedHex(
      'BAT V2 provider ID', selected.trust.providerId,
    )
        || this.redemptionValue.policyDigestHex !== this.policyDigestValue
        || this.redemptionValue.scopeIdHex !== this.scopeIdValue
        || this.redemptionValue.offerId !== this.offerIdValue) {
      throw new Error('BAT V2 verified redemption handle changed after selection');
    }
    assertVerifiedBatV2ClassBindingV2(this.redemptionValue, this.bindingValue);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.classBytesValue.fill(0);
    this.redemptionValue.free();
  }

  private assertOpen(): void {
    if (this.closed) throw new Error('BAT V2 provider projection is closed');
  }
}

/** Validate provider independence plus byte-exact common class identity. */
export function assertIndependentProviderBatV2ProjectionPairV2(
  first: VerifiedProviderBatV2ProjectionV2,
  second: VerifiedProviderBatV2ProjectionV2,
  options: IndependentProviderSelectionOptionsV1 = {},
): void {
  if (!(first instanceof VerifiedProviderBatV2ProjectionV2)
      || !(second instanceof VerifiedProviderBatV2ProjectionV2)) {
    throw new Error('BAT V2 pair requires exact verified provider projections');
  }
  const firstClass = first.classArtifact();
  const secondClass = second.classArtifact();
  try {
    if (!equalBytes(firstClass.classBytes, secondClass.classBytes)
        || classBindingKeyV2(firstClass.binding) !== classBindingKeyV2(secondClass.binding)) {
      throw new Error(
        'strict BAT V2 pair requires the same exact issuer-signed acceptance class',
      );
    }
    assertIndependentProviderOfferPairV1(first.selected(), second.selected(), options);
  } finally {
    firstClass.classBytes.fill(0);
    secondClass.classBytes.fill(0);
  }
}

export function assertIndependentProviderOfferPairV1(
  first: SelectedProviderOfferV1,
  second: SelectedProviderOfferV1,
  options: IndependentProviderSelectionOptionsV1 = {},
): void {
  const firstProvider = fixedHex('first provider ID', first.trust.providerId);
  const secondProvider = fixedHex('second provider ID', second.trust.providerId);
  if (firstProvider === secondProvider) {
    throw new Error('the two PIR selections must use distinct provider IDs');
  }
  if (fixedHex('first policy key', first.trust.policySigningKey)
      === fixedHex('second policy key', second.trust.policySigningKey)) {
    throw new Error('the two PIR providers must not reuse one policy signing key');
  }
  const firstOperator = requiredOperatorKey('first', first);
  const secondOperator = requiredOperatorKey('second', second);
  if (firstOperator === secondOperator) {
    throw new Error('the two PIR providers resolve to the same directory operator key');
  }

  const firstBat = batFingerprint(first.offer);
  const secondBat = batFingerprint(second.offer);
  if (firstBat !== null && secondBat !== null && firstBat === secondBat) {
    throw new Error('the two providers reuse one raw Cashu BAT verification key');
  }
  const firstArc = arcFingerprint(first.offer);
  const secondArc = arcFingerprint(second.offer);
  if (firstArc !== null && secondArc !== null && firstArc === secondArc) {
    throw new Error('the two providers reuse one raw ARC verification key');
  }

  if (options.allowSharedIssuerCorrelation !== true) {
    const firstIssuer = optionalIssuerId('first issuer ID', first.offer.issuerIdHex);
    const secondIssuer = optionalIssuerId('second issuer ID', second.offer.issuerIdHex);
    if (firstIssuer !== null && secondIssuer !== null && firstIssuer === secondIssuer) {
      throw new Error('strict pair privacy rejects one issuer observing both credential flows');
    }
    const firstOrigin = issuerOrigin(first.offer.endpoint);
    const secondOrigin = issuerOrigin(second.offer.endpoint);
    if (firstOrigin !== null && secondOrigin !== null && firstOrigin === secondOrigin) {
      throw new Error('strict pair privacy rejects one issuer origin serving both providers');
    }
  }
  const firstKeyId = directReceiptKeyId('first receipt key ID', first.offer);
  const secondKeyId = directReceiptKeyId('second receipt key ID', second.offer);
  if (firstKeyId !== null && secondKeyId !== null && firstKeyId === secondKeyId) {
    throw new Error('strict pair privacy rejects one receipt verification key serving both providers');
  }
  const firstPayee = optionalCompressedKey(
    'first Lightning payee', first.expectedLightningPayeePubkey,
  );
  const secondPayee = optionalCompressedKey(
    'second Lightning payee', second.expectedLightningPayeePubkey,
  );
  if (options.allowSharedLightningPayeeCorrelation !== true
      && firstPayee !== null && secondPayee !== null && firstPayee === secondPayee) {
    throw new Error('strict pair privacy rejects one Lightning payee observing both purchases');
  }
  const firstProviderOrigin = providerOrigin(first.providerEndpoint);
  const secondProviderOrigin = providerOrigin(second.providerEndpoint);
  if (firstProviderOrigin !== null && secondProviderOrigin !== null
      && firstProviderOrigin === secondProviderOrigin) {
    throw new Error('strict pair privacy rejects one WebSocket origin serving both PIR roles');
  }
}

function requiredOperatorKey(label: string, value: SelectedProviderOfferV1): string {
  const live = value.trustedOperatorSigningKey === undefined
    ? null
    : fixedHex(`${label} live operator key`, value.trustedOperatorSigningKey);
  const directoryBytes = value.trust.directoryAssertion?.operatorSigningKeyEd25519;
  const directory = directoryBytes === undefined
    ? null
    : fixedHex(`${label} directory operator key`, directoryBytes);
  if (live !== null && directory !== null && live !== directory) {
    throw new Error(`${label} live operator key does not match its directory assertion`);
  }
  const resolved = live ?? directory;
  if (resolved === null) {
    throw new Error(`${label} provider lacks an adapter-bound trusted operator key`);
  }
  return resolved;
}

function batFingerprint(offer: ServiceOfferViewV1): string | null {
  if (offer.authorization !== 'cashu-bat') {
    if (offer.batVerificationKeyFingerprintHex !== '') {
      throw new Error('a non-BAT offer exposed a BAT verification-key fingerprint');
    }
    return null;
  }
  return canonicalNonzeroHex32(
    'BAT verification-key fingerprint',
    offer.batVerificationKeyFingerprintHex,
  );
}

function arcFingerprint(offer: ServiceOfferViewV1): string | null {
  if (offer.authorization !== 'arc-experimental') {
    if (offer.arcVerificationKeyFingerprintHex !== '') {
      throw new Error('a non-ARC offer exposed an ARC verification-key fingerprint');
    }
    return null;
  }
  return canonicalNonzeroHex32(
    'ARC verification-key fingerprint',
    offer.arcVerificationKeyFingerprintHex,
  );
}

function optionalIssuerId(field: string, value: string): string | null {
  if (/^0{64}$/.test(value)) return null;
  return canonicalNonzeroHex32(field, value);
}

function directReceiptKeyId(field: string, offer: ServiceOfferViewV1): string | null {
  if (offer.authorization !== 'bolt11-direct-receipt') return null;
  const value = offer.keyIdHex;
  // The authenticated protocol permits 1..64 bytes. Preserve the exact byte
  // string for correlation comparison. Direct-receipt key IDs are derived
  // from the raw verification key, so equality also catches raw-key reuse;
  // BAT and ARC use their raw-key fingerprints above and free tickets remain
  // covered by the issuer guard.
  if (!/^(?:[0-9a-f]{2}){1,64}$/.test(value)) {
    throw new Error(`${field} must be 1..64 bytes of lowercase hex`);
  }
  if (/^0+$/.test(value)) return null;
  return value;
}

function optionalCompressedKey(field: string, value: Uint8Array | undefined): string | null {
  if (value === undefined) return null;
  if (!(value instanceof Uint8Array) || value.length !== 33
      || (value[0] !== 0x02 && value[0] !== 0x03)
      || value.subarray(1).every((byte) => byte === 0)) {
    throw new Error(`${field} must be a compressed secp256k1 public key`);
  }
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function providerOrigin(endpoint: string | undefined): string | null {
  if (endpoint === undefined || endpoint === '') return null;
  let parsed: URL;
  try { parsed = new URL(endpoint); } catch { throw new Error('provider WebSocket endpoint is invalid'); }
  if (parsed.protocol !== 'wss:' && parsed.protocol !== 'ws:') {
    throw new Error('provider endpoint is not WebSocket(S)');
  }
  return parsed.origin;
}

function issuerOrigin(endpoint: string): string | null {
  if (endpoint === '') return null;
  let parsed: URL;
  try { parsed = new URL(endpoint); } catch { throw new Error('issuer endpoint is invalid'); }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('issuer endpoint is not HTTP(S)');
  }
  return parsed.origin;
}

function fixedHex(field: string, value: Uint8Array): string {
  if (!(value instanceof Uint8Array) || value.length !== 32
      || value.every((byte) => byte === 0)) {
    throw new Error(`${field} must be a non-zero 32-byte value`);
  }
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function canonicalNonzeroHex32(field: string, value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value) || /^0{64}$/.test(value)) {
    throw new Error(`${field} must be non-zero lowercase 32-byte hex`);
  }
  return value;
}

function assertBatV2OfferShape(
  offer: ServiceOfferViewV1,
  binding: BatV2ClassBindingV2,
  offerId: number,
): void {
  if (offer.offerId !== offerId
      || offer.acquisition !== 'bolt11'
      || offer.authorization !== 'cashu-bat-v2'
      || offer.verification !== 'shared-issuer-online'
      || offer.issuerIdHex !== binding.issuerIdHex
      || offer.keyIdHex !== binding.classIdHex) {
    throw new Error('selected offer is not this exact BAT V2 class member');
  }
}

function cloneSelectedProviderOfferV1(
  value: SelectedProviderOfferV1,
): SelectedProviderOfferV1 {
  return {
    trust: {
      providerId: value.trust.providerId.slice(),
      policySigningKey: value.trust.policySigningKey.slice(),
      directoryAssertion: value.trust.directoryAssertion
        ? {
          ...value.trust.directoryAssertion,
          operatorSigningKeyEd25519:
            value.trust.directoryAssertion.operatorSigningKeyEd25519.slice(),
          policyDigest: value.trust.directoryAssertion.policyDigest.slice(),
        }
        : undefined,
    },
    offer: { ...value.offer, price: { ...value.offer.price } },
    providerEndpoint: value.providerEndpoint,
    expectedLightningPayeePubkey: value.expectedLightningPayeePubkey?.slice(),
    trustedOperatorSigningKey: value.trustedOperatorSigningKey?.slice(),
  };
}

function classBindingKeyV2(value: BatV2ClassBindingV2): string {
  validateBatV2ClassBindingV2(value);
  return [
    value.issuerIdHex,
    value.classIdHex,
    value.classDigestHex,
    value.classKeyEpoch,
    value.batKeyIdHex,
  ].join(':');
}

/**
 * Compare a trusted TypeScript binding with the full binding independently
 * derived by Rust from the canonical signed class. This is intentionally
 * shared by current and retained paths so neither can weaken to classId-only.
 */
export function assertVerifiedBatV2ClassBindingV2(
  verified: WasmVerifiedBatV2RedemptionV2,
  expected: BatV2ClassBindingV2,
): void {
  validateBatV2ClassBindingV2(expected);
  if (!verified || typeof verified.classBindingJson !== 'function') {
    throw new Error('BAT V2 verified redemption lacks a full class binding');
  }
  const projected = verified.classBindingJson() as unknown;
  if (projected === null || typeof projected !== 'object' || Array.isArray(projected)) {
    throw new Error('BAT V2 verified redemption returned an invalid class binding');
  }
  const value = projected as Partial<BatV2ClassBindingV2>;
  const actual: BatV2ClassBindingV2 = {
    issuerIdHex: value.issuerIdHex as string,
    classIdHex: value.classIdHex as string,
    classDigestHex: value.classDigestHex as string,
    classKeyEpoch: value.classKeyEpoch as string,
    batKeyIdHex: value.batKeyIdHex as string,
  };
  try {
    validateBatV2ClassBindingV2(actual);
  } catch {
    throw new Error('BAT V2 verified redemption returned an invalid class binding');
  }
  if (classBindingKeyV2(actual) !== classBindingKeyV2(expected)) {
    throw new Error('BAT V2 verified redemption does not match the exact signed class binding');
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) {
    mismatch |= left[index] ^ right[index];
  }
  return mismatch === 0;
}
