/**
 * Pure, local checks for independently selected provider offers.
 *
 * This module never sends a peer provider, pair identifier, token, or payment
 * method to either server. It only rejects selections whose already-verified
 * public metadata would create an avoidable common correlation point.
 */

import type { ProviderTrustAnchorV1 } from './service-admission.js';
import type { ServiceOfferViewV1 } from './sdk-bridge.js';

export interface SelectedProviderOfferV1 {
  trust: ProviderTrustAnchorV1;
  offer: ServiceOfferViewV1;
  /** Browser-trusted provider WebSocket endpoint; never sent to its peer. */
  providerEndpoint?: string;
  /** Browser-trusted Lightning payee key; never sent to its peer. */
  expectedLightningPayeePubkey?: Uint8Array;
}

export interface IndependentProviderSelectionOptionsV1 {
  /** Explicitly allow one issuer/origin to observe both credential flows. */
  allowSharedIssuerCorrelation?: boolean;
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
  const firstOperator = first.trust.directoryAssertion?.operatorSigningKeyEd25519;
  const secondOperator = second.trust.directoryAssertion?.operatorSigningKeyEd25519;
  if (firstOperator && secondOperator
      && fixedHex('first operator key', firstOperator)
        === fixedHex('second operator key', secondOperator)) {
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

  if (options.allowSharedIssuerCorrelation === true) {
    return;
  }
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
  const firstKeyId = optionalKeyId('first receipt key ID', first.offer.keyIdHex);
  const secondKeyId = optionalKeyId('second receipt key ID', second.offer.keyIdHex);
  if (firstKeyId !== null && secondKeyId !== null && firstKeyId === secondKeyId) {
    throw new Error('strict pair privacy rejects one receipt verification key serving both providers');
  }
  const firstPayee = optionalCompressedKey(
    'first Lightning payee', first.expectedLightningPayeePubkey,
  );
  const secondPayee = optionalCompressedKey(
    'second Lightning payee', second.expectedLightningPayeePubkey,
  );
  if (firstPayee !== null && secondPayee !== null && firstPayee === secondPayee) {
    throw new Error('strict pair privacy rejects one Lightning payee observing both purchases');
  }
  const firstProviderOrigin = providerOrigin(first.providerEndpoint);
  const secondProviderOrigin = providerOrigin(second.providerEndpoint);
  if (firstProviderOrigin !== null && secondProviderOrigin !== null
      && firstProviderOrigin === secondProviderOrigin) {
    throw new Error('strict pair privacy rejects one WebSocket origin serving both PIR roles');
  }
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

function optionalKeyId(field: string, value: string): string | null {
  if (value === '') return null;
  // The authenticated protocol permits 1..64 bytes here. In particular,
  // direct-receipt and ARC identifiers are 16 bytes while BAT identifiers are
  // 32 bytes. Preserve the exact byte string for correlation comparison.
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
