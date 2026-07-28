//! Canonical credential issuance messages for a settled BitcoinPIR BOLT11
//! quote.
//!
//! This is a pure wire module. It does not parse BOLT11 invoices, verify the
//! BIP340 claim signature, sign blind messages, finalize ARC credentials, do
//! HTTP, or persist idempotency state. Standard Cashu issuance deliberately
//! does not use these messages: it follows NUT-04 (and NUT-20 where enabled).

use std::collections::HashSet;
use std::fmt;

use ed25519_dalek::VerifyingKey;
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cashu_manifest::is_valid_compressed_point;
use crate::codec::{expect_v1, put_bytes_u32, Decoder};
use crate::{
    AuthScheme, Bolt11QuoteClaimV1, Bolt11QuoteIntentV1, CredentialKeyBindingV1,
    PaidReceiptBindingV1, PaidReceiptV1, ServiceProtocolError, UnverifiedBip340ClaimV1,
    VerifiedBolt11QuoteV1, MAX_BOLT11_QUOTE_CLAIM_LEN, MAX_BOLT11_QUOTE_INTENT_LEN,
    MAX_CREDENTIALS_PER_ACQUISITION_V1, MAX_CREDENTIAL_KEY_ID_LEN, SERVICE_PROTOCOL_VERSION,
};

pub const ARC_CREDENTIAL_REQUEST_LEN_V1: usize = 226;
pub const ARC_CREDENTIAL_RESPONSE_LEN_V1: usize = 454;
pub const PAID_RECEIPT_WIRE_LEN_V1: usize = 231;
pub const MAX_CREDENTIAL_ISSUANCE_REQUEST_LEN_V1: usize = 64 * 1024;
pub const MAX_CREDENTIAL_ISSUANCE_RESPONSE_LEN_V1: usize = 128 * 1024;
pub const MAX_BOLT11_QUOTE_CLAIM_ENVELOPE_LEN_V1: usize = 1
    + 4
    + MAX_BOLT11_QUOTE_INTENT_LEN
    + 4
    + MAX_BOLT11_QUOTE_CLAIM_LEN
    + 4
    + MAX_CREDENTIAL_ISSUANCE_REQUEST_LEN_V1;

pub const CREDENTIAL_ISSUANCE_REQUEST_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/credential-issuance-request-digest/v1";

/// Canonical binary body for `POST /v1/quotes/{quote_id}/claim`.
///
/// Keeping the original quote intent, signed claim, and exact ordered issuance request in one
/// bounded envelope prevents HTTP adapters from inventing ambiguous JSON or
/// base64 aliases. The URL quote id is routing-only and MUST equal
/// `claim.quote_id`; applications still verify that equality before touching
/// durable state.
#[derive(Clone, PartialEq, Eq)]
pub struct Bolt11QuoteClaimEnvelopeV1 {
    pub quote_intent: Bolt11QuoteIntentV1,
    pub claim: Bolt11QuoteClaimV1,
    pub credential_request: CredentialIssuanceRequestV1,
}

impl fmt::Debug for Bolt11QuoteClaimEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bolt11QuoteClaimEnvelopeV1")
            .field("claim_envelope", &"[REDACTED]")
            .finish()
    }
}

impl Bolt11QuoteClaimEnvelopeV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let quote_intent = Zeroizing::new(self.quote_intent.encode()?);
        let claim = Zeroizing::new(self.claim.encode()?);
        let credential_request = Zeroizing::new(self.credential_request.encode()?);
        if self.claim.credential_request_digest != self.credential_request.request_digest()?
            || self.claim.issuer_id != self.credential_request.issuer_id
            || self.claim.quote_id != self.credential_request.quote_id
            || self.claim.quote_request_digest != self.credential_request.quote_request_digest
            || self.claim.issuer_id != self.quote_intent.issuer_id
            || self.claim.quote_request_digest != self.quote_intent.request_digest()?
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteClaimEnvelopeV1.binding",
                reason: "claim and credential request differ",
            });
        }
        let mut out = Zeroizing::new(Vec::with_capacity(
            1 + 4 + quote_intent.len() + 4 + claim.len() + 4 + credential_request.len(),
        ));
        out.push(SERVICE_PROTOCOL_VERSION);
        put_bytes_u32(&mut out, &quote_intent);
        put_bytes_u32(&mut out, &claim);
        put_bytes_u32(&mut out, &credential_request);
        if out.len() > MAX_BOLT11_QUOTE_CLAIM_ENVELOPE_LEN_V1 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteClaimEnvelopeV1",
                len: out.len(),
                max: MAX_BOLT11_QUOTE_CLAIM_ENVELOPE_LEN_V1,
            });
        }
        Ok(std::mem::take(&mut *out))
    }

    pub fn decode(
        bytes: &[u8],
        arc_canonicalizer: Option<&dyn ArcIssuanceCanonicalizerV1>,
    ) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_BOLT11_QUOTE_CLAIM_ENVELOPE_LEN_V1 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteClaimEnvelopeV1",
                len: bytes.len(),
                max: MAX_BOLT11_QUOTE_CLAIM_ENVELOPE_LEN_V1,
            });
        }
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("Bolt11QuoteClaimEnvelopeV1.version")?,
            "Bolt11QuoteClaimEnvelopeV1",
        )?;
        let intent_bytes = Zeroizing::new(decoder.bytes_u32(
            "Bolt11QuoteClaimEnvelopeV1.quote_intent",
            MAX_BOLT11_QUOTE_INTENT_LEN,
        )?);
        let claim_bytes = Zeroizing::new(decoder.bytes_u32(
            "Bolt11QuoteClaimEnvelopeV1.claim",
            MAX_BOLT11_QUOTE_CLAIM_LEN,
        )?);
        let request_bytes = Zeroizing::new(decoder.bytes_u32(
            "Bolt11QuoteClaimEnvelopeV1.credential_request",
            MAX_CREDENTIAL_ISSUANCE_REQUEST_LEN_V1,
        )?);
        decoder.finish()?;
        let value = Self {
            quote_intent: Bolt11QuoteIntentV1::decode(&intent_bytes)?,
            claim: Bolt11QuoteClaimV1::decode(&claim_bytes)?,
            credential_request: CredentialIssuanceRequestV1::decode(
                &request_bytes,
                arc_canonicalizer,
            )?,
        };
        let exact_intent = Zeroizing::new(value.quote_intent.encode()?);
        let exact_claim = Zeroizing::new(value.claim.encode()?);
        let exact_request = Zeroizing::new(value.credential_request.encode()?);
        let exact_envelope = Zeroizing::new(value.encode()?);
        if exact_intent.as_slice() != intent_bytes.as_slice()
            || exact_claim.as_slice() != claim_bytes.as_slice()
            || exact_request.as_slice() != request_bytes.as_slice()
            || exact_envelope.as_slice() != bytes
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteClaimEnvelopeV1",
                reason: "nested object is not canonical",
            });
        }
        Ok(value)
    }
}

/// Adapter implemented by the reviewed ARC library.
///
/// Both methods must decode into the library's typed object and serialize the
/// typed value again. Returning the input without parsing violates this
/// contract. Keeping this adapter outside the pure protocol crate also keeps
/// ARC experimental until its cryptographic implementation is independently
/// reviewed.
pub trait ArcIssuanceCanonicalizerV1 {
    fn decode_and_reencode_request(&self, request: &[u8]) -> Result<Vec<u8>, ServiceProtocolError>;

    fn decode_and_reencode_response(
        &self,
        response: &[u8],
    ) -> Result<Vec<u8>, ServiceProtocolError>;
}

/// One canonical experimental ARC `CredentialRequest`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArcCredentialRequestV1 {
    canonical_bytes: [u8; ARC_CREDENTIAL_REQUEST_LEN_V1],
}

impl ArcCredentialRequestV1 {
    pub fn decode_canonical(
        bytes: &[u8],
        canonicalizer: &dyn ArcIssuanceCanonicalizerV1,
    ) -> Result<Self, ServiceProtocolError> {
        let canonical_bytes: [u8; ARC_CREDENTIAL_REQUEST_LEN_V1] =
            bytes
                .try_into()
                .map_err(|_| ServiceProtocolError::InvalidValue {
                    field: "ArcCredentialRequestV1",
                    reason: "ARC CredentialRequest must be exactly 226 bytes",
                })?;
        let reencoded = canonicalizer.decode_and_reencode_request(bytes)?;
        if reencoded.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ArcCredentialRequestV1",
                reason: "ARC request decode/re-encode is not byte-for-byte canonical",
            });
        }
        Ok(Self { canonical_bytes })
    }

    pub const fn as_bytes(&self) -> &[u8; ARC_CREDENTIAL_REQUEST_LEN_V1] {
        &self.canonical_bytes
    }
}

/// One canonical experimental ARC `CredentialResponse`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArcCredentialResponseV1 {
    canonical_bytes: [u8; ARC_CREDENTIAL_RESPONSE_LEN_V1],
}

impl ArcCredentialResponseV1 {
    pub fn decode_canonical(
        bytes: &[u8],
        canonicalizer: &dyn ArcIssuanceCanonicalizerV1,
    ) -> Result<Self, ServiceProtocolError> {
        let canonical_bytes: [u8; ARC_CREDENTIAL_RESPONSE_LEN_V1] =
            bytes
                .try_into()
                .map_err(|_| ServiceProtocolError::InvalidValue {
                    field: "ArcCredentialResponseV1",
                    reason: "ARC CredentialResponse must be exactly 454 bytes",
                })?;
        let reencoded = canonicalizer.decode_and_reencode_response(bytes)?;
        if reencoded.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ArcCredentialResponseV1",
                reason: "ARC response decode/re-encode is not byte-for-byte canonical",
            });
        }
        Ok(Self { canonical_bytes })
    }

    pub const fn as_bytes(&self) -> &[u8; ARC_CREDENTIAL_RESPONSE_LEN_V1] {
        &self.canonical_bytes
    }
}

/// One BitcoinPIR Cashu BAT blinded message. Request order is significant and
/// is preserved exactly in the response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BitcoinPirCashuBatIssuanceRequestItemV1 {
    pub blinded_message: [u8; 33],
}

/// NUT-12 proof attached to one BAT blind signature. The wallet's private
/// blinding scalar `r` has no field and therefore cannot cross this wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BitcoinPirCashuBatIssuanceResponseItemV1 {
    /// Exact request `B_`, echoed in the original request order.
    pub blinded_message: [u8; 33],
    /// Blind signature `C_`.
    pub blinded_signature: [u8; 33],
    pub dleq_e: [u8; 32],
    pub dleq_s: [u8; 32],
}

/// Explicitly unverified NUT-12 transcript. Obtaining this value is not proof
/// that the DLEQ equations hold; the wallet adapter must verify it before
/// unblinding or accepting the BAT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnverifiedCashuBatDleqTupleV1 {
    pub issuer_public_key: [u8; 33],
    pub blinded_message: [u8; 33],
    pub blinded_signature: [u8; 33],
    pub dleq_e: [u8; 32],
    pub dleq_s: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialIssuanceRequestItemsV1 {
    /// Direct receipts require no client blinded item. Their exact output
    /// count is inherited from the signed quote intent.
    DirectPaidReceipt,
    BitcoinPirCashuBat(Vec<BitcoinPirCashuBatIssuanceRequestItemV1>),
    ArcExperimental(Vec<ArcCredentialRequestV1>),
}

/// Exact ordered credential request committed by `Bolt11QuoteClaimV1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialIssuanceRequestV1 {
    pub issuer_id: [u8; 32],
    pub quote_id: [u8; 32],
    pub quote_request_digest: [u8; 32],
    pub authorization: AuthScheme,
    pub credential_binding_digest: [u8; 32],
    pub credential_key_id: Vec<u8>,
    pub items: CredentialIssuanceRequestItemsV1,
}

impl CredentialIssuanceRequestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Zeroizing::new(Vec::new());
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.quote_id);
        out.extend_from_slice(&self.quote_request_digest);
        out.push(self.authorization as u8);
        out.extend_from_slice(&self.credential_binding_digest);
        put_len_u8(
            &mut out,
            self.credential_key_id.len(),
            "CredentialIssuanceRequestV1.credential_key_id",
        )?;
        out.extend_from_slice(&self.credential_key_id);
        put_count_u16(
            &mut out,
            self.item_count(),
            "CredentialIssuanceRequestV1.items",
        )?;
        match &self.items {
            CredentialIssuanceRequestItemsV1::DirectPaidReceipt => {}
            CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(items) => {
                for item in items {
                    out.extend_from_slice(&item.blinded_message);
                }
            }
            CredentialIssuanceRequestItemsV1::ArcExperimental(items) => {
                for item in items {
                    out.extend_from_slice(item.as_bytes());
                }
            }
        }
        check_total_len(
            out.len(),
            MAX_CREDENTIAL_ISSUANCE_REQUEST_LEN_V1,
            "CredentialIssuanceRequestV1",
        )?;
        Ok(std::mem::take(&mut *out))
    }

    pub fn decode(
        bytes: &[u8],
        arc_canonicalizer: Option<&dyn ArcIssuanceCanonicalizerV1>,
    ) -> Result<Self, ServiceProtocolError> {
        check_total_len(
            bytes.len(),
            MAX_CREDENTIAL_ISSUANCE_REQUEST_LEN_V1,
            "CredentialIssuanceRequestV1",
        )?;
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("CredentialIssuanceRequestV1.version")?,
            "CredentialIssuanceRequestV1",
        )?;
        let issuer_id = decoder.fixed("CredentialIssuanceRequestV1.issuer_id")?;
        let quote_id = decoder.fixed("CredentialIssuanceRequestV1.quote_id")?;
        let quote_request_digest =
            decoder.fixed("CredentialIssuanceRequestV1.quote_request_digest")?;
        let authorization =
            AuthScheme::decode(decoder.u8("CredentialIssuanceRequestV1.authorization")?)?;
        let credential_binding_digest =
            decoder.fixed("CredentialIssuanceRequestV1.credential_binding_digest")?;
        let credential_key_id = decoder.bytes_u8(
            "CredentialIssuanceRequestV1.credential_key_id",
            MAX_CREDENTIAL_KEY_ID_LEN,
        )?;
        let item_count = usize::from(decoder.u16("CredentialIssuanceRequestV1.item_count")?);
        check_item_count(item_count, "CredentialIssuanceRequestV1.items", true)?;
        let items = match authorization {
            AuthScheme::Bolt11DirectReceiptV1 => {
                if item_count != 0 {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "CredentialIssuanceRequestV1.item_count",
                        reason: "direct receipt requests carry zero blinded items",
                    });
                }
                CredentialIssuanceRequestItemsV1::DirectPaidReceipt
            }
            AuthScheme::BitcoinPirCashuBatV1 => {
                if item_count == 0 {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "CredentialIssuanceRequestV1.item_count",
                        reason: "BAT issuance requires at least one blinded item",
                    });
                }
                let mut values = Vec::with_capacity(item_count);
                for _ in 0..item_count {
                    values.push(BitcoinPirCashuBatIssuanceRequestItemV1 {
                        blinded_message: decoder
                            .fixed("CredentialIssuanceRequestV1.bat.blinded_message")?,
                    });
                }
                CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(values)
            }
            AuthScheme::ArcV1Experimental => {
                if item_count == 0 {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "CredentialIssuanceRequestV1.item_count",
                        reason: "ARC issuance requires at least one request",
                    });
                }
                let canonicalizer =
                    arc_canonicalizer.ok_or(ServiceProtocolError::InvalidValue {
                        field: "CredentialIssuanceRequestV1.arc_canonicalizer",
                        reason: "experimental ARC decoding requires a typed canonicalizer",
                    })?;
                let mut values = Vec::with_capacity(item_count);
                for _ in 0..item_count {
                    let raw: [u8; ARC_CREDENTIAL_REQUEST_LEN_V1] =
                        decoder.fixed("CredentialIssuanceRequestV1.arc.request")?;
                    values.push(ArcCredentialRequestV1::decode_canonical(
                        &raw,
                        canonicalizer,
                    )?);
                }
                CredentialIssuanceRequestItemsV1::ArcExperimental(values)
            }
            AuthScheme::FreeV1 | AuthScheme::CashuEcashV1 => {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "CredentialIssuanceRequestV1.authorization",
                    reason: "custom BOLT11 claims support only direct receipt, BAT, or experimental ARC; standard Cashu uses NUT-04",
                })
            }
        };
        decoder.finish()?;
        let value = Self {
            issuer_id,
            quote_id,
            quote_request_digest,
            authorization,
            credential_binding_digest,
            credential_key_id,
            items,
        };
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialIssuanceRequestV1",
                reason: "non-canonical issuance request encoding",
            });
        }
        Ok(value)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(CREDENTIAL_ISSUANCE_REQUEST_DIGEST_DOMAIN_V1);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    /// Bind an issuance request and claim to a quote whose signature, BOLT11
    /// facts, root delegation, lifecycle, and signed intent have already been
    /// verified. The returned BIP340 tuple is intentionally unverified: the
    /// issuer must verify it before signing or returning any credential.
    pub fn verify_for_verified_quote(
        &self,
        claim: &Bolt11QuoteClaimV1,
        verified_quote: &VerifiedBolt11QuoteV1<'_>,
        now_unix: u64,
    ) -> Result<UnverifiedBip340ClaimV1, ServiceProtocolError> {
        self.verify_terms_for_quote(verified_quote)?;
        let request_digest = self.request_digest()?;
        if claim.credential_request_digest != request_digest {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteClaimV1.credential_request_digest",
                reason: "claim does not commit to the exact canonical issuance request",
            });
        }
        claim.unverified_bip340_input_for(verified_quote, now_unix)
    }

    fn verify_terms_for_quote(
        &self,
        verified_quote: &VerifiedBolt11QuoteV1<'_>,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        let quote = verified_quote.quote();
        let intent = verified_quote.intent();
        if self.issuer_id != intent.issuer_id
            || self.quote_id != quote.quote_id
            || self.quote_request_digest != quote.request_digest
            || self.authorization != intent.authorization
            || self.credential_binding_digest != intent.credential_binding_digest
            || self.credential_key_id != intent.credential_key_id
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialIssuanceRequestV1.quote_binding",
                reason: "issuer, quote, authorization, credential binding, or key differs from the verified quote intent",
            });
        }
        let expected_count = quote_credential_count(intent.credential_count)?;
        match &self.items {
            CredentialIssuanceRequestItemsV1::DirectPaidReceipt
                if intent.authorization == AuthScheme::Bolt11DirectReceiptV1 => {}
            CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(items)
                if intent.authorization == AuthScheme::BitcoinPirCashuBatV1
                    && items.len() == expected_count => {}
            CredentialIssuanceRequestItemsV1::ArcExperimental(items)
                if intent.authorization == AuthScheme::ArcV1Experimental
                    && items.len() == expected_count => {}
            _ => {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "CredentialIssuanceRequestV1.items",
                    reason: "scheme or blinded item count differs from the signed quote",
                })
            }
        }
        Ok(())
    }

    fn item_count(&self) -> usize {
        match &self.items {
            CredentialIssuanceRequestItemsV1::DirectPaidReceipt => 0,
            CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(items) => items.len(),
            CredentialIssuanceRequestItemsV1::ArcExperimental(items) => items.len(),
        }
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_common_binding(
            &self.issuer_id,
            &self.quote_id,
            &self.quote_request_digest,
            self.authorization,
            &self.credential_binding_digest,
            &self.credential_key_id,
            "CredentialIssuanceRequestV1",
        )?;
        match (&self.authorization, &self.items) {
            (
                AuthScheme::Bolt11DirectReceiptV1,
                CredentialIssuanceRequestItemsV1::DirectPaidReceipt,
            ) => Ok(()),
            (
                AuthScheme::BitcoinPirCashuBatV1,
                CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(items),
            ) => {
                check_item_count(items.len(), "CredentialIssuanceRequestV1.bat", false)?;
                let mut points = HashSet::with_capacity(items.len());
                for item in items {
                    if !is_valid_compressed_point(&item.blinded_message)
                        || !points.insert(item.blinded_message)
                    {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "CredentialIssuanceRequestV1.bat.blinded_message",
                            reason: "BAT blinded points must be valid, non-identity, and unique",
                        });
                    }
                }
                Ok(())
            }
            (
                AuthScheme::ArcV1Experimental,
                CredentialIssuanceRequestItemsV1::ArcExperimental(items),
            ) => {
                check_item_count(items.len(), "CredentialIssuanceRequestV1.arc", false)?;
                let mut requests = HashSet::with_capacity(items.len());
                if items.iter().all(|item| requests.insert(item.as_bytes())) {
                    Ok(())
                } else {
                    Err(ServiceProtocolError::InvalidValue {
                        field: "CredentialIssuanceRequestV1.arc",
                        reason: "duplicate ARC requests are forbidden",
                    })
                }
            }
            _ => Err(ServiceProtocolError::InvalidValue {
                field: "CredentialIssuanceRequestV1.authorization",
                reason: "scheme and item variant mismatch; standard Cashu uses NUT-04",
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialIssuanceResponseItemsV1 {
    DirectPaidReceipts(Vec<PaidReceiptV1>),
    BitcoinPirCashuBat(Vec<BitcoinPirCashuBatIssuanceResponseItemV1>),
    ArcExperimental(Vec<ArcCredentialResponseV1>),
}

/// Exact idempotent issuance response. Its envelope is bound to the precise
/// request digest; the returned credentials or proofs carry their own
/// cryptographic verification requirements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialIssuanceResponseV1 {
    pub issuer_id: [u8; 32],
    pub quote_id: [u8; 32],
    pub quote_request_digest: [u8; 32],
    pub credential_request_digest: [u8; 32],
    pub authorization: AuthScheme,
    pub credential_binding_digest: [u8; 32],
    pub credential_key_id: Vec<u8>,
    pub items: CredentialIssuanceResponseItemsV1,
}

impl CredentialIssuanceResponseV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Zeroizing::new(Vec::new());
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.quote_id);
        out.extend_from_slice(&self.quote_request_digest);
        out.extend_from_slice(&self.credential_request_digest);
        out.push(self.authorization as u8);
        out.extend_from_slice(&self.credential_binding_digest);
        put_len_u8(
            &mut out,
            self.credential_key_id.len(),
            "CredentialIssuanceResponseV1.credential_key_id",
        )?;
        out.extend_from_slice(&self.credential_key_id);
        put_count_u16(
            &mut out,
            self.item_count(),
            "CredentialIssuanceResponseV1.items",
        )?;
        match &self.items {
            CredentialIssuanceResponseItemsV1::DirectPaidReceipts(receipts) => {
                for receipt in receipts {
                    let encoded = Zeroizing::new(receipt.encode()?);
                    if encoded.len() != PAID_RECEIPT_WIRE_LEN_V1 {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "CredentialIssuanceResponseV1.receipt",
                            reason: "PaidReceiptV1 has an unexpected V1 wire length",
                        });
                    }
                    put_len_u16(
                        &mut out,
                        encoded.len(),
                        "CredentialIssuanceResponseV1.receipt",
                    )?;
                    out.extend_from_slice(&encoded);
                }
            }
            CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(items) => {
                for item in items {
                    out.extend_from_slice(&item.blinded_message);
                    out.extend_from_slice(&item.blinded_signature);
                    out.extend_from_slice(&item.dleq_e);
                    out.extend_from_slice(&item.dleq_s);
                }
            }
            CredentialIssuanceResponseItemsV1::ArcExperimental(items) => {
                for item in items {
                    out.extend_from_slice(item.as_bytes());
                }
            }
        }
        check_total_len(
            out.len(),
            MAX_CREDENTIAL_ISSUANCE_RESPONSE_LEN_V1,
            "CredentialIssuanceResponseV1",
        )?;
        Ok(std::mem::take(&mut *out))
    }

    pub fn decode(
        bytes: &[u8],
        arc_canonicalizer: Option<&dyn ArcIssuanceCanonicalizerV1>,
    ) -> Result<Self, ServiceProtocolError> {
        check_total_len(
            bytes.len(),
            MAX_CREDENTIAL_ISSUANCE_RESPONSE_LEN_V1,
            "CredentialIssuanceResponseV1",
        )?;
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("CredentialIssuanceResponseV1.version")?,
            "CredentialIssuanceResponseV1",
        )?;
        let issuer_id = decoder.fixed("CredentialIssuanceResponseV1.issuer_id")?;
        let quote_id = decoder.fixed("CredentialIssuanceResponseV1.quote_id")?;
        let quote_request_digest =
            decoder.fixed("CredentialIssuanceResponseV1.quote_request_digest")?;
        let credential_request_digest =
            decoder.fixed("CredentialIssuanceResponseV1.credential_request_digest")?;
        let authorization =
            AuthScheme::decode(decoder.u8("CredentialIssuanceResponseV1.authorization")?)?;
        let credential_binding_digest =
            decoder.fixed("CredentialIssuanceResponseV1.credential_binding_digest")?;
        let credential_key_id = decoder.bytes_u8(
            "CredentialIssuanceResponseV1.credential_key_id",
            MAX_CREDENTIAL_KEY_ID_LEN,
        )?;
        let item_count = usize::from(decoder.u16("CredentialIssuanceResponseV1.item_count")?);
        check_item_count(item_count, "CredentialIssuanceResponseV1.items", false)?;
        let items = match authorization {
            AuthScheme::Bolt11DirectReceiptV1 => {
                let mut receipts = Vec::with_capacity(item_count);
                for _ in 0..item_count {
                    let receipt_bytes = Zeroizing::new(decoder.bytes_u16(
                        "CredentialIssuanceResponseV1.receipt",
                        PAID_RECEIPT_WIRE_LEN_V1,
                    )?);
                    if receipt_bytes.len() != PAID_RECEIPT_WIRE_LEN_V1 {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "CredentialIssuanceResponseV1.receipt",
                            reason: "PaidReceiptV1 must use its exact V1 wire length",
                        });
                    }
                    let receipt = PaidReceiptV1::decode(&receipt_bytes)?;
                    let exact_reencoding = Zeroizing::new(receipt.encode()?);
                    if exact_reencoding.as_slice() != receipt_bytes.as_slice() {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "CredentialIssuanceResponseV1.receipt",
                            reason: "non-canonical PaidReceiptV1 encoding",
                        });
                    }
                    receipts.push(receipt);
                }
                CredentialIssuanceResponseItemsV1::DirectPaidReceipts(receipts)
            }
            AuthScheme::BitcoinPirCashuBatV1 => {
                let mut values = Vec::with_capacity(item_count);
                for _ in 0..item_count {
                    values.push(BitcoinPirCashuBatIssuanceResponseItemV1 {
                        blinded_message: decoder
                            .fixed("CredentialIssuanceResponseV1.bat.blinded_message")?,
                        blinded_signature: decoder
                            .fixed("CredentialIssuanceResponseV1.bat.blinded_signature")?,
                        dleq_e: decoder.fixed("CredentialIssuanceResponseV1.bat.dleq_e")?,
                        dleq_s: decoder.fixed("CredentialIssuanceResponseV1.bat.dleq_s")?,
                    });
                }
                CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(values)
            }
            AuthScheme::ArcV1Experimental => {
                let canonicalizer =
                    arc_canonicalizer.ok_or(ServiceProtocolError::InvalidValue {
                        field: "CredentialIssuanceResponseV1.arc_canonicalizer",
                        reason: "experimental ARC decoding requires a typed canonicalizer",
                    })?;
                let mut values = Vec::with_capacity(item_count);
                for _ in 0..item_count {
                    let raw: [u8; ARC_CREDENTIAL_RESPONSE_LEN_V1] =
                        decoder.fixed("CredentialIssuanceResponseV1.arc.response")?;
                    values.push(ArcCredentialResponseV1::decode_canonical(
                        &raw,
                        canonicalizer,
                    )?);
                }
                CredentialIssuanceResponseItemsV1::ArcExperimental(values)
            }
            AuthScheme::FreeV1 | AuthScheme::CashuEcashV1 => {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "CredentialIssuanceResponseV1.authorization",
                    reason: "custom BOLT11 claims support only direct receipt, BAT, or experimental ARC; standard Cashu uses NUT-04",
                })
            }
        };
        decoder.finish()?;
        let value = Self {
            issuer_id,
            quote_id,
            quote_request_digest,
            credential_request_digest,
            authorization,
            credential_binding_digest,
            credential_key_id,
            items,
        };
        value.validate()?;
        let exact_reencoding = Zeroizing::new(value.encode()?);
        if exact_reencoding.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialIssuanceResponseV1",
                reason: "non-canonical issuance response encoding",
            });
        }
        Ok(value)
    }

    /// Verify the response envelope and method-specific output against only
    /// the immutable terms in a verified quote, its exact issuance request,
    /// and the issuer-root-signed credential key binding.
    pub fn verify_for_verified_quote(
        &self,
        request: &CredentialIssuanceRequestV1,
        verified_quote: &VerifiedBolt11QuoteV1<'_>,
        credential_binding: &CredentialKeyBindingV1,
    ) -> Result<CheckedCredentialIssuanceResponseV1, ServiceProtocolError> {
        self.validate()?;
        request.verify_terms_for_quote(verified_quote)?;
        verify_credential_binding_for_quote(credential_binding, verified_quote)?;
        let quote = verified_quote.quote();
        let intent = verified_quote.intent();
        let request_digest = request.request_digest()?;
        if self.issuer_id != intent.issuer_id
            || self.quote_id != quote.quote_id
            || self.quote_request_digest != quote.request_digest
            || self.credential_request_digest != request_digest
            || self.authorization != intent.authorization
            || self.authorization != request.authorization
            || self.credential_binding_digest != intent.credential_binding_digest
            || self.credential_binding_digest != request.credential_binding_digest
            || self.credential_key_id != intent.credential_key_id
            || self.credential_key_id != request.credential_key_id
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialIssuanceResponseV1.binding",
                reason: "response does not bind the exact verified quote and issuance request",
            });
        }
        let expected_count = quote_credential_count(intent.credential_count)?;
        match (&request.items, &self.items) {
            (
                CredentialIssuanceRequestItemsV1::DirectPaidReceipt,
                CredentialIssuanceResponseItemsV1::DirectPaidReceipts(receipts),
            ) if receipts.len() == expected_count => {
                let binding = PaidReceiptBindingV1 {
                    scope_id: intent.scope_id,
                    offer_id: intent.offer_id,
                    policy_digest: intent.policy_digest,
                    entitlement_profile: intent.entitlement_profile,
                };
                let key_bytes: [u8; 32] = credential_binding
                    .claims
                    .verification_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| ServiceProtocolError::InvalidValue {
                        field: "CredentialKeyBindingV1.verification_key",
                        reason: "direct receipt verification key must be 32-byte Ed25519",
                    })?;
                let key = VerifyingKey::from_bytes(&key_bytes)
                    .map_err(|_| ServiceProtocolError::BadPublicKey)?;
                let mut serials = HashSet::with_capacity(receipts.len());
                for receipt in receipts {
                    if receipt.not_before < credential_binding.claims.not_before
                        || receipt.not_before < quote.invoice_created_at
                        || receipt.not_before > quote.claim_deadline
                        || receipt.not_after != quote.credential_not_after
                        || receipt.not_after > credential_binding.claims.not_after
                        || !serials.insert(receipt.serial)
                    {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "CredentialIssuanceResponseV1.receipts",
                            reason: "receipt activation/expiry is outside the quote or binding, or serial is duplicated",
                        });
                    }
                    // Verify the signature at the receipt's own lower bound so
                    // exact-response recovery remains possible after expiry.
                    receipt.verify(&key, &intent.issuer_id, &binding, receipt.not_before)?;
                }
                Ok(CheckedCredentialIssuanceResponseV1::DirectPaidReceipts(
                    receipts.clone(),
                ))
            }
            (
                CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(requests),
                CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(responses),
            ) if responses.len() == expected_count && requests.len() == responses.len() => {
                let issuer_public_key: [u8; 33] = credential_binding
                    .claims
                    .verification_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| ServiceProtocolError::InvalidValue {
                        field: "CredentialKeyBindingV1.verification_key",
                        reason: "BAT verification key must be 33 bytes",
                    })?;
                let mut tuples = Vec::with_capacity(responses.len());
                for (request_item, response_item) in requests.iter().zip(responses) {
                    if response_item.blinded_message != request_item.blinded_message {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "CredentialIssuanceResponseV1.bat.order",
                            reason: "BAT response must echo every B_ in exact request order",
                        });
                    }
                    tuples.push(UnverifiedCashuBatDleqTupleV1 {
                        issuer_public_key,
                        blinded_message: response_item.blinded_message,
                        blinded_signature: response_item.blinded_signature,
                        dleq_e: response_item.dleq_e,
                        dleq_s: response_item.dleq_s,
                    });
                }
                Ok(CheckedCredentialIssuanceResponseV1::BitcoinPirCashuBat {
                    unverified_dleq: tuples,
                })
            }
            (
                CredentialIssuanceRequestItemsV1::ArcExperimental(requests),
                CredentialIssuanceResponseItemsV1::ArcExperimental(responses),
            ) if responses.len() == expected_count && requests.len() == responses.len() => {
                let pending_finalize = requests
                    .iter()
                    .cloned()
                    .zip(responses.iter().cloned())
                    .map(|(request, response)| PendingArcCredentialFinalizeV1 { request, response })
                    .collect();
                Ok(CheckedCredentialIssuanceResponseV1::ArcExperimental { pending_finalize })
            }
            _ => Err(ServiceProtocolError::InvalidValue {
                field: "CredentialIssuanceResponseV1.items",
                reason: "response scheme, count, or request pairing differs from the signed quote",
            }),
        }
    }

    fn item_count(&self) -> usize {
        match &self.items {
            CredentialIssuanceResponseItemsV1::DirectPaidReceipts(items) => items.len(),
            CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(items) => items.len(),
            CredentialIssuanceResponseItemsV1::ArcExperimental(items) => items.len(),
        }
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.credential_request_digest.iter().all(|byte| *byte == 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialIssuanceResponseV1.credential_request_digest",
                reason: "must bind a non-zero canonical issuance request digest",
            });
        }
        validate_common_binding(
            &self.issuer_id,
            &self.quote_id,
            &self.quote_request_digest,
            self.authorization,
            &self.credential_binding_digest,
            &self.credential_key_id,
            "CredentialIssuanceResponseV1",
        )?;
        match (&self.authorization, &self.items) {
            (
                AuthScheme::Bolt11DirectReceiptV1,
                CredentialIssuanceResponseItemsV1::DirectPaidReceipts(receipts),
            ) => {
                check_item_count(
                    receipts.len(),
                    "CredentialIssuanceResponseV1.receipts",
                    false,
                )?;
                let mut serials = HashSet::with_capacity(receipts.len());
                for receipt in receipts {
                    let encoded = Zeroizing::new(receipt.encode()?);
                    if encoded.len() != PAID_RECEIPT_WIRE_LEN_V1
                        || !serials.insert((receipt.issuer_id, receipt.key_id, receipt.serial))
                    {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "CredentialIssuanceResponseV1.receipts",
                            reason: "receipts must be canonical and have unique issuer/key/serial tuples",
                        });
                    }
                }
                Ok(())
            }
            (
                AuthScheme::BitcoinPirCashuBatV1,
                CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(items),
            ) => validate_bat_responses(items),
            (
                AuthScheme::ArcV1Experimental,
                CredentialIssuanceResponseItemsV1::ArcExperimental(items),
            ) => {
                check_item_count(items.len(), "CredentialIssuanceResponseV1.arc", false)?;
                let mut responses = HashSet::with_capacity(items.len());
                if items.iter().all(|item| responses.insert(item.as_bytes())) {
                    Ok(())
                } else {
                    Err(ServiceProtocolError::InvalidValue {
                        field: "CredentialIssuanceResponseV1.arc",
                        reason: "duplicate ARC responses are forbidden",
                    })
                }
            }
            _ => Err(ServiceProtocolError::InvalidValue {
                field: "CredentialIssuanceResponseV1.authorization",
                reason: "scheme and item variant mismatch; standard Cashu uses NUT-04",
            }),
        }
    }
}

/// A canonical ARC request and response which still require the reviewed ARC
/// client to finalize and verify the response proof. No credential is implied
/// by this structural pairing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingArcCredentialFinalizeV1 {
    request: ArcCredentialRequestV1,
    response: ArcCredentialResponseV1,
}

impl PendingArcCredentialFinalizeV1 {
    pub const fn request(&self) -> &ArcCredentialRequestV1 {
        &self.request
    }

    pub const fn response(&self) -> &ArcCredentialResponseV1 {
        &self.response
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckedCredentialIssuanceResponseV1 {
    DirectPaidReceipts(Vec<PaidReceiptV1>),
    BitcoinPirCashuBat {
        unverified_dleq: Vec<UnverifiedCashuBatDleqTupleV1>,
    },
    ArcExperimental {
        pending_finalize: Vec<PendingArcCredentialFinalizeV1>,
    },
}

fn verify_credential_binding_for_quote(
    binding: &CredentialKeyBindingV1,
    verified_quote: &VerifiedBolt11QuoteV1<'_>,
) -> Result<(), ServiceProtocolError> {
    binding.verify_signature()?;
    let quote = verified_quote.quote();
    let intent = verified_quote.intent();
    let claims = &binding.claims;
    if binding.issuer_id != intent.issuer_id
        || binding.binding_digest()? != intent.credential_binding_digest
        || claims.provider_id != intent.provider_id
        || claims.scope_id != intent.scope_id
        || claims.offer_id != intent.offer_id
        || claims.scheme != intent.authorization
        || claims.entitlement_profile != intent.entitlement_profile
        || claims.presentation_limit != intent.credential_presentation_limit
        || claims.credential_key_id != intent.credential_key_id
        || quote.invoice_created_at < claims.not_before
        || quote.credential_not_after > claims.not_after
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "CredentialKeyBindingV1.quote_binding",
            reason: "credential key does not cover the exact quote audience, terms, and validity horizon",
        });
    }
    Ok(())
}

fn validate_bat_responses(
    items: &[BitcoinPirCashuBatIssuanceResponseItemV1],
) -> Result<(), ServiceProtocolError> {
    check_item_count(items.len(), "CredentialIssuanceResponseV1.bat", false)?;
    let mut messages = HashSet::with_capacity(items.len());
    let mut signatures = HashSet::with_capacity(items.len());
    for item in items {
        if !is_valid_compressed_point(&item.blinded_message)
            || !is_valid_compressed_point(&item.blinded_signature)
            || !is_valid_nonzero_scalar(&item.dleq_e)
            || !is_valid_nonzero_scalar(&item.dleq_s)
            || !messages.insert(item.blinded_message)
            || !signatures.insert(item.blinded_signature)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialIssuanceResponseV1.bat",
                reason: "BAT B_ and C_ points must be valid and unique, and NUT-12 scalars canonical and non-zero; DLEQ r is forbidden",
            });
        }
    }
    Ok(())
}

fn is_valid_nonzero_scalar(bytes: &[u8; 32]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
        && Option::<Scalar>::from(Scalar::from_repr((*bytes).into())).is_some()
}

fn validate_common_binding(
    issuer_id: &[u8; 32],
    quote_id: &[u8; 32],
    quote_request_digest: &[u8; 32],
    authorization: AuthScheme,
    credential_binding_digest: &[u8; 32],
    credential_key_id: &[u8],
    field: &'static str,
) -> Result<(), ServiceProtocolError> {
    if issuer_id.iter().all(|byte| *byte == 0)
        || quote_id.iter().all(|byte| *byte == 0)
        || quote_request_digest.iter().all(|byte| *byte == 0)
        || credential_binding_digest.iter().all(|byte| *byte == 0)
    {
        return Err(ServiceProtocolError::InvalidValue {
            field,
            reason: "issuer, quote, quote request, and credential binding IDs must be non-zero",
        });
    }
    if credential_key_id.is_empty() || credential_key_id.len() > MAX_CREDENTIAL_KEY_ID_LEN {
        return Err(ServiceProtocolError::FieldTooLong {
            field: "credential_key_id",
            len: credential_key_id.len(),
            max: MAX_CREDENTIAL_KEY_ID_LEN,
        });
    }
    if !matches!(
        authorization,
        AuthScheme::Bolt11DirectReceiptV1
            | AuthScheme::BitcoinPirCashuBatV1
            | AuthScheme::ArcV1Experimental
    ) {
        return Err(ServiceProtocolError::InvalidValue {
            field: "authorization",
            reason: "custom BOLT11 issuance excludes free and standard Cashu NUT-04",
        });
    }
    Ok(())
}

fn quote_credential_count(count: u32) -> Result<usize, ServiceProtocolError> {
    let max = usize::try_from(MAX_CREDENTIALS_PER_ACQUISITION_V1).map_err(|_| {
        ServiceProtocolError::InvalidValue {
            field: "MAX_CREDENTIALS_PER_ACQUISITION_V1",
            reason: "platform usize cannot represent the protocol maximum",
        }
    })?;
    if count == 0 || count > MAX_CREDENTIALS_PER_ACQUISITION_V1 {
        return Err(ServiceProtocolError::InvalidValue {
            field: "Bolt11QuoteIntentV1.credential_count",
            reason: "signed credential count is outside 1..=256",
        });
    }
    usize::try_from(count).map_err(|_| ServiceProtocolError::TooManyItems {
        field: "Bolt11QuoteIntentV1.credential_count",
        len: usize::MAX,
        max,
    })
}

fn check_item_count(
    count: usize,
    field: &'static str,
    allow_zero: bool,
) -> Result<(), ServiceProtocolError> {
    let max = usize::try_from(MAX_CREDENTIALS_PER_ACQUISITION_V1).map_err(|_| {
        ServiceProtocolError::InvalidValue {
            field: "MAX_CREDENTIALS_PER_ACQUISITION_V1",
            reason: "platform usize cannot represent the protocol maximum",
        }
    })?;
    if (!allow_zero && count == 0) || count > max {
        Err(ServiceProtocolError::TooManyItems {
            field,
            len: count,
            max,
        })
    } else {
        Ok(())
    }
}

fn put_len_u8(
    out: &mut Vec<u8>,
    len: usize,
    field: &'static str,
) -> Result<(), ServiceProtocolError> {
    let encoded = u8::try_from(len).map_err(|_| ServiceProtocolError::FieldTooLong {
        field,
        len,
        max: usize::from(u8::MAX),
    })?;
    out.push(encoded);
    Ok(())
}

fn put_len_u16(
    out: &mut Vec<u8>,
    len: usize,
    field: &'static str,
) -> Result<(), ServiceProtocolError> {
    let encoded = u16::try_from(len).map_err(|_| ServiceProtocolError::FieldTooLong {
        field,
        len,
        max: usize::from(u16::MAX),
    })?;
    out.extend_from_slice(&encoded.to_le_bytes());
    Ok(())
}

fn put_count_u16(
    out: &mut Vec<u8>,
    count: usize,
    field: &'static str,
) -> Result<(), ServiceProtocolError> {
    let encoded = u16::try_from(count).map_err(|_| ServiceProtocolError::TooManyItems {
        field,
        len: count,
        max: usize::from(u16::MAX),
    })?;
    out.extend_from_slice(&encoded.to_le_bytes());
    Ok(())
}

fn check_total_len(
    len: usize,
    max: usize,
    field: &'static str,
) -> Result<(), ServiceProtocolError> {
    if len > max {
        Err(ServiceProtocolError::FieldTooLong { field, len, max })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};

    use crate::{
        derive_bat_key_id_v1, paid_receipt_key_id, Bolt11QuoteIntentV1, Bolt11QuoteKeyDelegationV1,
        Bolt11QuoteStatusV1, Bolt11QuoteV1, CredentialKeyBindingClaimsV1, CredentialUnitV1,
        LightningNetworkV1, ParsedBolt11InvoiceV1,
    };

    const CREATED_AT: u64 = 1_000;
    const CLAIM_AT: u64 = 1_500;
    const INVOICE: &str = "lnbc10u1qqqqqqqq";

    struct ExactArcCodec;

    impl ArcIssuanceCanonicalizerV1 for ExactArcCodec {
        fn decode_and_reencode_request(
            &self,
            request: &[u8],
        ) -> Result<Vec<u8>, ServiceProtocolError> {
            Ok(request.to_vec())
        }

        fn decode_and_reencode_response(
            &self,
            response: &[u8],
        ) -> Result<Vec<u8>, ServiceProtocolError> {
            Ok(response.to_vec())
        }
    }

    struct NormalizingArcCodec;

    impl ArcIssuanceCanonicalizerV1 for NormalizingArcCodec {
        fn decode_and_reencode_request(
            &self,
            request: &[u8],
        ) -> Result<Vec<u8>, ServiceProtocolError> {
            let mut normalized = request.to_vec();
            normalized[0] ^= 1;
            Ok(normalized)
        }

        fn decode_and_reencode_response(
            &self,
            response: &[u8],
        ) -> Result<Vec<u8>, ServiceProtocolError> {
            let mut normalized = response.to_vec();
            normalized[0] ^= 1;
            Ok(normalized)
        }
    }

    struct Fixture {
        binding: CredentialKeyBindingV1,
        intent: Bolt11QuoteIntentV1,
        quote: Bolt11QuoteV1,
        delegation: Bolt11QuoteKeyDelegationV1,
        parsed_invoice: ParsedBolt11InvoiceV1,
    }

    impl Fixture {
        fn verified_quote(&self) -> VerifiedBolt11QuoteV1<'_> {
            self.quote
                .verify_for_claim_submission(
                    &self.intent,
                    &self.delegation,
                    &self.parsed_invoice,
                    CLAIM_AT,
                )
                .unwrap()
        }

        fn request(&self) -> CredentialIssuanceRequestV1 {
            let items = match self.intent.authorization {
                AuthScheme::Bolt11DirectReceiptV1 => {
                    CredentialIssuanceRequestItemsV1::DirectPaidReceipt
                }
                AuthScheme::BitcoinPirCashuBatV1 => {
                    CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(vec![
                        BitcoinPirCashuBatIssuanceRequestItemV1 {
                            blinded_message: point(11),
                        },
                        BitcoinPirCashuBatIssuanceRequestItemV1 {
                            blinded_message: point(12),
                        },
                    ])
                }
                AuthScheme::ArcV1Experimental => {
                    CredentialIssuanceRequestItemsV1::ArcExperimental(vec![
                        arc_request(21),
                        arc_request(22),
                    ])
                }
                _ => unreachable!(),
            };
            CredentialIssuanceRequestV1 {
                issuer_id: self.intent.issuer_id,
                quote_id: self.quote.quote_id,
                quote_request_digest: self.quote.request_digest,
                authorization: self.intent.authorization,
                credential_binding_digest: self.intent.credential_binding_digest,
                credential_key_id: self.intent.credential_key_id.clone(),
                items,
            }
        }

        fn claim(&self, request: &CredentialIssuanceRequestV1) -> Bolt11QuoteClaimV1 {
            Bolt11QuoteClaimV1 {
                issuer_id: self.intent.issuer_id,
                quote_id: self.quote.quote_id,
                quote_request_digest: self.quote.request_digest,
                credential_request_digest: request.request_digest().unwrap(),
                claim_pubkey_xonly: self.intent.claim_pubkey_xonly,
                // Quote creation and claim are separate idempotency domains.
                idempotency_key: [12; 32],
                signature: [13; 64],
            }
        }
    }

    fn point(multiplier: u64) -> [u8; 33] {
        (ProjectivePoint::GENERATOR * Scalar::from(multiplier))
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn scalar(multiplier: u64) -> [u8; 32] {
        Scalar::from(multiplier).to_bytes().into()
    }

    fn arc_request(seed: u8) -> ArcCredentialRequestV1 {
        ArcCredentialRequestV1::decode_canonical(
            &[seed; ARC_CREDENTIAL_REQUEST_LEN_V1],
            &ExactArcCodec,
        )
        .unwrap()
    }

    fn arc_response(seed: u8) -> ArcCredentialResponseV1 {
        ArcCredentialResponseV1::decode_canonical(
            &[seed; ARC_CREDENTIAL_RESPONSE_LEN_V1],
            &ExactArcCodec,
        )
        .unwrap()
    }

    fn fixture(scheme: AuthScheme) -> Fixture {
        let provider_id = [2; 32];
        let scope_id = [4; 32];
        let offer_id = 9;
        let entitlement_profile = 3;
        let issuer_key = SigningKey::from_bytes(&[7; 32]);
        let receipt_key = SigningKey::from_bytes(&[21; 32]);
        let (credential_key_id, verification_key, unit, presentation_limit) = match scheme {
            AuthScheme::Bolt11DirectReceiptV1 => (
                paid_receipt_key_id(&receipt_key.verifying_key()).to_vec(),
                receipt_key.verifying_key().to_bytes().to_vec(),
                CredentialUnitV1::Entitlement,
                1,
            ),
            AuthScheme::BitcoinPirCashuBatV1 => {
                let verification_key = point(7);
                (
                    derive_bat_key_id_v1(
                        &provider_id,
                        &scope_id,
                        offer_id,
                        entitlement_profile,
                        1,
                        &verification_key,
                    )
                    .to_vec(),
                    verification_key.to_vec(),
                    CredentialUnitV1::Auth,
                    1,
                )
            }
            AuthScheme::ArcV1Experimental => {
                (vec![31; 16], vec![32; 99], CredentialUnitV1::Auth, 4)
            }
            _ => unreachable!(),
        };
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id,
                offer_id,
                scheme,
                keyset_epoch: 1,
                entitlement_profile,
                unit,
                amount: 1,
                presentation_limit,
                not_before: 900,
                not_after: 7_000,
                credential_key_id: credential_key_id.clone(),
                verification_key,
            },
            &issuer_key,
        )
        .unwrap();
        let payee = point(3);
        let quote_key = SigningKey::from_bytes(&[8; 32]);
        let delegation = Bolt11QuoteKeyDelegationV1::sign(
            LightningNetworkV1::Bitcoin,
            payee,
            4,
            100,
            10_000,
            quote_key.verifying_key().to_bytes(),
            &issuer_key,
        )
        .unwrap();
        let intent = Bolt11QuoteIntentV1 {
            issuer_id: binding.issuer_id,
            provider_id,
            policy_digest: [3; 32],
            scope_id,
            offer_id,
            network: LightningNetworkV1::Bitcoin,
            expected_payee_pubkey: payee,
            minimum_quote_key_epoch: 4,
            quote_delegation_digest: delegation.delegation_digest().unwrap(),
            authorization: scheme,
            credential_binding_digest: binding.binding_digest().unwrap(),
            credential_key_id,
            exact_amount_msat: 100_000,
            entitlement_profile,
            credential_count: 2,
            credential_presentation_limit: presentation_limit,
            invoice_expiry_seconds: 600,
            claim_window_seconds: 900,
            minimum_credential_validity_seconds: 3_600,
            claim_pubkey_xonly: point(5)[1..].try_into().unwrap(),
            idempotency_key: [9; 32],
        };
        let parsed_invoice = ParsedBolt11InvoiceV1::from_signature_verified_invoice(
            INVOICE,
            intent.network,
            payee,
            intent.exact_amount_msat,
            CREATED_AT,
            intent.invoice_expiry_seconds,
        )
        .unwrap();
        let open_quote = Bolt11QuoteV1::sign(
            &intent,
            [10; 32],
            INVOICE.into(),
            CREATED_AT,
            Bolt11QuoteStatusV1::InvoiceOpen,
            CREATED_AT,
            &delegation,
            &quote_key,
        )
        .unwrap();
        let verified_open = open_quote
            .verify_snapshot(&intent, &delegation, &parsed_invoice, 1_400)
            .unwrap();
        let quote = Bolt11QuoteV1::with_status_from_verified_snapshot(
            &verified_open,
            Bolt11QuoteStatusV1::PaymentSettled,
            1_400,
            &delegation,
            &quote_key,
        )
        .unwrap();
        Fixture {
            binding,
            intent,
            quote,
            delegation,
            parsed_invoice,
        }
    }

    #[test]
    fn requests_roundtrip_and_claim_exact_ordered_digest() {
        for scheme in [
            AuthScheme::Bolt11DirectReceiptV1,
            AuthScheme::BitcoinPirCashuBatV1,
            AuthScheme::ArcV1Experimental,
        ] {
            let fixture = fixture(scheme);
            let request = fixture.request();
            let encoded = request.encode().unwrap();
            let arc = (scheme == AuthScheme::ArcV1Experimental)
                .then_some(&ExactArcCodec as &dyn ArcIssuanceCanonicalizerV1);
            assert_eq!(
                CredentialIssuanceRequestV1::decode(&encoded, arc).unwrap(),
                request
            );
            let claim = fixture.claim(&request);
            let unverified = request
                .verify_for_verified_quote(&claim, &fixture.verified_quote(), CLAIM_AT)
                .unwrap();
            assert_eq!(
                unverified.claim_pubkey_xonly,
                fixture.intent.claim_pubkey_xonly
            );

            let mut bad_claim = claim.clone();
            bad_claim.credential_request_digest[0] ^= 1;
            assert!(request
                .verify_for_verified_quote(&bad_claim, &fixture.verified_quote(), CLAIM_AT)
                .is_err());

            let mut trailing = encoded;
            trailing.push(0);
            assert!(CredentialIssuanceRequestV1::decode(&trailing, arc).is_err());
        }
    }

    #[test]
    fn claim_http_envelope_is_canonical_and_binds_both_objects() {
        for scheme in [
            AuthScheme::Bolt11DirectReceiptV1,
            AuthScheme::BitcoinPirCashuBatV1,
            AuthScheme::ArcV1Experimental,
        ] {
            let fixture = fixture(scheme);
            let credential_request = fixture.request();
            let envelope = Bolt11QuoteClaimEnvelopeV1 {
                quote_intent: fixture.intent.clone(),
                claim: fixture.claim(&credential_request),
                credential_request,
            };
            let encoded = envelope.encode().unwrap();
            let arc = (scheme == AuthScheme::ArcV1Experimental)
                .then_some(&ExactArcCodec as &dyn ArcIssuanceCanonicalizerV1);
            assert_eq!(
                Bolt11QuoteClaimEnvelopeV1::decode(&encoded, arc).unwrap(),
                envelope
            );

            let mut trailing = encoded.clone();
            trailing.push(0);
            assert!(Bolt11QuoteClaimEnvelopeV1::decode(&trailing, arc).is_err());

            let mut mismatched = envelope.clone();
            mismatched.claim.quote_request_digest[0] ^= 1;
            assert!(mismatched.encode().is_err());
        }
    }

    #[test]
    fn requests_reject_cross_scheme_counts_duplicates_points_and_oversize() {
        let bat_fixture = fixture(AuthScheme::BitcoinPirCashuBatV1);
        let mut request = bat_fixture.request();
        if let CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(items) = &mut request.items {
            items.pop();
        }
        let claim = bat_fixture.claim(&request);
        assert!(request
            .verify_for_verified_quote(&claim, &bat_fixture.verified_quote(), CLAIM_AT)
            .is_err());

        let mut duplicate = bat_fixture.request();
        if let CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(items) = &mut duplicate.items {
            items[1] = items[0];
        }
        assert!(duplicate.encode().is_err());

        let mut invalid = bat_fixture.request();
        if let CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(items) = &mut invalid.items {
            items[0].blinded_message = [0; 33];
        }
        assert!(invalid.encode().is_err());

        let mut standard_cashu = bat_fixture.request();
        standard_cashu.authorization = AuthScheme::CashuEcashV1;
        assert!(standard_cashu.encode().is_err());

        let arc_fixture = fixture(AuthScheme::ArcV1Experimental);
        let mut duplicate_arc = arc_fixture.request();
        if let CredentialIssuanceRequestItemsV1::ArcExperimental(items) = &mut duplicate_arc.items {
            items[1] = items[0].clone();
        }
        assert!(duplicate_arc.encode().is_err());
        assert!(ArcCredentialRequestV1::decode_canonical(
            &[1; ARC_CREDENTIAL_REQUEST_LEN_V1 - 1],
            &ExactArcCodec,
        )
        .is_err());
        assert!(ArcCredentialRequestV1::decode_canonical(
            &[1; ARC_CREDENTIAL_REQUEST_LEN_V1],
            &NormalizingArcCodec,
        )
        .is_err());
        assert!(CredentialIssuanceRequestV1::decode(
            &vec![0; MAX_CREDENTIAL_ISSUANCE_REQUEST_LEN_V1 + 1],
            None,
        )
        .is_err());
    }

    fn bat_response(
        fixture: &Fixture,
        request: &CredentialIssuanceRequestV1,
    ) -> CredentialIssuanceResponseV1 {
        let requests = match &request.items {
            CredentialIssuanceRequestItemsV1::BitcoinPirCashuBat(items) => items,
            _ => unreachable!(),
        };
        CredentialIssuanceResponseV1 {
            issuer_id: fixture.intent.issuer_id,
            quote_id: fixture.quote.quote_id,
            quote_request_digest: fixture.quote.request_digest,
            credential_request_digest: request.request_digest().unwrap(),
            authorization: AuthScheme::BitcoinPirCashuBatV1,
            credential_binding_digest: fixture.intent.credential_binding_digest,
            credential_key_id: fixture.intent.credential_key_id.clone(),
            items: CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(
                requests
                    .iter()
                    .enumerate()
                    .map(
                        |(index, request)| BitcoinPirCashuBatIssuanceResponseItemV1 {
                            blinded_message: request.blinded_message,
                            blinded_signature: point(30 + index as u64),
                            // Equal/repeated valid proof scalars are structurally
                            // legal; only the DLEQ verifier decides validity.
                            dleq_e: scalar(40),
                            dleq_s: scalar(40),
                        },
                    )
                    .collect(),
            ),
        }
    }

    #[test]
    fn bat_response_roundtrips_preserves_order_and_stays_unverified() {
        let fixture = fixture(AuthScheme::BitcoinPirCashuBatV1);
        let request = fixture.request();
        let response = bat_response(&fixture, &request);
        let encoded = response.encode().unwrap();
        assert_eq!(
            CredentialIssuanceResponseV1::decode(&encoded, None).unwrap(),
            response
        );
        match response
            .verify_for_verified_quote(&request, &fixture.verified_quote(), &fixture.binding)
            .unwrap()
        {
            CheckedCredentialIssuanceResponseV1::BitcoinPirCashuBat { unverified_dleq } => {
                assert_eq!(unverified_dleq.len(), 2);
                assert_eq!(unverified_dleq[0].blinded_message, point(11));
            }
            _ => panic!("wrong response variant"),
        }

        let mut reordered = response.clone();
        if let CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(items) = &mut reordered.items {
            items.swap(0, 1);
        }
        assert!(reordered
            .verify_for_verified_quote(&request, &fixture.verified_quote(), &fixture.binding)
            .is_err());

        let mut duplicate = response.clone();
        if let CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(items) = &mut duplicate.items {
            items[1].blinded_signature = items[0].blinded_signature;
        }
        assert!(duplicate.encode().is_err());

        let mut zero_scalar = response.clone();
        if let CredentialIssuanceResponseItemsV1::BitcoinPirCashuBat(items) = &mut zero_scalar.items
        {
            items[0].dleq_e = [0; 32];
        }
        assert!(zero_scalar.encode().is_err());
    }

    fn direct_response(
        fixture: &Fixture,
        request: &CredentialIssuanceRequestV1,
    ) -> CredentialIssuanceResponseV1 {
        let key = SigningKey::from_bytes(&[21; 32]);
        let binding = PaidReceiptBindingV1 {
            scope_id: fixture.intent.scope_id,
            offer_id: fixture.intent.offer_id,
            policy_digest: fixture.intent.policy_digest,
            entitlement_profile: fixture.intent.entitlement_profile,
        };
        let receipts = [1u8, 2]
            .into_iter()
            .map(|serial| {
                PaidReceiptV1::sign(
                    fixture.intent.issuer_id,
                    [serial; 32],
                    binding.clone(),
                    CLAIM_AT,
                    fixture.quote.credential_not_after,
                    &key,
                )
                .unwrap()
            })
            .collect();
        CredentialIssuanceResponseV1 {
            issuer_id: fixture.intent.issuer_id,
            quote_id: fixture.quote.quote_id,
            quote_request_digest: fixture.quote.request_digest,
            credential_request_digest: request.request_digest().unwrap(),
            authorization: fixture.intent.authorization,
            credential_binding_digest: fixture.intent.credential_binding_digest,
            credential_key_id: fixture.intent.credential_key_id.clone(),
            items: CredentialIssuanceResponseItemsV1::DirectPaidReceipts(receipts),
        }
    }

    #[test]
    fn direct_receipts_verify_signature_count_serial_and_horizons() {
        let fixture = fixture(AuthScheme::Bolt11DirectReceiptV1);
        let request = fixture.request();
        let response = direct_response(&fixture, &request);
        let encoded = response.encode().unwrap();
        assert_eq!(encoded.len(), 1 + 32 * 5 + 1 + 1 + 16 + 2 + 2 * (2 + 231));
        assert_eq!(
            CredentialIssuanceResponseV1::decode(&encoded, None).unwrap(),
            response
        );
        assert!(matches!(
            response
                .verify_for_verified_quote(&request, &fixture.verified_quote(), &fixture.binding)
                .unwrap(),
            CheckedCredentialIssuanceResponseV1::DirectPaidReceipts(receipts)
                if receipts.len() == 2
        ));

        let mutate_first = |mut response: CredentialIssuanceResponseV1,
                            f: fn(&mut PaidReceiptV1)| {
            if let CredentialIssuanceResponseItemsV1::DirectPaidReceipts(receipts) =
                &mut response.items
            {
                f(&mut receipts[0]);
            }
            response
        };
        let too_early = mutate_first(response.clone(), |receipt| {
            receipt.not_before = CREATED_AT - 1
        });
        assert!(too_early
            .verify_for_verified_quote(&request, &fixture.verified_quote(), &fixture.binding)
            .is_err());
        let too_late = mutate_first(response.clone(), |receipt| receipt.not_before = 2_501);
        assert!(too_late
            .verify_for_verified_quote(&request, &fixture.verified_quote(), &fixture.binding)
            .is_err());
        let wrong_expiry = mutate_first(response.clone(), |receipt| receipt.not_after -= 1);
        assert!(wrong_expiry
            .verify_for_verified_quote(&request, &fixture.verified_quote(), &fixture.binding)
            .is_err());

        let mut duplicate = response;
        if let CredentialIssuanceResponseItemsV1::DirectPaidReceipts(receipts) =
            &mut duplicate.items
        {
            receipts[1] = receipts[0].clone();
        }
        assert!(duplicate.encode().is_err());
    }

    #[test]
    fn arc_response_is_only_a_canonical_pending_finalize_pair() {
        let fixture = fixture(AuthScheme::ArcV1Experimental);
        let request = fixture.request();
        let response = CredentialIssuanceResponseV1 {
            issuer_id: fixture.intent.issuer_id,
            quote_id: fixture.quote.quote_id,
            quote_request_digest: fixture.quote.request_digest,
            credential_request_digest: request.request_digest().unwrap(),
            authorization: fixture.intent.authorization,
            credential_binding_digest: fixture.intent.credential_binding_digest,
            credential_key_id: fixture.intent.credential_key_id.clone(),
            items: CredentialIssuanceResponseItemsV1::ArcExperimental(vec![
                arc_response(41),
                arc_response(42),
            ]),
        };
        let encoded = response.encode().unwrap();
        assert!(CredentialIssuanceResponseV1::decode(&encoded, None).is_err());
        assert_eq!(
            CredentialIssuanceResponseV1::decode(&encoded, Some(&ExactArcCodec)).unwrap(),
            response
        );
        match response
            .verify_for_verified_quote(&request, &fixture.verified_quote(), &fixture.binding)
            .unwrap()
        {
            CheckedCredentialIssuanceResponseV1::ArcExperimental { pending_finalize } => {
                assert_eq!(pending_finalize.len(), 2);
                assert_eq!(pending_finalize[0].request().as_bytes(), &[21; 226]);
                assert_eq!(pending_finalize[0].response().as_bytes(), &[41; 454]);
            }
            _ => panic!("wrong response variant"),
        }
        assert!(ArcCredentialResponseV1::decode_canonical(
            &[1; ARC_CREDENTIAL_RESPONSE_LEN_V1 - 1],
            &ExactArcCodec,
        )
        .is_err());
        assert!(ArcCredentialResponseV1::decode_canonical(
            &[1; ARC_CREDENTIAL_RESPONSE_LEN_V1],
            &NormalizingArcCodec,
        )
        .is_err());
        let mut duplicate = response;
        if let CredentialIssuanceResponseItemsV1::ArcExperimental(items) = &mut duplicate.items {
            items[1] = items[0].clone();
        }
        assert!(duplicate.encode().is_err());
    }

    #[test]
    fn response_rejects_zero_request_digest_cross_scheme_and_oversize() {
        let fixture = fixture(AuthScheme::BitcoinPirCashuBatV1);
        let request = fixture.request();
        let mut response = bat_response(&fixture, &request);
        response.credential_request_digest = [0; 32];
        assert!(response.encode().is_err());

        let mut cross_scheme = bat_response(&fixture, &request);
        cross_scheme.authorization = AuthScheme::ArcV1Experimental;
        assert!(cross_scheme.encode().is_err());

        assert!(CredentialIssuanceResponseV1::decode(
            &vec![0; MAX_CREDENTIAL_ISSUANCE_RESPONSE_LEN_V1 + 1],
            None,
        )
        .is_err());

        let mut trailing = bat_response(&fixture, &request).encode().unwrap();
        trailing.push(0);
        assert!(CredentialIssuanceResponseV1::decode(&trailing, None).is_err());
    }
}
