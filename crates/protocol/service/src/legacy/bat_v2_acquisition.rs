//! Class-bound BOLT11 acquisition for issuer-wide BitcoinPIR Cashu BAT V2.
//!
//! This module deliberately does not reinterpret the provider-bound V1
//! credential binding. A V2 quote commits to an issuer-signed acceptance
//! class and key epoch; no provider, policy, scope, offer, or
//! `CredentialKeyBindingV1` digest is part of the issued BAT.

use core::fmt;
use std::collections::HashSet;

use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::cashu_manifest::is_valid_compressed_point;
use crate::codec::{put_bytes_u32, Decoder};
use crate::{
    BatAcceptanceClassV2, BitcoinPirCashuBatIssuanceRequestItemV1,
    BitcoinPirCashuBatIssuanceResponseItemV1, Bolt11QuoteClaimV1, Bolt11QuoteHorizonsV1,
    Bolt11QuoteKeyDelegationV1, Bolt11QuoteKeyRollbackGuardV1, Bolt11QuoteV1, LightningNetworkV1,
    ServiceProtocolError, UnverifiedBip340ClaimV1, UnverifiedCashuBatDleqTupleV1,
    VerifiedBatAcceptanceMemberV2, MAX_BITCOIN_MSAT_V1, MAX_BOLT11_CLAIM_WINDOW_SECONDS_V1,
    MAX_BOLT11_CREDENTIAL_VALIDITY_SECONDS_V1, MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1,
    MAX_BOLT11_QUOTE_CLAIM_LEN, MAX_CREDENTIALS_PER_ACQUISITION_V1,
};

pub const BAT_V2_QUOTE_INTENT_CODEC_MAGIC: &[u8; 8] = b"BPIRBQI2";
pub const BAT_V2_QUOTE_INTENT_WIRE_VERSION: u8 = 2;
pub const BAT_V2_QUOTE_INTENT_DIGEST_DOMAIN: &[u8] =
    b"BitcoinPIR/bat-v2-bolt11-quote-intent-digest/v2";

pub const BAT_V2_ISSUANCE_REQUEST_CODEC_MAGIC: &[u8; 8] = b"BPIRBQR2";
pub const BAT_V2_ISSUANCE_REQUEST_WIRE_VERSION: u8 = 2;
pub const BAT_V2_ISSUANCE_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"BitcoinPIR/bat-v2-issuance-request-digest/v2";

pub const BAT_V2_ISSUANCE_RESPONSE_CODEC_MAGIC: &[u8; 8] = b"BPIRBQS2";
pub const BAT_V2_ISSUANCE_RESPONSE_WIRE_VERSION: u8 = 2;

pub const BAT_V2_CLAIM_ENVELOPE_CODEC_MAGIC: &[u8; 8] = b"BPIRBQE2";
pub const BAT_V2_CLAIM_ENVELOPE_WIRE_VERSION: u8 = 2;

pub const MAX_BAT_V2_QUOTE_INTENT_LEN: usize = 512;
pub const MAX_BAT_V2_ISSUANCE_REQUEST_LEN: usize = 64 * 1024;
pub const MAX_BAT_V2_ISSUANCE_RESPONSE_LEN: usize = 128 * 1024;
pub const MAX_BAT_V2_CLAIM_ENVELOPE_LEN: usize = 1
    + BAT_V2_CLAIM_ENVELOPE_CODEC_MAGIC.len()
    + 4
    + MAX_BAT_V2_QUOTE_INTENT_LEN
    + 4
    + MAX_BOLT11_QUOTE_CLAIM_LEN
    + 4
    + MAX_BAT_V2_ISSUANCE_REQUEST_LEN;

/// Immutable, class-only BOLT11 acquisition intent.
///
/// The provider member used to discover this class is checked by the safe
/// constructor but intentionally does not appear on this wire object.
#[derive(Clone, PartialEq, Eq)]
pub struct Bolt11BatV2QuoteIntentV2 {
    pub issuer_id: [u8; 32],
    pub class_id: [u8; 32],
    pub class_digest: [u8; 32],
    pub class_key_epoch: u64,
    pub bat_key_id: [u8; 32],
    pub network: LightningNetworkV1,
    pub expected_payee_pubkey: [u8; 33],
    pub minimum_quote_key_epoch: u64,
    pub quote_delegation_digest: [u8; 32],
    pub exact_amount_msat: u64,
    pub credential_count: u32,
    pub invoice_expiry_seconds: u32,
    pub claim_window_seconds: u32,
    pub minimum_credential_validity_seconds: u32,
    /// BIP340 x-only public key controlling private status and claim calls.
    pub claim_pubkey_xonly: [u8; 32],
    pub idempotency_key: [u8; 32],
}

impl fmt::Debug for Bolt11BatV2QuoteIntentV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bolt11BatV2QuoteIntentV2")
            .field("class_key_epoch", &self.class_key_epoch)
            .field("commercial_and_client_binding", &"[REDACTED]")
            .finish()
    }
}

impl Drop for Bolt11BatV2QuoteIntentV2 {
    fn drop(&mut self) {
        self.idempotency_key.zeroize();
    }
}

impl Bolt11BatV2QuoteIntentV2 {
    /// Client integration entry point. The selected verified provider-policy
    /// member is checked against the exact issuer-signed class, but its
    /// provider coordinates are deliberately omitted from the resulting BAT.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_class_member_guarded(
        verified_member: &VerifiedBatAcceptanceMemberV2,
        class: &BatAcceptanceClassV2,
        quote_delegation: &Bolt11QuoteKeyDelegationV1,
        rollback_guard: &Bolt11QuoteKeyRollbackGuardV1,
        now_unix: u64,
        claim_pubkey_xonly: [u8; 32],
        idempotency_key: [u8; 32],
    ) -> Result<(Self, Bolt11QuoteKeyRollbackGuardV1), ServiceProtocolError> {
        validate_verified_member_for_class(verified_member, class, now_unix)?;
        let advanced_guard = rollback_guard.verify_and_advance(quote_delegation, now_unix)?;
        let intent = Self::from_verified_class(
            class,
            quote_delegation,
            &advanced_guard,
            now_unix,
            claim_pubkey_xonly,
            idempotency_key,
        )?;
        Ok((intent, advanced_guard))
    }

    /// Recheck both the selected member and the exact class-only wire intent.
    pub fn verify_for_class_member_guarded<'a>(
        &'a self,
        verified_member: &VerifiedBatAcceptanceMemberV2,
        class: &'a BatAcceptanceClassV2,
        quote_delegation: &'a Bolt11QuoteKeyDelegationV1,
        rollback_guard: &Bolt11QuoteKeyRollbackGuardV1,
        now_unix: u64,
    ) -> Result<VerifiedBolt11BatV2QuoteIntentV2<'a>, ServiceProtocolError> {
        validate_verified_member_for_class(verified_member, class, now_unix)?;
        self.verify_for_class_guarded(class, quote_delegation, rollback_guard, now_unix)
    }

    /// Issuer entry point. The wire intent carries no purchase-source member,
    /// so the issuer validates it directly against its authoritative exact
    /// class artifact and current-or-recovery selection policy.
    pub fn verify_for_class_guarded<'a>(
        &'a self,
        class: &'a BatAcceptanceClassV2,
        quote_delegation: &'a Bolt11QuoteKeyDelegationV1,
        rollback_guard: &Bolt11QuoteKeyRollbackGuardV1,
        now_unix: u64,
    ) -> Result<VerifiedBolt11BatV2QuoteIntentV2<'a>, ServiceProtocolError> {
        let advanced_guard = rollback_guard.verify_and_advance(quote_delegation, now_unix)?;
        let expected = Self::from_verified_class(
            class,
            quote_delegation,
            &advanced_guard,
            now_unix,
            self.claim_pubkey_xonly,
            self.idempotency_key,
        )?;
        if self != &expected {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11BatV2QuoteIntentV2.class_binding",
                reason: "intent differs from the exact signed class or quote-key delegation",
            });
        }
        Ok(VerifiedBolt11BatV2QuoteIntentV2 {
            intent: self,
            class,
            delegation: quote_delegation,
            advanced_guard,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn from_verified_class(
        class: &BatAcceptanceClassV2,
        quote_delegation: &Bolt11QuoteKeyDelegationV1,
        advanced_guard: &Bolt11QuoteKeyRollbackGuardV1,
        now_unix: u64,
        claim_pubkey_xonly: [u8; 32],
        idempotency_key: [u8; 32],
    ) -> Result<Self, ServiceProtocolError> {
        class.verify()?;
        if now_unix == 0 || now_unix < class.key_not_before || now_unix > class.key_not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceClassV2.key_validity",
                reason: "class key is not active at quote verification time",
            });
        }
        quote_delegation.verify_for(
            &class.issuer_id,
            advanced_guard.network(),
            &advanced_guard.expected_payee_pubkey(),
            advanced_guard.highest_epoch(),
            now_unix,
        )?;
        let value = Self {
            issuer_id: class.issuer_id,
            class_id: class.class_id,
            class_digest: class.class_digest()?,
            class_key_epoch: class.key_epoch,
            bat_key_id: class.bat_key_id(),
            network: advanced_guard.network(),
            expected_payee_pubkey: advanced_guard.expected_payee_pubkey(),
            minimum_quote_key_epoch: advanced_guard.highest_epoch(),
            quote_delegation_digest: quote_delegation.delegation_digest()?,
            exact_amount_msat: class.common_terms.price_msat,
            credential_count: class.common_terms.credential_count,
            invoice_expiry_seconds: class.common_terms.invoice_expiry_seconds,
            claim_window_seconds: class.common_terms.claim_window_seconds,
            minimum_credential_validity_seconds: class
                .common_terms
                .minimum_credential_validity_seconds,
            claim_pubkey_xonly,
            idempotency_key,
        };
        value.validate()?;
        if value.derived_horizons(now_unix)?.credential_not_after > class.key_not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceClassV2.key_not_after",
                reason: "class key does not cover a newly created quote and credential horizon",
            });
        }
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Zeroizing::new(Vec::with_capacity(320));
        out.extend_from_slice(BAT_V2_QUOTE_INTENT_CODEC_MAGIC);
        out.push(BAT_V2_QUOTE_INTENT_WIRE_VERSION);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.class_id);
        out.extend_from_slice(&self.class_digest);
        out.extend_from_slice(&self.class_key_epoch.to_le_bytes());
        out.extend_from_slice(&self.bat_key_id);
        out.push(self.network as u8);
        out.extend_from_slice(&self.expected_payee_pubkey);
        out.extend_from_slice(&self.minimum_quote_key_epoch.to_le_bytes());
        out.extend_from_slice(&self.quote_delegation_digest);
        out.extend_from_slice(&self.exact_amount_msat.to_le_bytes());
        out.extend_from_slice(&self.credential_count.to_le_bytes());
        out.extend_from_slice(&self.invoice_expiry_seconds.to_le_bytes());
        out.extend_from_slice(&self.claim_window_seconds.to_le_bytes());
        out.extend_from_slice(&self.minimum_credential_validity_seconds.to_le_bytes());
        out.extend_from_slice(&self.claim_pubkey_xonly);
        out.extend_from_slice(&self.idempotency_key);
        check_len(
            out.len(),
            MAX_BAT_V2_QUOTE_INTENT_LEN,
            "Bolt11BatV2QuoteIntentV2",
        )?;
        Ok(std::mem::take(&mut *out))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        check_len(
            bytes.len(),
            MAX_BAT_V2_QUOTE_INTENT_LEN,
            "Bolt11BatV2QuoteIntentV2",
        )?;
        let mut decoder = Decoder::new(bytes);
        expect_magic(
            decoder.fixed("Bolt11BatV2QuoteIntentV2.magic")?,
            BAT_V2_QUOTE_INTENT_CODEC_MAGIC,
            "Bolt11BatV2QuoteIntentV2.magic",
        )?;
        expect_v2(
            decoder.u8("Bolt11BatV2QuoteIntentV2.version")?,
            "Bolt11BatV2QuoteIntentV2",
        )?;
        let value = Self {
            issuer_id: decoder.fixed("Bolt11BatV2QuoteIntentV2.issuer_id")?,
            class_id: decoder.fixed("Bolt11BatV2QuoteIntentV2.class_id")?,
            class_digest: decoder.fixed("Bolt11BatV2QuoteIntentV2.class_digest")?,
            class_key_epoch: decoder.u64("Bolt11BatV2QuoteIntentV2.class_key_epoch")?,
            bat_key_id: decoder.fixed("Bolt11BatV2QuoteIntentV2.bat_key_id")?,
            network: LightningNetworkV1::decode(decoder.u8("Bolt11BatV2QuoteIntentV2.network")?)?,
            expected_payee_pubkey: decoder
                .fixed("Bolt11BatV2QuoteIntentV2.expected_payee_pubkey")?,
            minimum_quote_key_epoch: decoder
                .u64("Bolt11BatV2QuoteIntentV2.minimum_quote_key_epoch")?,
            quote_delegation_digest: decoder
                .fixed("Bolt11BatV2QuoteIntentV2.quote_delegation_digest")?,
            exact_amount_msat: decoder.u64("Bolt11BatV2QuoteIntentV2.exact_amount_msat")?,
            credential_count: decoder.u32("Bolt11BatV2QuoteIntentV2.credential_count")?,
            invoice_expiry_seconds: decoder
                .u32("Bolt11BatV2QuoteIntentV2.invoice_expiry_seconds")?,
            claim_window_seconds: decoder.u32("Bolt11BatV2QuoteIntentV2.claim_window_seconds")?,
            minimum_credential_validity_seconds: decoder
                .u32("Bolt11BatV2QuoteIntentV2.minimum_credential_validity_seconds")?,
            claim_pubkey_xonly: decoder.fixed("Bolt11BatV2QuoteIntentV2.claim_pubkey_xonly")?,
            idempotency_key: decoder.fixed("Bolt11BatV2QuoteIntentV2.idempotency_key")?,
        };
        decoder.finish()?;
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11BatV2QuoteIntentV2",
                reason: "non-canonical V2 quote intent encoding",
            });
        }
        Ok(value)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(BAT_V2_QUOTE_INTENT_DIGEST_DOMAIN);
        let encoded = Zeroizing::new(self.encode()?);
        hasher.update(encoded.as_slice());
        Ok(hasher.finalize().into())
    }

    pub fn derived_horizons(
        &self,
        invoice_created_at: u64,
    ) -> Result<Bolt11QuoteHorizonsV1, ServiceProtocolError> {
        self.validate()?;
        let invoice_expires_at = invoice_created_at
            .checked_add(u64::from(self.invoice_expiry_seconds))
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "Bolt11BatV2QuoteIntentV2.invoice_expiry_seconds",
                reason: "invoice expiry overflows Unix time",
            })?;
        let claim_deadline = invoice_expires_at
            .checked_add(u64::from(self.claim_window_seconds))
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "Bolt11BatV2QuoteIntentV2.claim_window_seconds",
                reason: "claim deadline overflows Unix time",
            })?;
        let credential_not_after = claim_deadline
            .checked_add(u64::from(self.minimum_credential_validity_seconds))
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "Bolt11BatV2QuoteIntentV2.minimum_credential_validity_seconds",
                reason: "credential horizon overflows Unix time",
            })?;
        Ok(Bolt11QuoteHorizonsV1 {
            invoice_expires_at,
            claim_deadline,
            credential_not_after,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.issuer_id.iter().all(|byte| *byte == 0)
            || self.class_id.iter().all(|byte| *byte == 0)
            || self.class_digest.iter().all(|byte| *byte == 0)
            || self.class_key_epoch == 0
            || self.bat_key_id.iter().all(|byte| *byte == 0)
            || self.minimum_quote_key_epoch == 0
            || self.quote_delegation_digest.iter().all(|byte| *byte == 0)
            || self.idempotency_key.iter().all(|byte| *byte == 0)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11BatV2QuoteIntentV2.binding",
                reason: "issuer, class, key epochs/digests, and idempotency must be non-zero",
            });
        }
        if !is_valid_compressed_point(&self.expected_payee_pubkey) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11BatV2QuoteIntentV2.expected_payee_pubkey",
                reason: "must be a compressed secp256k1 public key",
            });
        }
        crate::quote::validate_xonly_pubkey(&self.claim_pubkey_xonly)?;
        if self.exact_amount_msat == 0 || self.exact_amount_msat > MAX_BITCOIN_MSAT_V1 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11BatV2QuoteIntentV2.exact_amount_msat",
                reason: "must be non-zero and within the Bitcoin supply bound",
            });
        }
        if self.credential_count == 0 || self.credential_count > MAX_CREDENTIALS_PER_ACQUISITION_V1
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11BatV2QuoteIntentV2.credential_count",
                reason: "must be non-zero and within the acquisition bound",
            });
        }
        validate_horizons(
            self.invoice_expiry_seconds,
            self.claim_window_seconds,
            self.minimum_credential_validity_seconds,
            "Bolt11BatV2QuoteIntentV2.horizons",
        )
    }

    pub(crate) fn verify_exact_class_binding(
        &self,
        class: &BatAcceptanceClassV2,
        invoice_created_at: u64,
    ) -> Result<(), ServiceProtocolError> {
        class.verify_for(&self.issuer_id, &self.class_id)?;
        let horizons = self.derived_horizons(invoice_created_at)?;
        if self.class_digest != class.class_digest()?
            || self.class_key_epoch != class.key_epoch
            || self.bat_key_id != class.bat_key_id()
            || self.exact_amount_msat != class.common_terms.price_msat
            || self.credential_count != class.common_terms.credential_count
            || self.invoice_expiry_seconds != class.common_terms.invoice_expiry_seconds
            || self.claim_window_seconds != class.common_terms.claim_window_seconds
            || self.minimum_credential_validity_seconds
                != class.common_terms.minimum_credential_validity_seconds
            || invoice_created_at < class.key_not_before
            || horizons.credential_not_after > class.key_not_after
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11BatV2QuoteIntentV2.class_binding",
                reason: "intent terms, key epoch, or actual quote horizon differ from the class",
            });
        }
        Ok(())
    }
}

/// Typestate proving the class signature/terms and quote-key rollback stream
/// were checked without inventing a provider-bound credential binding.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedBolt11BatV2QuoteIntentV2<'a> {
    intent: &'a Bolt11BatV2QuoteIntentV2,
    class: &'a BatAcceptanceClassV2,
    delegation: &'a Bolt11QuoteKeyDelegationV1,
    advanced_guard: Bolt11QuoteKeyRollbackGuardV1,
}

impl<'a> VerifiedBolt11BatV2QuoteIntentV2<'a> {
    pub const fn intent(&self) -> &'a Bolt11BatV2QuoteIntentV2 {
        self.intent
    }

    pub const fn class(&self) -> &'a BatAcceptanceClassV2 {
        self.class
    }

    pub const fn delegation(&self) -> &'a Bolt11QuoteKeyDelegationV1 {
        self.delegation
    }

    pub const fn advanced_guard(&self) -> Bolt11QuoteKeyRollbackGuardV1 {
        self.advanced_guard
    }
}

/// Typestate proving one signed BOLT11 snapshot is bound to an exact V2 class
/// intent and class artifact.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedBolt11BatV2QuoteV2<'a> {
    pub(crate) quote: &'a Bolt11QuoteV1,
    pub(crate) intent: &'a Bolt11BatV2QuoteIntentV2,
    pub(crate) class: &'a BatAcceptanceClassV2,
    pub(crate) request_digest: [u8; 32],
}

impl<'a> VerifiedBolt11BatV2QuoteV2<'a> {
    pub const fn quote(&self) -> &'a Bolt11QuoteV1 {
        self.quote
    }

    pub const fn intent(&self) -> &'a Bolt11BatV2QuoteIntentV2 {
        self.intent
    }

    pub const fn class(&self) -> &'a BatAcceptanceClassV2 {
        self.class
    }

    /// Authoritative digest of the original client intent. For a persisted
    /// privacy-safe replay image this intentionally differs from recomputing
    /// the digest after its raw idempotency key was replaced.
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    pub fn ensure_payable_at(&self, now_unix: u64) -> Result<(), ServiceProtocolError> {
        crate::quote::ensure_quote_payable_at(self.quote, now_unix)
    }

    pub fn ensure_claim_submission_at(&self, now_unix: u64) -> Result<(), ServiceProtocolError> {
        crate::quote::ensure_quote_claim_submission_at(self.quote, now_unix)
    }
}

/// Durable BAT V2 quote facts needed to reconstruct a verified snapshot after
/// restart without retaining the client's raw creation-idempotency key.
/// `original_request_digest` remains the digest signed into the quote, while
/// `replay_intent` is the canonical privacy-safe image persisted by the store.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PersistedBolt11BatV2QuoteExpectationV2<'a> {
    pub original_request_digest: &'a [u8; 32],
    pub replay_intent: &'a Bolt11BatV2QuoteIntentV2,
    pub class: &'a BatAcceptanceClassV2,
    pub quote_id: &'a [u8; 32],
    pub invoice: &'a str,
    pub invoice_created_at: u64,
    pub invoice_expires_at: u64,
    pub claim_deadline: u64,
    pub credential_not_after: u64,
}

impl fmt::Debug for PersistedBolt11BatV2QuoteExpectationV2<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedBolt11BatV2QuoteExpectationV2")
            .field("class_key_epoch", &self.replay_intent.class_key_epoch)
            .field("payment_artifacts", &"[REDACTED]")
            .finish()
    }
}

/// Exact ordered blinded messages for one BAT V2 quote claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatV2IssuanceRequestV2 {
    pub issuer_id: [u8; 32],
    pub quote_id: [u8; 32],
    pub quote_request_digest: [u8; 32],
    pub class_id: [u8; 32],
    pub class_digest: [u8; 32],
    pub class_key_epoch: u64,
    pub bat_key_id: [u8; 32],
    pub items: Vec<BitcoinPirCashuBatIssuanceRequestItemV1>,
}

impl BatV2IssuanceRequestV2 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Zeroizing::new(Vec::with_capacity(256 + self.items.len() * 33));
        out.extend_from_slice(BAT_V2_ISSUANCE_REQUEST_CODEC_MAGIC);
        out.push(BAT_V2_ISSUANCE_REQUEST_WIRE_VERSION);
        encode_issuance_binding(
            &mut out,
            &self.issuer_id,
            &self.quote_id,
            &self.quote_request_digest,
            &self.class_id,
            &self.class_digest,
            self.class_key_epoch,
            &self.bat_key_id,
        );
        out.extend_from_slice(&(self.items.len() as u16).to_le_bytes());
        for item in &self.items {
            out.extend_from_slice(&item.blinded_message);
        }
        check_len(
            out.len(),
            MAX_BAT_V2_ISSUANCE_REQUEST_LEN,
            "BatV2IssuanceRequestV2",
        )?;
        Ok(std::mem::take(&mut *out))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        check_len(
            bytes.len(),
            MAX_BAT_V2_ISSUANCE_REQUEST_LEN,
            "BatV2IssuanceRequestV2",
        )?;
        let mut decoder = Decoder::new(bytes);
        expect_magic(
            decoder.fixed("BatV2IssuanceRequestV2.magic")?,
            BAT_V2_ISSUANCE_REQUEST_CODEC_MAGIC,
            "BatV2IssuanceRequestV2.magic",
        )?;
        expect_v2(
            decoder.u8("BatV2IssuanceRequestV2.version")?,
            "BatV2IssuanceRequestV2",
        )?;
        let issuer_id = decoder.fixed("BatV2IssuanceRequestV2.issuer_id")?;
        let quote_id = decoder.fixed("BatV2IssuanceRequestV2.quote_id")?;
        let quote_request_digest = decoder.fixed("BatV2IssuanceRequestV2.quote_request_digest")?;
        let class_id = decoder.fixed("BatV2IssuanceRequestV2.class_id")?;
        let class_digest = decoder.fixed("BatV2IssuanceRequestV2.class_digest")?;
        let class_key_epoch = decoder.u64("BatV2IssuanceRequestV2.class_key_epoch")?;
        let bat_key_id = decoder.fixed("BatV2IssuanceRequestV2.bat_key_id")?;
        let count = usize::from(decoder.u16("BatV2IssuanceRequestV2.item_count")?);
        validate_item_count(count, "BatV2IssuanceRequestV2.items")?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(BitcoinPirCashuBatIssuanceRequestItemV1 {
                blinded_message: decoder.fixed("BatV2IssuanceRequestV2.items.blinded_message")?,
            });
        }
        decoder.finish()?;
        let value = Self {
            issuer_id,
            quote_id,
            quote_request_digest,
            class_id,
            class_digest,
            class_key_epoch,
            bat_key_id,
            items,
        };
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatV2IssuanceRequestV2",
                reason: "non-canonical V2 issuance request encoding",
            });
        }
        Ok(value)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(BAT_V2_ISSUANCE_REQUEST_DIGEST_DOMAIN);
        let encoded = Zeroizing::new(self.encode()?);
        hasher.update(encoded.as_slice());
        Ok(hasher.finalize().into())
    }

    pub fn verify_for_verified_quote(
        &self,
        claim: &Bolt11QuoteClaimV1,
        verified_quote: &VerifiedBolt11BatV2QuoteV2<'_>,
        now_unix: u64,
    ) -> Result<UnverifiedBip340ClaimV1, ServiceProtocolError> {
        self.verify_terms_for_quote(verified_quote)?;
        if claim.credential_request_digest != self.request_digest()? {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteClaimV1.credential_request_digest",
                reason: "claim does not commit to the exact V2 issuance request",
            });
        }
        claim.unverified_bip340_input_for_bat_v2(verified_quote, now_unix)
    }

    pub(crate) fn verify_terms_for_quote(
        &self,
        verified_quote: &VerifiedBolt11BatV2QuoteV2<'_>,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        let quote = verified_quote.quote();
        let intent = verified_quote.intent();
        if self.issuer_id != intent.issuer_id
            || self.quote_id != quote.quote_id
            || self.quote_request_digest != quote.request_digest
            || self.class_id != intent.class_id
            || self.class_digest != intent.class_digest
            || self.class_key_epoch != intent.class_key_epoch
            || self.bat_key_id != intent.bat_key_id
            || self.items.len() != intent.credential_count as usize
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatV2IssuanceRequestV2.quote_binding",
                reason: "request differs from the exact class-bound quote",
            });
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_issuance_binding(
            &self.issuer_id,
            &self.quote_id,
            &self.quote_request_digest,
            &self.class_id,
            &self.class_digest,
            self.class_key_epoch,
            &self.bat_key_id,
            "BatV2IssuanceRequestV2.binding",
        )?;
        validate_item_count(self.items.len(), "BatV2IssuanceRequestV2.items")?;
        let mut messages = HashSet::with_capacity(self.items.len());
        if self.items.iter().all(|item| {
            is_valid_compressed_point(&item.blinded_message)
                && messages.insert(item.blinded_message)
        }) {
            Ok(())
        } else {
            Err(ServiceProtocolError::InvalidValue {
                field: "BatV2IssuanceRequestV2.items",
                reason: "blinded messages must be valid, unique compressed points",
            })
        }
    }
}

/// Exact ordered blind signatures and NUT-12 transcripts for BAT V2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatV2IssuanceResponseV2 {
    pub issuer_id: [u8; 32],
    pub quote_id: [u8; 32],
    pub quote_request_digest: [u8; 32],
    pub credential_request_digest: [u8; 32],
    pub class_id: [u8; 32],
    pub class_digest: [u8; 32],
    pub class_key_epoch: u64,
    pub bat_key_id: [u8; 32],
    pub items: Vec<BitcoinPirCashuBatIssuanceResponseItemV1>,
}

impl BatV2IssuanceResponseV2 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Zeroizing::new(Vec::with_capacity(288 + self.items.len() * 130));
        out.extend_from_slice(BAT_V2_ISSUANCE_RESPONSE_CODEC_MAGIC);
        out.push(BAT_V2_ISSUANCE_RESPONSE_WIRE_VERSION);
        encode_issuance_binding(
            &mut out,
            &self.issuer_id,
            &self.quote_id,
            &self.quote_request_digest,
            &self.class_id,
            &self.class_digest,
            self.class_key_epoch,
            &self.bat_key_id,
        );
        out.extend_from_slice(&self.credential_request_digest);
        out.extend_from_slice(&(self.items.len() as u16).to_le_bytes());
        for item in &self.items {
            out.extend_from_slice(&item.blinded_message);
            out.extend_from_slice(&item.blinded_signature);
            out.extend_from_slice(&item.dleq_e);
            out.extend_from_slice(&item.dleq_s);
        }
        check_len(
            out.len(),
            MAX_BAT_V2_ISSUANCE_RESPONSE_LEN,
            "BatV2IssuanceResponseV2",
        )?;
        Ok(std::mem::take(&mut *out))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        check_len(
            bytes.len(),
            MAX_BAT_V2_ISSUANCE_RESPONSE_LEN,
            "BatV2IssuanceResponseV2",
        )?;
        let mut decoder = Decoder::new(bytes);
        expect_magic(
            decoder.fixed("BatV2IssuanceResponseV2.magic")?,
            BAT_V2_ISSUANCE_RESPONSE_CODEC_MAGIC,
            "BatV2IssuanceResponseV2.magic",
        )?;
        expect_v2(
            decoder.u8("BatV2IssuanceResponseV2.version")?,
            "BatV2IssuanceResponseV2",
        )?;
        let issuer_id = decoder.fixed("BatV2IssuanceResponseV2.issuer_id")?;
        let quote_id = decoder.fixed("BatV2IssuanceResponseV2.quote_id")?;
        let quote_request_digest = decoder.fixed("BatV2IssuanceResponseV2.quote_request_digest")?;
        let class_id = decoder.fixed("BatV2IssuanceResponseV2.class_id")?;
        let class_digest = decoder.fixed("BatV2IssuanceResponseV2.class_digest")?;
        let class_key_epoch = decoder.u64("BatV2IssuanceResponseV2.class_key_epoch")?;
        let bat_key_id = decoder.fixed("BatV2IssuanceResponseV2.bat_key_id")?;
        let credential_request_digest =
            decoder.fixed("BatV2IssuanceResponseV2.credential_request_digest")?;
        let count = usize::from(decoder.u16("BatV2IssuanceResponseV2.item_count")?);
        validate_item_count(count, "BatV2IssuanceResponseV2.items")?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(BitcoinPirCashuBatIssuanceResponseItemV1 {
                blinded_message: decoder.fixed("BatV2IssuanceResponseV2.items.blinded_message")?,
                blinded_signature: decoder
                    .fixed("BatV2IssuanceResponseV2.items.blinded_signature")?,
                dleq_e: decoder.fixed("BatV2IssuanceResponseV2.items.dleq_e")?,
                dleq_s: decoder.fixed("BatV2IssuanceResponseV2.items.dleq_s")?,
            });
        }
        decoder.finish()?;
        let value = Self {
            issuer_id,
            quote_id,
            quote_request_digest,
            credential_request_digest,
            class_id,
            class_digest,
            class_key_epoch,
            bat_key_id,
            items,
        };
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatV2IssuanceResponseV2",
                reason: "non-canonical V2 issuance response encoding",
            });
        }
        Ok(value)
    }

    pub fn verify_for_verified_quote(
        &self,
        request: &BatV2IssuanceRequestV2,
        verified_quote: &VerifiedBolt11BatV2QuoteV2<'_>,
    ) -> Result<CheckedBatV2IssuanceResponseV2, ServiceProtocolError> {
        self.validate()?;
        request.verify_terms_for_quote(verified_quote)?;
        let intent = verified_quote.intent();
        let quote = verified_quote.quote();
        if self.issuer_id != intent.issuer_id
            || self.quote_id != quote.quote_id
            || self.quote_request_digest != quote.request_digest
            || self.credential_request_digest != request.request_digest()?
            || self.class_id != request.class_id
            || self.class_digest != request.class_digest
            || self.class_key_epoch != request.class_key_epoch
            || self.bat_key_id != request.bat_key_id
            || self.items.len() != request.items.len()
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatV2IssuanceResponseV2.binding",
                reason: "response differs from the exact class-bound quote or request",
            });
        }
        let issuer_public_key = verified_quote.class().bat_verification_key;
        let mut unverified_dleq = Vec::with_capacity(self.items.len());
        for (request_item, response_item) in request.items.iter().zip(&self.items) {
            if request_item.blinded_message != response_item.blinded_message {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "BatV2IssuanceResponseV2.items.order",
                    reason: "response must echo every blinded message in exact request order",
                });
            }
            unverified_dleq.push(UnverifiedCashuBatDleqTupleV1 {
                issuer_public_key,
                blinded_message: response_item.blinded_message,
                blinded_signature: response_item.blinded_signature,
                dleq_e: response_item.dleq_e,
                dleq_s: response_item.dleq_s,
            });
        }
        Ok(CheckedBatV2IssuanceResponseV2 { unverified_dleq })
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_issuance_binding(
            &self.issuer_id,
            &self.quote_id,
            &self.quote_request_digest,
            &self.class_id,
            &self.class_digest,
            self.class_key_epoch,
            &self.bat_key_id,
            "BatV2IssuanceResponseV2.binding",
        )?;
        if self.credential_request_digest.iter().all(|byte| *byte == 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatV2IssuanceResponseV2.credential_request_digest",
                reason: "must bind a non-zero V2 issuance request digest",
            });
        }
        validate_item_count(self.items.len(), "BatV2IssuanceResponseV2.items")?;
        let mut messages = HashSet::with_capacity(self.items.len());
        let mut signatures = HashSet::with_capacity(self.items.len());
        if self.items.iter().all(|item| {
            is_valid_compressed_point(&item.blinded_message)
                && is_valid_compressed_point(&item.blinded_signature)
                && is_valid_nonzero_scalar(&item.dleq_e)
                && is_valid_nonzero_scalar(&item.dleq_s)
                && messages.insert(item.blinded_message)
                && signatures.insert(item.blinded_signature)
        }) {
            Ok(())
        } else {
            Err(ServiceProtocolError::InvalidValue {
                field: "BatV2IssuanceResponseV2.items",
                reason: "BAT points must be valid/unique and DLEQ scalars canonical/non-zero",
            })
        }
    }
}

/// Structurally checked NUT-12 tuples. The wallet still has to perform the
/// actual DLEQ equations before unblinding or storing a BAT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedBatV2IssuanceResponseV2 {
    unverified_dleq: Vec<UnverifiedCashuBatDleqTupleV1>,
}

impl CheckedBatV2IssuanceResponseV2 {
    pub fn unverified_dleq(&self) -> &[UnverifiedCashuBatDleqTupleV1] {
        &self.unverified_dleq
    }

    pub fn into_unverified_dleq(self) -> Vec<UnverifiedCashuBatDleqTupleV1> {
        self.unverified_dleq
    }
}

/// Canonical binary body for the V2 quote claim endpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct Bolt11BatV2ClaimEnvelopeV2 {
    pub quote_intent: Bolt11BatV2QuoteIntentV2,
    pub claim: Bolt11QuoteClaimV1,
    pub credential_request: BatV2IssuanceRequestV2,
}

impl fmt::Debug for Bolt11BatV2ClaimEnvelopeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bolt11BatV2ClaimEnvelopeV2")
            .field("claim_envelope", &"[REDACTED]")
            .finish()
    }
}

impl Bolt11BatV2ClaimEnvelopeV2 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate_binding()?;
        let intent = Zeroizing::new(self.quote_intent.encode()?);
        let claim = Zeroizing::new(self.claim.encode()?);
        let request = Zeroizing::new(self.credential_request.encode()?);
        let mut out = Zeroizing::new(Vec::with_capacity(
            BAT_V2_CLAIM_ENVELOPE_CODEC_MAGIC.len()
                + 1
                + 12
                + intent.len()
                + claim.len()
                + request.len(),
        ));
        out.extend_from_slice(BAT_V2_CLAIM_ENVELOPE_CODEC_MAGIC);
        out.push(BAT_V2_CLAIM_ENVELOPE_WIRE_VERSION);
        put_bytes_u32(&mut out, &intent);
        put_bytes_u32(&mut out, &claim);
        put_bytes_u32(&mut out, &request);
        check_len(
            out.len(),
            MAX_BAT_V2_CLAIM_ENVELOPE_LEN,
            "Bolt11BatV2ClaimEnvelopeV2",
        )?;
        Ok(std::mem::take(&mut *out))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        check_len(
            bytes.len(),
            MAX_BAT_V2_CLAIM_ENVELOPE_LEN,
            "Bolt11BatV2ClaimEnvelopeV2",
        )?;
        let mut decoder = Decoder::new(bytes);
        expect_magic(
            decoder.fixed("Bolt11BatV2ClaimEnvelopeV2.magic")?,
            BAT_V2_CLAIM_ENVELOPE_CODEC_MAGIC,
            "Bolt11BatV2ClaimEnvelopeV2.magic",
        )?;
        expect_v2(
            decoder.u8("Bolt11BatV2ClaimEnvelopeV2.version")?,
            "Bolt11BatV2ClaimEnvelopeV2",
        )?;
        let intent = Zeroizing::new(decoder.bytes_u32(
            "Bolt11BatV2ClaimEnvelopeV2.quote_intent",
            MAX_BAT_V2_QUOTE_INTENT_LEN,
        )?);
        let claim = Zeroizing::new(decoder.bytes_u32(
            "Bolt11BatV2ClaimEnvelopeV2.claim",
            MAX_BOLT11_QUOTE_CLAIM_LEN,
        )?);
        let request = Zeroizing::new(decoder.bytes_u32(
            "Bolt11BatV2ClaimEnvelopeV2.credential_request",
            MAX_BAT_V2_ISSUANCE_REQUEST_LEN,
        )?);
        decoder.finish()?;
        let value = Self {
            quote_intent: Bolt11BatV2QuoteIntentV2::decode(&intent)?,
            claim: Bolt11QuoteClaimV1::decode(&claim)?,
            credential_request: BatV2IssuanceRequestV2::decode(&request)?,
        };
        value.validate_binding()?;
        if value.encode()?.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11BatV2ClaimEnvelopeV2",
                reason: "nested V2 claim object is not canonical",
            });
        }
        Ok(value)
    }

    fn validate_binding(&self) -> Result<(), ServiceProtocolError> {
        let intent_digest = self.quote_intent.request_digest()?;
        let request_digest = self.credential_request.request_digest()?;
        if self.claim.issuer_id != self.quote_intent.issuer_id
            || self.claim.quote_request_digest != intent_digest
            || self.claim.credential_request_digest != request_digest
            || self.credential_request.issuer_id != self.quote_intent.issuer_id
            || self.credential_request.quote_id != self.claim.quote_id
            || self.credential_request.quote_request_digest != intent_digest
            || self.credential_request.class_id != self.quote_intent.class_id
            || self.credential_request.class_digest != self.quote_intent.class_digest
            || self.credential_request.class_key_epoch != self.quote_intent.class_key_epoch
            || self.credential_request.bat_key_id != self.quote_intent.bat_key_id
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11BatV2ClaimEnvelopeV2.binding",
                reason: "claim, quote intent, and V2 issuance request differ",
            });
        }
        Ok(())
    }
}

fn validate_verified_member_for_class(
    verified_member: &VerifiedBatAcceptanceMemberV2,
    class: &BatAcceptanceClassV2,
    now_unix: u64,
) -> Result<(), ServiceProtocolError> {
    class.verify_for(&verified_member.issuer_id, &verified_member.class_id)?;
    if !verified_member
        .common_terms
        .commercially_equivalent_to(&class.common_terms)
        || class
            .members
            .binary_search(&verified_member.member)
            .is_err()
        || class.key_not_before > verified_member.policy_issued_at
        || class.key_not_after > verified_member.redemption_deadline
        || now_unix < verified_member.policy_issued_at
        || now_unix > verified_member.policy_expires_at
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "VerifiedBatAcceptanceMemberV2.class_binding",
            reason: "selected current policy member differs from the exact signed class",
        });
    }
    Ok(())
}

fn validate_horizons(
    invoice_expiry_seconds: u32,
    claim_window_seconds: u32,
    minimum_credential_validity_seconds: u32,
    field: &'static str,
) -> Result<(), ServiceProtocolError> {
    if invoice_expiry_seconds == 0
        || invoice_expiry_seconds > MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1
        || claim_window_seconds == 0
        || claim_window_seconds > MAX_BOLT11_CLAIM_WINDOW_SECONDS_V1
        || minimum_credential_validity_seconds == 0
        || minimum_credential_validity_seconds > MAX_BOLT11_CREDENTIAL_VALIDITY_SECONDS_V1
    {
        Err(ServiceProtocolError::InvalidValue {
            field,
            reason: "invoice, claim, and credential horizons must be non-zero and bounded",
        })
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_issuance_binding(
    out: &mut Vec<u8>,
    issuer_id: &[u8; 32],
    quote_id: &[u8; 32],
    quote_request_digest: &[u8; 32],
    class_id: &[u8; 32],
    class_digest: &[u8; 32],
    class_key_epoch: u64,
    bat_key_id: &[u8; 32],
) {
    out.extend_from_slice(issuer_id);
    out.extend_from_slice(quote_id);
    out.extend_from_slice(quote_request_digest);
    out.extend_from_slice(class_id);
    out.extend_from_slice(class_digest);
    out.extend_from_slice(&class_key_epoch.to_le_bytes());
    out.extend_from_slice(bat_key_id);
}

#[allow(clippy::too_many_arguments)]
fn validate_issuance_binding(
    issuer_id: &[u8; 32],
    quote_id: &[u8; 32],
    quote_request_digest: &[u8; 32],
    class_id: &[u8; 32],
    class_digest: &[u8; 32],
    class_key_epoch: u64,
    bat_key_id: &[u8; 32],
    field: &'static str,
) -> Result<(), ServiceProtocolError> {
    if issuer_id.iter().all(|byte| *byte == 0)
        || quote_id.iter().all(|byte| *byte == 0)
        || quote_request_digest.iter().all(|byte| *byte == 0)
        || class_id.iter().all(|byte| *byte == 0)
        || class_digest.iter().all(|byte| *byte == 0)
        || class_key_epoch == 0
        || bat_key_id.iter().all(|byte| *byte == 0)
    {
        Err(ServiceProtocolError::InvalidValue {
            field,
            reason: "issuer, quote, class, epoch, and digests must be non-zero",
        })
    } else {
        Ok(())
    }
}

fn validate_item_count(count: usize, field: &'static str) -> Result<(), ServiceProtocolError> {
    if count == 0
        || u32::try_from(count)
            .map(|count| count > MAX_CREDENTIALS_PER_ACQUISITION_V1)
            .unwrap_or(true)
    {
        Err(ServiceProtocolError::InvalidValue {
            field,
            reason: "BAT V2 item count must be non-zero and bounded",
        })
    } else {
        Ok(())
    }
}

fn is_valid_nonzero_scalar(bytes: &[u8; 32]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
        && Option::<Scalar>::from(Scalar::from_repr((*bytes).into())).is_some()
}

fn check_len(len: usize, max: usize, field: &'static str) -> Result<(), ServiceProtocolError> {
    if len > max {
        Err(ServiceProtocolError::FieldTooLong { field, len, max })
    } else {
        Ok(())
    }
}

fn expect_v2(version: u8, kind: &'static str) -> Result<(), ServiceProtocolError> {
    if version == 2 {
        Ok(())
    } else {
        Err(ServiceProtocolError::UnknownVersion { kind, version })
    }
}

fn expect_magic(
    actual: [u8; 8],
    expected: &[u8; 8],
    field: &'static str,
) -> Result<(), ServiceProtocolError> {
    if &actual == expected {
        Ok(())
    } else {
        Err(ServiceProtocolError::InvalidValue {
            field,
            reason: "wrong BAT V2 acquisition codec domain",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthPaddingClassV1, BackendId, BatAcceptanceMemberV2, BatAcceptanceTermsV2,
        Bolt11QuoteStatusRequestV1, Bolt11QuoteStatusV1, DatasetBindingV1, DeploymentStatus,
        EntitlementLimitsV1, ParsedBolt11InvoiceV1, PrivacyLeakageV1, WorkloadId,
        BOLT11_QUOTE_INTENT_DIGEST_DOMAIN,
    };
    use ed25519_dalek::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::ProjectivePoint;

    const NOW: u64 = 1_000;
    const INVOICE: &str = "lnbc20n1qqqqqqqq";

    struct Fixture {
        quote_key: SigningKey,
        class: BatAcceptanceClassV2,
        first_member: VerifiedBatAcceptanceMemberV2,
        second_member: VerifiedBatAcceptanceMemberV2,
        delegation: Bolt11QuoteKeyDelegationV1,
        initial_guard: Bolt11QuoteKeyRollbackGuardV1,
        parsed_invoice: ParsedBolt11InvoiceV1,
    }

    fn point(multiplier: u64) -> [u8; 33] {
        (ProjectivePoint::GENERATOR * Scalar::from(multiplier))
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn xonly_point(multiplier: u64) -> [u8; 32] {
        point(multiplier)[1..].try_into().unwrap()
    }

    fn scalar(multiplier: u64) -> [u8; 32] {
        Scalar::from(multiplier).to_bytes().into()
    }

    fn common_terms() -> BatAcceptanceTermsV2 {
        BatAcceptanceTermsV2 {
            auth_padding_class: AuthPaddingClassV1::Class16KiB,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 2,
            limits: EntitlementLimitsV1 {
                max_logical_inputs: 4,
                max_frames: 200,
                max_request_bytes: 1_000_000,
                max_response_bytes: 2_000_000,
                max_wall_time_ms: 60_000,
                max_concurrent_sockets: 1,
                max_hint_groups: 0,
                max_work_units: 9_000,
            },
            priority_class: 1,
            deployment_status: DeploymentStatus::Stable,
            price_msat: 2_000,
            issuer_endpoint: "https://issuer.invalid".into(),
            invoice_expiry_seconds: 60,
            claim_window_seconds: 120,
            minimum_credential_validity_seconds: 300,
            retired_policy_grace_seconds: 480,
            credential_count: 2,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                    | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .unwrap(),
        }
    }

    fn fixture() -> Fixture {
        let issuer_key = SigningKey::from_bytes(&[8; 32]);
        let quote_key = SigningKey::from_bytes(&[9; 32]);
        let members = vec![
            BatAcceptanceMemberV2 {
                provider_id: [2; 32],
                policy_digest: [3; 32],
                scope_id: [4; 32],
                offer_id: 5,
            },
            BatAcceptanceMemberV2 {
                provider_id: [6; 32],
                policy_digest: [7; 32],
                scope_id: [8; 32],
                offer_id: 9,
            },
        ];
        let class = BatAcceptanceClassV2::sign(
            [0x42; 32],
            3,
            900,
            10_000,
            point(11),
            common_terms(),
            members.clone(),
            &issuer_key,
        )
        .unwrap();
        let member = |member: BatAcceptanceMemberV2| VerifiedBatAcceptanceMemberV2 {
            issuer_id: class.issuer_id,
            class_id: class.class_id,
            member,
            common_terms: class.common_terms.clone(),
            policy_issued_at: 900,
            policy_expires_at: 10_000,
            redemption_deadline: 10_000,
        };
        let first_member = member(members[0].clone());
        let second_member = member(members[1].clone());
        let payee = point(3);
        let delegation = Bolt11QuoteKeyDelegationV1::sign(
            LightningNetworkV1::Bitcoin,
            payee,
            4,
            900,
            10_000,
            quote_key.verifying_key().to_bytes(),
            &issuer_key,
        )
        .unwrap();
        let initial_guard = Bolt11QuoteKeyRollbackGuardV1::initial(
            class.issuer_id,
            LightningNetworkV1::Bitcoin,
            payee,
        )
        .unwrap();
        let parsed_invoice = ParsedBolt11InvoiceV1::from_signature_verified_invoice(
            INVOICE,
            LightningNetworkV1::Bitcoin,
            payee,
            class.common_terms.price_msat,
            NOW,
            class.common_terms.invoice_expiry_seconds,
        )
        .unwrap();
        Fixture {
            quote_key,
            class,
            first_member,
            second_member,
            delegation,
            initial_guard,
            parsed_invoice,
        }
    }

    fn intent_for(
        fixture: &Fixture,
        member: &VerifiedBatAcceptanceMemberV2,
    ) -> Bolt11BatV2QuoteIntentV2 {
        Bolt11BatV2QuoteIntentV2::from_verified_class_member_guarded(
            member,
            &fixture.class,
            &fixture.delegation,
            &fixture.initial_guard,
            NOW,
            xonly_point(5),
            [0x51; 32],
        )
        .unwrap()
        .0
    }

    fn settled_quote(fixture: &Fixture) -> (Bolt11BatV2QuoteIntentV2, Bolt11QuoteV1) {
        let intent = intent_for(fixture, &fixture.first_member);
        let verified_intent = intent
            .verify_for_class_member_guarded(
                &fixture.first_member,
                &fixture.class,
                &fixture.delegation,
                &fixture.initial_guard,
                NOW,
            )
            .unwrap();
        let open = Bolt11QuoteV1::sign_for_verified_bat_v2_intent(
            &verified_intent,
            [0x52; 32],
            INVOICE.into(),
            &fixture.parsed_invoice,
            Bolt11QuoteStatusV1::InvoiceOpen,
            NOW,
            &fixture.quote_key,
        )
        .unwrap();
        let verified_open = open
            .verify_bat_v2_for_payment(
                &intent,
                &fixture.class,
                &fixture.delegation,
                &fixture.parsed_invoice,
                NOW + 1,
            )
            .unwrap();
        let settled = Bolt11QuoteV1::with_status_from_verified_bat_v2_snapshot(
            &verified_open,
            Bolt11QuoteStatusV1::PaymentSettled,
            NOW + 1,
            &fixture.delegation,
            &fixture.quote_key,
        )
        .unwrap();
        (intent, settled)
    }

    fn issuance_request(
        intent: &Bolt11BatV2QuoteIntentV2,
        quote: &Bolt11QuoteV1,
    ) -> BatV2IssuanceRequestV2 {
        BatV2IssuanceRequestV2 {
            issuer_id: intent.issuer_id,
            quote_id: quote.quote_id,
            quote_request_digest: quote.request_digest,
            class_id: intent.class_id,
            class_digest: intent.class_digest,
            class_key_epoch: intent.class_key_epoch,
            bat_key_id: intent.bat_key_id,
            items: vec![
                BitcoinPirCashuBatIssuanceRequestItemV1 {
                    blinded_message: point(13),
                },
                BitcoinPirCashuBatIssuanceRequestItemV1 {
                    blinded_message: point(14),
                },
            ],
        }
    }

    #[test]
    fn bat_v2_acquisition_intent_is_class_bound_and_provider_independent() {
        let fixture = fixture();
        let first = intent_for(&fixture, &fixture.first_member);
        let second = intent_for(&fixture, &fixture.second_member);
        assert_eq!(first, second);
        assert_eq!(
            first.request_digest().unwrap(),
            second.request_digest().unwrap()
        );

        let encoded = first.encode().unwrap();
        assert_eq!(&encoded[..8], BAT_V2_QUOTE_INTENT_CODEC_MAGIC);
        assert_eq!(encoded[8], BAT_V2_QUOTE_INTENT_WIRE_VERSION);
        assert_ne!(
            BAT_V2_QUOTE_INTENT_DIGEST_DOMAIN,
            BOLT11_QUOTE_INTENT_DIGEST_DOMAIN
        );
        assert!(!encoded
            .windows(32)
            .any(|window| window == fixture.first_member.member.provider_id));
        assert!(!encoded
            .windows(32)
            .any(|window| window == fixture.second_member.member.provider_id));
        assert_eq!(Bolt11BatV2QuoteIntentV2::decode(&encoded).unwrap(), first);

        first
            .verify_for_class_member_guarded(
                &fixture.second_member,
                &fixture.class,
                &fixture.delegation,
                &fixture.initial_guard,
                NOW,
            )
            .unwrap();
        let mut wrong_class = first.clone();
        wrong_class.class_digest[0] ^= 1;
        assert!(wrong_class
            .verify_for_class_guarded(
                &fixture.class,
                &fixture.delegation,
                &fixture.initial_guard,
                NOW,
            )
            .is_err());
    }

    #[test]
    fn bat_v2_acquisition_quote_claim_and_status_bind_v2_digest() {
        let fixture = fixture();
        let (intent, settled) = settled_quote(&fixture);
        let verified_settled = settled
            .verify_bat_v2_for_claim_submission(
                &intent,
                &fixture.class,
                &fixture.delegation,
                &fixture.parsed_invoice,
                NOW + 2,
            )
            .unwrap();
        let request = issuance_request(&intent, &settled);
        let claim = Bolt11QuoteClaimV1 {
            issuer_id: intent.issuer_id,
            quote_id: settled.quote_id,
            quote_request_digest: intent.request_digest().unwrap(),
            credential_request_digest: request.request_digest().unwrap(),
            claim_pubkey_xonly: intent.claim_pubkey_xonly,
            idempotency_key: [0x53; 32],
            signature: [0x54; 64],
        };
        let unverified = request
            .verify_for_verified_quote(&claim, &verified_settled, NOW + 2)
            .unwrap();
        assert_eq!(unverified.claim_pubkey_xonly, intent.claim_pubkey_xonly);
        assert_eq!(
            unverified.message_digest,
            claim.bip340_signing_digest().unwrap()
        );

        let status = Bolt11QuoteStatusRequestV1 {
            issuer_id: intent.issuer_id,
            quote_id: settled.quote_id,
            quote_request_digest: intent.request_digest().unwrap(),
            claim_pubkey_xonly: intent.claim_pubkey_xonly,
            requested_at: NOW + 2,
            request_nonce: [0x55; 32],
            signature: [0x56; 64],
        };
        let status_input = status
            .unverified_bip340_input_for_bat_v2(&intent, &settled.quote_id, NOW + 3)
            .unwrap();
        assert_eq!(status_input.quote_id, settled.quote_id);
        assert_eq!(
            status_input.message_digest,
            status.bip340_signing_digest().unwrap()
        );

        let mut wrong_request = request.clone();
        wrong_request.class_id[0] ^= 1;
        assert!(wrong_request
            .verify_for_verified_quote(&claim, &verified_settled, NOW + 2)
            .is_err());

        let original_request_digest = intent.request_digest().unwrap();
        let mut replay_intent = intent.clone();
        replay_intent.idempotency_key = [0xa5; 32];
        assert_ne!(
            replay_intent.request_digest().unwrap(),
            original_request_digest
        );
        let persisted = settled
            .verify_persisted_bat_v2_quote_for_store(
                PersistedBolt11BatV2QuoteExpectationV2 {
                    original_request_digest: &original_request_digest,
                    replay_intent: &replay_intent,
                    class: &fixture.class,
                    quote_id: &settled.quote_id,
                    invoice: &settled.invoice,
                    invoice_created_at: settled.invoice_created_at,
                    invoice_expires_at: settled.invoice_expires_at,
                    claim_deadline: settled.claim_deadline,
                    credential_not_after: settled.credential_not_after,
                },
                &fixture.delegation,
                NOW + 2,
            )
            .unwrap();
        assert_eq!(persisted.request_digest(), original_request_digest);
        status
            .unverified_bip340_input_for_verified_bat_v2_quote(&persisted, NOW + 3)
            .unwrap();
        let claimed = Bolt11QuoteV1::with_status_from_verified_bat_v2_snapshot(
            &persisted,
            Bolt11QuoteStatusV1::CredentialClaimed,
            NOW + 2,
            &fixture.delegation,
            &fixture.quote_key,
        )
        .unwrap();
        assert_eq!(claimed.status, Bolt11QuoteStatusV1::CredentialClaimed);
    }

    #[test]
    fn bat_v2_acquisition_issuance_and_envelope_preserve_exact_order() {
        let fixture = fixture();
        let (intent, settled) = settled_quote(&fixture);
        let verified_settled = settled
            .verify_bat_v2_for_claim_submission(
                &intent,
                &fixture.class,
                &fixture.delegation,
                &fixture.parsed_invoice,
                NOW + 2,
            )
            .unwrap();
        let request = issuance_request(&intent, &settled);
        let request_bytes = request.encode().unwrap();
        assert_eq!(
            BatV2IssuanceRequestV2::decode(&request_bytes).unwrap(),
            request
        );
        let claim = Bolt11QuoteClaimV1 {
            issuer_id: intent.issuer_id,
            quote_id: settled.quote_id,
            quote_request_digest: intent.request_digest().unwrap(),
            credential_request_digest: request.request_digest().unwrap(),
            claim_pubkey_xonly: intent.claim_pubkey_xonly,
            idempotency_key: [0x57; 32],
            signature: [0x58; 64],
        };
        let envelope = Bolt11BatV2ClaimEnvelopeV2 {
            quote_intent: intent.clone(),
            claim: claim.clone(),
            credential_request: request.clone(),
        };
        let envelope_bytes = envelope.encode().unwrap();
        assert_eq!(
            Bolt11BatV2ClaimEnvelopeV2::decode(&envelope_bytes).unwrap(),
            envelope
        );

        let response = BatV2IssuanceResponseV2 {
            issuer_id: intent.issuer_id,
            quote_id: settled.quote_id,
            quote_request_digest: settled.request_digest,
            credential_request_digest: request.request_digest().unwrap(),
            class_id: intent.class_id,
            class_digest: intent.class_digest,
            class_key_epoch: intent.class_key_epoch,
            bat_key_id: intent.bat_key_id,
            items: vec![
                BitcoinPirCashuBatIssuanceResponseItemV1 {
                    blinded_message: request.items[0].blinded_message,
                    blinded_signature: point(21),
                    dleq_e: scalar(1),
                    dleq_s: scalar(2),
                },
                BitcoinPirCashuBatIssuanceResponseItemV1 {
                    blinded_message: request.items[1].blinded_message,
                    blinded_signature: point(22),
                    dleq_e: scalar(3),
                    dleq_s: scalar(4),
                },
            ],
        };
        let response_bytes = response.encode().unwrap();
        assert_eq!(
            BatV2IssuanceResponseV2::decode(&response_bytes).unwrap(),
            response
        );
        let checked = response
            .verify_for_verified_quote(&request, &verified_settled)
            .unwrap();
        assert_eq!(checked.unverified_dleq().len(), 2);
        assert_eq!(
            checked.unverified_dleq()[0].issuer_public_key,
            fixture.class.bat_verification_key
        );

        let mut reordered = response.clone();
        reordered.items.swap(0, 1);
        assert!(reordered
            .verify_for_verified_quote(&request, &verified_settled)
            .is_err());
        let mut zero_dleq = response;
        zero_dleq.items[0].dleq_e = [0; 32];
        assert!(zero_dleq.encode().is_err());
    }
}
