//! Canonical HTTP protocol objects for acquiring BitcoinPIR credentials with
//! a BOLT11 payment.
//!
//! These types are deliberately not PIR wire messages. In particular, a PIR
//! server must never receive `Bolt11QuoteV1::invoice`, a Lightning payment
//! hash, or a preimage. The quote and claim exchange terminates at the payment
//! or credential issuer; only the resulting authorization credential is
//! presented to a PIR server.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
#[cfg(not(target_family = "wasm"))]
use lightning_invoice::{Bolt11Invoice, Currency as Bolt11Currency};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::cashu_manifest::is_valid_compressed_point;
use crate::codec::{expect_v1, put_bytes_u16, Decoder};
use crate::{
    derive_issuer_id, AcquisitionMethod, AuthScheme, PriceV1, ProviderId, ScopeId,
    ServiceProtocolError, VerifiedServiceOfferV1, MAX_BITCOIN_MSAT_V1,
    MAX_CREDENTIALS_PER_ACQUISITION_V1, MAX_CREDENTIAL_KEY_ID_LEN, MAX_CREDENTIAL_PRESENTATIONS_V1,
    MAX_TOTAL_PRESENTATIONS_PER_ACQUISITION_V1, SERVICE_PROTOCOL_VERSION,
};

pub const MAX_BOLT11_INVOICE_LEN: usize = 8 * 1024;
pub const MAX_BOLT11_QUOTE_KEY_DELEGATION_LEN: usize = 256;
pub const MAX_BOLT11_QUOTE_INTENT_LEN: usize = 512;
pub const MAX_BOLT11_QUOTE_LEN: usize = 12 * 1024;
pub const MAX_BOLT11_QUOTE_CLAIM_LEN: usize = 384;
pub const MAX_BOLT11_QUOTE_STATUS_REQUEST_LEN: usize = 256;
pub const MAX_BOLT11_QUOTE_STATUS_REQUEST_AGE_SECONDS_V1: u64 = 5 * 60;

/// Deliberately generous protocol caps. A signed provider policy may impose
/// lower limits, but implementations must never accept larger V1 horizons.
pub const MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1: u32 = 7 * 24 * 60 * 60;
pub const MAX_BOLT11_CLAIM_WINDOW_SECONDS_V1: u32 = 30 * 24 * 60 * 60;
pub const MAX_BOLT11_CREDENTIAL_VALIDITY_SECONDS_V1: u32 = 366 * 24 * 60 * 60;

pub const BOLT11_QUOTE_KEY_ID_DOMAIN: &[u8] = b"BitcoinPIR/bolt11-quote-key-id/v1";
pub const BOLT11_QUOTE_KEY_DELEGATION_SIGNATURE_DOMAIN: &[u8] =
    b"BitcoinPIR/bolt11-quote-key-delegation-signature/v1";
pub const BOLT11_QUOTE_KEY_DELEGATION_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/bolt11-quote-key-delegation-digest/v1";
pub const BOLT11_QUOTE_INTENT_DIGEST_DOMAIN: &[u8] = b"BitcoinPIR/bolt11-quote-intent-digest/v1";
pub const BOLT11_QUOTE_SIGNATURE_DOMAIN: &[u8] = b"BitcoinPIR/bolt11-quote-signature/v1";
pub const BOLT11_INVOICE_TEXT_DIGEST_DOMAIN: &[u8] = b"BitcoinPIR/bolt11-invoice-text-digest/v1";
pub const BOLT11_QUOTE_CLAIM_SIGNATURE_DOMAIN: &[u8] =
    b"BitcoinPIR/bolt11-quote-claim-bip340-signature/v1";
pub const BOLT11_QUOTE_CLAIM_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"BitcoinPIR/bolt11-quote-claim-request-digest/v1";
pub const BOLT11_QUOTE_STATUS_REQUEST_SIGNATURE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/bolt11-quote-status-request-bip340-signature/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LightningNetworkV1 {
    Bitcoin = 1,
    Testnet = 2,
    Signet = 3,
    Regtest = 4,
}

impl LightningNetworkV1 {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::Bitcoin),
            2 => Ok(Self::Testnet),
            3 => Ok(Self::Signet),
            4 => Ok(Self::Regtest),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "LightningNetworkV1",
                value,
            }),
        }
    }
}

/// A quote's durable lifecycle state.
///
/// `InvoiceExpiredPendingReconcile` is intentionally not a terminal payment
/// state: a Lightning settlement may be observed after the invoice expiry and
/// transition to `LateSettledReconcile`. An issuer must retain reconciliation
/// state instead of treating an expiry observation as proof of non-payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Bolt11QuoteStatusV1 {
    InvoiceOpen = 1,
    PaymentSettled = 2,
    CredentialClaimed = 3,
    InvoiceExpiredPendingReconcile = 4,
    LateSettledReconcile = 5,
}

impl Bolt11QuoteStatusV1 {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::InvoiceOpen),
            2 => Ok(Self::PaymentSettled),
            3 => Ok(Self::CredentialClaimed),
            4 => Ok(Self::InvoiceExpiredPendingReconcile),
            5 => Ok(Self::LateSettledReconcile),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "Bolt11QuoteStatusV1",
                value,
            }),
        }
    }

    /// State-machine helper for issuer persistence. Repeating a state is
    /// allowed so an idempotent status update can replay exactly.
    pub const fn allows_transition_to(self, next: Self) -> bool {
        if self as u8 == next as u8 {
            return true;
        }
        matches!(
            (self, next),
            (Self::InvoiceOpen, Self::PaymentSettled)
                | (Self::InvoiceOpen, Self::InvoiceExpiredPendingReconcile)
                | (Self::PaymentSettled, Self::CredentialClaimed)
                | (
                    Self::InvoiceExpiredPendingReconcile,
                    Self::LateSettledReconcile
                )
                | (Self::LateSettledReconcile, Self::CredentialClaimed)
        )
    }
}

/// Issuer-root authorization for a short-lived online quote signing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bolt11QuoteKeyDelegationV1 {
    pub issuer_id: [u8; 32],
    pub issuer_verifying_key: [u8; 32],
    pub network: LightningNetworkV1,
    pub expected_payee_pubkey: [u8; 33],
    pub key_epoch: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub quote_key_id: [u8; 16],
    pub quote_verifying_key: [u8; 32],
    pub signature: [u8; 64],
}

impl Bolt11QuoteKeyDelegationV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        network: LightningNetworkV1,
        expected_payee_pubkey: [u8; 33],
        key_epoch: u64,
        not_before: u64,
        not_after: u64,
        quote_verifying_key: [u8; 32],
        issuer_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let issuer_verifying_key = issuer_signing_key.verifying_key().to_bytes();
        let issuer_id = derive_issuer_id(&issuer_verifying_key);
        let quote_key_id = bolt11_quote_key_id_v1(
            &issuer_id,
            network,
            &expected_payee_pubkey,
            key_epoch,
            not_before,
            not_after,
            &quote_verifying_key,
        );
        let mut delegation = Self {
            issuer_id,
            issuer_verifying_key,
            network,
            expected_payee_pubkey,
            key_epoch,
            not_before,
            not_after,
            quote_key_id,
            quote_verifying_key,
            signature: [0; 64],
        };
        delegation.validate_structure()?;
        delegation.signature = issuer_signing_key
            .sign(&delegation.signing_preimage()?)
            .to_bytes();
        Ok(delegation)
    }

    pub fn verify_for(
        &self,
        expected_issuer_id: &[u8; 32],
        expected_network: LightningNetworkV1,
        expected_payee_pubkey: &[u8; 33],
        minimum_key_epoch: u64,
        at_unix: u64,
    ) -> Result<VerifyingKey, ServiceProtocolError> {
        self.verify_signature()?;
        if &self.issuer_id != expected_issuer_id
            || self.network != expected_network
            || &self.expected_payee_pubkey != expected_payee_pubkey
            || self.key_epoch < minimum_key_epoch
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteKeyDelegationV1.binding",
                reason: "issuer, network, payee, or quote-key epoch mismatch",
            });
        }
        if at_unix < self.not_before || at_unix > self.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteKeyDelegationV1.validity",
                reason: "quote key was not valid at the asserted event time",
            });
        }
        VerifyingKey::from_bytes(&self.quote_verifying_key)
            .map_err(|_| ServiceProtocolError::BadPublicKey)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Digest of the exact signed delegation, including its validity window.
    /// Quote intents bind this digest so a different root-signed delegation
    /// cannot be substituted during quote creation or recovery.
    pub fn delegation_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(BOLT11_QUOTE_KEY_DELEGATION_DIGEST_DOMAIN_V1);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_BOLT11_QUOTE_KEY_DELEGATION_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteKeyDelegationV1",
                len: bytes.len(),
                max: MAX_BOLT11_QUOTE_KEY_DELEGATION_LEN,
            });
        }
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("Bolt11QuoteKeyDelegationV1.version")?;
        expect_v1(version, "Bolt11QuoteKeyDelegationV1")?;
        let value = Self {
            issuer_id: decoder.fixed("Bolt11QuoteKeyDelegationV1.issuer_id")?,
            issuer_verifying_key: decoder
                .fixed("Bolt11QuoteKeyDelegationV1.issuer_verifying_key")?,
            network: LightningNetworkV1::decode(decoder.u8("Bolt11QuoteKeyDelegationV1.network")?)?,
            expected_payee_pubkey: decoder
                .fixed("Bolt11QuoteKeyDelegationV1.expected_payee_pubkey")?,
            key_epoch: decoder.u64("Bolt11QuoteKeyDelegationV1.key_epoch")?,
            not_before: decoder.u64("Bolt11QuoteKeyDelegationV1.not_before")?,
            not_after: decoder.u64("Bolt11QuoteKeyDelegationV1.not_after")?,
            quote_key_id: decoder.fixed("Bolt11QuoteKeyDelegationV1.quote_key_id")?,
            quote_verifying_key: decoder.fixed("Bolt11QuoteKeyDelegationV1.quote_verifying_key")?,
            signature: decoder.fixed("Bolt11QuoteKeyDelegationV1.signature")?,
        };
        decoder.finish()?;
        value.validate_structure()?;
        Ok(value)
    }

    fn verify_signature(&self) -> Result<(), ServiceProtocolError> {
        self.validate_structure()?;
        let key = VerifyingKey::from_bytes(&self.issuer_verifying_key)
            .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        key.verify_strict(
            &self.signing_preimage()?,
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| ServiceProtocolError::BadSignature)
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut out =
            Vec::with_capacity(BOLT11_QUOTE_KEY_DELEGATION_SIGNATURE_DOMAIN.len() + unsigned.len());
        out.extend_from_slice(BOLT11_QUOTE_KEY_DELEGATION_SIGNATURE_DOMAIN);
        out.extend_from_slice(&unsigned);
        Ok(out)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate_structure()?;
        let mut out = Vec::with_capacity(192);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.issuer_verifying_key);
        out.push(self.network as u8);
        out.extend_from_slice(&self.expected_payee_pubkey);
        out.extend_from_slice(&self.key_epoch.to_le_bytes());
        out.extend_from_slice(&self.not_before.to_le_bytes());
        out.extend_from_slice(&self.not_after.to_le_bytes());
        out.extend_from_slice(&self.quote_key_id);
        out.extend_from_slice(&self.quote_verifying_key);
        if out.len() + 64 > MAX_BOLT11_QUOTE_KEY_DELEGATION_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteKeyDelegationV1",
                len: out.len() + 64,
                max: MAX_BOLT11_QUOTE_KEY_DELEGATION_LEN,
            });
        }
        Ok(out)
    }

    fn validate_structure(&self) -> Result<(), ServiceProtocolError> {
        if self.issuer_id != derive_issuer_id(&self.issuer_verifying_key) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteKeyDelegationV1.issuer_id",
                reason: "does not match issuer root verifying key",
            });
        }
        VerifyingKey::from_bytes(&self.issuer_verifying_key)
            .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        VerifyingKey::from_bytes(&self.quote_verifying_key)
            .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        if !is_valid_compressed_point(&self.expected_payee_pubkey) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteKeyDelegationV1.expected_payee_pubkey",
                reason: "must be a compressed secp256k1 public key",
            });
        }
        if self.key_epoch == 0 || self.not_before > self.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteKeyDelegationV1.validity",
                reason: "key epoch must be non-zero and validity must be ordered",
            });
        }
        let expected_key_id = bolt11_quote_key_id_v1(
            &self.issuer_id,
            self.network,
            &self.expected_payee_pubkey,
            self.key_epoch,
            self.not_before,
            self.not_after,
            &self.quote_verifying_key,
        );
        if self.quote_key_id != expected_key_id {
            return Err(ServiceProtocolError::WrongSigningKeyId);
        }
        Ok(())
    }
}

/// Durable rollback/fork guard for one `(issuer, network, payee)` quote-key
/// stream. The returned advanced guard must be persisted atomically before an
/// invoice is displayed, paid, or signed by the issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bolt11QuoteKeyRollbackGuardV1 {
    issuer_id: [u8; 32],
    network: LightningNetworkV1,
    expected_payee_pubkey: [u8; 33],
    highest_epoch: u64,
    delegation_digest_at_highest_epoch: [u8; 32],
}

impl Bolt11QuoteKeyRollbackGuardV1 {
    pub fn initial(
        issuer_id: [u8; 32],
        network: LightningNetworkV1,
        expected_payee_pubkey: [u8; 33],
    ) -> Result<Self, ServiceProtocolError> {
        let value = Self {
            issuer_id,
            network,
            expected_payee_pubkey,
            highest_epoch: 0,
            delegation_digest_at_highest_epoch: [0; 32],
        };
        value.validate()?;
        Ok(value)
    }

    pub fn from_persisted(
        issuer_id: [u8; 32],
        network: LightningNetworkV1,
        expected_payee_pubkey: [u8; 33],
        highest_epoch: u64,
        delegation_digest_at_highest_epoch: [u8; 32],
    ) -> Result<Self, ServiceProtocolError> {
        let value = Self {
            issuer_id,
            network,
            expected_payee_pubkey,
            highest_epoch,
            delegation_digest_at_highest_epoch,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn issuer_id(&self) -> [u8; 32] {
        self.issuer_id
    }

    pub const fn network(&self) -> LightningNetworkV1 {
        self.network
    }

    pub const fn expected_payee_pubkey(&self) -> [u8; 33] {
        self.expected_payee_pubkey
    }

    pub const fn highest_epoch(&self) -> u64 {
        self.highest_epoch
    }

    pub const fn delegation_digest_at_highest_epoch(&self) -> [u8; 32] {
        self.delegation_digest_at_highest_epoch
    }

    /// Verify one exact root-signed delegation and produce the state that must
    /// replace this guard. Same-epoch different delegations and lower epochs
    /// fail closed.
    pub fn verify_and_advance(
        &self,
        delegation: &Bolt11QuoteKeyDelegationV1,
        now_unix: u64,
    ) -> Result<Self, ServiceProtocolError> {
        self.validate()?;
        delegation.verify_for(
            &self.issuer_id,
            self.network,
            &self.expected_payee_pubkey,
            self.highest_epoch,
            now_unix,
        )?;
        let digest = delegation.delegation_digest()?;
        if delegation.key_epoch < self.highest_epoch {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteKeyDelegationV1.key_epoch",
                reason: "quote-key delegation epoch rollback",
            });
        }
        if delegation.key_epoch == self.highest_epoch
            && self.highest_epoch != 0
            && digest != self.delegation_digest_at_highest_epoch
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteKeyDelegationV1.delegation_digest",
                reason: "different quote-key delegation at an already accepted epoch",
            });
        }
        Ok(Self {
            issuer_id: self.issuer_id,
            network: self.network,
            expected_payee_pubkey: self.expected_payee_pubkey,
            highest_epoch: delegation.key_epoch,
            delegation_digest_at_highest_epoch: digest,
        })
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.issuer_id.iter().all(|byte| *byte == 0)
            || !is_valid_compressed_point(&self.expected_payee_pubkey)
            || (self.highest_epoch == 0
                && self
                    .delegation_digest_at_highest_epoch
                    .iter()
                    .any(|byte| *byte != 0))
            || (self.highest_epoch != 0
                && self
                    .delegation_digest_at_highest_epoch
                    .iter()
                    .all(|byte| *byte == 0))
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteKeyRollbackGuardV1",
                reason: "stream identity or persisted epoch/digest state is invalid",
            });
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn bolt11_quote_key_id_v1(
    issuer_id: &[u8; 32],
    network: LightningNetworkV1,
    expected_payee_pubkey: &[u8; 33],
    key_epoch: u64,
    not_before: u64,
    not_after: u64,
    quote_verifying_key: &[u8; 32],
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(BOLT11_QUOTE_KEY_ID_DOMAIN);
    hasher.update(issuer_id);
    hasher.update([network as u8]);
    hasher.update(expected_payee_pubkey);
    hasher.update(key_epoch.to_le_bytes());
    hasher.update(not_before.to_le_bytes());
    hasher.update(not_after.to_le_bytes());
    hasher.update(quote_verifying_key);
    let digest: [u8; 32] = hasher.finalize().into();
    digest[..16].try_into().expect("fixed digest prefix")
}

/// Immutable client intent for a BOLT11 credential acquisition.
#[derive(Clone, PartialEq, Eq)]
pub struct Bolt11QuoteIntentV1 {
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub policy_digest: [u8; 32],
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub network: LightningNetworkV1,
    pub expected_payee_pubkey: [u8; 33],
    pub minimum_quote_key_epoch: u64,
    pub quote_delegation_digest: [u8; 32],
    pub authorization: AuthScheme,
    pub credential_binding_digest: [u8; 32],
    pub credential_key_id: Vec<u8>,
    pub exact_amount_msat: u64,
    pub entitlement_profile: u16,
    pub credential_count: u32,
    pub credential_presentation_limit: u32,
    pub invoice_expiry_seconds: u32,
    pub claim_window_seconds: u32,
    pub minimum_credential_validity_seconds: u32,
    /// BIP340 x-only public key. Never encode this as an ambiguous 33-byte
    /// SEC1 point: BIP340 selects the even-Y point for this x-coordinate.
    pub claim_pubkey_xonly: [u8; 32],
    pub idempotency_key: [u8; 32],
}

impl fmt::Debug for Bolt11QuoteIntentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bolt11QuoteIntentV1")
            .field("authorization", &self.authorization)
            .field("commercial_and_client_binding", &"[REDACTED]")
            .finish()
    }
}

impl Drop for Bolt11QuoteIntentV1 {
    fn drop(&mut self) {
        self.idempotency_key.zeroize();
    }
}

impl Bolt11QuoteIntentV1 {
    /// Integration-safe constructor. It verifies the exact quote-key stream
    /// against the durable rollback/fork guard and returns the advanced guard
    /// that callers MUST persist before displaying or paying the invoice.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_offer_guarded(
        verified_offer: &VerifiedServiceOfferV1<'_>,
        quote_delegation: &Bolt11QuoteKeyDelegationV1,
        rollback_guard: &Bolt11QuoteKeyRollbackGuardV1,
        now_unix: u64,
        claim_pubkey_xonly: [u8; 32],
        idempotency_key: [u8; 32],
    ) -> Result<(Self, Bolt11QuoteKeyRollbackGuardV1), ServiceProtocolError> {
        let advanced_guard = rollback_guard.verify_and_advance(quote_delegation, now_unix)?;
        let intent = Self::from_verified_offer(
            verified_offer,
            quote_delegation,
            advanced_guard.network(),
            &advanced_guard.expected_payee_pubkey(),
            advanced_guard.highest_epoch(),
            now_unix,
            claim_pubkey_xonly,
            idempotency_key,
        )?;
        Ok((intent, advanced_guard))
    }

    /// Construct the only valid BOLT11 intent for a verified provider offer.
    /// All commercial and credential terms come from the signed policy. The
    /// network and payee are accepted only through an issuer-root-signed quote
    /// delegation checked against caller-trusted expectations and a durable
    /// anti-rollback floor.
    #[allow(clippy::too_many_arguments)]
    fn from_verified_offer(
        verified_offer: &VerifiedServiceOfferV1<'_>,
        quote_delegation: &Bolt11QuoteKeyDelegationV1,
        expected_network: LightningNetworkV1,
        expected_payee_pubkey: &[u8; 33],
        minimum_quote_key_epoch: u64,
        now_unix: u64,
        claim_pubkey_xonly: [u8; 32],
        idempotency_key: [u8; 32],
    ) -> Result<Self, ServiceProtocolError> {
        let scope = verified_offer.scope();
        let offer = verified_offer.offer();
        if offer.acquisition != AcquisitionMethod::Bolt11V1 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.acquisition",
                reason: "quote intent requires a BOLT11 acquisition offer",
            });
        }
        let exact_amount_msat = match &offer.price {
            PriceV1::MilliSatoshi(amount) => *amount,
            _ => {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServiceOfferV1.price",
                    reason: "BOLT11 quote requires an exact millisatoshi price",
                })
            }
        };
        let credential_binding =
            offer
                .credential_binding
                .as_ref()
                .ok_or(ServiceProtocolError::InvalidValue {
                    field: "ServiceOfferV1.credential_binding",
                    reason: "BOLT11 credential issuance requires a signed credential binding",
                })?;
        quote_delegation.verify_for(
            &offer.issuer_id,
            expected_network,
            expected_payee_pubkey,
            minimum_quote_key_epoch,
            now_unix,
        )?;
        let intent = Self {
            issuer_id: offer.issuer_id,
            provider_id: scope.provider_id,
            policy_digest: verified_offer.policy_digest(),
            scope_id: scope.scope_id(),
            offer_id: offer.offer_id,
            network: expected_network,
            expected_payee_pubkey: *expected_payee_pubkey,
            minimum_quote_key_epoch,
            quote_delegation_digest: quote_delegation.delegation_digest()?,
            authorization: offer.authorization,
            credential_binding_digest: credential_binding.binding_digest()?,
            credential_key_id: offer.key_id.clone(),
            exact_amount_msat,
            entitlement_profile: scope.entitlement_profile,
            credential_count: offer.credential_count,
            credential_presentation_limit: offer.credential_presentation_limit,
            invoice_expiry_seconds: offer.invoice_expiry_seconds,
            claim_window_seconds: offer.claim_window_seconds,
            minimum_credential_validity_seconds: offer.minimum_credential_validity_seconds,
            claim_pubkey_xonly,
            idempotency_key,
        };
        intent.validate()?;
        Ok(intent)
    }

    /// Issuer/client shared fail-closed check for a received quote intent.
    /// Client-selected claim and idempotency keys are retained, while every
    /// offer-derived field is independently reconstructed and compared.
    #[allow(clippy::too_many_arguments)]
    fn verify_for_offer(
        &self,
        verified_offer: &VerifiedServiceOfferV1<'_>,
        quote_delegation: &Bolt11QuoteKeyDelegationV1,
        expected_network: LightningNetworkV1,
        expected_payee_pubkey: &[u8; 33],
        minimum_quote_key_epoch: u64,
        now_unix: u64,
    ) -> Result<(), ServiceProtocolError> {
        let expected = Self::from_verified_offer(
            verified_offer,
            quote_delegation,
            expected_network,
            expected_payee_pubkey,
            minimum_quote_key_epoch,
            now_unix,
            self.claim_pubkey_xonly,
            self.idempotency_key,
        )?;
        if self != &expected {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.offer_binding",
                reason: "intent differs from the verified policy offer or quote-key delegation",
            });
        }
        Ok(())
    }

    /// Integration-safe issuer/client verification. As with construction, the
    /// advanced guard must be durably committed before invoice creation,
    /// display, or payment proceeds.
    pub fn verify_for_offer_guarded<'a>(
        &'a self,
        verified_offer: &VerifiedServiceOfferV1<'_>,
        quote_delegation: &'a Bolt11QuoteKeyDelegationV1,
        rollback_guard: &Bolt11QuoteKeyRollbackGuardV1,
        now_unix: u64,
    ) -> Result<VerifiedBolt11QuoteIntentV1<'a>, ServiceProtocolError> {
        let advanced_guard = rollback_guard.verify_and_advance(quote_delegation, now_unix)?;
        self.verify_for_offer(
            verified_offer,
            quote_delegation,
            advanced_guard.network(),
            &advanced_guard.expected_payee_pubkey(),
            advanced_guard.highest_epoch(),
            now_unix,
        )?;
        Ok(VerifiedBolt11QuoteIntentV1 {
            intent: self,
            delegation: quote_delegation,
            advanced_guard,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Zeroizing::new(Vec::with_capacity(320));
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.scope_id);
        out.extend_from_slice(&self.offer_id.to_le_bytes());
        out.push(self.network as u8);
        out.extend_from_slice(&self.expected_payee_pubkey);
        out.extend_from_slice(&self.minimum_quote_key_epoch.to_le_bytes());
        out.extend_from_slice(&self.quote_delegation_digest);
        out.push(self.authorization as u8);
        out.extend_from_slice(&self.credential_binding_digest);
        out.push(self.credential_key_id.len() as u8);
        out.extend_from_slice(&self.credential_key_id);
        out.extend_from_slice(&self.exact_amount_msat.to_le_bytes());
        out.extend_from_slice(&self.entitlement_profile.to_le_bytes());
        out.extend_from_slice(&self.credential_count.to_le_bytes());
        out.extend_from_slice(&self.credential_presentation_limit.to_le_bytes());
        out.extend_from_slice(&self.invoice_expiry_seconds.to_le_bytes());
        out.extend_from_slice(&self.claim_window_seconds.to_le_bytes());
        out.extend_from_slice(&self.minimum_credential_validity_seconds.to_le_bytes());
        out.extend_from_slice(&self.claim_pubkey_xonly);
        out.extend_from_slice(&self.idempotency_key);
        if out.len() > MAX_BOLT11_QUOTE_INTENT_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteIntentV1",
                len: out.len(),
                max: MAX_BOLT11_QUOTE_INTENT_LEN,
            });
        }
        Ok(std::mem::take(&mut *out))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_BOLT11_QUOTE_INTENT_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteIntentV1",
                len: bytes.len(),
                max: MAX_BOLT11_QUOTE_INTENT_LEN,
            });
        }
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("Bolt11QuoteIntentV1.version")?;
        expect_v1(version, "Bolt11QuoteIntentV1")?;
        let value = Self {
            issuer_id: decoder.fixed("Bolt11QuoteIntentV1.issuer_id")?,
            provider_id: decoder.fixed("Bolt11QuoteIntentV1.provider_id")?,
            policy_digest: decoder.fixed("Bolt11QuoteIntentV1.policy_digest")?,
            scope_id: decoder.fixed("Bolt11QuoteIntentV1.scope_id")?,
            offer_id: decoder.u32("Bolt11QuoteIntentV1.offer_id")?,
            network: LightningNetworkV1::decode(decoder.u8("Bolt11QuoteIntentV1.network")?)?,
            expected_payee_pubkey: decoder.fixed("Bolt11QuoteIntentV1.expected_payee_pubkey")?,
            minimum_quote_key_epoch: decoder.u64("Bolt11QuoteIntentV1.minimum_quote_key_epoch")?,
            quote_delegation_digest: decoder
                .fixed("Bolt11QuoteIntentV1.quote_delegation_digest")?,
            authorization: AuthScheme::decode(decoder.u8("Bolt11QuoteIntentV1.authorization")?)?,
            credential_binding_digest: decoder
                .fixed("Bolt11QuoteIntentV1.credential_binding_digest")?,
            credential_key_id: decoder.bytes_u8(
                "Bolt11QuoteIntentV1.credential_key_id",
                MAX_CREDENTIAL_KEY_ID_LEN,
            )?,
            exact_amount_msat: decoder.u64("Bolt11QuoteIntentV1.exact_amount_msat")?,
            entitlement_profile: decoder.u16("Bolt11QuoteIntentV1.entitlement_profile")?,
            credential_count: decoder.u32("Bolt11QuoteIntentV1.credential_count")?,
            credential_presentation_limit: decoder
                .u32("Bolt11QuoteIntentV1.credential_presentation_limit")?,
            invoice_expiry_seconds: decoder.u32("Bolt11QuoteIntentV1.invoice_expiry_seconds")?,
            claim_window_seconds: decoder.u32("Bolt11QuoteIntentV1.claim_window_seconds")?,
            minimum_credential_validity_seconds: decoder
                .u32("Bolt11QuoteIntentV1.minimum_credential_validity_seconds")?,
            claim_pubkey_xonly: decoder.fixed("Bolt11QuoteIntentV1.claim_pubkey_xonly")?,
            idempotency_key: decoder.fixed("Bolt11QuoteIntentV1.idempotency_key")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(BOLT11_QUOTE_INTENT_DIGEST_DOMAIN);
        let encoded = Zeroizing::new(self.encode()?);
        hasher.update(&encoded);
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
                field: "Bolt11QuoteIntentV1.invoice_expiry_seconds",
                reason: "invoice expiry overflows Unix time",
            })?;
        let claim_deadline = invoice_expires_at
            .checked_add(u64::from(self.claim_window_seconds))
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.claim_window_seconds",
                reason: "claim deadline overflows Unix time",
            })?;
        let credential_not_after = claim_deadline
            .checked_add(u64::from(self.minimum_credential_validity_seconds))
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.minimum_credential_validity_seconds",
                reason: "credential horizon overflows Unix time",
            })?;
        Ok(Bolt11QuoteHorizonsV1 {
            invoice_expires_at,
            claim_deadline,
            credential_not_after,
        })
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.issuer_id.iter().all(|byte| *byte == 0)
            || self.provider_id.iter().all(|byte| *byte == 0)
            || self.policy_digest.iter().all(|byte| *byte == 0)
            || self.scope_id.iter().all(|byte| *byte == 0)
            || self.offer_id == 0
            || self.minimum_quote_key_epoch == 0
            || self.quote_delegation_digest.iter().all(|byte| *byte == 0)
            || self.credential_binding_digest.iter().all(|byte| *byte == 0)
            || self.entitlement_profile == 0
            || self.idempotency_key.iter().all(|byte| *byte == 0)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.binding",
                reason: "issuer, provider, policy, scope, offer, key epoch, profile, and IDs must be non-zero",
            });
        }
        if !is_valid_compressed_point(&self.expected_payee_pubkey) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.expected_payee_pubkey",
                reason: "must be a compressed secp256k1 public key",
            });
        }
        validate_xonly_pubkey(&self.claim_pubkey_xonly)?;
        if !matches!(
            self.authorization,
            AuthScheme::Bolt11DirectReceiptV1
                | AuthScheme::BitcoinPirCashuBatV1
                | AuthScheme::ArcV1Experimental
        ) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.authorization",
                reason: "BOLT11 acquisition supports receipt, BAT, or experimental ARC issuance",
            });
        }
        if self.credential_key_id.is_empty()
            || self.credential_key_id.len() > MAX_CREDENTIAL_KEY_ID_LEN
        {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteIntentV1.credential_key_id",
                len: self.credential_key_id.len(),
                max: MAX_CREDENTIAL_KEY_ID_LEN,
            });
        }
        if self.exact_amount_msat == 0 || self.exact_amount_msat > MAX_BITCOIN_MSAT_V1 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.exact_amount_msat",
                reason: "must be non-zero and within the Bitcoin supply bound",
            });
        }
        if self.credential_count == 0
            || self.credential_count > MAX_CREDENTIALS_PER_ACQUISITION_V1
            || self.credential_presentation_limit == 0
            || self.credential_presentation_limit > MAX_CREDENTIAL_PRESENTATIONS_V1
            || self
                .credential_count
                .checked_mul(self.credential_presentation_limit)
                .map_or(true, |total| {
                    total > MAX_TOTAL_PRESENTATIONS_PER_ACQUISITION_V1
                })
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.credential_limits",
                reason: "credential count/presentation limits are zero, excessive, or overflow",
            });
        }
        if self.authorization == AuthScheme::ArcV1Experimental
            && self.credential_presentation_limit < 2
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.credential_presentation_limit",
                reason: "experimental ARC draft-01 requires at least two presentations",
            });
        }
        if self.invoice_expiry_seconds == 0
            || self.invoice_expiry_seconds > MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1
            || self.claim_window_seconds == 0
            || self.claim_window_seconds > MAX_BOLT11_CLAIM_WINDOW_SECONDS_V1
            || self.minimum_credential_validity_seconds == 0
            || self.minimum_credential_validity_seconds > MAX_BOLT11_CREDENTIAL_VALIDITY_SECONDS_V1
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.horizons",
                reason: "invoice, claim, and credential horizons must be non-zero and bounded",
            });
        }
        Ok(())
    }
}

/// Typestate proving that every commercial/credential term came from one
/// verified service offer and that the exact quote-key delegation passed its
/// durable stream rollback/fork guard.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedBolt11QuoteIntentV1<'a> {
    intent: &'a Bolt11QuoteIntentV1,
    delegation: &'a Bolt11QuoteKeyDelegationV1,
    advanced_guard: Bolt11QuoteKeyRollbackGuardV1,
}

impl<'a> VerifiedBolt11QuoteIntentV1<'a> {
    pub const fn intent(&self) -> &'a Bolt11QuoteIntentV1 {
        self.intent
    }

    pub const fn delegation(&self) -> &'a Bolt11QuoteKeyDelegationV1 {
        self.delegation
    }

    /// State the caller must durably store before creating/displaying an
    /// invoice. Returning it here does not itself persist anything.
    pub const fn advanced_guard(&self) -> Bolt11QuoteKeyRollbackGuardV1 {
        self.advanced_guard
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bolt11QuoteHorizonsV1 {
    pub invoice_expires_at: u64,
    pub claim_deadline: u64,
    pub credential_not_after: u64,
}

/// Facts returned by a signature-verifying BOLT11 parser for the exact invoice
/// text in a quote. Production code can construct this type only by calling
/// [`ParsedBolt11InvoiceV1::parse`], which uses a pure-Rust verifier on every
/// target and additionally cross-checks `lightning-invoice` on native builds.
/// This type intentionally has no payment-hash field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedBolt11InvoiceV1 {
    invoice_text_digest: [u8; 32],
    network: LightningNetworkV1,
    payee_pubkey: [u8; 33],
    amount_msat: u64,
    created_at: u64,
    expiry_seconds: u32,
}

impl ParsedBolt11InvoiceV1 {
    /// Parse and verify one exact, canonical, fixed-amount BOLT11 invoice.
    ///
    /// `Bolt11Invoice::from_str` performs syntax, semantic and recoverable
    /// ECDSA signature verification. The exact serialization round-trip is an
    /// additional BitcoinPIR requirement: it prevents a caller from binding a
    /// quote digest to a non-canonical spelling that normalizes to different
    /// text. Simnet and amountless invoices are deliberately unsupported.
    #[cfg(not(target_family = "wasm"))]
    pub fn parse(invoice: &str) -> Result<Self, ServiceProtocolError> {
        // Bound work and reject non-lowercase/mixed-case encodings before the
        // full parser allocates for tagged fields.
        validate_invoice_text(invoice)?;
        let parsed =
            invoice
                .parse::<Bolt11Invoice>()
                .map_err(|_| ServiceProtocolError::InvalidValue {
                    field: "ParsedBolt11InvoiceV1.invoice",
                    reason: "BOLT11 syntax, semantics, or signature validation failed",
                })?;
        parsed
            .check_signature()
            .map_err(|_| ServiceProtocolError::BadSignature)?;
        if parsed.to_string() != invoice {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ParsedBolt11InvoiceV1.invoice",
                reason: "invoice is not in its exact canonical lowercase encoding",
            });
        }

        let network = match parsed.currency() {
            Bolt11Currency::Bitcoin => LightningNetworkV1::Bitcoin,
            Bolt11Currency::BitcoinTestnet => LightningNetworkV1::Testnet,
            Bolt11Currency::Signet => LightningNetworkV1::Signet,
            Bolt11Currency::Regtest => LightningNetworkV1::Regtest,
            Bolt11Currency::Simnet => {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ParsedBolt11InvoiceV1.network",
                    reason: "simnet is not a supported BitcoinPIR Lightning network",
                });
            }
        };
        let amount_msat =
            parsed
                .amount_milli_satoshis()
                .ok_or(ServiceProtocolError::InvalidValue {
                    field: "ParsedBolt11InvoiceV1.amount_msat",
                    reason: "amountless BOLT11 invoices are not supported",
                })?;
        let expiry_seconds = u32::try_from(parsed.expiry_time().as_secs()).map_err(|_| {
            ServiceProtocolError::InvalidValue {
                field: "ParsedBolt11InvoiceV1.expiry_seconds",
                reason: "invoice expiry does not fit the V1 representation",
            }
        })?;
        let value = Self {
            invoice_text_digest: bolt11_invoice_text_digest_v1(invoice),
            network,
            payee_pubkey: parsed.get_payee_pub_key().serialize(),
            amount_msat,
            created_at: parsed.duration_since_epoch().as_secs(),
            expiry_seconds,
        };
        value.validate()?;
        let pure = crate::quote_wasm::parse_and_verify(invoice)?;
        if pure.network != value.network
            || pure.payee_pubkey != value.payee_pubkey
            || pure.amount_msat != value.amount_msat
            || pure.created_at != value.created_at
            || pure.expiry_seconds != value.expiry_seconds
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ParsedBolt11InvoiceV1.invoice",
                reason: "native and pure-Rust BOLT11 parser facts disagree",
            });
        }
        Ok(value)
    }

    /// Parse and verify one exact, canonical, fixed-amount BOLT11 invoice in a
    /// browser without a C secp256k1 toolchain.
    #[cfg(target_family = "wasm")]
    pub fn parse(invoice: &str) -> Result<Self, ServiceProtocolError> {
        validate_invoice_text(invoice)?;
        let parsed = crate::quote_wasm::parse_and_verify(invoice)?;
        let value = Self {
            invoice_text_digest: bolt11_invoice_text_digest_v1(invoice),
            network: parsed.network,
            payee_pubkey: parsed.payee_pubkey,
            amount_msat: parsed.amount_msat,
            created_at: parsed.created_at,
            expiry_seconds: parsed.expiry_seconds,
        };
        value.validate()?;
        Ok(value)
    }

    /// Test-only constructor for protocol fixtures that intentionally do not
    /// carry a real BOLT11 signature. It is not present in production builds.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_signature_verified_invoice(
        invoice: &str,
        network: LightningNetworkV1,
        payee_pubkey: [u8; 33],
        amount_msat: u64,
        created_at: u64,
        expiry_seconds: u32,
    ) -> Result<Self, ServiceProtocolError> {
        validate_invoice_text(invoice)?;
        let value = Self {
            invoice_text_digest: bolt11_invoice_text_digest_v1(invoice),
            network,
            payee_pubkey,
            amount_msat,
            created_at,
            expiry_seconds,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn invoice_text_digest(&self) -> [u8; 32] {
        self.invoice_text_digest
    }

    pub const fn network(&self) -> LightningNetworkV1 {
        self.network
    }

    pub const fn payee_pubkey(&self) -> [u8; 33] {
        self.payee_pubkey
    }

    pub const fn amount_msat(&self) -> u64 {
        self.amount_msat
    }

    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    pub const fn expiry_seconds(&self) -> u32 {
        self.expiry_seconds
    }

    pub fn expires_at(&self) -> Result<u64, ServiceProtocolError> {
        self.created_at
            .checked_add(u64::from(self.expiry_seconds))
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "ParsedBolt11InvoiceV1.expiry_seconds",
                reason: "invoice expiry overflows Unix time",
            })
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.invoice_text_digest.iter().all(|byte| *byte == 0)
            || !is_valid_compressed_point(&self.payee_pubkey)
            || self.amount_msat == 0
            || self.amount_msat > MAX_BITCOIN_MSAT_V1
            || self.expiry_seconds == 0
            || self.expiry_seconds > MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ParsedBolt11InvoiceV1",
                reason: "invoice digest, payee, amount, or expiry is invalid",
            });
        }
        self.expires_at().map(|_| ())
    }
}

/// Signed quote/status snapshot returned by the issuer.
#[derive(Clone, PartialEq, Eq)]
pub struct Bolt11QuoteV1 {
    pub request_digest: [u8; 32],
    pub quote_id: [u8; 32],
    pub quote_key_id: [u8; 16],
    pub invoice: String,
    pub network: LightningNetworkV1,
    pub payee_pubkey: [u8; 33],
    pub amount_msat: u64,
    pub invoice_created_at: u64,
    pub invoice_expires_at: u64,
    pub claim_deadline: u64,
    pub credential_not_after: u64,
    pub status: Bolt11QuoteStatusV1,
    /// Monotonic issuer-store state version. Initial `InvoiceOpen` is version
    /// one; every committed state transition increments it exactly once.
    pub state_version: u64,
    /// Time of the asserted lifecycle transition, not an unsigned HTTP cache
    /// timestamp. It is part of the signed response.
    pub status_updated_at: u64,
    pub signature: [u8; 64],
}

impl fmt::Debug for Bolt11QuoteV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bolt11QuoteV1")
            .field("status", &self.status)
            .field("state_version", &self.state_version)
            .field("payment_artifacts", &"[REDACTED]")
            .finish()
    }
}

impl Drop for Bolt11QuoteV1 {
    fn drop(&mut self) {
        self.invoice.zeroize();
        self.signature.zeroize();
    }
}

impl Bolt11QuoteV1 {
    /// Initial issuer-side signing entry point. The BOLT11 facts can only come
    /// from [`ParsedBolt11InvoiceV1::parse`] in a native production build;
    /// this function binds them exactly to the verified commercial intent.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_for_verified_intent(
        verified_intent: &VerifiedBolt11QuoteIntentV1<'_>,
        quote_id: [u8; 32],
        invoice: String,
        parsed_invoice: &ParsedBolt11InvoiceV1,
        status: Bolt11QuoteStatusV1,
        status_updated_at: u64,
        quote_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let mut invoice = Zeroizing::new(invoice);
        let intent = verified_intent.intent();
        parsed_invoice.validate()?;
        if parsed_invoice.invoice_text_digest != bolt11_invoice_text_digest_v1(&invoice)
            || parsed_invoice.network != intent.network
            || parsed_invoice.payee_pubkey != intent.expected_payee_pubkey
            || parsed_invoice.amount_msat != intent.exact_amount_msat
            || parsed_invoice.expiry_seconds != intent.invoice_expiry_seconds
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ParsedBolt11InvoiceV1.offer_binding",
                reason: "invoice parser facts do not match the verified quote intent",
            });
        }
        Self::sign_verified_fields(
            intent,
            quote_id,
            std::mem::take(&mut *invoice),
            parsed_invoice.created_at,
            status,
            status_updated_at,
            verified_intent.delegation(),
            quote_signing_key,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_verified_fields(
        intent: &Bolt11QuoteIntentV1,
        quote_id: [u8; 32],
        invoice: String,
        invoice_created_at: u64,
        status: Bolt11QuoteStatusV1,
        status_updated_at: u64,
        delegation: &Bolt11QuoteKeyDelegationV1,
        quote_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let mut invoice = Zeroizing::new(invoice);
        intent.validate()?;
        validate_invoice_text(&invoice)?;
        if status != Bolt11QuoteStatusV1::InvoiceOpen {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteStatusV1.initial",
                reason: "the initial quote snapshot must be InvoiceOpen",
            });
        }
        if intent.quote_delegation_digest != delegation.delegation_digest()? {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.quote_delegation_digest",
                reason: "intent does not bind the exact signed quote-key delegation",
            });
        }
        let horizons = intent.derived_horizons(invoice_created_at)?;
        delegation.verify_for(
            &intent.issuer_id,
            intent.network,
            &intent.expected_payee_pubkey,
            intent.minimum_quote_key_epoch,
            invoice_created_at,
        )?;
        delegation.verify_for(
            &intent.issuer_id,
            intent.network,
            &intent.expected_payee_pubkey,
            intent.minimum_quote_key_epoch,
            status_updated_at,
        )?;
        // The same delegated online key must remain authorized for every
        // lifecycle signature that can be required after payment. Otherwise
        // an invoice could be payable while a settled payment becomes
        // impossible to claim once a too-short delegation expires.
        delegation.verify_for(
            &intent.issuer_id,
            intent.network,
            &intent.expected_payee_pubkey,
            intent.minimum_quote_key_epoch,
            horizons.claim_deadline,
        )?;
        if quote_signing_key.verifying_key().to_bytes() != delegation.quote_verifying_key {
            return Err(ServiceProtocolError::WrongSigningKeyId);
        }
        let mut value = Self {
            request_digest: intent.request_digest()?,
            quote_id,
            quote_key_id: delegation.quote_key_id,
            invoice: std::mem::take(&mut *invoice),
            network: intent.network,
            payee_pubkey: intent.expected_payee_pubkey,
            amount_msat: intent.exact_amount_msat,
            invoice_created_at,
            invoice_expires_at: horizons.invoice_expires_at,
            claim_deadline: horizons.claim_deadline,
            credential_not_after: horizons.credential_not_after,
            status,
            state_version: 1,
            status_updated_at,
            signature: [0; 64],
        };
        value.validate_structure()?;
        value.signature = quote_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    /// Test-only raw quote constructor for protocol fixtures. Production
    /// callers must go through `sign_for_verified_intent` and the concrete
    /// BOLT11 parser.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign(
        intent: &Bolt11QuoteIntentV1,
        quote_id: [u8; 32],
        invoice: String,
        invoice_created_at: u64,
        status: Bolt11QuoteStatusV1,
        status_updated_at: u64,
        delegation: &Bolt11QuoteKeyDelegationV1,
        quote_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        Self::sign_verified_fields(
            intent,
            quote_id,
            invoice,
            invoice_created_at,
            status,
            status_updated_at,
            delegation,
            quote_signing_key,
        )
    }

    /// Create a signed status transition without changing any immutable quote
    /// term. The issuer-root delegation is required so this helper cannot sign
    /// with an unrelated Ed25519 key that happens to be supplied by a caller.
    pub(crate) fn with_status(
        &self,
        intent: &Bolt11QuoteIntentV1,
        status: Bolt11QuoteStatusV1,
        status_updated_at: u64,
        delegation: &Bolt11QuoteKeyDelegationV1,
        quote_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        if !self.status.allows_transition_to(status) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteStatusV1.transition",
                reason: "invalid quote status transition",
            });
        }
        if status == self.status && status_updated_at != self.status_updated_at {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.status_updated_at",
                reason: "an idempotent status replay must preserve the exact transition time",
            });
        }
        if status != self.status && status_updated_at <= self.status_updated_at {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.status_updated_at",
                reason: "status transition time must strictly increase",
            });
        }
        if intent.quote_delegation_digest != delegation.delegation_digest()? {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.quote_delegation_digest",
                reason: "intent does not bind the exact signed quote-key delegation",
            });
        }
        delegation.verify_for(
            &intent.issuer_id,
            intent.network,
            &intent.expected_payee_pubkey,
            intent.minimum_quote_key_epoch,
            status_updated_at,
        )?;
        delegation.verify_for(
            &intent.issuer_id,
            intent.network,
            &intent.expected_payee_pubkey,
            intent.minimum_quote_key_epoch,
            self.claim_deadline,
        )?;
        if self.request_digest != intent.request_digest()?
            || self.quote_key_id != delegation.quote_key_id
            || self.network != delegation.network
            || self.payee_pubkey != delegation.expected_payee_pubkey
            || quote_signing_key.verifying_key().to_bytes() != delegation.quote_verifying_key
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.status_signing_key",
                reason: "status signer is outside the original root delegation",
            });
        }
        let mut next = self.clone();
        next.status = status;
        if status != self.status {
            next.state_version =
                self.state_version
                    .checked_add(1)
                    .ok_or(ServiceProtocolError::InvalidValue {
                        field: "Bolt11QuoteV1.state_version",
                        reason: "state version overflow",
                    })?;
        }
        next.status_updated_at = status_updated_at;
        next.signature = [0; 64];
        next.validate_structure()?;
        next.signature = quote_signing_key.sign(&next.signing_preimage()?).to_bytes();
        Ok(next)
    }

    /// Sign a transition only from a snapshot whose issuer signature,
    /// delegation, invoice facts, and immutable request terms were already
    /// verified.
    pub fn with_status_from_verified_snapshot(
        verified_snapshot: &VerifiedBolt11QuoteV1<'_>,
        status: Bolt11QuoteStatusV1,
        status_updated_at: u64,
        delegation: &Bolt11QuoteKeyDelegationV1,
        quote_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        verified_snapshot.quote.with_status(
            verified_snapshot.intent,
            status,
            status_updated_at,
            delegation,
            quote_signing_key,
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        Ok(std::mem::take(&mut *out))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_BOLT11_QUOTE_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteV1",
                len: bytes.len(),
                max: MAX_BOLT11_QUOTE_LEN,
            });
        }
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("Bolt11QuoteV1.version")?;
        expect_v1(version, "Bolt11QuoteV1")?;
        let request_digest = decoder.fixed("Bolt11QuoteV1.request_digest")?;
        let quote_id = decoder.fixed("Bolt11QuoteV1.quote_id")?;
        let quote_key_id = decoder.fixed("Bolt11QuoteV1.quote_key_id")?;
        let mut invoice =
            Zeroizing::new(decoder.string_u16("Bolt11QuoteV1.invoice", MAX_BOLT11_INVOICE_LEN)?);
        let value = Self {
            request_digest,
            quote_id,
            quote_key_id,
            invoice: std::mem::take(&mut *invoice),
            network: LightningNetworkV1::decode(decoder.u8("Bolt11QuoteV1.network")?)?,
            payee_pubkey: decoder.fixed("Bolt11QuoteV1.payee_pubkey")?,
            amount_msat: decoder.u64("Bolt11QuoteV1.amount_msat")?,
            invoice_created_at: decoder.u64("Bolt11QuoteV1.invoice_created_at")?,
            invoice_expires_at: decoder.u64("Bolt11QuoteV1.invoice_expires_at")?,
            claim_deadline: decoder.u64("Bolt11QuoteV1.claim_deadline")?,
            credential_not_after: decoder.u64("Bolt11QuoteV1.credential_not_after")?,
            status: Bolt11QuoteStatusV1::decode(decoder.u8("Bolt11QuoteV1.status")?)?,
            state_version: decoder.u64("Bolt11QuoteV1.state_version")?,
            status_updated_at: decoder.u64("Bolt11QuoteV1.status_updated_at")?,
            signature: decoder.fixed("Bolt11QuoteV1.signature")?,
        };
        decoder.finish()?;
        value.validate_structure()?;
        Ok(value)
    }

    /// Verify a quote/status snapshot for restoration or polling. This checks
    /// the exact invoice parser facts, all immutable request terms, both
    /// signature layers, event times, and quote-key rollback floor. It does
    /// not imply that the invoice is still payable or the claim is timely;
    /// use `verify_for_payment` or `verify_for_claim_submission` for that.
    pub fn verify_snapshot<'a>(
        &'a self,
        intent: &'a Bolt11QuoteIntentV1,
        delegation: &Bolt11QuoteKeyDelegationV1,
        parsed_invoice: &ParsedBolt11InvoiceV1,
        now_unix: u64,
    ) -> Result<VerifiedBolt11QuoteV1<'a>, ServiceProtocolError> {
        self.validate_structure()?;
        intent.validate()?;
        parsed_invoice.validate()?;
        if intent.quote_delegation_digest != delegation.delegation_digest()? {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.quote_delegation_digest",
                reason: "intent does not bind the exact signed quote-key delegation",
            });
        }
        if self.request_digest != intent.request_digest()?
            || self.network != intent.network
            || self.payee_pubkey != intent.expected_payee_pubkey
            || self.amount_msat != intent.exact_amount_msat
            || self.quote_key_id != delegation.quote_key_id
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.intent",
                reason: "quote does not echo the immutable request terms",
            });
        }
        let quote_verifying_key = delegation.verify_for(
            &intent.issuer_id,
            intent.network,
            &intent.expected_payee_pubkey,
            intent.minimum_quote_key_epoch,
            self.invoice_created_at,
        )?;
        delegation.verify_for(
            &intent.issuer_id,
            intent.network,
            &intent.expected_payee_pubkey,
            intent.minimum_quote_key_epoch,
            self.status_updated_at,
        )?;
        let horizons = intent.derived_horizons(self.invoice_created_at)?;
        delegation.verify_for(
            &intent.issuer_id,
            intent.network,
            &intent.expected_payee_pubkey,
            intent.minimum_quote_key_epoch,
            horizons.claim_deadline,
        )?;
        if self.invoice_expires_at != horizons.invoice_expires_at
            || self.claim_deadline != horizons.claim_deadline
            || self.credential_not_after != horizons.credential_not_after
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.horizons",
                reason: "response deadlines do not exactly match the signed intent",
            });
        }
        if parsed_invoice.invoice_text_digest != bolt11_invoice_text_digest_v1(&self.invoice)
            || parsed_invoice.network != self.network
            || parsed_invoice.payee_pubkey != self.payee_pubkey
            || parsed_invoice.amount_msat != self.amount_msat
            || parsed_invoice.created_at != self.invoice_created_at
            || parsed_invoice.expiry_seconds != intent.invoice_expiry_seconds
            || parsed_invoice.expires_at()? != self.invoice_expires_at
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.invoice",
                reason: "parsed BOLT11 network, payee, amount, timestamp, or expiry mismatch",
            });
        }
        if self.invoice_created_at > now_unix || self.status_updated_at > now_unix {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.time",
                reason: "quote or status update is from the future",
            });
        }
        quote_verifying_key
            .verify_strict(
                &self.signing_preimage()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ServiceProtocolError::BadSignature)?;
        Ok(VerifiedBolt11QuoteV1 {
            quote: self,
            intent,
        })
    }

    pub fn verify_for_payment<'a>(
        &'a self,
        intent: &'a Bolt11QuoteIntentV1,
        delegation: &Bolt11QuoteKeyDelegationV1,
        parsed_invoice: &ParsedBolt11InvoiceV1,
        now_unix: u64,
    ) -> Result<VerifiedBolt11QuoteV1<'a>, ServiceProtocolError> {
        let verified = self.verify_snapshot(intent, delegation, parsed_invoice, now_unix)?;
        verified.ensure_payable_at(now_unix)?;
        Ok(verified)
    }

    pub fn verify_for_claim_submission<'a>(
        &'a self,
        intent: &'a Bolt11QuoteIntentV1,
        delegation: &Bolt11QuoteKeyDelegationV1,
        parsed_invoice: &ParsedBolt11InvoiceV1,
        now_unix: u64,
    ) -> Result<VerifiedBolt11QuoteV1<'a>, ServiceProtocolError> {
        let verified = self.verify_snapshot(intent, delegation, parsed_invoice, now_unix)?;
        verified.ensure_claim_submission_at(now_unix)?;
        Ok(verified)
    }

    /// Verify a newly polled snapshot relative to an already verified local
    /// snapshot. This prevents an issuer, cache, or restored database from
    /// rolling a client back or presenting two different signed snapshots at
    /// the same state version.
    pub fn verify_latest_after<'a>(
        &'a self,
        previous: &Bolt11QuoteV1,
        intent: &'a Bolt11QuoteIntentV1,
        delegation: &Bolt11QuoteKeyDelegationV1,
        parsed_invoice: &ParsedBolt11InvoiceV1,
        now_unix: u64,
    ) -> Result<VerifiedBolt11QuoteV1<'a>, ServiceProtocolError> {
        previous.verify_snapshot(intent, delegation, parsed_invoice, now_unix)?;
        let verified = self.verify_snapshot(intent, delegation, parsed_invoice, now_unix)?;
        let prior = previous;
        if self.quote_id != prior.quote_id {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.quote_id",
                reason: "status polling cannot replace the original quote",
            });
        }
        if self.state_version < prior.state_version {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.state_version",
                reason: "status snapshot rolls back the locally accepted version",
            });
        }
        if self.state_version == prior.state_version {
            let current = Zeroizing::new(self.encode()?);
            let previous = Zeroizing::new(prior.encode()?);
            if current.as_slice() != previous.as_slice() {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "Bolt11QuoteV1.state_version",
                    reason: "different signed snapshots exist at the same state version",
                });
            }
            return Ok(verified);
        }
        if self.status_updated_at <= prior.status_updated_at
            || !is_observable_quote_successor_v1(prior, self)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.status",
                reason: "status snapshot is not a reachable monotonic successor",
            });
        }
        Ok(verified)
    }

    fn signing_preimage(&self) -> Result<Zeroizing<Vec<u8>>, ServiceProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut out = Zeroizing::new(Vec::with_capacity(
            BOLT11_QUOTE_SIGNATURE_DOMAIN.len() + unsigned.len(),
        ));
        out.extend_from_slice(BOLT11_QUOTE_SIGNATURE_DOMAIN);
        out.extend_from_slice(&unsigned);
        Ok(out)
    }

    fn encode_unsigned(&self) -> Result<Zeroizing<Vec<u8>>, ServiceProtocolError> {
        self.validate_structure()?;
        let mut out = Zeroizing::new(Vec::with_capacity(320 + self.invoice.len()));
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.request_digest);
        out.extend_from_slice(&self.quote_id);
        out.extend_from_slice(&self.quote_key_id);
        put_bytes_u16(&mut out, self.invoice.as_bytes());
        out.push(self.network as u8);
        out.extend_from_slice(&self.payee_pubkey);
        out.extend_from_slice(&self.amount_msat.to_le_bytes());
        out.extend_from_slice(&self.invoice_created_at.to_le_bytes());
        out.extend_from_slice(&self.invoice_expires_at.to_le_bytes());
        out.extend_from_slice(&self.claim_deadline.to_le_bytes());
        out.extend_from_slice(&self.credential_not_after.to_le_bytes());
        out.push(self.status as u8);
        out.extend_from_slice(&self.state_version.to_le_bytes());
        out.extend_from_slice(&self.status_updated_at.to_le_bytes());
        if out.len() + 64 > MAX_BOLT11_QUOTE_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteV1",
                len: out.len() + 64,
                max: MAX_BOLT11_QUOTE_LEN,
            });
        }
        Ok(out)
    }

    fn validate_structure(&self) -> Result<(), ServiceProtocolError> {
        if self.request_digest.iter().all(|byte| *byte == 0)
            || self.quote_id.iter().all(|byte| *byte == 0)
            || self.quote_key_id.iter().all(|byte| *byte == 0)
            || self.amount_msat == 0
            || self.amount_msat > MAX_BITCOIN_MSAT_V1
            || self.invoice_created_at > self.invoice_expires_at
            || self.invoice_expires_at > self.claim_deadline
            || self.claim_deadline > self.credential_not_after
            || self.state_version == 0
            || self.status_updated_at < self.invoice_created_at
            || !is_valid_compressed_point(&self.payee_pubkey)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1",
                reason: "IDs, amount, payee, or quote time ordering is invalid",
            });
        }
        validate_invoice_text(&self.invoice)?;
        let state_version_matches = match self.status {
            Bolt11QuoteStatusV1::InvoiceOpen => self.state_version == 1,
            Bolt11QuoteStatusV1::PaymentSettled
            | Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile => self.state_version == 2,
            Bolt11QuoteStatusV1::LateSettledReconcile => self.state_version == 3,
            Bolt11QuoteStatusV1::CredentialClaimed => {
                self.state_version == 3 || self.state_version == 4
            }
        };
        if !state_version_matches {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.state_version",
                reason: "state version does not match the asserted lifecycle path",
            });
        }
        match self.status {
            Bolt11QuoteStatusV1::InvoiceOpen
                if self.status_updated_at > self.invoice_expires_at =>
            {
                Err(ServiceProtocolError::InvalidValue {
                    field: "Bolt11QuoteV1.status_updated_at",
                    reason: "open status cannot originate after invoice expiry",
                })
            }
            Bolt11QuoteStatusV1::PaymentSettled
                if self.status_updated_at > self.invoice_expires_at =>
            {
                Err(ServiceProtocolError::InvalidValue {
                    field: "Bolt11QuoteV1.status_updated_at",
                    reason: "post-expiry settlement must use late-reconcile status",
                })
            }
            Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile
            | Bolt11QuoteStatusV1::LateSettledReconcile
                if self.status_updated_at < self.invoice_expires_at =>
            {
                Err(ServiceProtocolError::InvalidValue {
                    field: "Bolt11QuoteV1.status_updated_at",
                    reason: "expiry/reconcile status cannot originate before invoice expiry",
                })
            }
            Bolt11QuoteStatusV1::CredentialClaimed
                if self.status_updated_at > self.claim_deadline =>
            {
                Err(ServiceProtocolError::InvalidValue {
                    field: "Bolt11QuoteV1.status_updated_at",
                    reason: "credential claim cannot originate after the claim deadline",
                })
            }
            _ => Ok(()),
        }
    }
}

/// Typestate proving the quote signature, root delegation, exact BOLT11 facts,
/// immutable request terms, and lifecycle timestamp were all checked.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedBolt11QuoteV1<'a> {
    quote: &'a Bolt11QuoteV1,
    intent: &'a Bolt11QuoteIntentV1,
}

/// Issuer-store facts required to verify and advance a persisted quote after
/// restart without retaining the client's raw idempotency key. The exact
/// original request digest remains authoritative; the store's privacy-safe
/// replay image is never substituted for it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PersistedBolt11QuoteExpectationV1<'a> {
    pub issuer_id: &'a [u8; 32],
    pub network: LightningNetworkV1,
    pub payee_pubkey: &'a [u8; 33],
    pub minimum_quote_key_epoch: u64,
    pub quote_delegation_digest: &'a [u8; 32],
    pub request_digest: &'a [u8; 32],
    pub quote_id: &'a [u8; 32],
    pub invoice: &'a str,
    pub amount_msat: u64,
    pub invoice_created_at: u64,
    pub invoice_expires_at: u64,
    pub claim_deadline: u64,
    pub credential_not_after: u64,
}

impl fmt::Debug for PersistedBolt11QuoteExpectationV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedBolt11QuoteExpectationV1")
            .field("network", &self.network)
            .field("payment_artifacts", &"[REDACTED]")
            .finish()
    }
}

/// Evidence that one exact persisted snapshot, root delegation and immutable
/// store record agree. Private fields prevent callers from skipping the
/// signature and recovery-state checks before signing a successor.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedPersistedBolt11QuoteV1<'a> {
    quote: &'a Bolt11QuoteV1,
    expectation: PersistedBolt11QuoteExpectationV1<'a>,
}

impl<'a> VerifiedPersistedBolt11QuoteV1<'a> {
    pub const fn quote(&self) -> &'a Bolt11QuoteV1 {
        self.quote
    }

    pub const fn expectation(&self) -> PersistedBolt11QuoteExpectationV1<'a> {
        self.expectation
    }
}

impl<'a> VerifiedBolt11QuoteV1<'a> {
    pub const fn quote(&self) -> &'a Bolt11QuoteV1 {
        self.quote
    }

    pub const fn intent(&self) -> &'a Bolt11QuoteIntentV1 {
        self.intent
    }

    pub fn ensure_payable_at(&self, now_unix: u64) -> Result<(), ServiceProtocolError> {
        if self.quote.status != Bolt11QuoteStatusV1::InvoiceOpen
            || now_unix < self.quote.invoice_created_at
            || now_unix > self.quote.invoice_expires_at
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.payment",
                reason: "quote is not open and unexpired",
            });
        }
        Ok(())
    }

    pub fn ensure_claim_submission_at(&self, now_unix: u64) -> Result<(), ServiceProtocolError> {
        let eligible_status = matches!(
            self.quote.status,
            Bolt11QuoteStatusV1::PaymentSettled | Bolt11QuoteStatusV1::LateSettledReconcile
        );
        // An already-claimed quote remains recoverable with the exact durable
        // idempotency request even after the claim deadline. The issuer store
        // must reject a different request for that quote.
        let idempotent_recovery = self.quote.status == Bolt11QuoteStatusV1::CredentialClaimed;
        if now_unix < self.quote.invoice_created_at
            || (!idempotent_recovery && (!eligible_status || now_unix > self.quote.claim_deadline))
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.claim",
                reason: "payment is not settled or the claim window has ended",
            });
        }
        Ok(())
    }
}

impl Bolt11QuoteV1 {
    /// Verify the exact current snapshot against a durable issuer-store row.
    /// This is the restart-safe counterpart of `verify_snapshot`: it does not
    /// need the raw quote intent (and therefore does not require retaining the
    /// raw HTTP idempotency key), but it repeats every immutable-field,
    /// root-delegation and quote-signature check needed for a transition.
    pub fn verify_persisted_for_transition<'a>(
        &'a self,
        expected: PersistedBolt11QuoteExpectationV1<'a>,
        delegation: &Bolt11QuoteKeyDelegationV1,
        now_unix: u64,
    ) -> Result<VerifiedPersistedBolt11QuoteV1<'a>, ServiceProtocolError> {
        self.validate_structure()?;
        validate_persisted_quote_expectation(&expected)?;
        if delegation.delegation_digest()? != *expected.quote_delegation_digest
            || self.request_digest != *expected.request_digest
            || self.quote_id != *expected.quote_id
            || self.invoice != expected.invoice
            || self.network != expected.network
            || self.payee_pubkey != *expected.payee_pubkey
            || self.amount_msat != expected.amount_msat
            || self.invoice_created_at != expected.invoice_created_at
            || self.invoice_expires_at != expected.invoice_expires_at
            || self.claim_deadline != expected.claim_deadline
            || self.credential_not_after != expected.credential_not_after
            || self.invoice_created_at > now_unix
            || self.status_updated_at > now_unix
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PersistedBolt11QuoteExpectationV1",
                reason: "persisted quote facts, delegation, or observation time mismatch",
            });
        }
        let quote_verifying_key = delegation.verify_for(
            expected.issuer_id,
            expected.network,
            expected.payee_pubkey,
            expected.minimum_quote_key_epoch,
            self.invoice_created_at,
        )?;
        delegation.verify_for(
            expected.issuer_id,
            expected.network,
            expected.payee_pubkey,
            expected.minimum_quote_key_epoch,
            self.status_updated_at,
        )?;
        delegation.verify_for(
            expected.issuer_id,
            expected.network,
            expected.payee_pubkey,
            expected.minimum_quote_key_epoch,
            self.claim_deadline,
        )?;
        if self.quote_key_id != delegation.quote_key_id {
            return Err(ServiceProtocolError::WrongSigningKeyId);
        }
        quote_verifying_key
            .verify_strict(
                &self.signing_preimage()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ServiceProtocolError::BadSignature)?;
        Ok(VerifiedPersistedBolt11QuoteV1 {
            quote: self,
            expectation: expected,
        })
    }

    /// Sign one legal lifecycle successor from a fully verified persisted
    /// snapshot. This API is intentionally unable to create an initial quote.
    pub fn with_status_from_verified_persisted_snapshot(
        verified: &VerifiedPersistedBolt11QuoteV1<'_>,
        status: Bolt11QuoteStatusV1,
        status_updated_at: u64,
        delegation: &Bolt11QuoteKeyDelegationV1,
        quote_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let previous = verified.quote;
        let expected = verified.expectation;
        if !previous.status.allows_transition_to(status) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteStatusV1.transition",
                reason: "invalid persisted quote status transition",
            });
        }
        if status == previous.status && status_updated_at != previous.status_updated_at {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.status_updated_at",
                reason: "an idempotent status replay must preserve the exact transition time",
            });
        }
        if status != previous.status && status_updated_at <= previous.status_updated_at {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteV1.status_updated_at",
                reason: "status transition time must strictly increase",
            });
        }
        if delegation.delegation_digest()? != *expected.quote_delegation_digest
            || quote_signing_key.verifying_key().to_bytes() != delegation.quote_verifying_key
        {
            return Err(ServiceProtocolError::WrongSigningKeyId);
        }
        delegation.verify_for(
            expected.issuer_id,
            expected.network,
            expected.payee_pubkey,
            expected.minimum_quote_key_epoch,
            status_updated_at,
        )?;
        delegation.verify_for(
            expected.issuer_id,
            expected.network,
            expected.payee_pubkey,
            expected.minimum_quote_key_epoch,
            previous.claim_deadline,
        )?;

        let mut next = previous.clone();
        next.status = status;
        if status != previous.status {
            next.state_version = previous.state_version.checked_add(1).ok_or(
                ServiceProtocolError::InvalidValue {
                    field: "Bolt11QuoteV1.state_version",
                    reason: "state version overflow",
                },
            )?;
        }
        next.status_updated_at = status_updated_at;
        next.signature = [0; 64];
        next.validate_structure()?;
        next.signature = quote_signing_key.sign(&next.signing_preimage()?).to_bytes();
        Ok(next)
    }
}

fn validate_persisted_quote_expectation(
    expected: &PersistedBolt11QuoteExpectationV1<'_>,
) -> Result<(), ServiceProtocolError> {
    if expected.issuer_id.iter().all(|byte| *byte == 0)
        || expected.payee_pubkey.iter().all(|byte| *byte == 0)
        || expected.minimum_quote_key_epoch == 0
        || expected
            .quote_delegation_digest
            .iter()
            .all(|byte| *byte == 0)
        || expected.request_digest.iter().all(|byte| *byte == 0)
        || expected.quote_id.iter().all(|byte| *byte == 0)
        || expected.invoice.is_empty()
        || expected.amount_msat == 0
        || expected.amount_msat > MAX_BITCOIN_MSAT_V1
        || expected.invoice_created_at == 0
        || expected.invoice_created_at > expected.invoice_expires_at
        || expected.invoice_expires_at > expected.claim_deadline
        || expected.claim_deadline > expected.credential_not_after
        || !is_valid_compressed_point(expected.payee_pubkey)
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "PersistedBolt11QuoteExpectationV1",
            reason: "persisted quote identity, amount, invoice, or horizon is invalid",
        });
    }
    validate_invoice_text(expected.invoice)
}

fn is_observable_quote_successor_v1(previous: &Bolt11QuoteV1, next: &Bolt11QuoteV1) -> bool {
    use Bolt11QuoteStatusV1::{
        CredentialClaimed, InvoiceExpiredPendingReconcile, InvoiceOpen, LateSettledReconcile,
        PaymentSettled,
    };

    matches!(
        (
            previous.status,
            previous.state_version,
            next.status,
            next.state_version,
        ),
        (InvoiceOpen, 1, PaymentSettled, 2)
            | (InvoiceOpen, 1, CredentialClaimed, 3)
            | (InvoiceOpen, 1, InvoiceExpiredPendingReconcile, 2)
            | (InvoiceOpen, 1, LateSettledReconcile, 3)
            | (InvoiceOpen, 1, CredentialClaimed, 4)
            | (PaymentSettled, 2, CredentialClaimed, 3)
            | (InvoiceExpiredPendingReconcile, 2, LateSettledReconcile, 3)
            | (InvoiceExpiredPendingReconcile, 2, CredentialClaimed, 4)
            | (LateSettledReconcile, 3, CredentialClaimed, 4)
    )
}

/// Authenticated request for one quote status snapshot. This is an HTTP
/// issuer message, never a PIR wire message. Servers must accept it only over
/// TLS, verify the returned BIP340 tuple, and atomically consume
/// `(quote_id, request_nonce)` until the freshness window has elapsed before
/// returning an invoice or status.
#[derive(Clone, PartialEq, Eq)]
pub struct Bolt11QuoteStatusRequestV1 {
    pub issuer_id: [u8; 32],
    pub quote_id: [u8; 32],
    pub quote_request_digest: [u8; 32],
    pub claim_pubkey_xonly: [u8; 32],
    pub requested_at: u64,
    pub request_nonce: [u8; 32],
    pub signature: [u8; 64],
}

impl fmt::Debug for Bolt11QuoteStatusRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bolt11QuoteStatusRequestV1")
            .field("private_status_request", &"[REDACTED]")
            .finish()
    }
}

impl Drop for Bolt11QuoteStatusRequestV1 {
    fn drop(&mut self) {
        self.request_nonce.zeroize();
        self.signature.zeroize();
    }
}

impl Bolt11QuoteStatusRequestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_BOLT11_QUOTE_STATUS_REQUEST_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteStatusRequestV1",
                len: out.len(),
                max: MAX_BOLT11_QUOTE_STATUS_REQUEST_LEN,
            });
        }
        Ok(std::mem::take(&mut *out))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_BOLT11_QUOTE_STATUS_REQUEST_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteStatusRequestV1",
                len: bytes.len(),
                max: MAX_BOLT11_QUOTE_STATUS_REQUEST_LEN,
            });
        }
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("Bolt11QuoteStatusRequestV1.version")?;
        expect_v1(version, "Bolt11QuoteStatusRequestV1")?;
        let value = Self {
            issuer_id: decoder.fixed("Bolt11QuoteStatusRequestV1.issuer_id")?,
            quote_id: decoder.fixed("Bolt11QuoteStatusRequestV1.quote_id")?,
            quote_request_digest: decoder
                .fixed("Bolt11QuoteStatusRequestV1.quote_request_digest")?,
            claim_pubkey_xonly: decoder.fixed("Bolt11QuoteStatusRequestV1.claim_pubkey_xonly")?,
            requested_at: decoder.u64("Bolt11QuoteStatusRequestV1.requested_at")?,
            request_nonce: decoder.fixed("Bolt11QuoteStatusRequestV1.request_nonce")?,
            signature: decoder.fixed("Bolt11QuoteStatusRequestV1.signature")?,
        };
        decoder.finish()?;
        value.validate_structure()?;
        Ok(value)
    }

    /// Exact BIP340 message signed by the quote's claim key.
    pub fn bip340_signing_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(BOLT11_QUOTE_STATUS_REQUEST_SIGNATURE_DOMAIN_V1);
        let unsigned = self.encode_unsigned()?;
        hasher.update(&unsigned);
        Ok(hasher.finalize().into())
    }

    /// Bind this request to the issuer's durable quote intent and enforce a
    /// bounded freshness window. The caller must still verify the returned
    /// BIP340 tuple and atomically reject a reused nonce before disclosure.
    pub fn unverified_bip340_input_for(
        &self,
        intent: &Bolt11QuoteIntentV1,
        expected_quote_id: &[u8; 32],
        now_unix: u64,
    ) -> Result<UnverifiedBip340QuoteStatusRequestV1, ServiceProtocolError> {
        self.validate_structure()?;
        intent.validate()?;
        if &self.quote_id != expected_quote_id
            || self.issuer_id != intent.issuer_id
            || self.quote_request_digest != intent.request_digest()?
            || self.claim_pubkey_xonly != intent.claim_pubkey_xonly
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteStatusRequestV1.binding",
                reason: "issuer, quote, request, or x-only claim key mismatch",
            });
        }
        if self.requested_at > now_unix
            || now_unix.saturating_sub(self.requested_at)
                > MAX_BOLT11_QUOTE_STATUS_REQUEST_AGE_SECONDS_V1
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteStatusRequestV1.requested_at",
                reason: "status request is from the future or outside the freshness window",
            });
        }
        Ok(UnverifiedBip340QuoteStatusRequestV1 {
            claim_pubkey_xonly: self.claim_pubkey_xonly,
            message_digest: self.bip340_signing_digest()?,
            signature: self.signature,
            quote_id: self.quote_id,
            requested_at: self.requested_at,
            request_nonce: self.request_nonce,
        })
    }

    fn encode_unsigned(&self) -> Result<Zeroizing<Vec<u8>>, ServiceProtocolError> {
        self.validate_structure()?;
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_BOLT11_QUOTE_STATUS_REQUEST_LEN - 64));
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.quote_id);
        out.extend_from_slice(&self.quote_request_digest);
        out.extend_from_slice(&self.claim_pubkey_xonly);
        out.extend_from_slice(&self.requested_at.to_le_bytes());
        out.extend_from_slice(&self.request_nonce);
        Ok(out)
    }

    fn validate_structure(&self) -> Result<(), ServiceProtocolError> {
        if self.issuer_id.iter().all(|byte| *byte == 0)
            || self.quote_id.iter().all(|byte| *byte == 0)
            || self.quote_request_digest.iter().all(|byte| *byte == 0)
            || self.requested_at == 0
            || self.request_nonce.iter().all(|byte| *byte == 0)
            || self.signature.iter().all(|byte| *byte == 0)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteStatusRequestV1",
                reason: "issuer, quote, request, time, nonce, and signature must be non-zero",
            });
        }
        validate_xonly_pubkey(&self.claim_pubkey_xonly)
    }
}

/// Explicitly unverified BIP340 tuple plus the fields an issuer must use for
/// freshness/replay bookkeeping before returning private quote data.
#[derive(Clone, PartialEq, Eq)]
pub struct UnverifiedBip340QuoteStatusRequestV1 {
    pub claim_pubkey_xonly: [u8; 32],
    pub message_digest: [u8; 32],
    pub signature: [u8; 64],
    pub quote_id: [u8; 32],
    pub requested_at: u64,
    pub request_nonce: [u8; 32],
}

impl fmt::Debug for UnverifiedBip340QuoteStatusRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnverifiedBip340QuoteStatusRequestV1")
            .field("private_status_request", &"[REDACTED]")
            .finish()
    }
}

impl Drop for UnverifiedBip340QuoteStatusRequestV1 {
    fn drop(&mut self) {
        self.message_digest.zeroize();
        self.signature.zeroize();
        self.request_nonce.zeroize();
    }
}

/// Canonical claim of a paid quote. The signature is BIP340 over
/// `bip340_signing_digest`; no compressed 33-byte claim key is accepted.
#[derive(Clone, PartialEq, Eq)]
pub struct Bolt11QuoteClaimV1 {
    pub issuer_id: [u8; 32],
    pub quote_id: [u8; 32],
    pub quote_request_digest: [u8; 32],
    /// Digest of the exact ordered, canonical credential issuance request.
    /// The caller must persist that request before posting this claim.
    pub credential_request_digest: [u8; 32],
    pub claim_pubkey_xonly: [u8; 32],
    pub idempotency_key: [u8; 32],
    pub signature: [u8; 64],
}

impl fmt::Debug for Bolt11QuoteClaimV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bolt11QuoteClaimV1")
            .field("claim", &"[REDACTED]")
            .finish()
    }
}

impl Drop for Bolt11QuoteClaimV1 {
    fn drop(&mut self) {
        self.idempotency_key.zeroize();
        self.signature.zeroize();
    }
}

impl Bolt11QuoteClaimV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_BOLT11_QUOTE_CLAIM_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteClaimV1",
                len: out.len(),
                max: MAX_BOLT11_QUOTE_CLAIM_LEN,
            });
        }
        Ok(std::mem::take(&mut *out))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_BOLT11_QUOTE_CLAIM_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "Bolt11QuoteClaimV1",
                len: bytes.len(),
                max: MAX_BOLT11_QUOTE_CLAIM_LEN,
            });
        }
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("Bolt11QuoteClaimV1.version")?;
        expect_v1(version, "Bolt11QuoteClaimV1")?;
        let value = Self {
            issuer_id: decoder.fixed("Bolt11QuoteClaimV1.issuer_id")?,
            quote_id: decoder.fixed("Bolt11QuoteClaimV1.quote_id")?,
            quote_request_digest: decoder.fixed("Bolt11QuoteClaimV1.quote_request_digest")?,
            credential_request_digest: decoder
                .fixed("Bolt11QuoteClaimV1.credential_request_digest")?,
            claim_pubkey_xonly: decoder.fixed("Bolt11QuoteClaimV1.claim_pubkey_xonly")?,
            idempotency_key: decoder.fixed("Bolt11QuoteClaimV1.idempotency_key")?,
            signature: decoder.fixed("Bolt11QuoteClaimV1.signature")?,
        };
        decoder.finish()?;
        value.validate_structure()?;
        Ok(value)
    }

    /// The exact 32-byte message an upper layer MUST verify with a BIP340
    /// implementation before issuing credentials.
    pub fn bip340_signing_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(BOLT11_QUOTE_CLAIM_SIGNATURE_DOMAIN);
        hasher.update(self.encode_unsigned()?);
        Ok(hasher.finalize().into())
    }

    /// Digest of the exact signed HTTP claim request, suitable for durable
    /// idempotency comparison and exact-response replay.
    pub fn claim_request_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(BOLT11_QUOTE_CLAIM_REQUEST_DIGEST_DOMAIN);
        let encoded = Zeroizing::new(self.encode()?);
        hasher.update(&encoded);
        Ok(hasher.finalize().into())
    }

    /// Validate the quote/claim binding and return an explicitly *unverified*
    /// BIP340 tuple. The issuer MUST verify this tuple with a conforming BIP340
    /// library before minting or returning any credential. This crate does not
    /// enable k256's Schnorr feature, so merely obtaining this value is never
    /// proof of claim-key possession.
    pub fn unverified_bip340_input_for(
        &self,
        verified_quote: &VerifiedBolt11QuoteV1<'_>,
        now_unix: u64,
    ) -> Result<UnverifiedBip340ClaimV1, ServiceProtocolError> {
        self.validate_structure()?;
        verified_quote.ensure_claim_submission_at(now_unix)?;
        let quote = verified_quote.quote();
        let intent = verified_quote.intent();
        if self.issuer_id != intent.issuer_id
            || self.quote_id != quote.quote_id
            || self.quote_request_digest != quote.request_digest
            || self.claim_pubkey_xonly != intent.claim_pubkey_xonly
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteClaimV1.binding",
                reason: "issuer, quote, request, or x-only claim key mismatch",
            });
        }
        Ok(UnverifiedBip340ClaimV1 {
            claim_pubkey_xonly: self.claim_pubkey_xonly,
            message_digest: self.bip340_signing_digest()?,
            signature: self.signature,
        })
    }

    fn encode_unsigned(&self) -> Result<Zeroizing<Vec<u8>>, ServiceProtocolError> {
        self.validate_structure()?;
        let mut out = Zeroizing::new(Vec::with_capacity(256));
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.quote_id);
        out.extend_from_slice(&self.quote_request_digest);
        out.extend_from_slice(&self.credential_request_digest);
        out.extend_from_slice(&self.claim_pubkey_xonly);
        out.extend_from_slice(&self.idempotency_key);
        Ok(out)
    }

    fn validate_structure(&self) -> Result<(), ServiceProtocolError> {
        if self.issuer_id.iter().all(|byte| *byte == 0)
            || self.quote_id.iter().all(|byte| *byte == 0)
            || self.quote_request_digest.iter().all(|byte| *byte == 0)
            || self.credential_request_digest.iter().all(|byte| *byte == 0)
            || self.idempotency_key.iter().all(|byte| *byte == 0)
            || self.signature.iter().all(|byte| *byte == 0)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteClaimV1",
                reason:
                    "issuer, quote, request digests, idempotency, and signature must be non-zero",
            });
        }
        validate_xonly_pubkey(&self.claim_pubkey_xonly)
    }
}

/// Deliberately named to prevent callers mistaking transcript construction for
/// signature verification.
#[derive(Clone, PartialEq, Eq)]
pub struct UnverifiedBip340ClaimV1 {
    pub claim_pubkey_xonly: [u8; 32],
    pub message_digest: [u8; 32],
    pub signature: [u8; 64],
}

impl fmt::Debug for UnverifiedBip340ClaimV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnverifiedBip340ClaimV1")
            .field("claim", &"[REDACTED]")
            .finish()
    }
}

impl Drop for UnverifiedBip340ClaimV1 {
    fn drop(&mut self) {
        self.message_digest.zeroize();
        self.signature.zeroize();
    }
}

pub fn bolt11_invoice_text_digest_v1(invoice: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BOLT11_INVOICE_TEXT_DIGEST_DOMAIN);
    hasher.update((invoice.len() as u32).to_le_bytes());
    hasher.update(invoice.as_bytes());
    hasher.finalize().into()
}

fn validate_invoice_text(invoice: &str) -> Result<(), ServiceProtocolError> {
    if invoice.is_empty()
        || invoice.len() > MAX_BOLT11_INVOICE_LEN
        || !invoice.starts_with("ln")
        || !invoice.is_ascii()
        || !invoice
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "Bolt11QuoteV1.invoice",
            reason: "must be a bounded canonical lowercase ASCII BOLT11 string",
        });
    }
    Ok(())
}

fn validate_xonly_pubkey(key: &[u8; 32]) -> Result<(), ServiceProtocolError> {
    let mut even_y_point = [0u8; 33];
    even_y_point[0] = 0x02;
    even_y_point[1..].copy_from_slice(key);
    if !is_valid_compressed_point(&even_y_point) {
        return Err(ServiceProtocolError::InvalidValue {
            field: "BIP340.xonly_pubkey",
            reason: "must be the x-coordinate of a secp256k1 point",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_bat_key_id_v1, AuthPaddingClassV1, BackendId, CredentialKeyBindingClaimsV1,
        CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1, DeploymentStatus,
        EntitlementLimitsV1, FreeModeV1, PolicyRollbackGuardV1, PrivacyLeakageV1, ServiceOfferV1,
        ServicePolicyEpochFloorsV1, ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1,
        VerificationMode, WorkloadId,
    };
    #[cfg(not(target_family = "wasm"))]
    use bitcoin::hashes::{sha256, Hash};
    #[cfg(not(target_family = "wasm"))]
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};
    #[cfg(not(target_family = "wasm"))]
    use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
    #[cfg(not(target_family = "wasm"))]
    use std::time::Duration;

    const CREATED_AT: u64 = 1_000;
    const INVOICE_EXPIRY: u32 = 600;
    const CLAIM_WINDOW: u32 = 900;
    const CREDENTIAL_VALIDITY: u32 = 3_600;
    const INVOICE: &str = "lnbc10u1qqqqqqqq";
    // BOLT 11 reference vector, mirrored by rust-lightning's upstream tests.
    // It omits the `n` field, so the payee below must be recovered from the
    // verified compact signature.
    #[cfg(not(target_family = "wasm"))]
    const OFFICIAL_FIXED_AMOUNT_INVOICE: &str = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
    #[cfg(not(target_family = "wasm"))]
    const OFFICIAL_AMOUNTLESS_INVOICE: &str = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";

    #[cfg(not(target_family = "wasm"))]
    fn signed_test_invoice(
        currency: Currency,
        amount_msat: Option<u64>,
        include_payee: bool,
        signing_secret_byte: u8,
    ) -> (String, [u8; 33]) {
        let secp = Secp256k1::new();
        let payee_secret = SecretKey::from_slice(&[42; 32]).unwrap();
        let signer_secret = SecretKey::from_slice(&[signing_secret_byte; 32]).unwrap();
        let payee = PublicKey::from_secret_key(&secp, &payee_secret);
        let mut builder = InvoiceBuilder::new(currency)
            .description("BitcoinPIR parser test".to_owned())
            .payment_hash(sha256::Hash::hash(b"BitcoinPIR/BOLT11/test-payment-hash"))
            .duration_since_epoch(Duration::from_secs(1_700_000_000))
            .min_final_cltv_expiry_delta(18)
            .payment_secret(PaymentSecret([17; 32]))
            .expiry_time(Duration::from_secs(600));
        if let Some(amount_msat) = amount_msat {
            builder = builder.amount_milli_satoshis(amount_msat);
        }
        if include_payee {
            builder = builder.payee_pub_key(payee);
        }
        let invoice = builder
            .build_signed(|message| secp.sign_ecdsa_recoverable(message, &signer_secret))
            .unwrap()
            .to_string();
        (invoice, payee.serialize())
    }

    fn compressed_point(multiplier: u64) -> [u8; 33] {
        let point = (ProjectivePoint::GENERATOR * Scalar::from(multiplier))
            .to_affine()
            .to_encoded_point(true);
        point.as_bytes().try_into().unwrap()
    }

    fn xonly_point(multiplier: u64) -> [u8; 32] {
        compressed_point(multiplier)[1..].try_into().unwrap()
    }

    fn fixture() -> (
        SigningKey,
        SigningKey,
        Bolt11QuoteKeyDelegationV1,
        Bolt11QuoteIntentV1,
        ParsedBolt11InvoiceV1,
    ) {
        let issuer_key = SigningKey::from_bytes(&[7; 32]);
        let quote_key = SigningKey::from_bytes(&[8; 32]);
        let payee = compressed_point(3);
        let delegation = Bolt11QuoteKeyDelegationV1::sign(
            LightningNetworkV1::Bitcoin,
            payee,
            4,
            100,
            20_000,
            quote_key.verifying_key().to_bytes(),
            &issuer_key,
        )
        .unwrap();
        let intent = Bolt11QuoteIntentV1 {
            issuer_id: delegation.issuer_id,
            provider_id: [2; 32],
            policy_digest: [3; 32],
            scope_id: [4; 32],
            offer_id: 9,
            network: LightningNetworkV1::Bitcoin,
            expected_payee_pubkey: payee,
            minimum_quote_key_epoch: 4,
            quote_delegation_digest: delegation.delegation_digest().unwrap(),
            authorization: AuthScheme::BitcoinPirCashuBatV1,
            credential_binding_digest: [5; 32],
            credential_key_id: vec![6; 32],
            exact_amount_msat: 1_000_000,
            entitlement_profile: 3,
            credential_count: 8,
            credential_presentation_limit: 1,
            invoice_expiry_seconds: INVOICE_EXPIRY,
            claim_window_seconds: CLAIM_WINDOW,
            minimum_credential_validity_seconds: CREDENTIAL_VALIDITY,
            claim_pubkey_xonly: xonly_point(5),
            idempotency_key: [9; 32],
        };
        let parsed_invoice = ParsedBolt11InvoiceV1::from_signature_verified_invoice(
            INVOICE,
            LightningNetworkV1::Bitcoin,
            payee,
            intent.exact_amount_msat,
            CREATED_AT,
            INVOICE_EXPIRY,
        )
        .unwrap();
        (issuer_key, quote_key, delegation, intent, parsed_invoice)
    }

    fn open_quote(
        quote_key: &SigningKey,
        delegation: &Bolt11QuoteKeyDelegationV1,
        intent: &Bolt11QuoteIntentV1,
    ) -> Bolt11QuoteV1 {
        Bolt11QuoteV1::sign(
            intent,
            [10; 32],
            INVOICE.into(),
            CREATED_AT,
            Bolt11QuoteStatusV1::InvoiceOpen,
            CREATED_AT,
            delegation,
            quote_key,
        )
        .unwrap()
    }

    fn persisted_expectation<'a>(
        quote: &'a Bolt11QuoteV1,
        intent: &'a Bolt11QuoteIntentV1,
    ) -> PersistedBolt11QuoteExpectationV1<'a> {
        PersistedBolt11QuoteExpectationV1 {
            issuer_id: &intent.issuer_id,
            network: intent.network,
            payee_pubkey: &intent.expected_payee_pubkey,
            minimum_quote_key_epoch: intent.minimum_quote_key_epoch,
            quote_delegation_digest: &intent.quote_delegation_digest,
            request_digest: &quote.request_digest,
            quote_id: &quote.quote_id,
            invoice: &quote.invoice,
            amount_msat: quote.amount_msat,
            invoice_created_at: quote.invoice_created_at,
            invoice_expires_at: quote.invoice_expires_at,
            claim_deadline: quote.claim_deadline,
            credential_not_after: quote.credential_not_after,
        }
    }

    #[test]
    fn payment_artifact_debug_redacts_invoice_and_replay_authority() {
        assert!(core::mem::needs_drop::<Bolt11QuoteIntentV1>());
        assert!(core::mem::needs_drop::<Bolt11QuoteV1>());
        assert!(core::mem::needs_drop::<Bolt11QuoteStatusRequestV1>());
        assert!(core::mem::needs_drop::<Bolt11QuoteClaimV1>());
        assert!(core::mem::needs_drop::<UnverifiedBip340ClaimV1>());
        assert!(core::mem::needs_drop::<UnverifiedBip340QuoteStatusRequestV1>());

        let (_, quote_key, delegation, intent, _) = fixture();
        let quote = open_quote(&quote_key, &delegation, &intent);
        let status = Bolt11QuoteStatusRequestV1 {
            issuer_id: intent.issuer_id,
            quote_id: quote.quote_id,
            quote_request_digest: quote.request_digest,
            claim_pubkey_xonly: intent.claim_pubkey_xonly,
            requested_at: CREATED_AT,
            request_nonce: [0x51; 32],
            signature: [0x52; 64],
        };
        let claim = Bolt11QuoteClaimV1 {
            issuer_id: intent.issuer_id,
            quote_id: quote.quote_id,
            quote_request_digest: quote.request_digest,
            credential_request_digest: [0x53; 32],
            claim_pubkey_xonly: intent.claim_pubkey_xonly,
            idempotency_key: [0x54; 32],
            signature: [0x55; 64],
        };
        let rendered = format!(
            "{intent:?} {quote:?} {status:?} {claim:?} {:?}",
            persisted_expectation(&quote, &intent)
        );
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(INVOICE));
        for canary in [
            format!("{:?}", intent.idempotency_key),
            format!("{:?}", status.request_nonce),
            format!("{:?}", status.signature),
            format!("{:?}", claim.idempotency_key),
            format!("{:?}", claim.signature),
        ] {
            assert!(!rendered.contains(&canary));
        }
    }

    fn verified_offer_fixture() -> (
        ServicePolicyV1,
        VerifyingKey,
        Bolt11QuoteKeyDelegationV1,
        [u8; 33],
    ) {
        let provider_id = [2; 32];
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 2,
            entitlement_profile: 3,
        };
        let issuer_key = SigningKey::from_bytes(&[7; 32]);
        let credential_verification_key = compressed_point(11);
        let credential_key_id = derive_bat_key_id_v1(
            &provider_id,
            &scope.scope_id(),
            9,
            scope.entitlement_profile,
            1,
            &credential_verification_key,
        )
        .to_vec();
        let credential_binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id: scope.scope_id(),
                offer_id: 9,
                scheme: AuthScheme::BitcoinPirCashuBatV1,
                keyset_epoch: 1,
                entitlement_profile: scope.entitlement_profile,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 1,
                not_before: 50,
                not_after: 6_000,
                credential_key_id: credential_key_id.clone(),
                verification_key: credential_verification_key.to_vec(),
            },
            &issuer_key,
        )
        .unwrap();
        let offer = ServiceOfferV1 {
            offer_id: 9,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::BitcoinPirCashuBatV1,
            verification: VerificationMode::SharedIssuerOnline,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::MilliSatoshi(100_000),
            issuer_id: credential_binding.issuer_id,
            key_id: credential_key_id,
            credential_binding: Some(credential_binding),
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".into(),
            invoice_expiry_seconds: INVOICE_EXPIRY,
            claim_window_seconds: CLAIM_WINDOW,
            minimum_credential_validity_seconds: CREDENTIAL_VALIDITY,
            retired_policy_grace_seconds: 5_500,
            credential_count: 8,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                    | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .unwrap(),
        };
        let policy_key = SigningKey::from_bytes(&[3; 32]);
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            100,
            500,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 10,
                    max_request_bytes: 10_000,
                    max_response_bytes: 20_000,
                    max_wall_time_ms: 1_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 100,
                },
                offers: vec![offer],
            }],
            &policy_key,
        )
        .unwrap();
        let payee = compressed_point(3);
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
        (policy, policy_key.verifying_key(), delegation, payee)
    }

    #[test]
    fn quote_key_delegation_roundtrips_and_rejects_tampering() {
        let (_, _, delegation, intent, _) = fixture();
        let encoded = delegation.encode().unwrap();
        let decoded = Bolt11QuoteKeyDelegationV1::decode(&encoded).unwrap();
        assert_eq!(decoded, delegation);
        decoded
            .verify_for(
                &intent.issuer_id,
                intent.network,
                &intent.expected_payee_pubkey,
                intent.minimum_quote_key_epoch,
                CREATED_AT,
            )
            .unwrap();

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            Bolt11QuoteKeyDelegationV1::decode(&trailing),
            Err(ServiceProtocolError::TrailingBytes(1))
        ));

        let mut unknown_network = encoded.clone();
        unknown_network[65] = 0xff;
        assert!(matches!(
            Bolt11QuoteKeyDelegationV1::decode(&unknown_network),
            Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "LightningNetworkV1",
                value: 0xff
            })
        ));

        let mut bad_signature = delegation.clone();
        bad_signature.signature[0] ^= 1;
        assert_eq!(
            bad_signature.verify_for(
                &intent.issuer_id,
                intent.network,
                &intent.expected_payee_pubkey,
                4,
                CREATED_AT,
            ),
            Err(ServiceProtocolError::BadSignature)
        );
        assert!(delegation
            .verify_for(
                &intent.issuer_id,
                LightningNetworkV1::Testnet,
                &intent.expected_payee_pubkey,
                4,
                CREATED_AT,
            )
            .is_err());
        assert!(delegation
            .verify_for(
                &intent.issuer_id,
                intent.network,
                &intent.expected_payee_pubkey,
                5,
                CREATED_AT,
            )
            .is_err());
    }

    #[test]
    fn quote_key_id_commits_to_the_exact_validity_window() {
        let (issuer_key, quote_key, delegation, intent, _) = fixture();
        let different_window = Bolt11QuoteKeyDelegationV1::sign(
            intent.network,
            intent.expected_payee_pubkey,
            delegation.key_epoch,
            delegation.not_before,
            delegation.not_after + 1,
            quote_key.verifying_key().to_bytes(),
            &issuer_key,
        )
        .unwrap();

        assert_ne!(delegation.quote_key_id, different_window.quote_key_id);
        let guard = Bolt11QuoteKeyRollbackGuardV1::initial(
            delegation.issuer_id,
            intent.network,
            intent.expected_payee_pubkey,
        )
        .unwrap();
        let advanced = guard.verify_and_advance(&delegation, CREATED_AT).unwrap();
        assert_eq!(
            advanced
                .verify_and_advance(&delegation, CREATED_AT)
                .unwrap(),
            advanced
        );
        assert!(advanced
            .verify_and_advance(&different_window, CREATED_AT)
            .is_err());
    }

    #[test]
    fn quote_intent_roundtrips_and_idempotency_is_digest_bound() {
        let (_, _, _, intent, _) = fixture();
        let encoded = intent.encode().unwrap();
        assert_eq!(Bolt11QuoteIntentV1::decode(&encoded).unwrap(), intent);

        let mut same = intent.clone();
        assert_eq!(
            same.request_digest().unwrap(),
            intent.request_digest().unwrap()
        );
        same.idempotency_key[0] ^= 1;
        assert_ne!(
            same.request_digest().unwrap(),
            intent.request_digest().unwrap()
        );

        let mut changed_profile = intent.clone();
        changed_profile.entitlement_profile += 1;
        assert_ne!(
            changed_profile.request_digest().unwrap(),
            intent.request_digest().unwrap()
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            Bolt11QuoteIntentV1::decode(&trailing),
            Err(ServiceProtocolError::TrailingBytes(1))
        ));

        // The authorization byte follows version, four 32-byte IDs, offer,
        // network, payee, quote-key epoch, and exact delegation digest.
        let mut unknown_auth = encoded;
        let authorization_offset = 1 + (4 * 32) + 4 + 1 + 33 + 8 + 32;
        unknown_auth[authorization_offset] = 0xff;
        assert!(matches!(
            Bolt11QuoteIntentV1::decode(&unknown_auth),
            Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "AuthScheme",
                value: 0xff
            })
        ));
    }

    #[test]
    fn quote_intent_rejects_bounds_invalid_points_and_time_overflow() {
        let (_, _, _, intent, _) = fixture();

        let mut bad = intent.clone();
        bad.credential_count = MAX_CREDENTIALS_PER_ACQUISITION_V1;
        bad.credential_presentation_limit = MAX_CREDENTIAL_PRESENTATIONS_V1;
        assert!(bad.encode().is_err());

        let mut bad = intent.clone();
        bad.claim_pubkey_xonly = [0xff; 32];
        assert!(bad.encode().is_err());

        let mut bad = intent.clone();
        bad.exact_amount_msat = MAX_BITCOIN_MSAT_V1 + 1;
        assert!(bad.encode().is_err());

        let mut bad = intent.clone();
        bad.authorization = AuthScheme::ArcV1Experimental;
        bad.credential_presentation_limit = 1;
        assert!(matches!(
            bad.encode(),
            Err(ServiceProtocolError::InvalidValue {
                field: "Bolt11QuoteIntentV1.credential_presentation_limit",
                ..
            })
        ));

        let mut bad = intent.clone();
        bad.invoice_expiry_seconds = MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1 + 1;
        assert!(bad.encode().is_err());

        assert!(intent.derived_horizons(u64::MAX - 1).is_err());
    }

    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn concrete_bolt11_parser_accepts_official_vector_and_recovers_payee() {
        let parsed = ParsedBolt11InvoiceV1::parse(OFFICIAL_FIXED_AMOUNT_INVOICE).unwrap();
        assert_eq!(parsed.network(), LightningNetworkV1::Bitcoin);
        assert_eq!(parsed.amount_msat(), 250_000_000);
        assert_eq!(parsed.created_at(), 1_496_314_658);
        assert_eq!(parsed.expiry_seconds(), 60);
        assert_eq!(parsed.expires_at().unwrap(), 1_496_314_718);
        assert_eq!(
            parsed.payee_pubkey(),
            [
                0x03, 0xe7, 0x15, 0x6a, 0xe3, 0x3b, 0x0a, 0x20, 0x8d, 0x07, 0x44, 0x19, 0x91, 0x63,
                0x17, 0x7e, 0x90, 0x9e, 0x80, 0x17, 0x6e, 0x55, 0xd9, 0x7a, 0x2f, 0x22, 0x1e, 0xde,
                0x0f, 0x93, 0x4d, 0xd9, 0xad,
            ]
        );
        assert_eq!(
            parsed.invoice_text_digest(),
            bolt11_invoice_text_digest_v1(OFFICIAL_FIXED_AMOUNT_INVOICE)
        );
    }

    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn concrete_bolt11_parser_maps_supported_networks_and_rejects_simnet() {
        for (currency, expected) in [
            (Currency::Bitcoin, LightningNetworkV1::Bitcoin),
            (Currency::BitcoinTestnet, LightningNetworkV1::Testnet),
            (Currency::Signet, LightningNetworkV1::Signet),
            (Currency::Regtest, LightningNetworkV1::Regtest),
        ] {
            let (invoice, _) = signed_test_invoice(currency, Some(123_000), false, 42);
            let parsed = ParsedBolt11InvoiceV1::parse(&invoice).unwrap();
            assert_eq!(parsed.network(), expected);
            assert_eq!(parsed.amount_msat(), 123_000);
        }

        let (simnet, _) = signed_test_invoice(Currency::Simnet, Some(123_000), false, 42);
        assert!(ParsedBolt11InvoiceV1::parse(&simnet).is_err());
    }

    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn concrete_bolt11_parser_checks_explicit_payee_and_signature() {
        let (valid, expected_payee) =
            signed_test_invoice(Currency::Bitcoin, Some(123_000), true, 42);
        assert_eq!(
            ParsedBolt11InvoiceV1::parse(&valid).unwrap().payee_pubkey(),
            expected_payee
        );

        // The invoice remains syntactically valid and has a valid Bech32
        // checksum, but its signature was made by a key other than its `n`
        // field. The concrete parser must fail closed on ECDSA verification.
        let (wrongly_signed, _) = signed_test_invoice(Currency::Bitcoin, Some(123_000), true, 43);
        assert!(matches!(
            ParsedBolt11InvoiceV1::parse(&wrongly_signed),
            Err(ServiceProtocolError::InvalidValue {
                field: "ParsedBolt11InvoiceV1.invoice",
                ..
            })
        ));
    }

    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn concrete_bolt11_parser_rejects_amountless_and_noncanonical_case() {
        assert!(ParsedBolt11InvoiceV1::parse(OFFICIAL_AMOUNTLESS_INVOICE).is_err());
        let (zero_amount, _) = signed_test_invoice(Currency::Bitcoin, Some(0), false, 42);
        assert!(ParsedBolt11InvoiceV1::parse(&zero_amount).is_err());

        let (valid, _) = signed_test_invoice(Currency::Bitcoin, Some(123_000), false, 42);
        let uppercase = valid.to_ascii_uppercase();
        assert!(ParsedBolt11InvoiceV1::parse(&uppercase).is_err());

        let mut mixed_case = valid;
        mixed_case.replace_range(0..1, "L");
        assert!(ParsedBolt11InvoiceV1::parse(&mixed_case).is_err());
    }

    #[test]
    fn signed_quote_roundtrips_and_verifies_every_invoice_fact() {
        let (_, quote_key, delegation, intent, parsed_invoice) = fixture();
        let quote = open_quote(&quote_key, &delegation, &intent);
        let encoded = quote.encode().unwrap();
        let decoded = Bolt11QuoteV1::decode(&encoded).unwrap();
        assert_eq!(decoded, quote);
        decoded
            .verify_for_payment(&intent, &delegation, &parsed_invoice, 1_200)
            .unwrap();

        let mut wrong_amount = parsed_invoice.clone();
        wrong_amount.amount_msat -= 1;
        assert!(quote
            .verify_for_payment(&intent, &delegation, &wrong_amount, 1_200)
            .is_err());

        let mut wrong_invoice = parsed_invoice.clone();
        wrong_invoice.invoice_text_digest = bolt11_invoice_text_digest_v1("lnbc1different");
        assert!(quote
            .verify_for_payment(&intent, &delegation, &wrong_invoice, 1_200)
            .is_err());

        let mut bad_signature = quote.clone();
        bad_signature.signature[0] ^= 1;
        assert!(matches!(
            bad_signature.verify_for_payment(&intent, &delegation, &parsed_invoice, 1_200),
            Err(ServiceProtocolError::BadSignature)
        ));

        let mut changed_intent = intent.clone();
        changed_intent.credential_count += 1;
        assert!(quote
            .verify_for_payment(&changed_intent, &delegation, &parsed_invoice, 1_200)
            .is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            Bolt11QuoteV1::decode(&trailing),
            Err(ServiceProtocolError::TrailingBytes(1))
        ));
    }

    #[test]
    fn quote_status_enum_and_late_settlement_are_fail_closed_but_recoverable() {
        let (_, quote_key, delegation, intent, parsed_invoice) = fixture();
        let open = open_quote(&quote_key, &delegation, &intent);

        // A cryptographically valid historical open snapshot is restorable,
        // but it cannot be paid after the BOLT11 expiry.
        open.verify_snapshot(&intent, &delegation, &parsed_invoice, 1_700)
            .unwrap();
        assert!(open
            .verify_for_payment(&intent, &delegation, &parsed_invoice, 1_700)
            .is_err());

        let expired = open
            .with_status(
                &intent,
                Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile,
                1_600,
                &delegation,
                &quote_key,
            )
            .unwrap();
        let verified_expired = expired
            .verify_snapshot(&intent, &delegation, &parsed_invoice, 1_700)
            .unwrap();
        assert!(verified_expired.ensure_claim_submission_at(1_700).is_err());

        assert!(Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile
            .allows_transition_to(Bolt11QuoteStatusV1::LateSettledReconcile));
        let late = expired
            .with_status(
                &intent,
                Bolt11QuoteStatusV1::LateSettledReconcile,
                1_700,
                &delegation,
                &quote_key,
            )
            .unwrap();
        late.verify_for_claim_submission(&intent, &delegation, &parsed_invoice, 1_800)
            .unwrap();

        let mut encoded = late.encode().unwrap();
        let invoice_len = usize::from(u16::from_le_bytes([encoded[81], encoded[82]]));
        let status_offset = 83 + invoice_len + 1 + 33 + 8 + 8 + 8 + 8 + 8;
        encoded[status_offset] = 0xff;
        assert!(matches!(
            Bolt11QuoteV1::decode(&encoded),
            Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "Bolt11QuoteStatusV1",
                value: 0xff
            })
        ));
    }

    #[test]
    fn quote_status_time_is_monotonic_and_exact_replay_is_stable() {
        let (_, quote_key, delegation, intent, _) = fixture();
        let open = open_quote(&quote_key, &delegation, &intent);

        let exact_replay = open
            .with_status(
                &intent,
                Bolt11QuoteStatusV1::InvoiceOpen,
                open.status_updated_at,
                &delegation,
                &quote_key,
            )
            .unwrap();
        assert_eq!(exact_replay, open);
        assert!(open
            .with_status(
                &intent,
                Bolt11QuoteStatusV1::InvoiceOpen,
                open.status_updated_at + 1,
                &delegation,
                &quote_key,
            )
            .is_err());

        let settled = open
            .with_status(
                &intent,
                Bolt11QuoteStatusV1::PaymentSettled,
                1_400,
                &delegation,
                &quote_key,
            )
            .unwrap();
        assert_eq!(open.state_version, 1);
        assert_eq!(settled.state_version, 2);
        assert!(settled
            .with_status(
                &intent,
                Bolt11QuoteStatusV1::CredentialClaimed,
                1_399,
                &delegation,
                &quote_key,
            )
            .is_err());
    }

    #[test]
    fn persisted_quote_transition_survives_restart_without_raw_intent() {
        let (_, quote_key, delegation, intent, _) = fixture();
        let open = open_quote(&quote_key, &delegation, &intent);
        let expected = persisted_expectation(&open, &intent);
        let verified = open
            .verify_persisted_for_transition(expected, &delegation, 1_300)
            .unwrap();

        let settled = Bolt11QuoteV1::with_status_from_verified_persisted_snapshot(
            &verified,
            Bolt11QuoteStatusV1::PaymentSettled,
            1_400,
            &delegation,
            &quote_key,
        )
        .unwrap();
        assert_eq!(settled.state_version, 2);

        // A restart needs only the exact durable record and signed snapshot;
        // the client's raw HTTP idempotency key is intentionally absent.
        let settled_expected = PersistedBolt11QuoteExpectationV1 {
            request_digest: &settled.request_digest,
            quote_id: &settled.quote_id,
            invoice: &settled.invoice,
            ..expected
        };
        let verified_after_restart = settled
            .verify_persisted_for_transition(settled_expected, &delegation, 1_500)
            .unwrap();
        let exact_replay = Bolt11QuoteV1::with_status_from_verified_persisted_snapshot(
            &verified_after_restart,
            Bolt11QuoteStatusV1::PaymentSettled,
            settled.status_updated_at,
            &delegation,
            &quote_key,
        )
        .unwrap();
        assert_eq!(exact_replay, settled);

        let claimed = Bolt11QuoteV1::with_status_from_verified_persisted_snapshot(
            &verified_after_restart,
            Bolt11QuoteStatusV1::CredentialClaimed,
            1_500,
            &delegation,
            &quote_key,
        )
        .unwrap();
        assert_eq!(claimed.state_version, 3);
    }

    #[test]
    fn persisted_quote_transition_rejects_forks_and_mismatched_store_facts() {
        let (_, quote_key, delegation, intent, _) = fixture();
        let open = open_quote(&quote_key, &delegation, &intent);

        let mut wrong_request_digest = open.request_digest;
        wrong_request_digest[0] ^= 1;
        let expected = persisted_expectation(&open, &intent);
        assert!(open
            .verify_persisted_for_transition(
                PersistedBolt11QuoteExpectationV1 {
                    request_digest: &wrong_request_digest,
                    ..expected
                },
                &delegation,
                1_300,
            )
            .is_err());

        let wrong_invoice = "lnbc10u1different";
        assert!(open
            .verify_persisted_for_transition(
                PersistedBolt11QuoteExpectationV1 {
                    invoice: wrong_invoice,
                    ..expected
                },
                &delegation,
                1_300,
            )
            .is_err());

        let mut bad_signature = open.clone();
        bad_signature.signature[0] ^= 1;
        assert!(matches!(
            bad_signature.verify_persisted_for_transition(expected, &delegation, 1_300),
            Err(ServiceProtocolError::BadSignature)
        ));

        let verified = open
            .verify_persisted_for_transition(expected, &delegation, 1_300)
            .unwrap();
        assert!(Bolt11QuoteV1::with_status_from_verified_persisted_snapshot(
            &verified,
            Bolt11QuoteStatusV1::CredentialClaimed,
            1_400,
            &delegation,
            &quote_key,
        )
        .is_err());
        assert!(Bolt11QuoteV1::with_status_from_verified_persisted_snapshot(
            &verified,
            Bolt11QuoteStatusV1::InvoiceOpen,
            open.status_updated_at + 1,
            &delegation,
            &quote_key,
        )
        .is_err());

        let unrelated_quote_key = SigningKey::from_bytes(&[11; 32]);
        assert!(Bolt11QuoteV1::with_status_from_verified_persisted_snapshot(
            &verified,
            Bolt11QuoteStatusV1::PaymentSettled,
            1_400,
            &delegation,
            &unrelated_quote_key,
        )
        .is_err());
    }

    #[test]
    fn initial_quote_signer_rejects_non_open_status() {
        let (_, quote_key, delegation, intent, _) = fixture();
        assert!(Bolt11QuoteV1::sign(
            &intent,
            [10; 32],
            INVOICE.into(),
            CREATED_AT,
            Bolt11QuoteStatusV1::PaymentSettled,
            CREATED_AT,
            &delegation,
            &quote_key,
        )
        .is_err());
    }

    #[test]
    fn latest_snapshot_guard_rejects_rollback_and_same_version_fork() {
        let (_, quote_key, delegation, intent, parsed_invoice) = fixture();
        let open = open_quote(&quote_key, &delegation, &intent);
        open.verify_snapshot(&intent, &delegation, &parsed_invoice, 1_300)
            .unwrap();
        let settled = open
            .with_status(
                &intent,
                Bolt11QuoteStatusV1::PaymentSettled,
                1_400,
                &delegation,
                &quote_key,
            )
            .unwrap();
        settled
            .verify_latest_after(&open, &intent, &delegation, &parsed_invoice, 1_500)
            .unwrap();
        settled
            .verify_latest_after(&settled, &intent, &delegation, &parsed_invoice, 1_500)
            .unwrap();
        assert!(open
            .verify_latest_after(&settled, &intent, &delegation, &parsed_invoice, 1_500)
            .is_err());

        let expired_fork = open
            .with_status(
                &intent,
                Bolt11QuoteStatusV1::InvoiceExpiredPendingReconcile,
                open.invoice_expires_at,
                &delegation,
                &quote_key,
            )
            .unwrap();
        assert_eq!(expired_fork.state_version, settled.state_version);
        assert!(expired_fork
            .verify_latest_after(&settled, &intent, &delegation, &parsed_invoice, 1_700)
            .is_err());

        let claimed = settled
            .with_status(
                &intent,
                Bolt11QuoteStatusV1::CredentialClaimed,
                1_500,
                &delegation,
                &quote_key,
            )
            .unwrap();
        claimed
            .verify_latest_after(&open, &intent, &delegation, &parsed_invoice, 1_500)
            .unwrap();
    }

    #[test]
    fn quote_status_request_is_bound_fresh_and_nonce_bearing() {
        let (_, _, _, intent, _) = fixture();
        let request = Bolt11QuoteStatusRequestV1 {
            issuer_id: intent.issuer_id,
            quote_id: [10; 32],
            quote_request_digest: intent.request_digest().unwrap(),
            claim_pubkey_xonly: intent.claim_pubkey_xonly,
            requested_at: 1_500,
            request_nonce: [14; 32],
            signature: [15; 64],
        };
        let encoded = request.encode().unwrap();
        assert!(encoded.len() <= MAX_BOLT11_QUOTE_STATUS_REQUEST_LEN);
        assert_eq!(
            Bolt11QuoteStatusRequestV1::decode(&encoded).unwrap(),
            request
        );
        let input = request
            .unverified_bip340_input_for(&intent, &[10; 32], 1_600)
            .unwrap();
        assert_eq!(input.claim_pubkey_xonly, intent.claim_pubkey_xonly);
        assert_eq!(input.quote_id, [10; 32]);
        assert_eq!(input.request_nonce, [14; 32]);
        assert_eq!(
            input.message_digest,
            request.bip340_signing_digest().unwrap()
        );

        let mut wrong_quote = request.clone();
        wrong_quote.quote_id[0] ^= 1;
        assert!(wrong_quote
            .unverified_bip340_input_for(&intent, &[10; 32], 1_600)
            .is_err());
        assert!(request
            .unverified_bip340_input_for(
                &intent,
                &[10; 32],
                request.requested_at + MAX_BOLT11_QUOTE_STATUS_REQUEST_AGE_SECONDS_V1 + 1,
            )
            .is_err());
        assert!(request
            .unverified_bip340_input_for(&intent, &[10; 32], request.requested_at - 1)
            .is_err());

        let mut changed_nonce = request.clone();
        changed_nonce.request_nonce[0] ^= 1;
        assert_ne!(
            changed_nonce.bip340_signing_digest().unwrap(),
            request.bip340_signing_digest().unwrap()
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            Bolt11QuoteStatusRequestV1::decode(&trailing),
            Err(ServiceProtocolError::TrailingBytes(1))
        ));
    }

    #[test]
    fn claim_transcript_is_xonly_bound_and_explicitly_unverified() {
        let (_, quote_key, delegation, intent, parsed_invoice) = fixture();
        let open = open_quote(&quote_key, &delegation, &intent);
        let settled = open
            .with_status(
                &intent,
                Bolt11QuoteStatusV1::PaymentSettled,
                1_400,
                &delegation,
                &quote_key,
            )
            .unwrap();
        let verified = settled
            .verify_for_claim_submission(&intent, &delegation, &parsed_invoice, 1_500)
            .unwrap();
        let claim = Bolt11QuoteClaimV1 {
            issuer_id: intent.issuer_id,
            quote_id: settled.quote_id,
            quote_request_digest: settled.request_digest,
            credential_request_digest: [11; 32],
            claim_pubkey_xonly: intent.claim_pubkey_xonly,
            idempotency_key: [12; 32],
            signature: [13; 64],
        };
        let encoded = claim.encode().unwrap();
        assert_eq!(Bolt11QuoteClaimV1::decode(&encoded).unwrap(), claim);
        let verification_input = claim.unverified_bip340_input_for(&verified, 1_500).unwrap();
        assert_eq!(verification_input.claim_pubkey_xonly.len(), 32);
        assert_eq!(
            verification_input.message_digest,
            claim.bip340_signing_digest().unwrap()
        );

        let mut changed = claim.clone();
        changed.idempotency_key[0] ^= 1;
        assert_ne!(
            changed.bip340_signing_digest().unwrap(),
            claim.bip340_signing_digest().unwrap()
        );
        assert_ne!(
            changed.claim_request_digest().unwrap(),
            claim.claim_request_digest().unwrap()
        );

        let mut wrong_quote = claim.clone();
        wrong_quote.quote_id[0] ^= 1;
        assert!(wrong_quote
            .unverified_bip340_input_for(&verified, 1_500)
            .is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            Bolt11QuoteClaimV1::decode(&trailing),
            Err(ServiceProtocolError::TrailingBytes(1))
        ));
    }

    #[test]
    fn already_claimed_quote_allows_only_store_enforced_idempotent_recovery() {
        let (_, quote_key, delegation, intent, parsed_invoice) = fixture();
        let open = open_quote(&quote_key, &delegation, &intent);
        let settled = open
            .with_status(
                &intent,
                Bolt11QuoteStatusV1::PaymentSettled,
                1_400,
                &delegation,
                &quote_key,
            )
            .unwrap();
        let claimed = settled
            .with_status(
                &intent,
                Bolt11QuoteStatusV1::CredentialClaimed,
                2_000,
                &delegation,
                &quote_key,
            )
            .unwrap();
        let after_deadline = claimed.claim_deadline + 10;
        claimed
            .verify_for_claim_submission(&intent, &delegation, &parsed_invoice, after_deadline)
            .unwrap();
    }

    #[test]
    fn quote_rejects_noncanonical_or_oversized_invoice_and_zero_quote_id() {
        let (_, quote_key, delegation, intent, _) = fixture();
        assert!(Bolt11QuoteV1::sign(
            &intent,
            [10; 32],
            "LNBC10U1QQQQ".into(),
            CREATED_AT,
            Bolt11QuoteStatusV1::InvoiceOpen,
            CREATED_AT,
            &delegation,
            &quote_key,
        )
        .is_err());
        assert!(Bolt11QuoteV1::sign(
            &intent,
            [10; 32],
            format!("ln{}", "q".repeat(MAX_BOLT11_INVOICE_LEN)),
            CREATED_AT,
            Bolt11QuoteStatusV1::InvoiceOpen,
            CREATED_AT,
            &delegation,
            &quote_key,
        )
        .is_err());
        assert!(Bolt11QuoteV1::sign(
            &intent,
            [0; 32],
            INVOICE.into(),
            CREATED_AT,
            Bolt11QuoteStatusV1::InvoiceOpen,
            CREATED_AT,
            &delegation,
            &quote_key,
        )
        .is_err());
    }

    #[test]
    fn quote_key_delegation_must_cover_the_full_claim_window() {
        let (issuer_key, quote_key, _, intent, _) = fixture();
        let short_delegation = Bolt11QuoteKeyDelegationV1::sign(
            intent.network,
            intent.expected_payee_pubkey,
            intent.minimum_quote_key_epoch,
            100,
            CREATED_AT + u64::from(INVOICE_EXPIRY),
            quote_key.verifying_key().to_bytes(),
            &issuer_key,
        )
        .unwrap();
        let mut short_intent = intent.clone();
        short_intent.quote_delegation_digest = short_delegation.delegation_digest().unwrap();

        assert!(Bolt11QuoteV1::sign(
            &short_intent,
            [10; 32],
            INVOICE.into(),
            CREATED_AT,
            Bolt11QuoteStatusV1::InvoiceOpen,
            CREATED_AT,
            &short_delegation,
            &quote_key,
        )
        .is_err());
    }

    #[test]
    fn verified_offer_derives_quote_intent_and_rejects_commercial_tampering() {
        let (policy, policy_verifying_key, delegation, payee) = verified_offer_fixture();
        let verified_policy = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &policy_verifying_key,
            )
            .unwrap();
        let scope_id = policy.scopes[0].scope.scope_id();
        let verified_offer = verified_policy.offer(&scope_id, 9).unwrap();
        let guard = Bolt11QuoteKeyRollbackGuardV1::initial(
            delegation.issuer_id,
            LightningNetworkV1::Bitcoin,
            payee,
        )
        .unwrap();
        let (intent, advanced_guard) = Bolt11QuoteIntentV1::from_verified_offer_guarded(
            &verified_offer,
            &delegation,
            &guard,
            150,
            xonly_point(5),
            [9; 32],
        )
        .unwrap();
        let verified_intent = intent
            .verify_for_offer_guarded(&verified_offer, &delegation, &guard, 150)
            .unwrap();
        assert_eq!(advanced_guard.highest_epoch(), 4);
        assert_eq!(verified_intent.advanced_guard(), advanced_guard);
        let parsed_invoice = ParsedBolt11InvoiceV1::from_signature_verified_invoice(
            INVOICE,
            LightningNetworkV1::Bitcoin,
            payee,
            intent.exact_amount_msat,
            CREATED_AT,
            intent.invoice_expiry_seconds,
        )
        .unwrap();
        let quote_key = SigningKey::from_bytes(&[8; 32]);
        Bolt11QuoteV1::sign_for_verified_intent(
            &verified_intent,
            [10; 32],
            INVOICE.into(),
            &parsed_invoice,
            Bolt11QuoteStatusV1::InvoiceOpen,
            CREATED_AT,
            &quote_key,
        )
        .unwrap();
        let wrong_amount = ParsedBolt11InvoiceV1::from_signature_verified_invoice(
            INVOICE,
            LightningNetworkV1::Bitcoin,
            payee,
            1_000,
            CREATED_AT,
            intent.invoice_expiry_seconds,
        )
        .unwrap();
        assert!(Bolt11QuoteV1::sign_for_verified_intent(
            &verified_intent,
            [11; 32],
            INVOICE.into(),
            &wrong_amount,
            Bolt11QuoteStatusV1::InvoiceOpen,
            CREATED_AT,
            &quote_key,
        )
        .is_err());
        assert_eq!(intent.exact_amount_msat, 100_000);
        assert_eq!(intent.credential_count, 8);
        assert_eq!(intent.provider_id, policy.provider_id);
        assert_eq!(intent.policy_digest, verified_policy.policy_digest());
        assert_eq!(
            intent.credential_binding_digest,
            verified_offer
                .offer()
                .credential_binding
                .as_ref()
                .unwrap()
                .binding_digest()
                .unwrap()
        );

        let assert_rejected = |candidate: &Bolt11QuoteIntentV1| {
            assert!(candidate
                .verify_for_offer_guarded(&verified_offer, &delegation, &guard, 150)
                .is_err());
        };

        let mut one_sat = intent.clone();
        one_sat.exact_amount_msat = 1_000;
        assert_rejected(&one_sat);

        let mut count = intent.clone();
        count.credential_count = 1;
        assert_rejected(&count);

        let mut key = intent.clone();
        key.credential_key_id[0] ^= 1;
        assert_rejected(&key);

        let mut binding = intent.clone();
        binding.credential_binding_digest[0] ^= 1;
        assert_rejected(&binding);

        let mut provider = intent.clone();
        provider.provider_id[0] ^= 1;
        assert_rejected(&provider);

        let mut policy_binding = intent.clone();
        policy_binding.policy_digest[0] ^= 1;
        assert_rejected(&policy_binding);

        let wrong_network = Bolt11QuoteKeyRollbackGuardV1::initial(
            delegation.issuer_id,
            LightningNetworkV1::Testnet,
            payee,
        )
        .unwrap();
        assert!(intent
            .verify_for_offer_guarded(&verified_offer, &delegation, &wrong_network, 150)
            .is_err());
        let wrong_payee = Bolt11QuoteKeyRollbackGuardV1::initial(
            delegation.issuer_id,
            LightningNetworkV1::Bitcoin,
            compressed_point(13),
        )
        .unwrap();
        assert!(intent
            .verify_for_offer_guarded(&verified_offer, &delegation, &wrong_payee, 150)
            .is_err());
        let future_floor = Bolt11QuoteKeyRollbackGuardV1::from_persisted(
            delegation.issuer_id,
            LightningNetworkV1::Bitcoin,
            payee,
            5,
            [0x55; 32],
        )
        .unwrap();
        assert!(intent
            .verify_for_offer_guarded(&verified_offer, &delegation, &future_floor, 150)
            .is_err());
    }
}
