//! Canonical method-specific authorization proof codecs.
//!
//! `AuthBeginV1.proof` is intentionally opaque to the outer frame.  This
//! module gives each authorization scheme exactly one bounded binary shape so
//! providers never have to accept JSON, legacy Cashu variants, or optional
//! proof fields on the PIR wire.

use core::{cmp::Ordering, fmt, mem};
use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::cashu_manifest::is_valid_compressed_point;
use crate::codec::{expect_v1, put_bytes_u16, put_bytes_u32, Decoder};
use crate::{
    is_canonical_cashu_keyset_id_v2, AcquisitionMethod, AuthScheme, FreeModeV1, PaidReceiptV1,
    PriceV1, ProviderId, ScopeId, ServiceProtocolError, VerificationMode, VerifiedServiceOfferV1,
    CASHU_KEYSET_ID_V2_LEN, MAX_AUTH_PROOF_LEN, MAX_SERVICE_VALUE_V1, SERVICE_PROTOCOL_VERSION,
};

pub const FREE_POW_PROOF_LEN_V1: usize = 1 + 32 + 8;
pub const MAX_STANDARD_CASHU_PROOFS_V1: usize = 64;
pub const MAX_STANDARD_CASHU_SECRET_LEN_V1: usize = 1_024;
const STANDARD_CASHU_PROOF_FIXED_WIRE_LEN_V1: usize = CASHU_KEYSET_ID_V2_LEN + 8 + 2 + 33;
pub const BAT_PROOF_LEN_V1: usize = 1 + 32 + 33;
pub const MAX_ARC_PRESENTATION_LEN_V1: usize = MAX_AUTH_PROOF_LEN - 5;

pub const FREE_ANONYMOUS_TICKET_SIGNATURE_DOMAIN: &[u8] =
    b"BitcoinPIR/free-anonymous-ticket-signature/v1";
pub const FREE_ANONYMOUS_TICKET_KEY_ID_DOMAIN: &[u8] =
    b"BitcoinPIR/free-anonymous-ticket-key-id/v1";
pub const FREE_ANONYMOUS_TICKET_SPEND_DOMAIN: &[u8] = b"BitcoinPIR/free-anonymous-ticket-spend/v1";
pub const BAT_SPEND_DOMAIN: &[u8] = b"BitcoinPIR/cashu-bat-spend/v1";
pub const BAT_VERIFICATION_KEY_FINGERPRINT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/cashu-bat-verification-key-fingerprint/v1";
pub const ARC_PROVIDER_GLOBAL_SPEND_KEY_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/arc-provider-global-spend-key/v1";
pub const ARC_CANONICAL_TAG_LEN_V1: usize = 33;

/// Canonical provider-global ARC nullifier derivation shared by the reviewed
/// cryptographic adapter and durable provider store.
pub fn arc_provider_global_spend_key_v1(
    public_key_fingerprint: &[u8; 32],
    credential_binding_digest: &[u8; 32],
    canonical_tag: &[u8; ARC_CANONICAL_TAG_LEN_V1],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ARC_PROVIDER_GLOBAL_SPEND_KEY_DOMAIN_V1);
    hasher.update(public_key_fingerprint);
    hasher.update(credential_binding_digest);
    hasher.update(canonical_tag);
    hasher.finalize().into()
}

/// Server-fresh proof-of-work solution.  Challenge construction and target
/// verification are defined by the challenge exchange, not by this codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreePowProofV1 {
    pub challenge_id: [u8; 32],
    pub nonce: u64,
}

impl FreePowProofV1 {
    pub fn encode(&self) -> Result<[u8; FREE_POW_PROOF_LEN_V1], ServiceProtocolError> {
        self.validate()?;
        let mut out = [0u8; FREE_POW_PROOF_LEN_V1];
        out[0] = SERVICE_PROTOCOL_VERSION;
        out[1..33].copy_from_slice(&self.challenge_id);
        out[33..].copy_from_slice(&self.nonce.to_le_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        expect_v1(decoder.u8("FreePowProofV1.version")?, "FreePowProofV1")?;
        let value = Self {
            challenge_id: decoder.fixed("FreePowProofV1.challenge_id")?,
            nonce: decoder.u64("FreePowProofV1.nonce")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.challenge_id.iter().all(|byte| *byte == 0) {
            Err(ServiceProtocolError::InvalidValue {
                field: "FreePowProofV1.challenge_id",
                reason: "must be a non-zero server-issued challenge identifier",
            })
        } else {
            Ok(())
        }
    }
}

/// Exact audience and entitlement a free anonymous ticket is expected to
/// authorize.  Keeping this separate makes it difficult to verify only the
/// signature while forgetting the provider, policy, or profile binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreeAnonymousTicketExpectationV1 {
    pub provider_id: ProviderId,
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub policy_digest: [u8; 32],
    pub entitlement_profile: u16,
    pub issuer_id: [u8; 32],
}

/// Provider-specific, single-use, Ed25519-signed free capability.
#[derive(Clone, PartialEq, Eq)]
pub struct FreeAnonymousTicketV1 {
    pub provider_id: ProviderId,
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub policy_digest: [u8; 32],
    pub entitlement_profile: u16,
    pub issuer_id: [u8; 32],
    pub key_id: [u8; 16],
    pub serial: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub signature: [u8; 64],
}

impl fmt::Debug for FreeAnonymousTicketV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreeAnonymousTicketV1")
            .field("provider_id", &"[REDACTED]")
            .field("scope_id", &"[REDACTED]")
            .field("offer_id", &self.offer_id)
            .field("entitlement_profile", &self.entitlement_profile)
            .field("serial", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

impl Drop for FreeAnonymousTicketV1 {
    fn drop(&mut self) {
        self.serial.zeroize();
        self.signature.zeroize();
    }
}

impl FreeAnonymousTicketV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        provider_id: ProviderId,
        scope_id: ScopeId,
        offer_id: u32,
        policy_digest: [u8; 32],
        entitlement_profile: u16,
        issuer_id: [u8; 32],
        serial: [u8; 32],
        not_before: u64,
        not_after: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let mut ticket = Self {
            provider_id,
            scope_id,
            offer_id,
            policy_digest,
            entitlement_profile,
            issuer_id,
            key_id: free_anonymous_ticket_key_id(&signing_key.verifying_key()),
            serial,
            not_before,
            not_after,
            signature: [0; 64],
        };
        ticket.validate_unsigned()?;
        ticket.signature = signing_key.sign(&ticket.signing_preimage()?).to_bytes();
        Ok(ticket)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        Ok(mem::take(&mut *out))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("FreeAnonymousTicketV1.version")?,
            "FreeAnonymousTicketV1",
        )?;
        let ticket = Self {
            provider_id: decoder.fixed("FreeAnonymousTicketV1.provider_id")?,
            scope_id: decoder.fixed("FreeAnonymousTicketV1.scope_id")?,
            offer_id: decoder.u32("FreeAnonymousTicketV1.offer_id")?,
            policy_digest: decoder.fixed("FreeAnonymousTicketV1.policy_digest")?,
            entitlement_profile: decoder.u16("FreeAnonymousTicketV1.entitlement_profile")?,
            issuer_id: decoder.fixed("FreeAnonymousTicketV1.issuer_id")?,
            key_id: decoder.fixed("FreeAnonymousTicketV1.key_id")?,
            serial: decoder.fixed("FreeAnonymousTicketV1.serial")?,
            not_before: decoder.u64("FreeAnonymousTicketV1.not_before")?,
            not_after: decoder.u64("FreeAnonymousTicketV1.not_after")?,
            signature: decoder.fixed("FreeAnonymousTicketV1.signature")?,
        };
        decoder.finish()?;
        ticket.validate_unsigned()?;
        let exact_reencoding = Zeroizing::new(ticket.encode()?);
        if exact_reencoding.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: "FreeAnonymousTicketV1",
                reason: "non-canonical ticket encoding",
            });
        }
        Ok(ticket)
    }

    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        expected: &FreeAnonymousTicketExpectationV1,
        now_unix: u64,
    ) -> Result<(), ServiceProtocolError> {
        self.validate_unsigned()?;
        if self.provider_id != expected.provider_id
            || self.scope_id != expected.scope_id
            || self.offer_id != expected.offer_id
            || self.policy_digest != expected.policy_digest
            || self.entitlement_profile != expected.entitlement_profile
            || self.issuer_id != expected.issuer_id
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "FreeAnonymousTicketV1.audience",
                reason: "ticket does not match provider, scope, offer, policy, profile, or issuer",
            });
        }
        if self.key_id != free_anonymous_ticket_key_id(verifying_key) {
            return Err(ServiceProtocolError::WrongSigningKeyId);
        }
        if now_unix < self.not_before || now_unix > self.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "FreeAnonymousTicketV1.validity",
                reason: "ticket is not currently valid",
            });
        }
        verifying_key
            .verify_strict(
                &self.signing_preimage()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ServiceProtocolError::BadSignature)
    }

    /// Provider-local durable uniqueness key. The issuer/key/serial tuple is
    /// deliberately independent of the ticket audience so an issuer cannot
    /// accidentally (or maliciously) make one serial spendable once per
    /// scope. It has a different domain from paid receipts and BAT credentials.
    pub fn spend_key(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(FREE_ANONYMOUS_TICKET_SPEND_DOMAIN);
        hasher.update(self.issuer_id);
        hasher.update(self.key_id);
        hasher.update(self.serial);
        hasher.finalize().into()
    }

    fn signing_preimage(&self) -> Result<Zeroizing<Vec<u8>>, ServiceProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut preimage = Zeroizing::new(Vec::with_capacity(
            FREE_ANONYMOUS_TICKET_SIGNATURE_DOMAIN.len() + unsigned.len(),
        ));
        preimage.extend_from_slice(FREE_ANONYMOUS_TICKET_SIGNATURE_DOMAIN);
        preimage.extend_from_slice(&unsigned);
        Ok(preimage)
    }

    fn encode_unsigned(&self) -> Result<Zeroizing<Vec<u8>>, ServiceProtocolError> {
        self.validate_unsigned()?;
        let mut out = Zeroizing::new(Vec::with_capacity(200));
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.scope_id);
        out.extend_from_slice(&self.offer_id.to_le_bytes());
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.entitlement_profile.to_le_bytes());
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&self.serial);
        out.extend_from_slice(&self.not_before.to_le_bytes());
        out.extend_from_slice(&self.not_after.to_le_bytes());
        Ok(out)
    }

    fn validate_unsigned(&self) -> Result<(), ServiceProtocolError> {
        if self.provider_id.iter().all(|byte| *byte == 0)
            || self.scope_id.iter().all(|byte| *byte == 0)
            || self.offer_id == 0
            || self.policy_digest.iter().all(|byte| *byte == 0)
            || self.entitlement_profile == 0
            || self.issuer_id.iter().all(|byte| *byte == 0)
            || self.key_id.iter().all(|byte| *byte == 0)
            || self.serial.iter().all(|byte| *byte == 0)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "FreeAnonymousTicketV1",
                reason:
                    "audience, issuer, key, serial, policy, offer, and profile must be non-zero",
            });
        }
        if self.not_after == 0 || self.not_before > self.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "FreeAnonymousTicketV1.validity",
                reason: "validity interval is empty or reversed",
            });
        }
        Ok(())
    }
}

pub fn free_anonymous_ticket_key_id(verifying_key: &VerifyingKey) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(FREE_ANONYMOUS_TICKET_KEY_ID_DOMAIN);
    hasher.update(verifying_key.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    digest[..16].try_into().expect("fixed digest prefix")
}

/// Verify a free anonymous ticket only against an offer obtained from a
/// verified current policy or an exact retained policy in its redemption
/// grace. This integration-safe entry point checks the issuer-root delegation,
/// delegated key, exact provider/scope/offer/policy/profile audience, and all
/// validity horizons before returning the provider's durable spend key.
pub fn verify_free_anonymous_ticket_for_offer(
    ticket: &FreeAnonymousTicketV1,
    verified_offer: &VerifiedServiceOfferV1<'_>,
    now_unix: u64,
) -> Result<[u8; 32], ServiceProtocolError> {
    let scope = verified_offer.scope();
    let offer = verified_offer.offer();
    if offer.authorization != AuthScheme::FreeV1 || offer.free_mode != FreeModeV1::AnonymousTicket {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ServiceOfferV1.authorization",
            reason: "verified offer does not authorize free anonymous tickets",
        });
    }
    if now_unix > verified_offer.redemption_deadline() {
        return Err(ServiceProtocolError::InvalidValue {
            field: "VerifiedServiceOfferV1.redemption_deadline",
            reason: "anonymous-ticket redemption is outside the retained-policy grace",
        });
    }
    let binding = offer
        .credential_binding
        .as_ref()
        .ok_or(ServiceProtocolError::InvalidValue {
            field: "ServiceOfferV1.credential_binding",
            reason: "anonymous-ticket offer has no delegated verification key",
        })?;
    binding.verify_signature()?;
    binding.check_validity(now_unix)?;
    if ticket.not_before < binding.claims.not_before
        || ticket.not_after > binding.claims.not_after
        || ticket.not_after > verified_offer.redemption_deadline()
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "FreeAnonymousTicketV1.validity",
            reason: "ticket outlives its delegated key or retained policy",
        });
    }
    let verifying_key_bytes: [u8; 32] = binding
        .claims
        .verification_key
        .as_slice()
        .try_into()
        .map_err(|_| ServiceProtocolError::InvalidValue {
            field: "CredentialKeyBindingV1.verification_key",
            reason: "anonymous-ticket Ed25519 key must be 32 bytes",
        })?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| ServiceProtocolError::BadPublicKey)?;
    ticket.verify(
        &verifying_key,
        &FreeAnonymousTicketExpectationV1 {
            provider_id: scope.provider_id,
            scope_id: scope.scope_id(),
            offer_id: offer.offer_id,
            policy_digest: verified_offer.policy_digest(),
            entitlement_profile: scope.entitlement_profile,
            issuer_id: offer.issuer_id,
        },
        now_unix,
    )?;
    Ok(ticket.spend_key())
}

/// One normalized standard Cashu proof.  V1 accepts only NUT-02 V2 keyset
/// IDs, canonical UTF-8 secrets, and compressed secp256k1 `C` points.  Witness
/// and proof-level DLEQ fields have no representation here; in particular,
/// the wallet's private DLEQ blinding scalar `r` can never cross this wire.
#[derive(Clone, PartialEq, Eq)]
pub struct StandardCashuProofV1 {
    pub keyset_id: String,
    pub amount: u64,
    pub secret: String,
    pub c: [u8; 33],
}

impl fmt::Debug for StandardCashuProofV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StandardCashuProofV1")
            .field("keyset_id", &self.keyset_id)
            .field("amount", &self.amount)
            .field("secret", &"[REDACTED]")
            .field("c", &"[REDACTED]")
            .finish()
    }
}

impl Drop for StandardCashuProofV1 {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.c.zeroize();
    }
}

impl StandardCashuProofV1 {
    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if !is_canonical_cashu_keyset_id_v2(&self.keyset_id) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuProofV1.keyset_id",
                reason: "must be a full lowercase NUT-02 V2 keyset ID",
            });
        }
        if self.amount == 0 || self.amount > MAX_SERVICE_VALUE_V1 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuProofV1.amount",
                reason: "must be non-zero and fit the durable signed-value range",
            });
        }
        if self.secret.is_empty() || self.secret.len() > MAX_STANDARD_CASHU_SECRET_LEN_V1 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "StandardCashuProofV1.secret",
                len: self.secret.len(),
                max: MAX_STANDARD_CASHU_SECRET_LEN_V1,
            });
        }
        if !is_valid_compressed_point(&self.c) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuProofV1.c",
                reason: "must be a non-identity compressed secp256k1 point",
            });
        }
        Ok(())
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        debug_assert_eq!(self.keyset_id.len(), CASHU_KEYSET_ID_V2_LEN);
        out.extend_from_slice(self.keyset_id.as_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        put_bytes_u16(out, self.secret.as_bytes());
        out.extend_from_slice(&self.c);
        Ok(())
    }
}

/// Canonically sorted standard Cashu input list.
#[derive(Clone, PartialEq, Eq)]
pub struct StandardCashuSpendV1 {
    pub proofs: Vec<StandardCashuProofV1>,
}

impl fmt::Debug for StandardCashuSpendV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StandardCashuSpendV1")
            .field("proof_count", &self.proofs.len())
            .field("proofs", &"[REDACTED]")
            .finish()
    }
}

impl StandardCashuSpendV1 {
    /// Sort wallet proofs into the sole V1 wire order and reject duplicate
    /// Cashu secrets or `C` points.
    pub fn new_canonical(
        mut proofs: Vec<StandardCashuProofV1>,
    ) -> Result<Self, ServiceProtocolError> {
        proofs.sort_by(cashu_proof_order);
        let value = Self { proofs };
        value.validate()?;
        Ok(value)
    }

    /// The returned bytes intentionally remain caller-owned because they are
    /// the next-hop bearer passed into `AuthBeginV1`.
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let encoded_len = self.proofs.iter().try_fold(2usize, |len, proof| {
            len.checked_add(STANDARD_CASHU_PROOF_FIXED_WIRE_LEN_V1)
                .and_then(|len| len.checked_add(proof.secret.len()))
                .ok_or(ServiceProtocolError::InvalidValue {
                    field: "StandardCashuSpendV1",
                    reason: "encoded length overflow",
                })
        })?;
        if encoded_len > MAX_AUTH_PROOF_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "StandardCashuSpendV1",
                len: encoded_len,
                max: MAX_AUTH_PROOF_LEN,
            });
        }

        let mut out = Zeroizing::new(Vec::with_capacity(encoded_len));
        out.push(SERVICE_PROTOCOL_VERSION);
        out.push(self.proofs.len() as u8);
        for proof in &self.proofs {
            proof.encode_into(&mut out)?;
        }
        debug_assert_eq!(out.len(), encoded_len);
        Ok(mem::take(&mut *out))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_AUTH_PROOF_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "StandardCashuSpendV1",
                len: bytes.len(),
                max: MAX_AUTH_PROOF_LEN,
            });
        }
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("StandardCashuSpendV1.version")?,
            "StandardCashuSpendV1",
        )?;
        let count = decoder.u8("StandardCashuSpendV1.proof_count")? as usize;
        if count == 0 || count > MAX_STANDARD_CASHU_PROOFS_V1 {
            return Err(ServiceProtocolError::TooManyItems {
                field: "StandardCashuSpendV1.proofs",
                len: count,
                max: MAX_STANDARD_CASHU_PROOFS_V1,
            });
        }
        let mut proofs = Vec::with_capacity(count);
        for _ in 0..count {
            let keyset_id_bytes: [u8; CASHU_KEYSET_ID_V2_LEN] =
                decoder.fixed("StandardCashuProofV1.keyset_id")?;
            let keyset_id = String::from_utf8(keyset_id_bytes.to_vec())
                .map_err(|_| ServiceProtocolError::InvalidUtf8("StandardCashuProofV1.keyset_id"))?;
            let amount = decoder.u64("StandardCashuProofV1.amount")?;
            let mut secret_bytes = Zeroizing::new(decoder.bytes_u16(
                "StandardCashuProofV1.secret",
                MAX_STANDARD_CASHU_SECRET_LEN_V1,
            )?);
            let mut secret = match String::from_utf8(mem::take(&mut *secret_bytes)) {
                Ok(secret) => Zeroizing::new(secret),
                Err(error) => {
                    let _invalid_secret = Zeroizing::new(error.into_bytes());
                    return Err(ServiceProtocolError::InvalidUtf8(
                        "StandardCashuProofV1.secret",
                    ));
                }
            };
            let c = decoder.fixed("StandardCashuProofV1.c")?;
            proofs.push(StandardCashuProofV1 {
                keyset_id,
                amount,
                secret: mem::take(&mut *secret),
                c,
            });
        }
        decoder.finish()?;
        let value = Self { proofs };
        value.validate()?;
        let canonical = Zeroizing::new(value.encode()?);
        if canonical.as_slice() != bytes {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuSpendV1",
                reason: "non-canonical proof-list encoding",
            });
        }
        Ok(value)
    }

    pub fn total_amount(&self) -> Result<u64, ServiceProtocolError> {
        self.validate()?;
        self.proofs.iter().try_fold(0u64, |total, proof| {
            total
                .checked_add(proof.amount)
                .filter(|sum| *sum <= MAX_SERVICE_VALUE_V1)
                .ok_or(ServiceProtocolError::InvalidValue {
                    field: "StandardCashuSpendV1.total_amount",
                    reason: "sum overflows the durable signed-value range",
                })
        })
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.proofs.is_empty() || self.proofs.len() > MAX_STANDARD_CASHU_PROOFS_V1 {
            return Err(ServiceProtocolError::TooManyItems {
                field: "StandardCashuSpendV1.proofs",
                len: self.proofs.len(),
                max: MAX_STANDARD_CASHU_PROOFS_V1,
            });
        }
        let mut secrets = HashSet::with_capacity(self.proofs.len());
        let mut points = HashSet::with_capacity(self.proofs.len());
        for (index, proof) in self.proofs.iter().enumerate() {
            proof.validate()?;
            if index > 0 && cashu_proof_order(&self.proofs[index - 1], proof) != Ordering::Less {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "StandardCashuSpendV1.proofs",
                    reason: "proofs must be strictly sorted in canonical V1 order",
                });
            }
            if !secrets.insert(proof.secret.as_str()) || !points.insert(&proof.c) {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "StandardCashuSpendV1.proofs",
                    reason: "duplicate Cashu secrets or C points are forbidden",
                });
            }
        }
        self.total_amount_unchecked()?;
        Ok(())
    }

    fn total_amount_unchecked(&self) -> Result<u64, ServiceProtocolError> {
        self.proofs.iter().try_fold(0u64, |total, proof| {
            total
                .checked_add(proof.amount)
                .filter(|sum| *sum <= MAX_SERVICE_VALUE_V1)
                .ok_or(ServiceProtocolError::InvalidValue {
                    field: "StandardCashuSpendV1.total_amount",
                    reason: "sum overflows the durable signed-value range",
                })
        })
    }
}

/// Policy-only result for constructing the authoritative NUT-03 swap.
///
/// This check does not validate Cashu signatures, DLEQ proofs, or spent state.
/// A provider must grant the PIR operation only after the pinned mint accepts
/// the exact inputs in an authoritative NUT-03 commit. V1 intentionally has no
/// change path: `net_amount` must equal the signed offer price exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardCashuSpendCheckV1 {
    pub mint_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub mint_endpoint: String,
    pub unit: String,
    pub gross_input_amount: u64,
    /// Sum of the NUT-02 `input_fee_ppk` value selected once per input proof.
    pub input_fee_ppk_total: u64,
    /// `ceil(input_fee_ppk_total / 1000)` in the manifest's unit.
    pub input_fee_amount: u64,
    pub net_amount: u64,
    pub policy_price: u64,
}

/// Check a canonical standard Cashu input list against one exact, signed
/// service offer before handing it to the mint adapter for NUT-03.
///
/// This is deliberately a policy/amount guard, not payment verification. The
/// external Cashu mint remains the sole authority for proof signatures and
/// spent state, and the caller must not grant service before that swap commits.
pub fn check_standard_cashu_spend_for_offer(
    spend: &StandardCashuSpendV1,
    verified_offer: &VerifiedServiceOfferV1<'_>,
    now_unix: u64,
) -> Result<StandardCashuSpendCheckV1, ServiceProtocolError> {
    spend.validate()?;
    let offer = verified_offer.offer();
    if offer.acquisition != AcquisitionMethod::CashuEcashV1
        || offer.authorization != AuthScheme::CashuEcashV1
        || offer.verification != VerificationMode::StandardCashuMintOnline
        || offer.free_mode != FreeModeV1::NotFree
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ServiceOfferV1.standard_cashu_method",
            reason: "offer is not CashuEcashV1 with authoritative mint-online verification",
        });
    }
    if now_unix > verified_offer.redemption_deadline() {
        return Err(ServiceProtocolError::InvalidValue {
            field: "VerifiedServiceOfferV1.redemption_deadline",
            reason: "standard Cashu spend is outside the signed offer deadline",
        });
    }
    let (price_unit, policy_price) = match &offer.price {
        PriceV1::Cashu { unit, amount } => (unit.as_str(), *amount),
        _ => {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.price",
                reason: "standard Cashu offer must carry a Cashu unit and amount",
            })
        }
    };
    let manifest =
        offer
            .cashu_mint_manifest
            .as_ref()
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.cashu_mint_manifest",
                reason: "standard Cashu offer has no embedded signed manifest",
            })?;
    let manifest_digest = manifest.manifest_digest()?;
    if offer.issuer_id != manifest.mint_id()
        || offer.key_id.as_slice() != manifest_digest
        || offer.endpoint != manifest.mint_endpoint
        || price_unit != manifest.unit
        || offer.credential_binding.is_some()
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ServiceOfferV1.cashu_mint_binding",
            reason: "issuer, manifest digest, endpoint, unit, or binding mode mismatch",
        });
    }

    let mut gross_input_amount = 0u64;
    let mut input_fee_ppk_total = 0u64;
    for proof in &spend.proofs {
        let keyset_index = manifest
            .accepted_input_keysets
            .binary_search_by(|keyset| keyset.keyset_id.as_str().cmp(&proof.keyset_id))
            .map_err(|_| ServiceProtocolError::InvalidValue {
                field: "StandardCashuProofV1.keyset_id",
                reason: "proof keyset is not an accepted input keyset in the signed manifest",
            })?;
        let keyset = &manifest.accepted_input_keysets[keyset_index];
        if keyset.unit != manifest.unit || keyset.unit != price_unit {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CashuKeysetBindingV1.unit",
                reason: "proof keyset unit does not match the signed Cashu price",
            });
        }
        if keyset
            .final_expiry
            .is_some_and(|final_expiry| now_unix > final_expiry)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CashuKeysetBindingV1.final_expiry",
                reason: "proof keyset is past its signed final redemption time",
            });
        }
        if keyset
            .keys
            .binary_search_by_key(&proof.amount, |key| key.amount)
            .is_err()
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuProofV1.amount",
                reason: "proof amount has no denomination key in its signed keyset",
            });
        }
        gross_input_amount = gross_input_amount.checked_add(proof.amount).ok_or(
            ServiceProtocolError::InvalidValue {
                field: "StandardCashuSpendV1.gross_input_amount",
                reason: "input amount sum overflow",
            },
        )?;
        input_fee_ppk_total = input_fee_ppk_total
            .checked_add(u64::from(keyset.input_fee_ppk))
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "StandardCashuSpendV1.input_fee_ppk_total",
                reason: "NUT-02 input fee sum overflow",
            })?;
    }
    if gross_input_amount > MAX_SERVICE_VALUE_V1 {
        return Err(ServiceProtocolError::InvalidValue {
            field: "StandardCashuSpendV1.gross_input_amount",
            reason: "input amount exceeds the durable signed-value range",
        });
    }
    // NUT-02: fee = (sum(input_fee_ppk per proof) + 999) / 1000.
    let fee_numerator =
        input_fee_ppk_total
            .checked_add(999)
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "StandardCashuSpendV1.input_fee_ppk_total",
                reason: "NUT-02 input fee rounding overflow",
            })?;
    let input_fee_amount = fee_numerator / 1_000;
    let net_amount = gross_input_amount.checked_sub(input_fee_amount).ok_or(
        ServiceProtocolError::InvalidValue {
            field: "StandardCashuSpendV1.net_amount",
            reason: "NUT-02 input fees exceed the supplied amount",
        },
    )?;
    if net_amount < policy_price {
        return Err(ServiceProtocolError::InvalidValue {
            field: "StandardCashuSpendV1.net_amount",
            reason: "underpayment after NUT-02 input fees",
        });
    }
    if net_amount > policy_price {
        return Err(ServiceProtocolError::InvalidValue {
            field: "StandardCashuSpendV1.net_amount",
            reason: "overpayment is forbidden because V1 returns no change",
        });
    }

    Ok(StandardCashuSpendCheckV1 {
        mint_id: offer.issuer_id,
        manifest_digest,
        mint_endpoint: offer.endpoint.clone(),
        unit: price_unit.to_owned(),
        gross_input_amount,
        input_fee_ppk_total,
        input_fee_amount,
        net_amount,
        policy_price,
    })
}

fn cashu_proof_order(left: &StandardCashuProofV1, right: &StandardCashuProofV1) -> Ordering {
    left.keyset_id
        .as_bytes()
        .cmp(right.keyset_id.as_bytes())
        .then_with(|| left.amount.cmp(&right.amount))
        .then_with(|| left.secret.as_bytes().cmp(right.secret.as_bytes()))
        .then_with(|| left.c.cmp(&right.c))
}

/// BitcoinPIR's compact Cashu BAT proof.  The selected `AuthBeginV1.key_id`
/// is intentionally outside this fixed proof and must match the verified
/// provider policy before signature verification.
#[derive(Clone, PartialEq, Eq)]
pub struct BitcoinPirCashuBatProofV1 {
    pub secret_raw: [u8; 32],
    pub c: [u8; 33],
}

impl fmt::Debug for BitcoinPirCashuBatProofV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitcoinPirCashuBatProofV1")
            .field("secret_raw", &"[REDACTED]")
            .field("c", &"[REDACTED]")
            .finish()
    }
}

impl Drop for BitcoinPirCashuBatProofV1 {
    fn drop(&mut self) {
        self.secret_raw.zeroize();
        self.c.zeroize();
    }
}

impl BitcoinPirCashuBatProofV1 {
    pub fn encode(&self) -> Result<[u8; BAT_PROOF_LEN_V1], ServiceProtocolError> {
        let mut encoded = self.encode_zeroizing()?;
        Ok(mem::replace(&mut *encoded, [0u8; BAT_PROOF_LEN_V1]))
    }

    pub fn encode_zeroizing(
        &self,
    ) -> Result<Zeroizing<[u8; BAT_PROOF_LEN_V1]>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Zeroizing::new([0u8; BAT_PROOF_LEN_V1]);
        out[0] = SERVICE_PROTOCOL_VERSION;
        out[1..33].copy_from_slice(&self.secret_raw);
        out[33..].copy_from_slice(&self.c);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("BitcoinPirCashuBatProofV1.version")?,
            "BitcoinPirCashuBatProofV1",
        )?;
        let value = Self {
            secret_raw: decoder.fixed("BitcoinPirCashuBatProofV1.secret_raw")?,
            c: decoder.fixed("BitcoinPirCashuBatProofV1.c")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Provider-local durable uniqueness key.
    ///
    /// This deliberately uses the underlying DHKE verification key rather
    /// than the audience-derived policy `key_id`. Rebinding one raw key to a
    /// new scope, offer, profile, epoch, or issuer must not make the same BAT
    /// secret spendable again. Issuers additionally have to enforce that one
    /// raw BAT key belongs to exactly one provider lineage, because separate
    /// providers do not share spent state.
    pub fn spend_key(&self, verification_key: &[u8; 33]) -> Result<[u8; 32], ServiceProtocolError> {
        self.validate()?;
        let key_fingerprint = bat_verification_key_fingerprint_v1(verification_key)?;
        let mut hasher = Sha256::new();
        hasher.update(BAT_SPEND_DOMAIN);
        hasher.update(key_fingerprint);
        hasher.update(self.secret_raw);
        Ok(hasher.finalize().into())
    }

    pub fn verification_key_fingerprint(
        verification_key: &[u8; 33],
    ) -> Result<[u8; 32], ServiceProtocolError> {
        bat_verification_key_fingerprint_v1(verification_key)
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.secret_raw.iter().all(|byte| *byte == 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BitcoinPirCashuBatProofV1.secret_raw",
                reason: "must be non-zero",
            });
        }
        if !is_valid_compressed_point(&self.c) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BitcoinPirCashuBatProofV1.c",
                reason: "must be a non-identity compressed secp256k1 point",
            });
        }
        Ok(())
    }
}

/// Stable fingerprint used both by provider spent-state derivation and by the
/// issuer's cross-policy key-lineage registry.
pub fn bat_verification_key_fingerprint_v1(
    verification_key: &[u8; 33],
) -> Result<[u8; 32], ServiceProtocolError> {
    if !is_valid_compressed_point(verification_key) {
        return Err(ServiceProtocolError::InvalidValue {
            field: "CredentialKeyBindingV1.verification_key",
            reason: "BAT verification key must be a non-identity compressed secp256k1 point",
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(BAT_VERIFICATION_KEY_FINGERPRINT_DOMAIN_V1);
    hasher.update(verification_key);
    Ok(hasher.finalize().into())
}

/// Adapter implemented by the reviewed ARC library.  The implementation must
/// parse the presentation into its typed representation and serialize that
/// value again; returning the input without decoding violates this contract.
pub trait ArcPresentationCanonicalizerV1 {
    fn decode_and_reencode(&self, presentation: &[u8]) -> Result<Vec<u8>, ServiceProtocolError>;
}

impl<F> ArcPresentationCanonicalizerV1 for F
where
    F: Fn(&[u8]) -> Result<Vec<u8>, ServiceProtocolError>,
{
    fn decode_and_reencode(&self, presentation: &[u8]) -> Result<Vec<u8>, ServiceProtocolError> {
        self(presentation)
    }
}

/// Experimental ARC presentation envelope.  It deliberately carries no
/// client-selected serial or spent key.  The provider must obtain the durable
/// nullifier from successful ARC verification.
#[derive(Clone, PartialEq, Eq)]
pub struct ArcPresentationV1 {
    canonical_presentation: Vec<u8>,
}

impl fmt::Debug for ArcPresentationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArcPresentationV1")
            .field(
                "canonical_presentation_len",
                &self.canonical_presentation.len(),
            )
            .field("canonical_presentation", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ArcPresentationV1 {
    fn drop(&mut self) {
        self.canonical_presentation.zeroize();
    }
}

impl ArcPresentationV1 {
    /// Construct from bytes already emitted canonically by the ARC library.
    /// Providers must use `decode_canonical`; this constructor is for issuers
    /// and clients serializing a freshly produced typed presentation.
    pub fn from_canonical_bytes(
        canonical_presentation: Vec<u8>,
    ) -> Result<Self, ServiceProtocolError> {
        let mut canonical_presentation = Zeroizing::new(canonical_presentation);
        validate_arc_presentation_len(&canonical_presentation)?;
        Ok(Self {
            canonical_presentation: mem::take(&mut *canonical_presentation),
        })
    }

    pub fn presentation_bytes(&self) -> &[u8] {
        &self.canonical_presentation
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        validate_arc_presentation_len(&self.canonical_presentation)?;
        let mut out = Zeroizing::new(Vec::with_capacity(5 + self.canonical_presentation.len()));
        out.push(SERVICE_PROTOCOL_VERSION);
        put_bytes_u32(&mut out, &self.canonical_presentation);
        Ok(mem::take(&mut *out))
    }

    pub fn decode_canonical(
        bytes: &[u8],
        canonicalizer: &dyn ArcPresentationCanonicalizerV1,
    ) -> Result<Self, ServiceProtocolError> {
        let value = Self::decode_structural(bytes)?;
        let reencoded =
            Zeroizing::new(canonicalizer.decode_and_reencode(&value.canonical_presentation)?);
        if reencoded.as_slice() != value.canonical_presentation.as_slice() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ArcPresentationV1.presentation",
                reason: "ARC decode/re-encode is not byte-for-byte canonical",
            });
        }
        Ok(value)
    }

    fn decode_structural(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_AUTH_PROOF_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ArcPresentationV1",
                len: bytes.len(),
                max: MAX_AUTH_PROOF_LEN,
            });
        }
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("ArcPresentationV1.version")?,
            "ArcPresentationV1",
        )?;
        let mut canonical_presentation = Zeroizing::new(decoder.bytes_u32(
            "ArcPresentationV1.presentation",
            MAX_ARC_PRESENTATION_LEN_V1,
        )?);
        decoder.finish()?;
        validate_arc_presentation_len(&canonical_presentation)?;
        Ok(Self {
            canonical_presentation: mem::take(&mut *canonical_presentation),
        })
    }
}

fn validate_arc_presentation_len(bytes: &[u8]) -> Result<(), ServiceProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_ARC_PRESENTATION_LEN_V1 {
        Err(ServiceProtocolError::FieldTooLong {
            field: "ArcPresentationV1.presentation",
            len: bytes.len(),
            max: MAX_ARC_PRESENTATION_LEN_V1,
        })
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FreeAuthorizationProofV1 {
    OpenBestEffort,
    IpRateLimited,
    ProofOfWork(FreePowProofV1),
    AnonymousTicket(Box<FreeAnonymousTicketV1>),
}

#[derive(Clone, PartialEq, Eq)]
pub enum AuthorizationProofV1 {
    Free(FreeAuthorizationProofV1),
    Bolt11DirectReceipt(Box<PaidReceiptV1>),
    StandardCashu(StandardCashuSpendV1),
    BitcoinPirCashuBat(BitcoinPirCashuBatProofV1),
    ArcExperimental(ArcPresentationV1),
}

impl fmt::Debug for AuthorizationProofV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Free(FreeAuthorizationProofV1::OpenBestEffort) => {
                formatter.write_str("AuthorizationProofV1::Free(OpenBestEffort)")
            }
            Self::Free(FreeAuthorizationProofV1::IpRateLimited) => {
                formatter.write_str("AuthorizationProofV1::Free(IpRateLimited)")
            }
            Self::Free(FreeAuthorizationProofV1::ProofOfWork(_)) => formatter
                .debug_tuple("AuthorizationProofV1::Free(ProofOfWork)")
                .field(&"[REDACTED]")
                .finish(),
            Self::Free(FreeAuthorizationProofV1::AnonymousTicket(_)) => formatter
                .debug_tuple("AuthorizationProofV1::Free(AnonymousTicket)")
                .field(&"[REDACTED]")
                .finish(),
            Self::Bolt11DirectReceipt(_) => formatter
                .debug_tuple("AuthorizationProofV1::Bolt11DirectReceipt")
                .field(&"[REDACTED]")
                .finish(),
            Self::StandardCashu(spend) => formatter
                .debug_tuple("AuthorizationProofV1::StandardCashu")
                .field(spend)
                .finish(),
            Self::BitcoinPirCashuBat(_) => formatter
                .debug_tuple("AuthorizationProofV1::BitcoinPirCashuBat")
                .field(&"[REDACTED]")
                .finish(),
            Self::ArcExperimental(_) => formatter
                .debug_tuple("AuthorizationProofV1::ArcExperimental")
                .field(&"[REDACTED]")
                .finish(),
        }
    }
}

impl AuthorizationProofV1 {
    /// Encode only when the typed proof matches the signed offer's scheme and
    /// free mode.  This prevents a caller from changing only the outer tag.
    pub fn encode_for(
        &self,
        scheme: AuthScheme,
        free_mode: FreeModeV1,
    ) -> Result<Vec<u8>, ServiceProtocolError> {
        match (scheme, free_mode, self) {
            (
                AuthScheme::FreeV1,
                FreeModeV1::OpenBestEffort,
                Self::Free(FreeAuthorizationProofV1::OpenBestEffort),
            )
            | (
                AuthScheme::FreeV1,
                FreeModeV1::IpRateLimited,
                Self::Free(FreeAuthorizationProofV1::IpRateLimited),
            ) => Ok(Vec::new()),
            (
                AuthScheme::FreeV1,
                FreeModeV1::ProofOfWork,
                Self::Free(FreeAuthorizationProofV1::ProofOfWork(proof)),
            ) => Ok(proof.encode()?.to_vec()),
            (
                AuthScheme::FreeV1,
                FreeModeV1::AnonymousTicket,
                Self::Free(FreeAuthorizationProofV1::AnonymousTicket(ticket)),
            ) => ticket.encode(),
            (
                AuthScheme::Bolt11DirectReceiptV1,
                FreeModeV1::NotFree,
                Self::Bolt11DirectReceipt(receipt),
            ) => receipt.encode(),
            (AuthScheme::CashuEcashV1, FreeModeV1::NotFree, Self::StandardCashu(spend)) => {
                spend.encode()
            }
            (
                AuthScheme::BitcoinPirCashuBatV1,
                FreeModeV1::NotFree,
                Self::BitcoinPirCashuBat(proof),
            ) => Ok(proof.encode_zeroizing()?.to_vec()),
            (
                AuthScheme::ArcV1Experimental,
                FreeModeV1::NotFree,
                Self::ArcExperimental(presentation),
            ) => presentation.encode(),
            _ => Err(ServiceProtocolError::InvalidValue {
                field: "AuthorizationProofV1",
                reason: "typed proof does not match the selected authorization scheme/free mode",
            }),
        }
    }
}

/// Strict provider-side method dispatch.  ARC cannot be decoded without a
/// reviewed typed decode/re-encode adapter.  For every other method pass
/// `None`; the value is ignored unless the selected scheme is ARC.
pub(crate) fn decode_authorization_proof_v1(
    scheme: AuthScheme,
    free_mode: FreeModeV1,
    bytes: &[u8],
    arc_canonicalizer: Option<&dyn ArcPresentationCanonicalizerV1>,
) -> Result<AuthorizationProofV1, ServiceProtocolError> {
    if bytes.len() > MAX_AUTH_PROOF_LEN {
        return Err(ServiceProtocolError::FieldTooLong {
            field: "AuthBeginV1.proof",
            len: bytes.len(),
            max: MAX_AUTH_PROOF_LEN,
        });
    }
    match (scheme, free_mode) {
        (AuthScheme::FreeV1, FreeModeV1::OpenBestEffort) => {
            require_empty_free_proof(bytes, "OpenBestEffort")?;
            Ok(AuthorizationProofV1::Free(
                FreeAuthorizationProofV1::OpenBestEffort,
            ))
        }
        (AuthScheme::FreeV1, FreeModeV1::IpRateLimited) => {
            require_empty_free_proof(bytes, "IpRateLimited")?;
            Ok(AuthorizationProofV1::Free(
                FreeAuthorizationProofV1::IpRateLimited,
            ))
        }
        (AuthScheme::FreeV1, FreeModeV1::ProofOfWork) => Ok(AuthorizationProofV1::Free(
            FreeAuthorizationProofV1::ProofOfWork(FreePowProofV1::decode(bytes)?),
        )),
        (AuthScheme::FreeV1, FreeModeV1::AnonymousTicket) => Ok(AuthorizationProofV1::Free(
            FreeAuthorizationProofV1::AnonymousTicket(Box::new(FreeAnonymousTicketV1::decode(
                bytes,
            )?)),
        )),
        (AuthScheme::FreeV1, FreeModeV1::NotFree) => Err(ServiceProtocolError::InvalidValue {
            field: "FreeModeV1",
            reason: "FreeV1 authorization requires an actual free mode",
        }),
        (AuthScheme::Bolt11DirectReceiptV1, FreeModeV1::NotFree) => {
            let receipt = PaidReceiptV1::decode(bytes)?;
            let exact_reencoding = Zeroizing::new(receipt.encode()?);
            if exact_reencoding.as_slice() != bytes {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "PaidReceiptV1",
                    reason: "direct BOLT proof must be exact canonical receipt bytes",
                });
            }
            Ok(AuthorizationProofV1::Bolt11DirectReceipt(Box::new(receipt)))
        }
        (AuthScheme::CashuEcashV1, FreeModeV1::NotFree) => Ok(AuthorizationProofV1::StandardCashu(
            StandardCashuSpendV1::decode(bytes)?,
        )),
        (AuthScheme::BitcoinPirCashuBatV1, FreeModeV1::NotFree) => Ok(
            AuthorizationProofV1::BitcoinPirCashuBat(BitcoinPirCashuBatProofV1::decode(bytes)?),
        ),
        (AuthScheme::ArcV1Experimental, FreeModeV1::NotFree) => {
            let canonicalizer = arc_canonicalizer.ok_or(ServiceProtocolError::InvalidValue {
                field: "ArcPresentationV1.presentation",
                reason: "ARC requires typed decode/re-encode canonicality validation",
            })?;
            Ok(AuthorizationProofV1::ArcExperimental(
                ArcPresentationV1::decode_canonical(bytes, canonicalizer)?,
            ))
        }
        (_, _) => Err(ServiceProtocolError::InvalidValue {
            field: "FreeModeV1",
            reason: "paid authorization schemes require NotFree",
        }),
    }
}

fn require_empty_free_proof(bytes: &[u8], mode: &'static str) -> Result<(), ServiceProtocolError> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(ServiceProtocolError::InvalidValue {
            field: "AuthBeginV1.proof",
            reason: match mode {
                "OpenBestEffort" => "OpenBestEffort proof must be empty",
                _ => "IpRateLimited proof must be empty",
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_cashu_keyset_id_v2, AcquisitionMethod, AuthPaddingClassV1, BackendId,
        CashuDenominationKeyV1, CashuKeysetBindingV1, CashuRequiredNutsV1,
        CredentialKeyBindingClaimsV1, CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1,
        DeploymentStatus, EntitlementLimitsV1, PaidReceiptBindingV1, PolicyRollbackGuardV1,
        PriceV1, PrivacyLeakageV1, ServiceOfferV1, ServicePolicyEpochFloorsV1, ServicePolicyV1,
        ServiceScopePolicyV1, ServiceScopeV1, StandardCashuMintManifestV1, VerificationMode,
        WorkloadId,
    };
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};

    fn point(multiplier: u64) -> [u8; 33] {
        let affine = (ProjectivePoint::GENERATOR * Scalar::from(multiplier)).to_affine();
        affine.to_encoded_point(true).as_bytes().try_into().unwrap()
    }

    fn keyset(suffix: u8) -> String {
        format!("01{}", format!("{suffix:02x}").repeat(32))
    }

    fn cashu_proof(key: u8, amount: u64, secret: &str, multiplier: u64) -> StandardCashuProofV1 {
        StandardCashuProofV1 {
            keyset_id: keyset(key),
            amount,
            secret: secret.to_owned(),
            c: point(multiplier),
        }
    }

    fn cashu_manifest_keyset(
        amounts: &[u64],
        input_fee_ppk: u32,
        final_expiry: Option<u64>,
        first_key_multiplier: u64,
    ) -> CashuKeysetBindingV1 {
        let keys: Vec<_> = amounts
            .iter()
            .enumerate()
            .map(|(index, amount)| CashuDenominationKeyV1 {
                amount: *amount,
                public_key: point(first_key_multiplier + index as u64),
            })
            .collect();
        CashuKeysetBindingV1 {
            keyset_id: derive_cashu_keyset_id_v2(&keys, "sat", input_fee_ppk, final_expiry)
                .unwrap(),
            unit: "sat".into(),
            input_fee_ppk,
            final_expiry,
            keys,
        }
    }

    fn standard_cashu_policy(
        price: u64,
        mut accepted_input_keysets: Vec<CashuKeysetBindingV1>,
        active_output_keyset: CashuKeysetBindingV1,
        expires_at: u64,
        retired_policy_grace_seconds: u32,
    ) -> (ServicePolicyV1, SigningKey) {
        accepted_input_keysets.sort_by(|left, right| left.keyset_id.cmp(&right.keyset_id));
        let manifest = StandardCashuMintManifestV1 {
            manifest_epoch: 1,
            mint_endpoint: "https://mint.example".into(),
            leaf_spki_sha256_pins: vec![[0x31; 32]],
            unit: "sat".into(),
            required_nuts: CashuRequiredNutsV1::required_v1(),
            accepted_input_keysets,
            active_output_keyset,
        };
        let provider_id = [0x51; 32];
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 2 },
            operation_profile: 1,
            entitlement_profile: 8,
        };
        let offer = ServiceOfferV1 {
            offer_id: 17,
            acquisition: AcquisitionMethod::CashuEcashV1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::CashuEcashV1,
            verification: VerificationMode::StandardCashuMintOnline,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::Cashu {
                unit: "sat".into(),
                amount: price,
            },
            issuer_id: manifest.mint_id(),
            key_id: manifest.manifest_digest().unwrap().to_vec(),
            credential_binding: None,
            cashu_mint_manifest: Some(manifest),
            endpoint: "https://mint.example".into(),
            invoice_expiry_seconds: 0,
            claim_window_seconds: 0,
            minimum_credential_validity_seconds: 100,
            retired_policy_grace_seconds,
            credential_count: 1,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .unwrap(),
        };
        let policy_key = SigningKey::from_bytes(&[0x52; 32]);
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            100,
            expires_at,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 10,
                    max_request_bytes: 1_000,
                    max_response_bytes: 2_000,
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
        (policy, policy_key)
    }

    fn standard_cashu_offer<'a>(
        policy: &'a ServicePolicyV1,
        policy_key: &SigningKey,
        now_unix: u64,
    ) -> VerifiedServiceOfferV1<'a> {
        let verified_policy = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                now_unix,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &policy_key.verifying_key(),
            )
            .unwrap();
        let scope_id = policy.scopes[0].scope.scope_id();
        verified_policy.offer(&scope_id, 17).unwrap()
    }

    fn anonymous_ticket_policy() -> (ServicePolicyV1, SigningKey) {
        let provider_id = [9; 32];
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 3,
        };
        let ticket_key = SigningKey::from_bytes(&[5; 32]);
        let credential_key_id = free_anonymous_ticket_key_id(&ticket_key.verifying_key());
        let credential_binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id: scope.scope_id(),
                offer_id: 9,
                scheme: AuthScheme::FreeV1,
                keyset_epoch: 1,
                entitlement_profile: 3,
                unit: CredentialUnitV1::Entitlement,
                amount: 1,
                presentation_limit: 1,
                not_before: 50,
                not_after: 300,
                credential_key_id: credential_key_id.to_vec(),
                verification_key: ticket_key.verifying_key().to_bytes().to_vec(),
            },
            &SigningKey::from_bytes(&[7; 32]),
        )
        .unwrap();
        let offer = ServiceOfferV1 {
            offer_id: 9,
            acquisition: AcquisitionMethod::FreeV1,
            free_mode: FreeModeV1::AnonymousTicket,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::FreeV1,
            verification: VerificationMode::ProviderLocal,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::Free,
            issuer_id: credential_binding.issuer_id,
            key_id: credential_key_id.to_vec(),
            credential_binding: Some(credential_binding),
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".into(),
            invoice_expiry_seconds: 0,
            claim_window_seconds: 0,
            minimum_credential_validity_seconds: 100,
            retired_policy_grace_seconds: 100,
            credential_count: 4,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER
                    | PrivacyLeakageV1::PROVIDER_LOCAL_BEARER,
            )
            .unwrap(),
        };
        let policy_key = SigningKey::from_bytes(&[3; 32]);
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 10,
                    max_request_bytes: 1_000,
                    max_response_bytes: 2_000,
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
        (policy, ticket_key)
    }

    #[test]
    fn authorization_debug_redacts_every_bearer_payload() {
        assert!(core::mem::needs_drop::<StandardCashuProofV1>());
        assert!(core::mem::needs_drop::<FreeAnonymousTicketV1>());
        assert!(core::mem::needs_drop::<BitcoinPirCashuBatProofV1>());
        assert!(core::mem::needs_drop::<ArcPresentationV1>());

        let cashu_secret = "cashu-proof-debug-canary";
        let cashu_c = point(701);
        let cashu_spend =
            StandardCashuSpendV1::new_canonical(vec![cashu_proof(0x71, 8, cashu_secret, 701)])
                .unwrap();
        let cashu_proof_rendered = format!("{:?}", cashu_spend.proofs[0]);
        assert!(cashu_proof_rendered.contains("[REDACTED]"));
        assert!(!cashu_proof_rendered.contains(cashu_secret));
        assert!(!cashu_proof_rendered.contains(&format!("{cashu_c:?}")));

        let cashu_spend_rendered = format!("{cashu_spend:?}");
        assert!(cashu_spend_rendered.contains("[REDACTED]"));
        assert!(!cashu_spend_rendered.contains(cashu_secret));
        assert!(!cashu_spend_rendered.contains(&format!("{cashu_c:?}")));

        let assert_wrapped_redacted = |proof: &AuthorizationProofV1, forbidden: &[String]| {
            let rendered = format!("{proof:?}");
            assert!(rendered.contains("[REDACTED]"), "{rendered}");
            for canary in forbidden {
                assert!(!rendered.contains(canary), "{rendered}");
            }
        };

        assert_wrapped_redacted(
            &AuthorizationProofV1::StandardCashu(cashu_spend),
            &[cashu_secret.to_owned(), format!("{cashu_c:?}")],
        );

        let receipt_serial = [0x72; 32];
        let receipt_signature = [0x73; 64];
        let receipt = PaidReceiptV1 {
            issuer_id: [0x74; 32],
            key_id: [0x75; 16],
            serial: receipt_serial,
            binding: PaidReceiptBindingV1 {
                scope_id: [0x76; 32],
                offer_id: 7,
                policy_digest: [0x77; 32],
                entitlement_profile: 8,
            },
            not_before: 9,
            not_after: 10,
            signature: receipt_signature,
        };
        assert_wrapped_redacted(
            &AuthorizationProofV1::Bolt11DirectReceipt(Box::new(receipt)),
            &[
                format!("{receipt_serial:?}"),
                format!("{receipt_signature:?}"),
            ],
        );

        let bat_secret = [0x78; 32];
        let bat_c = point(702);
        let direct_bat = BitcoinPirCashuBatProofV1 {
            secret_raw: bat_secret,
            c: bat_c,
        };
        let direct_bat_rendered = format!("{direct_bat:?}");
        assert!(direct_bat_rendered.contains("[REDACTED]"));
        assert!(!direct_bat_rendered.contains(&format!("{bat_secret:?}")));
        assert!(!direct_bat_rendered.contains(&format!("{bat_c:?}")));
        assert_wrapped_redacted(
            &AuthorizationProofV1::BitcoinPirCashuBat(direct_bat),
            &[format!("{bat_secret:?}"), format!("{bat_c:?}")],
        );

        let arc_payload = b"arc-presentation-debug-canary".to_vec();
        let arc_payload_rendered = format!("{arc_payload:?}");
        let direct_arc = ArcPresentationV1::from_canonical_bytes(arc_payload).unwrap();
        let direct_arc_rendered = format!("{direct_arc:?}");
        assert!(direct_arc_rendered.contains("[REDACTED]"));
        assert!(!direct_arc_rendered.contains(&arc_payload_rendered));
        assert_wrapped_redacted(
            &AuthorizationProofV1::ArcExperimental(direct_arc),
            &[arc_payload_rendered],
        );

        let ticket_serial = [0x79; 32];
        let ticket_signature = [0x7a; 64];
        let ticket = FreeAnonymousTicketV1 {
            provider_id: [0x7b; 32],
            scope_id: [0x7c; 32],
            offer_id: 11,
            policy_digest: [0x7d; 32],
            entitlement_profile: 12,
            issuer_id: [0x7e; 32],
            key_id: [0x7f; 16],
            serial: ticket_serial,
            not_before: 13,
            not_after: 14,
            signature: ticket_signature,
        };
        let direct_ticket_rendered = format!("{ticket:?}");
        assert!(direct_ticket_rendered.contains("[REDACTED]"));
        assert!(!direct_ticket_rendered.contains(&format!("{ticket_serial:?}")));
        assert!(!direct_ticket_rendered.contains(&format!("{ticket_signature:?}")));
        assert_wrapped_redacted(
            &AuthorizationProofV1::Free(FreeAuthorizationProofV1::AnonymousTicket(Box::new(
                ticket,
            ))),
            &[
                format!("{ticket_serial:?}"),
                format!("{ticket_signature:?}"),
            ],
        );

        let pow_challenge_id = [0x80; 32];
        assert_wrapped_redacted(
            &AuthorizationProofV1::Free(FreeAuthorizationProofV1::ProofOfWork(FreePowProofV1 {
                challenge_id: pow_challenge_id,
                nonce: 15,
            })),
            &[format!("{pow_challenge_id:?}")],
        );
    }

    #[test]
    fn pow_has_fixed_golden_encoding_and_rejects_trailing() {
        let proof = FreePowProofV1 {
            challenge_id: [0x11; 32],
            nonce: 0x0102_0304_0506_0708,
        };
        let encoded = proof.encode().unwrap();
        let expected = [
            vec![1],
            vec![0x11; 32],
            vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        ]
        .concat();
        assert_eq!(encoded.as_slice(), expected);
        assert_eq!(FreePowProofV1::decode(&encoded).unwrap(), proof);
        assert!(matches!(
            FreePowProofV1::decode(&[encoded.as_slice(), &[0]].concat()),
            Err(ServiceProtocolError::TrailingBytes(1))
        ));
    }

    #[test]
    fn free_open_and_ip_require_exactly_empty_proofs() {
        for mode in [FreeModeV1::OpenBestEffort, FreeModeV1::IpRateLimited] {
            assert!(decode_authorization_proof_v1(AuthScheme::FreeV1, mode, &[], None).is_ok());
            assert!(decode_authorization_proof_v1(AuthScheme::FreeV1, mode, &[1], None).is_err());
        }
    }

    #[test]
    fn anonymous_ticket_roundtrips_verifies_and_has_global_serial_spend_key() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let ticket = FreeAnonymousTicketV1::sign(
            [1; 32],
            [2; 32],
            3,
            [4; 32],
            5,
            [6; 32],
            [8; 32],
            100,
            200,
            &signing_key,
        )
        .unwrap();
        let encoded = ticket.encode().unwrap();
        assert_eq!(FreeAnonymousTicketV1::decode(&encoded).unwrap(), ticket);
        ticket
            .verify(
                &signing_key.verifying_key(),
                &FreeAnonymousTicketExpectationV1 {
                    provider_id: [1; 32],
                    scope_id: [2; 32],
                    offer_id: 3,
                    policy_digest: [4; 32],
                    entitlement_profile: 5,
                    issuer_id: [6; 32],
                },
                150,
            )
            .unwrap();
        let mut another_scope = ticket.clone();
        another_scope.scope_id = [9; 32];
        assert_eq!(ticket.spend_key(), another_scope.spend_key());
        assert!(ticket
            .verify(
                &signing_key.verifying_key(),
                &FreeAnonymousTicketExpectationV1 {
                    provider_id: [1; 32],
                    scope_id: [9; 32],
                    offer_id: 3,
                    policy_digest: [4; 32],
                    entitlement_profile: 5,
                    issuer_id: [6; 32],
                },
                150,
            )
            .is_err());
    }

    #[test]
    fn anonymous_ticket_rejects_wrong_key_time_signature_and_trailing() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let ticket = FreeAnonymousTicketV1::sign(
            [1; 32],
            [2; 32],
            3,
            [4; 32],
            5,
            [6; 32],
            [8; 32],
            100,
            200,
            &signing_key,
        )
        .unwrap();
        let expected = FreeAnonymousTicketExpectationV1 {
            provider_id: [1; 32],
            scope_id: [2; 32],
            offer_id: 3,
            policy_digest: [4; 32],
            entitlement_profile: 5,
            issuer_id: [6; 32],
        };
        assert!(matches!(
            ticket.verify(
                &SigningKey::from_bytes(&[9; 32]).verifying_key(),
                &expected,
                150
            ),
            Err(ServiceProtocolError::WrongSigningKeyId)
        ));
        assert!(ticket
            .verify(&signing_key.verifying_key(), &expected, 99)
            .is_err());
        let mut tampered = ticket.clone();
        tampered.serial[0] ^= 1;
        assert!(matches!(
            tampered.verify(&signing_key.verifying_key(), &expected, 150),
            Err(ServiceProtocolError::BadSignature)
        ));
        let mut trailing = ticket.encode().unwrap();
        trailing.push(0);
        assert!(matches!(
            FreeAnonymousTicketV1::decode(&trailing),
            Err(ServiceProtocolError::TrailingBytes(1))
        ));
    }

    #[test]
    fn composite_anonymous_ticket_verifier_checks_policy_and_horizons() {
        let (policy, ticket_key) = anonymous_ticket_policy();
        let policy_key = SigningKey::from_bytes(&[3; 32]);
        let verified_policy = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &policy_key.verifying_key(),
            )
            .unwrap();
        let scope = &policy.scopes[0].scope;
        let verified_offer = verified_policy.offer(&scope.scope_id(), 9).unwrap();
        let ticket = FreeAnonymousTicketV1::sign(
            scope.provider_id,
            scope.scope_id(),
            9,
            verified_policy.policy_digest(),
            scope.entitlement_profile,
            policy.scopes[0].offers[0].issuer_id,
            [6; 32],
            100,
            300,
            &ticket_key,
        )
        .unwrap();
        assert_eq!(
            verify_free_anonymous_ticket_for_offer(&ticket, &verified_offer, 150).unwrap(),
            ticket.spend_key()
        );

        let outliving = FreeAnonymousTicketV1::sign(
            scope.provider_id,
            scope.scope_id(),
            9,
            verified_policy.policy_digest(),
            scope.entitlement_profile,
            policy.scopes[0].offers[0].issuer_id,
            [8; 32],
            100,
            301,
            &ticket_key,
        )
        .unwrap();
        assert!(verify_free_anonymous_ticket_for_offer(&outliving, &verified_offer, 150).is_err());
    }

    #[test]
    fn standard_cashu_normalizes_order_and_roundtrips() {
        let spend = StandardCashuSpendV1::new_canonical(vec![
            cashu_proof(2, 4, "second", 2),
            cashu_proof(1, 2, "first", 1),
        ])
        .unwrap();
        assert_eq!(spend.proofs[0].keyset_id, keyset(1));
        assert_eq!(spend.total_amount().unwrap(), 6);
        let encoded = spend.encode().unwrap();
        assert_eq!(encoded.capacity(), encoded.len());
        assert_eq!(StandardCashuSpendV1::decode(&encoded).unwrap(), spend);
    }

    #[test]
    fn standard_cashu_has_one_proof_golden_prefix() {
        let spend = StandardCashuSpendV1::new_canonical(vec![cashu_proof(0, 1, "s", 1)]).unwrap();
        let encoded = spend.encode().unwrap();
        let mut expected_prefix = vec![1, 1];
        expected_prefix.extend_from_slice(keyset(0).as_bytes());
        expected_prefix.extend_from_slice(&1u64.to_le_bytes());
        expected_prefix.extend_from_slice(&1u16.to_le_bytes());
        expected_prefix.push(b's');
        assert_eq!(&encoded[..expected_prefix.len()], expected_prefix);
        assert_eq!(&encoded[expected_prefix.len()..], point(1));
    }

    #[test]
    fn standard_cashu_rejects_unsorted_duplicates_and_forbidden_extra_fields() {
        let unsorted = StandardCashuSpendV1 {
            proofs: vec![cashu_proof(2, 1, "b", 2), cashu_proof(1, 1, "a", 1)],
        };
        assert!(unsorted.encode().is_err());

        let duplicate_secret = StandardCashuSpendV1::new_canonical(vec![
            cashu_proof(1, 1, "same", 1),
            cashu_proof(2, 1, "same", 2),
        ]);
        assert!(duplicate_secret.is_err());

        let spend = StandardCashuSpendV1::new_canonical(vec![cashu_proof(1, 1, "a", 1)]).unwrap();
        let encoded = spend.encode().unwrap();
        let mut truncated_c = encoded.clone();
        truncated_c.pop();
        assert!(matches!(
            StandardCashuSpendV1::decode(&truncated_c),
            Err(ServiceProtocolError::Truncated("StandardCashuProofV1.c"))
        ));

        let mut witness_like_trailing = encoded;
        witness_like_trailing.extend_from_slice(b"witness");
        assert!(matches!(
            StandardCashuSpendV1::decode(&witness_like_trailing),
            Err(ServiceProtocolError::TrailingBytes(_))
        ));
    }

    #[test]
    fn standard_cashu_rejects_v1_or_uppercase_keyset_ids_and_bad_points() {
        let mut proof = cashu_proof(1, 1, "a", 1);
        proof.keyset_id.replace_range(..2, "00");
        assert!(StandardCashuSpendV1::new_canonical(vec![proof]).is_err());

        let mut proof = cashu_proof(0xab, 1, "a", 1);
        proof.keyset_id.make_ascii_uppercase();
        assert!(StandardCashuSpendV1::new_canonical(vec![proof]).is_err());

        let mut proof = cashu_proof(1, 1, "a", 1);
        proof.c = [0; 33];
        assert!(StandardCashuSpendV1::new_canonical(vec![proof]).is_err());
    }

    #[test]
    fn standard_cashu_offer_guard_computes_mixed_keyset_fees_exactly() {
        let keyset_a = cashu_manifest_keyset(&[4], 499, None, 101);
        let keyset_b = cashu_manifest_keyset(&[4], 502, None, 102);
        let (policy, policy_key) = standard_cashu_policy(
            6,
            vec![keyset_a.clone(), keyset_b.clone()],
            keyset_a.clone(),
            500,
            0,
        );
        let verified_offer = standard_cashu_offer(&policy, &policy_key, 120);
        let spend = StandardCashuSpendV1::new_canonical(vec![
            StandardCashuProofV1 {
                keyset_id: keyset_b.keyset_id,
                amount: 4,
                secret: "mixed-b".into(),
                c: point(202),
            },
            StandardCashuProofV1 {
                keyset_id: keyset_a.keyset_id,
                amount: 4,
                secret: "mixed-a".into(),
                c: point(201),
            },
        ])
        .unwrap();

        let checked = check_standard_cashu_spend_for_offer(&spend, &verified_offer, 120).unwrap();
        assert_eq!(checked.gross_input_amount, 8);
        assert_eq!(checked.input_fee_ppk_total, 1_001);
        assert_eq!(checked.input_fee_amount, 2);
        assert_eq!(checked.net_amount, 6);
        assert_eq!(checked.policy_price, 6);
        assert_eq!(checked.unit, "sat");
        assert_eq!(checked.mint_endpoint, "https://mint.example");
        assert_eq!(checked.mint_id, verified_offer.offer().issuer_id);
        assert_eq!(
            checked.manifest_digest.as_slice(),
            verified_offer.offer().key_id
        );
    }

    #[test]
    fn standard_cashu_offer_guard_accepts_exact_one_sat_without_fee() {
        let keyset = cashu_manifest_keyset(&[1], 0, None, 111);
        let (policy, policy_key) =
            standard_cashu_policy(1, vec![keyset.clone()], keyset.clone(), 500, 0);
        let verified_offer = standard_cashu_offer(&policy, &policy_key, 120);
        let spend = StandardCashuSpendV1::new_canonical(vec![StandardCashuProofV1 {
            keyset_id: keyset.keyset_id,
            amount: 1,
            secret: "one-sat".into(),
            c: point(211),
        }])
        .unwrap();

        let checked = check_standard_cashu_spend_for_offer(&spend, &verified_offer, 120).unwrap();
        assert_eq!(checked.gross_input_amount, 1);
        assert_eq!(checked.input_fee_amount, 0);
        assert_eq!(checked.net_amount, 1);
    }

    #[test]
    fn standard_cashu_offer_guard_rejects_underpayment_and_overpayment() {
        let keyset = cashu_manifest_keyset(&[1, 2], 0, None, 121);
        let (policy, policy_key) =
            standard_cashu_policy(2, vec![keyset.clone()], keyset.clone(), 500, 0);
        let verified_offer = standard_cashu_offer(&policy, &policy_key, 120);
        let underpayment = StandardCashuSpendV1::new_canonical(vec![StandardCashuProofV1 {
            keyset_id: keyset.keyset_id.clone(),
            amount: 1,
            secret: "under".into(),
            c: point(221),
        }])
        .unwrap();
        assert!(matches!(
            check_standard_cashu_spend_for_offer(&underpayment, &verified_offer, 120),
            Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuSpendV1.net_amount",
                reason: "underpayment after NUT-02 input fees",
            })
        ));

        let (policy, policy_key) =
            standard_cashu_policy(1, vec![keyset.clone()], keyset.clone(), 500, 0);
        let verified_offer = standard_cashu_offer(&policy, &policy_key, 120);
        let overpayment = StandardCashuSpendV1::new_canonical(vec![StandardCashuProofV1 {
            keyset_id: keyset.keyset_id,
            amount: 2,
            secret: "over".into(),
            c: point(222),
        }])
        .unwrap();
        assert!(matches!(
            check_standard_cashu_spend_for_offer(&overpayment, &verified_offer, 120),
            Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuSpendV1.net_amount",
                reason: "overpayment is forbidden because V1 returns no change",
            })
        ));
    }

    #[test]
    fn standard_cashu_offer_guard_rejects_unknown_keyset_and_wrong_denomination() {
        let keyset = cashu_manifest_keyset(&[1, 4], 0, None, 131);
        let (policy, policy_key) =
            standard_cashu_policy(1, vec![keyset.clone()], keyset.clone(), 500, 0);
        let verified_offer = standard_cashu_offer(&policy, &policy_key, 120);

        let unknown =
            StandardCashuSpendV1::new_canonical(vec![cashu_proof(0xee, 1, "unknown", 231)])
                .unwrap();
        assert!(matches!(
            check_standard_cashu_spend_for_offer(&unknown, &verified_offer, 120),
            Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuProofV1.keyset_id",
                ..
            })
        ));

        let wrong_denomination = StandardCashuSpendV1::new_canonical(vec![StandardCashuProofV1 {
            keyset_id: keyset.keyset_id,
            amount: 2,
            secret: "wrong-denomination".into(),
            c: point(232),
        }])
        .unwrap();
        assert!(matches!(
            check_standard_cashu_spend_for_offer(&wrong_denomination, &verified_offer, 120),
            Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuProofV1.amount",
                ..
            })
        ));
    }

    #[test]
    fn standard_cashu_offer_guard_rejects_past_final_expiry() {
        let retired_input = cashu_manifest_keyset(&[1], 0, Some(150), 141);
        let active_output = cashu_manifest_keyset(&[2], 0, None, 142);
        let (policy, policy_key) = standard_cashu_policy(
            1,
            vec![retired_input.clone(), active_output.clone()],
            active_output,
            150,
            100,
        );
        let verified_offer = standard_cashu_offer(&policy, &policy_key, 120);
        let spend = StandardCashuSpendV1::new_canonical(vec![StandardCashuProofV1 {
            keyset_id: retired_input.keyset_id,
            amount: 1,
            secret: "expired".into(),
            c: point(241),
        }])
        .unwrap();

        assert!(matches!(
            check_standard_cashu_spend_for_offer(&spend, &verified_offer, 151),
            Err(ServiceProtocolError::InvalidValue {
                field: "CashuKeysetBindingV1.final_expiry",
                ..
            })
        ));
    }

    #[test]
    fn standard_cashu_policy_tamper_cannot_reach_offer_guard_typestate() {
        let keyset = cashu_manifest_keyset(&[1], 0, None, 151);
        let (policy, policy_key) = standard_cashu_policy(1, vec![keyset.clone()], keyset, 500, 0);

        for mutate in [0u8, 1u8] {
            let mut tampered = policy.clone();
            let offer = &mut tampered.scopes[0].offers[0];
            if mutate == 0 {
                offer.issuer_id[0] ^= 1;
            } else {
                offer.key_id[0] ^= 1;
            }
            assert!(tampered
                .verify_current_for_acquisition(
                    &policy.provider_id,
                    120,
                    &PolicyRollbackGuardV1::initial(),
                    &ServicePolicyEpochFloorsV1::initial(),
                    &policy_key.verifying_key(),
                )
                .is_err());
        }
    }

    #[test]
    fn standard_cashu_guard_does_not_claim_signature_or_spent_verification() {
        let keyset = cashu_manifest_keyset(&[1], 0, None, 161);
        let (policy, policy_key) =
            standard_cashu_policy(1, vec![keyset.clone()], keyset.clone(), 500, 0);
        let verified_offer = standard_cashu_offer(&policy, &policy_key, 120);
        // These are merely valid curve points, not signatures produced by the
        // manifest key. Only the authoritative NUT-03 swap may accept them.
        for c in [point(261), point(262)] {
            let spend = StandardCashuSpendV1::new_canonical(vec![StandardCashuProofV1 {
                keyset_id: keyset.keyset_id.clone(),
                amount: 1,
                secret: format!("unverified-{c:?}"),
                c,
            }])
            .unwrap();
            assert!(check_standard_cashu_spend_for_offer(&spend, &verified_offer, 120).is_ok());
        }
    }

    #[test]
    fn bat_is_fixed_binary_and_uses_underlying_key_for_global_spend_key() {
        let proof = BitcoinPirCashuBatProofV1 {
            secret_raw: [0x22; 32],
            c: point(1),
        };
        let encoded = proof.encode().unwrap();
        assert_eq!(encoded[0], 1);
        assert_eq!(&encoded[1..33], &[0x22; 32]);
        assert_eq!(&encoded[33..], point(1));
        assert_eq!(BitcoinPirCashuBatProofV1::decode(&encoded).unwrap(), proof);
        let first_key = point(2);
        let second_key = point(3);
        assert_eq!(
            proof.spend_key(&first_key).unwrap(),
            proof.spend_key(&first_key).unwrap()
        );
        assert_ne!(
            proof.spend_key(&first_key).unwrap(),
            proof.spend_key(&second_key).unwrap()
        );
        assert!(proof.spend_key(&[0; 33]).is_err());
        assert!(BitcoinPirCashuBatProofV1::decode(&encoded[..65]).is_err());
    }

    #[test]
    fn arc_requires_and_enforces_decode_reencode_hook() {
        let presentation = ArcPresentationV1::from_canonical_bytes(vec![1, 2, 3]).unwrap();
        let encoded = presentation.encode().unwrap();
        assert!(decode_authorization_proof_v1(
            AuthScheme::ArcV1Experimental,
            FreeModeV1::NotFree,
            &encoded,
            None,
        )
        .is_err());

        let identity = |bytes: &[u8]| Ok(bytes.to_vec());
        assert!(decode_authorization_proof_v1(
            AuthScheme::ArcV1Experimental,
            FreeModeV1::NotFree,
            &encoded,
            Some(&identity),
        )
        .is_ok());

        let normalize = |_bytes: &[u8]| Ok(vec![1, 2]);
        assert!(decode_authorization_proof_v1(
            AuthScheme::ArcV1Experimental,
            FreeModeV1::NotFree,
            &encoded,
            Some(&normalize),
        )
        .is_err());
    }

    #[test]
    fn high_level_dispatch_rejects_cross_scheme_and_free_mode_confusion() {
        let bat = AuthorizationProofV1::BitcoinPirCashuBat(BitcoinPirCashuBatProofV1 {
            secret_raw: [1; 32],
            c: point(1),
        });
        let encoded = bat
            .encode_for(AuthScheme::BitcoinPirCashuBatV1, FreeModeV1::NotFree)
            .unwrap();
        assert!(bat
            .encode_for(AuthScheme::CashuEcashV1, FreeModeV1::NotFree)
            .is_err());
        assert!(decode_authorization_proof_v1(
            AuthScheme::CashuEcashV1,
            FreeModeV1::NotFree,
            &encoded,
            None,
        )
        .is_err());
        assert!(decode_authorization_proof_v1(
            AuthScheme::BitcoinPirCashuBatV1,
            FreeModeV1::ProofOfWork,
            &encoded,
            None,
        )
        .is_err());
    }
}
