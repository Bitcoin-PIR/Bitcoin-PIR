//! Canonical shared-issuer settlement messages.
//!
//! These types deliberately contain no network client and cannot move funds.
//! Debt-creating provider requests are signed with
//! [`ProviderClearingRequestAuthV1`] under a current, operator-authorized
//! clearing key. Deposit recovery and read-only payout status instead use
//! [`ProviderSettlementRequestAuthV1`] under a current provider registration,
//! independent of the original clearing authorization. Each successful
//! response is signed by the issuer settlement key and binds the exact request.

use core::fmt;
use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::codec::{expect_v1, put_bytes_u16, Decoder};
use crate::{
    issuer_settlement_key_id, IssuerClearingApprovalV1, ProviderClearingAuthorizationV1,
    ProviderClearingExpectationV1, ProviderClearingRequestAuthV1, ProviderId,
    ProviderRedeemRequestV1, ServiceProtocolError, SettlementDestinationV1, SettlementUnitV1,
    CASHU_KEYSET_ID_V2_LEN, MAX_SERVICE_VALUE_V1, MAX_SETTLEMENT_OUTPUTS, SERVICE_PROTOCOL_VERSION,
};

pub const MAX_SETTLEMENT_SECRET_LEN_V1: usize = 1_024;
pub const MAX_SETTLEMENT_WITNESS_LEN_V1: usize = 2_048;
pub const MAX_SETTLEMENT_NOTES_V1: usize = 64;

pub const PROVIDER_REDEEM_RESPONSE_SIGNATURE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-redeem-response/POST-/v1/redeems/v1";
pub const SETTLEMENT_NOTE_PRESENTATION_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/settlement-note-presentation-digest/v1";
pub const PROVIDER_SETTLEMENT_DEPOSIT_REQUEST_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-settlement-deposit-request/POST-/v1/settlement/deposits/v1";
pub const PROVIDER_SETTLEMENT_DEPOSIT_RESPONSE_SIGNATURE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-settlement-deposit-response/POST-/v1/settlement/deposits/v1";
pub const PROVIDER_BALANCE_REQUEST_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-balance-request/POST-/v1/settlement/balance/v1";
pub const ISSUER_BALANCE_RESPONSE_SIGNATURE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-balance-response/POST-/v1/settlement/balance/v1";
pub const PROVIDER_PAYOUT_INTENT_REQUEST_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-payout-intent-request/POST-/v1/settlement/payout-intents/v1";
pub const ISSUER_PAYOUT_INTENT_RESPONSE_SIGNATURE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-payout-intent-response/POST-/v1/settlement/payout-intents/v1";
pub const PROVIDER_PAYOUT_REQUEST_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-payout-request/POST-/v1/settlement/payouts/v1";
pub const ISSUER_PAYOUT_RESPONSE_SIGNATURE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-payout-response/POST-/v1/settlement/payouts/v1";
pub const PROVIDER_PAYOUT_STATUS_REQUEST_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-payout-status-request/POST-/v1/settlement/payout-status/v1";
pub const ISSUER_PAYOUT_STATUS_RESPONSE_SIGNATURE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/issuer-payout-status-response/POST-/v1/settlement/payout-status/v1";
pub const PAYOUT_INTENT_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/payout-intent-digest/v1";
pub const PROVIDER_SETTLEMENT_REQUEST_SIGNATURE_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/provider-settlement-request-auth/v1";
pub const SETTLEMENT_DENOMINATION_KEY_FINGERPRINT_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/settlement-denomination-key-fingerprint/v1";
pub const SETTLEMENT_NOTE_SPEND_KEY_DOMAIN_V1: &[u8] = b"BitcoinPIR/settlement-note-spend-key/v1";

/// Exact public inputs which a Cashu implementation must pass to its NUT-12
/// DLEQ verifier. The protocol crate deliberately does not implement the
/// secp256k1 DLEQ relation itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CashuDleqVerificationInputV1<'a> {
    pub denomination: u64,
    pub denomination_public_key: &'a [u8; 33],
    pub blinded_message: &'a [u8; 33],
    pub blinded_signature: &'a [u8; 33],
    pub dleq_e: &'a [u8; 32],
    pub dleq_s: &'a [u8; 32],
}

/// Adapter boundary for authoritative NUT-12 verification.
///
/// Returning `Ok(())` asserts that the exact tuple in `input` satisfies the
/// NUT-12 DLEQ relation under `denomination_public_key`. Structural point and
/// scalar parsing performed by this crate is not a substitute for this call.
pub trait CashuDleqVerifierV1 {
    fn verify_dleq(
        &self,
        input: CashuDleqVerificationInputV1<'_>,
    ) -> Result<(), ServiceProtocolError>;
}

/// Exact public inputs which the issuer's Cashu implementation must verify
/// before a settlement note may be treated as authentic or spent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CashuSettlementNoteVerificationInputV1<'a> {
    pub denomination: u64,
    pub denomination_public_key: &'a [u8; 33],
    pub secret: &'a str,
    pub signature: &'a [u8; 33],
    pub witness: Option<&'a str>,
}

impl fmt::Debug for CashuSettlementNoteVerificationInputV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CashuSettlementNoteVerificationInputV1")
            .field("denomination", &self.denomination)
            .field("secret", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .field("witness", &self.witness.map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
}

/// Adapter boundary for authoritative Cashu-note verification.
///
/// The adapter must verify the Cashu signature and every spending condition
/// represented by `secret`/`witness`, then return the authoritative Cashu
/// `Y = hash_to_curve(secret)` as a canonical compressed point. Returning a Y
/// supplied by the request instead of deriving it is unsafe.
pub trait CashuSettlementNoteVerifierV1 {
    fn verify_note_and_derive_y(
        &self,
        input: CashuSettlementNoteVerificationInputV1<'_>,
    ) -> Result<[u8; 33], ServiceProtocolError>;
}

/// Trusted, current provider registration loaded from the issuer's local
/// registry. It is deliberately independent of a debt-creating clearing
/// authorization, so note recovery and payout-status recovery remain possible
/// after the original clearing authorization expires.
///
/// Every field is trusted local context, never copied from a request body.
pub struct ProviderSettlementRegistrationExpectationV1<'a> {
    pub registration_digest: &'a [u8; 32],
    pub provider_id: &'a ProviderId,
    pub issuer_id: &'a [u8; 32],
    pub settlement_account_id: &'a [u8; 32],
    pub provider_request_key: &'a VerifyingKey,
    pub issuer_settlement_key: &'a VerifyingKey,
    pub not_before: u64,
    pub not_after: u64,
    pub now_unix: u64,
}

impl ProviderSettlementRegistrationExpectationV1<'_> {
    fn validate_current(&self) -> Result<(), ServiceProtocolError> {
        validate_nonzero(self.registration_digest, "provider registration digest")?;
        validate_nonzero(self.provider_id, "provider registration provider_id")?;
        validate_nonzero(self.issuer_id, "provider registration issuer_id")?;
        validate_nonzero(
            self.settlement_account_id,
            "provider registration settlement_account_id",
        )?;
        if self.not_before == 0
            || self.not_after < self.not_before
            || self.now_unix < self.not_before
            || self.now_unix > self.not_after
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderSettlementRegistrationExpectationV1.validity",
                reason: "trusted provider registration is not currently valid",
            });
        }
        Ok(())
    }
}

/// Trusted issuer settlement-signing-key lineage used to verify durable
/// responses across key rotation. The current key is the key named by the
/// provider's current registration; retained keys exist only to verify
/// already-persisted historical responses.
///
/// Key lookup is always by the key ID carried inside the signed response. A
/// caller cannot substitute another issuer's registry because `issuer_id` is
/// checked against the request/registration before any key is returned.
pub struct IssuerSettlementKeyringExpectationV1<'a> {
    pub issuer_id: &'a [u8; 32],
    pub current_key: &'a VerifyingKey,
    pub retained_keys: &'a [VerifyingKey],
}

impl IssuerSettlementKeyringExpectationV1<'_> {
    fn validate_for_issuer(
        &self,
        expected_issuer_id: &[u8; 32],
    ) -> Result<(), ServiceProtocolError> {
        validate_nonzero(
            self.issuer_id,
            "IssuerSettlementKeyringExpectationV1.issuer_id",
        )?;
        if self.issuer_id != expected_issuer_id {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerSettlementKeyringExpectationV1.issuer_id",
                reason: "settlement key lineage belongs to another issuer",
            });
        }

        let current_id = issuer_settlement_key_id(self.current_key);
        if self
            .retained_keys
            .iter()
            .any(|key| issuer_settlement_key_id(key) == current_id)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerSettlementKeyringExpectationV1.retained_keys",
                reason: "current settlement key is duplicated in retained keys",
            });
        }
        let mut retained_ids = HashSet::with_capacity(self.retained_keys.len());
        if self
            .retained_keys
            .iter()
            .any(|key| !retained_ids.insert(issuer_settlement_key_id(key)))
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerSettlementKeyringExpectationV1.retained_keys",
                reason: "retained settlement key IDs must be unique",
            });
        }
        Ok(())
    }

    fn validate_for_registration(
        &self,
        registration: &ProviderSettlementRegistrationExpectationV1<'_>,
    ) -> Result<(), ServiceProtocolError> {
        registration.validate_current()?;
        self.validate_for_issuer(registration.issuer_id)?;
        if self.current_key.to_bytes() != registration.issuer_settlement_key.to_bytes() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerSettlementKeyringExpectationV1.current_key",
                reason: "current key does not match the provider registration",
            });
        }
        Ok(())
    }

    /// Resolves a signed response key ID only within this caller-supplied,
    /// issuer-bound current/retained lineage. This never accepts a key from a
    /// response or network payload as trust material.
    pub fn resolve_for_issuer(
        &self,
        expected_issuer_id: &[u8; 32],
        signed_key_id: &[u8; 16],
    ) -> Result<&VerifyingKey, ServiceProtocolError> {
        self.validate_for_issuer(expected_issuer_id)?;
        if issuer_settlement_key_id(self.current_key) == *signed_key_id {
            return Ok(self.current_key);
        }
        self.retained_keys
            .iter()
            .find(|key| issuer_settlement_key_id(key) == *signed_key_id)
            .ok_or(ServiceProtocolError::WrongSigningKeyId)
    }
}

/// Provider authentication for recovery/read-only settlement endpoints.
/// This is separate from [`ProviderClearingRequestAuthV1`], whose authority is
/// intentionally tied to a debt-creating clearing authorization.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderSettlementRequestAuthV1 {
    pub registration_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub signature: [u8; 64],
}

impl fmt::Debug for ProviderSettlementRequestAuthV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSettlementRequestAuthV1")
            .field("registration_digest", &"[REDACTED]")
            .field("request_digest", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ProviderSettlementRequestAuthV1 {
    fn drop(&mut self) {
        self.registration_digest.zeroize();
        self.request_digest.zeroize();
        self.signature.zeroize();
    }
}

impl ProviderSettlementRequestAuthV1 {
    pub fn sign(
        registration_digest: [u8; 32],
        request_digest: [u8; 32],
        provider_request_signing_key: &SigningKey,
    ) -> Self {
        let mut value = Self {
            registration_digest,
            request_digest,
            signature: [0; 64],
        };
        value.signature = provider_request_signing_key
            .sign(&value.signing_preimage())
            .to_bytes();
        value
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(129);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.registration_digest);
        out.extend_from_slice(&self.request_digest);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("ProviderSettlementRequestAuthV1.version")?,
            "ProviderSettlementRequestAuthV1",
        )?;
        let value = Self {
            registration_digest: decoder
                .fixed("ProviderSettlementRequestAuthV1.registration_digest")?,
            request_digest: decoder.fixed("ProviderSettlementRequestAuthV1.request_digest")?,
            signature: decoder.fixed("ProviderSettlementRequestAuthV1.signature")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    fn verify_for(
        &self,
        expected_request_digest: &[u8; 32],
        expectation: &ProviderSettlementRegistrationExpectationV1<'_>,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        expectation.validate_current()?;
        if &self.registration_digest != expectation.registration_digest
            || &self.request_digest != expected_request_digest
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderSettlementRequestAuthV1.binding",
                reason: "registration or exact request digest mismatch",
            });
        }
        expectation
            .provider_request_key
            .verify_strict(
                &self.signing_preimage(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ServiceProtocolError::BadSignature)
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_nonzero(
            &self.registration_digest,
            "ProviderSettlementRequestAuthV1.registration_digest",
        )?;
        validate_nonzero(
            &self.request_digest,
            "ProviderSettlementRequestAuthV1.request_digest",
        )
    }

    fn signing_preimage(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(PROVIDER_SETTLEMENT_REQUEST_SIGNATURE_DOMAIN_V1.len() + 64);
        out.extend_from_slice(PROVIDER_SETTLEMENT_REQUEST_SIGNATURE_DOMAIN_V1);
        out.extend_from_slice(&self.registration_digest);
        out.extend_from_slice(&self.request_digest);
        out
    }
}

/// The issuer's retained settlement keyset registry. New settlement deposits
/// and blind-output verification resolve an exact keyset from this registry;
/// they do not trust a keyset embedded in an old clearing authorization.
pub struct RetainedSettlementKeysetExpectationV1<'a> {
    /// Stable issuer/root lineage that authorized every keyset in this
    /// registry. Keyset IDs alone do not identify an issuer.
    pub issuer_id: &'a [u8; 32],
    pub retained_keysets: &'a [crate::CashuKeysetBindingV1],
    pub now_unix: u64,
}

/// A validated, unexpired exact keyset selected from the trusted registry.
pub struct RetainedSettlementKeysetV1<'a> {
    keyset: &'a crate::CashuKeysetBindingV1,
}

impl<'a> RetainedSettlementKeysetExpectationV1<'a> {
    fn verify_exact_keyset_for_issuer(
        &'a self,
        expected_issuer_id: &[u8; 32],
        keyset_id: &str,
        unit: SettlementUnitV1,
        denominations: impl IntoIterator<Item = u64>,
    ) -> Result<RetainedSettlementKeysetV1<'a>, ServiceProtocolError> {
        validate_nonzero(
            self.issuer_id,
            "RetainedSettlementKeysetExpectationV1.issuer_id",
        )?;
        if self.issuer_id != expected_issuer_id {
            return Err(ServiceProtocolError::InvalidValue {
                field: "RetainedSettlementKeysetExpectationV1.issuer_id",
                reason: "retained settlement keysets belong to another issuer",
            });
        }
        if self.now_unix == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "RetainedSettlementKeysetExpectationV1.now_unix",
                reason: "must be non-zero",
            });
        }
        let mut matches = self
            .retained_keysets
            .iter()
            .filter(|candidate| candidate.keyset_id == keyset_id);
        let keyset = matches.next().ok_or(ServiceProtocolError::InvalidValue {
            field: "settlement_keyset_id",
            reason: "keyset is absent from the trusted retained registry",
        })?;
        if matches.next().is_some() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "settlement_keyset_id",
                reason: "trusted retained registry contains a duplicate keyset ID",
            });
        }
        keyset.validate()?;
        if keyset.unit != unit.cashu_unit()
            || match keyset.final_expiry {
                Some(final_expiry) => self.now_unix >= final_expiry,
                None => true,
            }
            || denominations.into_iter().any(|denomination| {
                keyset
                    .keys
                    .binary_search_by_key(&denomination, |key| key.amount)
                    .is_err()
            })
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "RetainedSettlementKeysetExpectationV1.keyset",
                reason: "unit, denomination, or unexpired recovery horizon does not match",
            });
        }
        Ok(RetainedSettlementKeysetV1 { keyset })
    }
}

impl RetainedSettlementKeysetV1<'_> {
    pub fn keyset_id(&self) -> &str {
        &self.keyset.keyset_id
    }

    pub fn unit(&self) -> &str {
        &self.keyset.unit
    }

    pub fn final_expiry(&self) -> u64 {
        self.keyset
            .final_expiry
            .expect("retained keyset constructor requires final_expiry")
    }

    pub fn denomination_public_key(
        &self,
        denomination: u64,
    ) -> Result<&[u8; 33], ServiceProtocolError> {
        self.keyset
            .keys
            .binary_search_by_key(&denomination, |key| key.amount)
            .map(|index| &self.keyset.keys[index].public_key)
            .map_err(|_| ServiceProtocolError::InvalidValue {
                field: "settlement denomination",
                reason: "denomination is absent from the retained keyset",
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlindSettlementSignatureV1 {
    pub denomination: u64,
    /// Exact request `B_` echoed by the issuer.
    pub blinded_message: [u8; 33],
    /// Blind signature `C_`.
    pub blinded_signature: [u8; 33],
    /// NUT-12 DLEQ proof scalars. The wallet blinding scalar `r` is never part
    /// of this protocol.
    pub dleq_e: [u8; 32],
    pub dleq_s: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RedeemSettlementResultV1 {
    LedgerCredit {
        account_id: [u8; 32],
        ledger_transaction_id: [u8; 32],
    },
    BlindOutputs {
        settlement_keyset_id: String,
        signatures: Vec<BlindSettlementSignatureV1>,
    },
}

/// Issuer-signed success response for one exact provider redeem request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRedeemResponseV1 {
    pub issuer_settlement_key_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub authorization_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub unit: SettlementUnitV1,
    pub accepted_value: u64,
    pub provider_credit: u64,
    pub issuer_fee: u64,
    pub result: RedeemSettlementResultV1,
    pub signature: [u8; 64],
}

impl ProviderRedeemResponseV1 {
    pub fn sign(
        mut value: Self,
        issuer_settlement_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        value.issuer_settlement_key_id =
            issuer_settlement_key_id(&issuer_settlement_signing_key.verifying_key());
        value.signature = [0; 64];
        value.validate()?;
        value.signature = issuer_settlement_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("ProviderRedeemResponseV1.version")?,
            "ProviderRedeemResponseV1",
        )?;
        let issuer_settlement_key_id =
            decoder.fixed("ProviderRedeemResponseV1.issuer_settlement_key_id")?;
        let request_digest = decoder.fixed("ProviderRedeemResponseV1.request_digest")?;
        let authorization_digest =
            decoder.fixed("ProviderRedeemResponseV1.authorization_digest")?;
        let issuer_id = decoder.fixed("ProviderRedeemResponseV1.issuer_id")?;
        let provider_id = decoder.fixed("ProviderRedeemResponseV1.provider_id")?;
        let unit = SettlementUnitV1::decode(decoder.u8("ProviderRedeemResponseV1.unit")?)?;
        let accepted_value = decoder.u64("ProviderRedeemResponseV1.accepted_value")?;
        let provider_credit = decoder.u64("ProviderRedeemResponseV1.provider_credit")?;
        let issuer_fee = decoder.u64("ProviderRedeemResponseV1.issuer_fee")?;
        let result = match decoder.u8("ProviderRedeemResponseV1.result")? {
            1 => RedeemSettlementResultV1::LedgerCredit {
                account_id: decoder.fixed("ProviderRedeemResponseV1.account_id")?,
                ledger_transaction_id: decoder
                    .fixed("ProviderRedeemResponseV1.ledger_transaction_id")?,
            },
            2 => {
                let settlement_keyset_id = decode_keyset_id(
                    &mut decoder,
                    "ProviderRedeemResponseV1.settlement_keyset_id",
                )?;
                let count = decoder.u8("ProviderRedeemResponseV1.signature_count")? as usize;
                if count > MAX_SETTLEMENT_OUTPUTS {
                    return Err(ServiceProtocolError::TooManyItems {
                        field: "ProviderRedeemResponseV1.signatures",
                        len: count,
                        max: MAX_SETTLEMENT_OUTPUTS,
                    });
                }
                let mut signatures = Vec::with_capacity(count);
                for _ in 0..count {
                    signatures.push(BlindSettlementSignatureV1 {
                        denomination: decoder.u64("BlindSettlementSignatureV1.denomination")?,
                        blinded_message: decoder
                            .fixed("BlindSettlementSignatureV1.blinded_message")?,
                        blinded_signature: decoder
                            .fixed("BlindSettlementSignatureV1.blinded_signature")?,
                        dleq_e: decoder.fixed("BlindSettlementSignatureV1.dleq_e")?,
                        dleq_s: decoder.fixed("BlindSettlementSignatureV1.dleq_s")?,
                    });
                }
                RedeemSettlementResultV1::BlindOutputs {
                    settlement_keyset_id,
                    signatures,
                }
            }
            value => {
                return Err(ServiceProtocolError::UnknownDiscriminant {
                    kind: "ProviderRedeemResponseV1.result",
                    value,
                })
            }
        };
        let value = Self {
            issuer_settlement_key_id,
            request_digest,
            authorization_digest,
            issuer_id,
            provider_id,
            unit,
            accepted_value,
            provider_credit,
            issuer_fee,
            result,
            signature: decoder.fixed("ProviderRedeemResponseV1.signature")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Structural and outer-signature verification only. In particular this
    /// does **not** prove a NUT-12 DLEQ relation for blind outputs. Public
    /// callers must use [`verify_redeem_response_for_exact_request`] or
    /// [`verify_new_redeem_response_for`], both of which require a Cashu
    /// verifier adapter and return a verified typestate.
    fn verify_structure_for_exact_request(
        &self,
        request: &ProviderRedeemRequestV1,
        authorization: &ProviderClearingAuthorizationV1,
        expected_issuer_settlement_key: &VerifyingKey,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        verify_issuer_signature(
            self.issuer_settlement_key_id,
            &self.signature,
            &self.signing_preimage()?,
            expected_issuer_settlement_key,
        )?;
        request.validate()?;
        request.validate_against_authorization(authorization)?;
        let rule = authorization
            .rule_for_binding(&request.credential_binding_digest)
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemResponseV1.rule",
                reason: "request binding has no approved settlement rule",
            })?;
        if self.request_digest != request.request_digest()?
            || self.authorization_digest != authorization.authorization_digest()?
            || self.issuer_id != request.issuer_id
            || self.provider_id != request.provider_id
            || self.unit != rule.unit
            || self.accepted_value != rule.accepted_value
            || self.provider_credit != rule.provider_credit
            || self.issuer_fee != rule.issuer_fee
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemResponseV1.binding",
                reason: "response does not bind the exact request and issuer-approved rule",
            });
        }
        match (&request.destination, &self.result) {
            (
                SettlementDestinationV1::LedgerCredit { account_id },
                RedeemSettlementResultV1::LedgerCredit {
                    account_id: response_account,
                    ..
                },
            ) if account_id == response_account => Ok(()),
            (
                SettlementDestinationV1::BlindOutputs {
                    settlement_keyset_id,
                    outputs,
                },
                RedeemSettlementResultV1::BlindOutputs {
                    settlement_keyset_id: response_keyset,
                    signatures,
                },
            ) if settlement_keyset_id == response_keyset
                && outputs.len() == signatures.len()
                && outputs.iter().zip(signatures).all(|(output, signature)| {
                    output.denomination == signature.denomination
                        && output.blinded_message == signature.blinded_message
                }) =>
            {
                Ok(())
            }
            _ => Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemResponseV1.result",
                reason: "response changed settlement mode, account, keyset, or blinded output",
            }),
        }
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(512);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.issuer_settlement_key_id);
        out.extend_from_slice(&self.request_digest);
        out.extend_from_slice(&self.authorization_digest);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.provider_id);
        out.push(self.unit as u8);
        out.extend_from_slice(&self.accepted_value.to_le_bytes());
        out.extend_from_slice(&self.provider_credit.to_le_bytes());
        out.extend_from_slice(&self.issuer_fee.to_le_bytes());
        match &self.result {
            RedeemSettlementResultV1::LedgerCredit {
                account_id,
                ledger_transaction_id,
            } => {
                out.push(1);
                out.extend_from_slice(account_id);
                out.extend_from_slice(ledger_transaction_id);
            }
            RedeemSettlementResultV1::BlindOutputs {
                settlement_keyset_id,
                signatures,
            } => {
                out.push(2);
                put_keyset_id(&mut out, settlement_keyset_id);
                out.push(signatures.len() as u8);
                for signature in signatures {
                    out.extend_from_slice(&signature.denomination.to_le_bytes());
                    out.extend_from_slice(&signature.blinded_message);
                    out.extend_from_slice(&signature.blinded_signature);
                    out.extend_from_slice(&signature.dleq_e);
                    out.extend_from_slice(&signature.dleq_s);
                }
            }
        }
        Ok(out)
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut out =
            Vec::with_capacity(PROVIDER_REDEEM_RESPONSE_SIGNATURE_DOMAIN_V1.len() + unsigned.len());
        out.extend_from_slice(PROVIDER_REDEEM_RESPONSE_SIGNATURE_DOMAIN_V1);
        out.extend_from_slice(&unsigned);
        Ok(out)
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_common_response(
            self.issuer_settlement_key_id,
            self.request_digest,
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
        )?;
        validate_value(
            self.accepted_value,
            "ProviderRedeemResponseV1.accepted_value",
        )?;
        validate_value(
            self.provider_credit,
            "ProviderRedeemResponseV1.provider_credit",
        )?;
        if self.issuer_fee > MAX_SERVICE_VALUE_V1
            || self.provider_credit.checked_add(self.issuer_fee) != Some(self.accepted_value)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemResponseV1.value",
                reason: "provider credit plus issuer fee must equal accepted value",
            });
        }
        match &self.result {
            RedeemSettlementResultV1::LedgerCredit {
                account_id,
                ledger_transaction_id,
            } => {
                validate_nonzero(account_id, "ProviderRedeemResponseV1.account_id")?;
                validate_nonzero(
                    ledger_transaction_id,
                    "ProviderRedeemResponseV1.ledger_transaction_id",
                )?;
            }
            RedeemSettlementResultV1::BlindOutputs {
                settlement_keyset_id,
                signatures,
            } => {
                validate_keyset_id(settlement_keyset_id)?;
                if signatures.is_empty() || signatures.len() > MAX_SETTLEMENT_OUTPUTS {
                    return Err(ServiceProtocolError::TooManyItems {
                        field: "ProviderRedeemResponseV1.signatures",
                        len: signatures.len(),
                        max: MAX_SETTLEMENT_OUTPUTS,
                    });
                }
                let mut prior: Option<(u64, [u8; 33])> = None;
                let mut messages = HashSet::with_capacity(signatures.len());
                let mut returned = HashSet::with_capacity(signatures.len());
                let mut total = 0u64;
                for item in signatures {
                    validate_value(item.denomination, "BlindSettlementSignatureV1.denomination")?;
                    if !crate::cashu_manifest::is_valid_compressed_point(&item.blinded_message)
                        || !crate::cashu_manifest::is_valid_compressed_point(
                            &item.blinded_signature,
                        )
                        || !is_valid_nonzero_scalar(&item.dleq_e)
                        || !is_valid_nonzero_scalar(&item.dleq_s)
                        || !messages.insert(item.blinded_message)
                        || !returned.insert(item.blinded_signature)
                    {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "BlindSettlementSignatureV1",
                            reason:
                                "points/scalars must be canonical and unique; DLEQ r is forbidden",
                        });
                    }
                    let key = (item.denomination, item.blinded_message);
                    if prior.is_some_and(|value| value >= key) {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "ProviderRedeemResponseV1.signatures",
                            reason:
                                "blind signatures must follow request denomination/message order",
                        });
                    }
                    prior = Some(key);
                    total = checked_add(
                        total,
                        item.denomination,
                        "ProviderRedeemResponseV1.signatures",
                    )?;
                }
                if total != self.provider_credit {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ProviderRedeemResponseV1.signatures",
                        reason: "blind signature denominations do not equal provider credit",
                    });
                }
            }
        }
        Ok(())
    }
}

/// A NUT-12 tuple accepted by the caller-supplied Cashu verifier under the
/// exact denomination public key from the retained registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBlindSettlementPromiseV1 {
    denomination: u64,
    denomination_public_key: [u8; 33],
    blinded_message: [u8; 33],
    blinded_signature: [u8; 33],
}

impl VerifiedBlindSettlementPromiseV1 {
    pub fn denomination(&self) -> u64 {
        self.denomination
    }

    pub fn denomination_public_key(&self) -> &[u8; 33] {
        &self.denomination_public_key
    }

    pub fn blinded_message(&self) -> &[u8; 33] {
        &self.blinded_message
    }

    pub fn blinded_signature(&self) -> &[u8; 33] {
        &self.blinded_signature
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedRedeemSettlementResultV1 {
    LedgerCredit,
    BlindOutputs {
        settlement_keyset_id: String,
        promises: Vec<VerifiedBlindSettlementPromiseV1>,
    },
}

/// A redeem response whose issuer signature, exact request echo, and (for
/// blind outputs) every NUT-12 proof have all been verified.
pub struct VerifiedProviderRedeemResponseV1<'a> {
    response: &'a ProviderRedeemResponseV1,
    result: VerifiedRedeemSettlementResultV1,
}

/// Trusted Cashu verification dependencies for a redeem response. Grouping
/// these inputs makes it harder for handlers to accidentally pass a keyset
/// registry and DLEQ adapter from different integration paths.
pub struct RedeemResponseCryptoExpectationV1<'a, 'keysets> {
    pub retained_keysets: &'a RetainedSettlementKeysetExpectationV1<'keysets>,
    pub dleq_verifier: &'a dyn CashuDleqVerifierV1,
}

impl<'a> VerifiedProviderRedeemResponseV1<'a> {
    pub fn response(&self) -> &'a ProviderRedeemResponseV1 {
        self.response
    }

    pub fn result(&self) -> &VerifiedRedeemSettlementResultV1 {
        &self.result
    }
}

/// Verifies a stored exact response without re-applying current-time clearing
/// authorization checks. A blind-output replay still requires an unexpired
/// retained keyset and authoritative NUT-12 verification; an outer Ed25519
/// signature alone never produces this typestate.
pub fn verify_redeem_response_for_exact_request<'a>(
    response: &'a ProviderRedeemResponseV1,
    request: &ProviderRedeemRequestV1,
    authorization: &ProviderClearingAuthorizationV1,
    expected_issuer_settlement_key: &VerifyingKey,
    retained_keysets: &RetainedSettlementKeysetExpectationV1<'_>,
    dleq_verifier: &dyn CashuDleqVerifierV1,
) -> Result<VerifiedProviderRedeemResponseV1<'a>, ServiceProtocolError> {
    response.verify_structure_for_exact_request(
        request,
        authorization,
        expected_issuer_settlement_key,
    )?;
    let result = match &response.result {
        RedeemSettlementResultV1::LedgerCredit { .. } => {
            VerifiedRedeemSettlementResultV1::LedgerCredit
        }
        RedeemSettlementResultV1::BlindOutputs {
            settlement_keyset_id,
            signatures,
        } => {
            let retained = retained_keysets.verify_exact_keyset_for_issuer(
                &response.issuer_id,
                settlement_keyset_id,
                response.unit,
                signatures.iter().map(|signature| signature.denomination),
            )?;
            let mut promises = Vec::with_capacity(signatures.len());
            for signature in signatures {
                let denomination_public_key =
                    retained.denomination_public_key(signature.denomination)?;
                dleq_verifier.verify_dleq(CashuDleqVerificationInputV1 {
                    denomination: signature.denomination,
                    denomination_public_key,
                    blinded_message: &signature.blinded_message,
                    blinded_signature: &signature.blinded_signature,
                    dleq_e: &signature.dleq_e,
                    dleq_s: &signature.dleq_s,
                })?;
                promises.push(VerifiedBlindSettlementPromiseV1 {
                    denomination: signature.denomination,
                    denomination_public_key: *denomination_public_key,
                    blinded_message: signature.blinded_message,
                    blinded_signature: signature.blinded_signature,
                });
            }
            VerifiedRedeemSettlementResultV1::BlindOutputs {
                settlement_keyset_id: settlement_keyset_id.clone(),
                promises,
            }
        }
    };
    Ok(VerifiedProviderRedeemResponseV1 { response, result })
}

/// Verify the ledger-credit form of an exact shared-issuer redemption without
/// requiring irrelevant Cashu blind-output dependencies. Both directions must
/// select the issuer-approved ledger destination.
pub fn verify_ledger_redeem_response_for_exact_request_v1<'a>(
    response: &'a ProviderRedeemResponseV1,
    request: &ProviderRedeemRequestV1,
    authorization: &ProviderClearingAuthorizationV1,
    expected_issuer_settlement_key: &VerifyingKey,
) -> Result<VerifiedProviderRedeemResponseV1<'a>, ServiceProtocolError> {
    if !matches!(
        request.destination,
        SettlementDestinationV1::LedgerCredit { .. }
    ) || !matches!(
        response.result,
        RedeemSettlementResultV1::LedgerCredit { .. }
    ) {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ProviderRedeemResponseV1.result",
            reason: "ledger verifier accepts only exact ledger-credit requests and responses",
        });
    }
    response.verify_structure_for_exact_request(
        request,
        authorization,
        expected_issuer_settlement_key,
    )?;
    Ok(VerifiedProviderRedeemResponseV1 {
        response,
        result: VerifiedRedeemSettlementResultV1::LedgerCredit,
    })
}

/// Composite new-request/response validation. Exact committed replays use
/// [`verify_redeem_response_for_exact_request`] before applying any current
/// authorization policy.
pub fn verify_new_redeem_response_for<'a>(
    response: &'a ProviderRedeemResponseV1,
    request: &ProviderRedeemRequestV1,
    authorization: &ProviderClearingAuthorizationV1,
    issuer_approval: &IssuerClearingApprovalV1,
    request_auth: &ProviderClearingRequestAuthV1,
    expectation: &ProviderClearingExpectationV1<'_>,
    crypto: &RedeemResponseCryptoExpectationV1<'_, '_>,
) -> Result<VerifiedProviderRedeemResponseV1<'a>, ServiceProtocolError> {
    let authorization_digest = authorization.authorization_digest()?;
    let request_digest = request.request_digest()?;
    request_auth.verify_for(
        &authorization_digest,
        &request_digest,
        authorization,
        issuer_approval,
        expectation,
    )?;
    if crypto.retained_keysets.now_unix != expectation.now_unix {
        return Err(ServiceProtocolError::InvalidValue {
            field: "RetainedSettlementKeysetExpectationV1.now_unix",
            reason: "must use the same trusted clock as clearing authorization verification",
        });
    }
    verify_redeem_response_for_exact_request(
        response,
        request,
        authorization,
        expectation.issuer_settlement_key,
        crypto.retained_keysets,
        crypto.dleq_verifier,
    )
}

/// Canonical settlement-note wire data. Constructing or decoding this value
/// checks only bounds, canonical point encoding, and presentation digest. It
/// does not assert that `signature` is a valid Cashu signature. Only
/// [`verify_new_settlement_deposit_request_for`] returns an authenticated-note
/// typestate after calling [`CashuSettlementNoteVerifierV1`].
#[derive(Clone, PartialEq, Eq)]
pub struct SettlementNoteV1 {
    pub presentation_digest: [u8; 32],
    pub denomination: u64,
    pub secret: String,
    pub signature: [u8; 33],
    pub witness: Option<String>,
}

impl fmt::Debug for SettlementNoteV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SettlementNoteV1")
            .field("denomination", &self.denomination)
            .field("secret", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .field("witness", &self.witness.as_ref().map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
}

impl Drop for SettlementNoteV1 {
    fn drop(&mut self) {
        self.presentation_digest.zeroize();
        self.denomination.zeroize();
        self.secret.zeroize();
        self.signature.zeroize();
        self.witness.zeroize();
    }
}

impl SettlementNoteV1 {
    pub fn new(
        settlement_keyset_id: &str,
        denomination: u64,
        secret: String,
        signature: [u8; 33],
        witness: Option<String>,
    ) -> Result<Self, ServiceProtocolError> {
        let presentation_digest = settlement_note_presentation_digest(
            settlement_keyset_id,
            denomination,
            &secret,
            &signature,
            witness.as_deref(),
        )?;
        let value = Self {
            presentation_digest,
            denomination,
            secret,
            signature,
            witness,
        };
        value.validate_for_keyset(settlement_keyset_id)?;
        Ok(value)
    }

    fn validate_for_keyset(&self, settlement_keyset_id: &str) -> Result<(), ServiceProtocolError> {
        validate_value(self.denomination, "SettlementNoteV1.denomination")?;
        if self.secret.is_empty() || self.secret.len() > MAX_SETTLEMENT_SECRET_LEN_V1 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "SettlementNoteV1.secret",
                len: self.secret.len(),
                max: MAX_SETTLEMENT_SECRET_LEN_V1,
            });
        }
        if !crate::cashu_manifest::is_valid_compressed_point(&self.signature) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "SettlementNoteV1.signature",
                reason: "must be a canonical compressed secp256k1 point",
            });
        }
        if self
            .witness
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_SETTLEMENT_WITNESS_LEN_V1)
        {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "SettlementNoteV1.witness",
                len: self.witness.as_ref().map_or(0, String::len),
                max: MAX_SETTLEMENT_WITNESS_LEN_V1,
            });
        }
        if self.presentation_digest
            != settlement_note_presentation_digest(
                settlement_keyset_id,
                self.denomination,
                &self.secret,
                &self.signature,
                self.witness.as_deref(),
            )?
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "SettlementNoteV1.presentation_digest",
                reason: "does not match the exact independently-domain-separated proof",
            });
        }
        Ok(())
    }
}

pub fn settlement_note_presentation_digest(
    settlement_keyset_id: &str,
    denomination: u64,
    secret: &str,
    signature: &[u8; 33],
    witness: Option<&str>,
) -> Result<[u8; 32], ServiceProtocolError> {
    validate_keyset_id(settlement_keyset_id)?;
    validate_value(denomination, "SettlementNoteV1.denomination")?;
    if secret.is_empty() || secret.len() > MAX_SETTLEMENT_SECRET_LEN_V1 {
        return Err(ServiceProtocolError::FieldTooLong {
            field: "SettlementNoteV1.secret",
            len: secret.len(),
            max: MAX_SETTLEMENT_SECRET_LEN_V1,
        });
    }
    if witness.is_some_and(|value| value.is_empty() || value.len() > MAX_SETTLEMENT_WITNESS_LEN_V1)
    {
        return Err(ServiceProtocolError::FieldTooLong {
            field: "SettlementNoteV1.witness",
            len: witness.map_or(0, str::len),
            max: MAX_SETTLEMENT_WITNESS_LEN_V1,
        });
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        128 + secret.len() + witness.map_or(0, str::len),
    ));
    bytes.extend_from_slice(SETTLEMENT_NOTE_PRESENTATION_DIGEST_DOMAIN_V1);
    bytes.push(SERVICE_PROTOCOL_VERSION);
    put_keyset_id(&mut bytes, settlement_keyset_id);
    bytes.extend_from_slice(&denomination.to_le_bytes());
    put_bytes_u16(&mut bytes, secret.as_bytes());
    bytes.extend_from_slice(signature);
    match witness {
        None => bytes.push(0),
        Some(witness) => {
            bytes.push(1);
            put_bytes_u16(&mut bytes, witness.as_bytes());
        }
    }
    Ok(Sha256::digest(bytes.as_slice()).into())
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderSettlementDepositRequestV1 {
    pub registration_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub account_id: [u8; 32],
    pub unit: SettlementUnitV1,
    pub settlement_keyset_id: String,
    pub notes: Vec<SettlementNoteV1>,
    pub total_value: u64,
    pub idempotency_key: [u8; 32],
}

impl fmt::Debug for ProviderSettlementDepositRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSettlementDepositRequestV1")
            .field("unit", &self.unit)
            .field("settlement_keyset_id", &self.settlement_keyset_id)
            .field("note_count", &self.notes.len())
            .field("total_value", &self.total_value)
            .field("notes", &"[REDACTED]")
            .field("idempotency_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Drop for ProviderSettlementDepositRequestV1 {
    fn drop(&mut self) {
        self.registration_digest.zeroize();
        self.issuer_id.zeroize();
        self.provider_id.zeroize();
        self.account_id.zeroize();
        self.settlement_keyset_id.zeroize();
        self.idempotency_key.zeroize();
        // `SettlementNoteV1::drop` scrubs each bearer note before the vector
        // allocation is released.
    }
}

impl ProviderSettlementDepositRequestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_zeroizing()?;
        Ok(std::mem::take(&mut *out))
    }

    pub(crate) fn encode_zeroizing(&self) -> Result<Zeroizing<Vec<u8>>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Zeroizing::new(Vec::with_capacity(512));
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.registration_digest);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.account_id);
        out.push(self.unit as u8);
        put_keyset_id(&mut out, &self.settlement_keyset_id);
        out.push(self.notes.len() as u8);
        for note in &self.notes {
            out.extend_from_slice(&note.presentation_digest);
            out.extend_from_slice(&note.denomination.to_le_bytes());
            put_bytes_u16(&mut out, note.secret.as_bytes());
            out.extend_from_slice(&note.signature);
            match &note.witness {
                None => out.push(0),
                Some(witness) => {
                    out.push(1);
                    put_bytes_u16(&mut out, witness.as_bytes());
                }
            }
        }
        out.extend_from_slice(&self.total_value.to_le_bytes());
        out.extend_from_slice(&self.idempotency_key);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("ProviderSettlementDepositRequestV1.version")?,
            "ProviderSettlementDepositRequestV1",
        )?;
        let registration_digest =
            decoder.fixed("ProviderSettlementDepositRequestV1.registration_digest")?;
        let issuer_id = decoder.fixed("ProviderSettlementDepositRequestV1.issuer_id")?;
        let provider_id = decoder.fixed("ProviderSettlementDepositRequestV1.provider_id")?;
        let account_id = decoder.fixed("ProviderSettlementDepositRequestV1.account_id")?;
        let unit =
            SettlementUnitV1::decode(decoder.u8("ProviderSettlementDepositRequestV1.unit")?)?;
        let settlement_keyset_id = decode_keyset_id(
            &mut decoder,
            "ProviderSettlementDepositRequestV1.settlement_keyset_id",
        )?;
        let count = decoder.u8("ProviderSettlementDepositRequestV1.note_count")? as usize;
        if count > MAX_SETTLEMENT_NOTES_V1 {
            return Err(ServiceProtocolError::TooManyItems {
                field: "ProviderSettlementDepositRequestV1.notes",
                len: count,
                max: MAX_SETTLEMENT_NOTES_V1,
            });
        }
        let mut notes = Vec::with_capacity(count);
        for _ in 0..count {
            let presentation_digest = decoder.fixed("SettlementNoteV1.presentation_digest")?;
            let denomination = decoder.u64("SettlementNoteV1.denomination")?;
            let mut secret = Zeroizing::new(decode_string_u16(
                &mut decoder,
                "SettlementNoteV1.secret",
                MAX_SETTLEMENT_SECRET_LEN_V1,
            )?);
            let mut signature = Zeroizing::new(decoder.fixed("SettlementNoteV1.signature")?);
            let mut witness = match decoder.u8("SettlementNoteV1.has_witness")? {
                0 => None,
                1 => Some(Zeroizing::new(decode_string_u16(
                    &mut decoder,
                    "SettlementNoteV1.witness",
                    MAX_SETTLEMENT_WITNESS_LEN_V1,
                )?)),
                value => {
                    return Err(ServiceProtocolError::UnknownDiscriminant {
                        kind: "SettlementNoteV1.has_witness",
                        value,
                    })
                }
            };
            notes.push(SettlementNoteV1 {
                presentation_digest,
                denomination,
                secret: std::mem::take(&mut *secret),
                signature: std::mem::replace(&mut *signature, [0; 33]),
                witness: witness.as_mut().map(|value| std::mem::take(&mut **value)),
            });
        }
        let value = Self {
            registration_digest,
            issuer_id,
            provider_id,
            account_id,
            unit,
            settlement_keyset_id,
            notes,
            total_value: decoder.u64("ProviderSettlementDepositRequestV1.total_value")?,
            idempotency_key: decoder.fixed("ProviderSettlementDepositRequestV1.idempotency_key")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let encoded = self.encode_zeroizing()?;
        hash_canonical(
            PROVIDER_SETTLEMENT_DEPOSIT_REQUEST_DIGEST_DOMAIN_V1,
            encoded.as_slice(),
        )
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_request_context(
            self.registration_digest,
            self.issuer_id,
            self.provider_id,
            self.account_id,
            self.idempotency_key,
            "ProviderSettlementDepositRequestV1",
        )?;
        validate_keyset_id(&self.settlement_keyset_id)?;
        validate_value(
            self.total_value,
            "ProviderSettlementDepositRequestV1.total_value",
        )?;
        if self.notes.is_empty() || self.notes.len() > MAX_SETTLEMENT_NOTES_V1 {
            return Err(ServiceProtocolError::TooManyItems {
                field: "ProviderSettlementDepositRequestV1.notes",
                len: self.notes.len(),
                max: MAX_SETTLEMENT_NOTES_V1,
            });
        }
        let mut prior: Option<(u64, [u8; 32])> = None;
        let mut digests = HashSet::with_capacity(self.notes.len());
        let mut secrets = HashSet::with_capacity(self.notes.len());
        let mut signatures = HashSet::with_capacity(self.notes.len());
        let mut total = 0u64;
        for note in &self.notes {
            note.validate_for_keyset(&self.settlement_keyset_id)?;
            let key = (note.denomination, note.presentation_digest);
            if prior.is_some_and(|value| value >= key)
                || !digests.insert(note.presentation_digest)
                || !secrets.insert(note.secret.as_bytes())
                || !signatures.insert(note.signature)
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ProviderSettlementDepositRequestV1.notes",
                    reason: "notes must be unique and sorted by denomination/presentation digest",
                });
            }
            prior = Some(key);
            total = checked_add(
                total,
                note.denomination,
                "ProviderSettlementDepositRequestV1.notes",
            )?;
        }
        if total != self.total_value {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderSettlementDepositRequestV1.total_value",
                reason: "does not equal the canonical note sum",
            });
        }
        Ok(())
    }

    fn validate_against_registration(
        &self,
        registration: &ProviderSettlementRegistrationExpectationV1<'_>,
    ) -> Result<(), ServiceProtocolError> {
        registration.validate_current()?;
        if &self.registration_digest != registration.registration_digest
            || &self.issuer_id != registration.issuer_id
            || &self.provider_id != registration.provider_id
            || &self.account_id != registration.settlement_account_id
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderSettlementDepositRequestV1.audience",
                reason: "request does not match current provider registration or fixed account",
            });
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedSettlementNoteV1 {
    denomination: u64,
    denomination_public_key: [u8; 33],
    authoritative_y: [u8; 33],
    spend_key: [u8; 32],
    presentation_digest: [u8; 32],
}

impl fmt::Debug for VerifiedSettlementNoteV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSettlementNoteV1")
            .field("denomination", &self.denomination)
            .field("denomination_public_key", &"[REDACTED]")
            .field("authoritative_y", &"[REDACTED]")
            .field("spend_key", &"[REDACTED]")
            .field("presentation_digest", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Drop for VerifiedSettlementNoteV1 {
    fn drop(&mut self) {
        self.denomination_public_key.zeroize();
        self.authoritative_y.zeroize();
        self.spend_key.zeroize();
        self.presentation_digest.zeroize();
    }
}

impl VerifiedSettlementNoteV1 {
    pub fn denomination(&self) -> u64 {
        self.denomination
    }

    pub fn denomination_public_key(&self) -> &[u8; 33] {
        &self.denomination_public_key
    }

    pub fn authoritative_y(&self) -> &[u8; 33] {
        &self.authoritative_y
    }

    /// Stable global spend key. It intentionally contains no issuer, keyset,
    /// account, provider, or other audience identifier.
    pub fn spend_key(&self) -> &[u8; 32] {
        &self.spend_key
    }

    pub fn presentation_digest(&self) -> &[u8; 32] {
        &self.presentation_digest
    }
}

pub struct VerifiedSettlementDepositV1<'a> {
    request: &'a ProviderSettlementDepositRequestV1,
    keyset_id: String,
    notes: Vec<VerifiedSettlementNoteV1>,
}

impl<'a> VerifiedSettlementDepositV1<'a> {
    pub fn request(&self) -> &'a ProviderSettlementDepositRequestV1 {
        self.request
    }

    pub fn keyset_id(&self) -> &str {
        &self.keyset_id
    }

    pub fn notes(&self) -> &[VerifiedSettlementNoteV1] {
        &self.notes
    }
}

pub fn settlement_denomination_key_fingerprint_v1(
    denomination_public_key: &[u8; 33],
) -> Result<[u8; 32], ServiceProtocolError> {
    if !crate::cashu_manifest::is_valid_compressed_point(denomination_public_key) {
        return Err(ServiceProtocolError::InvalidValue {
            field: "settlement denomination public key",
            reason: "must be a canonical compressed secp256k1 point",
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(SETTLEMENT_DENOMINATION_KEY_FINGERPRINT_DOMAIN_V1);
    hasher.update(denomination_public_key);
    Ok(hasher.finalize().into())
}

pub fn settlement_note_spend_key_v1(
    denomination_public_key: &[u8; 33],
    authoritative_y: &[u8; 33],
) -> Result<[u8; 32], ServiceProtocolError> {
    if !crate::cashu_manifest::is_valid_compressed_point(authoritative_y) {
        return Err(ServiceProtocolError::InvalidValue {
            field: "authoritative Cashu Y",
            reason: "must be a canonical compressed secp256k1 point",
        });
    }
    let key_fingerprint = settlement_denomination_key_fingerprint_v1(denomination_public_key)?;
    let mut hasher = Sha256::new();
    hasher.update(SETTLEMENT_NOTE_SPEND_KEY_DOMAIN_V1);
    hasher.update(key_fingerprint);
    hasher.update(authoritative_y);
    Ok(hasher.finalize().into())
}

/// Verifies a new deposit under the provider's current registration and an
/// independently retained, unexpired Cashu keyset. The returned typestate is
/// the only successful path and contains authoritative Y/spend keys from the
/// caller-supplied Cashu verifier. The issuer store must atomically insert all
/// returned spend keys into a UNIQUE spent set and credit the provider ledger;
/// partial insertion/credit is forbidden.
pub fn verify_new_settlement_deposit_request_for<'a>(
    request: &'a ProviderSettlementDepositRequestV1,
    request_auth: &ProviderSettlementRequestAuthV1,
    registration: &ProviderSettlementRegistrationExpectationV1<'_>,
    retained_keysets: &RetainedSettlementKeysetExpectationV1<'_>,
    note_verifier: &dyn CashuSettlementNoteVerifierV1,
) -> Result<VerifiedSettlementDepositV1<'a>, ServiceProtocolError> {
    request.validate()?;
    request.validate_against_registration(registration)?;
    request_auth.verify_for(&request.request_digest()?, registration)?;
    if retained_keysets.now_unix != registration.now_unix {
        return Err(ServiceProtocolError::InvalidValue {
            field: "RetainedSettlementKeysetExpectationV1.now_unix",
            reason: "must use the same trusted clock as provider registration",
        });
    }
    let retained = retained_keysets.verify_exact_keyset_for_issuer(
        &request.issuer_id,
        &request.settlement_keyset_id,
        request.unit,
        request.notes.iter().map(|note| note.denomination),
    )?;
    let mut verified_notes = Vec::with_capacity(request.notes.len());
    let mut authoritative_ys = HashSet::with_capacity(request.notes.len());
    let mut spend_keys = HashSet::with_capacity(request.notes.len());
    for note in &request.notes {
        let denomination_public_key = retained.denomination_public_key(note.denomination)?;
        let authoritative_y =
            note_verifier.verify_note_and_derive_y(CashuSettlementNoteVerificationInputV1 {
                denomination: note.denomination,
                denomination_public_key,
                secret: &note.secret,
                signature: &note.signature,
                witness: note.witness.as_deref(),
            })?;
        let spend_key = settlement_note_spend_key_v1(denomination_public_key, &authoritative_y)?;
        if !authoritative_ys.insert(authoritative_y) || !spend_keys.insert(spend_key) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderSettlementDepositRequestV1.notes",
                reason: "authoritative Cashu Y and global spend keys must be unique",
            });
        }
        verified_notes.push(VerifiedSettlementNoteV1 {
            denomination: note.denomination,
            denomination_public_key: *denomination_public_key,
            authoritative_y,
            spend_key,
            presentation_digest: note.presentation_digest,
        });
    }
    Ok(VerifiedSettlementDepositV1 {
        request,
        keyset_id: retained.keyset_id().to_owned(),
        notes: verified_notes,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderSettlementDepositResponseV1 {
    pub issuer_settlement_key_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub registration_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub account_id: [u8; 32],
    pub unit: SettlementUnitV1,
    pub settlement_keyset_id: String,
    pub total_value: u64,
    pub ledger_transaction_id: [u8; 32],
    pub ledger_sequence: u64,
    pub signature: [u8; 64],
}

impl ProviderSettlementDepositResponseV1 {
    pub fn sign(
        mut value: Self,
        issuer_settlement_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        value.issuer_settlement_key_id =
            issuer_settlement_key_id(&issuer_settlement_signing_key.verifying_key());
        value.signature = [0; 64];
        value.validate()?;
        value.signature = issuer_settlement_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("ProviderSettlementDepositResponseV1.version")?,
            "ProviderSettlementDepositResponseV1",
        )?;
        let value = Self {
            issuer_settlement_key_id: decoder
                .fixed("ProviderSettlementDepositResponseV1.issuer_settlement_key_id")?,
            request_digest: decoder.fixed("ProviderSettlementDepositResponseV1.request_digest")?,
            registration_digest: decoder
                .fixed("ProviderSettlementDepositResponseV1.registration_digest")?,
            issuer_id: decoder.fixed("ProviderSettlementDepositResponseV1.issuer_id")?,
            provider_id: decoder.fixed("ProviderSettlementDepositResponseV1.provider_id")?,
            account_id: decoder.fixed("ProviderSettlementDepositResponseV1.account_id")?,
            unit: SettlementUnitV1::decode(
                decoder.u8("ProviderSettlementDepositResponseV1.unit")?,
            )?,
            settlement_keyset_id: decode_keyset_id(
                &mut decoder,
                "ProviderSettlementDepositResponseV1.settlement_keyset_id",
            )?,
            total_value: decoder.u64("ProviderSettlementDepositResponseV1.total_value")?,
            ledger_transaction_id: decoder
                .fixed("ProviderSettlementDepositResponseV1.ledger_transaction_id")?,
            ledger_sequence: decoder.u64("ProviderSettlementDepositResponseV1.ledger_sequence")?,
            signature: decoder.fixed("ProviderSettlementDepositResponseV1.signature")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn verify_for_exact_request(
        &self,
        request: &ProviderSettlementDepositRequestV1,
        expected_issuer_settlement_key: &VerifyingKey,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        verify_issuer_signature(
            self.issuer_settlement_key_id,
            &self.signature,
            &self.signing_preimage()?,
            expected_issuer_settlement_key,
        )?;
        if self.request_digest != request.request_digest()?
            || self.registration_digest != request.registration_digest
            || self.issuer_id != request.issuer_id
            || self.provider_id != request.provider_id
            || self.account_id != request.account_id
            || self.unit != request.unit
            || self.settlement_keyset_id != request.settlement_keyset_id
            || self.total_value != request.total_value
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderSettlementDepositResponseV1.binding",
                reason: "response does not bind the exact deposit request",
            });
        }
        Ok(())
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(320);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.issuer_settlement_key_id);
        out.extend_from_slice(&self.request_digest);
        out.extend_from_slice(&self.registration_digest);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.account_id);
        out.push(self.unit as u8);
        put_keyset_id(&mut out, &self.settlement_keyset_id);
        out.extend_from_slice(&self.total_value.to_le_bytes());
        out.extend_from_slice(&self.ledger_transaction_id);
        out.extend_from_slice(&self.ledger_sequence.to_le_bytes());
        Ok(out)
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        signing_preimage(
            PROVIDER_SETTLEMENT_DEPOSIT_RESPONSE_SIGNATURE_DOMAIN_V1,
            self.encode_unsigned()?,
        )
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_common_response(
            self.issuer_settlement_key_id,
            self.request_digest,
            self.registration_digest,
            self.issuer_id,
            self.provider_id,
        )?;
        validate_nonzero(
            &self.account_id,
            "ProviderSettlementDepositResponseV1.account_id",
        )?;
        validate_keyset_id(&self.settlement_keyset_id)?;
        validate_value(
            self.total_value,
            "ProviderSettlementDepositResponseV1.total_value",
        )?;
        validate_nonzero(
            &self.ledger_transaction_id,
            "ProviderSettlementDepositResponseV1.ledger_transaction_id",
        )?;
        if self.ledger_sequence == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderSettlementDepositResponseV1.ledger_sequence",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

pub fn verify_new_settlement_deposit_response_for<'a>(
    response: &'a ProviderSettlementDepositResponseV1,
    request: &'a ProviderSettlementDepositRequestV1,
    request_auth: &ProviderSettlementRequestAuthV1,
    registration: &ProviderSettlementRegistrationExpectationV1<'_>,
    retained_keysets: &RetainedSettlementKeysetExpectationV1<'_>,
    note_verifier: &dyn CashuSettlementNoteVerifierV1,
) -> Result<VerifiedSettlementDepositV1<'a>, ServiceProtocolError> {
    let verified = verify_new_settlement_deposit_request_for(
        request,
        request_auth,
        registration,
        retained_keysets,
        note_verifier,
    )?;
    response.verify_for_exact_request(request, registration.issuer_settlement_key)?;
    Ok(verified)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderBalanceRequestV1 {
    pub authorization_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub account_id: [u8; 32],
    pub unit: SettlementUnitV1,
    pub idempotency_key: [u8; 32],
}

impl ProviderBalanceRequestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = encode_request_context(
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
            self.account_id,
        );
        out.push(self.unit as u8);
        out.extend_from_slice(&self.idempotency_key);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let (authorization_digest, issuer_id, provider_id, account_id) =
            decode_request_context(&mut decoder, "ProviderBalanceRequestV1")?;
        let value = Self {
            authorization_digest,
            issuer_id,
            provider_id,
            account_id,
            unit: SettlementUnitV1::decode(decoder.u8("ProviderBalanceRequestV1.unit")?)?,
            idempotency_key: decoder.fixed("ProviderBalanceRequestV1.idempotency_key")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        hash_canonical(PROVIDER_BALANCE_REQUEST_DIGEST_DOMAIN_V1, &self.encode()?)
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_request_context(
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
            self.account_id,
            self.idempotency_key,
            "ProviderBalanceRequestV1",
        )
    }

    fn validate_against_authorization(
        &self,
        authorization: &ProviderClearingAuthorizationV1,
    ) -> Result<(), ServiceProtocolError> {
        validate_authorized_account(
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
            self.account_id,
            authorization,
            "ProviderBalanceRequestV1.audience",
        )
    }
}

pub fn verify_new_balance_request_for(
    request: &ProviderBalanceRequestV1,
    authorization: &ProviderClearingAuthorizationV1,
    issuer_approval: &IssuerClearingApprovalV1,
    request_auth: &ProviderClearingRequestAuthV1,
    expectation: &ProviderClearingExpectationV1<'_>,
) -> Result<(), ServiceProtocolError> {
    request.validate()?;
    request.validate_against_authorization(authorization)?;
    verify_current_request(
        request.request_digest()?,
        authorization,
        issuer_approval,
        request_auth,
        expectation,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerBalanceResponseV1 {
    pub issuer_settlement_key_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub authorization_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub account_id: [u8; 32],
    pub unit: SettlementUnitV1,
    pub available_value: u64,
    pub reserved_value: u64,
    pub ledger_sequence: u64,
    pub as_of_unix: u64,
    pub signature: [u8; 64],
}

impl IssuerBalanceResponseV1 {
    pub fn sign(
        mut value: Self,
        issuer_settlement_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        value.issuer_settlement_key_id =
            issuer_settlement_key_id(&issuer_settlement_signing_key.verifying_key());
        value.signature = [0; 64];
        value.validate()?;
        value.signature = issuer_settlement_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let (
            issuer_settlement_key_id,
            request_digest,
            authorization_digest,
            issuer_id,
            provider_id,
        ) = decode_common_response(&mut decoder, "IssuerBalanceResponseV1")?;
        let value = Self {
            issuer_settlement_key_id,
            request_digest,
            authorization_digest,
            issuer_id,
            provider_id,
            account_id: decoder.fixed("IssuerBalanceResponseV1.account_id")?,
            unit: SettlementUnitV1::decode(decoder.u8("IssuerBalanceResponseV1.unit")?)?,
            available_value: decoder.u64("IssuerBalanceResponseV1.available_value")?,
            reserved_value: decoder.u64("IssuerBalanceResponseV1.reserved_value")?,
            ledger_sequence: decoder.u64("IssuerBalanceResponseV1.ledger_sequence")?,
            as_of_unix: decoder.u64("IssuerBalanceResponseV1.as_of_unix")?,
            signature: decoder.fixed("IssuerBalanceResponseV1.signature")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn verify_for_exact_request(
        &self,
        request: &ProviderBalanceRequestV1,
        expected_issuer_settlement_key: &VerifyingKey,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        verify_issuer_signature(
            self.issuer_settlement_key_id,
            &self.signature,
            &self.signing_preimage()?,
            expected_issuer_settlement_key,
        )?;
        if self.request_digest != request.request_digest()?
            || self.authorization_digest != request.authorization_digest
            || self.issuer_id != request.issuer_id
            || self.provider_id != request.provider_id
            || self.account_id != request.account_id
            || self.unit != request.unit
        {
            return Err(binding_error("IssuerBalanceResponseV1.binding"));
        }
        Ok(())
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = encode_common_response(
            self.issuer_settlement_key_id,
            self.request_digest,
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
        );
        out.extend_from_slice(&self.account_id);
        out.push(self.unit as u8);
        out.extend_from_slice(&self.available_value.to_le_bytes());
        out.extend_from_slice(&self.reserved_value.to_le_bytes());
        out.extend_from_slice(&self.ledger_sequence.to_le_bytes());
        out.extend_from_slice(&self.as_of_unix.to_le_bytes());
        Ok(out)
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        signing_preimage(
            ISSUER_BALANCE_RESPONSE_SIGNATURE_DOMAIN_V1,
            self.encode_unsigned()?,
        )
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_common_response(
            self.issuer_settlement_key_id,
            self.request_digest,
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
        )?;
        validate_nonzero(&self.account_id, "IssuerBalanceResponseV1.account_id")?;
        if self.available_value > MAX_SERVICE_VALUE_V1
            || self.reserved_value > MAX_SERVICE_VALUE_V1
            || self.ledger_sequence == 0
            || self.as_of_unix == 0
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerBalanceResponseV1",
                reason: "balances must fit durable bounds and ledger/time values must be non-zero",
            });
        }
        Ok(())
    }
}

pub fn verify_new_balance_response_for(
    response: &IssuerBalanceResponseV1,
    request: &ProviderBalanceRequestV1,
    authorization: &ProviderClearingAuthorizationV1,
    issuer_approval: &IssuerClearingApprovalV1,
    request_auth: &ProviderClearingRequestAuthV1,
    expectation: &ProviderClearingExpectationV1<'_>,
) -> Result<(), ServiceProtocolError> {
    verify_new_balance_request_for(
        request,
        authorization,
        issuer_approval,
        request_auth,
        expectation,
    )?;
    response.verify_for_exact_request(request, expectation.issuer_settlement_key)
}

/// Opaque issuer-registry handle. It is never an invoice, address, URL, or
/// wallet-controlled destination. New payout validators compare it with a
/// trusted registry value supplied out of band.
pub type PayoutTargetIdV1 = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderPayoutIntentRequestV1 {
    pub authorization_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub account_id: [u8; 32],
    pub payout_target_id: PayoutTargetIdV1,
    pub unit: SettlementUnitV1,
    pub payout_value: u64,
    pub idempotency_key: [u8; 32],
}

impl ProviderPayoutIntentRequestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = encode_request_context(
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
            self.account_id,
        );
        out.extend_from_slice(&self.payout_target_id);
        out.push(self.unit as u8);
        out.extend_from_slice(&self.payout_value.to_le_bytes());
        out.extend_from_slice(&self.idempotency_key);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let (authorization_digest, issuer_id, provider_id, account_id) =
            decode_request_context(&mut decoder, "ProviderPayoutIntentRequestV1")?;
        let value = Self {
            authorization_digest,
            issuer_id,
            provider_id,
            account_id,
            payout_target_id: decoder.fixed("ProviderPayoutIntentRequestV1.payout_target_id")?,
            unit: SettlementUnitV1::decode(decoder.u8("ProviderPayoutIntentRequestV1.unit")?)?,
            payout_value: decoder.u64("ProviderPayoutIntentRequestV1.payout_value")?,
            idempotency_key: decoder.fixed("ProviderPayoutIntentRequestV1.idempotency_key")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        hash_canonical(
            PROVIDER_PAYOUT_INTENT_REQUEST_DIGEST_DOMAIN_V1,
            &self.encode()?,
        )
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_request_context(
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
            self.account_id,
            self.idempotency_key,
            "ProviderPayoutIntentRequestV1",
        )?;
        validate_nonzero(
            &self.payout_target_id,
            "ProviderPayoutIntentRequestV1.payout_target_id",
        )?;
        validate_value(
            self.payout_value,
            "ProviderPayoutIntentRequestV1.payout_value",
        )
    }
}

pub fn verify_new_payout_intent_request_for(
    request: &ProviderPayoutIntentRequestV1,
    registered_payout_target_id: &PayoutTargetIdV1,
    authorization: &ProviderClearingAuthorizationV1,
    issuer_approval: &IssuerClearingApprovalV1,
    request_auth: &ProviderClearingRequestAuthV1,
    expectation: &ProviderClearingExpectationV1<'_>,
) -> Result<(), ServiceProtocolError> {
    request.validate()?;
    validate_authorized_account(
        request.authorization_digest,
        request.issuer_id,
        request.provider_id,
        request.account_id,
        authorization,
        "ProviderPayoutIntentRequestV1.audience",
    )?;
    if &request.payout_target_id != registered_payout_target_id {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ProviderPayoutIntentRequestV1.payout_target_id",
            reason: "target is not the issuer-pre-registered opaque payout target",
        });
    }
    verify_current_request(
        request.request_digest()?,
        authorization,
        issuer_approval,
        request_auth,
        expectation,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerPayoutIntentResponseV1 {
    pub issuer_settlement_key_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub authorization_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub account_id: [u8; 32],
    pub payout_target_id: PayoutTargetIdV1,
    pub unit: SettlementUnitV1,
    pub payout_value: u64,
    pub issuer_fee: u64,
    pub total_debit: u64,
    pub payout_intent_id: [u8; 32],
    pub expires_at: u64,
    pub signature: [u8; 64],
}

impl IssuerPayoutIntentResponseV1 {
    pub fn sign(
        mut value: Self,
        issuer_settlement_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        value.issuer_settlement_key_id =
            issuer_settlement_key_id(&issuer_settlement_signing_key.verifying_key());
        value.signature = [0; 64];
        value.validate()?;
        value.signature = issuer_settlement_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let (
            issuer_settlement_key_id,
            request_digest,
            authorization_digest,
            issuer_id,
            provider_id,
        ) = decode_common_response(&mut decoder, "IssuerPayoutIntentResponseV1")?;
        let value = Self {
            issuer_settlement_key_id,
            request_digest,
            authorization_digest,
            issuer_id,
            provider_id,
            account_id: decoder.fixed("IssuerPayoutIntentResponseV1.account_id")?,
            payout_target_id: decoder.fixed("IssuerPayoutIntentResponseV1.payout_target_id")?,
            unit: SettlementUnitV1::decode(decoder.u8("IssuerPayoutIntentResponseV1.unit")?)?,
            payout_value: decoder.u64("IssuerPayoutIntentResponseV1.payout_value")?,
            issuer_fee: decoder.u64("IssuerPayoutIntentResponseV1.issuer_fee")?,
            total_debit: decoder.u64("IssuerPayoutIntentResponseV1.total_debit")?,
            payout_intent_id: decoder.fixed("IssuerPayoutIntentResponseV1.payout_intent_id")?,
            expires_at: decoder.u64("IssuerPayoutIntentResponseV1.expires_at")?,
            signature: decoder.fixed("IssuerPayoutIntentResponseV1.signature")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn payout_intent_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        hash_canonical(PAYOUT_INTENT_DIGEST_DOMAIN_V1, &self.encode()?)
    }

    pub fn verify_for_exact_request(
        &self,
        request: &ProviderPayoutIntentRequestV1,
        expected_issuer_settlement_key: &VerifyingKey,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        verify_issuer_signature(
            self.issuer_settlement_key_id,
            &self.signature,
            &self.signing_preimage()?,
            expected_issuer_settlement_key,
        )?;
        if self.request_digest != request.request_digest()?
            || self.authorization_digest != request.authorization_digest
            || self.issuer_id != request.issuer_id
            || self.provider_id != request.provider_id
            || self.account_id != request.account_id
            || self.payout_target_id != request.payout_target_id
            || self.unit != request.unit
            || self.payout_value != request.payout_value
        {
            return Err(binding_error("IssuerPayoutIntentResponseV1.binding"));
        }
        Ok(())
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = encode_common_response(
            self.issuer_settlement_key_id,
            self.request_digest,
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
        );
        out.extend_from_slice(&self.account_id);
        out.extend_from_slice(&self.payout_target_id);
        out.push(self.unit as u8);
        out.extend_from_slice(&self.payout_value.to_le_bytes());
        out.extend_from_slice(&self.issuer_fee.to_le_bytes());
        out.extend_from_slice(&self.total_debit.to_le_bytes());
        out.extend_from_slice(&self.payout_intent_id);
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        Ok(out)
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        signing_preimage(
            ISSUER_PAYOUT_INTENT_RESPONSE_SIGNATURE_DOMAIN_V1,
            self.encode_unsigned()?,
        )
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_common_response(
            self.issuer_settlement_key_id,
            self.request_digest,
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
        )?;
        validate_nonzero(&self.account_id, "IssuerPayoutIntentResponseV1.account_id")?;
        validate_nonzero(
            &self.payout_target_id,
            "IssuerPayoutIntentResponseV1.payout_target_id",
        )?;
        validate_nonzero(
            &self.payout_intent_id,
            "IssuerPayoutIntentResponseV1.payout_intent_id",
        )?;
        validate_value(
            self.payout_value,
            "IssuerPayoutIntentResponseV1.payout_value",
        )?;
        if self.issuer_fee > MAX_SERVICE_VALUE_V1
            || self.payout_value.checked_add(self.issuer_fee) != Some(self.total_debit)
            || self.total_debit > MAX_SERVICE_VALUE_V1
            || self.expires_at == 0
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerPayoutIntentResponseV1.value",
                reason: "fee must conserve bounded debit and expiry must be non-zero",
            });
        }
        Ok(())
    }
}

pub fn verify_new_payout_intent_response_for(
    response: &IssuerPayoutIntentResponseV1,
    request: &ProviderPayoutIntentRequestV1,
    registered_payout_target_id: &PayoutTargetIdV1,
    authorization: &ProviderClearingAuthorizationV1,
    issuer_approval: &IssuerClearingApprovalV1,
    request_auth: &ProviderClearingRequestAuthV1,
    expectation: &ProviderClearingExpectationV1<'_>,
) -> Result<(), ServiceProtocolError> {
    verify_new_payout_intent_request_for(
        request,
        registered_payout_target_id,
        authorization,
        issuer_approval,
        request_auth,
        expectation,
    )?;
    response.verify_for_exact_request(request, expectation.issuer_settlement_key)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderPayoutRequestV1 {
    pub authorization_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub account_id: [u8; 32],
    pub payout_target_id: PayoutTargetIdV1,
    pub payout_intent_id: [u8; 32],
    pub payout_intent_digest: [u8; 32],
    pub unit: SettlementUnitV1,
    pub payout_value: u64,
    pub total_debit: u64,
    pub idempotency_key: [u8; 32],
}

impl ProviderPayoutRequestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = encode_request_context(
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
            self.account_id,
        );
        out.extend_from_slice(&self.payout_target_id);
        out.extend_from_slice(&self.payout_intent_id);
        out.extend_from_slice(&self.payout_intent_digest);
        out.push(self.unit as u8);
        out.extend_from_slice(&self.payout_value.to_le_bytes());
        out.extend_from_slice(&self.total_debit.to_le_bytes());
        out.extend_from_slice(&self.idempotency_key);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let (authorization_digest, issuer_id, provider_id, account_id) =
            decode_request_context(&mut decoder, "ProviderPayoutRequestV1")?;
        let value = Self {
            authorization_digest,
            issuer_id,
            provider_id,
            account_id,
            payout_target_id: decoder.fixed("ProviderPayoutRequestV1.payout_target_id")?,
            payout_intent_id: decoder.fixed("ProviderPayoutRequestV1.payout_intent_id")?,
            payout_intent_digest: decoder.fixed("ProviderPayoutRequestV1.payout_intent_digest")?,
            unit: SettlementUnitV1::decode(decoder.u8("ProviderPayoutRequestV1.unit")?)?,
            payout_value: decoder.u64("ProviderPayoutRequestV1.payout_value")?,
            total_debit: decoder.u64("ProviderPayoutRequestV1.total_debit")?,
            idempotency_key: decoder.fixed("ProviderPayoutRequestV1.idempotency_key")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        hash_canonical(PROVIDER_PAYOUT_REQUEST_DIGEST_DOMAIN_V1, &self.encode()?)
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_request_context(
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
            self.account_id,
            self.idempotency_key,
            "ProviderPayoutRequestV1",
        )?;
        validate_nonzero(
            &self.payout_target_id,
            "ProviderPayoutRequestV1.payout_target_id",
        )?;
        validate_nonzero(
            &self.payout_intent_id,
            "ProviderPayoutRequestV1.payout_intent_id",
        )?;
        validate_nonzero(
            &self.payout_intent_digest,
            "ProviderPayoutRequestV1.payout_intent_digest",
        )?;
        validate_value(self.payout_value, "ProviderPayoutRequestV1.payout_value")?;
        validate_value(self.total_debit, "ProviderPayoutRequestV1.total_debit")?;
        if self.total_debit < self.payout_value {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderPayoutRequestV1.total_debit",
                reason: "cannot be less than payout value",
            });
        }
        Ok(())
    }
}

pub struct PayoutExecutionContextV1<'a> {
    pub intent_request: &'a ProviderPayoutIntentRequestV1,
    pub intent_response: &'a IssuerPayoutIntentResponseV1,
    pub registered_payout_target_id: &'a PayoutTargetIdV1,
}

/// Successful payout-execution verification. The issuer store MUST use
/// [`payout_intent_id`](Self::payout_intent_id) as a globally UNIQUE consumed
/// key and, in one durable transaction, (1) consume the intent, (2)
/// reserve/debit the account, and (3) insert exactly one payout plus exactly
/// one durable outbox command. HTTP idempotency alone is insufficient because
/// two differently encoded requests can consume the same signed intent.
pub struct VerifiedPayoutExecutionV1<'a> {
    request: &'a ProviderPayoutRequestV1,
    payout_intent_id: [u8; 32],
}

impl<'a> VerifiedPayoutExecutionV1<'a> {
    pub fn request(&self) -> &'a ProviderPayoutRequestV1 {
        self.request
    }

    /// Mandatory database uniqueness/consumption identifier.
    pub fn payout_intent_id(&self) -> &[u8; 32] {
        &self.payout_intent_id
    }
}

/// Failure returned by the protocol's sign-and-durably-commit payout APIs.
/// A signed economic-success response is never returned when the store reports
/// an error or loses the required uniqueness/CAS race.
#[derive(Debug, PartialEq, Eq)]
pub enum PayoutCommitErrorV1<E> {
    Protocol(ServiceProtocolError),
    Store(E),
    Conflict { operation: &'static str },
}

impl<E: core::fmt::Display> core::fmt::Display for PayoutCommitErrorV1<E> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(error) => {
                write!(formatter, "payout protocol validation failed: {error}")
            }
            Self::Store(error) => write!(formatter, "payout store commit failed: {error}"),
            Self::Conflict { operation } => {
                write!(formatter, "payout atomic commit conflict: {operation}")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for PayoutCommitErrorV1<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Conflict { .. } => None,
        }
    }
}

/// Issuer-store boundary for accepting a new payout. Implementations MUST, in
/// one durable transaction, consume the globally unique payout intent, debit
/// or reserve the account, create the payout, persist the exact signed
/// response, and enqueue exactly one payout command.
pub trait PayoutExecutionCommitStoreV1 {
    type Error;

    fn commit_new_payout(
        &mut self,
        execution: &VerifiedPayoutExecutionV1<'_>,
        signed_response: &IssuerPayoutResponseV1,
    ) -> Result<bool, Self::Error>;
}

pub fn verify_new_payout_request_for<'a>(
    request: &'a ProviderPayoutRequestV1,
    payout_context: &PayoutExecutionContextV1<'_>,
    authorization: &ProviderClearingAuthorizationV1,
    issuer_approval: &IssuerClearingApprovalV1,
    request_auth: &ProviderClearingRequestAuthV1,
    expectation: &ProviderClearingExpectationV1<'_>,
) -> Result<VerifiedPayoutExecutionV1<'a>, ServiceProtocolError> {
    request.validate()?;
    validate_authorized_account(
        request.authorization_digest,
        request.issuer_id,
        request.provider_id,
        request.account_id,
        authorization,
        "ProviderPayoutRequestV1.audience",
    )?;
    if &request.payout_target_id != payout_context.registered_payout_target_id {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ProviderPayoutRequestV1.payout_target_id",
            reason: "target is not the issuer-pre-registered opaque payout target",
        });
    }
    payout_context.intent_response.verify_for_exact_request(
        payout_context.intent_request,
        expectation.issuer_settlement_key,
    )?;
    if expectation.now_unix > payout_context.intent_response.expires_at
        || request.authorization_digest != payout_context.intent_response.authorization_digest
        || request.issuer_id != payout_context.intent_response.issuer_id
        || request.provider_id != payout_context.intent_response.provider_id
        || request.account_id != payout_context.intent_response.account_id
        || request.payout_target_id != payout_context.intent_response.payout_target_id
        || request.payout_intent_id != payout_context.intent_response.payout_intent_id
        || request.payout_intent_digest != payout_context.intent_response.payout_intent_digest()?
        || request.unit != payout_context.intent_response.unit
        || request.payout_value != payout_context.intent_response.payout_value
        || request.total_debit != payout_context.intent_response.total_debit
    {
        return Err(binding_error("ProviderPayoutRequestV1.intent_binding"));
    }
    verify_current_request(
        request.request_digest()?,
        authorization,
        issuer_approval,
        request_auth,
        expectation,
    )?;
    Ok(VerifiedPayoutExecutionV1 {
        request,
        payout_intent_id: request.payout_intent_id,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PayoutStateV1 {
    Accepted = 1,
    InFlight = 2,
    Succeeded = 3,
    Failed = 4,
}

impl PayoutStateV1 {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::InFlight),
            3 => Ok(Self::Succeeded),
            4 => Ok(Self::Failed),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "PayoutStateV1",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerPayoutResponseV1 {
    pub issuer_settlement_key_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub authorization_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub account_id: [u8; 32],
    pub payout_target_id: PayoutTargetIdV1,
    pub payout_intent_id: [u8; 32],
    pub payout_id: [u8; 32],
    pub unit: SettlementUnitV1,
    pub payout_value: u64,
    pub total_debit: u64,
    pub state: PayoutStateV1,
    pub ledger_transaction_id: [u8; 32],
    pub state_version: u64,
    pub updated_at: u64,
    pub signature: [u8; 64],
}

impl IssuerPayoutResponseV1 {
    /// Signs an initial `Accepted` response only for a fully verified payout
    /// execution and returns it only after the issuer store atomically commits
    /// the economic state transition. `Ok(false)` from the store is a lost
    /// intent-consumption race and never releases the signed response.
    pub fn sign_and_commit_execution<Store: PayoutExecutionCommitStoreV1>(
        value: Self,
        execution: &VerifiedPayoutExecutionV1<'_>,
        issuer_settlement_signing_key: &SigningKey,
        store: &mut Store,
    ) -> Result<Self, PayoutCommitErrorV1<Store::Error>> {
        let signed = Self::sign_structural(value, issuer_settlement_signing_key)
            .map_err(PayoutCommitErrorV1::Protocol)?;
        signed
            .verify_for_exact_request(
                execution.request(),
                &issuer_settlement_signing_key.verifying_key(),
            )
            .map_err(PayoutCommitErrorV1::Protocol)?;
        if execution.payout_intent_id() != &signed.payout_intent_id {
            return Err(PayoutCommitErrorV1::Protocol(binding_error(
                "IssuerPayoutResponseV1.payout_intent_id",
            )));
        }
        let committed = store
            .commit_new_payout(execution, &signed)
            .map_err(PayoutCommitErrorV1::Store)?;
        if !committed {
            return Err(PayoutCommitErrorV1::Conflict {
                operation: "payout_intent_consume",
            });
        }
        Ok(signed)
    }

    fn sign_structural(
        mut value: Self,
        issuer_settlement_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        value.issuer_settlement_key_id =
            issuer_settlement_key_id(&issuer_settlement_signing_key.verifying_key());
        value.signature = [0; 64];
        value.validate()?;
        value.signature = issuer_settlement_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let (
            issuer_settlement_key_id,
            request_digest,
            authorization_digest,
            issuer_id,
            provider_id,
        ) = decode_common_response(&mut decoder, "IssuerPayoutResponseV1")?;
        let value = Self {
            issuer_settlement_key_id,
            request_digest,
            authorization_digest,
            issuer_id,
            provider_id,
            account_id: decoder.fixed("IssuerPayoutResponseV1.account_id")?,
            payout_target_id: decoder.fixed("IssuerPayoutResponseV1.payout_target_id")?,
            payout_intent_id: decoder.fixed("IssuerPayoutResponseV1.payout_intent_id")?,
            payout_id: decoder.fixed("IssuerPayoutResponseV1.payout_id")?,
            unit: SettlementUnitV1::decode(decoder.u8("IssuerPayoutResponseV1.unit")?)?,
            payout_value: decoder.u64("IssuerPayoutResponseV1.payout_value")?,
            total_debit: decoder.u64("IssuerPayoutResponseV1.total_debit")?,
            state: PayoutStateV1::decode(decoder.u8("IssuerPayoutResponseV1.state")?)?,
            ledger_transaction_id: decoder.fixed("IssuerPayoutResponseV1.ledger_transaction_id")?,
            state_version: decoder.u64("IssuerPayoutResponseV1.state_version")?,
            updated_at: decoder.u64("IssuerPayoutResponseV1.updated_at")?,
            signature: decoder.fixed("IssuerPayoutResponseV1.signature")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    fn verify_for_exact_request(
        &self,
        request: &ProviderPayoutRequestV1,
        expected_issuer_settlement_key: &VerifyingKey,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        verify_issuer_signature(
            self.issuer_settlement_key_id,
            &self.signature,
            &self.signing_preimage()?,
            expected_issuer_settlement_key,
        )?;
        if self.request_digest != request.request_digest()?
            || self.authorization_digest != request.authorization_digest
            || self.issuer_id != request.issuer_id
            || self.provider_id != request.provider_id
            || self.account_id != request.account_id
            || self.payout_target_id != request.payout_target_id
            || self.payout_intent_id != request.payout_intent_id
            || self.unit != request.unit
            || self.payout_value != request.payout_value
            || self.total_debit != request.total_debit
        {
            return Err(binding_error("IssuerPayoutResponseV1.binding"));
        }
        Ok(())
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = encode_common_response(
            self.issuer_settlement_key_id,
            self.request_digest,
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
        );
        out.extend_from_slice(&self.account_id);
        out.extend_from_slice(&self.payout_target_id);
        out.extend_from_slice(&self.payout_intent_id);
        out.extend_from_slice(&self.payout_id);
        out.push(self.unit as u8);
        out.extend_from_slice(&self.payout_value.to_le_bytes());
        out.extend_from_slice(&self.total_debit.to_le_bytes());
        out.push(self.state as u8);
        out.extend_from_slice(&self.ledger_transaction_id);
        out.extend_from_slice(&self.state_version.to_le_bytes());
        out.extend_from_slice(&self.updated_at.to_le_bytes());
        Ok(out)
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        signing_preimage(
            ISSUER_PAYOUT_RESPONSE_SIGNATURE_DOMAIN_V1,
            self.encode_unsigned()?,
        )
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_common_response(
            self.issuer_settlement_key_id,
            self.request_digest,
            self.authorization_digest,
            self.issuer_id,
            self.provider_id,
        )?;
        validate_payout_common(
            self.account_id,
            self.payout_target_id,
            self.payout_intent_id,
            self.payout_value,
            self.total_debit,
            "IssuerPayoutResponseV1",
        )?;
        validate_nonzero(&self.payout_id, "IssuerPayoutResponseV1.payout_id")?;
        validate_nonzero(
            &self.ledger_transaction_id,
            "IssuerPayoutResponseV1.ledger_transaction_id",
        )?;
        if self.state != PayoutStateV1::Accepted || self.state_version != 1 || self.updated_at == 0
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerPayoutResponseV1.initial_state",
                reason: "initial signed payout response must be Accepted at state_version 1",
            });
        }
        Ok(())
    }
}

/// Issuer-authenticated payout snapshot. Its fields are private so only the
/// exact-response and monotonic-status verification paths can construct it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPayoutSnapshotV1 {
    payout_id: [u8; 32],
    payout_request_digest: [u8; 32],
    ledger_transaction_id: [u8; 32],
    state: PayoutStateV1,
    state_version: u64,
    updated_at: u64,
}

impl VerifiedPayoutSnapshotV1 {
    fn from_initial(response: &IssuerPayoutResponseV1) -> Self {
        Self {
            payout_id: response.payout_id,
            payout_request_digest: response.request_digest,
            ledger_transaction_id: response.ledger_transaction_id,
            state: response.state,
            state_version: response.state_version,
            updated_at: response.updated_at,
        }
    }

    fn from_status(response: &IssuerPayoutStatusResponseV1) -> Self {
        Self {
            payout_id: response.payout_id,
            payout_request_digest: response.payout_request_digest,
            ledger_transaction_id: response.ledger_transaction_id,
            state: response.state,
            state_version: response.state_version,
            updated_at: response.updated_at,
        }
    }

    pub fn payout_id(&self) -> &[u8; 32] {
        &self.payout_id
    }

    pub fn payout_request_digest(&self) -> &[u8; 32] {
        &self.payout_request_digest
    }

    pub fn ledger_transaction_id(&self) -> &[u8; 32] {
        &self.ledger_transaction_id
    }

    pub fn state(&self) -> PayoutStateV1 {
        self.state
    }

    pub fn state_version(&self) -> u64 {
        self.state_version
    }

    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }
}

/// Reconstructs the issuer-authenticated latest payout snapshot from exact
/// bytes already protected by a rollback-detecting durable store.
///
/// This is deliberately narrower than client status verification: it does not
/// authorize a request or accept a browser-supplied state claim. The caller
/// must load `initial_response` and `latest_status_response` from its trusted
/// payout row, compare the returned fields with that row, and only then use the
/// snapshot as the predecessor of a store-CAS status successor. It exists so a
/// restarted issuer can continue a payout without retaining an in-memory
/// typestate object or the historical polling request that produced the latest
/// signed snapshot.
pub fn verify_persisted_payout_snapshot_for_store_v1(
    payout_request: &ProviderPayoutRequestV1,
    initial_response: &IssuerPayoutResponseV1,
    latest_status_response: Option<&IssuerPayoutStatusResponseV1>,
    issuer_keyring: &IssuerSettlementKeyringExpectationV1<'_>,
) -> Result<VerifiedPayoutSnapshotV1, ServiceProtocolError> {
    let initial = verify_payout_initial_response_for_exact_request(
        initial_response,
        payout_request,
        issuer_keyring,
    )?;
    verify_persisted_payout_status_successor_for_store_v1(
        initial_response,
        latest_status_response,
        issuer_keyring,
        initial,
    )
}

/// Reconstructs a payout snapshot when the original raw idempotency key is no
/// longer available, using the request digest and exact signed responses from
/// a rollback-protected issuer-store row.
///
/// This is an issuer-worker boundary, not a client-verification shortcut. The
/// caller MUST load every argument from one authenticated durable row and MUST
/// compare every returned coordinate with that row before attempting a CAS.
/// In particular, a network-supplied digest or response is not sufficient.
pub fn verify_persisted_payout_snapshot_from_store_record_v1(
    persisted_payout_request_digest: &[u8; 32],
    initial_response: &IssuerPayoutResponseV1,
    latest_status_response: Option<&IssuerPayoutStatusResponseV1>,
    issuer_keyring: &IssuerSettlementKeyringExpectationV1<'_>,
) -> Result<VerifiedPayoutSnapshotV1, ServiceProtocolError> {
    initial_response.validate()?;
    let signing_key = issuer_keyring.resolve_for_issuer(
        &initial_response.issuer_id,
        &initial_response.issuer_settlement_key_id,
    )?;
    verify_issuer_signature(
        initial_response.issuer_settlement_key_id,
        &initial_response.signature,
        &initial_response.signing_preimage()?,
        signing_key,
    )?;
    if &initial_response.request_digest != persisted_payout_request_digest {
        return Err(binding_error(
            "IssuerPayoutResponseV1.persisted_request_digest",
        ));
    }
    verify_persisted_payout_status_successor_for_store_v1(
        initial_response,
        latest_status_response,
        issuer_keyring,
        VerifiedPayoutSnapshotV1::from_initial(initial_response),
    )
}

fn verify_persisted_payout_status_successor_for_store_v1(
    initial_response: &IssuerPayoutResponseV1,
    latest_status_response: Option<&IssuerPayoutStatusResponseV1>,
    issuer_keyring: &IssuerSettlementKeyringExpectationV1<'_>,
    initial: VerifiedPayoutSnapshotV1,
) -> Result<VerifiedPayoutSnapshotV1, ServiceProtocolError> {
    let Some(latest) = latest_status_response else {
        return Ok(initial);
    };
    latest.validate()?;
    let signing_key = issuer_keyring.resolve_for_issuer(
        &initial_response.issuer_id,
        &latest.issuer_settlement_key_id,
    )?;
    verify_issuer_signature(
        latest.issuer_settlement_key_id,
        &latest.signature,
        &latest.signing_preimage()?,
        signing_key,
    )?;
    if latest.issuer_id != initial_response.issuer_id
        || latest.provider_id != initial_response.provider_id
        || latest.account_id != initial_response.account_id
        || latest.payout_id != initial_response.payout_id
        || latest.payout_request_digest != initial_response.request_digest
        || latest.payout_target_id != initial_response.payout_target_id
        || latest.unit != initial_response.unit
        || latest.payout_value != initial_response.payout_value
        || latest.total_debit != initial_response.total_debit
        || latest.ledger_transaction_id != initial_response.ledger_transaction_id
        || latest.state_version <= initial.state_version
        || latest.updated_at <= initial.updated_at
    {
        return Err(binding_error(
            "IssuerPayoutStatusResponseV1.persisted_snapshot",
        ));
    }
    // Every V1 state is reachable from the durably authenticated initial
    // Accepted state. The store's exact-version CAS and rollback floor, not
    // this restart helper, prove that intermediate transitions were committed.
    Ok(VerifiedPayoutSnapshotV1::from_status(latest))
}

/// Exact durable predecessor that an issuer store must compare before
/// committing a signed payout-status successor. Matching only `payout_id` is
/// insufficient: concurrent workers starting from the same version could
/// otherwise publish divergent terminal outcomes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutStatusCasExpectationV1 {
    payout_id: [u8; 32],
    payout_request_digest: [u8; 32],
    ledger_transaction_id: [u8; 32],
    state: PayoutStateV1,
    state_version: u64,
    updated_at: u64,
}

impl PayoutStatusCasExpectationV1 {
    fn from_verified_snapshot(snapshot: &VerifiedPayoutSnapshotV1) -> Self {
        Self {
            payout_id: snapshot.payout_id,
            payout_request_digest: snapshot.payout_request_digest,
            ledger_transaction_id: snapshot.ledger_transaction_id,
            state: snapshot.state,
            state_version: snapshot.state_version,
            updated_at: snapshot.updated_at,
        }
    }

    pub fn payout_id(&self) -> &[u8; 32] {
        &self.payout_id
    }

    pub fn payout_request_digest(&self) -> &[u8; 32] {
        &self.payout_request_digest
    }

    pub fn ledger_transaction_id(&self) -> &[u8; 32] {
        &self.ledger_transaction_id
    }

    pub fn state(&self) -> PayoutStateV1 {
        self.state
    }

    pub fn state_version(&self) -> u64 {
        self.state_version
    }

    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }
}

/// Issuer-store boundary for payout status changes. Implementations MUST issue
/// a single atomic `UPDATE ... WHERE payout_id = ? AND state = ? AND
/// state_version = ? AND updated_at = ?` (or equivalent), persist the exact
/// signed successor/outbox effects in the same transaction, and return
/// `Ok(false)` when another worker already advanced the predecessor.
pub trait PayoutStatusCompareAndSwapStoreV1 {
    type Error;

    fn compare_and_swap_payout_status(
        &mut self,
        predecessor: &PayoutStatusCasExpectationV1,
        signed_successor: &IssuerPayoutStatusResponseV1,
    ) -> Result<bool, Self::Error>;
}

/// Revalidates the exact signed successor at the durable store boundary.
///
/// The sign-and-commit API keeps unsigned candidates from escaping, but the
/// store trait is public and can be called directly. Production stores must
/// therefore authenticate the issuer signature and the exact predecessor
/// again instead of treating trait dispatch itself as proof of signing.
pub fn verify_payout_status_successor_for_store_v1(
    response: &IssuerPayoutStatusResponseV1,
    predecessor: &PayoutStatusCasExpectationV1,
    expected_issuer_settlement_key: &VerifyingKey,
) -> Result<(), ServiceProtocolError> {
    response.validate()?;
    verify_issuer_signature(
        response.issuer_settlement_key_id,
        &response.signature,
        &response.signing_preimage()?,
        expected_issuer_settlement_key,
    )?;
    let previous = VerifiedPayoutSnapshotV1 {
        payout_id: *predecessor.payout_id(),
        payout_request_digest: *predecessor.payout_request_digest(),
        ledger_transaction_id: *predecessor.ledger_transaction_id(),
        state: predecessor.state(),
        state_version: predecessor.state_version(),
        updated_at: predecessor.updated_at(),
    };
    verify_payout_state_progression(&previous, response)?;
    if predecessor.state_version().checked_add(1) != Some(response.state_version) {
        return Err(ServiceProtocolError::InvalidValue {
            field: "IssuerPayoutStatusResponseV1.state_version",
            reason: "durable successor must increment the exact predecessor by one",
        });
    }
    Ok(())
}

/// Recovery-safe verification of the initial issuer-signed payout response.
/// This intentionally needs no still-current debt-creating clearing
/// authorization: the exact original request plus issuer signature are the
/// durable evidence that the issuer accepted the payout.
pub fn verify_payout_initial_response_for_exact_request(
    response: &IssuerPayoutResponseV1,
    request: &ProviderPayoutRequestV1,
    issuer_keyring: &IssuerSettlementKeyringExpectationV1<'_>,
) -> Result<VerifiedPayoutSnapshotV1, ServiceProtocolError> {
    let signing_key = issuer_keyring
        .resolve_for_issuer(&request.issuer_id, &response.issuer_settlement_key_id)?;
    response.verify_for_exact_request(request, signing_key)?;
    Ok(VerifiedPayoutSnapshotV1::from_initial(response))
}

pub fn verify_new_payout_response_for<'a>(
    response: &'a IssuerPayoutResponseV1,
    request: &'a ProviderPayoutRequestV1,
    payout_context: &PayoutExecutionContextV1<'_>,
    authorization: &ProviderClearingAuthorizationV1,
    issuer_approval: &IssuerClearingApprovalV1,
    request_auth: &ProviderClearingRequestAuthV1,
    expectation: &ProviderClearingExpectationV1<'_>,
) -> Result<VerifiedPayoutSnapshotV1, ServiceProtocolError> {
    let execution = verify_new_payout_request_for(
        request,
        payout_context,
        authorization,
        issuer_approval,
        request_auth,
        expectation,
    )?;
    if execution.payout_intent_id() != &response.payout_intent_id {
        return Err(binding_error("IssuerPayoutResponseV1.payout_intent_id"));
    }
    response.verify_for_exact_request(request, expectation.issuer_settlement_key)?;
    Ok(VerifiedPayoutSnapshotV1::from_initial(response))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderPayoutStatusRequestV1 {
    pub registration_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub account_id: [u8; 32],
    pub payout_id: [u8; 32],
    pub payout_request_digest: [u8; 32],
    /// Fresh nonce for this read-only latest-snapshot request. Issuers MUST NOT
    /// idempotency-cache payout status by this value (or by any other key).
    pub request_nonce: [u8; 32],
}

impl ProviderPayoutStatusRequestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = encode_request_context(
            self.registration_digest,
            self.issuer_id,
            self.provider_id,
            self.account_id,
        );
        out.extend_from_slice(&self.payout_id);
        out.extend_from_slice(&self.payout_request_digest);
        out.extend_from_slice(&self.request_nonce);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let (registration_digest, issuer_id, provider_id, account_id) =
            decode_request_context(&mut decoder, "ProviderPayoutStatusRequestV1")?;
        let value = Self {
            registration_digest,
            issuer_id,
            provider_id,
            account_id,
            payout_id: decoder.fixed("ProviderPayoutStatusRequestV1.payout_id")?,
            payout_request_digest: decoder
                .fixed("ProviderPayoutStatusRequestV1.payout_request_digest")?,
            request_nonce: decoder.fixed("ProviderPayoutStatusRequestV1.request_nonce")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        hash_canonical(
            PROVIDER_PAYOUT_STATUS_REQUEST_DIGEST_DOMAIN_V1,
            &self.encode()?,
        )
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_request_context(
            self.registration_digest,
            self.issuer_id,
            self.provider_id,
            self.account_id,
            self.request_nonce,
            "ProviderPayoutStatusRequestV1",
        )?;
        validate_nonzero(&self.payout_id, "ProviderPayoutStatusRequestV1.payout_id")?;
        validate_nonzero(
            &self.payout_request_digest,
            "ProviderPayoutStatusRequestV1.payout_request_digest",
        )
    }
}

pub struct PayoutStatusContextV1<'a> {
    pub payout_request: &'a ProviderPayoutRequestV1,
    pub initial_payout_response: &'a IssuerPayoutResponseV1,
}

/// Verifies a read-only latest-status request. This path authenticates the
/// provider under its current registration and validates the exact original
/// payout request plus initial issuer-signed response. It deliberately does
/// not require the original debt-creating clearing authorization to remain
/// current.
pub fn verify_new_payout_status_request_for(
    request: &ProviderPayoutStatusRequestV1,
    payout_context: &PayoutStatusContextV1<'_>,
    request_auth: &ProviderSettlementRequestAuthV1,
    registration: &ProviderSettlementRegistrationExpectationV1<'_>,
    issuer_keyring: &IssuerSettlementKeyringExpectationV1<'_>,
) -> Result<VerifiedPayoutSnapshotV1, ServiceProtocolError> {
    request.validate()?;
    payout_context.payout_request.validate()?;
    registration.validate_current()?;
    issuer_keyring.validate_for_registration(registration)?;
    let initial = verify_payout_initial_response_for_exact_request(
        payout_context.initial_payout_response,
        payout_context.payout_request,
        issuer_keyring,
    )?;
    if request.payout_request_digest != payout_context.payout_request.request_digest()?
        || request.payout_id != payout_context.initial_payout_response.payout_id
        || &request.registration_digest != registration.registration_digest
        || &request.issuer_id != registration.issuer_id
        || &request.provider_id != registration.provider_id
        || &request.account_id != registration.settlement_account_id
        || request.issuer_id != payout_context.payout_request.issuer_id
        || request.provider_id != payout_context.payout_request.provider_id
        || request.account_id != payout_context.payout_request.account_id
    {
        return Err(binding_error(
            "ProviderPayoutStatusRequestV1.payout_binding",
        ));
    }
    request_auth.verify_for(&request.request_digest()?, registration)?;
    Ok(initial)
}

/// Authenticates an exact payout-status request whose signed response is
/// already present in a rollback-protected issuer store.
///
/// The caller MUST first prove that the request digest matches the durable
/// latest-status response for this payout. This helper never authorizes a new
/// status successor. It evaluates the retained provider registration at the
/// start of its signed validity window so ordinary registration expiry cannot
/// strand bytes that were committed before an HTTP response was lost.
pub fn verify_committed_payout_status_replay_auth_v1(
    request: &ProviderPayoutStatusRequestV1,
    payout_context: &PayoutStatusContextV1<'_>,
    request_auth: &ProviderSettlementRequestAuthV1,
    registration: &ProviderSettlementRegistrationExpectationV1<'_>,
    issuer_keyring: &IssuerSettlementKeyringExpectationV1<'_>,
) -> Result<VerifiedPayoutSnapshotV1, ServiceProtocolError> {
    let historical_registration = ProviderSettlementRegistrationExpectationV1 {
        registration_digest: registration.registration_digest,
        provider_id: registration.provider_id,
        issuer_id: registration.issuer_id,
        settlement_account_id: registration.settlement_account_id,
        provider_request_key: registration.provider_request_key,
        issuer_settlement_key: registration.issuer_settlement_key,
        not_before: registration.not_before,
        not_after: registration.not_after,
        now_unix: registration.not_before,
    };
    verify_new_payout_status_request_for(
        request,
        payout_context,
        request_auth,
        &historical_registration,
        issuer_keyring,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerPayoutStatusResponseV1 {
    pub issuer_settlement_key_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub registration_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub account_id: [u8; 32],
    pub payout_id: [u8; 32],
    pub payout_request_digest: [u8; 32],
    pub payout_target_id: PayoutTargetIdV1,
    pub unit: SettlementUnitV1,
    pub payout_value: u64,
    pub total_debit: u64,
    pub state: PayoutStateV1,
    pub ledger_transaction_id: [u8; 32],
    pub state_version: u64,
    pub updated_at: u64,
    pub signature: [u8; 64],
}

impl IssuerPayoutStatusResponseV1 {
    /// Signs only a monotonic successor and returns it only after the issuer
    /// store atomically compares the exact verified predecessor and commits
    /// the exact signed successor. This is the production issuer path.
    pub fn sign_and_commit_successor<Store: PayoutStatusCompareAndSwapStoreV1>(
        value: Self,
        previous: &VerifiedPayoutSnapshotV1,
        issuer_settlement_signing_key: &SigningKey,
        store: &mut Store,
    ) -> Result<Self, PayoutCommitErrorV1<Store::Error>> {
        let signed = Self::sign_structural(value, issuer_settlement_signing_key)
            .map_err(PayoutCommitErrorV1::Protocol)?;
        verify_payout_state_progression(previous, &signed)
            .map_err(PayoutCommitErrorV1::Protocol)?;
        if previous.state_version.checked_add(1) != Some(signed.state_version) {
            return Err(PayoutCommitErrorV1::Protocol(
                ServiceProtocolError::InvalidValue {
                    field: "IssuerPayoutStatusResponseV1.state_version",
                    reason: "a committed successor must increment the exact predecessor by one",
                },
            ));
        }
        let predecessor = PayoutStatusCasExpectationV1::from_verified_snapshot(previous);
        let committed = store
            .compare_and_swap_payout_status(&predecessor, &signed)
            .map_err(PayoutCommitErrorV1::Store)?;
        if !committed {
            return Err(PayoutCommitErrorV1::Conflict {
                operation: "payout_status_compare_and_swap",
            });
        }
        Ok(signed)
    }

    fn sign_structural(
        mut value: Self,
        issuer_settlement_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        value.issuer_settlement_key_id =
            issuer_settlement_key_id(&issuer_settlement_signing_key.verifying_key());
        value.signature = [0; 64];
        value.validate()?;
        value.signature = issuer_settlement_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let (issuer_settlement_key_id, request_digest, registration_digest, issuer_id, provider_id) =
            decode_common_response(&mut decoder, "IssuerPayoutStatusResponseV1")?;
        let value = Self {
            issuer_settlement_key_id,
            request_digest,
            registration_digest,
            issuer_id,
            provider_id,
            account_id: decoder.fixed("IssuerPayoutStatusResponseV1.account_id")?,
            payout_id: decoder.fixed("IssuerPayoutStatusResponseV1.payout_id")?,
            payout_request_digest: decoder
                .fixed("IssuerPayoutStatusResponseV1.payout_request_digest")?,
            payout_target_id: decoder.fixed("IssuerPayoutStatusResponseV1.payout_target_id")?,
            unit: SettlementUnitV1::decode(decoder.u8("IssuerPayoutStatusResponseV1.unit")?)?,
            payout_value: decoder.u64("IssuerPayoutStatusResponseV1.payout_value")?,
            total_debit: decoder.u64("IssuerPayoutStatusResponseV1.total_debit")?,
            state: PayoutStateV1::decode(decoder.u8("IssuerPayoutStatusResponseV1.state")?)?,
            ledger_transaction_id: decoder
                .fixed("IssuerPayoutStatusResponseV1.ledger_transaction_id")?,
            state_version: decoder.u64("IssuerPayoutStatusResponseV1.state_version")?,
            updated_at: decoder.u64("IssuerPayoutStatusResponseV1.updated_at")?,
            signature: decoder.fixed("IssuerPayoutStatusResponseV1.signature")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Outer signature and exact request/context binding only. This stays
    /// private because it does not enforce monotonic state progression.
    fn verify_structure_for_exact_request(
        &self,
        request: &ProviderPayoutStatusRequestV1,
        payout_context: &PayoutStatusContextV1<'_>,
        expected_status_signing_key: &VerifyingKey,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        verify_issuer_signature(
            self.issuer_settlement_key_id,
            &self.signature,
            &self.signing_preimage()?,
            expected_status_signing_key,
        )?;
        if self.request_digest != request.request_digest()?
            || self.registration_digest != request.registration_digest
            || self.issuer_id != request.issuer_id
            || self.provider_id != request.provider_id
            || self.account_id != request.account_id
            || self.payout_id != request.payout_id
            || self.payout_request_digest != request.payout_request_digest
            || self.payout_id != payout_context.initial_payout_response.payout_id
            || self.payout_target_id != payout_context.payout_request.payout_target_id
            || self.unit != payout_context.payout_request.unit
            || self.payout_value != payout_context.payout_request.payout_value
            || self.total_debit != payout_context.payout_request.total_debit
            || self.ledger_transaction_id
                != payout_context.initial_payout_response.ledger_transaction_id
        {
            return Err(binding_error("IssuerPayoutStatusResponseV1.binding"));
        }
        Ok(())
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = encode_common_response(
            self.issuer_settlement_key_id,
            self.request_digest,
            self.registration_digest,
            self.issuer_id,
            self.provider_id,
        );
        out.extend_from_slice(&self.account_id);
        out.extend_from_slice(&self.payout_id);
        out.extend_from_slice(&self.payout_request_digest);
        out.extend_from_slice(&self.payout_target_id);
        out.push(self.unit as u8);
        out.extend_from_slice(&self.payout_value.to_le_bytes());
        out.extend_from_slice(&self.total_debit.to_le_bytes());
        out.push(self.state as u8);
        out.extend_from_slice(&self.ledger_transaction_id);
        out.extend_from_slice(&self.state_version.to_le_bytes());
        out.extend_from_slice(&self.updated_at.to_le_bytes());
        Ok(out)
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        signing_preimage(
            ISSUER_PAYOUT_STATUS_RESPONSE_SIGNATURE_DOMAIN_V1,
            self.encode_unsigned()?,
        )
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_common_response(
            self.issuer_settlement_key_id,
            self.request_digest,
            self.registration_digest,
            self.issuer_id,
            self.provider_id,
        )?;
        validate_nonzero(&self.account_id, "IssuerPayoutStatusResponseV1.account_id")?;
        validate_nonzero(
            &self.payout_target_id,
            "IssuerPayoutStatusResponseV1.payout_target_id",
        )?;
        validate_value(
            self.payout_value,
            "IssuerPayoutStatusResponseV1.payout_value",
        )?;
        validate_value(self.total_debit, "IssuerPayoutStatusResponseV1.total_debit")?;
        if self.total_debit < self.payout_value {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerPayoutStatusResponseV1.total_debit",
                reason: "cannot be less than payout value",
            });
        }
        validate_nonzero(&self.payout_id, "IssuerPayoutStatusResponseV1.payout_id")?;
        validate_nonzero(
            &self.payout_request_digest,
            "IssuerPayoutStatusResponseV1.payout_request_digest",
        )?;
        validate_nonzero(
            &self.ledger_transaction_id,
            "IssuerPayoutStatusResponseV1.ledger_transaction_id",
        )?;
        if self.state_version == 0 || self.updated_at == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerPayoutStatusResponseV1.version_time",
                reason: "state version and update time must be non-zero",
            });
        }
        Ok(())
    }
}

/// Verifies the issuer's latest read-only snapshot against the exact initial
/// response and the caller's highest previously verified snapshot. Callers
/// must durably retain the highest accepted `(state_version, updated_at)` and
/// always pass it back; the issuer must query live state for each fresh nonce
/// and must not return an idempotency-cached snapshot.
pub fn verify_new_payout_status_response_for(
    response: &IssuerPayoutStatusResponseV1,
    request: &ProviderPayoutStatusRequestV1,
    payout_context: &PayoutStatusContextV1<'_>,
    previous_snapshot: &VerifiedPayoutSnapshotV1,
    request_auth: &ProviderSettlementRequestAuthV1,
    registration: &ProviderSettlementRegistrationExpectationV1<'_>,
    issuer_keyring: &IssuerSettlementKeyringExpectationV1<'_>,
) -> Result<VerifiedPayoutSnapshotV1, ServiceProtocolError> {
    let initial = verify_new_payout_status_request_for(
        request,
        payout_context,
        request_auth,
        registration,
        issuer_keyring,
    )?;
    let status_signing_key = issuer_keyring
        .resolve_for_issuer(registration.issuer_id, &response.issuer_settlement_key_id)?;
    response.verify_structure_for_exact_request(request, payout_context, status_signing_key)?;
    if previous_snapshot.payout_id != initial.payout_id
        || previous_snapshot.payout_request_digest != initial.payout_request_digest
        || previous_snapshot.ledger_transaction_id != initial.ledger_transaction_id
    {
        return Err(binding_error(
            "IssuerPayoutStatusResponseV1.previous_snapshot",
        ));
    }
    verify_payout_state_progression(previous_snapshot, response)?;
    Ok(VerifiedPayoutSnapshotV1::from_status(response))
}

fn verify_payout_state_progression(
    previous: &VerifiedPayoutSnapshotV1,
    next: &IssuerPayoutStatusResponseV1,
) -> Result<(), ServiceProtocolError> {
    if next.payout_id != previous.payout_id
        || next.payout_request_digest != previous.payout_request_digest
        || next.ledger_transaction_id != previous.ledger_transaction_id
        || next.state_version <= previous.state_version
        || next.updated_at <= previous.updated_at
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "IssuerPayoutStatusResponseV1.progression",
            reason: "payout identity must be stable and signed version/time must strictly increase",
        });
    }
    let allowed = next.state == previous.state
        || matches!(
            (previous.state, next.state),
            (PayoutStateV1::Accepted, PayoutStateV1::InFlight)
                | (PayoutStateV1::InFlight, PayoutStateV1::Succeeded)
                | (PayoutStateV1::InFlight, PayoutStateV1::Failed)
        );
    if !allowed {
        return Err(ServiceProtocolError::InvalidValue {
            field: "IssuerPayoutStatusResponseV1.state",
            reason: "invalid payout state transition or terminal-state reversal",
        });
    }
    Ok(())
}

fn verify_current_request(
    request_digest: [u8; 32],
    authorization: &ProviderClearingAuthorizationV1,
    issuer_approval: &IssuerClearingApprovalV1,
    request_auth: &ProviderClearingRequestAuthV1,
    expectation: &ProviderClearingExpectationV1<'_>,
) -> Result<(), ServiceProtocolError> {
    let authorization_digest = authorization.authorization_digest()?;
    request_auth.verify_for(
        &authorization_digest,
        &request_digest,
        authorization,
        issuer_approval,
        expectation,
    )
}

fn validate_authorized_account(
    authorization_digest: [u8; 32],
    issuer_id: [u8; 32],
    provider_id: ProviderId,
    account_id: [u8; 32],
    authorization: &ProviderClearingAuthorizationV1,
    field: &'static str,
) -> Result<(), ServiceProtocolError> {
    if authorization_digest != authorization.authorization_digest()?
        || issuer_id != authorization.claims.issuer_id
        || provider_id != authorization.claims.provider_id
        || account_id != authorization.claims.settlement_account_id
    {
        Err(ServiceProtocolError::InvalidValue {
            field,
            reason: "request does not match authorization or fixed settlement account",
        })
    } else {
        Ok(())
    }
}

fn validate_request_context(
    authorization_digest: [u8; 32],
    issuer_id: [u8; 32],
    provider_id: ProviderId,
    account_id: [u8; 32],
    idempotency_key: [u8; 32],
    field: &'static str,
) -> Result<(), ServiceProtocolError> {
    if authorization_digest.iter().all(|byte| *byte == 0)
        || issuer_id.iter().all(|byte| *byte == 0)
        || provider_id.iter().all(|byte| *byte == 0)
        || account_id.iter().all(|byte| *byte == 0)
        || idempotency_key.iter().all(|byte| *byte == 0)
    {
        Err(ServiceProtocolError::InvalidValue {
            field,
            reason: "context digest, audience, account, and request control value must be non-zero",
        })
    } else {
        Ok(())
    }
}

fn encode_request_context(
    authorization_digest: [u8; 32],
    issuer_id: [u8; 32],
    provider_id: ProviderId,
    account_id: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(193);
    out.push(SERVICE_PROTOCOL_VERSION);
    out.extend_from_slice(&authorization_digest);
    out.extend_from_slice(&issuer_id);
    out.extend_from_slice(&provider_id);
    out.extend_from_slice(&account_id);
    out
}

type RequestContextV1 = ([u8; 32], [u8; 32], ProviderId, [u8; 32]);

fn decode_request_context(
    decoder: &mut Decoder<'_>,
    kind: &'static str,
) -> Result<RequestContextV1, ServiceProtocolError> {
    expect_v1(decoder.u8(kind)?, kind)?;
    Ok((
        decoder.fixed(kind)?,
        decoder.fixed(kind)?,
        decoder.fixed(kind)?,
        decoder.fixed(kind)?,
    ))
}

fn encode_common_response(
    issuer_key_id: [u8; 16],
    request_digest: [u8; 32],
    authorization_digest: [u8; 32],
    issuer_id: [u8; 32],
    provider_id: ProviderId,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(145);
    out.push(SERVICE_PROTOCOL_VERSION);
    out.extend_from_slice(&issuer_key_id);
    out.extend_from_slice(&request_digest);
    out.extend_from_slice(&authorization_digest);
    out.extend_from_slice(&issuer_id);
    out.extend_from_slice(&provider_id);
    out
}

type ResponseContextV1 = ([u8; 16], [u8; 32], [u8; 32], [u8; 32], ProviderId);

fn decode_common_response(
    decoder: &mut Decoder<'_>,
    kind: &'static str,
) -> Result<ResponseContextV1, ServiceProtocolError> {
    expect_v1(decoder.u8(kind)?, kind)?;
    Ok((
        decoder.fixed(kind)?,
        decoder.fixed(kind)?,
        decoder.fixed(kind)?,
        decoder.fixed(kind)?,
        decoder.fixed(kind)?,
    ))
}

fn validate_common_response(
    issuer_key_id: [u8; 16],
    request_digest: [u8; 32],
    authorization_digest: [u8; 32],
    issuer_id: [u8; 32],
    provider_id: ProviderId,
) -> Result<(), ServiceProtocolError> {
    if issuer_key_id.iter().all(|byte| *byte == 0)
        || request_digest.iter().all(|byte| *byte == 0)
        || authorization_digest.iter().all(|byte| *byte == 0)
        || issuer_id.iter().all(|byte| *byte == 0)
        || provider_id.iter().all(|byte| *byte == 0)
    {
        Err(ServiceProtocolError::InvalidValue {
            field: "issuer response context",
            reason: "issuer key, request, context digest, and audience must be non-zero",
        })
    } else {
        Ok(())
    }
}

fn validate_payout_common(
    account_id: [u8; 32],
    payout_target_id: [u8; 32],
    payout_intent_id: [u8; 32],
    payout_value: u64,
    total_debit: u64,
    field: &'static str,
) -> Result<(), ServiceProtocolError> {
    validate_nonzero(&account_id, field)?;
    validate_nonzero(&payout_target_id, field)?;
    validate_nonzero(&payout_intent_id, field)?;
    validate_value(payout_value, field)?;
    validate_value(total_debit, field)?;
    if total_debit < payout_value {
        return Err(ServiceProtocolError::InvalidValue {
            field,
            reason: "total debit cannot be less than payout value",
        });
    }
    Ok(())
}

fn put_keyset_id(out: &mut Vec<u8>, keyset_id: &str) {
    out.push(keyset_id.len() as u8);
    out.extend_from_slice(keyset_id.as_bytes());
}

fn decode_keyset_id(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<String, ServiceProtocolError> {
    let bytes = decoder.bytes_u8(field, CASHU_KEYSET_ID_V2_LEN)?;
    String::from_utf8(bytes).map_err(|_| ServiceProtocolError::InvalidUtf8(field))
}

fn validate_keyset_id(keyset_id: &str) -> Result<(), ServiceProtocolError> {
    if crate::is_canonical_cashu_keyset_id_v2(keyset_id) {
        Ok(())
    } else {
        Err(ServiceProtocolError::InvalidValue {
            field: "settlement_keyset_id",
            reason: "must be an exact canonical NUT-02 V2 keyset ID",
        })
    }
}

fn decode_string_u16(
    decoder: &mut Decoder<'_>,
    field: &'static str,
    max: usize,
) -> Result<String, ServiceProtocolError> {
    String::from_utf8(decoder.bytes_u16(field, max)?)
        .map_err(|_| ServiceProtocolError::InvalidUtf8(field))
}

fn validate_nonzero<const N: usize>(
    value: &[u8; N],
    field: &'static str,
) -> Result<(), ServiceProtocolError> {
    if value.iter().all(|byte| *byte == 0) {
        Err(ServiceProtocolError::InvalidValue {
            field,
            reason: "must be non-zero",
        })
    } else {
        Ok(())
    }
}

fn validate_value(value: u64, field: &'static str) -> Result<(), ServiceProtocolError> {
    if value == 0 || value > MAX_SERVICE_VALUE_V1 {
        Err(ServiceProtocolError::InvalidValue {
            field,
            reason: "must be non-zero and fit signed durable storage",
        })
    } else {
        Ok(())
    }
}

fn checked_add(left: u64, right: u64, field: &'static str) -> Result<u64, ServiceProtocolError> {
    left.checked_add(right)
        .filter(|value| *value <= MAX_SERVICE_VALUE_V1)
        .ok_or(ServiceProtocolError::InvalidValue {
            field,
            reason: "sum exceeds signed durable storage",
        })
}

fn is_valid_nonzero_scalar(bytes: &[u8; 32]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
        && Option::<Scalar>::from(Scalar::from_repr((*bytes).into())).is_some()
}

fn verify_issuer_signature(
    encoded_key_id: [u8; 16],
    signature: &[u8; 64],
    preimage: &[u8],
    expected_key: &VerifyingKey,
) -> Result<(), ServiceProtocolError> {
    if encoded_key_id != issuer_settlement_key_id(expected_key) {
        return Err(ServiceProtocolError::WrongSigningKeyId);
    }
    expected_key
        .verify_strict(preimage, &Signature::from_bytes(signature))
        .map_err(|_| ServiceProtocolError::BadSignature)
}

fn signing_preimage(domain: &[u8], unsigned: Vec<u8>) -> Result<Vec<u8>, ServiceProtocolError> {
    let mut out = Vec::with_capacity(domain.len() + unsigned.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(&unsigned);
    Ok(out)
}

fn hash_canonical(domain: &[u8], canonical: &[u8]) -> Result<[u8; 32], ServiceProtocolError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

fn binding_error(field: &'static str) -> ServiceProtocolError {
    ServiceProtocolError::InvalidValue {
        field,
        reason: "response or dependent request does not bind the exact canonical predecessor",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        credential_presentation_digest, derive_cashu_keyset_id_v2, AuthScheme,
        BlindSettlementOutputV1, CashuDenominationKeyV1, CashuKeysetBindingV1,
        ProviderClearingAuthorizationClaimsV1, SettlementModesV1, SettlementRuleV1,
    };
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::ProjectivePoint;

    fn point(multiplier: u64) -> [u8; 33] {
        (ProjectivePoint::GENERATOR * Scalar::from(multiplier))
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed point")
    }

    fn scalar(multiplier: u64) -> [u8; 32] {
        Scalar::from(multiplier).to_bytes().into()
    }

    fn keyset() -> CashuKeysetBindingV1 {
        let keys = [1, 2, 4, 8]
            .into_iter()
            .enumerate()
            .map(|(index, amount)| CashuDenominationKeyV1 {
                amount,
                public_key: point(50 + index as u64),
            })
            .collect::<Vec<_>>();
        CashuKeysetBindingV1 {
            keyset_id: derive_cashu_keyset_id_v2(&keys, "auth", 0, Some(4_000)).expect("keyset ID"),
            unit: "auth".into(),
            input_fee_ppk: 0,
            final_expiry: Some(4_000),
            keys,
        }
    }

    struct Fixture {
        authorization: ProviderClearingAuthorizationV1,
        approval: IssuerClearingApprovalV1,
        operator_key: VerifyingKey,
        clearing: SigningKey,
        registration_request: SigningKey,
        registration_request_key: VerifyingKey,
        issuer: SigningKey,
        issuer_key: VerifyingKey,
    }

    const REGISTRATION_DIGEST: [u8; 32] = [80; 32];

    fn fixture() -> Fixture {
        let operator = SigningKey::from_bytes(&[3; 32]);
        let clearing = SigningKey::from_bytes(&[4; 32]);
        let registration_request = SigningKey::from_bytes(&[14; 32]);
        let issuer = SigningKey::from_bytes(&[13; 32]);
        let authorization = ProviderClearingAuthorizationV1::sign(
            ProviderClearingAuthorizationClaimsV1 {
                authorization_id: [1; 16],
                authorization_epoch: 2,
                provider_id: [5; 32],
                issuer_id: [6; 32],
                redeem_endpoint: "https://issuer.example".to_owned(),
                redeem_leaf_spki_sha256_pins: vec![[0x41; 32]],
                settlement_account_id: [17; 32],
                clearing_verifying_key: clearing.verifying_key().to_bytes(),
                not_before: 100,
                not_after: 200,
                rules: vec![SettlementRuleV1 {
                    credential_binding_digest: [7; 32],
                    unit: SettlementUnitV1::AuthCredit,
                    accepted_value: 10,
                    provider_credit: 9,
                    issuer_fee: 1,
                    denomination_profile: 8,
                    settlement_modes: SettlementModesV1::from_bits(
                        SettlementModesV1::LEDGER_CREDIT | SettlementModesV1::BLIND_OUTPUTS,
                    )
                    .expect("modes"),
                    blind_output_minimum_validity_seconds: 3_600,
                    blind_output_keyset: Some(keyset()),
                }],
            },
            &operator,
        )
        .expect("authorization");
        let approval = IssuerClearingApprovalV1::sign(&authorization, 100, 200, &issuer)
            .expect("issuer approval");
        Fixture {
            authorization,
            approval,
            operator_key: operator.verifying_key(),
            issuer_key: issuer.verifying_key(),
            registration_request_key: registration_request.verifying_key(),
            clearing,
            registration_request,
            issuer,
        }
    }

    fn expectation<'a>(fixture: &'a Fixture) -> ProviderClearingExpectationV1<'a> {
        ProviderClearingExpectationV1 {
            provider_id: &[5; 32],
            issuer_id: &[6; 32],
            operator_key: &fixture.operator_key,
            issuer_settlement_key: &fixture.issuer_key,
            now_unix: 150,
            minimum_authorization_epoch: 2,
        }
    }

    fn registration<'a>(fixture: &'a Fixture) -> ProviderSettlementRegistrationExpectationV1<'a> {
        registration_at(fixture, 150)
    }

    fn registration_at<'a>(
        fixture: &'a Fixture,
        now_unix: u64,
    ) -> ProviderSettlementRegistrationExpectationV1<'a> {
        ProviderSettlementRegistrationExpectationV1 {
            registration_digest: &REGISTRATION_DIGEST,
            provider_id: &fixture.authorization.claims.provider_id,
            issuer_id: &fixture.authorization.claims.issuer_id,
            settlement_account_id: &fixture.authorization.claims.settlement_account_id,
            provider_request_key: &fixture.registration_request_key,
            issuer_settlement_key: &fixture.issuer_key,
            not_before: 100,
            not_after: 10_000,
            now_unix,
        }
    }

    fn retained_keysets<'a>(fixture: &'a Fixture) -> RetainedSettlementKeysetExpectationV1<'a> {
        retained_keysets_at(fixture, 150)
    }

    fn retained_keysets_at<'a>(
        fixture: &'a Fixture,
        now_unix: u64,
    ) -> RetainedSettlementKeysetExpectationV1<'a> {
        let keyset = fixture.authorization.claims.rules[0]
            .blind_output_keyset
            .as_ref()
            .expect("test retained keyset");
        RetainedSettlementKeysetExpectationV1 {
            issuer_id: &fixture.authorization.claims.issuer_id,
            retained_keysets: std::slice::from_ref(keyset),
            now_unix,
        }
    }

    #[derive(Default)]
    struct TestPayoutExecutionStore {
        consumed_intents: HashSet<[u8; 32]>,
    }

    impl PayoutExecutionCommitStoreV1 for TestPayoutExecutionStore {
        type Error = ();

        fn commit_new_payout(
            &mut self,
            execution: &VerifiedPayoutExecutionV1<'_>,
            _signed_response: &IssuerPayoutResponseV1,
        ) -> Result<bool, Self::Error> {
            Ok(self.consumed_intents.insert(*execution.payout_intent_id()))
        }
    }

    struct TestPayoutStatusStore {
        current: PayoutStatusCasExpectationV1,
    }

    impl TestPayoutStatusStore {
        fn from_snapshot(snapshot: &VerifiedPayoutSnapshotV1) -> Self {
            Self {
                current: PayoutStatusCasExpectationV1::from_verified_snapshot(snapshot),
            }
        }
    }

    impl PayoutStatusCompareAndSwapStoreV1 for TestPayoutStatusStore {
        type Error = ();

        fn compare_and_swap_payout_status(
            &mut self,
            predecessor: &PayoutStatusCasExpectationV1,
            signed_successor: &IssuerPayoutStatusResponseV1,
        ) -> Result<bool, Self::Error> {
            if &self.current != predecessor {
                return Ok(false);
            }
            self.current = PayoutStatusCasExpectationV1 {
                payout_id: signed_successor.payout_id,
                payout_request_digest: signed_successor.payout_request_digest,
                ledger_transaction_id: signed_successor.ledger_transaction_id,
                state: signed_successor.state,
                state_version: signed_successor.state_version,
                updated_at: signed_successor.updated_at,
            };
            Ok(true)
        }
    }

    struct TestDleqVerifier;

    impl CashuDleqVerifierV1 for TestDleqVerifier {
        fn verify_dleq(
            &self,
            input: CashuDleqVerificationInputV1<'_>,
        ) -> Result<(), ServiceProtocolError> {
            let valid = match input.denomination {
                1 => {
                    *input.denomination_public_key == point(50)
                        && *input.blinded_message == point(21)
                        && *input.blinded_signature == point(31)
                        && *input.dleq_e == scalar(3)
                        && *input.dleq_s == scalar(4)
                }
                8 => {
                    *input.denomination_public_key == point(53)
                        && *input.blinded_message == point(22)
                        && *input.blinded_signature == point(32)
                        && *input.dleq_e == scalar(5)
                        && *input.dleq_s == scalar(6)
                }
                _ => false,
            };
            if valid {
                Ok(())
            } else {
                Err(ServiceProtocolError::BadSignature)
            }
        }
    }

    struct TestNoteVerifier;

    impl CashuSettlementNoteVerifierV1 for TestNoteVerifier {
        fn verify_note_and_derive_y(
            &self,
            input: CashuSettlementNoteVerificationInputV1<'_>,
        ) -> Result<[u8; 33], ServiceProtocolError> {
            match input.denomination {
                1 if *input.denomination_public_key == point(50)
                    && input.secret == "secret-a"
                    && *input.signature == point(61)
                    && input.witness.is_none() =>
                {
                    Ok(point(71))
                }
                8 if *input.denomination_public_key == point(53)
                    && input.secret == "secret-b"
                    && *input.signature == point(62)
                    && input.witness == Some("witness-b") =>
                {
                    Ok(point(72))
                }
                _ => Err(ServiceProtocolError::BadSignature),
            }
        }
    }

    struct DuplicateYNoteVerifier;

    impl CashuSettlementNoteVerifierV1 for DuplicateYNoteVerifier {
        fn verify_note_and_derive_y(
            &self,
            input: CashuSettlementNoteVerificationInputV1<'_>,
        ) -> Result<[u8; 33], ServiceProtocolError> {
            TestNoteVerifier.verify_note_and_derive_y(input)?;
            Ok(point(71))
        }
    }

    fn redeem_request(fixture: &Fixture) -> ProviderRedeemRequestV1 {
        ProviderRedeemRequestV1 {
            authorization_digest: fixture
                .authorization
                .authorization_digest()
                .expect("authorization digest"),
            issuer_id: [6; 32],
            provider_id: [5; 32],
            scope_id: [15; 32],
            offer_id: 7,
            credential_binding_digest: [7; 32],
            scheme: AuthScheme::BitcoinPirCashuBatV1,
            credential_digest: credential_presentation_digest(
                AuthScheme::BitcoinPirCashuBatV1,
                b"canonical credential",
            )
            .expect("credential digest"),
            accepted_value: 10,
            denomination_profile: 8,
            idempotency_key: [16; 32],
            destination: SettlementDestinationV1::BlindOutputs {
                settlement_keyset_id: keyset().keyset_id,
                outputs: vec![
                    BlindSettlementOutputV1 {
                        denomination: 1,
                        blinded_message: point(21),
                    },
                    BlindSettlementOutputV1 {
                        denomination: 8,
                        blinded_message: point(22),
                    },
                ],
            },
        }
    }

    #[test]
    fn redeem_response_echoes_every_blind_output_and_has_no_blinding_scalar() {
        let fixture = fixture();
        let request = redeem_request(&fixture);
        let response = ProviderRedeemResponseV1::sign(
            ProviderRedeemResponseV1 {
                issuer_settlement_key_id: [0; 16],
                request_digest: request.request_digest().expect("request digest"),
                authorization_digest: request.authorization_digest,
                issuer_id: request.issuer_id,
                provider_id: request.provider_id,
                unit: SettlementUnitV1::AuthCredit,
                accepted_value: 10,
                provider_credit: 9,
                issuer_fee: 1,
                result: RedeemSettlementResultV1::BlindOutputs {
                    settlement_keyset_id: keyset().keyset_id,
                    signatures: vec![
                        BlindSettlementSignatureV1 {
                            denomination: 1,
                            blinded_message: point(21),
                            blinded_signature: point(31),
                            dleq_e: scalar(3),
                            dleq_s: scalar(4),
                        },
                        BlindSettlementSignatureV1 {
                            denomination: 8,
                            blinded_message: point(22),
                            blinded_signature: point(32),
                            dleq_e: scalar(5),
                            dleq_s: scalar(6),
                        },
                    ],
                },
                signature: [0; 64],
            },
            &fixture.issuer,
        )
        .expect("signed redeem response");
        let bytes = response.encode().expect("encode");
        assert_eq!(
            ProviderRedeemResponseV1::decode(&bytes).expect("decode"),
            response
        );
        let verified = verify_redeem_response_for_exact_request(
            &response,
            &request,
            &fixture.authorization,
            &fixture.issuer.verifying_key(),
            &retained_keysets(&fixture),
            &TestDleqVerifier,
        )
        .expect("exact cryptographically verified response");
        assert!(matches!(
            verified.result(),
            VerifiedRedeemSettlementResultV1::BlindOutputs { promises, .. }
                if promises.len() == 2
        ));
        let trusted_keysets = retained_keysets(&fixture);
        let wrong_issuer_id = [97; 32];
        let wrong_issuer_keysets = RetainedSettlementKeysetExpectationV1 {
            issuer_id: &wrong_issuer_id,
            retained_keysets: trusted_keysets.retained_keysets,
            now_unix: trusted_keysets.now_unix,
        };
        assert!(verify_redeem_response_for_exact_request(
            &response,
            &request,
            &fixture.authorization,
            &fixture.issuer.verifying_key(),
            &wrong_issuer_keysets,
            &TestDleqVerifier,
        )
        .is_err());
        let auth = ProviderClearingRequestAuthV1::sign(
            request.authorization_digest,
            request.request_digest().expect("request digest"),
            &fixture.clearing,
        );
        let retained = retained_keysets(&fixture);
        let crypto = RedeemResponseCryptoExpectationV1 {
            retained_keysets: &retained,
            dleq_verifier: &TestDleqVerifier,
        };
        verify_new_redeem_response_for(
            &response,
            &request,
            &fixture.authorization,
            &fixture.approval,
            &auth,
            &expectation(&fixture),
            &crypto,
        )
        .expect("composite response");

        let mut changed = response.clone();
        if let RedeemSettlementResultV1::BlindOutputs { signatures, .. } = &mut changed.result {
            signatures[0].blinded_message = point(23);
        }
        assert!(verify_redeem_response_for_exact_request(
            &changed,
            &request,
            &fixture.authorization,
            &fixture.issuer.verifying_key(),
            &retained_keysets(&fixture),
            &TestDleqVerifier,
        )
        .is_err());

        let mut invalid_scalar = response.clone();
        if let RedeemSettlementResultV1::BlindOutputs { signatures, .. } =
            &mut invalid_scalar.result
        {
            signatures[0].dleq_e = [0; 32];
        }
        assert!(invalid_scalar.encode().is_err());

        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            ProviderRedeemResponseV1::decode(&trailing),
            Err(ServiceProtocolError::TrailingBytes(1))
        ));

        // PoC regression: a valid outer issuer signature and canonical fake
        // scalar/point tuple is not enough without authoritative NUT-12.
        let mut fake_dleq = response.clone();
        if let RedeemSettlementResultV1::BlindOutputs { signatures, .. } = &mut fake_dleq.result {
            signatures[0].dleq_e = scalar(9);
        }
        fake_dleq = ProviderRedeemResponseV1::sign(fake_dleq, &fixture.issuer)
            .expect("issuer-signed structurally canonical fake DLEQ");
        assert!(verify_redeem_response_for_exact_request(
            &fake_dleq,
            &request,
            &fixture.authorization,
            &fixture.issuer.verifying_key(),
            &retained_keysets(&fixture),
            &TestDleqVerifier,
        )
        .is_err());
        assert!(verify_redeem_response_for_exact_request(
            &response,
            &request,
            &fixture.authorization,
            &fixture.issuer.verifying_key(),
            &retained_keysets_at(&fixture, 4_000),
            &TestDleqVerifier,
        )
        .is_err());
    }

    fn deposit_request(_fixture: &Fixture) -> ProviderSettlementDepositRequestV1 {
        let keyset_id = keyset().keyset_id;
        ProviderSettlementDepositRequestV1 {
            registration_digest: REGISTRATION_DIGEST,
            issuer_id: [6; 32],
            provider_id: [5; 32],
            account_id: [17; 32],
            unit: SettlementUnitV1::AuthCredit,
            settlement_keyset_id: keyset_id.clone(),
            notes: vec![
                SettlementNoteV1::new(&keyset_id, 1, "secret-a".into(), point(61), None)
                    .expect("note"),
                SettlementNoteV1::new(
                    &keyset_id,
                    8,
                    "secret-b".into(),
                    point(62),
                    Some("witness-b".into()),
                )
                .expect("note"),
            ],
            total_value: 9,
            idempotency_key: [18; 32],
        }
    }

    #[test]
    fn cashu_settlement_bearers_are_redacted_from_debug() {
        let fixture = fixture();
        let request = deposit_request(&fixture);
        let request_debug = format!("{request:?}");
        assert!(request_debug.contains("note_count: 2"));
        for forbidden in ["secret-a", "secret-b", "witness-b"] {
            assert!(!request_debug.contains(forbidden));
        }

        let note_debug = format!("{:?}", request.notes[1]);
        assert!(note_debug.contains("[REDACTED]"));
        assert!(!note_debug.contains("secret-b"));
        assert!(!note_debug.contains("witness-b"));

        let signature = point(62);
        let input = CashuSettlementNoteVerificationInputV1 {
            denomination: 8,
            denomination_public_key: &signature,
            secret: "verification-secret-sentinel",
            signature: &signature,
            witness: Some("verification-witness-sentinel"),
        };
        let input_debug = format!("{input:?}");
        assert!(!input_debug.contains("verification-secret-sentinel"));
        assert!(!input_debug.contains("verification-witness-sentinel"));

        let verified = VerifiedSettlementNoteV1 {
            denomination: 8,
            denomination_public_key: [0x71; 33],
            authoritative_y: [0x72; 33],
            spend_key: [0x73; 32],
            presentation_digest: [0x74; 32],
        };
        let verified_debug = format!("{verified:?}");
        assert!(verified_debug.contains("denomination: 8"));
        assert!(verified_debug.contains("[REDACTED]"));
        for forbidden in ["113, 113", "114, 114", "115, 115", "116, 116"] {
            assert!(!verified_debug.contains(forbidden));
        }
    }

    #[test]
    fn deposit_is_one_exact_keyset_sorted_and_bound_to_fixed_account() {
        let fixture = fixture();
        let request = deposit_request(&fixture);
        let bytes = request.encode().expect("encode");
        assert_eq!(
            ProviderSettlementDepositRequestV1::decode(&bytes).expect("decode"),
            request
        );
        let request_auth = ProviderSettlementRequestAuthV1::sign(
            request.registration_digest,
            request.request_digest().expect("request digest"),
            &fixture.registration_request,
        );
        assert_eq!(
            ProviderSettlementRequestAuthV1::decode(
                &request_auth.encode().expect("registration auth encode")
            )
            .expect("registration auth decode"),
            request_auth
        );
        let verified = verify_new_settlement_deposit_request_for(
            &request,
            &request_auth,
            &registration(&fixture),
            &retained_keysets(&fixture),
            &TestNoteVerifier,
        )
        .expect("new deposit");
        assert_eq!(verified.notes().len(), 2);
        assert_ne!(
            verified.notes()[0].spend_key(),
            verified.notes()[1].spend_key()
        );

        // A byte-for-byte valid keyset registry from another issuer lineage
        // cannot authenticate or credit this provider's deposit.
        let trusted_keysets = retained_keysets(&fixture);
        let wrong_issuer_id = [99; 32];
        let wrong_issuer_keysets = RetainedSettlementKeysetExpectationV1 {
            issuer_id: &wrong_issuer_id,
            retained_keysets: trusted_keysets.retained_keysets,
            now_unix: trusted_keysets.now_unix,
        };
        assert!(verify_new_settlement_deposit_request_for(
            &request,
            &request_auth,
            &registration(&fixture),
            &wrong_issuer_keysets,
            &TestNoteVerifier,
        )
        .is_err());

        let response = ProviderSettlementDepositResponseV1::sign(
            ProviderSettlementDepositResponseV1 {
                issuer_settlement_key_id: [0; 16],
                request_digest: request.request_digest().expect("request digest"),
                registration_digest: request.registration_digest,
                issuer_id: request.issuer_id,
                provider_id: request.provider_id,
                account_id: request.account_id,
                unit: request.unit,
                settlement_keyset_id: request.settlement_keyset_id.clone(),
                total_value: request.total_value,
                ledger_transaction_id: [21; 32],
                ledger_sequence: 7,
                signature: [0; 64],
            },
            &fixture.issuer,
        )
        .expect("deposit response");
        verify_new_settlement_deposit_response_for(
            &response,
            &request,
            &request_auth,
            &registration(&fixture),
            &retained_keysets(&fixture),
            &TestNoteVerifier,
        )
        .expect("deposit response verification");
        assert_eq!(
            ProviderSettlementDepositResponseV1::decode(
                &response.encode().expect("response bytes")
            )
            .expect("response decode"),
            response
        );

        let mut wrong_account = request.clone();
        wrong_account.account_id[0] ^= 1;
        let wrong_auth = ProviderSettlementRequestAuthV1::sign(
            wrong_account.registration_digest,
            wrong_account.request_digest().expect("request digest"),
            &fixture.registration_request,
        );
        assert!(verify_new_settlement_deposit_request_for(
            &wrong_account,
            &wrong_auth,
            &registration(&fixture),
            &retained_keysets(&fixture),
            &TestNoteVerifier,
        )
        .is_err());

        let attacker_registration_key = SigningKey::from_bytes(&[91; 32]);
        let forged_auth = ProviderSettlementRequestAuthV1::sign(
            request.registration_digest,
            request
                .request_digest()
                .expect("forged auth request digest"),
            &attacker_registration_key,
        );
        assert!(verify_new_settlement_deposit_request_for(
            &request,
            &forged_auth,
            &registration(&fixture),
            &retained_keysets(&fixture),
            &TestNoteVerifier,
        )
        .is_err());

        let mut wrong_total = request.clone();
        wrong_total.total_value = 8;
        assert!(wrong_total.encode().is_err());
        let mut wrong_digest = request;
        wrong_digest.notes[0].presentation_digest[0] ^= 1;
        assert!(wrong_digest.encode().is_err());

        // PoC regression: any canonical curve point used to pass the protocol
        // layer as if it were an authentic Cashu note.
        let mut arbitrary_point = deposit_request(&fixture);
        arbitrary_point.notes[0] = SettlementNoteV1::new(
            &arbitrary_point.settlement_keyset_id,
            1,
            "secret-a".into(),
            point(99),
            None,
        )
        .expect("structurally canonical arbitrary point");
        let arbitrary_auth = ProviderSettlementRequestAuthV1::sign(
            arbitrary_point.registration_digest,
            arbitrary_point.request_digest().expect("arbitrary digest"),
            &fixture.registration_request,
        );
        assert!(verify_new_settlement_deposit_request_for(
            &arbitrary_point,
            &arbitrary_auth,
            &registration(&fixture),
            &retained_keysets(&fixture),
            &TestNoteVerifier,
        )
        .is_err());

        // Recovery uses a current provider registration and retained keyset,
        // not the old clearing authorization which expired at t=200.
        let recovery_request = deposit_request(&fixture);
        let recovery_auth = ProviderSettlementRequestAuthV1::sign(
            recovery_request.registration_digest,
            recovery_request.request_digest().expect("recovery digest"),
            &fixture.registration_request,
        );
        verify_new_settlement_deposit_request_for(
            &recovery_request,
            &recovery_auth,
            &registration_at(&fixture, 300),
            &retained_keysets_at(&fixture, 300),
            &TestNoteVerifier,
        )
        .expect("recovery after debt-authorization expiry");

        assert!(verify_new_settlement_deposit_request_for(
            &recovery_request,
            &recovery_auth,
            &registration(&fixture),
            &retained_keysets(&fixture),
            &DuplicateYNoteVerifier,
        )
        .is_err());

        let expired_registry = retained_keysets_at(&fixture, 4_000);
        assert!(verify_new_settlement_deposit_request_for(
            &recovery_request,
            &recovery_auth,
            &registration_at(&fixture, 4_000),
            &expired_registry,
            &TestNoteVerifier,
        )
        .is_err());
    }

    #[test]
    fn balance_and_payout_protocol_is_canonical_but_moves_no_funds() {
        let fixture = fixture();
        let auth_digest = fixture
            .authorization
            .authorization_digest()
            .expect("authorization digest");
        let balance_request = ProviderBalanceRequestV1 {
            authorization_digest: auth_digest,
            issuer_id: [6; 32],
            provider_id: [5; 32],
            account_id: [17; 32],
            unit: SettlementUnitV1::MilliSatoshi,
            idempotency_key: [31; 32],
        };
        let balance_auth = ProviderClearingRequestAuthV1::sign(
            auth_digest,
            balance_request.request_digest().expect("balance digest"),
            &fixture.clearing,
        );
        let balance = IssuerBalanceResponseV1::sign(
            IssuerBalanceResponseV1 {
                issuer_settlement_key_id: [0; 16],
                request_digest: balance_request.request_digest().expect("balance digest"),
                authorization_digest: auth_digest,
                issuer_id: [6; 32],
                provider_id: [5; 32],
                account_id: [17; 32],
                unit: SettlementUnitV1::MilliSatoshi,
                available_value: 5_000,
                reserved_value: 500,
                ledger_sequence: 8,
                as_of_unix: 150,
                signature: [0; 64],
            },
            &fixture.issuer,
        )
        .expect("balance response");
        verify_new_balance_response_for(
            &balance,
            &balance_request,
            &fixture.authorization,
            &fixture.approval,
            &balance_auth,
            &expectation(&fixture),
        )
        .expect("balance flow");

        let registered_target = [41; 32];
        let intent_request = ProviderPayoutIntentRequestV1 {
            authorization_digest: auth_digest,
            issuer_id: [6; 32],
            provider_id: [5; 32],
            account_id: [17; 32],
            payout_target_id: registered_target,
            unit: SettlementUnitV1::MilliSatoshi,
            payout_value: 1_000,
            idempotency_key: [42; 32],
        };
        let intent_auth = ProviderClearingRequestAuthV1::sign(
            auth_digest,
            intent_request.request_digest().expect("intent digest"),
            &fixture.clearing,
        );
        let intent_response = IssuerPayoutIntentResponseV1::sign(
            IssuerPayoutIntentResponseV1 {
                issuer_settlement_key_id: [0; 16],
                request_digest: intent_request.request_digest().expect("intent digest"),
                authorization_digest: auth_digest,
                issuer_id: [6; 32],
                provider_id: [5; 32],
                account_id: [17; 32],
                payout_target_id: registered_target,
                unit: SettlementUnitV1::MilliSatoshi,
                payout_value: 1_000,
                issuer_fee: 10,
                total_debit: 1_010,
                payout_intent_id: [43; 32],
                expires_at: 180,
                signature: [0; 64],
            },
            &fixture.issuer,
        )
        .expect("intent response");
        verify_new_payout_intent_response_for(
            &intent_response,
            &intent_request,
            &registered_target,
            &fixture.authorization,
            &fixture.approval,
            &intent_auth,
            &expectation(&fixture),
        )
        .expect("intent flow");

        let payout_request = ProviderPayoutRequestV1 {
            authorization_digest: auth_digest,
            issuer_id: [6; 32],
            provider_id: [5; 32],
            account_id: [17; 32],
            payout_target_id: registered_target,
            payout_intent_id: intent_response.payout_intent_id,
            payout_intent_digest: intent_response
                .payout_intent_digest()
                .expect("signed intent digest"),
            unit: SettlementUnitV1::MilliSatoshi,
            payout_value: 1_000,
            total_debit: 1_010,
            idempotency_key: [44; 32],
        };
        let payout_auth = ProviderClearingRequestAuthV1::sign(
            auth_digest,
            payout_request.request_digest().expect("payout digest"),
            &fixture.clearing,
        );
        let payout_context = PayoutExecutionContextV1 {
            intent_request: &intent_request,
            intent_response: &intent_response,
            registered_payout_target_id: &registered_target,
        };
        let first_execution = verify_new_payout_request_for(
            &payout_request,
            &payout_context,
            &fixture.authorization,
            &fixture.approval,
            &payout_auth,
            &expectation(&fixture),
        )
        .expect("verified payout execution");
        let mut execution_store = TestPayoutExecutionStore::default();
        let payout_response = IssuerPayoutResponseV1::sign_and_commit_execution(
            IssuerPayoutResponseV1 {
                issuer_settlement_key_id: [0; 16],
                request_digest: payout_request.request_digest().expect("payout digest"),
                authorization_digest: auth_digest,
                issuer_id: [6; 32],
                provider_id: [5; 32],
                account_id: [17; 32],
                payout_target_id: registered_target,
                payout_intent_id: [43; 32],
                payout_id: [45; 32],
                unit: SettlementUnitV1::MilliSatoshi,
                payout_value: 1_000,
                total_debit: 1_010,
                state: PayoutStateV1::Accepted,
                ledger_transaction_id: [46; 32],
                state_version: 1,
                updated_at: 151,
                signature: [0; 64],
            },
            &first_execution,
            &fixture.issuer,
            &mut execution_store,
        )
        .expect("payout response");
        let initial_snapshot = verify_new_payout_response_for(
            &payout_response,
            &payout_request,
            &payout_context,
            &fixture.authorization,
            &fixture.approval,
            &payout_auth,
            &expectation(&fixture),
        )
        .expect("fake payout flow");

        // Two differently idempotent requests can validly reference the same
        // signed intent. Both typestates expose the same mandatory UNIQUE
        // payout_intent_id, which the issuer store must consume atomically.
        let replay_request = ProviderPayoutRequestV1 {
            idempotency_key: [54; 32],
            ..payout_request.clone()
        };
        let replay_auth = ProviderClearingRequestAuthV1::sign(
            auth_digest,
            replay_request
                .request_digest()
                .expect("replay payout digest"),
            &fixture.clearing,
        );
        let replay_execution = verify_new_payout_request_for(
            &replay_request,
            &payout_context,
            &fixture.authorization,
            &fixture.approval,
            &replay_auth,
            &expectation(&fixture),
        )
        .expect("second intent consumption candidate");
        assert_ne!(
            payout_request
                .request_digest()
                .expect("first payout digest"),
            replay_request
                .request_digest()
                .expect("replay payout digest")
        );
        assert_eq!(
            first_execution.payout_intent_id(),
            replay_execution.payout_intent_id()
        );
        let replay_response = IssuerPayoutResponseV1 {
            request_digest: replay_request
                .request_digest()
                .expect("replay payout digest"),
            signature: [0; 64],
            ..payout_response.clone()
        };
        assert!(matches!(
            IssuerPayoutResponseV1::sign_and_commit_execution(
                replay_response,
                &replay_execution,
                &fixture.issuer,
                &mut execution_store,
            ),
            Err(PayoutCommitErrorV1::Conflict {
                operation: "payout_intent_consume"
            })
        ));

        let status_request = ProviderPayoutStatusRequestV1 {
            registration_digest: REGISTRATION_DIGEST,
            issuer_id: [6; 32],
            provider_id: [5; 32],
            account_id: [17; 32],
            payout_id: payout_response.payout_id,
            payout_request_digest: payout_request.request_digest().expect("payout digest"),
            request_nonce: [47; 32],
        };
        let status_auth = ProviderSettlementRequestAuthV1::sign(
            REGISTRATION_DIGEST,
            status_request.request_digest().expect("status digest"),
            &fixture.registration_request,
        );
        // Rotate the issuer settlement key after the initial response. The
        // current registration and new status use the rotated key, while the
        // exact initial response remains recoverable through the retained key.
        let rotated_issuer = SigningKey::from_bytes(&[77; 32]);
        let rotated_issuer_key = rotated_issuer.verifying_key();
        let retained_issuer_keys = [fixture.issuer_key];
        let rotated_keyring = IssuerSettlementKeyringExpectationV1 {
            issuer_id: &fixture.authorization.claims.issuer_id,
            current_key: &rotated_issuer_key,
            retained_keys: &retained_issuer_keys,
        };
        let rotated_registration = ProviderSettlementRegistrationExpectationV1 {
            registration_digest: &REGISTRATION_DIGEST,
            provider_id: &fixture.authorization.claims.provider_id,
            issuer_id: &fixture.authorization.claims.issuer_id,
            settlement_account_id: &fixture.authorization.claims.settlement_account_id,
            provider_request_key: &fixture.registration_request_key,
            issuer_settlement_key: &rotated_issuer_key,
            not_before: 100,
            not_after: 10_000,
            now_unix: 300,
        };
        let mut status_store = TestPayoutStatusStore::from_snapshot(&initial_snapshot);
        let status = IssuerPayoutStatusResponseV1::sign_and_commit_successor(
            IssuerPayoutStatusResponseV1 {
                issuer_settlement_key_id: [0; 16],
                request_digest: status_request.request_digest().expect("status digest"),
                registration_digest: REGISTRATION_DIGEST,
                issuer_id: [6; 32],
                provider_id: [5; 32],
                account_id: [17; 32],
                payout_id: [45; 32],
                payout_request_digest: payout_request.request_digest().expect("payout digest"),
                payout_target_id: registered_target,
                unit: SettlementUnitV1::MilliSatoshi,
                payout_value: 1_000,
                total_debit: 1_010,
                state: PayoutStateV1::InFlight,
                ledger_transaction_id: [46; 32],
                state_version: 2,
                updated_at: 160,
                signature: [0; 64],
            },
            &initial_snapshot,
            &rotated_issuer,
            &mut status_store,
        )
        .expect("status response");
        let mut skipped_version_store = TestPayoutStatusStore::from_snapshot(&initial_snapshot);
        assert!(matches!(
            IssuerPayoutStatusResponseV1::sign_and_commit_successor(
                IssuerPayoutStatusResponseV1 {
                    state_version: 3,
                    updated_at: 161,
                    signature: [0; 64],
                    ..status.clone()
                },
                &initial_snapshot,
                &rotated_issuer,
                &mut skipped_version_store,
            ),
            Err(PayoutCommitErrorV1::Protocol(
                ServiceProtocolError::InvalidValue {
                    field: "IssuerPayoutStatusResponseV1.state_version",
                    ..
                }
            ))
        ));
        let payout_status_context = PayoutStatusContextV1 {
            payout_request: &payout_request,
            initial_payout_response: &payout_response,
        };
        assert_ne!(
            payout_response.issuer_settlement_key_id,
            status.issuer_settlement_key_id
        );
        let missing_retained_keyring = IssuerSettlementKeyringExpectationV1 {
            issuer_id: &fixture.authorization.claims.issuer_id,
            current_key: &rotated_issuer_key,
            retained_keys: &[],
        };
        assert!(verify_new_payout_status_request_for(
            &status_request,
            &payout_status_context,
            &status_auth,
            &rotated_registration,
            &missing_retained_keyring,
        )
        .is_err());
        let wrong_issuer_id = [98; 32];
        let wrong_issuer_keyring = IssuerSettlementKeyringExpectationV1 {
            issuer_id: &wrong_issuer_id,
            current_key: &rotated_issuer_key,
            retained_keys: &retained_issuer_keys,
        };
        assert!(verify_new_payout_status_request_for(
            &status_request,
            &payout_status_context,
            &status_auth,
            &rotated_registration,
            &wrong_issuer_keyring,
        )
        .is_err());
        let in_flight_snapshot = verify_new_payout_status_response_for(
            &status,
            &status_request,
            &payout_status_context,
            &initial_snapshot,
            &status_auth,
            &rotated_registration,
            &rotated_keyring,
        )
        .expect("status recovery after original clearing authorization expired");

        let succeeded_request = ProviderPayoutStatusRequestV1 {
            request_nonce: [48; 32],
            ..status_request.clone()
        };
        let succeeded_auth = ProviderSettlementRequestAuthV1::sign(
            REGISTRATION_DIGEST,
            succeeded_request
                .request_digest()
                .expect("succeeded status digest"),
            &fixture.registration_request,
        );
        let succeeded = IssuerPayoutStatusResponseV1::sign_and_commit_successor(
            IssuerPayoutStatusResponseV1 {
                request_digest: succeeded_request
                    .request_digest()
                    .expect("succeeded status digest"),
                state: PayoutStateV1::Succeeded,
                state_version: 3,
                updated_at: 170,
                signature: [0; 64],
                ..status.clone()
            },
            &in_flight_snapshot,
            &rotated_issuer,
            &mut status_store,
        )
        .expect("succeeded status response");
        let succeeded_snapshot = verify_new_payout_status_response_for(
            &succeeded,
            &succeeded_request,
            &payout_status_context,
            &in_flight_snapshot,
            &succeeded_auth,
            &rotated_registration,
            &rotated_keyring,
        )
        .expect("monotonic terminal status");

        // Two workers can both construct a valid successor from version 2,
        // but the exact predecessor CAS permits only one durable terminal
        // result. The losing signed value is never returned to the caller.
        let competing_failed = IssuerPayoutStatusResponseV1 {
            request_digest: [88; 32],
            state: PayoutStateV1::Failed,
            state_version: 3,
            updated_at: 171,
            signature: [0; 64],
            ..status.clone()
        };
        assert!(matches!(
            IssuerPayoutStatusResponseV1::sign_and_commit_successor(
                competing_failed,
                &in_flight_snapshot,
                &rotated_issuer,
                &mut status_store,
            ),
            Err(PayoutCommitErrorV1::Conflict {
                operation: "payout_status_compare_and_swap"
            })
        ));

        // Exact stale snapshots and terminal rollback are rejected even when
        // every issuer signature is otherwise valid.
        assert!(verify_new_payout_status_response_for(
            &succeeded,
            &succeeded_request,
            &payout_status_context,
            &succeeded_snapshot,
            &succeeded_auth,
            &rotated_registration,
            &rotated_keyring,
        )
        .is_err());
        let rollback_request = ProviderPayoutStatusRequestV1 {
            request_nonce: [49; 32],
            ..status_request.clone()
        };
        let rollback_auth = ProviderSettlementRequestAuthV1::sign(
            REGISTRATION_DIGEST,
            rollback_request.request_digest().expect("rollback digest"),
            &fixture.registration_request,
        );
        let rollback_unsigned = IssuerPayoutStatusResponseV1 {
            request_digest: rollback_request.request_digest().expect("rollback digest"),
            state: PayoutStateV1::InFlight,
            state_version: 4,
            updated_at: 180,
            signature: [0; 64],
            ..status.clone()
        };
        assert!(IssuerPayoutStatusResponseV1::sign_and_commit_successor(
            rollback_unsigned.clone(),
            &succeeded_snapshot,
            &rotated_issuer,
            &mut status_store,
        )
        .is_err());
        let rollback =
            IssuerPayoutStatusResponseV1::sign_structural(rollback_unsigned, &rotated_issuer)
                .expect("issuer-signed rollback fixture");
        assert!(verify_new_payout_status_response_for(
            &rollback,
            &rollback_request,
            &payout_status_context,
            &succeeded_snapshot,
            &rollback_auth,
            &rotated_registration,
            &rotated_keyring,
        )
        .is_err());

        // A valid registration signature cannot substitute another payout ID;
        // the initial issuer response is part of the required context.
        let substituted = ProviderPayoutStatusRequestV1 {
            payout_id: [99; 32],
            request_nonce: [50; 32],
            ..status_request.clone()
        };
        let substituted_auth = ProviderSettlementRequestAuthV1::sign(
            REGISTRATION_DIGEST,
            substituted.request_digest().expect("substitution digest"),
            &fixture.registration_request,
        );
        assert!(verify_new_payout_status_request_for(
            &substituted,
            &payout_status_context,
            &substituted_auth,
            &rotated_registration,
            &rotated_keyring,
        )
        .is_err());

        assert_ne!(
            intent_request.request_digest().expect("intent digest"),
            payout_request.request_digest().expect("payout digest")
        );
        assert_ne!(
            payout_request.request_digest().expect("payout digest"),
            status_request.request_digest().expect("status digest")
        );

        let mut attacker_target = intent_request;
        attacker_target.payout_target_id = [99; 32];
        let attacker_auth = ProviderClearingRequestAuthV1::sign(
            auth_digest,
            attacker_target
                .request_digest()
                .expect("attacker request digest"),
            &fixture.clearing,
        );
        assert!(verify_new_payout_intent_request_for(
            &attacker_target,
            &registered_target,
            &fixture.authorization,
            &fixture.approval,
            &attacker_auth,
            &expectation(&fixture),
        )
        .is_err());

        assert_eq!(
            IssuerPayoutStatusResponseV1::decode(&succeeded.encode().expect("status bytes"))
                .expect("status decode"),
            succeeded
        );
    }

    #[test]
    fn clearing_request_cannot_self_authorize_settlement_endpoints() {
        let fixture = fixture();
        let request = ProviderBalanceRequestV1 {
            authorization_digest: fixture
                .authorization
                .authorization_digest()
                .expect("authorization digest"),
            issuer_id: [6; 32],
            provider_id: [5; 32],
            account_id: [17; 32],
            unit: SettlementUnitV1::AuthCredit,
            idempotency_key: [71; 32],
        };
        let attacker_operator = SigningKey::from_bytes(&[72; 32]);
        let attacker_clearing = SigningKey::from_bytes(&[73; 32]);
        let forged = ProviderClearingAuthorizationV1::sign(
            ProviderClearingAuthorizationClaimsV1 {
                clearing_verifying_key: attacker_clearing.verifying_key().to_bytes(),
                ..fixture.authorization.claims.clone()
            },
            &attacker_operator,
        )
        .expect("forged authorization");
        let forged_request = ProviderBalanceRequestV1 {
            authorization_digest: forged.authorization_digest().expect("forged digest"),
            ..request
        };
        let forged_auth = ProviderClearingRequestAuthV1::sign(
            forged_request.authorization_digest,
            forged_request.request_digest().expect("request digest"),
            &attacker_clearing,
        );
        let forged_approval = IssuerClearingApprovalV1::sign(&forged, 100, 200, &fixture.issuer)
            .expect("forged approval fixture");
        assert!(verify_new_balance_request_for(
            &forged_request,
            &forged,
            &forged_approval,
            &forged_auth,
            &expectation(&fixture),
        )
        .is_err());
    }
}
