//! Operator-authorized provider clearing identity and settlement rules.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::codec::{expect_v1, put_bytes_u16, put_bytes_u32, Decoder};
use crate::{
    is_canonical_cashu_keyset_id_v2, AuthScheme, CashuKeysetBindingV1, CredentialKeyBindingV1,
    CredentialUnitV1, ProviderId, ScopeId, ServiceProtocolError, MAX_CASHU_KEYSET_ENCODING_LEN,
    MAX_SERVICE_VALUE_V1, SERVICE_PROTOCOL_VERSION,
};

pub const MAX_SETTLEMENT_RULES: usize = 64;
pub const CLEARING_AUTH_SIGNATURE_DOMAIN: &[u8] =
    b"BitcoinPIR/provider-clearing-authorization-signature/v1";
pub const CLEARING_AUTH_DIGEST_DOMAIN: &[u8] =
    b"BitcoinPIR/provider-clearing-authorization-digest/v1";
pub const CLEARING_REQUEST_SIGNATURE_DOMAIN: &[u8] =
    b"BitcoinPIR/provider-clearing-request-signature/v1";
pub const ISSUER_CLEARING_APPROVAL_SIGNATURE_DOMAIN: &[u8] =
    b"BitcoinPIR/issuer-clearing-approval-signature/v1";
pub const ISSUER_SETTLEMENT_KEY_ID_DOMAIN: &[u8] = b"BitcoinPIR/issuer-settlement-key-id/v1";
pub const PROVIDER_REDEEM_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"BitcoinPIR/provider-redeem-request/POST-/v1/redeems/v1";
pub const CREDENTIAL_PRESENTATION_DIGEST_DOMAIN: &[u8] =
    b"BitcoinPIR/credential-presentation-digest/v1";
pub const MAX_SETTLEMENT_OUTPUTS: usize = 64;
pub const MAX_SETTLEMENT_DENOMINATIONS: usize = 32;
pub const MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1: usize = 64 * 1024;
pub const MAX_PROVIDER_REDEEM_CREDENTIAL_LEN_V1: usize = 12 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SettlementUnitV1 {
    MilliSatoshi = 1,
    Satoshi = 2,
    AuthCredit = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementModesV1(u8);

impl SettlementModesV1 {
    pub const LEDGER_CREDIT: u8 = 1 << 0;
    pub const BLIND_OUTPUTS: u8 = 1 << 1;
    pub const KNOWN_MASK: u8 = Self::LEDGER_CREDIT | Self::BLIND_OUTPUTS;

    pub fn from_bits(bits: u8) -> Result<Self, ServiceProtocolError> {
        if bits == 0 || bits & !Self::KNOWN_MASK != 0 {
            Err(ServiceProtocolError::InvalidValue {
                field: "SettlementModesV1",
                reason: "must select at least one known settlement mode",
            })
        } else {
            Ok(Self(bits))
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn allows(self, mode: u8) -> bool {
        self.0 & mode == mode
    }
}

impl SettlementUnitV1 {
    pub(crate) fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::MilliSatoshi),
            2 => Ok(Self::Satoshi),
            3 => Ok(Self::AuthCredit),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "SettlementUnitV1",
                value,
            }),
        }
    }

    pub(crate) const fn cashu_unit(self) -> &'static str {
        match self {
            Self::MilliSatoshi => "msat",
            Self::Satoshi => "sat",
            Self::AuthCredit => "auth",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementRuleV1 {
    pub credential_binding_digest: [u8; 32],
    pub unit: SettlementUnitV1,
    pub accepted_value: u64,
    pub provider_credit: u64,
    pub issuer_fee: u64,
    pub denomination_profile: u32,
    pub settlement_modes: SettlementModesV1,
    /// Minimum time after clearing authorization expiry during which blind
    /// settlement notes remain redeemable. Zero exactly when blind settlement
    /// is disabled.
    pub blind_output_minimum_validity_seconds: u32,
    /// Exact issuer keyset for blind settlement. The issuer countersignature
    /// commits to its unit, fees, expiry, denominations, and public keys.
    pub blind_output_keyset: Option<CashuKeysetBindingV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderClearingAuthorizationClaimsV1 {
    pub authorization_id: [u8; 16],
    pub authorization_epoch: u64,
    pub provider_id: ProviderId,
    pub issuer_id: [u8; 32],
    /// Issuer-registered destination for identified ledger credit. Requests
    /// cannot redirect funds to a different account.
    pub settlement_account_id: [u8; 32],
    pub clearing_verifying_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub rules: Vec<SettlementRuleV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderClearingAuthorizationV1 {
    pub operator_verifying_key: [u8; 32],
    pub claims: ProviderClearingAuthorizationClaimsV1,
    pub signature: [u8; 64],
}

impl ProviderClearingAuthorizationV1 {
    pub fn sign(
        claims: ProviderClearingAuthorizationClaimsV1,
        operator_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let mut value = Self {
            operator_verifying_key: operator_signing_key.verifying_key().to_bytes(),
            claims,
            signature: [0; 64],
        };
        value.validate_claims()?;
        value.signature = operator_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    pub fn verify_for(
        &self,
        expected_provider_id: &ProviderId,
        expected_issuer_id: &[u8; 32],
        expected_operator_key: &VerifyingKey,
        now_unix: u64,
        minimum_authorization_epoch: u64,
    ) -> Result<(), ServiceProtocolError> {
        self.validate_claims()?;
        if &self.claims.provider_id != expected_provider_id
            || &self.claims.issuer_id != expected_issuer_id
            || self.operator_verifying_key != expected_operator_key.to_bytes()
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderClearingAuthorizationV1.audience",
                reason: "provider, issuer, or operator does not match registration",
            });
        }
        if self.claims.authorization_epoch < minimum_authorization_epoch {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderClearingAuthorizationV1.authorization_epoch",
                reason: "clearing authorization rollback",
            });
        }
        if now_unix < self.claims.not_before || now_unix > self.claims.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderClearingAuthorizationV1.validity",
                reason: "clearing authorization is not currently valid",
            });
        }
        expected_operator_key
            .verify_strict(
                &self.signing_preimage()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ServiceProtocolError::BadSignature)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("ProviderClearingAuthorizationV1.version")?;
        expect_v1(version, "ProviderClearingAuthorizationV1")?;
        let operator_verifying_key =
            decoder.fixed("ProviderClearingAuthorizationV1.operator_verifying_key")?;
        let authorization_id = decoder.fixed("ProviderClearingAuthorizationV1.authorization_id")?;
        let authorization_epoch =
            decoder.u64("ProviderClearingAuthorizationV1.authorization_epoch")?;
        let provider_id = decoder.fixed("ProviderClearingAuthorizationV1.provider_id")?;
        let issuer_id = decoder.fixed("ProviderClearingAuthorizationV1.issuer_id")?;
        let settlement_account_id =
            decoder.fixed("ProviderClearingAuthorizationV1.settlement_account_id")?;
        let clearing_verifying_key =
            decoder.fixed("ProviderClearingAuthorizationV1.clearing_verifying_key")?;
        let not_before = decoder.u64("ProviderClearingAuthorizationV1.not_before")?;
        let not_after = decoder.u64("ProviderClearingAuthorizationV1.not_after")?;
        let rule_count = decoder.u8("ProviderClearingAuthorizationV1.rule_count")? as usize;
        if rule_count > MAX_SETTLEMENT_RULES {
            return Err(ServiceProtocolError::TooManyItems {
                field: "ProviderClearingAuthorizationV1.rules",
                len: rule_count,
                max: MAX_SETTLEMENT_RULES,
            });
        }
        let mut rules = Vec::with_capacity(rule_count);
        for _ in 0..rule_count {
            let credential_binding_digest =
                decoder.fixed("SettlementRuleV1.credential_binding_digest")?;
            let unit = SettlementUnitV1::decode(decoder.u8("SettlementRuleV1.unit")?)?;
            let accepted_value = decoder.u64("SettlementRuleV1.accepted_value")?;
            let provider_credit = decoder.u64("SettlementRuleV1.provider_credit")?;
            let issuer_fee = decoder.u64("SettlementRuleV1.issuer_fee")?;
            let denomination_profile = decoder.u32("SettlementRuleV1.denomination_profile")?;
            let settlement_modes =
                SettlementModesV1::from_bits(decoder.u8("SettlementRuleV1.settlement_modes")?)?;
            let blind_output_minimum_validity_seconds =
                decoder.u32("SettlementRuleV1.blind_output_minimum_validity_seconds")?;
            let blind_output_keyset = match decoder.u8("SettlementRuleV1.has_blind_keyset")? {
                0 => None,
                1 => Some(CashuKeysetBindingV1::decode(&decoder.bytes_u16(
                    "SettlementRuleV1.blind_output_keyset",
                    MAX_CASHU_KEYSET_ENCODING_LEN,
                )?)?),
                value => {
                    return Err(ServiceProtocolError::UnknownDiscriminant {
                        kind: "SettlementRuleV1.has_blind_keyset",
                        value,
                    })
                }
            };
            rules.push(SettlementRuleV1 {
                credential_binding_digest,
                unit,
                accepted_value,
                provider_credit,
                issuer_fee,
                denomination_profile,
                settlement_modes,
                blind_output_minimum_validity_seconds,
                blind_output_keyset,
            });
        }
        let value = Self {
            operator_verifying_key,
            claims: ProviderClearingAuthorizationClaimsV1 {
                authorization_id,
                authorization_epoch,
                provider_id,
                issuer_id,
                settlement_account_id,
                clearing_verifying_key,
                not_before,
                not_after,
                rules,
            },
            signature: decoder.fixed("ProviderClearingAuthorizationV1.signature")?,
        };
        decoder.finish()?;
        value.validate_claims()?;
        Ok(value)
    }

    pub fn authorization_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(CLEARING_AUTH_DIGEST_DOMAIN);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    pub fn rule_for_binding(&self, digest: &[u8; 32]) -> Option<&SettlementRuleV1> {
        self.claims
            .rules
            .iter()
            .find(|rule| &rule.credential_binding_digest == digest)
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut out = Vec::with_capacity(CLEARING_AUTH_SIGNATURE_DOMAIN.len() + unsigned.len());
        out.extend_from_slice(CLEARING_AUTH_SIGNATURE_DOMAIN);
        out.extend_from_slice(&unsigned);
        Ok(out)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate_claims()?;
        let claims = &self.claims;
        let mut out = Vec::with_capacity(256 + claims.rules.len() * 69);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.operator_verifying_key);
        out.extend_from_slice(&claims.authorization_id);
        out.extend_from_slice(&claims.authorization_epoch.to_le_bytes());
        out.extend_from_slice(&claims.provider_id);
        out.extend_from_slice(&claims.issuer_id);
        out.extend_from_slice(&claims.settlement_account_id);
        out.extend_from_slice(&claims.clearing_verifying_key);
        out.extend_from_slice(&claims.not_before.to_le_bytes());
        out.extend_from_slice(&claims.not_after.to_le_bytes());
        out.push(claims.rules.len() as u8);
        for rule in &claims.rules {
            out.extend_from_slice(&rule.credential_binding_digest);
            out.push(rule.unit as u8);
            out.extend_from_slice(&rule.accepted_value.to_le_bytes());
            out.extend_from_slice(&rule.provider_credit.to_le_bytes());
            out.extend_from_slice(&rule.issuer_fee.to_le_bytes());
            out.extend_from_slice(&rule.denomination_profile.to_le_bytes());
            out.push(rule.settlement_modes.bits());
            out.extend_from_slice(&rule.blind_output_minimum_validity_seconds.to_le_bytes());
            match &rule.blind_output_keyset {
                None => out.push(0),
                Some(keyset) => {
                    out.push(1);
                    put_bytes_u16(&mut out, &keyset.encode()?);
                }
            }
        }
        Ok(out)
    }

    fn validate_claims(&self) -> Result<(), ServiceProtocolError> {
        let claims = &self.claims;
        if claims.authorization_id.iter().all(|byte| *byte == 0)
            || claims.authorization_epoch == 0
            || claims.provider_id.iter().all(|byte| *byte == 0)
            || claims.issuer_id.iter().all(|byte| *byte == 0)
            || claims.settlement_account_id.iter().all(|byte| *byte == 0)
            || claims.rules.is_empty()
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderClearingAuthorizationV1.claims",
                reason: "authorization, audience, epoch, and rules must be non-zero",
            });
        }
        if claims.not_before > claims.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderClearingAuthorizationV1.validity",
                reason: "not_before is after not_after",
            });
        }
        if claims.rules.len() > MAX_SETTLEMENT_RULES {
            return Err(ServiceProtocolError::TooManyItems {
                field: "ProviderClearingAuthorizationV1.rules",
                len: claims.rules.len(),
                max: MAX_SETTLEMENT_RULES,
            });
        }
        VerifyingKey::from_bytes(&self.operator_verifying_key)
            .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        VerifyingKey::from_bytes(&claims.clearing_verifying_key)
            .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        let mut bindings = HashSet::with_capacity(claims.rules.len());
        for rule in &claims.rules {
            let blind_allowed = rule
                .settlement_modes
                .allows(SettlementModesV1::BLIND_OUTPUTS);
            let blind_keyset_present = rule.blind_output_keyset.is_some();
            if rule.credential_binding_digest.iter().all(|byte| *byte == 0)
                || rule.accepted_value == 0
                || rule.accepted_value > MAX_SERVICE_VALUE_V1
                || rule.provider_credit == 0
                || rule.provider_credit > MAX_SERVICE_VALUE_V1
                || rule.issuer_fee > MAX_SERVICE_VALUE_V1
                || rule.denomination_profile == 0
                || rule.provider_credit.checked_add(rule.issuer_fee) != Some(rule.accepted_value)
                || !bindings.insert(rule.credential_binding_digest)
                || blind_allowed != blind_keyset_present
                || blind_allowed != (rule.blind_output_minimum_validity_seconds != 0)
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "SettlementRuleV1",
                    reason: "invalid/duplicate binding or non-conserving settlement value",
                });
            }
            if let Some(keyset) = &rule.blind_output_keyset {
                keyset.validate()?;
                let required_expiry = claims
                    .not_after
                    .checked_add(rule.blind_output_minimum_validity_seconds as u64)
                    .ok_or(ServiceProtocolError::InvalidValue {
                        field: "SettlementRuleV1.blind_output_keyset.final_expiry",
                        reason: "blind settlement validity horizon overflow",
                    })?;
                if keyset.unit != rule.unit.cashu_unit()
                    || keyset.input_fee_ppk != 0
                    || keyset.keys.len() > MAX_SETTLEMENT_DENOMINATIONS
                    || keyset
                        .final_expiry
                        .is_some_and(|expiry| expiry < required_expiry)
                {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "SettlementRuleV1.blind_output_keyset",
                        reason: "keyset unit, fee, size, or validity is not acceptable",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Issuer countersignature over the exact operator authorization and its
/// settlement rules. The issuer MUST persist the highest accepted epoch and
/// this approval; an operator signature alone never creates issuer debt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerClearingApprovalV1 {
    pub issuer_settlement_key_id: [u8; 16],
    pub authorization_digest: [u8; 32],
    pub authorization_epoch: u64,
    pub approved_at: u64,
    pub not_after: u64,
    pub signature: [u8; 64],
}

impl IssuerClearingApprovalV1 {
    pub fn sign(
        authorization: &ProviderClearingAuthorizationV1,
        approved_at: u64,
        not_after: u64,
        issuer_settlement_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        if approved_at > not_after || not_after > authorization.claims.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerClearingApprovalV1.validity",
                reason: "approval validity is empty or outlives operator authorization",
            });
        }
        let mut value = Self {
            issuer_settlement_key_id: issuer_settlement_key_id(
                &issuer_settlement_signing_key.verifying_key(),
            ),
            authorization_digest: authorization.authorization_digest()?,
            authorization_epoch: authorization.claims.authorization_epoch,
            approved_at,
            not_after,
            signature: [0; 64],
        };
        value.signature = issuer_settlement_signing_key
            .sign(&value.signing_preimage())
            .to_bytes();
        Ok(value)
    }

    pub fn verify_for(
        &self,
        authorization: &ProviderClearingAuthorizationV1,
        expected_issuer_settlement_key: &VerifyingKey,
        now_unix: u64,
        minimum_authorization_epoch: u64,
    ) -> Result<(), ServiceProtocolError> {
        if self.issuer_settlement_key_id != issuer_settlement_key_id(expected_issuer_settlement_key)
            || self.authorization_digest != authorization.authorization_digest()?
            || self.authorization_epoch != authorization.claims.authorization_epoch
            || self.authorization_epoch < minimum_authorization_epoch
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerClearingApprovalV1.binding",
                reason: "issuer key, authorization digest, or epoch mismatch",
            });
        }
        if self.approved_at > self.not_after
            || self.not_after > authorization.claims.not_after
            || now_unix < self.approved_at
            || now_unix > self.not_after
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerClearingApprovalV1.validity",
                reason: "issuer approval is not currently valid",
            });
        }
        expected_issuer_settlement_key
            .verify_strict(
                &self.signing_preimage(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ServiceProtocolError::BadSignature)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.encode_unsigned();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("IssuerClearingApprovalV1.version")?,
            "IssuerClearingApprovalV1",
        )?;
        let value = Self {
            issuer_settlement_key_id: decoder
                .fixed("IssuerClearingApprovalV1.issuer_settlement_key_id")?,
            authorization_digest: decoder.fixed("IssuerClearingApprovalV1.authorization_digest")?,
            authorization_epoch: decoder.u64("IssuerClearingApprovalV1.authorization_epoch")?,
            approved_at: decoder.u64("IssuerClearingApprovalV1.approved_at")?,
            not_after: decoder.u64("IssuerClearingApprovalV1.not_after")?,
            signature: decoder.fixed("IssuerClearingApprovalV1.signature")?,
        };
        decoder.finish()?;
        if value.authorization_epoch == 0
            || value.authorization_digest.iter().all(|byte| *byte == 0)
            || value.approved_at > value.not_after
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerClearingApprovalV1",
                reason: "invalid authorization binding or validity",
            });
        }
        Ok(value)
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(73);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.issuer_settlement_key_id);
        out.extend_from_slice(&self.authorization_digest);
        out.extend_from_slice(&self.authorization_epoch.to_le_bytes());
        out.extend_from_slice(&self.approved_at.to_le_bytes());
        out.extend_from_slice(&self.not_after.to_le_bytes());
        out
    }

    fn signing_preimage(&self) -> Vec<u8> {
        let unsigned = self.encode_unsigned();
        let mut out =
            Vec::with_capacity(ISSUER_CLEARING_APPROVAL_SIGNATURE_DOMAIN.len() + unsigned.len());
        out.extend_from_slice(ISSUER_CLEARING_APPROVAL_SIGNATURE_DOMAIN);
        out.extend_from_slice(&unsigned);
        out
    }
}

pub fn issuer_settlement_key_id(verifying_key: &VerifyingKey) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(ISSUER_SETTLEMENT_KEY_ID_DOMAIN);
    hasher.update(verifying_key.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    digest[..16].try_into().expect("fixed digest prefix")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlindSettlementOutputV1 {
    pub denomination: u64,
    /// Compressed secp256k1 point `B_`, never accompanied by the wallet's
    /// blinding scalar or proof-level `dleq.r`.
    pub blinded_message: [u8; 33],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettlementDestinationV1 {
    LedgerCredit {
        account_id: [u8; 32],
    },
    BlindOutputs {
        settlement_keyset_id: String,
        outputs: Vec<BlindSettlementOutputV1>,
    },
}

/// Canonical provider-to-issuer redeem request covered by the provider's
/// clearing-key signature. The digest domain fixes the HTTP operation to
/// `POST /v1/redeems`; transports must disable redirects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRedeemRequestV1 {
    pub authorization_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub credential_binding_digest: [u8; 32],
    pub scheme: AuthScheme,
    pub credential_digest: [u8; 32],
    pub accepted_value: u64,
    pub denomination_profile: u32,
    pub idempotency_key: [u8; 32],
    pub destination: SettlementDestinationV1,
}

impl ProviderRedeemRequestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(320);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.authorization_digest);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.scope_id);
        out.extend_from_slice(&self.offer_id.to_le_bytes());
        out.extend_from_slice(&self.credential_binding_digest);
        out.push(self.scheme as u8);
        out.extend_from_slice(&self.credential_digest);
        out.extend_from_slice(&self.accepted_value.to_le_bytes());
        out.extend_from_slice(&self.denomination_profile.to_le_bytes());
        out.extend_from_slice(&self.idempotency_key);
        match &self.destination {
            SettlementDestinationV1::LedgerCredit { account_id } => {
                out.push(1);
                out.extend_from_slice(account_id);
            }
            SettlementDestinationV1::BlindOutputs {
                settlement_keyset_id,
                outputs,
            } => {
                out.push(2);
                out.push(settlement_keyset_id.len() as u8);
                out.extend_from_slice(settlement_keyset_id.as_bytes());
                out.push(outputs.len() as u8);
                for output in outputs {
                    out.extend_from_slice(&output.denomination.to_le_bytes());
                    out.extend_from_slice(&output.blinded_message);
                }
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("ProviderRedeemRequestV1.version")?,
            "ProviderRedeemRequestV1",
        )?;
        let authorization_digest = decoder.fixed("ProviderRedeemRequestV1.authorization_digest")?;
        let issuer_id = decoder.fixed("ProviderRedeemRequestV1.issuer_id")?;
        let provider_id = decoder.fixed("ProviderRedeemRequestV1.provider_id")?;
        let scope_id = decoder.fixed("ProviderRedeemRequestV1.scope_id")?;
        let offer_id = decoder.u32("ProviderRedeemRequestV1.offer_id")?;
        let credential_binding_digest =
            decoder.fixed("ProviderRedeemRequestV1.credential_binding_digest")?;
        let scheme = AuthScheme::decode(decoder.u8("ProviderRedeemRequestV1.scheme")?)?;
        let credential_digest = decoder.fixed("ProviderRedeemRequestV1.credential_digest")?;
        let accepted_value = decoder.u64("ProviderRedeemRequestV1.accepted_value")?;
        let denomination_profile = decoder.u32("ProviderRedeemRequestV1.denomination_profile")?;
        let idempotency_key = decoder.fixed("ProviderRedeemRequestV1.idempotency_key")?;
        let destination = match decoder.u8("ProviderRedeemRequestV1.destination")? {
            1 => SettlementDestinationV1::LedgerCredit {
                account_id: decoder.fixed("ProviderRedeemRequestV1.account_id")?,
            },
            2 => {
                let settlement_keyset_id_bytes = decoder.bytes_u8(
                    "ProviderRedeemRequestV1.settlement_keyset_id",
                    crate::CASHU_KEYSET_ID_V2_LEN,
                )?;
                let settlement_keyset_id =
                    String::from_utf8(settlement_keyset_id_bytes).map_err(|_| {
                        ServiceProtocolError::InvalidUtf8(
                            "ProviderRedeemRequestV1.settlement_keyset_id",
                        )
                    })?;
                let count = decoder.u8("ProviderRedeemRequestV1.output_count")? as usize;
                if count > MAX_SETTLEMENT_OUTPUTS {
                    return Err(ServiceProtocolError::TooManyItems {
                        field: "ProviderRedeemRequestV1.outputs",
                        len: count,
                        max: MAX_SETTLEMENT_OUTPUTS,
                    });
                }
                let mut outputs = Vec::with_capacity(count);
                for _ in 0..count {
                    outputs.push(BlindSettlementOutputV1 {
                        denomination: decoder.u64("BlindSettlementOutputV1.denomination")?,
                        blinded_message: decoder
                            .fixed("BlindSettlementOutputV1.blinded_message")?,
                    });
                }
                SettlementDestinationV1::BlindOutputs {
                    settlement_keyset_id,
                    outputs,
                }
            }
            value => {
                return Err(ServiceProtocolError::UnknownDiscriminant {
                    kind: "SettlementDestinationV1",
                    value,
                })
            }
        };
        decoder.finish()?;
        let value = Self {
            authorization_digest,
            issuer_id,
            provider_id,
            scope_id,
            offer_id,
            credential_binding_digest,
            scheme,
            credential_digest,
            accepted_value,
            denomination_profile,
            idempotency_key,
            destination,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(PROVIDER_REDEEM_REQUEST_DIGEST_DOMAIN);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    pub(crate) fn validate_against_authorization(
        &self,
        authorization: &ProviderClearingAuthorizationV1,
    ) -> Result<(), ServiceProtocolError> {
        if self.authorization_digest != authorization.authorization_digest()?
            || self.issuer_id != authorization.claims.issuer_id
            || self.provider_id != authorization.claims.provider_id
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemRequestV1.audience",
                reason: "request does not match clearing authorization",
            });
        }
        let rule = authorization
            .rule_for_binding(&self.credential_binding_digest)
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemRequestV1.credential_binding_digest",
                reason: "credential binding has no approved settlement rule",
            })?;
        if self.accepted_value != rule.accepted_value
            || self.denomination_profile != rule.denomination_profile
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemRequestV1.settlement_rule",
                reason: "value or denomination profile differs from issuer-approved rule",
            });
        }
        match &self.destination {
            SettlementDestinationV1::LedgerCredit { account_id } => {
                if !rule
                    .settlement_modes
                    .allows(SettlementModesV1::LEDGER_CREDIT)
                    || account_id != &authorization.claims.settlement_account_id
                {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ProviderRedeemRequestV1.account_id",
                        reason: "ledger mode or destination is not issuer-approved",
                    });
                }
            }
            SettlementDestinationV1::BlindOutputs {
                settlement_keyset_id,
                outputs,
            } => {
                let keyset = rule.blind_output_keyset.as_ref().ok_or(
                    ServiceProtocolError::InvalidValue {
                        field: "ProviderRedeemRequestV1.settlement_keyset_id",
                        reason: "blind settlement has no issuer-approved keyset",
                    },
                )?;
                let total = outputs
                    .iter()
                    .try_fold(0u64, |sum, output| sum.checked_add(output.denomination));
                if !rule
                    .settlement_modes
                    .allows(SettlementModesV1::BLIND_OUTPUTS)
                    || settlement_keyset_id != &keyset.keyset_id
                    || total != Some(rule.provider_credit)
                    || outputs.iter().any(|output| {
                        keyset
                            .keys
                            .binary_search_by_key(&output.denomination, |key| key.amount)
                            .is_err()
                    })
                {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ProviderRedeemRequestV1.outputs",
                        reason: "blind mode, denominations, or value is not issuer-approved",
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_against_credential_binding(
        &self,
        binding: &CredentialKeyBindingV1,
        authorization: &ProviderClearingAuthorizationV1,
        now_unix: u64,
    ) -> Result<(), ServiceProtocolError> {
        binding.verify_signature()?;
        binding.check_validity(now_unix)?;
        let claims = &binding.claims;
        if self.credential_binding_digest != binding.binding_digest()?
            || self.issuer_id != binding.issuer_id
            || self.provider_id != claims.provider_id
            || self.scope_id != claims.scope_id
            || self.offer_id != claims.offer_id
            || self.scheme != claims.scheme
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemRequestV1.credential_binding",
                reason: "binding digest, issuer, provider, scope, offer, or scheme mismatch",
            });
        }
        let rule = authorization
            .rule_for_binding(&self.credential_binding_digest)
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemRequestV1.credential_binding_digest",
                reason: "credential binding has no approved settlement rule",
            })?;
        if !matches!(
            claims.unit,
            CredentialUnitV1::Auth | CredentialUnitV1::Entitlement
        ) || rule.unit != SettlementUnitV1::AuthCredit
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemRequestV1.credential_value",
                reason: "credential and settlement units are incompatible",
            });
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.authorization_digest.iter().all(|byte| *byte == 0)
            || self.issuer_id.iter().all(|byte| *byte == 0)
            || self.provider_id.iter().all(|byte| *byte == 0)
            || self.scope_id.iter().all(|byte| *byte == 0)
            || self.offer_id == 0
            || self.credential_binding_digest.iter().all(|byte| *byte == 0)
            || self.credential_digest.iter().all(|byte| *byte == 0)
            || self.idempotency_key.iter().all(|byte| *byte == 0)
            || self.accepted_value == 0
            || self.accepted_value > MAX_SERVICE_VALUE_V1
            || self.denomination_profile == 0
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemRequestV1",
                reason: "binding, audience, value, profile, and idempotency must be non-zero",
            });
        }
        if !matches!(
            self.scheme,
            AuthScheme::FreeV1 | AuthScheme::BitcoinPirCashuBatV1 | AuthScheme::ArcV1Experimental
        ) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemRequestV1.scheme",
                reason: "scheme is not redeemable through shared credential clearing",
            });
        }
        match &self.destination {
            SettlementDestinationV1::LedgerCredit { account_id } => {
                if account_id.iter().all(|byte| *byte == 0) {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ProviderRedeemRequestV1.account_id",
                        reason: "ledger account ID must be non-zero",
                    });
                }
            }
            SettlementDestinationV1::BlindOutputs {
                settlement_keyset_id,
                outputs,
            } => {
                if !is_canonical_cashu_keyset_id_v2(settlement_keyset_id) {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ProviderRedeemRequestV1.settlement_keyset_id",
                        reason: "must be an exact canonical NUT-02 V2 keyset ID",
                    });
                }
                if outputs.is_empty() || outputs.len() > MAX_SETTLEMENT_OUTPUTS {
                    return Err(ServiceProtocolError::TooManyItems {
                        field: "ProviderRedeemRequestV1.outputs",
                        len: outputs.len(),
                        max: MAX_SETTLEMENT_OUTPUTS,
                    });
                }
                let mut messages = HashSet::with_capacity(outputs.len());
                let mut total = 0u64;
                let mut previous: Option<(u64, [u8; 33])> = None;
                for output in outputs {
                    if output.denomination == 0
                        || output.denomination > MAX_SERVICE_VALUE_V1
                        || !crate::cashu_manifest::is_valid_compressed_point(
                            &output.blinded_message,
                        )
                        || !messages.insert(output.blinded_message)
                    {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "BlindSettlementOutputV1",
                            reason: "invalid value, SEC1 prefix, or duplicate blinded message",
                        });
                    }
                    let order_key = (output.denomination, output.blinded_message);
                    if previous.is_some_and(|prior| prior >= order_key) {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "ProviderRedeemRequestV1.outputs",
                            reason: "blind outputs must be in canonical denomination/message order",
                        });
                    }
                    previous = Some(order_key);
                    total = total.checked_add(output.denomination).ok_or(
                        ServiceProtocolError::InvalidValue {
                            field: "ProviderRedeemRequestV1.outputs",
                            reason: "settlement output sum overflow",
                        },
                    )?;
                }
                if total > MAX_SERVICE_VALUE_V1 {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ProviderRedeemRequestV1.outputs",
                        reason: "settlement output sum exceeds durable ledger bound",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Canonical binary body for `POST /v1/redeems`. Keeping the HTTP envelope in
/// the protocol crate prevents provider and issuer implementations from
/// independently inventing JSON field aliases or base64 canonicalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRedeemEnvelopeV1 {
    pub request: ProviderRedeemRequestV1,
    pub request_auth: ProviderClearingRequestAuthV1,
    pub credential_binding: CredentialKeyBindingV1,
    pub canonical_credential: Vec<u8>,
}

impl ProviderRedeemEnvelopeV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        if self.canonical_credential.is_empty()
            || self.canonical_credential.len() > MAX_PROVIDER_REDEEM_CREDENTIAL_LEN_V1
        {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ProviderRedeemEnvelopeV1.canonical_credential",
                len: self.canonical_credential.len(),
                max: MAX_PROVIDER_REDEEM_CREDENTIAL_LEN_V1,
            });
        }
        let request = self.request.encode()?;
        let request_auth = self.request_auth.encode();
        let binding = self.credential_binding.encode()?;
        let mut out = Vec::with_capacity(
            1 + 16
                + request.len()
                + request_auth.len()
                + binding.len()
                + self.canonical_credential.len(),
        );
        out.push(SERVICE_PROTOCOL_VERSION);
        put_bytes_u32(&mut out, &request);
        put_bytes_u32(&mut out, &request_auth);
        put_bytes_u32(&mut out, &binding);
        put_bytes_u32(&mut out, &self.canonical_credential);
        if out.len() > MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ProviderRedeemEnvelopeV1",
                len: out.len(),
                max: MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1,
            });
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ProviderRedeemEnvelopeV1",
                len: bytes.len(),
                max: MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1,
            });
        }
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("ProviderRedeemEnvelopeV1.version")?,
            "ProviderRedeemEnvelopeV1",
        )?;
        let request_bytes = decoder.bytes_u32(
            "ProviderRedeemEnvelopeV1.request",
            MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1,
        )?;
        let request_auth_bytes = decoder.bytes_u32(
            "ProviderRedeemEnvelopeV1.request_auth",
            MAX_PROVIDER_REDEEM_ENVELOPE_LEN_V1,
        )?;
        let binding_bytes = decoder.bytes_u32(
            "ProviderRedeemEnvelopeV1.credential_binding",
            crate::MAX_CREDENTIAL_BINDING_LEN,
        )?;
        let canonical_credential = decoder.bytes_u32(
            "ProviderRedeemEnvelopeV1.canonical_credential",
            MAX_PROVIDER_REDEEM_CREDENTIAL_LEN_V1,
        )?;
        decoder.finish()?;
        if canonical_credential.is_empty() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemEnvelopeV1.canonical_credential",
                reason: "must not be empty",
            });
        }
        let request = ProviderRedeemRequestV1::decode(&request_bytes)?;
        let request_auth = ProviderClearingRequestAuthV1::decode(&request_auth_bytes)?;
        let credential_binding = CredentialKeyBindingV1::decode(&binding_bytes)?;
        if request.encode()? != request_bytes
            || request_auth.encode() != request_auth_bytes
            || credential_binding.encode()? != binding_bytes
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemEnvelopeV1",
                reason: "nested object is not canonical",
            });
        }
        Ok(Self {
            request,
            request_auth,
            credential_binding,
            canonical_credential,
        })
    }
}

pub fn credential_presentation_digest(
    scheme: AuthScheme,
    canonical_credential: &[u8],
) -> Result<[u8; 32], ServiceProtocolError> {
    let len = u32::try_from(canonical_credential.len()).map_err(|_| {
        ServiceProtocolError::FieldTooLong {
            field: "canonical_credential",
            len: canonical_credential.len(),
            max: u32::MAX as usize,
        }
    })?;
    let mut hasher = Sha256::new();
    hasher.update(CREDENTIAL_PRESENTATION_DIGEST_DOMAIN);
    hasher.update([SERVICE_PROTOCOL_VERSION, scheme as u8]);
    hasher.update(len.to_le_bytes());
    hasher.update(canonical_credential);
    Ok(hasher.finalize().into())
}

/// The only public verification path for a *new* shared-issuer redemption.
///
/// An issuer handler must first check its idempotency table. An exact request
/// that already committed returns its stored response even if an
/// authorization later expired or was revoked. Only a request that would
/// create new debt calls this verifier. Scheme-specific proof validity is
/// checked by the issuer adapter before the same transaction commits.
pub fn verify_new_redeem_request_for(
    request: &ProviderRedeemRequestV1,
    canonical_credential: &[u8],
    credential_binding: &CredentialKeyBindingV1,
    authorization: &ProviderClearingAuthorizationV1,
    issuer_approval: &IssuerClearingApprovalV1,
    request_auth: &ProviderClearingRequestAuthV1,
    expectation: &ProviderClearingExpectationV1<'_>,
) -> Result<(), ServiceProtocolError> {
    request.validate()?;
    if request.credential_digest
        != credential_presentation_digest(request.scheme, canonical_credential)?
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ProviderRedeemRequestV1.credential_digest",
            reason: "does not match the canonical credential presentation",
        });
    }
    request.validate_against_authorization(authorization)?;
    request.validate_against_credential_binding(
        credential_binding,
        authorization,
        expectation.now_unix,
    )?;
    let authorization_digest = authorization.authorization_digest()?;
    let request_digest = request.request_digest()?;
    request_auth.verify_for(
        &authorization_digest,
        &request_digest,
        authorization,
        issuer_approval,
        expectation,
    )
}

/// Authenticates an exact already-committed redeem request before replaying
/// its stored response. This deliberately does not revalidate credential
/// freshness or consume it again. The caller MUST first prove through its
/// durable idempotency table that the request bytes match one committed row.
///
/// Historical operator/issuer signatures are checked at the start of their
/// overlapping signed window, so key expiry does not strand a lost HTTP
/// response. This function never authorizes a new ledger mutation.
pub struct CommittedRedeemReplayExpectationV1<'a> {
    pub provider_id: &'a ProviderId,
    pub issuer_id: &'a [u8; 32],
    pub operator_key: &'a VerifyingKey,
    pub issuer_settlement_key: &'a VerifyingKey,
}

pub fn verify_committed_redeem_replay_auth_v1(
    request: &ProviderRedeemRequestV1,
    authorization: &ProviderClearingAuthorizationV1,
    issuer_approval: &IssuerClearingApprovalV1,
    request_auth: &ProviderClearingRequestAuthV1,
    expectation: &CommittedRedeemReplayExpectationV1<'_>,
) -> Result<(), ServiceProtocolError> {
    request.validate()?;
    request.validate_against_authorization(authorization)?;
    verify_committed_clearing_request_auth_v1(
        &request.authorization_digest,
        &request.request_digest()?,
        authorization,
        issuer_approval,
        request_auth,
        expectation,
    )
}

/// Authenticates an exact request whose economic response is already present
/// in a rollback-protected issuer store. It never authorizes a new mutation.
///
/// The caller must first match the request against the durable idempotency row
/// and perform operation-specific binding checks. Historical signature
/// validity is evaluated at the start of the authorization/approval overlap so
/// routine expiry does not strand a response lost at the HTTP boundary.
pub fn verify_committed_clearing_request_auth_v1(
    expected_authorization_digest: &[u8; 32],
    expected_request_digest: &[u8; 32],
    authorization: &ProviderClearingAuthorizationV1,
    issuer_approval: &IssuerClearingApprovalV1,
    request_auth: &ProviderClearingRequestAuthV1,
    expectation: &CommittedRedeemReplayExpectationV1<'_>,
) -> Result<(), ServiceProtocolError> {
    let verification_time = authorization
        .claims
        .not_before
        .max(issuer_approval.approved_at);
    if verification_time > authorization.claims.not_after
        || verification_time > issuer_approval.not_after
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "committed_redeem_replay.validity",
            reason: "authorization and approval have no overlapping signed window",
        });
    }
    request_auth.verify_for(
        expected_authorization_digest,
        expected_request_digest,
        authorization,
        issuer_approval,
        &ProviderClearingExpectationV1 {
            provider_id: expectation.provider_id,
            issuer_id: expectation.issuer_id,
            operator_key: expectation.operator_key,
            issuer_settlement_key: expectation.issuer_settlement_key,
            now_unix: verification_time,
            minimum_authorization_epoch: authorization.claims.authorization_epoch,
        },
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderClearingRequestAuthV1 {
    pub authorization_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub signature: [u8; 64],
}

/// Trusted context required before a provider clearing request can be
/// accepted. Callers construct this from local issuer configuration, never
/// from the request body.
pub struct ProviderClearingExpectationV1<'a> {
    pub provider_id: &'a ProviderId,
    pub issuer_id: &'a [u8; 32],
    pub operator_key: &'a VerifyingKey,
    pub issuer_settlement_key: &'a VerifyingKey,
    pub now_unix: u64,
    pub minimum_authorization_epoch: u64,
}

impl ProviderClearingRequestAuthV1 {
    pub fn sign(
        authorization_digest: [u8; 32],
        request_digest: [u8; 32],
        clearing_signing_key: &SigningKey,
    ) -> Self {
        let mut value = Self {
            authorization_digest,
            request_digest,
            signature: [0; 64],
        };
        value.signature = clearing_signing_key
            .sign(&value.signing_preimage())
            .to_bytes();
        value
    }

    pub(crate) fn verify_for(
        &self,
        expected_authorization_digest: &[u8; 32],
        expected_request_digest: &[u8; 32],
        authorization: &ProviderClearingAuthorizationV1,
        issuer_approval: &IssuerClearingApprovalV1,
        expectation: &ProviderClearingExpectationV1<'_>,
    ) -> Result<(), ServiceProtocolError> {
        // A request signature is only meaningful under an authorization that
        // has itself been checked against the operator trust root, audience,
        // validity window, and rollback floor. Keeping this call here avoids
        // a dangerous "self-authorized clearing key" integration footgun.
        authorization.verify_for(
            expectation.provider_id,
            expectation.issuer_id,
            expectation.operator_key,
            expectation.now_unix,
            expectation.minimum_authorization_epoch,
        )?;
        issuer_approval.verify_for(
            authorization,
            expectation.issuer_settlement_key,
            expectation.now_unix,
            expectation.minimum_authorization_epoch,
        )?;
        if &self.authorization_digest != expected_authorization_digest
            || &self.request_digest != expected_request_digest
            || authorization.authorization_digest()?.as_slice()
                != expected_authorization_digest.as_slice()
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderClearingRequestAuthV1.binding",
                reason: "authorization or request digest mismatch",
            });
        }
        let key = VerifyingKey::from_bytes(&authorization.claims.clearing_verifying_key)
            .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        key.verify_strict(
            &self.signing_preimage(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| ServiceProtocolError::BadSignature)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(129);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.authorization_digest);
        out.extend_from_slice(&self.request_digest);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("ProviderClearingRequestAuthV1.version")?;
        expect_v1(version, "ProviderClearingRequestAuthV1")?;
        let value = Self {
            authorization_digest: decoder
                .fixed("ProviderClearingRequestAuthV1.authorization_digest")?,
            request_digest: decoder.fixed("ProviderClearingRequestAuthV1.request_digest")?,
            signature: decoder.fixed("ProviderClearingRequestAuthV1.signature")?,
        };
        decoder.finish()?;
        Ok(value)
    }

    fn signing_preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CLEARING_REQUEST_SIGNATURE_DOMAIN.len() + 64);
        out.extend_from_slice(CLEARING_REQUEST_SIGNATURE_DOMAIN);
        out.extend_from_slice(&self.authorization_digest);
        out.extend_from_slice(&self.request_digest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{derive_cashu_keyset_id_v2, CashuDenominationKeyV1, CredentialKeyBindingClaimsV1};
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};

    fn point(multiplier: u64) -> [u8; 33] {
        (ProjectivePoint::GENERATOR * Scalar::from(multiplier))
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn settlement_keyset() -> CashuKeysetBindingV1 {
        let keys = vec![
            CashuDenominationKeyV1 {
                amount: 1,
                public_key: point(51),
            },
            CashuDenominationKeyV1 {
                amount: 2,
                public_key: point(52),
            },
            CashuDenominationKeyV1 {
                amount: 4,
                public_key: point(53),
            },
            CashuDenominationKeyV1 {
                amount: 8,
                public_key: point(54),
            },
        ];
        CashuKeysetBindingV1 {
            keyset_id: derive_cashu_keyset_id_v2(&keys, "auth", 0, Some(4_000)).unwrap(),
            unit: "auth".into(),
            input_fee_ppk: 0,
            final_expiry: Some(4_000),
            keys,
        }
    }

    fn authorization() -> (ProviderClearingAuthorizationV1, SigningKey, SigningKey) {
        let operator = SigningKey::from_bytes(&[3; 32]);
        let clearing = SigningKey::from_bytes(&[4; 32]);
        let authorization = ProviderClearingAuthorizationV1::sign(
            ProviderClearingAuthorizationClaimsV1 {
                authorization_id: [1; 16],
                authorization_epoch: 2,
                provider_id: [5; 32],
                issuer_id: [6; 32],
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
                    .unwrap(),
                    blind_output_minimum_validity_seconds: 3_600,
                    blind_output_keyset: Some(settlement_keyset()),
                }],
            },
            &operator,
        )
        .unwrap();
        (authorization, operator, clearing)
    }

    #[test]
    fn authorization_and_request_auth_roundtrip() {
        let (authorization, operator, clearing) = authorization();
        authorization
            .verify_for(&[5; 32], &[6; 32], &operator.verifying_key(), 150, 2)
            .unwrap();
        let decoded =
            ProviderClearingAuthorizationV1::decode(&authorization.encode().unwrap()).unwrap();
        assert_eq!(decoded, authorization);

        let auth_digest = authorization.authorization_digest().unwrap();
        let request = ProviderClearingRequestAuthV1::sign(auth_digest, [9; 32], &clearing);
        let operator_key = operator.verifying_key();
        let issuer_settlement = SigningKey::from_bytes(&[13; 32]);
        let approval =
            IssuerClearingApprovalV1::sign(&authorization, 100, 200, &issuer_settlement).unwrap();
        request
            .verify_for(
                &auth_digest,
                &[9; 32],
                &authorization,
                &approval,
                &ProviderClearingExpectationV1 {
                    provider_id: &[5; 32],
                    issuer_id: &[6; 32],
                    operator_key: &operator_key,
                    issuer_settlement_key: &issuer_settlement.verifying_key(),
                    now_unix: 150,
                    minimum_authorization_epoch: 2,
                },
            )
            .unwrap();
        assert_eq!(
            ProviderClearingRequestAuthV1::decode(&request.encode()).unwrap(),
            request
        );
    }

    #[test]
    fn wrong_provider_request_or_nonconserving_rule_fails() {
        let (mut authorization, operator, clearing) = authorization();
        assert!(authorization
            .verify_for(&[8; 32], &[6; 32], &operator.verifying_key(), 150, 2)
            .is_err());

        let auth_digest = authorization.authorization_digest().unwrap();
        let request = ProviderClearingRequestAuthV1::sign(auth_digest, [9; 32], &clearing);
        let operator_key = operator.verifying_key();
        let issuer_settlement = SigningKey::from_bytes(&[13; 32]);
        let approval =
            IssuerClearingApprovalV1::sign(&authorization, 100, 200, &issuer_settlement).unwrap();
        assert!(request
            .verify_for(
                &auth_digest,
                &[8; 32],
                &authorization,
                &approval,
                &ProviderClearingExpectationV1 {
                    provider_id: &[5; 32],
                    issuer_id: &[6; 32],
                    operator_key: &operator_key,
                    issuer_settlement_key: &issuer_settlement.verifying_key(),
                    now_unix: 150,
                    minimum_authorization_epoch: 2,
                },
            )
            .is_err());

        authorization.claims.rules[0].provider_credit = 10;
        assert!(authorization.encode().is_err());
    }

    #[test]
    fn request_rejects_self_authorized_clearing_key() {
        let (trusted, operator, _) = authorization();
        let attacker_operator = SigningKey::from_bytes(&[11; 32]);
        let attacker_clearing = SigningKey::from_bytes(&[12; 32]);
        let forged = ProviderClearingAuthorizationV1::sign(
            ProviderClearingAuthorizationClaimsV1 {
                clearing_verifying_key: attacker_clearing.verifying_key().to_bytes(),
                ..trusted.claims.clone()
            },
            &attacker_operator,
        )
        .unwrap();
        let digest = forged.authorization_digest().unwrap();
        let request = ProviderClearingRequestAuthV1::sign(digest, [9; 32], &attacker_clearing);
        let operator_key = operator.verifying_key();
        let issuer_settlement = SigningKey::from_bytes(&[13; 32]);
        let forged_approval =
            IssuerClearingApprovalV1::sign(&forged, 100, 200, &issuer_settlement).unwrap();
        assert!(request
            .verify_for(
                &digest,
                &[9; 32],
                &forged,
                &forged_approval,
                &ProviderClearingExpectationV1 {
                    provider_id: &[5; 32],
                    issuer_id: &[6; 32],
                    operator_key: &operator_key,
                    issuer_settlement_key: &issuer_settlement.verifying_key(),
                    now_unix: 150,
                    minimum_authorization_epoch: 2,
                },
            )
            .is_err());
    }

    #[test]
    fn issuer_must_countersign_exact_rules() {
        let (authorization, _, _) = authorization();
        let issuer = SigningKey::from_bytes(&[13; 32]);
        let approval = IssuerClearingApprovalV1::sign(&authorization, 100, 190, &issuer).unwrap();
        approval
            .verify_for(&authorization, &issuer.verifying_key(), 150, 2)
            .unwrap();
        assert_eq!(
            IssuerClearingApprovalV1::decode(&approval.encode()).unwrap(),
            approval
        );

        let attacker = SigningKey::from_bytes(&[14; 32]);
        assert!(approval
            .verify_for(&authorization, &attacker.verifying_key(), 150, 2)
            .is_err());

        let mut changed = authorization.clone();
        changed.claims.rules[0].provider_credit = 8;
        changed.claims.rules[0].issuer_fee = 2;
        assert!(approval
            .verify_for(&changed, &issuer.verifying_key(), 150, 2)
            .is_err());
    }

    #[test]
    fn redeem_request_covers_audience_token_value_destination_and_idempotency() {
        let (authorization, operator, clearing) = authorization();
        let auth_digest = authorization.authorization_digest().unwrap();
        let settlement_keyset_id = authorization.claims.rules[0]
            .blind_output_keyset
            .as_ref()
            .unwrap()
            .keyset_id
            .clone();
        let blinded_message = point(21);
        let second_blinded_message = point(22);
        let request = ProviderRedeemRequestV1 {
            authorization_digest: auth_digest,
            issuer_id: [6; 32],
            provider_id: [5; 32],
            scope_id: [15; 32],
            offer_id: 7,
            credential_binding_digest: [7; 32],
            scheme: AuthScheme::BitcoinPirCashuBatV1,
            credential_digest: credential_presentation_digest(
                AuthScheme::BitcoinPirCashuBatV1,
                b"canonical BAT",
            )
            .unwrap(),
            accepted_value: 10,
            denomination_profile: 8,
            idempotency_key: [16; 32],
            destination: SettlementDestinationV1::BlindOutputs {
                settlement_keyset_id,
                outputs: vec![
                    BlindSettlementOutputV1 {
                        denomination: 1,
                        blinded_message,
                    },
                    BlindSettlementOutputV1 {
                        denomination: 8,
                        blinded_message: second_blinded_message,
                    },
                ],
            },
        };
        request
            .validate_against_authorization(&authorization)
            .unwrap();
        let decoded = ProviderRedeemRequestV1::decode(&request.encode().unwrap()).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.request_digest(), request.request_digest());

        let issuer = SigningKey::from_bytes(&[13; 32]);
        let approval = IssuerClearingApprovalV1::sign(&authorization, 100, 200, &issuer).unwrap();
        let signed_request = ProviderClearingRequestAuthV1::sign(
            auth_digest,
            request.request_digest().unwrap(),
            &clearing,
        );
        signed_request
            .verify_for(
                &auth_digest,
                &request.request_digest().unwrap(),
                &authorization,
                &approval,
                &ProviderClearingExpectationV1 {
                    provider_id: &[5; 32],
                    issuer_id: &[6; 32],
                    operator_key: &operator.verifying_key(),
                    issuer_settlement_key: &issuer.verifying_key(),
                    now_unix: 150,
                    minimum_authorization_epoch: 2,
                },
            )
            .unwrap();

        let mut changed = request;
        changed.idempotency_key[0] ^= 1;
        assert_ne!(changed.request_digest(), decoded.request_digest());
        changed.idempotency_key[0] ^= 1;
        if let SettlementDestinationV1::BlindOutputs {
            settlement_keyset_id,
            ..
        } = &mut changed.destination
        {
            *settlement_keyset_id = format!("01{}", "0".repeat(64));
        }
        assert!(changed
            .validate_against_authorization(&authorization)
            .is_err());
        changed.destination = decoded.destination.clone();
        if let SettlementDestinationV1::BlindOutputs { outputs, .. } = &mut changed.destination {
            outputs[0].denomination = 2;
        }
        assert!(changed
            .validate_against_authorization(&authorization)
            .is_err());
    }

    #[test]
    fn settlement_values_cannot_exceed_signed_sqlite_range() {
        let (mut authorization, _, _) = authorization();
        authorization.claims.rules[0].accepted_value = MAX_SERVICE_VALUE_V1 + 1;
        authorization.claims.rules[0].provider_credit = MAX_SERVICE_VALUE_V1;
        authorization.claims.rules[0].issuer_fee = 1;
        assert!(authorization.encode().is_err());
    }

    #[test]
    fn blind_settlement_keyset_is_exact_and_covers_recovery_horizon() {
        let (mut short_lived, _, _) = authorization();
        let keyset = short_lived.claims.rules[0]
            .blind_output_keyset
            .as_mut()
            .unwrap();
        keyset.final_expiry = Some(3_799);
        keyset.keyset_id = derive_cashu_keyset_id_v2(
            &keyset.keys,
            &keyset.unit,
            keyset.input_fee_ppk,
            keyset.final_expiry,
        )
        .unwrap();
        assert!(short_lived.encode().is_err());

        let (mut fee_charging, _, _) = authorization();
        let keyset = fee_charging.claims.rules[0]
            .blind_output_keyset
            .as_mut()
            .unwrap();
        keyset.input_fee_ppk = 1;
        keyset.keyset_id = derive_cashu_keyset_id_v2(
            &keyset.keys,
            &keyset.unit,
            keyset.input_fee_ppk,
            keyset.final_expiry,
        )
        .unwrap();
        assert!(fee_charging.encode().is_err());
    }

    #[test]
    fn combined_redeem_verifier_rejects_every_routing_tamper() {
        let issuer_root = SigningKey::from_bytes(&[18; 32]);
        let bat_verification_key = point(31);
        let bat_key_id =
            crate::derive_bat_key_id_v1(&[5; 32], &[15; 32], 7, 4, 3, &bat_verification_key);
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id: [5; 32],
                scope_id: [15; 32],
                offer_id: 7,
                scheme: AuthScheme::BitcoinPirCashuBatV1,
                keyset_epoch: 3,
                entitlement_profile: 4,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 1,
                not_before: 100,
                not_after: 300,
                credential_key_id: bat_key_id.to_vec(),
                verification_key: bat_verification_key.to_vec(),
            },
            &issuer_root,
        )
        .unwrap();
        let binding_digest = binding.binding_digest().unwrap();
        let operator = SigningKey::from_bytes(&[3; 32]);
        let clearing = SigningKey::from_bytes(&[4; 32]);
        let authorization = ProviderClearingAuthorizationV1::sign(
            ProviderClearingAuthorizationClaimsV1 {
                authorization_id: [1; 16],
                authorization_epoch: 2,
                provider_id: [5; 32],
                issuer_id: binding.issuer_id,
                settlement_account_id: [17; 32],
                clearing_verifying_key: clearing.verifying_key().to_bytes(),
                not_before: 100,
                not_after: 250,
                rules: vec![SettlementRuleV1 {
                    credential_binding_digest: binding_digest,
                    unit: SettlementUnitV1::AuthCredit,
                    accepted_value: 10,
                    provider_credit: 9,
                    issuer_fee: 1,
                    denomination_profile: 8,
                    settlement_modes: SettlementModesV1::from_bits(
                        SettlementModesV1::LEDGER_CREDIT | SettlementModesV1::BLIND_OUTPUTS,
                    )
                    .unwrap(),
                    blind_output_minimum_validity_seconds: 3_600,
                    blind_output_keyset: Some(settlement_keyset()),
                }],
            },
            &operator,
        )
        .unwrap();
        let issuer_settlement = SigningKey::from_bytes(&[13; 32]);
        let approval =
            IssuerClearingApprovalV1::sign(&authorization, 100, 250, &issuer_settlement).unwrap();
        let canonical_credential = b"BitcoinPIR canonical BAT proof";
        let settlement_keyset_id = authorization.claims.rules[0]
            .blind_output_keyset
            .as_ref()
            .unwrap()
            .keyset_id
            .clone();
        let request = ProviderRedeemRequestV1 {
            authorization_digest: authorization.authorization_digest().unwrap(),
            issuer_id: binding.issuer_id,
            provider_id: [5; 32],
            scope_id: [15; 32],
            offer_id: 7,
            credential_binding_digest: binding_digest,
            scheme: AuthScheme::BitcoinPirCashuBatV1,
            credential_digest: credential_presentation_digest(
                AuthScheme::BitcoinPirCashuBatV1,
                canonical_credential,
            )
            .unwrap(),
            accepted_value: 10,
            denomination_profile: 8,
            idempotency_key: [16; 32],
            destination: SettlementDestinationV1::BlindOutputs {
                settlement_keyset_id,
                outputs: vec![
                    BlindSettlementOutputV1 {
                        denomination: 1,
                        blinded_message: point(41),
                    },
                    BlindSettlementOutputV1 {
                        denomination: 8,
                        blinded_message: point(42),
                    },
                ],
            },
        };
        let sign_request = |request: &ProviderRedeemRequestV1| {
            ProviderClearingRequestAuthV1::sign(
                authorization.authorization_digest().unwrap(),
                request.request_digest().unwrap(),
                &clearing,
            )
        };
        let operator_key = operator.verifying_key();
        let issuer_settlement_key = issuer_settlement.verifying_key();
        let expectation = ProviderClearingExpectationV1 {
            provider_id: &[5; 32],
            issuer_id: &binding.issuer_id,
            operator_key: &operator_key,
            issuer_settlement_key: &issuer_settlement_key,
            now_unix: 150,
            minimum_authorization_epoch: 2,
        };
        verify_new_redeem_request_for(
            &request,
            canonical_credential,
            &binding,
            &authorization,
            &approval,
            &sign_request(&request),
            &expectation,
        )
        .unwrap();

        let mut wrong_scope = request.clone();
        wrong_scope.scope_id[0] ^= 1;
        assert!(verify_new_redeem_request_for(
            &wrong_scope,
            canonical_credential,
            &binding,
            &authorization,
            &approval,
            &sign_request(&wrong_scope),
            &expectation,
        )
        .is_err());

        let mut wrong_keyset = request.clone();
        if let SettlementDestinationV1::BlindOutputs {
            settlement_keyset_id,
            ..
        } = &mut wrong_keyset.destination
        {
            *settlement_keyset_id = format!("01{}", "0".repeat(64));
        }
        assert!(verify_new_redeem_request_for(
            &wrong_keyset,
            canonical_credential,
            &binding,
            &authorization,
            &approval,
            &sign_request(&wrong_keyset),
            &expectation,
        )
        .is_err());

        let mut wrong_account = request.clone();
        wrong_account.destination = SettlementDestinationV1::LedgerCredit {
            account_id: [99; 32],
        };
        assert!(verify_new_redeem_request_for(
            &wrong_account,
            canonical_credential,
            &binding,
            &authorization,
            &approval,
            &sign_request(&wrong_account),
            &expectation,
        )
        .is_err());

        let mut wrong_denominations = request.clone();
        if let SettlementDestinationV1::BlindOutputs { outputs, .. } =
            &mut wrong_denominations.destination
        {
            outputs[0].denomination = 3;
            outputs[1].denomination = 6;
        }
        assert!(verify_new_redeem_request_for(
            &wrong_denominations,
            canonical_credential,
            &binding,
            &authorization,
            &approval,
            &sign_request(&wrong_denominations),
            &expectation,
        )
        .is_err());

        let mut wrong_idempotency = request.clone();
        wrong_idempotency.idempotency_key[0] ^= 1;
        assert!(verify_new_redeem_request_for(
            &wrong_idempotency,
            canonical_credential,
            &binding,
            &authorization,
            &approval,
            &sign_request(&request),
            &expectation,
        )
        .is_err());

        assert!(verify_new_redeem_request_for(
            &request,
            b"different canonical credential",
            &binding,
            &authorization,
            &approval,
            &sign_request(&request),
            &expectation,
        )
        .is_err());
    }
}
