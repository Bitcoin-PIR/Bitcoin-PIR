//! Issuer-mediated, class-bound BAT V2 provider redemption.
//!
//! This module deliberately owns a wire namespace separate from V1 clearing.
//! The only shared cryptographic primitive is the issuer-global BAT spend key:
//! a raw BAT key and secret must identify the same spend across V1 and V2.

use core::fmt;
use std::cmp::Ordering;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::codec::{put_bytes_u16, put_bytes_u32, Decoder};
use crate::{
    is_canonical_service_https_origin_v1, issuer_settlement_key_id,
    validate_leaf_spki_sha256_pins_v1, BatAcceptanceClassV2, BatAcceptanceMemberV2,
    BitcoinPirCashuBatProofV1, ProviderId, ScopeId, ServiceProtocolError, SettlementUnitV1,
    VerifiedBatAcceptanceMemberV2, MAX_ENDPOINT_LEN, MAX_LEAF_SPKI_SHA256_PINS_V1,
    MAX_SERVICE_VALUE_V1,
};

pub const BAT_V2_REDEMPTION_WIRE_VERSION_V2: u8 = 2;
pub const BAT_V2_PROOF_CODEC_MAGIC_V2: &[u8; 8] = b"BPIRBRP2";
pub const BAT_V2_PROVIDER_REDEEM_REQUEST_CODEC_MAGIC_V2: &[u8; 8] = b"BPIRBRQ2";
pub const BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_CODEC_MAGIC_V2: &[u8; 8] = b"BPIRBRA2";
pub const BAT_V2_PROVIDER_REDEEM_ENVELOPE_CODEC_MAGIC_V2: &[u8; 8] = b"BPIRBRE2";
pub const BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_CODEC_MAGIC_V2: &[u8; 8] = b"BPIRBAA2";
pub const BAT_V2_ISSUER_ACCOUNTING_APPROVAL_CODEC_MAGIC_V2: &[u8; 8] = b"BPIRBAP2";
pub const BAT_V2_PROVIDER_REDEEM_RESPONSE_CODEC_MAGIC_V2: &[u8; 8] = b"BPIRBRS2";

pub const BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_SIGNATURE_DOMAIN_V2: &[u8] =
    b"BitcoinPIR/bat-v2-provider-accounting-authorization-signature/v2";
pub const BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_DIGEST_DOMAIN_V2: &[u8] =
    b"BitcoinPIR/bat-v2-provider-accounting-authorization-digest/v2";
pub const BAT_V2_ISSUER_ACCOUNTING_APPROVAL_SIGNATURE_DOMAIN_V2: &[u8] =
    b"BitcoinPIR/bat-v2-issuer-accounting-approval-signature/v2";
pub const BAT_V2_CREDENTIAL_PRESENTATION_DIGEST_DOMAIN_V2: &[u8] =
    b"BitcoinPIR/bat-v2-credential-presentation-digest/v2";
pub const BAT_V2_PROVIDER_REDEEM_REQUEST_DIGEST_DOMAIN_V2: &[u8] =
    b"BitcoinPIR/bat-v2-provider-redeem-request/POST-/v2/redeems/v2";
pub const BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_SIGNATURE_DOMAIN_V2: &[u8] =
    b"BitcoinPIR/bat-v2-provider-redeem-request-auth-signature/POST-/v2/redeems/v2";
pub const BAT_V2_PROVIDER_REDEEM_RESPONSE_SIGNATURE_DOMAIN_V2: &[u8] =
    b"BitcoinPIR/bat-v2-provider-redeem-response-signature/v2";
pub const BAT_V2_REDEEM_LEDGER_TRANSACTION_ID_DOMAIN_V2: &[u8] =
    b"BitcoinPIR/bat-v2-redeem-ledger-transaction-id/v2";

pub const BAT_V2_PROOF_LEN_V2: usize = 210;
pub const BAT_V2_PROVIDER_REDEEM_REQUEST_LEN_V2: usize = 382;
pub const BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_LEN_V2: usize = 169;
pub const BAT_V2_PROVIDER_REDEEM_ENVELOPE_LEN_V2: usize = 782;
pub const BAT_V2_ISSUER_ACCOUNTING_APPROVAL_LEN_V2: usize = 145;
pub const MAX_BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_LEN_V2: usize = 16 * 1024;
pub const MAX_BAT_V2_ACCOUNTING_RULES_V2: usize = 64;
pub const MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2: usize = 339;

fn decode_v2_magic(
    decoder: &mut Decoder<'_>,
    expected: &[u8; 8],
    kind: &'static str,
) -> Result<(), ServiceProtocolError> {
    let magic: [u8; 8] = decoder.fixed(kind)?;
    if &magic != expected {
        return Err(ServiceProtocolError::InvalidValue {
            field: kind,
            reason: "wrong BAT V2 redemption codec domain",
        });
    }
    let version = decoder.u8(kind)?;
    if version != BAT_V2_REDEMPTION_WIRE_VERSION_V2 {
        return Err(ServiceProtocolError::UnknownVersion { kind, version });
    }
    Ok(())
}

fn begin_v2(out: &mut Vec<u8>, magic: &[u8; 8]) {
    out.extend_from_slice(magic);
    out.push(BAT_V2_REDEMPTION_WIRE_VERSION_V2);
}

fn require_nonzero(bytes: &[u8], field: &'static str) -> Result<(), ServiceProtocolError> {
    if bytes.iter().all(|byte| *byte == 0) {
        Err(ServiceProtocolError::InvalidValue {
            field,
            reason: "must be non-zero",
        })
    } else {
        Ok(())
    }
}

/// V2 presentation wrapper. It cannot be decoded as a V1 proof, while its
/// `spend_key` intentionally delegates to V1's issuer-global BAT derivation.
#[derive(Clone, PartialEq, Eq)]
pub struct BitcoinPirCashuBatProofV2 {
    pub issuer_id: [u8; 32],
    pub class_id: [u8; 32],
    pub class_digest: [u8; 32],
    pub class_key_epoch: u64,
    pub bat_key_id: [u8; 32],
    pub secret_raw: [u8; 32],
    pub c: [u8; 33],
}

impl fmt::Debug for BitcoinPirCashuBatProofV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitcoinPirCashuBatProofV2")
            .field("issuer_id", &self.issuer_id)
            .field("class_id", &self.class_id)
            .field("class_digest", &self.class_digest)
            .field("class_key_epoch", &self.class_key_epoch)
            .field("bat_key_id", &self.bat_key_id)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

impl Drop for BitcoinPirCashuBatProofV2 {
    fn drop(&mut self) {
        self.secret_raw.zeroize();
        self.c.zeroize();
    }
}

impl BitcoinPirCashuBatProofV2 {
    pub fn from_class(
        class: &BatAcceptanceClassV2,
        secret_raw: [u8; 32],
        c: [u8; 33],
    ) -> Result<Self, ServiceProtocolError> {
        class.verify()?;
        let value = Self {
            issuer_id: class.issuer_id,
            class_id: class.class_id,
            class_digest: class.class_digest()?,
            class_key_epoch: class.key_epoch,
            bat_key_id: class.bat_key_id(),
            secret_raw,
            c,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn encode(&self) -> Result<[u8; BAT_V2_PROOF_LEN_V2], ServiceProtocolError> {
        self.validate()?;
        let mut out = [0u8; BAT_V2_PROOF_LEN_V2];
        out[..8].copy_from_slice(BAT_V2_PROOF_CODEC_MAGIC_V2);
        out[8] = BAT_V2_REDEMPTION_WIRE_VERSION_V2;
        let mut cursor = 9;
        for bytes in [
            self.issuer_id.as_slice(),
            self.class_id.as_slice(),
            self.class_digest.as_slice(),
        ] {
            out[cursor..cursor + bytes.len()].copy_from_slice(bytes);
            cursor += bytes.len();
        }
        out[cursor..cursor + 8].copy_from_slice(&self.class_key_epoch.to_le_bytes());
        cursor += 8;
        for bytes in [
            self.bat_key_id.as_slice(),
            self.secret_raw.as_slice(),
            self.c.as_slice(),
        ] {
            out[cursor..cursor + bytes.len()].copy_from_slice(bytes);
            cursor += bytes.len();
        }
        debug_assert_eq!(cursor, BAT_V2_PROOF_LEN_V2);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        decode_v2_magic(
            &mut decoder,
            BAT_V2_PROOF_CODEC_MAGIC_V2,
            "BitcoinPirCashuBatProofV2",
        )?;
        let value = Self {
            issuer_id: decoder.fixed("BitcoinPirCashuBatProofV2.issuer_id")?,
            class_id: decoder.fixed("BitcoinPirCashuBatProofV2.class_id")?,
            class_digest: decoder.fixed("BitcoinPirCashuBatProofV2.class_digest")?,
            class_key_epoch: decoder.u64("BitcoinPirCashuBatProofV2.class_key_epoch")?,
            bat_key_id: decoder.fixed("BitcoinPirCashuBatProofV2.bat_key_id")?,
            secret_raw: decoder.fixed("BitcoinPirCashuBatProofV2.secret_raw")?,
            c: decoder.fixed("BitcoinPirCashuBatProofV2.c")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn presentation_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(BAT_V2_CREDENTIAL_PRESENTATION_DIGEST_DOMAIN_V2);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    /// Verifies only the signed class artifact and the wrapper's exact class
    /// coordinates. It does not verify the Cashu credential relation; issuer
    /// callers must use [`verify_bat_v2_credential_for_commit_v2`].
    pub fn verify_class_binding(
        &self,
        class: &BatAcceptanceClassV2,
    ) -> Result<(), ServiceProtocolError> {
        class.verify()?;
        if self.issuer_id != class.issuer_id
            || self.class_id != class.class_id
            || self.class_digest != class.class_digest()?
            || self.class_key_epoch != class.key_epoch
            || self.bat_key_id != class.bat_key_id()
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BitcoinPirCashuBatProofV2.class_binding",
                reason: "proof is not bound to the exact verified class and key epoch",
            });
        }
        Ok(())
    }

    pub fn spend_key(
        &self,
        bat_verification_key: &[u8; 33],
    ) -> Result<[u8; 32], ServiceProtocolError> {
        self.inner_v1()?.spend_key(bat_verification_key)
    }

    fn inner_v1(&self) -> Result<BitcoinPirCashuBatProofV1, ServiceProtocolError> {
        let value = BitcoinPirCashuBatProofV1 {
            secret_raw: self.secret_raw,
            c: self.c,
        };
        value.encode()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        require_nonzero(&self.issuer_id, "BitcoinPirCashuBatProofV2.issuer_id")?;
        require_nonzero(&self.class_id, "BitcoinPirCashuBatProofV2.class_id")?;
        require_nonzero(&self.class_digest, "BitcoinPirCashuBatProofV2.class_digest")?;
        require_nonzero(&self.bat_key_id, "BitcoinPirCashuBatProofV2.bat_key_id")?;
        if self.class_key_epoch == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BitcoinPirCashuBatProofV2.class_key_epoch",
                reason: "must be non-zero",
            });
        }
        self.inner_v1().map(|_| ())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderAccountingRuleV2 {
    pub class_id: [u8; 32],
    pub policy_digest: [u8; 32],
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub unit: SettlementUnitV1,
    pub accepted_value: u64,
    pub provider_credit: u64,
    pub issuer_fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderAccountingAuthorizationClaimsV2 {
    pub authorization_id: [u8; 16],
    pub authorization_epoch: u64,
    pub provider_id: ProviderId,
    pub issuer_id: [u8; 32],
    pub redeem_endpoint: String,
    pub redeem_leaf_spki_sha256_pins: Vec<[u8; 32]>,
    pub settlement_account_id: [u8; 32],
    pub clearing_verifying_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub rules: Vec<ProviderAccountingRuleV2>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderAccountingAuthorizationV2 {
    pub operator_verifying_key: [u8; 32],
    pub claims: ProviderAccountingAuthorizationClaimsV2,
    pub signature: [u8; 64],
}

impl ProviderAccountingAuthorizationV2 {
    pub fn sign(
        claims: ProviderAccountingAuthorizationClaimsV2,
        operator_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let mut value = Self {
            operator_verifying_key: operator_signing_key.verifying_key().to_bytes(),
            claims,
            signature: [0; 64],
        };
        value.validate()?;
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
        self.validate()?;
        if &self.claims.provider_id != expected_provider_id
            || &self.claims.issuer_id != expected_issuer_id
            || self.operator_verifying_key != expected_operator_key.to_bytes()
            || self.claims.authorization_epoch < minimum_authorization_epoch
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderAccountingAuthorizationV2.audience",
                reason: "provider, issuer, operator, or epoch does not match registration",
            });
        }
        if now_unix < self.claims.not_before || now_unix > self.claims.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderAccountingAuthorizationV2.validity",
                reason: "accounting authorization is not currently valid",
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
        if out.len() > MAX_BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_LEN_V2 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ProviderAccountingAuthorizationV2",
                len: out.len(),
                max: MAX_BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_LEN_V2,
            });
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_LEN_V2 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ProviderAccountingAuthorizationV2",
                len: bytes.len(),
                max: MAX_BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_LEN_V2,
            });
        }
        let mut decoder = Decoder::new(bytes);
        decode_v2_magic(
            &mut decoder,
            BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_CODEC_MAGIC_V2,
            "ProviderAccountingAuthorizationV2",
        )?;
        let operator_verifying_key =
            decoder.fixed("ProviderAccountingAuthorizationV2.operator_verifying_key")?;
        let authorization_id =
            decoder.fixed("ProviderAccountingAuthorizationV2.authorization_id")?;
        let authorization_epoch =
            decoder.u64("ProviderAccountingAuthorizationV2.authorization_epoch")?;
        let provider_id = decoder.fixed("ProviderAccountingAuthorizationV2.provider_id")?;
        let issuer_id = decoder.fixed("ProviderAccountingAuthorizationV2.issuer_id")?;
        let redeem_endpoint = decoder.string_u16(
            "ProviderAccountingAuthorizationV2.redeem_endpoint",
            MAX_ENDPOINT_LEN,
        )?;
        let pin_count = decoder.u8("ProviderAccountingAuthorizationV2.pin_count")? as usize;
        if pin_count > MAX_LEAF_SPKI_SHA256_PINS_V1 {
            return Err(ServiceProtocolError::TooManyItems {
                field: "ProviderAccountingAuthorizationV2.redeem_leaf_spki_sha256_pins",
                len: pin_count,
                max: MAX_LEAF_SPKI_SHA256_PINS_V1,
            });
        }
        let mut redeem_leaf_spki_sha256_pins = Vec::with_capacity(pin_count);
        for _ in 0..pin_count {
            redeem_leaf_spki_sha256_pins
                .push(decoder.fixed("ProviderAccountingAuthorizationV2.pin")?);
        }
        let settlement_account_id =
            decoder.fixed("ProviderAccountingAuthorizationV2.settlement_account_id")?;
        let clearing_verifying_key =
            decoder.fixed("ProviderAccountingAuthorizationV2.clearing_verifying_key")?;
        let not_before = decoder.u64("ProviderAccountingAuthorizationV2.not_before")?;
        let not_after = decoder.u64("ProviderAccountingAuthorizationV2.not_after")?;
        let rule_count = decoder.u8("ProviderAccountingAuthorizationV2.rule_count")? as usize;
        if rule_count > MAX_BAT_V2_ACCOUNTING_RULES_V2 {
            return Err(ServiceProtocolError::TooManyItems {
                field: "ProviderAccountingAuthorizationV2.rules",
                len: rule_count,
                max: MAX_BAT_V2_ACCOUNTING_RULES_V2,
            });
        }
        let mut rules = Vec::with_capacity(rule_count);
        for _ in 0..rule_count {
            rules.push(ProviderAccountingRuleV2 {
                class_id: decoder.fixed("ProviderAccountingRuleV2.class_id")?,
                policy_digest: decoder.fixed("ProviderAccountingRuleV2.policy_digest")?,
                scope_id: decoder.fixed("ProviderAccountingRuleV2.scope_id")?,
                offer_id: decoder.u32("ProviderAccountingRuleV2.offer_id")?,
                unit: SettlementUnitV1::decode(decoder.u8("ProviderAccountingRuleV2.unit")?)?,
                accepted_value: decoder.u64("ProviderAccountingRuleV2.accepted_value")?,
                provider_credit: decoder.u64("ProviderAccountingRuleV2.provider_credit")?,
                issuer_fee: decoder.u64("ProviderAccountingRuleV2.issuer_fee")?,
            });
        }
        let value = Self {
            operator_verifying_key,
            claims: ProviderAccountingAuthorizationClaimsV2 {
                authorization_id,
                authorization_epoch,
                provider_id,
                issuer_id,
                redeem_endpoint,
                redeem_leaf_spki_sha256_pins,
                settlement_account_id,
                clearing_verifying_key,
                not_before,
                not_after,
                rules,
            },
            signature: decoder.fixed("ProviderAccountingAuthorizationV2.signature")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn authorization_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_DIGEST_DOMAIN_V2);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    pub fn rule_for_member(
        &self,
        member: &BatAcceptanceMemberV2,
        class_id: &[u8; 32],
    ) -> Option<&ProviderAccountingRuleV2> {
        self.claims.rules.iter().find(|rule| {
            &rule.class_id == class_id
                && rule.policy_digest == member.policy_digest
                && rule.scope_id == member.scope_id
                && rule.offer_id == member.offer_id
        })
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut out = Vec::with_capacity(
            BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_SIGNATURE_DOMAIN_V2.len() + unsigned.len(),
        );
        out.extend_from_slice(BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_SIGNATURE_DOMAIN_V2);
        out.extend_from_slice(&unsigned);
        Ok(out)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let claims = &self.claims;
        let mut out = Vec::with_capacity(256 + claims.rules.len() * 125);
        begin_v2(
            &mut out,
            BAT_V2_PROVIDER_ACCOUNTING_AUTHORIZATION_CODEC_MAGIC_V2,
        );
        out.extend_from_slice(&self.operator_verifying_key);
        out.extend_from_slice(&claims.authorization_id);
        out.extend_from_slice(&claims.authorization_epoch.to_le_bytes());
        out.extend_from_slice(&claims.provider_id);
        out.extend_from_slice(&claims.issuer_id);
        put_bytes_u16(&mut out, claims.redeem_endpoint.as_bytes());
        out.push(claims.redeem_leaf_spki_sha256_pins.len() as u8);
        for pin in &claims.redeem_leaf_spki_sha256_pins {
            out.extend_from_slice(pin);
        }
        out.extend_from_slice(&claims.settlement_account_id);
        out.extend_from_slice(&claims.clearing_verifying_key);
        out.extend_from_slice(&claims.not_before.to_le_bytes());
        out.extend_from_slice(&claims.not_after.to_le_bytes());
        out.push(claims.rules.len() as u8);
        for rule in &claims.rules {
            out.extend_from_slice(&rule.class_id);
            out.extend_from_slice(&rule.policy_digest);
            out.extend_from_slice(&rule.scope_id);
            out.extend_from_slice(&rule.offer_id.to_le_bytes());
            out.push(rule.unit as u8);
            out.extend_from_slice(&rule.accepted_value.to_le_bytes());
            out.extend_from_slice(&rule.provider_credit.to_le_bytes());
            out.extend_from_slice(&rule.issuer_fee.to_le_bytes());
        }
        Ok(out)
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        let claims = &self.claims;
        require_nonzero(
            &claims.authorization_id,
            "ProviderAccountingAuthorizationV2.authorization_id",
        )?;
        require_nonzero(
            &claims.provider_id,
            "ProviderAccountingAuthorizationV2.provider_id",
        )?;
        require_nonzero(
            &claims.issuer_id,
            "ProviderAccountingAuthorizationV2.issuer_id",
        )?;
        require_nonzero(
            &claims.settlement_account_id,
            "ProviderAccountingAuthorizationV2.settlement_account_id",
        )?;
        if claims.authorization_epoch == 0 || claims.rules.is_empty() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderAccountingAuthorizationV2.claims",
                reason: "epoch and rule list must be non-zero",
            });
        }
        if !is_canonical_service_https_origin_v1(&claims.redeem_endpoint) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderAccountingAuthorizationV2.redeem_endpoint",
                reason: "must be one canonical HTTPS origin",
            });
        }
        validate_leaf_spki_sha256_pins_v1(
            &claims.redeem_leaf_spki_sha256_pins,
            "ProviderAccountingAuthorizationV2.redeem_leaf_spki_sha256_pins",
        )?;
        VerifyingKey::from_bytes(&self.operator_verifying_key)
            .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        VerifyingKey::from_bytes(&claims.clearing_verifying_key)
            .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        if claims.not_before > claims.not_after
            || claims.rules.len() > MAX_BAT_V2_ACCOUNTING_RULES_V2
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderAccountingAuthorizationV2.validity_or_rules",
                reason: "invalid validity interval or rule count",
            });
        }
        let mut previous: Option<&ProviderAccountingRuleV2> = None;
        for rule in &claims.rules {
            require_nonzero(&rule.class_id, "ProviderAccountingRuleV2.class_id")?;
            require_nonzero(
                &rule.policy_digest,
                "ProviderAccountingRuleV2.policy_digest",
            )?;
            require_nonzero(&rule.scope_id, "ProviderAccountingRuleV2.scope_id")?;
            if rule.offer_id == 0
                || rule.unit != SettlementUnitV1::AuthCredit
                || rule.accepted_value == 0
                || rule.accepted_value > MAX_SERVICE_VALUE_V1
                || rule.provider_credit == 0
                || rule.provider_credit.checked_add(rule.issuer_fee) != Some(rule.accepted_value)
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ProviderAccountingRuleV2",
                    reason: "must be an exact, value-conserving AuthCredit ledger rule",
                });
            }
            if previous.is_some_and(|prior| compare_accounting_rules(prior, rule) != Ordering::Less)
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ProviderAccountingAuthorizationV2.rules",
                    reason: "rules must be strictly sorted and unique by class and policy member",
                });
            }
            previous = Some(rule);
        }
        Ok(())
    }
}

fn compare_accounting_rules(
    left: &ProviderAccountingRuleV2,
    right: &ProviderAccountingRuleV2,
) -> Ordering {
    left.class_id
        .cmp(&right.class_id)
        .then_with(|| left.policy_digest.cmp(&right.policy_digest))
        .then_with(|| left.scope_id.cmp(&right.scope_id))
        .then_with(|| left.offer_id.cmp(&right.offer_id))
}

/// Issuer countersignature authorizing the exact operator accounting artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerAccountingApprovalV2 {
    pub issuer_settlement_key_id: [u8; 16],
    pub accounting_authorization_digest: [u8; 32],
    pub authorization_epoch: u64,
    pub approved_at: u64,
    pub not_after: u64,
    pub signature: [u8; 64],
}

impl IssuerAccountingApprovalV2 {
    pub fn sign(
        authorization: &ProviderAccountingAuthorizationV2,
        approved_at: u64,
        not_after: u64,
        issuer_settlement_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        if approved_at > not_after || not_after > authorization.claims.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerAccountingApprovalV2.validity",
                reason: "approval validity is empty or outlives operator authorization",
            });
        }
        let mut value = Self {
            issuer_settlement_key_id: issuer_settlement_key_id(
                &issuer_settlement_signing_key.verifying_key(),
            ),
            accounting_authorization_digest: authorization.authorization_digest()?,
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
        authorization: &ProviderAccountingAuthorizationV2,
        expected_issuer_settlement_key: &VerifyingKey,
        now_unix: u64,
        minimum_authorization_epoch: u64,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        if self.issuer_settlement_key_id != issuer_settlement_key_id(expected_issuer_settlement_key)
            || self.accounting_authorization_digest != authorization.authorization_digest()?
            || self.authorization_epoch != authorization.claims.authorization_epoch
            || self.authorization_epoch < minimum_authorization_epoch
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerAccountingApprovalV2.binding",
                reason: "issuer key, authorization digest, or epoch mismatch",
            });
        }
        if self.not_after > authorization.claims.not_after
            || now_unix < self.approved_at
            || now_unix > self.not_after
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerAccountingApprovalV2.validity",
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

    pub fn encode(&self) -> [u8; BAT_V2_ISSUER_ACCOUNTING_APPROVAL_LEN_V2] {
        let mut out = [0u8; BAT_V2_ISSUER_ACCOUNTING_APPROVAL_LEN_V2];
        out[..8].copy_from_slice(BAT_V2_ISSUER_ACCOUNTING_APPROVAL_CODEC_MAGIC_V2);
        out[8] = BAT_V2_REDEMPTION_WIRE_VERSION_V2;
        out[9..25].copy_from_slice(&self.issuer_settlement_key_id);
        out[25..57].copy_from_slice(&self.accounting_authorization_digest);
        out[57..65].copy_from_slice(&self.authorization_epoch.to_le_bytes());
        out[65..73].copy_from_slice(&self.approved_at.to_le_bytes());
        out[73..81].copy_from_slice(&self.not_after.to_le_bytes());
        out[81..].copy_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        decode_v2_magic(
            &mut decoder,
            BAT_V2_ISSUER_ACCOUNTING_APPROVAL_CODEC_MAGIC_V2,
            "IssuerAccountingApprovalV2",
        )?;
        let value = Self {
            issuer_settlement_key_id: decoder
                .fixed("IssuerAccountingApprovalV2.issuer_settlement_key_id")?,
            accounting_authorization_digest: decoder
                .fixed("IssuerAccountingApprovalV2.accounting_authorization_digest")?,
            authorization_epoch: decoder.u64("IssuerAccountingApprovalV2.authorization_epoch")?,
            approved_at: decoder.u64("IssuerAccountingApprovalV2.approved_at")?,
            not_after: decoder.u64("IssuerAccountingApprovalV2.not_after")?,
            signature: decoder.fixed("IssuerAccountingApprovalV2.signature")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    fn encode_unsigned(&self) -> [u8; 81] {
        let mut out = [0u8; 81];
        out[..8].copy_from_slice(BAT_V2_ISSUER_ACCOUNTING_APPROVAL_CODEC_MAGIC_V2);
        out[8] = BAT_V2_REDEMPTION_WIRE_VERSION_V2;
        out[9..25].copy_from_slice(&self.issuer_settlement_key_id);
        out[25..57].copy_from_slice(&self.accounting_authorization_digest);
        out[57..65].copy_from_slice(&self.authorization_epoch.to_le_bytes());
        out[65..73].copy_from_slice(&self.approved_at.to_le_bytes());
        out[73..81].copy_from_slice(&self.not_after.to_le_bytes());
        out
    }

    fn signing_preimage(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(BAT_V2_ISSUER_ACCOUNTING_APPROVAL_SIGNATURE_DOMAIN_V2.len() + 81);
        out.extend_from_slice(BAT_V2_ISSUER_ACCOUNTING_APPROVAL_SIGNATURE_DOMAIN_V2);
        out.extend_from_slice(&self.encode_unsigned());
        out
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        require_nonzero(
            &self.issuer_settlement_key_id,
            "IssuerAccountingApprovalV2.issuer_settlement_key_id",
        )?;
        require_nonzero(
            &self.accounting_authorization_digest,
            "IssuerAccountingApprovalV2.accounting_authorization_digest",
        )?;
        if self.authorization_epoch == 0 || self.approved_at > self.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "IssuerAccountingApprovalV2",
                reason: "invalid authorization epoch or validity",
            });
        }
        Ok(())
    }
}

/// Canonical V2 redeem request. `attempt_id` binds this one in-flight attempt;
/// it is explicitly not an idempotency or success-recovery key.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRedeemRequestV2 {
    pub accounting_authorization_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub policy_digest: [u8; 32],
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub class_id: [u8; 32],
    pub class_digest: [u8; 32],
    pub class_key_epoch: u64,
    pub bat_key_id: [u8; 32],
    pub credential_digest: [u8; 32],
    pub unit: SettlementUnitV1,
    pub accepted_value: u64,
    pub settlement_account_id: [u8; 32],
    pub attempt_id: [u8; 32],
}

impl fmt::Debug for ProviderRedeemRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRedeemRequestV2")
            .field("issuer_id", &self.issuer_id)
            .field("provider_id", &self.provider_id)
            .field("attempt_id", &self.attempt_id)
            .field("request", &"[REDACTED]")
            .finish()
    }
}

impl ProviderRedeemRequestV2 {
    pub fn prepare(
        authorization: &ProviderAccountingAuthorizationV2,
        member: &VerifiedBatAcceptanceMemberV2,
        class: &BatAcceptanceClassV2,
        proof: &BitcoinPirCashuBatProofV2,
        attempt_id: [u8; 32],
    ) -> Result<PreparedProviderRedeemRequestV2, ServiceProtocolError> {
        class.verify_for(&member.issuer_id, &member.class_id)?;
        proof.verify_class_binding(class)?;
        if member.member.provider_id != authorization.claims.provider_id
            || !class.members.contains(&member.member)
            || !member
                .common_terms
                .commercially_equivalent_to(&class.common_terms)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemRequestV2.member",
                reason: "verified member projection does not belong to authorization and class",
            });
        }
        let rule = authorization
            .rule_for_member(&member.member, &class.class_id)
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemRequestV2.accounting_rule",
                reason: "no exact class and policy-member accounting rule",
            })?;
        let value = Self {
            accounting_authorization_digest: authorization.authorization_digest()?,
            issuer_id: class.issuer_id,
            provider_id: member.member.provider_id,
            policy_digest: member.member.policy_digest,
            scope_id: member.member.scope_id,
            offer_id: member.member.offer_id,
            class_id: class.class_id,
            class_digest: class.class_digest()?,
            class_key_epoch: class.key_epoch,
            bat_key_id: class.bat_key_id(),
            credential_digest: proof.presentation_digest()?,
            unit: rule.unit,
            accepted_value: rule.accepted_value,
            settlement_account_id: authorization.claims.settlement_account_id,
            attempt_id,
        };
        value.validate()?;
        let in_flight = ProviderInFlightRedeemAttemptV2 {
            request_digest: value.request_digest()?,
            accounting_authorization_digest: value.accounting_authorization_digest,
            attempt_id: value.attempt_id,
            issuer_id: value.issuer_id,
            provider_id: value.provider_id,
            settlement_account_id: value.settlement_account_id,
            unit: value.unit,
            accepted_value: value.accepted_value,
            provider_credit: rule.provider_credit,
            issuer_fee: rule.issuer_fee,
        };
        Ok(PreparedProviderRedeemRequestV2 {
            request: value,
            in_flight,
        })
    }

    pub fn encode(
        &self,
    ) -> Result<[u8; BAT_V2_PROVIDER_REDEEM_REQUEST_LEN_V2], ServiceProtocolError> {
        self.validate()?;
        let mut out = [0u8; BAT_V2_PROVIDER_REDEEM_REQUEST_LEN_V2];
        out[..8].copy_from_slice(BAT_V2_PROVIDER_REDEEM_REQUEST_CODEC_MAGIC_V2);
        out[8] = BAT_V2_REDEMPTION_WIRE_VERSION_V2;
        let mut cursor = 9;
        for bytes in [
            self.accounting_authorization_digest.as_slice(),
            self.issuer_id.as_slice(),
            self.provider_id.as_slice(),
            self.policy_digest.as_slice(),
            self.scope_id.as_slice(),
        ] {
            out[cursor..cursor + 32].copy_from_slice(bytes);
            cursor += 32;
        }
        out[cursor..cursor + 4].copy_from_slice(&self.offer_id.to_le_bytes());
        cursor += 4;
        for bytes in [self.class_id.as_slice(), self.class_digest.as_slice()] {
            out[cursor..cursor + 32].copy_from_slice(bytes);
            cursor += 32;
        }
        out[cursor..cursor + 8].copy_from_slice(&self.class_key_epoch.to_le_bytes());
        cursor += 8;
        for bytes in [
            self.bat_key_id.as_slice(),
            self.credential_digest.as_slice(),
        ] {
            out[cursor..cursor + 32].copy_from_slice(bytes);
            cursor += 32;
        }
        out[cursor] = self.unit as u8;
        cursor += 1;
        out[cursor..cursor + 8].copy_from_slice(&self.accepted_value.to_le_bytes());
        cursor += 8;
        for bytes in [
            self.settlement_account_id.as_slice(),
            self.attempt_id.as_slice(),
        ] {
            out[cursor..cursor + 32].copy_from_slice(bytes);
            cursor += 32;
        }
        debug_assert_eq!(cursor, BAT_V2_PROVIDER_REDEEM_REQUEST_LEN_V2);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        decode_v2_magic(
            &mut decoder,
            BAT_V2_PROVIDER_REDEEM_REQUEST_CODEC_MAGIC_V2,
            "ProviderRedeemRequestV2",
        )?;
        let value = Self {
            accounting_authorization_digest: decoder
                .fixed("ProviderRedeemRequestV2.accounting_authorization_digest")?,
            issuer_id: decoder.fixed("ProviderRedeemRequestV2.issuer_id")?,
            provider_id: decoder.fixed("ProviderRedeemRequestV2.provider_id")?,
            policy_digest: decoder.fixed("ProviderRedeemRequestV2.policy_digest")?,
            scope_id: decoder.fixed("ProviderRedeemRequestV2.scope_id")?,
            offer_id: decoder.u32("ProviderRedeemRequestV2.offer_id")?,
            class_id: decoder.fixed("ProviderRedeemRequestV2.class_id")?,
            class_digest: decoder.fixed("ProviderRedeemRequestV2.class_digest")?,
            class_key_epoch: decoder.u64("ProviderRedeemRequestV2.class_key_epoch")?,
            bat_key_id: decoder.fixed("ProviderRedeemRequestV2.bat_key_id")?,
            credential_digest: decoder.fixed("ProviderRedeemRequestV2.credential_digest")?,
            unit: SettlementUnitV1::decode(decoder.u8("ProviderRedeemRequestV2.unit")?)?,
            accepted_value: decoder.u64("ProviderRedeemRequestV2.accepted_value")?,
            settlement_account_id: decoder
                .fixed("ProviderRedeemRequestV2.settlement_account_id")?,
            attempt_id: decoder.fixed("ProviderRedeemRequestV2.attempt_id")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(BAT_V2_PROVIDER_REDEEM_REQUEST_DIGEST_DOMAIN_V2);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        for (bytes, field) in [
            (
                &self.accounting_authorization_digest,
                "ProviderRedeemRequestV2.accounting_authorization_digest",
            ),
            (&self.issuer_id, "ProviderRedeemRequestV2.issuer_id"),
            (&self.provider_id, "ProviderRedeemRequestV2.provider_id"),
            (&self.policy_digest, "ProviderRedeemRequestV2.policy_digest"),
            (&self.scope_id, "ProviderRedeemRequestV2.scope_id"),
            (&self.class_id, "ProviderRedeemRequestV2.class_id"),
            (&self.class_digest, "ProviderRedeemRequestV2.class_digest"),
            (&self.bat_key_id, "ProviderRedeemRequestV2.bat_key_id"),
            (
                &self.credential_digest,
                "ProviderRedeemRequestV2.credential_digest",
            ),
            (
                &self.settlement_account_id,
                "ProviderRedeemRequestV2.settlement_account_id",
            ),
            (&self.attempt_id, "ProviderRedeemRequestV2.attempt_id"),
        ] {
            require_nonzero(bytes, field)?;
        }
        if self.offer_id == 0
            || self.class_key_epoch == 0
            || self.unit != SettlementUnitV1::AuthCredit
            || self.accepted_value == 0
            || self.accepted_value > MAX_SERVICE_VALUE_V1
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemRequestV2",
                reason: "offer, epoch, and bounded AuthCredit value must be non-zero",
            });
        }
        Ok(())
    }
}

/// Provider-side creation result. Splitting it is the only public way to
/// obtain the non-clone in-flight witness used to accept a grantable response.
pub struct PreparedProviderRedeemRequestV2 {
    request: ProviderRedeemRequestV2,
    in_flight: ProviderInFlightRedeemAttemptV2,
}

impl PreparedProviderRedeemRequestV2 {
    pub fn into_parts(self) -> (ProviderRedeemRequestV2, ProviderInFlightRedeemAttemptV2) {
        (self.request, self.in_flight)
    }
}

pub struct ProviderInFlightRedeemAttemptV2 {
    request_digest: [u8; 32],
    accounting_authorization_digest: [u8; 32],
    attempt_id: [u8; 32],
    issuer_id: [u8; 32],
    provider_id: ProviderId,
    settlement_account_id: [u8; 32],
    unit: SettlementUnitV1,
    accepted_value: u64,
    provider_credit: u64,
    issuer_fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRedeemRequestAuthV2 {
    pub accounting_authorization_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub attempt_id: [u8; 32],
    pub signature: [u8; 64],
}

impl ProviderRedeemRequestAuthV2 {
    pub fn sign(
        request: &ProviderRedeemRequestV2,
        clearing_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let mut value = Self {
            accounting_authorization_digest: request.accounting_authorization_digest,
            request_digest: request.request_digest()?,
            attempt_id: request.attempt_id,
            signature: [0; 64],
        };
        value.signature = clearing_signing_key
            .sign(&value.signing_preimage())
            .to_bytes();
        Ok(value)
    }

    pub fn verify_for(
        &self,
        request: &ProviderRedeemRequestV2,
        expected_clearing_key: &VerifyingKey,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        if self.accounting_authorization_digest != request.accounting_authorization_digest
            || self.request_digest != request.request_digest()?
            || self.attempt_id != request.attempt_id
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemRequestAuthV2.binding",
                reason: "authorization, request, or attempt binding mismatch",
            });
        }
        expected_clearing_key
            .verify_strict(
                &self.signing_preimage(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ServiceProtocolError::BadSignature)
    }

    pub fn encode(
        &self,
    ) -> Result<[u8; BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_LEN_V2], ServiceProtocolError> {
        self.validate()?;
        let mut out = [0u8; BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_LEN_V2];
        out[..8].copy_from_slice(BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_CODEC_MAGIC_V2);
        out[8] = BAT_V2_REDEMPTION_WIRE_VERSION_V2;
        out[9..41].copy_from_slice(&self.accounting_authorization_digest);
        out[41..73].copy_from_slice(&self.request_digest);
        out[73..105].copy_from_slice(&self.attempt_id);
        out[105..].copy_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        decode_v2_magic(
            &mut decoder,
            BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_CODEC_MAGIC_V2,
            "ProviderRedeemRequestAuthV2",
        )?;
        let value = Self {
            accounting_authorization_digest: decoder
                .fixed("ProviderRedeemRequestAuthV2.accounting_authorization_digest")?,
            request_digest: decoder.fixed("ProviderRedeemRequestAuthV2.request_digest")?,
            attempt_id: decoder.fixed("ProviderRedeemRequestAuthV2.attempt_id")?,
            signature: decoder.fixed("ProviderRedeemRequestAuthV2.signature")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    fn signing_preimage(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_SIGNATURE_DOMAIN_V2.len() + 105);
        out.extend_from_slice(BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_SIGNATURE_DOMAIN_V2);
        out.extend_from_slice(BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_CODEC_MAGIC_V2);
        out.push(BAT_V2_REDEMPTION_WIRE_VERSION_V2);
        out.extend_from_slice(&self.accounting_authorization_digest);
        out.extend_from_slice(&self.request_digest);
        out.extend_from_slice(&self.attempt_id);
        out
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        require_nonzero(
            &self.accounting_authorization_digest,
            "ProviderRedeemRequestAuthV2.accounting_authorization_digest",
        )?;
        require_nonzero(
            &self.request_digest,
            "ProviderRedeemRequestAuthV2.request_digest",
        )?;
        require_nonzero(&self.attempt_id, "ProviderRedeemRequestAuthV2.attempt_id")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRedeemEnvelopeV2 {
    pub request: ProviderRedeemRequestV2,
    pub request_auth: ProviderRedeemRequestAuthV2,
    pub credential: BitcoinPirCashuBatProofV2,
}

impl ProviderRedeemEnvelopeV2 {
    pub fn encode(
        &self,
    ) -> Result<[u8; BAT_V2_PROVIDER_REDEEM_ENVELOPE_LEN_V2], ServiceProtocolError> {
        let request = self.request.encode()?;
        let auth = self.request_auth.encode()?;
        let credential = self.credential.encode()?;
        let mut out = Vec::with_capacity(BAT_V2_PROVIDER_REDEEM_ENVELOPE_LEN_V2);
        begin_v2(&mut out, BAT_V2_PROVIDER_REDEEM_ENVELOPE_CODEC_MAGIC_V2);
        put_bytes_u32(&mut out, &request);
        put_bytes_u32(&mut out, &auth);
        put_bytes_u32(&mut out, &credential);
        out.try_into()
            .map_err(|value: Vec<u8>| ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemEnvelopeV2",
                reason: if value.len() == BAT_V2_PROVIDER_REDEEM_ENVELOPE_LEN_V2 {
                    "unreachable fixed-length conversion"
                } else {
                    "nested V2 wire lengths changed"
                },
            })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        decode_v2_magic(
            &mut decoder,
            BAT_V2_PROVIDER_REDEEM_ENVELOPE_CODEC_MAGIC_V2,
            "ProviderRedeemEnvelopeV2",
        )?;
        let request = ProviderRedeemRequestV2::decode(&decoder.bytes_u32(
            "ProviderRedeemEnvelopeV2.request",
            BAT_V2_PROVIDER_REDEEM_REQUEST_LEN_V2,
        )?)?;
        let request_auth = ProviderRedeemRequestAuthV2::decode(&decoder.bytes_u32(
            "ProviderRedeemEnvelopeV2.request_auth",
            BAT_V2_PROVIDER_REDEEM_REQUEST_AUTH_LEN_V2,
        )?)?;
        let credential = BitcoinPirCashuBatProofV2::decode(
            &decoder.bytes_u32("ProviderRedeemEnvelopeV2.credential", BAT_V2_PROOF_LEN_V2)?,
        )?;
        decoder.finish()?;
        if request.credential_digest != credential.presentation_digest()? {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemEnvelopeV2.credential_digest",
                reason: "request does not bind the exact credential presentation",
            });
        }
        Ok(Self {
            request,
            request_auth,
            credential,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RetrySafeNonConsumingReasonV2 {
    ProviderAuthentication = 1,
    AccountingTarget = 2,
    ClassCompatibility = 3,
}

impl RetrySafeNonConsumingReasonV2 {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::ProviderAuthentication),
            2 => Ok(Self::AccountingTarget),
            3 => Ok(Self::ClassCompatibility),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "RetrySafeNonConsumingReasonV2",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderRedeemOutcomeV2 {
    GrantableSuccess {
        account_id: [u8; 32],
        ledger_transaction_id: [u8; 32],
        unit: SettlementUnitV1,
        accepted_value: u64,
        provider_credit: u64,
        issuer_fee: u64,
    },
    RetrySafeNonConsuming {
        reason: RetrySafeNonConsumingReasonV2,
    },
    /// Unified terminal result for invalid proof, expiry, spent state, exact
    /// replay, cross-attempt/provider replay, and attempt conflict.
    TerminalInvalidOrSpent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRedeemResponseV2 {
    pub issuer_settlement_key_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub accounting_authorization_digest: [u8; 32],
    pub issuer_id: [u8; 32],
    pub provider_id: ProviderId,
    pub attempt_id: [u8; 32],
    pub outcome: ProviderRedeemOutcomeV2,
    pub signature: [u8; 64],
}

impl ProviderRedeemResponseV2 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ProviderRedeemResponseV2",
                len: out.len(),
                max: MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2,
            });
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ProviderRedeemResponseV2",
                len: bytes.len(),
                max: MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2,
            });
        }
        let mut decoder = Decoder::new(bytes);
        decode_v2_magic(
            &mut decoder,
            BAT_V2_PROVIDER_REDEEM_RESPONSE_CODEC_MAGIC_V2,
            "ProviderRedeemResponseV2",
        )?;
        let issuer_settlement_key_id =
            decoder.fixed("ProviderRedeemResponseV2.issuer_settlement_key_id")?;
        let request_digest = decoder.fixed("ProviderRedeemResponseV2.request_digest")?;
        let accounting_authorization_digest =
            decoder.fixed("ProviderRedeemResponseV2.accounting_authorization_digest")?;
        let issuer_id = decoder.fixed("ProviderRedeemResponseV2.issuer_id")?;
        let provider_id = decoder.fixed("ProviderRedeemResponseV2.provider_id")?;
        let attempt_id = decoder.fixed("ProviderRedeemResponseV2.attempt_id")?;
        let outcome = match decoder.u8("ProviderRedeemResponseV2.outcome")? {
            1 => ProviderRedeemOutcomeV2::GrantableSuccess {
                account_id: decoder.fixed("ProviderRedeemResponseV2.account_id")?,
                ledger_transaction_id: decoder
                    .fixed("ProviderRedeemResponseV2.ledger_transaction_id")?,
                unit: SettlementUnitV1::decode(decoder.u8("ProviderRedeemResponseV2.unit")?)?,
                accepted_value: decoder.u64("ProviderRedeemResponseV2.accepted_value")?,
                provider_credit: decoder.u64("ProviderRedeemResponseV2.provider_credit")?,
                issuer_fee: decoder.u64("ProviderRedeemResponseV2.issuer_fee")?,
            },
            2 => ProviderRedeemOutcomeV2::RetrySafeNonConsuming {
                reason: RetrySafeNonConsumingReasonV2::decode(
                    decoder.u8("ProviderRedeemResponseV2.retry_reason")?,
                )?,
            },
            3 => ProviderRedeemOutcomeV2::TerminalInvalidOrSpent,
            value => {
                return Err(ServiceProtocolError::UnknownDiscriminant {
                    kind: "ProviderRedeemOutcomeV2",
                    value,
                })
            }
        };
        let value = Self {
            issuer_settlement_key_id,
            request_digest,
            accounting_authorization_digest,
            issuer_id,
            provider_id,
            attempt_id,
            outcome,
            signature: decoder.fixed("ProviderRedeemResponseV2.signature")?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    /// Checks canonical binding and the issuer signature, but deliberately
    /// returns no capability to grant service.
    pub fn verify_for_exact_request(
        &self,
        request: &ProviderRedeemRequestV2,
        expected_issuer_settlement_key: &VerifyingKey,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        if self.issuer_settlement_key_id != issuer_settlement_key_id(expected_issuer_settlement_key)
            || self.request_digest != request.request_digest()?
            || self.accounting_authorization_digest != request.accounting_authorization_digest
            || self.issuer_id != request.issuer_id
            || self.provider_id != request.provider_id
            || self.attempt_id != request.attempt_id
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemResponseV2.binding",
                reason: "response is not for the exact issuer/provider request and attempt",
            });
        }
        expected_issuer_settlement_key
            .verify_strict(
                &self.signing_preimage()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ServiceProtocolError::BadSignature)
    }

    fn sign_terminal_invalid_or_spent(
        request: &ProviderRedeemRequestV2,
        issuer_settlement_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        Self::sign_outcome(
            request,
            ProviderRedeemOutcomeV2::TerminalInvalidOrSpent,
            issuer_settlement_signing_key,
        )
    }

    fn sign_retry_safe_non_consuming(
        rejection: VerifiedRetrySafeNonConsumingV2,
        issuer_settlement_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        Self::sign_outcome(
            &rejection.request,
            ProviderRedeemOutcomeV2::RetrySafeNonConsuming {
                reason: rejection.reason,
            },
            issuer_settlement_signing_key,
        )
    }

    fn sign_outcome(
        request: &ProviderRedeemRequestV2,
        outcome: ProviderRedeemOutcomeV2,
        issuer_settlement_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let mut value = Self {
            issuer_settlement_key_id: issuer_settlement_key_id(
                &issuer_settlement_signing_key.verifying_key(),
            ),
            request_digest: request.request_digest()?,
            accounting_authorization_digest: request.accounting_authorization_digest,
            issuer_id: request.issuer_id,
            provider_id: request.provider_id,
            attempt_id: request.attempt_id,
            outcome,
            signature: [0; 64],
        };
        value.validate()?;
        value.signature = issuer_settlement_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(MAX_BAT_V2_PROVIDER_REDEEM_RESPONSE_LEN_V2 - 64);
        begin_v2(&mut out, BAT_V2_PROVIDER_REDEEM_RESPONSE_CODEC_MAGIC_V2);
        out.extend_from_slice(&self.issuer_settlement_key_id);
        out.extend_from_slice(&self.request_digest);
        out.extend_from_slice(&self.accounting_authorization_digest);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.attempt_id);
        match &self.outcome {
            ProviderRedeemOutcomeV2::GrantableSuccess {
                account_id,
                ledger_transaction_id,
                unit,
                accepted_value,
                provider_credit,
                issuer_fee,
            } => {
                out.push(1);
                out.extend_from_slice(account_id);
                out.extend_from_slice(ledger_transaction_id);
                out.push(*unit as u8);
                out.extend_from_slice(&accepted_value.to_le_bytes());
                out.extend_from_slice(&provider_credit.to_le_bytes());
                out.extend_from_slice(&issuer_fee.to_le_bytes());
            }
            ProviderRedeemOutcomeV2::RetrySafeNonConsuming { reason } => {
                out.push(2);
                out.push(*reason as u8);
            }
            ProviderRedeemOutcomeV2::TerminalInvalidOrSpent => out.push(3),
        }
        Ok(out)
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut out = Vec::with_capacity(
            BAT_V2_PROVIDER_REDEEM_RESPONSE_SIGNATURE_DOMAIN_V2.len() + unsigned.len(),
        );
        out.extend_from_slice(BAT_V2_PROVIDER_REDEEM_RESPONSE_SIGNATURE_DOMAIN_V2);
        out.extend_from_slice(&unsigned);
        Ok(out)
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        require_nonzero(
            &self.issuer_settlement_key_id,
            "ProviderRedeemResponseV2.issuer_settlement_key_id",
        )?;
        require_nonzero(
            &self.request_digest,
            "ProviderRedeemResponseV2.request_digest",
        )?;
        require_nonzero(
            &self.accounting_authorization_digest,
            "ProviderRedeemResponseV2.accounting_authorization_digest",
        )?;
        require_nonzero(&self.issuer_id, "ProviderRedeemResponseV2.issuer_id")?;
        require_nonzero(&self.provider_id, "ProviderRedeemResponseV2.provider_id")?;
        require_nonzero(&self.attempt_id, "ProviderRedeemResponseV2.attempt_id")?;
        if let ProviderRedeemOutcomeV2::GrantableSuccess {
            account_id,
            ledger_transaction_id,
            unit,
            accepted_value,
            provider_credit,
            issuer_fee,
        } = &self.outcome
        {
            require_nonzero(account_id, "ProviderRedeemResponseV2.account_id")?;
            require_nonzero(
                ledger_transaction_id,
                "ProviderRedeemResponseV2.ledger_transaction_id",
            )?;
            if *unit != SettlementUnitV1::AuthCredit
                || *accepted_value == 0
                || *accepted_value > MAX_SERVICE_VALUE_V1
                || *provider_credit == 0
                || provider_credit.checked_add(*issuer_fee) != Some(*accepted_value)
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ProviderRedeemResponseV2.success",
                    reason: "success must be a non-zero, value-conserving AuthCredit result",
                });
            }
        }
        Ok(())
    }
}

pub struct VerifiedGrantableProviderRedeemSuccessV2 {
    response: ProviderRedeemResponseV2,
}

impl VerifiedGrantableProviderRedeemSuccessV2 {
    pub fn response(&self) -> &ProviderRedeemResponseV2 {
        &self.response
    }

    pub fn into_response(self) -> ProviderRedeemResponseV2 {
        self.response
    }
}

/// The only provider-side API which creates a grant capability. The in-flight
/// witness is consumed, so a decoded/generic response alone cannot grant.
pub fn verify_grantable_success_for_inflight_attempt_v2(
    response: ProviderRedeemResponseV2,
    request: &ProviderRedeemRequestV2,
    in_flight: ProviderInFlightRedeemAttemptV2,
    expected_issuer_settlement_key: &VerifyingKey,
) -> Result<VerifiedGrantableProviderRedeemSuccessV2, ServiceProtocolError> {
    response.verify_for_exact_request(request, expected_issuer_settlement_key)?;
    if in_flight.request_digest != request.request_digest()?
        || in_flight.accounting_authorization_digest != request.accounting_authorization_digest
        || in_flight.attempt_id != request.attempt_id
        || in_flight.issuer_id != request.issuer_id
        || in_flight.provider_id != request.provider_id
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ProviderInFlightRedeemAttemptV2",
            reason: "in-flight witness does not bind this exact request",
        });
    }
    match &response.outcome {
        ProviderRedeemOutcomeV2::GrantableSuccess {
            account_id,
            unit,
            accepted_value,
            provider_credit,
            issuer_fee,
            ..
        } if *account_id == in_flight.settlement_account_id
            && *unit == in_flight.unit
            && *accepted_value == in_flight.accepted_value
            && *provider_credit == in_flight.provider_credit
            && *issuer_fee == in_flight.issuer_fee =>
        {
            Ok(VerifiedGrantableProviderRedeemSuccessV2 { response })
        }
        ProviderRedeemOutcomeV2::GrantableSuccess { .. } => {
            Err(ServiceProtocolError::InvalidValue {
                field: "ProviderRedeemResponseV2.success_binding",
                reason: "grantable result does not match the requested account, unit, or value",
            })
        }
        _ => Err(ServiceProtocolError::InvalidValue {
            field: "ProviderRedeemResponseV2.outcome",
            reason: "only a grantable success may create a provider grant capability",
        }),
    }
}

pub struct ProviderAccountingExpectationV2<'a> {
    pub provider_id: ProviderId,
    pub issuer_id: [u8; 32],
    pub operator_verifying_key: &'a VerifyingKey,
    pub issuer_settlement_verifying_key: &'a VerifyingKey,
    pub now_unix: u64,
    pub minimum_authorization_epoch: u64,
}

pub enum BatV2RedeemPrecheckV2 {
    Authorized(Box<VerifiedProviderRedeemAuthorizationV2>),
    RetrySafeNonConsuming(VerifiedRetrySafeNonConsumingV2),
    TerminalInvalidOrSpent(VerifiedTerminalInvalidOrSpentV2),
}

pub struct VerifiedProviderRedeemAuthorizationV2 {
    envelope: ProviderRedeemEnvelopeV2,
    class: BatAcceptanceClassV2,
    rule: ProviderAccountingRuleV2,
}

pub struct VerifiedRetrySafeNonConsumingV2 {
    request: ProviderRedeemRequestV2,
    reason: RetrySafeNonConsumingReasonV2,
}

pub struct VerifiedTerminalInvalidOrSpentV2 {
    request: ProviderRedeemRequestV2,
}

/// Performs only definitive, non-mutating checks. A service/store must perform
/// its committed-attempt lookup before this function so an already committed
/// attempt remains terminal even after an authorization expires.
pub fn precheck_bat_v2_redeem_v2(
    envelope: ProviderRedeemEnvelopeV2,
    authorization: &ProviderAccountingAuthorizationV2,
    approval: &IssuerAccountingApprovalV2,
    class: &BatAcceptanceClassV2,
    member: &VerifiedBatAcceptanceMemberV2,
    expectation: ProviderAccountingExpectationV2<'_>,
) -> Result<BatV2RedeemPrecheckV2, ServiceProtocolError> {
    let request = &envelope.request;

    // Validate the registered artifacts and signatures independently of their
    // current time. Corrupt/rollback artifacts are protocol errors rather than
    // signed retry claims.
    if authorization.claims.not_before > authorization.claims.not_after
        || approval.approved_at > approval.not_after
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "BAT V2 accounting artifact validity",
            reason: "not_before is after not_after",
        });
    }
    let auth_signature_time = expectation.now_unix.clamp(
        authorization.claims.not_before,
        authorization.claims.not_after,
    );
    authorization.verify_for(
        &expectation.provider_id,
        &expectation.issuer_id,
        expectation.operator_verifying_key,
        auth_signature_time,
        expectation.minimum_authorization_epoch,
    )?;
    let approval_signature_time = expectation
        .now_unix
        .clamp(approval.approved_at, approval.not_after);
    approval.verify_for(
        authorization,
        expectation.issuer_settlement_verifying_key,
        approval_signature_time,
        expectation.minimum_authorization_epoch,
    )?;
    class.verify_for(&expectation.issuer_id, &member.class_id)?;

    if member.issuer_id != expectation.issuer_id
        || member.class_id != class.class_id
        || !member
            .common_terms
            .commercially_equivalent_to(&class.common_terms)
        || !class.members.contains(&member.member)
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "VerifiedBatAcceptanceMemberV2",
            reason: "retained member projection is inconsistent with the verified class",
        });
    }

    if expectation.now_unix < authorization.claims.not_before
        || expectation.now_unix > authorization.claims.not_after
        || expectation.now_unix < approval.approved_at
        || expectation.now_unix > approval.not_after
    {
        return Ok(BatV2RedeemPrecheckV2::RetrySafeNonConsuming(
            VerifiedRetrySafeNonConsumingV2 {
                request: request.clone(),
                reason: RetrySafeNonConsumingReasonV2::ProviderAuthentication,
            },
        ));
    }

    let clearing_key = VerifyingKey::from_bytes(&authorization.claims.clearing_verifying_key)
        .map_err(|_| ServiceProtocolError::BadPublicKey)?;
    if envelope
        .request_auth
        .verify_for(request, &clearing_key)
        .is_err()
        || request.provider_id != expectation.provider_id
        || request.issuer_id != expectation.issuer_id
        || request.accounting_authorization_digest != authorization.authorization_digest()?
    {
        return Ok(BatV2RedeemPrecheckV2::RetrySafeNonConsuming(
            VerifiedRetrySafeNonConsumingV2 {
                request: request.clone(),
                reason: RetrySafeNonConsumingReasonV2::ProviderAuthentication,
            },
        ));
    }

    if member.member.provider_id != expectation.provider_id
        || request.policy_digest != member.member.policy_digest
        || request.scope_id != member.member.scope_id
        || request.offer_id != member.member.offer_id
        || request.class_id != class.class_id
        || request.class_digest != class.class_digest()?
        || request.class_key_epoch != class.key_epoch
        || request.bat_key_id != class.bat_key_id()
    {
        return Ok(BatV2RedeemPrecheckV2::RetrySafeNonConsuming(
            VerifiedRetrySafeNonConsumingV2 {
                request: request.clone(),
                reason: RetrySafeNonConsumingReasonV2::ClassCompatibility,
            },
        ));
    }

    let Some(rule) = authorization.rule_for_member(&member.member, &class.class_id) else {
        return Ok(BatV2RedeemPrecheckV2::RetrySafeNonConsuming(
            VerifiedRetrySafeNonConsumingV2 {
                request: request.clone(),
                reason: RetrySafeNonConsumingReasonV2::AccountingTarget,
            },
        ));
    };
    if request.settlement_account_id != authorization.claims.settlement_account_id
        || request.unit != rule.unit
        || request.accepted_value != rule.accepted_value
    {
        return Ok(BatV2RedeemPrecheckV2::RetrySafeNonConsuming(
            VerifiedRetrySafeNonConsumingV2 {
                request: request.clone(),
                reason: RetrySafeNonConsumingReasonV2::AccountingTarget,
            },
        ));
    }

    if expectation.now_unix < member.policy_issued_at
        || expectation.now_unix > member.redemption_deadline
        || expectation.now_unix < class.key_not_before
        || expectation.now_unix > class.key_not_after
    {
        return Ok(BatV2RedeemPrecheckV2::TerminalInvalidOrSpent(
            VerifiedTerminalInvalidOrSpentV2 {
                request: request.clone(),
            },
        ));
    }

    Ok(BatV2RedeemPrecheckV2::Authorized(Box::new(
        VerifiedProviderRedeemAuthorizationV2 {
            envelope,
            class: class.clone(),
            rule: rule.clone(),
        },
    )))
}

pub fn sign_retry_safe_non_consuming_v2(
    rejection: VerifiedRetrySafeNonConsumingV2,
    issuer_settlement_signing_key: &SigningKey,
) -> Result<ProviderRedeemResponseV2, ServiceProtocolError> {
    ProviderRedeemResponseV2::sign_retry_safe_non_consuming(
        rejection,
        issuer_settlement_signing_key,
    )
}

pub fn sign_terminal_invalid_or_spent_v2(
    terminal: VerifiedTerminalInvalidOrSpentV2,
    issuer_settlement_signing_key: &SigningKey,
) -> Result<ProviderRedeemResponseV2, ServiceProtocolError> {
    ProviderRedeemResponseV2::sign_terminal_invalid_or_spent(
        &terminal.request,
        issuer_settlement_signing_key,
    )
}

pub struct BatV2ProofVerificationInputV2<'a> {
    pub secret_raw: &'a [u8; 32],
    pub c: &'a [u8; 33],
    pub bat_verification_key: &'a [u8; 33],
}

pub trait BatV2ProofVerifierV2 {
    type Error;

    /// `Ok(true)` is a valid BAT relation, `Ok(false)` is a definitive invalid
    /// proof, and `Err` is operational/outcome-unknown.
    fn verify_bat_v2_proof(
        &self,
        input: BatV2ProofVerificationInputV2<'_>,
    ) -> Result<bool, Self::Error>;
}

impl<F, E> BatV2ProofVerifierV2 for F
where
    F: for<'a> Fn(BatV2ProofVerificationInputV2<'a>) -> Result<bool, E>,
{
    type Error = E;

    fn verify_bat_v2_proof(
        &self,
        input: BatV2ProofVerificationInputV2<'_>,
    ) -> Result<bool, Self::Error> {
        self(input)
    }
}

pub enum BatV2CredentialCheckV2 {
    Verified(VerifiedBatV2RedeemCommitV2),
    TerminalInvalidOrSpent(VerifiedTerminalInvalidOrSpentV2),
}

#[derive(Debug)]
pub enum BatV2CredentialVerificationErrorV2<E> {
    Protocol(ServiceProtocolError),
    Verifier(E),
}

impl<E> From<ServiceProtocolError> for BatV2CredentialVerificationErrorV2<E> {
    fn from(value: ServiceProtocolError) -> Self {
        Self::Protocol(value)
    }
}

/// Performs the credential relation check and is the sole constructor for the
/// move-only issuer commit capability. Proof failure is a unified terminal
/// result; adapter/storage failures must not be passed through this verifier.
pub fn verify_bat_v2_credential_for_commit_v2<V: BatV2ProofVerifierV2>(
    authorized: VerifiedProviderRedeemAuthorizationV2,
    verifier: &V,
) -> Result<BatV2CredentialCheckV2, BatV2CredentialVerificationErrorV2<V::Error>> {
    let proof = &authorized.envelope.credential;
    let request = &authorized.envelope.request;
    let presentation_matches = proof
        .presentation_digest()
        .is_ok_and(|digest| digest == request.credential_digest);
    if proof.verify_class_binding(&authorized.class).is_err() || !presentation_matches {
        return Ok(BatV2CredentialCheckV2::TerminalInvalidOrSpent(
            VerifiedTerminalInvalidOrSpentV2 {
                request: request.clone(),
            },
        ));
    }
    match verifier.verify_bat_v2_proof(BatV2ProofVerificationInputV2 {
        secret_raw: &proof.secret_raw,
        c: &proof.c,
        bat_verification_key: &authorized.class.bat_verification_key,
    }) {
        Ok(true) => {}
        Ok(false) => {
            return Ok(BatV2CredentialCheckV2::TerminalInvalidOrSpent(
                VerifiedTerminalInvalidOrSpentV2 {
                    request: request.clone(),
                },
            ))
        }
        Err(error) => return Err(BatV2CredentialVerificationErrorV2::Verifier(error)),
    }
    let global_spend_key = proof.spend_key(&authorized.class.bat_verification_key)?;
    Ok(BatV2CredentialCheckV2::Verified(
        VerifiedBatV2RedeemCommitV2 {
            request: authorized.envelope.request,
            global_spend_key,
            provider_credit: authorized.rule.provider_credit,
            issuer_fee: authorized.rule.issuer_fee,
        },
    ))
}

/// Move-only fresh-commit authority. Its global spend key is deliberately
/// independent of provider, class, policy member, and attempt.
pub struct VerifiedBatV2RedeemCommitV2 {
    request: ProviderRedeemRequestV2,
    global_spend_key: [u8; 32],
    provider_credit: u64,
    issuer_fee: u64,
}

impl VerifiedBatV2RedeemCommitV2 {
    pub fn request(&self) -> &ProviderRedeemRequestV2 {
        &self.request
    }

    pub fn global_spend_key(&self) -> &[u8; 32] {
        &self.global_spend_key
    }

    pub fn provider_credit(&self) -> u64 {
        self.provider_credit
    }

    pub fn issuer_fee(&self) -> u64 {
        self.issuer_fee
    }
}

pub trait BatV2RedeemCommitStoreV2 {
    type Error;

    /// Returns whether this provider-local public attempt identifier was
    /// already committed. Services must perform this durable lookup before
    /// authorization/class prechecks so a committed attempt remains terminal
    /// after expiry or rotation. Store errors are outcome-unknown and must not
    /// produce a wire response.
    fn attempt_is_committed(&self, request: &ProviderRedeemRequestV2) -> Result<bool, Self::Error>;

    /// Atomically claim both the issuer-global spend key and the issuer-local
    /// `(provider_id, attempt_id)` pair, then persist the derived ledger
    /// transaction ID, credit, and exact signed initial success. Any uniqueness
    /// conflict returns `false` and must never expose or replay prior success.
    fn commit_fresh(
        &mut self,
        verified: &VerifiedBatV2RedeemCommitV2,
        signed_initial_success: &ProviderRedeemResponseV2,
    ) -> Result<bool, Self::Error>;
}

pub fn bat_v2_redeem_ledger_transaction_id_v2(
    request: &ProviderRedeemRequestV2,
) -> Result<[u8; 32], ServiceProtocolError> {
    let mut hasher = Sha256::new();
    hasher.update(BAT_V2_REDEEM_LEDGER_TRANSACTION_ID_DOMAIN_V2);
    hasher.update(request.issuer_id);
    hasher.update(request.request_digest()?);
    Ok(hasher.finalize().into())
}

pub struct FreshCommittedProviderRedeemV2 {
    response: ProviderRedeemResponseV2,
}

impl FreshCommittedProviderRedeemV2 {
    pub fn into_response(self) -> ProviderRedeemResponseV2 {
        self.response
    }
}

pub enum BatV2RedeemCommitResultV2 {
    FreshCommitted(FreshCommittedProviderRedeemV2),
    TerminalInvalidOrSpent(ProviderRedeemResponseV2),
}

#[derive(Debug)]
pub enum BatV2RedeemCommitErrorV2<E> {
    Protocol(ServiceProtocolError),
    Store(E),
}

impl<E> From<ServiceProtocolError> for BatV2RedeemCommitErrorV2<E> {
    fn from(value: ServiceProtocolError) -> Self {
        Self::Protocol(value)
    }
}

/// Produces a fresh signed terminal response only after a durable store lookup
/// confirms that the exact provider/attempt pair was already committed. A
/// negative lookup returns `None`; a store error is outcome-unknown and signs
/// nothing. This is the only pre-precheck entry point for committed attempts.
pub fn sign_terminal_if_attempt_committed_v2<S: BatV2RedeemCommitStoreV2>(
    request: &ProviderRedeemRequestV2,
    issuer_settlement_signing_key: &SigningKey,
    store: &S,
) -> Result<Option<ProviderRedeemResponseV2>, BatV2RedeemCommitErrorV2<S::Error>> {
    if !store
        .attempt_is_committed(request)
        .map_err(BatV2RedeemCommitErrorV2::Store)?
    {
        return Ok(None);
    }
    Ok(Some(
        ProviderRedeemResponseV2::sign_terminal_invalid_or_spent(
            request,
            issuer_settlement_signing_key,
        )?,
    ))
}

/// Signs a candidate success, then gives the store one atomic opportunity to
/// commit it. Only a fresh commit releases the success response. Store errors
/// are outcome-unknown and intentionally produce no wire response.
pub fn sign_and_commit_grantable_success_v2<S: BatV2RedeemCommitStoreV2>(
    verified: VerifiedBatV2RedeemCommitV2,
    issuer_settlement_signing_key: &SigningKey,
    store: &mut S,
) -> Result<BatV2RedeemCommitResultV2, BatV2RedeemCommitErrorV2<S::Error>> {
    let ledger_transaction_id = bat_v2_redeem_ledger_transaction_id_v2(&verified.request)?;
    let success = ProviderRedeemResponseV2::sign_outcome(
        &verified.request,
        ProviderRedeemOutcomeV2::GrantableSuccess {
            account_id: verified.request.settlement_account_id,
            ledger_transaction_id,
            unit: verified.request.unit,
            accepted_value: verified.request.accepted_value,
            provider_credit: verified.provider_credit,
            issuer_fee: verified.issuer_fee,
        },
        issuer_settlement_signing_key,
    )?;
    match store
        .commit_fresh(&verified, &success)
        .map_err(BatV2RedeemCommitErrorV2::Store)?
    {
        true => Ok(BatV2RedeemCommitResultV2::FreshCommitted(
            FreshCommittedProviderRedeemV2 { response: success },
        )),
        false => Ok(BatV2RedeemCommitResultV2::TerminalInvalidOrSpent(
            ProviderRedeemResponseV2::sign_terminal_invalid_or_spent(
                &verified.request,
                issuer_settlement_signing_key,
            )?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn accounting_authorization() -> ProviderAccountingAuthorizationV2 {
        ProviderAccountingAuthorizationV2::sign(
            ProviderAccountingAuthorizationClaimsV2 {
                authorization_id: [1; 16],
                authorization_epoch: 7,
                provider_id: [2; 32],
                issuer_id: [3; 32],
                redeem_endpoint: "https://issuer.invalid".into(),
                redeem_leaf_spki_sha256_pins: vec![[4; 32]],
                settlement_account_id: [5; 32],
                clearing_verifying_key: SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes(),
                not_before: 100,
                not_after: 1_000,
                rules: vec![ProviderAccountingRuleV2 {
                    class_id: [7; 32],
                    policy_digest: [8; 32],
                    scope_id: [9; 32],
                    offer_id: 10,
                    unit: SettlementUnitV1::AuthCredit,
                    accepted_value: 10,
                    provider_credit: 8,
                    issuer_fee: 2,
                }],
            },
            &SigningKey::from_bytes(&[11; 32]),
        )
        .unwrap()
    }

    fn proof() -> BitcoinPirCashuBatProofV2 {
        BitcoinPirCashuBatProofV2 {
            issuer_id: [3; 32],
            class_id: [7; 32],
            class_digest: [12; 32],
            class_key_epoch: 13,
            bat_key_id: [14; 32],
            secret_raw: [15; 32],
            c: point(16),
        }
    }

    fn request(credential_digest: [u8; 32]) -> ProviderRedeemRequestV2 {
        ProviderRedeemRequestV2 {
            accounting_authorization_digest: accounting_authorization()
                .authorization_digest()
                .unwrap(),
            issuer_id: [3; 32],
            provider_id: [2; 32],
            policy_digest: [8; 32],
            scope_id: [9; 32],
            offer_id: 10,
            class_id: [7; 32],
            class_digest: [12; 32],
            class_key_epoch: 13,
            bat_key_id: [14; 32],
            credential_digest,
            unit: SettlementUnitV1::AuthCredit,
            accepted_value: 10,
            settlement_account_id: [5; 32],
            attempt_id: [17; 32],
        }
    }

    fn in_flight(request: &ProviderRedeemRequestV2) -> ProviderInFlightRedeemAttemptV2 {
        ProviderInFlightRedeemAttemptV2 {
            request_digest: request.request_digest().unwrap(),
            accounting_authorization_digest: request.accounting_authorization_digest,
            attempt_id: request.attempt_id,
            issuer_id: request.issuer_id,
            provider_id: request.provider_id,
            settlement_account_id: request.settlement_account_id,
            unit: request.unit,
            accepted_value: request.accepted_value,
            provider_credit: 8,
            issuer_fee: 2,
        }
    }

    #[test]
    fn bat_v2_redemption_proof_wire_isolated_and_spend_key_is_global() {
        let first = proof();
        let mut rebound = proof();
        rebound.issuer_id = [18; 32];
        rebound.class_id = [19; 32];
        rebound.class_digest = [20; 32];
        rebound.class_key_epoch = 21;
        rebound.bat_key_id = [22; 32];

        let raw_key = point(23);
        assert_eq!(
            first.spend_key(&raw_key).unwrap(),
            rebound.spend_key(&raw_key).unwrap()
        );
        let encoded = first.encode().unwrap();
        assert_eq!(encoded.len(), BAT_V2_PROOF_LEN_V2);
        assert_eq!(BitcoinPirCashuBatProofV2::decode(&encoded).unwrap(), first);
        assert!(BitcoinPirCashuBatProofV1::decode(&encoded).is_err());
        let v1 = BitcoinPirCashuBatProofV1 {
            secret_raw: [15; 32],
            c: point(16),
        }
        .encode()
        .unwrap();
        assert!(BitcoinPirCashuBatProofV2::decode(&v1).is_err());
    }

    #[test]
    fn bat_v2_redemption_accounting_request_auth_and_envelope_are_canonical() {
        let authorization = accounting_authorization();
        let operator = SigningKey::from_bytes(&[11; 32]);
        authorization
            .verify_for(&[2; 32], &[3; 32], &operator.verifying_key(), 200, 7)
            .unwrap();
        let encoded_authorization = authorization.encode().unwrap();
        assert_eq!(
            ProviderAccountingAuthorizationV2::decode(&encoded_authorization).unwrap(),
            authorization
        );

        let settlement_key = SigningKey::from_bytes(&[24; 32]);
        let approval =
            IssuerAccountingApprovalV2::sign(&authorization, 150, 900, &settlement_key).unwrap();
        assert_eq!(
            approval.encode().len(),
            BAT_V2_ISSUER_ACCOUNTING_APPROVAL_LEN_V2
        );
        IssuerAccountingApprovalV2::decode(&approval.encode())
            .unwrap()
            .verify_for(&authorization, &settlement_key.verifying_key(), 200, 7)
            .unwrap();

        let credential = proof();
        let request = request(credential.presentation_digest().unwrap());
        assert_eq!(
            request.encode().unwrap().len(),
            BAT_V2_PROVIDER_REDEEM_REQUEST_LEN_V2
        );
        let clearing_key = SigningKey::from_bytes(&[6; 32]);
        let request_auth = ProviderRedeemRequestAuthV2::sign(&request, &clearing_key).unwrap();
        request_auth
            .verify_for(&request, &clearing_key.verifying_key())
            .unwrap();
        let envelope = ProviderRedeemEnvelopeV2 {
            request: request.clone(),
            request_auth: request_auth.clone(),
            credential,
        };
        let encoded = envelope.encode().unwrap();
        assert_eq!(encoded.len(), BAT_V2_PROVIDER_REDEEM_ENVELOPE_LEN_V2);
        assert_eq!(
            ProviderRedeemEnvelopeV2::decode(&encoded).unwrap(),
            envelope
        );

        let mut changed_attempt = request;
        changed_attempt.attempt_id[0] ^= 1;
        assert!(request_auth
            .verify_for(&changed_attempt, &clearing_key.verifying_key())
            .is_err());

        let mut unsorted_claims = authorization.claims.clone();
        let mut earlier = unsorted_claims.rules[0].clone();
        earlier.class_id = [6; 32];
        unsorted_claims.rules.push(earlier);
        assert!(ProviderAccountingAuthorizationV2::sign(unsorted_claims, &operator).is_err());
    }

    #[test]
    fn bat_v2_redemption_grant_requires_exact_inflight_accounting_split() {
        let request = request(proof().presentation_digest().unwrap());
        let settlement_key = SigningKey::from_bytes(&[24; 32]);
        let exact = ProviderRedeemResponseV2::sign_outcome(
            &request,
            ProviderRedeemOutcomeV2::GrantableSuccess {
                account_id: request.settlement_account_id,
                ledger_transaction_id: [25; 32],
                unit: request.unit,
                accepted_value: request.accepted_value,
                provider_credit: 8,
                issuer_fee: 2,
            },
            &settlement_key,
        )
        .unwrap();
        exact
            .verify_for_exact_request(&request, &settlement_key.verifying_key())
            .unwrap();
        let verified = verify_grantable_success_for_inflight_attempt_v2(
            exact,
            &request,
            in_flight(&request),
            &settlement_key.verifying_key(),
        )
        .unwrap();
        assert!(matches!(
            verified.response().outcome,
            ProviderRedeemOutcomeV2::GrantableSuccess { .. }
        ));

        let wrong_split = ProviderRedeemResponseV2::sign_outcome(
            &request,
            ProviderRedeemOutcomeV2::GrantableSuccess {
                account_id: request.settlement_account_id,
                ledger_transaction_id: [26; 32],
                unit: request.unit,
                accepted_value: request.accepted_value,
                provider_credit: 7,
                issuer_fee: 3,
            },
            &settlement_key,
        )
        .unwrap();
        wrong_split
            .verify_for_exact_request(&request, &settlement_key.verifying_key())
            .unwrap();
        assert!(verify_grantable_success_for_inflight_attempt_v2(
            wrong_split,
            &request,
            in_flight(&request),
            &settlement_key.verifying_key(),
        )
        .is_err());
    }

    struct CommitStore {
        lookup_result: Result<bool, &'static str>,
        result: Result<bool, &'static str>,
        saw_success: bool,
    }

    impl BatV2RedeemCommitStoreV2 for CommitStore {
        type Error = &'static str;

        fn attempt_is_committed(
            &self,
            _request: &ProviderRedeemRequestV2,
        ) -> Result<bool, Self::Error> {
            self.lookup_result
        }

        fn commit_fresh(
            &mut self,
            _verified: &VerifiedBatV2RedeemCommitV2,
            signed_initial_success: &ProviderRedeemResponseV2,
        ) -> Result<bool, Self::Error> {
            self.saw_success = matches!(
                signed_initial_success.outcome,
                ProviderRedeemOutcomeV2::GrantableSuccess { .. }
            );
            self.result
        }
    }

    #[test]
    fn bat_v2_redemption_committed_lookup_is_the_only_precheck_terminal_gate() {
        let settlement_key = SigningKey::from_bytes(&[24; 32]);
        let request = request(proof().presentation_digest().unwrap());
        let committed_store = CommitStore {
            lookup_result: Ok(true),
            result: Ok(false),
            saw_success: false,
        };
        let terminal =
            sign_terminal_if_attempt_committed_v2(&request, &settlement_key, &committed_store)
                .unwrap()
                .expect("a durable committed attempt must return a terminal response");
        assert_eq!(
            terminal.outcome,
            ProviderRedeemOutcomeV2::TerminalInvalidOrSpent
        );
        terminal
            .verify_for_exact_request(&request, &settlement_key.verifying_key())
            .unwrap();

        let fresh_store = CommitStore {
            lookup_result: Ok(false),
            result: Ok(false),
            saw_success: false,
        };
        assert!(
            sign_terminal_if_attempt_committed_v2(&request, &settlement_key, &fresh_store,)
                .unwrap()
                .is_none()
        );

        let failed_store = CommitStore {
            lookup_result: Err("database unavailable"),
            result: Ok(false),
            saw_success: false,
        };
        assert!(matches!(
            sign_terminal_if_attempt_committed_v2(&request, &settlement_key, &failed_store,),
            Err(BatV2RedeemCommitErrorV2::Store("database unavailable"))
        ));
    }

    fn verified_commit(request: ProviderRedeemRequestV2) -> VerifiedBatV2RedeemCommitV2 {
        VerifiedBatV2RedeemCommitV2 {
            request,
            global_spend_key: [27; 32],
            provider_credit: 8,
            issuer_fee: 2,
        }
    }

    #[test]
    fn bat_v2_redemption_commit_releases_success_once_and_errors_are_outcome_unknown() {
        let settlement_key = SigningKey::from_bytes(&[24; 32]);
        let request = request(proof().presentation_digest().unwrap());
        let mut fresh_store = CommitStore {
            lookup_result: Ok(false),
            result: Ok(true),
            saw_success: false,
        };
        let fresh = sign_and_commit_grantable_success_v2(
            verified_commit(request.clone()),
            &settlement_key,
            &mut fresh_store,
        )
        .unwrap();
        assert!(fresh_store.saw_success);
        let BatV2RedeemCommitResultV2::FreshCommitted(fresh) = fresh else {
            panic!("fresh commit must release success")
        };
        assert!(matches!(
            fresh.into_response().outcome,
            ProviderRedeemOutcomeV2::GrantableSuccess { .. }
        ));

        let mut spent_store = CommitStore {
            lookup_result: Ok(false),
            result: Ok(false),
            saw_success: false,
        };
        let spent = sign_and_commit_grantable_success_v2(
            verified_commit(request.clone()),
            &settlement_key,
            &mut spent_store,
        )
        .unwrap();
        let BatV2RedeemCommitResultV2::TerminalInvalidOrSpent(terminal) = spent else {
            panic!("non-fresh commit must not replay success")
        };
        assert_eq!(
            terminal.outcome,
            ProviderRedeemOutcomeV2::TerminalInvalidOrSpent
        );

        let mut failed_store = CommitStore {
            lookup_result: Ok(false),
            result: Err("database unavailable"),
            saw_success: false,
        };
        assert!(matches!(
            sign_and_commit_grantable_success_v2(
                verified_commit(request),
                &settlement_key,
                &mut failed_store,
            ),
            Err(BatV2RedeemCommitErrorV2::Store("database unavailable"))
        ));
    }
}
