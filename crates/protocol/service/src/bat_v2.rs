//! Issuer-wide BitcoinPIR Cashu BAT acceptance classes.
//!
//! A class identifier is allocated before providers sign policies that refer
//! to it. The issuer then signs the exact, canonical set of policy members and
//! one raw BAT verification key epoch. This ordering avoids a digest cycle
//! between provider policy signatures and the issuer class signature.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::codec::{put_bytes_u16, Decoder};
use crate::{
    derive_issuer_id, is_canonical_service_https_origin_v1, AuthPaddingClassV1, AuthScheme,
    BackendId, DatasetBindingV1, DeploymentStatus, EntitlementLimitsV1, PriceV1, PrivacyLeakageV1,
    ProviderId, ScopeId, ServiceProtocolError, ServiceScopeV1, VerifiedCurrentPolicyV1, WorkloadId,
    MAX_BITCOIN_MSAT_V1, MAX_BOLT11_CLAIM_WINDOW_SECONDS_V1,
    MAX_BOLT11_CREDENTIAL_VALIDITY_SECONDS_V1, MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1,
    MAX_CREDENTIALS_PER_ACQUISITION_V1, MAX_ENDPOINT_LEN,
};

pub const BAT_ACCEPTANCE_CLASS_CODEC_MAGIC_V2: &[u8; 8] = b"BPIRBAT2";
pub const BAT_ACCEPTANCE_CLASS_WIRE_VERSION_V2: u8 = 2;
pub const BAT_ACCEPTANCE_CLASS_SIGNATURE_DOMAIN_V2: &[u8] =
    b"BitcoinPIR/bat-acceptance-class-signature/v2";
pub const BAT_ACCEPTANCE_CLASS_DIGEST_DOMAIN_V2: &[u8] =
    b"BitcoinPIR/bat-acceptance-class-digest/v2";
pub const BAT_ACCEPTANCE_TERMS_DIGEST_DOMAIN_V2: &[u8] =
    b"BitcoinPIR/bat-acceptance-terms-digest/v2";
pub const BAT_ACCEPTANCE_KEY_ID_DOMAIN_V2: &[u8] = b"BitcoinPIR/cashu-bat-acceptance-key-id/v2";
pub const MAX_BAT_ACCEPTANCE_CLASS_MEMBERS_V2: usize = 4_096;
pub const MAX_BAT_ACCEPTANCE_TERMS_LEN_V2: usize = 2_048;
pub const MAX_BAT_ACCEPTANCE_CLASS_LEN_V2: usize = 512 * 1024;

pub type BatAcceptanceClassIdV2 = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatAcceptanceTermsV2 {
    pub auth_padding_class: AuthPaddingClassV1,
    pub backend: BackendId,
    pub workload: WorkloadId,
    pub protocol_version: u16,
    pub dataset: DatasetBindingV1,
    pub operation_profile: u16,
    pub entitlement_profile: u16,
    pub limits: EntitlementLimitsV1,
    pub priority_class: u16,
    pub deployment_status: DeploymentStatus,
    pub price_msat: u64,
    pub issuer_endpoint: String,
    pub invoice_expiry_seconds: u32,
    pub claim_window_seconds: u32,
    pub minimum_credential_validity_seconds: u32,
    pub retired_policy_grace_seconds: u32,
    pub credential_count: u32,
    pub credential_presentation_limit: u32,
    pub privacy_leakage: PrivacyLeakageV1,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BatAcceptanceMemberV2 {
    pub provider_id: ProviderId,
    pub policy_digest: [u8; 32],
    pub scope_id: ScopeId,
    pub offer_id: u32,
}

/// Owned projection of one live, verified provider policy member. Issuer-store
/// registration can retain this after the policy typestate borrow ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBatAcceptanceMemberV2 {
    pub issuer_id: [u8; 32],
    pub class_id: BatAcceptanceClassIdV2,
    pub member: BatAcceptanceMemberV2,
    pub common_terms: BatAcceptanceTermsV2,
    pub policy_issued_at: u64,
    pub policy_expires_at: u64,
    pub redemption_deadline: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatAcceptanceClassV2 {
    pub issuer_id: [u8; 32],
    pub issuer_verifying_key: [u8; 32],
    pub class_id: BatAcceptanceClassIdV2,
    pub key_epoch: u64,
    pub key_not_before: u64,
    pub key_not_after: u64,
    pub bat_verification_key: [u8; 33],
    pub common_terms: BatAcceptanceTermsV2,
    pub members: Vec<BatAcceptanceMemberV2>,
    pub signature: [u8; 64],
}

pub fn validate_bat_acceptance_class_id_v2(
    class_id: &BatAcceptanceClassIdV2,
) -> Result<(), ServiceProtocolError> {
    if class_id.iter().all(|byte| *byte == 0) {
        Err(ServiceProtocolError::InvalidValue {
            field: "BatAcceptanceClassV2.class_id",
            reason: "preallocated class ID must be non-zero",
        })
    } else {
        Ok(())
    }
}

pub fn derive_bat_acceptance_key_id_v2(
    issuer_id: &[u8; 32],
    class_id: &BatAcceptanceClassIdV2,
    key_epoch: u64,
    bat_verification_key: &[u8; 33],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BAT_ACCEPTANCE_KEY_ID_DOMAIN_V2);
    hasher.update(issuer_id);
    hasher.update(class_id);
    hasher.update(key_epoch.to_le_bytes());
    hasher.update(bat_verification_key);
    hasher.finalize().into()
}

pub fn bat_acceptance_member_from_verified_policy_v2(
    verified: &VerifiedCurrentPolicyV1<'_>,
    expected_scope_id: &ScopeId,
    offer_id: u32,
) -> Result<VerifiedBatAcceptanceMemberV2, ServiceProtocolError> {
    let selected = verified.offer(expected_scope_id, offer_id)?;
    let scope = selected.scope();
    let offer = selected.offer();
    if offer.authorization != AuthScheme::BitcoinPirCashuBatV2
        || offer.acquisition != crate::AcquisitionMethod::Bolt11V1
        || offer.verification != crate::VerificationMode::SharedIssuerOnline
        || offer.credential_binding.is_some()
        || offer.cashu_mint_manifest.is_some()
        || offer.credential_presentation_limit != 1
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ServiceOfferV1.bat_v2_class_binding",
            reason: "verified member is not an issuer-wide BAT V2 offer",
        });
    }
    let class_id: BatAcceptanceClassIdV2 =
        offer
            .key_id
            .as_slice()
            .try_into()
            .map_err(|_| ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.key_id",
                reason: "BAT V2 class ID must be exactly 32 bytes",
            })?;
    validate_bat_acceptance_class_id_v2(&class_id)?;
    let PriceV1::MilliSatoshi(price_msat) = &offer.price else {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ServiceOfferV1.price",
            reason: "BAT V2 uses a millisatoshi BOLT11 price",
        });
    };
    let common_terms = BatAcceptanceTermsV2 {
        auth_padding_class: verified.policy().auth_padding_class,
        backend: scope.backend,
        workload: scope.workload,
        protocol_version: scope.protocol_version,
        dataset: scope.dataset.clone(),
        operation_profile: scope.operation_profile,
        entitlement_profile: scope.entitlement_profile,
        limits: selected.limits().clone(),
        priority_class: offer.priority_class,
        deployment_status: offer.deployment_status,
        price_msat: *price_msat,
        issuer_endpoint: offer.endpoint.clone(),
        invoice_expiry_seconds: offer.invoice_expiry_seconds,
        claim_window_seconds: offer.claim_window_seconds,
        minimum_credential_validity_seconds: offer.minimum_credential_validity_seconds,
        retired_policy_grace_seconds: offer.retired_policy_grace_seconds,
        credential_count: offer.credential_count,
        credential_presentation_limit: offer.credential_presentation_limit,
        privacy_leakage: offer.privacy_leakage,
    };
    common_terms.validate()?;
    Ok(VerifiedBatAcceptanceMemberV2 {
        issuer_id: offer.issuer_id,
        class_id,
        member: BatAcceptanceMemberV2 {
            provider_id: scope.provider_id,
            policy_digest: verified.policy_digest(),
            scope_id: *expected_scope_id,
            offer_id,
        },
        common_terms,
        policy_issued_at: verified.policy().issued_at,
        policy_expires_at: verified.policy().expires_at,
        redemption_deadline: selected.redemption_deadline(),
    })
}

impl BatAcceptanceTermsV2 {
    pub fn validate(&self) -> Result<(), ServiceProtocolError> {
        ServiceScopeV1 {
            provider_id: [1; 32],
            backend: self.backend,
            workload: self.workload,
            protocol_version: self.protocol_version,
            dataset: self.dataset.clone(),
            operation_profile: self.operation_profile,
            entitlement_profile: self.entitlement_profile,
        }
        .validate()?;
        self.limits.validate()?;
        if self.priority_class == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceTermsV2.priority_class",
                reason: "must be non-zero",
            });
        }
        if self.price_msat == 0 || self.price_msat > MAX_BITCOIN_MSAT_V1 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceTermsV2.price_msat",
                reason: "must be non-zero and within the Bitcoin supply bound",
            });
        }
        if self.issuer_endpoint.len() > MAX_ENDPOINT_LEN
            || !is_canonical_service_https_origin_v1(&self.issuer_endpoint)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceTermsV2.issuer_endpoint",
                reason: "must be a bounded canonical HTTPS origin",
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
                field: "BatAcceptanceTermsV2.validity_windows",
                reason: "BOLT11 and credential windows must be non-zero and within protocol caps",
            });
        }
        let required_grace = self
            .invoice_expiry_seconds
            .checked_add(self.claim_window_seconds)
            .and_then(|value| value.checked_add(self.minimum_credential_validity_seconds))
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceTermsV2.retired_policy_grace_seconds",
                reason: "validity horizon overflow",
            })?;
        if self.retired_policy_grace_seconds < required_grace {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceTermsV2.retired_policy_grace_seconds",
                reason: "must cover invoice, claim, and credential horizons",
            });
        }
        if self.credential_count == 0
            || self.credential_count > MAX_CREDENTIALS_PER_ACQUISITION_V1
            || self.credential_presentation_limit != 1
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceTermsV2.credential_shape",
                reason: "credential count must be bounded and each BAT is single-presentation",
            });
        }
        let required_privacy = PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
            | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
            | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER;
        if !self.privacy_leakage.contains_all(required_privacy) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceTermsV2.privacy_leakage",
                reason: "flags understate issuer-wide BAT V2 leakage",
            });
        }
        Ok(())
    }

    pub fn terms_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(BAT_ACCEPTANCE_TERMS_DIGEST_DOMAIN_V2);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(160 + self.issuer_endpoint.len());
        out.push(self.auth_padding_class as u8);
        out.push(self.backend as u8);
        out.push(self.workload as u8);
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        self.dataset.encode_into(&mut out);
        out.extend_from_slice(&self.operation_profile.to_le_bytes());
        out.extend_from_slice(&self.entitlement_profile.to_le_bytes());
        self.limits.encode_into(&mut out)?;
        out.extend_from_slice(&self.priority_class.to_le_bytes());
        out.push(self.deployment_status as u8);
        out.extend_from_slice(&self.price_msat.to_le_bytes());
        put_bytes_u16(&mut out, self.issuer_endpoint.as_bytes());
        out.extend_from_slice(&self.invoice_expiry_seconds.to_le_bytes());
        out.extend_from_slice(&self.claim_window_seconds.to_le_bytes());
        out.extend_from_slice(&self.minimum_credential_validity_seconds.to_le_bytes());
        out.extend_from_slice(&self.retired_policy_grace_seconds.to_le_bytes());
        out.extend_from_slice(&self.credential_count.to_le_bytes());
        out.extend_from_slice(&self.credential_presentation_limit.to_le_bytes());
        out.extend_from_slice(&self.privacy_leakage.bits().to_le_bytes());
        if out.len() > MAX_BAT_ACCEPTANCE_TERMS_LEN_V2 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "BatAcceptanceTermsV2",
                len: out.len(),
                max: MAX_BAT_ACCEPTANCE_TERMS_LEN_V2,
            });
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_BAT_ACCEPTANCE_TERMS_LEN_V2 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "BatAcceptanceTermsV2",
                len: bytes.len(),
                max: MAX_BAT_ACCEPTANCE_TERMS_LEN_V2,
            });
        }
        let mut decoder = Decoder::new(bytes);
        let value = Self {
            auth_padding_class: AuthPaddingClassV1::decode(
                decoder.u8("BatAcceptanceTermsV2.auth_padding_class")?,
            )?,
            backend: BackendId::decode(decoder.u8("BatAcceptanceTermsV2.backend")?)?,
            workload: WorkloadId::decode(decoder.u8("BatAcceptanceTermsV2.workload")?)?,
            protocol_version: decoder.u16("BatAcceptanceTermsV2.protocol_version")?,
            dataset: DatasetBindingV1::decode_from(&mut decoder)?,
            operation_profile: decoder.u16("BatAcceptanceTermsV2.operation_profile")?,
            entitlement_profile: decoder.u16("BatAcceptanceTermsV2.entitlement_profile")?,
            limits: EntitlementLimitsV1::decode_from(&mut decoder)?,
            priority_class: decoder.u16("BatAcceptanceTermsV2.priority_class")?,
            deployment_status: DeploymentStatus::decode(
                decoder.u8("BatAcceptanceTermsV2.deployment_status")?,
            )?,
            price_msat: decoder.u64("BatAcceptanceTermsV2.price_msat")?,
            issuer_endpoint: decoder
                .string_u16("BatAcceptanceTermsV2.issuer_endpoint", MAX_ENDPOINT_LEN)?,
            invoice_expiry_seconds: decoder.u32("BatAcceptanceTermsV2.invoice_expiry_seconds")?,
            claim_window_seconds: decoder.u32("BatAcceptanceTermsV2.claim_window_seconds")?,
            minimum_credential_validity_seconds: decoder
                .u32("BatAcceptanceTermsV2.minimum_credential_validity_seconds")?,
            retired_policy_grace_seconds: decoder
                .u32("BatAcceptanceTermsV2.retired_policy_grace_seconds")?,
            credential_count: decoder.u32("BatAcceptanceTermsV2.credential_count")?,
            credential_presentation_limit: decoder
                .u32("BatAcceptanceTermsV2.credential_presentation_limit")?,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                decoder.u16("BatAcceptanceTermsV2.privacy_leakage")?,
            )?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }
}

impl BatAcceptanceClassV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        class_id: BatAcceptanceClassIdV2,
        key_epoch: u64,
        key_not_before: u64,
        key_not_after: u64,
        bat_verification_key: [u8; 33],
        common_terms: BatAcceptanceTermsV2,
        members: Vec<BatAcceptanceMemberV2>,
        issuer_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let issuer_verifying_key = issuer_signing_key.verifying_key().to_bytes();
        let mut value = Self {
            issuer_id: derive_issuer_id(&issuer_verifying_key),
            issuer_verifying_key,
            class_id,
            key_epoch,
            key_not_before,
            key_not_after,
            bat_verification_key,
            common_terms,
            members,
            signature: [0; 64],
        };
        value.validate()?;
        value.signature = issuer_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    pub fn verify(&self) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        let verifying_key = VerifyingKey::from_bytes(&self.issuer_verifying_key)
            .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        verifying_key
            .verify_strict(
                &self.signing_preimage()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| ServiceProtocolError::BadSignature)
    }

    pub fn verify_for(
        &self,
        expected_issuer_id: &[u8; 32],
        expected_class_id: &BatAcceptanceClassIdV2,
    ) -> Result<(), ServiceProtocolError> {
        self.verify()?;
        if &self.issuer_id != expected_issuer_id || &self.class_id != expected_class_id {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceClassV2.identity",
                reason: "issuer or preallocated class ID does not match",
            });
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_BAT_ACCEPTANCE_CLASS_LEN_V2 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "BatAcceptanceClassV2",
                len: out.len(),
                max: MAX_BAT_ACCEPTANCE_CLASS_LEN_V2,
            });
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_BAT_ACCEPTANCE_CLASS_LEN_V2 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "BatAcceptanceClassV2",
                len: bytes.len(),
                max: MAX_BAT_ACCEPTANCE_CLASS_LEN_V2,
            });
        }
        let mut decoder = Decoder::new(bytes);
        let magic: [u8; 8] = decoder.fixed("BatAcceptanceClassV2.magic")?;
        if &magic != BAT_ACCEPTANCE_CLASS_CODEC_MAGIC_V2 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceClassV2.magic",
                reason: "wrong BAT acceptance-class codec domain",
            });
        }
        let version = decoder.u8("BatAcceptanceClassV2.version")?;
        if version != BAT_ACCEPTANCE_CLASS_WIRE_VERSION_V2 {
            return Err(ServiceProtocolError::UnknownVersion {
                kind: "BatAcceptanceClassV2",
                version,
            });
        }
        let issuer_id = decoder.fixed("BatAcceptanceClassV2.issuer_id")?;
        let issuer_verifying_key = decoder.fixed("BatAcceptanceClassV2.issuer_verifying_key")?;
        let class_id = decoder.fixed("BatAcceptanceClassV2.class_id")?;
        let key_epoch = decoder.u64("BatAcceptanceClassV2.key_epoch")?;
        let key_not_before = decoder.u64("BatAcceptanceClassV2.key_not_before")?;
        let key_not_after = decoder.u64("BatAcceptanceClassV2.key_not_after")?;
        let bat_verification_key = decoder.fixed("BatAcceptanceClassV2.bat_verification_key")?;
        let common_terms = BatAcceptanceTermsV2::decode(&decoder.bytes_u16(
            "BatAcceptanceClassV2.common_terms",
            MAX_BAT_ACCEPTANCE_TERMS_LEN_V2,
        )?)?;
        let member_count = decoder.u32("BatAcceptanceClassV2.member_count")? as usize;
        if member_count > MAX_BAT_ACCEPTANCE_CLASS_MEMBERS_V2 {
            return Err(ServiceProtocolError::TooManyItems {
                field: "BatAcceptanceClassV2.members",
                len: member_count,
                max: MAX_BAT_ACCEPTANCE_CLASS_MEMBERS_V2,
            });
        }
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            members.push(BatAcceptanceMemberV2 {
                provider_id: decoder.fixed("BatAcceptanceMemberV2.provider_id")?,
                policy_digest: decoder.fixed("BatAcceptanceMemberV2.policy_digest")?,
                scope_id: decoder.fixed("BatAcceptanceMemberV2.scope_id")?,
                offer_id: decoder.u32("BatAcceptanceMemberV2.offer_id")?,
            });
        }
        let signature = decoder.fixed("BatAcceptanceClassV2.signature")?;
        decoder.finish()?;
        let value = Self {
            issuer_id,
            issuer_verifying_key,
            class_id,
            key_epoch,
            key_not_before,
            key_not_after,
            bat_verification_key,
            common_terms,
            members,
            signature,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn class_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(BAT_ACCEPTANCE_CLASS_DIGEST_DOMAIN_V2);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    pub fn bat_key_id(&self) -> [u8; 32] {
        derive_bat_acceptance_key_id_v2(
            &self.issuer_id,
            &self.class_id,
            self.key_epoch,
            &self.bat_verification_key,
        )
    }

    pub fn validate(&self) -> Result<(), ServiceProtocolError> {
        validate_bat_acceptance_class_id_v2(&self.class_id)?;
        if self.issuer_id != derive_issuer_id(&self.issuer_verifying_key) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceClassV2.issuer_id",
                reason: "does not derive from the embedded issuer verifying key",
            });
        }
        VerifyingKey::from_bytes(&self.issuer_verifying_key)
            .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        if self.key_epoch == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceClassV2.key_epoch",
                reason: "must be non-zero",
            });
        }
        if self.key_not_before > self.key_not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceClassV2.key_validity",
                reason: "not_before is after not_after",
            });
        }
        if !crate::cashu_manifest::is_valid_compressed_point(&self.bat_verification_key) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceClassV2.bat_verification_key",
                reason: "must be a compressed secp256k1 point",
            });
        }
        self.common_terms.validate()?;
        if self.members.is_empty() || self.members.len() > MAX_BAT_ACCEPTANCE_CLASS_MEMBERS_V2 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceClassV2.members",
                reason: "member list must be non-empty and bounded",
            });
        }
        let mut previous: Option<&BatAcceptanceMemberV2> = None;
        for member in &self.members {
            if member.provider_id.iter().all(|byte| *byte == 0)
                || member.policy_digest.iter().all(|byte| *byte == 0)
                || member.scope_id.iter().all(|byte| *byte == 0)
                || member.offer_id == 0
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "BatAcceptanceClassV2.members",
                    reason: "member identifiers and policy digest must be non-zero",
                });
            }
            if previous.is_some_and(|prior| prior >= member) {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "BatAcceptanceClassV2.members",
                    reason: "members must be strictly canonical-sorted without duplicates",
                });
            }
            previous = Some(member);
        }
        Ok(())
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut preimage =
            Vec::with_capacity(BAT_ACCEPTANCE_CLASS_SIGNATURE_DOMAIN_V2.len() + unsigned.len());
        preimage.extend_from_slice(BAT_ACCEPTANCE_CLASS_SIGNATURE_DOMAIN_V2);
        preimage.extend_from_slice(&unsigned);
        Ok(preimage)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let terms = self.common_terms.encode()?;
        let mut out = Vec::with_capacity(256 + terms.len() + self.members.len() * 100);
        out.extend_from_slice(BAT_ACCEPTANCE_CLASS_CODEC_MAGIC_V2);
        out.push(BAT_ACCEPTANCE_CLASS_WIRE_VERSION_V2);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.issuer_verifying_key);
        out.extend_from_slice(&self.class_id);
        out.extend_from_slice(&self.key_epoch.to_le_bytes());
        out.extend_from_slice(&self.key_not_before.to_le_bytes());
        out.extend_from_slice(&self.key_not_after.to_le_bytes());
        out.extend_from_slice(&self.bat_verification_key);
        put_bytes_u16(&mut out, &terms);
        out.extend_from_slice(&(self.members.len() as u32).to_le_bytes());
        for member in &self.members {
            out.extend_from_slice(&member.provider_id);
            out.extend_from_slice(&member.policy_digest);
            out.extend_from_slice(&member.scope_id);
            out.extend_from_slice(&member.offer_id.to_le_bytes());
        }
        if out.len() + 64 > MAX_BAT_ACCEPTANCE_CLASS_LEN_V2 {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "BatAcceptanceClassV2",
                len: out.len() + 64,
                max: MAX_BAT_ACCEPTANCE_CLASS_LEN_V2,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_bat_key_id_v1, AcquisitionMethod, CredentialKeyBindingClaimsV1,
        CredentialKeyBindingV1, CredentialUnitV1, FreeModeV1, PolicyRollbackGuardV1,
        ServiceOfferV1, ServicePolicyEpochFloorsV1, ServicePolicyV1, ServiceScopePolicyV1,
        VerificationMode,
    };
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

    fn limits() -> EntitlementLimitsV1 {
        EntitlementLimitsV1 {
            max_logical_inputs: 4,
            max_frames: 200,
            max_request_bytes: 1_000_000,
            max_response_bytes: 2_000_000,
            max_wall_time_ms: 60_000,
            max_concurrent_sockets: 1,
            max_hint_groups: 0,
            max_work_units: 9_000,
        }
    }

    fn scope(provider_id: ProviderId) -> ServiceScopeV1 {
        ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 2,
        }
    }

    fn v2_offer(_provider_scope: &ServiceScopeV1) -> ServiceOfferV1 {
        let issuer_key = SigningKey::from_bytes(&[8; 32]);
        ServiceOfferV1 {
            offer_id: 7,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::BitcoinPirCashuBatV2,
            verification: VerificationMode::SharedIssuerOnline,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::MilliSatoshi(2_000),
            issuer_id: derive_issuer_id(&issuer_key.verifying_key().to_bytes()),
            key_id: vec![0x42; 32],
            credential_binding: None,
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".into(),
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

    fn sign_policy_with_offer(
        provider_scope: ServiceScopeV1,
        offer: ServiceOfferV1,
    ) -> Result<ServicePolicyV1, ServiceProtocolError> {
        ServicePolicyV1::sign(
            provider_scope.provider_id,
            8,
            100,
            1_000,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope: provider_scope,
                limits: limits(),
                offers: vec![offer],
            }],
            &SigningKey::from_bytes(&[3; 32]),
        )
    }

    fn terms() -> BatAcceptanceTermsV2 {
        let provider_scope = scope([9; 32]);
        let offer = v2_offer(&provider_scope);
        BatAcceptanceTermsV2 {
            auth_padding_class: AuthPaddingClassV1::Class16KiB,
            backend: provider_scope.backend,
            workload: provider_scope.workload,
            protocol_version: provider_scope.protocol_version,
            dataset: provider_scope.dataset,
            operation_profile: provider_scope.operation_profile,
            entitlement_profile: provider_scope.entitlement_profile,
            limits: limits(),
            priority_class: offer.priority_class,
            deployment_status: offer.deployment_status,
            price_msat: 2_000,
            issuer_endpoint: offer.endpoint,
            invoice_expiry_seconds: offer.invoice_expiry_seconds,
            claim_window_seconds: offer.claim_window_seconds,
            minimum_credential_validity_seconds: offer.minimum_credential_validity_seconds,
            retired_policy_grace_seconds: offer.retired_policy_grace_seconds,
            credential_count: offer.credential_count,
            credential_presentation_limit: offer.credential_presentation_limit,
            privacy_leakage: offer.privacy_leakage,
        }
    }

    fn members() -> Vec<BatAcceptanceMemberV2> {
        vec![
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
        ]
    }

    fn signed_class() -> BatAcceptanceClassV2 {
        BatAcceptanceClassV2::sign(
            [0x42; 32],
            3,
            100,
            2_000,
            point(11),
            terms(),
            members(),
            &SigningKey::from_bytes(&[8; 32]),
        )
        .unwrap()
    }

    #[test]
    fn bat_v2_class_codec_signature_digest_and_key_id() {
        let value = signed_class();
        value.verify().unwrap();
        value.verify_for(&value.issuer_id, &value.class_id).unwrap();
        let encoded = value.encode().unwrap();
        let decoded = BatAcceptanceClassV2::decode(&encoded).unwrap();
        assert_eq!(decoded, value);
        decoded.verify().unwrap();
        assert_eq!(
            decoded.class_digest().unwrap(),
            value.class_digest().unwrap()
        );
        assert_eq!(
            decoded.bat_key_id(),
            derive_bat_acceptance_key_id_v2(
                &decoded.issuer_id,
                &decoded.class_id,
                decoded.key_epoch,
                &decoded.bat_verification_key,
            )
        );
        assert_ne!(decoded.bat_key_id(), [0; 32]);
        assert_ne!(decoded.common_terms.terms_digest().unwrap(), [0; 32]);

        let mut excessive_members = encoded;
        let terms_len_offset = 8 + 1 + 32 + 32 + 32 + (8 * 3) + 33;
        let terms_len = u16::from_le_bytes(
            excessive_members[terms_len_offset..terms_len_offset + 2]
                .try_into()
                .unwrap(),
        ) as usize;
        let member_count_offset = terms_len_offset + 2 + terms_len;
        excessive_members[member_count_offset..member_count_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            BatAcceptanceClassV2::decode(&excessive_members),
            Err(ServiceProtocolError::TooManyItems {
                field: "BatAcceptanceClassV2.members",
                ..
            })
        ));
    }

    #[test]
    fn bat_v2_rejects_noncanonical_members_and_tampering() {
        let mut unsorted = members();
        unsorted.reverse();
        assert!(BatAcceptanceClassV2::sign(
            [0x42; 32],
            3,
            100,
            2_000,
            point(11),
            terms(),
            unsorted,
            &SigningKey::from_bytes(&[8; 32]),
        )
        .is_err());

        let mut duplicate = members();
        duplicate.push(duplicate[1].clone());
        assert!(BatAcceptanceClassV2::sign(
            [0x42; 32],
            3,
            100,
            2_000,
            point(11),
            terms(),
            duplicate,
            &SigningKey::from_bytes(&[8; 32]),
        )
        .is_err());

        let mut tampered = signed_class();
        tampered.common_terms.price_msat += 1;
        assert_eq!(tampered.verify(), Err(ServiceProtocolError::BadSignature));

        let mut wrong_identity = signed_class();
        wrong_identity.issuer_id[0] ^= 1;
        assert!(matches!(
            wrong_identity.verify(),
            Err(ServiceProtocolError::InvalidValue {
                field: "BatAcceptanceClassV2.issuer_id",
                ..
            })
        ));

        assert!(BatAcceptanceClassV2::sign(
            [0; 32],
            3,
            100,
            2_000,
            point(11),
            terms(),
            members(),
            &SigningKey::from_bytes(&[8; 32]),
        )
        .is_err());
    }

    #[test]
    fn bat_v2_offer_and_verified_member_projection_are_exact() {
        let provider_scope = scope([9; 32]);
        let scope_id = provider_scope.scope_id();
        let policy =
            sign_policy_with_offer(provider_scope.clone(), v2_offer(&provider_scope)).unwrap();
        let provider_key = SigningKey::from_bytes(&[3; 32]);
        let verified = policy
            .verify_current_for_acquisition(
                &provider_scope.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &provider_key.verifying_key(),
            )
            .unwrap();
        let projected =
            bat_acceptance_member_from_verified_policy_v2(&verified, &scope_id, 7).unwrap();
        assert_eq!(projected.issuer_id, policy.scopes[0].offers[0].issuer_id);
        assert_eq!(projected.class_id, [0x42; 32]);
        assert_eq!(projected.member.provider_id, [9; 32]);
        assert_eq!(
            projected.member.policy_digest,
            policy.policy_digest().unwrap()
        );
        assert_eq!(projected.member.scope_id, scope_id);
        assert_eq!(projected.member.offer_id, 7);
        assert_eq!(projected.common_terms, terms());
        assert_eq!(projected.policy_issued_at, 100);
        assert_eq!(projected.policy_expires_at, 1_000);
        assert_eq!(projected.redemption_deadline, 1_480);
    }

    #[test]
    fn bat_v2_offer_rejects_v1_delegation_and_wrong_shape() {
        let provider_scope = scope([9; 32]);

        let mut wrong_verification = v2_offer(&provider_scope);
        wrong_verification.verification = VerificationMode::ProviderLocal;
        assert!(sign_policy_with_offer(provider_scope.clone(), wrong_verification).is_err());

        let mut wrong_class_id = v2_offer(&provider_scope);
        wrong_class_id.key_id.pop();
        assert!(sign_policy_with_offer(provider_scope.clone(), wrong_class_id).is_err());

        let mut multi_presentation = v2_offer(&provider_scope);
        multi_presentation.credential_presentation_limit = 2;
        assert!(sign_policy_with_offer(provider_scope.clone(), multi_presentation).is_err());

        let v1_key = point(11);
        let v1_key_id = derive_bat_key_id_v1(
            &provider_scope.provider_id,
            &provider_scope.scope_id(),
            7,
            provider_scope.entitlement_profile,
            1,
            &v1_key,
        );
        let v1_binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id: provider_scope.provider_id,
                scope_id: provider_scope.scope_id(),
                offer_id: 7,
                scheme: AuthScheme::BitcoinPirCashuBatV1,
                keyset_epoch: 1,
                entitlement_profile: provider_scope.entitlement_profile,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 1,
                not_before: 50,
                not_after: 1_480,
                credential_key_id: v1_key_id.to_vec(),
                verification_key: v1_key.to_vec(),
            },
            &SigningKey::from_bytes(&[8; 32]),
        )
        .unwrap();
        let mut v1_delegated = v2_offer(&provider_scope);
        v1_delegated.credential_binding = Some(v1_binding);
        assert!(sign_policy_with_offer(provider_scope, v1_delegated).is_err());

        let rejected_v2_binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id: [9; 32],
                scope_id: [10; 32],
                offer_id: 7,
                scheme: AuthScheme::BitcoinPirCashuBatV2,
                keyset_epoch: 1,
                entitlement_profile: 2,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 1,
                not_before: 50,
                not_after: 1_480,
                credential_key_id: vec![0x42; 32],
                verification_key: point(11).to_vec(),
            },
            &SigningKey::from_bytes(&[8; 32]),
        );
        assert!(matches!(
            rejected_v2_binding,
            Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.scheme",
                ..
            })
        ));
    }

    fn v1_golden_policy() -> ServicePolicyV1 {
        let provider_scope = scope([9; 32]);
        let verification_key = point(11);
        let credential_key_id = derive_bat_key_id_v1(
            &provider_scope.provider_id,
            &provider_scope.scope_id(),
            7,
            provider_scope.entitlement_profile,
            1,
            &verification_key,
        )
        .to_vec();
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id: provider_scope.provider_id,
                scope_id: provider_scope.scope_id(),
                offer_id: 7,
                scheme: AuthScheme::BitcoinPirCashuBatV1,
                keyset_epoch: 1,
                entitlement_profile: provider_scope.entitlement_profile,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 1,
                not_before: 50,
                not_after: 173_600,
                credential_key_id: credential_key_id.clone(),
                verification_key: verification_key.to_vec(),
            },
            &SigningKey::from_bytes(&[8; 32]),
        )
        .unwrap();
        let offer = ServiceOfferV1 {
            offer_id: 7,
            acquisition: AcquisitionMethod::Bolt11V1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::BitcoinPirCashuBatV1,
            verification: VerificationMode::SharedIssuerOnline,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::MilliSatoshi(2_000),
            issuer_id: binding.issuer_id,
            key_id: credential_key_id,
            credential_binding: Some(binding),
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".into(),
            invoice_expiry_seconds: 600,
            claim_window_seconds: 86_400,
            minimum_credential_validity_seconds: 86_400,
            retired_policy_grace_seconds: 173_400,
            credential_count: 10,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                    | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .unwrap(),
        };
        ServicePolicyV1::sign(
            provider_scope.provider_id,
            8,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope: provider_scope,
                limits: limits(),
                offers: vec![offer],
            }],
            &SigningKey::from_bytes(&[3; 32]),
        )
        .unwrap()
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }

    #[test]
    fn bat_v2_v1_signed_policy_bytes_and_digest_golden() {
        const EXPECTED_POLICY_HEX: &str = "01090909090909090909090909090909090909090909090909090909090909090908000000000000006400000000000000c80000000000000001012c0001090909090909090909090909090909090909090909090909090909090909090901010100010100010002000400c800000040420f000000000080841e000000000060ea0000010000282300000000000001c501070000000200000000000000000000010004020102d0070000000000003aab74cb18daa3a6c0f76b81213f9e3f80aa19b5a39dcfda63b2832f9906fb7a20159ce3e88cead7043d67c1392dba945e7d3733735a66e8cc364191bd61ebeff6013101013aab74cb18daa3a6c0f76b81213f9e3f80aa19b5a39dcfda63b2832f9906fb7a1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca0909090909090909090909090909090909090909090909090909090909090909a7a70edebede938c46c4e867a8850308401981d5035dfc04ab8dbcb27f0e02a707000000040100000000000000020002010000000000000001000000320000000000000020a602000000000020159ce3e88cead7043d67c1392dba945e7d3733735a66e8cc364191bd61ebeff6210003774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb1d7dbd76a08307b7d95b7fd7196e87d39c76165e1089f7b1c3dbcafd86457fb41dab56dc96293bfaea8db36481c5f76c18a18d4bbd51bebbe39ba87adc3dd00500160068747470733a2f2f6973737565722e696e76616c696458020000805101008051010058a502000a000000010000001c00d9b115c08cdf9b332b91ca2b6a951913ccdf7a90a968e681cf54e717aff0bc9bdf9c12fb9dedcc1fe535452602a5ade2de38a29b262cd62ad932cffdc1394fbff84ceb729fe2b39b8789f8846418300e";
        const EXPECTED_DIGEST_HEX: &str =
            "b14880fc4fedc792914693a4eb36f00a789c4b18b849cffec0539044a54ff54d";
        let policy = v1_golden_policy();
        let encoded = policy.encode().unwrap();
        let digest = policy.policy_digest().unwrap();
        assert_eq!(hex_lower(&encoded), EXPECTED_POLICY_HEX);
        assert_eq!(hex_lower(&digest), EXPECTED_DIGEST_HEX);
    }
}
