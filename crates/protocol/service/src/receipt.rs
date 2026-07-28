//! Linkable direct-BOLT11 receipt capability.
//!
//! The payment sidecar may retain an invoice-to-receipt mapping, so this is a
//! deliberately lower-privacy method. The credential itself never contains an
//! invoice, payment hash, preimage, payer identifier, or routing data.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::codec::{expect_v1, Decoder};
use crate::{
    AuthScheme, ScopeId, ServiceProtocolError, VerifiedServiceOfferV1, SERVICE_PROTOCOL_VERSION,
};

pub const PAID_RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"BitcoinPIR/paid-receipt-signature/v1";
pub const PAID_RECEIPT_KEY_ID_DOMAIN: &[u8] = b"BitcoinPIR/paid-receipt-key-id/v1";
pub const PAID_RECEIPT_SPEND_DOMAIN: &[u8] = b"BitcoinPIR/paid-receipt-spend/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaidReceiptBindingV1 {
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub policy_digest: [u8; 32],
    pub entitlement_profile: u16,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PaidReceiptV1 {
    pub issuer_id: [u8; 32],
    pub key_id: [u8; 16],
    pub serial: [u8; 32],
    pub binding: PaidReceiptBindingV1,
    pub not_before: u64,
    pub not_after: u64,
    pub signature: [u8; 64],
}

impl fmt::Debug for PaidReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaidReceiptV1")
            .field("issuer_id", &"[REDACTED]")
            .field("key_id", &"[REDACTED]")
            .field("serial", &"[REDACTED]")
            .field("binding", &"[REDACTED]")
            .field("validity", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PaidReceiptV1 {
    fn drop(&mut self) {
        self.serial.zeroize();
        self.signature.zeroize();
    }
}

impl PaidReceiptV1 {
    pub fn sign(
        issuer_id: [u8; 32],
        serial: [u8; 32],
        binding: PaidReceiptBindingV1,
        not_before: u64,
        not_after: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let mut receipt = Self {
            issuer_id,
            key_id: paid_receipt_key_id(&signing_key.verifying_key()),
            serial,
            binding,
            not_before,
            not_after,
            signature: [0; 64],
        };
        receipt.validate()?;
        receipt.signature = signing_key.sign(&receipt.signing_preimage()?).to_bytes();
        Ok(receipt)
    }

    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        expected_issuer_id: &[u8; 32],
        expected: &PaidReceiptBindingV1,
        now_unix: u64,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        if &self.issuer_id != expected_issuer_id {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PaidReceiptV1.issuer_id",
                reason: "receipt issuer does not match the selected offer",
            });
        }
        if self.key_id != paid_receipt_key_id(verifying_key) {
            return Err(ServiceProtocolError::WrongSigningKeyId);
        }
        if &self.binding != expected {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PaidReceiptV1.binding",
                reason: "receipt does not match the selected scope/offer/policy/profile",
            });
        }
        if now_unix < self.not_before || now_unix > self.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PaidReceiptV1.validity",
                reason: "receipt is not currently valid",
            });
        }
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify_strict(&self.signing_preimage()?, &signature)
            .map_err(|_| ServiceProtocolError::BadSignature)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        Ok(std::mem::take(&mut *out))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("PaidReceiptV1.version")?;
        expect_v1(version, "PaidReceiptV1")?;
        let receipt = Self {
            issuer_id: decoder.fixed("PaidReceiptV1.issuer_id")?,
            key_id: decoder.fixed("PaidReceiptV1.key_id")?,
            serial: decoder.fixed("PaidReceiptV1.serial")?,
            binding: PaidReceiptBindingV1 {
                scope_id: decoder.fixed("PaidReceiptV1.scope_id")?,
                offer_id: decoder.u32("PaidReceiptV1.offer_id")?,
                policy_digest: decoder.fixed("PaidReceiptV1.policy_digest")?,
                entitlement_profile: decoder.u16("PaidReceiptV1.entitlement_profile")?,
            },
            not_before: decoder.u64("PaidReceiptV1.not_before")?,
            not_after: decoder.u64("PaidReceiptV1.not_after")?,
            signature: decoder.fixed("PaidReceiptV1.signature")?,
        };
        decoder.finish()?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// Provider-local durable uniqueness key. This is not a payment hash.
    pub fn spend_key(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PAID_RECEIPT_SPEND_DOMAIN);
        hasher.update(self.issuer_id);
        hasher.update(self.key_id);
        hasher.update(self.serial);
        hasher.finalize().into()
    }

    fn signing_preimage(&self) -> Result<Zeroizing<Vec<u8>>, ServiceProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut preimage = Zeroizing::new(Vec::with_capacity(
            PAID_RECEIPT_SIGNATURE_DOMAIN.len() + unsigned.len(),
        ));
        preimage.extend_from_slice(PAID_RECEIPT_SIGNATURE_DOMAIN);
        preimage.extend_from_slice(&unsigned);
        Ok(preimage)
    }

    fn encode_unsigned(&self) -> Result<Zeroizing<Vec<u8>>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Zeroizing::new(Vec::with_capacity(200));
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&self.serial);
        out.extend_from_slice(&self.binding.scope_id);
        out.extend_from_slice(&self.binding.offer_id.to_le_bytes());
        out.extend_from_slice(&self.binding.policy_digest);
        out.extend_from_slice(&self.binding.entitlement_profile.to_le_bytes());
        out.extend_from_slice(&self.not_before.to_le_bytes());
        out.extend_from_slice(&self.not_after.to_le_bytes());
        Ok(out)
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.issuer_id.iter().all(|byte| *byte == 0)
            || self.key_id.iter().all(|byte| *byte == 0)
            || self.serial.iter().all(|byte| *byte == 0)
            || self.binding.scope_id.iter().all(|byte| *byte == 0)
            || self.binding.offer_id == 0
            || self.binding.policy_digest.iter().all(|byte| *byte == 0)
            || self.binding.entitlement_profile == 0
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PaidReceiptV1.binding",
                reason: "issuer, key, serial, scope, offer, policy, and profile must be non-zero",
            });
        }
        if self.not_before > self.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PaidReceiptV1.validity",
                reason: "not_before is after not_after",
            });
        }
        Ok(())
    }
}

/// Verify a direct-payment receipt against an offer obtained only from a
/// successfully verified current policy or an exact retained policy in its
/// redemption grace. This is the integration-safe entry point: it verifies
/// the issuer-root delegation, delegated key, receipt, scope, profile, policy
/// digest, and all nested validity horizons together.
pub fn verify_paid_receipt_for_offer(
    receipt: &PaidReceiptV1,
    verified_offer: &VerifiedServiceOfferV1<'_>,
    now_unix: u64,
) -> Result<[u8; 32], ServiceProtocolError> {
    let scope = verified_offer.scope();
    let offer = verified_offer.offer();
    if offer.authorization != AuthScheme::Bolt11DirectReceiptV1 {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ServiceOfferV1.authorization",
            reason: "verified offer does not authorize direct BOLT11 receipts",
        });
    }
    if now_unix > verified_offer.redemption_deadline() {
        return Err(ServiceProtocolError::InvalidValue {
            field: "VerifiedServiceOfferV1.redemption_deadline",
            reason: "receipt redemption is outside the retained-policy grace",
        });
    }
    let binding = offer
        .credential_binding
        .as_ref()
        .ok_or(ServiceProtocolError::InvalidValue {
            field: "ServiceOfferV1.credential_binding",
            reason: "direct receipt offer has no delegated verification key",
        })?;
    binding.verify_signature()?;
    binding.check_validity(now_unix)?;
    if receipt.not_before < binding.claims.not_before
        || receipt.not_after > binding.claims.not_after
        || receipt.not_after > verified_offer.redemption_deadline()
    {
        return Err(ServiceProtocolError::InvalidValue {
            field: "PaidReceiptV1.validity",
            reason: "receipt outlives its delegated key or retained policy",
        });
    }
    let verifying_key_bytes: [u8; 32] = binding
        .claims
        .verification_key
        .as_slice()
        .try_into()
        .map_err(|_| ServiceProtocolError::InvalidValue {
            field: "CredentialKeyBindingV1.verification_key",
            reason: "direct receipt Ed25519 key must be 32 bytes",
        })?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| ServiceProtocolError::BadPublicKey)?;
    receipt.verify(
        &verifying_key,
        &offer.issuer_id,
        &PaidReceiptBindingV1 {
            scope_id: scope.scope_id(),
            offer_id: offer.offer_id,
            policy_digest: verified_offer.policy_digest(),
            entitlement_profile: scope.entitlement_profile,
        },
        now_unix,
    )?;
    Ok(receipt.spend_key())
}

pub fn paid_receipt_key_id(verifying_key: &VerifyingKey) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(PAID_RECEIPT_KEY_ID_DOMAIN);
    hasher.update(verifying_key.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    digest[..16].try_into().expect("fixed digest prefix")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AcquisitionMethod, AuthPaddingClassV1, BackendId, CredentialKeyBindingClaimsV1,
        CredentialKeyBindingV1, CredentialUnitV1, DatasetBindingV1, DeploymentStatus,
        EntitlementLimitsV1, FreeModeV1, PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1,
        ServiceOfferV1, ServicePolicyEpochFloorsV1, ServicePolicyV1, ServiceScopePolicyV1,
        ServiceScopeV1, VerificationMode, WorkloadId,
    };

    fn receipt() -> (PaidReceiptV1, PaidReceiptBindingV1, VerifyingKey) {
        let key = SigningKey::from_bytes(&[5; 32]);
        let binding = PaidReceiptBindingV1 {
            scope_id: [1; 32],
            offer_id: 9,
            policy_digest: [2; 32],
            entitlement_profile: 3,
        };
        let receipt =
            PaidReceiptV1::sign([4; 32], [6; 32], binding.clone(), 100, 200, &key).unwrap();
        (receipt, binding, key.verifying_key())
    }

    fn direct_receipt_policy() -> (ServicePolicyV1, SigningKey) {
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
        let receipt_key = SigningKey::from_bytes(&[5; 32]);
        let credential_key_id = paid_receipt_key_id(&receipt_key.verifying_key());
        let credential_binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id: scope.scope_id(),
                offer_id: 9,
                scheme: AuthScheme::Bolt11DirectReceiptV1,
                keyset_epoch: 1,
                entitlement_profile: 3,
                unit: CredentialUnitV1::Entitlement,
                amount: 1,
                presentation_limit: 1,
                not_before: 50,
                not_after: 1_500,
                credential_key_id: credential_key_id.to_vec(),
                verification_key: receipt_key.verifying_key().to_bytes().to_vec(),
            },
            &SigningKey::from_bytes(&[7; 32]),
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
            authorization: AuthScheme::Bolt11DirectReceiptV1,
            verification: VerificationMode::ProviderLocal,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::MilliSatoshi(1_000),
            issuer_id: credential_binding.issuer_id,
            key_id: credential_key_id.to_vec(),
            credential_binding: Some(credential_binding),
            cashu_mint_manifest: None,
            endpoint: "https://issuer.invalid".into(),
            invoice_expiry_seconds: 600,
            claim_window_seconds: 600,
            minimum_credential_validity_seconds: 100,
            retired_policy_grace_seconds: 1_300,
            credential_count: 1,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(PrivacyLeakageV1::DIRECT_PAYMENT_TO_SPEND)
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
        (policy, receipt_key)
    }

    #[test]
    fn paid_receipt_debug_redacts_bearer_and_type_zeroizes_on_drop() {
        assert!(core::mem::needs_drop::<PaidReceiptV1>());
        let (receipt, _, _) = receipt();
        let serial = format!("{:?}", receipt.serial);
        let signature = format!("{:?}", receipt.signature);
        let rendered = format!("{receipt:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&serial));
        assert!(!rendered.contains(&signature));
    }

    #[test]
    fn receipt_roundtrips_verifies_and_has_stable_spend_key() {
        let (receipt, binding, verifying) = receipt();
        receipt.verify(&verifying, &[4; 32], &binding, 150).unwrap();
        let decoded = PaidReceiptV1::decode(&receipt.encode().unwrap()).unwrap();
        assert_eq!(decoded, receipt);
        assert_eq!(decoded.spend_key(), receipt.spend_key());
    }

    #[test]
    fn receipt_binds_offer_policy_scope_profile_and_time() {
        let (receipt, mut binding, verifying) = receipt();
        binding.offer_id += 1;
        assert!(matches!(
            receipt.verify(&verifying, &[4; 32], &binding, 150),
            Err(ServiceProtocolError::InvalidValue {
                field: "PaidReceiptV1.binding",
                ..
            })
        ));
        assert!(receipt
            .verify(&verifying, &[4; 32], &receipt.binding, 99)
            .is_err());
        assert!(receipt
            .verify(&verifying, &[4; 32], &receipt.binding, 201)
            .is_err());
    }

    #[test]
    fn receipt_tampering_fails_signature() {
        let (mut receipt, binding, verifying) = receipt();
        receipt.serial[0] ^= 1;
        assert_eq!(
            receipt.verify(&verifying, &[4; 32], &binding, 150),
            Err(ServiceProtocolError::BadSignature)
        );
    }

    #[test]
    fn receipt_rejects_wrong_expected_issuer_even_with_same_key() {
        let (receipt, binding, verifying) = receipt();
        assert!(matches!(
            receipt.verify(&verifying, &[8; 32], &binding, 150),
            Err(ServiceProtocolError::InvalidValue {
                field: "PaidReceiptV1.issuer_id",
                ..
            })
        ));
    }

    #[test]
    fn composite_verifier_checks_delegation_policy_and_nested_horizons() {
        let (policy, receipt_key) = direct_receipt_policy();
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
        let scope_id = policy.scopes[0].scope.scope_id();
        let verified_offer = verified_policy.offer(&scope_id, 9).unwrap();
        let receipt_binding = PaidReceiptBindingV1 {
            scope_id,
            offer_id: 9,
            policy_digest: verified_policy.policy_digest(),
            entitlement_profile: 3,
        };
        let receipt = PaidReceiptV1::sign(
            policy.scopes[0].offers[0].issuer_id,
            [6; 32],
            receipt_binding.clone(),
            100,
            1_000,
            &receipt_key,
        )
        .unwrap();
        assert_eq!(
            verify_paid_receipt_for_offer(&receipt, &verified_offer, 150).unwrap(),
            receipt.spend_key()
        );

        let outliving = PaidReceiptV1::sign(
            policy.scopes[0].offers[0].issuer_id,
            [8; 32],
            receipt_binding,
            100,
            1_501,
            &receipt_key,
        )
        .unwrap();
        assert!(verify_paid_receipt_for_offer(&outliving, &verified_offer, 150).is_err());
    }
}
