//! Issuer-signed, provider/scope-specific credential-key delegation.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::codec::{expect_v1, put_bytes_u16, Decoder};
use crate::{AuthScheme, ProviderId, ScopeId, ServiceProtocolError, SERVICE_PROTOCOL_VERSION};

pub const MAX_CREDENTIAL_KEY_ID_LEN: usize = 64;
pub const MAX_CREDENTIAL_VERIFICATION_KEY_LEN: usize = 256;
pub const MAX_CREDENTIAL_BINDING_LEN: usize = 1_024;
pub const ISSUER_ID_DOMAIN: &[u8] = b"BitcoinPIR/issuer-id/v1";
pub const CREDENTIAL_BINDING_SIGNATURE_DOMAIN: &[u8] =
    b"BitcoinPIR/credential-key-binding-signature/v1";
pub const CREDENTIAL_BINDING_DIGEST_DOMAIN: &[u8] = b"BitcoinPIR/credential-key-binding-digest/v1";
pub const CREDENTIAL_REQUEST_CONTEXT_DOMAIN: &[u8] = b"BitcoinPIR/credential-request-context/v1";
pub const CREDENTIAL_PRESENTATION_CONTEXT_DOMAIN: &[u8] =
    b"BitcoinPIR/credential-presentation-context/v1";
pub const BAT_KEY_ID_DOMAIN: &[u8] = b"BitcoinPIR/cashu-bat-key-id/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CredentialUnitV1 {
    Entitlement = 1,
    Auth = 2,
}

impl CredentialUnitV1 {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::Entitlement),
            2 => Ok(Self::Auth),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "CredentialUnitV1",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialKeyBindingClaimsV1 {
    pub provider_id: ProviderId,
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub scheme: AuthScheme,
    pub keyset_epoch: u64,
    pub entitlement_profile: u16,
    pub unit: CredentialUnitV1,
    pub amount: u64,
    pub presentation_limit: u32,
    pub not_before: u64,
    pub not_after: u64,
    pub credential_key_id: Vec<u8>,
    pub verification_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialKeyBindingV1 {
    pub issuer_id: [u8; 32],
    pub issuer_verifying_key: [u8; 32],
    pub claims: CredentialKeyBindingClaimsV1,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialKeyBindingExpectationV1<'a> {
    pub issuer_id: &'a [u8; 32],
    pub provider_id: &'a ProviderId,
    pub scope_id: &'a ScopeId,
    pub offer_id: u32,
    pub scheme: AuthScheme,
    pub minimum_keyset_epoch: u64,
    pub entitlement_profile: u16,
    pub presentation_limit: u32,
    pub credential_key_id: &'a [u8],
}

impl CredentialKeyBindingV1 {
    pub fn sign(
        claims: CredentialKeyBindingClaimsV1,
        issuer_signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let issuer_verifying_key = issuer_signing_key.verifying_key().to_bytes();
        let mut value = Self {
            issuer_id: derive_issuer_id(&issuer_verifying_key),
            issuer_verifying_key,
            claims,
            signature: [0; 64],
        };
        value.validate_claims()?;
        value.signature = issuer_signing_key
            .sign(&value.signing_preimage()?)
            .to_bytes();
        Ok(value)
    }

    pub fn verify_for(
        &self,
        expected: &CredentialKeyBindingExpectationV1<'_>,
        now_unix: u64,
    ) -> Result<(), ServiceProtocolError> {
        self.verify_signature()?;
        let claims = &self.claims;
        if &self.issuer_id != expected.issuer_id
            || &claims.provider_id != expected.provider_id
            || &claims.scope_id != expected.scope_id
            || claims.offer_id != expected.offer_id
            || claims.scheme != expected.scheme
            || claims.keyset_epoch < expected.minimum_keyset_epoch
            || claims.entitlement_profile != expected.entitlement_profile
            || claims.presentation_limit != expected.presentation_limit
            || claims.credential_key_id.as_slice() != expected.credential_key_id
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.expected",
                reason: "issuer/audience/scope/offer/scheme/profile/key mismatch",
            });
        }
        self.check_validity(now_unix)
    }

    pub(crate) fn verify_signature(&self) -> Result<(), ServiceProtocolError> {
        self.validate_claims()?;
        if self.issuer_id != derive_issuer_id(&self.issuer_verifying_key) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.issuer_id",
                reason: "does not match issuer verifying key",
            });
        }
        let key = VerifyingKey::from_bytes(&self.issuer_verifying_key)
            .map_err(|_| ServiceProtocolError::BadPublicKey)?;
        key.verify_strict(
            &self.signing_preimage()?,
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| ServiceProtocolError::BadSignature)
    }

    pub(crate) fn check_validity(&self, now_unix: u64) -> Result<(), ServiceProtocolError> {
        if now_unix < self.claims.not_before || now_unix > self.claims.not_after {
            Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.validity",
                reason: "binding is not currently valid",
            })
        } else {
            Ok(())
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let mut out = self.encode_unsigned()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_CREDENTIAL_BINDING_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "CredentialKeyBindingV1",
                len: bytes.len(),
                max: MAX_CREDENTIAL_BINDING_LEN,
            });
        }
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("CredentialKeyBindingV1.version")?;
        expect_v1(version, "CredentialKeyBindingV1")?;
        let value = Self {
            issuer_id: decoder.fixed("CredentialKeyBindingV1.issuer_id")?,
            issuer_verifying_key: decoder.fixed("CredentialKeyBindingV1.issuer_verifying_key")?,
            claims: CredentialKeyBindingClaimsV1 {
                provider_id: decoder.fixed("CredentialKeyBindingV1.provider_id")?,
                scope_id: decoder.fixed("CredentialKeyBindingV1.scope_id")?,
                offer_id: decoder.u32("CredentialKeyBindingV1.offer_id")?,
                scheme: AuthScheme::decode(decoder.u8("CredentialKeyBindingV1.scheme")?)?,
                keyset_epoch: decoder.u64("CredentialKeyBindingV1.keyset_epoch")?,
                entitlement_profile: decoder.u16("CredentialKeyBindingV1.entitlement_profile")?,
                unit: CredentialUnitV1::decode(decoder.u8("CredentialKeyBindingV1.unit")?)?,
                amount: decoder.u64("CredentialKeyBindingV1.amount")?,
                presentation_limit: decoder.u32("CredentialKeyBindingV1.presentation_limit")?,
                not_before: decoder.u64("CredentialKeyBindingV1.not_before")?,
                not_after: decoder.u64("CredentialKeyBindingV1.not_after")?,
                credential_key_id: decoder.bytes_u8(
                    "CredentialKeyBindingV1.credential_key_id",
                    MAX_CREDENTIAL_KEY_ID_LEN,
                )?,
                verification_key: decoder.bytes_u16(
                    "CredentialKeyBindingV1.verification_key",
                    MAX_CREDENTIAL_VERIFICATION_KEY_LEN,
                )?,
            },
            signature: decoder.fixed("CredentialKeyBindingV1.signature")?,
        };
        decoder.finish()?;
        value.validate_claims()?;
        Ok(value)
    }

    pub fn binding_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(CREDENTIAL_BINDING_DIGEST_DOMAIN);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    pub fn request_context_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(CREDENTIAL_REQUEST_CONTEXT_DOMAIN);
        // Bind the complete issuer-signed delegation, not merely its claims.
        // Otherwise two issuers which accidentally reuse the same underlying
        // private-verification key and claims would share one ARC context.
        hasher.update(self.binding_digest()?);
        Ok(hasher.finalize().into())
    }

    pub fn presentation_context_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(CREDENTIAL_PRESENTATION_CONTEXT_DOMAIN);
        hasher.update(self.binding_digest()?);
        Ok(hasher.finalize().into())
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut out =
            Vec::with_capacity(CREDENTIAL_BINDING_SIGNATURE_DOMAIN.len() + unsigned.len());
        out.extend_from_slice(CREDENTIAL_BINDING_SIGNATURE_DOMAIN);
        out.extend_from_slice(&unsigned);
        Ok(out)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate_claims()?;
        let mut out = Vec::with_capacity(256);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.issuer_id);
        out.extend_from_slice(&self.issuer_verifying_key);
        out.extend_from_slice(&self.encode_claims()?);
        if out.len() + 64 > MAX_CREDENTIAL_BINDING_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "CredentialKeyBindingV1",
                len: out.len() + 64,
                max: MAX_CREDENTIAL_BINDING_LEN,
            });
        }
        Ok(out)
    }

    fn encode_claims(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate_claims()?;
        let claims = &self.claims;
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(&claims.provider_id);
        out.extend_from_slice(&claims.scope_id);
        out.extend_from_slice(&claims.offer_id.to_le_bytes());
        out.push(claims.scheme as u8);
        out.extend_from_slice(&claims.keyset_epoch.to_le_bytes());
        out.extend_from_slice(&claims.entitlement_profile.to_le_bytes());
        out.push(claims.unit as u8);
        out.extend_from_slice(&claims.amount.to_le_bytes());
        out.extend_from_slice(&claims.presentation_limit.to_le_bytes());
        out.extend_from_slice(&claims.not_before.to_le_bytes());
        out.extend_from_slice(&claims.not_after.to_le_bytes());
        out.push(claims.credential_key_id.len() as u8);
        out.extend_from_slice(&claims.credential_key_id);
        put_bytes_u16(&mut out, &claims.verification_key);
        Ok(out)
    }

    fn validate_claims(&self) -> Result<(), ServiceProtocolError> {
        let claims = &self.claims;
        if claims.provider_id.iter().all(|byte| *byte == 0)
            || claims.scope_id.iter().all(|byte| *byte == 0)
            || claims.offer_id == 0
            || claims.keyset_epoch == 0
            || claims.entitlement_profile == 0
            || claims.amount == 0
            || claims.presentation_limit == 0
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.claims",
                reason: "audience, IDs, epoch, amount, profile, and limit must be non-zero",
            });
        }
        if claims.not_before > claims.not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.validity",
                reason: "not_before is after not_after",
            });
        }
        if claims.credential_key_id.is_empty()
            || claims.credential_key_id.len() > MAX_CREDENTIAL_KEY_ID_LEN
        {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "CredentialKeyBindingV1.credential_key_id",
                len: claims.credential_key_id.len(),
                max: MAX_CREDENTIAL_KEY_ID_LEN,
            });
        }
        if claims.verification_key.is_empty()
            || claims.verification_key.len() > MAX_CREDENTIAL_VERIFICATION_KEY_LEN
        {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "CredentialKeyBindingV1.verification_key",
                len: claims.verification_key.len(),
                max: MAX_CREDENTIAL_VERIFICATION_KEY_LEN,
            });
        }
        let expected = match claims.scheme {
            AuthScheme::FreeV1 | AuthScheme::Bolt11DirectReceiptV1 => {
                (CredentialUnitV1::Entitlement, 32usize, true)
            }
            AuthScheme::BitcoinPirCashuBatV1 => (CredentialUnitV1::Auth, 33usize, true),
            AuthScheme::ArcV1Experimental => (CredentialUnitV1::Auth, 99usize, false),
            AuthScheme::CashuEcashV1 => {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "CredentialKeyBindingV1.scheme",
                    reason: "standard Cashu uses a mint/keyset policy binding",
                })
            }
        };
        if claims.unit != expected.0
            || claims.amount != 1
            || claims.verification_key.len() != expected.1
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.credential_parameters",
                reason: "unit, amount, or verification-key shape does not match scheme",
            });
        }
        if expected.2 && claims.presentation_limit != 1 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.presentation_limit",
                reason: "scheme is single-presentation",
            });
        }
        if claims.scheme == AuthScheme::ArcV1Experimental && claims.presentation_limit < 2 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.presentation_limit",
                reason: "experimental ARC draft-01 requires at least two presentations",
            });
        }
        if claims.scheme == AuthScheme::BitcoinPirCashuBatV1 {
            let key: [u8; 33] = claims.verification_key.as_slice().try_into().map_err(|_| {
                ServiceProtocolError::InvalidValue {
                    field: "CredentialKeyBindingV1.verification_key",
                    reason: "BAT verification key must be a compressed secp256k1 point",
                }
            })?;
            if !crate::cashu_manifest::is_valid_compressed_point(&key)
                || claims.credential_key_id.as_slice()
                    != derive_bat_key_id_v1(
                        &claims.provider_id,
                        &claims.scope_id,
                        claims.offer_id,
                        claims.entitlement_profile,
                        claims.keyset_epoch,
                        &key,
                    )
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "CredentialKeyBindingV1.bat_key",
                    reason: "invalid BAT point or non-canonical provider/scope key ID",
                });
            }
        }
        Ok(())
    }
}

pub fn derive_bat_key_id_v1(
    provider_id: &ProviderId,
    scope_id: &ScopeId,
    offer_id: u32,
    entitlement_profile: u16,
    keyset_epoch: u64,
    verification_key: &[u8; 33],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BAT_KEY_ID_DOMAIN);
    hasher.update(provider_id);
    hasher.update(scope_id);
    hasher.update(offer_id.to_le_bytes());
    hasher.update(entitlement_profile.to_le_bytes());
    hasher.update(keyset_epoch.to_le_bytes());
    hasher.update(verification_key);
    hasher.finalize().into()
}

pub fn derive_issuer_id(issuer_verifying_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ISSUER_ID_DOMAIN);
    hasher.update(issuer_verifying_key);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};

    fn bat_public_key() -> [u8; 33] {
        (ProjectivePoint::GENERATOR * Scalar::from(7u64))
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn binding() -> CredentialKeyBindingV1 {
        let key = SigningKey::from_bytes(&[7; 32]);
        let provider_id = [1; 32];
        let scope_id = [2; 32];
        let bat_public_key = bat_public_key();
        let credential_key_id =
            derive_bat_key_id_v1(&provider_id, &scope_id, 3, 5, 4, &bat_public_key).to_vec();
        CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id,
                scope_id,
                offer_id: 3,
                scheme: AuthScheme::BitcoinPirCashuBatV1,
                keyset_epoch: 4,
                entitlement_profile: 5,
                unit: CredentialUnitV1::Auth,
                amount: 1,
                presentation_limit: 1,
                not_before: 100,
                not_after: 200,
                credential_key_id,
                verification_key: bat_public_key.to_vec(),
            },
            &key,
        )
        .unwrap()
    }

    #[test]
    fn binding_roundtrips_and_verifies() {
        let value = binding();
        let expected = CredentialKeyBindingExpectationV1 {
            issuer_id: &value.issuer_id,
            provider_id: &value.claims.provider_id,
            scope_id: &value.claims.scope_id,
            offer_id: value.claims.offer_id,
            scheme: value.claims.scheme,
            minimum_keyset_epoch: value.claims.keyset_epoch,
            entitlement_profile: value.claims.entitlement_profile,
            presentation_limit: value.claims.presentation_limit,
            credential_key_id: &value.claims.credential_key_id,
        };
        value.verify_for(&expected, 150).unwrap();
        let decoded = CredentialKeyBindingV1::decode(&value.encode().unwrap()).unwrap();
        assert_eq!(decoded, value);
        decoded.verify_for(&expected, 150).unwrap();
        assert_eq!(
            decoded.request_context_digest().unwrap(),
            value.request_context_digest().unwrap()
        );
        assert_eq!(
            decoded.presentation_context_digest().unwrap(),
            value.presentation_context_digest().unwrap()
        );
        assert_ne!(
            value.request_context_digest().unwrap(),
            value.presentation_context_digest().unwrap()
        );

        let other_issuer =
            CredentialKeyBindingV1::sign(value.claims.clone(), &SigningKey::from_bytes(&[8; 32]))
                .unwrap();
        assert_ne!(
            value.request_context_digest().unwrap(),
            other_issuer.request_context_digest().unwrap()
        );
        assert_ne!(
            value.presentation_context_digest().unwrap(),
            other_issuer.presentation_context_digest().unwrap()
        );
    }

    #[test]
    fn arc_binding_rejects_unverifiable_single_presentation_limit() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let claims = CredentialKeyBindingClaimsV1 {
            provider_id: [1; 32],
            scope_id: [2; 32],
            offer_id: 3,
            scheme: AuthScheme::ArcV1Experimental,
            keyset_epoch: 4,
            entitlement_profile: 5,
            unit: CredentialUnitV1::Auth,
            amount: 1,
            presentation_limit: 1,
            not_before: 100,
            not_after: 200,
            credential_key_id: vec![6; 32],
            verification_key: vec![7; 99],
        };
        assert!(matches!(
            CredentialKeyBindingV1::sign(claims, &key),
            Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.presentation_limit",
                ..
            })
        ));
    }

    #[test]
    fn binding_rejects_tampering_time_and_standard_cashu() {
        let mut value = binding();
        value.claims.scope_id[0] ^= 1;
        assert!(value.verify_signature().is_err());

        let value = binding();
        assert!(value.check_validity(99).is_err());

        let mut claims = value.claims;
        claims.scheme = AuthScheme::CashuEcashV1;
        assert!(CredentialKeyBindingV1::sign(claims, &SigningKey::from_bytes(&[7; 32])).is_err());
    }
}
