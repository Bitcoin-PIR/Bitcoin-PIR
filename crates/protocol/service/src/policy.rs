//! Signed provider service policy and commercial offers.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::challenge::MAX_POW_DIFFICULTY_BITS_V1;
use crate::codec::{expect_v1, put_bytes_u16, Decoder};
use crate::quote::{
    MAX_BOLT11_CLAIM_WINDOW_SECONDS_V1, MAX_BOLT11_CREDENTIAL_VALIDITY_SECONDS_V1,
    MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1,
};
use crate::{
    derive_cashu_mint_id, free_anonymous_ticket_key_id, paid_receipt_key_id, AuthScheme,
    CredentialKeyBindingExpectationV1, CredentialKeyBindingV1, ProviderId, ServiceProtocolError,
    ServiceScopeV1, StandardCashuMintExpectationV1, StandardCashuMintManifestV1,
    MAX_CASHU_MINT_MANIFEST_LEN, MAX_CREDENTIAL_BINDING_LEN, SERVICE_PROTOCOL_VERSION,
};

pub const MAX_POLICY_SCOPES: usize = 64;
pub const MAX_OFFERS_PER_SCOPE: usize = 16;
pub const MAX_KEY_ID_LEN: usize = 64;
pub const MAX_ENDPOINT_LEN: usize = 512;
pub const MAX_PRICE_UNIT_LEN: usize = 16;
pub const MAX_SIGNED_POLICY_LEN: usize = 128 * 1024;
/// Largest generic value stored in the V1 durable SQLite ledgers. Keeping
/// values within signed 64-bit range makes arithmetic identical in Rust and
/// SQLite instead of relying on lossy casts.
pub const MAX_SERVICE_VALUE_V1: u64 = i64::MAX as u64;
/// Consensus maximum Bitcoin supply expressed in millisatoshis.
pub const MAX_BITCOIN_MSAT_V1: u64 = 2_100_000_000_000_000_000;
pub const MAX_CREDENTIALS_PER_ACQUISITION_V1: u32 = 256;
pub const MAX_CREDENTIAL_PRESENTATIONS_V1: u32 = 1_024;
pub const MAX_TOTAL_PRESENTATIONS_PER_ACQUISITION_V1: u32 = 4_096;
const MAX_SCOPE_ENCODING_LEN: usize = 128;
/// Maximum canonical bytes for one offer, including an embedded credential
/// key binding and HTTPS endpoint. Kept below the `u16` wire length while
/// leaving room for both independently bounded fields.
pub const MAX_OFFER_ENCODING_LEN: usize = 63 * 1024;

pub const POLICY_SIGNATURE_DOMAIN: &[u8] = b"BitcoinPIR/service-policy-signature/v1";
pub const POLICY_DIGEST_DOMAIN: &[u8] = b"BitcoinPIR/service-policy-digest/v1";
pub const POLICY_KEY_ID_DOMAIN: &[u8] = b"BitcoinPIR/service-policy-key-id/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AcquisitionMethod {
    FreeV1 = 1,
    Bolt11V1 = 2,
    CashuEcashV1 = 3,
}

/// Provider-selected admission rule for a `FreeV1` offer. This is signed
/// policy, never a client-selected proof tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FreeModeV1 {
    NotFree = 0,
    OpenBestEffort = 1,
    IpRateLimited = 2,
    ProofOfWork = 3,
    AnonymousTicket = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthPaddingClassV1 {
    Class16KiB = 1,
}

impl AuthPaddingClassV1 {
    pub const fn body_len(self) -> usize {
        match self {
            Self::Class16KiB => 16 * 1024,
        }
    }

    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::Class16KiB),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "AuthPaddingClassV1",
                value,
            }),
        }
    }
}

impl FreeModeV1 {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            0 => Ok(Self::NotFree),
            1 => Ok(Self::OpenBestEffort),
            2 => Ok(Self::IpRateLimited),
            3 => Ok(Self::ProofOfWork),
            4 => Ok(Self::AnonymousTicket),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "FreeModeV1",
                value,
            }),
        }
    }
}

impl AcquisitionMethod {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::FreeV1),
            2 => Ok(Self::Bolt11V1),
            3 => Ok(Self::CashuEcashV1),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "AcquisitionMethod",
                value,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VerificationMode {
    ProviderLocal = 1,
    SharedIssuerOnline = 2,
    StandardCashuMintOnline = 3,
}

impl VerificationMode {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::ProviderLocal),
            2 => Ok(Self::SharedIssuerOnline),
            3 => Ok(Self::StandardCashuMintOnline),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "VerificationMode",
                value,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeploymentStatus {
    Stable = 1,
    Experimental = 2,
}

impl DeploymentStatus {
    fn decode(value: u8) -> Result<Self, ServiceProtocolError> {
        match value {
            1 => Ok(Self::Stable),
            2 => Ok(Self::Experimental),
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "DeploymentStatus",
                value,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivacyLeakageV1(u16);

impl PrivacyLeakageV1 {
    pub const IP_RATE_BUCKET: u16 = 1 << 0;
    pub const DIRECT_PAYMENT_TO_SPEND: u16 = 1 << 1;
    pub const ISSUER_ISSUANCE_TIMING: u16 = 1 << 2;
    pub const ISSUER_REDEMPTION_TIMING: u16 = 1 << 3;
    pub const ISSUER_LEARNS_PROVIDER: u16 = 1 << 4;
    pub const PROVIDER_LOCAL_BEARER: u16 = 1 << 5;
    pub const KNOWN_MASK: u16 = Self::IP_RATE_BUCKET
        | Self::DIRECT_PAYMENT_TO_SPEND
        | Self::ISSUER_ISSUANCE_TIMING
        | Self::ISSUER_REDEMPTION_TIMING
        | Self::ISSUER_LEARNS_PROVIDER
        | Self::PROVIDER_LOCAL_BEARER;

    pub const NONE: Self = Self(0);

    pub fn from_bits(bits: u16) -> Result<Self, ServiceProtocolError> {
        if bits & !Self::KNOWN_MASK != 0 {
            Err(ServiceProtocolError::InvalidValue {
                field: "PrivacyLeakageV1",
                reason: "contains unknown leakage flags",
            })
        } else {
            Ok(Self(bits))
        }
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains_all(self, required: u16) -> bool {
        self.0 & required == required
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PriceV1 {
    Free,
    MilliSatoshi(u64),
    Cashu { unit: String, amount: u64 },
}

impl PriceV1 {
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), ServiceProtocolError> {
        match self {
            Self::Free => out.push(1),
            Self::MilliSatoshi(amount) => {
                if *amount == 0 || *amount > MAX_BITCOIN_MSAT_V1 {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "PriceV1.MilliSatoshi",
                        reason: "amount must be non-zero and within the Bitcoin supply bound",
                    });
                }
                out.push(2);
                out.extend_from_slice(&amount.to_le_bytes());
            }
            Self::Cashu { unit, amount } => {
                if unit.is_empty() || unit.len() > MAX_PRICE_UNIT_LEN {
                    return Err(ServiceProtocolError::FieldTooLong {
                        field: "PriceV1.Cashu.unit",
                        len: unit.len(),
                        max: MAX_PRICE_UNIT_LEN,
                    });
                }
                if *amount == 0 || *amount > MAX_SERVICE_VALUE_V1 {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "PriceV1.Cashu.amount",
                        reason: "amount must be non-zero and fit the durable ledger",
                    });
                }
                out.push(3);
                out.push(unit.len() as u8);
                out.extend_from_slice(unit.as_bytes());
                out.extend_from_slice(&amount.to_le_bytes());
            }
        }
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ServiceProtocolError> {
        match decoder.u8("PriceV1.type")? {
            1 => Ok(Self::Free),
            2 => {
                let amount = decoder.u64("PriceV1.MilliSatoshi.amount")?;
                if amount == 0 || amount > MAX_BITCOIN_MSAT_V1 {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "PriceV1.MilliSatoshi.amount",
                        reason: "amount must be non-zero and within the Bitcoin supply bound",
                    });
                }
                Ok(Self::MilliSatoshi(amount))
            }
            3 => {
                let unit_bytes = decoder.bytes_u8("PriceV1.Cashu.unit", MAX_PRICE_UNIT_LEN)?;
                if unit_bytes.is_empty() {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "PriceV1.Cashu.unit",
                        reason: "unit must not be empty",
                    });
                }
                let unit = String::from_utf8(unit_bytes)
                    .map_err(|_| ServiceProtocolError::InvalidUtf8("PriceV1.Cashu.unit"))?;
                let amount = decoder.u64("PriceV1.Cashu.amount")?;
                if amount == 0 || amount > MAX_SERVICE_VALUE_V1 {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "PriceV1.Cashu.amount",
                        reason: "amount must be non-zero and fit the durable ledger",
                    });
                }
                Ok(Self::Cashu { unit, amount })
            }
            value => Err(ServiceProtocolError::UnknownDiscriminant {
                kind: "PriceV1",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntitlementLimitsV1 {
    pub max_logical_inputs: u16,
    pub max_frames: u32,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_wall_time_ms: u32,
    pub max_concurrent_sockets: u8,
    pub max_hint_groups: u16,
    pub max_work_units: u64,
}

impl EntitlementLimitsV1 {
    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.max_frames == 0 || self.max_wall_time_ms == 0 || self.max_concurrent_sockets == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "EntitlementLimitsV1",
                reason: "frame, lifetime, and socket limits must be non-zero",
            });
        }
        Ok(())
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        out.extend_from_slice(&self.max_logical_inputs.to_le_bytes());
        out.extend_from_slice(&self.max_frames.to_le_bytes());
        out.extend_from_slice(&self.max_request_bytes.to_le_bytes());
        out.extend_from_slice(&self.max_response_bytes.to_le_bytes());
        out.extend_from_slice(&self.max_wall_time_ms.to_le_bytes());
        out.push(self.max_concurrent_sockets);
        out.extend_from_slice(&self.max_hint_groups.to_le_bytes());
        out.extend_from_slice(&self.max_work_units.to_le_bytes());
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ServiceProtocolError> {
        let value = Self {
            max_logical_inputs: decoder.u16("EntitlementLimitsV1.max_logical_inputs")?,
            max_frames: decoder.u32("EntitlementLimitsV1.max_frames")?,
            max_request_bytes: decoder.u64("EntitlementLimitsV1.max_request_bytes")?,
            max_response_bytes: decoder.u64("EntitlementLimitsV1.max_response_bytes")?,
            max_wall_time_ms: decoder.u32("EntitlementLimitsV1.max_wall_time_ms")?,
            max_concurrent_sockets: decoder.u8("EntitlementLimitsV1.max_concurrent_sockets")?,
            max_hint_groups: decoder.u16("EntitlementLimitsV1.max_hint_groups")?,
            max_work_units: decoder.u64("EntitlementLimitsV1.max_work_units")?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceOfferV1 {
    pub offer_id: u32,
    pub acquisition: AcquisitionMethod,
    pub free_mode: FreeModeV1,
    /// Maximum grants in `free_window_seconds` for `IpRateLimited`.
    pub free_quota: u32,
    /// Signed quota window for `IpRateLimited`.
    pub free_window_seconds: u32,
    /// Leading-zero-bit target for `ProofOfWork`.
    pub free_pow_difficulty_bits: u8,
    /// Provider-defined scheduling class. Zero is reserved/invalid.
    pub priority_class: u16,
    pub authorization: AuthScheme,
    pub verification: VerificationMode,
    pub deployment_status: DeploymentStatus,
    pub price: PriceV1,
    pub issuer_id: [u8; 32],
    pub key_id: Vec<u8>,
    pub credential_binding: Option<CredentialKeyBindingV1>,
    /// Embedded canonical standard Cashu manifest. Its digest is `key_id`, so
    /// no unsigned fetch or JSON canonicalization is needed before spending.
    pub cashu_mint_manifest: Option<StandardCashuMintManifestV1>,
    pub endpoint: String,
    pub invoice_expiry_seconds: u32,
    pub claim_window_seconds: u32,
    pub minimum_credential_validity_seconds: u32,
    pub retired_policy_grace_seconds: u32,
    /// Number of independently spendable credentials issued per acquisition.
    pub credential_count: u32,
    /// Presentations allowed by each credential (greater than one only for ARC).
    pub credential_presentation_limit: u32,
    pub privacy_leakage: PrivacyLeakageV1,
}

impl ServiceOfferV1 {
    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.offer_id == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.offer_id",
                reason: "must be non-zero",
            });
        }
        if self.key_id.len() > MAX_KEY_ID_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ServiceOfferV1.key_id",
                len: self.key_id.len(),
                max: MAX_KEY_ID_LEN,
            });
        }
        if self.endpoint.len() > MAX_ENDPOINT_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ServiceOfferV1.endpoint",
                len: self.endpoint.len(),
                max: MAX_ENDPOINT_LEN,
            });
        }
        if !self.endpoint.is_empty() && !is_allowed_service_endpoint(&self.endpoint) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.endpoint",
                reason:
                    "must be a canonical HTTPS endpoint without credentials, query, or fragment",
            });
        }
        if self.acquisition == AcquisitionMethod::Bolt11V1
            && !is_allowed_service_origin(&self.endpoint)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.endpoint",
                reason: "BOLT11 acquisition requires a canonical HTTPS origin without a path",
            });
        }
        if self.verification == VerificationMode::SharedIssuerOnline
            && !is_allowed_service_origin(&self.endpoint)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.endpoint",
                reason:
                    "shared-issuer verification requires a canonical HTTPS origin without a path",
            });
        }
        if self.minimum_credential_validity_seconds == 0
            || self.credential_count == 0
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
                field: "ServiceOfferV1",
                reason:
                    "credential validity/count/presentation limits are zero, excessive, or overflow",
            });
        }
        if self.priority_class == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.priority_class",
                reason: "must be non-zero",
            });
        }
        if self.authorization == AuthScheme::ArcV1Experimental
            && self.deployment_status != DeploymentStatus::Experimental
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.deployment_status",
                reason: "ARC must remain experimental",
            });
        }
        match (&self.acquisition, &self.price) {
            (AcquisitionMethod::FreeV1, PriceV1::Free) => {
                if self.free_mode == FreeModeV1::NotFree {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ServiceOfferV1.free_mode",
                        reason: "free acquisition requires an explicit free mode",
                    });
                }
                if self.authorization != AuthScheme::FreeV1 {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ServiceOfferV1.authorization",
                        reason: "free acquisition requires the FreeV1 authorization scheme",
                    });
                }
            }
            (AcquisitionMethod::FreeV1, _) => {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServiceOfferV1.price",
                    reason: "free acquisition must have a free price",
                })
            }
            (_, PriceV1::Free) => {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServiceOfferV1.price",
                    reason: "paid acquisition cannot have a free price",
                })
            }
            _ => {}
        }
        let method_pair_ok = matches!(
            (self.acquisition, self.authorization),
            (AcquisitionMethod::FreeV1, AuthScheme::FreeV1)
                | (
                    AcquisitionMethod::Bolt11V1,
                    AuthScheme::Bolt11DirectReceiptV1
                        | AuthScheme::BitcoinPirCashuBatV1
                        | AuthScheme::ArcV1Experimental
                )
                | (AcquisitionMethod::CashuEcashV1, AuthScheme::CashuEcashV1)
        );
        if !method_pair_ok {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.authorization",
                reason: "acquisition and authorization methods are incompatible",
            });
        }
        let price_matches_acquisition = matches!(
            (&self.acquisition, &self.price),
            (AcquisitionMethod::FreeV1, PriceV1::Free)
                | (AcquisitionMethod::Bolt11V1, PriceV1::MilliSatoshi(_))
                | (AcquisitionMethod::CashuEcashV1, PriceV1::Cashu { .. })
        );
        if !price_matches_acquisition {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.price",
                reason: "price type does not match acquisition method",
            });
        }
        let verification_matches_authorization = match self.authorization {
            AuthScheme::FreeV1 => match self.free_mode {
                FreeModeV1::AnonymousTicket => matches!(
                    self.verification,
                    VerificationMode::ProviderLocal | VerificationMode::SharedIssuerOnline
                ),
                _ => self.verification == VerificationMode::ProviderLocal,
            },
            AuthScheme::Bolt11DirectReceiptV1 => {
                self.verification == VerificationMode::ProviderLocal
            }
            AuthScheme::CashuEcashV1 => {
                self.verification == VerificationMode::StandardCashuMintOnline
            }
            AuthScheme::BitcoinPirCashuBatV1 => matches!(
                self.verification,
                VerificationMode::ProviderLocal | VerificationMode::SharedIssuerOnline
            ),
            AuthScheme::ArcV1Experimental => matches!(
                self.verification,
                VerificationMode::ProviderLocal | VerificationMode::SharedIssuerOnline
            ),
        };
        if !verification_matches_authorization {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.verification",
                reason: "verification mode does not support the authorization scheme",
            });
        }
        if self.authorization != AuthScheme::ArcV1Experimental
            && self.credential_presentation_limit != 1
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.credential_presentation_limit",
                reason: "only ARC credentials may authorize multiple presentations",
            });
        }
        // The pinned ARC draft-01 construction has no presentation base at
        // limit one (`compute_bases(1)` is empty), so such a credential cannot
        // satisfy the verifier's nonce-commitment sum check. Keep this
        // experimental method fail closed until an independently reviewed
        // construction changes that lower bound.
        if self.authorization == AuthScheme::ArcV1Experimental
            && self.credential_presentation_limit < 2
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.credential_presentation_limit",
                reason: "experimental ARC draft-01 requires at least two presentations",
            });
        }
        if (self.authorization == AuthScheme::CashuEcashV1
            || (self.authorization == AuthScheme::FreeV1
                && self.free_mode != FreeModeV1::AnonymousTicket))
            && self.credential_count != 1
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.credential_count",
                reason: "non-issued Free grants and standard Cashu spends authorize one operation",
            });
        }
        let credential_backed = self.authorization != AuthScheme::FreeV1
            && self.authorization != AuthScheme::CashuEcashV1
            || self.free_mode == FreeModeV1::AnonymousTicket;
        if credential_backed {
            if self.issuer_id.iter().all(|byte| *byte == 0)
                || self.key_id.is_empty()
                || self.endpoint.is_empty()
                || self.credential_binding.is_none()
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServiceOfferV1.credential_delegation",
                    reason: "credential-backed offers require issuer, key ID, and endpoint",
                });
            }
        } else if self.authorization == AuthScheme::FreeV1
            && (self.issuer_id.iter().any(|byte| *byte != 0)
                || !self.key_id.is_empty()
                || self.credential_binding.is_some())
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.credential_delegation",
                reason: "non-ticket Free offers must not carry credential issuer state",
            });
        }
        if self.authorization == AuthScheme::CashuEcashV1
            && (self.issuer_id.iter().all(|byte| *byte == 0)
                || self.key_id.len() != 32
                || self.endpoint.is_empty()
                || self.credential_binding.is_some()
                || self.cashu_mint_manifest.is_none()
                || self.issuer_id != derive_cashu_mint_id(&self.endpoint))
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.cashu_mint_binding",
                reason: "standard Cashu requires mint ID and 32-byte keyset manifest digest",
            });
        }
        if self.authorization != AuthScheme::CashuEcashV1 && self.cashu_mint_manifest.is_some() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.cashu_mint_manifest",
                reason: "only standard Cashu offers embed a mint manifest",
            });
        }
        if self.authorization == AuthScheme::Bolt11DirectReceiptV1 && self.key_id.len() != 16 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.key_id",
                reason: "direct receipt key ID must be 16 bytes",
            });
        }
        let mut required_privacy = match self.authorization {
            AuthScheme::FreeV1 => match self.free_mode {
                FreeModeV1::IpRateLimited => PrivacyLeakageV1::IP_RATE_BUCKET,
                FreeModeV1::AnonymousTicket => {
                    let mut leakage = PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                        | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER;
                    if self.verification == VerificationMode::SharedIssuerOnline {
                        leakage |= PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                            | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER;
                    } else {
                        leakage |= PrivacyLeakageV1::PROVIDER_LOCAL_BEARER;
                    }
                    leakage
                }
                _ => 0,
            },
            AuthScheme::Bolt11DirectReceiptV1 => PrivacyLeakageV1::DIRECT_PAYMENT_TO_SPEND,
            AuthScheme::CashuEcashV1 => {
                PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER
            }
            AuthScheme::BitcoinPirCashuBatV1 | AuthScheme::ArcV1Experimental => {
                if self.verification == VerificationMode::SharedIssuerOnline {
                    PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                        | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER
                } else {
                    PrivacyLeakageV1::PROVIDER_LOCAL_BEARER
                        | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER
                }
            }
        };
        if matches!(self.acquisition, AcquisitionMethod::Bolt11V1)
            && self.authorization != AuthScheme::Bolt11DirectReceiptV1
        {
            required_privacy |= PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING;
        }
        if !self.privacy_leakage.contains_all(required_privacy) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.privacy_leakage",
                reason: "privacy flags understate method leakage",
            });
        }
        if self.acquisition == AcquisitionMethod::Bolt11V1 {
            if self.invoice_expiry_seconds == 0
                || self.invoice_expiry_seconds > MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServiceOfferV1.invoice_expiry_seconds",
                    reason: "must be non-zero and within the BOLT11 quote protocol cap",
                });
            }
            if self.claim_window_seconds == 0
                || self.claim_window_seconds > MAX_BOLT11_CLAIM_WINDOW_SECONDS_V1
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServiceOfferV1.claim_window_seconds",
                    reason: "must be non-zero and within the BOLT11 quote protocol cap",
                });
            }
            if self.minimum_credential_validity_seconds > MAX_BOLT11_CREDENTIAL_VALIDITY_SECONDS_V1
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServiceOfferV1.minimum_credential_validity_seconds",
                    reason: "exceeds the BOLT11 quote protocol cap",
                });
            }
            let required_grace = self
                .invoice_expiry_seconds
                .checked_add(self.claim_window_seconds)
                .and_then(|value| value.checked_add(self.minimum_credential_validity_seconds))
                .ok_or(ServiceProtocolError::InvalidValue {
                    field: "ServiceOfferV1.retired_policy_grace_seconds",
                    reason: "validity horizon overflow",
                })?;
            if self.retired_policy_grace_seconds < required_grace {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServiceOfferV1.retired_policy_grace_seconds",
                    reason: "BOLT11 grace must cover invoice, claim, and credential horizons",
                });
            }
        } else if self.invoice_expiry_seconds != 0 || self.claim_window_seconds != 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.invoice_or_claim_window",
                reason: "only BOLT11 acquisition declares invoice and claim windows",
            });
        }
        if credential_backed
            && self.retired_policy_grace_seconds < self.minimum_credential_validity_seconds
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.retired_policy_grace_seconds",
                reason:
                    "credential-backed offers must retain retired policy for the credential horizon",
            });
        }
        if self.acquisition != AcquisitionMethod::FreeV1 && self.free_mode != FreeModeV1::NotFree {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.free_mode",
                reason: "paid acquisition must use NotFree",
            });
        }
        if self.acquisition != AcquisitionMethod::FreeV1 && self.authorization == AuthScheme::FreeV1
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.authorization",
                reason: "paid acquisition cannot create a FreeV1 grant",
            });
        }
        match self.free_mode {
            FreeModeV1::NotFree | FreeModeV1::OpenBestEffort => {
                if self.free_quota != 0
                    || self.free_window_seconds != 0
                    || self.free_pow_difficulty_bits != 0
                {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ServiceOfferV1.free_parameters",
                        reason: "mode does not accept free quota or proof-of-work parameters",
                    });
                }
            }
            FreeModeV1::IpRateLimited => {
                if self.free_quota == 0
                    || self.free_window_seconds == 0
                    || self.free_pow_difficulty_bits != 0
                {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ServiceOfferV1.free_parameters",
                        reason: "IP rate limit requires a non-zero quota/window and no PoW target",
                    });
                }
            }
            FreeModeV1::ProofOfWork => {
                if self.free_quota != 0
                    || self.free_window_seconds != 0
                    || self.free_pow_difficulty_bits == 0
                    || self.free_pow_difficulty_bits > MAX_POW_DIFFICULTY_BITS_V1
                {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ServiceOfferV1.free_parameters",
                        reason: "PoW target must be non-zero, capped, and the only free parameter",
                    });
                }
            }
            FreeModeV1::AnonymousTicket => {
                if self.free_quota != 0
                    || self.free_window_seconds != 0
                    || self.free_pow_difficulty_bits != 0
                {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ServiceOfferV1.free_parameters",
                        reason: "anonymous-ticket quota comes from its issuer/key binding",
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_for_scope(
        &self,
        scope: &ServiceScopeV1,
        policy_issued_at: u64,
        policy_expires_at: u64,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        let Some(binding) = &self.credential_binding else {
            if let Some(manifest) = &self.cashu_mint_manifest {
                let PriceV1::Cashu { unit, .. } = &self.price else {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ServiceOfferV1.price",
                        reason: "standard Cashu manifest requires a Cashu price",
                    });
                };
                let manifest_digest = manifest.manifest_digest()?;
                let expected_digest: [u8; 32] =
                    self.key_id.as_slice().try_into().map_err(|_| {
                        ServiceProtocolError::InvalidValue {
                            field: "ServiceOfferV1.key_id",
                            reason: "Cashu manifest digest must be 32 bytes",
                        }
                    })?;
                let active_output_valid_through = policy_expires_at
                    .checked_add(self.minimum_credential_validity_seconds as u64)
                    .ok_or(ServiceProtocolError::InvalidValue {
                        field: "StandardCashuMintManifestV1.output_final_expiry",
                        reason: "Cashu recovery horizon overflow",
                    })?;
                manifest.verify_for(
                    &StandardCashuMintExpectationV1 {
                        mint_id: &self.issuer_id,
                        manifest_digest: &expected_digest,
                        mint_endpoint: &self.endpoint,
                        unit,
                        accepted_inputs_valid_through: policy_expires_at,
                        active_output_valid_through,
                    },
                    manifest.manifest_epoch,
                )?;
                if manifest_digest != expected_digest {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ServiceOfferV1.key_id",
                        reason: "does not equal the embedded Cashu manifest digest",
                    });
                }
            }
            return Ok(());
        };
        let claims = &binding.claims;
        let scope_id = scope.scope_id();
        binding.verify_for(
            &CredentialKeyBindingExpectationV1 {
                issuer_id: &self.issuer_id,
                provider_id: &scope.provider_id,
                scope_id: &scope_id,
                offer_id: self.offer_id,
                scheme: self.authorization,
                minimum_keyset_epoch: 1,
                entitlement_profile: scope.entitlement_profile,
                presentation_limit: self.credential_presentation_limit,
                credential_key_id: &self.key_id,
            },
            policy_issued_at,
        )?;
        if claims.not_before > policy_issued_at {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.not_before",
                reason: "binding starts after policy issuance",
            });
        }
        let required_not_after = policy_expires_at
            .checked_add(self.invoice_expiry_seconds as u64)
            .and_then(|value| value.checked_add(self.claim_window_seconds as u64))
            .and_then(|value| value.checked_add(self.minimum_credential_validity_seconds as u64))
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.not_after",
                reason: "policy and credential horizon overflow",
            })?;
        if claims.not_after < required_not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.not_after",
                reason: "binding does not cover policy, claim, and credential horizons",
            });
        }
        let maximum_not_after = policy_expires_at
            .checked_add(self.retired_policy_grace_seconds as u64)
            .ok_or(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.not_after",
                reason: "retired-policy horizon overflow",
            })?;
        if claims.not_after > maximum_not_after {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.not_after",
                reason: "binding outlives the signed retired-policy retention horizon",
            });
        }
        if self.authorization == AuthScheme::Bolt11DirectReceiptV1 {
            let key_bytes: [u8; 32] =
                claims.verification_key.as_slice().try_into().map_err(|_| {
                    ServiceProtocolError::InvalidValue {
                        field: "CredentialKeyBindingV1.verification_key",
                        reason: "receipt Ed25519 key must be 32 bytes",
                    }
                })?;
            let key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| ServiceProtocolError::BadPublicKey)?;
            if self.key_id.as_slice() != paid_receipt_key_id(&key) {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServiceOfferV1.key_id",
                    reason: "does not derive from delegated receipt key",
                });
            }
        }
        if self.authorization == AuthScheme::FreeV1 && self.free_mode == FreeModeV1::AnonymousTicket
        {
            let key_bytes: [u8; 32] =
                claims.verification_key.as_slice().try_into().map_err(|_| {
                    ServiceProtocolError::InvalidValue {
                        field: "CredentialKeyBindingV1.verification_key",
                        reason: "anonymous-ticket Ed25519 key must be 32 bytes",
                    }
                })?;
            let key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| ServiceProtocolError::BadPublicKey)?;
            if self.key_id.as_slice() != free_anonymous_ticket_key_id(&key) {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServiceOfferV1.key_id",
                    reason: "does not derive from delegated anonymous-ticket key",
                });
            }
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(128 + self.endpoint.len());
        out.extend_from_slice(&self.offer_id.to_le_bytes());
        out.push(self.acquisition as u8);
        out.push(self.free_mode as u8);
        out.extend_from_slice(&self.free_quota.to_le_bytes());
        out.extend_from_slice(&self.free_window_seconds.to_le_bytes());
        out.push(self.free_pow_difficulty_bits);
        out.extend_from_slice(&self.priority_class.to_le_bytes());
        out.push(self.authorization as u8);
        out.push(self.verification as u8);
        out.push(self.deployment_status as u8);
        self.price.encode_into(&mut out)?;
        out.extend_from_slice(&self.issuer_id);
        out.push(self.key_id.len() as u8);
        out.extend_from_slice(&self.key_id);
        match &self.credential_binding {
            Some(binding) => {
                out.push(1);
                put_bytes_u16(&mut out, &binding.encode()?);
            }
            None => out.push(0),
        }
        match &self.cashu_mint_manifest {
            Some(manifest) => {
                out.push(1);
                put_bytes_u16(&mut out, &manifest.encode()?);
            }
            None => out.push(0),
        }
        put_bytes_u16(&mut out, self.endpoint.as_bytes());
        out.extend_from_slice(&self.invoice_expiry_seconds.to_le_bytes());
        out.extend_from_slice(&self.claim_window_seconds.to_le_bytes());
        out.extend_from_slice(&self.minimum_credential_validity_seconds.to_le_bytes());
        out.extend_from_slice(&self.retired_policy_grace_seconds.to_le_bytes());
        out.extend_from_slice(&self.credential_count.to_le_bytes());
        out.extend_from_slice(&self.credential_presentation_limit.to_le_bytes());
        out.extend_from_slice(&self.privacy_leakage.bits().to_le_bytes());
        if out.len() > MAX_OFFER_ENCODING_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ServiceOfferV1",
                len: out.len(),
                max: MAX_OFFER_ENCODING_LEN,
            });
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let offer_id = decoder.u32("ServiceOfferV1.offer_id")?;
        let acquisition = AcquisitionMethod::decode(decoder.u8("ServiceOfferV1.acquisition")?)?;
        let free_mode = FreeModeV1::decode(decoder.u8("ServiceOfferV1.free_mode")?)?;
        let free_quota = decoder.u32("ServiceOfferV1.free_quota")?;
        let free_window_seconds = decoder.u32("ServiceOfferV1.free_window_seconds")?;
        let free_pow_difficulty_bits = decoder.u8("ServiceOfferV1.free_pow_difficulty_bits")?;
        let priority_class = decoder.u16("ServiceOfferV1.priority_class")?;
        let authorization = AuthScheme::decode(decoder.u8("ServiceOfferV1.authorization")?)?;
        let verification = VerificationMode::decode(decoder.u8("ServiceOfferV1.verification")?)?;
        let deployment_status =
            DeploymentStatus::decode(decoder.u8("ServiceOfferV1.deployment_status")?)?;
        let price = PriceV1::decode_from(&mut decoder)?;
        let issuer_id = decoder.fixed("ServiceOfferV1.issuer_id")?;
        let key_id = decoder.bytes_u8("ServiceOfferV1.key_id", MAX_KEY_ID_LEN)?;
        let credential_binding = match decoder.u8("ServiceOfferV1.has_credential_binding")? {
            0 => None,
            1 => {
                let bytes = decoder.bytes_u16(
                    "ServiceOfferV1.credential_binding",
                    MAX_CREDENTIAL_BINDING_LEN,
                )?;
                Some(CredentialKeyBindingV1::decode(&bytes)?)
            }
            value => {
                return Err(ServiceProtocolError::UnknownDiscriminant {
                    kind: "ServiceOfferV1.has_credential_binding",
                    value,
                })
            }
        };
        let cashu_mint_manifest = match decoder.u8("ServiceOfferV1.has_cashu_mint_manifest")? {
            0 => None,
            1 => Some(StandardCashuMintManifestV1::decode(&decoder.bytes_u16(
                "ServiceOfferV1.cashu_mint_manifest",
                MAX_CASHU_MINT_MANIFEST_LEN,
            )?)?),
            value => {
                return Err(ServiceProtocolError::UnknownDiscriminant {
                    kind: "ServiceOfferV1.has_cashu_mint_manifest",
                    value,
                })
            }
        };
        let endpoint = decoder.string_u16("ServiceOfferV1.endpoint", MAX_ENDPOINT_LEN)?;
        let invoice_expiry_seconds = decoder.u32("ServiceOfferV1.invoice_expiry_seconds")?;
        let claim_window_seconds = decoder.u32("ServiceOfferV1.claim_window_seconds")?;
        let minimum_credential_validity_seconds =
            decoder.u32("ServiceOfferV1.minimum_credential_validity_seconds")?;
        let retired_policy_grace_seconds =
            decoder.u32("ServiceOfferV1.retired_policy_grace_seconds")?;
        let credential_count = decoder.u32("ServiceOfferV1.credential_count")?;
        let credential_presentation_limit =
            decoder.u32("ServiceOfferV1.credential_presentation_limit")?;
        let privacy_leakage =
            PrivacyLeakageV1::from_bits(decoder.u16("ServiceOfferV1.privacy_leakage")?)?;
        decoder.finish()?;
        let value = Self {
            offer_id,
            acquisition,
            free_mode,
            free_quota,
            free_window_seconds,
            free_pow_difficulty_bits,
            priority_class,
            authorization,
            verification,
            deployment_status,
            price,
            issuer_id,
            key_id,
            credential_binding,
            cashu_mint_manifest,
            endpoint,
            invoice_expiry_seconds,
            claim_window_seconds,
            minimum_credential_validity_seconds,
            retired_policy_grace_seconds,
            credential_count,
            credential_presentation_limit,
            privacy_leakage,
        };
        value.validate()?;
        Ok(value)
    }
}

pub(crate) fn is_allowed_service_endpoint(endpoint: &str) -> bool {
    if !endpoint.is_ascii()
        || endpoint
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return false;
    }
    let Some(rest) = endpoint.strip_prefix("https://") else {
        return false;
    };
    if rest.is_empty()
        || rest.ends_with('/')
        || rest.contains(['@', '\\', '?', '#'])
        || endpoint.bytes().any(|byte| byte == 0x7f)
    {
        return false;
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || (!path.is_empty() && !path.is_ascii()) {
        return false;
    }

    // V1 excludes IP literals. DNS/punycode names have one portable canonical
    // spelling: lowercase ASCII with no trailing dot. This makes the exact URL
    // bytes safe to use as a mint/service identity across Rust and Web clients.
    if authority.starts_with('[') || authority.matches(':').count() > 1 {
        return false;
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'x' || byte == b'X' || byte == b'.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return false;
    }
    if let Some(port) = port {
        let parsed_port = port.parse::<u16>().ok();
        let noncanonical_port = match parsed_port {
            Some(value) => value == 0 || value == 443 || value.to_string() != port,
            None => true,
        };
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) || noncanonical_port {
            return false;
        }
    }
    if !path.is_empty()
        && (path.ends_with('/')
            || path.contains("//")
            || path.contains('%')
            || !path.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/')
            })
            || path
                .split('/')
                .any(|segment| segment == "." || segment == ".."))
    {
        return false;
    }
    true
}

/// Public canonical HTTPS endpoint predicate for transports that consume a
/// previously verified signed service artifact.
pub fn is_canonical_service_https_endpoint_v1(endpoint: &str) -> bool {
    is_allowed_service_endpoint(endpoint)
}

pub(crate) fn is_allowed_service_origin(endpoint: &str) -> bool {
    is_allowed_service_endpoint(endpoint)
        && endpoint
            .strip_prefix("https://")
            .is_some_and(|authority| !authority.contains('/'))
}

/// Public origin-only form used when a transport appends a fixed protocol
/// route such as `/v1/redeems`.
pub fn is_canonical_service_https_origin_v1(endpoint: &str) -> bool {
    is_allowed_service_origin(endpoint)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceScopePolicyV1 {
    pub scope: ServiceScopeV1,
    pub limits: EntitlementLimitsV1,
    pub offers: Vec<ServiceOfferV1>,
}

impl ServiceScopePolicyV1 {
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), ServiceProtocolError> {
        if self.offers.len() > MAX_OFFERS_PER_SCOPE {
            return Err(ServiceProtocolError::TooManyItems {
                field: "ServiceScopePolicyV1.offers",
                len: self.offers.len(),
                max: MAX_OFFERS_PER_SCOPE,
            });
        }
        let scope = self.scope.encode();
        put_bytes_u16(out, &scope);
        self.limits.encode_into(out)?;
        out.push(self.offers.len() as u8);
        for offer in &self.offers {
            let encoded = offer.encode()?;
            put_bytes_u16(out, &encoded);
        }
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, ServiceProtocolError> {
        let scope_bytes =
            decoder.bytes_u16("ServiceScopePolicyV1.scope", MAX_SCOPE_ENCODING_LEN)?;
        let scope = ServiceScopeV1::decode(&scope_bytes)?;
        let limits = EntitlementLimitsV1::decode_from(decoder)?;
        let count = decoder.u8("ServiceScopePolicyV1.offer_count")? as usize;
        if count > MAX_OFFERS_PER_SCOPE {
            return Err(ServiceProtocolError::TooManyItems {
                field: "ServiceScopePolicyV1.offers",
                len: count,
                max: MAX_OFFERS_PER_SCOPE,
            });
        }
        let mut offers = Vec::with_capacity(count);
        for _ in 0..count {
            let bytes = decoder.bytes_u16("ServiceScopePolicyV1.offer", MAX_OFFER_ENCODING_LEN)?;
            offers.push(ServiceOfferV1::decode(&bytes)?);
        }
        Ok(Self {
            scope,
            limits,
            offers,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServicePolicyV1 {
    pub provider_id: ProviderId,
    pub policy_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub auth_padding_class: AuthPaddingClassV1,
    pub scopes: Vec<ServiceScopePolicyV1>,
    pub signing_key_id: [u8; 16],
    pub signature: [u8; 64],
}

/// Persisted per-provider rollback/fork guard. At a given epoch exactly one
/// signed digest is accepted; a different policy at the same epoch fails
/// closed instead of silently selecting an operator fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyRollbackGuardV1 {
    pub highest_epoch: u64,
    pub digest_at_highest_epoch: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialKeysetEpochFloorV1 {
    pub scope_id: crate::ScopeId,
    pub scheme: AuthScheme,
    pub issuer_id: [u8; 32],
    pub minimum_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashuManifestEpochFloorV1 {
    pub mint_id: [u8; 32],
    pub unit: String,
    pub minimum_epoch: u64,
}

/// Durable anti-rollback floors learned from previously accepted policies.
/// Missing entries mean first use and therefore default to epoch one. These
/// floors are provider-local state and are never supplied by an untrusted
/// policy response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServicePolicyEpochFloorsV1 {
    pub credential_keysets: Vec<CredentialKeysetEpochFloorV1>,
    pub cashu_manifests: Vec<CashuManifestEpochFloorV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedCurrentPolicyV1<'a> {
    policy: &'a ServicePolicyV1,
    policy_digest: [u8; 32],
    policy_signing_key_ed25519: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedServiceOfferV1<'a> {
    scope: &'a ServiceScopeV1,
    limits: &'a EntitlementLimitsV1,
    offer: &'a ServiceOfferV1,
    policy_digest: [u8; 32],
    redemption_deadline: u64,
}

pub type VerifiedRetiredOfferV1<'a> = VerifiedServiceOfferV1<'a>;

impl<'a> VerifiedCurrentPolicyV1<'a> {
    pub const fn policy(&self) -> &'a ServicePolicyV1 {
        self.policy
    }

    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    /// Exact Ed25519 key used to verify this live policy. Keeping it in the
    /// typestate prevents directory binding from accepting an unrelated key
    /// supplied after policy verification.
    pub const fn policy_signing_key_ed25519(&self) -> [u8; 32] {
        self.policy_signing_key_ed25519
    }

    pub fn offer(
        &self,
        expected_scope_id: &crate::ScopeId,
        offer_id: u32,
    ) -> Result<VerifiedServiceOfferV1<'a>, ServiceProtocolError> {
        verified_offer_from_policy(self.policy, self.policy_digest, expected_scope_id, offer_id)
    }
}

impl<'a> VerifiedServiceOfferV1<'a> {
    pub const fn scope(&self) -> &'a ServiceScopeV1 {
        self.scope
    }

    /// Provider-enforced limits from the same signed scope-policy entry as
    /// [`Self::scope`] and [`Self::offer`]. These limits are never taken from
    /// an authorization request.
    pub const fn limits(&self) -> &'a EntitlementLimitsV1 {
        self.limits
    }

    pub const fn offer(&self) -> &'a ServiceOfferV1 {
        self.offer
    }

    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    pub const fn redemption_deadline(&self) -> u64 {
        self.redemption_deadline
    }
}

fn verified_offer_from_policy<'a>(
    policy: &'a ServicePolicyV1,
    policy_digest: [u8; 32],
    expected_scope_id: &crate::ScopeId,
    offer_id: u32,
) -> Result<VerifiedServiceOfferV1<'a>, ServiceProtocolError> {
    let (scope, limits, offer) = policy
        .scopes
        .iter()
        .find_map(|scope_policy| {
            if &scope_policy.scope.scope_id() != expected_scope_id {
                return None;
            }
            scope_policy
                .offers
                .iter()
                .find(|offer| offer.offer_id == offer_id)
                .map(|offer| (&scope_policy.scope, &scope_policy.limits, offer))
        })
        .ok_or(ServiceProtocolError::InvalidValue {
            field: "ServicePolicyV1.offer",
            reason: "scope or offer is not present in the verified policy",
        })?;
    let redemption_deadline = policy
        .expires_at
        .checked_add(offer.retired_policy_grace_seconds as u64)
        .ok_or(ServiceProtocolError::InvalidValue {
            field: "ServicePolicyV1.offer",
            reason: "redemption deadline overflow",
        })?;
    Ok(VerifiedServiceOfferV1 {
        scope,
        limits,
        offer,
        policy_digest,
        redemption_deadline,
    })
}

impl PolicyRollbackGuardV1 {
    pub const fn initial() -> Self {
        Self {
            highest_epoch: 0,
            digest_at_highest_epoch: [0; 32],
        }
    }

    pub const fn from_verified(verified: &VerifiedCurrentPolicyV1<'_>) -> Self {
        Self {
            highest_epoch: verified.policy.policy_epoch,
            digest_at_highest_epoch: verified.policy_digest,
        }
    }
}

impl ServicePolicyEpochFloorsV1 {
    pub const fn initial() -> Self {
        Self {
            credential_keysets: Vec::new(),
            cashu_manifests: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        let mut credential_keys = HashSet::with_capacity(self.credential_keysets.len());
        for floor in &self.credential_keysets {
            if floor.scope_id.iter().all(|byte| *byte == 0)
                || floor.issuer_id.iter().all(|byte| *byte == 0)
                || floor.minimum_epoch == 0
                || !credential_keys.insert((floor.scope_id, floor.scheme as u8, floor.issuer_id))
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServicePolicyEpochFloorsV1.credential_keysets",
                    reason: "floor keys and epochs must be non-zero and unique",
                });
            }
        }
        let mut cashu_keys = HashSet::with_capacity(self.cashu_manifests.len());
        for floor in &self.cashu_manifests {
            if floor.mint_id.iter().all(|byte| *byte == 0)
                || floor.minimum_epoch == 0
                || floor.unit.is_empty()
                || floor.unit.len() > MAX_PRICE_UNIT_LEN
                || !floor.unit.is_ascii()
                || !cashu_keys.insert((floor.mint_id, floor.unit.clone()))
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServicePolicyEpochFloorsV1.cashu_manifests",
                    reason: "floor keys, units, and epochs must be valid and unique",
                });
            }
        }
        Ok(())
    }

    fn credential_minimum(
        &self,
        scope_id: &crate::ScopeId,
        scheme: AuthScheme,
        issuer_id: &[u8; 32],
    ) -> u64 {
        self.credential_keysets
            .iter()
            .find(|floor| {
                &floor.scope_id == scope_id
                    && floor.scheme == scheme
                    && &floor.issuer_id == issuer_id
            })
            .map_or(1, |floor| floor.minimum_epoch)
    }

    fn cashu_minimum(&self, mint_id: &[u8; 32], unit: &str) -> u64 {
        self.cashu_manifests
            .iter()
            .find(|floor| &floor.mint_id == mint_id && floor.unit == unit)
            .map_or(1, |floor| floor.minimum_epoch)
    }

    pub fn updated_from_verified(
        &self,
        verified: &VerifiedCurrentPolicyV1<'_>,
    ) -> Result<Self, ServiceProtocolError> {
        self.validate()?;
        let mut updated = self.clone();
        for scope_policy in &verified.policy.scopes {
            let scope_id = scope_policy.scope.scope_id();
            for offer in &scope_policy.offers {
                if let Some(binding) = &offer.credential_binding {
                    if let Some(floor) = updated.credential_keysets.iter_mut().find(|floor| {
                        floor.scope_id == scope_id
                            && floor.scheme == offer.authorization
                            && floor.issuer_id == offer.issuer_id
                    }) {
                        floor.minimum_epoch = floor.minimum_epoch.max(binding.claims.keyset_epoch);
                    } else {
                        updated
                            .credential_keysets
                            .push(CredentialKeysetEpochFloorV1 {
                                scope_id,
                                scheme: offer.authorization,
                                issuer_id: offer.issuer_id,
                                minimum_epoch: binding.claims.keyset_epoch,
                            });
                    }
                }
                if let Some(manifest) = &offer.cashu_mint_manifest {
                    if let Some(floor) = updated.cashu_manifests.iter_mut().find(|floor| {
                        floor.mint_id == offer.issuer_id && floor.unit == manifest.unit
                    }) {
                        floor.minimum_epoch = floor.minimum_epoch.max(manifest.manifest_epoch);
                    } else {
                        updated.cashu_manifests.push(CashuManifestEpochFloorV1 {
                            mint_id: offer.issuer_id,
                            unit: manifest.unit.clone(),
                            minimum_epoch: manifest.manifest_epoch,
                        });
                    }
                }
            }
        }
        updated.credential_keysets.sort_by(|left, right| {
            (&left.scope_id, left.scheme as u8, &left.issuer_id).cmp(&(
                &right.scope_id,
                right.scheme as u8,
                &right.issuer_id,
            ))
        });
        updated.cashu_manifests.sort_by(|left, right| {
            (&left.mint_id, left.unit.as_str()).cmp(&(&right.mint_id, right.unit.as_str()))
        });
        updated.validate()?;
        Ok(updated)
    }
}

impl ServicePolicyV1 {
    pub fn sign(
        provider_id: ProviderId,
        policy_epoch: u64,
        issued_at: u64,
        expires_at: u64,
        auth_padding_class: AuthPaddingClassV1,
        scopes: Vec<ServiceScopePolicyV1>,
        signing_key: &SigningKey,
    ) -> Result<Self, ServiceProtocolError> {
        let signing_key_id = policy_signing_key_id(&signing_key.verifying_key());
        let mut policy = Self {
            provider_id,
            policy_epoch,
            issued_at,
            expires_at,
            auth_padding_class,
            scopes,
            signing_key_id,
            signature: [0; 64],
        };
        policy.validate()?;
        let signature = signing_key.sign(&policy.signing_preimage()?);
        policy.signature = signature.to_bytes();
        Ok(policy)
    }

    pub fn verify_current_for_acquisition<'a>(
        &'a self,
        expected_provider_id: &ProviderId,
        now_unix: u64,
        rollback_guard: &PolicyRollbackGuardV1,
        epoch_floors: &ServicePolicyEpochFloorsV1,
        verifying_key: &VerifyingKey,
    ) -> Result<VerifiedCurrentPolicyV1<'a>, ServiceProtocolError> {
        self.verify_signature_and_identity(expected_provider_id, verifying_key)?;
        self.check_validity(now_unix)?;
        self.verify_epoch_floors(epoch_floors)?;
        if (rollback_guard.highest_epoch == 0
            && rollback_guard
                .digest_at_highest_epoch
                .iter()
                .any(|byte| *byte != 0))
            || (rollback_guard.highest_epoch != 0
                && rollback_guard
                    .digest_at_highest_epoch
                    .iter()
                    .all(|byte| *byte == 0))
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PolicyRollbackGuardV1",
                reason: "initial and persisted rollback states are inconsistent",
            });
        }
        if self.policy_epoch < rollback_guard.highest_epoch {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyV1.policy_epoch",
                reason: "policy epoch rollback",
            });
        }
        let policy_digest = self.policy_digest()?;
        if self.policy_epoch == rollback_guard.highest_epoch
            && self.policy_epoch != 0
            && policy_digest != rollback_guard.digest_at_highest_epoch
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyV1.policy_digest",
                reason: "different signed policy at an already accepted epoch",
            });
        }
        Ok(VerifiedCurrentPolicyV1 {
            policy: self,
            policy_digest,
            policy_signing_key_ed25519: verifying_key.to_bytes(),
        })
    }

    fn verify_epoch_floors(
        &self,
        epoch_floors: &ServicePolicyEpochFloorsV1,
    ) -> Result<(), ServiceProtocolError> {
        epoch_floors.validate()?;
        for scope_policy in &self.scopes {
            let scope_id = scope_policy.scope.scope_id();
            for offer in &scope_policy.offers {
                if let Some(binding) = &offer.credential_binding {
                    let minimum = epoch_floors.credential_minimum(
                        &scope_id,
                        offer.authorization,
                        &offer.issuer_id,
                    );
                    if binding.claims.keyset_epoch < minimum {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "CredentialKeyBindingV1.keyset_epoch",
                            reason: "credential keyset epoch rollback",
                        });
                    }
                }
                if let Some(manifest) = &offer.cashu_mint_manifest {
                    let minimum = epoch_floors.cashu_minimum(&offer.issuer_id, &manifest.unit);
                    if manifest.manifest_epoch < minimum {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "StandardCashuMintManifestV1.manifest_epoch",
                            reason: "Cashu manifest epoch rollback",
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub fn verify_signature_and_identity(
        &self,
        expected_provider_id: &ProviderId,
        verifying_key: &VerifyingKey,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        if &self.provider_id != expected_provider_id {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyV1.provider_id",
                reason: "does not match the strictly verified provider",
            });
        }
        if self.signing_key_id != policy_signing_key_id(verifying_key) {
            return Err(ServiceProtocolError::WrongSigningKeyId);
        }
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify_strict(&self.signing_preimage()?, &signature)
            .map_err(|_| ServiceProtocolError::BadSignature)
    }

    /// Verify one exact locally retained policy/offer solely for consuming an
    /// already issued provider-bound credential. This API never authorizes a
    /// new quote or acquisition and intentionally ignores the current epoch
    /// floor; the exact digest must already be in the caller's retired-policy
    /// allowlist.
    pub fn verify_retired_for_redemption<'a>(
        &'a self,
        expected_provider_id: &ProviderId,
        expected_policy_digest: &[u8; 32],
        expected_scope_id: &crate::ScopeId,
        offer_id: u32,
        now_unix: u64,
        verifying_key: &VerifyingKey,
    ) -> Result<VerifiedRetiredOfferV1<'a>, ServiceProtocolError> {
        self.verify_signature_and_identity(expected_provider_id, verifying_key)?;
        let policy_digest = self.policy_digest()?;
        if &policy_digest != expected_policy_digest {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyV1.policy_digest",
                reason: "policy is not the exact locally retained redemption policy",
            });
        }
        let verified =
            verified_offer_from_policy(self, policy_digest, expected_scope_id, offer_id)?;
        let offer = verified.offer;
        if offer.credential_binding.is_none() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyV1.retired_offer",
                reason: "only provider-bound credentials use retired-policy redemption",
            });
        }
        let redemption_deadline = verified.redemption_deadline;
        if now_unix < self.issued_at || now_unix > redemption_deadline {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyV1.retired_offer",
                reason: "retained policy is outside its redemption grace",
            });
        }
        Ok(verified)
    }

    /// Reconstruct the verified offer needed to recover an exact, already
    /// reserved BOLT11 quote after the provider has published a newer policy.
    ///
    /// The caller must first locate this exact policy digest in its durable
    /// issuer-retained allowlist and must supply the immutable reservation
    /// time.  This does not authorize a new acquisition at the current wall
    /// clock and deliberately performs no rollback-floor advance.
    pub fn verify_historical_for_exact_quote_recovery<'a>(
        &'a self,
        expected_provider_id: &ProviderId,
        expected_policy_digest: &[u8; 32],
        expected_scope_id: &crate::ScopeId,
        offer_id: u32,
        reservation_time_unix: u64,
        verifying_key: &VerifyingKey,
    ) -> Result<VerifiedServiceOfferV1<'a>, ServiceProtocolError> {
        self.verify_signature_and_identity(expected_provider_id, verifying_key)?;
        if &self.policy_digest()? != expected_policy_digest
            || reservation_time_unix < self.issued_at
            || reservation_time_unix > self.expires_at
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyV1.exact_quote_recovery",
                reason: "retained digest or original reservation time does not match",
            });
        }
        let verified =
            verified_offer_from_policy(self, *expected_policy_digest, expected_scope_id, offer_id)?;
        if verified.offer.credential_binding.is_none() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyV1.exact_quote_recovery",
                reason: "BOLT11 recovery requires a provider-bound paid credential",
            });
        }
        Ok(verified)
    }

    pub fn check_validity(&self, now_unix: u64) -> Result<(), ServiceProtocolError> {
        if now_unix < self.issued_at || now_unix > self.expires_at {
            Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyV1.validity",
                reason: "policy is not currently valid",
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
        let mut decoder = Decoder::new(bytes);
        let version = decoder.u8("ServicePolicyV1.version")?;
        expect_v1(version, "ServicePolicyV1")?;
        let provider_id = decoder.fixed("ServicePolicyV1.provider_id")?;
        let policy_epoch = decoder.u64("ServicePolicyV1.policy_epoch")?;
        let issued_at = decoder.u64("ServicePolicyV1.issued_at")?;
        let expires_at = decoder.u64("ServicePolicyV1.expires_at")?;
        let auth_padding_class =
            AuthPaddingClassV1::decode(decoder.u8("ServicePolicyV1.auth_padding_class")?)?;
        let scope_count = decoder.u8("ServicePolicyV1.scope_count")? as usize;
        if scope_count > MAX_POLICY_SCOPES {
            return Err(ServiceProtocolError::TooManyItems {
                field: "ServicePolicyV1.scopes",
                len: scope_count,
                max: MAX_POLICY_SCOPES,
            });
        }
        let mut scopes = Vec::with_capacity(scope_count);
        for _ in 0..scope_count {
            scopes.push(ServiceScopePolicyV1::decode_from(&mut decoder)?);
        }
        let signing_key_id = decoder.fixed("ServicePolicyV1.signing_key_id")?;
        let signature = decoder.fixed("ServicePolicyV1.signature")?;
        decoder.finish()?;
        let policy = Self {
            provider_id,
            policy_epoch,
            issued_at,
            expires_at,
            auth_padding_class,
            scopes,
            signing_key_id,
            signature,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn policy_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(POLICY_DIGEST_DOMAIN);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut preimage = Vec::with_capacity(POLICY_SIGNATURE_DOMAIN.len() + unsigned.len());
        preimage.extend_from_slice(POLICY_SIGNATURE_DOMAIN);
        preimage.extend_from_slice(&unsigned);
        Ok(preimage)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(512);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.provider_id);
        out.extend_from_slice(&self.policy_epoch.to_le_bytes());
        out.extend_from_slice(&self.issued_at.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.push(self.auth_padding_class as u8);
        out.push(self.scopes.len() as u8);
        for scope in &self.scopes {
            scope.encode_into(&mut out)?;
        }
        out.extend_from_slice(&self.signing_key_id);
        Ok(out)
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.policy_epoch == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyV1",
                reason: "policy epoch must be non-zero",
            });
        }
        if self.issued_at > self.expires_at {
            return Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyV1.validity",
                reason: "issued_at is after expires_at",
            });
        }
        if self.scopes.len() > MAX_POLICY_SCOPES {
            return Err(ServiceProtocolError::TooManyItems {
                field: "ServicePolicyV1.scopes",
                len: self.scopes.len(),
                max: MAX_POLICY_SCOPES,
            });
        }
        let mut scope_ids = HashSet::with_capacity(self.scopes.len());
        let mut offer_ids = HashSet::new();
        let mut bat_verification_keys = HashSet::new();
        let mut encoded_len = 1usize + 32 + (8 * 3) + 1 + 1 + 16 + 64;
        for scope_policy in &self.scopes {
            scope_policy.scope.validate()?;
            if scope_policy.scope.provider_id != self.provider_id {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServiceScopeV1.provider_id",
                    reason: "does not match policy provider",
                });
            }
            if let crate::DatasetBindingV1::CatalogEpoch { epoch } = &scope_policy.scope.dataset {
                if *epoch != self.policy_epoch {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ServiceScopeV1.dataset.catalog_epoch",
                        reason: "catalog dataset binding must equal signed policy epoch",
                    });
                }
            }
            if !scope_ids.insert(scope_policy.scope.scope_id()) {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "ServicePolicyV1.scopes",
                    reason: "duplicate scope ID",
                });
            }
            scope_policy.limits.validate()?;
            encoded_len = encoded_len
                .checked_add(2 + scope_policy.scope.encode().len() + 37 + 1)
                .ok_or(ServiceProtocolError::FieldTooLong {
                    field: "ServicePolicyV1",
                    len: usize::MAX,
                    max: MAX_SIGNED_POLICY_LEN,
                })?;
            if scope_policy.offers.len() > MAX_OFFERS_PER_SCOPE {
                return Err(ServiceProtocolError::TooManyItems {
                    field: "ServiceScopePolicyV1.offers",
                    len: scope_policy.offers.len(),
                    max: MAX_OFFERS_PER_SCOPE,
                });
            }
            for offer in &scope_policy.offers {
                offer.validate_for_scope(&scope_policy.scope, self.issued_at, self.expires_at)?;
                if offer.authorization == AuthScheme::BitcoinPirCashuBatV1 {
                    let verification_key = &offer
                        .credential_binding
                        .as_ref()
                        .ok_or(ServiceProtocolError::InvalidValue {
                            field: "ServicePolicyV1.bat_verification_keys",
                            reason: "BAT offer has no credential key binding",
                        })?
                        .claims
                        .verification_key;
                    if !bat_verification_keys.insert(verification_key.clone()) {
                        return Err(ServiceProtocolError::InvalidValue {
                            field: "ServicePolicyV1.bat_verification_keys",
                            reason: "a BAT key must not span offers, scopes, or profiles",
                        });
                    }
                }
                let offer_len = offer.encode()?.len();
                encoded_len = encoded_len.checked_add(2 + offer_len).ok_or(
                    ServiceProtocolError::FieldTooLong {
                        field: "ServicePolicyV1",
                        len: usize::MAX,
                        max: MAX_SIGNED_POLICY_LEN,
                    },
                )?;
                if !offer_ids.insert(offer.offer_id) {
                    return Err(ServiceProtocolError::InvalidValue {
                        field: "ServiceOfferV1.offer_id",
                        reason: "duplicate offer ID",
                    });
                }
            }
        }
        if encoded_len > MAX_SIGNED_POLICY_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "ServicePolicyV1",
                len: encoded_len,
                max: MAX_SIGNED_POLICY_LEN,
            });
        }
        Ok(())
    }
}

pub fn policy_signing_key_id(verifying_key: &VerifyingKey) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_KEY_ID_DOMAIN);
    hasher.update(verifying_key.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    digest[..16].try_into().expect("fixed digest prefix")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_bat_key_id_v1, derive_cashu_keyset_id_v2, BackendId, CashuDenominationKeyV1,
        CashuKeysetBindingV1, CashuRequiredNutsV1, CredentialKeyBindingClaimsV1, CredentialUnitV1,
        DatasetBindingV1, WorkloadId,
    };
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};

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

    fn scope() -> ServiceScopeV1 {
        ServiceScopeV1 {
            provider_id: [9; 32],
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 2,
        }
    }

    fn offer() -> ServiceOfferV1 {
        let scope = scope();
        let verification_key: [u8; 33] = (ProjectivePoint::GENERATOR * Scalar::from(11u64))
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let credential_key_id = derive_bat_key_id_v1(
            &scope.provider_id,
            &scope.scope_id(),
            7,
            scope.entitlement_profile,
            1,
            &verification_key,
        )
        .to_vec();
        let binding = CredentialKeyBindingV1::sign(
            CredentialKeyBindingClaimsV1 {
                provider_id: scope.provider_id,
                scope_id: scope.scope_id(),
                offer_id: 7,
                scheme: AuthScheme::BitcoinPirCashuBatV1,
                keyset_epoch: 1,
                entitlement_profile: scope.entitlement_profile,
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
        ServiceOfferV1 {
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
        }
    }

    fn cashu_offer() -> ServiceOfferV1 {
        let keys = vec![
            CashuDenominationKeyV1 {
                amount: 1,
                public_key: (ProjectivePoint::GENERATOR * Scalar::from(21u64))
                    .to_affine()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            },
            CashuDenominationKeyV1 {
                amount: 8,
                public_key: (ProjectivePoint::GENERATOR * Scalar::from(22u64))
                    .to_affine()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            },
        ];
        let keyset = CashuKeysetBindingV1 {
            keyset_id: derive_cashu_keyset_id_v2(&keys, "sat", 0, Some(10_000)).unwrap(),
            unit: "sat".into(),
            input_fee_ppk: 0,
            final_expiry: Some(10_000),
            keys,
        };
        let manifest = StandardCashuMintManifestV1 {
            manifest_epoch: 1,
            mint_endpoint: "https://mint.example".into(),
            leaf_spki_sha256_pins: vec![[0x31; 32]],
            unit: "sat".into(),
            required_nuts: CashuRequiredNutsV1::required_v1(),
            accepted_input_keysets: vec![keyset.clone()],
            active_output_keyset: keyset,
        };
        ServiceOfferV1 {
            offer_id: 9,
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
                amount: 9,
            },
            issuer_id: manifest.mint_id(),
            key_id: manifest.manifest_digest().unwrap().to_vec(),
            credential_binding: None,
            cashu_mint_manifest: Some(manifest),
            endpoint: "https://mint.example".into(),
            invoice_expiry_seconds: 0,
            claim_window_seconds: 0,
            minimum_credential_validity_seconds: 3_600,
            retired_policy_grace_seconds: 0,
            credential_count: 1,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .unwrap(),
        }
    }

    fn signed_policy() -> (ServicePolicyV1, VerifyingKey) {
        let scope = scope();
        let provider_id = scope.provider_id;
        let key = SigningKey::from_bytes(&[3; 32]);
        let verifying = key.verifying_key();
        let policy = ServicePolicyV1::sign(
            provider_id,
            8,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: limits(),
                offers: vec![offer()],
            }],
            &key,
        )
        .unwrap();
        (policy, verifying)
    }

    #[test]
    fn signed_policy_roundtrips_and_verifies() {
        let (policy, verifying) = signed_policy();
        let verified = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &verifying,
            )
            .unwrap();
        let guard = PolicyRollbackGuardV1::from_verified(&verified);
        let floors = ServicePolicyEpochFloorsV1::initial()
            .updated_from_verified(&verified)
            .unwrap();
        let decoded = ServicePolicyV1::decode(&policy.encode().unwrap()).unwrap();
        assert_eq!(decoded, policy);
        decoded
            .verify_current_for_acquisition(&policy.provider_id, 150, &guard, &floors, &verifying)
            .unwrap();
        assert_eq!(
            decoded.policy_digest().unwrap(),
            policy.policy_digest().unwrap()
        );
    }

    #[test]
    fn rollback_guard_rejects_same_epoch_fork() {
        let (policy, verifying) = signed_policy();
        let verified = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &verifying,
            )
            .unwrap();
        let guard = PolicyRollbackGuardV1::from_verified(&verified);
        let mut scopes = policy.scopes.clone();
        scopes[0].offers[0].priority_class += 1;
        let fork = ServicePolicyV1::sign(
            policy.provider_id,
            policy.policy_epoch,
            policy.issued_at,
            policy.expires_at,
            policy.auth_padding_class,
            scopes,
            &SigningKey::from_bytes(&[3; 32]),
        )
        .unwrap();

        assert!(matches!(
            fork.verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &guard,
                &ServicePolicyEpochFloorsV1::initial(),
                &verifying,
            ),
            Err(ServiceProtocolError::InvalidValue {
                field: "ServicePolicyV1.policy_digest",
                ..
            })
        ));
    }

    #[test]
    fn credential_epoch_floor_rejects_keyset_rollback() {
        let (policy, verifying) = signed_policy();
        let scope_id = policy.scopes[0].scope.scope_id();
        let offer = &policy.scopes[0].offers[0];
        let floors = ServicePolicyEpochFloorsV1 {
            credential_keysets: vec![CredentialKeysetEpochFloorV1 {
                scope_id,
                scheme: offer.authorization,
                issuer_id: offer.issuer_id,
                minimum_epoch: 2,
            }],
            cashu_manifests: vec![],
        };
        assert!(matches!(
            policy.verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &floors,
                &verifying,
            ),
            Err(ServiceProtocolError::InvalidValue {
                field: "CredentialKeyBindingV1.keyset_epoch",
                ..
            })
        ));
    }

    #[test]
    fn embedded_cashu_manifest_obeys_durable_epoch_floor() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let cashu = cashu_offer();
        let mint_id = cashu.issuer_id;
        let policy = ServicePolicyV1::sign(
            scope().provider_id,
            8,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope: scope(),
                limits: limits(),
                offers: vec![cashu],
            }],
            &key,
        )
        .unwrap();
        let floors = ServicePolicyEpochFloorsV1 {
            credential_keysets: vec![],
            cashu_manifests: vec![CashuManifestEpochFloorV1 {
                mint_id,
                unit: "sat".into(),
                minimum_epoch: 2,
            }],
        };
        assert!(matches!(
            policy.verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &floors,
                &key.verifying_key(),
            ),
            Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuMintManifestV1.manifest_epoch",
                ..
            })
        ));
    }

    #[test]
    fn retired_policy_is_exact_and_redemption_only_within_grace() {
        let (policy, verifying) = signed_policy();
        let digest = policy.policy_digest().unwrap();
        let scope_id = policy.scopes[0].scope.scope_id();
        let verified = policy
            .verify_retired_for_redemption(
                &policy.provider_id,
                &digest,
                &scope_id,
                policy.scopes[0].offers[0].offer_id,
                201,
                &verifying,
            )
            .unwrap();
        assert_eq!(verified.policy_digest, digest);
        assert_eq!(verified.redemption_deadline, 173_600);

        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        assert!(policy
            .verify_retired_for_redemption(
                &policy.provider_id,
                &wrong_digest,
                &scope_id,
                policy.scopes[0].offers[0].offer_id,
                201,
                &verifying,
            )
            .is_err());
        assert!(policy
            .verify_retired_for_redemption(
                &policy.provider_id,
                &digest,
                &scope_id,
                policy.scopes[0].offers[0].offer_id,
                173_601,
                &verifying,
            )
            .is_err());
    }

    #[test]
    fn signature_and_key_id_fail_closed() {
        let (mut policy, verifying) = signed_policy();
        policy.signature[0] ^= 1;
        assert_eq!(
            policy.verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &verifying,
            ),
            Err(ServiceProtocolError::BadSignature)
        );

        let other = SigningKey::from_bytes(&[8; 32]).verifying_key();
        assert_eq!(
            policy.verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &other,
            ),
            Err(ServiceProtocolError::WrongSigningKeyId)
        );
    }

    #[test]
    fn arc_cannot_be_advertised_stable() {
        let mut offer = offer();
        offer.authorization = AuthScheme::ArcV1Experimental;
        assert!(matches!(
            offer.validate(),
            Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.deployment_status",
                ..
            })
        ));

        offer.deployment_status = DeploymentStatus::Experimental;
        assert!(matches!(
            offer.validate(),
            Err(ServiceProtocolError::InvalidValue {
                field: "ServiceOfferV1.credential_presentation_limit",
                ..
            })
        ));
    }

    #[test]
    fn free_mode_is_signed_policy_not_a_paid_offer_option() {
        let mut free = offer();
        free.acquisition = AcquisitionMethod::FreeV1;
        free.authorization = AuthScheme::FreeV1;
        free.verification = VerificationMode::ProviderLocal;
        free.price = PriceV1::Free;
        free.free_mode = FreeModeV1::OpenBestEffort;
        free.issuer_id = [0; 32];
        free.key_id.clear();
        free.credential_binding = None;
        free.endpoint.clear();
        free.privacy_leakage = PrivacyLeakageV1::NONE;
        free.invoice_expiry_seconds = 0;
        free.claim_window_seconds = 0;
        free.retired_policy_grace_seconds = 0;
        free.credential_count = 1;
        free.validate().unwrap();

        free.free_mode = FreeModeV1::NotFree;
        assert!(free.validate().is_err());
        free.free_mode = FreeModeV1::OpenBestEffort;

        let mut paid = offer();
        paid.free_mode = FreeModeV1::ProofOfWork;
        paid.free_pow_difficulty_bits = 20;
        assert!(paid.validate().is_err());

        let mut ip = free.clone();
        ip.free_mode = FreeModeV1::IpRateLimited;
        ip.free_quota = 10;
        ip.free_window_seconds = 60;
        ip.privacy_leakage = PrivacyLeakageV1::from_bits(PrivacyLeakageV1::IP_RATE_BUCKET).unwrap();
        ip.validate().unwrap();

        let mut pow = free;
        pow.free_mode = FreeModeV1::ProofOfWork;
        pow.free_pow_difficulty_bits = MAX_POW_DIFFICULTY_BITS_V1;
        pow.validate().unwrap();
        pow.free_pow_difficulty_bits = MAX_POW_DIFFICULTY_BITS_V1 + 1;
        assert!(pow.validate().is_err());
    }

    #[test]
    fn bolt11_offer_horizons_share_quote_protocol_caps() {
        let mut paid = offer();
        paid.invoice_expiry_seconds = MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1;
        paid.claim_window_seconds = MAX_BOLT11_CLAIM_WINDOW_SECONDS_V1;
        paid.minimum_credential_validity_seconds = MAX_BOLT11_CREDENTIAL_VALIDITY_SECONDS_V1;
        paid.retired_policy_grace_seconds = paid
            .invoice_expiry_seconds
            .checked_add(paid.claim_window_seconds)
            .and_then(|value| value.checked_add(paid.minimum_credential_validity_seconds))
            .unwrap();
        paid.validate().unwrap();

        let mut too_long = paid.clone();
        too_long.invoice_expiry_seconds = MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1 + 1;
        assert!(too_long.validate().is_err());

        let mut too_long = paid.clone();
        too_long.claim_window_seconds = MAX_BOLT11_CLAIM_WINDOW_SECONDS_V1 + 1;
        assert!(too_long.validate().is_err());

        let mut too_long = paid;
        too_long.minimum_credential_validity_seconds =
            MAX_BOLT11_CREDENTIAL_VALIDITY_SECONDS_V1 + 1;
        assert!(too_long.validate().is_err());
    }

    #[test]
    fn endpoint_validation_is_https_and_rejects_authority_confusion() {
        for valid in [
            "https://issuer.example",
            "https://issuer.example:8443/v1/quotes",
        ] {
            assert!(is_allowed_service_endpoint(valid), "{valid}");
        }
        for invalid in [
            "http://127.0.0.1:5601",
            "http://localhost:@evil.example:80/v1",
            "https://user@issuer.example/v1",
            "https://issuer.example/v1?redirect=evil",
            "https://issuer.example/v1#fragment",
            "https://issuer.example\\@evil.example/v1",
            "https://.issuer.example/v1",
            "https://issuer..example/v1",
            "https://issuer.example:0/v1",
            "https://issuer.example:70000/v1",
            "https://Issuer.example/v1",
            "https://issuer.example:443/v1",
            "https://issuer.example:0443/v1",
            "https://issuer.example/v1/",
            "https://issuer.example/",
            "https://issuer.example/v1//quotes",
            "https://issuer.example/v1/../quotes",
            "https://issuer.example/v%31/quotes",
            "https://issuer.example/v1/<quotes",
            "https://issuer.example/v1/`quotes",
            "https://issuer.example/v1/{quotes",
            "https://[2001:db8::1]/v1",
            "https://127.0.0.1/v1",
            "https://2130706433/v1",
            "https://127.1/v1",
            "https://0x7f000001/v1",
        ] {
            assert!(!is_allowed_service_endpoint(invalid), "{invalid}");
        }
    }

    #[test]
    fn bolt11_and_shared_issuer_require_origin_while_standard_cashu_may_use_a_base_path() {
        let mut bolt11 = offer();
        bolt11.endpoint = "https://issuer.example:8443/v1/quotes".into();
        assert!(bolt11.validate().is_err());

        let mut shared = offer();
        shared.endpoint = "https://issuer.example:8443/v1/redeems".into();
        assert!(shared.validate().is_err());

        let mut cashu = cashu_offer();
        let manifest = cashu.cashu_mint_manifest.as_mut().unwrap();
        manifest.mint_endpoint = "https://mint.example/api/v1".into();
        cashu.endpoint = manifest.mint_endpoint.clone();
        cashu.issuer_id = manifest.mint_id();
        cashu.key_id = manifest.manifest_digest().unwrap().to_vec();
        assert!(cashu.validate().is_ok());
    }

    #[test]
    fn anonymous_ticket_privacy_cannot_understate_online_redeem() {
        let mut ticket = offer();
        ticket.acquisition = AcquisitionMethod::FreeV1;
        ticket.authorization = AuthScheme::FreeV1;
        ticket.free_mode = FreeModeV1::AnonymousTicket;
        ticket.price = PriceV1::Free;
        ticket.invoice_expiry_seconds = 0;
        ticket.claim_window_seconds = 0;
        ticket.credential_count = 3;
        ticket.retired_policy_grace_seconds = ticket.minimum_credential_validity_seconds;
        ticket.privacy_leakage =
            PrivacyLeakageV1::from_bits(PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING).unwrap();
        assert!(ticket.validate().is_err());

        ticket.privacy_leakage = PrivacyLeakageV1::from_bits(
            PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                | PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
        )
        .unwrap();
        assert!(ticket.validate().is_ok());
    }

    #[test]
    fn provider_local_blind_credential_discloses_provider_at_issuance() {
        let mut local = offer();
        local.verification = VerificationMode::ProviderLocal;
        local.privacy_leakage = PrivacyLeakageV1::from_bits(
            PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING | PrivacyLeakageV1::PROVIDER_LOCAL_BEARER,
        )
        .unwrap();
        assert!(local.validate().is_err());

        local.privacy_leakage = PrivacyLeakageV1::from_bits(
            PrivacyLeakageV1::ISSUER_ISSUANCE_TIMING
                | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER
                | PrivacyLeakageV1::PROVIDER_LOCAL_BEARER,
        )
        .unwrap();
        local.validate().unwrap();
    }

    #[test]
    fn credential_retention_and_count_fail_closed() {
        let mut paid = offer();
        paid.retired_policy_grace_seconds = paid.minimum_credential_validity_seconds - 1;
        assert!(paid.validate().is_err());

        let mut free = offer();
        free.acquisition = AcquisitionMethod::FreeV1;
        free.authorization = AuthScheme::FreeV1;
        free.verification = VerificationMode::ProviderLocal;
        free.price = PriceV1::Free;
        free.free_mode = FreeModeV1::OpenBestEffort;
        free.issuer_id = [0; 32];
        free.key_id.clear();
        free.credential_binding = None;
        free.endpoint.clear();
        free.invoice_expiry_seconds = 0;
        free.claim_window_seconds = 0;
        free.retired_policy_grace_seconds = 0;
        free.credential_count = 2;
        free.privacy_leakage = PrivacyLeakageV1::NONE;
        assert!(free.validate().is_err());
    }

    #[test]
    fn binding_cannot_outlive_retired_policy_grace() {
        let mut paid = offer();
        let mut claims = paid.credential_binding.take().unwrap().claims;
        claims.not_after += 1;
        paid.credential_binding =
            Some(CredentialKeyBindingV1::sign(claims, &SigningKey::from_bytes(&[8; 32])).unwrap());
        assert!(ServicePolicyV1::sign(
            scope().provider_id,
            8,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope: scope(),
                limits: limits(),
                offers: vec![paid],
            }],
            &SigningKey::from_bytes(&[3; 32]),
        )
        .is_err());
    }

    #[test]
    fn catalog_epoch_binding_must_equal_policy_epoch() {
        let mut catalog_scope = scope();
        catalog_scope.dataset = DatasetBindingV1::CatalogEpoch { epoch: 7 };
        assert!(ServicePolicyV1::sign(
            catalog_scope.provider_id,
            8,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope: catalog_scope,
                limits: limits(),
                offers: vec![],
            }],
            &SigningKey::from_bytes(&[3; 32]),
        )
        .is_err());
    }

    #[test]
    fn bat_verification_key_cannot_span_offers() {
        let first = offer();
        let verification_key: [u8; 33] = first
            .credential_binding
            .as_ref()
            .unwrap()
            .claims
            .verification_key
            .as_slice()
            .try_into()
            .unwrap();
        let mut second = first.clone();
        second.offer_id = 8;
        second.key_id = derive_bat_key_id_v1(
            &scope().provider_id,
            &scope().scope_id(),
            second.offer_id,
            scope().entitlement_profile,
            1,
            &verification_key,
        )
        .to_vec();
        let mut claims = second.credential_binding.take().unwrap().claims;
        claims.offer_id = second.offer_id;
        claims.credential_key_id = second.key_id.clone();
        second.credential_binding =
            Some(CredentialKeyBindingV1::sign(claims, &SigningKey::from_bytes(&[8; 32])).unwrap());

        assert!(ServicePolicyV1::sign(
            scope().provider_id,
            8,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope: scope(),
                limits: limits(),
                offers: vec![first, second],
            }],
            &SigningKey::from_bytes(&[3; 32]),
        )
        .is_err());
    }

    #[test]
    fn prices_fit_bitcoin_and_durable_ledger_bounds() {
        assert!(PriceV1::MilliSatoshi(MAX_BITCOIN_MSAT_V1)
            .encode_into(&mut Vec::new())
            .is_ok());
        assert!(PriceV1::MilliSatoshi(MAX_BITCOIN_MSAT_V1 + 1)
            .encode_into(&mut Vec::new())
            .is_err());
        assert!(PriceV1::Cashu {
            unit: "sat".into(),
            amount: MAX_SERVICE_VALUE_V1,
        }
        .encode_into(&mut Vec::new())
        .is_ok());
        assert!(PriceV1::Cashu {
            unit: "sat".into(),
            amount: MAX_SERVICE_VALUE_V1 + 1,
        }
        .encode_into(&mut Vec::new())
        .is_err());
    }

    #[test]
    fn policy_rejects_duplicate_offer_ids() {
        let (policy, _) = signed_policy();
        let key = SigningKey::from_bytes(&[3; 32]);
        let mut scopes = policy.scopes.clone();
        let duplicate = scopes[0].offers[0].clone();
        scopes[0].offers.push(duplicate);
        assert!(ServicePolicyV1::sign(
            [9; 32],
            8,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            scopes,
            &key
        )
        .is_err());
    }

    #[test]
    fn decode_rejects_trailing_bytes_and_excessive_counts() {
        let (policy, _) = signed_policy();
        let mut encoded = policy.encode().unwrap();
        encoded.push(0);
        assert_eq!(
            ServicePolicyV1::decode(&encoded),
            Err(ServiceProtocolError::TrailingBytes(1))
        );

        let mut encoded = policy.encode().unwrap();
        // version + provider + epoch + issued + expires + padding class
        let scope_count_offset = 1 + 32 + 8 + 8 + 8 + 1;
        encoded[scope_count_offset] = (MAX_POLICY_SCOPES + 1) as u8;
        assert!(matches!(
            ServicePolicyV1::decode(&encoded),
            Err(ServiceProtocolError::TooManyItems { .. })
        ));
    }
}
