//! Canonical manifest pinned by a standard Cashu eCash service offer.
//!
//! Cashu itself transports JSON maps whose ordering is not canonical. This
//! structure gives BitcoinPIR providers and clients one deterministic binary
//! commitment to the exact mint origin, accepted input keysets, active output
//! keyset, denomination keys, NUT-02 fees, and recovery/security features.

use std::collections::HashSet;

use k256::elliptic_curve::{group::prime::PrimeCurveAffine, sec1::FromEncodedPoint};
use k256::{AffinePoint, EncodedPoint};
use sha2::{Digest, Sha256};

use crate::codec::{expect_v1, put_bytes_u16, Decoder};
use crate::policy::is_allowed_service_endpoint;
use crate::{
    ServiceProtocolError, MAX_PRICE_UNIT_LEN, MAX_SERVICE_VALUE_V1, SERVICE_PROTOCOL_VERSION,
};

/// NUT-02 keyset ID V2 is one version byte plus a 32-byte SHA-256 digest,
/// represented as exactly 66 lowercase hexadecimal characters.
pub const CASHU_KEYSET_ID_V2_LEN: usize = 66;
pub const MAX_CASHU_KEYSET_ID_LEN: usize = CASHU_KEYSET_ID_V2_LEN;
pub const MAX_CASHU_INPUT_KEYSETS: usize = 16;
pub const MAX_CASHU_DENOMINATION_KEYS: usize = 64;
pub const MAX_CASHU_KEYSET_ENCODING_LEN: usize = 4 * 1024;
pub const MAX_CASHU_MINT_MANIFEST_LEN: usize = 60 * 1024;

pub const CASHU_MINT_ID_DOMAIN: &[u8] = b"BitcoinPIR/standard-cashu-mint-id/v1";
pub const CASHU_MINT_MANIFEST_DIGEST_DOMAIN: &[u8] =
    b"BitcoinPIR/standard-cashu-mint-manifest-digest/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CashuRequiredNutsV1(u8);

impl CashuRequiredNutsV1 {
    pub const NUT03_SWAP: u8 = 1 << 0;
    pub const NUT07_CHECK_STATE: u8 = 1 << 1;
    pub const NUT09_RESTORE: u8 = 1 << 2;
    pub const NUT12_DLEQ: u8 = 1 << 3;
    pub const REQUIRED_V1: u8 =
        Self::NUT03_SWAP | Self::NUT07_CHECK_STATE | Self::NUT09_RESTORE | Self::NUT12_DLEQ;

    pub fn from_bits(bits: u8) -> Result<Self, ServiceProtocolError> {
        if bits & !Self::REQUIRED_V1 != 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CashuRequiredNutsV1",
                reason: "contains unknown feature flags",
            });
        }
        Ok(Self(bits))
    }

    pub const fn required_v1() -> Self {
        Self(Self::REQUIRED_V1)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    fn validate(self) -> Result<(), ServiceProtocolError> {
        if self.0 != Self::REQUIRED_V1 {
            Err(ServiceProtocolError::InvalidValue {
                field: "CashuRequiredNutsV1",
                reason: "V1 requires NUT-03, NUT-07, NUT-09, and NUT-12",
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashuDenominationKeyV1 {
    pub amount: u64,
    pub public_key: [u8; 33],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashuKeysetBindingV1 {
    pub keyset_id: String,
    pub unit: String,
    pub input_fee_ppk: u32,
    pub final_expiry: Option<u64>,
    pub keys: Vec<CashuDenominationKeyV1>,
}

impl CashuKeysetBindingV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(80 + self.keys.len() * 41);
        out.push(self.keyset_id.len() as u8);
        out.extend_from_slice(self.keyset_id.as_bytes());
        out.push(self.unit.len() as u8);
        out.extend_from_slice(self.unit.as_bytes());
        out.extend_from_slice(&self.input_fee_ppk.to_le_bytes());
        match self.final_expiry {
            Some(final_expiry) => {
                out.push(1);
                out.extend_from_slice(&final_expiry.to_le_bytes());
            }
            None => out.push(0),
        }
        out.push(self.keys.len() as u8);
        for key in &self.keys {
            out.extend_from_slice(&key.amount.to_le_bytes());
            out.extend_from_slice(&key.public_key);
        }
        if out.len() > MAX_CASHU_KEYSET_ENCODING_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "CashuKeysetBindingV1",
                len: out.len(),
                max: MAX_CASHU_KEYSET_ENCODING_LEN,
            });
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        let mut decoder = Decoder::new(bytes);
        let keyset_id_bytes =
            decoder.bytes_u8("CashuKeysetBindingV1.keyset_id", MAX_CASHU_KEYSET_ID_LEN)?;
        let keyset_id = String::from_utf8(keyset_id_bytes)
            .map_err(|_| ServiceProtocolError::InvalidUtf8("CashuKeysetBindingV1.keyset_id"))?;
        let unit_bytes = decoder.bytes_u8("CashuKeysetBindingV1.unit", MAX_PRICE_UNIT_LEN)?;
        let unit = String::from_utf8(unit_bytes)
            .map_err(|_| ServiceProtocolError::InvalidUtf8("CashuKeysetBindingV1.unit"))?;
        let input_fee_ppk = decoder.u32("CashuKeysetBindingV1.input_fee_ppk")?;
        let final_expiry = match decoder.u8("CashuKeysetBindingV1.has_final_expiry")? {
            0 => None,
            1 => Some(decoder.u64("CashuKeysetBindingV1.final_expiry")?),
            value => {
                return Err(ServiceProtocolError::UnknownDiscriminant {
                    kind: "CashuKeysetBindingV1.has_final_expiry",
                    value,
                })
            }
        };
        let count = decoder.u8("CashuKeysetBindingV1.key_count")? as usize;
        if count > MAX_CASHU_DENOMINATION_KEYS {
            return Err(ServiceProtocolError::TooManyItems {
                field: "CashuKeysetBindingV1.keys",
                len: count,
                max: MAX_CASHU_DENOMINATION_KEYS,
            });
        }
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            keys.push(CashuDenominationKeyV1 {
                amount: decoder.u64("CashuDenominationKeyV1.amount")?,
                public_key: decoder.fixed("CashuDenominationKeyV1.public_key")?,
            });
        }
        decoder.finish()?;
        let value = Self {
            keyset_id,
            unit,
            input_fee_ppk,
            final_expiry,
            keys,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ServiceProtocolError> {
        if !is_canonical_cashu_keyset_id_v2(&self.keyset_id) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CashuKeysetBindingV1.keyset_id",
                reason: "V1 integration accepts only canonical lowercase NUT-02 keyset ID V2",
            });
        }
        validate_cashu_unit(&self.unit)?;
        if self.final_expiry == Some(0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CashuKeysetBindingV1.final_expiry",
                reason: "zero must be represented as absent",
            });
        }
        if self.keys.is_empty() || self.keys.len() > MAX_CASHU_DENOMINATION_KEYS {
            return Err(ServiceProtocolError::TooManyItems {
                field: "CashuKeysetBindingV1.keys",
                len: self.keys.len(),
                max: MAX_CASHU_DENOMINATION_KEYS,
            });
        }
        let mut previous = 0u64;
        let mut public_keys = HashSet::with_capacity(self.keys.len());
        for key in &self.keys {
            if key.amount == 0
                || key.amount > MAX_SERVICE_VALUE_V1
                || key.amount <= previous
                || !is_valid_compressed_point(&key.public_key)
                || !public_keys.insert(key.public_key)
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "CashuKeysetBindingV1.keys",
                    reason: "denominations must be strictly increasing with unique compressed keys",
                });
            }
            previous = key.amount;
        }
        if self.keyset_id
            != derive_cashu_keyset_id_v2(
                &self.keys,
                &self.unit,
                self.input_fee_ppk,
                self.final_expiry,
            )?
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CashuKeysetBindingV1.keyset_id",
                reason: "does not match the canonical NUT-02 V2 derivation",
            });
        }
        Ok(())
    }
}

pub fn is_canonical_cashu_keyset_id_v2(keyset_id: &str) -> bool {
    keyset_id.len() == CASHU_KEYSET_ID_V2_LEN
        && keyset_id.starts_with("01")
        && keyset_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardCashuMintManifestV1 {
    pub manifest_epoch: u64,
    pub mint_endpoint: String,
    pub unit: String,
    pub required_nuts: CashuRequiredNutsV1,
    /// Sorted lexicographically by keyset ID; includes active and explicitly
    /// retained input keysets accepted during NUT-03 swap.
    pub accepted_input_keysets: Vec<CashuKeysetBindingV1>,
    pub active_output_keyset: CashuKeysetBindingV1,
}

pub struct StandardCashuMintExpectationV1<'a> {
    pub mint_id: &'a [u8; 32],
    pub manifest_digest: &'a [u8; 32],
    pub mint_endpoint: &'a str,
    pub unit: &'a str,
    /// All advertised input keysets must remain redeemable through this time.
    pub accepted_inputs_valid_through: u64,
    /// Newly created outputs must remain recoverable through this time.
    pub active_output_valid_through: u64,
}

impl StandardCashuMintManifestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ServiceProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(512);
        out.push(SERVICE_PROTOCOL_VERSION);
        out.extend_from_slice(&self.manifest_epoch.to_le_bytes());
        put_bytes_u16(&mut out, self.mint_endpoint.as_bytes());
        out.push(self.unit.len() as u8);
        out.extend_from_slice(self.unit.as_bytes());
        out.push(self.required_nuts.bits());
        out.push(self.accepted_input_keysets.len() as u8);
        for keyset in &self.accepted_input_keysets {
            put_bytes_u16(&mut out, &keyset.encode()?);
        }
        put_bytes_u16(&mut out, &self.active_output_keyset.encode()?);
        if out.len() > MAX_CASHU_MINT_MANIFEST_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "StandardCashuMintManifestV1",
                len: out.len(),
                max: MAX_CASHU_MINT_MANIFEST_LEN,
            });
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ServiceProtocolError> {
        if bytes.len() > MAX_CASHU_MINT_MANIFEST_LEN {
            return Err(ServiceProtocolError::FieldTooLong {
                field: "StandardCashuMintManifestV1",
                len: bytes.len(),
                max: MAX_CASHU_MINT_MANIFEST_LEN,
            });
        }
        let mut decoder = Decoder::new(bytes);
        expect_v1(
            decoder.u8("StandardCashuMintManifestV1.version")?,
            "StandardCashuMintManifestV1",
        )?;
        let manifest_epoch = decoder.u64("StandardCashuMintManifestV1.manifest_epoch")?;
        let mint_endpoint = decoder.string_u16(
            "StandardCashuMintManifestV1.mint_endpoint",
            crate::MAX_ENDPOINT_LEN,
        )?;
        let unit_bytes =
            decoder.bytes_u8("StandardCashuMintManifestV1.unit", MAX_PRICE_UNIT_LEN)?;
        let unit = String::from_utf8(unit_bytes)
            .map_err(|_| ServiceProtocolError::InvalidUtf8("StandardCashuMintManifestV1.unit"))?;
        let required_nuts = CashuRequiredNutsV1::from_bits(
            decoder.u8("StandardCashuMintManifestV1.required_nuts")?,
        )?;
        let count = decoder.u8("StandardCashuMintManifestV1.input_keyset_count")? as usize;
        if count > MAX_CASHU_INPUT_KEYSETS {
            return Err(ServiceProtocolError::TooManyItems {
                field: "StandardCashuMintManifestV1.accepted_input_keysets",
                len: count,
                max: MAX_CASHU_INPUT_KEYSETS,
            });
        }
        let mut accepted_input_keysets = Vec::with_capacity(count);
        for _ in 0..count {
            accepted_input_keysets.push(CashuKeysetBindingV1::decode(&decoder.bytes_u16(
                "StandardCashuMintManifestV1.input_keyset",
                MAX_CASHU_KEYSET_ENCODING_LEN,
            )?)?);
        }
        let active_output_keyset = CashuKeysetBindingV1::decode(&decoder.bytes_u16(
            "StandardCashuMintManifestV1.active_output_keyset",
            MAX_CASHU_KEYSET_ENCODING_LEN,
        )?)?;
        decoder.finish()?;
        let value = Self {
            manifest_epoch,
            mint_endpoint,
            unit,
            required_nuts,
            accepted_input_keysets,
            active_output_keyset,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn manifest_digest(&self) -> Result<[u8; 32], ServiceProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(CASHU_MINT_MANIFEST_DIGEST_DOMAIN);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }

    pub fn mint_id(&self) -> [u8; 32] {
        derive_cashu_mint_id(&self.mint_endpoint)
    }

    pub fn verify_for(
        &self,
        expected: &StandardCashuMintExpectationV1<'_>,
        minimum_manifest_epoch: u64,
    ) -> Result<(), ServiceProtocolError> {
        self.validate()?;
        if &self.mint_id() != expected.mint_id
            || &self.manifest_digest()? != expected.manifest_digest
            || self.mint_endpoint != expected.mint_endpoint
            || self.unit != expected.unit
            || self.manifest_epoch < minimum_manifest_epoch
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuMintManifestV1.binding",
                reason: "mint, manifest, endpoint, unit, or epoch mismatch",
            });
        }
        for keyset in &self.accepted_input_keysets {
            if keyset
                .final_expiry
                .is_some_and(|expiry| expiry < expected.accepted_inputs_valid_through)
            {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "StandardCashuMintManifestV1.input_final_expiry",
                    reason: "accepted input keyset expires before the offer horizon",
                });
            }
        }
        if self
            .active_output_keyset
            .final_expiry
            .is_some_and(|expiry| expiry < expected.active_output_valid_through)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuMintManifestV1.output_final_expiry",
                reason: "active output keyset expires before the recovery horizon",
            });
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ServiceProtocolError> {
        if self.manifest_epoch == 0 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuMintManifestV1.manifest_epoch",
                reason: "must be non-zero",
            });
        }
        if !is_allowed_service_endpoint(&self.mint_endpoint) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuMintManifestV1.mint_endpoint",
                reason: "must be a canonical HTTPS mint base URL",
            });
        }
        validate_cashu_unit(&self.unit)?;
        self.required_nuts.validate()?;
        if self.accepted_input_keysets.is_empty()
            || self.accepted_input_keysets.len() > MAX_CASHU_INPUT_KEYSETS
        {
            return Err(ServiceProtocolError::TooManyItems {
                field: "StandardCashuMintManifestV1.accepted_input_keysets",
                len: self.accepted_input_keysets.len(),
                max: MAX_CASHU_INPUT_KEYSETS,
            });
        }
        self.active_output_keyset.validate()?;
        let mut previous: Option<&str> = None;
        let mut active_matches = 0usize;
        for keyset in &self.accepted_input_keysets {
            keyset.validate()?;
            if keyset.unit != self.unit {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "StandardCashuMintManifestV1.unit",
                    reason: "every accepted keyset must use the manifest unit",
                });
            }
            if previous.is_some_and(|id| id >= keyset.keyset_id.as_str()) {
                return Err(ServiceProtocolError::InvalidValue {
                    field: "StandardCashuMintManifestV1.accepted_input_keysets",
                    reason: "input keysets must be unique and lexicographically sorted",
                });
            }
            if keyset == &self.active_output_keyset {
                active_matches += 1;
            }
            previous = Some(&keyset.keyset_id);
        }
        if active_matches != 1 {
            return Err(ServiceProtocolError::InvalidValue {
                field: "StandardCashuMintManifestV1.active_output_keyset",
                reason: "active output keyset must appear exactly in accepted inputs",
            });
        }
        Ok(())
    }
}

pub fn derive_cashu_keyset_id_v2(
    keys: &[CashuDenominationKeyV1],
    unit: &str,
    input_fee_ppk: u32,
    final_expiry: Option<u64>,
) -> Result<String, ServiceProtocolError> {
    validate_cashu_unit(unit)?;
    if keys.is_empty() || keys.len() > MAX_CASHU_DENOMINATION_KEYS {
        return Err(ServiceProtocolError::TooManyItems {
            field: "CashuKeysetBindingV1.keys",
            len: keys.len(),
            max: MAX_CASHU_DENOMINATION_KEYS,
        });
    }
    if final_expiry == Some(0) {
        return Err(ServiceProtocolError::InvalidValue {
            field: "CashuKeysetBindingV1.final_expiry",
            reason: "zero must be represented as absent",
        });
    }
    let mut preimage = String::new();
    let mut previous = 0u64;
    for (index, key) in keys.iter().enumerate() {
        if key.amount == 0
            || key.amount > MAX_SERVICE_VALUE_V1
            || key.amount <= previous
            || !is_valid_compressed_point(&key.public_key)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "CashuKeysetBindingV1.keys",
                reason: "cannot derive ID from invalid or unsorted denomination keys",
            });
        }
        if index != 0 {
            preimage.push(',');
        }
        preimage.push_str(&key.amount.to_string());
        preimage.push(':');
        preimage.push_str(&hex_lower(&key.public_key));
        previous = key.amount;
    }
    preimage.push_str("|unit:");
    preimage.push_str(unit);
    if input_fee_ppk != 0 {
        preimage.push_str("|input_fee_ppk:");
        preimage.push_str(&input_fee_ppk.to_string());
    }
    if let Some(final_expiry) = final_expiry {
        preimage.push_str("|final_expiry:");
        preimage.push_str(&final_expiry.to_string());
    }
    let digest = Sha256::digest(preimage.as_bytes());
    let mut id = String::with_capacity(CASHU_KEYSET_ID_V2_LEN);
    id.push_str("01");
    id.push_str(&hex_lower(&digest));
    Ok(id)
}

fn validate_cashu_unit(unit: &str) -> Result<(), ServiceProtocolError> {
    if unit.is_empty()
        || unit.len() > MAX_PRICE_UNIT_LEN
        || !unit.is_ascii()
        || !unit
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        Err(ServiceProtocolError::InvalidValue {
            field: "Cashu.unit",
            reason: "unit must be bounded lowercase ASCII",
        })
    } else {
        Ok(())
    }
}

pub(crate) fn is_valid_compressed_point(bytes: &[u8; 33]) -> bool {
    EncodedPoint::from_bytes(bytes)
        .ok()
        .and_then(|encoded| Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)))
        .is_some_and(|point| !bool::from(point.is_identity()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn derive_cashu_mint_id(canonical_https_endpoint: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CASHU_MINT_ID_DOMAIN);
    hasher.update((canonical_https_endpoint.len() as u32).to_le_bytes());
    hasher.update(canonical_https_endpoint.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};

    fn point(multiplier: u64) -> [u8; 33] {
        let encoded = (ProjectivePoint::GENERATOR * Scalar::from(multiplier))
            .to_affine()
            .to_encoded_point(true);
        encoded.as_bytes().try_into().unwrap()
    }

    fn keyset(seed: u64) -> CashuKeysetBindingV1 {
        let keys = vec![
            CashuDenominationKeyV1 {
                amount: 1,
                public_key: point(seed),
            },
            CashuDenominationKeyV1 {
                amount: 2,
                public_key: point(seed + 1),
            },
        ];
        let input_fee_ppk = 100;
        let final_expiry = Some(2_000_000_000);
        let keyset_id =
            derive_cashu_keyset_id_v2(&keys, "sat", input_fee_ppk, final_expiry).unwrap();
        CashuKeysetBindingV1 {
            keyset_id,
            unit: "sat".into(),
            input_fee_ppk: 100,
            final_expiry,
            keys,
        }
    }

    fn sample_manifest() -> StandardCashuMintManifestV1 {
        let active = keyset(1);
        let retired = keyset(10);
        let mut accepted_input_keysets = vec![active.clone(), retired];
        accepted_input_keysets.sort_by(|left, right| left.keyset_id.cmp(&right.keyset_id));
        StandardCashuMintManifestV1 {
            manifest_epoch: 7,
            mint_endpoint: "https://mint.example".into(),
            unit: "sat".into(),
            required_nuts: CashuRequiredNutsV1::required_v1(),
            accepted_input_keysets,
            active_output_keyset: active,
        }
    }

    #[test]
    fn manifest_roundtrips_and_binds_offer_fields() {
        let manifest = sample_manifest();
        let decoded = StandardCashuMintManifestV1::decode(&manifest.encode().unwrap()).unwrap();
        assert_eq!(decoded, manifest);
        manifest
            .verify_for(
                &StandardCashuMintExpectationV1 {
                    mint_id: &manifest.mint_id(),
                    manifest_digest: &manifest.manifest_digest().unwrap(),
                    mint_endpoint: "https://mint.example",
                    unit: "sat",
                    accepted_inputs_valid_through: 1_900_000_000,
                    active_output_valid_through: 1_900_000_000,
                },
                7,
            )
            .unwrap();
    }

    #[test]
    fn manifest_rejects_missing_nuts_unsorted_keys_and_endpoint_drift() {
        let mut manifest = sample_manifest();
        manifest.required_nuts =
            CashuRequiredNutsV1::from_bits(CashuRequiredNutsV1::NUT03_SWAP).unwrap();
        assert!(manifest.encode().is_err());

        let mut manifest = sample_manifest();
        manifest.accepted_input_keysets.reverse();
        assert!(manifest.encode().is_err());

        let mut manifest = sample_manifest();
        manifest.active_output_keyset.keys.reverse();
        assert!(manifest.encode().is_err());

        let mut manifest = sample_manifest();
        manifest.accepted_input_keysets[0]
            .keyset_id
            .replace_range(0..2, "00");
        assert!(manifest.encode().is_err());

        let manifest = sample_manifest();
        assert!(manifest
            .verify_for(
                &StandardCashuMintExpectationV1 {
                    mint_id: &manifest.mint_id(),
                    manifest_digest: &manifest.manifest_digest().unwrap(),
                    mint_endpoint: "https://other.example",
                    unit: "sat",
                    accepted_inputs_valid_through: 1_900_000_000,
                    active_output_valid_through: 1_900_000_000,
                },
                7,
            )
            .is_err());
    }
}
