//! Pure-Rust BOLT11 verification shared by native and browser builds.
//!
//! This deliberately extracts only the signed facts BitcoinPIR binds into a
//! quote. Payment hashes, payment secrets, descriptions, routes, and fallback
//! addresses are validated only as BOLT11 structural/semantic fields and are
//! never returned to a caller.

use bech32::primitives::checksum::Checksum;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Fe32, Fe32IterExt};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{LightningNetworkV1, ServiceProtocolError};

const SIGNATURE_LEN_FE32: usize = 104;
const TIMESTAMP_LEN_FE32: usize = 7;
const DEFAULT_EXPIRY_SECONDS: u64 = 3_600;

const TAG_PAYMENT_HASH: u8 = 1;
const TAG_DESCRIPTION: u8 = 13;
const TAG_PAYEE_PUBKEY: u8 = 19;
const TAG_DESCRIPTION_HASH: u8 = 23;
const TAG_EXPIRY: u8 = 6;
const TAG_MIN_FINAL_CLTV: u8 = 24;
const TAG_FALLBACK: u8 = 9;
const TAG_PRIVATE_ROUTE: u8 = 3;
const TAG_PAYMENT_SECRET: u8 = 16;
const TAG_PAYMENT_METADATA: u8 = 27;
const TAG_FEATURES: u8 = 5;

/// Standard Bech32 checksum with the ecosystem BOLT11/QR length ceiling.
enum Bolt11Bech32 {}

impl Checksum for Bolt11Bech32 {
    const CODE_LENGTH: usize = 7_089;
    type MidstateRepr = <Bech32 as Checksum>::MidstateRepr;
    const CHECKSUM_LENGTH: usize = Bech32::CHECKSUM_LENGTH;
    const GENERATOR_SH: [Self::MidstateRepr; 5] = Bech32::GENERATOR_SH;
    const TARGET_RESIDUE: Self::MidstateRepr = Bech32::TARGET_RESIDUE;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PureBolt11FactsV1 {
    pub(crate) network: LightningNetworkV1,
    pub(crate) payee_pubkey: [u8; 33],
    pub(crate) amount_msat: u64,
    pub(crate) created_at: u64,
    pub(crate) expiry_seconds: u32,
}

pub(crate) fn parse_and_verify(invoice: &str) -> Result<PureBolt11FactsV1, ServiceProtocolError> {
    let checked = CheckedHrpstring::new::<Bolt11Bech32>(invoice).map_err(|_| invalid_invoice())?;
    let hrp = checked.hrp();
    let (network, amount_msat) = parse_hrp(hrp.as_str())?;
    let data: Vec<Fe32> = checked
        .fe32_iter::<&mut dyn Iterator<Item = u8>>()
        .collect();
    if data.len() < TIMESTAMP_LEN_FE32 + SIGNATURE_LEN_FE32 {
        return Err(invalid_invoice());
    }

    let signature_offset = data.len() - SIGNATURE_LEN_FE32;
    let signed_data = &data[..signature_offset];
    let created_at = parse_u64_be(&signed_data[..TIMESTAMP_LEN_FE32])?;

    let mut payment_hash_count = 0u8;
    let mut description_count = 0u8;
    let mut payment_secret_count = 0u8;
    let mut payee_pubkey = None;
    let mut expiry_seconds = None;
    let mut first_features = None;

    let mut cursor = TIMESTAMP_LEN_FE32;
    while cursor < signed_data.len() {
        if signed_data.len() - cursor < 3 {
            return Err(invalid_invoice());
        }
        let tag = signed_data[cursor].to_u8();
        let len = (usize::from(signed_data[cursor + 1].to_u8()) << 5)
            | usize::from(signed_data[cursor + 2].to_u8());
        cursor = cursor.checked_add(3).ok_or_else(invalid_invoice)?;
        let end = cursor.checked_add(len).ok_or_else(invalid_invoice)?;
        if end > signed_data.len() {
            return Err(invalid_invoice());
        }
        let field = &signed_data[cursor..end];
        cursor = end;

        match tag {
            TAG_PAYMENT_HASH if field.len() == 52 && canonical_byte_field(field) => {
                payment_hash_count = payment_hash_count.saturating_add(1);
            }
            TAG_DESCRIPTION => {
                if !canonical_byte_field(field)
                    || core::str::from_utf8(&field_bytes(field)).is_err()
                {
                    return Err(invalid_invoice());
                }
                description_count = description_count.saturating_add(1);
            }
            TAG_DESCRIPTION_HASH if field.len() == 52 && canonical_byte_field(field) => {
                description_count = description_count.saturating_add(1);
            }
            TAG_PAYEE_PUBKEY if field.len() == 53 && canonical_byte_field(field) => {
                let bytes = field_bytes(field);
                let key = VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| invalid_invoice())?;
                if payee_pubkey.is_none() {
                    let encoded = key.to_encoded_point(true);
                    let mut exact = [0u8; 33];
                    exact.copy_from_slice(encoded.as_bytes());
                    payee_pubkey = Some(exact);
                }
            }
            TAG_EXPIRY => {
                if !canonical_integer_field(field) {
                    return Err(invalid_invoice());
                }
                let value = parse_u64_be(field)?;
                if expiry_seconds.is_none() {
                    expiry_seconds = Some(value);
                }
            }
            TAG_MIN_FINAL_CLTV => {
                if !canonical_integer_field(field) {
                    return Err(invalid_invoice());
                }
                let _ = parse_u64_be(field)?;
            }
            TAG_FALLBACK => validate_fallback_field(field)?,
            TAG_PRIVATE_ROUTE => validate_private_route_field(field)?,
            TAG_PAYMENT_SECRET if field.len() == 52 && canonical_byte_field(field) => {
                payment_secret_count = payment_secret_count.saturating_add(1);
            }
            TAG_PAYMENT_METADATA => {
                if !canonical_byte_field(field) {
                    return Err(invalid_invoice());
                }
            }
            TAG_FEATURES => {
                let features = parse_features(field);
                if !canonical_features(field, &features) {
                    return Err(invalid_invoice());
                }
                if first_features.is_none() {
                    first_features = Some(features);
                }
            }
            _ => {}
        }
    }

    if payment_hash_count != 1 || description_count != 1 || payment_secret_count != 1 {
        return Err(invalid_invoice());
    }
    let features = first_features.ok_or_else(invalid_invoice)?;
    if requires_unknown_feature_bits(&features) || !supports_payment_secret(&features) {
        return Err(invalid_invoice());
    }

    let signature_bytes = field_bytes(&data[signature_offset..]);
    if signature_bytes.len() != 65 {
        return Err(invalid_invoice());
    }
    let signature = Signature::from_slice(&signature_bytes[..64])
        .map_err(|_| ServiceProtocolError::BadSignature)?;
    let recovery_id = RecoveryId::try_from(signature_bytes[64])
        .map_err(|_| ServiceProtocolError::BadSignature)?;
    let signable_hash = signable_hash(hrp.as_str(), signed_data);

    let payee_pubkey = match payee_pubkey {
        Some(encoded) => {
            VerifyingKey::from_sec1_bytes(&encoded)
                .and_then(|key| key.verify_prehash(&signable_hash, &signature))
                .map_err(|_| ServiceProtocolError::BadSignature)?;
            encoded
        }
        None => {
            let recovered =
                VerifyingKey::recover_from_prehash(&signable_hash, &signature, recovery_id)
                    .map_err(|_| ServiceProtocolError::BadSignature)?;
            let encoded = recovered.to_encoded_point(true);
            let mut exact = [0u8; 33];
            exact.copy_from_slice(encoded.as_bytes());
            exact
        }
    };

    let expiry_seconds = u32::try_from(expiry_seconds.unwrap_or(DEFAULT_EXPIRY_SECONDS))
        .map_err(|_| invalid_invoice())?;
    Ok(PureBolt11FactsV1 {
        network,
        payee_pubkey,
        amount_msat,
        created_at,
        expiry_seconds,
    })
}

fn parse_hrp(hrp: &str) -> Result<(LightningNetworkV1, u64), ServiceProtocolError> {
    let body = hrp.strip_prefix("ln").ok_or_else(invalid_invoice)?;
    let (network, amount) = if let Some(amount) = body.strip_prefix("bcrt") {
        (LightningNetworkV1::Regtest, amount)
    } else if let Some(amount) = body.strip_prefix("tbs") {
        (LightningNetworkV1::Signet, amount)
    } else if let Some(amount) = body.strip_prefix("bc") {
        (LightningNetworkV1::Bitcoin, amount)
    } else if let Some(amount) = body.strip_prefix("tb") {
        (LightningNetworkV1::Testnet, amount)
    } else {
        return Err(invalid_invoice());
    };
    if amount.is_empty() {
        return Err(ServiceProtocolError::InvalidValue {
            field: "ParsedBolt11InvoiceV1.amount_msat",
            reason: "amountless BOLT11 invoices are not supported",
        });
    }
    let (digits, multiplier) = match amount.as_bytes().last().copied() {
        Some(b'm') => (&amount[..amount.len() - 1], 100_000_000u64),
        Some(b'u') => (&amount[..amount.len() - 1], 100_000u64),
        Some(b'n') => (&amount[..amount.len() - 1], 100u64),
        Some(b'p') => {
            let digits = &amount[..amount.len() - 1];
            let value = parse_canonical_decimal(digits)?;
            if value % 10 != 0 {
                return Err(invalid_invoice());
            }
            return Ok((network, value / 10));
        }
        _ => (amount, 100_000_000_000u64),
    };
    let value = parse_canonical_decimal(digits)?;
    let amount_msat = value.checked_mul(multiplier).ok_or_else(invalid_invoice)?;
    Ok((network, amount_msat))
}

fn parse_canonical_decimal(value: &str) -> Result<u64, ServiceProtocolError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid_invoice());
    }
    value.parse::<u64>().map_err(|_| invalid_invoice())
}

fn parse_u64_be(field: &[Fe32]) -> Result<u64, ServiceProtocolError> {
    field.iter().try_fold(0u64, |value, digit| {
        value
            .checked_mul(32)
            .and_then(|value| value.checked_add(u64::from(digit.to_u8())))
            .ok_or_else(invalid_invoice)
    })
}

fn field_bytes(field: &[Fe32]) -> Vec<u8> {
    field.iter().copied().fes_to_bytes().collect()
}

fn canonical_byte_field(field: &[Fe32]) -> bool {
    let overhang = field.len() * 5 % 8;
    if overhang > 4 {
        return false;
    }
    overhang == 0
        || field
            .last()
            .is_some_and(|last| last.to_u8() & ((1u8 << overhang) - 1) == 0)
}

fn canonical_integer_field(field: &[Fe32]) -> bool {
    field.is_empty() || field.first().is_some_and(|digit| digit.to_u8() != 0)
}

fn validate_fallback_field(field: &[Fe32]) -> Result<(), ServiceProtocolError> {
    let Some(version) = field.first().map(|value| value.to_u8()) else {
        return Err(invalid_invoice());
    };
    // Unknown fallback versions are explicitly skippable BOLT11 fields and
    // retain their exact signed Fe32 representation.
    if version > 18 {
        return Ok(());
    }
    let program = &field[1..];
    if !canonical_byte_field(program) {
        return Err(invalid_invoice());
    }
    let bytes = field_bytes(program);
    let valid_len = match version {
        0..=16 => (2..=40).contains(&bytes.len()),
        17 => bytes.len() == 20,
        18 => bytes.len() == 32,
        _ => unreachable!(),
    };
    if !valid_len {
        return Err(invalid_invoice());
    }
    Ok(())
}

fn validate_private_route_field(field: &[Fe32]) -> Result<(), ServiceProtocolError> {
    if !canonical_byte_field(field) {
        return Err(invalid_invoice());
    }
    let bytes = field_bytes(field);
    if bytes.len() % 51 != 0 {
        return Err(invalid_invoice());
    }
    for hop in bytes.chunks_exact(51) {
        VerifyingKey::from_sec1_bytes(&hop[..33]).map_err(|_| invalid_invoice())?;
    }
    Ok(())
}

fn parse_features(field: &[Fe32]) -> Vec<u8> {
    let mut carry_bits = 0usize;
    let mut carry = 0u8;
    let mut output = Vec::with_capacity((field.len() * 5).div_ceil(8));
    for digit in field.iter().rev() {
        let digit = digit.to_u8();
        if carry_bits >= 3 {
            output.push(carry + (digit << carry_bits));
            carry = digit >> (8 - carry_bits);
            carry_bits -= 3;
        } else {
            carry += digit << carry_bits;
            carry_bits += 5;
        }
    }
    if carry_bits > 0 {
        output.push(carry);
    }
    while output.last() == Some(&0) {
        output.pop();
    }
    output
}

fn canonical_features(field: &[Fe32], features: &[u8]) -> bool {
    let mut carry = 0u8;
    let mut carry_bits = 0usize;
    let mut output = Vec::new();
    let mut input = features.iter();
    loop {
        let next = if carry_bits >= 5 {
            let next = carry;
            carry >>= 5;
            carry_bits -= 5;
            next
        } else if let Some(byte) = input.next() {
            let next = carry + (*byte << carry_bits);
            carry = *byte >> (5 - carry_bits);
            carry_bits += 3;
            next
        } else if carry_bits > 0 {
            carry_bits = 0;
            carry
        } else {
            break;
        };
        output.push(Fe32::try_from(next & 31).expect("masked to Fe32"));
    }
    output.reverse();
    let first_nonzero = output
        .iter()
        .position(|digit| digit.to_u8() != 0)
        .unwrap_or(output.len());
    output[first_nonzero..] == *field
}

fn supports_payment_secret(features_le: &[u8]) -> bool {
    features_le
        .get(1)
        .is_some_and(|byte| byte & 0b1100_0000 != 0)
}

fn requires_unknown_feature_bits(features_le: &[u8]) -> bool {
    // This is the Bolt11InvoiceContext known-feature mask from LDK 0.3.1:
    // var_onion_optin, payment_secret, basic_mpp, payment_metadata, and
    // trampoline. Feature bytes are little-endian; even bits are required.
    const KNOWN: [u8; 8] = [0x00, 0xc3, 0x03, 0x00, 0x00, 0x00, 0x03, 0x03];
    features_le.iter().enumerate().any(|(index, byte)| {
        let known = KNOWN.get(index).copied().unwrap_or(0);
        byte & (0x55 & !known) != 0
    })
}

fn signable_hash(hrp: &str, signed_data: &[Fe32]) -> [u8; 32] {
    let mut padded = signed_data.to_vec();
    let overhang = padded.len() * 5 % 8;
    if overhang > 0 {
        padded.push(Fe32::Q);
        if overhang < 3 {
            padded.push(Fe32::Q);
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(hrp.as_bytes());
    hasher.update(padded.into_iter().fes_to_bytes().collect::<Vec<_>>());
    hasher.finalize().into()
}

fn invalid_invoice() -> ServiceProtocolError {
    ServiceProtocolError::InvalidValue {
        field: "ParsedBolt11InvoiceV1.invoice",
        reason: "BOLT11 syntax, semantics, or signature validation failed",
    }
}
