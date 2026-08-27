//! Deterministic, strict Cashu NUT-00 V4 (`cashuB`) token codec.

use std::collections::HashSet;
use std::fmt;

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{BoundedZeroizingWriterV1, CashuClientErrorV1};
use pir_service_protocol::{validate_cashu_unit_v1, MAX_PRICE_UNIT_LEN};

pub const MAX_CASHUB_SERIALIZED_CHARS_V1: usize = 128 * 1024;
pub const MAX_CASHUB_CBOR_BYTES_V1: usize = 64 * 1024;
pub const MAX_CASHUB_PROOFS_V1: usize = 512;
pub const MAX_CASHUB_GROUPS_V1: usize = 16;
pub const MAX_CASHUB_MINT_ENDPOINT_BYTES_V1: usize = 2_048;

/// Conservative bound for this codec's deterministic no-memo/no-DLEQ V4
/// representation: 117 bytes per proof, 43 per full-ID group, and root text.
pub fn cashub_encoded_upper_bound_v1(
    proof_count: usize,
    group_count: usize,
    mint_endpoint_bytes: usize,
    unit_bytes: usize,
) -> Result<usize, CashuClientErrorV1> {
    if proof_count == 0
        || proof_count > MAX_CASHUB_PROOFS_V1
        || group_count == 0
        || group_count > MAX_CASHUB_GROUPS_V1
        || mint_endpoint_bytes == 0
        || mint_endpoint_bytes > MAX_CASHUB_MINT_ENDPOINT_BYTES_V1
        || unit_bytes == 0
        || unit_bytes > MAX_PRICE_UNIT_LEN
    {
        return Err(CashuClientErrorV1::InvalidCashuToken);
    }
    let cbor = 15usize
        .checked_add(mint_endpoint_bytes)
        .and_then(|value| value.checked_add(unit_bytes))
        .and_then(|value| value.checked_add(group_count.checked_mul(43)?))
        .and_then(|value| value.checked_add(proof_count.checked_mul(117)?))
        .ok_or(CashuClientErrorV1::InvalidCashuToken)?;
    if cbor > MAX_CASHUB_CBOR_BYTES_V1 {
        return Err(CashuClientErrorV1::InvalidCashuToken);
    }
    let base64 = cbor
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .and_then(|value| value.checked_add(6))
        .ok_or(CashuClientErrorV1::InvalidCashuToken)?;
    if base64 > MAX_CASHUB_SERIALIZED_CHARS_V1 {
        return Err(CashuClientErrorV1::InvalidCashuToken);
    }
    Ok(base64)
}

#[derive(Eq, PartialEq)]
pub struct CashuTokenV4ProofV1 {
    amount: u64,
    secret: String,
    c: [u8; 33],
}

impl CashuTokenV4ProofV1 {
    pub fn new(amount: u64, secret: String, mut c: [u8; 33]) -> Result<Self, CashuClientErrorV1> {
        let mut secret = Zeroizing::new(secret);
        if amount == 0 || !is_lower_hex_32(&secret) || !is_compressed_point_encoding(&c) {
            c.zeroize();
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        Ok(Self {
            amount,
            secret: std::mem::take(&mut *secret),
            c,
        })
    }

    pub const fn amount(&self) -> u64 {
        self.amount
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub const fn c(&self) -> &[u8; 33] {
        &self.c
    }
}

impl fmt::Debug for CashuTokenV4ProofV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CashuTokenV4ProofV1")
            .field("amount", &self.amount)
            .field("secret", &"[REDACTED]")
            .field("c", &"[COMPRESSED_POINT]")
            .finish()
    }
}

impl Drop for CashuTokenV4ProofV1 {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.c.zeroize();
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CashuTokenV4GroupV1 {
    keyset_id: Vec<u8>,
    proofs: Vec<CashuTokenV4ProofV1>,
}

impl CashuTokenV4GroupV1 {
    pub fn new(
        keyset_id: Vec<u8>,
        proofs: Vec<CashuTokenV4ProofV1>,
    ) -> Result<Self, CashuClientErrorV1> {
        if !matches!(keyset_id.len(), 8 | 33)
            || proofs.is_empty()
            || proofs.len() > MAX_CASHUB_PROOFS_V1
        {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        Ok(Self { keyset_id, proofs })
    }

    /// Use the standard first-eight-byte short form for a canonical full
    /// lowercase-hex keyset ID.
    pub fn short_from_full_hex(
        full_keyset_id: &str,
        proofs: Vec<CashuTokenV4ProofV1>,
    ) -> Result<Self, CashuClientErrorV1> {
        if full_keyset_id.len() != 66 || !is_lower_hex(full_keyset_id.as_bytes()) {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        let mut short = Vec::with_capacity(8);
        for pair in full_keyset_id.as_bytes()[..16].chunks_exact(2) {
            short.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
        }
        Self::new(short, proofs)
    }

    pub fn keyset_id(&self) -> &[u8] {
        &self.keyset_id
    }

    pub fn proofs(&self) -> &[CashuTokenV4ProofV1] {
        &self.proofs
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CashuTokenV4V1 {
    mint_endpoint: String,
    unit: String,
    groups: Vec<CashuTokenV4GroupV1>,
}

impl CashuTokenV4V1 {
    pub fn new(
        mint_endpoint: String,
        unit: String,
        groups: Vec<CashuTokenV4GroupV1>,
    ) -> Result<Self, CashuClientErrorV1> {
        if mint_endpoint.is_empty()
            || mint_endpoint.ends_with('/')
            || mint_endpoint.len() > MAX_CASHUB_MINT_ENDPOINT_BYTES_V1
            || validate_cashu_unit_v1(&unit).is_err()
            || groups.is_empty()
            || groups.len() > MAX_CASHUB_GROUPS_V1
        {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        let mut ids = HashSet::with_capacity(groups.len());
        let mut proof_count = 0usize;
        for group in &groups {
            if !ids.insert(group.keyset_id.clone()) {
                return Err(CashuClientErrorV1::InvalidCashuToken);
            }
            proof_count = proof_count
                .checked_add(group.proofs.len())
                .ok_or(CashuClientErrorV1::InvalidCashuToken)?;
        }
        if proof_count == 0 || proof_count > MAX_CASHUB_PROOFS_V1 {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        cashub_encoded_upper_bound_v1(proof_count, groups.len(), mint_endpoint.len(), unit.len())?;
        Ok(Self {
            mint_endpoint,
            unit,
            groups,
        })
    }

    pub fn mint_endpoint(&self) -> &str {
        &self.mint_endpoint
    }

    pub fn unit(&self) -> &str {
        &self.unit
    }

    pub fn groups(&self) -> &[CashuTokenV4GroupV1] {
        &self.groups
    }

    pub fn encode_cashub(&self) -> Result<Zeroizing<String>, CashuClientErrorV1> {
        let bytes = self.encode_cbor()?;
        let proof_count = self.groups.iter().try_fold(0usize, |count, group| {
            count
                .checked_add(group.proofs.len())
                .ok_or(CashuClientErrorV1::InvalidCashuToken)
        })?;
        let encoded_bound = cashub_encoded_upper_bound_v1(
            proof_count,
            self.groups.len(),
            self.mint_endpoint.len(),
            self.unit.len(),
        )?;
        let mut encoded = Zeroizing::new(String::with_capacity(encoded_bound));
        encoded.push_str("cashuB");
        URL_SAFE_NO_PAD.encode_string(bytes.as_slice(), &mut encoded);
        if encoded.len() > encoded_bound {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        Ok(encoded)
    }

    fn encode_cbor(&self) -> Result<Zeroizing<Vec<u8>>, CashuClientErrorV1> {
        let groups = self
            .groups
            .iter()
            .map(|group| {
                let proofs = group
                    .proofs
                    .iter()
                    .map(|proof| EncodedProofV4 {
                        amount: proof.amount,
                        secret: &proof.secret,
                        c: &proof.c,
                    })
                    .collect();
                EncodedGroupV4 {
                    keyset_id: &group.keyset_id,
                    proofs,
                }
            })
            .collect();
        let root = EncodedTokenV4 {
            groups,
            mint_endpoint: &self.mint_endpoint,
            unit: &self.unit,
        };
        let mut writer = BoundedZeroizingWriterV1::new(MAX_CASHUB_CBOR_BYTES_V1);
        ciborium::into_writer(&root, &mut writer)
            .map_err(|_| CashuClientErrorV1::InvalidCashuToken)?;
        let bytes = writer.into_inner();
        if bytes.is_empty() || bytes.len() > MAX_CASHUB_CBOR_BYTES_V1 {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        Ok(bytes)
    }

    pub fn decode_cashub(serialized: &str) -> Result<Self, CashuClientErrorV1> {
        let token = serialized.strip_prefix("cashu:").unwrap_or(serialized);
        if token.len() > MAX_CASHUB_SERIALIZED_CHARS_V1 || token.trim() != token {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        let encoded = token
            .strip_prefix("cashuB")
            .ok_or(CashuClientErrorV1::InvalidCashuToken)?;
        let padded = encoded.contains('=');
        let decoded_len = decoded_base64_len_v1(encoded, padded)?;
        if decoded_len == 0 || decoded_len > MAX_CASHUB_CBOR_BYTES_V1 {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(decoded_len));
        bytes.resize(decoded_len, 0);
        let mut canonical = Zeroizing::new(String::with_capacity(encoded.len()));
        let written = if padded {
            URL_SAFE
                .decode_slice(encoded, bytes.as_mut_slice())
                .map_err(|_| CashuClientErrorV1::InvalidCashuToken)?
        } else {
            URL_SAFE_NO_PAD
                .decode_slice(encoded, bytes.as_mut_slice())
                .map_err(|_| CashuClientErrorV1::InvalidCashuToken)?
        };
        if written != decoded_len {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        if padded {
            URL_SAFE.encode_string(bytes.as_slice(), &mut canonical);
        } else {
            URL_SAFE_NO_PAD.encode_string(bytes.as_slice(), &mut canonical);
        }
        if canonical.as_str() != encoded {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        if bytes.is_empty() || bytes.len() > MAX_CASHUB_CBOR_BYTES_V1 {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        // Ciborium's default decoder owns an ordinary 4 KiB scratch buffer.
        // Supply our own zeroizing scratch because it temporarily contains
        // proof secrets, C values, and optional DLEQ material before visitors
        // take ownership.
        let mut scratch = Zeroizing::new([0u8; 4_096]);
        let value: DecodedTokenV4 =
            ciborium::from_reader_with_buffer(bytes.as_slice(), scratch.as_mut_slice())
                .map_err(|_| CashuClientErrorV1::InvalidCashuToken)?;
        parse_token(value)
    }
}

fn decoded_base64_len_v1(encoded: &str, padded: bool) -> Result<usize, CashuClientErrorV1> {
    let full_quads = encoded.len() / 4;
    let remainder = encoded.len() % 4;
    let decoded = full_quads
        .checked_mul(3)
        .ok_or(CashuClientErrorV1::InvalidCashuToken)?;
    if padded {
        if remainder != 0 {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        let padding = encoded
            .as_bytes()
            .iter()
            .rev()
            .take_while(|byte| **byte == b'=')
            .count();
        if !(1..=2).contains(&padding) {
            return Err(CashuClientErrorV1::InvalidCashuToken);
        }
        decoded
            .checked_sub(padding)
            .ok_or(CashuClientErrorV1::InvalidCashuToken)
    } else {
        let tail = match remainder {
            0 => 0,
            2 => 1,
            3 => 2,
            _ => return Err(CashuClientErrorV1::InvalidCashuToken),
        };
        decoded
            .checked_add(tail)
            .ok_or(CashuClientErrorV1::InvalidCashuToken)
    }
}

#[derive(Serialize)]
struct EncodedTokenV4<'a> {
    /// Declaration order matches CDK's deterministic V4 encoder.
    #[serde(rename = "m")]
    mint_endpoint: &'a str,
    #[serde(rename = "u")]
    unit: &'a str,
    #[serde(rename = "t")]
    groups: Vec<EncodedGroupV4<'a>>,
}

#[derive(Serialize)]
struct EncodedGroupV4<'a> {
    #[serde(rename = "i", with = "serde_bytes")]
    keyset_id: &'a [u8],
    #[serde(rename = "p")]
    proofs: Vec<EncodedProofV4<'a>>,
}

#[derive(Serialize)]
struct EncodedProofV4<'a> {
    #[serde(rename = "a")]
    amount: u64,
    #[serde(rename = "s")]
    secret: &'a str,
    #[serde(rename = "c", with = "serde_bytes")]
    c: &'a [u8],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodedTokenV4 {
    #[serde(rename = "m")]
    mint_endpoint: String,
    #[serde(rename = "u")]
    unit: String,
    #[serde(rename = "t")]
    groups: Vec<DecodedGroupV4>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodedGroupV4 {
    #[serde(rename = "i", with = "serde_bytes")]
    keyset_id: Vec<u8>,
    #[serde(rename = "p")]
    proofs: Vec<DecodedProofV4>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodedProofV4 {
    #[serde(rename = "a")]
    amount: u64,
    #[serde(rename = "s")]
    secret: SensitiveString,
    #[serde(rename = "c")]
    c: SensitiveBytes,
    #[serde(rename = "d")]
    dleq: Option<DecodedDleqV4>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodedDleqV4 {
    e: SensitiveBytes,
    s: SensitiveBytes,
    r: SensitiveBytes,
}

struct SensitiveString(Zeroizing<String>);

impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(SensitiveStringVisitor)
    }
}

impl SensitiveString {
    fn take(&mut self) -> String {
        std::mem::take(&mut *self.0)
    }
}

struct SensitiveStringVisitor;

impl<'de> Visitor<'de> for SensitiveStringVisitor {
    type Value = SensitiveString;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Cashu proof secret of at most 64 bytes")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(value)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > 64 {
            return Err(E::invalid_length(value.len(), &self));
        }
        let mut owned = Zeroizing::new(String::with_capacity(value.len()));
        owned.push_str(value);
        Ok(SensitiveString(owned))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let owned = Zeroizing::new(value);
        if owned.len() > 64 {
            return Err(E::invalid_length(owned.len(), &self));
        }
        Ok(SensitiveString(owned))
    }
}

struct SensitiveBytes(Zeroizing<Vec<u8>>);

impl<'de> Deserialize<'de> for SensitiveBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SensitiveBytesVisitor)
    }
}

impl SensitiveBytes {
    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut *self.0)
    }
}

struct SensitiveBytesVisitor;

impl<'de> Visitor<'de> for SensitiveBytesVisitor {
    type Value = SensitiveBytes;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("at most 33 Cashu proof bytes")
    }

    fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_bytes(value)
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > 33 {
            return Err(E::invalid_length(value.len(), &self));
        }
        let mut owned = Zeroizing::new(Vec::with_capacity(value.len()));
        owned.extend_from_slice(value);
        Ok(SensitiveBytes(owned))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let owned = Zeroizing::new(value);
        if owned.len() > 33 {
            return Err(E::invalid_length(owned.len(), &self));
        }
        Ok(SensitiveBytes(owned))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut owned = Zeroizing::new(Vec::with_capacity(33));
        while let Some(byte) = sequence.next_element()? {
            if owned.len() == 33 {
                return Err(de::Error::invalid_length(34, &self));
            }
            owned.push(byte);
        }
        Ok(SensitiveBytes(owned))
    }
}

fn parse_token(value: DecodedTokenV4) -> Result<CashuTokenV4V1, CashuClientErrorV1> {
    let groups = value
        .groups
        .into_iter()
        .map(|group| {
            let proofs = group
                .proofs
                .into_iter()
                .map(|mut proof| {
                    if proof.dleq.as_ref().is_some_and(|dleq| {
                        dleq.e.0.len() != 32 || dleq.s.0.len() != 32 || dleq.r.0.len() != 32
                    }) {
                        return Err(CashuClientErrorV1::InvalidCashuToken);
                    }
                    let c_bytes = Zeroizing::new(proof.c.take());
                    if c_bytes.len() != 33 {
                        return Err(CashuClientErrorV1::InvalidCashuToken);
                    }
                    let mut c = Zeroizing::new([0u8; 33]);
                    c.copy_from_slice(c_bytes.as_slice());
                    if proof.amount == 0
                        || !is_lower_hex_32(&proof.secret.0)
                        || !is_compressed_point_encoding(&c)
                    {
                        return Err(CashuClientErrorV1::InvalidCashuToken);
                    }
                    Ok(CashuTokenV4ProofV1 {
                        amount: proof.amount,
                        secret: proof.secret.take(),
                        c: *c,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            CashuTokenV4GroupV1::new(group.keyset_id, proofs)
        })
        .collect::<Result<Vec<_>, _>>()?;
    CashuTokenV4V1::new(value.mint_endpoint, value.unit, groups)
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64 && is_lower_hex(value.as_bytes())
}

fn is_lower_hex(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn hex_nibble(byte: u8) -> Result<u8, CashuClientErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(CashuClientErrorV1::InvalidCashuToken),
    }
}

fn is_compressed_point_encoding(value: &[u8; 33]) -> bool {
    matches!(value[0], 0x02 | 0x03) && value[1..].iter().any(|byte| *byte != 0)
}
