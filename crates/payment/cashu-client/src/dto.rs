use std::{fmt, mem};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    BoundedZeroizingWriterV1, CashuClientErrorV1, MAX_CASHU_MINT_JSON_BYTES_V1,
    MAX_CASHU_SWAP_ITEMS_V1,
};

pub(crate) const MAX_NUT07_WITNESS_BYTES_V1: usize = 16 * 1024;

/// Owns mint-controlled text while serde is still fallible.
///
/// In particular, a later duplicate/unknown/type error must wipe an already
/// decoded NUT-07 Y/witness even though its outer DTO was
/// never constructed. Successful NUT-07 decoding transfers the allocation to
/// the existing public `String` fields, whose DTO `Drop` performs the wipe.
struct SensitiveCashuStringV1(String);

impl SensitiveCashuStringV1 {
    #[cfg(test)]
    fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn into_string(mut self) -> String {
        mem::take(&mut self.0)
    }
}

impl fmt::Debug for SensitiveCashuStringV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for SensitiveCashuStringV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

impl Drop for SensitiveCashuStringV1 {
    fn drop(&mut self) {
        #[cfg(test)]
        let contained_bytes = !self.0.is_empty();
        self.0.zeroize();
        #[cfg(test)]
        if contained_bytes {
            debug_assert!(self.0.is_empty());
            SENSITIVE_CASHU_STRING_ZEROIZED_DROPS_V1
                .with(|count| count.set(count.get().saturating_add(1)));
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static SENSITIVE_CASHU_STRING_ZEROIZED_DROPS_V1: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CashuProofJsonV1 {
    pub amount: u64,
    pub id: String,
    pub secret: String,
    #[serde(rename = "C")]
    pub c: String,
}

impl Drop for CashuProofJsonV1 {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.c.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensitiveCashuProofJsonV1 {
    amount: u64,
    id: String,
    secret: SensitiveCashuStringV1,
    #[serde(rename = "C")]
    c: SensitiveCashuStringV1,
}

impl<'de> Deserialize<'de> for CashuProofJsonV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let sensitive = SensitiveCashuProofJsonV1::deserialize(deserializer)?;
        Ok(Self {
            amount: sensitive.amount,
            id: sensitive.id,
            secret: sensitive.secret.into_string(),
            c: sensitive.c.into_string(),
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuBlindedMessageJsonV1 {
    pub amount: u64,
    pub id: String,
    #[serde(rename = "B_")]
    pub blinded_message: String,
}

impl Drop for CashuBlindedMessageJsonV1 {
    fn drop(&mut self) {
        self.blinded_message.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensitiveCashuBlindedMessageJsonV1 {
    amount: u64,
    id: String,
    #[serde(rename = "B_")]
    blinded_message: SensitiveCashuStringV1,
}

impl<'de> Deserialize<'de> for CashuBlindedMessageJsonV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let sensitive = SensitiveCashuBlindedMessageJsonV1::deserialize(deserializer)?;
        Ok(Self {
            amount: sensitive.amount,
            id: sensitive.id,
            blinded_message: sensitive.blinded_message.into_string(),
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuPostSwapRequestJsonV1 {
    pub inputs: Vec<CashuProofJsonV1>,
    pub outputs: Vec<CashuBlindedMessageJsonV1>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuDleqJsonV1 {
    pub e: String,
    pub s: String,
}

impl Drop for CashuDleqJsonV1 {
    fn drop(&mut self) {
        self.e.zeroize();
        self.s.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensitiveCashuDleqJsonV1 {
    e: SensitiveCashuStringV1,
    s: SensitiveCashuStringV1,
}

impl<'de> Deserialize<'de> for CashuDleqJsonV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let sensitive = SensitiveCashuDleqJsonV1::deserialize(deserializer)?;
        Ok(Self {
            e: sensitive.e.into_string(),
            s: sensitive.s.into_string(),
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuBlindSignatureJsonV1 {
    pub amount: u64,
    pub id: String,
    #[serde(rename = "C_")]
    pub blinded_signature: String,
    pub dleq: CashuDleqJsonV1,
}

impl Drop for CashuBlindSignatureJsonV1 {
    fn drop(&mut self) {
        self.blinded_signature.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensitiveCashuBlindSignatureJsonV1 {
    amount: u64,
    id: String,
    #[serde(rename = "C_")]
    blinded_signature: SensitiveCashuStringV1,
    dleq: CashuDleqJsonV1,
}

impl<'de> Deserialize<'de> for CashuBlindSignatureJsonV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let sensitive = SensitiveCashuBlindSignatureJsonV1::deserialize(deserializer)?;
        Ok(Self {
            amount: sensitive.amount,
            id: sensitive.id,
            blinded_signature: sensitive.blinded_signature.into_string(),
            dleq: sensitive.dleq,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuPostSwapResponseJsonV1 {
    pub signatures: Vec<CashuBlindSignatureJsonV1>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuPostRestoreRequestJsonV1 {
    pub outputs: Vec<CashuBlindedMessageJsonV1>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuPostRestoreResponseJsonV1 {
    pub outputs: Vec<CashuBlindedMessageJsonV1>,
    pub signatures: Vec<CashuBlindSignatureJsonV1>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuPostCheckStateRequestJsonV1 {
    #[serde(rename = "Ys")]
    pub ys: Vec<String>,
}

impl Drop for CashuPostCheckStateRequestJsonV1 {
    fn drop(&mut self) {
        for y in &mut self.ys {
            y.zeroize();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum CashuProofStateJsonV1 {
    #[serde(rename = "UNSPENT")]
    Unspent,
    #[serde(rename = "PENDING")]
    Pending,
    #[serde(rename = "SPENT")]
    Spent,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CashuProofStateEntryJsonV1 {
    #[serde(rename = "Y")]
    pub y: String,
    pub state: CashuProofStateJsonV1,
    pub witness: Option<String>,
}

impl Drop for CashuProofStateEntryJsonV1 {
    fn drop(&mut self) {
        self.y.zeroize();
        if let Some(witness) = &mut self.witness {
            witness.zeroize();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensitiveCashuProofStateEntryJsonV1 {
    #[serde(rename = "Y")]
    y: SensitiveCashuStringV1,
    state: CashuProofStateJsonV1,
    #[serde(deserialize_with = "deserialize_required_nullable_sensitive_string_v1")]
    witness: Option<SensitiveCashuStringV1>,
}

impl<'de> Deserialize<'de> for CashuProofStateEntryJsonV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let sensitive = SensitiveCashuProofStateEntryJsonV1::deserialize(deserializer)?;
        Ok(Self {
            y: sensitive.y.into_string(),
            state: sensitive.state,
            witness: sensitive.witness.map(SensitiveCashuStringV1::into_string),
        })
    }
}

fn deserialize_required_nullable_sensitive_string_v1<'de, D>(
    deserializer: D,
) -> Result<Option<SensitiveCashuStringV1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<SensitiveCashuStringV1>::deserialize(deserializer)
}

pub(crate) fn is_bounded_nut07_witness_v1(witness: Option<&str>) -> bool {
    match witness {
        None => true,
        Some(value) => value.len() <= MAX_NUT07_WITNESS_BYTES_V1,
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuPostCheckStateResponseJsonV1 {
    pub states: Vec<CashuProofStateEntryJsonV1>,
}

/// Serialize into a maximum-sized sensitive buffer so every valid bounded
/// result avoids reallocation. Error paths wipe the current allocation;
/// success transfers that same allocation to the caller's bearer lifecycle.
pub(crate) fn encode_json_v1<T: Serialize>(value: &T) -> Result<Vec<u8>, CashuClientErrorV1> {
    let mut writer = BoundedZeroizingWriterV1::new(MAX_CASHU_MINT_JSON_BYTES_V1);
    if serde_json::to_writer(&mut writer, value).is_err() {
        return Err(if writer.limit_exceeded() {
            CashuClientErrorV1::JsonTooLarge
        } else {
            CashuClientErrorV1::InvalidJson
        });
    }
    let mut bytes = writer.into_inner();
    Ok(mem::take(&mut *bytes))
}

pub(crate) fn decode_json_v1<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<T, CashuClientErrorV1> {
    if bytes.len() > MAX_CASHU_MINT_JSON_BYTES_V1 {
        return Err(CashuClientErrorV1::JsonTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| CashuClientErrorV1::InvalidJson)
}

/// Decode a mint response under the V1 canonical-response profile.
///
/// All accepted response values (key IDs, points, DLEQ scalars, Y values,
/// states, and the nullable witness for unconditional provider-owned notes)
/// have direct ASCII encodings. Rejecting JSON escapes also prevents
/// `serde_json` from copying bearer-adjacent values into its ordinary heap
/// scratch before the sensitive field visitors take ownership.
pub(crate) fn decode_mint_response_json_v1<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<T, CashuClientErrorV1> {
    if bytes.contains(&b'\\') {
        return Err(CashuClientErrorV1::InvalidJson);
    }
    decode_json_v1(bytes)
}

pub(crate) fn validate_item_count_v1(len: usize) -> Result<(), CashuClientErrorV1> {
    if len == 0 || len > MAX_CASHU_SWAP_ITEMS_V1 {
        return Err(CashuClientErrorV1::InvalidItemCount);
    }
    Ok(())
}

pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(LOWER_HEX[(byte >> 4) as usize] as char);
        output.push(LOWER_HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn decode_lower_hex<const N: usize>(
    value: &str,
    error: CashuClientErrorV1,
) -> Result<[u8; N], CashuClientErrorV1> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error);
    }
    let mut output = [0u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] =
            (hex_nibble(pair[0]).ok_or(error)? << 4) | hex_nibble(pair[1]).ok_or(error)?;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod dto_tests {
    use super::*;

    fn zeroized_sensitive_drop_count() -> usize {
        SENSITIVE_CASHU_STRING_ZEROIZED_DROPS_V1.with(std::cell::Cell::get)
    }

    #[test]
    fn sensitive_cashu_string_is_drop_guarded_redacted_and_string_only() {
        fn assert_traits<T>()
        where
            T: for<'de> Deserialize<'de> + fmt::Debug + Send + Sync,
        {
        }
        assert_traits::<SensitiveCashuStringV1>();
        assert!(mem::needs_drop::<SensitiveCashuStringV1>());

        let before = zeroized_sensitive_drop_count();
        let sensitive: SensitiveCashuStringV1 = serde_json::from_str(r#""bearer-secret""#).unwrap();
        assert_eq!(sensitive.as_str(), "bearer-secret");
        assert_eq!(format!("{sensitive:?}"), "[REDACTED]");
        drop(sensitive);
        assert_eq!(zeroized_sensitive_drop_count() - before, 1);

        for invalid in ["null", "7", "true", "{}", "[]"] {
            assert!(serde_json::from_str::<SensitiveCashuStringV1>(invalid).is_err());
        }
    }

    #[test]
    fn nut07_entry_preserves_wire_and_required_nullable_semantics() {
        let wire = br#"{"Y":"bearer-y","state":"SPENT","witness":"bearer-witness"}"#;
        let entry: CashuProofStateEntryJsonV1 = decode_json_v1(wire).unwrap();
        assert_eq!(entry.y, "bearer-y");
        assert_eq!(entry.state, CashuProofStateJsonV1::Spent);
        assert_eq!(entry.witness.as_deref(), Some("bearer-witness"));
        assert_eq!(encode_json_v1(&entry).unwrap().as_slice(), wire);

        let nullable: CashuProofStateEntryJsonV1 =
            decode_json_v1(br#"{"Y":"bearer-y","state":"UNSPENT","witness":null}"#).unwrap();
        assert_eq!(nullable.witness, None);

        for invalid in [
            br#"{"Y":"bearer-y","state":"SPENT"}"#.as_slice(),
            br#"{"Y":"bearer-y","state":"SPENT","witness":7}"#.as_slice(),
            br#"{"Y":null,"state":"SPENT","witness":null}"#.as_slice(),
        ] {
            assert!(decode_json_v1::<CashuProofStateEntryJsonV1>(invalid).is_err());
        }
    }

    #[test]
    fn adversarial_deserialize_failures_drop_completed_sensitive_fields() {
        let cases: [(&[u8], usize); 3] = [
            (
                br#"{"Y":"bearer-y","state":"SPENT","witness":"bearer-witness","extra":true}"#,
                2,
            ),
            (
                br#"{"Y":"bearer-y","state":"SPENT","witness":"bearer-witness","Y":"duplicate"}"#,
                2,
            ),
            (
                br#"{"Y":"bearer-y","state":7,"witness":"bearer-witness"}"#,
                1,
            ),
        ];
        for (wire, expected_drops) in cases {
            let before = zeroized_sensitive_drop_count();
            assert!(serde_json::from_slice::<CashuProofStateEntryJsonV1>(wire).is_err());
            assert_eq!(zeroized_sensitive_drop_count() - before, expected_drops);
        }

        let before = zeroized_sensitive_drop_count();
        assert!(serde_json::from_slice::<CashuProofJsonV1>(
            br#"{"amount":1,"id":"keyset","secret":"bearer-secret","C":"bearer-signature","extra":true}"#,
        )
        .is_err());
        assert_eq!(zeroized_sensitive_drop_count() - before, 2);

        let before = zeroized_sensitive_drop_count();
        assert!(serde_json::from_slice::<CashuBlindedMessageJsonV1>(
            br#"{"amount":1,"id":"keyset","B_":"blinded-output","extra":true}"#,
        )
        .is_err());
        assert_eq!(zeroized_sensitive_drop_count() - before, 1);

        let before = zeroized_sensitive_drop_count();
        assert!(serde_json::from_slice::<CashuDleqJsonV1>(
            br#"{"e":"dleq-e","s":"dleq-s","extra":true}"#,
        )
        .is_err());
        assert_eq!(zeroized_sensitive_drop_count() - before, 2);

        let before = zeroized_sensitive_drop_count();
        assert!(serde_json::from_slice::<CashuBlindSignatureJsonV1>(
            br#"{"amount":1,"id":"keyset","C_":"blinded-signature","dleq":{"e":"dleq-e","s":"dleq-s","extra":true}}"#,
        )
        .is_err());
        assert_eq!(zeroized_sensitive_drop_count() - before, 3);

        assert!(mem::needs_drop::<CashuBlindedMessageJsonV1>());
        assert!(mem::needs_drop::<CashuDleqJsonV1>());
        assert!(mem::needs_drop::<CashuBlindSignatureJsonV1>());
    }

    #[test]
    fn json_encoding_returns_the_preallocated_buffer() {
        let request = CashuPostCheckStateRequestJsonV1 {
            ys: vec!["bearer-y".to_owned()],
        };
        let encoded = encode_json_v1(&request).unwrap();
        assert_eq!(encoded.as_slice(), br#"{"Ys":["bearer-y"]}"#);
        assert!(encoded.capacity() >= MAX_CASHU_MINT_JSON_BYTES_V1);

        let oversized = CashuPostCheckStateRequestJsonV1 {
            ys: vec!["y".repeat(MAX_CASHU_MINT_JSON_BYTES_V1)],
        };
        assert!(matches!(
            encode_json_v1(&oversized),
            Err(CashuClientErrorV1::JsonTooLarge)
        ));

        let mut writer = BoundedZeroizingWriterV1::new(8);
        let original_capacity = writer.capacity();
        assert!(std::io::Write::write_all(&mut writer, b"123456789").is_err());
        assert!(writer.limit_exceeded());
        assert_eq!(writer.capacity(), original_capacity);
    }
}
