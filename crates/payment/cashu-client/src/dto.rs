use serde::{Deserialize, Serialize};

use crate::{CashuClientErrorV1, MAX_CASHU_MINT_JSON_BYTES_V1, MAX_CASHU_SWAP_ITEMS_V1};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuProofJsonV1 {
    pub amount: u64,
    pub id: String,
    pub secret: String,
    #[serde(rename = "C")]
    pub c: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuBlindedMessageJsonV1 {
    pub amount: u64,
    pub id: String,
    #[serde(rename = "B_")]
    pub blinded_message: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuPostSwapRequestJsonV1 {
    pub inputs: Vec<CashuProofJsonV1>,
    pub outputs: Vec<CashuBlindedMessageJsonV1>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuDleqJsonV1 {
    pub e: String,
    pub s: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuBlindSignatureJsonV1 {
    pub amount: u64,
    pub id: String,
    #[serde(rename = "C_")]
    pub blinded_signature: String,
    pub dleq: CashuDleqJsonV1,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum CashuProofStateJsonV1 {
    #[serde(rename = "UNSPENT")]
    Unspent,
    #[serde(rename = "PENDING")]
    Pending,
    #[serde(rename = "SPENT")]
    Spent,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuProofStateEntryJsonV1 {
    #[serde(rename = "Y")]
    pub y: String,
    pub state: CashuProofStateJsonV1,
    pub witness: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CashuPostCheckStateResponseJsonV1 {
    pub states: Vec<CashuProofStateEntryJsonV1>,
}

pub(crate) fn encode_json_v1<T: Serialize>(value: &T) -> Result<Vec<u8>, CashuClientErrorV1> {
    let bytes = serde_json::to_vec(value).map_err(|_| CashuClientErrorV1::InvalidJson)?;
    if bytes.len() > MAX_CASHU_MINT_JSON_BYTES_V1 {
        return Err(CashuClientErrorV1::JsonTooLarge);
    }
    Ok(bytes)
}

pub(crate) fn decode_json_v1<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<T, CashuClientErrorV1> {
    if bytes.len() > MAX_CASHU_MINT_JSON_BYTES_V1 {
        return Err(CashuClientErrorV1::JsonTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| CashuClientErrorV1::InvalidJson)
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
