use crate::DirectoryErrorV1;

pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

pub(crate) fn decode_lower_hex<const N: usize>(value: &str) -> Result<[u8; N], DirectoryErrorV1> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(DirectoryErrorV1::InvalidHex);
    }
    let mut decoded = [0u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(decoded)
}

fn nibble(value: u8) -> Result<u8, DirectoryErrorV1> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(DirectoryErrorV1::InvalidHex),
    }
}

pub(crate) fn contains_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}
