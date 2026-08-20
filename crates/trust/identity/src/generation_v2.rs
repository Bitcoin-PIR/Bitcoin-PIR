use crate::{IdentityError, ED25519_PUBKEY_LEN, ED25519_SIG_LEN};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub const GENERATION_BOUND_IDENTITY_CERT_DOMAIN_TAG_V2: &[u8] =
    b"BPIR-GENERATION-BOUND-IDENTITY-CERT-V2";
const MAX_SERVER_ID_LEN_V2: usize = 256;
const TYPE_DISCRIMINATOR_V2: u8 = 3;

/// Separate V2 artifact for a specifically reserved server identity
/// generation. It is intentionally not accepted by the legacy IdentityCert
/// V1 decoder or runtime path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationBoundIdentityCertV2 {
    pub version: u8,
    pub operator_pubkey: [u8; ED25519_PUBKEY_LEN],
    pub server_id: String,
    pub identity_generation: u64,
    pub identity_pubkey: [u8; ED25519_PUBKEY_LEN],
    pub valid_from: i64,
    pub valid_until: i64,
    pub signature: [u8; ED25519_SIG_LEN],
}

impl GenerationBoundIdentityCertV2 {
    pub const CURRENT_VERSION: u8 = 2;

    pub fn signing_preimage(
        version: u8,
        operator_pubkey: &[u8; ED25519_PUBKEY_LEN],
        server_id: &str,
        identity_generation: u64,
        identity_pubkey: &[u8; ED25519_PUBKEY_LEN],
        valid_from: i64,
        valid_until: i64,
    ) -> Vec<u8> {
        let server_id = server_id.as_bytes();
        let mut out = Vec::with_capacity(
            GENERATION_BOUND_IDENTITY_CERT_DOMAIN_TAG_V2.len()
                + 1
                + ED25519_PUBKEY_LEN
                + 2
                + server_id.len()
                + 8
                + ED25519_PUBKEY_LEN
                + 16,
        );
        out.extend_from_slice(GENERATION_BOUND_IDENTITY_CERT_DOMAIN_TAG_V2);
        out.push(version);
        out.extend_from_slice(operator_pubkey);
        out.extend_from_slice(&(server_id.len() as u16).to_le_bytes());
        out.extend_from_slice(server_id);
        out.extend_from_slice(&identity_generation.to_le_bytes());
        out.extend_from_slice(identity_pubkey);
        out.extend_from_slice(&valid_from.to_le_bytes());
        out.extend_from_slice(&valid_until.to_le_bytes());
        out
    }

    pub fn verify(&self) -> Result<(), IdentityError> {
        validate_fields(
            self.version,
            &self.server_id,
            self.identity_generation,
            &self.identity_pubkey,
            self.valid_from,
            self.valid_until,
        )?;
        let key = VerifyingKey::from_bytes(&self.operator_pubkey)
            .map_err(|_| IdentityError::BadPubkey)?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(
            &Self::signing_preimage(
                self.version,
                &self.operator_pubkey,
                &self.server_id,
                self.identity_generation,
                &self.identity_pubkey,
                self.valid_from,
                self.valid_until,
            ),
            &signature,
        )
        .map_err(|_| IdentityError::BadSignature)
    }

    pub fn check_validity(&self, now_unix: i64) -> Result<(), IdentityError> {
        if now_unix < self.valid_from || (self.valid_until != 0 && now_unix > self.valid_until) {
            return Err(IdentityError::BadSignature);
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let server_id = self.server_id.as_bytes();
        let mut out = Vec::with_capacity(
            2 + ED25519_PUBKEY_LEN
                + 2
                + server_id.len()
                + 8
                + ED25519_PUBKEY_LEN
                + 16
                + ED25519_SIG_LEN,
        );
        out.push(self.version);
        out.push(TYPE_DISCRIMINATOR_V2);
        out.extend_from_slice(&self.operator_pubkey);
        out.extend_from_slice(&(server_id.len() as u16).to_le_bytes());
        out.extend_from_slice(server_id);
        out.extend_from_slice(&self.identity_generation.to_le_bytes());
        out.extend_from_slice(&self.identity_pubkey);
        out.extend_from_slice(&self.valid_from.to_le_bytes());
        out.extend_from_slice(&self.valid_until.to_le_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut position = 0usize;
        let version = read_u8(
            bytes,
            &mut position,
            "GenerationBoundIdentityCertV2.version",
        )?;
        if version != Self::CURRENT_VERSION {
            return Err(IdentityError::UnknownVersion {
                kind: "GenerationBoundIdentityCertV2",
                version,
            });
        }
        let discriminator = read_u8(bytes, &mut position, "GenerationBoundIdentityCertV2.type")?;
        if discriminator != TYPE_DISCRIMINATOR_V2 {
            return Err(IdentityError::UnknownVersion {
                kind: "GenerationBoundIdentityCertV2.type",
                version: discriminator,
            });
        }
        let operator_pubkey = read_fixed(bytes, &mut position, "operator_pubkey")?;
        let server_len =
            u16::from_le_bytes(read_fixed(bytes, &mut position, "server_id_len")?) as usize;
        if server_len > MAX_SERVER_ID_LEN_V2 {
            return Err(IdentityError::FieldTooLong {
                field: "server_id",
                len: server_len,
            });
        }
        let server_end = position
            .checked_add(server_len)
            .ok_or(IdentityError::Truncated("server_id"))?;
        let server_bytes = bytes
            .get(position..server_end)
            .ok_or(IdentityError::Truncated("server_id"))?;
        position = server_end;
        let server_id = String::from_utf8(server_bytes.to_vec())
            .map_err(|_| IdentityError::InvalidField("server_id utf8"))?;
        let identity_generation =
            u64::from_le_bytes(read_fixed(bytes, &mut position, "identity_generation")?);
        let identity_pubkey = read_fixed(bytes, &mut position, "identity_pubkey")?;
        let valid_from = i64::from_le_bytes(read_fixed(bytes, &mut position, "valid_from")?);
        let valid_until = i64::from_le_bytes(read_fixed(bytes, &mut position, "valid_until")?);
        let signature = read_fixed(bytes, &mut position, "signature")?;
        if position != bytes.len() {
            return Err(IdentityError::TrailingBytes(bytes.len() - position));
        }
        let cert = Self {
            version,
            operator_pubkey,
            server_id,
            identity_generation,
            identity_pubkey,
            valid_from,
            valid_until,
            signature,
        };
        validate_fields(
            cert.version,
            &cert.server_id,
            cert.identity_generation,
            &cert.identity_pubkey,
            cert.valid_from,
            cert.valid_until,
        )?;
        Ok(cert)
    }
}

pub fn sign_generation_bound_identity_cert_v2(
    operator_key: &SigningKey,
    server_id: &str,
    identity_generation: u64,
    identity_pubkey: [u8; ED25519_PUBKEY_LEN],
    valid_from: i64,
    valid_until: i64,
) -> Result<GenerationBoundIdentityCertV2, IdentityError> {
    validate_fields(
        GenerationBoundIdentityCertV2::CURRENT_VERSION,
        server_id,
        identity_generation,
        &identity_pubkey,
        valid_from,
        valid_until,
    )?;
    let operator_pubkey = operator_key.verifying_key().to_bytes();
    let signature = operator_key
        .sign(&GenerationBoundIdentityCertV2::signing_preimage(
            GenerationBoundIdentityCertV2::CURRENT_VERSION,
            &operator_pubkey,
            server_id,
            identity_generation,
            &identity_pubkey,
            valid_from,
            valid_until,
        ))
        .to_bytes();
    Ok(GenerationBoundIdentityCertV2 {
        version: GenerationBoundIdentityCertV2::CURRENT_VERSION,
        operator_pubkey,
        server_id: server_id.to_owned(),
        identity_generation,
        identity_pubkey,
        valid_from,
        valid_until,
        signature,
    })
}

fn validate_fields(
    version: u8,
    server_id: &str,
    identity_generation: u64,
    identity_pubkey: &[u8; 32],
    valid_from: i64,
    valid_until: i64,
) -> Result<(), IdentityError> {
    if version != GenerationBoundIdentityCertV2::CURRENT_VERSION {
        return Err(IdentityError::UnknownVersion {
            kind: "GenerationBoundIdentityCertV2",
            version,
        });
    }
    if server_id.is_empty() {
        return Err(IdentityError::InvalidField("server_id"));
    }
    if server_id.len() > MAX_SERVER_ID_LEN_V2 {
        return Err(IdentityError::FieldTooLong {
            field: "server_id",
            len: server_id.len(),
        });
    }
    if identity_generation == 0 {
        return Err(IdentityError::InvalidField("identity_generation"));
    }
    if identity_pubkey.iter().all(|byte| *byte == 0) {
        return Err(IdentityError::BadPubkey);
    }
    VerifyingKey::from_bytes(identity_pubkey).map_err(|_| IdentityError::BadPubkey)?;
    if valid_until != 0 && valid_until < valid_from {
        return Err(IdentityError::InvalidField("validity window"));
    }
    Ok(())
}

fn read_u8(bytes: &[u8], position: &mut usize, field: &'static str) -> Result<u8, IdentityError> {
    let value = *bytes
        .get(*position)
        .ok_or(IdentityError::Truncated(field))?;
    *position += 1;
    Ok(value)
}

fn read_fixed<const N: usize>(
    bytes: &[u8],
    position: &mut usize,
    field: &'static str,
) -> Result<[u8; N], IdentityError> {
    let end = position
        .checked_add(N)
        .ok_or(IdentityError::Truncated(field))?;
    let slice = bytes
        .get(*position..end)
        .ok_or(IdentityError::Truncated(field))?;
    *position = end;
    slice.try_into().map_err(|_| IdentityError::BadLength {
        field,
        expected: N,
        got: slice.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentityCert;

    #[test]
    fn generation_bound_v2_roundtrip_and_v1_rejects() {
        let operator = SigningKey::from_bytes(&[0x31; 32]);
        let identity = SigningKey::from_bytes(&[0x32; 32]);
        let cert = sign_generation_bound_identity_cert_v2(
            &operator,
            "pir2",
            7,
            identity.verifying_key().to_bytes(),
            10,
            20,
        )
        .unwrap();
        cert.verify().unwrap();
        assert_eq!(
            GenerationBoundIdentityCertV2::decode(&cert.encode()).unwrap(),
            cert
        );
        assert!(IdentityCert::decode(&cert.encode()).is_err());
    }
}
