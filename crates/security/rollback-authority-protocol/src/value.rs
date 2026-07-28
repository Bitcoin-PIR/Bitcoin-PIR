use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::codec::{domain_hash_v1, is_all_zero, put_u64, Reader};
use crate::wire::AuthorityBindingV1;
use crate::RollbackAuthorityProtocolErrorV1;

/// Exact bytes occupied by the nonce and authenticated fixed-size ciphertext.
pub const SEALED_AUTHORITY_VALUE_BYTES_V1: usize = 512;

/// Maximum opaque floor encoding that can be sealed in a V1 record.
pub const MAX_AUTHORITY_VALUE_BYTES_V1: usize = 462;

/// Exact canonical size of `revision || value_tag || sealed_value`.
pub const AUTHORITY_RECORD_BYTES_V1: usize = 8 + 32 + SEALED_AUTHORITY_VALUE_BYTES_V1;

const ROOT_KEY_BYTES_V1: usize = 32;
const VALUE_TAG_BYTES_V1: usize = 32;
const XCHACHA_NONCE_BYTES: usize = 24;
const POLY1305_TAG_BYTES: usize = 16;
const PADDED_PLAINTEXT_BYTES_V1: usize =
    SEALED_AUTHORITY_VALUE_BYTES_V1 - XCHACHA_NONCE_BYTES - POLY1305_TAG_BYTES;
const PADDED_PLAINTEXT_HEADER_BYTES_V1: usize = 10;

const PADDED_PLAINTEXT_MAGIC_V1: &[u8; 8] = b"BPRAVP1\0";
const KDF_SALT_DOMAIN_V1: &[u8] = b"BitcoinPIR/rollback-authority/value-kdf-salt/v1";
const KDF_AEAD_INFO_DOMAIN_V1: &[u8] = b"BitcoinPIR/rollback-authority/value-aead-key/v1";
const KDF_TAG_INFO_DOMAIN_V1: &[u8] = b"BitcoinPIR/rollback-authority/value-tag-key/v1";
const VALUE_TAG_DOMAIN_V1: &[u8] = b"BitcoinPIR/rollback-authority/value-tag/v1";
const VALUE_AAD_DOMAIN_V1: &[u8] = b"BitcoinPIR/rollback-authority/value-aad/v1";

type HmacSha256 = Hmac<Sha256>;

/// Long-lived client-only root key for opaque authority records.
///
/// It intentionally implements neither `Clone` nor `Debug`; the allocation is
/// zeroized on drop. It is distinct from the Ed25519 client authentication key.
pub struct AuthorityValueRootKeyV1 {
    bytes: Zeroizing<[u8; ROOT_KEY_BYTES_V1]>,
}

impl AuthorityValueRootKeyV1 {
    pub fn from_bytes(
        bytes: [u8; ROOT_KEY_BYTES_V1],
    ) -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        let bytes = Zeroizing::new(bytes);
        if is_all_zero(bytes.as_slice()) {
            return Err(RollbackAuthorityProtocolErrorV1::InvalidIdentifier);
        }
        Ok(Self { bytes })
    }

    pub fn generate() -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        let mut bytes = Zeroizing::new([0_u8; ROOT_KEY_BYTES_V1]);
        loop {
            getrandom::getrandom(bytes.as_mut())
                .map_err(|_| RollbackAuthorityProtocolErrorV1::RandomnessUnavailable)?;
            if !is_all_zero(bytes.as_slice()) {
                return Ok(Self { bytes });
            }
        }
    }
}

/// Namespace-bound client codec with separately derived AEAD and HMAC keys.
///
/// `Debug` reveals no binding or key material. A codec for one authority
/// instance, namespace, or Ed25519 client key cannot open another binding's
/// records even if both were derived from the same root key.
pub struct AuthorityValueCodecV1 {
    binding: AuthorityBindingV1,
    aead_key: Zeroizing<[u8; 32]>,
    tag_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for AuthorityValueCodecV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityValueCodecV1")
            .field("binding", &"[REDACTED]")
            .field("aead_key", &"[REDACTED]")
            .field("tag_key", &"[REDACTED]")
            .finish()
    }
}

impl AuthorityValueCodecV1 {
    pub fn derive(
        root_key: &AuthorityValueRootKeyV1,
        authority_instance_id: [u8; 32],
        namespace: [u8; 32],
        client_verifying_key: &VerifyingKey,
    ) -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        let binding = AuthorityBindingV1::for_client_key(
            authority_instance_id,
            namespace,
            client_verifying_key,
        )?;
        let mut salt_input = Zeroizing::new(Vec::with_capacity(96));
        salt_input.extend_from_slice(binding.authority_instance_id());
        salt_input.extend_from_slice(binding.namespace());
        salt_input.extend_from_slice(binding.client_key_id());
        let mut salt = Zeroizing::new(domain_hash_v1(KDF_SALT_DOMAIN_V1, &salt_input));
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), root_key.bytes.as_slice());

        let mut aead_key = Zeroizing::new([0_u8; 32]);
        hkdf.expand(KDF_AEAD_INFO_DOMAIN_V1, aead_key.as_mut())
            .map_err(|_| RollbackAuthorityProtocolErrorV1::KeyDerivationFailed)?;
        let mut tag_key = Zeroizing::new([0_u8; 32]);
        hkdf.expand(KDF_TAG_INFO_DOMAIN_V1, tag_key.as_mut())
            .map_err(|_| RollbackAuthorityProtocolErrorV1::KeyDerivationFailed)?;
        salt.zeroize();

        Ok(Self {
            binding,
            aead_key,
            tag_key,
        })
    }

    pub fn binding(&self) -> &AuthorityBindingV1 {
        &self.binding
    }

    /// Seals one canonical floor encoding under a fresh nonce and random
    /// fixed-size padding. The authority learns no plaintext length.
    pub fn seal(
        &self,
        revision: u64,
        value: &[u8],
    ) -> Result<OpaqueAuthorityRecordV1, RollbackAuthorityProtocolErrorV1> {
        if value.is_empty() {
            return Err(RollbackAuthorityProtocolErrorV1::EmptyValue);
        }
        if value.len() > MAX_AUTHORITY_VALUE_BYTES_V1 {
            return Err(RollbackAuthorityProtocolErrorV1::ValueTooLong);
        }

        let mut padded = Zeroizing::new(vec![0_u8; PADDED_PLAINTEXT_BYTES_V1]);
        getrandom::getrandom(padded.as_mut_slice())
            .map_err(|_| RollbackAuthorityProtocolErrorV1::RandomnessUnavailable)?;
        padded[..8].copy_from_slice(PADDED_PLAINTEXT_MAGIC_V1);
        padded[8..10].copy_from_slice(&(value.len() as u16).to_be_bytes());
        padded[PADDED_PLAINTEXT_HEADER_BYTES_V1..PADDED_PLAINTEXT_HEADER_BYTES_V1 + value.len()]
            .copy_from_slice(value);

        let value_tag = self.value_tag(revision, value)?;
        let aad = self.value_aad(revision, &value_tag);
        let mut nonce = Zeroizing::new([0_u8; XCHACHA_NONCE_BYTES]);
        getrandom::getrandom(nonce.as_mut())
            .map_err(|_| RollbackAuthorityProtocolErrorV1::RandomnessUnavailable)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.aead_key.as_slice())
            .map_err(|_| RollbackAuthorityProtocolErrorV1::KeyDerivationFailed)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(nonce.as_slice()),
                Payload {
                    msg: padded.as_slice(),
                    aad: aad.as_slice(),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| RollbackAuthorityProtocolErrorV1::EncryptionFailed)?;
        if ciphertext.len() != SEALED_AUTHORITY_VALUE_BYTES_V1 - XCHACHA_NONCE_BYTES {
            return Err(RollbackAuthorityProtocolErrorV1::EncryptionFailed);
        }

        let mut sealed_value = [0_u8; SEALED_AUTHORITY_VALUE_BYTES_V1];
        sealed_value[..XCHACHA_NONCE_BYTES].copy_from_slice(nonce.as_slice());
        sealed_value[XCHACHA_NONCE_BYTES..].copy_from_slice(ciphertext.as_slice());
        Ok(OpaqueAuthorityRecordV1 {
            revision,
            value_tag,
            sealed_value,
        })
    }

    /// Opens and authenticates a fixed-size record. The plaintext remains in
    /// a zeroizing allocation and cannot be converted into an unguarded owned
    /// vector through this API.
    pub fn open(
        &self,
        record: &OpaqueAuthorityRecordV1,
    ) -> Result<OpenedAuthorityValueV1, RollbackAuthorityProtocolErrorV1> {
        let aad = self.value_aad(record.revision, &record.value_tag);
        let cipher = XChaCha20Poly1305::new_from_slice(self.aead_key.as_slice())
            .map_err(|_| RollbackAuthorityProtocolErrorV1::KeyDerivationFailed)?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&record.sealed_value[..XCHACHA_NONCE_BYTES]),
                Payload {
                    msg: &record.sealed_value[XCHACHA_NONCE_BYTES..],
                    aad: aad.as_slice(),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| RollbackAuthorityProtocolErrorV1::DecryptionFailed)?;
        if plaintext.len() != PADDED_PLAINTEXT_BYTES_V1
            || plaintext.get(..8) != Some(PADDED_PLAINTEXT_MAGIC_V1.as_slice())
        {
            return Err(RollbackAuthorityProtocolErrorV1::NonCanonicalEncoding);
        }
        let value_length = usize::from(u16::from_be_bytes([plaintext[8], plaintext[9]]));
        if value_length == 0 || value_length > MAX_AUTHORITY_VALUE_BYTES_V1 {
            return Err(RollbackAuthorityProtocolErrorV1::NonCanonicalEncoding);
        }
        let value_end = PADDED_PLAINTEXT_HEADER_BYTES_V1
            .checked_add(value_length)
            .ok_or(RollbackAuthorityProtocolErrorV1::InvalidLength)?;
        let value = plaintext
            .get(PADDED_PLAINTEXT_HEADER_BYTES_V1..value_end)
            .ok_or(RollbackAuthorityProtocolErrorV1::InvalidLength)?;
        self.verify_value_tag(record.revision, value, &record.value_tag)?;

        Ok(OpenedAuthorityValueV1 {
            padded_plaintext: plaintext,
            value_length,
        })
    }

    fn value_tag(
        &self,
        revision: u64,
        value: &[u8],
    ) -> Result<[u8; VALUE_TAG_BYTES_V1], RollbackAuthorityProtocolErrorV1> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.tag_key.as_slice())
            .map_err(|_| RollbackAuthorityProtocolErrorV1::KeyDerivationFailed)?;
        mac.update(VALUE_TAG_DOMAIN_V1);
        mac.update(self.binding.authority_instance_id());
        mac.update(self.binding.namespace());
        mac.update(self.binding.client_key_id());
        mac.update(&revision.to_be_bytes());
        mac.update(&(value.len() as u16).to_be_bytes());
        mac.update(value);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_value_tag(
        &self,
        revision: u64,
        value: &[u8],
        expected: &[u8; VALUE_TAG_BYTES_V1],
    ) -> Result<(), RollbackAuthorityProtocolErrorV1> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.tag_key.as_slice())
            .map_err(|_| RollbackAuthorityProtocolErrorV1::KeyDerivationFailed)?;
        mac.update(VALUE_TAG_DOMAIN_V1);
        mac.update(self.binding.authority_instance_id());
        mac.update(self.binding.namespace());
        mac.update(self.binding.client_key_id());
        mac.update(&revision.to_be_bytes());
        mac.update(&(value.len() as u16).to_be_bytes());
        mac.update(value);
        mac.verify_slice(expected)
            .map_err(|_| RollbackAuthorityProtocolErrorV1::ValueAuthenticationFailed)
    }

    fn value_aad(&self, revision: u64, value_tag: &[u8; 32]) -> Zeroizing<Vec<u8>> {
        let mut aad = Zeroizing::new(Vec::with_capacity(
            VALUE_AAD_DOMAIN_V1.len() + 32 + 32 + 32 + 8 + 32,
        ));
        aad.extend_from_slice(VALUE_AAD_DOMAIN_V1);
        aad.extend_from_slice(self.binding.authority_instance_id());
        aad.extend_from_slice(self.binding.namespace());
        aad.extend_from_slice(self.binding.client_key_id());
        put_u64(&mut aad, revision);
        aad.extend_from_slice(value_tag);
        aad
    }
}

/// Authority-visible record. `value_tag` is a namespace-keyed pseudorandom
/// equality/commitment tag, not a plaintext digest. The sealed value always has
/// exactly the same length.
pub struct OpaqueAuthorityRecordV1 {
    pub(crate) revision: u64,
    pub(crate) value_tag: [u8; VALUE_TAG_BYTES_V1],
    pub(crate) sealed_value: [u8; SEALED_AUTHORITY_VALUE_BYTES_V1],
}

impl fmt::Debug for OpaqueAuthorityRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueAuthorityRecordV1")
            .field("revision", &"[REDACTED]")
            .field("value_tag", &"[REDACTED]")
            .field("sealed_value", &"[REDACTED]")
            .finish()
    }
}

impl Drop for OpaqueAuthorityRecordV1 {
    fn drop(&mut self) {
        self.revision.zeroize();
        self.value_tag.zeroize();
        self.sealed_value.zeroize();
    }
}

impl PartialEq for OpaqueAuthorityRecordV1 {
    fn eq(&self, other: &Self) -> bool {
        self.revision == other.revision
            && self.value_tag == other.value_tag
            && self.sealed_value == other.sealed_value
    }
}

impl Eq for OpaqueAuthorityRecordV1 {}

impl OpaqueAuthorityRecordV1 {
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn value_tag(&self) -> &[u8; VALUE_TAG_BYTES_V1] {
        &self.value_tag
    }

    pub fn sealed_value(&self) -> &[u8; SEALED_AUTHORITY_VALUE_BYTES_V1] {
        &self.sealed_value
    }

    /// Explicitly duplicates the opaque record for a durable CAS/retry path.
    /// This is intentionally not an implicit `Clone` implementation.
    pub fn duplicate_for_protocol(&self) -> Self {
        Self {
            revision: self.revision,
            value_tag: self.value_tag,
            sealed_value: self.sealed_value,
        }
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut encoded = Zeroizing::new(Vec::with_capacity(AUTHORITY_RECORD_BYTES_V1));
        self.write_to(&mut encoded);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        if encoded.len() != AUTHORITY_RECORD_BYTES_V1 {
            return Err(RollbackAuthorityProtocolErrorV1::InvalidLength);
        }
        let mut reader = Reader::new(encoded);
        let record = Self::read_from(&mut reader)?;
        reader.finish()?;
        Ok(record)
    }

    pub(crate) fn write_to(&self, target: &mut Vec<u8>) {
        put_u64(target, self.revision);
        target.extend_from_slice(&self.value_tag);
        target.extend_from_slice(&self.sealed_value);
    }

    pub(crate) fn read_from(
        reader: &mut Reader<'_>,
    ) -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        Ok(Self {
            revision: reader.u64()?,
            value_tag: reader.fixed()?,
            sealed_value: reader.fixed()?,
        })
    }
}

/// Opened value backed by the complete zeroizing padded plaintext allocation.
/// It intentionally implements neither `Clone` nor `Debug`.
pub struct OpenedAuthorityValueV1 {
    padded_plaintext: Zeroizing<Vec<u8>>,
    value_length: usize,
}

impl OpenedAuthorityValueV1 {
    pub fn as_bytes(&self) -> &[u8] {
        &self.padded_plaintext
            [PADDED_PLAINTEXT_HEADER_BYTES_V1..PADDED_PLAINTEXT_HEADER_BYTES_V1 + self.value_length]
    }
}
