//! Recipient-sealed, opaque Cashu custody export envelopes.
//!
//! This crate deliberately knows nothing about Cashu note structure or
//! provider storage. Callers serialize the custody payload canonically, seal
//! it once, and durably replay the exact returned envelope bytes. Re-sealing a
//! stored export would create a different envelope and is not a retry model.

#![forbid(unsafe_code)]

use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Maximum opaque custody payload accepted by the V1 envelope.
pub const MAX_CASHU_CUSTODY_PLAINTEXT_BYTES_V1: usize = 256 * 1024;

/// Fixed, authenticated V1 envelope header size.
pub const CASHU_CUSTODY_ENVELOPE_HEADER_BYTES_V1: usize = 148;

/// Maximum canonical encoded V1 envelope size.
pub const MAX_CASHU_CUSTODY_ENVELOPE_BYTES_V1: usize =
    CASHU_CUSTODY_ENVELOPE_HEADER_BYTES_V1 + MAX_CASHU_CUSTODY_PLAINTEXT_BYTES_V1 + 16;

const MAGIC_V1: &[u8; 8] = b"BPCCEV1\0";
const AEAD_TAG_BYTES: usize = 16;
const HEADER_BYTES_V1: usize = CASHU_CUSTODY_ENVELOPE_HEADER_BYTES_V1;
const MAX_CIPHERTEXT_BYTES_V1: usize = MAX_CASHU_CUSTODY_PLAINTEXT_BYTES_V1 + AEAD_TAG_BYTES;

const RECIPIENT_KEY_ID_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-custody/recipient-key-id/v1";
const HKDF_SALT_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-custody/hkdf-salt/v1";
const HKDF_INFO_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-custody/aead-key/v1";
const AAD_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-custody/envelope-aad/v1";

const EXPORT_ID_OFFSET: usize = 8;
const PROVIDER_ID_OFFSET: usize = EXPORT_ID_OFFSET + 16;
const RECIPIENT_KEY_ID_OFFSET: usize = PROVIDER_ID_OFFSET + 32;
const EPHEMERAL_PUBLIC_KEY_OFFSET: usize = RECIPIENT_KEY_ID_OFFSET + 32;
const NONCE_OFFSET: usize = EPHEMERAL_PUBLIC_KEY_OFFSET + 32;
const CIPHERTEXT_LENGTH_OFFSET: usize = NONCE_OFFSET + 24;

/// Fail-closed custody envelope error. It contains no key, plaintext, or
/// ciphertext material and is safe to surface as an operational category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CashuCustodyErrorV1 {
    InvalidRecipientKey,
    InvalidEphemeralKey,
    InvalidIdentifier,
    EmptyPlaintext,
    PlaintextTooLong,
    InvalidEnvelope,
    WrongRecipient,
    AuthenticationFailed,
    RandomnessUnavailable,
    KeyDerivationFailed,
}

impl fmt::Display for CashuCustodyErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRecipientKey => "Cashu custody recipient key is invalid",
            Self::InvalidEphemeralKey => "Cashu custody ephemeral key is invalid",
            Self::InvalidIdentifier => "Cashu custody identifier is invalid",
            Self::EmptyPlaintext => "Cashu custody plaintext is empty",
            Self::PlaintextTooLong => "Cashu custody plaintext exceeds the V1 bound",
            Self::InvalidEnvelope => "Cashu custody envelope is invalid or non-canonical",
            Self::WrongRecipient => "Cashu custody envelope belongs to another recipient",
            Self::AuthenticationFailed => "Cashu custody envelope authentication failed",
            Self::RandomnessUnavailable => "operating-system randomness is unavailable",
            Self::KeyDerivationFailed => "Cashu custody key derivation failed",
        })
    }
}

impl std::error::Error for CashuCustodyErrorV1 {}

/// Long-lived recipient secret. It intentionally implements neither `Debug`
/// nor `Clone`; its inner X25519 secret is zeroized on drop.
pub struct CashuCustodyRecipientSecretKeyV1 {
    secret: StaticSecret,
}

impl CashuCustodyRecipientSecretKeyV1 {
    /// Imports exactly 32 bytes of recipient secret material.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CashuCustodyErrorV1> {
        let bytes = Zeroizing::new(bytes);
        if is_all_zero(bytes.as_slice()) {
            return Err(CashuCustodyErrorV1::InvalidRecipientKey);
        }
        Ok(Self {
            secret: StaticSecret::from(*bytes),
        })
    }

    /// Generates a recipient key from the operating system CSPRNG.
    pub fn generate() -> Result<Self, CashuCustodyErrorV1> {
        let bytes = random_nonzero_32()?;
        Ok(Self {
            secret: StaticSecret::from(*bytes),
        })
    }

    /// Derives the corresponding canonical 32-byte X25519 public key.
    pub fn public_key(&self) -> CashuCustodyRecipientPublicKeyV1 {
        CashuCustodyRecipientPublicKeyV1(PublicKey::from(&self.secret).to_bytes())
    }
}

/// Canonical X25519 recipient public key. Low-order encodings are rejected by
/// the contributory Diffie-Hellman check during sealing/opening.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CashuCustodyRecipientPublicKeyV1([u8; 32]);

impl CashuCustodyRecipientPublicKeyV1 {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CashuCustodyErrorV1> {
        if !is_canonical_x25519_public_key_v1(&bytes)
            || is_all_zero(&bytes)
            || !is_contributory_x25519_public_key_v1(&bytes)
        {
            return Err(CashuCustodyErrorV1::InvalidRecipientKey);
        }
        Ok(Self(bytes))
    }

    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Stable key selector derived from the canonical public key under a
    /// dedicated domain. It is an identifier, never a cryptographic key.
    pub fn key_id(&self) -> [u8; 32] {
        domain_hash_v1(RECIPIENT_KEY_ID_DOMAIN_V1, &self.0)
    }
}

/// Authenticated, canonical V1 envelope bytes. Its custom `Debug` output
/// redacts the complete stable envelope so logs cannot dump ciphertext,
/// identifiers, or length metadata; dropping it zeroizes the owned bytes.
///
/// The binary format is exactly:
///
/// - `BPCCEV1\0` (8 bytes),
/// - `export_id` (16 bytes),
/// - `provider_id` (32 bytes),
/// - domain-separated `recipient_key_id` (32 bytes),
/// - canonical X25519 ephemeral public key (32 bytes),
/// - XChaCha20 nonce (24 bytes),
/// - ciphertext length as a big-endian `u32` (4 bytes), and
/// - ciphertext including the 16-byte Poly1305 tag.
///
/// The entire fixed header is authenticated as AEAD associated data under a
/// separate protocol domain.
pub struct CashuCustodyEnvelopeV1 {
    encoded: Vec<u8>,
}

impl fmt::Debug for CashuCustodyEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CashuCustodyEnvelopeV1")
            .field("encoded", &"[REDACTED_ENVELOPE]")
            .finish()
    }
}

impl Drop for CashuCustodyEnvelopeV1 {
    fn drop(&mut self) {
        self.encoded.zeroize();
    }
}

impl CashuCustodyEnvelopeV1 {
    /// Parses a canonical envelope. The exact bytes are retained for durable,
    /// idempotent replay; parsing never re-encrypts or re-randomizes it.
    pub fn decode(encoded: &[u8]) -> Result<Self, CashuCustodyErrorV1> {
        validate_envelope_v1(encoded)?;
        Ok(Self {
            encoded: encoded.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.encoded)
    }

    pub fn export_id(&self) -> [u8; 16] {
        array_at::<16>(&self.encoded, EXPORT_ID_OFFSET)
    }

    pub fn provider_id(&self) -> [u8; 32] {
        array_at::<32>(&self.encoded, PROVIDER_ID_OFFSET)
    }

    pub fn recipient_key_id(&self) -> [u8; 32] {
        array_at::<32>(&self.encoded, RECIPIENT_KEY_ID_OFFSET)
    }

    pub fn ephemeral_public_key(&self) -> [u8; 32] {
        array_at::<32>(&self.encoded, EPHEMERAL_PUBLIC_KEY_OFFSET)
    }
}

/// Opened opaque payload that zeroizes its allocation on drop and does not
/// implement `Debug` or expose an unprotected owned byte vector.
pub struct OpenedCashuCustodyPlaintextV1 {
    bytes: Zeroizing<Vec<u8>>,
}

impl OpenedCashuCustodyPlaintextV1 {
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Seals opaque canonical payload bytes using a fresh OS-random ephemeral key
/// and XChaCha20 nonce.
pub fn seal_cashu_custody_with_os_random_v1(
    export_id: [u8; 16],
    provider_id: [u8; 32],
    recipient: &CashuCustodyRecipientPublicKeyV1,
    plaintext: &[u8],
) -> Result<CashuCustodyEnvelopeV1, CashuCustodyErrorV1> {
    let material = CashuCustodySealMaterialV1::from_os_random()?;
    seal_with_material_v1(export_id, provider_id, recipient, plaintext, material)
}

/// Opens and authenticates an envelope for one recipient.
pub fn open_cashu_custody_v1(
    envelope: &CashuCustodyEnvelopeV1,
    recipient: &CashuCustodyRecipientSecretKeyV1,
) -> Result<OpenedCashuCustodyPlaintextV1, CashuCustodyErrorV1> {
    validate_envelope_v1(envelope.as_bytes())?;

    let recipient_public_key = recipient.public_key();
    if envelope.recipient_key_id() != recipient_public_key.key_id() {
        return Err(CashuCustodyErrorV1::WrongRecipient);
    }

    let ephemeral_public_bytes = envelope.ephemeral_public_key();
    if !is_canonical_x25519_public_key_v1(&ephemeral_public_bytes)
        || is_all_zero(&ephemeral_public_bytes)
        || !is_contributory_x25519_public_key_v1(&ephemeral_public_bytes)
    {
        return Err(CashuCustodyErrorV1::InvalidEphemeralKey);
    }
    let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
    let shared_secret = recipient.secret.diffie_hellman(&ephemeral_public);
    if !shared_secret.was_contributory() {
        return Err(CashuCustodyErrorV1::InvalidEphemeralKey);
    }

    let key = derive_aead_key_v1(
        shared_secret.as_bytes(),
        &recipient_public_key.0,
        &envelope.encoded[..HEADER_BYTES_V1],
    )?;
    let nonce_bytes = array_at::<24>(&envelope.encoded, NONCE_OFFSET);
    let aad = aad_v1(&envelope.encoded[..HEADER_BYTES_V1]);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CashuCustodyErrorV1::KeyDerivationFailed)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                (&nonce_bytes).into(),
                Payload {
                    msg: &envelope.encoded[HEADER_BYTES_V1..],
                    aad: &aad,
                },
            )
            .map_err(|_| CashuCustodyErrorV1::AuthenticationFailed)?,
    );

    if plaintext.is_empty() || plaintext.len() > MAX_CASHU_CUSTODY_PLAINTEXT_BYTES_V1 {
        return Err(CashuCustodyErrorV1::InvalidEnvelope);
    }
    Ok(OpenedCashuCustodyPlaintextV1 { bytes: plaintext })
}

/// Deterministic seal material is available only to crate tests or consumers
/// that opt into `test-vectors`. It is consumed by sealing to discourage
/// nonce/key reuse and zeroizes its secret on drop.
#[cfg(any(test, feature = "test-vectors"))]
pub struct CashuCustodySealMaterialV1 {
    ephemeral_secret: [u8; 32],
    nonce: [u8; 24],
}

#[cfg(any(test, feature = "test-vectors"))]
impl CashuCustodySealMaterialV1 {
    pub fn for_test(
        ephemeral_secret: [u8; 32],
        nonce: [u8; 24],
    ) -> Result<Self, CashuCustodyErrorV1> {
        let ephemeral_secret = Zeroizing::new(ephemeral_secret);
        let nonce = Zeroizing::new(nonce);
        if is_all_zero(ephemeral_secret.as_slice()) {
            return Err(CashuCustodyErrorV1::InvalidEphemeralKey);
        }
        Ok(Self {
            ephemeral_secret: *ephemeral_secret,
            nonce: *nonce,
        })
    }
}

#[cfg(any(test, feature = "test-vectors"))]
impl Drop for CashuCustodySealMaterialV1 {
    fn drop(&mut self) {
        self.ephemeral_secret.zeroize();
        self.nonce.zeroize();
    }
}

#[cfg(not(any(test, feature = "test-vectors")))]
struct CashuCustodySealMaterialV1 {
    ephemeral_secret: [u8; 32],
    nonce: [u8; 24],
}

#[cfg(not(any(test, feature = "test-vectors")))]
impl Drop for CashuCustodySealMaterialV1 {
    fn drop(&mut self) {
        self.ephemeral_secret.zeroize();
        self.nonce.zeroize();
    }
}

impl CashuCustodySealMaterialV1 {
    fn from_os_random() -> Result<Self, CashuCustodyErrorV1> {
        let ephemeral_secret = random_nonzero_32()?;
        let mut nonce = Zeroizing::new([0u8; 24]);
        getrandom::getrandom(&mut *nonce)
            .map_err(|_| CashuCustodyErrorV1::RandomnessUnavailable)?;
        Ok(Self {
            ephemeral_secret: *ephemeral_secret,
            nonce: *nonce,
        })
    }
}

#[cfg(any(test, feature = "test-vectors"))]
pub fn seal_cashu_custody_with_test_material_v1(
    export_id: [u8; 16],
    provider_id: [u8; 32],
    recipient: &CashuCustodyRecipientPublicKeyV1,
    plaintext: &[u8],
    material: CashuCustodySealMaterialV1,
) -> Result<CashuCustodyEnvelopeV1, CashuCustodyErrorV1> {
    seal_with_material_v1(export_id, provider_id, recipient, plaintext, material)
}

fn seal_with_material_v1(
    export_id: [u8; 16],
    provider_id: [u8; 32],
    recipient: &CashuCustodyRecipientPublicKeyV1,
    plaintext: &[u8],
    material: CashuCustodySealMaterialV1,
) -> Result<CashuCustodyEnvelopeV1, CashuCustodyErrorV1> {
    validate_identifiers_and_plaintext_v1(&export_id, &provider_id, plaintext)?;

    let ephemeral_secret = StaticSecret::from(material.ephemeral_secret);
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret).to_bytes();
    let recipient_public = PublicKey::from(recipient.0);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);
    if !shared_secret.was_contributory() {
        return Err(CashuCustodyErrorV1::InvalidRecipientKey);
    }

    let ciphertext_len = plaintext
        .len()
        .checked_add(AEAD_TAG_BYTES)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(CashuCustodyErrorV1::PlaintextTooLong)?;
    let ciphertext_len_usize =
        usize::try_from(ciphertext_len).map_err(|_| CashuCustodyErrorV1::PlaintextTooLong)?;
    let envelope_len = HEADER_BYTES_V1
        .checked_add(ciphertext_len_usize)
        .ok_or(CashuCustodyErrorV1::PlaintextTooLong)?;
    let mut header = Zeroizing::new(Vec::with_capacity(envelope_len));
    header.extend_from_slice(MAGIC_V1);
    header.extend_from_slice(&export_id);
    header.extend_from_slice(&provider_id);
    header.extend_from_slice(&recipient.key_id());
    header.extend_from_slice(&ephemeral_public_key);
    header.extend_from_slice(&material.nonce);
    header.extend_from_slice(&ciphertext_len.to_be_bytes());
    debug_assert_eq!(header.len(), HEADER_BYTES_V1);
    debug_assert!(header.capacity() >= envelope_len);

    let key = derive_aead_key_v1(
        shared_secret.as_bytes(),
        &recipient.0,
        &header[..HEADER_BYTES_V1],
    )?;
    let aad = aad_v1(&header[..HEADER_BYTES_V1]);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CashuCustodyErrorV1::KeyDerivationFailed)?;
    let ciphertext = Zeroizing::new(
        cipher
            .encrypt(
                (&material.nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CashuCustodyErrorV1::InvalidEnvelope)?,
    );
    if ciphertext.len() != ciphertext_len_usize {
        return Err(CashuCustodyErrorV1::InvalidEnvelope);
    }

    let allocation = header.as_ptr();
    header.extend_from_slice(&ciphertext);
    debug_assert_eq!(header.len(), envelope_len);
    debug_assert_eq!(header.as_ptr(), allocation);
    CashuCustodyEnvelopeV1::decode(&header)
}

fn validate_identifiers_and_plaintext_v1(
    export_id: &[u8; 16],
    provider_id: &[u8; 32],
    plaintext: &[u8],
) -> Result<(), CashuCustodyErrorV1> {
    if is_all_zero(export_id) || is_all_zero(provider_id) {
        return Err(CashuCustodyErrorV1::InvalidIdentifier);
    }
    if plaintext.is_empty() {
        return Err(CashuCustodyErrorV1::EmptyPlaintext);
    }
    if plaintext.len() > MAX_CASHU_CUSTODY_PLAINTEXT_BYTES_V1 {
        return Err(CashuCustodyErrorV1::PlaintextTooLong);
    }
    Ok(())
}

fn validate_envelope_v1(encoded: &[u8]) -> Result<(), CashuCustodyErrorV1> {
    if encoded.len() < HEADER_BYTES_V1 + AEAD_TAG_BYTES + 1
        || encoded.len() > HEADER_BYTES_V1 + MAX_CIPHERTEXT_BYTES_V1
        || encoded.get(..MAGIC_V1.len()) != Some(MAGIC_V1.as_slice())
    {
        return Err(CashuCustodyErrorV1::InvalidEnvelope);
    }
    if is_all_zero(&array_at::<16>(encoded, EXPORT_ID_OFFSET))
        || is_all_zero(&array_at::<32>(encoded, PROVIDER_ID_OFFSET))
        || is_all_zero(&array_at::<32>(encoded, RECIPIENT_KEY_ID_OFFSET))
    {
        return Err(CashuCustodyErrorV1::InvalidIdentifier);
    }
    let ephemeral_public_key = array_at::<32>(encoded, EPHEMERAL_PUBLIC_KEY_OFFSET);
    if !is_canonical_x25519_public_key_v1(&ephemeral_public_key)
        || is_all_zero(&ephemeral_public_key)
        || !is_contributory_x25519_public_key_v1(&ephemeral_public_key)
    {
        return Err(CashuCustodyErrorV1::InvalidEphemeralKey);
    }

    let ciphertext_len = u32::from_be_bytes(array_at::<4>(encoded, CIPHERTEXT_LENGTH_OFFSET));
    let ciphertext_len =
        usize::try_from(ciphertext_len).map_err(|_| CashuCustodyErrorV1::InvalidEnvelope)?;
    if !(AEAD_TAG_BYTES + 1..=MAX_CIPHERTEXT_BYTES_V1).contains(&ciphertext_len)
        || HEADER_BYTES_V1.checked_add(ciphertext_len) != Some(encoded.len())
    {
        return Err(CashuCustodyErrorV1::InvalidEnvelope);
    }
    Ok(())
}

fn derive_aead_key_v1(
    shared_secret: &[u8; 32],
    recipient_public_key: &[u8; 32],
    header: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CashuCustodyErrorV1> {
    let salt = domain_hash_v1(HKDF_SALT_DOMAIN_V1, b"");
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let info = domain_message_v1(HKDF_INFO_DOMAIN_V1, &[recipient_public_key, header]);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| CashuCustodyErrorV1::KeyDerivationFailed)?;
    Ok(key)
}

fn aad_v1(header: &[u8]) -> Vec<u8> {
    domain_message_v1(AAD_DOMAIN_V1, &[header])
}

fn domain_hash_v1(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let message = domain_message_v1(domain, &[value]);
    Sha256::digest(message).into()
}

fn domain_message_v1(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&(domain.len() as u32).to_be_bytes());
    output.extend_from_slice(domain);
    output.extend_from_slice(&(fields.len() as u32).to_be_bytes());
    for field in fields {
        output.extend_from_slice(&(field.len() as u64).to_be_bytes());
        output.extend_from_slice(field);
    }
    output
}

fn random_nonzero_32() -> Result<Zeroizing<[u8; 32]>, CashuCustodyErrorV1> {
    // A zero CSPRNG sample is astronomically unlikely. A small bounded retry
    // keeps malformed test RNG behavior from becoming an unbounded loop.
    for _ in 0..4 {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut *bytes)
            .map_err(|_| CashuCustodyErrorV1::RandomnessUnavailable)?;
        if !is_all_zero(bytes.as_slice()) {
            return Ok(bytes);
        }
    }
    Err(CashuCustodyErrorV1::RandomnessUnavailable)
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("validated fixed-length envelope field")
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn is_canonical_x25519_public_key_v1(bytes: &[u8; 32]) -> bool {
    // Canonical little-endian field element encoding: 0 <= u < 2^255 - 19.
    // X25519 itself accepts/masks non-canonical encodings, but key identifiers
    // need one unique public-key byte string.
    const FIELD_MODULUS_LE: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    for index in (0..32).rev() {
        if bytes[index] < FIELD_MODULUS_LE[index] {
            return true;
        }
        if bytes[index] > FIELD_MODULUS_LE[index] {
            return false;
        }
    }
    false
}

fn is_contributory_x25519_public_key_v1(bytes: &[u8; 32]) -> bool {
    // Non-contributory X25519 public inputs yield the identity for every
    // clamped scalar. A fixed non-secret probe scalar lets key parsing reject
    // all such encodings before any envelope work begins.
    let probe = StaticSecret::from([0x42; 32]);
    probe
        .diffie_hellman(&PublicKey::from(*bytes))
        .was_contributory()
}

#[cfg(test)]
mod tests;
