//! Concrete cryptographic adapters for BitcoinPIR payment messages.
//!
//! Protocol parsing deliberately labels BIP340 inputs as unverified. This
//! crate is the small, auditable boundary that upgrades them only after a
//! conforming secp256k1/BIP340 prehash verification. The 32-byte protocol
//! transcript is already hashed with its BitcoinPIR domain, so using the
//! ordinary `Verifier` API (which hashes once more) would be incorrect.

#![forbid(unsafe_code)]

use core::fmt;

use k256::{
    elliptic_curve::{
        group::{prime::PrimeCurveAffine, Group},
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField,
    },
    schnorr::{
        signature::hazmat::PrehashVerifier, Signature as SchnorrSignature, SigningKey, VerifyingKey,
    },
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar, SecretKey as K256SecretKey,
};
#[cfg(feature = "provider-store")]
use pir_service_protocol::BitcoinPirCashuBatProofV1;
use pir_service_protocol::{
    CashuDleqVerificationInputV1, CashuDleqVerifierV1, CashuSettlementNoteVerificationInputV1,
    CashuSettlementNoteVerifierV1, ServiceProtocolError, UnverifiedBip340ClaimV1,
    UnverifiedBip340QuoteStatusRequestV1,
};
#[cfg(feature = "provider-store")]
use pir_service_store::CashuBatProofVerifierV1;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentCryptoError {
    InvalidBip340PublicKey,
    InvalidBip340SignatureEncoding,
    BadBip340Signature,
    InvalidBip340SecretKey,
    Bip340SigningFailed,
    InvalidCashuPoint,
    InvalidCashuScalar,
    CashuDleqIdentity,
    BadCashuDleqProof,
    CashuDleqResponseScalarInvalid,
    CashuHashToCurveFailed,
    CashuBlindedMessageMismatch,
    CashuMintKeyNotFound,
    DuplicateCashuMintKey,
    UnsupportedCashuSpendingCondition,
    BadCashuNoteSignature,
}

impl fmt::Display for PaymentCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidBip340PublicKey => "invalid BIP340 x-only public key",
            Self::InvalidBip340SignatureEncoding => "invalid BIP340 signature encoding",
            Self::BadBip340Signature => "BIP340 signature verification failed",
            Self::InvalidBip340SecretKey => "invalid BIP340 secret key",
            Self::Bip340SigningFailed => "BIP340 signing failed",
            Self::InvalidCashuPoint => "invalid Cashu secp256k1 point",
            Self::InvalidCashuScalar => "invalid Cashu secp256k1 scalar",
            Self::CashuDleqIdentity => "Cashu DLEQ reconstructed the identity point",
            Self::BadCashuDleqProof => "Cashu NUT-12 DLEQ verification failed",
            Self::CashuDleqResponseScalarInvalid => {
                "Cashu NUT-12 response scalar is zero or non-canonical; retry with fresh randomness"
            }
            Self::CashuHashToCurveFailed => "Cashu hash-to-curve exhausted its safety bound",
            Self::CashuBlindedMessageMismatch => {
                "Cashu blinded message does not match the wallet secret and blinding scalar"
            }
            Self::CashuMintKeyNotFound => "Cashu mint denomination key is not retained",
            Self::DuplicateCashuMintKey => "duplicate Cashu mint denomination key",
            Self::UnsupportedCashuSpendingCondition => {
                "Cashu spending condition is unsupported by this verifier"
            }
            Self::BadCashuNoteSignature => "Cashu note signature verification failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PaymentCryptoError {}

/// Evidence that one exact quote-claim transcript passed BIP340 verification.
/// Fields are private so callers cannot construct successful evidence by
/// assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedBip340ClaimV1 {
    claim_pubkey_xonly: [u8; 32],
    message_digest: [u8; 32],
}

impl VerifiedBip340ClaimV1 {
    pub const fn claim_pubkey_xonly(&self) -> &[u8; 32] {
        &self.claim_pubkey_xonly
    }

    pub const fn message_digest(&self) -> &[u8; 32] {
        &self.message_digest
    }
}

/// Evidence that one exact private quote-status request passed BIP340
/// verification. The nonce remains available for atomic store consumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedBip340QuoteStatusRequestV1 {
    claim_pubkey_xonly: [u8; 32],
    message_digest: [u8; 32],
    quote_id: [u8; 32],
    requested_at: u64,
    request_nonce: [u8; 32],
}

/// Stateless concrete verifier suitable for wiring into issuer-store callback
/// traits without reconstructing a protocol-specific wrapper object.
#[derive(Clone, Copy, Debug, Default)]
pub struct K256Bip340PrehashVerifierV1;

/// Concrete verifier for the mint-to-wallet NUT-12 DLEQ relation used by
/// Cashu swaps and BitcoinPIR BAT issuance.
///
/// This adapter accepts only canonical compressed secp256k1 points and
/// canonical non-zero `e`/`s` scalars. It hashes the lowercase hexadecimal
/// encoding of the four uncompressed points exactly as required by NUT-12.
#[derive(Clone, Copy, Debug, Default)]
pub struct K256CashuDleqVerifierV1;

/// A DLEQ-verified and locally unblinded Cashu promise. Private fields prevent
/// downstream issuance code from constructing this evidence by assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedUnblindedCashuPromiseV1 {
    hashed_secret: [u8; 33],
    unblinded_signature: [u8; 33],
}

/// One issuer-generated blind signature and its NUT-12 DLEQ proof. The
/// caller-supplied proof nonce and denomination secret key are never retained
/// or exposed through this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CashuBlindSignatureWithDleqV1 {
    blinded_signature: [u8; 33],
    dleq_e: [u8; 32],
    dleq_s: [u8; 32],
}

impl CashuBlindSignatureWithDleqV1 {
    pub const fn blinded_signature(&self) -> &[u8; 33] {
        &self.blinded_signature
    }

    pub const fn dleq_e(&self) -> &[u8; 32] {
        &self.dleq_e
    }

    pub const fn dleq_s(&self) -> &[u8; 32] {
        &self.dleq_s
    }
}

impl VerifiedUnblindedCashuPromiseV1 {
    pub const fn hashed_secret(&self) -> &[u8; 33] {
        &self.hashed_secret
    }

    pub const fn unblinded_signature(&self) -> &[u8; 33] {
        &self.unblinded_signature
    }
}

struct CashuMintKeyV1 {
    public_key: [u8; 33],
    secret_key: K256SecretKey,
}

/// In-memory view of the issuer's retained Cashu denomination secret keys.
/// Secret material is held by k256's zeroizing `SecretKey` type and is never
/// exposed by this API or its `Debug` implementation.
pub struct K256CashuMintKeyringV1 {
    keys: Vec<CashuMintKeyV1>,
}

impl fmt::Debug for K256CashuMintKeyringV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("K256CashuMintKeyringV1")
            .field("key_count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl K256CashuMintKeyringV1 {
    /// Construct a retained verifier keyring from raw 32-byte secret scalars.
    /// The returned public-key list can be bound into the signed issuer
    /// keyset; secret bytes cannot be read back through this type.
    pub fn from_secret_keys(
        secret_keys: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<Self, PaymentCryptoError> {
        let mut keys = Vec::new();
        for secret_bytes in secret_keys {
            let secret_key = K256SecretKey::from_slice(&secret_bytes)
                .map_err(|_| PaymentCryptoError::InvalidCashuScalar)?;
            let encoded = secret_key.public_key().to_encoded_point(true);
            let public_key: [u8; 33] = encoded
                .as_bytes()
                .try_into()
                .map_err(|_| PaymentCryptoError::InvalidCashuPoint)?;
            keys.push(CashuMintKeyV1 {
                public_key,
                secret_key,
            });
        }
        keys.sort_by_key(|key| key.public_key);
        if keys.is_empty() {
            return Err(PaymentCryptoError::CashuMintKeyNotFound);
        }
        if keys
            .windows(2)
            .any(|pair| pair[0].public_key == pair[1].public_key)
        {
            return Err(PaymentCryptoError::DuplicateCashuMintKey);
        }
        Ok(Self { keys })
    }

    pub fn denomination_public_keys(&self) -> Vec<[u8; 33]> {
        self.keys.iter().map(|key| key.public_key).collect()
    }

    fn find(&self, public_key: &[u8; 33]) -> Result<&CashuMintKeyV1, PaymentCryptoError> {
        self.keys
            .binary_search_by_key(public_key, |key| key.public_key)
            .map(|index| &self.keys[index])
            .map_err(|_| PaymentCryptoError::CashuMintKeyNotFound)
    }

    /// Blind-sign `B_` and prove in zero knowledge that the same retained
    /// denomination scalar relates `G -> A` and `B_ -> C_`.
    ///
    /// `proof_nonce_scalar` must be freshly sampled for this response by a
    /// cryptographically secure RNG. It is caller-supplied so native and WASM
    /// key-custody adapters can own their entropy boundary. A vanishingly rare
    /// non-canonical challenge or zero response scalar is rejected; callers
    /// must retry with fresh randomness and must never reuse the failed nonce.
    pub fn blind_sign_with_dleq_v1(
        &self,
        denomination_public_key: &[u8; 33],
        blinded_message: &[u8; 33],
        proof_nonce_scalar: &[u8; 32],
    ) -> Result<CashuBlindSignatureWithDleqV1, PaymentCryptoError> {
        let key = self.find(denomination_public_key)?;
        let b_prime = parse_cashu_point(blinded_message)?;
        let a_scalar = *key.secret_key.to_nonzero_scalar().as_ref();
        let nonce = parse_cashu_scalar(proof_nonce_scalar)?;
        let a = parse_cashu_point(&key.public_key)?;
        let c_prime = b_prime * a_scalar;
        let r1 = ProjectivePoint::GENERATOR * nonce;
        let r2 = b_prime * nonce;
        let dleq_e = cashu_nut12_challenge_v1(&r1, &r2, &a, &c_prime)?;
        let e = parse_cashu_scalar(&dleq_e)
            .map_err(|_| PaymentCryptoError::CashuDleqResponseScalarInvalid)?;
        let s = nonce + e * a_scalar;
        if bool::from(s.is_zero()) {
            return Err(PaymentCryptoError::CashuDleqResponseScalarInvalid);
        }
        Ok(CashuBlindSignatureWithDleqV1 {
            blinded_signature: compress_cashu_point(&c_prime)?,
            dleq_e,
            dleq_s: s.to_bytes().into(),
        })
    }
}

impl K256Bip340PrehashVerifierV1 {
    pub fn verify(
        &self,
        public_key_xonly: &[u8; 32],
        message_digest: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), PaymentCryptoError> {
        verify_bip340_prehash(public_key_xonly, message_digest, signature)
    }
}

impl K256CashuDleqVerifierV1 {
    pub fn verify(
        &self,
        denomination_public_key: &[u8; 33],
        blinded_message: &[u8; 33],
        blinded_signature: &[u8; 33],
        dleq_e: &[u8; 32],
        dleq_s: &[u8; 32],
    ) -> Result<(), PaymentCryptoError> {
        verify_cashu_nut12_dleq_v1(
            denomination_public_key,
            blinded_message,
            blinded_signature,
            dleq_e,
            dleq_s,
        )
    }
}

impl CashuDleqVerifierV1 for K256CashuDleqVerifierV1 {
    fn verify_dleq(
        &self,
        input: CashuDleqVerificationInputV1<'_>,
    ) -> Result<(), ServiceProtocolError> {
        self.verify(
            input.denomination_public_key,
            input.blinded_message,
            input.blinded_signature,
            input.dleq_e,
            input.dleq_s,
        )
        .map_err(|_| ServiceProtocolError::InvalidValue {
            field: "CashuDleqVerificationInputV1",
            reason: "authoritative NUT-12 DLEQ verification failed",
        })
    }
}

impl CashuSettlementNoteVerifierV1 for K256CashuMintKeyringV1 {
    fn verify_note_and_derive_y(
        &self,
        input: CashuSettlementNoteVerificationInputV1<'_>,
    ) -> Result<[u8; 33], ServiceProtocolError> {
        self.verify_unconditional_note(
            input.denomination_public_key,
            input.secret,
            input.signature,
            input.witness,
        )
        .map_err(|_| ServiceProtocolError::InvalidValue {
            field: "CashuSettlementNoteVerificationInputV1",
            reason: "Cashu note signature, mint key, or spending condition is invalid",
        })
    }
}

#[cfg(feature = "provider-store")]
impl CashuBatProofVerifierV1 for K256CashuMintKeyringV1 {
    fn verify_cashu_bat_proof_v1(
        &self,
        proof: &BitcoinPirCashuBatProofV1,
        raw_verification_key: &[u8; 33],
    ) -> Result<(), ServiceProtocolError> {
        self.verify_raw_cashu_signature(raw_verification_key, &proof.secret_raw, &proof.c)
            .map(|_| ())
            .map_err(|_| ServiceProtocolError::InvalidValue {
                field: "BitcoinPirCashuBatProofV1",
                reason: "authoritative Cashu BAT signature verification failed",
            })
    }
}

impl K256CashuMintKeyringV1 {
    /// Verify an ordinary, anyone-can-spend Cashu note issued by this keyring.
    /// V1 deliberately rejects every witness and every NUT-10-shaped JSON
    /// secret; conditional P2PK/HTLC notes require a separate reviewed adapter.
    pub fn verify_unconditional_note(
        &self,
        denomination_public_key: &[u8; 33],
        secret: &str,
        signature: &[u8; 33],
        witness: Option<&str>,
    ) -> Result<[u8; 33], PaymentCryptoError> {
        if witness.is_some() || is_nut10_shaped_secret(secret) {
            return Err(PaymentCryptoError::UnsupportedCashuSpendingCondition);
        }
        self.verify_raw_cashu_signature(denomination_public_key, secret.as_bytes(), signature)
    }

    /// Verify a raw-secret Cashu signature under a retained denomination key.
    /// BitcoinPIR BAT uses exactly 32 random bytes here rather than a UTF-8
    /// Cashu proof string. This method authenticates the signature only;
    /// callers must independently bind denomination/public key and capability
    /// audience through a verified policy before treating it as admission.
    pub fn verify_raw_cashu_signature(
        &self,
        denomination_public_key: &[u8; 33],
        secret: &[u8],
        signature: &[u8; 33],
    ) -> Result<[u8; 33], PaymentCryptoError> {
        let key = self.find(denomination_public_key)?;
        let signature = parse_cashu_point(signature)?;
        let y = cashu_hash_to_curve_point_v1(secret)?;
        if y * key.secret_key.to_nonzero_scalar().as_ref() != signature {
            return Err(PaymentCryptoError::BadCashuNoteSignature);
        }
        compress_cashu_point(&y)
    }
}

impl VerifiedBip340QuoteStatusRequestV1 {
    pub const fn claim_pubkey_xonly(&self) -> &[u8; 32] {
        &self.claim_pubkey_xonly
    }

    pub const fn message_digest(&self) -> &[u8; 32] {
        &self.message_digest
    }

    pub const fn quote_id(&self) -> &[u8; 32] {
        &self.quote_id
    }

    pub const fn requested_at(&self) -> u64 {
        self.requested_at
    }

    pub const fn request_nonce(&self) -> &[u8; 32] {
        &self.request_nonce
    }
}

pub fn verify_quote_claim_v1(
    input: &UnverifiedBip340ClaimV1,
) -> Result<VerifiedBip340ClaimV1, PaymentCryptoError> {
    verify_bip340_prehash(
        &input.claim_pubkey_xonly,
        &input.message_digest,
        &input.signature,
    )?;
    Ok(VerifiedBip340ClaimV1 {
        claim_pubkey_xonly: input.claim_pubkey_xonly,
        message_digest: input.message_digest,
    })
}

pub fn verify_quote_status_request_v1(
    input: &UnverifiedBip340QuoteStatusRequestV1,
) -> Result<VerifiedBip340QuoteStatusRequestV1, PaymentCryptoError> {
    verify_bip340_prehash(
        &input.claim_pubkey_xonly,
        &input.message_digest,
        &input.signature,
    )?;
    Ok(VerifiedBip340QuoteStatusRequestV1 {
        claim_pubkey_xonly: input.claim_pubkey_xonly,
        message_digest: input.message_digest,
        quote_id: input.quote_id,
        requested_at: input.requested_at,
        request_nonce: input.request_nonce,
    })
}

/// Browser-side helper for signing an already domain-separated 32-byte
/// protocol transcript. Random auxiliary data is caller-supplied so WASM can
/// obtain it from Web Crypto without this crate owning an RNG.
pub fn sign_bip340_prehash_v1(
    secret_key: &[u8; 32],
    message_digest: &[u8; 32],
    auxiliary_randomness: &[u8; 32],
) -> Result<([u8; 32], [u8; 64]), PaymentCryptoError> {
    let signing_key = SigningKey::from_bytes(secret_key)
        .map_err(|_| PaymentCryptoError::InvalidBip340SecretKey)?;
    let signature = signing_key
        .sign_prehash_with_aux_rand(message_digest, auxiliary_randomness)
        .map_err(|_| PaymentCryptoError::Bip340SigningFailed)?;
    Ok((
        signing_key.verifying_key().to_bytes().into(),
        signature.to_bytes(),
    ))
}

fn verify_bip340_prehash(
    claim_pubkey_xonly: &[u8; 32],
    message_digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), PaymentCryptoError> {
    let verifying_key = VerifyingKey::from_bytes(claim_pubkey_xonly)
        .map_err(|_| PaymentCryptoError::InvalidBip340PublicKey)?;
    let signature = SchnorrSignature::try_from(signature.as_slice())
        .map_err(|_| PaymentCryptoError::InvalidBip340SignatureEncoding)?;
    verifying_key
        .verify_prehash(message_digest, &signature)
        .map_err(|_| PaymentCryptoError::BadBip340Signature)
}

/// Verify the NUT-12 proof returned alongside one blind Cashu signature.
///
/// The wallet's private blinding scalar is intentionally not accepted by
/// this function. A mint or provider that learns that scalar can link the
/// blinded issuance transcript to the later unblinded proof.
pub fn verify_cashu_nut12_dleq_v1(
    denomination_public_key: &[u8; 33],
    blinded_message: &[u8; 33],
    blinded_signature: &[u8; 33],
    dleq_e: &[u8; 32],
    dleq_s: &[u8; 32],
) -> Result<(), PaymentCryptoError> {
    let a = parse_cashu_point(denomination_public_key)?;
    let b_prime = parse_cashu_point(blinded_message)?;
    let c_prime = parse_cashu_point(blinded_signature)?;
    let e = parse_cashu_scalar(dleq_e)?;
    let s = parse_cashu_scalar(dleq_s)?;

    let r1 = ProjectivePoint::GENERATOR * s - a * e;
    let r2 = b_prime * s - c_prime * e;
    if bool::from(r1.is_identity()) || bool::from(r2.is_identity()) {
        return Err(PaymentCryptoError::CashuDleqIdentity);
    }

    let computed = cashu_nut12_challenge_v1(&r1, &r2, &a, &c_prime)?;
    if computed != *dleq_e {
        return Err(PaymentCryptoError::BadCashuDleqProof);
    }
    Ok(())
}

/// Verify the NUT-12 proof attached to an already-unblinded Cashu `Proof`.
///
/// A receiver is given `(secret, C, e, s, r)` rather than the original blind
/// issuance transcript. NUT-12 requires reconstructing `B_ = H(secret) + rG`
/// and `C_ = C + rA`, then checking the ordinary DLEQ relation. The private
/// blinding scalar is accepted only at this wallet-side boundary and must not
/// be forwarded to the mint or a service provider.
#[allow(clippy::too_many_arguments)]
pub fn verify_cashu_received_proof_dleq_v1(
    secret: &[u8],
    unblinded_signature: &[u8; 33],
    denomination_public_key: &[u8; 33],
    dleq_e: &[u8; 32],
    dleq_s: &[u8; 32],
    blinding_scalar: &[u8; 32],
) -> Result<(), PaymentCryptoError> {
    let r = parse_cashu_scalar(blinding_scalar)?;
    let y = cashu_hash_to_curve_point_v1(secret)?;
    let a = parse_cashu_point(denomination_public_key)?;
    let c = parse_cashu_point(unblinded_signature)?;
    let blinded_message = compress_cashu_point(&(y + ProjectivePoint::GENERATOR * r))?;
    let blinded_signature = compress_cashu_point(&(c + a * r))?;
    verify_cashu_nut12_dleq_v1(
        denomination_public_key,
        &blinded_message,
        &blinded_signature,
        dleq_e,
        dleq_s,
    )
}

/// Derive Cashu's NUT-00 `Y = hash_to_curve(secret)` as a canonical compressed
/// secp256k1 point.
pub fn cashu_hash_to_curve_v1(secret: &[u8]) -> Result<[u8; 33], PaymentCryptoError> {
    compress_cashu_point(&cashu_hash_to_curve_point_v1(secret)?)
}

/// Verify a mint's NUT-12 response, prove that the wallet's locally retained
/// secret/blinding scalar produced the echoed `B_`, and only then unblind
/// `C_`. The blinding scalar never leaves the caller through protocol types.
#[allow(clippy::too_many_arguments)]
pub fn verify_and_unblind_cashu_promise_v1(
    secret: &[u8],
    blinding_scalar: &[u8; 32],
    denomination_public_key: &[u8; 33],
    echoed_blinded_message: &[u8; 33],
    blinded_signature: &[u8; 33],
    dleq_e: &[u8; 32],
    dleq_s: &[u8; 32],
) -> Result<VerifiedUnblindedCashuPromiseV1, PaymentCryptoError> {
    verify_cashu_nut12_dleq_v1(
        denomination_public_key,
        echoed_blinded_message,
        blinded_signature,
        dleq_e,
        dleq_s,
    )?;

    let r = parse_cashu_scalar(blinding_scalar)?;
    let y = cashu_hash_to_curve_point_v1(secret)?;
    let expected_blinded_message = y + ProjectivePoint::GENERATOR * r;
    if compress_cashu_point(&expected_blinded_message)? != *echoed_blinded_message {
        return Err(PaymentCryptoError::CashuBlindedMessageMismatch);
    }

    let c_prime = parse_cashu_point(blinded_signature)?;
    let a = parse_cashu_point(denomination_public_key)?;
    let unblinded_signature = c_prime - a * r;
    Ok(VerifiedUnblindedCashuPromiseV1 {
        hashed_secret: compress_cashu_point(&y)?,
        unblinded_signature: compress_cashu_point(&unblinded_signature)?,
    })
}

/// Build the blinded NUT-00 message `B_ = hash_to_curve(secret) + rG` from a
/// caller-generated canonical non-zero scalar.
pub fn blind_cashu_message_v1(
    secret: &[u8],
    blinding_scalar: &[u8; 32],
) -> Result<[u8; 33], PaymentCryptoError> {
    let r = parse_cashu_scalar(blinding_scalar)?;
    let blinded = cashu_hash_to_curve_point_v1(secret)? + ProjectivePoint::GENERATOR * r;
    compress_cashu_point(&blinded)
}

fn parse_cashu_point(bytes: &[u8; 33]) -> Result<ProjectivePoint, PaymentCryptoError> {
    if !matches!(bytes[0], 0x02 | 0x03) {
        return Err(PaymentCryptoError::InvalidCashuPoint);
    }
    let encoded =
        EncodedPoint::from_bytes(bytes).map_err(|_| PaymentCryptoError::InvalidCashuPoint)?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .filter(|point| !bool::from(point.is_identity()))
        .ok_or(PaymentCryptoError::InvalidCashuPoint)?;
    Ok(affine.into())
}

fn parse_cashu_scalar(bytes: &[u8; 32]) -> Result<Scalar, PaymentCryptoError> {
    Option::<Scalar>::from(Scalar::from_repr((*bytes).into()))
        .filter(|scalar| !bool::from(scalar.is_zero()))
        .ok_or(PaymentCryptoError::InvalidCashuScalar)
}

fn cashu_hash_to_curve_point_v1(secret: &[u8]) -> Result<ProjectivePoint, PaymentCryptoError> {
    let mut initial_hasher = Sha256::new();
    initial_hasher.update(b"Secp256k1_HashToCurve_Cashu_");
    initial_hasher.update(secret);
    let message_hash = initial_hasher.finalize();

    // The chance of exhausting even a handful of attempts is negligible. A
    // 2^16 bound matches the reference CDK implementation and gives hostile
    // inputs an explicit work ceiling.
    for counter in 0..=u16::MAX {
        let mut hasher = Sha256::new();
        hasher.update(message_hash);
        hasher.update(u32::from(counter).to_le_bytes());
        let x: [u8; 32] = hasher.finalize().into();
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&x);
        if let Ok(point) = parse_cashu_point(&compressed) {
            return Ok(point);
        }
    }
    Err(PaymentCryptoError::CashuHashToCurveFailed)
}

fn compress_cashu_point(point: &ProjectivePoint) -> Result<[u8; 33], PaymentCryptoError> {
    if bool::from(point.is_identity()) {
        return Err(PaymentCryptoError::InvalidCashuPoint);
    }
    point
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| PaymentCryptoError::InvalidCashuPoint)
}

fn is_nut10_shaped_secret(secret: &str) -> bool {
    let Ok(serde_json::Value::Array(elements)) = serde_json::from_str(secret) else {
        return false;
    };
    elements.len() == 2 && elements[0].is_string() && elements[1].is_object()
}

fn cashu_nut12_challenge_v1(
    r1: &ProjectivePoint,
    r2: &ProjectivePoint,
    a: &ProjectivePoint,
    c_prime: &ProjectivePoint,
) -> Result<[u8; 32], PaymentCryptoError> {
    let mut hasher = Sha256::new();
    for point in [r1, r2, a, c_prime] {
        if bool::from(point.is_identity()) {
            return Err(PaymentCryptoError::CashuDleqIdentity);
        }
        let encoded = point.to_affine().to_encoded_point(false);
        hash_lower_hex(&mut hasher, encoded.as_bytes());
    }
    Ok(hasher.finalize().into())
}

fn hash_lower_hex(hasher: &mut Sha256, bytes: &[u8]) {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0u8; 130];
    debug_assert!(bytes.len() <= encoded.len() / 2);
    for (index, byte) in bytes.iter().copied().enumerate() {
        encoded[index * 2] = LOWER_HEX[(byte >> 4) as usize];
        encoded[index * 2 + 1] = LOWER_HEX[(byte & 0x0f) as usize];
    }
    hasher.update(&encoded[..bytes.len() * 2]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_array<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    fn signed_claim() -> UnverifiedBip340ClaimV1 {
        let secret_key = [7; 32];
        let digest = [9; 32];
        let (public_key, signature) =
            sign_bip340_prehash_v1(&secret_key, &digest, &[11; 32]).unwrap();
        UnverifiedBip340ClaimV1 {
            claim_pubkey_xonly: public_key,
            message_digest: digest,
            signature,
        }
    }

    #[test]
    fn verifies_exact_claim_prehash_without_double_hashing() {
        let input = signed_claim();
        let verified = verify_quote_claim_v1(&input).unwrap();
        assert_eq!(verified.claim_pubkey_xonly(), &input.claim_pubkey_xonly);
        assert_eq!(verified.message_digest(), &input.message_digest);

        let key = VerifyingKey::from_bytes(&input.claim_pubkey_xonly).unwrap();
        let signature = SchnorrSignature::try_from(input.signature.as_slice()).unwrap();
        use k256::schnorr::signature::Verifier;
        assert!(key.verify(&input.message_digest, &signature).is_err());
    }

    #[test]
    fn rejects_tampered_claim_and_malformed_signature() {
        let input = signed_claim();
        let mut changed_digest = input;
        changed_digest.message_digest[0] ^= 1;
        assert_eq!(
            verify_quote_claim_v1(&changed_digest),
            Err(PaymentCryptoError::BadBip340Signature)
        );

        let mut malformed = input;
        malformed.signature[32..].fill(0);
        assert!(matches!(
            verify_quote_claim_v1(&malformed),
            Err(PaymentCryptoError::InvalidBip340SignatureEncoding)
                | Err(PaymentCryptoError::BadBip340Signature)
        ));
    }

    #[test]
    fn verifies_status_and_preserves_nonce_bookkeeping_fields() {
        let claim = signed_claim();
        let input = UnverifiedBip340QuoteStatusRequestV1 {
            claim_pubkey_xonly: claim.claim_pubkey_xonly,
            message_digest: claim.message_digest,
            signature: claim.signature,
            quote_id: [3; 32],
            requested_at: 123,
            request_nonce: [5; 32],
        };
        let verified = verify_quote_status_request_v1(&input).unwrap();
        assert_eq!(verified.quote_id(), &[3; 32]);
        assert_eq!(verified.requested_at(), 123);
        assert_eq!(verified.request_nonce(), &[5; 32]);
    }

    #[test]
    fn rejects_zero_or_out_of_range_secret_key() {
        assert_eq!(
            sign_bip340_prehash_v1(&[0; 32], &[1; 32], &[2; 32]),
            Err(PaymentCryptoError::InvalidBip340SecretKey)
        );
        assert_eq!(
            sign_bip340_prehash_v1(&[0xff; 32], &[1; 32], &[2; 32]),
            Err(PaymentCryptoError::InvalidBip340SecretKey)
        );
    }

    #[test]
    fn stateless_verifier_is_suitable_for_store_adapter_callbacks() {
        let input = signed_claim();
        K256Bip340PrehashVerifierV1
            .verify(
                &input.claim_pubkey_xonly,
                &input.message_digest,
                &input.signature,
            )
            .unwrap();
    }

    #[test]
    fn matches_official_bip340_vector_zero() {
        // bitcoin/bips bip-0340/test-vectors.csv, vector 0.
        let secret_key =
            hex_array("0000000000000000000000000000000000000000000000000000000000000003");
        let expected_public_key =
            hex_array("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
        let expected_signature = hex_array("e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0");
        let (public_key, signature) =
            sign_bip340_prehash_v1(&secret_key, &[0; 32], &[0; 32]).unwrap();
        assert_eq!(public_key, expected_public_key);
        assert_eq!(signature, expected_signature);
        K256Bip340PrehashVerifierV1
            .verify(&public_key, &[0; 32], &signature)
            .unwrap();
    }

    #[test]
    fn matches_official_cashu_nut12_blind_signature_vector() {
        let a = hex_array("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let b_prime =
            hex_array("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
        let c_prime = b_prime;
        let e = hex_array("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9");
        let s = hex_array("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da");

        K256CashuDleqVerifierV1
            .verify(&a, &b_prime, &c_prime, &e, &s)
            .unwrap();
    }

    #[test]
    fn matches_official_cashu_nut12_hash_e_vector() {
        let repeated = parse_cashu_point(&hex_array(
            "020000000000000000000000000000000000000000000000000000000000000001",
        ))
        .unwrap();
        let c_prime = parse_cashu_point(&hex_array(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
        ))
        .unwrap();
        assert_eq!(
            cashu_nut12_challenge_v1(&repeated, &repeated, &repeated, &c_prime).unwrap(),
            hex_array("a4dc034b74338c28c6bc3ea49731f2a24440fc7c4affc08b31a93fc9fbe6401e")
        );
    }

    #[test]
    fn cashu_dleq_rejects_tampering_and_noncanonical_inputs() {
        let a = hex_array("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let b_prime =
            hex_array("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
        let e = hex_array("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9");
        let s = hex_array("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da");

        let mut changed_s = s;
        changed_s[31] ^= 1;
        assert_eq!(
            verify_cashu_nut12_dleq_v1(&a, &b_prime, &b_prime, &e, &changed_s),
            Err(PaymentCryptoError::BadCashuDleqProof)
        );

        let mut uncompressed_marker = b_prime;
        uncompressed_marker[0] = 0x04;
        assert_eq!(
            verify_cashu_nut12_dleq_v1(&a, &uncompressed_marker, &b_prime, &e, &s),
            Err(PaymentCryptoError::InvalidCashuPoint)
        );
        assert_eq!(
            verify_cashu_nut12_dleq_v1(&a, &b_prime, &b_prime, &[0; 32], &s),
            Err(PaymentCryptoError::InvalidCashuScalar)
        );
        assert_eq!(
            verify_cashu_nut12_dleq_v1(&a, &b_prime, &b_prime, &e, &[0xff; 32]),
            Err(PaymentCryptoError::InvalidCashuScalar)
        );
    }

    #[test]
    fn issuer_blind_signature_roundtrips_through_nut12_and_unblinding() {
        let keyring = K256CashuMintKeyringV1::from_secret_keys([[13; 32]]).unwrap();
        let public_key = keyring.denomination_public_keys()[0];
        let secret = b"independent browser BAT secret";
        let blinding_scalar = [7; 32];
        let blinded_message = blind_cashu_message_v1(secret, &blinding_scalar).unwrap();
        let response = keyring
            .blind_sign_with_dleq_v1(&public_key, &blinded_message, &[17; 32])
            .unwrap();

        verify_cashu_nut12_dleq_v1(
            &public_key,
            &blinded_message,
            response.blinded_signature(),
            response.dleq_e(),
            response.dleq_s(),
        )
        .unwrap();
        let unblinded = verify_and_unblind_cashu_promise_v1(
            secret,
            &blinding_scalar,
            &public_key,
            &blinded_message,
            response.blinded_signature(),
            response.dleq_e(),
            response.dleq_s(),
        )
        .unwrap();
        keyring
            .verify_raw_cashu_signature(&public_key, secret, unblinded.unblinded_signature())
            .unwrap();
        verify_cashu_received_proof_dleq_v1(
            secret,
            unblinded.unblinded_signature(),
            &public_key,
            response.dleq_e(),
            response.dleq_s(),
            &blinding_scalar,
        )
        .unwrap();

        let mut tampered_r = blinding_scalar;
        tampered_r[31] ^= 1;
        assert_eq!(
            verify_cashu_received_proof_dleq_v1(
                secret,
                unblinded.unblinded_signature(),
                &public_key,
                response.dleq_e(),
                response.dleq_s(),
                &tampered_r,
            ),
            Err(PaymentCryptoError::BadCashuDleqProof)
        );

        let malformed_message = [0; 33];
        assert_eq!(
            keyring.blind_sign_with_dleq_v1(&public_key, &malformed_message, &[17; 32]),
            Err(PaymentCryptoError::InvalidCashuPoint)
        );
        assert_eq!(
            keyring.blind_sign_with_dleq_v1(&public_key, &blinded_message, &[0; 32]),
            Err(PaymentCryptoError::InvalidCashuScalar)
        );
    }

    #[test]
    fn cashu_hash_to_curve_matches_official_vectors() {
        assert_eq!(
            cashu_hash_to_curve_v1(
                &hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap()
            )
            .unwrap(),
            hex_array("024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725")
        );
        assert_eq!(
            cashu_hash_to_curve_v1(
                &hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                    .unwrap()
            )
            .unwrap(),
            hex_array("022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf")
        );
    }

    #[test]
    fn verified_unblinding_checks_local_blinding_transcript() {
        let secret = b"wallet-secret";
        let mint_scalar = Scalar::from(13u64);
        let blinding_scalar = Scalar::from(7u64);
        let nonce = Scalar::from(19u64);
        let y = cashu_hash_to_curve_point_v1(secret).unwrap();
        let a_point = ProjectivePoint::GENERATOR * mint_scalar;
        let b_prime_point = y + ProjectivePoint::GENERATOR * blinding_scalar;
        let c_prime_point = b_prime_point * mint_scalar;
        let r1 = ProjectivePoint::GENERATOR * nonce;
        let r2 = b_prime_point * nonce;
        let e_bytes = cashu_nut12_challenge_v1(&r1, &r2, &a_point, &c_prime_point).unwrap();
        let e = parse_cashu_scalar(&e_bytes).unwrap();
        let s = nonce + e * mint_scalar;
        let a = compress_cashu_point(&a_point).unwrap();
        let b_prime = compress_cashu_point(&b_prime_point).unwrap();
        let c_prime = compress_cashu_point(&c_prime_point).unwrap();
        let r_bytes: [u8; 32] = blinding_scalar.to_bytes().into();
        let s_bytes: [u8; 32] = s.to_bytes().into();

        let verified = verify_and_unblind_cashu_promise_v1(
            secret, &r_bytes, &a, &b_prime, &c_prime, &e_bytes, &s_bytes,
        )
        .unwrap();
        assert_eq!(verified.hashed_secret(), &compress_cashu_point(&y).unwrap());
        assert_eq!(
            verified.unblinded_signature(),
            &compress_cashu_point(&(y * mint_scalar)).unwrap()
        );

        let wrong_r: [u8; 32] = Scalar::from(8u64).to_bytes().into();
        assert_eq!(
            verify_and_unblind_cashu_promise_v1(
                secret, &wrong_r, &a, &b_prime, &c_prime, &e_bytes, &s_bytes,
            ),
            Err(PaymentCryptoError::CashuBlindedMessageMismatch)
        );
    }

    #[test]
    fn cashu_mint_keyring_verifies_only_unconditional_notes() {
        let keyring = K256CashuMintKeyringV1::from_secret_keys([[3; 32]]).unwrap();
        let public_key = keyring.denomination_public_keys()[0];
        let secret = "ordinary-random-secret";
        let y = cashu_hash_to_curve_point_v1(secret.as_bytes()).unwrap();
        let scalar = parse_cashu_scalar(&[3; 32]).unwrap();
        let signature = compress_cashu_point(&(y * scalar)).unwrap();

        assert_eq!(
            keyring
                .verify_unconditional_note(&public_key, secret, &signature, None)
                .unwrap(),
            compress_cashu_point(&y).unwrap()
        );
        assert_eq!(
            keyring.verify_unconditional_note(
                &public_key,
                r#"["P2PK",{"nonce":"n","data":"02aa"}]"#,
                &signature,
                None,
            ),
            Err(PaymentCryptoError::UnsupportedCashuSpendingCondition)
        );
        assert_eq!(
            keyring.verify_unconditional_note(&public_key, secret, &signature, Some("{}")),
            Err(PaymentCryptoError::UnsupportedCashuSpendingCondition)
        );

        let mut wrong_signature = signature;
        wrong_signature[32] ^= 1;
        assert!(matches!(
            keyring.verify_unconditional_note(&public_key, secret, &wrong_signature, None),
            Err(PaymentCryptoError::InvalidCashuPoint)
                | Err(PaymentCryptoError::BadCashuNoteSignature)
        ));
    }

    #[test]
    fn cashu_mint_keyring_rejects_duplicate_and_unknown_keys() {
        assert_eq!(
            K256CashuMintKeyringV1::from_secret_keys([[4; 32], [4; 32]]).unwrap_err(),
            PaymentCryptoError::DuplicateCashuMintKey
        );
        let keyring = K256CashuMintKeyringV1::from_secret_keys([[4; 32]]).unwrap();
        let other_public = K256CashuMintKeyringV1::from_secret_keys([[5; 32]])
            .unwrap()
            .denomination_public_keys()[0];
        assert_eq!(
            keyring.verify_unconditional_note(
                &other_public,
                "secret",
                &hex_array("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
                None,
            ),
            Err(PaymentCryptoError::CashuMintKeyNotFound)
        );
    }
}
