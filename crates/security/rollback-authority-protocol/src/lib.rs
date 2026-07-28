//! Wire and client-value cryptography for an independently operated remote
//! rollback authority.
//!
//! The authority sees only a pre-provisioned random namespace, a monotonically
//! increasing revision, a keyed opaque value tag, and a fixed-size sealed
//! value. It cannot decrypt provider or issuer floor records. Every request is
//! signed by its provisioned client key and every response is signed by the
//! pinned authority key. A response is bound to one exact canonical request,
//! including its fresh call nonce and durable idempotency operation ID.
//!
//! A CAS retry signs a new request with a fresh call nonce, the same operation
//! ID, and the same stable operation digest. The authority atomically persists
//! the first terminal result for every operation ID, including `Empty` and
//! `ConflictCurrent`, and compares a stored operation digest before answering a
//! retry. A response always reports the live record: a formerly applied value
//! which has since advanced is a live conflict, never a stale success.
//!
//! Read requests are type-level single-use online freshness checks:
//! [`AuthorityClientSignerV1::sign_fresh_read`] generates the call material
//! internally and read-response verification consumes the resulting
//! [`SignedAuthorityReadAttemptV1`]. Startup and post-CAS recovery must issue a
//! new Read; an old request/response transcript is never evidence of the
//! current rollback floor.
//!
//! This crate deliberately defines no delete, reset, enumerate, or namespace
//! provisioning operation. Provisioning and destructive recovery ceremonies
//! belong to a separate, offline administrative interface.
//!
//! Long-lived roots, derived keys, plaintext allocations, records, and signed
//! wire buffers are explicitly zeroized, and consuming wire exports retain a
//! [`zeroize::Zeroizing<Vec<u8>>`] wrapper. The selected RustCrypto HKDF and HMAC
//! implementations do not promise zeroization of their short-lived internal
//! keyed state; deployments requiring resistance to live-process memory
//! forensics must account for that library boundary separately.

#![forbid(unsafe_code)]

mod codec;
mod value;
mod wire;

#[cfg(test)]
mod tests;

pub use value::{
    AuthorityValueCodecV1, AuthorityValueRootKeyV1, OpaqueAuthorityRecordV1,
    OpenedAuthorityValueV1, AUTHORITY_RECORD_BYTES_V1, MAX_AUTHORITY_VALUE_BYTES_V1,
    SEALED_AUTHORITY_VALUE_BYTES_V1,
};
pub use wire::{
    authority_client_key_id_v1, inspect_authority_request_locator_v1,
    verify_authority_read_response_v1, verify_authority_request_v1, verify_authority_response_v1,
    AuthorityBindingV1, AuthorityCallV1, AuthorityCasDispositionV1, AuthorityCasResolutionRefV1,
    AuthorityClientSignerV1, AuthorityRequestLocatorV1, AuthorityServerSignerV1,
    PersistedAuthorityOperationRefV1, PersistedAuthorityTerminalOutcomeRefV1,
    SignedAuthorityReadAttemptV1, SignedAuthorityRequestV1, SignedAuthorityResponseV1,
    VerifiedAuthorityCasOutcomeV1, VerifiedAuthorityOperationRefV1, VerifiedAuthorityRequestV1,
    VerifiedAuthorityResponseBodyRefV1, VerifiedAuthorityResponseV1, AUTHORITY_CALL_NONCE_BYTES_V1,
    AUTHORITY_CLIENT_KEY_ID_BYTES_V1, AUTHORITY_INSTANCE_ID_BYTES_V1, AUTHORITY_NAMESPACE_BYTES_V1,
    AUTHORITY_OPERATION_DIGEST_BYTES_V1, AUTHORITY_OPERATION_ID_BYTES_V1,
    AUTHORITY_REQUEST_DIGEST_BYTES_V1, AUTHORITY_WIRE_VERSION_V1,
    MAX_SIGNED_AUTHORITY_REQUEST_BYTES_V1, MAX_SIGNED_AUTHORITY_RESPONSE_BYTES_V1,
    SIGNED_AUTHORITY_CAS_REQUEST_BYTES_V1, SIGNED_AUTHORITY_EMPTY_RESPONSE_BYTES_V1,
    SIGNED_AUTHORITY_INITIALIZE_REQUEST_BYTES_V1, SIGNED_AUTHORITY_READ_REQUEST_BYTES_V1,
    SIGNED_AUTHORITY_RECORD_RESPONSE_BYTES_V1,
};

use core::fmt;

/// Fail-closed error categories. No variant contains keys, namespaces, record
/// bytes, signatures, or plaintext and all are therefore safe to log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAuthorityProtocolErrorV1 {
    InvalidIdentifier,
    InvalidCallNonce,
    InvalidOperationId,
    EmptyValue,
    ValueTooLong,
    RandomnessUnavailable,
    KeyDerivationFailed,
    EncryptionFailed,
    DecryptionFailed,
    ValueAuthenticationFailed,
    InvalidMagic,
    UnsupportedVersion,
    UnknownOperation,
    InvalidLength,
    NonCanonicalEncoding,
    OperationDigestMismatch,
    RequestDigestMismatch,
    BadSignature,
    BindingMismatch,
    UnexpectedResponse,
    InvalidOutcome,
}

impl fmt::Display for RollbackAuthorityProtocolErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "rollback-authority identifier is invalid",
            Self::InvalidCallNonce => "rollback-authority call nonce is invalid",
            Self::InvalidOperationId => "rollback-authority operation ID is invalid",
            Self::EmptyValue => "rollback-authority value is empty",
            Self::ValueTooLong => "rollback-authority value exceeds the V1 bound",
            Self::RandomnessUnavailable => "operating-system randomness is unavailable",
            Self::KeyDerivationFailed => "rollback-authority key derivation failed",
            Self::EncryptionFailed => "rollback-authority value encryption failed",
            Self::DecryptionFailed => "rollback-authority value decryption failed",
            Self::ValueAuthenticationFailed => "rollback-authority value authentication failed",
            Self::InvalidMagic => "rollback-authority wire magic is invalid",
            Self::UnsupportedVersion => "rollback-authority wire version is unsupported",
            Self::UnknownOperation => "rollback-authority operation is unknown",
            Self::InvalidLength => "rollback-authority message length is invalid",
            Self::NonCanonicalEncoding => "rollback-authority message is non-canonical",
            Self::OperationDigestMismatch => "rollback-authority operation digest mismatch",
            Self::RequestDigestMismatch => "rollback-authority request digest mismatch",
            Self::BadSignature => "rollback-authority signature verification failed",
            Self::BindingMismatch => "rollback-authority binding mismatch",
            Self::UnexpectedResponse => "rollback-authority response does not match its request",
            Self::InvalidOutcome => "rollback-authority response outcome is invalid",
        })
    }
}

impl std::error::Error for RollbackAuthorityProtocolErrorV1 {}
