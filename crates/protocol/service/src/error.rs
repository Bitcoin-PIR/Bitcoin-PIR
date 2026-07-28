//! Structured fail-closed codec and signature errors.

/// Wire-format and policy-verification failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceProtocolError {
    Truncated(&'static str),
    UnknownVersion {
        kind: &'static str,
        version: u8,
    },
    UnknownDiscriminant {
        kind: &'static str,
        value: u8,
    },
    FieldTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    TooManyItems {
        field: &'static str,
        len: usize,
        max: usize,
    },
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
    InvalidUtf8(&'static str),
    TrailingBytes(usize),
    BadSignature,
    BadPublicKey,
    WrongSigningKeyId,
    FrameClass {
        expected: usize,
        got: usize,
    },
    ProofDoesNotFit {
        encoded: usize,
        frame_class: usize,
    },
}

impl core::fmt::Display for ServiceProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated(field) => write!(f, "truncated field: {field}"),
            Self::UnknownVersion { kind, version } => {
                write!(f, "{kind}: unknown version {version}")
            }
            Self::UnknownDiscriminant { kind, value } => {
                write!(f, "{kind}: unknown discriminant {value}")
            }
            Self::FieldTooLong { field, len, max } => {
                write!(f, "field {field} too long: {len} > {max}")
            }
            Self::TooManyItems { field, len, max } => {
                write!(f, "too many {field}: {len} > {max}")
            }
            Self::InvalidValue { field, reason } => {
                write!(f, "invalid {field}: {reason}")
            }
            Self::InvalidUtf8(field) => write!(f, "field {field} is not UTF-8"),
            Self::TrailingBytes(n) => write!(f, "{n} trailing bytes"),
            Self::BadSignature => write!(f, "signature verification failed"),
            Self::BadPublicKey => write!(f, "invalid Ed25519 public key"),
            Self::WrongSigningKeyId => write!(f, "signing key ID mismatch"),
            Self::FrameClass { expected, got } => {
                write!(
                    f,
                    "wrong authorization frame class: expected {expected}, got {got}"
                )
            }
            Self::ProofDoesNotFit {
                encoded,
                frame_class,
            } => write!(
                f,
                "authorization body {encoded} bytes does not fit frame class {frame_class}"
            ),
        }
    }
}

impl std::error::Error for ServiceProtocolError {}
