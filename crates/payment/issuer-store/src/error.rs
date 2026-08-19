use std::fmt;
use std::io;
use std::path::PathBuf;

#[derive(Debug)]
pub enum StoreError {
    InvalidInput(&'static str),
    MissingDatabase(PathBuf),
    NotRegularDatabase(PathBuf),
    SchemaMismatch(String),
    IntegrityCheckFailed(String),
    StoreInstanceMismatch,
    IssuerMismatch,
    NetworkMismatch,
    RollbackFloorMissing,
    RollbackFloorIdentityMismatch,
    RollbackDetected {
        database_generation: u64,
        authority_generation: u64,
    },
    RollbackFork,
    RollbackAuthorityProtocol(String),
    RollbackAuthorityUnavailable(String),
    UnanchoredCommit {
        store_generation: u64,
        authority_error: String,
    },
    QuoteMissing,
    QuoteProtocolMismatch,
    QuoteConflict,
    QuoteCapacityExceeded,
    CreationIdempotencyConflict,
    InvoiceConflict,
    PaymentHashConflict,
    InvalidQuoteState,
    RequiresExpiryReconcile,
    SettlementConflict,
    SignedQuoteMismatch,
    ClaimIdempotencyConflict,
    QuoteAlreadyClaimed,
    QuoteNotSettled,
    ClaimDeadlineExpired,
    ClaimProtocolMismatch,
    BadClaimCryptography,
    StatusRequestBindingMismatch,
    StatusRequestStale,
    StatusTimeRollback,
    BadStatusRequestSignature,
    StatusNonceReplay,
    StatusNonceCapacityExceeded,
    ReceiptSerialConflict,
    DelegationRollback,
    DelegationFork,
    ServicePolicyRollback,
    ServicePolicyFork,
    ServicePolicySigningKeyConflict,
    BatKeyLineageConflict,
    BatV2ClassRollback,
    BatV2ClassFork,
    BatV2ClassTermsConflict,
    BatV2ClassMemberMismatch,
    BatV2RawKeyConflict,
    ArcKeyLineageConflict,
    SettlementKeyLineageConflict,
    ProviderRegistrationRollback,
    ProviderRegistrationFork,
    ClearingAuthorizationRollback,
    ClearingAuthorizationFork,
    RedeemIdempotencyConflict,
    CredentialAlreadySpent,
    LedgerBalanceOverflow,
    SettlementDepositIdempotencyConflict,
    SettlementNoteAlreadySpent,
    SettlementLedgerSequenceConflict,
    PayoutIntentIdempotencyConflict,
    PayoutIntentAlreadyConsumed,
    PayoutIdempotencyConflict,
    InsufficientProviderBalance,
    PayoutOutboxUnavailable,
    PayoutStatusConflict,
    Protocol(pir_service_protocol::ServiceProtocolError),
    CommitSequenceExhausted,
    /// SQLite returned an error while committing. This operation never
    /// returns a success marker, even if diagnostic read-back later suggests
    /// that the write became visible.
    CommitOutcomeUnknown(String),
    Io(io::Error),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(reason) => write!(f, "invalid issuer-store input: {reason}"),
            Self::MissingDatabase(path) => {
                write!(f, "issuer database does not exist: {}", path.display())
            }
            Self::NotRegularDatabase(path) => write!(
                f,
                "issuer database is not a regular non-symlink file: {}",
                path.display()
            ),
            Self::SchemaMismatch(reason) => write!(f, "issuer database schema mismatch: {reason}"),
            Self::IntegrityCheckFailed(reason) => {
                write!(f, "issuer database integrity check failed: {reason}")
            }
            Self::StoreInstanceMismatch => write!(f, "issuer store instance identity mismatch"),
            Self::IssuerMismatch => write!(f, "issuer database identity mismatch"),
            Self::NetworkMismatch => write!(f, "issuer database Lightning network mismatch"),
            Self::RollbackFloorMissing => {
                write!(f, "independently durable issuer rollback floor is missing")
            }
            Self::RollbackFloorIdentityMismatch => {
                write!(f, "issuer rollback floor belongs to a different store identity")
            }
            Self::RollbackDetected {
                database_generation,
                authority_generation,
            } => write!(
                f,
                "issuer database rollback detected (database generation {database_generation}, authority floor {authority_generation})"
            ),
            Self::RollbackFork => write!(
                f,
                "issuer database and rollback authority conflict at one generation"
            ),
            Self::RollbackAuthorityProtocol(reason) => {
                write!(f, "issuer rollback authority contract violation: {reason}")
            }
            Self::RollbackAuthorityUnavailable(reason) => {
                write!(f, "issuer rollback authority unavailable: {reason}")
            }
            Self::UnanchoredCommit {
                store_generation,
                authority_error,
            } => write!(
                f,
                "issuer-store generation {store_generation} committed but is not externally anchored: {authority_error}"
            ),
            Self::QuoteMissing => write!(f, "quote is missing"),
            Self::QuoteProtocolMismatch => {
                write!(f, "quote or claim belongs to a different acquisition protocol")
            }
            Self::QuoteConflict => write!(f, "quote id conflicts with durable state"),
            Self::QuoteCapacityExceeded => {
                write!(f, "issuer quote capacity is exhausted")
            }
            Self::CreationIdempotencyConflict => {
                write!(
                    f,
                    "quote creation idempotency key conflicts with durable state"
                )
            }
            Self::InvoiceConflict => write!(f, "invoice finalization conflicts with durable state"),
            Self::PaymentHashConflict => {
                write!(f, "payment hash is already assigned to another quote")
            }
            Self::InvalidQuoteState => write!(f, "quote lifecycle transition is invalid"),
            Self::RequiresExpiryReconcile => write!(
                f,
                "post-expiry settlement requires an expired-pending-reconcile transition first"
            ),
            Self::SettlementConflict => {
                write!(f, "settlement observation conflicts with durable state")
            }
            Self::SignedQuoteMismatch => write!(
                f,
                "signed quote snapshot is invalid or conflicts with durable lifecycle state"
            ),
            Self::ClaimIdempotencyConflict => {
                write!(f, "claim idempotency key conflicts with durable state")
            }
            Self::QuoteAlreadyClaimed => write!(f, "quote already has a different claim"),
            Self::QuoteNotSettled => write!(f, "quote is not in a claimable settled state"),
            Self::ClaimDeadlineExpired => write!(f, "new claim is past the durable claim deadline"),
            Self::ClaimProtocolMismatch => {
                write!(f, "claim or issuance envelope does not bind the durable quote")
            }
            Self::BadClaimCryptography => write!(
                f,
                "claim BIP340 or scheme-specific issuance verification failed"
            ),
            Self::StatusRequestBindingMismatch => {
                write!(f, "status request does not bind the durable quote intent")
            }
            Self::StatusRequestStale => write!(f, "status request is outside its freshness window"),
            Self::StatusTimeRollback => write!(f, "status-service wall clock moved backwards"),
            Self::BadStatusRequestSignature => {
                write!(f, "status request BIP340 signature is invalid")
            }
            Self::StatusNonceReplay => write!(f, "status request nonce was already consumed"),
            Self::StatusNonceCapacityExceeded => {
                write!(f, "active quote-status nonce capacity is exhausted")
            }
            Self::ReceiptSerialConflict => write!(
                f,
                "paid-receipt serial is already allocated anywhere under this issuer"
            ),
            Self::DelegationRollback => write!(f, "quote-key delegation epoch rollback rejected"),
            Self::DelegationFork => write!(
                f,
                "different quote-key delegation at an accepted epoch rejected"
            ),
            Self::ServicePolicyRollback => {
                write!(f, "issuer provider-policy epoch rollback rejected")
            }
            Self::ServicePolicyFork => write!(
                f,
                "different issuer provider policy at an accepted epoch rejected"
            ),
            Self::ServicePolicySigningKeyConflict => write!(
                f,
                "issuer provider policy signing key changed without an authorized rotation"
            ),
            Self::BatKeyLineageConflict => {
                write!(f, "Cashu BAT raw key conflicts with immutable lineage")
            }
            Self::BatV2ClassRollback => {
                write!(f, "BAT V2 class key epoch rollback rejected")
            }
            Self::BatV2ClassFork => write!(
                f,
                "different BAT V2 class artifact at an accepted key epoch rejected"
            ),
            Self::BatV2ClassTermsConflict => write!(
                f,
                "BAT V2 common terms changed under an existing class ID"
            ),
            Self::BatV2ClassMemberMismatch => write!(
                f,
                "BAT V2 class member does not match a current exact provider policy"
            ),
            Self::BatV2RawKeyConflict => write!(
                f,
                "BAT raw key is already owned by another V1 or V2 lineage"
            ),
            Self::ArcKeyLineageConflict => {
                write!(f, "experimental ARC raw key conflicts with immutable lineage")
            }
            Self::SettlementKeyLineageConflict => write!(
                f,
                "settlement denomination raw key conflicts with immutable keyset lineage"
            ),
            Self::ProviderRegistrationRollback => {
                write!(f, "provider settlement registration epoch rollback rejected")
            }
            Self::ProviderRegistrationFork => write!(
                f,
                "different provider settlement registration at an accepted epoch rejected"
            ),
            Self::ClearingAuthorizationRollback => {
                write!(f, "provider clearing authorization epoch rollback rejected")
            }
            Self::ClearingAuthorizationFork => write!(
                f,
                "different provider clearing authorization at an accepted epoch rejected"
            ),
            Self::RedeemIdempotencyConflict => {
                write!(f, "redeem idempotency key conflicts with durable state")
            }
            Self::CredentialAlreadySpent => {
                write!(f, "shared credential was already redeemed")
            }
            Self::LedgerBalanceOverflow => {
                write!(f, "provider ledger balance would exceed the protocol bound")
            }
            Self::SettlementDepositIdempotencyConflict => {
                write!(f, "settlement deposit idempotency key conflicts with durable state")
            }
            Self::SettlementNoteAlreadySpent => {
                write!(f, "blind settlement note was already deposited")
            }
            Self::SettlementLedgerSequenceConflict => {
                write!(f, "provider ledger sequence changed before settlement commit")
            }
            Self::PayoutIntentIdempotencyConflict => {
                write!(f, "payout intent idempotency key conflicts with durable state")
            }
            Self::PayoutIntentAlreadyConsumed => {
                write!(f, "payout intent was already consumed")
            }
            Self::PayoutIdempotencyConflict => {
                write!(f, "payout idempotency key conflicts with durable state")
            }
            Self::InsufficientProviderBalance => {
                write!(f, "provider has insufficient available balance")
            }
            Self::PayoutOutboxUnavailable => {
                write!(f, "no claimable payout outbox command is available")
            }
            Self::PayoutStatusConflict => {
                write!(f, "payout status compare-and-swap conflict")
            }
            Self::Protocol(error) => write!(f, "issuer clearing protocol error: {error}"),
            Self::CommitSequenceExhausted => write!(f, "issuer commit sequence is exhausted"),
            Self::CommitOutcomeUnknown(error) => {
                write!(f, "issuer database commit outcome is unknown: {error}")
            }
            Self::Io(error) => write!(f, "issuer database I/O error: {error}"),
            Self::Sqlite(error) => write!(f, "issuer database error: {error}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<pir_service_protocol::ServiceProtocolError> for StoreError {
    fn from(value: pir_service_protocol::ServiceProtocolError) -> Self {
        Self::Protocol(value)
    }
}

pub type StoreResult<T> = Result<T, StoreError>;
