use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryErrorV1 {
    InputTooLarge,
    InvalidJson,
    NonCanonicalJson,
    InvalidHex,
    InvalidValue,
    UnsupportedVersion,
    WrongDirectoryKey,
    WrongEventKind,
    InvalidEventId,
    InvalidEventSignature,
    InvalidDirectoryPublicKey,
    InvalidTags,
    DifferentAddressableCoordinate,
    ReplaceableTimestampNotAdvanced,
    InvalidEntryTag,
    InvalidCheckpointTag,
    InvalidShard,
    EntryExpired,
    CheckpointExpired,
    InvalidOperatorAssertion,
    WrongOperatorIdentity,
    InvalidCatalogHints,
    InvalidCatalogRoot,
    CatalogEntrySetMismatch,
    LivePolicyMismatch,
    DirectorySequenceRollback,
    DirectorySequenceFork,
    OperatorEpochRollback,
    OperatorEpochFork,
    ReactivationRequiresNewOperatorEpoch,
    CheckpointEpochRollback,
    CheckpointEpochFork,
    CheckpointSplitView,
    CorruptRollbackState,
}

impl fmt::Display for DirectoryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InputTooLarge => "directory input exceeds its v1 bound",
            Self::InvalidJson => "directory JSON is malformed, duplicated, or unknown",
            Self::NonCanonicalJson => "directory content JSON is not canonical",
            Self::InvalidHex => "directory fixed bytes are not canonical lowercase hex",
            Self::InvalidValue => "directory value is invalid or outside its v1 bound",
            Self::UnsupportedVersion => "directory protocol version is unsupported",
            Self::WrongDirectoryKey => "Nostr event is not signed by the pinned directory key",
            Self::WrongEventKind => "Nostr event kind is not BitcoinPIR NIP-78 v1",
            Self::InvalidEventId => "Nostr event id does not match its canonical NIP-01 preimage",
            Self::InvalidEventSignature => "Nostr event BIP340 signature is invalid",
            Self::InvalidDirectoryPublicKey => {
                "directory public key is not a valid secp256k1 x-only key"
            }
            Self::InvalidTags => "Nostr event tags are malformed or outside their v1 bound",
            Self::DifferentAddressableCoordinate => {
                "Nostr events do not have the same addressable coordinate"
            }
            Self::ReplaceableTimestampNotAdvanced => {
                "Nostr addressable-event timestamp did not advance"
            }
            Self::InvalidEntryTag => "directory entry d tag is missing, duplicated, or mismatched",
            Self::InvalidCheckpointTag => {
                "directory checkpoint d tag is missing, duplicated, or mismatched"
            }
            Self::InvalidShard => "directory coarse shard tag is missing or mismatched",
            Self::EntryExpired => "directory entry is not currently valid",
            Self::CheckpointExpired => "directory checkpoint is not currently valid",
            Self::InvalidOperatorAssertion => {
                "directory operator assertion is malformed or has a bad signature"
            }
            Self::WrongOperatorIdentity => {
                "directory assertion does not match the independently pinned operator"
            }
            Self::InvalidCatalogHints => "directory catalog hints are malformed or unsorted",
            Self::InvalidCatalogRoot => "directory catalog checkpoint root is invalid",
            Self::CatalogEntrySetMismatch => {
                "directory shard entries do not exactly match the signed checkpoint"
            }
            Self::LivePolicyMismatch => {
                "directory entry does not match the strictly verified live policy"
            }
            Self::DirectorySequenceRollback => "directory sequence rollback was rejected",
            Self::DirectorySequenceFork => "directory published a fork at one sequence",
            Self::OperatorEpochRollback => "operator assertion epoch rollback was rejected",
            Self::OperatorEpochFork => "operator assertion fork at one epoch was rejected",
            Self::ReactivationRequiresNewOperatorEpoch => {
                "directory tombstone reactivation requires a newer operator assertion"
            }
            Self::CheckpointEpochRollback => "catalog checkpoint epoch rollback was rejected",
            Self::CheckpointEpochFork => {
                "catalog checkpoint event differs at an already retained epoch"
            }
            Self::CheckpointSplitView => {
                "catalog checkpoint root differs at an already retained epoch"
            }
            Self::CorruptRollbackState => "durable directory rollback state is inconsistent",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DirectoryErrorV1 {}

#[derive(Debug)]
pub enum DirectoryAcceptErrorV1<E> {
    Protocol(DirectoryErrorV1),
    Store(E),
    ConcurrentStateChanged,
}

impl<E: fmt::Display> fmt::Display for DirectoryAcceptErrorV1<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "directory candidate rejected: {error}"),
            Self::Store(error) => write!(formatter, "directory durable state unavailable: {error}"),
            Self::ConcurrentStateChanged => {
                formatter.write_str("directory durable state changed concurrently")
            }
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for DirectoryAcceptErrorV1<E> {}

impl<E> From<DirectoryErrorV1> for DirectoryAcceptErrorV1<E> {
    fn from(value: DirectoryErrorV1) -> Self {
        Self::Protocol(value)
    }
}
