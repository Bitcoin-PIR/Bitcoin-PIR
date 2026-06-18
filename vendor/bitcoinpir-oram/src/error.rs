use chacha20poly1305::aead;

/// Crate-local result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the ORAM prototype.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The requested ORAM configuration is invalid.
    #[error("invalid ORAM parameters: {0}")]
    InvalidParams(String),

    /// The caller supplied malformed data.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The stash exceeded the configured capacity.
    #[error("stash overflow: len={len}, capacity={capacity}")]
    StashOverflow {
        /// Current stash length.
        len: usize,
        /// Configured stash capacity.
        capacity: usize,
    },

    /// A logical block was not present in the ORAM state.
    #[error("logical block {0} not found")]
    BlockNotFound(u64),

    /// I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// State serialization failed.
    #[error(transparent)]
    Bincode(#[from] bincode::Error),

    /// Hex decoding failed.
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    /// Page encryption or authentication failed.
    #[error("page authentication failed")]
    Aead,
}

impl From<aead::Error> for Error {
    fn from(_: aead::Error) -> Self {
        Self::Aead
    }
}
