//! Error types for PIR SDK.

use std::io;
use thiserror::Error;

/// Result type alias for PIR operations.
pub type PirResult<T> = Result<T, PirError>;

/// Unified error type for all PIR operations.
#[derive(Error, Debug)]
pub enum PirError {
    // ─── Connection errors ──────────────────────────────────────────────────

    /// Failed to connect to a PIR server.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Connection was closed unexpectedly.
    #[error("connection closed: {0}")]
    ConnectionClosed(String),

    /// Timeout waiting for server response.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Not connected to server.
    #[error("not connected")]
    NotConnected,

    // ─── Protocol errors ────────────────────────────────────────────────────

    /// Invalid protocol message received.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Server returned an error response.
    #[error("server error: {0}")]
    ServerError(String),

    /// Unexpected response variant.
    #[error("unexpected response: expected {expected}, got {actual}")]
    UnexpectedResponse {
        expected: &'static str,
        actual: String,
    },

    // ─── Database errors ────────────────────────────────────────────────────

    /// Database not found.
    #[error("database not found: db_id={0}")]
    DatabaseNotFound(u8),

    /// Invalid database catalog.
    #[error("invalid catalog: {0}")]
    InvalidCatalog(String),

    /// No valid sync path found.
    #[error("no sync path: {0}")]
    NoSyncPath(String),

    // ─── Query errors ───────────────────────────────────────────────────────

    /// Invalid script hash.
    #[error("invalid script hash: {0}")]
    InvalidScriptHash(String),

    /// Query failed.
    #[error("query failed: {0}")]
    QueryFailed(String),

    /// Merkle verification failed.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    // ─── State errors ───────────────────────────────────────────────────────

    /// Client is in invalid state for this operation.
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Backend-specific state error (e.g., HarmonyPIR hints not computed).
    #[error("backend state error: {0}")]
    BackendState(String),

    // ─── Configuration errors ───────────────────────────────────────────────

    /// Invalid configuration.
    #[error("configuration error: {0}")]
    Config(String),

    /// Missing required server URL.
    #[error("missing server: {0}")]
    MissingServer(String),

    // ─── I/O errors ─────────────────────────────────────────────────────────

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    // ─── Codec errors ───────────────────────────────────────────────────────

    /// Failed to decode data.
    #[error("decode error: {0}")]
    Decode(String),

    /// Failed to encode data.
    #[error("encode error: {0}")]
    Encode(String),

    // ─── Delta merge errors ─────────────────────────────────────────────────

    /// Failed to merge delta into snapshot.
    #[error("merge error: {0}")]
    MergeError(String),

    // ─── Internal errors ────────────────────────────────────────────────────

    /// Internal error (bug).
    #[error("internal error: {0}")]
    Internal(String),
}

impl PirError {
    /// Returns true if this is a connection-related error.
    pub fn is_connection_error(&self) -> bool {
        matches!(
            self,
            PirError::ConnectionFailed(_)
                | PirError::ConnectionClosed(_)
                | PirError::Timeout(_)
                | PirError::NotConnected
        )
    }

    /// Returns true if this is a protocol-related error.
    pub fn is_protocol_error(&self) -> bool {
        matches!(
            self,
            PirError::Protocol(_) | PirError::ServerError(_) | PirError::UnexpectedResponse { .. }
        )
    }

    /// Returns true if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            PirError::Timeout(_) | PirError::ConnectionClosed(_)
        )
    }
}

// ─── Conversion helpers ─────────────────────────────────────────────────────

impl From<&str> for PirError {
    fn from(s: &str) -> Self {
        PirError::Internal(s.to_string())
    }
}

impl From<String> for PirError {
    fn from(s: String) -> Self {
        PirError::Internal(s)
    }
}
