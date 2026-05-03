//! Error types for HarmonyPIR.
//!
//! All fallible operations in the library return [`HarmonyPirError`].

use std::fmt;

/// Errors that can occur during HarmonyPIR operations.
#[derive(Debug)]
pub enum HarmonyPirError {
    /// The provided parameters are invalid.
    InvalidParams(&'static str),

    /// A database or cell index is out of range.
    InvalidIndex {
        index: usize,
        max: usize,
    },

    /// The client has exhausted all M/2 queries and must re-run the offline phase.
    NoMoreQueries,

    /// FF1 requires a domain size of at least 10^6 (NIST recommendation).
    Ff1DomainTooSmall {
        domain: usize,
        minimum: usize,
    },

    /// A Locate or Access chain-walk exceeded the maximum expected length,
    /// indicating a bug or data corruption.
    ChainWalkExceeded {
        max_steps: usize,
    },
}

impl fmt::Display for HarmonyPirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParams(msg) => write!(f, "invalid parameters: {msg}"),
            Self::InvalidIndex { index, max } => {
                write!(f, "index {index} out of range (max {max})")
            }
            Self::NoMoreQueries => {
                write!(f, "no more queries available; re-run the offline phase")
            }
            Self::Ff1DomainTooSmall { domain, minimum } => {
                write!(f, "FF1 domain {domain} too small (minimum {minimum})")
            }
            Self::ChainWalkExceeded { max_steps } => {
                write!(f, "chain-walk exceeded {max_steps} steps")
            }
        }
    }
}

impl std::error::Error for HarmonyPirError {}

pub type Result<T> = std::result::Result<T, HarmonyPirError>;
