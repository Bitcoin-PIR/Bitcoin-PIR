// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use bitcoin::amount::ParseAmountError;

use crate::error::write_err;

/// Error when converting a `GetBalances` type into the model type.
#[derive(Debug)]
pub enum GetBalancesError {
    /// Conversion of the `mine` field failed.
    Mine(ParseAmountError),
    /// Conversion of the `watchonly` field failed.
    WatchOnly(ParseAmountError),
}

impl fmt::Display for GetBalancesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Mine(ref e) => write_err!(f, "conversion of the `mine` field failed"; e),
            Self::WatchOnly(ref e) =>
                write_err!(f, "conversion of the `watchonly` field failed"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetBalancesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Mine(ref e) => Some(e),
            Self::WatchOnly(ref e) => Some(e),
        }
    }
}
