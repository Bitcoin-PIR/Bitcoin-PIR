// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use bitcoin::amount::ParseAmountError;

use crate::error::write_err;

/// Error when converting a `GetTransaction` type into the model type.
#[derive(Debug)]
pub enum GetNetworkInfoError {
    /// Conversion of the `relay_fee` field failed.
    RelayFee(ParseAmountError),
    /// Conversion of the `incremental_fee` field failed.
    IncrementalFee(ParseAmountError),
}

impl fmt::Display for GetNetworkInfoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::RelayFee(ref e) => write_err!(f, "conversion of the `relay_fee` field failed"; e),
            Self::IncrementalFee(ref e) =>
                write_err!(f, "conversion of the `incremental_fee` field failed"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetNetworkInfoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::RelayFee(ref e) => Some(e),
            Self::IncrementalFee(ref e) => Some(e),
        }
    }
}
