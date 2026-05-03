// SPDX-License-Identifier: CC0-1.0

//! The JSON-RPC API for Bitcoin Core `v0.21` - generating.
//!
//! Types for methods found under the `== Generating ==` section of the API docs.

use bitcoin::consensus::encode;
use bitcoin::BlockHash;

use super::{GenerateBlock, GenerateBlockError};
use crate::model;

impl GenerateBlock {
    /// Converts version specific type to a version nonspecific, more strongly typed type.
    pub fn into_model(self) -> Result<model::GenerateBlock, GenerateBlockError> {
        use GenerateBlockError as E;

        let hash = self.hash.parse::<BlockHash>().map_err(E::Hash)?;
        let hex =
            self.hex.as_ref().map(|h| encode::deserialize_hex(h)).transpose().map_err(E::Hex)?;
        Ok(model::GenerateBlock { hash, hex })
    }
}
