// SPDX-License-Identifier: CC0-1.0

use bitcoin::address;

use super::DeriveAddresses;
use crate::model;

impl DeriveAddresses {
    /// Converts version specific type to a version nonspecific, more strongly typed type.
    pub fn into_model(self) -> Result<model::DeriveAddresses, address::ParseError> {
        let mut addresses = Vec::with_capacity(self.0.len());
        for addr_str in self.0 {
            let addr = addr_str.parse()?;
            addresses.push(addr);
        }
        Ok(model::DeriveAddresses { addresses })
    }
}
