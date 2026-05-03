// SPDX-License-Identifier: CC0-1.0

use bitcoin::{Address, ScriptBuf};

use super::{CreateMultisig, CreateMultisigError};
use crate::model;

impl CreateMultisig {
    /// Converts version specific type to a version nonspecific, more strongly typed type.
    pub fn into_model(self) -> Result<model::CreateMultisig, CreateMultisigError> {
        use CreateMultisigError as E;

        let address = self.address.parse::<Address<_>>().map_err(E::Address)?;
        let redeem_script = ScriptBuf::from_hex(&self.redeem_script).map_err(E::RedeemScript)?;

        Ok(model::CreateMultisig {
            address,
            redeem_script,
            descriptor: Some(self.descriptor),
            warnings: None,
        })
    }
}
