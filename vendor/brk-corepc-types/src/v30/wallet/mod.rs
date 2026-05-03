// SPDX-License-Identifier: CC0-1.0

//! The JSON-RPC API for Bitcoin Core `v30` - wallet.
//!
//! Types for methods found under the `== Wallet ==` section of the API docs.

mod error;
mod into;

use serde::{Deserialize, Serialize};

pub use self::error::{GetWalletInfoError, LastProcessedBlockError};

/// Result of the JSON-RPC method `getwalletinfo`.
///
/// > getwalletinfo
/// >
/// > Returns an object containing various wallet state info.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "serde-deny-unknown-fields", serde(deny_unknown_fields))]
pub struct GetWalletInfo {
    /// the wallet name
    #[serde(rename = "walletname")]
    pub wallet_name: String,
    /// the wallet version
    #[serde(rename = "walletversion")]
    pub wallet_version: i64,
    /// the database format (bdb or sqlite)
    pub format: String,
    /// the total number of transactions in the wallet
    #[serde(rename = "txcount")]
    pub tx_count: i64,
    /// how many new keys are pre-generated (only counts external keys)
    #[serde(rename = "keypoolsize")]
    pub keypool_size: i64,
    /// how many new keys are pre-generated for internal use (used for change outputs, only appears if the wallet is using this feature, otherwise external keys are used)
    #[serde(rename = "keypoolsize_hd_internal")]
    pub keypool_size_hd_internal: Option<i64>,
    /// the UNIX epoch time until which the wallet is unlocked for transfers, or 0 if the wallet is locked (only present for passphrase-encrypted wallets)
    pub unlocked_until: Option<u32>,
    /// the transaction fee configuration, set in BTC/kvB
    #[serde(rename = "paytxfee")]
    pub pay_tx_fee: f64,
    /// false if privatekeys are disabled for this wallet (enforced watch-only wallet)
    pub private_keys_enabled: bool,
    /// whether this wallet tracks clean/dirty coins in terms of reuse
    pub avoid_reuse: bool,
    /// current scanning details, or false if no scan is in progress
    pub scanning: GetWalletInfoScanning,
    /// whether this wallet uses descriptors for scriptPubKey management
    pub descriptors: bool,
    /// whether this wallet is configured to use an external signer such as a hardware wallet
    pub external_signer: bool,
    /// Whether this wallet intentionally does not contain any keys, scripts, or descriptors
    pub blank: bool,
    /// The start time for blocks scanning. It could be modified by (re)importing any descriptor with an earlier timestamp.
    pub birthtime: Option<u32>,
    /// The flags currently set on the wallet.
    pub flags: Vec<String>,
    /// hash and height of the block this information was generated on
    #[serde(rename = "lastprocessedblock")]
    pub last_processed_block: Option<LastProcessedBlock>,
}

/// Current scanning details. Part of `getwalletinfo`.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum GetWalletInfoScanning {
    /// Scanning details.
    Details { duration: u64, progress: f64 },
    /// Not scanning (false).
    NotScanning(bool),
}

/// Last processed block item. Part of of `getwalletinfo`.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "serde-deny-unknown-fields", serde(deny_unknown_fields))]
pub struct LastProcessedBlock {
    /// Hash of the block this information was generated on.
    pub hash: String,
    /// Height of the block this information was generated on.
    pub height: i64,
}

/// Result of the JSON-RPC method `listwalletdir`.
///
/// > listwalletdir
/// >
/// > Returns a list of wallets in the wallet directory.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "serde-deny-unknown-fields", serde(deny_unknown_fields))]
pub struct ListWalletDir {
    /// The list of wallets in the wallet directory.
    pub wallets: Vec<ListWalletDirWallet>,
}

/// Wallet entry. Part of `listwalletdir`.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "serde-deny-unknown-fields", serde(deny_unknown_fields))]
pub struct ListWalletDirWallet {
    /// The wallet name.
    pub name: String,
    /// Warning messages, if any, related to loading the wallet.
    pub warnings: Option<Vec<String>>,
}
