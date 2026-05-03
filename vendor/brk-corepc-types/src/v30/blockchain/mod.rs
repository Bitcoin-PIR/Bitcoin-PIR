// SPDX-License-Identifier: CC0-1.0

//! The JSON-RPC API for Bitcoin Core `v30` - blockchain.
//!
//! Types for methods found under the `== Blockchain ==` section of the API docs.

mod into;

use serde::{Deserialize, Serialize};

pub use super::GetMempoolInfoError;

/// Result of JSON-RPC method `getmempoolinfo` with verbose set to `true`.
///
/// > getmempoolinfo
/// >
/// > Returns details on the active state of the TX memory pool.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "serde-deny-unknown-fields", serde(deny_unknown_fields))]
pub struct GetMempoolInfo {
    /// True if the initial load attempt of the persisted mempool finished.
    pub loaded: bool,
    /// Current tx count.
    pub size: i64,
    /// Sum of all virtual transaction sizes as defined in BIP 141.
    ///
    /// Differs from actual serialized size because witness data is discounted.
    pub bytes: i64,
    /// Total memory usage for the mempool.
    pub usage: i64,
    /// Total fees for the mempool in BTC, ignoring modified fees through prioritisetransaction.
    pub total_fee: f64,
    /// Maximum memory usage for the mempool.
    #[serde(rename = "maxmempool")]
    pub max_mempool: i64,
    /// Minimum fee rate in BTC/kB for a transaction to be accepted.
    ///
    /// This is the maximum of `minrelaytxfee` and the minimum mempool fee.
    #[serde(rename = "mempoolminfee")]
    pub mempool_min_fee: f64,
    /// Current minimum relay fee for transactions.
    #[serde(rename = "minrelaytxfee")]
    pub min_relay_tx_fee: f64,
    /// Minimum fee rate increment for mempool limiting or replacement in BTC/kvB.
    #[serde(rename = "incrementalrelayfee")]
    pub incremental_relay_fee: f64,
    /// Current number of transactions that haven't passed initial broadcast yet.
    #[serde(rename = "unbroadcastcount")]
    pub unbroadcast_count: i64,
    /// True if the mempool accepts RBF without replaceability signaling inspection.
    #[serde(rename = "fullrbf")]
    pub full_rbf: bool,
    /// True if the mempool accepts transactions with bare multisig outputs.
    #[serde(rename = "permitbaremultisig")]
    pub permit_bare_multisig: bool,
    /// Maximum number of bytes that can be used by OP_RETURN outputs in the mempool.
    #[serde(rename = "maxdatacarriersize")]
    pub max_data_carrier_size: u64,
}
