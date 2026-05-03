// SPDX-License-Identifier: CC0-1.0

//! Macros for implementing JSON-RPC methods on a client.
//!
//! Specifically this is `== Hidden ==` methods that are not listed in the
//! API docs of Bitcoin Core `v0.20`.
//!
//! All macros require `Client` to be in scope.
//!
//! See or use the `define_jsonrpc_bitreq_client!` macro to define a `Client`.

/// Implements Bitcoin Core JSON-RPC API method `mockscheduler`.
#[macro_export]
macro_rules! impl_client_v20__mock_scheduler {
    () => {
        impl Client {
            pub fn mock_scheduler(&self, delta_time: u64) -> Result<()> {
                self.call("mockscheduler", &[into_json(delta_time)?])
            }
        }
    };
}
