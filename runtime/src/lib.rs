//! Reference PIR server runtime: exposes the shared server primitives
//! (hosted in `pir-runtime-core`) alongside the binary-only helpers that
//! wire up the `unified_server` / CLI client binaries in `src/bin/`.
//!
//! The library surface exists so the `src/bin/*` entry points can import
//! through `use runtime::{protocol, table, handler, eval, ...};`. Its
//! role is deliberately thin: publishable server primitives are re-exported
//! from `pir-runtime-core`, while deployment-only glue stays here.

pub use pir_runtime_core::{db_proof, eval, handler, protocol, table};

pub mod config;
pub mod harmony_state;
pub mod hint_pool;
pub mod onionpir;
