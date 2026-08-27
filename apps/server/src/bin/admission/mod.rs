//! Admission decoupling root (D1).
//!
//! PIR serving lives in `unified_server.rs`; all legacy payment/policy
//! handling is being extracted under `admission::legacy` so it can be
//! removed independently (series D, then R4 deletion).

pub(crate) mod arc;
pub mod legacy;
pub(crate) mod local;
