//! Admission decoupling root.
//!
//! PIR serving lives in `unified_server.rs`. The legacy payment/policy
//! admission layer is deleted; what remains is the operator-local
//! configuration (`local`) and the single-issuer ARC facade (`arc`).

pub(crate) mod arc;
pub(crate) mod local;
