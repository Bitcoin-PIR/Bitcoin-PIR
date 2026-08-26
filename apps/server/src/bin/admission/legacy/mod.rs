//! Legacy payment/policy admission surface (extracted from `unified_server.rs`).

pub(crate) mod admission_runtime;
pub(crate) mod cashu;
pub(crate) mod strict_admission;

pub(crate) use strict_admission::{load_strict_service_admission_v1, validate_legacy_experimental_arc_cli_v1};
