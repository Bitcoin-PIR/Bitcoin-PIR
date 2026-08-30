//! Kept BitcoinPIR service identifiers and operation-start wire types.
//!
//! This crate owns provider/scope identifiers and the method-neutral
//! operation-start messages used by the PIR query path. It does not
//! implement payment, issuance, or admission.

mod codec;
mod error;
mod operation;
mod scope;

pub use error::ServiceProtocolError;
pub use operation::{
    HarmonyHintSideV1, HintTransport, OperationStartV1, AUTH_FRAME_CLASS_V1, MAX_AUTH_PROOF_LEN,
    OPERATION_START_DIGEST_DOMAIN,
};
pub use scope::{
    derive_provider_id, AuthScheme, BackendId, DatasetBindingV1, ProviderId, ScopeId,
    ServiceScopeV1, WorkloadId, PROVIDER_ID_DOMAIN, SCOPE_ID_DOMAIN,
};

/// Current version of the kept V1 structures in this crate.
pub const SERVICE_PROTOCOL_VERSION: u8 = 1;

/// Length of provider, scope, and policy digests.
pub const HASH_LEN: usize = 32;
