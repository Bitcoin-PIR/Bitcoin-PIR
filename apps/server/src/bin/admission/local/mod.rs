//! Local admission (post-policy model, D2).
//!
//! Free queries are open, governed only by the operator's local configuration
//! file; paid queries are delegated to a single designated issuer's ARC
//! tokens. There is no signed policy document, no epoch, and no digest pin:
//! the file is operator-local, read once at boot, and never leaves the host.
//!
//! This module currently provides the configuration surface and startup
//! wiring; per-connection enforcement admits on the existing request paths
//! and does not change wire behavior.

mod config;

pub(crate) use config::LocalAdmissionConfigV1;

use std::path::Path;

use pir_runtime_core::service_admission::{
    AdmissionCommitErrorV1, AdmissionMethodCommitterV1, AdmissionMethodRouteV1,
};
use pir_service_protocol::BoundAuthAttemptV1;

/// Open, credential-free admission committer (the post-PoW free path):
/// admits the OpenBestEffort route unconditionally. Proof-of-work as an
/// admission mechanism is deleted; throttling, when desired, belongs to the
/// operator-local configuration rather than to a cryptographic challenge.
pub(crate) struct OpenFreeCommitterV1;

impl AdmissionMethodCommitterV1 for OpenFreeCommitterV1 {
    fn verify_and_commit_v1(
        &self,
        route: AdmissionMethodRouteV1,
        _attempt: &BoundAuthAttemptV1<'_>,
        _now_unix_seconds: u64,
    ) -> Result<(), AdmissionCommitErrorV1> {
        match route {
            AdmissionMethodRouteV1::FreeOpenBestEffort => Ok(()),
            _ => Err(AdmissionCommitErrorV1::UnsupportedScheme),
        }
    }
}

#[cfg(test)]
mod open_free_tests {
    use super::OpenFreeCommitterV1;

    #[test]
    fn open_free_object_is_zero_sized() {
        assert_eq!(core::mem::size_of::<OpenFreeCommitterV1>(), 0);
    }
}

/// Resolved local admission settings for this boot.
#[derive(Clone, Debug)]
pub(crate) struct LocalAdmissionV1 {
    config: LocalAdmissionConfigV1,
}

impl LocalAdmissionV1 {
    /// Load an explicit `--local-admission-config FILE`, or start with the
    /// open defaults when the flag is absent.
    pub(crate) fn load(path: Option<&Path>) -> Result<Self, String> {
        let config = LocalAdmissionConfigV1::load(path)?;
        Ok(Self { config })
    }

    pub(crate) fn free_open(&self) -> bool {
        self.config.free_open
    }

    pub(crate) fn arc_issuer_url(&self) -> Option<&str> {
        self.config.arc_issuer_url.as_deref()
    }

    pub(crate) fn startup_log_line(&self) -> String {
        let issuer = match self.arc_issuer_url() {
            Some(url) => format!("arc_issuer_url={url}"),
            None => "arc_issuer_url=unset".to_owned(),
        };
        format!("local admission: free_open={} {issuer}", self.free_open())
    }
}

#[cfg(test)]
mod tests {
    use super::LocalAdmissionV1;

    #[test]
    fn defaults_are_open_without_issuer() {
        let admission = LocalAdmissionV1::load(None).expect("default load");
        assert!(admission.free_open());
        assert_eq!(admission.arc_issuer_url(), None);
        assert_eq!(
            admission.startup_log_line(),
            "local admission: free_open=true arc_issuer_url=unset"
        );
    }
}
