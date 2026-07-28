//! Fail-closed remote client for the authenticated rollback-authority
//! protocol.
//!
//! The production constructor requires ordinary WebPKI authentication *and*
//! one or two out-of-band leaf-SPKI SHA-256 pins. It has no plaintext,
//! pin-only, TOFU, redirect, proxy, cookie, or unpinned fallback.
//!
//! Every Read is signed through the protocol crate's one-shot fresh-read
//! typestate. Every CAS network attempt creates a fresh call nonce while the
//! caller-owned [`DurableAuthorityCasOperationV1`] keeps the operation ID and
//! exact expected/desired records stable. An unknown CAS is recovered by a
//! fresh Read followed by a freshly signed replay of that same durable CAS;
//! old Read request/response transcripts are never reused as freshness proof.

#![forbid(unsafe_code)]

mod deployment;

use core::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use pir_rollback_authority_protocol::{
    verify_authority_read_response_v1, verify_authority_response_v1, AuthorityBindingV1,
    AuthorityCallV1, AuthorityClientSignerV1, OpaqueAuthorityRecordV1,
    VerifiedAuthorityCasOutcomeV1, VerifiedAuthorityResponseBodyRefV1,
    AUTHORITY_OPERATION_ID_BYTES_V1, MAX_SIGNED_AUTHORITY_RESPONSE_BYTES_V1,
    SIGNED_AUTHORITY_CAS_REQUEST_BYTES_V1, SIGNED_AUTHORITY_INITIALIZE_REQUEST_BYTES_V1,
    SIGNED_AUTHORITY_READ_REQUEST_BYTES_V1,
};
use pir_strict_https::{HttpsPostErrorV1, StrictHttpsClientV1};
use zeroize::Zeroizing;

pub use deployment::{
    load_remote_rollback_authority_deployment_descriptor_v1,
    load_remote_rollback_authority_deployment_for_business_domain_v1,
    validate_independent_remote_rollback_authority_deployments_v1,
    ConfiguredRemoteRollbackAuthorityV1, RemoteAuthorityDeploymentConfigErrorV1,
    RemoteRollbackAuthorityDeploymentDescriptorV1, MAX_INDEPENDENT_DEPLOYMENTS_V1,
    MIN_INDEPENDENT_DEPLOYMENTS_V1,
};

pub const ROLLBACK_AUTHORITY_CALL_ROUTE_V1: &str = "/v1/rollback-authority/calls";
pub const ROLLBACK_AUTHORITY_REQUEST_CONTENT_TYPE_V1: &str =
    "application/vnd.bitcoinpir.rollback-authority-request-v1";
pub const ROLLBACK_AUTHORITY_RESPONSE_CONTENT_TYPE_V1: &str =
    "application/vnd.bitcoinpir.rollback-authority-response-v1";
pub const ROLLBACK_AUTHORITY_ERROR_CONTENT_TYPE_V1: &str = "application/problem+json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteAuthorityClientConfigErrorV1 {
    InvalidEndpoint,
    InvalidAttemptTimeout,
    InvalidPinnedHttpsConfiguration,
}

impl fmt::Display for RemoteAuthorityClientConfigErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEndpoint => "rollback-authority HTTPS endpoint is invalid",
            Self::InvalidAttemptTimeout => {
                "rollback-authority attempt timeout must be in 1ns..=60s"
            }
            Self::InvalidPinnedHttpsConfiguration => {
                "rollback-authority pinned HTTPS configuration is invalid"
            }
        })
    }
}

impl std::error::Error for RemoteAuthorityClientConfigErrorV1 {}

/// Network-attempt classification safe for retry policy and safe to log.
///
/// `DefinitelyNotSent` means no HTTP application request could have reached
/// the authority. `OutcomeUnknown` means it may have reached the authority;
/// the caller must retain the exact durable CAS operation and use the
/// reconciliation protocol rather than inventing a new operation ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteAuthorityCallErrorV1 {
    DefinitelyNotSent,
    OutcomeUnknown,
}

impl fmt::Display for RemoteAuthorityCallErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DefinitelyNotSent => "rollback-authority request was definitely not sent",
            Self::OutcomeUnknown => "rollback-authority request outcome is unknown",
        })
    }
}

impl std::error::Error for RemoteAuthorityCallErrorV1 {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteAuthorityOperationErrorV1 {
    InvalidOperationId,
    InvalidRevisionTransition,
    RandomnessUnavailable,
}

impl fmt::Display for RemoteAuthorityOperationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOperationId => "rollback-authority operation ID is invalid",
            Self::InvalidRevisionTransition => {
                "rollback-authority CAS revision transition is invalid"
            }
            Self::RandomnessUnavailable => "rollback-authority operation randomness is unavailable",
        })
    }
}

impl std::error::Error for RemoteAuthorityOperationErrorV1 {}

/// The exact durable state required to retry or reconcile one CAS.
///
/// Before the first network attempt, persist the operation ID together with
/// the canonical encodings of `expected` and `desired`. Restore all three via
/// [`Self::from_durable_parts`]. Never generate a replacement operation ID
/// after an outcome-unknown failure.
pub struct DurableAuthorityCasOperationV1 {
    operation_id: Zeroizing<[u8; AUTHORITY_OPERATION_ID_BYTES_V1]>,
    expected: Option<OpaqueAuthorityRecordV1>,
    desired: OpaqueAuthorityRecordV1,
}

impl fmt::Debug for DurableAuthorityCasOperationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableAuthorityCasOperationV1")
            .field("operation_id", &"[REDACTED]")
            .field("records", &"[REDACTED]")
            .finish()
    }
}

impl DurableAuthorityCasOperationV1 {
    pub fn generate(
        expected: Option<OpaqueAuthorityRecordV1>,
        desired: OpaqueAuthorityRecordV1,
    ) -> Result<Self, RemoteAuthorityOperationErrorV1> {
        let call = AuthorityCallV1::generate()
            .map_err(|_| RemoteAuthorityOperationErrorV1::RandomnessUnavailable)?;
        Self::from_durable_parts(*call.operation_id(), expected, desired)
    }

    pub fn from_durable_parts(
        operation_id: [u8; AUTHORITY_OPERATION_ID_BYTES_V1],
        expected: Option<OpaqueAuthorityRecordV1>,
        desired: OpaqueAuthorityRecordV1,
    ) -> Result<Self, RemoteAuthorityOperationErrorV1> {
        if operation_id.iter().all(|byte| *byte == 0) {
            return Err(RemoteAuthorityOperationErrorV1::InvalidOperationId);
        }
        if let Some(expected) = expected.as_ref() {
            let next_revision = expected
                .revision()
                .checked_add(1)
                .ok_or(RemoteAuthorityOperationErrorV1::InvalidRevisionTransition)?;
            if desired.revision() != next_revision {
                return Err(RemoteAuthorityOperationErrorV1::InvalidRevisionTransition);
            }
        }
        Ok(Self {
            operation_id: Zeroizing::new(operation_id),
            expected,
            desired,
        })
    }

    pub fn operation_id(&self) -> &[u8; AUTHORITY_OPERATION_ID_BYTES_V1] {
        &self.operation_id
    }

    pub fn expected(&self) -> Option<&OpaqueAuthorityRecordV1> {
        self.expected.as_ref()
    }

    pub fn desired(&self) -> &OpaqueAuthorityRecordV1 {
        &self.desired
    }
}

pub struct RemoteAuthorityReadOutcomeV1 {
    current: Option<OpaqueAuthorityRecordV1>,
}

impl fmt::Debug for RemoteAuthorityReadOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteAuthorityReadOutcomeV1")
            .field("current", &self.current.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl RemoteAuthorityReadOutcomeV1 {
    pub fn current(&self) -> Option<&OpaqueAuthorityRecordV1> {
        self.current.as_ref()
    }

    pub fn into_current(self) -> Option<OpaqueAuthorityRecordV1> {
        self.current
    }
}

pub enum RemoteAuthorityCasOutcomeV1 {
    Empty,
    Applied(OpaqueAuthorityRecordV1),
    AlreadyApplied(OpaqueAuthorityRecordV1),
    ConflictCurrent(OpaqueAuthorityRecordV1),
}

impl fmt::Debug for RemoteAuthorityCasOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "Empty",
            Self::Applied(_) => "Applied([REDACTED])",
            Self::AlreadyApplied(_) => "AlreadyApplied([REDACTED])",
            Self::ConflictCurrent(_) => "ConflictCurrent([REDACTED])",
        })
    }
}

/// Evidence returned by explicit outcome-unknown recovery.
///
/// The Read is a fresh online observation only. The following CAS replay with
/// the stable operation ID is what reconciles the durable authority operation
/// log and determines the operation's authenticated terminal result.
pub struct RemoteAuthorityCasRecoveryV1 {
    observed_before_reconcile: RemoteAuthorityReadOutcomeV1,
    reconciled: RemoteAuthorityCasOutcomeV1,
}

impl fmt::Debug for RemoteAuthorityCasRecoveryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteAuthorityCasRecoveryV1")
            .field("observed_before_reconcile", &"[REDACTED]")
            .field("reconciled", &self.reconciled)
            .finish()
    }
}

impl RemoteAuthorityCasRecoveryV1 {
    pub fn observed_before_reconcile(&self) -> &RemoteAuthorityReadOutcomeV1 {
        &self.observed_before_reconcile
    }

    pub fn reconciled(&self) -> &RemoteAuthorityCasOutcomeV1 {
        &self.reconciled
    }

    pub fn into_parts(self) -> (RemoteAuthorityReadOutcomeV1, RemoteAuthorityCasOutcomeV1) {
        (self.observed_before_reconcile, self.reconciled)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityTransportErrorV1 {
    DefinitelyNotSent,
    OutcomeUnknown,
}

trait AuthorityHttpsTransportV1: Send + Sync {
    fn post(
        &self,
        canonical_request: &[u8],
        absolute_deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, AuthorityTransportErrorV1>;
}

struct StrictPinnedAuthorityHttpsTransportV1 {
    endpoint: String,
    https: StrictHttpsClientV1,
}

impl fmt::Debug for StrictPinnedAuthorityHttpsTransportV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StrictPinnedAuthorityHttpsTransportV1")
            .field("endpoint", &"[REDACTED]")
            .field("https", &"[REDACTED]")
            .finish()
    }
}

impl AuthorityHttpsTransportV1 for StrictPinnedAuthorityHttpsTransportV1 {
    fn post(
        &self,
        canonical_request: &[u8],
        absolute_deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, AuthorityTransportErrorV1> {
        self.https
            .post_with_error_content_type_until(
                &self.endpoint,
                ROLLBACK_AUTHORITY_CALL_ROUTE_V1,
                ROLLBACK_AUTHORITY_REQUEST_CONTENT_TYPE_V1,
                ROLLBACK_AUTHORITY_RESPONSE_CONTENT_TYPE_V1,
                ROLLBACK_AUTHORITY_ERROR_CONTENT_TYPE_V1,
                canonical_request,
                MAX_SIGNED_AUTHORITY_RESPONSE_BYTES_V1,
                absolute_deadline,
            )
            .map(Zeroizing::new)
            .map_err(map_https_error_v1)
    }
}

fn map_https_error_v1(error: HttpsPostErrorV1) -> AuthorityTransportErrorV1 {
    match error {
        HttpsPostErrorV1::DefinitelyNotSent => AuthorityTransportErrorV1::DefinitelyNotSent,
        HttpsPostErrorV1::OutcomeUnknown
        | HttpsPostErrorV1::InvalidResponse
        | HttpsPostErrorV1::HttpStatus { .. } => AuthorityTransportErrorV1::OutcomeUnknown,
    }
}

pub struct RemoteRollbackAuthorityClientV1 {
    transport: Arc<dyn AuthorityHttpsTransportV1>,
    signer: AuthorityClientSignerV1,
    authority_verifying_key: VerifyingKey,
    attempt_timeout: Duration,
}

impl fmt::Debug for RemoteRollbackAuthorityClientV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteRollbackAuthorityClientV1")
            .field("transport", &"[REDACTED]")
            .field("signer", &"[REDACTED]")
            .field("authority_verifying_key", &"[REDACTED]")
            .field("attempt_timeout", &self.attempt_timeout)
            .finish()
    }
}

impl RemoteRollbackAuthorityClientV1 {
    /// Constructs the production transport. Pins are mandatory; the strict
    /// HTTPS constructor rejects empty, duplicate, or more than two pins.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: String,
        connect_timeout: Duration,
        io_timeout: Duration,
        attempt_timeout: Duration,
        leaf_spki_sha256_pins: &[[u8; 32]],
        signer: AuthorityClientSignerV1,
        authority_verifying_key: VerifyingKey,
    ) -> Result<Self, RemoteAuthorityClientConfigErrorV1> {
        StrictHttpsClientV1::validate_base_endpoint(&endpoint)
            .map_err(|_| RemoteAuthorityClientConfigErrorV1::InvalidEndpoint)?;
        validate_attempt_timeout_v1(attempt_timeout)?;
        let https = StrictHttpsClientV1::new_with_leaf_spki_sha256_pins(
            connect_timeout,
            io_timeout,
            leaf_spki_sha256_pins,
        )
        .map_err(|_| RemoteAuthorityClientConfigErrorV1::InvalidPinnedHttpsConfiguration)?;
        Ok(Self {
            transport: Arc::new(StrictPinnedAuthorityHttpsTransportV1 { endpoint, https }),
            signer,
            authority_verifying_key,
            attempt_timeout,
        })
    }

    /// Test-only constructor used by the real-process loopback TLS harness.
    /// The private root is additive: hostname, validity, signature, chain, and
    /// mandatory leaf-SPKI validation remain enabled. Normal production
    /// builds do not contain this constructor.
    #[cfg(feature = "test-only-webpki-root")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_test_only_webpki_root_pem(
        endpoint: String,
        connect_timeout: Duration,
        io_timeout: Duration,
        attempt_timeout: Duration,
        leaf_spki_sha256_pins: &[[u8; 32]],
        test_only_root_pem: &[u8],
        signer: AuthorityClientSignerV1,
        authority_verifying_key: VerifyingKey,
    ) -> Result<Self, RemoteAuthorityClientConfigErrorV1> {
        StrictHttpsClientV1::validate_base_endpoint(&endpoint)
            .map_err(|_| RemoteAuthorityClientConfigErrorV1::InvalidEndpoint)?;
        validate_attempt_timeout_v1(attempt_timeout)?;
        let https =
            StrictHttpsClientV1::new_with_leaf_spki_sha256_pins_and_test_only_webpki_root_pem(
                connect_timeout,
                io_timeout,
                leaf_spki_sha256_pins,
                test_only_root_pem,
            )
            .map_err(|_| RemoteAuthorityClientConfigErrorV1::InvalidPinnedHttpsConfiguration)?;
        Ok(Self {
            transport: Arc::new(StrictPinnedAuthorityHttpsTransportV1 { endpoint, https }),
            signer,
            authority_verifying_key,
            attempt_timeout,
        })
    }

    /// Returns the redacted authority/namespace/client-key binding so an
    /// application can fail closed on codec/client configuration mismatch
    /// before issuing an online request.
    pub fn binding(&self) -> &AuthorityBindingV1 {
        self.signer.binding()
    }

    /// Performs one freshly signed online Read. This function does not retry.
    pub fn read_until(
        &self,
        absolute_deadline: Instant,
    ) -> Result<RemoteAuthorityReadOutcomeV1, RemoteAuthorityCallErrorV1> {
        ensure_before_deadline_v1(absolute_deadline)?;
        let attempt = self
            .signer
            .sign_fresh_read()
            .map_err(|_| RemoteAuthorityCallErrorV1::DefinitelyNotSent)?;
        let response = self.send_one_attempt_v1(attempt.as_bytes(), absolute_deadline)?;
        let verified = verify_authority_read_response_v1(
            response.as_slice(),
            attempt,
            &self.authority_verifying_key,
        )
        .map_err(|_| RemoteAuthorityCallErrorV1::OutcomeUnknown)?;
        match verified.body() {
            VerifiedAuthorityResponseBodyRefV1::Read { current } => {
                Ok(RemoteAuthorityReadOutcomeV1 {
                    current: current.map(OpaqueAuthorityRecordV1::duplicate_for_protocol),
                })
            }
            VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(_) => {
                Err(RemoteAuthorityCallErrorV1::OutcomeUnknown)
            }
        }
    }

    /// Performs exactly one freshly signed CAS attempt for a durable
    /// operation. The operation ID and records remain stable while the call
    /// nonce and exact request digest are fresh on every invocation.
    pub fn compare_and_swap_until(
        &self,
        operation: &DurableAuthorityCasOperationV1,
        absolute_deadline: Instant,
    ) -> Result<RemoteAuthorityCasOutcomeV1, RemoteAuthorityCallErrorV1> {
        ensure_before_deadline_v1(absolute_deadline)?;
        let call = AuthorityCallV1::for_operation(*operation.operation_id())
            .map_err(|_| RemoteAuthorityCallErrorV1::DefinitelyNotSent)?;
        let request = self
            .signer
            .sign_compare_and_swap(&call, operation.expected(), operation.desired())
            .map_err(|_| RemoteAuthorityCallErrorV1::DefinitelyNotSent)?;
        let response = self.send_one_attempt_v1(request.as_bytes(), absolute_deadline)?;
        let verified = verify_authority_response_v1(
            response.as_slice(),
            &request,
            &self.authority_verifying_key,
        )
        .map_err(|_| RemoteAuthorityCallErrorV1::OutcomeUnknown)?;
        match verified.body() {
            VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(outcome) => {
                Ok(duplicate_cas_outcome_v1(outcome))
            }
            VerifiedAuthorityResponseBodyRefV1::Read { .. } => {
                Err(RemoteAuthorityCallErrorV1::OutcomeUnknown)
            }
        }
    }

    /// Reconciles a prior outcome-unknown CAS under one absolute deadline.
    ///
    /// This always performs a new one-shot Read and then a fresh CAS request
    /// with the original operation ID and exact expected/desired records. It
    /// never replays an old Read transcript or old signed CAS bytes.
    pub fn reconcile_unknown_compare_and_swap_until(
        &self,
        operation: &DurableAuthorityCasOperationV1,
        absolute_deadline: Instant,
    ) -> Result<RemoteAuthorityCasRecoveryV1, RemoteAuthorityCallErrorV1> {
        let observed_before_reconcile = self.read_until(absolute_deadline)?;
        let reconciled = self.compare_and_swap_until(operation, absolute_deadline)?;
        Ok(RemoteAuthorityCasRecoveryV1 {
            observed_before_reconcile,
            reconciled,
        })
    }

    fn send_one_attempt_v1(
        &self,
        canonical_request: &[u8],
        absolute_deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, RemoteAuthorityCallErrorV1> {
        if !valid_request_length_v1(canonical_request.len()) {
            return Err(RemoteAuthorityCallErrorV1::DefinitelyNotSent);
        }
        let attempt_deadline = attempt_deadline_v1(absolute_deadline, self.attempt_timeout)?;
        let response = self
            .transport
            .post(canonical_request, attempt_deadline)
            .map_err(|error| match error {
                AuthorityTransportErrorV1::DefinitelyNotSent => {
                    RemoteAuthorityCallErrorV1::DefinitelyNotSent
                }
                AuthorityTransportErrorV1::OutcomeUnknown => {
                    RemoteAuthorityCallErrorV1::OutcomeUnknown
                }
            })?;
        // The production transport enforces this deadline itself. Rechecking
        // here keeps injected/test transports and scheduler delays from
        // turning a response received after the contract into success.
        if Instant::now() >= attempt_deadline
            || response.is_empty()
            || response.len() > MAX_SIGNED_AUTHORITY_RESPONSE_BYTES_V1
        {
            return Err(RemoteAuthorityCallErrorV1::OutcomeUnknown);
        }
        Ok(response)
    }

    #[cfg(test)]
    fn with_test_transport(
        transport: Arc<dyn AuthorityHttpsTransportV1>,
        signer: AuthorityClientSignerV1,
        authority_verifying_key: VerifyingKey,
        attempt_timeout: Duration,
    ) -> Result<Self, RemoteAuthorityClientConfigErrorV1> {
        validate_attempt_timeout_v1(attempt_timeout)?;
        Ok(Self {
            transport,
            signer,
            authority_verifying_key,
            attempt_timeout,
        })
    }
}

fn duplicate_cas_outcome_v1(
    outcome: &VerifiedAuthorityCasOutcomeV1,
) -> RemoteAuthorityCasOutcomeV1 {
    match outcome {
        VerifiedAuthorityCasOutcomeV1::Empty => RemoteAuthorityCasOutcomeV1::Empty,
        VerifiedAuthorityCasOutcomeV1::Applied(record) => {
            RemoteAuthorityCasOutcomeV1::Applied(record.duplicate_for_protocol())
        }
        VerifiedAuthorityCasOutcomeV1::AlreadyApplied(record) => {
            RemoteAuthorityCasOutcomeV1::AlreadyApplied(record.duplicate_for_protocol())
        }
        VerifiedAuthorityCasOutcomeV1::ConflictCurrent(record) => {
            RemoteAuthorityCasOutcomeV1::ConflictCurrent(record.duplicate_for_protocol())
        }
    }
}

fn valid_request_length_v1(length: usize) -> bool {
    length == SIGNED_AUTHORITY_READ_REQUEST_BYTES_V1
        || length == SIGNED_AUTHORITY_INITIALIZE_REQUEST_BYTES_V1
        || length == SIGNED_AUTHORITY_CAS_REQUEST_BYTES_V1
}

fn validate_attempt_timeout_v1(
    attempt_timeout: Duration,
) -> Result<(), RemoteAuthorityClientConfigErrorV1> {
    if attempt_timeout.is_zero() || attempt_timeout > Duration::from_secs(60) {
        return Err(RemoteAuthorityClientConfigErrorV1::InvalidAttemptTimeout);
    }
    Ok(())
}

fn ensure_before_deadline_v1(absolute_deadline: Instant) -> Result<(), RemoteAuthorityCallErrorV1> {
    if Instant::now() >= absolute_deadline {
        return Err(RemoteAuthorityCallErrorV1::DefinitelyNotSent);
    }
    Ok(())
}

fn attempt_deadline_v1(
    absolute_deadline: Instant,
    attempt_timeout: Duration,
) -> Result<Instant, RemoteAuthorityCallErrorV1> {
    let now = Instant::now();
    if now >= absolute_deadline {
        return Err(RemoteAuthorityCallErrorV1::DefinitelyNotSent);
    }
    Ok(now
        .checked_add(attempt_timeout)
        .unwrap_or(absolute_deadline)
        .min(absolute_deadline))
}

#[cfg(test)]
mod tests;
