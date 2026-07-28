//! Fail-closed, connection-local service-admission state machine.
//!
//! This module is deliberately split from the WebSocket handler.  It accepts
//! no payer, invoice, payment hash, peer-provider, pair, query identifier, or
//! client-selected resource budget.  A grant is installed only after
//! [`bind_auth_begin_v1`] has bound the untrusted request to a verified signed
//! offer and trusted provider-local catalog, and a trusted method adapter has
//! reported that its authoritative admission transition committed.
//!
//! [`AdmissionMethodCommitterV1`] is a security boundary, not a convenience
//! callback.  Production implementations must perform the exact operation
//! described by [`AdmissionMethodRouteV1`].  Provider-local single-use bearer
//! methods should use [`ProviderStoreBearerCommitterV1`], which can reach the
//! provider store only through its sealed verified-spend entry point.  Shared
//! issuer BAT/ARC and standard Cashu routes must use online authoritative
//! redemption; copying issuer secret keys into this runtime is forbidden.

use std::fmt;

use pir_service_protocol::{
    bind_auth_begin_v1, ArcPresentationCanonicalizerV1, AuthBeginV1, AuthGrantedV1, AuthRejectCode,
    AuthRejectedV1, AuthResultV1, AuthScheme, AuthorizationProofV1, BoundAuthAttemptV1,
    EntitlementLimitsV1, FreeAuthorizationProofV1, FreeModeV1, HarmonyAttachResultV1,
    HarmonyAttachV1, HintTransport, OperationStartV1, PowChallengeRequestV1,
    PowChallengeResponseV1, ScopeId, ServicePolicyRequestV1, ServicePolicyResponseV1,
    ServiceProtocolError, TrustedServiceCatalogV1, VerificationMode, VerifiedServiceOfferV1,
    REQ_AUTH_BEGIN_V1, REQ_HARMONY_ATTACH_V1, REQ_POW_CHALLENGE_V1, REQ_SERVICE_POLICY_V1,
    RESP_AUTH_RESULT_V1, RESP_HARMONY_ATTACH_V1, RESP_POW_CHALLENGE_V1, RESP_SERVICE_POLICY_V1,
};
use pir_service_store::{
    verify_provider_local_arc_spend_v1, verify_provider_local_bearer_spend_v1,
    ArcProviderLocalAdapterV1, CashuBatProofVerifierV1, ProviderStore, StoreError,
};

use crate::harmony_attach_runtime::{
    AttachedHarmonyGrantV1, HarmonyAttachRegistryV1, SharedGrantUsageV1,
};

/// Canonically decoded service request from the inner PIR record payload
/// (`opcode || body`). Encryption is checked by the connection gate/handler,
/// not inferred from these plaintext bytes.
#[derive(Clone, Eq, PartialEq)]
pub enum ServiceWireRequestV1 {
    Policy(ServicePolicyRequestV1),
    Auth(Box<AuthBeginV1>),
    PowChallenge(Box<PowChallengeRequestV1>),
    HarmonyAttach(Box<HarmonyAttachV1>),
}

impl fmt::Debug for ServiceWireRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(request) => formatter
                .debug_tuple("ServiceWireRequestV1::Policy")
                .field(request)
                .finish(),
            Self::Auth(request) => formatter
                .debug_tuple("ServiceWireRequestV1::Auth")
                .field(request)
                .finish(),
            Self::PowChallenge(request) => formatter
                .debug_tuple("ServiceWireRequestV1::PowChallenge")
                .field(request)
                .finish(),
            Self::HarmonyAttach(request) => formatter
                .debug_tuple("ServiceWireRequestV1::HarmonyAttach")
                .field(request)
                .finish(),
        }
    }
}

impl ServiceWireRequestV1 {
    /// Return `Ok(None)` for a non-service opcode so the existing PIR decoder
    /// can handle it. Known service opcodes never fall through on malformed
    /// bodies.
    pub fn decode_inner_payload(payload: &[u8]) -> Result<Option<Self>, ServiceProtocolError> {
        let Some((&opcode, body)) = payload.split_first() else {
            return Ok(None);
        };
        match opcode {
            REQ_SERVICE_POLICY_V1 => Ok(Some(Self::Policy(ServicePolicyRequestV1::decode(body)?))),
            REQ_AUTH_BEGIN_V1 => Ok(Some(Self::Auth(Box::new(AuthBeginV1::decode_padded(
                body,
            )?)))),
            REQ_POW_CHALLENGE_V1 => Ok(Some(Self::PowChallenge(Box::new(
                PowChallengeRequestV1::decode_padded(body)?,
            )))),
            REQ_HARMONY_ATTACH_V1 => Ok(Some(Self::HarmonyAttach(Box::new(
                HarmonyAttachV1::decode_padded(body)?,
            )))),
            _ => Ok(None),
        }
    }
}

/// Encode a canonical service response with the repository's normal
/// `[len:u32le][opcode][body]` outer record framing.
pub fn encode_service_policy_response_v1(
    response: &ServicePolicyResponseV1,
) -> Result<Vec<u8>, ServiceProtocolError> {
    Ok(encode_service_record_v1(
        RESP_SERVICE_POLICY_V1,
        &response.encode()?,
    ))
}

pub fn encode_auth_result_response_v1(
    response: &AuthResultV1,
) -> Result<Vec<u8>, ServiceProtocolError> {
    Ok(encode_service_record_v1(
        RESP_AUTH_RESULT_V1,
        &response.encode()?,
    ))
}

pub fn encode_pow_challenge_response_v1(
    response: &PowChallengeResponseV1,
) -> Result<Vec<u8>, ServiceProtocolError> {
    Ok(encode_service_record_v1(
        RESP_POW_CHALLENGE_V1,
        &response.encode_padded()?,
    ))
}

pub fn encode_harmony_attach_result_response_v1(
    response: &HarmonyAttachResultV1,
) -> Result<Vec<u8>, ServiceProtocolError> {
    Ok(encode_service_record_v1(
        RESP_HARMONY_ATTACH_V1,
        &response.encode_padded()?,
    ))
}

fn encode_service_record_v1(opcode: u8, body: &[u8]) -> Vec<u8> {
    let payload_len = 1usize
        .checked_add(body.len())
        .and_then(|value| u32::try_from(value).ok())
        .expect("bounded service message length must fit u32");
    let mut record = Vec::with_capacity(4 + payload_len as usize);
    record.extend_from_slice(&payload_len.to_le_bytes());
    record.push(opcode);
    record.extend_from_slice(body);
    record
}

/// Explicit server mode. Legacy mode is never interpreted as a production
/// grant and cannot be entered as a fallback from enforced mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionEnforcementV1 {
    /// Operator-selected migration mode. The v1 gate returns
    /// [`GateErrorV1::ExplicitLegacyMode`] for backend work; the caller may
    /// route it through a separately named legacy policy.
    ExplicitLegacyMode,
    /// Every expensive backend frame needs a committed v1 grant.
    Enforced,
}

/// Exhaustive method route selected only from the verified offer and its
/// canonically decoded proof. No untrusted outer method tag is authoritative.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdmissionMethodRouteV1 {
    FreeOpenBestEffort,
    FreeIpRateLimited,
    FreeProofOfWork,
    FreeAnonymousTicketProviderLocal,
    FreeAnonymousTicketSharedIssuerOnline,
    Bolt11DirectReceiptProviderLocal,
    StandardCashuMintOnline,
    BitcoinPirCashuBatProviderLocal,
    BitcoinPirCashuBatSharedIssuerOnline,
    ArcProviderLocalExperimental,
    ArcSharedIssuerOnlineExperimental,
}

/// Trusted method adapter result. The coarse categories avoid exposing proof
/// details on the PIR wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionCommitErrorV1 {
    /// No authoritative implementation exists for this exact route.
    UnsupportedScheme,
    /// The signed offer is valid, but its authoritative local namespace or
    /// other required admission state is not installed on this provider.
    ScopeUnavailable,
    /// Verification/redeem/spend failed. Clients conservatively treat the
    /// presented capability as spent.
    InvalidOrSpent,
    /// A pre-consumption capacity decision rejected the operation.
    ServerBusy { retry_after_ms: u32 },
    /// Commit outcome is ambiguous or a durable commit could not be anchored.
    /// The connection must terminate and the capability must not be retried.
    InternalAfterSpend,
}

/// Security-critical adapter called only after policy and catalog binding.
///
/// Returning `Ok(())` asserts that the exact route's authoritative transition
/// has completed. For bearer methods this means durable at-most-once spend;
/// for standard Cashu it means the mint's NUT-03 invalidation completed; for
/// shared issuer methods it means online redeem committed; for non-bearer Free
/// it means the provider's signed quota/admission rule committed.
pub trait AdmissionMethodCommitterV1: Send + Sync {
    fn verify_and_commit_v1(
        &self,
        route: AdmissionMethodRouteV1,
        attempt: &BoundAuthAttemptV1<'_>,
        now_unix_seconds: u64,
    ) -> Result<(), AdmissionCommitErrorV1>;
}

/// Explicit method-family fan-out used by a production provider runtime.
///
/// Each slot is optional and an absent slot fails closed.  The caller cannot
/// select the slot: [`AdmissionMethodRouteV1`] was already derived from the
/// verified signed offer and the canonically decoded proof.  Keeping the
/// families separate is important operationally because provider-local
/// bearer spending, a third-party Cashu mint, and a shared BitcoinPIR issuer
/// have different trust, persistence, and network-failure semantics.
#[derive(Clone, Copy, Default)]
pub struct CompositeAdmissionMethodCommitterV1<'a> {
    free: Option<&'a dyn AdmissionMethodCommitterV1>,
    provider_local: Option<&'a dyn AdmissionMethodCommitterV1>,
    standard_cashu: Option<&'a dyn AdmissionMethodCommitterV1>,
    shared_issuer: Option<&'a dyn AdmissionMethodCommitterV1>,
}

impl fmt::Debug for CompositeAdmissionMethodCommitterV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompositeAdmissionMethodCommitterV1")
            .field("free", &self.free.is_some())
            .field("provider_local", &self.provider_local.is_some())
            .field("standard_cashu", &self.standard_cashu.is_some())
            .field("shared_issuer", &self.shared_issuer.is_some())
            .finish()
    }
}

impl<'a> CompositeAdmissionMethodCommitterV1<'a> {
    pub const fn new() -> Self {
        Self {
            free: None,
            provider_local: None,
            standard_cashu: None,
            shared_issuer: None,
        }
    }

    pub const fn with_free(mut self, committer: &'a dyn AdmissionMethodCommitterV1) -> Self {
        self.free = Some(committer);
        self
    }

    pub const fn with_provider_local(
        mut self,
        committer: &'a dyn AdmissionMethodCommitterV1,
    ) -> Self {
        self.provider_local = Some(committer);
        self
    }

    pub const fn with_standard_cashu(
        mut self,
        committer: &'a dyn AdmissionMethodCommitterV1,
    ) -> Self {
        self.standard_cashu = Some(committer);
        self
    }

    pub const fn with_shared_issuer(
        mut self,
        committer: &'a dyn AdmissionMethodCommitterV1,
    ) -> Self {
        self.shared_issuer = Some(committer);
        self
    }

    fn committer_for(
        &self,
        route: AdmissionMethodRouteV1,
    ) -> Option<&'a dyn AdmissionMethodCommitterV1> {
        match route {
            AdmissionMethodRouteV1::FreeOpenBestEffort
            | AdmissionMethodRouteV1::FreeIpRateLimited
            | AdmissionMethodRouteV1::FreeProofOfWork => self.free,
            AdmissionMethodRouteV1::FreeAnonymousTicketProviderLocal
            | AdmissionMethodRouteV1::Bolt11DirectReceiptProviderLocal
            | AdmissionMethodRouteV1::BitcoinPirCashuBatProviderLocal
            | AdmissionMethodRouteV1::ArcProviderLocalExperimental => self.provider_local,
            AdmissionMethodRouteV1::StandardCashuMintOnline => self.standard_cashu,
            AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline
            | AdmissionMethodRouteV1::BitcoinPirCashuBatSharedIssuerOnline
            | AdmissionMethodRouteV1::ArcSharedIssuerOnlineExperimental => self.shared_issuer,
        }
    }
}

impl AdmissionMethodCommitterV1 for CompositeAdmissionMethodCommitterV1<'_> {
    fn verify_and_commit_v1(
        &self,
        route: AdmissionMethodRouteV1,
        attempt: &BoundAuthAttemptV1<'_>,
        now_unix_seconds: u64,
    ) -> Result<(), AdmissionCommitErrorV1> {
        self.committer_for(route)
            .ok_or(AdmissionCommitErrorV1::UnsupportedScheme)?
            .verify_and_commit_v1(route, attempt, now_unix_seconds)
    }
}

/// Production-safe adapter for the provider-local bearer subset. ARC remains
/// explicitly experimental: it is available only when a reviewed adapter is
/// injected here. Unified-server may inject one only after its explicit
/// experimental acknowledgement and keyring checks both succeed.
/// Every shared-issuer route still fails closed.
pub struct ProviderStoreBearerCommitterV1<'a> {
    store: &'a ProviderStore,
    cashu_bat_verifier: Option<&'a dyn CashuBatProofVerifierV1>,
    arc_adapter: Option<&'a dyn ArcProviderLocalAdapterV1>,
}

impl<'a> ProviderStoreBearerCommitterV1<'a> {
    pub const fn new(
        store: &'a ProviderStore,
        cashu_bat_verifier: Option<&'a dyn CashuBatProofVerifierV1>,
    ) -> Self {
        Self {
            store,
            cashu_bat_verifier,
            arc_adapter: None,
        }
    }

    /// Opt into the experimental provider-local ARC path. Callers must retain
    /// the independent cryptographic review/deployment gate; constructing the
    /// default committer leaves ARC fail closed.
    pub const fn with_arc_adapter_v1(
        mut self,
        arc_adapter: &'a dyn ArcProviderLocalAdapterV1,
    ) -> Self {
        self.arc_adapter = Some(arc_adapter);
        self
    }
}

impl AdmissionMethodCommitterV1 for ProviderStoreBearerCommitterV1<'_> {
    fn verify_and_commit_v1(
        &self,
        route: AdmissionMethodRouteV1,
        attempt: &BoundAuthAttemptV1<'_>,
        now_unix_seconds: u64,
    ) -> Result<(), AdmissionCommitErrorV1> {
        match route {
            AdmissionMethodRouteV1::FreeAnonymousTicketProviderLocal
            | AdmissionMethodRouteV1::Bolt11DirectReceiptProviderLocal
            | AdmissionMethodRouteV1::BitcoinPirCashuBatProviderLocal => {
                let cashu_bat_verifier =
                    if route == AdmissionMethodRouteV1::BitcoinPirCashuBatProviderLocal {
                        Some(
                            self.cashu_bat_verifier
                                .ok_or(AdmissionCommitErrorV1::ScopeUnavailable)?,
                        )
                    } else {
                        None
                    };
                let verified = verify_provider_local_bearer_spend_v1(
                    attempt,
                    now_unix_seconds,
                    cashu_bat_verifier,
                )
                .map_err(map_provider_store_verification_error)?;
                self.store
                    .spend_verified_provider_local_v1(verified)
                    .map_err(map_provider_store_commit_error)?;
                Ok(())
            }
            AdmissionMethodRouteV1::ArcProviderLocalExperimental => {
                let arc_adapter = self
                    .arc_adapter
                    .ok_or(AdmissionCommitErrorV1::ScopeUnavailable)?;
                let verified =
                    verify_provider_local_arc_spend_v1(attempt, now_unix_seconds, arc_adapter)
                        .map_err(map_provider_store_verification_error)?;
                self.store
                    .spend_verified_arc_provider_local_v1(verified)
                    .map_err(map_provider_store_commit_error)?;
                Ok(())
            }
            AdmissionMethodRouteV1::ArcSharedIssuerOnlineExperimental
            | AdmissionMethodRouteV1::FreeOpenBestEffort
            | AdmissionMethodRouteV1::FreeIpRateLimited
            | AdmissionMethodRouteV1::FreeProofOfWork
            | AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline
            | AdmissionMethodRouteV1::StandardCashuMintOnline
            | AdmissionMethodRouteV1::BitcoinPirCashuBatSharedIssuerOnline => {
                Err(AdmissionCommitErrorV1::UnsupportedScheme)
            }
        }
    }
}

fn map_provider_store_verification_error(_: StoreError) -> AdmissionCommitErrorV1 {
    // Do not turn detailed signature, expiry, or namespace errors into a wire
    // oracle. A client that presented the proof conservatively burns it.
    AdmissionCommitErrorV1::InvalidOrSpent
}

fn map_provider_store_commit_error(error: StoreError) -> AdmissionCommitErrorV1 {
    match error {
        StoreError::AlreadySpent
        | StoreError::NamespaceClosed
        | StoreError::NamespaceExpired
        | StoreError::ServiceProtocol(_)
        | StoreError::InvalidInput(_) => AdmissionCommitErrorV1::InvalidOrSpent,
        StoreError::InternalAfterSpend { .. } | StoreError::UnanchoredCommit { .. } => {
            AdmissionCommitErrorV1::InternalAfterSpend
        }
        StoreError::Sqlite(_)
        | StoreError::Io(_)
        | StoreError::RollbackAuthorityUnavailable(_)
        | StoreError::MissingDatabase(_)
        | StoreError::NotRegularDatabase(_) => AdmissionCommitErrorV1::ServerBusy {
            retry_after_ms: 1_000,
        },
        // Every remaining store error is raised before SQLite COMMIT. The
        // transaction is dropped/rolled back, so the capability was not
        // consumed. Permanent operator/configuration incidents are exposed
        // only as coarse scope unavailability, never as a proof oracle.
        StoreError::NamespaceMissing => AdmissionCommitErrorV1::ScopeUnavailable,
        StoreError::SchemaMismatch(_)
        | StoreError::IntegrityCheckFailed(_)
        | StoreError::ProviderMismatch
        | StoreError::RollbackFloorMissing
        | StoreError::RollbackFloorIdentityMismatch
        | StoreError::RollbackDetected { .. }
        | StoreError::RollbackFork
        | StoreError::RollbackAuthorityProtocol(_)
        | StoreError::NamespaceConflict
        | StoreError::ExclusiveKeyLineageConflict
        | StoreError::StoreGenerationExhausted
        | StoreError::SpendSequenceExhausted
        | StoreError::PolicyRollback
        | StoreError::PolicyFork
        | StoreError::CredentialFloorRollback
        | StoreError::CashuCustodyExposureExceeded
        | StoreError::CashuCustodyLotMissing
        | StoreError::CashuCustodyLotConflict
        | StoreError::CashuCustodyExportMissing
        | StoreError::CashuCustodyExportConflict
        | StoreError::CashuCustodyStateConflict
        | StoreError::CashuCustodyUnavailable
        | StoreError::CashuCustodyNotesNotFullySpent
        | StoreError::CashuCustodyRetirementFloorMismatch
        | StoreError::CashuCustodyRetirementEvidenceMissing
        | StoreError::CashuCustodyRetirementEvidenceConflict
        | StoreError::CashuFloorRollback
        | StoreError::CashuSwapIntentMissing
        | StoreError::CashuSwapIntentConflict
        | StoreError::CashuSwapStateConflict
        | StoreError::FreeIpQuotaExhausted
        | StoreError::FreeIpClockRollback => AdmissionCommitErrorV1::ScopeUnavailable,
    }
}

/// Explicit fail-closed production placeholder. It is useful while a provider
/// has loaded policy support but has not installed every advertised method
/// adapter; it never fabricates a successful verification.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectAllAdmissionMethodsV1;

impl AdmissionMethodCommitterV1 for RejectAllAdmissionMethodsV1 {
    fn verify_and_commit_v1(
        &self,
        route: AdmissionMethodRouteV1,
        _attempt: &BoundAuthAttemptV1<'_>,
        _now_unix_seconds: u64,
    ) -> Result<(), AdmissionCommitErrorV1> {
        match route {
            AdmissionMethodRouteV1::FreeOpenBestEffort
            | AdmissionMethodRouteV1::FreeIpRateLimited
            | AdmissionMethodRouteV1::FreeProofOfWork
            | AdmissionMethodRouteV1::FreeAnonymousTicketProviderLocal
            | AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline
            | AdmissionMethodRouteV1::Bolt11DirectReceiptProviderLocal
            | AdmissionMethodRouteV1::StandardCashuMintOnline
            | AdmissionMethodRouteV1::BitcoinPirCashuBatProviderLocal
            | AdmissionMethodRouteV1::BitcoinPirCashuBatSharedIssuerOnline
            | AdmissionMethodRouteV1::ArcProviderLocalExperimental
            | AdmissionMethodRouteV1::ArcSharedIssuerOnlineExperimental => {
                Err(AdmissionCommitErrorV1::UnsupportedScheme)
            }
        }
    }
}

/// Exact expensive backend frame category. Merkle tree tops and metadata are
/// intentionally absent: they are cheap reusable preflight data. PIR-evaluated
/// Merkle siblings are present because they consume backend work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendFrameKindV1 {
    DpfIndexBatch,
    DpfChunkBatch,
    DpfMerkleSiblingBatch,
    /// Legacy on-demand Harmony hints have no V1 operation binding.
    HarmonyHintLegacyV1 {
        level: u8,
        index_sibling_levels: u8,
        chunk_sibling_levels: u8,
        expected_groups: u8,
    },
    HarmonyHintV2Full,
    HarmonyHintV2Half {
        session_token: [u8; 16],
        side: pir_service_protocol::HarmonyHintSideV1,
    },
    /// Legacy unpadded single-group opcode (`0x42`). It is classified so an
    /// enforced V1 grant rejects and terminalizes it explicitly; no signed V1
    /// scope authorizes this shape because it has no pair/round padding DFA.
    HarmonyLegacySingleQuery,
    HarmonyBatchQuery {
        level: u8,
        round_id: u16,
        index_sibling_levels: u8,
        chunk_sibling_levels: u8,
    },
    OnionRegisterKeys,
    OnionIndexQuery {
        round_id: u16,
    },
    OnionChunkQuery {
        round_id: u16,
    },
    OnionMerkleIndexSibling {
        round_id: u16,
    },
    OnionMerkleDataSibling {
        round_id: u16,
    },
    TeeOramQuery,
}

/// Trusted metadata derived by the runtime decoder from the actual backend
/// request. Resource counts are never copied from `AUTH_BEGIN_V1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendFrameV1 {
    pub kind: BackendFrameKindV1,
    pub db_id: u8,
    pub logical_inputs: u64,
    pub hint_groups: u64,
    pub request_bytes: u64,
    pub work_units: u64,
}

impl BackendFrameV1 {
    pub fn validate(&self) -> Result<(), GateErrorV1> {
        if self.request_bytes == 0 || self.work_units == 0 {
            return Err(GateErrorV1::InvalidFrameMetadata);
        }
        if self.hint_groups != 0
            && !matches!(
                &self.kind,
                BackendFrameKindV1::HarmonyHintLegacyV1 { .. }
                    | BackendFrameKindV1::HarmonyHintV2Full
                    | BackendFrameKindV1::HarmonyHintV2Half { .. }
            )
        {
            return Err(GateErrorV1::InvalidFrameMetadata);
        }
        if matches!(
            &self.kind,
            BackendFrameKindV1::HarmonyHintLegacyV1 { .. }
                | BackendFrameKindV1::HarmonyHintV2Full
                | BackendFrameKindV1::HarmonyHintV2Half { .. }
        ) && (self.logical_inputs != 0 || self.hint_groups == 0)
        {
            return Err(GateErrorV1::InvalidFrameMetadata);
        }
        if let BackendFrameKindV1::HarmonyHintLegacyV1 {
            level,
            index_sibling_levels,
            chunk_sibling_levels,
            expected_groups,
        } = &self.kind
        {
            let level_in_declared_range = match *level {
                10..=19 => *level - 10 < *index_sibling_levels,
                20..=29 => *level - 20 < *chunk_sibling_levels,
                _ => false,
            };
            if !level_in_declared_range
                || *expected_groups == 0
                || self.hint_groups != u64::from(*expected_groups)
                || self.logical_inputs != 0
            {
                return Err(GateErrorV1::InvalidFrameMetadata);
            }
        }
        if let BackendFrameKindV1::HarmonyBatchQuery {
            level,
            index_sibling_levels,
            chunk_sibling_levels,
            ..
        } = &self.kind
        {
            if *index_sibling_levels > 10 || *chunk_sibling_levels > 10 {
                return Err(GateErrorV1::InvalidFrameMetadata);
            }
            let valid_level = match *level {
                0 | 1 => true,
                10..=19 => *level - 10 < *index_sibling_levels,
                20..=29 => *level - 20 < *chunk_sibling_levels,
                _ => false,
            };
            if !valid_level {
                return Err(GateErrorV1::InvalidFrameMetadata);
            }
        }
        Ok(())
    }
}

/// Snapshot of server-enforced usage; useful for metrics and tests. It has no
/// credential, invoice, peer, or query identity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GrantUsageV1 {
    pub frames: u32,
    pub logical_inputs: u64,
    pub hint_groups: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub work_units: u64,
}

#[derive(Clone, Debug)]
struct ActiveGrantV1 {
    scope_id: ScopeId,
    operation: OperationStartV1,
    limits: EntitlementLimitsV1,
    started_at_ms: u64,
    usage: GrantUsageTrackerV1,
    dpf_phase: DpfPhaseV1,
    onion_phase: OnionPhaseV1,
    harmony_query_phase: HarmonyQueryPhaseV1,
    harmony_hint_full_phase: HarmonyHintFullPhaseV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DpfPhaseV1 {
    AwaitingFirstIndex,
    Index,
    Followup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OnionPhaseV1 {
    AwaitingRegistration,
    AwaitingFirstIndex,
    Index { next_round_id: u16 },
    Chunk { next_round_id: u16 },
    MerkleIndex,
    MerkleData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HarmonyQueryPhaseV1 {
    AwaitingFirstIndex,
    Index { next_round_id: u16 },
    Chunk { next_round_id: u16 },
    Merkle(HarmonyMerkleProgressV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HarmonyMerkleProgressV1 {
    family: HarmonyMerkleFamilyV1,
    level: u8,
    level_state: HarmonyMerkleLevelStateV1,
    index_levels: u8,
    chunk_levels: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HarmonyMerkleFamilyV1 {
    Index,
    Chunk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HarmonyMerkleLevelStateV1 {
    Complete,
    AwaitingPairCompanion {
        round_id: u16,
        may_also_be_single: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HarmonyHintFullPhaseV1 {
    AwaitingMain,
    AwaitingSiblings,
    Siblings {
        index_levels: u8,
        chunk_levels: u8,
        next_level: Option<u8>,
    },
}

#[derive(Clone, Debug)]
enum GrantUsageTrackerV1 {
    Local(GrantUsageV1),
    Shared(SharedGrantUsageV1),
}

impl GrantUsageTrackerV1 {
    const fn local() -> Self {
        Self::Local(GrantUsageV1 {
            frames: 0,
            logical_inputs: 0,
            hint_groups: 0,
            request_bytes: 0,
            response_bytes: 0,
            work_units: 0,
        })
    }

    fn snapshot(&self) -> Result<GrantUsageV1, GateErrorV1> {
        match self {
            Self::Local(usage) => Ok(*usage),
            Self::Shared(shared) => {
                let state = shared.snapshot();
                if state.terminal {
                    Err(GateErrorV1::TerminalAfterSpend)
                } else {
                    Ok(state.usage)
                }
            }
        }
    }

    fn terminalize(&mut self) {
        if let Self::Shared(shared) = self {
            shared.mutate(|state| state.terminal = true);
        }
    }

    fn consume_frame(
        &mut self,
        frame: &BackendFrameV1,
        limits: &EntitlementLimitsV1,
    ) -> Result<(), GateErrorV1> {
        match self {
            Self::Local(usage) => {
                *usage = checked_next_usage(*usage, frame, limits)?;
                Ok(())
            }
            Self::Shared(shared) => shared.mutate(|state| {
                if state.terminal {
                    return Err(GateErrorV1::TerminalAfterSpend);
                }
                match checked_next_usage(state.usage, frame, limits) {
                    Ok(next) => {
                        state.usage = next;
                        Ok(())
                    }
                    Err(error) => {
                        state.terminal = true;
                        Err(error)
                    }
                }
            }),
        }
    }

    fn reserve_response_bytes(&mut self, bytes: u64, limit: u64) -> Result<(), GateErrorV1> {
        let advance = |usage: &mut GrantUsageV1| {
            let next = usage
                .response_bytes
                .checked_add(bytes)
                .ok_or(GateErrorV1::ResourceLimitExceeded)?;
            if next > limit {
                return Err(GateErrorV1::ResourceLimitExceeded);
            }
            usage.response_bytes = next;
            Ok(())
        };
        match self {
            Self::Local(usage) => advance(usage),
            Self::Shared(shared) => shared.mutate(|state| {
                if state.terminal {
                    return Err(GateErrorV1::TerminalAfterSpend);
                }
                match advance(&mut state.usage) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        state.terminal = true;
                        Err(error)
                    }
                }
            }),
        }
    }
}

#[derive(Clone, Debug)]
enum ConnectionStateV1 {
    AwaitingSecureChannel,
    AwaitingPolicy,
    AwaitingAuthorization { policy_digest: [u8; 32] },
    Granted(ActiveGrantV1),
    Complete(ActiveGrantV1),
    TerminalAfterSpend,
}

/// Per-connection v1 admission state. Disconnect simply drops this value;
/// durable spend state is never rolled back.
#[derive(Clone, Debug)]
pub struct ConnectionAdmissionGateV1 {
    enforcement: AdmissionEnforcementV1,
    state: ConnectionStateV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateErrorV1 {
    ExplicitLegacyMode,
    SecureChannelRequired,
    PolicyRequired,
    PolicyChanged,
    AuthorizationRequired,
    AuthorizationAlreadyUsed,
    OperationMismatch,
    OperationSequence,
    GrantExpired,
    ResourceLimitExceeded,
    InvalidFrameMetadata,
    TerminalAfterSpend,
}

impl fmt::Display for GateErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExplicitLegacyMode => "explicit legacy admission mode has no v1 grant",
            Self::SecureChannelRequired => "secure encrypted channel is required",
            Self::PolicyRequired => "signed service policy must be fetched first",
            Self::PolicyChanged => "the selected service policy changed",
            Self::AuthorizationRequired => "a committed service authorization is required",
            Self::AuthorizationAlreadyUsed => "this connection already used an authorization",
            Self::OperationMismatch => "backend frame does not match the granted operation",
            Self::OperationSequence => "backend frame violates the operation sequence",
            Self::GrantExpired => "service grant expired",
            Self::ResourceLimitExceeded => "service entitlement limit exceeded",
            Self::InvalidFrameMetadata => "runtime supplied invalid backend frame metadata",
            Self::TerminalAfterSpend => "connection is terminal after capability consumption",
        })
    }
}

impl std::error::Error for GateErrorV1 {}

/// Zero-sized proof that the caller passed the gate for exactly one frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "backend work must run only after receiving this permit"]
pub struct BackendFramePermitV1 {
    _private: (),
}

impl ConnectionAdmissionGateV1 {
    pub const fn new(enforcement: AdmissionEnforcementV1) -> Self {
        Self {
            enforcement,
            state: ConnectionStateV1::AwaitingSecureChannel,
        }
    }

    pub const fn enforcement(&self) -> AdmissionEnforcementV1 {
        self.enforcement
    }

    fn terminalize_active_grant(&mut self) {
        if let ConnectionStateV1::Granted(grant) | ConnectionStateV1::Complete(grant) =
            &mut self.state
        {
            grant.usage.terminalize();
            self.state = ConnectionStateV1::TerminalAfterSpend;
        }
    }

    /// Called only after the server has successfully completed its secure
    /// channel handshake. Calling it twice does not reset a grant.
    pub fn secure_channel_established(&mut self) {
        if matches!(self.state, ConnectionStateV1::AwaitingSecureChannel) {
            self.state = ConnectionStateV1::AwaitingPolicy;
        }
    }

    /// Record that this exact signed policy was returned on an encrypted
    /// frame. Re-serving the same digest is idempotent; changing it invalidates
    /// any pre-authorization state and requires the client to use the new one.
    pub fn policy_served(
        &mut self,
        frame_was_encrypted: bool,
        policy_digest: [u8; 32],
    ) -> Result<(), GateErrorV1> {
        if !frame_was_encrypted || matches!(self.state, ConnectionStateV1::AwaitingSecureChannel) {
            return Err(GateErrorV1::SecureChannelRequired);
        }
        if policy_digest.iter().all(|byte| *byte == 0) {
            return Err(GateErrorV1::PolicyChanged);
        }
        match &self.state {
            ConnectionStateV1::AwaitingPolicy => {
                self.state = ConnectionStateV1::AwaitingAuthorization { policy_digest };
                Ok(())
            }
            ConnectionStateV1::AwaitingAuthorization {
                policy_digest: current,
            } if current == &policy_digest => Ok(()),
            ConnectionStateV1::AwaitingAuthorization { .. } => {
                self.state = ConnectionStateV1::AwaitingAuthorization { policy_digest };
                Ok(())
            }
            ConnectionStateV1::Granted(_) | ConnectionStateV1::Complete(_) => {
                Err(GateErrorV1::AuthorizationAlreadyUsed)
            }
            ConnectionStateV1::TerminalAfterSpend => Err(GateErrorV1::TerminalAfterSpend),
            ConnectionStateV1::AwaitingSecureChannel => Err(GateErrorV1::SecureChannelRequired),
        }
    }

    /// Check that a PoW challenge request belongs to the exact policy already
    /// served on this encrypted connection. Challenge issuance does not grant
    /// work and does not consume a capability.
    pub fn permit_pow_challenge(
        &self,
        frame_was_encrypted: bool,
        policy_digest: &[u8; 32],
    ) -> Result<(), GateErrorV1> {
        if !frame_was_encrypted {
            return Err(GateErrorV1::SecureChannelRequired);
        }
        match &self.state {
            ConnectionStateV1::AwaitingAuthorization {
                policy_digest: expected,
            } if expected == policy_digest => Ok(()),
            ConnectionStateV1::AwaitingAuthorization { .. } | ConnectionStateV1::AwaitingPolicy => {
                Err(GateErrorV1::PolicyRequired)
            }
            ConnectionStateV1::AwaitingSecureChannel => Err(GateErrorV1::SecureChannelRequired),
            ConnectionStateV1::Granted(_) | ConnectionStateV1::Complete(_) => {
                Err(GateErrorV1::AuthorizationAlreadyUsed)
            }
            ConnectionStateV1::TerminalAfterSpend => Err(GateErrorV1::TerminalAfterSpend),
        }
    }

    /// Preflight a complementary Harmony attach before consuming the
    /// process-wide one-shot slot. This prevents a connection which skipped
    /// the exact policy response from burning another connection's attach.
    pub fn permit_harmony_attach(
        &self,
        frame_was_encrypted: bool,
        policy_digest: &[u8; 32],
    ) -> Result<(), GateErrorV1> {
        self.permit_pow_challenge(frame_was_encrypted, policy_digest)
    }

    /// Full binding -> method dispatch -> authoritative commit -> grant path.
    /// No caller can directly install a grant through the public API.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_and_commit(
        &mut self,
        frame_was_encrypted: bool,
        request: &AuthBeginV1,
        verified_offer: VerifiedServiceOfferV1<'_>,
        trusted_catalog: &dyn TrustedServiceCatalogV1,
        arc_canonicalizer: Option<&dyn ArcPresentationCanonicalizerV1>,
        committer: &dyn AdmissionMethodCommitterV1,
        now_unix_seconds: u64,
        now_monotonic_ms: u64,
    ) -> AuthResultV1 {
        self.authorize_and_commit_with_harmony_registry(
            frame_was_encrypted,
            request,
            verified_offer,
            trusted_catalog,
            arc_canonicalizer,
            committer,
            None,
            now_unix_seconds,
            &|| now_monotonic_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_and_commit_with_harmony_registry(
        &mut self,
        frame_was_encrypted: bool,
        request: &AuthBeginV1,
        verified_offer: VerifiedServiceOfferV1<'_>,
        trusted_catalog: &dyn TrustedServiceCatalogV1,
        arc_canonicalizer: Option<&dyn ArcPresentationCanonicalizerV1>,
        committer: &dyn AdmissionMethodCommitterV1,
        harmony_registry: Option<&HarmonyAttachRegistryV1>,
        now_unix_seconds: u64,
        monotonic_now_ms: &dyn Fn() -> u64,
    ) -> AuthResultV1 {
        let expected_policy = match &self.state {
            ConnectionStateV1::AwaitingSecureChannel | ConnectionStateV1::AwaitingPolicy => {
                return rejected(
                    if frame_was_encrypted {
                        AuthRejectCode::PolicyChanged
                    } else {
                        AuthRejectCode::SecureChannelRequired
                    },
                    0,
                )
            }
            ConnectionStateV1::AwaitingAuthorization { policy_digest } => *policy_digest,
            ConnectionStateV1::Granted(_) | ConnectionStateV1::Complete(_) => {
                return rejected(AuthRejectCode::InvalidOrSpent, 0)
            }
            ConnectionStateV1::TerminalAfterSpend => {
                return rejected(AuthRejectCode::InternalAfterSpend, 0)
            }
        };
        if !frame_was_encrypted {
            return rejected(AuthRejectCode::SecureChannelRequired, 0);
        }
        if request.policy_digest != expected_policy
            || verified_offer.policy_digest() != expected_policy
        {
            return rejected(AuthRejectCode::PolicyChanged, 0);
        }
        // A zero wall-clock is never forwarded to a trusted adapter. In
        // particular, a custom adapter must not be able to turn an unknown
        // verification time into a committed authorization.
        if now_unix_seconds == 0 {
            return rejected(AuthRejectCode::ScopeUnavailable, 0);
        }

        let attempt =
            match bind_auth_begin_v1(request, verified_offer, trusted_catalog, arc_canonicalizer) {
                Ok(attempt) => attempt,
                Err(_) => return rejected(AuthRejectCode::WrongScope, 0),
            };
        let route = match admission_route_v1(&attempt) {
            Ok(route) => route,
            Err(_) => return rejected(AuthRejectCode::UnsupportedScheme, 0),
        };

        let is_harmony_half = matches!(
            attempt.operation(),
            OperationStartV1::HarmonyHint {
                transport: HintTransport::V2Half,
                ..
            }
        );
        if is_harmony_half && attempt.limits().max_concurrent_sockets < 2 {
            return rejected(AuthRejectCode::ScopeUnavailable, 0);
        }
        let harmony_reservation = if is_harmony_half {
            let Some(registry) = harmony_registry else {
                return rejected(AuthRejectCode::ScopeUnavailable, 0);
            };
            match registry.reserve_before_commit_v1(
                *attempt.verified_offer(),
                attempt.operation(),
                attempt.limits(),
                monotonic_now_ms(),
            ) {
                Ok(reservation) => Some(reservation),
                Err(_) => return rejected(AuthRejectCode::ServerBusy, 1_000),
            }
        } else {
            None
        };

        match committer.verify_and_commit_v1(route, &attempt, now_unix_seconds) {
            Ok(()) => {
                let scope_id = attempt.scope().scope_id();
                let enforced_profile = attempt.scope().entitlement_profile;
                let limits = attempt.limits().clone();
                let operation = attempt.operation().clone();
                let expires_in_ms = limits.max_wall_time_ms;
                let started_at_ms = monotonic_now_ms();
                let finalized = harmony_reservation
                    .map(|reservation| reservation.finalize_after_commit_v1(started_at_ms));
                let harmony_attach = finalized.as_ref().map(|value| value.grant.clone());
                let usage = finalized.map_or_else(GrantUsageTrackerV1::local, |value| {
                    GrantUsageTrackerV1::Shared(value.shared_usage)
                });
                self.state = ConnectionStateV1::Granted(ActiveGrantV1 {
                    scope_id,
                    operation,
                    limits,
                    started_at_ms,
                    usage,
                    dpf_phase: DpfPhaseV1::AwaitingFirstIndex,
                    onion_phase: OnionPhaseV1::AwaitingRegistration,
                    harmony_query_phase: HarmonyQueryPhaseV1::AwaitingFirstIndex,
                    harmony_hint_full_phase: HarmonyHintFullPhaseV1::AwaitingMain,
                });
                AuthResultV1::Granted(AuthGrantedV1 {
                    scope_id,
                    enforced_profile,
                    expires_in_ms,
                    harmony_attach,
                })
            }
            Err(AdmissionCommitErrorV1::UnsupportedScheme) => {
                rejected(AuthRejectCode::UnsupportedScheme, 0)
            }
            Err(AdmissionCommitErrorV1::ScopeUnavailable) => {
                rejected(AuthRejectCode::ScopeUnavailable, 0)
            }
            Err(AdmissionCommitErrorV1::InvalidOrSpent) => {
                self.state = ConnectionStateV1::TerminalAfterSpend;
                rejected(AuthRejectCode::InvalidOrSpent, 0)
            }
            Err(AdmissionCommitErrorV1::ServerBusy { retry_after_ms }) => {
                rejected(AuthRejectCode::ServerBusy, retry_after_ms)
            }
            Err(AdmissionCommitErrorV1::InternalAfterSpend) => {
                self.state = ConnectionStateV1::TerminalAfterSpend;
                rejected(AuthRejectCode::InternalAfterSpend, 0)
            }
        }
    }

    /// Install the complementary half only from private-field evidence
    /// returned by the process-wide attach registry. No payment method runs a
    /// second time and no public caller can fabricate this evidence.
    pub fn install_attached_harmony_grant_v1(
        &mut self,
        frame_was_encrypted: bool,
        attached: AttachedHarmonyGrantV1,
        now_monotonic_ms: u64,
    ) -> Result<(), GateErrorV1> {
        if !frame_was_encrypted {
            return Err(GateErrorV1::SecureChannelRequired);
        }
        let (policy_digest, scope_id, operation, limits, started_at_ms, shared_usage) =
            attached.into_gate_parts();
        let state_check = match &self.state {
            ConnectionStateV1::AwaitingAuthorization {
                policy_digest: expected,
            } if expected == &policy_digest => Ok(()),
            ConnectionStateV1::AwaitingSecureChannel => Err(GateErrorV1::SecureChannelRequired),
            ConnectionStateV1::AwaitingPolicy | ConnectionStateV1::AwaitingAuthorization { .. } => {
                Err(GateErrorV1::PolicyRequired)
            }
            ConnectionStateV1::Granted(_) | ConnectionStateV1::Complete(_) => {
                Err(GateErrorV1::AuthorizationAlreadyUsed)
            }
            ConnectionStateV1::TerminalAfterSpend => Err(GateErrorV1::TerminalAfterSpend),
        };
        if let Err(error) = state_check {
            shared_usage.mutate(|state| state.terminal = true);
            return Err(error);
        }
        if now_monotonic_ms.saturating_sub(started_at_ms) >= u64::from(limits.max_wall_time_ms) {
            shared_usage.mutate(|state| state.terminal = true);
            return Err(GateErrorV1::GrantExpired);
        }
        self.state = ConnectionStateV1::Granted(ActiveGrantV1 {
            scope_id,
            operation,
            limits,
            started_at_ms,
            usage: GrantUsageTrackerV1::Shared(shared_usage),
            dpf_phase: DpfPhaseV1::AwaitingFirstIndex,
            onion_phase: OnionPhaseV1::AwaitingRegistration,
            harmony_query_phase: HarmonyQueryPhaseV1::AwaitingFirstIndex,
            harmony_hint_full_phase: HarmonyHintFullPhaseV1::AwaitingMain,
        });
        Ok(())
    }

    /// Reject a known expensive opcode that failed runtime decoding. Once a
    /// capability was committed, malformed backend input terminalizes it just
    /// like an operation or resource-limit mismatch; it cannot become a retry
    /// oracle on the same grant.
    pub fn reject_malformed_backend_frame(&mut self, frame_was_encrypted: bool) -> GateErrorV1 {
        if self.enforcement == AdmissionEnforcementV1::ExplicitLegacyMode {
            return GateErrorV1::ExplicitLegacyMode;
        }
        if !frame_was_encrypted {
            if matches!(self.state, ConnectionStateV1::Granted(_)) {
                self.terminalize_active_grant();
            }
            return GateErrorV1::SecureChannelRequired;
        }
        match self.state {
            ConnectionStateV1::AwaitingSecureChannel => GateErrorV1::SecureChannelRequired,
            ConnectionStateV1::AwaitingPolicy => GateErrorV1::PolicyRequired,
            ConnectionStateV1::AwaitingAuthorization { .. } => GateErrorV1::AuthorizationRequired,
            ConnectionStateV1::Granted(_) => {
                self.terminalize_active_grant();
                GateErrorV1::InvalidFrameMetadata
            }
            ConnectionStateV1::Complete(_) => GateErrorV1::AuthorizationAlreadyUsed,
            ConnectionStateV1::TerminalAfterSpend => GateErrorV1::TerminalAfterSpend,
        }
    }

    /// Consume one frame from the exact connection-local grant before any
    /// blocking or expensive backend work starts.
    pub fn permit_backend_frame(
        &mut self,
        frame_was_encrypted: bool,
        frame: &BackendFrameV1,
        now_monotonic_ms: u64,
    ) -> Result<BackendFramePermitV1, GateErrorV1> {
        if self.enforcement == AdmissionEnforcementV1::ExplicitLegacyMode {
            return Err(GateErrorV1::ExplicitLegacyMode);
        }
        if !frame_was_encrypted {
            if matches!(self.state, ConnectionStateV1::Granted(_)) {
                self.terminalize_active_grant();
            }
            return Err(GateErrorV1::SecureChannelRequired);
        }
        if let Err(error) = frame.validate() {
            if matches!(self.state, ConnectionStateV1::Granted(_)) {
                self.terminalize_active_grant();
            }
            return Err(error);
        }

        let grant = match &mut self.state {
            ConnectionStateV1::AwaitingSecureChannel => {
                return Err(GateErrorV1::SecureChannelRequired)
            }
            ConnectionStateV1::AwaitingPolicy => return Err(GateErrorV1::PolicyRequired),
            ConnectionStateV1::AwaitingAuthorization { .. } => {
                return Err(GateErrorV1::AuthorizationRequired)
            }
            ConnectionStateV1::Granted(grant) => grant,
            ConnectionStateV1::Complete(_) => return Err(GateErrorV1::AuthorizationAlreadyUsed),
            ConnectionStateV1::TerminalAfterSpend => return Err(GateErrorV1::TerminalAfterSpend),
        };

        if now_monotonic_ms.saturating_sub(grant.started_at_ms)
            >= u64::from(grant.limits.max_wall_time_ms)
        {
            grant.usage.terminalize();
            self.state = ConnectionStateV1::TerminalAfterSpend;
            return Err(GateErrorV1::GrantExpired);
        }
        let transition = match operation_accepts_frame(
            &grant.operation,
            frame,
            grant.dpf_phase,
            grant.onion_phase,
            grant.harmony_query_phase,
            grant.harmony_hint_full_phase,
        ) {
            Ok(transition) => transition,
            Err(error) => {
                grant.usage.terminalize();
                self.state = ConnectionStateV1::TerminalAfterSpend;
                return Err(error);
            }
        };
        if let Err(error) = grant.usage.consume_frame(frame, &grant.limits) {
            self.state = ConnectionStateV1::TerminalAfterSpend;
            return Err(error);
        }
        match transition {
            OperationFrameTransitionV1::Stay { .. } => {}
            OperationFrameTransitionV1::Dpf(next) => {
                grant.dpf_phase = next;
            }
            OperationFrameTransitionV1::HarmonyQuery(next) => {
                grant.harmony_query_phase = next;
            }
            OperationFrameTransitionV1::HarmonyHintFull(next) => {
                grant.harmony_hint_full_phase = next;
            }
            OperationFrameTransitionV1::Onion(next) => {
                grant.onion_phase = next;
            }
        }
        if matches!(
            transition,
            OperationFrameTransitionV1::Stay { completes: true }
        ) {
            let completed = grant.clone();
            self.state = ConnectionStateV1::Complete(completed);
        }
        Ok(BackendFramePermitV1 { _private: () })
    }

    /// Reserve actual encoded response bytes before they are written. A
    /// streaming handler calls this once per batch. Exceeding the budget makes
    /// the connection terminal; it never extends or refunds the grant.
    pub fn reserve_response_bytes(&mut self, bytes: u64) -> Result<(), GateErrorV1> {
        if bytes == 0 {
            return Ok(());
        }
        let grant = match &mut self.state {
            ConnectionStateV1::Granted(grant) | ConnectionStateV1::Complete(grant) => grant,
            ConnectionStateV1::TerminalAfterSpend => return Err(GateErrorV1::TerminalAfterSpend),
            _ => return Err(GateErrorV1::AuthorizationRequired),
        };
        if let Err(error) = grant
            .usage
            .reserve_response_bytes(bytes, grant.limits.max_response_bytes)
        {
            self.state = ConnectionStateV1::TerminalAfterSpend;
            return Err(error);
        }
        Ok(())
    }

    pub fn usage(&self) -> Option<GrantUsageV1> {
        match &self.state {
            ConnectionStateV1::Granted(grant) | ConnectionStateV1::Complete(grant) => {
                grant.usage.snapshot().ok()
            }
            _ => None,
        }
    }

    pub fn granted_scope_id(&self) -> Option<ScopeId> {
        match &self.state {
            ConnectionStateV1::Granted(grant) | ConnectionStateV1::Complete(grant) => {
                Some(grant.scope_id)
            }
            _ => None,
        }
    }

    /// Maximum plaintext request bytes for the currently active grant.
    ///
    /// The transport uses this before allocating a multi-frame reassembly
    /// buffer.  Pre-authorization and completed connections deliberately
    /// return `None`: policy, challenge and authorization messages are small
    /// canonical frames and must never need transport chunking.
    pub fn active_request_byte_limit(&self) -> Option<u64> {
        match &self.state {
            ConnectionStateV1::Granted(grant) => Some(grant.limits.max_request_bytes),
            _ => None,
        }
    }

    #[cfg(test)]
    fn install_committed_grant_for_test(
        &mut self,
        scope_id: ScopeId,
        operation: OperationStartV1,
        limits: EntitlementLimitsV1,
        started_at_ms: u64,
    ) {
        self.state = ConnectionStateV1::Granted(ActiveGrantV1 {
            scope_id,
            operation,
            limits,
            started_at_ms,
            usage: GrantUsageTrackerV1::local(),
            dpf_phase: DpfPhaseV1::AwaitingFirstIndex,
            onion_phase: OnionPhaseV1::AwaitingRegistration,
            harmony_query_phase: HarmonyQueryPhaseV1::AwaitingFirstIndex,
            harmony_hint_full_phase: HarmonyHintFullPhaseV1::AwaitingMain,
        });
    }
}

fn rejected(code: AuthRejectCode, retry_after_ms: u32) -> AuthResultV1 {
    AuthResultV1::Rejected(AuthRejectedV1 {
        code,
        retry_after_ms,
    })
}

fn admission_route_v1(
    attempt: &BoundAuthAttemptV1<'_>,
) -> Result<AdmissionMethodRouteV1, ServiceProtocolError> {
    let offer = attempt.offer();
    let route = match (
        offer.authorization,
        offer.free_mode,
        offer.verification,
        attempt.proof(),
    ) {
        (
            AuthScheme::FreeV1,
            FreeModeV1::OpenBestEffort,
            VerificationMode::ProviderLocal,
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::OpenBestEffort),
        ) => AdmissionMethodRouteV1::FreeOpenBestEffort,
        (
            AuthScheme::FreeV1,
            FreeModeV1::IpRateLimited,
            VerificationMode::ProviderLocal,
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::IpRateLimited),
        ) => AdmissionMethodRouteV1::FreeIpRateLimited,
        (
            AuthScheme::FreeV1,
            FreeModeV1::ProofOfWork,
            VerificationMode::ProviderLocal,
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::ProofOfWork(_)),
        ) => AdmissionMethodRouteV1::FreeProofOfWork,
        (
            AuthScheme::FreeV1,
            FreeModeV1::AnonymousTicket,
            VerificationMode::ProviderLocal,
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::AnonymousTicket(_)),
        ) => AdmissionMethodRouteV1::FreeAnonymousTicketProviderLocal,
        (
            AuthScheme::FreeV1,
            FreeModeV1::AnonymousTicket,
            VerificationMode::SharedIssuerOnline,
            AuthorizationProofV1::Free(FreeAuthorizationProofV1::AnonymousTicket(_)),
        ) => AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline,
        (
            AuthScheme::Bolt11DirectReceiptV1,
            FreeModeV1::NotFree,
            VerificationMode::ProviderLocal,
            AuthorizationProofV1::Bolt11DirectReceipt(_),
        ) => AdmissionMethodRouteV1::Bolt11DirectReceiptProviderLocal,
        (
            AuthScheme::CashuEcashV1,
            FreeModeV1::NotFree,
            VerificationMode::StandardCashuMintOnline,
            AuthorizationProofV1::StandardCashu(_),
        ) => AdmissionMethodRouteV1::StandardCashuMintOnline,
        (
            AuthScheme::BitcoinPirCashuBatV1,
            FreeModeV1::NotFree,
            VerificationMode::ProviderLocal,
            AuthorizationProofV1::BitcoinPirCashuBat(_),
        ) => AdmissionMethodRouteV1::BitcoinPirCashuBatProviderLocal,
        (
            AuthScheme::BitcoinPirCashuBatV1,
            FreeModeV1::NotFree,
            VerificationMode::SharedIssuerOnline,
            AuthorizationProofV1::BitcoinPirCashuBat(_),
        ) => AdmissionMethodRouteV1::BitcoinPirCashuBatSharedIssuerOnline,
        (
            AuthScheme::ArcV1Experimental,
            FreeModeV1::NotFree,
            VerificationMode::ProviderLocal,
            AuthorizationProofV1::ArcExperimental(_),
        ) => AdmissionMethodRouteV1::ArcProviderLocalExperimental,
        (
            AuthScheme::ArcV1Experimental,
            FreeModeV1::NotFree,
            VerificationMode::SharedIssuerOnline,
            AuthorizationProofV1::ArcExperimental(_),
        ) => AdmissionMethodRouteV1::ArcSharedIssuerOnlineExperimental,
        _ => {
            return Err(ServiceProtocolError::InvalidValue {
                field: "AdmissionMethodRouteV1",
                reason: "verified offer, verification mode, and typed proof do not match",
            })
        }
    };
    Ok(route)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationFrameTransitionV1 {
    Stay { completes: bool },
    Dpf(DpfPhaseV1),
    HarmonyQuery(HarmonyQueryPhaseV1),
    HarmonyHintFull(HarmonyHintFullPhaseV1),
    Onion(OnionPhaseV1),
}

fn operation_accepts_frame(
    operation: &OperationStartV1,
    frame: &BackendFrameV1,
    dpf_phase: DpfPhaseV1,
    onion_phase: OnionPhaseV1,
    harmony_query_phase: HarmonyQueryPhaseV1,
    harmony_hint_full_phase: HarmonyHintFullPhaseV1,
) -> Result<OperationFrameTransitionV1, GateErrorV1> {
    let same_db = |expected: u8| expected == frame.db_id;
    match (operation, &frame.kind) {
        (OperationStartV1::DpfQuery { db_id }, BackendFrameKindV1::DpfIndexBatch)
            if same_db(*db_id) =>
        {
            match dpf_phase {
                DpfPhaseV1::AwaitingFirstIndex | DpfPhaseV1::Index if frame.logical_inputs == 1 => {
                    Ok(OperationFrameTransitionV1::Dpf(DpfPhaseV1::Index))
                }
                DpfPhaseV1::Followup => Err(GateErrorV1::OperationSequence),
                _ => Err(GateErrorV1::InvalidFrameMetadata),
            }
        }
        (
            OperationStartV1::DpfQuery { db_id },
            BackendFrameKindV1::DpfChunkBatch | BackendFrameKindV1::DpfMerkleSiblingBatch,
        ) if same_db(*db_id) => match dpf_phase {
            DpfPhaseV1::Index | DpfPhaseV1::Followup if frame.logical_inputs == 0 => {
                Ok(OperationFrameTransitionV1::Dpf(DpfPhaseV1::Followup))
            }
            DpfPhaseV1::AwaitingFirstIndex => Err(GateErrorV1::OperationSequence),
            _ => Err(GateErrorV1::InvalidFrameMetadata),
        },
        (
            OperationStartV1::HarmonyHint {
                db_id,
                transport: HintTransport::V2Full,
                session_token: None,
                primary_side: None,
            },
            BackendFrameKindV1::HarmonyHintV2Full,
        ) if same_db(*db_id)
            && matches!(
                harmony_hint_full_phase,
                HarmonyHintFullPhaseV1::AwaitingMain
            ) =>
        {
            Ok(OperationFrameTransitionV1::HarmonyHintFull(
                HarmonyHintFullPhaseV1::AwaitingSiblings,
            ))
        }
        (
            OperationStartV1::HarmonyHint {
                db_id,
                transport: HintTransport::V2Full,
                session_token: None,
                primary_side: None,
            },
            BackendFrameKindV1::HarmonyHintV2Full,
        ) if same_db(*db_id) => Err(GateErrorV1::OperationSequence),
        (
            OperationStartV1::HarmonyHint {
                db_id,
                transport: HintTransport::V2Full,
                session_token: None,
                primary_side: None,
            },
            BackendFrameKindV1::HarmonyHintLegacyV1 {
                level,
                index_sibling_levels,
                chunk_sibling_levels,
                ..
            },
        ) if same_db(*db_id) => {
            let expected_level = match harmony_hint_full_phase {
                HarmonyHintFullPhaseV1::AwaitingMain => return Err(GateErrorV1::OperationSequence),
                HarmonyHintFullPhaseV1::AwaitingSiblings => {
                    first_harmony_sibling_level(*index_sibling_levels, *chunk_sibling_levels)
                }
                HarmonyHintFullPhaseV1::Siblings {
                    index_levels,
                    chunk_levels,
                    next_level,
                } => {
                    if index_levels != *index_sibling_levels
                        || chunk_levels != *chunk_sibling_levels
                    {
                        return Err(GateErrorV1::InvalidFrameMetadata);
                    }
                    next_level
                }
            };
            if expected_level != Some(*level) {
                return Err(GateErrorV1::OperationSequence);
            }
            Ok(OperationFrameTransitionV1::HarmonyHintFull(
                HarmonyHintFullPhaseV1::Siblings {
                    index_levels: *index_sibling_levels,
                    chunk_levels: *chunk_sibling_levels,
                    next_level: next_harmony_sibling_level(
                        *level,
                        *index_sibling_levels,
                        *chunk_sibling_levels,
                    ),
                },
            ))
        }
        (
            OperationStartV1::HarmonyHint {
                db_id,
                transport: HintTransport::V2Half,
                session_token: Some(expected_token),
                primary_side: Some(expected_side),
            },
            BackendFrameKindV1::HarmonyHintV2Half {
                session_token,
                side,
            },
        ) if same_db(*db_id) && expected_token == session_token && expected_side == side => {
            Ok(OperationFrameTransitionV1::Stay { completes: true })
        }
        (
            OperationStartV1::HarmonyQuery { db_id },
            BackendFrameKindV1::HarmonyBatchQuery {
                level,
                round_id,
                index_sibling_levels,
                chunk_sibling_levels,
            },
        ) if same_db(*db_id) => Ok(OperationFrameTransitionV1::HarmonyQuery(
            next_harmony_query_phase(
                harmony_query_phase,
                *level,
                *round_id,
                *index_sibling_levels,
                *chunk_sibling_levels,
                frame.logical_inputs,
            )?,
        )),
        (OperationStartV1::OnionSession { db_id }, BackendFrameKindV1::OnionRegisterKeys)
            if same_db(*db_id) && onion_phase == OnionPhaseV1::AwaitingRegistration =>
        {
            if frame.logical_inputs != 0 {
                return Err(GateErrorV1::InvalidFrameMetadata);
            }
            Ok(OperationFrameTransitionV1::Onion(
                OnionPhaseV1::AwaitingFirstIndex,
            ))
        }
        (OperationStartV1::OnionSession { db_id }, BackendFrameKindV1::OnionRegisterKeys)
            if same_db(*db_id) =>
        {
            Err(GateErrorV1::OperationSequence)
        }
        (
            OperationStartV1::OnionSession { db_id },
            BackendFrameKindV1::OnionIndexQuery { .. }
            | BackendFrameKindV1::OnionChunkQuery { .. }
            | BackendFrameKindV1::OnionMerkleIndexSibling { .. }
            | BackendFrameKindV1::OnionMerkleDataSibling { .. },
        ) if same_db(*db_id) => Ok(OperationFrameTransitionV1::Onion(next_onion_phase(
            onion_phase,
            &frame.kind,
            frame.logical_inputs,
        )?)),
        (OperationStartV1::TeeOramQuery { db_id }, BackendFrameKindV1::TeeOramQuery)
            if same_db(*db_id) =>
        {
            Ok(OperationFrameTransitionV1::Stay { completes: true })
        }
        _ => Err(GateErrorV1::OperationMismatch),
    }
}

fn first_harmony_sibling_level(index_levels: u8, chunk_levels: u8) -> Option<u8> {
    if index_levels != 0 {
        Some(10)
    } else if chunk_levels != 0 {
        Some(20)
    } else {
        None
    }
}

fn next_harmony_sibling_level(level: u8, index_levels: u8, chunk_levels: u8) -> Option<u8> {
    match level {
        10..=19 => {
            let sibling_level = level - 10;
            if sibling_level + 1 < index_levels {
                Some(level + 1)
            } else if chunk_levels != 0 {
                Some(20)
            } else {
                None
            }
        }
        20..=29 => {
            let sibling_level = level - 20;
            (sibling_level + 1 < chunk_levels).then_some(level + 1)
        }
        _ => None,
    }
}

fn next_onion_phase(
    phase: OnionPhaseV1,
    kind: &BackendFrameKindV1,
    logical_inputs: u64,
) -> Result<OnionPhaseV1, GateErrorV1> {
    match (phase, kind) {
        (OnionPhaseV1::AwaitingFirstIndex, BackendFrameKindV1::OnionIndexQuery { round_id })
            if *round_id == 0 && logical_inputs == 1 =>
        {
            Ok(OnionPhaseV1::Index { next_round_id: 1 })
        }
        (
            OnionPhaseV1::Index { next_round_id },
            BackendFrameKindV1::OnionIndexQuery { round_id },
        ) if *round_id == next_round_id && logical_inputs == 1 => Ok(OnionPhaseV1::Index {
            next_round_id: next_round_id
                .checked_add(1)
                .ok_or(GateErrorV1::OperationSequence)?,
        }),
        (OnionPhaseV1::Index { .. }, BackendFrameKindV1::OnionChunkQuery { round_id })
            if *round_id == 0 && logical_inputs == 0 =>
        {
            Ok(OnionPhaseV1::Chunk { next_round_id: 1 })
        }
        (
            OnionPhaseV1::Chunk { next_round_id },
            BackendFrameKindV1::OnionChunkQuery { round_id },
        ) if *round_id == next_round_id && logical_inputs == 0 => Ok(OnionPhaseV1::Chunk {
            next_round_id: next_round_id
                .checked_add(1)
                .ok_or(GateErrorV1::OperationSequence)?,
        }),
        (OnionPhaseV1::Chunk { .. }, BackendFrameKindV1::OnionMerkleIndexSibling { round_id })
            if *round_id == 0 && logical_inputs == 0 =>
        {
            Ok(OnionPhaseV1::MerkleIndex)
        }
        (OnionPhaseV1::MerkleIndex, BackendFrameKindV1::OnionMerkleIndexSibling { round_id })
            if *round_id == 0 && logical_inputs == 0 =>
        {
            Ok(OnionPhaseV1::MerkleIndex)
        }
        (OnionPhaseV1::MerkleIndex, BackendFrameKindV1::OnionMerkleDataSibling { round_id })
            if *round_id == 0 && logical_inputs == 0 =>
        {
            Ok(OnionPhaseV1::MerkleData)
        }
        (OnionPhaseV1::MerkleData, BackendFrameKindV1::OnionMerkleDataSibling { round_id })
            if *round_id == 0 && logical_inputs == 0 =>
        {
            Ok(OnionPhaseV1::MerkleData)
        }
        _ => Err(GateErrorV1::OperationSequence),
    }
}

fn next_harmony_query_phase(
    phase: HarmonyQueryPhaseV1,
    level: u8,
    round_id: u16,
    index_sibling_levels: u8,
    chunk_sibling_levels: u8,
    logical_inputs: u64,
) -> Result<HarmonyQueryPhaseV1, GateErrorV1> {
    if index_sibling_levels > 10 || chunk_sibling_levels > 10 {
        return Err(GateErrorV1::InvalidFrameMetadata);
    }
    match phase {
        HarmonyQueryPhaseV1::AwaitingFirstIndex => {
            if level != 0 || round_id != 0 || logical_inputs != 1 {
                return Err(GateErrorV1::OperationSequence);
            }
            Ok(HarmonyQueryPhaseV1::Index { next_round_id: 1 })
        }
        HarmonyQueryPhaseV1::Index { next_round_id } if level == 0 => {
            let expected_logical = u64::from(next_round_id % 2 == 0);
            if round_id != next_round_id || logical_inputs != expected_logical {
                return Err(GateErrorV1::OperationSequence);
            }
            Ok(HarmonyQueryPhaseV1::Index {
                next_round_id: next_round_id
                    .checked_add(1)
                    .ok_or(GateErrorV1::OperationSequence)?,
            })
        }
        HarmonyQueryPhaseV1::Index { next_round_id } if level == 1 => {
            if next_round_id == 0 || next_round_id % 2 != 0 || round_id != 0 || logical_inputs != 0
            {
                return Err(GateErrorV1::OperationSequence);
            }
            Ok(HarmonyQueryPhaseV1::Chunk { next_round_id: 1 })
        }
        HarmonyQueryPhaseV1::Chunk { next_round_id } if level == 1 => {
            if round_id != next_round_id || logical_inputs != 0 {
                return Err(GateErrorV1::OperationSequence);
            }
            Ok(HarmonyQueryPhaseV1::Chunk {
                next_round_id: next_round_id
                    .checked_add(1)
                    .ok_or(GateErrorV1::OperationSequence)?,
            })
        }
        HarmonyQueryPhaseV1::Chunk { next_round_id } if level >= 10 => {
            if next_round_id == 0 || next_round_id % 2 != 0 || logical_inputs != 0 {
                return Err(GateErrorV1::OperationSequence);
            }
            Ok(HarmonyQueryPhaseV1::Merkle(start_harmony_merkle_progress(
                level,
                round_id,
                index_sibling_levels,
                chunk_sibling_levels,
            )?))
        }
        HarmonyQueryPhaseV1::Merkle(progress) if level >= 10 && logical_inputs == 0 => Ok(
            HarmonyQueryPhaseV1::Merkle(advance_harmony_merkle_progress(
                progress,
                level,
                round_id,
                index_sibling_levels,
                chunk_sibling_levels,
            )?),
        ),
        _ => Err(GateErrorV1::OperationSequence),
    }
}

fn start_harmony_merkle_progress(
    level: u8,
    round_id: u16,
    index_levels: u8,
    chunk_levels: u8,
) -> Result<HarmonyMerkleProgressV1, GateErrorV1> {
    if first_harmony_sibling_level(index_levels, chunk_levels) != Some(level) {
        return Err(GateErrorV1::OperationSequence);
    }
    harmony_merkle_progress_for_first_frame(level, round_id, index_levels, chunk_levels)
}

fn harmony_merkle_progress_for_first_frame(
    level: u8,
    round_id: u16,
    index_levels: u8,
    chunk_levels: u8,
) -> Result<HarmonyMerkleProgressV1, GateErrorV1> {
    let (family, sibling_level, table_type) = match level {
        10..=19 if level - 10 < index_levels => (HarmonyMerkleFamilyV1::Index, level - 10, 0u16),
        20..=29 if level - 20 < chunk_levels => (HarmonyMerkleFamilyV1::Chunk, level - 20, 1u16),
        _ => return Err(GateErrorV1::OperationSequence),
    };
    let single_round = table_type * 100 + u16::from(sibling_level);
    let pair_start = table_type * 1000 + u16::from(sibling_level) * 10;
    let level_state = if round_id == single_round && round_id == pair_start {
        HarmonyMerkleLevelStateV1::AwaitingPairCompanion {
            round_id: pair_start + 1,
            may_also_be_single: true,
        }
    } else if round_id == single_round {
        HarmonyMerkleLevelStateV1::Complete
    } else if round_id == pair_start {
        HarmonyMerkleLevelStateV1::AwaitingPairCompanion {
            round_id: pair_start + 1,
            may_also_be_single: false,
        }
    } else {
        return Err(GateErrorV1::OperationSequence);
    };
    Ok(HarmonyMerkleProgressV1 {
        family,
        level,
        level_state,
        index_levels,
        chunk_levels,
    })
}

fn advance_harmony_merkle_progress(
    progress: HarmonyMerkleProgressV1,
    level: u8,
    round_id: u16,
    index_levels: u8,
    chunk_levels: u8,
) -> Result<HarmonyMerkleProgressV1, GateErrorV1> {
    if progress.index_levels != index_levels || progress.chunk_levels != chunk_levels {
        return Err(GateErrorV1::InvalidFrameMetadata);
    }
    if level == progress.level {
        let HarmonyMerkleLevelStateV1::AwaitingPairCompanion {
            round_id: expected, ..
        } = progress.level_state
        else {
            return Err(GateErrorV1::OperationSequence);
        };
        if round_id != expected {
            return Err(GateErrorV1::OperationSequence);
        }
        return Ok(HarmonyMerkleProgressV1 {
            level_state: HarmonyMerkleLevelStateV1::Complete,
            ..progress
        });
    }

    let previous_complete = matches!(progress.level_state, HarmonyMerkleLevelStateV1::Complete)
        || matches!(
            progress.level_state,
            HarmonyMerkleLevelStateV1::AwaitingPairCompanion {
                may_also_be_single: true,
                ..
            }
        );
    if !previous_complete
        || next_harmony_sibling_level(progress.level, index_levels, chunk_levels) != Some(level)
    {
        return Err(GateErrorV1::OperationSequence);
    }
    harmony_merkle_progress_for_first_frame(level, round_id, index_levels, chunk_levels)
}

fn checked_next_usage(
    current: GrantUsageV1,
    frame: &BackendFrameV1,
    limits: &EntitlementLimitsV1,
) -> Result<GrantUsageV1, GateErrorV1> {
    let next = GrantUsageV1 {
        frames: current
            .frames
            .checked_add(1)
            .ok_or(GateErrorV1::ResourceLimitExceeded)?,
        logical_inputs: current
            .logical_inputs
            .checked_add(frame.logical_inputs)
            .ok_or(GateErrorV1::ResourceLimitExceeded)?,
        hint_groups: current
            .hint_groups
            .checked_add(frame.hint_groups)
            .ok_or(GateErrorV1::ResourceLimitExceeded)?,
        request_bytes: current
            .request_bytes
            .checked_add(frame.request_bytes)
            .ok_or(GateErrorV1::ResourceLimitExceeded)?,
        response_bytes: current.response_bytes,
        work_units: current
            .work_units
            .checked_add(frame.work_units)
            .ok_or(GateErrorV1::ResourceLimitExceeded)?,
    };
    if next.frames > limits.max_frames
        || next.logical_inputs > u64::from(limits.max_logical_inputs)
        || next.hint_groups > u64::from(limits.max_hint_groups)
        || next.request_bytes > limits.max_request_bytes
        || next.work_units > limits.max_work_units
    {
        return Err(GateErrorV1::ResourceLimitExceeded);
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc as StdArc, Barrier, Mutex};

    use super::*;
    use ed25519_dalek::SigningKey;
    use pir_service_protocol::{
        AcquisitionMethod, AuthPaddingClassV1, BackendId, DatasetBindingV1, DeploymentStatus,
        HarmonyHintSideV1, PolicyRollbackGuardV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1,
        ServicePolicyEpochFloorsV1, ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1,
        TrustedCatalogResolutionV1, WorkloadId,
    };

    fn limits() -> EntitlementLimitsV1 {
        EntitlementLimitsV1 {
            max_logical_inputs: 8,
            max_frames: 4,
            max_request_bytes: 1_000,
            max_response_bytes: 2_000,
            max_wall_time_ms: 500,
            max_concurrent_sockets: 1,
            max_hint_groups: 8,
            max_work_units: 12,
        }
    }

    fn frame(kind: BackendFrameKindV1, db_id: u8) -> BackendFrameV1 {
        BackendFrameV1 {
            kind,
            db_id,
            logical_inputs: 1,
            hint_groups: 0,
            request_bytes: 100,
            work_units: 2,
        }
    }

    fn harmony_batch_frame(
        db_id: u8,
        level: u8,
        round_id: u16,
        index_sibling_levels: u8,
        chunk_sibling_levels: u8,
    ) -> BackendFrameV1 {
        BackendFrameV1 {
            kind: BackendFrameKindV1::HarmonyBatchQuery {
                level,
                round_id,
                index_sibling_levels,
                chunk_sibling_levels,
            },
            db_id,
            logical_inputs: u64::from(level == 0 && round_id % 2 == 0),
            hint_groups: 0,
            request_bytes: 100,
            work_units: 2,
        }
    }

    fn onion_frame(kind: BackendFrameKindV1, db_id: u8) -> BackendFrameV1 {
        BackendFrameV1 {
            logical_inputs: u64::from(matches!(&kind, BackendFrameKindV1::OnionIndexQuery { .. })),
            ..frame(kind, db_id)
        }
    }

    fn granted(operation: OperationStartV1) -> ConnectionAdmissionGateV1 {
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        gate.install_committed_grant_for_test([7; 32], operation, limits(), 1_000);
        gate
    }

    struct AcceptingTestCommitter {
        routes: Mutex<Vec<AdmissionMethodRouteV1>>,
    }

    impl AdmissionMethodCommitterV1 for AcceptingTestCommitter {
        fn verify_and_commit_v1(
            &self,
            route: AdmissionMethodRouteV1,
            _attempt: &BoundAuthAttemptV1<'_>,
            _now_unix_seconds: u64,
        ) -> Result<(), AdmissionCommitErrorV1> {
            self.routes.lock().unwrap().push(route);
            Ok(())
        }
    }

    struct FailingTestCommitter {
        calls: AtomicUsize,
        error: AdmissionCommitErrorV1,
    }

    impl AdmissionMethodCommitterV1 for FailingTestCommitter {
        fn verify_and_commit_v1(
            &self,
            _route: AdmissionMethodRouteV1,
            _attempt: &BoundAuthAttemptV1<'_>,
            _now_unix_seconds: u64,
        ) -> Result<(), AdmissionCommitErrorV1> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(self.error)
        }
    }

    #[test]
    fn composite_committer_routes_only_to_the_configured_method_family() {
        let free = AcceptingTestCommitter {
            routes: Mutex::new(Vec::new()),
        };
        let local = AcceptingTestCommitter {
            routes: Mutex::new(Vec::new()),
        };
        let cashu = AcceptingTestCommitter {
            routes: Mutex::new(Vec::new()),
        };
        let shared = AcceptingTestCommitter {
            routes: Mutex::new(Vec::new()),
        };
        let composite = CompositeAdmissionMethodCommitterV1::new()
            .with_free(&free)
            .with_provider_local(&local)
            .with_standard_cashu(&cashu)
            .with_shared_issuer(&shared);

        for route in [
            AdmissionMethodRouteV1::FreeOpenBestEffort,
            AdmissionMethodRouteV1::FreeIpRateLimited,
            AdmissionMethodRouteV1::FreeProofOfWork,
        ] {
            assert!(core::ptr::eq(
                composite.committer_for(route).unwrap(),
                &free as &dyn AdmissionMethodCommitterV1,
            ));
        }
        for route in [
            AdmissionMethodRouteV1::FreeAnonymousTicketProviderLocal,
            AdmissionMethodRouteV1::Bolt11DirectReceiptProviderLocal,
            AdmissionMethodRouteV1::BitcoinPirCashuBatProviderLocal,
            AdmissionMethodRouteV1::ArcProviderLocalExperimental,
        ] {
            assert!(core::ptr::eq(
                composite.committer_for(route).unwrap(),
                &local as &dyn AdmissionMethodCommitterV1,
            ));
        }
        assert!(core::ptr::eq(
            composite
                .committer_for(AdmissionMethodRouteV1::StandardCashuMintOnline)
                .unwrap(),
            &cashu as &dyn AdmissionMethodCommitterV1,
        ));
        for route in [
            AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline,
            AdmissionMethodRouteV1::BitcoinPirCashuBatSharedIssuerOnline,
            AdmissionMethodRouteV1::ArcSharedIssuerOnlineExperimental,
        ] {
            assert!(core::ptr::eq(
                composite.committer_for(route).unwrap(),
                &shared as &dyn AdmissionMethodCommitterV1,
            ));
        }

        let only_free = CompositeAdmissionMethodCommitterV1::new().with_free(&free);
        assert!(only_free
            .committer_for(AdmissionMethodRouteV1::FreeOpenBestEffort)
            .is_some());
        assert!(only_free
            .committer_for(AdmissionMethodRouteV1::Bolt11DirectReceiptProviderLocal)
            .is_none());
        assert!(only_free
            .committer_for(AdmissionMethodRouteV1::StandardCashuMintOnline)
            .is_none());
    }

    fn verified_free_fixture() -> (
        ServicePolicyV1,
        ed25519_dalek::VerifyingKey,
        AuthBeginV1,
        TrustedCatalogResolutionV1,
    ) {
        let scope = ServiceScopeV1 {
            provider_id: [9; 32],
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 11 },
            operation_profile: 21,
            entitlement_profile: 121,
        };
        let offer = ServiceOfferV1 {
            offer_id: 1,
            acquisition: AcquisitionMethod::FreeV1,
            free_mode: FreeModeV1::OpenBestEffort,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::FreeV1,
            verification: VerificationMode::ProviderLocal,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::Free,
            issuer_id: [0; 32],
            key_id: Vec::new(),
            credential_binding: None,
            cashu_mint_manifest: None,
            endpoint: String::new(),
            invoice_expiry_seconds: 0,
            claim_window_seconds: 0,
            minimum_credential_validity_seconds: 1,
            retired_policy_grace_seconds: 0,
            credential_count: 1,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::NONE,
        };
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let policy = ServicePolicyV1::sign(
            scope.provider_id,
            8,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope: scope.clone(),
                limits: limits(),
                offers: vec![offer],
            }],
            &signing_key,
        )
        .unwrap();
        let verifying_key = signing_key.verifying_key();
        let digest = policy.policy_digest().unwrap();
        let request = AuthBeginV1 {
            policy_digest: digest,
            scope_id: scope.scope_id(),
            offer_id: 1,
            scheme: AuthScheme::FreeV1,
            key_id: Vec::new(),
            operation: OperationStartV1::DpfQuery { db_id: 7 },
            proof: Vec::new(),
        };
        let resolution = TrustedCatalogResolutionV1::new(
            7,
            scope.backend,
            scope.workload,
            scope.protocol_version,
            scope.dataset,
            scope.operation_profile,
        );
        (policy, verifying_key, request, resolution)
    }

    fn verified_harmony_half_fixture(
        entitlement_limits: EntitlementLimitsV1,
    ) -> (
        ServicePolicyV1,
        ed25519_dalek::VerifyingKey,
        AuthBeginV1,
        TrustedCatalogResolutionV1,
    ) {
        let scope = ServiceScopeV1 {
            provider_id: [9; 32],
            backend: BackendId::HarmonyPirV2,
            workload: WorkloadId::HarmonyHintBundleV1,
            protocol_version: 2,
            dataset: DatasetBindingV1::Class { class_id: 11 },
            operation_profile: 21,
            entitlement_profile: 121,
        };
        let offer = ServiceOfferV1 {
            offer_id: 1,
            acquisition: AcquisitionMethod::FreeV1,
            free_mode: FreeModeV1::OpenBestEffort,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::FreeV1,
            verification: VerificationMode::ProviderLocal,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::Free,
            issuer_id: [0; 32],
            key_id: Vec::new(),
            credential_binding: None,
            cashu_mint_manifest: None,
            endpoint: String::new(),
            invoice_expiry_seconds: 0,
            claim_window_seconds: 0,
            minimum_credential_validity_seconds: 1,
            retired_policy_grace_seconds: 0,
            credential_count: 1,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::NONE,
        };
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let policy = ServicePolicyV1::sign(
            scope.provider_id,
            8,
            100,
            200,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope: scope.clone(),
                limits: entitlement_limits,
                offers: vec![offer],
            }],
            &signing_key,
        )
        .unwrap();
        let verifying_key = signing_key.verifying_key();
        let request = AuthBeginV1 {
            policy_digest: policy.policy_digest().unwrap(),
            scope_id: scope.scope_id(),
            offer_id: 1,
            scheme: AuthScheme::FreeV1,
            key_id: Vec::new(),
            operation: OperationStartV1::HarmonyHint {
                db_id: 7,
                transport: HintTransport::V2Half,
                session_token: Some([4; 16]),
                primary_side: Some(HarmonyHintSideV1::Index),
            },
            proof: Vec::new(),
        };
        let resolution = TrustedCatalogResolutionV1::new(
            7,
            scope.backend,
            scope.workload,
            scope.protocol_version,
            scope.dataset,
            scope.operation_profile,
        );
        (policy, verifying_key, request, resolution)
    }

    fn harmony_attach_request(
        request: &AuthBeginV1,
        offer: VerifiedServiceOfferV1<'_>,
        grant: &pir_service_protocol::HarmonyAttachGrantV1,
    ) -> HarmonyAttachV1 {
        let OperationStartV1::HarmonyHint {
            db_id,
            session_token: Some(session_token),
            primary_side: Some(primary_side),
            ..
        } = &request.operation
        else {
            panic!("fixture must contain a Harmony half operation")
        };
        HarmonyAttachV1 {
            provider_id: offer.scope().provider_id,
            policy_digest: offer.policy_digest(),
            scope_id: offer.scope().scope_id(),
            offer_id: offer.offer().offer_id,
            operation_id: grant.operation_id,
            operation_digest: request.operation.digest().unwrap(),
            attach_secret: grant.attach_secret,
            db_id: *db_id,
            session_token: *session_token,
            primary_side: *primary_side,
            attach_side: primary_side.complement(),
            operation_profile: offer.scope().operation_profile,
        }
    }

    fn authorized_harmony_pair(
        entitlement_limits: EntitlementLimitsV1,
    ) -> (ConnectionAdmissionGateV1, ConnectionAdmissionGateV1) {
        let (policy, key, request, resolution) = verified_harmony_half_fixture(entitlement_limits);
        let verified_policy = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &key,
            )
            .unwrap();
        let offer = verified_policy
            .offer(&request.scope_id, request.offer_id)
            .unwrap();
        let catalog = move |operation: &OperationStartV1| match operation {
            OperationStartV1::HarmonyHint {
                db_id: 7,
                transport: HintTransport::V2Half,
                ..
            } => Some(resolution.clone()),
            _ => None,
        };
        let committer = AcceptingTestCommitter {
            routes: Mutex::new(Vec::new()),
        };
        let registry = HarmonyAttachRegistryV1::new(1);
        let mut primary = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        primary.secure_channel_established();
        primary.policy_served(true, request.policy_digest).unwrap();
        let clock_calls = AtomicUsize::new(0);
        let result = primary.authorize_and_commit_with_harmony_registry(
            true,
            &request,
            offer,
            &catalog,
            None,
            &committer,
            Some(&registry),
            150,
            &|| {
                if clock_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    1_000
                } else {
                    1_100
                }
            },
        );
        let AuthResultV1::Granted(granted) = result else {
            panic!("Harmony primary authorization must succeed: {result:?}")
        };
        let grant = granted
            .harmony_attach
            .expect("Harmony half grant must carry attach material");
        let attach_request = harmony_attach_request(&request, offer, &grant);
        let attached = registry.try_attach_v1(&attach_request, 1_101).unwrap();

        let mut complementary = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        complementary.secure_channel_established();
        complementary
            .policy_served(true, request.policy_digest)
            .unwrap();
        complementary
            .install_attached_harmony_grant_v1(true, attached, 1_101)
            .unwrap();
        (primary, complementary)
    }

    #[test]
    fn harmony_half_requires_two_sockets_before_committing() {
        let mut one_socket_limits = limits();
        one_socket_limits.max_concurrent_sockets = 1;
        let (policy, key, request, resolution) = verified_harmony_half_fixture(one_socket_limits);
        let verified_policy = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &key,
            )
            .unwrap();
        let offer = verified_policy
            .offer(&request.scope_id, request.offer_id)
            .unwrap();
        let catalog = move |operation: &OperationStartV1| match operation {
            OperationStartV1::HarmonyHint { db_id: 7, .. } => Some(resolution.clone()),
            _ => None,
        };
        let committer = AcceptingTestCommitter {
            routes: Mutex::new(Vec::new()),
        };
        let registry = HarmonyAttachRegistryV1::new(1);
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        gate.secure_channel_established();
        gate.policy_served(true, request.policy_digest).unwrap();

        assert_eq!(
            gate.authorize_and_commit_with_harmony_registry(
                true,
                &request,
                offer,
                &catalog,
                None,
                &committer,
                Some(&registry),
                150,
                &|| 1_000,
            ),
            rejected(AuthRejectCode::ScopeUnavailable, 0)
        );
        assert!(committer.routes.lock().unwrap().is_empty());
        assert_eq!(gate.granted_scope_id(), None);
    }

    #[test]
    fn harmony_registry_full_rejects_before_committing() {
        let mut two_socket_limits = limits();
        two_socket_limits.max_concurrent_sockets = 2;
        let (policy, key, request, resolution) = verified_harmony_half_fixture(two_socket_limits);
        let verified_policy = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &key,
            )
            .unwrap();
        let offer = verified_policy
            .offer(&request.scope_id, request.offer_id)
            .unwrap();
        let catalog = |operation: &OperationStartV1| match operation {
            OperationStartV1::HarmonyHint { db_id: 7, .. } => Some(resolution.clone()),
            _ => None,
        };
        let committer = AcceptingTestCommitter {
            routes: Mutex::new(Vec::new()),
        };
        let registry = HarmonyAttachRegistryV1::new(1);

        let mut first = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        first.secure_channel_established();
        first.policy_served(true, request.policy_digest).unwrap();
        assert!(matches!(
            first.authorize_and_commit_with_harmony_registry(
                true,
                &request,
                offer,
                &catalog,
                None,
                &committer,
                Some(&registry),
                150,
                &|| 1_000,
            ),
            AuthResultV1::Granted(_)
        ));

        let mut second = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        second.secure_channel_established();
        second.policy_served(true, request.policy_digest).unwrap();
        assert_eq!(
            second.authorize_and_commit_with_harmony_registry(
                true,
                &request,
                offer,
                &catalog,
                None,
                &committer,
                Some(&registry),
                150,
                &|| 1_001,
            ),
            rejected(AuthRejectCode::ServerBusy, 1_000)
        );
        assert_eq!(
            committer.routes.lock().unwrap().len(),
            1,
            "the full registry must be detected before a second commit"
        );
    }

    #[test]
    fn harmony_commit_failure_releases_reserved_capacity() {
        let mut two_socket_limits = limits();
        two_socket_limits.max_concurrent_sockets = 2;
        let (policy, key, request, resolution) = verified_harmony_half_fixture(two_socket_limits);
        let verified_policy = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &key,
            )
            .unwrap();
        let offer = verified_policy
            .offer(&request.scope_id, request.offer_id)
            .unwrap();
        let catalog = |operation: &OperationStartV1| match operation {
            OperationStartV1::HarmonyHint { db_id: 7, .. } => Some(resolution.clone()),
            _ => None,
        };
        let registry = HarmonyAttachRegistryV1::new(1);
        let failing = FailingTestCommitter {
            calls: AtomicUsize::new(0),
            error: AdmissionCommitErrorV1::ServerBusy { retry_after_ms: 7 },
        };
        let mut failed = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        failed.secure_channel_established();
        failed.policy_served(true, request.policy_digest).unwrap();
        assert_eq!(
            failed.authorize_and_commit_with_harmony_registry(
                true,
                &request,
                offer,
                &catalog,
                None,
                &failing,
                Some(&registry),
                150,
                &|| 1_000,
            ),
            rejected(AuthRejectCode::ServerBusy, 7)
        );
        assert_eq!(failing.calls.load(Ordering::SeqCst), 1);

        let accepting = AcceptingTestCommitter {
            routes: Mutex::new(Vec::new()),
        };
        let mut retry = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        retry.secure_channel_established();
        retry.policy_served(true, request.policy_digest).unwrap();
        assert!(matches!(
            retry.authorize_and_commit_with_harmony_registry(
                true,
                &request,
                offer,
                &catalog,
                None,
                &accepting,
                Some(&registry),
                150,
                &|| 1_001,
            ),
            AuthResultV1::Granted(_)
        ));
    }

    #[test]
    fn harmony_primary_and_attach_share_every_request_counter() {
        enum Counter {
            Frames,
            HintGroups,
            RequestBytes,
            WorkUnits,
        }
        for counter in [
            Counter::Frames,
            Counter::HintGroups,
            Counter::RequestBytes,
            Counter::WorkUnits,
        ] {
            let mut shared_limits = limits();
            shared_limits.max_concurrent_sockets = 2;
            shared_limits.max_frames = 4;
            shared_limits.max_logical_inputs = 4;
            shared_limits.max_hint_groups = 4;
            shared_limits.max_request_bytes = 4;
            shared_limits.max_work_units = 4;
            match counter {
                Counter::Frames => shared_limits.max_frames = 1,
                Counter::HintGroups => shared_limits.max_hint_groups = 1,
                Counter::RequestBytes => shared_limits.max_request_bytes = 1,
                Counter::WorkUnits => shared_limits.max_work_units = 1,
            }
            let (mut primary, mut complementary) = authorized_harmony_pair(shared_limits);
            let primary_frame = BackendFrameV1 {
                kind: BackendFrameKindV1::HarmonyHintV2Half {
                    session_token: [4; 16],
                    side: HarmonyHintSideV1::Index,
                },
                db_id: 7,
                logical_inputs: 0,
                hint_groups: 1,
                request_bytes: 1,
                work_units: 1,
            };
            let complementary_frame = BackendFrameV1 {
                kind: BackendFrameKindV1::HarmonyHintV2Half {
                    session_token: [4; 16],
                    side: HarmonyHintSideV1::Chunk,
                },
                ..primary_frame.clone()
            };
            assert!(primary
                .permit_backend_frame(true, &primary_frame, 1_102)
                .is_ok());
            assert_eq!(
                complementary.permit_backend_frame(true, &complementary_frame, 1_102),
                Err(GateErrorV1::ResourceLimitExceeded)
            );
            assert_eq!(
                primary.reserve_response_bytes(1),
                Err(GateErrorV1::TerminalAfterSpend),
                "a limit failure on either socket terminalizes the shared grant"
            );
        }
    }

    #[test]
    fn harmony_primary_and_attach_share_response_budget() {
        let mut shared_limits = limits();
        shared_limits.max_concurrent_sockets = 2;
        shared_limits.max_response_bytes = 100;
        let (mut primary, mut complementary) = authorized_harmony_pair(shared_limits);
        primary.reserve_response_bytes(60).unwrap();
        assert_eq!(
            complementary.reserve_response_bytes(41),
            Err(GateErrorV1::ResourceLimitExceeded)
        );
        assert_eq!(
            primary.reserve_response_bytes(1),
            Err(GateErrorV1::TerminalAfterSpend)
        );
    }

    #[test]
    fn harmony_shared_accounting_is_atomic_across_concurrent_sockets() {
        let mut shared_limits = limits();
        shared_limits.max_concurrent_sockets = 2;
        shared_limits.max_frames = 1;
        shared_limits.max_logical_inputs = 2;
        shared_limits.max_hint_groups = 2;
        shared_limits.max_request_bytes = 2;
        shared_limits.max_work_units = 2;
        let (mut primary, mut complementary) = authorized_harmony_pair(shared_limits);
        let barrier = StdArc::new(Barrier::new(3));
        let primary_barrier = StdArc::clone(&barrier);
        let primary_thread = std::thread::spawn(move || {
            let request = BackendFrameV1 {
                kind: BackendFrameKindV1::HarmonyHintV2Half {
                    session_token: [4; 16],
                    side: HarmonyHintSideV1::Index,
                },
                db_id: 7,
                logical_inputs: 0,
                hint_groups: 1,
                request_bytes: 1,
                work_units: 1,
            };
            primary_barrier.wait();
            primary.permit_backend_frame(true, &request, 1_102)
        });
        let complementary_barrier = StdArc::clone(&barrier);
        let complementary_thread = std::thread::spawn(move || {
            let request = BackendFrameV1 {
                kind: BackendFrameKindV1::HarmonyHintV2Half {
                    session_token: [4; 16],
                    side: HarmonyHintSideV1::Chunk,
                },
                db_id: 7,
                logical_inputs: 0,
                hint_groups: 1,
                request_bytes: 1,
                work_units: 1,
            };
            complementary_barrier.wait();
            complementary.permit_backend_frame(true, &request, 1_102)
        });
        barrier.wait();
        let results = [
            primary_thread.join().unwrap(),
            complementary_thread.join().unwrap(),
        ];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(GateErrorV1::ResourceLimitExceeded))
                .count(),
            1
        );
    }

    #[test]
    fn harmony_attach_ttl_starts_only_after_commit_finishes() {
        let mut two_socket_limits = limits();
        two_socket_limits.max_concurrent_sockets = 2;
        two_socket_limits.max_wall_time_ms = 500;
        let (policy, key, request, resolution) = verified_harmony_half_fixture(two_socket_limits);
        let verified_policy = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &key,
            )
            .unwrap();
        let offer = verified_policy
            .offer(&request.scope_id, request.offer_id)
            .unwrap();
        let catalog = move |operation: &OperationStartV1| match operation {
            OperationStartV1::HarmonyHint { db_id: 7, .. } => Some(resolution.clone()),
            _ => None,
        };
        let committer = AcceptingTestCommitter {
            routes: Mutex::new(Vec::new()),
        };
        let registry = HarmonyAttachRegistryV1::new(1);
        let clock_calls = AtomicUsize::new(0);
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        gate.secure_channel_established();
        gate.policy_served(true, request.policy_digest).unwrap();
        let result = gate.authorize_and_commit_with_harmony_registry(
            true,
            &request,
            offer,
            &catalog,
            None,
            &committer,
            Some(&registry),
            150,
            &|| {
                if clock_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    1_000
                } else {
                    1_400
                }
            },
        );
        let AuthResultV1::Granted(granted) = result else {
            panic!("authorization must succeed")
        };
        let grant = granted.harmony_attach.unwrap();
        let attach = harmony_attach_request(&request, offer, &grant);
        assert!(registry.try_attach_v1(&attach, 1_899).is_ok());
    }

    #[test]
    fn public_auth_path_binds_then_commits_before_installing_one_grant() {
        let (policy, key, request, resolution) = verified_free_fixture();
        let verified_policy = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &key,
            )
            .unwrap();
        let offer = verified_policy
            .offer(&request.scope_id, request.offer_id)
            .unwrap();
        let catalog = move |operation: &OperationStartV1| match operation {
            OperationStartV1::DpfQuery { db_id: 7 } => Some(resolution.clone()),
            _ => None,
        };
        let committer = AcceptingTestCommitter {
            routes: Mutex::new(Vec::new()),
        };
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        gate.secure_channel_established();
        gate.policy_served(true, request.policy_digest).unwrap();

        let result = gate.authorize_and_commit(
            true, &request, offer, &catalog, None, &committer, 150, 1_000,
        );
        assert!(matches!(result, AuthResultV1::Granted(_)));
        assert_eq!(
            *committer.routes.lock().unwrap(),
            vec![AdmissionMethodRouteV1::FreeOpenBestEffort]
        );
        assert_eq!(gate.granted_scope_id(), Some(request.scope_id));
        assert!(gate
            .permit_backend_frame(true, &frame(BackendFrameKindV1::DpfIndexBatch, 7), 1_001,)
            .is_ok());

        let second = gate.authorize_and_commit(
            true, &request, offer, &catalog, None, &committer, 150, 1_002,
        );
        assert_eq!(
            second,
            rejected(AuthRejectCode::InvalidOrSpent, 0),
            "one committed entitlement cannot authorize a second operation"
        );
    }

    #[test]
    fn missing_method_adapter_never_installs_a_grant() {
        let (policy, key, request, resolution) = verified_free_fixture();
        let verified_policy = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &key,
            )
            .unwrap();
        let offer = verified_policy
            .offer(&request.scope_id, request.offer_id)
            .unwrap();
        let catalog = move |operation: &OperationStartV1| match operation {
            OperationStartV1::DpfQuery { db_id: 7 } => Some(resolution.clone()),
            _ => None,
        };
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        gate.secure_channel_established();
        gate.policy_served(true, request.policy_digest).unwrap();
        assert_eq!(
            gate.authorize_and_commit(
                true,
                &request,
                offer,
                &catalog,
                None,
                &RejectAllAdmissionMethodsV1,
                150,
                1_000,
            ),
            rejected(AuthRejectCode::UnsupportedScheme, 0)
        );
        assert_eq!(gate.granted_scope_id(), None);
        assert_eq!(
            gate.permit_backend_frame(true, &frame(BackendFrameKindV1::DpfIndexBatch, 7), 1_001,),
            Err(GateErrorV1::AuthorizationRequired)
        );
    }

    #[test]
    fn unknown_wall_clock_never_reaches_or_commits_an_adapter() {
        let (policy, key, request, resolution) = verified_free_fixture();
        let verified_policy = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &key,
            )
            .unwrap();
        let offer = verified_policy
            .offer(&request.scope_id, request.offer_id)
            .unwrap();
        let catalog = move |operation: &OperationStartV1| match operation {
            OperationStartV1::DpfQuery { db_id: 7 } => Some(resolution.clone()),
            _ => None,
        };
        let committer = AcceptingTestCommitter {
            routes: Mutex::new(Vec::new()),
        };
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        gate.secure_channel_established();
        gate.policy_served(true, request.policy_digest).unwrap();

        assert_eq!(
            gate.authorize_and_commit(true, &request, offer, &catalog, None, &committer, 0, 1_000,),
            rejected(AuthRejectCode::ScopeUnavailable, 0)
        );
        assert!(committer.routes.lock().unwrap().is_empty());
        assert_eq!(gate.granted_scope_id(), None);
    }

    #[test]
    fn store_error_mapping_separates_precommit_failures_from_commit_ambiguity() {
        assert_eq!(
            map_provider_store_commit_error(StoreError::Io(std::io::Error::other("pre-commit"))),
            AdmissionCommitErrorV1::ServerBusy {
                retry_after_ms: 1_000
            }
        );
        assert_eq!(
            map_provider_store_commit_error(StoreError::NamespaceMissing),
            AdmissionCommitErrorV1::ScopeUnavailable
        );
        assert_eq!(
            map_provider_store_commit_error(StoreError::RollbackAuthorityProtocol(
                "invalid floor".to_owned()
            )),
            AdmissionCommitErrorV1::ScopeUnavailable
        );
        assert_eq!(
            map_provider_store_commit_error(StoreError::CashuCustodyRetirementEvidenceConflict),
            AdmissionCommitErrorV1::ScopeUnavailable
        );
        assert_eq!(
            map_provider_store_commit_error(StoreError::InternalAfterSpend {
                read_back: pir_service_store::SpendReadBack::Present,
                database_error: "commit outcome ambiguous".to_owned(),
            }),
            AdmissionCommitErrorV1::InternalAfterSpend
        );
        assert_eq!(
            map_provider_store_commit_error(StoreError::UnanchoredCommit {
                store_generation: 7,
                authority_error: "anchor unavailable after commit".to_owned(),
            }),
            AdmissionCommitErrorV1::InternalAfterSpend
        );
    }

    #[test]
    fn service_wire_decoder_is_strict_and_does_not_capture_other_opcodes() {
        assert_eq!(
            ServiceWireRequestV1::decode_inner_payload(&[
                REQ_SERVICE_POLICY_V1,
                pir_service_protocol::SERVICE_PROTOCOL_VERSION,
            ])
            .unwrap(),
            Some(ServiceWireRequestV1::Policy(
                ServicePolicyRequestV1::Current
            ))
        );
        assert!(ServiceWireRequestV1::decode_inner_payload(&[REQ_SERVICE_POLICY_V1]).is_err());
        assert!(ServiceWireRequestV1::decode_inner_payload(&[
            REQ_SERVICE_POLICY_V1,
            pir_service_protocol::SERVICE_PROTOCOL_VERSION,
            0,
        ])
        .is_err());
        let retained = ServicePolicyRequestV1::retained([9; 32]).unwrap().encode();
        let mut retained_payload = vec![REQ_SERVICE_POLICY_V1];
        retained_payload.extend_from_slice(&retained);
        assert_eq!(
            ServiceWireRequestV1::decode_inner_payload(&retained_payload).unwrap(),
            Some(ServiceWireRequestV1::Policy(
                ServicePolicyRequestV1::Retained {
                    policy_digest: [9; 32],
                }
            ))
        );
        assert_eq!(
            ServiceWireRequestV1::decode_inner_payload(&[0x00]).unwrap(),
            None
        );

        let auth = AuthBeginV1 {
            policy_digest: [1; 32],
            scope_id: [2; 32],
            offer_id: 3,
            scheme: AuthScheme::FreeV1,
            key_id: Vec::new(),
            operation: OperationStartV1::DpfQuery { db_id: 4 },
            proof: Vec::new(),
        };
        let mut payload = vec![REQ_AUTH_BEGIN_V1];
        payload.extend_from_slice(&auth.encode_padded().unwrap());
        assert_eq!(
            ServiceWireRequestV1::decode_inner_payload(&payload).unwrap(),
            Some(ServiceWireRequestV1::Auth(Box::new(auth)))
        );
        payload.pop();
        assert!(ServiceWireRequestV1::decode_inner_payload(&payload).is_err());
    }

    #[test]
    fn service_wire_debug_keeps_nested_auth_proof_redacted() {
        let raw_proof = b"service-wire-auth-proof-debug-canary".to_vec();
        let request = ServiceWireRequestV1::Auth(Box::new(AuthBeginV1 {
            policy_digest: [1; 32],
            scope_id: [2; 32],
            offer_id: 3,
            scheme: AuthScheme::BitcoinPirCashuBatV1,
            key_id: b"public-key-id".to_vec(),
            operation: OperationStartV1::DpfQuery { db_id: 4 },
            proof: raw_proof.clone(),
        }));

        let rendered = format!("{request:?}");

        assert!(rendered.contains("ServiceWireRequestV1::Auth"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&format!("{raw_proof:?}")));
    }

    #[test]
    fn auth_result_uses_standard_outer_record_framing() {
        let response = rejected(AuthRejectCode::ScopeUnavailable, 42);
        let encoded = encode_auth_result_response_v1(&response).unwrap();
        let declared = u32::from_le_bytes(encoded[..4].try_into().unwrap()) as usize;
        assert_eq!(declared, encoded.len() - 4);
        assert_eq!(encoded[4], RESP_AUTH_RESULT_V1);
        assert_eq!(AuthResultV1::decode(&encoded[5..]).unwrap(), response);
    }

    #[test]
    fn secure_channel_and_policy_transitions_do_not_create_a_grant() {
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        let query = frame(BackendFrameKindV1::DpfIndexBatch, 0);
        assert_eq!(
            gate.permit_backend_frame(true, &query, 0),
            Err(GateErrorV1::SecureChannelRequired)
        );
        assert_eq!(
            gate.policy_served(true, [1; 32]),
            Err(GateErrorV1::SecureChannelRequired)
        );
        gate.secure_channel_established();
        assert_eq!(
            gate.permit_backend_frame(true, &query, 0),
            Err(GateErrorV1::PolicyRequired)
        );
        assert_eq!(
            gate.policy_served(false, [1; 32]),
            Err(GateErrorV1::SecureChannelRequired)
        );
        gate.policy_served(true, [1; 32]).unwrap();
        assert_eq!(
            gate.permit_backend_frame(true, &query, 0),
            Err(GateErrorV1::AuthorizationRequired)
        );
    }

    #[test]
    fn current_to_retained_transition_rejects_request_or_verified_digest_mismatch() {
        let (policy, key, mut request, resolution) = verified_free_fixture();
        let verified = policy
            .verify_current_for_acquisition(
                &policy.provider_id,
                150,
                &PolicyRollbackGuardV1::initial(),
                &ServicePolicyEpochFloorsV1::initial(),
                &key,
            )
            .unwrap();
        let offer = verified.offer(&request.scope_id, request.offer_id).unwrap();
        let catalog = move |_operation: &OperationStartV1| Some(resolution.clone());
        let committer = AcceptingTestCommitter {
            routes: Mutex::new(Vec::new()),
        };
        let retained_digest = [8; 32];
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        gate.secure_channel_established();
        gate.policy_served(true, request.policy_digest).unwrap();
        gate.policy_served(true, retained_digest).unwrap();

        assert!(matches!(
            gate.authorize_and_commit(
                true, &request, offer, &catalog, None, &committer, 150, 1_000,
            ),
            AuthResultV1::Rejected(AuthRejectedV1 {
                code: AuthRejectCode::PolicyChanged,
                ..
            })
        ));

        request.policy_digest = retained_digest;
        assert!(matches!(
            gate.authorize_and_commit(
                true, &request, offer, &catalog, None, &committer, 150, 1_000,
            ),
            AuthResultV1::Rejected(AuthRejectedV1 {
                code: AuthRejectCode::PolicyChanged,
                ..
            })
        ));
        assert!(committer.routes.lock().unwrap().is_empty());
    }

    #[test]
    fn transport_reassembly_limit_exists_only_for_an_active_grant() {
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        assert_eq!(gate.active_request_byte_limit(), None);
        gate.install_committed_grant_for_test(
            [7; 32],
            OperationStartV1::TeeOramQuery { db_id: 0 },
            limits(),
            1_000,
        );
        assert_eq!(
            gate.active_request_byte_limit(),
            Some(limits().max_request_bytes)
        );
        let _permit = gate
            .permit_backend_frame(true, &frame(BackendFrameKindV1::TeeOramQuery, 0), 1_001)
            .unwrap();
        assert_eq!(
            gate.active_request_byte_limit(),
            None,
            "a completed one-shot grant cannot authorize another chunk upload"
        );
    }

    #[test]
    fn explicit_legacy_mode_is_never_a_v1_grant() {
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::ExplicitLegacyMode);
        gate.secure_channel_established();
        gate.policy_served(true, [1; 32]).unwrap();
        assert_eq!(
            gate.permit_backend_frame(true, &frame(BackendFrameKindV1::DpfIndexBatch, 0), 1,),
            Err(GateErrorV1::ExplicitLegacyMode)
        );
    }

    #[test]
    fn every_operation_rejects_cleartext_backend_frames() {
        let operations = [
            OperationStartV1::DpfQuery { db_id: 1 },
            OperationStartV1::HarmonyHint {
                db_id: 1,
                transport: HintTransport::V2Full,
                session_token: None,
                primary_side: None,
            },
            OperationStartV1::HarmonyQuery { db_id: 1 },
            OperationStartV1::OnionSession { db_id: 1 },
            OperationStartV1::TeeOramQuery { db_id: 1 },
        ];
        let frames = [
            BackendFrameKindV1::DpfIndexBatch,
            BackendFrameKindV1::HarmonyHintV2Full,
            BackendFrameKindV1::HarmonyLegacySingleQuery,
            BackendFrameKindV1::OnionRegisterKeys,
            BackendFrameKindV1::TeeOramQuery,
        ];
        for (operation, kind) in operations.into_iter().zip(frames) {
            let mut gate = granted(operation);
            let mut valid_frame = frame(kind, 1);
            if matches!(valid_frame.kind, BackendFrameKindV1::HarmonyHintV2Full) {
                valid_frame.logical_inputs = 0;
                valid_frame.hint_groups = 1;
            }
            assert_eq!(
                gate.permit_backend_frame(false, &valid_frame, 1_001),
                Err(GateErrorV1::SecureChannelRequired)
            );
            assert_eq!(
                gate.permit_backend_frame(true, &valid_frame, 1_002),
                Err(GateErrorV1::TerminalAfterSpend),
                "a cleartext attempt after commit permanently closes the grant"
            );
        }
    }

    #[test]
    fn dpf_grant_accepts_only_dpf_frames_for_exact_database() {
        let mut gate = granted(OperationStartV1::DpfQuery { db_id: 3 });
        assert!(gate
            .permit_backend_frame(true, &frame(BackendFrameKindV1::DpfIndexBatch, 3), 1_001,)
            .is_ok());
        for (offset, kind) in [
            BackendFrameKindV1::DpfChunkBatch,
            BackendFrameKindV1::DpfMerkleSiblingBatch,
        ]
        .into_iter()
        .enumerate()
        {
            let followup = BackendFrameV1 {
                logical_inputs: 0,
                ..frame(kind, 3)
            };
            assert!(gate
                .permit_backend_frame(true, &followup, 1_002 + offset as u64)
                .is_ok());
        }
        assert_eq!(gate.usage().unwrap().logical_inputs, 1);

        let mut wrong_db = granted(OperationStartV1::DpfQuery { db_id: 3 });
        assert_eq!(
            wrong_db.permit_backend_frame(
                true,
                &frame(BackendFrameKindV1::DpfIndexBatch, 4),
                1_001,
            ),
            Err(GateErrorV1::OperationMismatch)
        );
        let mut wrong_backend = granted(OperationStartV1::DpfQuery { db_id: 3 });
        assert_eq!(
            wrong_backend.permit_backend_frame(
                true,
                &frame(BackendFrameKindV1::HarmonyLegacySingleQuery, 3),
                1_001,
            ),
            Err(GateErrorV1::OperationMismatch)
        );
    }

    #[test]
    fn dpf_followups_require_index_and_second_index_exhausts_one_job_grant() {
        for kind in [
            BackendFrameKindV1::DpfChunkBatch,
            BackendFrameKindV1::DpfMerkleSiblingBatch,
        ] {
            let mut gate = granted(OperationStartV1::DpfQuery { db_id: 3 });
            let followup = BackendFrameV1 {
                logical_inputs: 0,
                ..frame(kind, 3)
            };
            assert_eq!(
                gate.permit_backend_frame(true, &followup, 1_001),
                Err(GateErrorV1::OperationSequence),
            );
            assert_eq!(
                gate.permit_backend_frame(
                    true,
                    &frame(BackendFrameKindV1::DpfIndexBatch, 3),
                    1_002,
                ),
                Err(GateErrorV1::TerminalAfterSpend),
            );
        }

        let mut one_job_limits = limits();
        one_job_limits.max_logical_inputs = 1;
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        gate.install_committed_grant_for_test(
            [7; 32],
            OperationStartV1::DpfQuery { db_id: 3 },
            one_job_limits,
            1_000,
        );
        assert!(gate
            .permit_backend_frame(true, &frame(BackendFrameKindV1::DpfIndexBatch, 3), 1_001,)
            .is_ok());
        assert_eq!(gate.usage().unwrap().logical_inputs, 1);
        assert_eq!(
            gate.permit_backend_frame(true, &frame(BackendFrameKindV1::DpfIndexBatch, 3), 1_002,),
            Err(GateErrorV1::ResourceLimitExceeded),
        );
        assert_eq!(
            gate.permit_backend_frame(
                true,
                &BackendFrameV1 {
                    logical_inputs: 0,
                    ..frame(BackendFrameKindV1::DpfChunkBatch, 3)
                },
                1_003,
            ),
            Err(GateErrorV1::TerminalAfterSpend),
        );
    }

    #[test]
    fn dpf_rejects_index_rollback_after_chunk_or_merkle_followup() {
        for followup_kind in [
            BackendFrameKindV1::DpfChunkBatch,
            BackendFrameKindV1::DpfMerkleSiblingBatch,
        ] {
            let mut roomy = limits();
            roomy.max_frames = 8;
            roomy.max_work_units = 32;
            let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
            gate.install_committed_grant_for_test(
                [7; 32],
                OperationStartV1::DpfQuery { db_id: 3 },
                roomy,
                1_000,
            );
            assert!(gate
                .permit_backend_frame(true, &frame(BackendFrameKindV1::DpfIndexBatch, 3), 1_001,)
                .is_ok());
            assert!(gate
                .permit_backend_frame(
                    true,
                    &BackendFrameV1 {
                        logical_inputs: 0,
                        ..frame(followup_kind, 3)
                    },
                    1_002,
                )
                .is_ok());
            assert_eq!(
                gate.permit_backend_frame(
                    true,
                    &frame(BackendFrameKindV1::DpfIndexBatch, 3),
                    1_003,
                ),
                Err(GateErrorV1::OperationSequence)
            );
            assert_eq!(
                gate.permit_backend_frame(
                    true,
                    &BackendFrameV1 {
                        logical_inputs: 0,
                        ..frame(BackendFrameKindV1::DpfChunkBatch, 3)
                    },
                    1_004,
                ),
                Err(GateErrorV1::TerminalAfterSpend)
            );
        }
    }

    #[test]
    fn harmony_hint_and_query_grants_are_not_interchangeable() {
        let mut hint = granted(OperationStartV1::HarmonyHint {
            db_id: 2,
            transport: HintTransport::V2Full,
            session_token: None,
            primary_side: None,
        });
        assert_eq!(
            hint.permit_backend_frame(
                true,
                &frame(BackendFrameKindV1::HarmonyLegacySingleQuery, 2),
                1_001,
            ),
            Err(GateErrorV1::OperationMismatch)
        );
        let mut hint = granted(OperationStartV1::HarmonyHint {
            db_id: 2,
            transport: HintTransport::V2Full,
            session_token: None,
            primary_side: None,
        });
        assert!(hint
            .permit_backend_frame(
                true,
                &BackendFrameV1 {
                    logical_inputs: 0,
                    hint_groups: 8,
                    ..frame(BackendFrameKindV1::HarmonyHintV2Full, 2)
                },
                1_001,
            )
            .is_ok());

        let mut query = granted(OperationStartV1::HarmonyQuery { db_id: 2 });
        assert_eq!(
            query.permit_backend_frame(
                true,
                &BackendFrameV1 {
                    logical_inputs: 0,
                    hint_groups: 8,
                    ..frame(BackendFrameKindV1::HarmonyHintV2Full, 2)
                },
                1_001,
            ),
            Err(GateErrorV1::OperationMismatch)
        );
    }

    #[test]
    fn harmony_v2_full_main_then_cold_cache_siblings_stays_bounded_and_ordered() {
        let mut roomy = limits();
        roomy.max_frames = 8;
        roomy.max_hint_groups = 32;
        roomy.max_work_units = 32;
        let mut hint = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        hint.install_committed_grant_for_test(
            [7; 32],
            OperationStartV1::HarmonyHint {
                db_id: 2,
                transport: HintTransport::V2Full,
                session_token: None,
                primary_side: None,
            },
            roomy,
            1_000,
        );
        let main = BackendFrameV1 {
            logical_inputs: 0,
            hint_groups: 8,
            ..frame(BackendFrameKindV1::HarmonyHintV2Full, 2)
        };
        assert!(hint.permit_backend_frame(true, &main, 1_001).is_ok());

        let sibling = |level| BackendFrameV1 {
            kind: BackendFrameKindV1::HarmonyHintLegacyV1 {
                level,
                index_sibling_levels: 2,
                chunk_sibling_levels: 1,
                expected_groups: 3,
            },
            db_id: 2,
            logical_inputs: 0,
            hint_groups: 3,
            request_bytes: 100,
            work_units: 3,
        };
        for (offset, level) in [10, 11, 20].into_iter().enumerate() {
            assert!(hint
                .permit_backend_frame(true, &sibling(level), 1_002 + offset as u64)
                .is_ok());
        }
        assert_eq!(hint.usage().unwrap().hint_groups, 17);

        let mut repeated_main = granted(OperationStartV1::HarmonyHint {
            db_id: 2,
            transport: HintTransport::V2Full,
            session_token: None,
            primary_side: None,
        });
        assert!(repeated_main
            .permit_backend_frame(true, &main, 1_001)
            .is_ok());
        assert_eq!(
            repeated_main.permit_backend_frame(true, &main, 1_002),
            Err(GateErrorV1::OperationSequence)
        );

        let mut hint = granted(OperationStartV1::HarmonyHint {
            db_id: 2,
            transport: HintTransport::V2Full,
            session_token: None,
            primary_side: None,
        });
        assert_eq!(
            hint.permit_backend_frame(true, &sibling(10), 1_001),
            Err(GateErrorV1::OperationSequence)
        );
        assert_eq!(
            hint.permit_backend_frame(true, &main, 1_002),
            Err(GateErrorV1::TerminalAfterSpend)
        );

        let mut skipped = granted(OperationStartV1::HarmonyHint {
            db_id: 2,
            transport: HintTransport::V2Full,
            session_token: None,
            primary_side: None,
        });
        assert!(skipped.permit_backend_frame(true, &main, 1_001).is_ok());
        assert_eq!(
            skipped.permit_backend_frame(true, &sibling(11), 1_002),
            Err(GateErrorV1::OperationSequence)
        );
    }

    #[test]
    fn harmony_half_binds_token_side_and_is_one_shot() {
        let operation = OperationStartV1::HarmonyHint {
            db_id: 2,
            transport: HintTransport::V2Half,
            session_token: Some([4; 16]),
            primary_side: Some(HarmonyHintSideV1::Index),
        };
        let mut wrong_side = granted(operation.clone());
        assert_eq!(
            wrong_side.permit_backend_frame(
                true,
                &BackendFrameV1 {
                    logical_inputs: 0,
                    hint_groups: 2,
                    ..frame(
                        BackendFrameKindV1::HarmonyHintV2Half {
                            session_token: [4; 16],
                            side: HarmonyHintSideV1::Chunk,
                        },
                        2,
                    )
                },
                1_001,
            ),
            Err(GateErrorV1::OperationMismatch)
        );
        let mut gate = granted(operation);
        let exact = BackendFrameV1 {
            logical_inputs: 0,
            hint_groups: 2,
            ..frame(
                BackendFrameKindV1::HarmonyHintV2Half {
                    session_token: [4; 16],
                    side: HarmonyHintSideV1::Index,
                },
                2,
            )
        };
        assert!(gate.permit_backend_frame(true, &exact, 1_001).is_ok());
        assert_eq!(
            gate.permit_backend_frame(true, &exact, 1_002),
            Err(GateErrorV1::AuthorizationAlreadyUsed)
        );
    }

    #[test]
    fn harmony_half_operation_encoding_has_no_peer_or_pair_identity() {
        let index = OperationStartV1::HarmonyHint {
            db_id: 2,
            transport: HintTransport::V2Half,
            session_token: Some([4; 16]),
            primary_side: Some(HarmonyHintSideV1::Index),
        };
        let chunk = OperationStartV1::HarmonyHint {
            db_id: 2,
            transport: HintTransport::V2Half,
            session_token: Some([4; 16]),
            primary_side: Some(HarmonyHintSideV1::Chunk),
        };
        let mut expected = vec![2, 2, HintTransport::V2Half as u8];
        expected.extend_from_slice(&[4; 16]);
        expected.push(HarmonyHintSideV1::Index as u8);

        assert_eq!(index.encode().unwrap(), expected);
        assert_eq!(index.encode().unwrap().len(), 20);
        assert_ne!(index.digest().unwrap(), chunk.digest().unwrap());
    }

    #[test]
    fn harmony_query_enforces_pairs_phases_rounds_and_logical_jobs() {
        let mut roomy = limits();
        roomy.max_frames = 16;
        roomy.max_logical_inputs = 4;
        roomy.max_request_bytes = 10_000;
        roomy.max_response_bytes = 10_000;
        roomy.max_work_units = 100;
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        gate.install_committed_grant_for_test(
            [7; 32],
            OperationStartV1::HarmonyQuery { db_id: 1 },
            roomy,
            1_000,
        );
        for (offset, request) in [
            harmony_batch_frame(1, 0, 0, 2, 1),
            harmony_batch_frame(1, 0, 1, 2, 1),
            harmony_batch_frame(1, 0, 2, 2, 1),
            harmony_batch_frame(1, 0, 3, 2, 1),
            harmony_batch_frame(1, 1, 0, 2, 1),
            harmony_batch_frame(1, 1, 1, 2, 1),
            harmony_batch_frame(1, 10, 0, 2, 1),
            harmony_batch_frame(1, 11, 1, 2, 1),
            harmony_batch_frame(1, 20, 100, 2, 1),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(gate
                .permit_backend_frame(true, &request, 1_001 + offset as u64)
                .is_ok());
        }
        assert_eq!(gate.usage().unwrap().logical_inputs, 2);

        let mut one_pair_limits = limits();
        one_pair_limits.max_logical_inputs = 1;
        one_pair_limits.max_frames = 8;
        one_pair_limits.max_work_units = 32;
        let mut one_pair = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        one_pair.install_committed_grant_for_test(
            [7; 32],
            OperationStartV1::HarmonyQuery { db_id: 1 },
            one_pair_limits,
            1_000,
        );
        assert!(one_pair
            .permit_backend_frame(true, &harmony_batch_frame(1, 0, 0, 1, 1), 1_001,)
            .is_ok());
        assert!(one_pair
            .permit_backend_frame(true, &harmony_batch_frame(1, 0, 1, 1, 1), 1_002,)
            .is_ok());
        assert_eq!(
            one_pair.permit_backend_frame(true, &harmony_batch_frame(1, 0, 2, 1, 1), 1_003,),
            Err(GateErrorV1::ResourceLimitExceeded),
            "N>K needs a signed profile with another logical INDEX-pair allowance",
        );

        for invalid in [
            harmony_batch_frame(1, 0, 2, 1, 1),
            harmony_batch_frame(1, 1, 0, 1, 1),
            harmony_batch_frame(1, 10, 0, 1, 1),
        ] {
            let mut failed = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
            let mut roomy = limits();
            roomy.max_frames = 8;
            roomy.max_work_units = 32;
            failed.install_committed_grant_for_test(
                [7; 32],
                OperationStartV1::HarmonyQuery { db_id: 1 },
                roomy,
                1_000,
            );
            assert!(failed
                .permit_backend_frame(true, &harmony_batch_frame(1, 0, 0, 1, 1), 1_001,)
                .is_ok());
            assert_eq!(
                failed.permit_backend_frame(true, &invalid, 1_002),
                Err(GateErrorV1::OperationSequence)
            );
            assert_eq!(
                failed.permit_backend_frame(true, &harmony_batch_frame(1, 0, 1, 1, 1), 1_003,),
                Err(GateErrorV1::TerminalAfterSpend)
            );
        }
    }

    #[test]
    fn harmony_query_v1_rejects_legacy_single_group_opcode_and_terminalizes() {
        let mut gate = granted(OperationStartV1::HarmonyQuery { db_id: 1 });
        assert_eq!(
            gate.permit_backend_frame(
                true,
                &frame(BackendFrameKindV1::HarmonyLegacySingleQuery, 1),
                1_001,
            ),
            Err(GateErrorV1::OperationMismatch)
        );
        assert_eq!(
            gate.permit_backend_frame(true, &harmony_batch_frame(1, 0, 0, 1, 1), 1_002,),
            Err(GateErrorV1::TerminalAfterSpend)
        );
    }

    #[test]
    fn oram_grant_is_one_shot() {
        let mut gate = granted(OperationStartV1::TeeOramQuery { db_id: 1 });
        let request = frame(BackendFrameKindV1::TeeOramQuery, 1);
        assert!(gate.permit_backend_frame(true, &request, 1_001).is_ok());
        assert_eq!(
            gate.permit_backend_frame(true, &request, 1_002),
            Err(GateErrorV1::AuthorizationAlreadyUsed)
        );
    }

    #[test]
    fn one_oram_grant_covers_one_multi_input_frame_but_never_a_second_frame() {
        let mut oram_limits = limits();
        oram_limits.max_logical_inputs = 25;
        oram_limits.max_frames = 1;
        oram_limits.max_work_units = 25;
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        gate.install_committed_grant_for_test(
            [7; 32],
            OperationStartV1::TeeOramQuery { db_id: 1 },
            oram_limits,
            1_000,
        );
        let atomic_group = BackendFrameV1 {
            logical_inputs: 25,
            work_units: 25,
            ..frame(BackendFrameKindV1::TeeOramQuery, 1)
        };
        assert!(gate
            .permit_backend_frame(true, &atomic_group, 1_001)
            .is_ok());
        assert_eq!(gate.usage().unwrap().frames, 1);
        assert_eq!(gate.usage().unwrap().logical_inputs, 25);
        assert_eq!(
            gate.permit_backend_frame(true, &atomic_group, 1_002),
            Err(GateErrorV1::AuthorizationAlreadyUsed),
            "an atomic ORAM entitlement must never authorize a second query frame",
        );
    }

    #[test]
    fn onion_enforces_register_index_chunk_merkle_sequence_and_terminalizes() {
        let mut gate = granted(OperationStartV1::OnionSession { db_id: 5 });
        assert_eq!(
            gate.permit_backend_frame(
                true,
                &onion_frame(BackendFrameKindV1::OnionIndexQuery { round_id: 0 }, 5),
                1_001,
            ),
            Err(GateErrorV1::OperationSequence)
        );

        let mut roomy = limits();
        roomy.max_frames = 8;
        roomy.max_work_units = 32;
        let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        gate.install_committed_grant_for_test(
            [7; 32],
            OperationStartV1::OnionSession { db_id: 5 },
            roomy,
            1_000,
        );
        let sequence = [
            onion_frame(BackendFrameKindV1::OnionRegisterKeys, 5),
            onion_frame(BackendFrameKindV1::OnionIndexQuery { round_id: 0 }, 5),
            onion_frame(BackendFrameKindV1::OnionIndexQuery { round_id: 1 }, 5),
            onion_frame(BackendFrameKindV1::OnionChunkQuery { round_id: 0 }, 5),
            onion_frame(
                BackendFrameKindV1::OnionMerkleIndexSibling { round_id: 0 },
                5,
            ),
            onion_frame(
                BackendFrameKindV1::OnionMerkleDataSibling { round_id: 0 },
                5,
            ),
        ];
        for (offset, request) in sequence.iter().enumerate() {
            assert!(gate
                .permit_backend_frame(true, request, 1_001 + offset as u64)
                .is_ok());
        }
        assert_eq!(gate.usage().unwrap().logical_inputs, 2);

        assert_eq!(
            gate.permit_backend_frame(
                true,
                &onion_frame(BackendFrameKindV1::OnionRegisterKeys, 5),
                1_010,
            ),
            Err(GateErrorV1::OperationSequence)
        );
        assert_eq!(
            gate.permit_backend_frame(
                true,
                &onion_frame(
                    BackendFrameKindV1::OnionMerkleDataSibling { round_id: 0 },
                    5,
                ),
                1_011,
            ),
            Err(GateErrorV1::TerminalAfterSpend)
        );

        for skipped in [
            BackendFrameKindV1::OnionIndexQuery { round_id: 1 },
            BackendFrameKindV1::OnionChunkQuery { round_id: 0 },
            BackendFrameKindV1::OnionMerkleIndexSibling { round_id: 0 },
        ] {
            let mut failed = granted(OperationStartV1::OnionSession { db_id: 5 });
            assert!(failed
                .permit_backend_frame(
                    true,
                    &onion_frame(BackendFrameKindV1::OnionRegisterKeys, 5),
                    1_001,
                )
                .is_ok());
            assert_eq!(
                failed.permit_backend_frame(true, &onion_frame(skipped, 5), 1_002),
                Err(GateErrorV1::OperationSequence)
            );
        }

        let mut roomy = limits();
        roomy.max_frames = 8;
        roomy.max_work_units = 32;
        let mut rollback = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
        rollback.install_committed_grant_for_test(
            [7; 32],
            OperationStartV1::OnionSession { db_id: 5 },
            roomy,
            1_000,
        );
        for (offset, request) in sequence.iter().enumerate() {
            assert!(rollback
                .permit_backend_frame(true, request, 1_001 + offset as u64)
                .is_ok());
        }
        assert_eq!(
            rollback.permit_backend_frame(
                true,
                &onion_frame(
                    BackendFrameKindV1::OnionMerkleIndexSibling { round_id: 0 },
                    5,
                ),
                1_010,
            ),
            Err(GateErrorV1::OperationSequence)
        );
        assert_eq!(
            rollback.permit_backend_frame(
                true,
                &onion_frame(
                    BackendFrameKindV1::OnionMerkleDataSibling { round_id: 0 },
                    5,
                ),
                1_011,
            ),
            Err(GateErrorV1::TerminalAfterSpend)
        );
    }

    #[test]
    fn every_counter_is_checked_before_work() {
        let cases = [
            (
                OperationStartV1::TeeOramQuery { db_id: 0 },
                BackendFrameV1 {
                    logical_inputs: 9,
                    ..frame(BackendFrameKindV1::TeeOramQuery, 0)
                },
            ),
            (
                OperationStartV1::DpfQuery { db_id: 0 },
                BackendFrameV1 {
                    request_bytes: 1_001,
                    ..frame(BackendFrameKindV1::DpfIndexBatch, 0)
                },
            ),
            (
                OperationStartV1::DpfQuery { db_id: 0 },
                BackendFrameV1 {
                    work_units: 13,
                    ..frame(BackendFrameKindV1::DpfIndexBatch, 0)
                },
            ),
        ];
        for (operation, request) in cases {
            let mut gate = granted(operation);
            assert_eq!(
                gate.permit_backend_frame(true, &request, 1_001),
                Err(GateErrorV1::ResourceLimitExceeded)
            );
            assert_eq!(gate.usage(), None);
            assert_eq!(
                gate.permit_backend_frame(
                    true,
                    &frame(BackendFrameKindV1::DpfIndexBatch, 0),
                    1_002
                ),
                Err(GateErrorV1::TerminalAfterSpend),
                "a post-consumption limit failure cannot be retried on the same grant"
            );
        }

        let mut hints = granted(OperationStartV1::HarmonyHint {
            db_id: 0,
            transport: HintTransport::V2Full,
            session_token: None,
            primary_side: None,
        });
        assert_eq!(
            hints.permit_backend_frame(
                true,
                &BackendFrameV1 {
                    logical_inputs: 0,
                    hint_groups: 9,
                    ..frame(BackendFrameKindV1::HarmonyHintV2Full, 0)
                },
                1_001,
            ),
            Err(GateErrorV1::ResourceLimitExceeded)
        );
    }

    #[test]
    fn frame_count_expiry_and_response_budget_are_enforced() {
        let mut gate = granted(OperationStartV1::DpfQuery { db_id: 0 });
        for _ in 0..4 {
            assert!(gate
                .permit_backend_frame(
                    true,
                    &BackendFrameV1 {
                        logical_inputs: 1,
                        work_units: 1,
                        request_bytes: 1,
                        ..frame(BackendFrameKindV1::DpfIndexBatch, 0)
                    },
                    1_001,
                )
                .is_ok());
        }
        assert!(gate.reserve_response_bytes(2_000).is_ok());
        assert_eq!(
            gate.permit_backend_frame(
                true,
                &BackendFrameV1 {
                    logical_inputs: 1,
                    work_units: 1,
                    request_bytes: 1,
                    ..frame(BackendFrameKindV1::DpfIndexBatch, 0)
                },
                1_001,
            ),
            Err(GateErrorV1::ResourceLimitExceeded)
        );
        assert_eq!(
            gate.reserve_response_bytes(1),
            Err(GateErrorV1::TerminalAfterSpend)
        );

        let mut response_overflow = granted(OperationStartV1::HarmonyQuery { db_id: 0 });
        assert!(response_overflow
            .permit_backend_frame(true, &harmony_batch_frame(0, 0, 0, 1, 1), 1_001,)
            .is_ok());
        assert_eq!(
            response_overflow.reserve_response_bytes(2_001),
            Err(GateErrorV1::ResourceLimitExceeded)
        );
        assert_eq!(
            response_overflow.reserve_response_bytes(1),
            Err(GateErrorV1::TerminalAfterSpend)
        );

        let mut expired = granted(OperationStartV1::DpfQuery { db_id: 0 });
        assert_eq!(
            expired
                .permit_backend_frame(true, &frame(BackendFrameKindV1::DpfIndexBatch, 0), 1_500,),
            Err(GateErrorV1::GrantExpired)
        );
    }

    #[test]
    fn malformed_runtime_metadata_fails_closed() {
        let mut gate = granted(OperationStartV1::DpfQuery { db_id: 0 });
        assert_eq!(
            gate.permit_backend_frame(
                true,
                &BackendFrameV1 {
                    request_bytes: 0,
                    ..frame(BackendFrameKindV1::DpfIndexBatch, 0)
                },
                1_001,
            ),
            Err(GateErrorV1::InvalidFrameMetadata)
        );
        let mut gate = granted(OperationStartV1::DpfQuery { db_id: 0 });
        assert_eq!(
            gate.permit_backend_frame(
                true,
                &BackendFrameV1 {
                    hint_groups: 1,
                    ..frame(BackendFrameKindV1::DpfIndexBatch, 0)
                },
                1_001,
            ),
            Err(GateErrorV1::InvalidFrameMetadata)
        );

        let mut undecodable = granted(OperationStartV1::DpfQuery { db_id: 0 });
        assert_eq!(
            undecodable.reject_malformed_backend_frame(true),
            GateErrorV1::InvalidFrameMetadata
        );
        assert_eq!(
            undecodable.permit_backend_frame(
                true,
                &frame(BackendFrameKindV1::DpfIndexBatch, 0),
                1_002,
            ),
            Err(GateErrorV1::TerminalAfterSpend)
        );
    }
}
