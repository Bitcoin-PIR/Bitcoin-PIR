//! Strict service admission runtime state extracted from `unified_server.rs`
//! (legacy payment surface; slated for removal with R4).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use pir_arc_adapter::ArcSecretKeyringV1;
use pir_cashu_client::{
    CashuCustodyExposureLimitsV1, CashuMintRouteV1, CashuMintTransportFailureKindV1,
    CashuMintTransportFailureV1, CashuMintTransportV1, CashuMintTrustV1,
    ChaCha20Poly1305CustodyCipherV1, ChaCha20Poly1305RecoveryCipherV1,
};
use pir_payment_crypto::K256CashuMintKeyringV1;
use pir_provider_clearing_client::{
    ProviderRedeemIdempotencyKeyV1, SharedIssuerAdmissionCommitterV1,
    SharedIssuerRedeemEnvelopeV1, SharedIssuerRedeemTransportV1, SharedIssuerTransportErrorV1,
};
use pir_runtime_core::harmony_attach_runtime::HarmonyAttachRegistryV1;
use pir_runtime_core::service_admission::AdmissionMethodRouteV1;
use pir_runtime_core::service_policy_runtime::{
    ActivatedRetainedServicePolicyV1, ActivatedServicePolicyV1,
};
use pir_service_protocol::{
    IssuerClearingApprovalV1, ProviderClearingAuthorizationV1, ProviderRedeemEnvelopeV1,
    ServicePolicyRequestV1, ServicePolicyResponseV1, ServicePolicyV1, ServiceProtocolError,
    VerifiedServiceOfferV1,
};
use pir_service_store::ProviderStore;
use pir_strict_https::{HttpsPostErrorV1, StrictHttpsClientV1};
use crate::unified_server_bat_v2::StorelessBatV2RuntimeConfigV2;

use zeroize::{Zeroize, Zeroizing};

pub(crate) struct StrictServiceAdmissionRuntimeV1 {
    pub(crate) policy: ActivatedServicePolicyV1,
    pub(crate) retained_policies: BTreeMap<[u8; 32], ActivatedRetainedServicePolicyV1>,
    /// Absent only for an exact-digest-pinned storeless Free-PoW or closed BAT
    /// V2 profile.
    /// Every durable quota, credential, payment, Cashu, ARC, retained-policy,
    /// or shared-issuer route requires this store at startup.
    pub(crate) provider_store: Option<ProviderStore>,
    pub(crate) trust_direct_peer_ip: bool,
    pub(crate) bat_keyring: Option<K256CashuMintKeyringV1>,
    pub(crate) experimental_arc_keyring: Option<ArcSecretKeyringV1>,
    pub(crate) cashu_recovery_cipher: Option<ChaCha20Poly1305RecoveryCipherV1>,
    pub(crate) cashu_custody_cipher: Option<ChaCha20Poly1305CustodyCipherV1>,
    pub(crate) cashu_exposure_limits: BTreeMap<([u8; 32], String), CashuCustodyExposureLimitsV1>,
    pub(crate) shared_issuer: Option<SharedIssuerRuntimeConfigV1>,
    pub(crate) storeless_bat_v2: Option<StorelessBatV2RuntimeConfigV2>,
    pub(crate) http_transport: ProviderAdmissionHttpsTransportV1,
    pub(crate) harmony_attach_registry: Arc<HarmonyAttachRegistryV1>,
    pub(crate) monotonic_origin: Instant,
}

pub(crate) struct SharedIssuerRuntimeConfigV1 {
    pub(crate) authorization: ProviderClearingAuthorizationV1,
    pub(crate) issuer_approval: IssuerClearingApprovalV1,
    pub(crate) operator_verifying_key: VerifyingKey,
    pub(crate) issuer_settlement_verifying_key: VerifyingKey,
    pub(crate) clearing_signing_key: ed25519_dalek::SigningKey,
    pub(crate) minimum_authorization_epoch: u64,
    pub(crate) idempotency_key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for SharedIssuerRuntimeConfigV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SharedIssuerRuntimeConfigV1")
            .field("provider_id", &self.authorization.claims.provider_id)
            .field("issuer_id", &self.authorization.claims.issuer_id)
            .field(
                "minimum_authorization_epoch",
                &self.minimum_authorization_epoch,
            )
            .field("clearing_signing_key", &"[REDACTED]")
            .field("idempotency_key", &"[REDACTED]")
            .finish()
    }
}

impl SharedIssuerRuntimeConfigV1 {
    pub(crate) fn committer<'a>(
        &self,
        provider_store: &ProviderStore,
        transport: &'a dyn SharedIssuerRedeemTransportV1,
    ) -> Result<SharedIssuerAdmissionCommitterV1<'a>, pir_service_protocol::ServiceProtocolError>
    {
        SharedIssuerAdmissionCommitterV1::new(
            self.authorization.clone(),
            self.issuer_approval.clone(),
            self.operator_verifying_key,
            self.issuer_settlement_verifying_key,
            self.clearing_signing_key.clone(),
            self.minimum_authorization_epoch,
            ProviderRedeemIdempotencyKeyV1::from_bytes(*self.idempotency_key)?,
            provider_store.clone(),
            transport,
        )
    }
}

#[derive(Clone)]
pub(crate) struct ProviderAdmissionHttpsTransportV1 {
    pub(crate) connect_timeout: Duration,
    pub(crate) io_timeout: Duration,
    #[cfg(feature = "standard-cashu-process-e2e")]
    pub(crate) test_only_webpki_root_pem: Option<Arc<[u8]>>,
}

impl core::fmt::Debug for ProviderAdmissionHttpsTransportV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProviderAdmissionHttpsTransportV1")
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("test_only_webpki_root_pem", &"[REDACTED]")
            .finish()
    }
}

impl ProviderAdmissionHttpsTransportV1 {
    pub(crate) fn client_for_pins(
        &self,
        leaf_spki_sha256_pins: &[[u8; 32]],
    ) -> Result<StrictHttpsClientV1, String> {
        #[cfg(feature = "standard-cashu-process-e2e")]
        if let Some(root) = self.test_only_webpki_root_pem.as_deref() {
            return StrictHttpsClientV1::new_with_leaf_spki_sha256_pins_and_test_only_webpki_root_pem(
                self.connect_timeout,
                self.io_timeout,
                leaf_spki_sha256_pins,
                root,
            );
        }
        StrictHttpsClientV1::new_with_leaf_spki_sha256_pins(
            self.connect_timeout,
            self.io_timeout,
            leaf_spki_sha256_pins,
        )
    }

    pub(crate) fn validate_trust(
        &self,
        endpoint: &str,
        leaf_spki_sha256_pins: &[[u8; 32]],
    ) -> Result<(), String> {
        StrictHttpsClientV1::validate_base_endpoint(endpoint)?;
        self.client_for_pins(leaf_spki_sha256_pins).map(|_| ())
    }
}

impl CashuMintTransportV1 for ProviderAdmissionHttpsTransportV1 {
    fn post_json(
        &self,
        trust: CashuMintTrustV1<'_>,
        route: CashuMintRouteV1,
        request_json: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, CashuMintTransportFailureV1> {
        self.client_for_pins(trust.leaf_spki_sha256_pins())
            .map_err(|_| {
                CashuMintTransportFailureV1::ambiguous(
                    CashuMintTransportFailureKindV1::Network,
                    None,
                )
            })?
            .post(
                trust.mint_endpoint(),
                route.path(),
                "application/json",
                "application/json",
                request_json,
                max_response_bytes,
            )
            .map_err(|error| match error {
                HttpsPostErrorV1::DefinitelyNotSent => CashuMintTransportFailureV1::ambiguous(
                    CashuMintTransportFailureKindV1::Network,
                    None,
                ),
                HttpsPostErrorV1::OutcomeUnknown => CashuMintTransportFailureV1::ambiguous(
                    CashuMintTransportFailureKindV1::Timeout,
                    None,
                ),
                HttpsPostErrorV1::HttpStatus { status, body } => {
                    CashuMintTransportFailureV1::from_http_status(status, body.as_slice())
                }
                HttpsPostErrorV1::InvalidResponse => CashuMintTransportFailureV1::ambiguous(
                    CashuMintTransportFailureKindV1::InvalidContentType,
                    None,
                ),
            })
    }
}

impl SharedIssuerRedeemTransportV1 for ProviderAdmissionHttpsTransportV1 {
    fn redeem(
        &self,
        envelope: SharedIssuerRedeemEnvelopeV1<'_>,
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, SharedIssuerTransportErrorV1> {
        let mut request = ProviderRedeemEnvelopeV1 {
            request: envelope.request.clone(),
            request_auth: envelope.request_auth.clone(),
            credential_binding: envelope.credential_binding.clone(),
            canonical_credential: envelope.canonical_credential.to_vec(),
        };
        let encoded = request.encode();
        request.canonical_credential.zeroize();
        let body =
            Zeroizing::new(encoded.map_err(|_| SharedIssuerTransportErrorV1::ScopeUnavailable)?);
        self.client_for_pins(envelope.redeem_leaf_spki_sha256_pins)
            .map_err(|_| SharedIssuerTransportErrorV1::ScopeUnavailable)?
            .post_with_error_content_type(
                envelope.redeem_endpoint,
                "/v1/redeems",
                "application/vnd.bitcoinpir.redeem-v1",
                "application/vnd.bitcoinpir.redeem-result-v1",
                "application/problem+json",
                &body,
                max_response_bytes,
            )
            .map_err(|error| match error {
                HttpsPostErrorV1::DefinitelyNotSent => SharedIssuerTransportErrorV1::NotSent {
                    retry_after_ms: 1_000,
                },
                HttpsPostErrorV1::HttpStatus {
                    status: 400 | 409 | 410 | 422,
                    ..
                } => SharedIssuerTransportErrorV1::InvalidOrSpent,
                HttpsPostErrorV1::HttpStatus {
                    status: 401 | 403 | 404,
                    ..
                } => SharedIssuerTransportErrorV1::ScopeUnavailable,
                HttpsPostErrorV1::OutcomeUnknown | HttpsPostErrorV1::HttpStatus { .. } => {
                    SharedIssuerTransportErrorV1::OutcomeUnknown
                }
                HttpsPostErrorV1::InvalidResponse => SharedIssuerTransportErrorV1::InvalidResponse,
            })
    }
}

impl StrictServiceAdmissionRuntimeV1 {
    pub(crate) fn all_policies(&self) -> impl Iterator<Item = &ServicePolicyV1> {
        std::iter::once(self.policy.policy()).chain(
            self.retained_policies
                .values()
                .map(ActivatedRetainedServicePolicyV1::policy),
        )
    }

    pub(crate) fn response_for_policy_request(
        &self,
        request: ServicePolicyRequestV1,
        now_unix: u64,
    ) -> Option<(ServicePolicyResponseV1, [u8; 32])> {
        match request {
            ServicePolicyRequestV1::Current => {
                self.policy.verify_current(now_unix).ok()?;
                Some((self.policy.response(), self.policy.policy_digest()))
            }
            ServicePolicyRequestV1::Retained { policy_digest } => {
                let retained = self.retained_policies.get(&policy_digest)?;
                (retained.has_live_redemption(now_unix)
                    || retained.has_live_bat_v2_redemption(now_unix))
                .then(|| (retained.response(), policy_digest))
            }
        }
    }

    pub(crate) fn policy_for_digest(&self, policy_digest: &[u8; 32]) -> Option<&ServicePolicyV1> {
        if policy_digest == &self.policy.policy_digest() {
            Some(self.policy.policy())
        } else {
            self.retained_policies
                .get(policy_digest)
                .map(ActivatedRetainedServicePolicyV1::policy)
        }
    }

    pub(crate) fn verified_offer_for_authorization(
        &self,
        policy_digest: &[u8; 32],
        scope_id: &[u8; 32],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<Option<VerifiedServiceOfferV1<'_>>, ServiceProtocolError> {
        if policy_digest == &self.policy.policy_digest() {
            return self
                .policy
                .verified_offer(scope_id, offer_id, now_unix)
                .map(Some);
        }
        let Some(retained) = self.retained_policies.get(policy_digest) else {
            return Ok(None);
        };
        let is_bat_v2 = retained.policy().scopes.iter().any(|scope_policy| {
            scope_policy.scope.scope_id() == *scope_id
                && scope_policy.offers.iter().any(|offer| {
                    offer.offer_id == offer_id
                        && offer.authorization
                            == pir_service_protocol::AuthScheme::BitcoinPirCashuBatV2
                })
        });
        if is_bat_v2 {
            retained
                .verified_bat_v2_offer_for_redemption(scope_id, offer_id, now_unix)
                .map(Some)
        } else {
            retained
                .verified_offer_for_redemption(scope_id, offer_id, now_unix)
                .map(Some)
        }
    }

    pub(crate) fn verified_bat_v2_member_for_authorization(
        &self,
        policy_digest: &[u8; 32],
        scope_id: &[u8; 32],
        offer_id: u32,
        now_unix: u64,
    ) -> Result<Option<pir_service_protocol::VerifiedBatAcceptanceMemberV2>, ServiceProtocolError>
    {
        if policy_digest == &self.policy.policy_digest() {
            return self
                .policy
                .verified_bat_v2_member_for_admission(scope_id, offer_id, now_unix)
                .map(Some);
        }
        let Some(retained) = self.retained_policies.get(policy_digest) else {
            return Ok(None);
        };
        retained
            .verified_bat_v2_member_for_redemption(scope_id, offer_id, now_unix)
            .map(Some)
    }

    pub(crate) fn supports(&self, route: AdmissionMethodRouteV1) -> bool {
        match route {
            AdmissionMethodRouteV1::FreeOpenBestEffort => self.provider_store.is_some(),
            AdmissionMethodRouteV1::FreeAnonymousTicketProviderLocal
            | AdmissionMethodRouteV1::Bolt11DirectReceiptProviderLocal => {
                self.provider_store.is_some()
            }
            // Free proof-of-work and free IP-rate-limited routes were removed
            // with the proof-of-work mechanism (R2).
            AdmissionMethodRouteV1::FreeProofOfWork | AdmissionMethodRouteV1::FreeIpRateLimited => {
                false
            }
            AdmissionMethodRouteV1::BitcoinPirCashuBatProviderLocal => {
                self.provider_store.is_some() && self.bat_keyring.is_some()
            }
            AdmissionMethodRouteV1::ArcProviderLocalExperimental => {
                self.provider_store.is_some() && self.experimental_arc_keyring.is_some()
            }
            AdmissionMethodRouteV1::StandardCashuMintOnline => {
                self.provider_store.is_some()
                    && self.cashu_recovery_cipher.is_some()
                    && self.cashu_custody_cipher.is_some()
                    && !self.cashu_exposure_limits.is_empty()
            }
            AdmissionMethodRouteV1::FreeAnonymousTicketSharedIssuerOnline
            | AdmissionMethodRouteV1::BitcoinPirCashuBatSharedIssuerOnline
            | AdmissionMethodRouteV1::ArcSharedIssuerOnlineExperimental => {
                self.provider_store.is_some() && self.shared_issuer.is_some()
            }
            AdmissionMethodRouteV1::BitcoinPirCashuBatV2SharedIssuerOnline => {
                self.provider_store.is_none() && self.storeless_bat_v2.is_some()
            }
        }
    }
}

