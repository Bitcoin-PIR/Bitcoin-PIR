//! Provider-local Free admission adapters.
//!
//! Open, IP-window, and proof-of-work modes are deliberately separate from
//! anonymous-ticket issuance. Production IP quota state is provider-local,
//! rollback-anchored persistence: restart cannot refresh quota, and a clock
//! rollback fails closed without creating a bearer entitlement.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use getrandom::getrandom;
use hmac::{Hmac, Mac};
use pir_service_protocol::{
    AuthScheme, AuthorizationProofV1, BoundAuthAttemptV1, FreeAuthorizationProofV1, FreeModeV1,
    PowChallengeRequestV1, PowChallengeResponseV1, PowChallengeStateV1, ProviderId,
    ServiceProtocolError, VerificationMode, VerifiedServiceOfferV1,
    MAX_POW_CHALLENGE_TTL_SECONDS_V1,
};
use pir_service_store::{FreeIpRateLimitRequestV1, ProviderStore, StoreError};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::service_admission::{
    AdmissionCommitErrorV1, AdmissionMethodCommitterV1, AdmissionMethodRouteV1,
};

const FREE_IP_SUBJECT_DOMAIN_V1: &[u8] = b"BitcoinPIR/free-ip-subject/v1";
pub const DEFAULT_MAX_FREE_RATE_LIMIT_BUCKETS_V1: usize = 65_536;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FreeIpSubjectKeyV1([u8; 32]);

impl core::fmt::Debug for FreeIpSubjectKeyV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("FreeIpSubjectKeyV1")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl FreeIpSubjectKeyV1 {
    pub fn from_bytes(mut key: [u8; 32]) -> Result<Self, ServiceProtocolError> {
        if key.iter().all(|byte| *byte == 0) {
            key.zeroize();
            return Err(ServiceProtocolError::InvalidValue {
                field: "FreeIpSubjectKeyV1",
                reason: "must be non-zero",
            });
        }
        Ok(Self(key))
    }

    pub fn subject(&self, provider_id: &ProviderId, ip: IpAddr) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC-SHA256 accepts every key length");
        mac.update(FREE_IP_SUBJECT_DOMAIN_V1);
        mac.update(provider_id);
        match ip {
            IpAddr::V4(value) => {
                mac.update(&[4]);
                mac.update(&value.octets());
            }
            IpAddr::V6(value) => {
                mac.update(&[6]);
                mac.update(&value.octets());
            }
        }
        mac.finalize().into_bytes().into()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RateLimitKeyV1 {
    policy_digest: [u8; 32],
    scope_id: [u8; 32],
    offer_id: u32,
    subject: [u8; 32],
    window: u64,
}

#[derive(Debug)]
pub struct FreeRateLimitStateV1 {
    buckets: Mutex<HashMap<RateLimitKeyV1, u32>>,
    max_buckets: usize,
    provider_store: Option<ProviderStore>,
}

impl Default for FreeRateLimitStateV1 {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FREE_RATE_LIMIT_BUCKETS_V1)
    }
}

impl FreeRateLimitStateV1 {
    pub fn new(max_buckets: usize) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max_buckets: max_buckets.max(1),
            provider_store: None,
        }
    }

    /// Production signed IP-rate-limited offers use this durable backend.
    pub fn provider_store(store: ProviderStore, max_buckets: usize) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max_buckets: max_buckets.max(1),
            provider_store: Some(store),
        }
    }

    pub fn is_persistent(&self) -> bool {
        self.provider_store.is_some()
    }

    fn consume(
        &self,
        policy_digest: [u8; 32],
        scope_id: [u8; 32],
        offer_id: u32,
        subject: [u8; 32],
        quota: u32,
        window_seconds: u32,
        now_unix: u64,
    ) -> Result<(), AdmissionCommitErrorV1> {
        if quota == 0 || window_seconds == 0 || now_unix == 0 {
            return Err(AdmissionCommitErrorV1::ScopeUnavailable);
        }
        if let Some(store) = self.provider_store.as_ref() {
            return match store.consume_free_ip_rate_limit_v1(FreeIpRateLimitRequestV1 {
                subject,
                policy_digest,
                scope_id,
                offer_id,
                quota,
                window_seconds,
                max_buckets: self.max_buckets,
                now_unix_seconds: now_unix,
            }) {
                Ok(()) => Ok(()),
                Err(StoreError::FreeIpQuotaExhausted) => {
                    let window_end = (now_unix / u64::from(window_seconds))
                        .saturating_add(1)
                        .saturating_mul(u64::from(window_seconds));
                    Err(AdmissionCommitErrorV1::ServerBusy {
                        retry_after_ms: window_end
                            .saturating_sub(now_unix)
                            .saturating_mul(1_000)
                            .clamp(1, u64::from(u32::MAX))
                            as u32,
                    })
                }
                Err(StoreError::FreeIpClockRollback) => {
                    Err(AdmissionCommitErrorV1::ScopeUnavailable)
                }
                Err(_) => Err(AdmissionCommitErrorV1::ScopeUnavailable),
            };
        }
        let window_seconds = u64::from(window_seconds);
        let window = now_unix / window_seconds;
        let key = RateLimitKeyV1 {
            policy_digest,
            scope_id,
            offer_id,
            subject,
            window,
        };
        let mut buckets = self
            .buckets
            .lock()
            .map_err(|_| AdmissionCommitErrorV1::ServerBusy {
                retry_after_ms: 1_000,
            })?;
        buckets.retain(|candidate, _| candidate.window.saturating_add(1) >= window);
        if !buckets.contains_key(&key) && buckets.len() >= self.max_buckets {
            return Err(AdmissionCommitErrorV1::ServerBusy {
                retry_after_ms: 1_000,
            });
        }
        let count = buckets.entry(key).or_insert(0);
        if *count >= quota {
            let window_end = window.saturating_add(1).saturating_mul(window_seconds);
            let retry_ms = window_end
                .saturating_sub(now_unix)
                .saturating_mul(1_000)
                .clamp(1, u64::from(u32::MAX)) as u32;
            return Err(AdmissionCommitErrorV1::ServerBusy {
                retry_after_ms: retry_ms,
            });
        }
        *count += 1;
        Ok(())
    }
}

struct OutstandingPowV1 {
    request: PowChallengeRequestV1,
    state: PowChallengeStateV1,
}

/// Per-connection Free adapter. `ip_subject` is absent when the transport did
/// not provide a trustworthy direct peer address (for example, an untrusted
/// forwarded header), in which case IP-rate-limited offers fail closed.
pub struct FreeAdmissionCommitterV1 {
    provider_id: ProviderId,
    secure_channel_exporter: [u8; 32],
    ip_subject: Option<[u8; 32]>,
    rate_limits: Arc<FreeRateLimitStateV1>,
    pow: Mutex<Option<OutstandingPowV1>>,
}

impl core::fmt::Debug for FreeAdmissionCommitterV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FreeAdmissionCommitterV1")
            .field("provider_id", &self.provider_id)
            .field("has_ip_subject", &self.ip_subject.is_some())
            .finish_non_exhaustive()
    }
}

impl FreeAdmissionCommitterV1 {
    pub fn new(
        provider_id: ProviderId,
        secure_channel_exporter: [u8; 32],
        ip_subject: Option<[u8; 32]>,
        rate_limits: Arc<FreeRateLimitStateV1>,
    ) -> Result<Self, ServiceProtocolError> {
        if provider_id.iter().all(|byte| *byte == 0)
            || secure_channel_exporter.iter().all(|byte| *byte == 0)
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "FreeAdmissionCommitterV1",
                reason: "provider and secure-channel exporter must be non-zero",
            });
        }
        Ok(Self {
            provider_id,
            secure_channel_exporter,
            ip_subject,
            rate_limits,
            pow: Mutex::new(None),
        })
    }

    pub fn issue_pow_challenge(
        &self,
        request: PowChallengeRequestV1,
        verified_offer: VerifiedServiceOfferV1<'_>,
        now_unix: u64,
        ttl_seconds: u64,
    ) -> Result<PowChallengeResponseV1, ServiceProtocolError> {
        let scope = verified_offer.scope();
        let offer = verified_offer.offer();
        if scope.provider_id != self.provider_id
            || request.policy_digest != verified_offer.policy_digest()
            || request.scope_id != scope.scope_id()
            || request.offer_id != offer.offer_id
            || offer.authorization != AuthScheme::FreeV1
            || offer.free_mode != FreeModeV1::ProofOfWork
            || offer.verification != VerificationMode::ProviderLocal
            || now_unix == 0
            || ttl_seconds == 0
            || ttl_seconds > MAX_POW_CHALLENGE_TTL_SECONDS_V1
        {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PowChallengeRequestV1",
                reason: "request does not match a live provider-local Free PoW offer",
            });
        }
        let mut challenge_id = [0u8; 32];
        getrandom(&mut challenge_id).map_err(|_| ServiceProtocolError::InvalidValue {
            field: "PowChallengeResponseV1.challenge_id",
            reason: "secure random challenge source is unavailable",
        })?;
        if challenge_id.iter().all(|byte| *byte == 0) {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PowChallengeResponseV1.challenge_id",
                reason: "secure random challenge source returned zero",
            });
        }
        let response = PowChallengeResponseV1 {
            provider_id: self.provider_id,
            policy_digest: request.policy_digest,
            scope_id: request.scope_id,
            offer_id: request.offer_id,
            operation_digest: request.operation_digest()?,
            secure_channel_exporter: self.secure_channel_exporter,
            challenge_id,
            difficulty_bits: offer.free_pow_difficulty_bits,
            issued_at_unix: now_unix,
            expires_at_unix: now_unix.checked_add(ttl_seconds).ok_or(
                ServiceProtocolError::InvalidValue {
                    field: "PowChallengeResponseV1.expires_at_unix",
                    reason: "challenge expiry overflow",
                },
            )?,
        };
        let mut state = PowChallengeStateV1::default();
        state.issue(response.clone(), now_unix).map_err(|_| {
            ServiceProtocolError::InvalidValue {
                field: "PowChallengeStateV1",
                reason: "challenge state rejected issuance",
            }
        })?;
        let mut outstanding = self
            .pow
            .lock()
            .map_err(|_| ServiceProtocolError::InvalidValue {
                field: "PowChallengeStateV1",
                reason: "challenge state is unavailable",
            })?;
        if outstanding.is_some() {
            return Err(ServiceProtocolError::InvalidValue {
                field: "PowChallengeStateV1",
                reason: "connection already has an outstanding challenge",
            });
        }
        *outstanding = Some(OutstandingPowV1 { request, state });
        Ok(response)
    }

    fn consume_pow(
        &self,
        attempt: &BoundAuthAttemptV1<'_>,
        now_unix: u64,
    ) -> Result<(), AdmissionCommitErrorV1> {
        let AuthorizationProofV1::Free(FreeAuthorizationProofV1::ProofOfWork(solution)) =
            attempt.proof()
        else {
            return Err(AdmissionCommitErrorV1::InvalidOrSpent);
        };
        let expected_request = PowChallengeRequestV1 {
            policy_digest: attempt.verified_offer().policy_digest(),
            scope_id: attempt.scope().scope_id(),
            offer_id: attempt.offer().offer_id,
            operation: attempt.operation().clone(),
        };
        let mut outstanding = self
            .pow
            .lock()
            .map_err(|_| AdmissionCommitErrorV1::ServerBusy {
                retry_after_ms: 1_000,
            })?;
        let entry = outstanding
            .as_mut()
            .ok_or(AdmissionCommitErrorV1::InvalidOrSpent)?;
        if entry.request != expected_request {
            return Err(AdmissionCommitErrorV1::InvalidOrSpent);
        }
        entry
            .state
            .try_consume(
                &self.provider_id,
                &entry.request,
                &self.secure_channel_exporter,
                solution,
                now_unix,
            )
            .map_err(|_| AdmissionCommitErrorV1::InvalidOrSpent)?;
        *outstanding = None;
        Ok(())
    }
}

impl AdmissionMethodCommitterV1 for FreeAdmissionCommitterV1 {
    fn verify_and_commit_v1(
        &self,
        route: AdmissionMethodRouteV1,
        attempt: &BoundAuthAttemptV1<'_>,
        now_unix_seconds: u64,
    ) -> Result<(), AdmissionCommitErrorV1> {
        match route {
            AdmissionMethodRouteV1::FreeOpenBestEffort => Ok(()),
            AdmissionMethodRouteV1::FreeIpRateLimited => {
                if !self.rate_limits.is_persistent() {
                    return Err(AdmissionCommitErrorV1::ScopeUnavailable);
                }
                self.rate_limits.consume(
                    attempt.verified_offer().policy_digest(),
                    attempt.scope().scope_id(),
                    attempt.offer().offer_id,
                    self.ip_subject
                        .ok_or(AdmissionCommitErrorV1::ScopeUnavailable)?,
                    attempt.offer().free_quota,
                    attempt.offer().free_window_seconds,
                    now_unix_seconds,
                )
            }
            AdmissionMethodRouteV1::FreeProofOfWork => self.consume_pow(attempt, now_unix_seconds),
            _ => Err(AdmissionCommitErrorV1::UnsupportedScheme),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_subject_is_stable_per_provider_and_secret() {
        let key = FreeIpSubjectKeyV1::from_bytes([1; 32]).unwrap();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(key.subject(&[2; 32], ip), key.subject(&[2; 32], ip));
        assert_ne!(key.subject(&[2; 32], ip), key.subject(&[3; 32], ip));
    }

    #[test]
    fn fixed_window_is_atomic_bounded_and_resets() {
        let state = FreeRateLimitStateV1::new(2);
        for _ in 0..2 {
            state
                .consume([9; 32], [1; 32], 1, [2; 32], 2, 60, 120)
                .unwrap();
        }
        assert!(matches!(
            state.consume([9; 32], [1; 32], 1, [2; 32], 2, 60, 120),
            Err(AdmissionCommitErrorV1::ServerBusy { .. })
        ));
        state
            .consume([9; 32], [1; 32], 1, [2; 32], 2, 60, 180)
            .unwrap();
    }
}
