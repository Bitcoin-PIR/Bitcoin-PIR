//! Process-local cross-socket continuation registry for HarmonyPIR V2 halves.
//!
//! Scarce registry capacity and random continuation material are reserved
//! before a payment capability is consumed. The reservation holds no mutex
//! across the verifier/redeemer call and is cancelled by `Drop` on every
//! pre-commit failure. After a successful commit, finalization is an
//! infallible in-place state transition. Both sockets share one usage tracker,
//! so the second half cannot double any signed entitlement limit.

use std::collections::HashMap;
use std::sync::Arc;

use getrandom::getrandom;
use parking_lot::Mutex;
use pir_service_protocol::{
    EntitlementLimitsV1, HarmonyAttachGrantV1, HarmonyAttachSlotV1, HarmonyAttachTransitionErrorV1,
    HarmonyAttachV1, HintTransport, OperationStartV1, ServiceProtocolError, VerifiedServiceOfferV1,
    MAX_HARMONY_ATTACH_TTL_MS_V1,
};

use crate::service_admission::GrantUsageV1;

pub const DEFAULT_MAX_HARMONY_ATTACH_SLOTS_V1: usize = 65_536;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SharedGrantUsageStateV1 {
    pub usage: GrantUsageV1,
    pub terminal: bool,
}

/// One operation-wide usage ledger shared by the primary and complementary
/// Harmony sockets. It contains no payment, credential or query identifier.
#[derive(Clone, Debug)]
pub(crate) struct SharedGrantUsageV1 {
    inner: Arc<Mutex<SharedGrantUsageStateV1>>,
}

impl SharedGrantUsageV1 {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SharedGrantUsageStateV1::default())),
        }
    }

    pub(crate) fn mutate<R>(&self, operation: impl FnOnce(&mut SharedGrantUsageStateV1) -> R) -> R {
        operation(&mut self.inner.lock())
    }

    pub(crate) fn snapshot(&self) -> SharedGrantUsageStateV1 {
        *self.inner.lock()
    }
}

struct WaitingHarmonyAttachV1 {
    expected: Option<HarmonyAttachV1>,
    slot: Option<HarmonyAttachSlotV1>,
    activated: bool,
    expires_at_ms: u64,
    policy_digest: [u8; 32],
    scope_id: [u8; 32],
    operation: OperationStartV1,
    limits: EntitlementLimitsV1,
    started_at_ms: u64,
    shared_usage: SharedGrantUsageV1,
}

pub struct HarmonyAttachRegistryV1 {
    slots: Mutex<HashMap<[u8; 32], WaitingHarmonyAttachV1>>,
    maximum_slots: usize,
}

impl core::fmt::Debug for HarmonyAttachRegistryV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HarmonyAttachRegistryV1")
            .field("maximum_slots", &self.maximum_slots)
            .finish_non_exhaustive()
    }
}

impl Default for HarmonyAttachRegistryV1 {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_HARMONY_ATTACH_SLOTS_V1)
    }
}

impl HarmonyAttachRegistryV1 {
    pub fn new(maximum_slots: usize) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            maximum_slots: maximum_slots.max(1),
        }
    }

    /// Reserve capacity and all fallible continuation material before the
    /// payment adapter runs. Dropping the returned value cancels the slot.
    pub fn reserve_before_commit_v1(
        &self,
        verified_offer: VerifiedServiceOfferV1<'_>,
        operation: &OperationStartV1,
        limits: &EntitlementLimitsV1,
        now_monotonic_ms: u64,
    ) -> Result<ReservedHarmonyAttachV1<'_>, ServiceProtocolError> {
        let OperationStartV1::HarmonyHint {
            db_id,
            transport: HintTransport::V2Half,
            session_token: Some(session_token),
            primary_side: Some(primary_side),
        } = operation
        else {
            return Err(invalid("operation is not a canonical Harmony V2 half"));
        };
        if limits.max_concurrent_sockets < 2 {
            return Err(invalid("Harmony V2 half requires at least two sockets"));
        }
        let ttl = limits.max_wall_time_ms.min(MAX_HARMONY_ATTACH_TTL_MS_V1);
        if ttl == 0 || now_monotonic_ms.checked_add(u64::from(ttl)).is_none() {
            return Err(invalid("Harmony attach TTL is unavailable"));
        }

        let mut slots = self.slots.lock();
        slots.retain(|_, entry| !entry.activated || entry.expires_at_ms > now_monotonic_ms);
        if slots.len() >= self.maximum_slots {
            return Err(invalid("Harmony attach registry is full"));
        }

        let mut operation_id = [0u8; 32];
        for _ in 0..8 {
            getrandom(&mut operation_id)
                .map_err(|_| invalid("secure random operation ID source is unavailable"))?;
            if operation_id.iter().any(|byte| *byte != 0) && !slots.contains_key(&operation_id) {
                break;
            }
            operation_id = [0; 32];
        }
        if operation_id.iter().all(|byte| *byte == 0) {
            return Err(invalid("could not allocate unique Harmony operation ID"));
        }
        let mut attach_secret = [0u8; 32];
        getrandom(&mut attach_secret)
            .map_err(|_| invalid("secure random attach-secret source is unavailable"))?;
        if attach_secret.iter().all(|byte| *byte == 0) {
            return Err(invalid("secure random attach-secret source returned zero"));
        }

        let grant = HarmonyAttachGrantV1 {
            operation_id,
            attach_secret,
            primary_side: *primary_side,
            attach_side: primary_side.complement(),
            expires_in_ms: ttl,
        };
        let expected = HarmonyAttachV1 {
            provider_id: verified_offer.scope().provider_id,
            policy_digest: verified_offer.policy_digest(),
            scope_id: verified_offer.scope().scope_id(),
            offer_id: verified_offer.offer().offer_id,
            operation_id,
            operation_digest: operation.digest()?,
            attach_secret,
            db_id: *db_id,
            session_token: *session_token,
            primary_side: *primary_side,
            attach_side: primary_side.complement(),
            operation_profile: verified_offer.scope().operation_profile,
        };
        // Validate every binding now. Finalization only changes state and
        // starts the TTL after the payment transition has committed.
        HarmonyAttachSlotV1::new(expected.clone(), &grant, now_monotonic_ms)?;
        let attach_operation = OperationStartV1::HarmonyHint {
            db_id: *db_id,
            transport: HintTransport::V2Half,
            session_token: Some(*session_token),
            primary_side: Some(primary_side.complement()),
        };
        let shared_usage = SharedGrantUsageV1::new();
        slots.insert(
            operation_id,
            WaitingHarmonyAttachV1 {
                expected: Some(expected),
                slot: None,
                activated: false,
                expires_at_ms: 0,
                policy_digest: verified_offer.policy_digest(),
                scope_id: verified_offer.scope().scope_id(),
                operation: attach_operation,
                limits: limits.clone(),
                started_at_ms: 0,
                shared_usage: shared_usage.clone(),
            },
        );
        drop(slots);
        Ok(ReservedHarmonyAttachV1 {
            registry: self,
            operation_id,
            grant,
            shared_usage,
            finalized: false,
        })
    }

    pub fn try_attach_v1(
        &self,
        request: &HarmonyAttachV1,
        now_monotonic_ms: u64,
    ) -> Result<AttachedHarmonyGrantV1, HarmonyAttachTransitionErrorV1> {
        if request.validate().is_err() {
            return Err(HarmonyAttachTransitionErrorV1::WrongBinding);
        }
        let mut slots = self.slots.lock();
        let Some(entry) = slots.get_mut(&request.operation_id) else {
            return Err(HarmonyAttachTransitionErrorV1::NoWaitingOperation);
        };
        if !entry.activated {
            return Err(HarmonyAttachTransitionErrorV1::NoWaitingOperation);
        }
        if now_monotonic_ms >= entry.expires_at_ms {
            slots.remove(&request.operation_id);
            return Err(HarmonyAttachTransitionErrorV1::Expired);
        }
        entry
            .slot
            .as_mut()
            .expect("activated Harmony reservation has a slot")
            .try_attach(request, now_monotonic_ms)?;
        let entry = slots
            .remove(&request.operation_id)
            .expect("attached entry remains under registry lock");
        Ok(AttachedHarmonyGrantV1 {
            operation_id: request.operation_id,
            policy_digest: entry.policy_digest,
            scope_id: entry.scope_id,
            operation: entry.operation,
            limits: entry.limits,
            started_at_ms: entry.started_at_ms,
            shared_usage: entry.shared_usage,
        })
    }
}

/// RAII capacity reservation. It intentionally has no `Debug` implementation
/// because it owns the secret returned to the primary client.
pub struct ReservedHarmonyAttachV1<'a> {
    registry: &'a HarmonyAttachRegistryV1,
    operation_id: [u8; 32],
    grant: HarmonyAttachGrantV1,
    shared_usage: SharedGrantUsageV1,
    finalized: bool,
}

impl ReservedHarmonyAttachV1<'_> {
    /// Start the attach TTL and make the prevalidated slot visible. Every
    /// fallible operation already completed in `reserve_before_commit_v1`.
    pub(crate) fn finalize_after_commit_v1(
        mut self,
        now_monotonic_ms: u64,
    ) -> FinalizedHarmonyAttachV1 {
        let mut slots = self.registry.slots.lock();
        let entry = slots
            .get_mut(&self.operation_id)
            .expect("live Harmony reservation remains registered");
        let expected = entry
            .expected
            .take()
            .expect("unfinalized Harmony reservation retains its binding");
        entry.slot = Some(
            HarmonyAttachSlotV1::new(expected, &self.grant, now_monotonic_ms)
                .expect("prevalidated Harmony reservation remains valid at finalization"),
        );
        entry.expires_at_ms = now_monotonic_ms.saturating_add(u64::from(self.grant.expires_in_ms));
        entry.started_at_ms = now_monotonic_ms;
        entry.activated = true;
        self.finalized = true;
        FinalizedHarmonyAttachV1 {
            grant: self.grant.clone(),
            shared_usage: self.shared_usage.clone(),
        }
    }
}

impl Drop for ReservedHarmonyAttachV1<'_> {
    fn drop(&mut self) {
        if !self.finalized {
            self.registry.slots.lock().remove(&self.operation_id);
        }
    }
}

pub(crate) struct FinalizedHarmonyAttachV1 {
    pub grant: HarmonyAttachGrantV1,
    pub shared_usage: SharedGrantUsageV1,
}

/// Private-field evidence that one waiting complementary slot matched and was
/// consumed exactly once.
#[derive(Debug)]
pub struct AttachedHarmonyGrantV1 {
    operation_id: [u8; 32],
    policy_digest: [u8; 32],
    scope_id: [u8; 32],
    operation: OperationStartV1,
    limits: EntitlementLimitsV1,
    started_at_ms: u64,
    shared_usage: SharedGrantUsageV1,
}

impl AttachedHarmonyGrantV1 {
    pub const fn operation_id(&self) -> &[u8; 32] {
        &self.operation_id
    }

    pub(crate) fn into_gate_parts(
        self,
    ) -> (
        [u8; 32],
        [u8; 32],
        OperationStartV1,
        EntitlementLimitsV1,
        u64,
        SharedGrantUsageV1,
    ) {
        (
            self.policy_digest,
            self.scope_id,
            self.operation,
            self.limits,
            self.started_at_ms,
            self.shared_usage,
        )
    }
}

fn invalid(reason: &'static str) -> ServiceProtocolError {
    ServiceProtocolError::InvalidValue {
        field: "HarmonyAttachRegistryV1",
        reason,
    }
}

#[cfg(test)]
mod tests {
    // Verified-offer reservation and cross-socket accounting are exercised
    // through the admission-gate tests, which own the private offer typestate.
}
