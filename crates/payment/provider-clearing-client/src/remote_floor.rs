//! Production remote rollback authority for provider settlement state.
//!
//! Only the crate-internal authenticated transition capability can reach
//! [`ProviderSettlementFloorAuthorityV1::apply`]. The remote authority stores
//! a fixed-size, namespace-bound opaque AEAD record and learns only revisions
//! and mutation timing.
//!
//! The operation ID and randomized opaque successor are in-memory for one
//! active call. After process loss, the detailed SQLite transition journal can
//! reconstruct the already-authenticated one-step logical transition. A fresh
//! signed Read either sees that exact logical successor, sees its exact
//! predecessor and permits a new CAS, or exposes a conflict and fails closed.
//! This is logical-floor convergence, not replay of an old authority operation
//! entry.

use core::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pir_rollback_authority_client::{
    DurableAuthorityCasOperationV1, RemoteAuthorityCallErrorV1, RemoteAuthorityCasOutcomeV1,
    RemoteRollbackAuthorityClientV1,
};
use pir_rollback_authority_protocol::{
    AuthorityBindingV1, AuthorityValueCodecV1, OpaqueAuthorityRecordV1,
    MAX_AUTHORITY_VALUE_BYTES_V1,
};
use pir_service_protocol::ProviderId;
use zeroize::Zeroizing;

use crate::sqlite_store::{decode_authority_floor, encode_authority_floor};
use crate::{
    AuthenticatedProviderSettlementFloorTransitionV1, ProviderSettlementFloorAuthorityErrorV1,
    ProviderSettlementFloorAuthorityV1, ProviderSettlementFloorV1,
};

const SETTLEMENT_FLOOR_MAGIC_V1: &[u8; 8] = b"BPRSFV1\0";
const SETTLEMENT_FLOOR_VERSION_V1: u16 = 1;
const SETTLEMENT_FLOOR_HEADER_BYTES_V1: usize = 8 + 2 + 2;
const MAX_SETTLEMENT_FLOOR_BODY_BYTES_V1: usize =
    MAX_AUTHORITY_VALUE_BYTES_V1 - SETTLEMENT_FLOOR_HEADER_BYTES_V1;
const MAX_REMOTE_OPERATION_TIMEOUT_V1: Duration = Duration::from_secs(60);

trait SettlementRemoteAuthorityBackendV1: fmt::Debug + Send + Sync + 'static {
    fn binding(&self) -> &AuthorityBindingV1;

    fn read_until(
        &self,
        deadline: Instant,
    ) -> Result<Option<OpaqueAuthorityRecordV1>, RemoteAuthorityCallErrorV1>;

    fn compare_and_swap_until(
        &self,
        operation: &DurableAuthorityCasOperationV1,
        deadline: Instant,
    ) -> Result<RemoteAuthorityCasOutcomeV1, RemoteAuthorityCallErrorV1>;

    fn reconcile_unknown_until(
        &self,
        operation: &DurableAuthorityCasOperationV1,
        deadline: Instant,
    ) -> Result<RemoteAuthorityCasOutcomeV1, RemoteAuthorityCallErrorV1>;
}

impl SettlementRemoteAuthorityBackendV1 for RemoteRollbackAuthorityClientV1 {
    fn binding(&self) -> &AuthorityBindingV1 {
        RemoteRollbackAuthorityClientV1::binding(self)
    }

    fn read_until(
        &self,
        deadline: Instant,
    ) -> Result<Option<OpaqueAuthorityRecordV1>, RemoteAuthorityCallErrorV1> {
        RemoteRollbackAuthorityClientV1::read_until(self, deadline)
            .map(|outcome| outcome.into_current())
    }

    fn compare_and_swap_until(
        &self,
        operation: &DurableAuthorityCasOperationV1,
        deadline: Instant,
    ) -> Result<RemoteAuthorityCasOutcomeV1, RemoteAuthorityCallErrorV1> {
        RemoteRollbackAuthorityClientV1::compare_and_swap_until(self, operation, deadline)
    }

    fn reconcile_unknown_until(
        &self,
        operation: &DurableAuthorityCasOperationV1,
        deadline: Instant,
    ) -> Result<RemoteAuthorityCasOutcomeV1, RemoteAuthorityCallErrorV1> {
        RemoteRollbackAuthorityClientV1::reconcile_unknown_compare_and_swap_until(
            self, operation, deadline,
        )
        .map(|recovery| recovery.into_parts().1)
    }
}

/// Pinned-HTTPS, independently durable authority for one provider's
/// settlement workflow.
///
/// There is no local fallback. Network, signature, binding, AEAD, decoding,
/// deadline, and ambiguous-outcome errors fail the workflow closed.
pub struct RemoteProviderSettlementFloorAuthorityV1 {
    expected_provider_id: ProviderId,
    backend: Arc<dyn SettlementRemoteAuthorityBackendV1>,
    codec: AuthorityValueCodecV1,
    operation_timeout: Duration,
}

impl fmt::Debug for RemoteProviderSettlementFloorAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteProviderSettlementFloorAuthorityV1")
            .field("expected_provider_id", &"[REDACTED]")
            .field("backend", &"[REDACTED]")
            .field("codec", &"[REDACTED]")
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

impl RemoteProviderSettlementFloorAuthorityV1 {
    pub fn new(
        expected_provider_id: ProviderId,
        client: RemoteRollbackAuthorityClientV1,
        codec: AuthorityValueCodecV1,
        operation_timeout: Duration,
    ) -> Result<Self, ProviderSettlementFloorAuthorityErrorV1> {
        Self::with_backend(
            expected_provider_id,
            Arc::new(client),
            codec,
            operation_timeout,
        )
    }

    fn with_backend(
        expected_provider_id: ProviderId,
        backend: Arc<dyn SettlementRemoteAuthorityBackendV1>,
        codec: AuthorityValueCodecV1,
        operation_timeout: Duration,
    ) -> Result<Self, ProviderSettlementFloorAuthorityErrorV1> {
        if expected_provider_id.iter().all(|byte| *byte == 0) {
            return Err(error("remote settlement rollback binding is invalid"));
        }
        if operation_timeout.is_zero() || operation_timeout > MAX_REMOTE_OPERATION_TIMEOUT_V1 {
            return Err(error("remote settlement rollback timeout is invalid"));
        }
        if backend.binding() != codec.binding() {
            return Err(error(
                "remote settlement rollback cryptographic binding mismatch",
            ));
        }
        Ok(Self {
            expected_provider_id,
            backend,
            codec,
            operation_timeout,
        })
    }

    fn deadline(&self) -> Result<Instant, ProviderSettlementFloorAuthorityErrorV1> {
        Instant::now()
            .checked_add(self.operation_timeout)
            .ok_or_else(|| error("remote settlement rollback deadline is invalid"))
    }

    fn read_current(
        &self,
        deadline: Instant,
    ) -> Result<
        Option<(OpaqueAuthorityRecordV1, ProviderSettlementFloorV1)>,
        ProviderSettlementFloorAuthorityErrorV1,
    > {
        self.backend
            .read_until(deadline)
            .map_err(remote_call_error)?
            .map(|record| {
                let floor = self.open_record(&record)?;
                Ok((record, floor))
            })
            .transpose()
    }

    fn open_record(
        &self,
        record: &OpaqueAuthorityRecordV1,
    ) -> Result<ProviderSettlementFloorV1, ProviderSettlementFloorAuthorityErrorV1> {
        let opened = self
            .codec
            .open(record)
            .map_err(|_| error("remote settlement rollback record authentication failed"))?;
        let floor = decode_floor_v1(opened.as_bytes())?;
        if floor.provider_id() != &self.expected_provider_id
            || floor.revision() != record.revision()
        {
            return Err(error("remote settlement rollback record binding mismatch"));
        }
        Ok(floor)
    }

    fn seal_record(
        &self,
        floor: &ProviderSettlementFloorV1,
    ) -> Result<OpaqueAuthorityRecordV1, ProviderSettlementFloorAuthorityErrorV1> {
        let encoded = encode_floor_v1(floor)?;
        self.codec
            .seal(floor.revision(), encoded.as_slice())
            .map_err(|_| error("remote settlement rollback record sealing failed"))
    }

    fn apply_exact(
        &self,
        expected: Option<OpaqueAuthorityRecordV1>,
        desired_floor: &ProviderSettlementFloorV1,
        deadline: Instant,
    ) -> Result<ProviderSettlementFloorV1, ProviderSettlementFloorAuthorityErrorV1> {
        let desired = self.seal_record(desired_floor)?;
        let operation = DurableAuthorityCasOperationV1::generate(expected, desired)
            .map_err(|_| error("remote settlement rollback CAS construction failed"))?;
        let outcome = match self.backend.compare_and_swap_until(&operation, deadline) {
            Ok(outcome) => outcome,
            Err(RemoteAuthorityCallErrorV1::OutcomeUnknown) => self
                .backend
                .reconcile_unknown_until(&operation, deadline)
                .map_err(|_| error("remote settlement rollback CAS outcome remains unknown"))?,
            Err(RemoteAuthorityCallErrorV1::DefinitelyNotSent) => {
                return Err(error("remote settlement rollback CAS was not sent"));
            }
        };
        self.map_cas_outcome(outcome, &operation, desired_floor)
    }

    fn map_cas_outcome(
        &self,
        outcome: RemoteAuthorityCasOutcomeV1,
        operation: &DurableAuthorityCasOperationV1,
        desired_floor: &ProviderSettlementFloorV1,
    ) -> Result<ProviderSettlementFloorV1, ProviderSettlementFloorAuthorityErrorV1> {
        match outcome {
            RemoteAuthorityCasOutcomeV1::Applied(record)
            | RemoteAuthorityCasOutcomeV1::AlreadyApplied(record) => {
                if &record != operation.desired() {
                    return Err(error("remote settlement rollback applied outcome mismatch"));
                }
                let floor = self.open_record(&record)?;
                if floor != *desired_floor {
                    return Err(error("remote settlement rollback desired floor mismatch"));
                }
                Ok(floor)
            }
            RemoteAuthorityCasOutcomeV1::ConflictCurrent(record) => self.open_record(&record),
            RemoteAuthorityCasOutcomeV1::Empty => Err(error(
                "remote settlement rollback authority became unexpectedly empty",
            )),
        }
    }
}

impl ProviderSettlementFloorAuthorityV1 for RemoteProviderSettlementFloorAuthorityV1 {
    type Error = ProviderSettlementFloorAuthorityErrorV1;

    fn load(&self) -> Result<Option<ProviderSettlementFloorV1>, Self::Error> {
        Ok(self.read_current(self.deadline()?)?.map(|(_, floor)| floor))
    }

    fn apply(
        &self,
        transition: &AuthenticatedProviderSettlementFloorTransitionV1,
    ) -> Result<ProviderSettlementFloorV1, Self::Error> {
        let next = transition.next();
        if next.provider_id() != &self.expected_provider_id {
            return Err(error("remote settlement rollback logical binding mismatch"));
        }
        match transition.expected() {
            Some(expected) => {
                if expected.provider_id() != &self.expected_provider_id {
                    return Err(error("remote settlement rollback logical binding mismatch"));
                }
                expected
                    .validate_successor(next)
                    .map_err(|_| error("remote settlement rollback transition is invalid"))?;
            }
            None => next
                .validate_initial()
                .map_err(|_| error("remote settlement rollback initial floor is invalid"))?,
        }

        let deadline = self.deadline()?;
        match self.read_current(deadline)? {
            Some((_, current)) if current == *next => Ok(current),
            Some((_, current)) if transition.expected().is_none() => Ok(current),
            Some((_, current)) if Some(&current) != transition.expected() => Ok(current),
            Some((opaque_current, _)) => self.apply_exact(Some(opaque_current), next, deadline),
            None if transition.expected().is_some() => {
                Err(error("remote settlement rollback floor is missing"))
            }
            None => self.apply_exact(None, next, deadline),
        }
    }
}

fn encode_floor_v1(
    floor: &ProviderSettlementFloorV1,
) -> Result<Zeroizing<Vec<u8>>, ProviderSettlementFloorAuthorityErrorV1> {
    let body = Zeroizing::new(encode_authority_floor(floor));
    if body.is_empty() || body.len() > MAX_SETTLEMENT_FLOOR_BODY_BYTES_V1 {
        return Err(error("remote settlement rollback floor length is invalid"));
    }
    let body_len = u16::try_from(body.len())
        .map_err(|_| error("remote settlement rollback floor length is invalid"))?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(
        SETTLEMENT_FLOOR_HEADER_BYTES_V1 + body.len(),
    ));
    encoded.extend_from_slice(SETTLEMENT_FLOOR_MAGIC_V1);
    encoded.extend_from_slice(&SETTLEMENT_FLOOR_VERSION_V1.to_be_bytes());
    encoded.extend_from_slice(&body_len.to_be_bytes());
    encoded.extend_from_slice(body.as_slice());
    Ok(encoded)
}

fn decode_floor_v1(
    bytes: &[u8],
) -> Result<ProviderSettlementFloorV1, ProviderSettlementFloorAuthorityErrorV1> {
    if bytes.len() <= SETTLEMENT_FLOOR_HEADER_BYTES_V1
        || bytes.len() > MAX_AUTHORITY_VALUE_BYTES_V1
        || bytes.get(..8) != Some(SETTLEMENT_FLOOR_MAGIC_V1.as_slice())
    {
        return Err(error(
            "remote settlement rollback floor encoding is invalid",
        ));
    }
    let version = u16::from_be_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| error("remote settlement rollback floor is truncated"))?,
    );
    if version != SETTLEMENT_FLOOR_VERSION_V1 {
        return Err(error(
            "remote settlement rollback floor version is unsupported",
        ));
    }
    let body_len =
        usize::from(u16::from_be_bytes(bytes[10..12].try_into().map_err(
            |_| error("remote settlement rollback floor is truncated"),
        )?));
    if body_len == 0
        || body_len > MAX_SETTLEMENT_FLOOR_BODY_BYTES_V1
        || SETTLEMENT_FLOOR_HEADER_BYTES_V1.checked_add(body_len) != Some(bytes.len())
    {
        return Err(error("remote settlement rollback floor length is invalid"));
    }
    decode_authority_floor(&bytes[SETTLEMENT_FLOOR_HEADER_BYTES_V1..])
        .map_err(|_| error("remote settlement rollback floor decoding failed"))
}

fn remote_call_error(
    error_value: RemoteAuthorityCallErrorV1,
) -> ProviderSettlementFloorAuthorityErrorV1 {
    match error_value {
        RemoteAuthorityCallErrorV1::DefinitelyNotSent => {
            error("remote settlement rollback request was not sent")
        }
        RemoteAuthorityCallErrorV1::OutcomeUnknown => {
            error("remote settlement rollback request outcome is unknown")
        }
    }
}

fn error(reason: &'static str) -> ProviderSettlementFloorAuthorityErrorV1 {
    ProviderSettlementFloorAuthorityErrorV1::new(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProviderPayoutPendingFloorV1, ProviderPayoutRollbackFloorV1, ProviderSettlementFloorPhaseV1,
    };
    use ed25519_dalek::SigningKey;
    use pir_rollback_authority_protocol::AuthorityValueRootKeyV1;
    use pir_service_protocol::PayoutStateV1;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
    use std::sync::Mutex;

    const MODE_NORMAL: u8 = 0;
    const MODE_UNKNOWN_AFTER_APPLY: u8 = 1;
    const MODE_DEFINITELY_NOT_SENT: u8 = 2;
    const MODE_EMPTY: u8 = 3;

    struct FakeBackend {
        binding: AuthorityBindingV1,
        current: Mutex<Option<OpaqueAuthorityRecordV1>>,
        unknown_operation_id: Mutex<Option<Vec<u8>>>,
        mode: AtomicU8,
        fail_reads: AtomicBool,
        reconciles: AtomicUsize,
    }

    impl fmt::Debug for FakeBackend {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FakeBackend([REDACTED])")
        }
    }

    impl FakeBackend {
        fn new(binding: AuthorityBindingV1) -> Self {
            Self {
                binding,
                current: Mutex::new(None),
                unknown_operation_id: Mutex::new(None),
                mode: AtomicU8::new(MODE_NORMAL),
                fail_reads: AtomicBool::new(false),
                reconciles: AtomicUsize::new(0),
            }
        }

        fn set_mode(&self, mode: u8) {
            self.mode.store(mode, Ordering::SeqCst);
        }

        fn set_current(&self, record: OpaqueAuthorityRecordV1) {
            *self.current.lock().unwrap() = Some(record);
        }

        fn normal_cas(
            &self,
            operation: &DurableAuthorityCasOperationV1,
        ) -> RemoteAuthorityCasOutcomeV1 {
            let mut current = self.current.lock().unwrap();
            if current.as_ref() == Some(operation.desired()) {
                return RemoteAuthorityCasOutcomeV1::AlreadyApplied(
                    operation.desired().duplicate_for_protocol(),
                );
            }
            let expected_matches = match (current.as_ref(), operation.expected()) {
                (None, None) => true,
                (Some(actual), Some(expected)) => actual == expected,
                _ => false,
            };
            if expected_matches {
                *current = Some(operation.desired().duplicate_for_protocol());
                return RemoteAuthorityCasOutcomeV1::Applied(
                    operation.desired().duplicate_for_protocol(),
                );
            }
            match current.as_ref() {
                Some(record) => {
                    RemoteAuthorityCasOutcomeV1::ConflictCurrent(record.duplicate_for_protocol())
                }
                None => RemoteAuthorityCasOutcomeV1::Empty,
            }
        }
    }

    impl SettlementRemoteAuthorityBackendV1 for FakeBackend {
        fn binding(&self) -> &AuthorityBindingV1 {
            &self.binding
        }

        fn read_until(
            &self,
            _deadline: Instant,
        ) -> Result<Option<OpaqueAuthorityRecordV1>, RemoteAuthorityCallErrorV1> {
            if self.fail_reads.load(Ordering::SeqCst) {
                return Err(RemoteAuthorityCallErrorV1::DefinitelyNotSent);
            }
            Ok(self
                .current
                .lock()
                .unwrap()
                .as_ref()
                .map(OpaqueAuthorityRecordV1::duplicate_for_protocol))
        }

        fn compare_and_swap_until(
            &self,
            operation: &DurableAuthorityCasOperationV1,
            _deadline: Instant,
        ) -> Result<RemoteAuthorityCasOutcomeV1, RemoteAuthorityCallErrorV1> {
            match self.mode.swap(MODE_NORMAL, Ordering::SeqCst) {
                MODE_NORMAL => Ok(self.normal_cas(operation)),
                MODE_UNKNOWN_AFTER_APPLY => {
                    *self.unknown_operation_id.lock().unwrap() =
                        Some(operation.operation_id().to_vec());
                    let _ = self.normal_cas(operation);
                    Err(RemoteAuthorityCallErrorV1::OutcomeUnknown)
                }
                MODE_DEFINITELY_NOT_SENT => Err(RemoteAuthorityCallErrorV1::DefinitelyNotSent),
                MODE_EMPTY => Ok(RemoteAuthorityCasOutcomeV1::Empty),
                _ => Err(RemoteAuthorityCallErrorV1::OutcomeUnknown),
            }
        }

        fn reconcile_unknown_until(
            &self,
            operation: &DurableAuthorityCasOperationV1,
            _deadline: Instant,
        ) -> Result<RemoteAuthorityCasOutcomeV1, RemoteAuthorityCallErrorV1> {
            self.reconciles.fetch_add(1, Ordering::SeqCst);
            let stable_operation = self
                .unknown_operation_id
                .lock()
                .unwrap()
                .take()
                .is_some_and(|operation_id| {
                    operation_id.as_slice() == &operation.operation_id()[..]
                });
            if !stable_operation {
                return Err(RemoteAuthorityCallErrorV1::OutcomeUnknown);
            }
            Ok(self.normal_cas(operation))
        }
    }

    fn make_codec(namespace: u8, client_key: u8) -> AuthorityValueCodecV1 {
        let root = AuthorityValueRootKeyV1::from_bytes([7; 32]).unwrap();
        let signing_key = SigningKey::from_bytes(&[client_key; 32]);
        AuthorityValueCodecV1::derive(
            &root,
            [8; 32],
            [namespace; 32],
            &signing_key.verifying_key(),
        )
        .unwrap()
    }

    fn authority(
        backend: Arc<FakeBackend>,
        codec: AuthorityValueCodecV1,
    ) -> RemoteProviderSettlementFloorAuthorityV1 {
        RemoteProviderSettlementFloorAuthorityV1::with_backend(
            [2; 32],
            backend,
            codec,
            Duration::from_secs(1),
        )
        .unwrap()
    }

    fn initial_floor() -> ProviderSettlementFloorV1 {
        let store_instance_id = [1; 16];
        let provider_id = [2; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"BitcoinPIR/provider-settlement/history-initial/v2");
        hasher.update(store_instance_id);
        hasher.update(provider_id);
        let history_commitment = hasher.finalize().into();
        ProviderSettlementFloorV1 {
            store_instance_id,
            provider_id,
            revision: 1,
            active_commitment: [3; 32],
            history_length: 0,
            history_commitment,
            phase: ProviderSettlementFloorPhaseV1::Pending {
                pending: ProviderPayoutPendingFloorV1::from_digest([4; 32]).unwrap(),
                payout_request_digest: [5; 32],
            },
        }
    }

    fn initial_transition(
        floor: ProviderSettlementFloorV1,
    ) -> AuthenticatedProviderSettlementFloorTransitionV1 {
        AuthenticatedProviderSettlementFloorTransitionV1::for_remote_test(None, floor)
    }

    fn payout_successor(expected: ProviderSettlementFloorV1) -> ProviderSettlementFloorV1 {
        let payout = ProviderPayoutRollbackFloorV1::from_parts(
            [6; 32],
            [5; 32],
            [7; 32],
            PayoutStateV1::Accepted,
            1,
            1,
        )
        .unwrap();
        ProviderSettlementFloorV1 {
            store_instance_id: expected.store_instance_id,
            provider_id: expected.provider_id,
            revision: 2,
            active_commitment: [8; 32],
            history_length: expected.history_length,
            history_commitment: expected.history_commitment,
            phase: ProviderSettlementFloorPhaseV1::Payout { payout },
        }
    }

    #[test]
    fn settlement_remote_floor_encoding_is_exact_and_domain_separated() {
        let expected = initial_floor();
        expected.validate_initial().unwrap();
        let encoded = encode_floor_v1(&expected).unwrap();
        assert!(encoded.len() <= MAX_AUTHORITY_VALUE_BYTES_V1);
        assert_eq!(decode_floor_v1(&encoded).unwrap(), expected);

        let mut bad_magic = encoded.to_vec();
        bad_magic[0] ^= 1;
        assert!(decode_floor_v1(&bad_magic).is_err());
        let mut bad_version = encoded.to_vec();
        bad_version[9] = 2;
        assert!(decode_floor_v1(&bad_version).is_err());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode_floor_v1(&trailing).is_err());
    }

    #[test]
    fn settlement_remote_floor_maps_applied_replayed_conflict_and_empty() {
        let codec = make_codec(9, 10);
        let backend = Arc::new(FakeBackend::new(codec.binding().duplicate_for_protocol()));
        let authority = authority(backend, codec);
        let floor = initial_floor();
        let desired = authority.seal_record(&floor).unwrap();
        let operation = DurableAuthorityCasOperationV1::generate(None, desired).unwrap();

        assert_eq!(
            authority
                .map_cas_outcome(
                    RemoteAuthorityCasOutcomeV1::Applied(
                        operation.desired().duplicate_for_protocol(),
                    ),
                    &operation,
                    &floor,
                )
                .unwrap(),
            floor
        );
        assert_eq!(
            authority
                .map_cas_outcome(
                    RemoteAuthorityCasOutcomeV1::AlreadyApplied(
                        operation.desired().duplicate_for_protocol(),
                    ),
                    &operation,
                    &floor,
                )
                .unwrap(),
            floor
        );
        let mut mismatched_floor = floor;
        mismatched_floor.active_commitment = [77; 32];
        assert!(authority
            .map_cas_outcome(
                RemoteAuthorityCasOutcomeV1::Applied(
                    authority.seal_record(&mismatched_floor).unwrap(),
                ),
                &operation,
                &floor,
            )
            .is_err());
        let conflict = authority.seal_record(&floor).unwrap();
        assert_eq!(
            authority
                .map_cas_outcome(
                    RemoteAuthorityCasOutcomeV1::ConflictCurrent(conflict),
                    &operation,
                    &floor,
                )
                .unwrap(),
            floor
        );
        assert!(authority
            .map_cas_outcome(RemoteAuthorityCasOutcomeV1::Empty, &operation, &floor)
            .is_err());
    }

    #[test]
    fn settlement_remote_floor_reconciles_unknown_and_fails_closed() {
        let codec = make_codec(9, 10);
        let backend = Arc::new(FakeBackend::new(codec.binding().duplicate_for_protocol()));
        let authority = authority(backend.clone(), codec);
        let floor = initial_floor();

        backend.set_mode(MODE_UNKNOWN_AFTER_APPLY);
        assert_eq!(authority.apply(&initial_transition(floor)).unwrap(), floor);
        assert_eq!(backend.reconciles.load(Ordering::SeqCst), 1);
        assert_eq!(authority.apply(&initial_transition(floor)).unwrap(), floor);

        backend.fail_reads.store(true, Ordering::SeqCst);
        assert!(authority.load().is_err());
        backend.fail_reads.store(false, Ordering::SeqCst);
        assert_eq!(authority.load().unwrap(), Some(floor));

        let empty_codec = make_codec(12, 13);
        let empty_backend = Arc::new(FakeBackend::new(
            empty_codec.binding().duplicate_for_protocol(),
        ));
        let empty_authority = RemoteProviderSettlementFloorAuthorityV1::with_backend(
            [2; 32],
            empty_backend.clone(),
            empty_codec,
            Duration::from_secs(1),
        )
        .unwrap();
        empty_backend.set_mode(MODE_EMPTY);
        assert!(empty_authority.apply(&initial_transition(floor)).is_err());

        empty_backend.set_mode(MODE_DEFINITELY_NOT_SENT);
        assert!(empty_authority.apply(&initial_transition(floor)).is_err());
    }

    #[test]
    fn settlement_remote_floor_rejects_tamper_wrong_binding_and_revision() {
        let codec = make_codec(9, 10);
        let backend = Arc::new(FakeBackend::new(codec.binding().duplicate_for_protocol()));
        let authority = authority(backend.clone(), codec);
        let floor = initial_floor();

        let record = authority.seal_record(&floor).unwrap();
        let mut tampered = record.encode();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        backend.set_current(OpaqueAuthorityRecordV1::decode(&tampered).unwrap());
        assert!(authority.load().is_err());

        backend.set_current(
            authority
                .codec
                .seal(
                    floor.revision() + 1,
                    encode_floor_v1(&floor).unwrap().as_slice(),
                )
                .unwrap(),
        );
        assert!(authority.load().is_err());

        let mut rebound = floor;
        rebound.provider_id = [99; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"BitcoinPIR/provider-settlement/history-initial/v2");
        hasher.update(rebound.store_instance_id);
        hasher.update(rebound.provider_id);
        rebound.history_commitment = hasher.finalize().into();
        rebound.validate_initial().unwrap();
        backend.set_current(authority.seal_record(&rebound).unwrap());
        assert!(authority.load().is_err());

        let wrong_namespace = make_codec(11, 10);
        assert!(RemoteProviderSettlementFloorAuthorityV1::with_backend(
            [2; 32],
            backend.clone(),
            wrong_namespace,
            Duration::from_secs(1),
        )
        .is_err());
        assert!(make_codec(9, 12).open(&record).is_err());
    }

    #[test]
    fn settlement_remote_floor_fresh_restart_reads_durable_logical_floor() {
        let first_codec = make_codec(9, 10);
        let backend = Arc::new(FakeBackend::new(
            first_codec.binding().duplicate_for_protocol(),
        ));
        let first = authority(backend.clone(), first_codec);
        let floor = initial_floor();
        backend.set_mode(MODE_UNKNOWN_AFTER_APPLY);
        assert_eq!(first.apply(&initial_transition(floor)).unwrap(), floor);
        drop(first);

        let restarted = authority(backend.clone(), make_codec(9, 10));
        assert_eq!(restarted.load().unwrap(), Some(floor));
        assert_eq!(restarted.apply(&initial_transition(floor)).unwrap(), floor);
        let successor = payout_successor(floor);
        floor.validate_successor(&successor).unwrap();
        let transition = AuthenticatedProviderSettlementFloorTransitionV1::for_remote_test(
            Some(floor),
            successor,
        );
        assert_eq!(restarted.apply(&transition).unwrap(), successor);
        backend.fail_reads.store(true, Ordering::SeqCst);
        assert!(restarted.load().is_err());
        backend.fail_reads.store(false, Ordering::SeqCst);
        assert_eq!(restarted.load().unwrap(), Some(successor));
    }
}
