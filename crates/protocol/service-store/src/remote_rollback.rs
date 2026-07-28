//! Production remote rollback authority for provider admission state.
//!
//! The remote authority stores only a fixed-size, namespace-bound opaque
//! record. The provider floor is encoded canonically, then authenticated and
//! encrypted by [`AuthorityValueCodecV1`]. Every operation performs a fresh
//! signed Read; a CAS uses the exact opaque record returned by that Read.
//!
//! The CAS operation ID and randomized opaque successor live only for the
//! current call. Cross-process recovery instead relies on the provider store's
//! already-durable, authenticated one-step logical successor: a fresh signed
//! Read either observes that exact logical successor, observes its exact
//! predecessor and permits one new CAS, or exposes a conflict and fails the
//! caller closed. This is logical-floor convergence, not replay of an old
//! authority operation-log entry.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pir_rollback_authority_client::{
    DurableAuthorityCasOperationV1, RemoteAuthorityCallErrorV1, RemoteAuthorityCasOutcomeV1,
    RemoteRollbackAuthorityClientV1,
};
use pir_rollback_authority_protocol::{
    AuthorityBindingV1, AuthorityValueCodecV1, OpaqueAuthorityRecordV1,
};
use zeroize::Zeroizing;

use crate::{RollbackFloorAuthorityErrorV1, RollbackFloorAuthorityV1, RollbackFloorV1};

const PROVIDER_FLOOR_MAGIC_V1: &[u8; 8] = b"BPSRFLR\0";
const PROVIDER_FLOOR_VERSION_V1: u16 = 1;
const PROVIDER_FLOOR_BYTES_V1: usize = 8 + 2 + 16 + 32 + 8 + 8 + 32 + 4;
const MAX_REMOTE_OPERATION_TIMEOUT_V1: Duration = Duration::from_secs(60);

trait ProviderRemoteAuthorityBackendV1: fmt::Debug + Send + Sync + 'static {
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

impl ProviderRemoteAuthorityBackendV1 for RemoteRollbackAuthorityClientV1 {
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

/// Independently hosted, pinned-HTTPS rollback authority for one provider.
///
/// There is no local fallback. An HTTP, signature, AEAD, binding, decoding,
/// timeout, or outcome error fails the store operation closed.
pub struct RemoteProviderRollbackFloorAuthorityV1 {
    expected_provider_id: [u8; 32],
    backend: Arc<dyn ProviderRemoteAuthorityBackendV1>,
    codec: AuthorityValueCodecV1,
    operation_timeout: Duration,
}

impl fmt::Debug for RemoteProviderRollbackFloorAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteProviderRollbackFloorAuthorityV1")
            .field("expected_provider_id", &"[REDACTED]")
            .field("backend", &"[REDACTED]")
            .field("codec", &"[REDACTED]")
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

impl RemoteProviderRollbackFloorAuthorityV1 {
    pub fn new(
        expected_provider_id: [u8; 32],
        client: RemoteRollbackAuthorityClientV1,
        codec: AuthorityValueCodecV1,
        operation_timeout: Duration,
    ) -> Result<Self, RollbackFloorAuthorityErrorV1> {
        Self::with_backend(
            expected_provider_id,
            Arc::new(client),
            codec,
            operation_timeout,
        )
    }

    fn with_backend(
        expected_provider_id: [u8; 32],
        backend: Arc<dyn ProviderRemoteAuthorityBackendV1>,
        codec: AuthorityValueCodecV1,
        operation_timeout: Duration,
    ) -> Result<Self, RollbackFloorAuthorityErrorV1> {
        if expected_provider_id.iter().all(|byte| *byte == 0) {
            return Err(error("remote provider rollback binding is invalid"));
        }
        if operation_timeout.is_zero() || operation_timeout > MAX_REMOTE_OPERATION_TIMEOUT_V1 {
            return Err(error("remote provider rollback timeout is invalid"));
        }
        if backend.binding() != codec.binding() {
            return Err(error(
                "remote provider rollback cryptographic binding mismatch",
            ));
        }
        Ok(Self {
            expected_provider_id,
            backend,
            codec,
            operation_timeout,
        })
    }

    fn deadline(&self) -> Result<Instant, RollbackFloorAuthorityErrorV1> {
        Instant::now()
            .checked_add(self.operation_timeout)
            .ok_or_else(|| error("remote provider rollback deadline is invalid"))
    }

    fn read_current(
        &self,
        deadline: Instant,
    ) -> Result<Option<(OpaqueAuthorityRecordV1, RollbackFloorV1)>, RollbackFloorAuthorityErrorV1>
    {
        let current = self
            .backend
            .read_until(deadline)
            .map_err(remote_call_error)?;
        current
            .map(|record| {
                let floor = self.open_record(&record)?;
                Ok((record, floor))
            })
            .transpose()
    }

    fn open_record(
        &self,
        record: &OpaqueAuthorityRecordV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        let opened = self
            .codec
            .open(record)
            .map_err(|_| error("remote provider rollback record authentication failed"))?;
        let floor = decode_floor_v1(opened.as_bytes())?;
        if floor.provider_id != self.expected_provider_id
            || floor.store_generation != record.revision()
        {
            return Err(error("remote provider rollback record binding mismatch"));
        }
        Ok(floor)
    }

    fn seal_record(
        &self,
        floor: &RollbackFloorV1,
    ) -> Result<OpaqueAuthorityRecordV1, RollbackFloorAuthorityErrorV1> {
        let encoded = encode_floor_v1(floor)?;
        self.codec
            .seal(floor.store_generation, encoded.as_slice())
            .map_err(|_| error("remote provider rollback record sealing failed"))
    }

    fn apply_exact(
        &self,
        expected: Option<OpaqueAuthorityRecordV1>,
        desired_floor: &RollbackFloorV1,
        deadline: Instant,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        let desired = self.seal_record(desired_floor)?;
        let operation = DurableAuthorityCasOperationV1::generate(expected, desired)
            .map_err(|_| error("remote provider rollback CAS construction failed"))?;
        let outcome = match self.backend.compare_and_swap_until(&operation, deadline) {
            Ok(outcome) => outcome,
            Err(RemoteAuthorityCallErrorV1::OutcomeUnknown) => self
                .backend
                .reconcile_unknown_until(&operation, deadline)
                .map_err(|_| error("remote provider rollback CAS outcome remains unknown"))?,
            Err(RemoteAuthorityCallErrorV1::DefinitelyNotSent) => {
                return Err(error("remote provider rollback CAS was not sent"));
            }
        };
        self.map_cas_outcome(outcome, &operation, desired_floor)
    }

    fn map_cas_outcome(
        &self,
        outcome: RemoteAuthorityCasOutcomeV1,
        operation: &DurableAuthorityCasOperationV1,
        desired_floor: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        match outcome {
            RemoteAuthorityCasOutcomeV1::Applied(record)
            | RemoteAuthorityCasOutcomeV1::AlreadyApplied(record) => {
                if &record != operation.desired() {
                    return Err(error("remote provider rollback applied outcome mismatch"));
                }
                let floor = self.open_record(&record)?;
                if floor != *desired_floor {
                    return Err(error("remote provider rollback desired floor mismatch"));
                }
                Ok(floor)
            }
            RemoteAuthorityCasOutcomeV1::ConflictCurrent(record) => self.open_record(&record),
            RemoteAuthorityCasOutcomeV1::Empty => Err(error(
                "remote provider rollback authority became unexpectedly empty",
            )),
        }
    }
}

impl RollbackFloorAuthorityV1 for RemoteProviderRollbackFloorAuthorityV1 {
    fn load(
        &self,
        provider_id: &[u8; 32],
    ) -> Result<Option<RollbackFloorV1>, RollbackFloorAuthorityErrorV1> {
        if provider_id != &self.expected_provider_id {
            return Err(error("remote provider rollback logical binding mismatch"));
        }
        Ok(self.read_current(self.deadline()?)?.map(|(_, floor)| floor))
    }

    fn initialize(
        &self,
        initial: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        initial
            .validate()
            .map_err(|_| error("remote provider rollback initial floor is invalid"))?;
        if initial.provider_id != self.expected_provider_id
            || initial.store_generation != 0
            || initial.spend_commit_seq != 0
        {
            return Err(error(
                "remote provider rollback initial floor binding is invalid",
            ));
        }
        let deadline = self.deadline()?;
        match self.read_current(deadline)? {
            Some((_, current)) => Ok(current),
            None => self.apply_exact(None, initial, deadline),
        }
    }

    fn compare_and_advance(
        &self,
        expected: &RollbackFloorV1,
        next: &RollbackFloorV1,
    ) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
        validate_transition_v1(expected, next, &self.expected_provider_id)?;
        let deadline = self.deadline()?;
        let Some((opaque_current, current)) = self.read_current(deadline)? else {
            return Err(error("remote provider rollback floor is missing"));
        };
        if current == *next {
            return Ok(current);
        }
        if current != *expected {
            return Ok(current);
        }
        self.apply_exact(Some(opaque_current), next, deadline)
    }
}

fn validate_transition_v1(
    expected: &RollbackFloorV1,
    next: &RollbackFloorV1,
    provider_id: &[u8; 32],
) -> Result<(), RollbackFloorAuthorityErrorV1> {
    expected
        .validate()
        .map_err(|_| error("remote provider rollback expected floor is invalid"))?;
    next.validate()
        .map_err(|_| error("remote provider rollback next floor is invalid"))?;
    let next_generation = expected
        .store_generation
        .checked_add(1)
        .ok_or_else(|| error("remote provider rollback generation transition overflow"))?;
    if expected.provider_id != *provider_id
        || next.provider_id != *provider_id
        || expected.store_instance_id != next.store_instance_id
        || expected.schema_version != next.schema_version
        || next.store_generation != next_generation
        || next.spend_commit_seq < expected.spend_commit_seq
        || next.spend_commit_seq > expected.spend_commit_seq.saturating_add(1)
        || next.rollback_commitment == expected.rollback_commitment
    {
        return Err(error("remote provider rollback transition is invalid"));
    }
    Ok(())
}

fn encode_floor_v1(
    floor: &RollbackFloorV1,
) -> Result<Zeroizing<Vec<u8>>, RollbackFloorAuthorityErrorV1> {
    floor
        .validate()
        .map_err(|_| error("remote provider rollback floor is invalid"))?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(PROVIDER_FLOOR_BYTES_V1));
    encoded.extend_from_slice(PROVIDER_FLOOR_MAGIC_V1);
    encoded.extend_from_slice(&PROVIDER_FLOOR_VERSION_V1.to_be_bytes());
    encoded.extend_from_slice(&floor.store_instance_id);
    encoded.extend_from_slice(&floor.provider_id);
    encoded.extend_from_slice(&floor.store_generation.to_be_bytes());
    encoded.extend_from_slice(&floor.spend_commit_seq.to_be_bytes());
    encoded.extend_from_slice(&floor.rollback_commitment);
    encoded.extend_from_slice(&floor.schema_version.to_be_bytes());
    if encoded.len() != PROVIDER_FLOOR_BYTES_V1 {
        return Err(error("remote provider rollback floor encoding failed"));
    }
    Ok(encoded)
}

fn decode_floor_v1(bytes: &[u8]) -> Result<RollbackFloorV1, RollbackFloorAuthorityErrorV1> {
    if bytes.len() != PROVIDER_FLOOR_BYTES_V1
        || bytes.get(..8) != Some(PROVIDER_FLOOR_MAGIC_V1.as_slice())
    {
        return Err(error("remote provider rollback floor encoding is invalid"));
    }
    let version = u16::from_be_bytes(fixed(bytes, 8)?);
    if version != PROVIDER_FLOOR_VERSION_V1 {
        return Err(error(
            "remote provider rollback floor version is unsupported",
        ));
    }
    let floor = RollbackFloorV1 {
        store_instance_id: fixed(bytes, 10)?,
        provider_id: fixed(bytes, 26)?,
        store_generation: u64::from_be_bytes(fixed(bytes, 58)?),
        spend_commit_seq: u64::from_be_bytes(fixed(bytes, 66)?),
        rollback_commitment: fixed(bytes, 74)?,
        schema_version: u32::from_be_bytes(fixed(bytes, 106)?),
    };
    floor
        .validate()
        .map_err(|_| error("remote provider rollback floor decoding failed"))?;
    Ok(floor)
}

fn fixed<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], RollbackFloorAuthorityErrorV1> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| error("remote provider rollback floor is truncated"))?;
    bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| error("remote provider rollback floor is truncated"))
}

fn remote_call_error(error_value: RemoteAuthorityCallErrorV1) -> RollbackFloorAuthorityErrorV1 {
    match error_value {
        RemoteAuthorityCallErrorV1::DefinitelyNotSent => {
            error("remote provider rollback request was not sent")
        }
        RemoteAuthorityCallErrorV1::OutcomeUnknown => {
            error("remote provider rollback request outcome is unknown")
        }
    }
}

fn error(reason: &'static str) -> RollbackFloorAuthorityErrorV1 {
    RollbackFloorAuthorityErrorV1::new(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pir_rollback_authority_protocol::AuthorityValueRootKeyV1;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::Mutex;

    const MODE_NORMAL: u8 = 0;
    const MODE_UNKNOWN_AFTER_APPLY: u8 = 1;
    const MODE_DEFINITELY_NOT_SENT: u8 = 2;
    const MODE_EMPTY: u8 = 3;
    const MODE_CONFLICT_EXPECTED: u8 = 4;
    const MODE_READ_FAILURE: u8 = 5;

    struct FakeBackend {
        binding: AuthorityBindingV1,
        current: Mutex<Option<OpaqueAuthorityRecordV1>>,
        unknown_operation_id: Mutex<Option<Vec<u8>>>,
        mode: AtomicU8,
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

    impl ProviderRemoteAuthorityBackendV1 for FakeBackend {
        fn binding(&self) -> &AuthorityBindingV1 {
            &self.binding
        }

        fn read_until(
            &self,
            _deadline: Instant,
        ) -> Result<Option<OpaqueAuthorityRecordV1>, RemoteAuthorityCallErrorV1> {
            if self.mode.load(Ordering::SeqCst) == MODE_READ_FAILURE {
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
                MODE_CONFLICT_EXPECTED => operation
                    .expected()
                    .map(OpaqueAuthorityRecordV1::duplicate_for_protocol)
                    .map(RemoteAuthorityCasOutcomeV1::ConflictCurrent)
                    .ok_or(RemoteAuthorityCallErrorV1::OutcomeUnknown),
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
    ) -> RemoteProviderRollbackFloorAuthorityV1 {
        RemoteProviderRollbackFloorAuthorityV1::with_backend(
            [2; 32],
            backend,
            codec,
            Duration::from_secs(1),
        )
        .unwrap()
    }

    fn floor(generation: u64, spend: u64, commitment: u8) -> RollbackFloorV1 {
        RollbackFloorV1 {
            store_instance_id: [1; 16],
            provider_id: [2; 32],
            store_generation: generation,
            spend_commit_seq: spend,
            rollback_commitment: [commitment; 32],
            schema_version: crate::SCHEMA_VERSION,
        }
    }

    #[test]
    fn provider_remote_floor_encoding_is_exact_and_domain_separated() {
        let expected = floor(7, 3, 9);
        let encoded = encode_floor_v1(&expected).unwrap();
        assert_eq!(encoded.len(), PROVIDER_FLOOR_BYTES_V1);
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
    fn provider_remote_floor_transition_requires_exact_revision_and_identity() {
        let zero = floor(0, 0, 3);
        let one = floor(1, 1, 4);
        assert!(validate_transition_v1(&zero, &one, &[2; 32]).is_ok());
        assert!(validate_transition_v1(&zero, &floor(2, 1, 4), &[2; 32]).is_err());
        let mut rebound = one;
        rebound.provider_id = [8; 32];
        assert!(validate_transition_v1(&zero, &rebound, &[2; 32]).is_err());
    }

    #[test]
    fn provider_remote_floor_maps_applied_replayed_conflict_empty_and_unknown() {
        let codec = make_codec(9, 10);
        let backend = Arc::new(FakeBackend::new(codec.binding().duplicate_for_protocol()));
        let authority = authority(backend.clone(), codec);
        let zero = floor(0, 0, 3);
        let one = floor(1, 1, 4);
        let two = floor(2, 2, 5);

        assert_eq!(authority.initialize(&zero).unwrap(), zero);

        let desired = authority.seal_record(&zero).unwrap();
        let operation = DurableAuthorityCasOperationV1::generate(None, desired).unwrap();
        assert!(authority
            .map_cas_outcome(
                RemoteAuthorityCasOutcomeV1::Applied(
                    authority.seal_record(&floor(0, 0, 77)).unwrap(),
                ),
                &operation,
                &zero,
            )
            .is_err());

        backend.set_mode(MODE_UNKNOWN_AFTER_APPLY);
        assert_eq!(authority.compare_and_advance(&zero, &one).unwrap(), one);
        assert_eq!(backend.reconciles.load(Ordering::SeqCst), 1);

        // A fresh signed read sees the already-applied logical successor, so
        // retry is idempotent even though its opaque AEAD bytes are random.
        assert_eq!(authority.compare_and_advance(&zero, &one).unwrap(), one);

        let fork = floor(1, 1, 12);
        backend.set_current(authority.seal_record(&fork).unwrap());
        assert_eq!(authority.compare_and_advance(&one, &two).unwrap(), fork);

        backend.set_current(authority.seal_record(&one).unwrap());
        backend.set_mode(MODE_CONFLICT_EXPECTED);
        assert_eq!(authority.compare_and_advance(&one, &two).unwrap(), one);

        backend.set_mode(MODE_EMPTY);
        assert!(authority.compare_and_advance(&one, &two).is_err());

        backend.set_mode(MODE_DEFINITELY_NOT_SENT);
        assert!(authority.compare_and_advance(&one, &two).is_err());
    }

    #[test]
    fn provider_remote_floor_rejects_tamper_wrong_binding_and_revision() {
        let codec = make_codec(9, 10);
        let backend = Arc::new(FakeBackend::new(codec.binding().duplicate_for_protocol()));
        let authority = authority(backend.clone(), codec);
        let zero = floor(0, 0, 3);

        let record = authority.seal_record(&zero).unwrap();
        let mut tampered = record.encode();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        backend.set_current(OpaqueAuthorityRecordV1::decode(&tampered).unwrap());
        assert!(authority.load(&[2; 32]).is_err());

        backend.set_current(
            authority
                .codec
                .seal(
                    zero.store_generation + 1,
                    encode_floor_v1(&zero).unwrap().as_slice(),
                )
                .unwrap(),
        );
        assert!(authority.load(&[2; 32]).is_err());
        assert!(authority.load(&[99; 32]).is_err());

        let mut rebound = zero;
        rebound.provider_id = [99; 32];
        backend.set_current(authority.seal_record(&rebound).unwrap());
        assert!(authority.load(&[2; 32]).is_err());

        let wrong_namespace = make_codec(11, 10);
        assert!(RemoteProviderRollbackFloorAuthorityV1::with_backend(
            [2; 32],
            backend.clone(),
            wrong_namespace,
            Duration::from_secs(1),
        )
        .is_err());

        let wrong_client = make_codec(9, 12);
        assert!(wrong_client.open(&record).is_err());
    }

    #[test]
    fn provider_remote_floor_fresh_restart_converges_without_local_fallback() {
        let first_codec = make_codec(9, 10);
        let backend = Arc::new(FakeBackend::new(
            first_codec.binding().duplicate_for_protocol(),
        ));
        let first = authority(backend.clone(), first_codec);
        let zero = floor(0, 0, 3);
        let one = floor(1, 1, 4);
        assert_eq!(first.initialize(&zero).unwrap(), zero);
        backend.set_mode(MODE_UNKNOWN_AFTER_APPLY);
        assert_eq!(first.compare_and_advance(&zero, &one).unwrap(), one);
        drop(first);

        let restarted = authority(backend.clone(), make_codec(9, 10));
        assert_eq!(restarted.load(&[2; 32]).unwrap(), Some(one));

        // A fresh-process retry converges by logical equality. It does not
        // claim to recover the prior in-memory operation ID.
        assert_eq!(restarted.compare_and_advance(&zero, &one).unwrap(), one);
        let two = floor(2, 2, 5);
        assert_eq!(restarted.compare_and_advance(&one, &two).unwrap(), two);
        backend.set_mode(MODE_READ_FAILURE);
        assert!(restarted.load(&[2; 32]).is_err());
        backend.set_mode(MODE_NORMAL);
        assert_eq!(restarted.load(&[2; 32]).unwrap(), Some(two));
        backend.set_mode(MODE_DEFINITELY_NOT_SENT);
        assert!(restarted
            .compare_and_advance(&two, &floor(3, 3, 6))
            .is_err());
        assert_eq!(restarted.load(&[2; 32]).unwrap(), Some(two));
    }
}
