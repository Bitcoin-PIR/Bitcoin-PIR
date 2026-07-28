//! Production remote rollback authority for issuer state.
//!
//! The authority receives only a fixed-size opaque record. Issuer floors use
//! a strict, canonical domain encoding before namespace-bound AEAD sealing.
//!
//! The operation ID and randomized opaque successor exist only for the active
//! call. After process loss, the issuer's durable SQLite commit supplies the
//! authenticated one-step logical successor. A fresh signed Read either sees
//! that successor, sees its exact predecessor and permits a new CAS, or
//! exposes a fork and fails closed. This does not replay the prior remote
//! operation-log entry.

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
use pir_service_protocol::LightningNetworkV1;
use zeroize::Zeroizing;

use crate::{
    IssuerRollbackFloorAuthorityErrorV1, IssuerRollbackFloorAuthorityV1, IssuerRollbackFloorV1,
};

const ISSUER_FLOOR_MAGIC_V1: &[u8; 8] = b"BPIRFLR\0";
const ISSUER_FLOOR_VERSION_V1: u16 = 1;
const ISSUER_FLOOR_BYTES_V1: usize = 8 + 2 + 16 + 32 + 1 + 8 + 32 + 4;
const MAX_REMOTE_OPERATION_TIMEOUT_V1: Duration = Duration::from_secs(60);

trait IssuerRemoteAuthorityBackendV1: fmt::Debug + Send + Sync + 'static {
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

impl IssuerRemoteAuthorityBackendV1 for RemoteRollbackAuthorityClientV1 {
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

/// Independently hosted, pinned-HTTPS rollback authority for one issuer and
/// one Lightning network.
///
/// There is no local fallback. Remote, signature, binding, AEAD, decoding,
/// timeout, and outcome errors all fail the issuer store operation closed.
pub struct RemoteIssuerRollbackFloorAuthorityV1 {
    expected_issuer_id: [u8; 32],
    expected_network: LightningNetworkV1,
    backend: Arc<dyn IssuerRemoteAuthorityBackendV1>,
    codec: AuthorityValueCodecV1,
    operation_timeout: Duration,
}

impl fmt::Debug for RemoteIssuerRollbackFloorAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteIssuerRollbackFloorAuthorityV1")
            .field("expected_issuer_id", &"[REDACTED]")
            .field("expected_network", &"[REDACTED]")
            .field("backend", &"[REDACTED]")
            .field("codec", &"[REDACTED]")
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

impl RemoteIssuerRollbackFloorAuthorityV1 {
    pub fn new(
        expected_issuer_id: [u8; 32],
        expected_network: LightningNetworkV1,
        client: RemoteRollbackAuthorityClientV1,
        codec: AuthorityValueCodecV1,
        operation_timeout: Duration,
    ) -> Result<Self, IssuerRollbackFloorAuthorityErrorV1> {
        Self::with_backend(
            expected_issuer_id,
            expected_network,
            Arc::new(client),
            codec,
            operation_timeout,
        )
    }

    fn with_backend(
        expected_issuer_id: [u8; 32],
        expected_network: LightningNetworkV1,
        backend: Arc<dyn IssuerRemoteAuthorityBackendV1>,
        codec: AuthorityValueCodecV1,
        operation_timeout: Duration,
    ) -> Result<Self, IssuerRollbackFloorAuthorityErrorV1> {
        if expected_issuer_id.iter().all(|byte| *byte == 0) {
            return Err(error("remote issuer rollback binding is invalid"));
        }
        if operation_timeout.is_zero() || operation_timeout > MAX_REMOTE_OPERATION_TIMEOUT_V1 {
            return Err(error("remote issuer rollback timeout is invalid"));
        }
        if backend.binding() != codec.binding() {
            return Err(error(
                "remote issuer rollback cryptographic binding mismatch",
            ));
        }
        Ok(Self {
            expected_issuer_id,
            expected_network,
            backend,
            codec,
            operation_timeout,
        })
    }

    fn deadline(&self) -> Result<Instant, IssuerRollbackFloorAuthorityErrorV1> {
        Instant::now()
            .checked_add(self.operation_timeout)
            .ok_or_else(|| error("remote issuer rollback deadline is invalid"))
    }

    fn read_current(
        &self,
        deadline: Instant,
    ) -> Result<
        Option<(OpaqueAuthorityRecordV1, IssuerRollbackFloorV1)>,
        IssuerRollbackFloorAuthorityErrorV1,
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
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1> {
        let opened = self
            .codec
            .open(record)
            .map_err(|_| error("remote issuer rollback record authentication failed"))?;
        let floor = decode_floor_v1(opened.as_bytes())?;
        if floor.issuer_id != self.expected_issuer_id
            || floor.network != self.expected_network
            || floor.store_generation != record.revision()
        {
            return Err(error("remote issuer rollback record binding mismatch"));
        }
        Ok(floor)
    }

    fn seal_record(
        &self,
        floor: &IssuerRollbackFloorV1,
    ) -> Result<OpaqueAuthorityRecordV1, IssuerRollbackFloorAuthorityErrorV1> {
        let encoded = encode_floor_v1(floor)?;
        self.codec
            .seal(floor.store_generation, encoded.as_slice())
            .map_err(|_| error("remote issuer rollback record sealing failed"))
    }

    fn apply_exact(
        &self,
        expected: Option<OpaqueAuthorityRecordV1>,
        desired_floor: &IssuerRollbackFloorV1,
        deadline: Instant,
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1> {
        let desired = self.seal_record(desired_floor)?;
        let operation = DurableAuthorityCasOperationV1::generate(expected, desired)
            .map_err(|_| error("remote issuer rollback CAS construction failed"))?;
        let outcome = match self.backend.compare_and_swap_until(&operation, deadline) {
            Ok(outcome) => outcome,
            Err(RemoteAuthorityCallErrorV1::OutcomeUnknown) => self
                .backend
                .reconcile_unknown_until(&operation, deadline)
                .map_err(|_| error("remote issuer rollback CAS outcome remains unknown"))?,
            Err(RemoteAuthorityCallErrorV1::DefinitelyNotSent) => {
                return Err(error("remote issuer rollback CAS was not sent"));
            }
        };
        self.map_cas_outcome(outcome, &operation, desired_floor)
    }

    fn map_cas_outcome(
        &self,
        outcome: RemoteAuthorityCasOutcomeV1,
        operation: &DurableAuthorityCasOperationV1,
        desired_floor: &IssuerRollbackFloorV1,
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1> {
        match outcome {
            RemoteAuthorityCasOutcomeV1::Applied(record)
            | RemoteAuthorityCasOutcomeV1::AlreadyApplied(record) => {
                if &record != operation.desired() {
                    return Err(error("remote issuer rollback applied outcome mismatch"));
                }
                let floor = self.open_record(&record)?;
                if floor != *desired_floor {
                    return Err(error("remote issuer rollback desired floor mismatch"));
                }
                Ok(floor)
            }
            RemoteAuthorityCasOutcomeV1::ConflictCurrent(record) => self.open_record(&record),
            RemoteAuthorityCasOutcomeV1::Empty => Err(error(
                "remote issuer rollback authority became unexpectedly empty",
            )),
        }
    }
}

impl IssuerRollbackFloorAuthorityV1 for RemoteIssuerRollbackFloorAuthorityV1 {
    fn load(
        &self,
        issuer_id: &[u8; 32],
        network: LightningNetworkV1,
    ) -> Result<Option<IssuerRollbackFloorV1>, IssuerRollbackFloorAuthorityErrorV1> {
        if issuer_id != &self.expected_issuer_id || network != self.expected_network {
            return Err(error("remote issuer rollback logical binding mismatch"));
        }
        Ok(self.read_current(self.deadline()?)?.map(|(_, floor)| floor))
    }

    fn initialize(
        &self,
        initial: &IssuerRollbackFloorV1,
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1> {
        initial
            .validate()
            .map_err(|_| error("remote issuer rollback initial floor is invalid"))?;
        if initial.issuer_id != self.expected_issuer_id
            || initial.network != self.expected_network
            || initial.store_generation != 0
        {
            return Err(error("remote issuer rollback initial binding is invalid"));
        }
        let deadline = self.deadline()?;
        match self.read_current(deadline)? {
            Some((_, current)) => Ok(current),
            None => self.apply_exact(None, initial, deadline),
        }
    }

    fn compare_and_advance(
        &self,
        expected: &IssuerRollbackFloorV1,
        next: &IssuerRollbackFloorV1,
    ) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1> {
        validate_transition_v1(
            expected,
            next,
            &self.expected_issuer_id,
            self.expected_network,
        )?;
        let deadline = self.deadline()?;
        let Some((opaque_current, current)) = self.read_current(deadline)? else {
            return Err(error("remote issuer rollback floor is missing"));
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
    expected: &IssuerRollbackFloorV1,
    next: &IssuerRollbackFloorV1,
    issuer_id: &[u8; 32],
    network: LightningNetworkV1,
) -> Result<(), IssuerRollbackFloorAuthorityErrorV1> {
    expected
        .validate()
        .map_err(|_| error("remote issuer rollback expected floor is invalid"))?;
    next.validate()
        .map_err(|_| error("remote issuer rollback next floor is invalid"))?;
    let next_generation = expected
        .store_generation
        .checked_add(1)
        .ok_or_else(|| error("remote issuer rollback generation transition overflow"))?;
    if expected.issuer_id != *issuer_id
        || next.issuer_id != *issuer_id
        || expected.network != network
        || next.network != network
        || expected.store_instance_id != next.store_instance_id
        || expected.schema_version != next.schema_version
        || next.store_generation != next_generation
        || next.rollback_commitment == expected.rollback_commitment
    {
        return Err(error("remote issuer rollback transition is invalid"));
    }
    Ok(())
}

fn encode_floor_v1(
    floor: &IssuerRollbackFloorV1,
) -> Result<Zeroizing<Vec<u8>>, IssuerRollbackFloorAuthorityErrorV1> {
    floor
        .validate()
        .map_err(|_| error("remote issuer rollback floor is invalid"))?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(ISSUER_FLOOR_BYTES_V1));
    encoded.extend_from_slice(ISSUER_FLOOR_MAGIC_V1);
    encoded.extend_from_slice(&ISSUER_FLOOR_VERSION_V1.to_be_bytes());
    encoded.extend_from_slice(&floor.store_instance_id);
    encoded.extend_from_slice(&floor.issuer_id);
    encoded.push(floor.network as u8);
    encoded.extend_from_slice(&floor.store_generation.to_be_bytes());
    encoded.extend_from_slice(&floor.rollback_commitment);
    encoded.extend_from_slice(&floor.schema_version.to_be_bytes());
    if encoded.len() != ISSUER_FLOOR_BYTES_V1 {
        return Err(error("remote issuer rollback floor encoding failed"));
    }
    Ok(encoded)
}

fn decode_floor_v1(
    bytes: &[u8],
) -> Result<IssuerRollbackFloorV1, IssuerRollbackFloorAuthorityErrorV1> {
    if bytes.len() != ISSUER_FLOOR_BYTES_V1
        || bytes.get(..8) != Some(ISSUER_FLOOR_MAGIC_V1.as_slice())
    {
        return Err(error("remote issuer rollback floor encoding is invalid"));
    }
    if u16::from_be_bytes(fixed(bytes, 8)?) != ISSUER_FLOOR_VERSION_V1 {
        return Err(error("remote issuer rollback floor version is unsupported"));
    }
    let network = match bytes[58] {
        1 => LightningNetworkV1::Bitcoin,
        2 => LightningNetworkV1::Testnet,
        3 => LightningNetworkV1::Signet,
        4 => LightningNetworkV1::Regtest,
        _ => return Err(error("remote issuer rollback network is invalid")),
    };
    let floor = IssuerRollbackFloorV1 {
        store_instance_id: fixed(bytes, 10)?,
        issuer_id: fixed(bytes, 26)?,
        network,
        store_generation: u64::from_be_bytes(fixed(bytes, 59)?),
        rollback_commitment: fixed(bytes, 67)?,
        schema_version: u32::from_be_bytes(fixed(bytes, 99)?),
    };
    floor
        .validate()
        .map_err(|_| error("remote issuer rollback floor decoding failed"))?;
    Ok(floor)
}

fn fixed<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], IssuerRollbackFloorAuthorityErrorV1> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| error("remote issuer rollback floor is truncated"))?;
    bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| error("remote issuer rollback floor is truncated"))
}

fn remote_call_error(
    error_value: RemoteAuthorityCallErrorV1,
) -> IssuerRollbackFloorAuthorityErrorV1 {
    match error_value {
        RemoteAuthorityCallErrorV1::DefinitelyNotSent => {
            error("remote issuer rollback request was not sent")
        }
        RemoteAuthorityCallErrorV1::OutcomeUnknown => {
            error("remote issuer rollback request outcome is unknown")
        }
    }
}

fn error(reason: &'static str) -> IssuerRollbackFloorAuthorityErrorV1 {
    IssuerRollbackFloorAuthorityErrorV1::new(reason)
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

    impl IssuerRemoteAuthorityBackendV1 for FakeBackend {
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
    ) -> RemoteIssuerRollbackFloorAuthorityV1 {
        RemoteIssuerRollbackFloorAuthorityV1::with_backend(
            [2; 32],
            LightningNetworkV1::Signet,
            backend,
            codec,
            Duration::from_secs(1),
        )
        .unwrap()
    }

    fn floor(generation: u64, commitment: u8) -> IssuerRollbackFloorV1 {
        IssuerRollbackFloorV1 {
            store_instance_id: [1; 16],
            issuer_id: [2; 32],
            network: LightningNetworkV1::Signet,
            store_generation: generation,
            rollback_commitment: [commitment; 32],
            schema_version: crate::SCHEMA_VERSION,
        }
    }

    #[test]
    fn issuer_remote_floor_encoding_is_exact_and_domain_separated() {
        let expected = floor(7, 9);
        let encoded = encode_floor_v1(&expected).unwrap();
        assert_eq!(encoded.len(), ISSUER_FLOOR_BYTES_V1);
        assert_eq!(decode_floor_v1(&encoded).unwrap(), expected);

        let mut bad_magic = encoded.to_vec();
        bad_magic[0] ^= 1;
        assert!(decode_floor_v1(&bad_magic).is_err());
        let mut bad_version = encoded.to_vec();
        bad_version[9] = 2;
        assert!(decode_floor_v1(&bad_version).is_err());
        let mut bad_network = encoded.to_vec();
        bad_network[58] = 0;
        assert!(decode_floor_v1(&bad_network).is_err());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode_floor_v1(&trailing).is_err());
    }

    #[test]
    fn issuer_remote_floor_transition_requires_exact_revision_and_binding() {
        let zero = floor(0, 3);
        let one = floor(1, 4);
        assert!(validate_transition_v1(&zero, &one, &[2; 32], LightningNetworkV1::Signet).is_ok());
        assert!(
            validate_transition_v1(&zero, &floor(2, 4), &[2; 32], LightningNetworkV1::Signet)
                .is_err()
        );
        let mut rebound = one;
        rebound.network = LightningNetworkV1::Testnet;
        assert!(
            validate_transition_v1(&zero, &rebound, &[2; 32], LightningNetworkV1::Signet).is_err()
        );
    }

    #[test]
    fn issuer_remote_floor_maps_all_cas_outcomes_and_unknown_recovery() {
        let codec = make_codec(9, 10);
        let backend = Arc::new(FakeBackend::new(codec.binding().duplicate_for_protocol()));
        let authority = authority(backend.clone(), codec);
        let zero = floor(0, 3);
        let one = floor(1, 4);
        let two = floor(2, 5);

        assert_eq!(authority.initialize(&zero).unwrap(), zero);

        let desired = authority.seal_record(&zero).unwrap();
        let operation = DurableAuthorityCasOperationV1::generate(None, desired).unwrap();
        assert!(authority
            .map_cas_outcome(
                RemoteAuthorityCasOutcomeV1::Applied(authority.seal_record(&floor(0, 77)).unwrap()),
                &operation,
                &zero,
            )
            .is_err());

        backend.set_mode(MODE_UNKNOWN_AFTER_APPLY);
        assert_eq!(authority.compare_and_advance(&zero, &one).unwrap(), one);
        assert_eq!(backend.reconciles.load(Ordering::SeqCst), 1);
        assert_eq!(authority.compare_and_advance(&zero, &one).unwrap(), one);

        let fork = floor(1, 12);
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
    fn issuer_remote_floor_rejects_tamper_wrong_binding_network_and_revision() {
        let codec = make_codec(9, 10);
        let backend = Arc::new(FakeBackend::new(codec.binding().duplicate_for_protocol()));
        let authority = authority(backend.clone(), codec);
        let zero = floor(0, 3);

        let record = authority.seal_record(&zero).unwrap();
        let mut tampered = record.encode();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        backend.set_current(OpaqueAuthorityRecordV1::decode(&tampered).unwrap());
        assert!(authority
            .load(&[2; 32], LightningNetworkV1::Signet)
            .is_err());

        backend.set_current(
            authority
                .codec
                .seal(
                    zero.store_generation + 1,
                    encode_floor_v1(&zero).unwrap().as_slice(),
                )
                .unwrap(),
        );
        assert!(authority
            .load(&[2; 32], LightningNetworkV1::Signet)
            .is_err());
        assert!(authority
            .load(&[2; 32], LightningNetworkV1::Testnet)
            .is_err());

        let mut rebound = zero;
        rebound.network = LightningNetworkV1::Testnet;
        backend.set_current(authority.seal_record(&rebound).unwrap());
        assert!(authority
            .load(&[2; 32], LightningNetworkV1::Signet)
            .is_err());

        let wrong_namespace = make_codec(11, 10);
        assert!(RemoteIssuerRollbackFloorAuthorityV1::with_backend(
            [2; 32],
            LightningNetworkV1::Signet,
            backend.clone(),
            wrong_namespace,
            Duration::from_secs(1),
        )
        .is_err());
        assert!(make_codec(9, 12).open(&record).is_err());
    }

    #[test]
    fn issuer_remote_floor_fresh_restart_converges_by_logical_floor() {
        let first_codec = make_codec(9, 10);
        let backend = Arc::new(FakeBackend::new(
            first_codec.binding().duplicate_for_protocol(),
        ));
        let first = authority(backend.clone(), first_codec);
        let zero = floor(0, 3);
        let one = floor(1, 4);
        assert_eq!(first.initialize(&zero).unwrap(), zero);
        backend.set_mode(MODE_UNKNOWN_AFTER_APPLY);
        assert_eq!(first.compare_and_advance(&zero, &one).unwrap(), one);
        drop(first);

        let restarted = authority(backend.clone(), make_codec(9, 10));
        assert_eq!(
            restarted
                .load(&[2; 32], LightningNetworkV1::Signet)
                .unwrap(),
            Some(one)
        );
        assert_eq!(restarted.compare_and_advance(&zero, &one).unwrap(), one);
        let two = floor(2, 5);
        assert_eq!(restarted.compare_and_advance(&one, &two).unwrap(), two);
        backend.set_mode(MODE_READ_FAILURE);
        assert!(restarted
            .load(&[2; 32], LightningNetworkV1::Signet)
            .is_err());
        backend.set_mode(MODE_NORMAL);
        assert_eq!(
            restarted
                .load(&[2; 32], LightningNetworkV1::Signet)
                .unwrap(),
            Some(two)
        );
        backend.set_mode(MODE_DEFINITELY_NOT_SENT);
        assert!(restarted.compare_and_advance(&two, &floor(3, 6)).is_err());
        assert_eq!(
            restarted
                .load(&[2; 32], LightningNetworkV1::Signet)
                .unwrap(),
            Some(two)
        );
    }
}
