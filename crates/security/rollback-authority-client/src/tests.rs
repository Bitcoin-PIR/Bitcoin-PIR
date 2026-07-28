use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use ed25519_dalek::SigningKey;
use pir_rollback_authority_protocol::{
    verify_authority_request_v1, AuthorityCasDispositionV1, AuthorityCasResolutionRefV1,
    AuthorityServerSignerV1, AuthorityValueCodecV1, AuthorityValueRootKeyV1,
    PersistedAuthorityOperationRefV1, PersistedAuthorityTerminalOutcomeRefV1,
    VerifiedAuthorityOperationRefV1,
};
use static_assertions::assert_not_impl_any;

use super::*;

const INSTANCE: [u8; 32] = [0x11; 32];
const NAMESPACE: [u8; 32] = [0x21; 32];
const CLIENT_SECRET: [u8; 32] = [0x31; 32];
const AUTHORITY_SECRET: [u8; 32] = [0x41; 32];
const VALUE_ROOT: [u8; 32] = [0x51; 32];
const OPERATION_ID: [u8; 32] = [0x71; 32];

type ScriptedPostV1 =
    Box<dyn FnOnce(&[u8], Instant) -> Result<Zeroizing<Vec<u8>>, AuthorityTransportErrorV1> + Send>;

struct ScriptedTransportV1 {
    scripts: Mutex<VecDeque<ScriptedPostV1>>,
    calls: AtomicUsize,
}

impl ScriptedTransportV1 {
    fn new(scripts: Vec<ScriptedPostV1>) -> Self {
        Self {
            scripts: Mutex::new(scripts.into()),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl AuthorityHttpsTransportV1 for ScriptedTransportV1 {
    fn post(
        &self,
        canonical_request: &[u8],
        absolute_deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, AuthorityTransportErrorV1> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let script = self
            .scripts
            .lock()
            .expect("script lock")
            .pop_front()
            .expect("unexpected transport call");
        script(canonical_request, absolute_deadline)
    }
}

fn client_signer_v1() -> AuthorityClientSignerV1 {
    AuthorityClientSignerV1::new(INSTANCE, NAMESPACE, SigningKey::from_bytes(&CLIENT_SECRET))
        .expect("test client signer")
}

fn authority_signer_v1() -> AuthorityServerSignerV1 {
    AuthorityServerSignerV1::new(INSTANCE, SigningKey::from_bytes(&AUTHORITY_SECRET))
        .expect("test authority signer")
}

fn value_codec_v1() -> AuthorityValueCodecV1 {
    let root = AuthorityValueRootKeyV1::from_bytes(VALUE_ROOT).expect("test value root");
    AuthorityValueCodecV1::derive(
        &root,
        INSTANCE,
        NAMESPACE,
        &SigningKey::from_bytes(&CLIENT_SECRET).verifying_key(),
    )
    .expect("test value codec")
}

fn client_with_scripts_v1(
    scripts: Vec<ScriptedPostV1>,
    attempt_timeout: Duration,
) -> (RemoteRollbackAuthorityClientV1, Arc<ScriptedTransportV1>) {
    let transport = Arc::new(ScriptedTransportV1::new(scripts));
    let erased: Arc<dyn AuthorityHttpsTransportV1> = transport.clone();
    let client = RemoteRollbackAuthorityClientV1::with_test_transport(
        erased,
        client_signer_v1(),
        authority_signer_v1().verifying_key(),
        attempt_timeout,
    )
    .expect("test client");
    (client, transport)
}

fn signed_empty_read_response_v1(request: &[u8]) -> Zeroizing<Vec<u8>> {
    let client_key = SigningKey::from_bytes(&CLIENT_SECRET).verifying_key();
    let verified =
        verify_authority_request_v1(request, &INSTANCE, &NAMESPACE, &client_key).unwrap();
    authority_signer_v1()
        .sign_read_response(&verified, None)
        .unwrap()
        .into_bytes()
}

fn signed_current_read_response_v1(
    request: &[u8],
    current: &OpaqueAuthorityRecordV1,
) -> Zeroizing<Vec<u8>> {
    let client_key = SigningKey::from_bytes(&CLIENT_SECRET).verifying_key();
    let verified =
        verify_authority_request_v1(request, &INSTANCE, &NAMESPACE, &client_key).unwrap();
    authority_signer_v1()
        .sign_read_response(&verified, Some(current))
        .unwrap()
        .into_bytes()
}

fn signed_applied_cas_response_v1(
    request: &[u8],
    disposition: AuthorityCasDispositionV1,
) -> Zeroizing<Vec<u8>> {
    let client_key = SigningKey::from_bytes(&CLIENT_SECRET).verifying_key();
    let verified =
        verify_authority_request_v1(request, &INSTANCE, &NAMESPACE, &client_key).unwrap();
    let desired = match verified.operation() {
        VerifiedAuthorityOperationRefV1::CompareAndSwap { desired, .. } => desired,
        VerifiedAuthorityOperationRefV1::Read => panic!("expected CAS request"),
    };
    let persisted = PersistedAuthorityOperationRefV1::from_persisted_row(
        verified.binding().authority_instance_id(),
        verified.binding().namespace(),
        verified.binding().client_key_id(),
        verified.call().operation_id(),
        verified.operation_digest(),
        PersistedAuthorityTerminalOutcomeRefV1::Applied(desired),
    )
    .unwrap();
    let resolution = AuthorityCasResolutionRefV1::from_linearized_transaction(
        persisted,
        Some(desired),
        disposition,
    );
    authority_signer_v1()
        .sign_compare_and_swap_response(&verified, resolution)
        .unwrap()
        .into_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservedOperationKindV1 {
    Read,
    CompareAndSwap,
}

#[derive(Debug)]
struct ObservedRequestV1 {
    call_nonce: [u8; 32],
    operation_id: [u8; 32],
    operation_digest: [u8; 32],
    exact_bytes: Vec<u8>,
    kind: ObservedOperationKindV1,
}

fn observe_request_v1(request: &[u8]) -> ObservedRequestV1 {
    let client_key = SigningKey::from_bytes(&CLIENT_SECRET).verifying_key();
    let verified =
        verify_authority_request_v1(request, &INSTANCE, &NAMESPACE, &client_key).unwrap();
    ObservedRequestV1 {
        call_nonce: *verified.call().call_nonce(),
        operation_id: *verified.call().operation_id(),
        operation_digest: *verified.operation_digest(),
        exact_bytes: request.to_vec(),
        kind: match verified.operation() {
            VerifiedAuthorityOperationRefV1::Read => ObservedOperationKindV1::Read,
            VerifiedAuthorityOperationRefV1::CompareAndSwap { .. } => {
                ObservedOperationKindV1::CompareAndSwap
            }
        },
    }
}

#[test]
fn production_constructor_requires_https_pins_and_bounded_timeouts() {
    let timeout = Duration::from_secs(1);
    let authority_key = authority_signer_v1().verifying_key();
    assert_eq!(
        RemoteRollbackAuthorityClientV1::new(
            "http://authority.example".to_owned(),
            timeout,
            timeout,
            timeout,
            &[[1; 32]],
            client_signer_v1(),
            authority_key,
        )
        .unwrap_err(),
        RemoteAuthorityClientConfigErrorV1::InvalidEndpoint
    );
    assert_eq!(
        RemoteRollbackAuthorityClientV1::new(
            "https://authority.example".to_owned(),
            timeout,
            timeout,
            Duration::ZERO,
            &[[1; 32]],
            client_signer_v1(),
            authority_key,
        )
        .unwrap_err(),
        RemoteAuthorityClientConfigErrorV1::InvalidAttemptTimeout
    );
    for pins in [
        &[][..],
        &[[1; 32], [1; 32]][..],
        &[[1; 32], [2; 32], [3; 32]][..],
    ] {
        assert_eq!(
            RemoteRollbackAuthorityClientV1::new(
                "https://authority.example".to_owned(),
                timeout,
                timeout,
                timeout,
                pins,
                client_signer_v1(),
                authority_key,
            )
            .unwrap_err(),
            RemoteAuthorityClientConfigErrorV1::InvalidPinnedHttpsConfiguration
        );
    }
    assert!(RemoteRollbackAuthorityClientV1::new(
        "https://authority.example/api".to_owned(),
        timeout,
        timeout,
        timeout,
        &[[1; 32], [2; 32]],
        client_signer_v1(),
        authority_key,
    )
    .is_ok());
}

#[test]
fn durable_operation_validates_and_redacts_all_linkable_material() {
    assert_not_impl_any!(DurableAuthorityCasOperationV1: Clone);
    assert_not_impl_any!(RemoteRollbackAuthorityClientV1: Clone);

    let codec = value_codec_v1();
    let initial = codec.seal(7, b"never-log-initial").unwrap();
    let successor = codec.seal(8, b"never-log-successor").unwrap();
    assert_eq!(
        DurableAuthorityCasOperationV1::from_durable_parts(
            [0; 32],
            Some(initial.duplicate_for_protocol()),
            successor.duplicate_for_protocol(),
        )
        .unwrap_err(),
        RemoteAuthorityOperationErrorV1::InvalidOperationId
    );
    let skipped = codec.seal(9, b"never-log-skipped").unwrap();
    assert_eq!(
        DurableAuthorityCasOperationV1::from_durable_parts(
            OPERATION_ID,
            Some(initial.duplicate_for_protocol()),
            skipped,
        )
        .unwrap_err(),
        RemoteAuthorityOperationErrorV1::InvalidRevisionTransition
    );
    let operation =
        DurableAuthorityCasOperationV1::from_durable_parts(OPERATION_ID, Some(initial), successor)
            .unwrap();
    let rendered = format!("{operation:?}");
    assert!(rendered.contains("REDACTED"));
    assert!(!rendered.contains("never-log"));
    assert!(!rendered.contains("113"));
}

#[test]
fn reads_are_one_shot_and_old_signed_transcripts_fail_closed() {
    let old_response = Arc::new(Mutex::new(None::<Vec<u8>>));
    let store_old = Arc::clone(&old_response);
    let replay_old = Arc::clone(&old_response);
    let (client, transport) = client_with_scripts_v1(
        vec![
            Box::new(move |request, _| {
                let response = signed_empty_read_response_v1(request);
                *store_old.lock().unwrap() = Some(response.to_vec());
                Ok(response)
            }),
            Box::new(move |_, _| {
                Ok(Zeroizing::new(
                    replay_old.lock().unwrap().as_ref().unwrap().clone(),
                ))
            }),
        ],
        Duration::from_secs(1),
    );
    assert!(client
        .read_until(Instant::now() + Duration::from_secs(2))
        .unwrap()
        .current()
        .is_none());
    assert!(matches!(
        client.read_until(Instant::now() + Duration::from_secs(2)),
        Err(RemoteAuthorityCallErrorV1::OutcomeUnknown)
    ));
    assert_eq!(transport.calls(), 2);
}

#[test]
fn cas_unknown_recovery_uses_fresh_read_and_fresh_same_operation_cas() {
    let codec = value_codec_v1();
    let initial = codec.seal(10, b"floor-10").unwrap();
    let desired = codec.seal(11, b"floor-11").unwrap();
    let desired_wire = Arc::new(desired.encode().to_vec());
    let operation =
        DurableAuthorityCasOperationV1::from_durable_parts(OPERATION_ID, Some(initial), desired)
            .unwrap();

    let observed = Arc::new(Mutex::new(Vec::<ObservedRequestV1>::new()));
    let first_observed = Arc::clone(&observed);
    let read_observed = Arc::clone(&observed);
    let retry_observed = Arc::clone(&observed);
    let read_current = Arc::clone(&desired_wire);
    let (client, transport) = client_with_scripts_v1(
        vec![
            Box::new(move |request, _| {
                first_observed
                    .lock()
                    .unwrap()
                    .push(observe_request_v1(request));
                // The authority may have committed the request, but its
                // response was not authenticated by the client.
                Err(AuthorityTransportErrorV1::OutcomeUnknown)
            }),
            Box::new(move |request, _| {
                read_observed
                    .lock()
                    .unwrap()
                    .push(observe_request_v1(request));
                let current = OpaqueAuthorityRecordV1::decode(read_current.as_slice()).unwrap();
                Ok(signed_current_read_response_v1(request, &current))
            }),
            Box::new(move |request, _| {
                retry_observed
                    .lock()
                    .unwrap()
                    .push(observe_request_v1(request));
                Ok(signed_applied_cas_response_v1(
                    request,
                    AuthorityCasDispositionV1::ExactOperationReplay,
                ))
            }),
        ],
        Duration::from_secs(1),
    );

    assert!(matches!(
        client.compare_and_swap_until(&operation, Instant::now() + Duration::from_secs(3),),
        Err(RemoteAuthorityCallErrorV1::OutcomeUnknown)
    ));
    let recovery = client
        .reconcile_unknown_compare_and_swap_until(
            &operation,
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
    assert_eq!(
        recovery
            .observed_before_reconcile()
            .current()
            .expect("fresh read current"),
        operation.desired()
    );
    assert!(matches!(
        recovery.reconciled(),
        RemoteAuthorityCasOutcomeV1::AlreadyApplied(record) if record == operation.desired()
    ));

    let observed = observed.lock().unwrap();
    assert_eq!(observed.len(), 3);
    assert_eq!(observed[0].kind, ObservedOperationKindV1::CompareAndSwap);
    assert_eq!(observed[1].kind, ObservedOperationKindV1::Read);
    assert_eq!(observed[2].kind, ObservedOperationKindV1::CompareAndSwap);
    assert_eq!(observed[0].operation_id, OPERATION_ID);
    assert_eq!(observed[2].operation_id, OPERATION_ID);
    assert_eq!(observed[0].operation_digest, observed[2].operation_digest);
    assert_ne!(observed[0].call_nonce, observed[2].call_nonce);
    assert_ne!(observed[0].exact_bytes, observed[2].exact_bytes);
    assert_ne!(observed[1].operation_id, OPERATION_ID);
    assert_eq!(transport.calls(), 3);
}

#[test]
fn malformed_truncated_oversized_bad_signature_and_wrong_key_are_unknown() {
    let bad_signature: ScriptedPostV1 = Box::new(|request, _| {
        let mut response = signed_empty_read_response_v1(request);
        let last = response.len() - 1;
        response[last] ^= 1;
        Ok(response)
    });
    let truncated: ScriptedPostV1 = Box::new(|request, _| {
        let mut response = signed_empty_read_response_v1(request);
        let truncated_len = response.len() - 1;
        response.truncate(truncated_len);
        Ok(response)
    });
    let oversized: ScriptedPostV1 = Box::new(|_, _| {
        Ok(Zeroizing::new(vec![
            0;
            MAX_SIGNED_AUTHORITY_RESPONSE_BYTES_V1
                + 1
        ]))
    });
    let wrong_key: ScriptedPostV1 = Box::new(|request, _| {
        let client_key = SigningKey::from_bytes(&CLIENT_SECRET).verifying_key();
        let verified =
            verify_authority_request_v1(request, &INSTANCE, &NAMESPACE, &client_key).unwrap();
        let wrong =
            AuthorityServerSignerV1::new(INSTANCE, SigningKey::from_bytes(&[0x42; 32])).unwrap();
        Ok(wrong
            .sign_read_response(&verified, None)
            .unwrap()
            .into_bytes())
    });

    for script in [bad_signature, truncated, oversized, wrong_key] {
        let (client, _) = client_with_scripts_v1(vec![script], Duration::from_secs(1));
        assert!(matches!(
            client.read_until(Instant::now() + Duration::from_secs(2)),
            Err(RemoteAuthorityCallErrorV1::OutcomeUnknown)
        ));
    }
}

#[test]
fn every_http_status_and_post_send_parse_failure_is_outcome_unknown() {
    for status in 0..=u16::MAX {
        assert_eq!(
            map_https_error_v1(HttpsPostErrorV1::HttpStatus {
                status,
                body: Zeroizing::new(Vec::new()),
            }),
            AuthorityTransportErrorV1::OutcomeUnknown
        );
    }
    for error in [
        HttpsPostErrorV1::OutcomeUnknown,
        HttpsPostErrorV1::InvalidResponse,
    ] {
        assert_eq!(
            map_https_error_v1(error),
            AuthorityTransportErrorV1::OutcomeUnknown
        );
    }
    assert_eq!(
        map_https_error_v1(HttpsPostErrorV1::DefinitelyNotSent),
        AuthorityTransportErrorV1::DefinitelyNotSent
    );
}

#[test]
fn deadline_and_attempt_timeout_do_not_retry_or_refresh() {
    let (expired_client, expired_transport) =
        client_with_scripts_v1(Vec::new(), Duration::from_secs(1));
    assert!(matches!(
        expired_client.read_until(Instant::now()),
        Err(RemoteAuthorityCallErrorV1::DefinitelyNotSent)
    ));
    assert_eq!(expired_transport.calls(), 0);

    let (unknown_client, unknown_transport) = client_with_scripts_v1(
        vec![Box::new(|_, _| {
            Err(AuthorityTransportErrorV1::OutcomeUnknown)
        })],
        Duration::from_secs(1),
    );
    assert!(matches!(
        unknown_client.read_until(Instant::now() + Duration::from_secs(2)),
        Err(RemoteAuthorityCallErrorV1::OutcomeUnknown)
    ));
    assert_eq!(unknown_transport.calls(), 1);

    let seen_deadline = Arc::new(Mutex::new(None::<Instant>));
    let record_deadline = Arc::clone(&seen_deadline);
    let started = Instant::now();
    let (slow_client, slow_transport) = client_with_scripts_v1(
        vec![Box::new(move |_, deadline| {
            *record_deadline.lock().unwrap() = Some(deadline);
            thread::sleep(Duration::from_millis(10));
            Ok(Zeroizing::new(vec![0; 300]))
        })],
        Duration::from_millis(1),
    );
    assert!(matches!(
        slow_client.read_until(started + Duration::from_secs(1)),
        Err(RemoteAuthorityCallErrorV1::OutcomeUnknown)
    ));
    let deadline = seen_deadline.lock().unwrap().expect("attempt deadline");
    assert!(deadline < started + Duration::from_secs(1));
    assert_eq!(slow_transport.calls(), 1);
}

#[test]
fn media_types_and_wire_bounds_are_exact_and_nonempty() {
    assert_eq!(
        ROLLBACK_AUTHORITY_CALL_ROUTE_V1,
        "/v1/rollback-authority/calls"
    );
    assert_ne!(
        ROLLBACK_AUTHORITY_REQUEST_CONTENT_TYPE_V1,
        ROLLBACK_AUTHORITY_RESPONSE_CONTENT_TYPE_V1
    );
    assert_ne!(
        ROLLBACK_AUTHORITY_RESPONSE_CONTENT_TYPE_V1,
        ROLLBACK_AUTHORITY_ERROR_CONTENT_TYPE_V1
    );
    for length in [
        SIGNED_AUTHORITY_READ_REQUEST_BYTES_V1,
        SIGNED_AUTHORITY_INITIALIZE_REQUEST_BYTES_V1,
        SIGNED_AUTHORITY_CAS_REQUEST_BYTES_V1,
    ] {
        assert!(valid_request_length_v1(length));
    }
    for length in [0, 1, SIGNED_AUTHORITY_CAS_REQUEST_BYTES_V1 + 1] {
        assert!(!valid_request_length_v1(length));
    }
}
