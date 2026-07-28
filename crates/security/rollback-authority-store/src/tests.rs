use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use pir_rollback_authority_protocol::{
    verify_authority_read_response_v1, verify_authority_response_v1, AuthorityCallV1,
    AuthorityClientSignerV1, AuthorityServerSignerV1, AuthorityValueCodecV1,
    AuthorityValueRootKeyV1, OpaqueAuthorityRecordV1, VerifiedAuthorityCasOutcomeV1,
    VerifiedAuthorityResponseBodyRefV1, MAX_SIGNED_AUTHORITY_REQUEST_BYTES_V1,
};
use tempfile::TempDir;

use crate::{
    RollbackAuthorityStoreErrorV1, SqliteRollbackAuthorityProvisionerV1,
    SqliteRollbackAuthorityStoreV1, MAX_CALL_ROWS_PER_NAMESPACE_V1,
    MAX_OPERATION_ROWS_PER_NAMESPACE_V1,
};

const INSTANCE: [u8; 32] = [0x11; 32];
const OTHER_INSTANCE: [u8; 32] = [0x12; 32];
const NAMESPACE: [u8; 32] = [0x21; 32];
const OTHER_NAMESPACE: [u8; 32] = [0x22; 32];
const CLIENT_SECRET: [u8; 32] = [0x31; 32];
const OTHER_CLIENT_SECRET: [u8; 32] = [0x32; 32];
const SERVER_SECRET: [u8; 32] = [0x41; 32];
const VALUE_ROOT: [u8; 32] = [0x51; 32];
const TEST_OPERATION_ROWS: u64 = 16;
const TEST_CALL_ROWS: u64 = 64;

fn timeout() -> Duration {
    Duration::from_secs(5)
}

struct Fixture {
    _directory: TempDir,
    path: PathBuf,
    store: SqliteRollbackAuthorityStoreV1,
    client: AuthorityClientSignerV1,
    codec: AuthorityValueCodecV1,
}

fn private_tempdir() -> TempDir {
    let directory = tempfile::Builder::new()
        .prefix("bpir-rollback-authority-")
        .tempdir()
        .expect("temporary directory");
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary directory");
    directory
}

fn fixture() -> Fixture {
    fixture_with_capacity(TEST_OPERATION_ROWS)
}

fn fixture_with_capacity(max_operation_rows: u64) -> Fixture {
    fixture_with_capacities(max_operation_rows, TEST_CALL_ROWS)
}

fn fixture_with_capacities(max_operation_rows: u64, max_call_rows: u64) -> Fixture {
    let directory = private_tempdir();
    let path = directory.path().join("authority.sqlite3");
    let client_key = SigningKey::from_bytes(&CLIENT_SECRET);
    let provisioner = SqliteRollbackAuthorityProvisionerV1::create(&path, INSTANCE, timeout())
        .expect("create authority");
    provisioner
        .provision_namespace(
            NAMESPACE,
            &client_key.verifying_key(),
            max_operation_rows,
            max_call_rows,
        )
        .expect("provision namespace");
    let store = provisioner.into_online();
    let client =
        AuthorityClientSignerV1::new(INSTANCE, NAMESPACE, client_key).expect("client signer");
    let root = AuthorityValueRootKeyV1::from_bytes(VALUE_ROOT).expect("root key");
    let codec = AuthorityValueCodecV1::derive(&root, INSTANCE, NAMESPACE, &client.verifying_key())
        .expect("value codec");
    Fixture {
        _directory: directory,
        path,
        store,
        client,
        codec,
    }
}

fn server_signer() -> AuthorityServerSignerV1 {
    AuthorityServerSignerV1::new(INSTANCE, SigningKey::from_bytes(&SERVER_SECRET))
        .expect("server signer")
}

fn call(nonce: u8, operation: u8) -> AuthorityCallV1 {
    AuthorityCallV1::from_parts([nonce; 32], [operation; 32]).expect("authority call")
}

fn run_cas(
    fixture: &Fixture,
    call: &AuthorityCallV1,
    expected: Option<&OpaqueAuthorityRecordV1>,
    desired: &OpaqueAuthorityRecordV1,
) -> u8 {
    let request = fixture
        .client
        .sign_compare_and_swap(call, expected, desired)
        .expect("sign CAS");
    let response = fixture
        .store
        .handle_signed_request(request.as_bytes(), &server_signer())
        .expect("handle CAS");
    let verified = verify_authority_response_v1(
        response.as_bytes(),
        &request,
        &server_signer().verifying_key(),
    )
    .expect("verify CAS response");
    match verified.body() {
        VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(
            VerifiedAuthorityCasOutcomeV1::Empty,
        ) => 0,
        VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(
            VerifiedAuthorityCasOutcomeV1::Applied(_),
        ) => 1,
        VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(
            VerifiedAuthorityCasOutcomeV1::AlreadyApplied(_),
        ) => 2,
        VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(
            VerifiedAuthorityCasOutcomeV1::ConflictCurrent(_),
        ) => 3,
        other => panic!("unexpected response: {other:?}"),
    }
}

fn read_revision(
    store: &SqliteRollbackAuthorityStoreV1,
    client: &AuthorityClientSignerV1,
) -> Option<u64> {
    let attempt = client.sign_fresh_read().expect("fresh read");
    let response = store
        .handle_signed_request(attempt.as_bytes(), &server_signer())
        .expect("handle read");
    let verified = verify_authority_read_response_v1(
        response.as_bytes(),
        attempt,
        &server_signer().verifying_key(),
    )
    .expect("verify read");
    match verified.body() {
        VerifiedAuthorityResponseBodyRefV1::Read { current } => {
            current.map(OpaqueAuthorityRecordV1::revision)
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn initialize_advance_empty_and_conflict_each_persist_first_outcome() {
    let fixture = fixture();
    let absent_expected = fixture.codec.seal(0, b"absent").expect("absent");
    let absent_desired = fixture.codec.seal(1, b"unused").expect("unused");
    assert_eq!(
        run_cas(
            &fixture,
            &call(0x61, 0x71),
            Some(&absent_expected),
            &absent_desired,
        ),
        0
    );

    let initial = fixture.codec.seal(0, b"floor-zero").expect("initial");
    assert_eq!(run_cas(&fixture, &call(0x62, 0x72), None, &initial), 1);

    let wrong_expected = fixture
        .codec
        .seal(0, b"wrong-floor")
        .expect("wrong expected");
    let conflict_desired = fixture
        .codec
        .seal(1, b"must-not-apply")
        .expect("conflict desired");
    assert_eq!(
        run_cas(
            &fixture,
            &call(0x63, 0x73),
            Some(&wrong_expected),
            &conflict_desired,
        ),
        3
    );

    let successor = fixture.codec.seal(1, b"floor-one").expect("successor");
    assert_eq!(
        run_cas(&fixture, &call(0x64, 0x74), Some(&initial), &successor,),
        1
    );
    assert_eq!(fixture.store.operation_count_for_tests().unwrap(), 4);
    assert_eq!(read_revision(&fixture.store, &fixture.client), Some(1));

    // The first Empty is terminal. Once another operation initializes the
    // record, its exact retry reports live conflict and never applies.
    assert_eq!(
        run_cas(
            &fixture,
            &call(0x65, 0x71),
            Some(&absent_expected),
            &absent_desired,
        ),
        3
    );
    assert_eq!(fixture.store.operation_count_for_tests().unwrap(), 4);
}

#[test]
fn exact_operation_replay_uses_fresh_nonce_and_digest_mismatch_is_rejected() {
    let fixture = fixture();
    let desired = fixture.codec.seal(0, b"initial").expect("desired");
    assert_eq!(run_cas(&fixture, &call(0x61, 0x71), None, &desired), 1);
    assert_eq!(run_cas(&fixture, &call(0x62, 0x71), None, &desired), 2);
    assert_eq!(fixture.store.operation_count_for_tests().unwrap(), 1);

    let divergent = fixture
        .codec
        .seal(0, b"different-content")
        .expect("divergent");
    let request = fixture
        .client
        .sign_compare_and_swap(&call(0x63, 0x71), None, &divergent)
        .expect("sign divergent reuse");
    assert_eq!(
        fixture
            .store
            .handle_signed_request(request.as_bytes(), &server_signer())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::OperationReplayMismatch
    );
    assert_eq!(fixture.store.operation_count_for_tests().unwrap(), 1);
    assert_eq!(read_revision(&fixture.store, &fixture.client), Some(0));
}

#[test]
fn replay_of_applied_operation_reports_conflict_after_live_floor_advances() {
    let fixture = fixture();
    let initial = fixture.codec.seal(0, b"initial").expect("initial");
    let successor = fixture.codec.seal(1, b"successor").expect("successor");
    assert_eq!(run_cas(&fixture, &call(0x61, 0x71), None, &initial), 1);
    assert_eq!(
        run_cas(&fixture, &call(0x62, 0x72), Some(&initial), &successor,),
        1
    );
    assert_eq!(run_cas(&fixture, &call(0x63, 0x71), None, &initial), 3);
    assert_eq!(fixture.store.operation_count_for_tests().unwrap(), 2);
    assert_eq!(read_revision(&fixture.store, &fixture.client), Some(1));
}

#[test]
fn exact_signed_cas_replay_returns_its_first_snapshot_while_fresh_nonce_observes_live() {
    let fixture = fixture();
    let initial = fixture.codec.seal(0, b"initial").expect("initial");
    let first_call = call(0x61, 0x71);
    let first_request = fixture
        .client
        .sign_compare_and_swap(&first_call, None, &initial)
        .expect("first request");
    let first_response = fixture
        .store
        .handle_signed_request(first_request.as_bytes(), &server_signer())
        .expect("first response");
    let first_response_bytes = first_response.as_bytes().to_vec();

    let successor = fixture.codec.seal(1, b"successor").expect("successor");
    assert_eq!(
        run_cas(&fixture, &call(0x62, 0x72), Some(&initial), &successor,),
        1
    );

    let exact_replay = fixture
        .store
        .handle_signed_request(first_request.as_bytes(), &server_signer())
        .expect("exact request replay");
    assert_eq!(exact_replay.as_bytes(), first_response_bytes);
    let verified = verify_authority_response_v1(
        exact_replay.as_bytes(),
        &first_request,
        &server_signer().verifying_key(),
    )
    .expect("verify exact replay");
    assert!(matches!(
        verified.body(),
        VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(
            VerifiedAuthorityCasOutcomeV1::Applied(record)
        ) if record == &initial
    ));

    // A fresh nonce is a distinct call attempt and preserves the existing
    // outcome-unknown reconciliation semantics.
    assert_eq!(run_cas(&fixture, &call(0x63, 0x71), None, &initial), 3);
    assert_eq!(fixture.store.operation_count_for_tests().unwrap(), 2);
    assert_eq!(fixture.store.call_count_for_tests().unwrap(), 3);
}

#[test]
fn exact_signed_read_replay_returns_first_snapshot_not_later_live_floor() {
    let fixture = fixture();
    let initial = fixture.codec.seal(0, b"initial").expect("initial");
    assert_eq!(run_cas(&fixture, &call(0x61, 0x71), None, &initial), 1);

    let read_attempt = fixture.client.sign_fresh_read().expect("fresh read");
    let first_response = fixture
        .store
        .handle_signed_request(read_attempt.as_bytes(), &server_signer())
        .expect("first read");
    let first_response_bytes = first_response.as_bytes().to_vec();

    let successor = fixture.codec.seal(1, b"successor").expect("successor");
    assert_eq!(
        run_cas(&fixture, &call(0x62, 0x72), Some(&initial), &successor,),
        1
    );
    let reopened =
        SqliteRollbackAuthorityStoreV1::open_existing(&fixture.path, INSTANCE, timeout())
            .expect("reopen authority");
    let replay = reopened
        .handle_signed_request(read_attempt.as_bytes(), &server_signer())
        .expect("exact read replay after reopen");
    assert_eq!(replay.as_bytes(), first_response_bytes);
    let verified = verify_authority_read_response_v1(
        replay.as_bytes(),
        read_attempt,
        &server_signer().verifying_key(),
    )
    .expect("verify replayed read");
    assert!(matches!(
        verified.body(),
        VerifiedAuthorityResponseBodyRefV1::Read {
            current: Some(record)
        } if record == &initial
    ));

    // The client recovery API creates a new nonce and operation ID, so a
    // genuinely fresh Read still observes the successor.
    assert_eq!(read_revision(&fixture.store, &fixture.client), Some(1));
    assert_eq!(fixture.store.call_count_for_tests().unwrap(), 4);
}

#[test]
fn reused_call_nonce_with_different_signed_request_fails_closed() {
    let fixture = fixture();
    let initial = fixture.codec.seal(0, b"initial").expect("initial");
    assert_eq!(run_cas(&fixture, &call(0x61, 0x71), None, &initial), 1);

    let colliding = fixture
        .client
        .sign_compare_and_swap(&call(0x61, 0x72), None, &initial)
        .expect("signed colliding nonce");
    assert_eq!(
        fixture
            .store
            .handle_signed_request(colliding.as_bytes(), &server_signer())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::OperationReplayMismatch
    );
    assert_eq!(fixture.store.operation_count_for_tests().unwrap(), 1);
    assert_eq!(fixture.store.call_count_for_tests().unwrap(), 1);
}

#[test]
fn committed_cas_survives_response_signing_failure_and_reconciles_as_replay() {
    let fixture = fixture();
    let desired = fixture.codec.seal(0, b"initial").expect("desired");
    let first_request = fixture
        .client
        .sign_compare_and_swap(&call(0x61, 0x71), None, &desired)
        .expect("first request");
    let wrong_instance_signer =
        AuthorityServerSignerV1::new(OTHER_INSTANCE, SigningKey::from_bytes(&SERVER_SECRET))
            .expect("wrong-instance signer");
    assert_eq!(
        fixture
            .store
            .handle_signed_request(first_request.as_bytes(), &wrong_instance_signer)
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::ResponseSigningFailure
    );

    // The transaction committed before signing was attempted. A fresh-nonce
    // exact retry therefore reconciles through the durable operation row.
    assert_eq!(run_cas(&fixture, &call(0x62, 0x71), None, &desired), 2);
    assert_eq!(fixture.store.operation_count_for_tests().unwrap(), 1);
    assert_eq!(read_revision(&fixture.store, &fixture.client), Some(0));
}

#[test]
fn provisioning_is_exactly_idempotent_and_rebind_is_rejected() {
    let directory = private_tempdir();
    let path = directory.path().join("authority.sqlite3");
    let client = SigningKey::from_bytes(&CLIENT_SECRET).verifying_key();
    let provisioner =
        SqliteRollbackAuthorityProvisionerV1::create(&path, INSTANCE, timeout()).unwrap();
    assert_eq!(
        provisioner
            .provision_namespace(NAMESPACE, &client, 0, MAX_CALL_ROWS_PER_NAMESPACE_V1)
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::InvalidConfiguration
    );
    assert_eq!(
        provisioner
            .provision_namespace(
                NAMESPACE,
                &client,
                MAX_OPERATION_ROWS_PER_NAMESPACE_V1 + 1,
                MAX_CALL_ROWS_PER_NAMESPACE_V1,
            )
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::InvalidConfiguration
    );
    for invalid_call_rows in [0, MAX_CALL_ROWS_PER_NAMESPACE_V1 + 1] {
        assert_eq!(
            provisioner
                .provision_namespace(
                    NAMESPACE,
                    &client,
                    MAX_OPERATION_ROWS_PER_NAMESPACE_V1,
                    invalid_call_rows,
                )
                .unwrap_err(),
            RollbackAuthorityStoreErrorV1::InvalidConfiguration
        );
    }
    provisioner
        .provision_namespace(
            NAMESPACE,
            &client,
            MAX_OPERATION_ROWS_PER_NAMESPACE_V1,
            MAX_CALL_ROWS_PER_NAMESPACE_V1,
        )
        .unwrap();
    provisioner
        .provision_namespace(
            NAMESPACE,
            &client,
            MAX_OPERATION_ROWS_PER_NAMESPACE_V1,
            MAX_CALL_ROWS_PER_NAMESPACE_V1,
        )
        .unwrap();
    let other = SigningKey::from_bytes(&OTHER_CLIENT_SECRET).verifying_key();
    assert_eq!(
        provisioner
            .provision_namespace(
                NAMESPACE,
                &other,
                MAX_OPERATION_ROWS_PER_NAMESPACE_V1,
                MAX_CALL_ROWS_PER_NAMESPACE_V1,
            )
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::NamespaceRebindRejected
    );
    assert_eq!(
        provisioner
            .provision_namespace(
                NAMESPACE,
                &client,
                MAX_OPERATION_ROWS_PER_NAMESPACE_V1 - 1,
                MAX_CALL_ROWS_PER_NAMESPACE_V1,
            )
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::NamespaceRebindRejected
    );
    assert_eq!(
        provisioner
            .provision_namespace(
                NAMESPACE,
                &client,
                MAX_OPERATION_ROWS_PER_NAMESPACE_V1,
                MAX_CALL_ROWS_PER_NAMESPACE_V1 - 1,
            )
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::NamespaceRebindRejected
    );
    assert_eq!(
        provisioner
            .provision_namespace(
                OTHER_NAMESPACE,
                &other,
                MAX_OPERATION_ROWS_PER_NAMESPACE_V1,
                MAX_CALL_ROWS_PER_NAMESPACE_V1,
            )
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::NamespaceRebindRejected
    );
}

#[test]
fn offline_capacity_inventory_is_explicit_redacted_and_restart_safe() {
    let directory = private_tempdir();
    let path = directory.path().join("authority.sqlite3");
    let client_key = SigningKey::from_bytes(&CLIENT_SECRET);
    let provisioner =
        SqliteRollbackAuthorityProvisionerV1::create(&path, INSTANCE, timeout()).unwrap();
    let unprovisioned = provisioner.operation_capacity_inventory().unwrap();
    assert!(!unprovisioned.is_provisioned());
    assert_eq!(unprovisioned.provisioned_capacity(), None);
    assert_eq!(unprovisioned.provisioned_call_capacity(), None);
    assert!(format!("{unprovisioned:?}").contains("REDACTED"));

    provisioner
        .provision_namespace(
            NAMESPACE,
            &client_key.verifying_key(),
            TEST_OPERATION_ROWS,
            TEST_CALL_ROWS,
        )
        .unwrap();
    assert_eq!(
        provisioner
            .operation_capacity_inventory()
            .unwrap()
            .provisioned_capacity(),
        Some((0, TEST_OPERATION_ROWS))
    );
    assert_eq!(
        provisioner
            .operation_capacity_inventory()
            .unwrap()
            .provisioned_call_capacity(),
        Some((0, TEST_CALL_ROWS))
    );

    let client =
        AuthorityClientSignerV1::new(INSTANCE, NAMESPACE, client_key).expect("client signer");
    let root = AuthorityValueRootKeyV1::from_bytes(VALUE_ROOT).expect("root key");
    let codec = AuthorityValueCodecV1::derive(&root, INSTANCE, NAMESPACE, &client.verifying_key())
        .expect("value codec");
    let desired = codec.seal(0, b"initial").expect("initial");
    let store = provisioner.into_online();
    let request = client
        .sign_compare_and_swap(&call(0x61, 0x71), None, &desired)
        .unwrap();
    store
        .handle_signed_request(request.as_bytes(), &server_signer())
        .unwrap();
    drop(store);

    let reopened =
        SqliteRollbackAuthorityProvisionerV1::open_existing(&path, INSTANCE, timeout()).unwrap();
    assert_eq!(
        reopened
            .operation_capacity_inventory()
            .unwrap()
            .provisioned_capacity(),
        Some((1, TEST_OPERATION_ROWS))
    );
    assert_eq!(
        reopened
            .operation_capacity_inventory()
            .unwrap()
            .provisioned_call_capacity(),
        Some((1, TEST_CALL_ROWS))
    );
}

#[test]
fn call_capacity_is_hard_exact_replay_safe_and_restart_persistent() {
    let fixture = fixture_with_capacities(4, 1);
    let initial = fixture.codec.seal(0, b"initial").expect("initial");
    let request = fixture
        .client
        .sign_compare_and_swap(&call(0x61, 0x71), None, &initial)
        .expect("first request");
    let first = fixture
        .store
        .handle_signed_request(request.as_bytes(), &server_signer())
        .expect("first response");
    let first_bytes = first.as_bytes().to_vec();
    assert_eq!(fixture.store.call_capacity_for_tests().unwrap(), (1, 1));

    let exact = fixture
        .store
        .handle_signed_request(request.as_bytes(), &server_signer())
        .expect("exact replay at capacity");
    assert_eq!(exact.as_bytes(), first_bytes);
    assert_eq!(fixture.store.call_capacity_for_tests().unwrap(), (1, 1));

    let fresh_retry = fixture
        .client
        .sign_compare_and_swap(&call(0x62, 0x71), None, &initial)
        .expect("fresh CAS attempt");
    assert_eq!(
        fixture
            .store
            .handle_signed_request(fresh_retry.as_bytes(), &server_signer())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::CallCapacityExhausted
    );
    let fresh_read = fixture.client.sign_fresh_read().expect("fresh read");
    assert_eq!(
        fixture
            .store
            .handle_signed_request(fresh_read.as_bytes(), &server_signer())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::CallCapacityExhausted
    );

    let Fixture {
        _directory,
        path,
        store,
        client: _,
        codec: _,
    } = fixture;
    drop(store);
    let reopened =
        SqliteRollbackAuthorityStoreV1::open_existing(&path, INSTANCE, timeout()).unwrap();
    let replay_after_restart = reopened
        .handle_signed_request(request.as_bytes(), &server_signer())
        .expect("exact replay after restart");
    assert_eq!(replay_after_restart.as_bytes(), first_bytes);
    assert_eq!(reopened.call_capacity_for_tests().unwrap(), (1, 1));
    drop(reopened);
    drop(_directory);
}

#[test]
fn operation_capacity_is_hard_replay_safe_and_survives_restart() {
    let fixture = fixture_with_capacity(1);
    let initial = fixture.codec.seal(0, b"initial").expect("initial");
    assert_eq!(run_cas(&fixture, &call(0x61, 0x71), None, &initial), 1);
    assert_eq!(
        fixture.store.operation_capacity_for_tests().unwrap(),
        (1, 1)
    );

    // Exact replay remains available at capacity and consumes no second row.
    assert_eq!(run_cas(&fixture, &call(0x62, 0x71), None, &initial), 2);
    assert_eq!(
        fixture.store.operation_capacity_for_tests().unwrap(),
        (1, 1)
    );

    let successor = fixture.codec.seal(1, b"successor").expect("successor");
    let request = fixture
        .client
        .sign_compare_and_swap(&call(0x63, 0x72), Some(&initial), &successor)
        .expect("successor request");
    assert_eq!(
        fixture
            .store
            .handle_signed_request(request.as_bytes(), &server_signer())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::OperationCapacityExhausted
    );
    assert_eq!(fixture.store.operation_count_for_tests().unwrap(), 1);
    assert_eq!(
        fixture.store.operation_capacity_for_tests().unwrap(),
        (1, 1)
    );
    assert_eq!(read_revision(&fixture.store, &fixture.client), Some(0));

    let Fixture {
        _directory,
        path,
        store,
        client,
        codec: _,
    } = fixture;
    drop(store);
    let reopened =
        SqliteRollbackAuthorityStoreV1::open_existing(&path, INSTANCE, timeout()).unwrap();
    assert_eq!(reopened.operation_capacity_for_tests().unwrap(), (1, 1));
    assert_eq!(read_revision(&reopened, &client), Some(0));
    drop(reopened);
    drop(_directory);
}

#[test]
fn restart_preserves_current_record_and_operation_log() {
    let fixture = fixture();
    let initial = fixture.codec.seal(0, b"initial").expect("initial");
    assert_eq!(run_cas(&fixture, &call(0x61, 0x71), None, &initial), 1);
    let Fixture {
        _directory,
        path,
        store,
        client,
        codec: _,
    } = fixture;
    drop(store);

    let reopened =
        SqliteRollbackAuthorityStoreV1::open_existing(&path, INSTANCE, timeout()).unwrap();
    assert_eq!(reopened.operation_count_for_tests().unwrap(), 1);
    assert_eq!(
        reopened.operation_capacity_for_tests().unwrap(),
        (1, TEST_OPERATION_ROWS)
    );
    assert_eq!(read_revision(&reopened, &client), Some(0));
    drop(reopened);
    drop(_directory);
}

#[test]
fn malformed_unauthenticated_and_unprovisioned_requests_fail_closed() {
    let fixture = fixture();
    assert_eq!(
        fixture
            .store
            .handle_signed_request(&[0_u8; 8], &server_signer())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::MalformedRequest
    );
    let oversized = vec![0_u8; MAX_SIGNED_AUTHORITY_REQUEST_BYTES_V1 + 1];
    assert_eq!(
        fixture
            .store
            .handle_signed_request(&oversized, &server_signer())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::MalformedRequest
    );

    let mut tampered = fixture.client.sign_fresh_read().expect("read").into_bytes();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        fixture
            .store
            .handle_signed_request(&tampered, &server_signer())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::RequestRejected
    );

    let unprovisioned = AuthorityClientSignerV1::new(
        INSTANCE,
        OTHER_NAMESPACE,
        SigningKey::from_bytes(&OTHER_CLIENT_SECRET),
    )
    .unwrap()
    .sign_fresh_read()
    .unwrap();
    assert_eq!(
        fixture
            .store
            .handle_signed_request(unprovisioned.as_bytes(), &server_signer())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::RequestRejected
    );

    let wrong_instance = AuthorityClientSignerV1::new(
        OTHER_INSTANCE,
        NAMESPACE,
        SigningKey::from_bytes(&CLIENT_SECRET),
    )
    .unwrap()
    .sign_fresh_read()
    .unwrap();
    assert_eq!(
        fixture
            .store
            .handle_signed_request(wrong_instance.as_bytes(), &server_signer())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::RequestRejected
    );
}

#[test]
fn concurrent_same_expected_allows_only_one_application() {
    let fixture = fixture();
    let initial = fixture.codec.seal(0, b"initial").expect("initial");
    assert_eq!(run_cas(&fixture, &call(0x61, 0x71), None, &initial), 1);
    let desired_a = fixture.codec.seal(1, b"candidate-a").expect("A");
    let desired_b = fixture.codec.seal(1, b"candidate-b").expect("B");
    let expected_a = initial.duplicate_for_protocol();
    let expected_b = initial.duplicate_for_protocol();
    let path_a = fixture.path.clone();
    let path_b = fixture.path.clone();
    let barrier = Arc::new(Barrier::new(3));

    let spawn = |path: PathBuf,
                 barrier: Arc<Barrier>,
                 nonce: u8,
                 operation: u8,
                 expected: OpaqueAuthorityRecordV1,
                 desired: OpaqueAuthorityRecordV1| {
        thread::spawn(move || {
            let store =
                SqliteRollbackAuthorityStoreV1::open_existing(path, INSTANCE, timeout()).unwrap();
            let client = AuthorityClientSignerV1::new(
                INSTANCE,
                NAMESPACE,
                SigningKey::from_bytes(&CLIENT_SECRET),
            )
            .unwrap();
            let request = client
                .sign_compare_and_swap(&call(nonce, operation), Some(&expected), &desired)
                .unwrap();
            barrier.wait();
            let response = store
                .handle_signed_request(request.as_bytes(), &server_signer())
                .unwrap();
            let verified = verify_authority_response_v1(
                response.as_bytes(),
                &request,
                &server_signer().verifying_key(),
            )
            .unwrap();
            match verified.body() {
                VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(
                    VerifiedAuthorityCasOutcomeV1::Applied(_),
                ) => 1_u8,
                VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(
                    VerifiedAuthorityCasOutcomeV1::ConflictCurrent(_),
                ) => 3_u8,
                other => panic!("unexpected concurrent outcome: {other:?}"),
            }
        })
    };
    let first = spawn(
        path_a,
        Arc::clone(&barrier),
        0x62,
        0x72,
        expected_a,
        desired_a,
    );
    let second = spawn(
        path_b,
        Arc::clone(&barrier),
        0x63,
        0x73,
        expected_b,
        desired_b,
    );
    barrier.wait();
    let mut outcomes = [first.join().unwrap(), second.join().unwrap()];
    outcomes.sort_unstable();
    assert_eq!(outcomes, [1, 3]);
    assert_eq!(fixture.store.operation_count_for_tests().unwrap(), 3);
    assert_eq!(read_revision(&fixture.store, &fixture.client), Some(1));
}

#[test]
fn concurrent_new_operations_cannot_exceed_capacity_or_mutate_after_exhaustion() {
    let fixture = fixture_with_capacity(2);
    let initial = fixture.codec.seal(0, b"initial").expect("initial");
    assert_eq!(run_cas(&fixture, &call(0x61, 0x71), None, &initial), 1);
    let desired_a = fixture.codec.seal(1, b"candidate-a").expect("A");
    let desired_b = fixture.codec.seal(1, b"candidate-b").expect("B");
    let expected_a = initial.duplicate_for_protocol();
    let expected_b = initial.duplicate_for_protocol();
    let path_a = fixture.path.clone();
    let path_b = fixture.path.clone();
    let barrier = Arc::new(Barrier::new(3));

    let spawn = |path: PathBuf,
                 barrier: Arc<Barrier>,
                 nonce: u8,
                 operation: u8,
                 expected: OpaqueAuthorityRecordV1,
                 desired: OpaqueAuthorityRecordV1| {
        thread::spawn(move || {
            let store =
                SqliteRollbackAuthorityStoreV1::open_existing(path, INSTANCE, timeout()).unwrap();
            let client = AuthorityClientSignerV1::new(
                INSTANCE,
                NAMESPACE,
                SigningKey::from_bytes(&CLIENT_SECRET),
            )
            .unwrap();
            let request = client
                .sign_compare_and_swap(&call(nonce, operation), Some(&expected), &desired)
                .unwrap();
            barrier.wait();
            store
                .handle_signed_request(request.as_bytes(), &server_signer())
                .map(|response| {
                    let verified = verify_authority_response_v1(
                        response.as_bytes(),
                        &request,
                        &server_signer().verifying_key(),
                    )
                    .unwrap();
                    match verified.body() {
                        VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(
                            VerifiedAuthorityCasOutcomeV1::Applied(_),
                        ) => 1_u8,
                        other => panic!("unexpected capacity-race outcome: {other:?}"),
                    }
                })
        })
    };
    let first = spawn(
        path_a,
        Arc::clone(&barrier),
        0x62,
        0x72,
        expected_a,
        desired_a,
    );
    let second = spawn(
        path_b,
        Arc::clone(&barrier),
        0x63,
        0x73,
        expected_b,
        desired_b,
    );
    barrier.wait();
    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.as_ref() == Ok(&1_u8))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| {
                outcome.as_ref().err()
                    == Some(&RollbackAuthorityStoreErrorV1::OperationCapacityExhausted)
            })
            .count(),
        1
    );
    assert_eq!(
        fixture.store.operation_capacity_for_tests().unwrap(),
        (2, 2)
    );
    assert_eq!(read_revision(&fixture.store, &fixture.client), Some(1));
}

#[test]
fn startup_rejects_operation_counter_that_does_not_match_durable_rows() {
    let fixture = fixture_with_capacity(2);
    let initial = fixture.codec.seal(0, b"initial").expect("initial");
    assert_eq!(run_cas(&fixture, &call(0x61, 0x71), None, &initial), 1);
    let Fixture {
        _directory,
        path,
        store,
        client: _,
        codec: _,
    } = fixture;
    drop(store);

    let connection = rusqlite::Connection::open(&path).expect("open for corruption injection");
    connection
        .execute("UPDATE provisioned_namespaces SET operation_rows = 0", [])
        .expect("corrupt operation counter");
    drop(connection);
    assert_eq!(
        SqliteRollbackAuthorityStoreV1::open_existing(&path, INSTANCE, timeout()).unwrap_err(),
        RollbackAuthorityStoreErrorV1::SchemaMismatch
    );
    assert_eq!(
        SqliteRollbackAuthorityProvisionerV1::open_existing(&path, INSTANCE, timeout())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::SchemaMismatch
    );
    drop(_directory);
}

#[test]
fn startup_rejects_call_counter_that_does_not_match_durable_rows() {
    let fixture = fixture();
    let initial = fixture.codec.seal(0, b"initial").expect("initial");
    assert_eq!(run_cas(&fixture, &call(0x61, 0x71), None, &initial), 1);
    let Fixture {
        _directory,
        path,
        store,
        client: _,
        codec: _,
    } = fixture;
    drop(store);

    let connection = rusqlite::Connection::open(&path).expect("open for corruption injection");
    connection
        .execute("UPDATE provisioned_namespaces SET call_rows = 0", [])
        .expect("corrupt call counter");
    drop(connection);
    assert_eq!(
        SqliteRollbackAuthorityStoreV1::open_existing(&path, INSTANCE, timeout()).unwrap_err(),
        RollbackAuthorityStoreErrorV1::SchemaMismatch
    );
    assert_eq!(
        SqliteRollbackAuthorityProvisionerV1::open_existing(&path, INSTANCE, timeout())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::SchemaMismatch
    );
    drop(_directory);
}

#[cfg(unix)]
#[test]
fn path_identity_permissions_and_schema_fail_closed() {
    let missing_directory = private_tempdir();
    let missing = missing_directory.path().join("missing.sqlite3");
    assert_eq!(
        SqliteRollbackAuthorityStoreV1::open_existing(&missing, INSTANCE, timeout()).unwrap_err(),
        RollbackAuthorityStoreErrorV1::MissingDatabase
    );

    let fixture = fixture();
    assert_eq!(
        SqliteRollbackAuthorityStoreV1::open_existing(&fixture.path, OTHER_INSTANCE, timeout())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::AuthorityInstanceMismatch
    );
    let link = fixture._directory.path().join("authority-link.sqlite3");
    symlink(&fixture.path, &link).unwrap();
    assert_eq!(
        SqliteRollbackAuthorityStoreV1::open_existing(&link, INSTANCE, timeout()).unwrap_err(),
        RollbackAuthorityStoreErrorV1::UnsafeDatabasePath
    );
    let hardlink = fixture._directory.path().join("authority-hardlink.sqlite3");
    fs::hard_link(&fixture.path, &hardlink).unwrap();
    assert_eq!(
        SqliteRollbackAuthorityStoreV1::open_existing(&fixture.path, INSTANCE, timeout())
            .unwrap_err(),
        RollbackAuthorityStoreErrorV1::UnsafeDatabasePath
    );
    fs::remove_file(&hardlink).unwrap();

    let Fixture {
        _directory,
        path,
        store,
        client: _,
        codec: _,
    } = fixture;
    drop(store);
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute("CREATE TABLE unexpected(value INTEGER) STRICT", [])
        .unwrap();
    drop(raw);
    assert_eq!(
        SqliteRollbackAuthorityStoreV1::open_existing(&path, INSTANCE, timeout()).unwrap_err(),
        RollbackAuthorityStoreErrorV1::SchemaMismatch
    );

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        SqliteRollbackAuthorityStoreV1::open_existing(&path, INSTANCE, timeout()).unwrap_err(),
        RollbackAuthorityStoreErrorV1::UnsafeDatabasePath
    );
    drop(_directory);

    let public_parent = private_tempdir();
    fs::set_permissions(public_parent.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        SqliteRollbackAuthorityProvisionerV1::create(
            public_parent.path().join("unsafe.sqlite3"),
            INSTANCE,
            timeout(),
        )
        .unwrap_err(),
        RollbackAuthorityStoreErrorV1::UnsafeDatabasePath
    );
}

#[test]
fn debug_and_errors_do_not_render_linkable_protocol_material() {
    let fixture = fixture();
    let rendered = format!("{:?}", fixture.store);
    assert!(rendered.contains("REDACTED"));
    assert!(!rendered.contains("authority.sqlite3"));
    assert!(!rendered.contains("11111111"));

    for error in [
        RollbackAuthorityStoreErrorV1::MalformedRequest,
        RollbackAuthorityStoreErrorV1::RequestRejected,
        RollbackAuthorityStoreErrorV1::OperationReplayMismatch,
        RollbackAuthorityStoreErrorV1::OperationCapacityExhausted,
        RollbackAuthorityStoreErrorV1::CallCapacityExhausted,
        RollbackAuthorityStoreErrorV1::StorageFailure,
    ] {
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("21212121"));
        assert!(!rendered.contains("operation_id"));
    }
}
