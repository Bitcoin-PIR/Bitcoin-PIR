use ed25519_dalek::SigningKey;
use static_assertions::assert_not_impl_any;

use crate::{
    inspect_authority_request_locator_v1, verify_authority_read_response_v1,
    verify_authority_request_v1, verify_authority_response_v1, AuthorityCasDispositionV1,
    AuthorityCasResolutionRefV1, AuthorityClientSignerV1, AuthorityServerSignerV1,
    AuthorityValueCodecV1, AuthorityValueRootKeyV1, OpaqueAuthorityRecordV1,
    PersistedAuthorityOperationRefV1, PersistedAuthorityTerminalOutcomeRefV1,
    RollbackAuthorityProtocolErrorV1, SignedAuthorityReadAttemptV1, SignedAuthorityRequestV1,
    SignedAuthorityResponseV1, VerifiedAuthorityCasOutcomeV1, VerifiedAuthorityOperationRefV1,
    VerifiedAuthorityResponseBodyRefV1, AUTHORITY_RECORD_BYTES_V1, MAX_AUTHORITY_VALUE_BYTES_V1,
    SEALED_AUTHORITY_VALUE_BYTES_V1,
};

const INSTANCE: [u8; 32] = [0x11; 32];
const OTHER_INSTANCE: [u8; 32] = [0x12; 32];
const NAMESPACE: [u8; 32] = [0x21; 32];
const OTHER_NAMESPACE: [u8; 32] = [0x22; 32];
const CLIENT_SECRET: [u8; 32] = [0x31; 32];
const OTHER_CLIENT_SECRET: [u8; 32] = [0x32; 32];
const SERVER_SECRET: [u8; 32] = [0x41; 32];
const OTHER_SERVER_SECRET: [u8; 32] = [0x42; 32];
const VALUE_ROOT: [u8; 32] = [0x51; 32];
const CALL_NONCE: [u8; 32] = [0x61; 32];
const OPERATION_ID: [u8; 32] = [0x71; 32];

fn client_signer(
    instance: [u8; 32],
    namespace: [u8; 32],
    secret: [u8; 32],
) -> AuthorityClientSignerV1 {
    AuthorityClientSignerV1::new(instance, namespace, SigningKey::from_bytes(&secret))
        .expect("valid client signer")
}

fn server_signer(instance: [u8; 32], secret: [u8; 32]) -> AuthorityServerSignerV1 {
    AuthorityServerSignerV1::new(instance, SigningKey::from_bytes(&secret))
        .expect("valid authority signer")
}

fn value_codec(
    instance: [u8; 32],
    namespace: [u8; 32],
    client_secret: [u8; 32],
    root: [u8; 32],
) -> AuthorityValueCodecV1 {
    let client_key = SigningKey::from_bytes(&client_secret).verifying_key();
    let root = AuthorityValueRootKeyV1::from_bytes(root).expect("valid root");
    AuthorityValueCodecV1::derive(&root, instance, namespace, &client_key)
        .expect("derive value codec")
}

fn call() -> crate::AuthorityCallV1 {
    crate::AuthorityCallV1::from_parts(CALL_NONCE, OPERATION_ID).expect("valid call")
}

fn resolution_for_request<'a>(
    request: &'a crate::VerifiedAuthorityRequestV1,
    first_outcome: PersistedAuthorityTerminalOutcomeRefV1<'a>,
    live_current: Option<&'a OpaqueAuthorityRecordV1>,
    disposition: AuthorityCasDispositionV1,
) -> AuthorityCasResolutionRefV1<'a> {
    let persisted = PersistedAuthorityOperationRefV1::from_persisted_row(
        request.binding().authority_instance_id(),
        request.binding().namespace(),
        request.binding().client_key_id(),
        request.call().operation_id(),
        request.operation_digest(),
        first_outcome,
    )
    .expect("test persisted operation row");
    AuthorityCasResolutionRefV1::from_linearized_transaction(persisted, live_current, disposition)
}

#[test]
fn sealed_values_have_one_fixed_length_and_round_trip_at_bounds() {
    let codec = value_codec(INSTANCE, NAMESPACE, CLIENT_SECRET, VALUE_ROOT);
    let short = codec.seal(0, b"x").expect("seal short");
    let maximum_value = vec![0xa5; MAX_AUTHORITY_VALUE_BYTES_V1];
    let maximum = codec.seal(9, &maximum_value).expect("seal maximum");

    assert_eq!(short.sealed_value().len(), SEALED_AUTHORITY_VALUE_BYTES_V1);
    assert_eq!(
        maximum.sealed_value().len(),
        SEALED_AUTHORITY_VALUE_BYTES_V1
    );
    assert_eq!(short.encode().len(), AUTHORITY_RECORD_BYTES_V1);
    assert_eq!(maximum.encode().len(), AUTHORITY_RECORD_BYTES_V1);
    assert_eq!(codec.open(&short).expect("open short").as_bytes(), b"x");
    assert_eq!(
        codec.open(&maximum).expect("open maximum").as_bytes(),
        maximum_value
    );
    assert_eq!(
        codec.seal(1, b"").unwrap_err(),
        RollbackAuthorityProtocolErrorV1::EmptyValue
    );
    assert_eq!(
        codec
            .seal(1, &vec![0_u8; MAX_AUTHORITY_VALUE_BYTES_V1 + 1])
            .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::ValueTooLong
    );
}

#[test]
fn sealed_values_bind_key_namespace_instance_client_and_revision() {
    let codec = value_codec(INSTANCE, NAMESPACE, CLIENT_SECRET, VALUE_ROOT);
    let record = codec
        .seal(7, b"opaque-floor-sentinel")
        .expect("seal record");
    let same = codec
        .seal(7, b"opaque-floor-sentinel")
        .expect("reseal record");
    assert_eq!(record.value_tag(), same.value_tag());
    assert_ne!(record.sealed_value(), same.sealed_value());

    for wrong_codec in [
        value_codec(INSTANCE, NAMESPACE, CLIENT_SECRET, [0x52; 32]),
        value_codec(OTHER_INSTANCE, NAMESPACE, CLIENT_SECRET, VALUE_ROOT),
        value_codec(INSTANCE, OTHER_NAMESPACE, CLIENT_SECRET, VALUE_ROOT),
        value_codec(INSTANCE, NAMESPACE, OTHER_CLIENT_SECRET, VALUE_ROOT),
    ] {
        assert_eq!(
            wrong_codec.open(&record).err().expect("wrong codec fails"),
            RollbackAuthorityProtocolErrorV1::DecryptionFailed
        );
    }

    let different_revision = codec
        .seal(8, b"opaque-floor-sentinel")
        .expect("seal other revision");
    assert_ne!(record.value_tag(), different_revision.value_tag());
}

#[test]
fn record_tamper_and_noncanonical_lengths_fail_closed() {
    let codec = value_codec(INSTANCE, NAMESPACE, CLIENT_SECRET, VALUE_ROOT);
    let record = codec.seal(3, b"floor").expect("seal");

    let mut tag_tamper = record.encode();
    tag_tamper[8] ^= 1;
    let tag_tamper = OpaqueAuthorityRecordV1::decode(&tag_tamper).expect("parse fixed record");
    assert_eq!(
        codec.open(&tag_tamper).err().expect("tag tamper fails"),
        RollbackAuthorityProtocolErrorV1::DecryptionFailed
    );

    let mut ciphertext_tamper = record.encode();
    let last = ciphertext_tamper.len() - 1;
    ciphertext_tamper[last] ^= 1;
    let ciphertext_tamper =
        OpaqueAuthorityRecordV1::decode(&ciphertext_tamper).expect("parse fixed record");
    assert_eq!(
        codec
            .open(&ciphertext_tamper)
            .err()
            .expect("ciphertext tamper fails"),
        RollbackAuthorityProtocolErrorV1::DecryptionFailed
    );

    let mut trailing = record.encode().to_vec();
    trailing.push(0);
    assert_eq!(
        OpaqueAuthorityRecordV1::decode(&trailing).unwrap_err(),
        RollbackAuthorityProtocolErrorV1::InvalidLength
    );
}

#[test]
fn secret_and_opaque_types_are_not_implicitly_cloneable_or_debuggable() {
    assert_not_impl_any!(AuthorityValueRootKeyV1: Clone, core::fmt::Debug);
    assert_not_impl_any!(crate::OpenedAuthorityValueV1: Clone, core::fmt::Debug);
    assert_not_impl_any!(OpaqueAuthorityRecordV1: Clone);
    assert_not_impl_any!(SignedAuthorityReadAttemptV1: Clone);

    let signer = client_signer(INSTANCE, NAMESPACE, CLIENT_SECRET);
    let codec = value_codec(INSTANCE, NAMESPACE, CLIENT_SECRET, VALUE_ROOT);
    let record = codec.seal(0, b"never-log-this-floor").expect("seal record");
    let request = signer.sign_fresh_read().expect("sign fresh read");
    for rendered in [
        format!("{signer:?}"),
        format!("{:?}", signer.binding()),
        format!("{codec:?}"),
        format!("{record:?}"),
        format!("{request:?}"),
    ] {
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("never-log-this-floor"));
        assert!(!rendered.contains("21212121"));
    }
}

#[test]
fn read_request_is_strict_signed_and_bound_to_provisioning() {
    let signer = client_signer(INSTANCE, NAMESPACE, CLIENT_SECRET);
    let request = signer.sign_fresh_read().expect("sign fresh read");
    assert_eq!(request.as_bytes().len(), 299);

    let locator = inspect_authority_request_locator_v1(request.as_bytes()).expect("locator");
    assert_eq!(locator.authority_instance_id(), &INSTANCE);
    assert_eq!(locator.namespace(), &NAMESPACE);
    assert_eq!(locator.client_key_id(), signer.binding().client_key_id());

    let verified = verify_authority_request_v1(
        request.as_bytes(),
        &INSTANCE,
        &NAMESPACE,
        &signer.verifying_key(),
    )
    .expect("verify read");
    assert!(matches!(
        verified.operation(),
        VerifiedAuthorityOperationRefV1::Read
    ));

    let second_request = signer.sign_fresh_read().expect("second fresh read");
    let second_verified = verify_authority_request_v1(
        second_request.as_bytes(),
        &INSTANCE,
        &NAMESPACE,
        &signer.verifying_key(),
    )
    .expect("verify second read");
    assert_ne!(
        verified.call().call_nonce(),
        second_verified.call().call_nonce()
    );
    assert_ne!(
        verified.call().operation_id(),
        second_verified.call().operation_id()
    );
    assert_ne!(verified.request_digest(), second_verified.request_digest());

    assert_eq!(
        verify_authority_request_v1(
            request.as_bytes(),
            &OTHER_INSTANCE,
            &NAMESPACE,
            &signer.verifying_key(),
        )
        .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::BindingMismatch
    );
    assert_eq!(
        verify_authority_request_v1(
            request.as_bytes(),
            &INSTANCE,
            &OTHER_NAMESPACE,
            &signer.verifying_key(),
        )
        .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::BindingMismatch
    );
    let other_key = SigningKey::from_bytes(&OTHER_CLIENT_SECRET).verifying_key();
    assert_eq!(
        verify_authority_request_v1(request.as_bytes(), &INSTANCE, &NAMESPACE, &other_key)
            .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::BindingMismatch
    );
}

#[test]
fn request_tamper_unknown_version_operation_and_trailing_bytes_are_rejected() {
    let signer = client_signer(INSTANCE, NAMESPACE, CLIENT_SECRET);
    let request = signer.sign_fresh_read().expect("sign fresh read");
    let verify = |bytes: &[u8]| {
        verify_authority_request_v1(bytes, &INSTANCE, &NAMESPACE, &signer.verifying_key())
            .map(|_| ())
    };

    let mut magic = request.as_bytes().to_vec();
    magic[0] ^= 1;
    assert_eq!(
        verify(&magic).unwrap_err(),
        RollbackAuthorityProtocolErrorV1::InvalidMagic
    );

    let mut version = request.as_bytes().to_vec();
    version[9] = 2;
    assert_eq!(
        verify(&version).unwrap_err(),
        RollbackAuthorityProtocolErrorV1::UnsupportedVersion
    );

    let mut operation = request.as_bytes().to_vec();
    operation[10] = 3;
    assert_eq!(
        verify(&operation).unwrap_err(),
        RollbackAuthorityProtocolErrorV1::UnknownOperation
    );

    let mut digest = request.as_bytes().to_vec();
    let digest_offset = digest.len() - 64 - 32;
    digest[digest_offset] ^= 1;
    assert_eq!(
        verify(&digest).unwrap_err(),
        RollbackAuthorityProtocolErrorV1::RequestDigestMismatch
    );

    let mut operation_digest = request.as_bytes().to_vec();
    let operation_digest_offset = operation_digest.len() - 64 - 32 - 32;
    operation_digest[operation_digest_offset] ^= 1;
    assert_eq!(
        verify(&operation_digest).unwrap_err(),
        RollbackAuthorityProtocolErrorV1::OperationDigestMismatch
    );

    let mut signature = request.as_bytes().to_vec();
    let last = signature.len() - 1;
    signature[last] ^= 1;
    assert_eq!(
        verify(&signature).unwrap_err(),
        RollbackAuthorityProtocolErrorV1::BadSignature
    );

    let mut trailing = request.as_bytes().to_vec();
    trailing.push(0);
    assert_eq!(
        verify(&trailing).unwrap_err(),
        RollbackAuthorityProtocolErrorV1::NonCanonicalEncoding
    );
}

#[test]
fn cas_requests_have_fixed_records_and_require_exact_revision_successors() {
    let signer = client_signer(INSTANCE, NAMESPACE, CLIENT_SECRET);
    let codec = value_codec(INSTANCE, NAMESPACE, CLIENT_SECRET, VALUE_ROOT);
    let initial = codec.seal(0, b"floor-zero").expect("initial");
    let successor = codec.seal(1, b"floor-one").expect("successor");

    let initialize = signer
        .sign_compare_and_swap(&call(), None, &initial)
        .expect("sign initialize");
    assert_eq!(initialize.as_bytes().len(), 852);
    let advance = signer
        .sign_compare_and_swap(&call(), Some(&initial), &successor)
        .expect("sign advance");
    assert_eq!(advance.as_bytes().len(), 1404);
    let verified = verify_authority_request_v1(
        advance.as_bytes(),
        &INSTANCE,
        &NAMESPACE,
        &signer.verifying_key(),
    )
    .expect("verify CAS");
    match verified.operation() {
        VerifiedAuthorityOperationRefV1::CompareAndSwap { expected, desired } => {
            assert_eq!(expected.expect("expected").revision(), 0);
            assert_eq!(desired.revision(), 1);
        }
        VerifiedAuthorityOperationRefV1::Read => panic!("expected CAS"),
    }

    let skipped = codec.seal(2, b"skipped").expect("skipped");
    assert_eq!(
        signer
            .sign_compare_and_swap(&call(), Some(&initial), &skipped)
            .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::InvalidOutcome
    );

    let mut tampered = advance.as_bytes().to_vec();
    tampered[171 + 1 + 8 + 32] ^= 1;
    assert_eq!(
        verify_authority_request_v1(&tampered, &INSTANCE, &NAMESPACE, &signer.verifying_key(),)
            .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::OperationDigestMismatch
    );
}

#[test]
fn signed_read_responses_bind_request_and_authority_key() {
    let client = client_signer(INSTANCE, NAMESPACE, CLIENT_SECRET);
    let authority = server_signer(INSTANCE, SERVER_SECRET);
    let empty_attempt = client.sign_fresh_read().expect("empty read attempt");
    let verified_empty_request = verify_authority_request_v1(
        empty_attempt.as_bytes(),
        &INSTANCE,
        &NAMESPACE,
        &client.verifying_key(),
    )
    .expect("verify empty request");

    let empty = authority
        .sign_read_response(&verified_empty_request, None)
        .expect("sign empty response");
    assert_eq!(empty.as_bytes().len(), 300);
    let verified = verify_authority_read_response_v1(
        empty.as_bytes(),
        empty_attempt,
        &authority.verifying_key(),
    )
    .expect("verify empty response");
    assert!(matches!(
        verified.body(),
        VerifiedAuthorityResponseBodyRefV1::Read { current: None }
    ));

    let codec = value_codec(INSTANCE, NAMESPACE, CLIENT_SECRET, VALUE_ROOT);
    let record = codec.seal(0, b"floor").expect("record");
    let current_attempt = client.sign_fresh_read().expect("current read attempt");
    let verified_current_request = verify_authority_request_v1(
        current_attempt.as_bytes(),
        &INSTANCE,
        &NAMESPACE,
        &client.verifying_key(),
    )
    .expect("verify current request");
    let current = authority
        .sign_read_response(&verified_current_request, Some(&record))
        .expect("sign current response");
    assert_eq!(current.as_bytes().len(), 852);
    let verified = verify_authority_read_response_v1(
        current.as_bytes(),
        current_attempt,
        &authority.verifying_key(),
    )
    .expect("verify current response");
    match verified.body() {
        VerifiedAuthorityResponseBodyRefV1::Read {
            current: Some(current),
        } => assert_eq!(current, &record),
        other => panic!("unexpected response: {other:?}"),
    }

    let wrong_authority = server_signer(INSTANCE, OTHER_SERVER_SECRET);
    let wrong_key_attempt = client.sign_fresh_read().expect("wrong-key read attempt");
    let verified_wrong_key_request = verify_authority_request_v1(
        wrong_key_attempt.as_bytes(),
        &INSTANCE,
        &NAMESPACE,
        &client.verifying_key(),
    )
    .expect("verify wrong-key request");
    let wrong_key_response = authority
        .sign_read_response(&verified_wrong_key_request, Some(&record))
        .expect("sign wrong-key response");
    assert_eq!(
        verify_authority_read_response_v1(
            wrong_key_response.as_bytes(),
            wrong_key_attempt,
            &wrong_authority.verifying_key(),
        )
        .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::BadSignature
    );
}

#[test]
fn cas_outcomes_round_trip_and_wrong_response_kind_is_blocked() {
    let client = client_signer(INSTANCE, NAMESPACE, CLIENT_SECRET);
    let authority = server_signer(INSTANCE, SERVER_SECRET);
    let codec = value_codec(INSTANCE, NAMESPACE, CLIENT_SECRET, VALUE_ROOT);
    let initial = codec.seal(0, b"floor-zero").expect("initial");
    let successor = codec.seal(1, b"floor-one").expect("successor");
    let conflict = codec.seal(4, b"other-current").expect("conflict");
    let request = client
        .sign_compare_and_swap(&call(), Some(&initial), &successor)
        .expect("CAS request");
    let verified_request = verify_authority_request_v1(
        request.as_bytes(),
        &INSTANCE,
        &NAMESPACE,
        &client.verifying_key(),
    )
    .expect("verify CAS");

    for (resolution, expected_kind) in [
        (
            resolution_for_request(
                &verified_request,
                PersistedAuthorityTerminalOutcomeRefV1::Empty,
                None,
                AuthorityCasDispositionV1::NewlyLinearized,
            ),
            0_u8,
        ),
        (
            resolution_for_request(
                &verified_request,
                PersistedAuthorityTerminalOutcomeRefV1::Applied(&successor),
                Some(&successor),
                AuthorityCasDispositionV1::NewlyLinearized,
            ),
            1,
        ),
        (
            resolution_for_request(
                &verified_request,
                PersistedAuthorityTerminalOutcomeRefV1::Applied(&successor),
                Some(&successor),
                AuthorityCasDispositionV1::ExactOperationReplay,
            ),
            2,
        ),
        (
            resolution_for_request(
                &verified_request,
                PersistedAuthorityTerminalOutcomeRefV1::ConflictCurrent(&conflict),
                Some(&conflict),
                AuthorityCasDispositionV1::NewlyLinearized,
            ),
            3,
        ),
    ] {
        let response = authority
            .sign_compare_and_swap_response(&verified_request, resolution)
            .expect("sign CAS response");
        let verified =
            verify_authority_response_v1(response.as_bytes(), &request, &authority.verifying_key())
                .expect("verify CAS response");
        let actual_kind = match verified.body() {
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
            _ => 255,
        };
        assert_eq!(actual_kind, expected_kind);
    }

    assert_eq!(
        authority
            .sign_read_response(&verified_request, None)
            .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::UnexpectedResponse
    );
    assert_eq!(
        authority
            .sign_compare_and_swap_response(
                &verified_request,
                resolution_for_request(
                    &verified_request,
                    PersistedAuthorityTerminalOutcomeRefV1::Applied(&initial),
                    Some(&initial),
                    AuthorityCasDispositionV1::NewlyLinearized,
                ),
            )
            .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::InvalidOutcome
    );
    assert_eq!(
        authority
            .sign_compare_and_swap_response(
                &verified_request,
                resolution_for_request(
                    &verified_request,
                    PersistedAuthorityTerminalOutcomeRefV1::ConflictCurrent(&initial),
                    Some(&initial),
                    AuthorityCasDispositionV1::NewlyLinearized,
                ),
            )
            .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::InvalidOutcome
    );
    let wrong_operation_digest = [0xd1; 32];
    let wrong_row = PersistedAuthorityOperationRefV1::from_persisted_row(
        verified_request.binding().authority_instance_id(),
        verified_request.binding().namespace(),
        verified_request.binding().client_key_id(),
        verified_request.call().operation_id(),
        &wrong_operation_digest,
        PersistedAuthorityTerminalOutcomeRefV1::Applied(&successor),
    )
    .expect("well-formed but mismatched persisted row");
    assert_eq!(
        authority
            .sign_compare_and_swap_response(
                &verified_request,
                AuthorityCasResolutionRefV1::from_linearized_transaction(
                    wrong_row,
                    Some(&successor),
                    AuthorityCasDispositionV1::ExactOperationReplay,
                ),
            )
            .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::InvalidOutcome
    );

    // A successfully applied operation whose live floor has advanced must not
    // return the historical desired as AlreadyApplied.
    let advanced_response = authority
        .sign_compare_and_swap_response(
            &verified_request,
            resolution_for_request(
                &verified_request,
                PersistedAuthorityTerminalOutcomeRefV1::Applied(&successor),
                Some(&conflict),
                AuthorityCasDispositionV1::ExactOperationReplay,
            ),
        )
        .expect("advanced replay signs live conflict");
    let advanced = verify_authority_response_v1(
        advanced_response.as_bytes(),
        &request,
        &authority.verifying_key(),
    )
    .expect("verify advanced conflict");
    assert!(matches!(
        advanced.body(),
        VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(
            VerifiedAuthorityCasOutcomeV1::ConflictCurrent(current)
        ) if current == &conflict
    ));

    // A terminally failed Empty operation never becomes applicable when a
    // later operation installs its expected record.
    let failed_then_initialized = authority
        .sign_compare_and_swap_response(
            &verified_request,
            resolution_for_request(
                &verified_request,
                PersistedAuthorityTerminalOutcomeRefV1::Empty,
                Some(&initial),
                AuthorityCasDispositionV1::ExactOperationReplay,
            ),
        )
        .expect("failed replay remains non-mutating");
    let failed_then_initialized = verify_authority_response_v1(
        failed_then_initialized.as_bytes(),
        &request,
        &authority.verifying_key(),
    )
    .expect("verify terminal failure replay");
    assert!(matches!(
        failed_then_initialized.body(),
        VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(
            VerifiedAuthorityCasOutcomeV1::ConflictCurrent(current)
        ) if current == &initial
    ));
}

#[test]
fn response_replay_is_bound_to_exact_request_digest_nonce_and_operation() {
    let client = client_signer(INSTANCE, NAMESPACE, CLIENT_SECRET);
    let authority = server_signer(INSTANCE, SERVER_SECRET);
    let codec = value_codec(INSTANCE, NAMESPACE, CLIENT_SECRET, VALUE_ROOT);
    let first_value = codec.seal(0, b"same logical floor").expect("first");
    let second_value = codec.seal(0, b"same logical floor").expect("second");
    let first_call = call();
    let retry_call =
        crate::AuthorityCallV1::from_parts([0x62; 32], OPERATION_ID).expect("fresh retry nonce");
    let divergent_call = crate::AuthorityCallV1::from_parts([0x64; 32], OPERATION_ID)
        .expect("fresh divergent nonce");
    let first_request = client
        .sign_compare_and_swap(&first_call, None, &first_value)
        .expect("first request");
    let retry_request = client
        .sign_compare_and_swap(&retry_call, None, &first_value)
        .expect("retry request");
    let divergent_request = client
        .sign_compare_and_swap(&divergent_call, None, &second_value)
        .expect("divergent request");
    let verified_first = verify_authority_request_v1(
        first_request.as_bytes(),
        &INSTANCE,
        &NAMESPACE,
        &client.verifying_key(),
    )
    .expect("verify first");
    let verified_retry = verify_authority_request_v1(
        retry_request.as_bytes(),
        &INSTANCE,
        &NAMESPACE,
        &client.verifying_key(),
    )
    .expect("verify retry");
    let verified_divergent = verify_authority_request_v1(
        divergent_request.as_bytes(),
        &INSTANCE,
        &NAMESPACE,
        &client.verifying_key(),
    )
    .expect("verify divergent reuse");
    assert_eq!(
        verified_first.operation_digest(),
        verified_retry.operation_digest()
    );
    assert_ne!(
        verified_first.request_digest(),
        verified_retry.request_digest()
    );
    assert_ne!(
        verified_first.operation_digest(),
        verified_divergent.operation_digest()
    );

    let first_response = authority
        .sign_compare_and_swap_response(
            &verified_first,
            resolution_for_request(
                &verified_first,
                PersistedAuthorityTerminalOutcomeRefV1::Applied(&first_value),
                Some(&first_value),
                AuthorityCasDispositionV1::NewlyLinearized,
            ),
        )
        .expect("sign first response");
    verify_authority_response_v1(
        first_response.as_bytes(),
        &first_request,
        &authority.verifying_key(),
    )
    .expect("first response accepts only its attempt");
    assert_eq!(
        verify_authority_response_v1(
            first_response.as_bytes(),
            &retry_request,
            &authority.verifying_key(),
        )
        .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::UnexpectedResponse
    );

    let persisted_first = PersistedAuthorityOperationRefV1::from_persisted_row(
        verified_first.binding().authority_instance_id(),
        verified_first.binding().namespace(),
        verified_first.binding().client_key_id(),
        verified_first.call().operation_id(),
        verified_first.operation_digest(),
        PersistedAuthorityTerminalOutcomeRefV1::Applied(&first_value),
    )
    .expect("persisted first operation");
    let retry_response = authority
        .sign_compare_and_swap_response(
            &verified_retry,
            AuthorityCasResolutionRefV1::from_linearized_transaction(
                persisted_first,
                Some(&first_value),
                AuthorityCasDispositionV1::ExactOperationReplay,
            ),
        )
        .expect("sign fresh-nonce exact replay");
    let retry_response = verify_authority_response_v1(
        retry_response.as_bytes(),
        &retry_request,
        &authority.verifying_key(),
    )
    .expect("verify fresh retry response");
    assert!(matches!(
        retry_response.body(),
        VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(
            VerifiedAuthorityCasOutcomeV1::AlreadyApplied(current)
        ) if current == &first_value
    ));

    // The same operation ID with different stable content cannot use the old
    // row as a new operation or as an exact replay.
    assert_eq!(
        authority
            .sign_compare_and_swap_response(
                &verified_divergent,
                AuthorityCasResolutionRefV1::from_linearized_transaction(
                    persisted_first,
                    Some(&first_value),
                    AuthorityCasDispositionV1::ExactOperationReplay,
                ),
            )
            .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::InvalidOutcome
    );

    let fresh_read = client.sign_fresh_read().expect("fresh read");
    assert_eq!(
        verify_authority_read_response_v1(
            first_response.as_bytes(),
            fresh_read,
            &authority.verifying_key(),
        )
        .unwrap_err(),
        RollbackAuthorityProtocolErrorV1::UnexpectedResponse
    );
}

#[test]
fn signed_wire_exports_remain_zeroizing() {
    let client = client_signer(INSTANCE, NAMESPACE, CLIENT_SECRET);
    let authority = server_signer(INSTANCE, SERVER_SECRET);
    let codec = value_codec(INSTANCE, NAMESPACE, CLIENT_SECRET, VALUE_ROOT);
    let desired = codec.seal(0, b"initial").expect("desired");

    let cas_request = client
        .sign_compare_and_swap(&call(), None, &desired)
        .expect("CAS request");
    let request_bytes: zeroize::Zeroizing<Vec<u8>> = cas_request.into_bytes();
    assert_eq!(request_bytes.len(), 852);

    let read_attempt = client.sign_fresh_read().expect("fresh read");
    let verified_read = verify_authority_request_v1(
        read_attempt.as_bytes(),
        &INSTANCE,
        &NAMESPACE,
        &client.verifying_key(),
    )
    .expect("verify read");
    let response = authority
        .sign_read_response(&verified_read, None)
        .expect("read response");
    let response_bytes: zeroize::Zeroizing<Vec<u8>> = response.into_bytes();
    assert_eq!(response_bytes.len(), 300);

    let exported_read = client.sign_fresh_read().expect("exported read");
    let read_bytes: zeroize::Zeroizing<Vec<u8>> = exported_read.into_bytes();
    assert_eq!(read_bytes.len(), 299);

    assert_not_impl_any!(SignedAuthorityRequestV1: Clone);
    assert_not_impl_any!(SignedAuthorityResponseV1: Clone);
}

#[test]
fn response_tamper_unknown_outcome_version_and_trailing_are_rejected() {
    let client = client_signer(INSTANCE, NAMESPACE, CLIENT_SECRET);
    let authority = server_signer(INSTANCE, SERVER_SECRET);
    let codec = value_codec(INSTANCE, NAMESPACE, CLIENT_SECRET, VALUE_ROOT);
    let desired = codec.seal(0, b"initial").expect("desired");
    let request = client
        .sign_compare_and_swap(&call(), None, &desired)
        .expect("request");
    let verified_request = verify_authority_request_v1(
        request.as_bytes(),
        &INSTANCE,
        &NAMESPACE,
        &client.verifying_key(),
    )
    .expect("verify request");
    let response = authority
        .sign_compare_and_swap_response(
            &verified_request,
            resolution_for_request(
                &verified_request,
                PersistedAuthorityTerminalOutcomeRefV1::Applied(&desired),
                Some(&desired),
                AuthorityCasDispositionV1::NewlyLinearized,
            ),
        )
        .expect("response");
    let verify = |bytes: &[u8]| {
        verify_authority_response_v1(bytes, &request, &authority.verifying_key()).map(|_| ())
    };

    let mut version = response.as_bytes().to_vec();
    version[9] = 2;
    assert_eq!(
        verify(&version).unwrap_err(),
        RollbackAuthorityProtocolErrorV1::UnsupportedVersion
    );

    let mut outcome = response.as_bytes().to_vec();
    outcome[235] = 4;
    assert_eq!(
        verify(&outcome).unwrap_err(),
        RollbackAuthorityProtocolErrorV1::InvalidOutcome
    );

    let mut signature = response.as_bytes().to_vec();
    let last = signature.len() - 1;
    signature[last] ^= 1;
    assert_eq!(
        verify(&signature).unwrap_err(),
        RollbackAuthorityProtocolErrorV1::BadSignature
    );

    let mut trailing = response.as_bytes().to_vec();
    trailing.push(0);
    assert_eq!(
        verify(&trailing).unwrap_err(),
        RollbackAuthorityProtocolErrorV1::InvalidLength
    );
}
