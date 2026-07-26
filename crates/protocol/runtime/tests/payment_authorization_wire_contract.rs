use std::{fs, path::PathBuf};

use pir_channel::{
    ClientHandshake, Direction, ServerHandshake, AEAD_TAG_LEN, ENCRYPTED_FRAME_MAGIC,
};
use pir_runtime_core::service_admission::{
    AdmissionEnforcementV1, ConnectionAdmissionGateV1, GateErrorV1, ServiceWireRequestV1,
};
use pir_service_protocol::{
    AuthBeginV1, AuthGrantedV1, AuthPaddingClassV1, AuthRejectCode, AuthRejectedV1, AuthResultV1,
    AuthScheme, HintTransport, OperationStartV1, AUTH_FRAME_CLASS_V1, MAX_AUTH_PROOF_LEN,
    REQ_AUTH_BEGIN_V1, RESP_AUTH_RESULT_V1,
};
use serde_json::Value;
use x25519_dalek::{PublicKey, StaticSecret};

const OUTER_LENGTH_PREFIX_BYTES: usize = 4;
const INNER_OPCODE_BYTES: usize = 1;
const ENCRYPTED_MAGIC_BYTES: usize = 1;
const ENCRYPTED_SEQUENCE_BYTES: usize = 8;

fn contract() -> Value {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir
        .ancestors()
        .map(|ancestor| ancestor.join("verification/contracts/wire-shape-v1.json"))
        .find(|candidate| candidate.is_file())
        .expect("wire-shape contract must exist below a crate ancestor");
    let bytes = fs::read(&path)
        .unwrap_or_else(|err| panic!("failed to read contract {}: {err}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("failed to parse contract {}: {err}", path.display()))
}

fn number(value: &Value, pointer: &str) -> usize {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("missing numeric contract field {pointer}")) as usize
}

fn boolean(value: &Value, pointer: &str) -> bool {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("missing boolean contract field {pointer}"))
}

fn session_pair() -> (pir_channel::Session, pir_channel::Session) {
    let server_static = StaticSecret::from([0x31; 32]);
    let server_static_pub = PublicKey::from(&server_static);
    let client_handshake = ClientHandshake::new([0x32; 32], [0x33; 32]);
    let server_handshake = ServerHandshake::new(&server_static, [0x34; 32]);
    let client_eph_pub = client_handshake.client_eph_pub();
    let nonce = client_handshake.nonce();
    let server_eph_pub = server_handshake.server_eph_pub();
    let client_session =
        client_handshake.complete_handshake(server_static_pub.as_bytes(), &server_eph_pub);
    let server_session = server_handshake.complete_handshake(&client_eph_pub, &nonce);
    (client_session, server_session)
}

fn application_record(sealed_payload: &[u8]) -> Vec<u8> {
    let sealed_len = u32::try_from(sealed_payload.len()).expect("test frame length fits u32");
    let mut record = Vec::with_capacity(OUTER_LENGTH_PREFIX_BYTES + sealed_payload.len());
    record.extend_from_slice(&sealed_len.to_le_bytes());
    record.extend_from_slice(sealed_payload);
    record
}

fn operations() -> [OperationStartV1; 5] {
    [
        OperationStartV1::DpfQuery { db_id: 1 },
        OperationStartV1::HarmonyHint {
            db_id: 2,
            transport: HintTransport::V2Full,
            session_token: None,
            primary_side: None,
        },
        OperationStartV1::HarmonyQuery { db_id: 3 },
        OperationStartV1::OnionSession { db_id: 4 },
        OperationStartV1::TeeOramQuery { db_id: 5 },
    ]
}

fn schemes() -> [AuthScheme; 5] {
    [
        AuthScheme::FreeV1,
        AuthScheme::Bolt11DirectReceiptV1,
        AuthScheme::CashuEcashV1,
        AuthScheme::BitcoinPirCashuBatV1,
        AuthScheme::ArcV1Experimental,
    ]
}

#[test]
fn contract_numbers_match_compiled_payment_and_channel_constants() {
    let contract = contract();
    let request = "/serviceAuthorization/transport/request";

    assert_eq!(number(&contract, "/contractVersion"), 2);
    assert!(boolean(
        &contract,
        "/serviceAuthorization/independentPerServer"
    ));
    assert!(boolean(
        &contract,
        "/serviceAuthorization/transport/secureChannelRequired"
    ));
    assert_eq!(
        number(&contract, "/serviceAuthorization/transport/requestOpcode"),
        usize::from(REQ_AUTH_BEGIN_V1)
    );
    assert_eq!(
        number(&contract, "/serviceAuthorization/transport/responseOpcode"),
        usize::from(RESP_AUTH_RESULT_V1)
    );
    assert_eq!(
        number(&contract, &format!("{request}/paddingClassWireId")),
        usize::from(AuthPaddingClassV1::Class16KiB as u8)
    );
    assert_eq!(
        number(&contract, &format!("{request}/bodyBytes")),
        AUTH_FRAME_CLASS_V1
    );
    assert_eq!(
        number(&contract, &format!("{request}/canonicalPaddingByte")),
        0
    );
    assert_eq!(
        number(&contract, &format!("{request}/innerOpcodeBytes")),
        INNER_OPCODE_BYTES
    );
    assert_eq!(
        number(&contract, &format!("{request}/encryptedMagicBytes")),
        ENCRYPTED_MAGIC_BYTES
    );
    assert_eq!(
        number(&contract, &format!("{request}/encryptedSequenceBytes")),
        ENCRYPTED_SEQUENCE_BYTES
    );
    assert_eq!(
        number(&contract, &format!("{request}/aeadTagBytes")),
        AEAD_TAG_LEN
    );
    assert_eq!(
        number(&contract, &format!("{request}/outerLengthPrefixBytes")),
        OUTER_LENGTH_PREFIX_BYTES
    );

    let inner_plaintext = INNER_OPCODE_BYTES + AUTH_FRAME_CLASS_V1;
    let sealed_payload =
        ENCRYPTED_MAGIC_BYTES + ENCRYPTED_SEQUENCE_BYTES + inner_plaintext + AEAD_TAG_LEN;
    let application_record = OUTER_LENGTH_PREFIX_BYTES + sealed_payload;
    assert_eq!(
        number(&contract, &format!("{request}/innerPlaintextBytes")),
        inner_plaintext
    );
    assert_eq!(
        number(&contract, &format!("{request}/sealedPayloadBytes")),
        sealed_payload
    );
    assert_eq!(
        number(&contract, &format!("{request}/applicationRecordBytes")),
        application_record
    );
}

#[test]
fn every_v1_method_and_workload_has_the_same_encrypted_request_shape() {
    let contract = contract();
    let expected_body = number(
        &contract,
        "/serviceAuthorization/transport/request/bodyBytes",
    );
    let expected_sealed = number(
        &contract,
        "/serviceAuthorization/transport/request/sealedPayloadBytes",
    );
    let expected_record = number(
        &contract,
        "/serviceAuthorization/transport/request/applicationRecordBytes",
    );

    for (scheme_index, scheme) in schemes().into_iter().enumerate() {
        for (operation_index, operation) in operations().into_iter().enumerate() {
            let proof_len = if scheme_index == 4 && operation_index == 4 {
                MAX_AUTH_PROOF_LEN
            } else {
                scheme_index * 257 + operation_index * 31
            };
            let key_len = (scheme_index * 11 + operation_index * 7) % 65;
            let request = AuthBeginV1 {
                policy_digest: [0x41; 32],
                scope_id: [0x50 + operation_index as u8; 32],
                offer_id: 1 + scheme_index as u32,
                scheme,
                key_id: vec![0x60 + scheme_index as u8; key_len],
                operation,
                proof: vec![0x70 + operation_index as u8; proof_len],
            };
            let padded = request.encode_padded().expect("fixture must fit class 1");
            assert_eq!(padded.len(), expected_body);
            assert_eq!(
                AuthBeginV1::decode_padded(&padded).expect("padded request must decode"),
                request
            );

            let mut inner = Vec::with_capacity(INNER_OPCODE_BYTES + padded.len());
            inner.push(REQ_AUTH_BEGIN_V1);
            inner.extend_from_slice(&padded);
            let (mut client_session, mut server_session) = session_pair();
            let sealed = client_session
                .seal(Direction::ClientToServer, &inner)
                .expect("authorization request must seal");
            assert_eq!(sealed[0], ENCRYPTED_FRAME_MAGIC);
            assert_eq!(sealed.len(), expected_sealed);
            let record = application_record(&sealed);
            assert_eq!(record.len(), expected_record);
            assert_eq!(
                u32::from_le_bytes(record[..4].try_into().unwrap()) as usize,
                expected_sealed
            );

            let opened = server_session
                .open(Direction::ClientToServer, &record[4..])
                .expect("authorization request must authenticate and decrypt");
            let Some(ServiceWireRequestV1::Auth(decoded)) =
                ServiceWireRequestV1::decode_inner_payload(&opened)
                    .expect("decrypted authorization request must decode")
            else {
                panic!("decrypted record must be AUTH_BEGIN_V1")
            };
            assert_eq!(*decoded, request);
        }
    }
}

#[test]
fn padding_is_canonical_but_v1_response_shape_is_explicitly_visible() {
    let request = AuthBeginV1 {
        policy_digest: [0x11; 32],
        scope_id: [0x22; 32],
        offer_id: 1,
        scheme: AuthScheme::BitcoinPirCashuBatV1,
        key_id: vec![0x33; 16],
        operation: OperationStartV1::DpfQuery { db_id: 1 },
        proof: vec![0x44; 128],
    };
    let mut noncanonical = request.encode_padded().unwrap();
    *noncanonical.last_mut().unwrap() = 1;
    assert!(
        AuthBeginV1::decode_padded(&noncanonical).is_err(),
        "non-zero client-controlled padding must fail closed"
    );

    let granted = AuthResultV1::Granted(AuthGrantedV1 {
        scope_id: [0x55; 32],
        enforced_profile: 7,
        expires_in_ms: 1_000,
        harmony_attach: None,
    });
    let rejected = AuthResultV1::Rejected(AuthRejectedV1 {
        code: AuthRejectCode::InvalidOrSpent,
        retry_after_ms: 0,
    });
    let granted_body = granted.encode().unwrap();
    let rejected_body = rejected.encode().unwrap();
    assert_ne!(granted_body.len(), rejected_body.len());

    let (_, mut server_session) = session_pair();
    let mut granted_inner = vec![RESP_AUTH_RESULT_V1];
    granted_inner.extend_from_slice(&granted_body);
    let granted_sealed = server_session
        .seal(Direction::ServerToClient, &granted_inner)
        .unwrap();
    let mut rejected_inner = vec![RESP_AUTH_RESULT_V1];
    rejected_inner.extend_from_slice(&rejected_body);
    let rejected_sealed = server_session
        .seal(Direction::ServerToClient, &rejected_inner)
        .unwrap();
    assert_ne!(granted_sealed.len(), rejected_sealed.len());

    let contract = contract();
    assert!(!boolean(
        &contract,
        "/serviceAuthorization/transport/response/fixedLength"
    ));
    assert!(boolean(
        &contract,
        "/serviceAuthorization/transport/response/resultShapeObservableFromCiphertextLength"
    ));
}

#[test]
fn admission_gate_does_not_treat_plaintext_as_a_secure_authorization_context() {
    let mut gate = ConnectionAdmissionGateV1::new(AdmissionEnforcementV1::Enforced);
    assert_eq!(
        gate.policy_served(false, [0x81; 32]),
        Err(GateErrorV1::SecureChannelRequired)
    );
    gate.secure_channel_established();
    assert_eq!(
        gate.policy_served(false, [0x81; 32]),
        Err(GateErrorV1::SecureChannelRequired)
    );
}
