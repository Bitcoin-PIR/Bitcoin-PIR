//! Bounded malformed-wire regression gate for the provider admission parser.
//!
//! Known service opcodes must never fall through to legacy PIR decoding, and
//! an accepted body must be the byte-for-byte canonical encoding of its typed
//! value. The corpus is deterministic and small enough for every offline CI
//! run.

use std::panic::{catch_unwind, AssertUnwindSafe};

use pir_runtime_core::service_admission::ServiceWireRequestV1;
use pir_service_protocol::{
    AuthBeginV1, AuthScheme, OperationStartV1, ServicePolicyRequestV1, AUTH_FRAME_CLASS_V1,
    REQ_AUTH_BEGIN_V1, REQ_HARMONY_ATTACH_V1, REQ_POW_CHALLENGE_V1, REQ_SERVICE_POLICY_V1,
    SERVICE_PROTOCOL_VERSION,
};

fn deterministic_bytes(len: usize, mut state: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.push(state as u8);
    }
    bytes
}

fn bounded_bodies() -> Vec<Vec<u8>> {
    const LENGTHS: &[usize] = &[
        0,
        1,
        2,
        3,
        4,
        5,
        31,
        32,
        33,
        63,
        64,
        65,
        127,
        128,
        129,
        255,
        256,
        257,
        511,
        512,
        1_023,
        1_024,
        4_095,
        4_096,
        AUTH_FRAME_CLASS_V1 - 1,
        AUTH_FRAME_CLASS_V1,
        AUTH_FRAME_CLASS_V1 + 1,
    ];
    let mut corpus = Vec::new();
    for &len in LENGTHS {
        corpus.push(vec![0; len]);
        corpus.push(vec![u8::MAX; len]);
        let mut versioned = deterministic_bytes(len, 0xa54f_f53a_5f1d_36f1 ^ len as u64);
        if let Some(version) = versioned.first_mut() {
            *version = SERVICE_PROTOCOL_VERSION;
        }
        corpus.push(versioned);
    }
    corpus
}

fn canonical_body(request: &ServiceWireRequestV1) -> Vec<u8> {
    match request {
        ServiceWireRequestV1::Policy(request) => request.encode(),
        ServiceWireRequestV1::Auth(request) => request.encode_padded().unwrap(),
        ServiceWireRequestV1::PowChallenge(request) => request.encode_padded().unwrap(),
        ServiceWireRequestV1::HarmonyAttach(request) => request.encode_padded().unwrap(),
    }
}

#[test]
fn payment_v1_provider_admission_is_total_and_never_falls_through_known_opcodes() {
    let bodies = bounded_bodies();
    assert!(
        bodies.len() < 100,
        "the provider CI corpus must remain bounded"
    );

    for opcode in [
        REQ_SERVICE_POLICY_V1,
        REQ_AUTH_BEGIN_V1,
        REQ_POW_CHALLENGE_V1,
        REQ_HARMONY_ATTACH_V1,
    ] {
        for (case_index, body) in bodies.iter().enumerate() {
            let mut payload = Vec::with_capacity(1 + body.len());
            payload.push(opcode);
            payload.extend_from_slice(body);
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                ServiceWireRequestV1::decode_inner_payload(&payload)
            }))
            .unwrap_or_else(|_| {
                panic!(
                    "service opcode {opcode:#04x} panicked on adversarial case {case_index} (body_len={})",
                    body.len()
                )
            });
            match outcome {
                Ok(Some(request)) => assert_eq!(
                    canonical_body(&request),
                    *body,
                    "accepted service bodies must be canonical"
                ),
                Err(_) => {}
                Ok(None) => panic!("known service opcode {opcode:#04x} fell through"),
            }
        }
    }
}

#[test]
fn payment_v1_auth_length_and_padding_mutations_fail_before_admission() {
    let canonical = AuthBeginV1 {
        policy_digest: [0x11; 32],
        scope_id: [0x22; 32],
        offer_id: 1,
        scheme: AuthScheme::FreeV1,
        key_id: Vec::new(),
        operation: OperationStartV1::DpfQuery { db_id: 7 },
        proof: Vec::new(),
    }
    .encode_padded()
    .unwrap();
    assert_eq!(canonical.len(), AUTH_FRAME_CLASS_V1);

    let mut canonical_payload = vec![REQ_AUTH_BEGIN_V1];
    canonical_payload.extend_from_slice(&canonical);
    assert!(matches!(
        ServiceWireRequestV1::decode_inner_payload(&canonical_payload),
        Ok(Some(ServiceWireRequestV1::Auth(_)))
    ));

    let key_len_offset = 1 + 32 + 32 + 4 + 1;
    let operation_len_offset = key_len_offset + 1;
    let operation_len = canonical[operation_len_offset] as usize;
    let proof_len_offset = operation_len_offset + 1 + operation_len;

    let mut malformed = Vec::new();
    malformed.push(canonical[..canonical.len() - 1].to_vec());
    let mut extra = canonical.clone();
    extra.push(0);
    malformed.push(extra);

    let mut bad_key_len = canonical.clone();
    bad_key_len[key_len_offset] = u8::MAX;
    malformed.push(bad_key_len);

    let mut bad_operation_len = canonical.clone();
    bad_operation_len[operation_len_offset] = u8::MAX;
    malformed.push(bad_operation_len);

    let mut bad_proof_len = canonical.clone();
    bad_proof_len[proof_len_offset..proof_len_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    malformed.push(bad_proof_len);

    let mut nonzero_padding = canonical.clone();
    *nonzero_padding.last_mut().unwrap() = 1;
    malformed.push(nonzero_padding);

    let mut wrong_version = canonical.clone();
    wrong_version[0] = SERVICE_PROTOCOL_VERSION + 1;
    malformed.push(wrong_version);

    let mut zero_offer = canonical.clone();
    zero_offer[65..69].fill(0);
    malformed.push(zero_offer);

    for (case_index, body) in malformed.iter().enumerate() {
        let mut payload = vec![REQ_AUTH_BEGIN_V1];
        payload.extend_from_slice(body);
        assert!(
            ServiceWireRequestV1::decode_inner_payload(&payload).is_err(),
            "malformed AUTH_BEGIN case {case_index} crossed the typed provider boundary"
        );
    }
}

#[test]
fn payment_v1_unknown_opcodes_remain_outside_the_service_admission_namespace() {
    let current_policy = ServicePolicyRequestV1::Current.encode();
    for opcode in [0x00, 0x7f, 0xff] {
        assert!(![
            REQ_SERVICE_POLICY_V1,
            REQ_AUTH_BEGIN_V1,
            REQ_POW_CHALLENGE_V1,
            REQ_HARMONY_ATTACH_V1,
        ]
        .contains(&opcode));
        let mut payload = vec![opcode];
        payload.extend_from_slice(&current_policy);
        assert!(matches!(
            ServiceWireRequestV1::decode_inner_payload(&payload),
            Ok(None)
        ));
    }
}
