use std::{fs, path::PathBuf};

use pir_core::params::{INDEX_CUCKOO_NUM_HASHES, K, K_CHUNK};
use pir_sdk::{PirBackendType, RoundKind};
use serde_json::Value;

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

#[test]
fn public_parameters_match_the_implementation() {
    let contract = contract();

    assert_eq!(contract["schema"], "BitcoinPIR/wire-shape-contract/v1");
    assert_eq!(number(&contract, "/contractVersion"), 2);
    assert_eq!(number(&contract, "/parameters/indexGroups"), K);
    assert_eq!(number(&contract, "/parameters/chunkGroups"), K_CHUNK);
    assert_eq!(
        number(&contract, "/parameters/indexCuckooHashes"),
        INDEX_CUCKOO_NUM_HASHES
    );
    assert_eq!(
        number(&contract, "/backends/dpf/deploymentServerCount"),
        PirBackendType::Dpf.required_servers()
    );
    assert_eq!(
        number(&contract, "/backends/harmony/deploymentServerCount"),
        PirBackendType::Harmony.required_servers()
    );
    assert_eq!(
        number(&contract, "/backends/onion/deploymentServerCount"),
        PirBackendType::Onion.required_servers()
    );
    assert_eq!(
        contract["backends"]["dpf"]["formalPirRoundServerIds"],
        serde_json::json!([0, 1])
    );
    assert_eq!(
        contract["backends"]["harmony"]["formalPirRoundServerIds"],
        serde_json::json!([0])
    );
    assert_eq!(
        contract["backends"]["onion"]["formalPirRoundServerIds"],
        serde_json::json!([0])
    );
}

#[test]
fn round_kind_names_match_the_serde_wire_shape() {
    let contract = contract();
    let expected = contract["roundKinds"]
        .as_array()
        .expect("roundKinds must be an array");
    let actual = [
        RoundKind::Index,
        RoundKind::Chunk,
        RoundKind::IndexMerkleSiblings { level: 0 },
        RoundKind::ChunkMerkleSiblings { level: 0 },
        RoundKind::HarmonyHintRefresh,
        RoundKind::OnionKeyRegister,
        RoundKind::Info,
        RoundKind::MerkleTreeTops,
    ];

    let mut actual_names: Vec<String> = actual
        .into_iter()
        .map(|kind| {
            serde_json::to_value(kind)
                .expect("RoundKind must serialize")
                .get("kind")
                .and_then(Value::as_str)
                .expect("RoundKind must use a string kind tag")
                .to_owned()
        })
        .collect();
    actual_names.insert(7, "service_authorization".to_owned());
    let expected_names: Vec<&str> = expected
        .iter()
        .map(|value| value.as_str().expect("round kind must be a string"))
        .collect();

    assert_eq!(actual_names, expected_names);
}

#[test]
fn proof_scope_keeps_all_declared_leakage_axes_and_non_claims() {
    let contract = contract();
    let leakage = contract["admittedLeakage"]
        .as_array()
        .expect("admittedLeakage must be an array");
    let non_claims = contract["explicitNonClaims"]
        .as_array()
        .expect("explicitNonClaims must be an array");
    let expected_leakage = serde_json::json!([
        "index_max_items_per_group_per_level",
        "chunk_max_items_per_group_per_level",
        "session_query_index",
        "query_db_id",
        "authorization_scheme_by_server",
        "authorization_scope_id_by_server",
        "authorization_operation_by_server",
        "authorization_timing_by_server",
        "authorization_result_shape_by_server"
    ]);

    assert_eq!(
        leakage,
        expected_leakage.as_array().unwrap(),
        "changing L requires updating the proof"
    );
    assert!(non_claims
        .iter()
        .any(|value| value.as_str() == Some("NC-IMPLEMENTATION-REFINEMENT")));
    assert!(non_claims
        .iter()
        .any(|value| value.as_str() == Some("NC-CRYPTOGRAPHIC-REDUCTIONS")));
    assert!(non_claims
        .iter()
        .any(|value| value.as_str() == Some("NC-RESULT-CORRECTNESS")));

    assert_eq!(
        contract["implementationSurfaceIds"],
        serde_json::json!([
            "pir_core::params",
            "pir_channel::Session",
            "pir_service_protocol::AuthBeginV1",
            "pir_runtime_core::service_admission",
            "pir_sdk::leakage",
            "pir_sdk_client::dpf",
            "pir_sdk_client::harmony",
            "pir_sdk_client::onion",
            "pir_sdk_client::onion_merkle",
            "pir_sdk_client::leakage_integration",
            "pir_sdk_wasm::harmony_wire",
            "web::leakage",
            "web::onionpir_client"
        ])
    );
}

#[test]
fn payment_v1_observer_boundary_is_explicit_and_fail_closed() {
    let contract = contract();

    assert_eq!(
        contract.pointer("/serviceAuthorization/roundKind"),
        Some(&Value::String("service_authorization".to_owned()))
    );
    assert!(boolean(
        &contract,
        "/serviceAuthorization/independentPerServer"
    ));
    assert!(boolean(
        &contract,
        "/serviceAuthorization/transport/secureChannelRequired"
    ));
    assert!(!boolean(
        &contract,
        "/serviceAuthorization/transport/response/fixedLength"
    ));
    assert!(boolean(
        &contract,
        "/serviceAuthorization/transport/response/resultShapeObservableFromCiphertextLength"
    ));

    assert_eq!(
        contract.pointer(
            "/serviceAuthorization/observerModel/networkObserverWithoutChannelKeys/requestShapeHides"
        ),
        Some(&serde_json::json!([
            "authorization_scheme",
            "service_scope_id",
            "authorization_operation",
            "credential_proof_length"
        ]))
    );
    assert_eq!(
        contract.pointer(
            "/serviceAuthorization/observerModel/networkObserverWithoutChannelKeys/admittedLeakage"
        ),
        Some(&serde_json::json!([
            "authorization_occurrence_and_timing",
            "authorization_result_shape"
        ]))
    );
    assert_eq!(
        contract.pointer(
            "/serviceAuthorization/observerModel/providerAfterChannelDecryption/observableFields"
        ),
        Some(&serde_json::json!([
            "authorization_scheme",
            "service_scope_id",
            "authorization_operation",
            "credential_presentation",
            "authorization_timing",
            "authorization_result"
        ]))
    );
    assert_eq!(
        contract.pointer(
            "/serviceAuthorization/observerModel/providerAfterChannelDecryption/forbiddenFields"
        ),
        Some(&serde_json::json!([
            "bolt11_invoice",
            "payment_hash",
            "payment_preimage",
            "payer_identity",
            "peer_provider_id",
            "provider_pair_id",
            "pir_query_payload",
            "pir_result"
        ]))
    );
}
