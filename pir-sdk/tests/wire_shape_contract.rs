use std::{fs, path::PathBuf};

use pir_core::params::{INDEX_CUCKOO_NUM_HASHES, K, K_CHUNK};
use pir_sdk::{PirBackendType, RoundKind};
use serde_json::Value;

fn contract() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../verification/contracts/wire-shape-v1.json");
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

#[test]
fn public_parameters_match_the_implementation() {
    let contract = contract();

    assert_eq!(
        contract["schema"],
        "BitcoinPIR/wire-shape-contract/v1"
    );
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

    let actual_names: Vec<String> = actual
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

    assert_eq!(leakage.len(), 4, "changing L requires updating the proof");
    assert!(non_claims.iter().any(|value| {
        value.as_str() == Some("mechanical_correspondence_to_the_rust_implementation")
    }));
    assert!(non_claims
        .iter()
        .any(|value| value.as_str() == Some("cryptographic_primitive_reductions")));
}
