//! The JSON boundary only: the verification is tested in
//! `pir-directory-nostr` (`catalog/tests.rs`).

use pir_directory_nostr::{full_catalog_req_json_v1, DirectoryPublisherKeyV1};

use super::*;

const NOW: u64 = 1_800_000_000;

fn key() -> [u8; 32] {
    *DirectoryPublisherKeyV1::from_secret_bytes([51; 32])
        .unwrap()
        .public_key()
}

#[test]
fn catalog_requests_are_the_codec_requests_byte_for_byte() {
    let key = key();
    let requests = catalog_requests(&key).unwrap();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.as_bytes().to_vec())
            .collect::<Vec<_>>(),
        full_catalog_req_json_v1(&key).unwrap()
    );
    assert_eq!(
        requests[10],
        format!(
            r##"["REQ","bitcoinpir-directory-v1-shard-a",{{"authors":["{}"],"kinds":[30078],"#s":["bitcoinpir-service-directory-shard-v1:a"]}}]"##,
            hex::encode(key)
        )
    );
    assert!(catalog_requests(&key[..31]).is_err());
}

#[test]
fn json_entry_point_returns_camel_case_catalog_and_round_trips_floors() {
    let key = key();
    // One relay that answered every subscription with nothing: each shard
    // is rejected for that relay view and then as a whole, no view is
    // accepted, the floors stay empty.
    let empty: serde_json::Value =
        serde_json::from_str(&verify_catalog_json("[[]]", None, &key, NOW).unwrap()).unwrap();
    assert_eq!(empty["validUntil"], 0);
    assert_eq!(empty["shards"], serde_json::json!([]));
    assert_eq!(empty["entries"], serde_json::json!([]));
    assert_eq!(empty["rejected"].as_array().unwrap().len(), 32);
    assert_eq!(empty["rejected"][0]["relay"], 0);
    assert_eq!(empty["rejected"][0]["shard"], 0);
    assert_eq!(empty["rejected"][16]["relay"], serde_json::Value::Null);
    assert_eq!(empty["rejected"][16]["shard"], 0);
    assert_eq!(
        empty["state"],
        serde_json::json!({ "entries": {}, "checkpoints": {} })
    );

    let state = empty["state"].to_string();
    let replay: serde_json::Value =
        serde_json::from_str(&verify_catalog_json("[[]]", Some(&state), &key, NOW).unwrap())
            .unwrap();
    assert_eq!(replay["state"], empty["state"]);
    assert!(verify_catalog_json("[[]]", Some(r#"{"entries":{}}"#), &key, NOW).is_err());
    assert!(verify_catalog_json("{}", None, &key, NOW).is_err());
    assert!(verify_catalog_json("[[]]", None, &key[..31], NOW).is_err());
}
