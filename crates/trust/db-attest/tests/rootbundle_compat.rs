use pir_db_attest::{RootBundlePayload, SignedRootBundle};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const UPSTREAM_COMMIT: &str = "80ad9b185760d2e36fd24baef50dd3030af8e94f";

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|path| path.join("verification/locks/rootbundle.json").is_file())
        .expect("workspace root containing the rootbundle lock")
}

#[test]
fn consumer_lock_matches_the_cargo_pin() {
    let repo = repo_root();
    let lock: serde_json::Value = serde_json::from_slice(
        &fs::read(repo.join("verification/locks/rootbundle.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(lock["commit"], UPSTREAM_COMMIT);
    assert_eq!(lock["release_tag"], "rootbundle-v0.1.0");
    assert_eq!(
        lock["golden_bundle_sha256"],
        "71c32a0dbaf5d2fad4d2778fca5c6c88f317a0606358b4c49f429d368ebcd4dc"
    );
    let manifest = fs::read_to_string(repo.join("crates/trust/db-attest/Cargo.toml")).unwrap();
    assert!(manifest.contains(UPSTREAM_COMMIT));
}

#[test]
fn upstream_release_golden_bundle_decodes_reencodes_and_verifies() {
    let bytes = hex::decode(
        include_str!("../testdata/rootbundle-v0.1.0-bundle.hex").trim(),
    )
    .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "71c32a0dbaf5d2fad4d2778fca5c6c88f317a0606358b4c49f429d368ebcd4dc"
    );
    let bundle = SignedRootBundle::decode(&bytes).unwrap();
    assert_eq!(bundle.encode().unwrap(), bytes);
    let trusted = [
        hex::decode("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")
            .unwrap()
            .try_into()
            .unwrap(),
        hex::decode("fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618")
            .unwrap()
            .try_into()
            .unwrap(),
    ];
    assert_eq!(bundle.verify_quorum(&trusted, 2), Ok(2));
}

#[test]
fn retained_production_payloads_still_decode_byte_for_byte() {
    let repo = repo_root();
    for (relative, expected_sha256) in [(
        "web/public/proofs/oram-source/mainnet_948454/db/root-bundle-payload.bin",
        "cfbd67fd10d4f7cbaa29b82ffa1a60aa35229655bb24cdac8883547b221fca6f",
    )] {
        let bytes = fs::read(repo.join(relative)).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&bytes)), expected_sha256);
        let payload = RootBundlePayload::decode(&bytes).unwrap();
        assert_eq!(payload.encode().unwrap(), bytes, "{relative}");
    }
}
