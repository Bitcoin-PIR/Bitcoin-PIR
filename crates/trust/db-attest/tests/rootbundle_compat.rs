use pir_db_attest::SignedRootBundle;
use sha2::{Digest, Sha256};

// Golden vector of the upstream rootbundle-v0.1.0 release
// (Bitcoin-PIR/attested-builder @ 80ad9b185760d2e36fd24baef50dd3030af8e94f).
const GOLDEN_BUNDLE_SHA256: &str =
    "71c32a0dbaf5d2fad4d2778fca5c6c88f317a0606358b4c49f429d368ebcd4dc";

#[test]
fn upstream_release_golden_bundle_decodes_reencodes_and_verifies() {
    let bytes =
        hex::decode(include_str!("../testdata/rootbundle-v0.1.0-bundle.hex").trim()).unwrap();
    assert_eq!(hex::encode(Sha256::digest(&bytes)), GOLDEN_BUNDLE_SHA256);
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
