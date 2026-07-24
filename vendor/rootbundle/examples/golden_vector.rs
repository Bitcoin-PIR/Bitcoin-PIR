use ed25519_dalek::SigningKey;
use rootbundle::{
    sign_root_bundle, BuildKind, BuildParamsV2, ChainAnchor, NamedRoot,
    RootBundlePayload, SignedRootBundle,
};

fn main() {
    let params = BuildParamsV2::current_snapshot(
        565_684, 1_064_454, 3_328, 815_432, 612_345, 1_345_678,
    );
    let payload = RootBundlePayload {
        network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
        build_kind: BuildKind::Snapshot,
        from_anchor: ChainAnchor {
            block_hash: [0; 32],
            height: 0,
        },
        anchor: ChainAnchor {
            block_hash: [0xab; 32],
            height: 950_000,
        },
        utxo_muhash: [0xcd; 32],
        dust_threshold_sats: 576,
        max_utxos_per_spk: 100,
        params_hash: params.params_hash(),
        issued_at: 1_780_000_000,
        roots: vec![
            NamedRoot {
                label: "dpf/chunk/super_root".into(),
                root: [2; 32],
            },
            NamedRoot {
                label: "dpf/index/super_root".into(),
                root: [1; 32],
            },
            NamedRoot {
                label: "onion/super_root".into(),
                root: [3; 32],
            },
        ],
    };
    let key0 = SigningKey::from_bytes(&[7; 32]);
    let key1 = SigningKey::from_bytes(&[9; 32]);
    let bundle = SignedRootBundle {
        signatures: vec![
            sign_root_bundle(&payload, &key0).unwrap(),
            sign_root_bundle(&payload, &key1).unwrap(),
        ],
        payload,
    };
    println!("payload={}", hex::encode(bundle.payload.encode().unwrap()));
    println!("bundle={}", hex::encode(bundle.encode().unwrap()));
    println!("trusted0={}", hex::encode(key0.verifying_key().to_bytes()));
    println!("trusted1={}", hex::encode(key1.verifying_key().to_bytes()));
}
