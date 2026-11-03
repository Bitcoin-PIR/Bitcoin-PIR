use super::*;
use pir_directory_nostr::DirectoryBackendV1;

fn hint(backend: DirectoryBackendV1, access: DirectoryAccessClassV1) -> DirectoryCatalogHintV1 {
    DirectoryCatalogHintV1 {
        backend,
        role: DirectoryServerRoleV1::Primary,
        access,
        attestation: DirectoryAttestationV1::None,
    }
}

#[test]
fn live_info_must_serve_every_hint_with_its_role_and_access() {
    let hints = [
        hint(DirectoryBackendV1::Dpf, DirectoryAccessClassV1::BestEffort),
        hint(DirectoryBackendV1::Onion, DirectoryAccessClassV1::Paid),
    ];
    let served = br#"{"role":"primary","credits":{"enabled":true,"required":true,
        "access":{"dpf":{"mode":"best-effort","free_concurrency":2}}}}"#;
    assert_eq!(check_live_info(&hints, served), Ok(()));

    let secondary = br#"{"role":"secondary","credits":{"enabled":true,"required":true,
        "access":{"dpf":{"mode":"best-effort","free_concurrency":2}}}}"#;
    assert!(check_live_info(&hints, secondary)
        .unwrap_err()
        .contains("live role is secondary"));

    // Without credits a server serves everything free.
    let free = br#"{"role":"primary"}"#;
    assert!(check_live_info(&hints, free)
        .unwrap_err()
        .contains("live dpf access is free"));
}

#[test]
fn a_new_assertion_needs_a_higher_epoch_and_a_dropped_node_too() {
    let assertion = |epoch: u64, valid_until: u64| DirectoryOperatorAssertionV1 {
        operator_pubkey_ed25519: [1; 32],
        stable_server_id: "node-a".to_owned(),
        provider_id: pir_directory_nostr::derive_provider_id(&[1; 32], "node-a"),
        assertion_epoch: epoch,
        not_before: 1,
        valid_until,
        endpoints: vec![pir_directory_nostr::DirectoryEndpointV1 {
            transport: pir_directory_nostr::DirectoryTransportV1::Wss,
            url: "wss://node-a.example.com".to_owned(),
        }],
        signature_ed25519: [3; 64],
    };
    let first = assertion(4, 100);
    let first_bytes = first.encode().unwrap();
    let listed = (first_bytes.clone(), false);
    let dropped = (first_bytes.clone(), true);

    assert_eq!(check_epoch(None, &first_bytes, &first), Ok(()));
    assert_eq!(check_epoch(Some(&listed), &first_bytes, &first), Ok(()));
    let resigned = assertion(4, 200);
    let resigned_bytes = resigned.encode().unwrap();
    assert!(check_epoch(Some(&listed), &resigned_bytes, &resigned).is_err());
    assert!(check_epoch(Some(&dropped), &first_bytes, &first).is_err());
    let next = assertion(5, 200);
    let next_bytes = next.encode().unwrap();
    assert_eq!(check_epoch(Some(&listed), &next_bytes, &next), Ok(()));
    assert_eq!(check_epoch(Some(&dropped), &next_bytes, &next), Ok(()));
}
