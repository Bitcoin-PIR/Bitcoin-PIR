use ed25519_dalek::SigningKey;

use crate::*;

const NOW: u64 = 1_500;

fn assertion() -> DirectoryOperatorAssertionV1 {
    DirectoryOperatorAssertionV1::sign(
        "home-node".to_owned(),
        1,
        1_000,
        3_000,
        vec![DirectoryEndpointV1 {
            transport: DirectoryTransportV1::Wss,
            url: "wss://pir.home.example".to_owned(),
        }],
        &SigningKey::from_bytes(&[3; 32]),
    )
    .unwrap()
}

fn hints() -> Vec<DirectoryCatalogHintV1> {
    vec![DirectoryCatalogHintV1 {
        backend: DirectoryBackendV1::Dpf,
        role: DirectoryServerRoleV1::Secondary,
        access: DirectoryAccessClassV1::Free,
        attestation: DirectoryAttestationV1::None,
    }]
}

fn signed(created_at: u64) -> NostrEventV1 {
    let announcement = NodeAnnouncementV1::new(assertion(), hints(), NOW).unwrap();
    DirectoryPublisherKeyV1::from_secret_bytes([7; 32])
        .unwrap()
        .sign_node_announcement_event(&announcement, created_at, &[9; 32])
        .unwrap()
}

#[test]
fn announcement_roundtrips_under_any_nostr_key() {
    let event = signed(NOW);
    let json = event.to_json_bytes().unwrap();
    let verified = verify_node_announcement_event_v1(&json, NOW).unwrap();
    let announcement = verified.announcement();
    assert_eq!(announcement.catalog_hints(), hints().as_slice());
    assert_eq!(
        announcement.provider_id(),
        &derive_provider_id(&assertion().operator_pubkey_ed25519, "home-node")
    );
    assert_eq!(
        node_announcement_provider_id_v1(&event.tags()[0][1]).unwrap(),
        *announcement.provider_id()
    );
    assert_eq!(event.tags()[1], ["expiration", "3000"]);
    // A directory entry check never accepts an announcement.
    assert!(verify_directory_entry_event_v1(&json, event.pubkey(), NOW).is_err());
}

#[test]
fn announcement_rejects_tampering_expiry_and_empty_hints() {
    let json = signed(NOW).to_json_bytes().unwrap();
    // After the assertion's valid_until, and before its creation.
    assert!(verify_node_announcement_event_v1(&json, 3_001).is_err());
    assert!(verify_node_announcement_event_v1(&json, NOW - 1).is_err());
    // Any byte change breaks the id or the signature.
    let tampered = String::from_utf8(json.clone())
        .unwrap()
        .replace("home.example", "evil.example");
    assert!(verify_node_announcement_event_v1(tampered.as_bytes(), NOW).is_err());
    assert_eq!(
        NodeAnnouncementV1::new(assertion(), Vec::new(), NOW),
        Err(DirectoryErrorV1::InvalidCatalogHints)
    );
}

#[test]
fn announcement_req_is_one_fixed_filter() {
    assert_eq!(
        node_announcements_req_json_v1().unwrap(),
        br##"["REQ","bitcoinpir-node-announcements",{"kinds":[30078],"#t":["bitcoinpir-node"]}]"##
    );
}
