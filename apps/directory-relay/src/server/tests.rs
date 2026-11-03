use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use pir_directory_nostr::{
    catalog_req_json_v1, verify_directory_entry_event_v1, DirectoryEntryV1, DirectoryHealthClassV1,
    DirectoryHealthV1, DirectoryPublisherKeyV1, NostrEventV1,
};
use serde::Serialize;
use serde_json::Value;
use tokio_tungstenite::tungstenite::protocol::frame::{
    coding::{Data as FrameData, OpCode},
    Frame,
};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::wire::{MAX_READBACK_IDS, MAX_WIRE_MESSAGE_BYTES};

type TestClient = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Serialize)]
struct IdFilter {
    ids: Vec<String>,
}

/// Reserve an ephemeral port on 127.0.0.1 and release it; `start` binds
/// it moments later. macOS has no 127.0.0.2 alias, and `start` requires
/// two distinct socket addresses, so both lanes need concrete ports.
fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn test_config(database: std::path::PathBuf, key: [u8; 32]) -> RelayConfig {
    let public_port = free_loopback_port();
    let publisher_port = loop {
        let port = free_loopback_port();
        if port != public_port {
            break port;
        }
    };
    RelayConfig {
        public_listen: format!("127.0.0.1:{public_port}").parse().unwrap(),
        publisher_listen: format!("127.0.0.1:{publisher_port}").parse().unwrap(),
        database,
        directory_pubkey: key,
        max_connections: 32,
        max_public_connections: 24,
        max_publisher_connections: 8,
        max_in_flight_operations: 4,
        max_public_in_flight_operations: 3,
        max_publisher_in_flight_operations: 1,
        max_operations_per_second: 1_000_000,
        max_public_operations_per_second: 750_000,
        max_publisher_operations_per_second: 250_000,
        max_egress_bytes_per_second: 1024 * 1024 * 1024,
        max_public_egress_bytes_per_second: 768 * 1024 * 1024,
        max_publisher_egress_bytes_per_second: 256 * 1024 * 1024,
        max_egress_bytes_per_connection: 64 * 1024 * 1024,
        max_archive_events: 20_000,
        max_archive_bytes: 64 * 1024 * 1024,
        handshake_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(10),
        connection_timeout: Duration::from_secs(60),
        operation_timeout: Duration::from_secs(10),
        egress_timeout: Duration::from_secs(5),
    }
}

fn signed_entry(
    publisher: &DirectoryPublisherKeyV1,
    provider: [u8; 32],
    sequence: u64,
    created_at: u64,
    now: u64,
    randomness: u8,
) -> NostrEventV1 {
    let entry = DirectoryEntryV1::new_tombstone(
        provider,
        sequence,
        now + 3_600,
        DirectoryHealthV1 {
            class: DirectoryHealthClassV1::Unknown,
            observed_bucket: created_at - (created_at % 300),
        },
        now,
    )
    .unwrap();
    publisher
        .sign_entry_event(&entry, created_at, &[randomness; 32])
        .unwrap()
}

#[test]
fn signed_entry_health_bucket_does_not_postdate_event() {
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([62; 32]).unwrap();
    let created_at = 599;
    let event = signed_entry(&publisher, [0x32; 32], 1, created_at, 600, 1);

    verify_directory_entry_event_v1(
        &event.to_json_bytes().unwrap(),
        publisher.public_key(),
        created_at,
    )
    .unwrap();
}

async fn connect_public(handle: &RelayHandle) -> TestClient {
    connect_async(format!("ws://{}", handle.public_addr()))
        .await
        .unwrap()
        .0
}

async fn connect_publisher(handle: &RelayHandle) -> TestClient {
    connect_async(format!("ws://{}", handle.publisher_addr()))
        .await
        .unwrap()
        .0
}

async fn receive_text(client: &mut TestClient) -> String {
    let message = tokio::time::timeout(Duration::from_secs(10), client.next())
        .await
        .expect("relay response timeout")
        .expect("relay closed before response")
        .expect("relay WebSocket error");
    match message {
        Message::Text(text) => text.to_string(),
        other => panic!("unexpected relay message: {other:?}"),
    }
}

async fn publish(client: &mut TestClient, event: &NostrEventV1) -> (bool, String) {
    let message = String::from_utf8(event.to_event_message_json_bytes().unwrap()).unwrap();
    client.send(Message::Text(message.into())).await.unwrap();
    let response: Value = serde_json::from_str(&receive_text(client).await).unwrap();
    assert_eq!(response[0], "OK");
    assert_eq!(response[1], hex::encode(event.id()));
    (
        response[2].as_bool().unwrap(),
        response[3].as_str().unwrap().to_owned(),
    )
}

async fn receive_catalog(
    client: &mut TestClient,
    request: &str,
    subscription_id: &str,
) -> Vec<String> {
    client
        .send(Message::Text(request.to_owned().into()))
        .await
        .unwrap();
    let mut ids = Vec::new();
    loop {
        let response: Value = serde_json::from_str(&receive_text(client).await).unwrap();
        match response[0].as_str().unwrap() {
            "EVENT" => {
                assert_eq!(response[1], subscription_id);
                ids.push(response[2]["id"].as_str().unwrap().to_owned());
            }
            "EOSE" => {
                assert_eq!(response[1], subscription_id);
                return ids;
            }
            other => panic!("unexpected catalog response {other}"),
        }
    }
}

async fn expect_connection_failure(client: &mut TestClient) {
    let outcome = tokio::time::timeout(Duration::from_secs(5), client.next())
        .await
        .expect("connection did not fail closed");
    assert!(matches!(
        outcome,
        None | Some(Err(_)) | Some(Ok(Message::Close(_)))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_and_publisher_lanes_are_not_interchangeable() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([60; 32]).unwrap();
    let handle = start(test_config(
        directory.path().join("lanes.sqlite"),
        *publisher.public_key(),
    ))
    .await
    .unwrap();
    let now = now_unix().unwrap();
    let wrong_lane_sentinel = signed_entry(&publisher, [0x20; 32], 99, now - 2, now, 1);
    let event = signed_entry(&publisher, [0x21; 32], 1, now - 1, now, 2);

    let mut public_writer = connect_public(&handle).await;
    public_writer
        .send(Message::Text(
            String::from_utf8(wrong_lane_sentinel.to_event_message_json_bytes().unwrap())
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
    expect_connection_failure(&mut public_writer).await;

    let absence_subscription = "wrong-lane-absence";
    let absence_request = serde_json::to_string(&(
        "REQ",
        absence_subscription,
        IdFilter {
            ids: vec![hex::encode(wrong_lane_sentinel.id())],
        },
    ))
    .unwrap();
    let mut absence_reader = connect_public(&handle).await;
    assert!(
        receive_catalog(&mut absence_reader, &absence_request, absence_subscription,)
            .await
            .is_empty(),
        "public-lane EVENT must not be archived before its connection closes"
    );

    let mut publisher_reader = connect_publisher(&handle).await;
    publisher_reader
        .send(Message::Text(
            String::from_utf8(catalog_req_json_v1(publisher.public_key(), 0).unwrap())
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
    expect_connection_failure(&mut publisher_reader).await;

    let mut writer = connect_publisher(&handle).await;
    assert!(publish(&mut writer, &event).await.0);
    let mut reader = connect_public(&handle).await;
    let request =
        String::from_utf8(catalog_req_json_v1(publisher.public_key(), 2).unwrap()).unwrap();
    assert_eq!(
        receive_catalog(&mut reader, &request, "bitcoinpir-directory-v1-shard-2").await,
        vec![hex::encode(event.id())]
    );
    handle.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_profile_is_durable_paged_and_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let database = directory.path().join("relay.sqlite");
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([61; 32]).unwrap();
    let config = test_config(database.clone(), *publisher.public_key());
    let handle = start(config.clone()).await.unwrap();
    let now = now_unix().unwrap();
    let provider = [0x21; 32];
    let first = signed_entry(&publisher, provider, 1, now - 3, now, 1);
    let second = signed_entry(&publisher, provider, 2, now - 2, now, 2);
    let older = signed_entry(&publisher, provider, 1, now - 4, now, 3);

    let mut publisher_client = connect_publisher(&handle).await;
    assert!(publish(&mut publisher_client, &first).await.0);
    assert!(publish(&mut publisher_client, &second).await.0);
    let (accepted, reason) = publish(&mut publisher_client, &older).await;
    assert!(!accepted);
    assert!(reason.starts_with("replaced:"));
    let (accepted, reason) = publish(&mut publisher_client, &first).await;
    assert!(accepted);
    assert!(reason.starts_with("duplicate:"));

    let mut stored = vec![*first.id(), *second.id()];
    let mut expected_catalog = vec![hex::encode(second.id())];
    for offset in 0_u8..9 {
        let mut extra_provider = [0_u8; 32];
        extra_provider[0] = 0x22 + offset;
        extra_provider[31] = offset;
        let event = signed_entry(&publisher, extra_provider, 1, now - 1, now, 10 + offset);
        assert!(publish(&mut publisher_client, &event).await.0);
        stored.push(*event.id());
        expected_catalog.push(hex::encode(event.id()));
    }

    let catalog_request =
        String::from_utf8(catalog_req_json_v1(publisher.public_key(), 2).unwrap()).unwrap();
    let mut client = connect_public(&handle).await;
    let catalog = receive_catalog(
        &mut client,
        &catalog_request,
        "bitcoinpir-directory-v1-shard-2",
    )
    .await;
    assert_eq!(catalog, expected_catalog);

    client
        .send(Message::Text(catalog_request.clone().into()))
        .await
        .unwrap();
    let duplicate_subscription: Value =
        serde_json::from_str(&receive_text(&mut client).await).unwrap();
    assert_eq!(duplicate_subscription[0], "CLOSED");
    client
        .send(Message::Text(
            serde_json::to_string(&("CLOSE", "bitcoinpir-directory-v1-shard-2"))
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();

    stored.reverse();
    let mut requested = stored.clone();
    let mut requested_set = requested.iter().copied().collect::<BTreeSet<_>>();
    let mut next = 0u64;
    while requested.len() < MAX_READBACK_IDS {
        let mut id = [0xee; 32];
        id[24..].copy_from_slice(&next.to_be_bytes());
        next += 1;
        if requested_set.insert(id) {
            requested.push(id);
        }
    }
    let readback_request = serde_json::to_string(&(
        "REQ",
        "paged-readback",
        IdFilter {
            ids: requested.iter().map(hex::encode).collect(),
        },
    ))
    .unwrap();
    assert!(readback_request.len() < MAX_WIRE_MESSAGE_BYTES);
    let readback = receive_catalog(&mut client, &readback_request, "paged-readback").await;
    assert_eq!(
        readback,
        stored.iter().map(hex::encode).collect::<Vec<_>>(),
        "readback crosses the internal eight-event page and preserves request order"
    );

    // Simulate a committed EVENT whose positive OK is lost with the socket.
    let lost_ack_event = signed_entry(&publisher, [0x2f; 32], 1, now - 1, now, 31);
    let mut lost_ack_client = connect_publisher(&handle).await;
    lost_ack_client
        .send(Message::Text(
            String::from_utf8(lost_ack_event.to_event_message_json_bytes().unwrap())
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
    drop(lost_ack_client);
    let mut commit_probe = connect_public(&handle).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        for attempt in 0u64.. {
            let subscription_id = format!("commit-barrier-{attempt}");
            let request = serde_json::to_string(&(
                "REQ",
                &subscription_id,
                IdFilter {
                    ids: vec![hex::encode(lost_ack_event.id())],
                },
            ))
            .unwrap();
            let ids = receive_catalog(&mut commit_probe, &request, &subscription_id).await;
            if ids == [hex::encode(lost_ack_event.id())] {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("lost-ACK event never crossed the durable readback barrier");
    commit_probe.send(Message::Close(None)).await.unwrap();
    let mut retry_client = connect_publisher(&handle).await;
    let (accepted, reason) = publish(&mut retry_client, &lost_ack_event).await;
    assert!(accepted);
    assert!(reason.starts_with("duplicate:"));
    retry_client.send(Message::Close(None)).await.unwrap();

    client.send(Message::Close(None)).await.unwrap();
    drop(client);
    publisher_client.send(Message::Close(None)).await.unwrap();
    drop(publisher_client);
    handle.shutdown().await.unwrap();

    // A positive OK survived restart and all address heads are still deterministic.
    let restarted = start(config.clone()).await.unwrap();
    let mut after_restart = connect_public(&restarted).await;
    let catalog = receive_catalog(
        &mut after_restart,
        &catalog_request,
        "bitcoinpir-directory-v1-shard-2",
    )
    .await;
    let mut expected_after_restart = expected_catalog;
    expected_after_restart.push(hex::encode(lost_ack_event.id()));
    expected_after_restart.sort();
    let mut actual_sorted = catalog;
    actual_sorted.sort();
    assert_eq!(actual_sorted, expected_after_restart);
    after_restart.send(Message::Close(None)).await.unwrap();

    let mut malformed = connect_public(&restarted).await;
    malformed
        .send(Message::Text(
            r#"["REQ","bad",{"ids":[]}]"#.to_owned().into(),
        ))
        .await
        .unwrap();
    let response: Value = serde_json::from_str(&receive_text(&mut malformed).await).unwrap();
    assert_eq!(response[0], "CLOSED");
    malformed.send(Message::Close(None)).await.unwrap();

    let mut unknown = connect_public(&restarted).await;
    unknown
        .send(Message::Text(r#"["AUTH",{}]"#.to_owned().into()))
        .await
        .unwrap();
    expect_connection_failure(&mut unknown).await;

    let mut binary = connect_public(&restarted).await;
    binary
        .send(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    expect_connection_failure(&mut binary).await;

    let mut oversized = connect_public(&restarted).await;
    let oversized_message = format!(
        "[\"REQ\",\"oversized\",{{\"padding\":\"{}\"}}]",
        "x".repeat(MAX_WIRE_MESSAGE_BYTES)
    );
    assert!(oversized_message.len() > MAX_WIRE_MESSAGE_BYTES);
    if oversized
        .send(Message::Text(oversized_message.into()))
        .await
        .is_ok()
    {
        expect_connection_failure(&mut oversized).await;
    }

    let mut fragmented = connect_public(&restarted).await;
    fragmented
        .send(Message::Frame(Frame::message(
            vec![b'x'; MAX_WIRE_MESSAGE_BYTES / 2 + 1],
            OpCode::Data(FrameData::Text),
            false,
        )))
        .await
        .unwrap();
    if fragmented
        .send(Message::Frame(Frame::message(
            vec![b'x'; MAX_WIRE_MESSAGE_BYTES / 2 + 1],
            OpCode::Data(FrameData::Continue),
            true,
        )))
        .await
        .is_ok()
    {
        expect_connection_failure(&mut fragmented).await;
    }

    restarted.shutdown().await.unwrap();

    // The complete response is budgeted before its first EVENT. A cap that
    // cannot fit the catalog therefore closes without leaking a prefix.
    let mut low_budget_config = config;
    low_budget_config.max_egress_bytes_per_connection = 256;
    let low_budget = start(low_budget_config).await.unwrap();
    let mut capped = connect_public(&low_budget).await;
    capped
        .send(Message::Text(catalog_request.into()))
        .await
        .unwrap();
    expect_connection_failure(&mut capped).await;
    low_budget.shutdown().await.unwrap();
}

#[test]
fn legal_readback_wire_maximum_and_connection_budget_are_bounded() {
    assert_eq!(
        MAX_LEGAL_READBACK_EGRESS_BYTES,
        MAX_READBACK_IDS as u64 * MAX_OUTBOUND_EVENT_BYTES + MAX_WIRE_MESSAGE_BYTES as u64
    );
    let mut budget = ConnectionEgressBudget::new(10);
    assert!(budget.reserve(11).is_err());
    assert_eq!(budget.remaining, 10, "failed reservation is atomic");
    budget.reserve(10).unwrap();
    assert_eq!(budget.remaining, 0);

    let mut work = ConnectionWorkBudget::new(8);
    work.reserve(8).unwrap();
    assert_eq!(work.remaining, 0);
    assert!(work.reserve(1).is_err());
    assert_eq!(work.remaining, 0, "failed work reservation is atomic");

    assert_eq!(request_work_units(&RequestFilter::Ids(vec![[0; 32]; 1])), 1);
    assert_eq!(request_work_units(&RequestFilter::Ids(vec![[0; 32]; 8])), 1);
    assert_eq!(request_work_units(&RequestFilter::Ids(vec![[0; 32]; 9])), 2);
    assert_eq!(
        request_work_units(&RequestFilter::Ids(vec![[0; 32]; MAX_READBACK_IDS])),
        8,
    );

    let gate = RateGate::new(8);
    assert!(gate.admit(1));
    assert!(!gate.admit(8), "weighted admission must be atomic");
    assert!(gate.admit(7));
    assert!(!gate.admit(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limited_durable_duplicate_gets_no_negative_ack_and_retries_positive() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([62; 32]).unwrap();
    let mut config = test_config(
        directory.path().join("rate.sqlite"),
        *publisher.public_key(),
    );
    config.max_operations_per_second = 1;
    let handle = start(config).await.unwrap();
    let now = now_unix().unwrap();
    let event = signed_entry(&publisher, [0x31; 32], 1, now - 1, now, 1);

    let mut first = connect_publisher(&handle).await;
    assert!(publish(&mut first, &event).await.0);
    first.send(Message::Close(None)).await.unwrap();

    let wire = String::from_utf8(event.to_event_message_json_bytes().unwrap()).unwrap();
    let mut limited = connect_publisher(&handle).await;
    limited
        .send(Message::Text(wire.clone().into()))
        .await
        .unwrap();
    expect_connection_failure(&mut limited).await;

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut retry = connect_publisher(&handle).await;
            retry
                .send(Message::Text(wire.clone().into()))
                .await
                .unwrap();
            match tokio::time::timeout(Duration::from_secs(1), retry.next()).await {
                Ok(Some(Ok(Message::Text(response)))) => {
                    let response: Value = serde_json::from_str(response.as_str()).unwrap();
                    assert_eq!(response[0], "OK");
                    assert_eq!(
                        response[2], true,
                        "durable duplicate cannot become negative"
                    );
                    assert!(response[3].as_str().unwrap().starts_with("duplicate:"));
                    break;
                }
                Ok(None | Some(Err(_)) | Some(Ok(Message::Close(_)))) => {}
                Ok(Some(Ok(other))) => panic!("unexpected retry response: {other:?}"),
                Err(_) => panic!("rate-limited EVENT connection did not fail closed"),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("rate window never admitted an idempotent duplicate retry");
    handle.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn id_readback_rate_is_weighted_by_eight_id_pages() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([63; 32]).unwrap();

    let ids = (0u8..9)
        .map(|suffix| {
            let mut id = [0x42; 32];
            id[31] = suffix;
            hex::encode(id)
        })
        .collect::<Vec<_>>();
    let mut config = test_config(
        directory.path().join("weighted.sqlite"),
        *publisher.public_key(),
    );
    config.max_operations_per_second = 1;
    let handle = start(config).await.unwrap();
    let mut client = connect_public(&handle).await;
    let request =
        serde_json::to_string(&("REQ", "weighted-readback", IdFilter { ids: ids.clone() }))
            .unwrap();
    client.send(Message::Text(request.into())).await.unwrap();
    let response: Value = serde_json::from_str(&receive_text(&mut client).await).unwrap();
    assert_eq!(response[0], "CLOSED");
    assert_eq!(response[1], "weighted-readback");
    assert!(response[2].as_str().unwrap().starts_with("rate-limited:"));
    handle.shutdown().await.unwrap();

    let mut config = test_config(
        directory.path().join("one-unit.sqlite"),
        *publisher.public_key(),
    );
    config.max_operations_per_second = 1;
    let handle = start(config).await.unwrap();
    let mut client = connect_public(&handle).await;
    let request = serde_json::to_string(&(
        "REQ",
        "one-unit-readback",
        IdFilter {
            ids: ids[..8].to_vec(),
        },
    ))
    .unwrap();
    let response = receive_catalog(&mut client, &request, "one-unit-readback").await;
    assert!(response.is_empty());
    handle.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_equal_timestamp_replacement_and_shutdown_are_deterministic() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([63; 32]).unwrap();
    let config = test_config(
        directory.path().join("concurrent.sqlite"),
        *publisher.public_key(),
    );
    let handle = start(config).await.unwrap();
    let now = now_unix().unwrap();
    let events = (1u8..=8)
        .map(|randomness| {
            signed_entry(
                &publisher,
                [0x71; 32],
                u64::from(randomness),
                now - 1,
                now,
                randomness,
            )
        })
        .collect::<Vec<_>>();
    let unique_ids = events
        .iter()
        .map(|event| *event.id())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique_ids.len(), events.len());
    let expected = events.iter().map(|event| *event.id()).min().unwrap();

    let mut clients = Vec::new();
    for _ in &events {
        clients.push(connect_publisher(&handle).await);
    }
    let tasks = clients
        .into_iter()
        .zip(events)
        .map(|(mut client, event)| {
            tokio::spawn(async move {
                let outcome = publish(&mut client, &event).await;
                let _ = client.send(Message::Close(None)).await;
                outcome
            })
        })
        .collect::<Vec<_>>();
    for task in tasks {
        let _ = task.await.unwrap();
    }

    let request =
        String::from_utf8(catalog_req_json_v1(publisher.public_key(), 7).unwrap()).unwrap();
    let mut reader = connect_public(&handle).await;
    assert_eq!(
        receive_catalog(&mut reader, &request, "bitcoinpir-directory-v1-shard-7").await,
        vec![hex::encode(expected)]
    );

    tokio::time::timeout(Duration::from_secs(2), handle.shutdown())
        .await
        .expect("shutdown did not drain an idle open connection")
        .unwrap();
    expect_connection_failure(&mut reader).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absolute_connection_timeout_closes_idle_socket() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([64; 32]).unwrap();
    let mut config = test_config(
        directory.path().join("timeout.sqlite"),
        *publisher.public_key(),
    );
    config.connection_timeout = Duration::from_millis(50);
    let handle = start(config).await.unwrap();
    let mut client = connect_public(&handle).await;
    expect_connection_failure(&mut client).await;
    handle.shutdown().await.unwrap();
}

fn signed_announcement(now: u64, seed: u8) -> NostrEventV1 {
    use pir_directory_nostr::{
        DirectoryAccessClassV1, DirectoryAttestationV1, DirectoryBackendV1, DirectoryCatalogHintV1,
        DirectoryEndpointV1, DirectoryOperatorAssertionV1, DirectoryServerRoleV1,
        DirectoryTransportV1, NodeAnnouncementV1,
    };
    let assertion = DirectoryOperatorAssertionV1::sign(
        format!("home-{seed}"),
        1,
        now - 10,
        now + 86_400,
        vec![DirectoryEndpointV1 {
            transport: DirectoryTransportV1::Wss,
            url: "wss://pir.home.example".to_owned(),
        }],
        &ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
    )
    .unwrap();
    let hints = vec![DirectoryCatalogHintV1 {
        backend: DirectoryBackendV1::Dpf,
        role: DirectoryServerRoleV1::Secondary,
        access: DirectoryAccessClassV1::Free,
        attestation: DirectoryAttestationV1::None,
    }];
    let announcement = NodeAnnouncementV1::new(assertion, hints, now).unwrap();
    DirectoryPublisherKeyV1::from_secret_bytes([seed; 32])
        .unwrap()
        .sign_node_announcement_event(&announcement, now, &[seed; 32])
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anyone_announces_on_the_public_lane_and_reads_announcements_back() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([61; 32]).unwrap();
    let handle = start(test_config(
        directory.path().join("announce.sqlite"),
        *publisher.public_key(),
    ))
    .await
    .unwrap();
    let now = now_unix().unwrap();
    let first = signed_announcement(now, 5);
    let second = signed_announcement(now, 6);

    let mut announcer = connect_public(&handle).await;
    assert_eq!(
        publish(&mut announcer, &first).await,
        (true, "saved: announcement held".to_owned())
    );
    assert!(publish(&mut announcer, &first).await.0);
    assert!(publish(&mut announcer, &second).await.0);

    let request =
        String::from_utf8(pir_directory_nostr::node_announcements_req_json_v1().unwrap()).unwrap();
    let mut ids = receive_catalog(
        &mut announcer,
        &request,
        pir_directory_nostr::NODE_ANNOUNCEMENT_REQ_SUBSCRIPTION_V1,
    )
    .await;
    ids.sort();
    let mut expected = vec![hex::encode(first.id()), hex::encode(second.id())];
    expected.sort();
    assert_eq!(ids, expected);

    // Announcements are not directory events: the publisher lane refuses them.
    let mut publisher_writer = connect_publisher(&handle).await;
    publisher_writer
        .send(Message::Text(
            String::from_utf8(first.to_event_message_json_bytes().unwrap())
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
    expect_connection_failure(&mut publisher_writer).await;
    handle.shutdown().await.unwrap();
}
