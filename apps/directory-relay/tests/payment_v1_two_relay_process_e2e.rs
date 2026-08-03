//! Local process-topology coverage for two BitcoinPIR directory relays.
//!
//! This test launches two copies of the repository's production
//! `bitcoinpir-directory-relay` binary and proves process, listener,
//! configuration, and SQLite separation on one CI host. It does not prove
//! different operators, networks, machines, or administrative trust domains.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use pir_directory_nostr::{
    full_catalog_req_json_v1, verify_directory_checkpoint_event_v1,
    verify_directory_entry_event_v1, DirectoryCatalogCheckpointV1, DirectoryCheckpointEntryV1,
    DirectoryEntryV1, DirectoryHealthClassV1, DirectoryHealthV1, DirectoryPublisherKeyV1,
    NostrEventV1, DIRECTORY_SHARD_COUNT_V1,
};
use serde_json::Value;
use tokio::net::TcpStream as TokioTcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

const START_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

type RelayClient = WebSocketStream<MaybeTlsStream<TokioTcpStream>>;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ShardHead {
    entry_event_id: [u8; 32],
    directory_sequence: u64,
    checkpoint_event_id: [u8; 32],
    checkpoint_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogSnapshot(Vec<ShardHead>);

#[derive(Debug, Eq, PartialEq)]
enum DualRelayReadError {
    Relay0(String),
    Relay1(String),
    SplitView,
}

struct RelayMaterial {
    label: &'static str,
    public_port: u16,
    publisher_port: u16,
    config: PathBuf,
    database: PathBuf,
}

struct RelayProcess {
    label: &'static str,
    child: Option<Child>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl RelayProcess {
    fn spawn(root: &Path, material: &RelayMaterial, generation: u8) -> Self {
        let stdout_path = root.join(format!(
            "{}-generation-{generation}-stdout.log",
            material.label
        ));
        let stderr_path = root.join(format!(
            "{}-generation-{generation}-stderr.log",
            material.label
        ));
        let stdout = File::create(&stdout_path).expect("create relay stdout log");
        let stderr = File::create(&stderr_path).expect("create relay stderr log");
        let child = Command::new(env!("CARGO_BIN_EXE_bitcoinpir-directory-relay"))
            .args([
                "--config",
                material.config.to_str().expect("UTF-8 relay config path"),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn directory relay process");
        let mut process = Self {
            label: material.label,
            child: Some(child),
            stdout_path,
            stderr_path,
        };
        process.wait_until_listening(material.public_port);
        process.wait_until_listening(material.publisher_port);
        process
    }

    fn id(&self) -> u32 {
        self.child.as_ref().expect("relay process is running").id()
    }

    fn wait_until_listening(&mut self, port: u16) {
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            let child = self.child.as_mut().expect("relay process is running");
            if let Some(status) = child.try_wait().expect("poll relay process") {
                panic!(
                    "{} exited before listening ({status})\nstdout:\n{}\nstderr:\n{}",
                    self.label,
                    read_log(&self.stdout_path),
                    read_log(&self.stderr_path),
                );
            }
            if TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}")
                    .parse()
                    .expect("loopback address"),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {}\nstdout:\n{}\nstderr:\n{}",
                self.label,
                read_log(&self.stdout_path),
                read_log(&self.stderr_path),
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        self.stop();
        if thread::panicking() {
            eprintln!(
                "{} logs after test failure\nstdout:\n{}\nstderr:\n{}",
                self.label,
                read_log(&self.stdout_path),
                read_log(&self.stderr_path),
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run explicitly by payment-platform CI/full local acceptance"]
async fn two_relay_real_process_catalog_e2e() {
    let root = tempfile::tempdir().expect("two-relay process test root");
    chmod(root.path(), 0o700);
    let publisher = DirectoryPublisherKeyV1::from_secret_bytes([0x61; 32])
        .expect("deterministic test directory key");
    let now = unix_now();
    let relay0_public_port = distinct_unused_port(&[]);
    let relay0_publisher_port = distinct_unused_port(&[relay0_public_port]);
    let relay1_public_port = distinct_unused_port(&[relay0_public_port, relay0_publisher_port]);
    let relay1_publisher_port = distinct_unused_port(&[
        relay0_public_port,
        relay0_publisher_port,
        relay1_public_port,
    ]);
    let relay0 = prepare_relay(
        root.path(),
        "relay0",
        relay0_public_port,
        relay0_publisher_port,
        publisher.public_key(),
    );
    let relay1 = prepare_relay(
        root.path(),
        "relay1",
        relay1_public_port,
        relay1_publisher_port,
        publisher.public_key(),
    );
    assert_ne!(relay0.config, relay1.config);
    assert_ne!(relay0.database, relay1.database);
    assert_eq!(
        BTreeSet::from([
            relay0.public_port,
            relay0.publisher_port,
            relay1.public_port,
            relay1.publisher_port,
        ])
        .len(),
        4,
        "both relays require distinct public and publisher listeners"
    );

    let mut process0 = RelayProcess::spawn(root.path(), &relay0, 0);
    let mut process1 = RelayProcess::spawn(root.path(), &relay1, 0);
    assert_ne!(process0.id(), process1.id());
    assert_ne!(
        fs::metadata(&relay0.database)
            .expect("relay0 database")
            .ino(),
        fs::metadata(&relay1.database)
            .expect("relay1 database")
            .ino(),
        "the two relay processes must not alias one SQLite file"
    );

    let initial = signed_catalog(&publisher, now, now.saturating_sub(2), 1, 1);
    let wrong_lane_sentinel =
        signed_shard(&publisher, now, now.saturating_sub(3), 0, 99, 99, 0xe0)[0].clone();

    // The two sockets are protocol lanes, not interchangeable aliases. Wrong-
    // lane messages close without an acknowledgement so a public EVENT cannot
    // create either an acknowledgement or an archived record, and a publisher
    // connection cannot be repurposed as a read channel. The sentinel is not
    // reused by a later valid publish, so exact-ID absence proves rejection did
    // not silently commit before closing the connection.
    assert_wrong_lane_rejected(
        relay0.public_port,
        event_message_text(&wrong_lane_sentinel),
        "EVENT on public relay lane",
    )
    .await;
    assert_event_id_absent(relay0.public_port, wrong_lane_sentinel.id()).await;
    assert_wrong_lane_rejected(
        relay0.publisher_port,
        serde_json::json!([
            "REQ",
            "wrong-lane-read",
            {"ids": [hex::encode(initial[0].id())]}
        ])
        .to_string(),
        "REQ on publisher relay lane",
    )
    .await;

    // Relay 0 durably commits the first event, but the socket carrying its OK
    // disappears. ID readback is the commit barrier; retrying the same signed
    // event must be accepted as an idempotent duplicate.
    publish_without_reading_ack(relay0.publisher_port, &initial[0]).await;
    wait_for_event_id(relay0.public_port, initial[0].id()).await;
    let (accepted, reason) = publish(relay0.publisher_port, &initial[0]).await;
    assert!(accepted);
    assert!(
        reason.starts_with("duplicate:"),
        "unexpected retry reason: {reason}"
    );

    publish_many(relay0.publisher_port, &initial[1..]).await;
    publish_many(relay1.publisher_port, &initial).await;
    let baseline = read_consistent_catalog(
        relay0.public_port,
        relay1.public_port,
        publisher.public_key(),
        now,
    )
    .await
    .expect("identical complete catalog");
    assert_eq!(baseline.0.len(), usize::from(DIRECTORY_SHARD_COUNT_V1));

    // A newer shard-0 head on only one relay is a split view. The client must
    // reject the pair and must never merge the newer entry with the older
    // checkpoint (or vice versa).
    let shard0_update = signed_shard(&publisher, now, now.saturating_sub(1), 0, 2, 2, 0xb0);
    publish_many(relay0.publisher_port, &shard0_update).await;
    let relay0_split_head = read_catalog(relay0.public_port, publisher.public_key(), now)
        .await
        .expect("relay0 split-view head remains independently valid");
    let relay1_split_head = read_catalog(relay1.public_port, publisher.public_key(), now)
        .await
        .expect("relay1 split-view head remains independently valid");
    assert_ne!(
        relay0_split_head, relay1_split_head,
        "the two independently verified catalog heads must conflict"
    );
    assert_eq!(
        read_consistent_catalog(
            relay0.public_port,
            relay1.public_port,
            publisher.public_key(),
            now,
        )
        .await,
        Err(DualRelayReadError::SplitView),
        "stale relay head must fail closed with the exact split-view error"
    );
    publish_many(relay1.publisher_port, &shard0_update).await;
    let converged = read_consistent_catalog(
        relay0.public_port,
        relay1.public_port,
        publisher.public_key(),
        now,
    )
    .await
    .expect("relays converge after the same signed update");
    assert_ne!(converged, baseline);
    assert_eq!(converged.0[0].directory_sequence, 2);
    assert_eq!(converged.0[0].checkpoint_epoch, 2);

    // One offline relay is not silently replaced by the other relay's view.
    process1.stop();
    read_catalog(relay0.public_port, publisher.public_key(), now)
        .await
        .expect("relay0 remains independently readable");
    let offline_error = read_consistent_catalog(
        relay0.public_port,
        relay1.public_port,
        publisher.public_key(),
        now,
    )
    .await
    .expect_err("dual-relay policy must fail closed while one relay is offline");
    assert!(
        matches!(
            offline_error,
            DualRelayReadError::Relay1(reason)
                if reason.starts_with(&format!(
                    "connect relay {} failed:",
                    relay1.public_port
                ))
        ),
        "offline relay1 must be attributed to the relay1 transport boundary"
    );

    process1 = RelayProcess::spawn(root.path(), &relay1, 1);
    assert_eq!(
        read_consistent_catalog(
            relay0.public_port,
            relay1.public_port,
            publisher.public_key(),
            now,
        )
        .await
        .expect("relay1 durable restart restores the catalog"),
        converged
    );

    process0.stop();
    process0 = RelayProcess::spawn(root.path(), &relay0, 1);
    assert_ne!(process0.id(), process1.id());
    assert_eq!(
        read_consistent_catalog(
            relay0.public_port,
            relay1.public_port,
            publisher.public_key(),
            now,
        )
        .await
        .expect("both durable stores survive independent process restart"),
        converged
    );
}

fn prepare_relay(
    root: &Path,
    label: &'static str,
    public_port: u16,
    publisher_port: u16,
    directory_pubkey: &[u8; 32],
) -> RelayMaterial {
    let directory = root.join(label);
    fs::create_dir(&directory).expect("create relay domain directory");
    chmod(&directory, 0o700);
    let config = directory.join("relay.toml");
    let database = directory.join("relay.sqlite3");
    let text = format!(
        r#"profile = "bitcoinpir-directory-relay-v1"
public_listen = "127.0.0.1:{public_port}"
publisher_listen = "127.0.0.1:{publisher_port}"
database = "{}"
directory_pubkey_hex = "{}"
max_connections = 32
max_public_connections = 24
max_publisher_connections = 8
max_in_flight_operations = 4
max_public_in_flight_operations = 3
max_publisher_in_flight_operations = 1
max_operations_per_second = 1000000
max_public_operations_per_second = 750000
max_publisher_operations_per_second = 250000
max_egress_bytes_per_second = 1073741824
max_public_egress_bytes_per_second = 805306368
max_publisher_egress_bytes_per_second = 268435456
max_egress_bytes_per_connection = 67108864
max_archive_events = 20000
max_archive_bytes = 67108864
handshake_timeout_seconds = 5
idle_timeout_seconds = 10
connection_timeout_seconds = 60
operation_timeout_seconds = 10
egress_timeout_seconds = 10
"#,
        database.display(),
        hex::encode(directory_pubkey),
    );
    fs::write(&config, text).expect("write relay config");
    chmod(&config, 0o600);
    RelayMaterial {
        label,
        public_port,
        publisher_port,
        config,
        database,
    }
}

fn signed_catalog(
    publisher: &DirectoryPublisherKeyV1,
    now: u64,
    created_at: u64,
    sequence: u64,
    checkpoint_epoch: u64,
) -> Vec<NostrEventV1> {
    let mut events = Vec::with_capacity(usize::from(DIRECTORY_SHARD_COUNT_V1) * 2);
    for shard in 0..DIRECTORY_SHARD_COUNT_V1 {
        events.extend(signed_shard(
            publisher,
            now,
            created_at,
            shard,
            sequence,
            checkpoint_epoch,
            shard,
        ));
    }
    events
}

fn signed_shard(
    publisher: &DirectoryPublisherKeyV1,
    now: u64,
    created_at: u64,
    shard: u8,
    sequence: u64,
    checkpoint_epoch: u64,
    randomness: u8,
) -> [NostrEventV1; 2] {
    let mut provider_id = [0x41; 32];
    provider_id[0] = (shard << 4) | 1;
    provider_id[31] = shard.saturating_add(1);
    let entry = DirectoryEntryV1::new_tombstone(
        provider_id,
        sequence,
        now + 3_600,
        DirectoryHealthV1 {
            class: DirectoryHealthClassV1::Unknown,
            observed_bucket: now - (now % 300),
        },
        now,
    )
    .expect("valid directory tombstone");
    let entry_event = publisher
        .sign_entry_event(&entry, created_at, &[randomness.wrapping_add(1); 32])
        .expect("sign directory entry");
    let checkpoint = DirectoryCatalogCheckpointV1::new(
        shard,
        checkpoint_epoch,
        created_at,
        now + 3_600,
        vec![DirectoryCheckpointEntryV1 {
            provider_id,
            directory_sequence: sequence,
            event_id: *entry_event.id(),
        }],
        now,
    )
    .expect("valid directory checkpoint");
    let checkpoint_event = publisher
        .sign_checkpoint_event(
            &checkpoint,
            created_at,
            &[randomness.wrapping_add(0x41); 32],
        )
        .expect("sign directory checkpoint");
    [entry_event, checkpoint_event]
}

async fn relay_client(port: u16) -> Result<RelayClient, String> {
    connect_async(format!("ws://127.0.0.1:{port}"))
        .await
        .map(|(client, _)| client)
        .map_err(|error| format!("connect relay {port} failed: {error}"))
}

async fn receive_text(client: &mut RelayClient) -> Result<String, String> {
    let message = tokio::time::timeout(IO_TIMEOUT, client.next())
        .await
        .map_err(|_| "relay response timeout".to_owned())?
        .ok_or_else(|| "relay closed before response".to_owned())?
        .map_err(|error| format!("relay WebSocket response failed: {error}"))?;
    match message {
        Message::Text(text) => Ok(text.to_string()),
        other => Err(format!("unexpected relay message: {other:?}")),
    }
}

fn event_message_text(event: &NostrEventV1) -> String {
    String::from_utf8(
        event
            .to_event_message_json_bytes()
            .expect("publish envelope"),
    )
    .expect("UTF-8 publish envelope")
}

async fn assert_wrong_lane_rejected(port: u16, message: String, label: &str) {
    let mut client = relay_client(port)
        .await
        .unwrap_or_else(|error| panic!("connect {label} client failed: {error}"));
    client
        .send(Message::Text(message.into()))
        .await
        .unwrap_or_else(|error| panic!("send {label} message failed: {error}"));
    let observed = tokio::time::timeout(IO_TIMEOUT, client.next())
        .await
        .unwrap_or_else(|_| panic!("{label} was not rejected before the I/O timeout"));
    match observed {
        None | Some(Err(_)) | Some(Ok(Message::Close(_))) => {}
        Some(Ok(other)) => panic!("{label} produced an application response: {other:?}"),
    }
}

async fn publish(port: u16, event: &NostrEventV1) -> (bool, String) {
    let mut client = relay_client(port).await.expect("connect publish client");
    client
        .send(Message::Text(event_message_text(event).into()))
        .await
        .expect("send event");
    let response: Value = serde_json::from_str(
        &receive_text(&mut client)
            .await
            .expect("receive publish acknowledgement"),
    )
    .expect("parse publish acknowledgement");
    assert_eq!(response[0], "OK");
    assert_eq!(response[1], hex::encode(event.id()));
    let _ = client.send(Message::Close(None)).await;
    (
        response[2].as_bool().expect("OK acceptance flag"),
        response[3].as_str().expect("OK reason").to_owned(),
    )
}

async fn publish_many(port: u16, events: &[NostrEventV1]) {
    for event in events {
        let (accepted, reason) = publish(port, event).await;
        assert!(accepted, "relay {port} rejected event: {reason}");
    }
}

async fn publish_without_reading_ack(port: u16, event: &NostrEventV1) {
    let mut client = relay_client(port).await.expect("connect lost-ACK client");
    client
        .send(Message::Text(event_message_text(event).into()))
        .await
        .expect("send event before losing ACK");
    drop(client);
}

async fn wait_for_event_id(port: u16, event_id: &[u8; 32]) {
    let committed = tokio::time::timeout(Duration::from_secs(10), async {
        for attempt in 0u64..40 {
            let mut client = relay_client(port).await.expect("connect readback probe");
            let subscription = format!("lost-ack-readback-{attempt}");
            let request = serde_json::json!([
                "REQ",
                subscription,
                {"ids": [hex::encode(event_id)]}
            ]);
            client
                .send(Message::Text(request.to_string().into()))
                .await
                .expect("send readback probe");
            let mut found = false;
            loop {
                let response: Value = serde_json::from_str(
                    &receive_text(&mut client)
                        .await
                        .expect("receive readback probe"),
                )
                .expect("parse readback response");
                match response[0].as_str().expect("readback response kind") {
                    "EVENT" => {
                        found |= response[2]["id"] == hex::encode(event_id);
                    }
                    "EOSE" => break,
                    other => panic!("unexpected readback response: {other}"),
                }
            }
            let _ = client.send(Message::Close(None)).await;
            if found {
                return true;
            }
            let backoff_ms = 25 + attempt.min(15) * 10;
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        }
        false
    })
    .await
    .expect("lost-ACK event never crossed the durable readback barrier");
    assert!(
        committed,
        "lost-ACK event was not readable after 40 bounded probes"
    );
}

async fn assert_event_id_absent(port: u16, event_id: &[u8; 32]) {
    let mut client = relay_client(port)
        .await
        .expect("connect wrong-lane absence probe");
    let subscription = "wrong-lane-absence";
    let request = serde_json::json!([
        "REQ",
        subscription,
        {"ids": [hex::encode(event_id)]}
    ]);
    client
        .send(Message::Text(request.to_string().into()))
        .await
        .expect("send wrong-lane absence probe");
    let response: Value = serde_json::from_str(
        &receive_text(&mut client)
            .await
            .expect("receive wrong-lane absence probe"),
    )
    .expect("parse wrong-lane absence response");
    match response[0]
        .as_str()
        .expect("wrong-lane absence response kind")
    {
        "EVENT" => panic!(
            "public-lane EVENT was silently persisted: {}",
            hex::encode(event_id)
        ),
        "EOSE" => assert_eq!(response[1], subscription, "absence EOSE subscription"),
        other => panic!("unexpected wrong-lane absence response: {other}"),
    }
    let _ = client.send(Message::Close(None)).await;
}

async fn read_consistent_catalog(
    relay0_port: u16,
    relay1_port: u16,
    directory_pubkey: &[u8; 32],
    now: u64,
) -> Result<CatalogSnapshot, DualRelayReadError> {
    let (left, right) = tokio::join!(
        read_catalog(relay0_port, directory_pubkey, now),
        read_catalog(relay1_port, directory_pubkey, now),
    );
    let left = left.map_err(DualRelayReadError::Relay0)?;
    let right = right.map_err(DualRelayReadError::Relay1)?;
    if left != right {
        return Err(DualRelayReadError::SplitView);
    }
    Ok(left)
}

async fn read_catalog(
    port: u16,
    directory_pubkey: &[u8; 32],
    now: u64,
) -> Result<CatalogSnapshot, String> {
    let mut client = relay_client(port).await?;
    let requests = full_catalog_req_json_v1(directory_pubkey)
        .map_err(|error| format!("build catalog requests failed: {error}"))?;
    let mut heads = Vec::with_capacity(usize::from(DIRECTORY_SHARD_COUNT_V1));
    for (shard, request) in requests.into_iter().enumerate() {
        let request_text = String::from_utf8(request)
            .map_err(|error| format!("generated catalog request is not UTF-8: {error}"))?;
        let parsed_request: Value = serde_json::from_str(&request_text)
            .map_err(|error| format!("parse generated catalog request failed: {error}"))?;
        let subscription = parsed_request[1]
            .as_str()
            .ok_or_else(|| "generated request has no subscription".to_owned())?
            .to_owned();
        client
            .send(Message::Text(request_text.into()))
            .await
            .map_err(|error| format!("send catalog request failed: {error}"))?;
        let mut entry = None;
        let mut checkpoint = None;
        loop {
            let response: Value = serde_json::from_str(&receive_text(&mut client).await?)
                .map_err(|error| format!("parse catalog response failed: {error}"))?;
            match response[0]
                .as_str()
                .ok_or_else(|| "catalog response has no kind".to_owned())?
            {
                "EVENT" => {
                    if response[1] != subscription {
                        return Err("catalog subscription mismatch".to_owned());
                    }
                    let event_json = serde_json::to_vec(&response[2])
                        .map_err(|error| format!("serialize returned event failed: {error}"))?;
                    if let Ok(verified) =
                        verify_directory_entry_event_v1(&event_json, directory_pubkey, now)
                    {
                        if usize::from(verified.shard()) != shard || entry.is_some() {
                            return Err("catalog entry head is ambiguous".to_owned());
                        }
                        entry = Some((
                            *verified.discovery_entry().provider_id(),
                            *verified.event().id(),
                            verified.discovery_entry().directory_sequence(),
                        ));
                    } else {
                        let verified = verify_directory_checkpoint_event_v1(
                            &event_json,
                            directory_pubkey,
                            now,
                        )
                        .map_err(|error| format!("invalid returned catalog event: {error}"))?;
                        if usize::from(verified.checkpoint().shard()) != shard
                            || checkpoint.is_some()
                        {
                            return Err("catalog checkpoint head is ambiguous".to_owned());
                        }
                        checkpoint = Some((
                            *verified.event().id(),
                            verified.checkpoint().checkpoint_epoch(),
                            verified.checkpoint().entries().to_vec(),
                        ));
                    }
                }
                "EOSE" => {
                    if response[1] != subscription {
                        return Err("catalog EOSE subscription mismatch".to_owned());
                    }
                    break;
                }
                "CLOSED" => return Err("relay refused catalog snapshot".to_owned()),
                other => return Err(format!("unexpected catalog response: {other}")),
            }
        }
        let (provider_id, entry_event_id, directory_sequence) =
            entry.ok_or_else(|| format!("shard {shard} has no entry head"))?;
        let (checkpoint_event_id, checkpoint_epoch, checkpoint_entries) =
            checkpoint.ok_or_else(|| format!("shard {shard} has no checkpoint head"))?;
        if checkpoint_entries.as_slice()
            != [DirectoryCheckpointEntryV1 {
                provider_id,
                directory_sequence,
                event_id: entry_event_id,
            }]
        {
            return Err("catalog checkpoint does not bind the returned entry head".to_owned());
        }
        heads.push(ShardHead {
            entry_event_id,
            directory_sequence,
            checkpoint_event_id,
            checkpoint_epoch,
        });
    }
    let _ = client.send(Message::Close(None)).await;
    Ok(CatalogSnapshot(heads))
}

fn distinct_unused_port(excluded: &[u16]) -> u16 {
    loop {
        let port = TcpListener::bind("127.0.0.1:0")
            .expect("bind ephemeral port")
            .local_addr()
            .expect("ephemeral local address")
            .port();
        if !excluded.contains(&port) {
            return port;
        }
    }
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set private permissions");
}

fn read_log(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| format!("<read log failed: {error}>"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}
