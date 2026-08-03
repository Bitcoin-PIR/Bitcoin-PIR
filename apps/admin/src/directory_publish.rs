//! Strict NIP-01 transport for already-signed directory artifacts.
//!
//! The publisher never accepts a signing key and never reconstructs an EVENT
//! message. It verifies canonical artifacts against an explicit directory-key
//! pin, sends the exact input message bytes, and requires one positive NIP-01
//! `OK` for every event on every independently configured relay.

use std::collections::BTreeSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use clap::Args;
use futures_util::{SinkExt, StreamExt};
use pir_directory_nostr::{
    verify_directory_checkpoint_event_v1, verify_directory_entry_event_v1, NostrEventV1,
    DIRECTORY_SHARD_COUNT_V1,
};
use pir_service_protocol::is_canonical_public_wss_origin_v1;
use serde::Serialize;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::directory_artifact::{
    encode_json_array, parse_event_message, read_public_bounded, require_private_output_absent_v1,
    write_atomic_private_no_replace_v1, MAX_CHECKPOINT_BUNDLE_BYTES_V1, MAX_EVENT_MESSAGE_BYTES_V1,
};

const MIN_STRICT_RELAYS_V1: usize = 2;
const MAX_RELAYS_V1: usize = 8;
const MAX_PUBLISH_ARTIFACTS_V1: usize = 1_024;
const MAX_PUBLISH_EVENTS_V1: usize = 16 * 1_024;
const MAX_TOTAL_EVENT_BYTES_V1: usize = 64 * 1024 * 1024;
const MAX_RELAY_REPLY_MESSAGE_BYTES_V1: usize = 8 * 1024;
const MAX_TOTAL_RELAY_REPLY_BYTES_V1: usize = 8 * 1024 * 1024;
const DEFAULT_RELAY_TIMEOUT_SECONDS_V1: u64 = 60;
const MAX_RELAY_TIMEOUT_SECONDS_V1: u64 = 10 * 60;
const MAX_ARTIFACT_MANIFEST_BYTES_V1: usize = 256 * 1024;
const MAX_PUBLICATION_ARGV_ITEMS_V1: usize = 256;
const MAX_PUBLICATION_ARG_BYTES_V1: usize = 4 * 1024;
const PUBLICATION_RECEIPT_KIND_V1: &str = "bitcoinpir-directory-publication-receipt-v1";

#[derive(Args, Debug)]
pub struct DirectoryPublishArgs {
    /// Signed artifact: one canonical EVENT message or one exact 16-checkpoint array.
    #[arg(long = "artifact", required = true)]
    artifacts: Vec<PathBuf>,
    /// Strict sha256sum manifest that exactly binds every --artifact input.
    #[arg(long)]
    artifact_manifest: Option<PathBuf>,
    /// Distinct exact credential-free public wss origin (no path). Repeat 2..8 by default.
    #[arg(long = "relay", required = true)]
    relays: Vec<String>,
    /// Explicitly publish to exactly one centralized relay (degraded: no relay cross-check).
    #[arg(long)]
    centralized_single_relay: bool,
    /// Pinned x-only BIP340 directory publisher key (32-byte lowercase hex).
    #[arg(long)]
    directory_pubkey_hex: String,
    /// Explicit verification time for entry/checkpoint validity.
    #[arg(long)]
    now_unix: u64,
    /// Total connect, send and acknowledgement deadline for each relay.
    #[arg(long, default_value_t = DEFAULT_RELAY_TIMEOUT_SECONDS_V1)]
    relay_timeout_seconds: u64,
    /// Owner-only 0700 directory for immutable <INVOCATION_ID>.json publication receipts.
    #[arg(long)]
    receipt_directory: Option<PathBuf>,
    /// Validate the frozen artifacts, key pin and relay set without network I/O.
    #[arg(long)]
    validate_only: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelaySetModeV1 {
    StrictMultiRelay,
    CentralizedSingleRelay,
}

impl RelaySetModeV1 {
    const fn directory_mode(self) -> &'static str {
        match self {
            Self::StrictMultiRelay => "strict-multi-relay",
            Self::CentralizedSingleRelay => "centralized-single-relay",
        }
    }

    const fn assurance(self) -> &'static str {
        match self {
            Self::StrictMultiRelay => "multi-origin-split-view-capable",
            Self::CentralizedSingleRelay => "centralized-degraded-no-relay-cross-check",
        }
    }
}

#[derive(Clone)]
struct PublishEventV1 {
    exact_message: String,
    event_id: [u8; 32],
    signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PublicationFilePinV1 {
    path: String,
    sha256: String,
}

struct LoadedPublishInputsV1 {
    artifacts: Vec<PublicationFilePinV1>,
    events: Vec<PublishEventV1>,
}

struct ExactInvocationV1 {
    argv: Vec<String>,
    invocation_id: String,
}

#[derive(Serialize)]
struct PublicationReceiptV1 {
    artifact_manifest: PublicationFilePinV1,
    artifacts: Vec<PublicationFilePinV1>,
    argv: Vec<String>,
    argv_sha256: String,
    directory_mode: String,
    event_count: usize,
    event_set_digest_hex: String,
    invocation_id: String,
    kind: &'static str,
    outcome: &'static str,
    publisher_pubkey_hex: String,
    relay_origins: Vec<String>,
    schema_version: u8,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PublishArtifactKindV1 {
    Entry,
    Checkpoint { shard: u8, epoch: u64 },
}

struct CheckedPublishEventV1 {
    event: PublishEventV1,
    kind: PublishArtifactKindV1,
}

#[derive(Clone)]
struct RelayTargetV1 {
    url: String,
    host: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelayPublishFailureV1 {
    Transport,
    Timeout,
    RelayRejected,
    UnexpectedReply,
    DuplicateOk,
    MissingOk,
    NonTextReply,
    ReplyTooLarge,
}

impl RelayPublishFailureV1 {
    const fn code(self) -> &'static str {
        match self {
            Self::Transport => "transport-failed",
            Self::Timeout => "timeout",
            Self::RelayRejected => "relay-rejected",
            Self::UnexpectedReply => "unexpected-reply",
            Self::DuplicateOk => "duplicate-ok",
            Self::MissingOk => "missing-ok",
            Self::NonTextReply => "non-text-reply",
            Self::ReplyTooLarge => "reply-too-large",
        }
    }
}

struct RelayPublishOutcomeV1 {
    host: String,
    event_count: usize,
    event_set_digest: [u8; 32],
    result: Result<(), RelayPublishFailureV1>,
}

trait RelayPublisherV1 {
    fn publish<'a>(
        &'a mut self,
        target: &'a RelayTargetV1,
        events: &'a [PublishEventV1],
    ) -> Pin<Box<dyn Future<Output = Result<(), RelayPublishFailureV1>> + 'a>>;
}

struct NetworkRelayPublisherV1;

impl RelayPublisherV1 for NetworkRelayPublisherV1 {
    fn publish<'a>(
        &'a mut self,
        target: &'a RelayTargetV1,
        events: &'a [PublishEventV1],
    ) -> Pin<Box<dyn Future<Output = Result<(), RelayPublishFailureV1>> + 'a>> {
        Box::pin(async move {
            install_default_crypto_provider();
            let config = WebSocketConfig {
                max_message_size: Some(MAX_RELAY_REPLY_MESSAGE_BYTES_V1),
                max_frame_size: Some(MAX_RELAY_REPLY_MESSAGE_BYTES_V1),
                ..Default::default()
            };
            // This async connector performs one direct TCP+TLS handshake. It
            // does not consult proxy environment variables or follow HTTP
            // redirects. The URL grammar rejected credentials before dialing.
            let (mut websocket, _) = tokio_tungstenite::connect_async_with_config(
                target.url.as_str(),
                Some(config),
                true,
            )
            .await
            .map_err(|_| RelayPublishFailureV1::Transport)?;
            let result = publish_websocket_session_v1(&mut websocket, events).await;
            let _ = websocket.close(None).await;
            result
        })
    }
}

pub async fn run(args: DirectoryPublishArgs) -> Result<(), String> {
    let mut publisher = NetworkRelayPublisherV1;
    let invocation = if args.receipt_directory.is_some() || args.artifact_manifest.is_some() {
        Some(capture_exact_invocation_v1()?)
    } else {
        None
    };
    run_with_publisher_and_invocation_v1(args, &mut publisher, invocation).await
}

#[cfg(test)]
async fn run_with_publisher_v1<P: RelayPublisherV1>(
    args: DirectoryPublishArgs,
    publisher: &mut P,
) -> Result<(), String> {
    run_with_publisher_and_invocation_v1(args, publisher, None).await
}

async fn run_with_publisher_and_invocation_v1<P: RelayPublisherV1>(
    args: DirectoryPublishArgs,
    publisher: &mut P,
    invocation: Option<ExactInvocationV1>,
) -> Result<(), String> {
    if args.now_unix == 0 {
        return Err("--now-unix must be non-zero".to_owned());
    }
    if !(1..=MAX_RELAY_TIMEOUT_SECONDS_V1).contains(&args.relay_timeout_seconds) {
        return Err(format!(
            "--relay-timeout-seconds must be between 1 and {MAX_RELAY_TIMEOUT_SECONDS_V1}"
        ));
    }
    if args.artifact_manifest.is_some() != args.receipt_directory.is_some() {
        return Err(
            "--artifact-manifest and --receipt-directory must be supplied together".to_owned(),
        );
    }
    if args.validate_only && args.receipt_directory.is_some() {
        return Err("--receipt-directory is only valid for a real publication".to_owned());
    }
    if let Some(directory) = &args.receipt_directory {
        validate_canonical_absolute_path_v1(directory, "publication receipt directory")?;
    }
    let directory_pubkey =
        decode_lower_fixed_hex::<32>(&args.directory_pubkey_hex, "directory publisher public key")?;
    let loaded = load_publish_events_v1(&args.artifacts, &directory_pubkey, args.now_unix)?;
    let event_set_digest = event_set_digest_v1(&loaded.events)?;
    let relay_mode = if args.centralized_single_relay {
        RelaySetModeV1::CentralizedSingleRelay
    } else {
        RelaySetModeV1::StrictMultiRelay
    };
    let targets = validate_relay_targets_v1(args.relays.clone(), relay_mode)?;
    let manifest_pin = if let Some(path) = &args.artifact_manifest {
        Some(validate_artifact_manifest_v1(path, &loaded.artifacts)?)
    } else {
        None
    };
    if args.validate_only {
        emit_validation_outcomes_v1(&targets, loaded.events.len(), event_set_digest, relay_mode);
        return Ok(());
    }
    let receipt_output = match (&args.receipt_directory, invocation.as_ref()) {
        (Some(directory), Some(invocation)) => {
            let output = publication_receipt_path_v1(directory, &invocation.invocation_id)?;
            require_private_output_absent_v1(&output).map_err(|error| {
                format!(
                    "current systemd invocation receipt preflight failed before relay I/O: {error}"
                )
            })?;
            Some(output)
        }
        (Some(_), None) => {
            return Err(
                "publication receipt requires the exact process argv and systemd InvocationID"
                    .to_owned(),
            );
        }
        (None, _) => None,
    };
    let timeout = Duration::from_secs(args.relay_timeout_seconds);
    let outcomes = publish_all_relays_v1(
        publisher,
        &targets,
        &loaded.events,
        event_set_digest,
        timeout,
    )
    .await;
    let failures = emit_publish_outcomes_v1(&outcomes, relay_mode);
    if failures != 0 {
        return Err(format!(
            "publishing failed for {failures} of {} relays; exact artifacts may be rerun manually",
            outcomes.len()
        ));
    }
    if let (Some(output), Some(artifact_manifest), Some(invocation)) =
        (receipt_output.as_deref(), manifest_pin, invocation)
    {
        write_publication_receipt_v1(
            output,
            artifact_manifest,
            loaded.artifacts,
            invocation,
            &targets,
            relay_mode,
            &args.directory_pubkey_hex,
            loaded.events.len(),
            event_set_digest,
        )
        .map_err(|error| {
            format!(
                "all relays accepted the exact event set but immutable receipt creation failed; manual exact-artifact reconciliation/replay is required: {error}"
            )
        })?;
    } else if args.receipt_directory.is_some() {
        return Err(
            "publication receipt requires the exact process argv and systemd InvocationID"
                .to_owned(),
        );
    }
    Ok(())
}

fn publication_receipt_path_v1(directory: &Path, invocation_id: &str) -> Result<PathBuf, String> {
    validate_canonical_absolute_path_v1(directory, "publication receipt directory")?;
    if invocation_id.len() != 32
        || invocation_id == "0".repeat(32)
        || !invocation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("systemd INVOCATION_ID must be non-zero 32-byte lowercase hex".to_owned());
    }
    Ok(directory.join(format!("{invocation_id}.json")))
}

fn capture_exact_invocation_v1() -> Result<ExactInvocationV1, String> {
    let argv = std::env::args_os()
        .map(|value| {
            value
                .into_string()
                .map_err(|_| "publication argv must be valid UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_publication_argv_v1(&argv)?;
    let invocation_id = std::env::var("INVOCATION_ID")
        .map_err(|_| "receipt publication requires systemd INVOCATION_ID".to_owned())?;
    if invocation_id.len() != 32
        || invocation_id == "0".repeat(32)
        || !invocation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("systemd INVOCATION_ID must be non-zero 32-byte lowercase hex".to_owned());
    }
    Ok(ExactInvocationV1 {
        argv,
        invocation_id,
    })
}

fn validate_publication_argv_v1(argv: &[String]) -> Result<(), String> {
    if argv.is_empty() || argv.len() > MAX_PUBLICATION_ARGV_ITEMS_V1 {
        return Err(format!(
            "publication argv count must be between 1 and {MAX_PUBLICATION_ARGV_ITEMS_V1}"
        ));
    }
    if argv
        .iter()
        .any(|value| value.is_empty() || value.len() > MAX_PUBLICATION_ARG_BYTES_V1)
    {
        return Err(format!(
            "publication argv items must be non-empty and at most {MAX_PUBLICATION_ARG_BYTES_V1} bytes"
        ));
    }
    Ok(())
}

fn argv_sha256_v1(argv: &[String]) -> Result<String, String> {
    validate_publication_argv_v1(argv)?;
    let mut encoded = serde_json::to_vec(argv)
        .map_err(|error| format!("encode publication argv failed: {error}"))?;
    encoded.push(b'\n');
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoinpir-directory-publish-argv-v1\0");
    hasher.update(encoded);
    Ok(hex::encode(hasher.finalize()))
}

#[allow(clippy::too_many_arguments)]
fn write_publication_receipt_v1(
    output: &Path,
    artifact_manifest: PublicationFilePinV1,
    artifacts: Vec<PublicationFilePinV1>,
    invocation: ExactInvocationV1,
    targets: &[RelayTargetV1],
    relay_mode: RelaySetModeV1,
    publisher_pubkey_hex: &str,
    event_count: usize,
    event_set_digest: [u8; 32],
) -> Result<(), String> {
    let argv_sha256 = argv_sha256_v1(&invocation.argv)?;
    let receipt = PublicationReceiptV1 {
        artifact_manifest,
        artifacts,
        argv: invocation.argv,
        argv_sha256,
        directory_mode: relay_mode.directory_mode().to_owned(),
        event_count,
        event_set_digest_hex: hex::encode(event_set_digest),
        invocation_id: invocation.invocation_id,
        kind: PUBLICATION_RECEIPT_KIND_V1,
        outcome: "published",
        publisher_pubkey_hex: publisher_pubkey_hex.to_owned(),
        relay_origins: targets.iter().map(|target| target.url.clone()).collect(),
        schema_version: 1,
    };
    let mut bytes = serde_json::to_vec(&receipt)
        .map_err(|error| format!("encode publication receipt failed: {error}"))?;
    bytes.push(b'\n');
    write_atomic_private_no_replace_v1(output, &bytes)
}

fn emit_validation_outcomes_v1(
    targets: &[RelayTargetV1],
    event_count: usize,
    event_set_digest: [u8; 32],
    relay_mode: RelaySetModeV1,
) {
    for target in targets {
        println!(
            "relay_host={} event_count={} event_set_digest_hex={} directory_mode={} assurance={} result=validated",
            target.host,
            event_count,
            hex::encode(event_set_digest),
            relay_mode.directory_mode(),
            relay_mode.assurance(),
        );
    }
}

async fn publish_all_relays_v1<P: RelayPublisherV1>(
    publisher: &mut P,
    targets: &[RelayTargetV1],
    events: &[PublishEventV1],
    event_set_digest: [u8; 32],
    timeout: Duration,
) -> Vec<RelayPublishOutcomeV1> {
    let mut outcomes = Vec::with_capacity(targets.len());
    for target in targets {
        let result = match tokio::time::timeout(timeout, publisher.publish(target, events)).await {
            Ok(result) => result,
            Err(_) => Err(RelayPublishFailureV1::Timeout),
        };
        outcomes.push(RelayPublishOutcomeV1 {
            host: target.host.clone(),
            event_count: events.len(),
            event_set_digest,
            result,
        });
    }
    outcomes
}

fn emit_publish_outcomes_v1(
    outcomes: &[RelayPublishOutcomeV1],
    relay_mode: RelaySetModeV1,
) -> usize {
    let mut failures = 0usize;
    for outcome in outcomes {
        match outcome.result {
            Ok(()) => println!(
                "relay_host={} event_count={} event_set_digest_hex={} directory_mode={} assurance={} result=ok",
                outcome.host,
                outcome.event_count,
                hex::encode(outcome.event_set_digest),
                relay_mode.directory_mode(),
                relay_mode.assurance(),
            ),
            Err(error) => {
                failures += 1;
                eprintln!(
                    "relay_host={} event_count={} event_set_digest_hex={} directory_mode={} assurance={} result={}",
                    outcome.host,
                    outcome.event_count,
                    hex::encode(outcome.event_set_digest),
                    relay_mode.directory_mode(),
                    relay_mode.assurance(),
                    error.code()
                );
            }
        }
    }
    failures
}

fn event_set_digest_v1(events: &[PublishEventV1]) -> Result<[u8; 32], String> {
    let count = u32::try_from(events.len())
        .map_err(|_| "publish event count exceeds digest encoding".to_owned())?;
    let mut identities = events
        .iter()
        .map(|event| (event.event_id, event.signature))
        .collect::<Vec<_>>();
    identities.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoinpir-directory-event-set-v1\0");
    hasher.update(count.to_le_bytes());
    for (event_id, signature) in identities {
        hasher.update(event_id);
        hasher.update(signature);
    }
    Ok(hasher.finalize().into())
}

async fn publish_websocket_session_v1<S>(
    websocket: &mut WebSocketStream<S>,
    events: &[PublishEventV1],
) -> Result<(), RelayPublishFailureV1>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut confirmed = BTreeSet::new();
    let mut total_reply_bytes = 0usize;
    for event in events {
        websocket
            .send(Message::Text(event.exact_message.clone()))
            .await
            .map_err(|_| RelayPublishFailureV1::Transport)?;
        let message = match websocket.next().await {
            Some(Ok(message)) => message,
            Some(Err(_)) => return Err(RelayPublishFailureV1::Transport),
            None => return Err(RelayPublishFailureV1::MissingOk),
        };
        let message_len = match &message {
            Message::Text(value) => value.len(),
            Message::Binary(value) | Message::Ping(value) | Message::Pong(value) => value.len(),
            Message::Close(_) | Message::Frame(_) => 0,
        };
        total_reply_bytes = total_reply_bytes
            .checked_add(message_len)
            .ok_or(RelayPublishFailureV1::ReplyTooLarge)?;
        if message_len > MAX_RELAY_REPLY_MESSAGE_BYTES_V1
            || total_reply_bytes > MAX_TOTAL_RELAY_REPLY_BYTES_V1
        {
            return Err(RelayPublishFailureV1::ReplyTooLarge);
        }
        let Message::Text(text) = message else {
            return if matches!(message, Message::Close(_)) {
                Err(RelayPublishFailureV1::MissingOk)
            } else {
                Err(RelayPublishFailureV1::NonTextReply)
            };
        };
        let (acknowledged_id, accepted) = parse_strict_ok_v1(&text)?;
        if acknowledged_id != event.event_id {
            return if confirmed.contains(&acknowledged_id) {
                Err(RelayPublishFailureV1::DuplicateOk)
            } else {
                Err(RelayPublishFailureV1::UnexpectedReply)
            };
        }
        if !accepted {
            return Err(RelayPublishFailureV1::RelayRejected);
        }
        if !confirmed.insert(acknowledged_id) {
            return Err(RelayPublishFailureV1::DuplicateOk);
        }
    }
    Ok(())
}

fn parse_strict_ok_v1(text: &str) -> Result<([u8; 32], bool), RelayPublishFailureV1> {
    let values: Vec<Box<RawValue>> =
        serde_json::from_str(text).map_err(|_| RelayPublishFailureV1::UnexpectedReply)?;
    if values.len() != 4 {
        return Err(RelayPublishFailureV1::UnexpectedReply);
    }
    let verb: &str = serde_json::from_str(values[0].get())
        .map_err(|_| RelayPublishFailureV1::UnexpectedReply)?;
    if verb != "OK" {
        return Err(RelayPublishFailureV1::UnexpectedReply);
    }
    let id: &str = serde_json::from_str(values[1].get())
        .map_err(|_| RelayPublishFailureV1::UnexpectedReply)?;
    let accepted: bool = serde_json::from_str(values[2].get())
        .map_err(|_| RelayPublishFailureV1::UnexpectedReply)?;
    let _: &str = serde_json::from_str(values[3].get())
        .map_err(|_| RelayPublishFailureV1::UnexpectedReply)?;
    let id = decode_lower_fixed_hex::<32>(id, "relay OK event id")
        .map_err(|_| RelayPublishFailureV1::UnexpectedReply)?;
    Ok((id, accepted))
}

fn validate_canonical_absolute_path_v1(path: &Path, label: &str) -> Result<String, String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("{label} must be valid UTF-8"))?;
    if text.len() < 2
        || text.len() > MAX_PUBLICATION_ARG_BYTES_V1
        || !text.starts_with('/')
        || text.ends_with('/')
        || text.contains("//")
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        || text
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!("{label} must be one canonical ASCII absolute path"));
    }
    Ok(text.to_owned())
}

fn sha256_hex_v1(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn parse_artifact_manifest_v1(bytes: &[u8]) -> Result<Vec<PublicationFilePinV1>, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "artifact manifest must be valid UTF-8".to_owned())?;
    if text.is_empty() || !text.is_ascii() || !text.ends_with('\n') {
        return Err(
            "artifact manifest must be non-empty canonical ASCII ending in newline".to_owned(),
        );
    }
    let mut pins = Vec::new();
    for (index, line) in text[..text.len() - 1].split('\n').enumerate() {
        if line.len() < 68 || &line.as_bytes()[64..66] != b"  " {
            return Err(format!(
                "artifact manifest line {} is not strict sha256sum syntax",
                index + 1
            ));
        }
        let digest = &line[..64];
        if !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!(
                "artifact manifest line {} has a non-canonical SHA-256",
                index + 1
            ));
        }
        let path = validate_canonical_absolute_path_v1(
            Path::new(&line[66..]),
            &format!("artifact manifest line {} path", index + 1),
        )?;
        if pins.last().is_some_and(|previous: &PublicationFilePinV1| {
            previous.path.as_bytes() >= path.as_bytes()
        }) {
            return Err("artifact manifest paths must be unique and bytewise sorted".to_owned());
        }
        pins.push(PublicationFilePinV1 {
            path,
            sha256: digest.to_owned(),
        });
    }
    if pins.is_empty() || pins.len() > MAX_PUBLISH_ARTIFACTS_V1 {
        return Err(format!(
            "artifact manifest entry count must be between 1 and {MAX_PUBLISH_ARTIFACTS_V1}"
        ));
    }
    Ok(pins)
}

fn validate_artifact_manifest_v1(
    path: &Path,
    artifacts: &[PublicationFilePinV1],
) -> Result<PublicationFilePinV1, String> {
    let canonical_path = validate_canonical_absolute_path_v1(path, "artifact manifest path")?;
    let bytes = read_public_bounded(
        path,
        MAX_ARTIFACT_MANIFEST_BYTES_V1,
        "directory publish artifact manifest",
    )?;
    let manifest_artifacts = parse_artifact_manifest_v1(&bytes)?;
    if manifest_artifacts != artifacts {
        return Err(
            "artifact manifest does not exactly bind the sorted --artifact path/digest generation"
                .to_owned(),
        );
    }
    Ok(PublicationFilePinV1 {
        path: canonical_path,
        sha256: sha256_hex_v1(&bytes),
    })
}

fn load_publish_events_v1(
    artifacts: &[PathBuf],
    directory_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<LoadedPublishInputsV1, String> {
    if artifacts.is_empty() || artifacts.len() > MAX_PUBLISH_ARTIFACTS_V1 {
        return Err(format!(
            "--artifact count must be between 1 and {MAX_PUBLISH_ARTIFACTS_V1}"
        ));
    }
    let mut events = Vec::new();
    let mut artifact_pins = Vec::new();
    let mut seen_artifact_paths = BTreeSet::new();
    let mut seen_ids = BTreeSet::new();
    let mut total_bytes = 0usize;
    for path in artifacts {
        let canonical_path =
            validate_canonical_absolute_path_v1(path, "directory publish artifact path")?;
        if !seen_artifact_paths.insert(canonical_path.clone()) {
            return Err("duplicate --artifact path".to_owned());
        }
        let bytes = read_public_bounded(
            path,
            MAX_CHECKPOINT_BUNDLE_BYTES_V1,
            "directory publish artifact",
        )?;
        artifact_pins.push(PublicationFilePinV1 {
            path: canonical_path,
            sha256: sha256_hex_v1(&bytes),
        });
        let values: Vec<Box<RawValue>> = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid publish artifact {}: {error}", path.display()))?;
        let is_single_event = values.len() == 2 && values[0].get() == "\"EVENT\"";
        let checked = if is_single_event {
            vec![check_publish_event_message_v1(
                &bytes,
                directory_pubkey,
                now_unix,
            )?]
        } else {
            if values.len() != DIRECTORY_SHARD_COUNT_V1 as usize {
                return Err(format!(
                    "{} must be one EVENT or an exact 16-message checkpoint array",
                    path.display()
                ));
            }
            let item_bytes: Vec<Vec<u8>> = values
                .iter()
                .map(|value| value.get().as_bytes().to_vec())
                .collect();
            if encode_json_array(&item_bytes, MAX_CHECKPOINT_BUNDLE_BYTES_V1)? != bytes {
                return Err(format!(
                    "{} checkpoint array is not the canonical emitted artifact",
                    path.display()
                ));
            }
            let mut checked = Vec::with_capacity(DIRECTORY_SHARD_COUNT_V1 as usize);
            for message in &item_bytes {
                checked.push(check_publish_event_message_v1(
                    message,
                    directory_pubkey,
                    now_unix,
                )?);
            }
            validate_checkpoint_bundle_v1(&checked, path)?;
            checked
        };
        for checked_event in checked {
            total_bytes = total_bytes
                .checked_add(checked_event.event.exact_message.len())
                .ok_or_else(|| "publish event bytes overflow".to_owned())?;
            if total_bytes > MAX_TOTAL_EVENT_BYTES_V1 {
                return Err(format!(
                    "publish artifacts exceed the {MAX_TOTAL_EVENT_BYTES_V1}-byte total bound"
                ));
            }
            if !seen_ids.insert(checked_event.event.event_id) {
                return Err("duplicate event id across publish artifacts".to_owned());
            }
            events.push(checked_event.event);
            if events.len() > MAX_PUBLISH_EVENTS_V1 {
                return Err(format!(
                    "publish artifacts exceed the {MAX_PUBLISH_EVENTS_V1}-event bound"
                ));
            }
        }
    }
    artifact_pins.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    Ok(LoadedPublishInputsV1 {
        artifacts: artifact_pins,
        events,
    })
}

fn check_publish_event_message_v1(
    message: &[u8],
    directory_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<CheckedPublishEventV1, String> {
    if message.len() > MAX_EVENT_MESSAGE_BYTES_V1 {
        return Err("publish EVENT exceeds the message bound".to_owned());
    }
    let event_json = parse_event_message(message, "publish EVENT")?;
    let event = NostrEventV1::parse_json(&event_json)
        .map_err(|error| format!("publish EVENT parsing failed: {error}"))?;
    event
        .verify_for_directory_key(directory_pubkey)
        .map_err(|error| format!("publish EVENT signature/key verification failed: {error}"))?;
    if event
        .to_event_message_json_bytes()
        .map_err(|error| format!("publish EVENT canonical encoding failed: {error}"))?
        != message
    {
        return Err("publish EVENT is not the exact canonical signed artifact".to_owned());
    }
    let kind = match (
        verify_directory_entry_event_v1(&event_json, directory_pubkey, now_unix),
        verify_directory_checkpoint_event_v1(&event_json, directory_pubkey, now_unix),
    ) {
        (Ok(_), Err(_)) => PublishArtifactKindV1::Entry,
        (Err(_), Ok(verified)) => PublishArtifactKindV1::Checkpoint {
            shard: verified.checkpoint().shard(),
            epoch: verified.checkpoint().checkpoint_epoch(),
        },
        _ => {
            return Err(
                "publish EVENT is not one current BitcoinPIR entry or checkpoint".to_owned(),
            )
        }
    };
    let exact_message = String::from_utf8(message.to_vec())
        .map_err(|_| "publish EVENT must be UTF-8 JSON text".to_owned())?;
    Ok(CheckedPublishEventV1 {
        event: PublishEventV1 {
            exact_message,
            event_id: *event.id(),
            signature: *event.signature(),
        },
        kind,
    })
}

fn validate_checkpoint_bundle_v1(
    events: &[CheckedPublishEventV1],
    path: &std::path::Path,
) -> Result<(), String> {
    let mut shards = BTreeSet::new();
    let mut epoch = None;
    for event in events {
        let PublishArtifactKindV1::Checkpoint {
            shard,
            epoch: event_epoch,
        } = event.kind
        else {
            return Err(format!(
                "{} 16-message array contains a non-checkpoint EVENT",
                path.display()
            ));
        };
        if !shards.insert(shard) || epoch.is_some_and(|value| value != event_epoch) {
            return Err(format!(
                "{} checkpoint array has duplicate shards or mixed epochs",
                path.display()
            ));
        }
        epoch = Some(event_epoch);
    }
    if shards.len() != DIRECTORY_SHARD_COUNT_V1 as usize
        || !shards.iter().copied().eq(0..DIRECTORY_SHARD_COUNT_V1)
    {
        return Err(format!(
            "{} checkpoint array must contain every shard exactly once",
            path.display()
        ));
    }
    Ok(())
}

fn validate_relay_targets_v1(
    relays: Vec<String>,
    relay_mode: RelaySetModeV1,
) -> Result<Vec<RelayTargetV1>, String> {
    match relay_mode {
        RelaySetModeV1::StrictMultiRelay
            if !(MIN_STRICT_RELAYS_V1..=MAX_RELAYS_V1).contains(&relays.len()) =>
        {
            return Err(format!(
                "--relay count must be between {MIN_STRICT_RELAYS_V1} and {MAX_RELAYS_V1}; exactly one requires --centralized-single-relay"
            ));
        }
        RelaySetModeV1::CentralizedSingleRelay if relays.len() != 1 => {
            return Err(
                "--centralized-single-relay requires exactly one --relay and never downgrades a multi-relay configuration"
                    .to_owned(),
            );
        }
        _ => {}
    }
    let mut seen_urls = BTreeSet::new();
    let mut seen_hosts = BTreeSet::new();
    let mut targets = Vec::with_capacity(relays.len());
    for url in relays {
        if !is_canonical_public_wss_origin_v1(&url) {
            return Err(
                "every --relay must be an exact credential-free public wss origin with no path"
                    .to_owned(),
            );
        }
        if !seen_urls.insert(url.clone()) {
            return Err("--relay URLs must be distinct".to_owned());
        }
        let host = relay_host_v1(&url)?;
        if !seen_hosts.insert(host.clone()) {
            return Err("--relay hostnames must be distinct".to_owned());
        }
        targets.push(RelayTargetV1 { url, host });
    }
    Ok(targets)
}

fn relay_host_v1(url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("wss://")
        .ok_or_else(|| "relay URL is not wss".to_owned())?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host);
    if host.is_empty() {
        return Err("relay URL has no host".to_owned());
    }
    Ok(host.to_owned())
}

fn decode_lower_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be exactly {N} bytes of lowercase hex"
        ));
    }
    hex::decode(value)
        .map_err(|_| format!("{label} is invalid hex"))?
        .try_into()
        .map_err(|_| format!("{label} must be exactly {N} bytes"))
}

fn install_default_crypto_provider() {
    use std::sync::OnceLock;
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    use futures_util::future;
    use pir_directory_nostr::{
        DirectoryCatalogCheckpointV1, DirectoryEntryV1, DirectoryHealthClassV1, DirectoryHealthV1,
        DirectoryPublisherKeyV1,
    };
    use tokio_tungstenite::tungstenite::protocol::Role;

    const NOW: u64 = 1_500;

    fn entry_event(key: &DirectoryPublisherKeyV1, sequence: u64) -> PublishEventV1 {
        let entry = DirectoryEntryV1::new_tombstone(
            [sequence as u8; 32],
            sequence,
            2_000,
            DirectoryHealthV1 {
                class: DirectoryHealthClassV1::Unavailable,
                observed_bucket: NOW,
            },
            NOW,
        )
        .unwrap();
        let event = key
            .sign_entry_event(&entry, NOW, &[sequence as u8; 32])
            .unwrap();
        PublishEventV1 {
            exact_message: String::from_utf8(event.to_event_message_json_bytes().unwrap()).unwrap(),
            event_id: *event.id(),
            signature: *event.signature(),
        }
    }

    fn ok_message(event: &PublishEventV1, accepted: bool) -> String {
        serde_json::to_string(&("OK", hex::encode(event.event_id), accepted, "stored")).unwrap()
    }

    #[test]
    fn relay_targets_require_explicit_centralized_opt_in_or_two_to_eight_strict_hosts() {
        assert!(validate_relay_targets_v1(vec![], RelaySetModeV1::StrictMultiRelay).is_err());
        assert!(validate_relay_targets_v1(
            vec!["wss://one.example".into()],
            RelaySetModeV1::StrictMultiRelay
        )
        .is_err());
        let centralized = validate_relay_targets_v1(
            vec!["wss://one.example".into()],
            RelaySetModeV1::CentralizedSingleRelay,
        )
        .unwrap();
        assert_eq!(centralized.len(), 1);
        assert_eq!(
            RelaySetModeV1::CentralizedSingleRelay.assurance(),
            "centralized-degraded-no-relay-cross-check"
        );
        assert!(validate_relay_targets_v1(
            vec!["wss://one.example".into(), "wss://two.example".into()],
            RelaySetModeV1::CentralizedSingleRelay,
        )
        .is_err());
        assert!(validate_relay_targets_v1(
            (0..=MAX_RELAYS_V1)
                .map(|index| format!("wss://relay-{index}.example"))
                .collect(),
            RelaySetModeV1::StrictMultiRelay,
        )
        .is_err());
        assert!(validate_relay_targets_v1(
            vec!["ws://one.example".into(), "wss://two.example".into()],
            RelaySetModeV1::StrictMultiRelay
        )
        .is_err());
        assert!(validate_relay_targets_v1(
            vec!["wss://user@one.example".into(), "wss://two.example".into()],
            RelaySetModeV1::StrictMultiRelay
        )
        .is_err());
        assert!(validate_relay_targets_v1(
            vec!["wss://one.example/v1".into(), "wss://two.example".into()],
            RelaySetModeV1::StrictMultiRelay
        )
        .is_err());
        assert!(validate_relay_targets_v1(
            vec!["wss://one.example/a".into(), "wss://one.example/b".into()],
            RelaySetModeV1::StrictMultiRelay
        )
        .is_err());
        let targets = validate_relay_targets_v1(
            vec!["wss://one.example".into(), "wss://two.example:8443".into()],
            RelaySetModeV1::StrictMultiRelay,
        )
        .unwrap();
        assert_eq!(targets[0].host, "one.example");
        assert_eq!(targets[1].host, "two.example");
    }

    #[test]
    fn event_set_digest_fixture_is_stable_and_order_independent() {
        let events = vec![
            PublishEventV1 {
                exact_message: String::new(),
                event_id: [3; 32],
                signature: [4; 64],
            },
            PublishEventV1 {
                exact_message: String::new(),
                event_id: [1; 32],
                signature: [2; 64],
            },
        ];
        assert_eq!(
            hex::encode(event_set_digest_v1(&events).unwrap()),
            "56ae675b14cb305c03b5d6d9a6f9475702fc263629e9f33a4ac93d4c8399dd6c"
        );
    }

    #[test]
    fn artifact_loader_accepts_exact_single_and_checkpoint_bundle() {
        let directory = tempfile::tempdir().unwrap();
        let key = DirectoryPublisherKeyV1::from_secret_bytes([21; 32]).unwrap();
        let entry = entry_event(&key, 1);
        let entry_path = directory.path().join("entry.json");
        std::fs::write(&entry_path, entry.exact_message.as_bytes()).unwrap();

        let mut checkpoint_messages = Vec::new();
        for shard in 0..DIRECTORY_SHARD_COUNT_V1 {
            let checkpoint =
                DirectoryCatalogCheckpointV1::new(shard, 8, 1_000, 2_000, Vec::new(), NOW).unwrap();
            let event = key
                .sign_checkpoint_event(&checkpoint, NOW, &[shard; 32])
                .unwrap();
            checkpoint_messages.push(event.to_event_message_json_bytes().unwrap());
        }
        let checkpoints =
            encode_json_array(&checkpoint_messages, MAX_CHECKPOINT_BUNDLE_BYTES_V1).unwrap();
        let checkpoint_path = directory.path().join("checkpoints.json");
        std::fs::write(&checkpoint_path, checkpoints).unwrap();

        let loaded =
            load_publish_events_v1(&[entry_path, checkpoint_path], key.public_key(), NOW).unwrap();
        assert_eq!(loaded.events.len(), 17);
        assert_eq!(loaded.events[0].exact_message, entry.exact_message);
        assert_eq!(loaded.artifacts.len(), 2);
    }

    #[test]
    fn artifact_loader_rejects_wrong_key_tamper_noncanonical_and_duplicates() {
        let directory = tempfile::tempdir().unwrap();
        let key = DirectoryPublisherKeyV1::from_secret_bytes([22; 32]).unwrap();
        let wrong = DirectoryPublisherKeyV1::from_secret_bytes([23; 32]).unwrap();
        let event = entry_event(&key, 1);
        let path = directory.path().join("entry.json");
        std::fs::write(&path, event.exact_message.as_bytes()).unwrap();
        assert!(
            load_publish_events_v1(std::slice::from_ref(&path), wrong.public_key(), NOW).is_err()
        );
        let duplicate =
            load_publish_events_v1(&[path.clone(), path.clone()], key.public_key(), NOW);
        assert!(duplicate.is_err());
        assert!(duplicate.err().unwrap().contains("duplicate"));

        let noncanonical = directory.path().join("noncanonical.json");
        std::fs::write(
            &noncanonical,
            format!(" {}", event.exact_message).as_bytes(),
        )
        .unwrap();
        assert!(load_publish_events_v1(&[noncanonical], key.public_key(), NOW).is_err());

        let mut tampered = event.exact_message.into_bytes();
        let last = tampered.len() - 2;
        tampered[last] ^= 1;
        let tampered_path = directory.path().join("tampered.json");
        std::fs::write(&tampered_path, tampered).unwrap();
        assert!(load_publish_events_v1(&[tampered_path], key.public_key(), NOW).is_err());
    }

    #[tokio::test]
    async fn websocket_session_sends_exact_events_and_accepts_ordered_true_ok() {
        let key = DirectoryPublisherKeyV1::from_secret_bytes([24; 32]).unwrap();
        let events = vec![entry_event(&key, 1), entry_event(&key, 2)];
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let mut client = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;
        let mut server = WebSocketStream::from_raw_socket(server_io, Role::Server, None).await;
        let server_events = events.clone();
        let server_task = async move {
            for event in &server_events {
                let received = server.next().await.unwrap().unwrap();
                assert_eq!(received, Message::Text(event.exact_message.clone()));
                server
                    .send(Message::Text(ok_message(event, true)))
                    .await
                    .unwrap();
            }
        };
        let (result, ()) = tokio::join!(
            publish_websocket_session_v1(&mut client, &events),
            server_task
        );
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn websocket_session_rejects_false_unexpected_duplicate_and_non_text_replies() {
        let key = DirectoryPublisherKeyV1::from_secret_bytes([25; 32]).unwrap();
        let events = vec![entry_event(&key, 1), entry_event(&key, 2)];
        let cases = vec![
            (
                vec![Message::Text(ok_message(&events[0], false))],
                RelayPublishFailureV1::RelayRejected,
            ),
            (
                vec![Message::Text(
                    serde_json::to_string(&("NOTICE", "no")).unwrap(),
                )],
                RelayPublishFailureV1::UnexpectedReply,
            ),
            (
                vec![Message::Text(
                    serde_json::to_string(&("CLOSED", "subscription", "no")).unwrap(),
                )],
                RelayPublishFailureV1::UnexpectedReply,
            ),
            (
                vec![Message::Text(ok_message(&events[1], true))],
                RelayPublishFailureV1::UnexpectedReply,
            ),
            (
                vec![
                    Message::Text(ok_message(&events[0], true)),
                    Message::Text(ok_message(&events[0], true)),
                ],
                RelayPublishFailureV1::DuplicateOk,
            ),
            (
                vec![Message::Binary(b"not text".to_vec())],
                RelayPublishFailureV1::NonTextReply,
            ),
            (
                vec![Message::Ping(Vec::new())],
                RelayPublishFailureV1::NonTextReply,
            ),
        ];
        for (replies, expected) in cases {
            let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
            let mut client = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;
            let mut server = WebSocketStream::from_raw_socket(server_io, Role::Server, None).await;
            let server_task = async move {
                for reply in replies {
                    let _ = server.next().await.unwrap().unwrap();
                    server.send(reply).await.unwrap();
                }
            };
            let (result, ()) = tokio::join!(
                publish_websocket_session_v1(&mut client, &events),
                server_task
            );
            assert_eq!(result, Err(expected));
        }
    }

    #[tokio::test]
    async fn websocket_session_rejects_missing_and_oversized_ok() {
        let key = DirectoryPublisherKeyV1::from_secret_bytes([26; 32]).unwrap();
        let events = vec![entry_event(&key, 1)];

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let mut client = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;
        let mut server = WebSocketStream::from_raw_socket(server_io, Role::Server, None).await;
        let server_task = async move {
            let _ = server.next().await.unwrap().unwrap();
            server.close(None).await.unwrap();
        };
        let (missing, ()) = tokio::join!(
            publish_websocket_session_v1(&mut client, &events),
            server_task
        );
        assert_eq!(missing, Err(RelayPublishFailureV1::MissingOk));

        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let mut client = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;
        let mut server = WebSocketStream::from_raw_socket(server_io, Role::Server, None).await;
        let server_task = async move {
            let _ = server.next().await.unwrap().unwrap();
            server
                .send(Message::Text(
                    "x".repeat(MAX_RELAY_REPLY_MESSAGE_BYTES_V1 + 1),
                ))
                .await
                .unwrap();
        };
        let (oversized, ()) = tokio::join!(
            publish_websocket_session_v1(&mut client, &events),
            server_task
        );
        assert_eq!(oversized, Err(RelayPublishFailureV1::ReplyTooLarge));
    }

    enum FakeActionV1 {
        CreateReceiptCollision(PathBuf),
        Result(Result<(), RelayPublishFailureV1>),
        Pending,
    }

    struct FakePublisherV1 {
        actions: VecDeque<FakeActionV1>,
        attempted_hosts: Vec<String>,
    }

    impl RelayPublisherV1 for FakePublisherV1 {
        fn publish<'a>(
            &'a mut self,
            target: &'a RelayTargetV1,
            _events: &'a [PublishEventV1],
        ) -> Pin<Box<dyn Future<Output = Result<(), RelayPublishFailureV1>> + 'a>> {
            self.attempted_hosts.push(target.host.clone());
            match self.actions.pop_front().unwrap() {
                FakeActionV1::CreateReceiptCollision(path) => {
                    std::fs::write(path, b"untrusted same-uid collision\n").unwrap();
                    Box::pin(future::ready(Ok(())))
                }
                FakeActionV1::Result(result) => Box::pin(future::ready(result)),
                FakeActionV1::Pending => Box::pin(future::pending()),
            }
        }
    }

    #[tokio::test]
    async fn all_relays_are_attempted_and_partial_failure_or_timeout_is_non_success() {
        let targets = validate_relay_targets_v1(
            vec![
                "wss://one.example".into(),
                "wss://two.example".into(),
                "wss://three.example".into(),
            ],
            RelaySetModeV1::StrictMultiRelay,
        )
        .unwrap();
        let key = DirectoryPublisherKeyV1::from_secret_bytes([27; 32]).unwrap();
        let events = vec![entry_event(&key, 1)];
        let mut publisher = FakePublisherV1 {
            actions: VecDeque::from([
                FakeActionV1::Result(Ok(())),
                FakeActionV1::Result(Err(RelayPublishFailureV1::RelayRejected)),
                FakeActionV1::Pending,
            ]),
            attempted_hosts: Vec::new(),
        };
        let digest = event_set_digest_v1(&events).unwrap();
        let outcomes = publish_all_relays_v1(
            &mut publisher,
            &targets,
            &events,
            digest,
            Duration::from_millis(10),
        )
        .await;
        assert_eq!(publisher.attempted_hosts.len(), 3);
        assert_eq!(outcomes[0].result, Ok(()));
        assert_eq!(
            outcomes[1].result,
            Err(RelayPublishFailureV1::RelayRejected)
        );
        assert_eq!(outcomes[2].result, Err(RelayPublishFailureV1::Timeout));
        assert!(outcomes
            .iter()
            .all(|outcome| outcome.event_set_digest == digest));
        assert_eq!(
            emit_publish_outcomes_v1(&outcomes, RelaySetModeV1::StrictMultiRelay),
            2
        );
    }

    #[tokio::test]
    async fn validate_only_checks_the_exact_publish_inputs_without_calling_transport() {
        let directory = tempfile::tempdir().unwrap();
        let key = DirectoryPublisherKeyV1::from_secret_bytes([28; 32]).unwrap();
        let event = entry_event(&key, 1);
        let artifact = directory.path().join("entry.json");
        std::fs::write(&artifact, event.exact_message.as_bytes()).unwrap();
        let mut publisher = FakePublisherV1 {
            actions: VecDeque::new(),
            attempted_hosts: Vec::new(),
        };

        run_with_publisher_v1(
            DirectoryPublishArgs {
                artifacts: vec![artifact],
                artifact_manifest: None,
                relays: vec!["wss://one.example".into(), "wss://two.example".into()],
                centralized_single_relay: false,
                directory_pubkey_hex: hex::encode(key.public_key()),
                now_unix: NOW,
                relay_timeout_seconds: 1,
                receipt_directory: None,
                validate_only: true,
            },
            &mut publisher,
        )
        .await
        .unwrap();

        assert!(publisher.attempted_hosts.is_empty());
        assert!(publisher.actions.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn per_invocation_receipts_preflight_conflicts_and_converge_a_to_b() {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};

        let directory = tempfile::tempdir().unwrap();
        let key = DirectoryPublisherKeyV1::from_secret_bytes([29; 32]).unwrap();
        let event = entry_event(&key, 1);
        let artifact = directory.path().join("entry.json");
        std::fs::write(&artifact, event.exact_message.as_bytes()).unwrap();
        let manifest = directory.path().join("artifacts.sha256");
        std::fs::write(
            &manifest,
            format!(
                "{}  {}\n",
                sha256_hex_v1(event.exact_message.as_bytes()),
                artifact.display()
            ),
        )
        .unwrap();
        let receipt_directory = directory.path().join("receipts");
        let mut receipt_directory_builder = std::fs::DirBuilder::new();
        receipt_directory_builder.mode(0o700);
        receipt_directory_builder
            .create(&receipt_directory)
            .unwrap();
        let args = || DirectoryPublishArgs {
            artifacts: vec![artifact.clone()],
            artifact_manifest: Some(manifest.clone()),
            relays: vec!["wss://one.example".into()],
            centralized_single_relay: true,
            directory_pubkey_hex: hex::encode(key.public_key()),
            now_unix: NOW,
            relay_timeout_seconds: 1,
            receipt_directory: Some(receipt_directory.clone()),
            validate_only: false,
        };
        let invocation = |id: u8| ExactInvocationV1 {
            argv: vec![
                "/opt/bitcoinpir/bpir-admin/test/bpir-admin".into(),
                "directory-artifact".into(),
                "publish".into(),
            ],
            invocation_id: format!("{id:02x}").repeat(16),
        };

        let receipt_a = publication_receipt_path_v1(&receipt_directory, &"01".repeat(16)).unwrap();
        let mut publisher_a = FakePublisherV1 {
            actions: VecDeque::from([FakeActionV1::CreateReceiptCollision(receipt_a.clone())]),
            attempted_hosts: Vec::new(),
        };
        let error =
            run_with_publisher_and_invocation_v1(args(), &mut publisher_a, Some(invocation(1)))
                .await
                .unwrap_err();
        assert!(
            error.contains("all relays accepted the exact event set"),
            "unexpected post-relay failure: {error}"
        );
        assert!(
            error.contains("immutable private output already exists"),
            "receipt collision was not strict: {error}"
        );
        assert_eq!(publisher_a.attempted_hosts, vec!["one.example"]);
        let first = std::fs::read(&receipt_a).unwrap();
        assert_eq!(first, b"untrusted same-uid collision\n");

        // Model the reviewed centralized relay contract: replaying the exact
        // durable NIP-01 EVENT returns OK true. Invocation A may have failed
        // after its immutable receipt commit; approved invocation B can replay
        // the same bytes and publish a distinct receipt without mutating A.
        let mut exact_duplicate_b = FakePublisherV1 {
            actions: VecDeque::from([FakeActionV1::Result(Ok(()))]),
            attempted_hosts: Vec::new(),
        };
        run_with_publisher_and_invocation_v1(args(), &mut exact_duplicate_b, Some(invocation(2)))
            .await
            .unwrap();
        assert_eq!(exact_duplicate_b.attempted_hosts, vec!["one.example"]);
        let receipt_b = publication_receipt_path_v1(&receipt_directory, &"02".repeat(16)).unwrap();
        let second = std::fs::read(&receipt_b).unwrap();
        let parsed_b: serde_json::Value = serde_json::from_slice(&second).unwrap();
        assert_eq!(parsed_b["invocation_id"], "02".repeat(16));
        assert_eq!(
            parsed_b["artifacts"][0]["sha256"],
            sha256_hex_v1(event.exact_message.as_bytes())
        );

        let mut conflicting_b = FakePublisherV1 {
            actions: VecDeque::from([FakeActionV1::Result(Ok(()))]),
            attempted_hosts: Vec::new(),
        };
        let error =
            run_with_publisher_and_invocation_v1(args(), &mut conflicting_b, Some(invocation(2)))
                .await
                .unwrap_err();
        assert!(error.contains("preflight failed before relay I/O"));
        assert!(conflicting_b.attempted_hosts.is_empty());
        assert_eq!(std::fs::read(&receipt_a).unwrap(), first);
        assert_eq!(std::fs::read(&receipt_b).unwrap(), second);
        assert_eq!(std::fs::symlink_metadata(&receipt_a).unwrap().nlink(), 1);
        assert_eq!(std::fs::symlink_metadata(&receipt_b).unwrap().nlink(), 1);
    }
}
