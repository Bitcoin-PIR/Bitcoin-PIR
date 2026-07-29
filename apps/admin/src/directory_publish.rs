//! Strict NIP-01 transport for already-signed directory artifacts.
//!
//! The publisher never accepts a signing key and never reconstructs an EVENT
//! message. It verifies canonical artifacts against an explicit directory-key
//! pin, sends the exact input message bytes, and requires one positive NIP-01
//! `OK` for every event on every independently configured relay.

use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use clap::Args;
use futures_util::{SinkExt, StreamExt};
use pir_directory_nostr::{
    verify_directory_checkpoint_event_v1, verify_directory_entry_event_v1, NostrEventV1,
    DIRECTORY_SHARD_COUNT_V1,
};
use pir_service_protocol::is_canonical_public_wss_endpoint_v1;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::directory_artifact::{
    encode_json_array, parse_event_message, read_public_bounded, MAX_CHECKPOINT_BUNDLE_BYTES_V1,
    MAX_EVENT_MESSAGE_BYTES_V1,
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

#[derive(Args, Debug)]
pub struct DirectoryPublishArgs {
    /// Signed artifact: one canonical EVENT message or one exact 16-checkpoint array.
    #[arg(long = "artifact", required = true)]
    artifacts: Vec<PathBuf>,
    /// Distinct credential-free canonical public wss relay. Repeat 2..8 times by default.
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
    run_with_publisher_v1(args, &mut publisher).await
}

async fn run_with_publisher_v1<P: RelayPublisherV1>(
    args: DirectoryPublishArgs,
    publisher: &mut P,
) -> Result<(), String> {
    if args.now_unix == 0 {
        return Err("--now-unix must be non-zero".to_owned());
    }
    if !(1..=MAX_RELAY_TIMEOUT_SECONDS_V1).contains(&args.relay_timeout_seconds) {
        return Err(format!(
            "--relay-timeout-seconds must be between 1 and {MAX_RELAY_TIMEOUT_SECONDS_V1}"
        ));
    }
    let directory_pubkey =
        decode_lower_fixed_hex::<32>(&args.directory_pubkey_hex, "directory publisher public key")?;
    let events = load_publish_events_v1(&args.artifacts, &directory_pubkey, args.now_unix)?;
    let event_set_digest = event_set_digest_v1(&events)?;
    let relay_mode = if args.centralized_single_relay {
        RelaySetModeV1::CentralizedSingleRelay
    } else {
        RelaySetModeV1::StrictMultiRelay
    };
    let targets = validate_relay_targets_v1(args.relays, relay_mode)?;
    if args.validate_only {
        emit_validation_outcomes_v1(&targets, events.len(), event_set_digest, relay_mode);
        return Ok(());
    }
    let timeout = Duration::from_secs(args.relay_timeout_seconds);
    let outcomes =
        publish_all_relays_v1(publisher, &targets, &events, event_set_digest, timeout).await;
    let failures = emit_publish_outcomes_v1(&outcomes, relay_mode);
    if failures == 0 {
        Ok(())
    } else {
        Err(format!(
            "publishing failed for {failures} of {} relays; exact artifacts may be rerun manually",
            outcomes.len()
        ))
    }
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

fn load_publish_events_v1(
    artifacts: &[PathBuf],
    directory_pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<Vec<PublishEventV1>, String> {
    if artifacts.is_empty() || artifacts.len() > MAX_PUBLISH_ARTIFACTS_V1 {
        return Err(format!(
            "--artifact count must be between 1 and {MAX_PUBLISH_ARTIFACTS_V1}"
        ));
    }
    let mut events = Vec::new();
    let mut seen_ids = BTreeSet::new();
    let mut total_bytes = 0usize;
    for path in artifacts {
        let bytes = read_public_bounded(
            path,
            MAX_CHECKPOINT_BUNDLE_BYTES_V1,
            "directory publish artifact",
        )?;
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
    Ok(events)
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
        if !is_canonical_public_wss_endpoint_v1(&url) {
            return Err(
                "every --relay must be a canonical credential-free public wss URL".to_owned(),
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
            vec!["wss://one.example/a".into(), "wss://one.example/b".into()],
            RelaySetModeV1::StrictMultiRelay
        )
        .is_err());
        let targets = validate_relay_targets_v1(
            vec!["wss://one.example".into(), "wss://two.example/nostr".into()],
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
        assert_eq!(loaded.len(), 17);
        assert_eq!(loaded[0].exact_message, entry.exact_message);
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
                relays: vec!["wss://one.example".into(), "wss://two.example".into()],
                centralized_single_relay: false,
                directory_pubkey_hex: hex::encode(key.public_key()),
                now_unix: NOW,
                relay_timeout_seconds: 1,
                validate_only: true,
            },
            &mut publisher,
        )
        .await
        .unwrap();

        assert!(publisher.attempted_hosts.is_empty());
        assert!(publisher.actions.is_empty());
    }
}
