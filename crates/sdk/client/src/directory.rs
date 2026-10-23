//! Service-directory discovery over Nostr relays (`docs/DIRECTORY_PROTOCOL.md`).
//!
//! [`discover_directory_v1`] reads the full 16-shard catalog from the
//! configured relays (NIP-01 `REQ` / `EOSE`, one connection per relay, as
//! the browser client does), verifies it with
//! [`verify_directory_catalog_views_v1`] against the pinned directory key and
//! the caller's rollback floors, and returns the catalog with the advanced
//! floors. The caller persists the floors before using the catalog, and
//! decides whether a degraded catalog is good enough. An entry is a discovery
//! hint only: connect to it with the usual checks (attestation, operator
//! identity, database proof, server info), then close it against the live
//! server with `pir_directory_nostr::bind_directory_entry_to_live_identity_v1`.

use std::collections::BTreeSet;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use pir_directory_nostr::{
    full_catalog_req_json_v1, verify_directory_catalog_views_v1, DIRECTORY_SHARD_COUNT_V1,
};
pub use pir_directory_nostr::{
    DirectoryAccessClassV1, DirectoryAttestationV1, DirectoryBackendV1, DirectoryCatalogEntryV1,
    DirectoryCatalogHintV1, DirectoryCatalogRejectionV1, DirectoryCatalogShardV1,
    DirectoryCatalogV1, DirectoryHealthClassV1, DirectoryRollbackFloorsV1, DirectoryServerRoleV1,
};
use pir_sdk::{PirError, PirResult};
use tokio_tungstenite::tungstenite::Message;

/// `strict-multi-relay` takes this many distinct relays at most.
pub const DIRECTORY_MAX_STRICT_RELAYS_V1: usize = 8;
/// A relay that sends more than this for one catalog contributes no view.
pub const DIRECTORY_MAX_RELAY_BYTES_V1: usize = 16 * 1024 * 1024;
/// Per relay, for the whole catalog.
pub const DIRECTORY_DEFAULT_TIMEOUT_V1: Duration = Duration::from_secs(10);

/// `StrictMultiRelay`: two to eight distinct relays whose views are
/// compared. `CentralizedSingleRelay`: exactly one relay; its catalog is
/// always reported degraded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryRelayModeV1 {
    StrictMultiRelay,
    CentralizedSingleRelay,
}

#[derive(Clone, Debug)]
pub struct DirectoryConfigV1 {
    pub mode: DirectoryRelayModeV1,
    pub relays: Vec<String>,
    /// The directory publisher's x-only key (`PRODUCTION_DIRECTORY` in
    /// `web/src/production-providers.ts` for the production directory).
    pub directory_pubkey: [u8; 32],
    /// Per relay, for the whole catalog.
    pub timeout: Duration,
}

/// A relay that contributed no view, and why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryRelayFailureV1 {
    pub relay: String,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct DirectoryDiscoveryV1 {
    pub mode: DirectoryRelayModeV1,
    /// False only when all 16 shards came from at least two agreeing relays.
    pub degraded: bool,
    /// The relays whose complete view went into the catalog, in the order
    /// `catalog.rejected[..].relay` indexes them.
    pub relays: Vec<String>,
    pub unreachable: Vec<DirectoryRelayFailureV1>,
    pub catalog: DirectoryCatalogV1,
}

impl DirectoryDiscoveryV1 {
    /// Every entry listing `backend`, with its hint for it (role, access
    /// class, attestation).
    pub fn candidates(
        &self,
        backend: DirectoryBackendV1,
    ) -> impl Iterator<Item = (&DirectoryCatalogEntryV1, &DirectoryCatalogHintV1)> {
        self.catalog.entries.iter().filter_map(move |entry| {
            entry
                .hints
                .iter()
                .find(|hint| hint.backend == backend)
                .map(|hint| (entry, hint))
        })
    }
}

/// Read, verify and return the directory catalog; see the module comment.
/// A relay that fails is reported in `unreachable`, a rejected view or shard
/// in `catalog.rejected`; neither is an error.
pub async fn discover_directory_v1(
    config: &DirectoryConfigV1,
    floors: DirectoryRollbackFloorsV1,
    now_unix: u64,
) -> PirResult<DirectoryDiscoveryV1> {
    let distinct = config.relays.iter().collect::<BTreeSet<_>>().len();
    match config.mode {
        DirectoryRelayModeV1::CentralizedSingleRelay if config.relays.len() != 1 => {
            return Err(PirError::Config(
                "centralized-single-relay takes exactly one relay".to_owned(),
            ));
        }
        DirectoryRelayModeV1::StrictMultiRelay
            if config.relays.len() < 2
                || config.relays.len() > DIRECTORY_MAX_STRICT_RELAYS_V1
                || distinct != config.relays.len() =>
        {
            return Err(PirError::Config(
                "strict-multi-relay takes two to eight distinct relays".to_owned(),
            ));
        }
        _ => {}
    }
    let requests = full_catalog_req_json_v1(&config.directory_pubkey)
        .map_err(|error| PirError::Config(error.to_string()))?
        .into_iter()
        .map(|request| {
            String::from_utf8(request).map_err(|error| PirError::Config(error.to_string()))
        })
        .collect::<PirResult<Vec<String>>>()?;

    let reads = futures_util::future::join_all(
        config
            .relays
            .iter()
            .map(|relay| read_catalog(relay, &requests, config.timeout)),
    )
    .await;
    let mut views = Vec::new();
    let mut relays = Vec::new();
    let mut unreachable = Vec::new();
    for (relay, read) in config.relays.iter().zip(reads) {
        match read {
            Ok(view) => {
                views.push(view);
                relays.push(relay.clone());
            }
            Err(reason) => unreachable.push(DirectoryRelayFailureV1 {
                relay: relay.clone(),
                reason,
            }),
        }
    }
    let catalog =
        verify_directory_catalog_views_v1(&views, floors, &config.directory_pubkey, now_unix);
    let degraded = config.mode == DirectoryRelayModeV1::CentralizedSingleRelay
        || catalog.shards.len() < usize::from(DIRECTORY_SHARD_COUNT_V1)
        || catalog.shards.iter().any(|shard| shard.views < 2);
    Ok(DirectoryDiscoveryV1 {
        mode: config.mode,
        degraded,
        relays,
        unreachable,
        catalog,
    })
}

/// Every `EVENT` message one relay returns for `requests`, once each
/// subscription reached `EOSE`. The exact message text is kept: the codec
/// verifies the event's own JSON.
async fn read_catalog(
    url: &str,
    requests: &[String],
    timeout: Duration,
) -> Result<Vec<String>, String> {
    crate::connection::install_default_crypto_provider();
    let read = async {
        let (mut socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|error| format!("connect failed: {error}"))?;
        let mut open = BTreeSet::new();
        for request in requests {
            let (_, id, _): (String, String, serde_json::Value) = serde_json::from_str(request)
                .map_err(|_| "catalog request is not a REQ message".to_owned())?;
            open.insert(id);
            socket
                .send(Message::Text(request.clone()))
                .await
                .map_err(|error| format!("send failed: {error}"))?;
        }
        let mut events = Vec::new();
        let mut bytes = 0usize;
        while let Some(message) = socket.next().await {
            let text = match message.map_err(|error| format!("receive failed: {error}"))? {
                Message::Text(text) => text,
                Message::Binary(_) => return Err("relay sent a binary message".to_owned()),
                Message::Close(_) => {
                    return Err("relay closed the connection before EOSE".to_owned())
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
            };
            bytes += text.len();
            if bytes > DIRECTORY_MAX_RELAY_BYTES_V1 {
                return Err(format!(
                    "relay sent more than {DIRECTORY_MAX_RELAY_BYTES_V1} bytes"
                ));
            }
            let message: Vec<serde_json::Value> =
                serde_json::from_str(&text).map_err(|_| "relay sent malformed JSON".to_owned())?;
            let kind = message.first().and_then(serde_json::Value::as_str);
            let id = message.get(1).and_then(serde_json::Value::as_str);
            match (kind, id) {
                (Some("EVENT"), Some(id)) => {
                    if !open.contains(id) {
                        return Err("relay sent an EVENT outside an open subscription".to_owned());
                    }
                    events.push(text);
                }
                (Some("EOSE"), Some(id)) => {
                    if !open.remove(id) {
                        return Err("relay sent an unexpected EOSE".to_owned());
                    }
                    if open.is_empty() {
                        break;
                    }
                }
                (Some("CLOSED"), _) => {
                    return Err(format!(
                        "relay closed a subscription: {}",
                        message
                            .get(2)
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("")
                    ));
                }
                // NOTICE and anything else carries nothing the catalog needs.
                _ => {}
            }
        }
        if !open.is_empty() {
            return Err("relay closed the connection before EOSE".to_owned());
        }
        // Closing the connection ends every subscription; no CLOSE frames.
        let _ = socket.close(None).await;
        Ok(events)
    };
    tokio::time::timeout(timeout, read)
        .await
        .map_err(|_| format!("no EOSE on every shard within {} ms", timeout.as_millis()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const KEY: [u8; 32] = [7; 32];

    #[derive(Clone, Copy)]
    enum Relay {
        /// Answers every REQ with EOSE and no events.
        Empty,
        /// Refuses every subscription.
        Closed,
        /// Sends an EVENT under an unknown subscription id.
        Stray,
        /// Never answers.
        Silent,
    }

    /// An in-process relay with one behaviour; returns its `ws://` URL.
    async fn relay(behaviour: Relay) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let Message::Text(text) = message else {
                    continue;
                };
                let request: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
                let id = request[1].as_str().unwrap();
                let reply = match behaviour {
                    Relay::Empty => format!(r#"["EOSE","{id}"]"#),
                    Relay::Closed => format!(r#"["CLOSED","{id}","error: not here"]"#),
                    Relay::Stray => {
                        r#"["EVENT","bitcoinpir-directory-v1-elsewhere",{}]"#.to_owned()
                    }
                    Relay::Silent => continue,
                };
                if socket.send(Message::Text(reply)).await.is_err() {
                    break;
                }
            }
        });
        url
    }

    fn config(mode: DirectoryRelayModeV1, relays: Vec<String>) -> DirectoryConfigV1 {
        DirectoryConfigV1 {
            mode,
            relays,
            directory_pubkey: KEY,
            timeout: Duration::from_millis(500),
        }
    }

    #[tokio::test]
    async fn an_empty_relay_yields_a_degraded_catalog_with_every_shard_rejected() {
        let url = relay(Relay::Empty).await;
        let config = config(
            DirectoryRelayModeV1::CentralizedSingleRelay,
            vec![url.clone()],
        );
        let found = discover_directory_v1(&config, DirectoryRollbackFloorsV1::default(), NOW)
            .await
            .unwrap();
        assert_eq!(found.relays, [url]);
        assert!(found.unreachable.is_empty());
        assert!(found.degraded);
        assert_eq!(found.catalog.valid_until, 0);
        assert!(found.catalog.shards.is_empty() && found.catalog.entries.is_empty());
        // Each shard is rejected for the relay view, then as a whole.
        assert_eq!(found.catalog.rejected.len(), 32);
        assert!(found.catalog.rejected[..16]
            .iter()
            .all(|rejection| rejection.relay == Some(0)));
        assert!(found.catalog.rejected[16..]
            .iter()
            .all(|rejection| rejection.relay.is_none()));
        assert_eq!(found.catalog.state, DirectoryRollbackFloorsV1::default());
        assert_eq!(found.candidates(DirectoryBackendV1::Dpf).count(), 0);
    }

    #[tokio::test]
    async fn a_relay_that_closes_stalls_or_strays_contributes_no_view() {
        let good = relay(Relay::Empty).await;
        let closed = relay(Relay::Closed).await;
        let silent = relay(Relay::Silent).await;
        let stray = relay(Relay::Stray).await;
        let config = config(
            DirectoryRelayModeV1::StrictMultiRelay,
            vec![good.clone(), closed.clone(), silent.clone(), stray.clone()],
        );
        let found = discover_directory_v1(&config, DirectoryRollbackFloorsV1::default(), NOW)
            .await
            .unwrap();
        assert_eq!(found.relays, [good]);
        let reasons = found
            .unreachable
            .iter()
            .map(|failure| (failure.relay.as_str(), failure.reason.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(reasons.len(), 3);
        assert!(reasons.contains(&(
            closed.as_str(),
            "relay closed a subscription: error: not here"
        )));
        assert!(reasons.contains(&(silent.as_str(), "no EOSE on every shard within 500 ms")));
        assert!(reasons.contains(&(
            stray.as_str(),
            "relay sent an EVENT outside an open subscription"
        )));
        assert!(found.degraded);
    }

    #[tokio::test]
    async fn a_relay_that_is_not_listening_is_unreachable_not_an_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        drop(listener);
        let config = config(
            DirectoryRelayModeV1::CentralizedSingleRelay,
            vec![url.clone()],
        );
        let found = discover_directory_v1(&config, DirectoryRollbackFloorsV1::default(), NOW)
            .await
            .unwrap();
        assert!(found.relays.is_empty());
        assert_eq!(found.unreachable.len(), 1);
        assert_eq!(found.unreachable[0].relay, url);
        assert!(found.unreachable[0].reason.starts_with("connect failed"));
        assert_eq!(found.catalog.rejected.len(), 16);
    }

    #[tokio::test]
    async fn the_mode_fixes_the_relay_count() {
        let one = "wss://one.example".to_owned();
        let two = "wss://two.example".to_owned();
        for (mode, relays) in [
            (
                DirectoryRelayModeV1::CentralizedSingleRelay,
                vec![one.clone(), two.clone()],
            ),
            (DirectoryRelayModeV1::CentralizedSingleRelay, vec![]),
            (DirectoryRelayModeV1::StrictMultiRelay, vec![one.clone()]),
            (
                DirectoryRelayModeV1::StrictMultiRelay,
                vec![one.clone(), one.clone()],
            ),
            (
                DirectoryRelayModeV1::StrictMultiRelay,
                (0..9).map(|i| format!("wss://{i}.example")).collect(),
            ),
        ] {
            let error = discover_directory_v1(
                &config(mode, relays),
                DirectoryRollbackFloorsV1::default(),
                NOW,
            )
            .await
            .unwrap_err();
            assert!(matches!(error, PirError::Config(_)), "{error:?}");
        }
    }

    #[test]
    fn candidates_pair_each_entry_with_its_hint_for_the_backend() {
        let entry = |server_id: &str, hints: Vec<DirectoryCatalogHintV1>| DirectoryCatalogEntryV1 {
            provider_id: "00".repeat(32),
            event_id: "11".repeat(32),
            directory_sequence: 1,
            valid_until: NOW + 60,
            server_id: server_id.to_owned(),
            operator_pubkey: "22".repeat(32),
            endpoints: vec![format!("wss://{server_id}.example")],
            health: DirectoryHealthClassV1::Available,
            hints,
        };
        let hint = |backend, access| DirectoryCatalogHintV1 {
            backend,
            role: DirectoryServerRoleV1::Primary,
            access,
            attestation: DirectoryAttestationV1::None,
        };
        let found = DirectoryDiscoveryV1 {
            mode: DirectoryRelayModeV1::CentralizedSingleRelay,
            degraded: true,
            relays: vec![],
            unreachable: vec![],
            catalog: DirectoryCatalogV1 {
                valid_until: NOW + 60,
                shards: vec![],
                entries: vec![
                    entry(
                        "a",
                        vec![hint(DirectoryBackendV1::Dpf, DirectoryAccessClassV1::Free)],
                    ),
                    entry(
                        "b",
                        vec![
                            hint(DirectoryBackendV1::Dpf, DirectoryAccessClassV1::Paid),
                            hint(DirectoryBackendV1::Oram, DirectoryAccessClassV1::BestEffort),
                        ],
                    ),
                ],
                rejected: vec![],
                state: DirectoryRollbackFloorsV1::default(),
            },
        };
        let dpf = found
            .candidates(DirectoryBackendV1::Dpf)
            .map(|(entry, hint)| (entry.server_id.as_str(), hint.access))
            .collect::<Vec<_>>();
        assert_eq!(
            dpf,
            [
                ("a", DirectoryAccessClassV1::Free),
                ("b", DirectoryAccessClassV1::Paid)
            ]
        );
        assert_eq!(found.candidates(DirectoryBackendV1::Oram).count(), 1);
        assert_eq!(found.candidates(DirectoryBackendV1::Onion).count(), 0);
    }
}
