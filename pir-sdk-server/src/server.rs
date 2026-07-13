//! PIR server builder and runner.

use crate::config::{ConfigError, ServerConfig};
use crate::loader::DatabaseLoader;
use futures_util::{SinkExt, StreamExt};
use pir_runtime_core::handler::RequestHandler;
use pir_runtime_core::protocol::{Request, Response};
use pir_sdk::{DatabaseCatalog, PirError, PirResult, ServerRole};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio_tungstenite::tungstenite::Message;

/// Handle for graceful shutdown.
#[derive(Clone)]
pub struct ShutdownHandle {
    sender: watch::Sender<bool>,
}

impl ShutdownHandle {
    /// Signal the server to shut down.
    pub fn shutdown(&self) {
        let _ = self.sender.send(true);
    }
}

/// A running PIR server.
pub struct PirServer {
    config: ServerConfig,
    handler: Arc<RequestHandler>,
    catalog: DatabaseCatalog,
    listener: Option<TcpListener>,
    shutdown_rx: watch::Receiver<bool>,
    shutdown_tx: watch::Sender<bool>,
}

impl PirServer {
    /// Get the server configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Get the database catalog.
    pub fn catalog(&self) -> &DatabaseCatalog {
        &self.catalog
    }

    /// Get a shutdown handle.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            sender: self.shutdown_tx.clone(),
        }
    }

    /// Get the bound address.
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.listener.as_ref().and_then(|l| l.local_addr().ok())
    }

    /// Run the server until shutdown.
    pub async fn run(mut self) -> PirResult<()> {
        let listener = self
            .listener
            .take()
            .ok_or_else(|| PirError::InvalidState("server not bound".into()))?;

        let addr = listener.local_addr().map_err(PirError::Io)?;
        log::info!("PIR server listening on {}", addr);
        log::info!(
            "Serving {} databases, role={:?}",
            self.handler.databases().len(),
            self.config.role
        );
        log::info!(
            "Overload limits: max_connections={}, max_in_flight_requests={}, handshake_timeout={}s, idle_timeout={}s",
            self.config.max_connections,
            self.config.max_in_flight_requests,
            self.config.handshake_timeout_secs,
            self.config.idle_timeout_secs,
        );

        let connection_slots = Arc::new(Semaphore::new(self.config.max_connections));
        let request_slots = Arc::new(Semaphore::new(self.config.max_in_flight_requests));
        let handshake_timeout = Duration::from_secs(self.config.handshake_timeout_secs);
        let idle_timeout = Duration::from_secs(self.config.idle_timeout_secs);

        // Main accept loop
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            let connection_permit = match connection_slots.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    log::warn!(
                                        "Refusing connection from {}: max_connections={} reached",
                                        peer,
                                        self.config.max_connections,
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };
                            log::debug!("New connection from {}", peer);
                            let handler = self.handler.clone();
                            let request_slots = request_slots.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream,
                                    handler,
                                    connection_permit,
                                    request_slots,
                                    handshake_timeout,
                                    idle_timeout,
                                ).await {
                                    log::error!("Connection error from {}: {}", peer, e);
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("Accept error: {}", e);
                        }
                    }
                }
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        log::info!("Shutdown signal received");
                        break;
                    }
                }
            }
        }

        log::info!("PIR server stopped");
        Ok(())
    }
}

/// Handle a single WebSocket connection.
async fn handle_connection(
    stream: TcpStream,
    handler: Arc<RequestHandler>,
    _connection_permit: OwnedSemaphorePermit,
    request_slots: Arc<Semaphore>,
    handshake_timeout: Duration,
    idle_timeout: Duration,
) -> PirResult<()> {
    let ws_stream =
        tokio::time::timeout(handshake_timeout, tokio_tungstenite::accept_async(stream))
            .await
            .map_err(|_| PirError::ConnectionFailed("WebSocket handshake timed out".into()))?
            .map_err(|e| {
                PirError::ConnectionFailed(format!("WebSocket handshake failed: {}", e))
            })?;

    let (mut sink, mut stream) = ws_stream.split();

    loop {
        let Some(msg) = tokio::time::timeout(idle_timeout, stream.next())
            .await
            .map_err(|_| PirError::ConnectionFailed("connection idle timeout".into()))?
        else {
            break;
        };
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                log::debug!("WebSocket read error: {}", e);
                break;
            }
        };

        match msg {
            Message::Binary(data) => {
                // Parse request (skip 4-byte length prefix)
                if data.len() < 5 {
                    log::warn!("Message too short: {} bytes", data.len());
                    continue;
                }

                let payload = &data[4..];
                let request = match Request::decode(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        log::warn!("Failed to decode request: {}", e);
                        let error_resp = Response::Error(format!("decode error: {}", e));
                        let encoded = error_resp.encode();
                        let _ = sink.send(Message::Binary(encoded.into())).await;
                        continue;
                    }
                };

                // Bound CPU-heavy request evaluation globally and keep it off
                // Tokio's async worker threads. Waiting for a permit applies
                // backpressure to this connection without changing wire shape.
                let permit = request_slots
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| PirError::InvalidState("request limiter closed".into()))?;
                let request_handler = handler.clone();
                let response = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    request_handler.handle_request(&request)
                })
                .await
                .map_err(|e| PirError::InvalidState(format!("request worker failed: {}", e)))?;

                // Send response
                let encoded = response.encode();
                if let Err(e) = sink.send(Message::Binary(encoded.into())).await {
                    log::debug!("WebSocket send error: {}", e);
                    break;
                }
            }
            Message::Ping(data) => {
                let _ = sink.send(Message::Pong(data)).await;
            }
            Message::Close(_) => {
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

/// Builder for creating a PIR server.
pub struct PirServerBuilder {
    config: ServerConfig,
    /// Pre-encoded `pir_identity::AnnouncementBundle` bytes that
    /// REQ_ANNOUNCE returns verbatim. `None` (the default) leaves the
    /// server in "unannounced" mode (REQ_ANNOUNCE → RESP_ERROR). Build
    /// the bytes with `pir_runtime_core::identity::build_announcement_bundle`.
    announcement_bundle: Option<Vec<u8>>,
}

impl PirServerBuilder {
    /// Create a new server builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: ServerConfig::new(),
            announcement_bundle: None,
        }
    }

    /// Supply the operator-signed announcement bundle served by
    /// REQ_ANNOUNCE. Pass the pre-encoded
    /// `pir_identity::AnnouncementBundle` bytes (build them with
    /// `pir_runtime_core::identity::build_announcement_bundle`). `None`
    /// keeps the server in unannounced mode.
    pub fn with_announcement_bundle(mut self, bundle: Option<Vec<u8>>) -> Self {
        self.announcement_bundle = bundle;
        self
    }

    /// Load configuration from a TOML file.
    pub fn from_config(mut self, path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        self.config = ServerConfig::load(path.as_ref())?;
        Ok(self)
    }

    /// Set the listening port.
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Set the server role.
    pub fn role(mut self, role: ServerRole) -> Self {
        self.config.role(role);
        self
    }

    /// Add a full snapshot database.
    pub fn add_full_db(mut self, path: impl AsRef<Path>, height: u32) -> Self {
        self.config.add_full_db(path.as_ref(), height);
        self
    }

    /// Add a delta database.
    pub fn add_delta_db(
        mut self,
        path: impl AsRef<Path>,
        base_height: u32,
        tip_height: u32,
    ) -> Self {
        self.config
            .add_delta_db(path.as_ref(), base_height, tip_height);
        self
    }

    /// Enable or disable warmup.
    pub fn warmup(mut self, enable: bool) -> Self {
        self.config.warmup = enable;
        self
    }

    /// Set the global connection cap. Values below 1 are rejected by `build`.
    pub fn max_connections(mut self, limit: usize) -> Self {
        self.config.max_connections = limit;
        self
    }

    /// Set the global CPU-heavy request concurrency cap.
    pub fn max_in_flight_requests(mut self, limit: usize) -> Self {
        self.config.max_in_flight_requests = limit;
        self
    }

    /// Set the WebSocket handshake deadline in seconds.
    pub fn handshake_timeout_secs(mut self, seconds: u64) -> Self {
        self.config.handshake_timeout_secs = seconds;
        self
    }

    /// Set the idle connection timeout in seconds.
    pub fn idle_timeout_secs(mut self, seconds: u64) -> Self {
        self.config.idle_timeout_secs = seconds;
        self
    }

    /// Disable DPF backend.
    pub fn disable_dpf(mut self) -> Self {
        self.config.enable_dpf = false;
        self
    }

    /// Disable HarmonyPIR backend.
    pub fn disable_harmony(mut self) -> Self {
        self.config.enable_harmony = false;
        self
    }

    /// Disable OnionPIR backend.
    pub fn disable_onion(mut self) -> Self {
        self.config.enable_onion = false;
        self
    }

    /// Build and bind the server (but don't start accepting connections).
    pub async fn build(self) -> PirResult<PirServer> {
        self.config
            .validate()
            .map_err(|e| PirError::Config(e.to_string()))?;

        // Load databases
        let mut loader = DatabaseLoader::new();
        loader.load_all(&self.config.databases)?;

        if loader.is_empty() {
            return Err(PirError::Config("no databases configured".into()));
        }

        log::info!("Loaded {} databases", loader.len());
        for db in loader.catalog().databases.iter() {
            log::info!(
                "  [{}] {} {:?} height={} index_bins={} chunk_bins={}",
                db.db_id,
                db.name,
                db.kind,
                db.height,
                db.index_bins,
                db.chunk_bins
            );
        }

        // Create request handler
        let catalog = loader.catalog().clone();
        let handler = Arc::new(
            RequestHandler::new(loader.into_databases())
                .with_announcement_bundle(self.announcement_bundle),
        );

        // Bind listener
        let addr = format!("0.0.0.0:{}", self.config.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| PirError::ConnectionFailed(format!("bind {}: {}", addr, e)))?;

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Ok(PirServer {
            config: self.config,
            handler,
            catalog,
            listener: Some(listener),
            shutdown_rx,
            shutdown_tx,
        })
    }
}

impl Default for PirServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_cap_refuses_excess_and_recovers_after_drop() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let slots = Arc::new(Semaphore::new(2));
            let first = slots.clone().try_acquire_owned().unwrap();
            let _second = slots.clone().try_acquire_owned().unwrap();
            assert!(slots.clone().try_acquire_owned().is_err());
            drop(first);
            assert!(slots.clone().try_acquire_owned().is_ok());
        });
    }

    #[tokio::test]
    async fn request_cap_queues_excess_work() {
        let slots = Arc::new(Semaphore::new(1));
        let first = slots.clone().acquire_owned().await.unwrap();
        let waiting = slots.clone().acquire_owned();
        tokio::pin!(waiting);
        assert!(matches!(
            futures_util::poll!(&mut waiting),
            std::task::Poll::Pending
        ));
        drop(first);
        assert!(waiting.await.is_ok());
    }
}
