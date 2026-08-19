//! Loopback WebSocket transport with bounded snapshot-only semantics.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use rusqlite::InterruptHandle;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

use crate::store::{DirectoryStore, IngestDisposition, SnapshotPlan, StoreLimits};
use crate::wire::{
    best_effort_event_id, best_effort_subscription_id, closed_message, eose_message, event_message,
    ok_message, ok_message_hex, parse_client_message, ClientMessage, RequestFilter, ValidatedEvent,
    MAX_EVENT_MESSAGE_BYTES, MAX_READBACK_IDS, MAX_SUBSCRIPTION_ID_BYTES, MAX_WIRE_MESSAGE_BYTES,
};
use crate::RelayConfig;

const MAX_MESSAGES_PER_CONNECTION: usize = 16 * 1_024 + 64;
const MAX_WORK_UNITS_PER_CONNECTION: u32 = 256;
const READBACK_IDS_PER_WORK_UNIT: usize = 8;
const MAX_OUTBOUND_EVENT_BYTES: u64 =
    (MAX_EVENT_MESSAGE_BYTES + 2 * MAX_SUBSCRIPTION_ID_BYTES + 32) as u64;
/// Wire-level upper bound for one worst-case legal bounded ID readback.
pub const MAX_LEGAL_READBACK_EGRESS_BYTES: u64 =
    MAX_READBACK_IDS as u64 * MAX_OUTBOUND_EVENT_BYTES + MAX_WIRE_MESSAGE_BYTES as u64;

struct ServerState {
    store: Arc<Mutex<DirectoryStore>>,
    directory_pubkey: [u8; 32],
    lane: RelayLane,
    operation_slots: Arc<Semaphore>,
    global_operation_slots: Arc<Semaphore>,
    operation_timeout: Duration,
    egress_timeout: Duration,
    max_egress_bytes_per_connection: u64,
    rate_gate: RateGate,
    global_rate_gate: Arc<RateGate>,
    egress_rate_gate: ByteRateGate,
    global_egress_rate_gate: Arc<ByteRateGate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelayLane {
    Public,
    Publisher,
}

struct RateGate {
    limit: u32,
    state: Mutex<RateWindow>,
}

struct RateWindow {
    started: Instant,
    count: u32,
}

struct ByteRateGate {
    limit: u64,
    state: Mutex<ByteRateWindow>,
}

struct ByteRateWindow {
    started: Instant,
    bytes: u64,
}

struct ConnectionEgressBudget {
    remaining: u64,
}

struct ConnectionWorkBudget {
    remaining: u32,
}

enum IngestOperationError {
    NotStarted,
    OutcomeUnavailable,
}

impl RateGate {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            state: Mutex::new(RateWindow {
                started: Instant::now(),
                count: 0,
            }),
        }
    }

    fn admit(&self, cost: u32) -> bool {
        if cost == 0 {
            return true;
        }
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.started.elapsed() >= Duration::from_secs(1) {
            state.started = Instant::now();
            state.count = 0;
        }
        let Some(next) = state.count.checked_add(cost) else {
            return false;
        };
        if next > self.limit {
            return false;
        }
        state.count = next;
        true
    }
}

impl ByteRateGate {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            state: Mutex::new(ByteRateWindow {
                started: Instant::now(),
                bytes: 0,
            }),
        }
    }

    async fn wait_for_capacity(&self, bytes: u64) -> Result<(), String> {
        if bytes > self.limit {
            return Err("single egress frame exceeds the configured byte rate".to_owned());
        }
        loop {
            let delay = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| "directory egress byte limiter poisoned".to_owned())?;
                let elapsed = state.started.elapsed();
                if elapsed >= Duration::from_secs(1) {
                    state.started = Instant::now();
                    state.bytes = 0;
                }
                if state.bytes.saturating_add(bytes) <= self.limit {
                    state.bytes += bytes;
                    None
                } else {
                    Some(Duration::from_secs(1).saturating_sub(elapsed))
                }
            };
            let Some(delay) = delay else {
                return Ok(());
            };
            tokio::time::sleep(delay.max(Duration::from_millis(1))).await;
        }
    }
}

impl ConnectionEgressBudget {
    fn new(limit: u64) -> Self {
        Self { remaining: limit }
    }

    fn reserve(&mut self, bytes: usize) -> Result<(), String> {
        let bytes = u64::try_from(bytes).map_err(|_| "egress byte count overflow".to_owned())?;
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(|| "connection egress byte budget exhausted".to_owned())?;
        Ok(())
    }
}

impl ConnectionWorkBudget {
    fn new(limit: u32) -> Self {
        Self { remaining: limit }
    }

    fn reserve(&mut self, cost: u32) -> Result<(), String> {
        self.remaining = self
            .remaining
            .checked_sub(cost)
            .ok_or_else(|| "connection work budget exhausted".to_owned())?;
        Ok(())
    }
}

fn request_work_units(filter: &RequestFilter) -> u32 {
    match filter {
        RequestFilter::Catalog { .. } => 1,
        RequestFilter::Ids(ids) => {
            let units = ids.len().div_ceil(READBACK_IDS_PER_WORK_UNIT);
            u32::try_from(units).unwrap_or(u32::MAX).max(1)
        }
    }
}

fn admit_rate(state: &ServerState, cost: u32) -> bool {
    // Lane admission is deliberately first. A public reader cannot consume a
    // global unit until it has stayed within the public reservation.
    state.rate_gate.admit(cost) && state.global_rate_gate.admit(cost)
}

pub struct RelayHandle {
    public_addr: SocketAddr,
    publisher_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    store_interrupt: Arc<InterruptHandle>,
    task: JoinHandle<Result<(), String>>,
}

impl RelayHandle {
    pub fn public_addr(&self) -> SocketAddr {
        self.public_addr
    }

    pub fn publisher_addr(&self) -> SocketAddr {
        self.publisher_addr
    }

    pub async fn shutdown(self) -> Result<(), String> {
        let _ = self.shutdown.send(true);
        // sqlite3_interrupt is safe across threads. It makes a current long
        // query/transaction return instead of leaving shutdown to wait on an
        // invisible spawn_blocking worker. A write either returns its durable
        // outcome or the connection closes without an acknowledgement.
        self.store_interrupt.interrupt();
        self.task
            .await
            .map_err(|error| format!("directory relay task failed: {error}"))?
    }
}

pub async fn run(config: RelayConfig) -> Result<(), String> {
    let handle = start(config).await?;
    log::info!("BitcoinPIR directory-profile relay ready on loopback; limits are active");
    wait_for_shutdown_signal().await?;
    handle.shutdown().await
}

pub async fn start(config: RelayConfig) -> Result<RelayHandle, String> {
    if !config.public_listen.ip().is_loopback()
        || !config.publisher_listen.ip().is_loopback()
        || config.public_listen == config.publisher_listen
    {
        return Err("directory relay refused invalid public/publisher binds".to_owned());
    }
    let now = now_unix()?;
    let path = config.database.clone();
    let key = config.directory_pubkey;
    let limits = StoreLimits {
        max_archive_events: config.max_archive_events,
        max_archive_bytes: config.max_archive_bytes,
    };
    let store = tokio::task::spawn_blocking(move || {
        DirectoryStore::open_or_create(&path, key, limits, now)
    })
    .await
    .map_err(|error| format!("directory relay startup worker failed: {error}"))??;
    let store_interrupt = Arc::new(store.interrupt_handle());
    let public_listener = TcpListener::bind(config.public_listen)
        .await
        .map_err(|error| format!("bind directory public loopback socket failed: {error}"))?;
    let public_addr = public_listener
        .local_addr()
        .map_err(|error| format!("read directory public socket address failed: {error}"))?;
    let publisher_listener = TcpListener::bind(config.publisher_listen)
        .await
        .map_err(|error| format!("bind directory publisher loopback socket failed: {error}"))?;
    let publisher_addr = publisher_listener
        .local_addr()
        .map_err(|error| format!("read directory publisher socket address failed: {error}"))?;
    if !public_addr.ip().is_loopback()
        || !publisher_addr.ip().is_loopback()
        || public_addr == publisher_addr
    {
        return Err("bound directory relay sockets are not distinct loopback addresses".to_owned());
    }
    let store = Arc::new(Mutex::new(store));
    let global_operation_slots = Arc::new(Semaphore::new(config.max_in_flight_operations));
    let global_rate_gate = Arc::new(RateGate::new(config.max_operations_per_second));
    let global_egress_rate_gate = Arc::new(ByteRateGate::new(config.max_egress_bytes_per_second));
    let public_state = Arc::new(ServerState {
        store: store.clone(),
        directory_pubkey: config.directory_pubkey,
        lane: RelayLane::Public,
        operation_slots: Arc::new(Semaphore::new(config.max_public_in_flight_operations)),
        global_operation_slots: global_operation_slots.clone(),
        operation_timeout: config.operation_timeout,
        egress_timeout: config.egress_timeout,
        max_egress_bytes_per_connection: config.max_egress_bytes_per_connection,
        rate_gate: RateGate::new(config.max_public_operations_per_second),
        global_rate_gate: global_rate_gate.clone(),
        egress_rate_gate: ByteRateGate::new(config.max_public_egress_bytes_per_second),
        global_egress_rate_gate: global_egress_rate_gate.clone(),
    });
    let publisher_state = Arc::new(ServerState {
        store,
        directory_pubkey: config.directory_pubkey,
        lane: RelayLane::Publisher,
        operation_slots: Arc::new(Semaphore::new(config.max_publisher_in_flight_operations)),
        global_operation_slots,
        operation_timeout: config.operation_timeout,
        egress_timeout: config.egress_timeout,
        max_egress_bytes_per_connection: config.max_egress_bytes_per_connection,
        rate_gate: RateGate::new(config.max_publisher_operations_per_second),
        global_rate_gate,
        egress_rate_gate: ByteRateGate::new(config.max_publisher_egress_bytes_per_second),
        global_egress_rate_gate,
    });
    let global_connection_slots = Arc::new(Semaphore::new(config.max_connections));
    let public_connection_slots = Arc::new(Semaphore::new(config.max_public_connections));
    let publisher_connection_slots = Arc::new(Semaphore::new(config.max_publisher_connections));
    let connection_timeouts = ConnectionTimeouts {
        handshake: config.handshake_timeout,
        idle: config.idle_timeout,
        lifetime: config.connection_timeout,
    };
    let public_admission = ListenerAdmission {
        lane_slots: public_connection_slots,
        global_slots: global_connection_slots.clone(),
        timeouts: connection_timeouts,
    };
    let publisher_admission = ListenerAdmission {
        lane_slots: publisher_connection_slots,
        global_slots: global_connection_slots,
        timeouts: connection_timeouts,
    };
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        let mut listeners = JoinSet::new();
        listeners.spawn(serve(
            public_listener,
            public_state,
            public_admission,
            shutdown_rx.clone(),
        ));
        listeners.spawn(serve(
            publisher_listener,
            publisher_state,
            publisher_admission,
            shutdown_rx,
        ));
        let mut first_error = None;
        while let Some(result) = listeners.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    let _ = task_shutdown.send(true);
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(format!("directory listener task failed: {error}"));
                    }
                    let _ = task_shutdown.send(true);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    });
    Ok(RelayHandle {
        public_addr,
        publisher_addr,
        shutdown,
        store_interrupt,
        task,
    })
}

#[derive(Clone, Copy)]
struct ConnectionTimeouts {
    handshake: Duration,
    idle: Duration,
    lifetime: Duration,
}

struct ListenerAdmission {
    lane_slots: Arc<Semaphore>,
    global_slots: Arc<Semaphore>,
    timeouts: ConnectionTimeouts,
}

async fn serve(
    listener: TcpListener,
    state: Arc<ServerState>,
    admission: ListenerAdmission,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), String> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) {
                    log::warn!("directory_relay_connection_task_failed");
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted
                    .map_err(|error| format!("accept directory relay connection failed: {error}"))?;
                if !peer.ip().is_loopback() {
                    log::warn!("directory_relay_non_loopback_peer_rejected");
                    drop(stream);
                    continue;
                }
                // Acquire the lane reservation before the global slot. Since
                // configured lane maxima exactly partition the global maximum,
                // one lane can never wait on the other while holding global work.
                let Ok(lane_permit) = admission.lane_slots.clone().try_acquire_owned() else {
                    log::warn!("directory_relay_connection_capacity_rejected");
                    drop(stream);
                    continue;
                };
                let Ok(global_permit) = admission.global_slots.clone().try_acquire_owned() else {
                    log::warn!("directory_relay_global_connection_capacity_rejected");
                    drop(stream);
                    continue;
                };
                let state = state.clone();
                let connection_shutdown = shutdown.clone();
                let timeouts = admission.timeouts;
                connections.spawn(async move {
                    if handle_connection(
                        stream,
                        state,
                        lane_permit,
                        global_permit,
                        timeouts,
                        connection_shutdown,
                    )
                    .await
                    .is_err()
                    {
                        log::warn!("directory_relay_connection_failed");
                    }
                });
            }
        }
    }
    // Stop accepting first, signal is already visible to every connection,
    // then drain them. Started SQLite operations are not detached or cancelled.
    while let Some(result) = connections.join_next().await {
        if result.is_err() {
            log::warn!("directory_relay_connection_task_failed");
        }
    }
    Ok(())
}

async fn handle_connection(
    stream: TcpStream,
    state: Arc<ServerState>,
    _lane_connection_permit: OwnedSemaphorePermit,
    _global_connection_permit: OwnedSemaphorePermit,
    timeouts: ConnectionTimeouts,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), String> {
    let connection_deadline = Instant::now() + timeouts.lifetime;
    let websocket_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_WIRE_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_WIRE_MESSAGE_BYTES))
        .max_write_buffer_size(MAX_WIRE_MESSAGE_BYTES * 2);
    let mut websocket = tokio::time::timeout(
        timeouts.handshake,
        tokio_tungstenite::accept_async_with_config(stream, Some(websocket_config)),
    )
    .await
    .map_err(|_| "WebSocket handshake timeout".to_owned())?
    .map_err(|_| "WebSocket handshake rejected".to_owned())?;

    let mut subscriptions = BTreeSet::new();
    let mut egress_budget = ConnectionEgressBudget::new(state.max_egress_bytes_per_connection);
    let mut work_budget = ConnectionWorkBudget::new(MAX_WORK_UNITS_PER_CONNECTION);
    let mut message_count = 0usize;
    loop {
        let remaining = connection_deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| "WebSocket connection lifetime exceeded".to_owned())?;
        let receive_timeout = timeouts.idle.min(remaining);
        let next = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            next = tokio::time::timeout(receive_timeout, websocket.next()) => {
                next.map_err(|_| "WebSocket idle or connection timeout".to_owned())?
            }
        };
        let Some(message) = next else {
            return Ok(());
        };
        let message = message.map_err(|_| "WebSocket receive failed".to_owned())?;
        let Message::Text(text) = message else {
            if matches!(message, Message::Close(_)) {
                return Ok(());
            }
            // No binary protocol, live heartbeat, AUTH, NOTICE, or active Pong path.
            return Err("non-text WebSocket message rejected".to_owned());
        };
        message_count += 1;
        if message_count > MAX_MESSAGES_PER_CONNECTION {
            return Err("connection message bound exceeded".to_owned());
        }
        let bytes = text.as_str().as_bytes();
        match state.lane {
            RelayLane::Public if best_effort_event_id(bytes).is_some() => {
                // This signed event may already be durable from a private
                // publish whose ACK was lost. Do not contradict it with a
                // negative acknowledgement from the public lane.
                return Err("EVENT rejected on public directory lane".to_owned());
            }
            RelayLane::Publisher if best_effort_event_id(bytes).is_none() => {
                return Err("non-EVENT rejected on directory publisher lane".to_owned());
            }
            RelayLane::Public | RelayLane::Publisher => {}
        }
        work_budget.reserve(1)?;
        if !admit_rate(&state, 1) {
            // A syntactically recognizable EVENT may be a retry whose durable
            // positive OK was lost. Without consulting the archive, a negative
            // ACK would contradict that committed state. Close without any ACK
            // and let the publisher retry idempotently on a fresh connection.
            if best_effort_event_id(bytes).is_some() {
                return Err("EVENT rate-limited without acknowledgement".to_owned());
            }
            if !send_bounded_rejection(
                &mut websocket,
                bytes,
                "rate-limited: coarse relay limit",
                &state,
                &mut egress_budget,
            )
            .await?
            {
                return Err("rate-limited message had no safe rejection envelope".to_owned());
            }
            continue;
        }
        let now = now_unix()?;
        let message = match parse_client_message(bytes, &state.directory_pubkey, now) {
            Ok(message) => message,
            Err(_) => {
                if !send_bounded_rejection(
                    &mut websocket,
                    bytes,
                    "invalid: outside relay profile",
                    &state,
                    &mut egress_budget,
                )
                .await?
                {
                    return Err("invalid message had no safe rejection envelope".to_owned());
                }
                continue;
            }
        };
        if !matches!(
            (state.lane, &message),
            (RelayLane::Public, ClientMessage::Req { .. })
                | (RelayLane::Public, ClientMessage::Close { .. })
                | (RelayLane::Publisher, ClientMessage::Event(_))
        ) {
            return Err("message rejected on wrong directory lane".to_owned());
        }
        match message {
            ClientMessage::Event(event) => {
                let event_id = *event.event.id();
                let response = match ingest_operation(state.clone(), *event, now).await {
                    Ok(IngestDisposition::Saved) => {
                        ok_message(&event_id, true, "saved: durable commit complete")
                    }
                    Ok(IngestDisposition::Duplicate) => ok_message(
                        &event_id,
                        true,
                        "duplicate: durable archive already contains event",
                    ),
                    Ok(IngestDisposition::ReplacedByNewer) => ok_message(
                        &event_id,
                        false,
                        "replaced: newer addressable event retained",
                    ),
                    Ok(IngestDisposition::ShardCapacityExceeded) => {
                        ok_message(&event_id, false, "blocked: shard capacity exceeded")
                    }
                    Ok(IngestDisposition::ArchiveCapacityExceeded) => ok_message(
                        &event_id,
                        false,
                        "blocked: immutable archive capacity exceeded",
                    ),
                    Ok(IngestDisposition::InvalidCurrentEvent) => ok_message(
                        &event_id,
                        false,
                        "invalid: event is not current directory profile",
                    ),
                    Err(IngestOperationError::NotStarted) => {
                        log::warn!("directory_relay_event_store_failed");
                        return Err("EVENT operation did not start; no acknowledgement".to_owned());
                    }
                    Err(IngestOperationError::OutcomeUnavailable) => {
                        // A started SQLite transaction may have committed even if its
                        // final outcome could not be returned. Never emit a negative
                        // acknowledgement that could race a late durable commit.
                        log::warn!("directory_relay_event_outcome_unavailable");
                        return Err("EVENT durable outcome unavailable".to_owned());
                    }
                };
                send_text(&mut websocket, response, &state, &mut egress_budget).await?;
            }
            ClientMessage::Req {
                subscription_id,
                filter,
            } => {
                let additional_work = request_work_units(&filter).saturating_sub(1);
                if work_budget.reserve(additional_work).is_err()
                    || !admit_rate(&state, additional_work)
                {
                    let closed = closed_message(&subscription_id, "rate-limited: bounded REQ work");
                    send_text(&mut websocket, closed, &state, &mut egress_budget).await?;
                    continue;
                }
                if !subscriptions.insert(subscription_id.clone()) {
                    let closed =
                        closed_message(&subscription_id, "duplicate: subscription id in use");
                    send_text(&mut websocket, closed, &state, &mut egress_budget).await?;
                    continue;
                }
                let snapshot = match freeze_snapshot_operation(state.clone(), filter).await {
                    Ok(snapshot) => snapshot,
                    Err(_) => {
                        log::warn!("directory_relay_snapshot_failed");
                        let closed =
                            closed_message(&subscription_id, "error: bounded snapshot unavailable");
                        send_text(&mut websocket, closed, &state, &mut egress_budget).await?;
                        continue;
                    }
                };
                send_snapshot(
                    &mut websocket,
                    &subscription_id,
                    snapshot,
                    state.clone(),
                    &mut egress_budget,
                )
                .await?;
            }
            ClientMessage::Close { subscription_id } => {
                subscriptions.remove(&subscription_id);
            }
        }
    }
}

async fn ingest_operation(
    state: Arc<ServerState>,
    event: ValidatedEvent,
    received_at: u64,
) -> Result<IngestDisposition, IngestOperationError> {
    let permits = acquire_operation_permits(&state)
        .await
        .map_err(|_| IngestOperationError::NotStarted)?;
    let store = state.store.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _permits = permits;
        let mut store = store
            .lock()
            .map_err(|_| "directory store lock poisoned".to_owned())?;
        store.ingest(&event, received_at)
    });
    // Do not apply an acknowledgement timeout after the mutating operation has
    // started. Dropping a spawn_blocking JoinHandle does not cancel SQLite and
    // could otherwise produce OK=false followed by a late COMMIT.
    task.await
        .map_err(|_| IngestOperationError::OutcomeUnavailable)?
        .map_err(|_| IngestOperationError::OutcomeUnavailable)
}

async fn freeze_snapshot_operation(
    state: Arc<ServerState>,
    filter: RequestFilter,
) -> Result<SnapshotPlan, String> {
    let permits = acquire_operation_permits(&state).await?;
    let store = state.store.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _permits = permits;
        let store = store
            .lock()
            .map_err(|_| "directory store lock poisoned".to_owned())?;
        store.freeze_snapshot(&filter)
    });
    // Once a SQLite read starts, await its bounded result. Dropping a
    // spawn_blocking handle on timeout would not cancel the worker and could
    // leave it holding the single store mutex invisibly.
    task.await
        .map_err(|_| "directory snapshot worker failed".to_owned())?
}

async fn load_snapshot_page_operation(
    state: Arc<ServerState>,
    ids: Vec<[u8; 32]>,
) -> Result<Vec<Vec<u8>>, String> {
    let permits = acquire_operation_permits(&state).await?;
    let store = state.store.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _permits = permits;
        let store = store
            .lock()
            .map_err(|_| "directory store lock poisoned".to_owned())?;
        store.load_snapshot_page(&ids)
    });
    task.await
        .map_err(|_| "directory snapshot page worker failed".to_owned())?
}

async fn acquire_operation_permits(
    state: &ServerState,
) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), String> {
    let lane = tokio::time::timeout(
        state.operation_timeout,
        state.operation_slots.clone().acquire_owned(),
    )
    .await
    .map_err(|_| "directory lane operation queue timeout".to_owned())?
    .map_err(|_| "directory lane operation limiter closed".to_owned())?;
    let global = tokio::time::timeout(
        state.operation_timeout,
        state.global_operation_slots.clone().acquire_owned(),
    )
    .await
    .map_err(|_| "directory global operation queue timeout".to_owned())?
    .map_err(|_| "directory global operation limiter closed".to_owned())?;
    Ok((lane, global))
}

async fn send_snapshot<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    subscription_id: &str,
    snapshot: SnapshotPlan,
    state: Arc<ServerState>,
    egress_budget: &mut ConnectionEgressBudget,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let subscription_bytes = serde_json::to_string(subscription_id)
        .map_err(|_| "serialize subscription id failed".to_owned())?
        .len();
    let per_event_envelope = u64::try_from(subscription_bytes + 11)
        .map_err(|_| "snapshot envelope byte count overflow".to_owned())?;
    let event_count = u64::try_from(snapshot.event_ids.len())
        .map_err(|_| "snapshot event count overflow".to_owned())?;
    let response_bytes = snapshot
        .event_json_bytes
        .checked_add(
            per_event_envelope
                .checked_mul(event_count)
                .ok_or_else(|| "snapshot envelope byte count overflow".to_owned())?,
        )
        .and_then(|bytes| bytes.checked_add(eose_message(subscription_id).len() as u64))
        .ok_or_else(|| "snapshot response byte count overflow".to_owned())?;
    // Reserve the exact complete response before the first EVENT. A request
    // that exceeds the cumulative budget closes without leaking a prefix.
    egress_budget.reserve(
        usize::try_from(response_bytes)
            .map_err(|_| "snapshot response exceeds platform byte range".to_owned())?,
    )?;
    for ids in snapshot.event_ids.chunks(8) {
        let events = load_snapshot_page_operation(state.clone(), ids.to_vec()).await?;
        if events.len() != ids.len() {
            return Err("frozen snapshot page is incomplete".to_owned());
        }
        for event in events {
            let message = event_message(subscription_id, &event)?;
            send_text_reserved(websocket, message, &state).await?;
        }
    }
    send_text_reserved(websocket, eose_message(subscription_id), &state).await
}

async fn send_text<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    text: String,
    state: &ServerState,
    egress_budget: &mut ConnectionEgressBudget,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    egress_budget.reserve(text.len())?;
    send_text_reserved(websocket, text, state).await
}

async fn send_text_reserved<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    text: String,
    state: &ServerState,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let bytes = u64::try_from(text.len()).map_err(|_| "egress byte count overflow".to_owned())?;
    tokio::time::timeout(state.egress_timeout, async {
        state.egress_rate_gate.wait_for_capacity(bytes).await?;
        state
            .global_egress_rate_gate
            .wait_for_capacity(bytes)
            .await?;
        websocket
            .send(Message::Text(text.into()))
            .await
            .map_err(|_| "WebSocket egress failed".to_owned())
    })
    .await
    .map_err(|_| "WebSocket egress timeout".to_owned())?
}

async fn send_bounded_rejection<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    bytes: &[u8],
    reason: &str,
    state: &ServerState,
    egress_budget: &mut ConnectionEgressBudget,
) -> Result<bool, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let response = if let Some(event_id) = best_effort_event_id(bytes) {
        Some(ok_message_hex(&event_id, false, reason))
    } else {
        best_effort_subscription_id(bytes).map(|id| closed_message(&id, reason))
    };
    if let Some(response) = response {
        send_text(websocket, response, state, egress_budget).await?;
        return Ok(true);
    }
    Ok(false)
}

fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_owned())
        .map(|duration| duration.as_secs())
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> Result<(), String> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| format!("install SIGTERM handler failed: {error}"))?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map_err(|error| format!("wait for Ctrl-C failed: {error}")),
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> Result<(), String> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|error| format!("wait for Ctrl-C failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use pir_directory_nostr::{
        catalog_req_json_v1, verify_directory_entry_event_v1, DirectoryEntryV1,
        DirectoryHealthClassV1, DirectoryHealthV1, DirectoryPublisherKeyV1, NostrEventV1,
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

    fn test_config(database: std::path::PathBuf, key: [u8; 32]) -> RelayConfig {
        RelayConfig {
            public_listen: "127.0.0.1:0".parse().unwrap(),
            publisher_listen: "127.0.0.2:0".parse().unwrap(),
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
}
