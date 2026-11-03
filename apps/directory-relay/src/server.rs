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

use crate::announcements::{AnnounceDisposition, AnnouncementBoard};
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
    announcements: Arc<Mutex<AnnouncementBoard>>,
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
        RequestFilter::Catalog { .. } | RequestFilter::Announcements => 1,
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
    let announcements = Arc::new(Mutex::new(AnnouncementBoard::default()));
    let global_operation_slots = Arc::new(Semaphore::new(config.max_in_flight_operations));
    let global_rate_gate = Arc::new(RateGate::new(config.max_operations_per_second));
    let global_egress_rate_gate = Arc::new(ByteRateGate::new(config.max_egress_bytes_per_second));
    let public_state = Arc::new(ServerState {
        store: store.clone(),
        announcements: announcements.clone(),
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
        announcements,
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
        if state.lane == RelayLane::Publisher && best_effort_event_id(bytes).is_none() {
            return Err("non-EVENT rejected on directory publisher lane".to_owned());
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
            // An invalid EVENT on the public lane may be a directory event
            // whose private publish is already durable: close without an ACK
            // rather than contradict it.
            Err(_) if state.lane == RelayLane::Public && best_effort_event_id(bytes).is_some() => {
                return Err("invalid EVENT rejected on public directory lane".to_owned());
            }
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
                | (RelayLane::Public, ClientMessage::Announce(_))
                | (RelayLane::Publisher, ClientMessage::Event(_))
        ) {
            return Err("message rejected on wrong directory lane".to_owned());
        }
        match message {
            ClientMessage::Announce(announcement) => {
                let event_id = announcement.event_id;
                let disposition = state
                    .announcements
                    .lock()
                    .map_err(|_| "announcement board lock poisoned".to_owned())?
                    .offer(*announcement, now);
                let response = match disposition {
                    AnnounceDisposition::Saved => {
                        ok_message(&event_id, true, "saved: announcement held")
                    }
                    AnnounceDisposition::Duplicate => {
                        ok_message(&event_id, true, "duplicate: announcement already held")
                    }
                    AnnounceDisposition::ReplacedByNewer => {
                        ok_message(&event_id, false, "replaced: newer announcement retained")
                    }
                    AnnounceDisposition::CapacityExceeded => {
                        ok_message(&event_id, false, "blocked: announcement capacity exceeded")
                    }
                };
                send_text(&mut websocket, response, &state, &mut egress_budget).await?;
            }
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
                if filter == RequestFilter::Announcements {
                    let events = state
                        .announcements
                        .lock()
                        .map_err(|_| "announcement board lock poisoned".to_owned())?
                        .current(now);
                    send_announcements(
                        &mut websocket,
                        &subscription_id,
                        events,
                        &state,
                        &mut egress_budget,
                    )
                    .await?;
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

async fn send_announcements<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    subscription_id: &str,
    events: Vec<Vec<u8>>,
    state: &ServerState,
    egress_budget: &mut ConnectionEgressBudget,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let messages = events
        .iter()
        .map(|event| event_message(subscription_id, event))
        .chain(std::iter::once(Ok(eose_message(subscription_id))))
        .collect::<Result<Vec<_>, _>>()?;
    // Reserve the whole response first, as for a catalog snapshot.
    egress_budget.reserve(messages.iter().map(String::len).sum())?;
    for message in messages {
        send_text_reserved(websocket, message, state).await?;
    }
    Ok(())
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
mod tests;
