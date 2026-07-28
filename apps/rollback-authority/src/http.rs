use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use pir_rollback_authority_protocol::{
    AuthorityServerSignerV1, MAX_SIGNED_AUTHORITY_REQUEST_BYTES_V1,
    MAX_SIGNED_AUTHORITY_RESPONSE_BYTES_V1, SIGNED_AUTHORITY_CAS_REQUEST_BYTES_V1,
    SIGNED_AUTHORITY_INITIALIZE_REQUEST_BYTES_V1, SIGNED_AUTHORITY_READ_REQUEST_BYTES_V1,
};
use pir_rollback_authority_store::{RollbackAuthorityStoreErrorV1, SqliteRollbackAuthorityStoreV1};
use zeroize::Zeroizing;

pub const AUTHORITY_CALL_PATH_V1: &str = "/v1/rollback-authority/calls";
pub const AUTHORITY_CALL_MEDIA_TYPE_V1: &str =
    "application/vnd.bitcoinpir.rollback-authority-request-v1";
pub const AUTHORITY_RESPONSE_MEDIA_TYPE_V1: &str =
    "application/vnd.bitcoinpir.rollback-authority-response-v1";

const PROBLEM_MEDIA_TYPE_V1: &str = "application/problem+json";
pub(crate) const AUTHORITY_ACCEPT_VALUE_V1: &str =
    "application/vnd.bitcoinpir.rollback-authority-response-v1, application/problem+json";
pub(crate) const STRICT_CLIENT_USER_AGENT_V1: &str = "BitcoinPIR-service-admission/1";
const MAX_HEADER_BYTES_V1: usize = 8 * 1024;
const MAX_HEADERS_V1: usize = 16;
const READ_CHUNK_BYTES_V1: usize = 2 * 1024;
pub(crate) const MAX_ADMITTED_CONNECTIONS_V1: usize = 256;
pub(crate) const MAX_WORKER_THREADS_V1: usize = 16;

const INVALID_REQUEST_BODY_V1: &[u8] = br#"{"code":"invalid_request"}"#;
const METHOD_NOT_ALLOWED_BODY_V1: &[u8] = br#"{"code":"method_not_allowed"}"#;
const NOT_FOUND_BODY_V1: &[u8] = br#"{"code":"not_found"}"#;
const REQUEST_REJECTED_BODY_V1: &[u8] = br#"{"code":"request_rejected"}"#;
const SERVICE_UNAVAILABLE_BODY_V1: &[u8] = br#"{"code":"service_unavailable"}"#;

const _: () =
    assert!(SIGNED_AUTHORITY_READ_REQUEST_BYTES_V1 <= MAX_SIGNED_AUTHORITY_REQUEST_BYTES_V1);
const _: () =
    assert!(SIGNED_AUTHORITY_INITIALIZE_REQUEST_BYTES_V1 <= MAX_SIGNED_AUTHORITY_REQUEST_BYTES_V1);
const _: () =
    assert!(SIGNED_AUTHORITY_CAS_REQUEST_BYTES_V1 <= MAX_SIGNED_AUTHORITY_REQUEST_BYTES_V1);

pub(crate) struct AuthorityHttpStateV1 {
    store: SqliteRollbackAuthorityStoreV1,
    signer: AuthorityServerSignerV1,
    io_timeout: Duration,
}

impl AuthorityHttpStateV1 {
    pub(crate) fn new(
        store: SqliteRollbackAuthorityStoreV1,
        signer: AuthorityServerSignerV1,
        io_timeout: Duration,
    ) -> Self {
        Self {
            store,
            signer,
            io_timeout,
        }
    }
}

pub(crate) fn serve_loopback_v1(
    bind: SocketAddr,
    store: SqliteRollbackAuthorityStoreV1,
    signer: AuthorityServerSignerV1,
    max_connections: usize,
    io_timeout: Duration,
) -> Result<(), String> {
    if !bind.ip().is_loopback() {
        return Err("rollback authority listener requires a loopback bind".to_owned());
    }
    if !(1..=MAX_ADMITTED_CONNECTIONS_V1).contains(&max_connections) {
        return Err("rollback authority connection limit must be in 1..=256".to_owned());
    }
    let listener = TcpListener::bind(bind)
        .map_err(|_| "bind rollback authority loopback listener failed".to_owned())?;
    let local = listener
        .local_addr()
        .map_err(|_| "inspect rollback authority listener failed".to_owned())?;
    if !local.ip().is_loopback() {
        return Err("rollback authority listener resolved outside loopback".to_owned());
    }

    let state = Arc::new(AuthorityHttpStateV1::new(store, signer, io_timeout));
    let limiter = Arc::new(ConnectionLimiterV1::new(max_connections));
    let work_sender = spawn_worker_pool_v1(
        Arc::clone(&state),
        worker_count_for_limit_v1(max_connections),
        max_connections,
    )?;
    println!("rollback-authority-listening={local}");
    loop {
        // Intentionally discard the peer address. This process emits no
        // request, namespace, key, protocol-body, or client-address logs.
        let (stream, _) = listener
            .accept()
            .map_err(|_| "rollback authority listener accept failed".to_owned())?;
        let Some(permit) = limiter.try_acquire() else {
            // Never let a non-reading overload connection block the single
            // accept loop while it synchronously writes an unsigned 503. The
            // caller conservatively treats a close after possible send as an
            // unknown outcome and reconciles with a fresh authenticated Read.
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        };
        let work = ConnectionWorkV1 {
            stream,
            _permit: permit,
        };
        match work_sender.try_send(work) {
            Ok(()) => {}
            Err(TrySendError::Full(work)) => {
                let _ = work.stream.shutdown(Shutdown::Both);
            }
            Err(TrySendError::Disconnected(work)) => {
                let _ = work.stream.shutdown(Shutdown::Both);
                return Err("rollback authority worker pool stopped".to_owned());
            }
        }
    }
}

pub(crate) fn worker_count_for_limit_v1(max_connections: usize) -> usize {
    max_connections.min(MAX_WORKER_THREADS_V1)
}

struct ConnectionWorkV1 {
    stream: TcpStream,
    _permit: ConnectionPermitV1,
}

fn spawn_worker_pool_v1(
    state: Arc<AuthorityHttpStateV1>,
    worker_count: usize,
    queue_capacity: usize,
) -> Result<SyncSender<ConnectionWorkV1>, String> {
    if worker_count == 0 || queue_capacity == 0 {
        return Err("rollback authority worker-pool bounds must be nonzero".to_owned());
    }
    let (sender, receiver) = mpsc::sync_channel(queue_capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..worker_count {
        let worker_state = Arc::clone(&state);
        let worker_receiver = Arc::clone(&receiver);
        thread::Builder::new()
            .name(format!("rollback-authority-worker-{index}"))
            .spawn(move || worker_loop_v1(&worker_receiver, &worker_state))
            .map_err(|_| "spawn rollback authority worker pool failed".to_owned())?;
    }
    Ok(sender)
}

fn worker_loop_v1(receiver: &Mutex<Receiver<ConnectionWorkV1>>, state: &AuthorityHttpStateV1) {
    loop {
        let work = {
            let Ok(receiver) = receiver.lock() else {
                return;
            };
            receiver.recv()
        };
        let Ok(work) = work else {
            return;
        };
        handle_connection_v1(work.stream, state);
    }
}

pub(crate) fn handle_connection_v1(mut stream: TcpStream, state: &AuthorityHttpStateV1) {
    let _ = stream.set_nodelay(true);
    let outcome = read_request_v1(&mut stream, state.io_timeout).and_then(|request| {
        state
            .store
            .handle_signed_request(&request.body, &state.signer)
            .map_err(map_store_error_v1)
    });
    match outcome {
        Ok(response) => {
            let bytes = response.into_bytes();
            if bytes.len() <= MAX_SIGNED_AUTHORITY_RESPONSE_BYTES_V1 {
                let _ = write_response_v1(
                    &mut stream,
                    200,
                    "OK",
                    AUTHORITY_RESPONSE_MEDIA_TYPE_V1,
                    &bytes,
                    state.io_timeout,
                );
            } else {
                let _ = write_problem_v1(
                    &mut stream,
                    HttpRejectionV1::ServiceUnavailable,
                    state.io_timeout,
                );
            }
        }
        Err(rejection) => {
            let _ = write_problem_v1(&mut stream, rejection, state.io_timeout);
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

struct ParsedAuthorityRequestV1 {
    body: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpRejectionV1 {
    InvalidRequest,
    MethodNotAllowed,
    NotFound,
    RequestRejected,
    ServiceUnavailable,
}

fn map_store_error_v1(error: RollbackAuthorityStoreErrorV1) -> HttpRejectionV1 {
    match error {
        RollbackAuthorityStoreErrorV1::MalformedRequest => HttpRejectionV1::InvalidRequest,
        RollbackAuthorityStoreErrorV1::RequestRejected
        | RollbackAuthorityStoreErrorV1::OperationReplayMismatch => {
            HttpRejectionV1::RequestRejected
        }
        RollbackAuthorityStoreErrorV1::InvalidConfiguration
        | RollbackAuthorityStoreErrorV1::DatabaseAlreadyExists
        | RollbackAuthorityStoreErrorV1::MissingDatabase
        | RollbackAuthorityStoreErrorV1::UnsafeDatabasePath
        | RollbackAuthorityStoreErrorV1::SchemaMismatch
        | RollbackAuthorityStoreErrorV1::AuthorityInstanceMismatch
        | RollbackAuthorityStoreErrorV1::NamespaceRebindRejected
        | RollbackAuthorityStoreErrorV1::OperationCapacityExhausted
        | RollbackAuthorityStoreErrorV1::CallCapacityExhausted
        | RollbackAuthorityStoreErrorV1::StorageFailure
        | RollbackAuthorityStoreErrorV1::ResponseSigningFailure => {
            HttpRejectionV1::ServiceUnavailable
        }
    }
}

fn read_request_v1(
    stream: &mut TcpStream,
    io_timeout: Duration,
) -> Result<ParsedAuthorityRequestV1, HttpRejectionV1> {
    let deadline = Instant::now()
        .checked_add(io_timeout)
        .ok_or(HttpRejectionV1::InvalidRequest)?;
    let mut wire = Zeroizing::new(Vec::with_capacity(
        MAX_HEADER_BYTES_V1 + READ_CHUNK_BYTES_V1,
    ));
    let header_end = loop {
        if wire.len() >= MAX_HEADER_BYTES_V1 {
            return Err(HttpRejectionV1::InvalidRequest);
        }
        let mut chunk = Zeroizing::new([0_u8; READ_CHUNK_BYTES_V1]);
        let remaining = remaining_timeout_v1(deadline)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| HttpRejectionV1::InvalidRequest)?;
        let read = stream
            .read(&mut chunk[..])
            .map_err(|_| HttpRejectionV1::InvalidRequest)?;
        if read == 0 {
            return Err(HttpRejectionV1::InvalidRequest);
        }
        wire.extend_from_slice(&chunk[..read]);
        if let Some(position) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = position + 4;
            if end > MAX_HEADER_BYTES_V1 {
                return Err(HttpRejectionV1::InvalidRequest);
            }
            break end;
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS_V1];
    let mut parsed = httparse::Request::new(&mut headers);
    let parsed_end = match parsed
        .parse(&wire[..header_end])
        .map_err(|_| HttpRejectionV1::InvalidRequest)?
    {
        httparse::Status::Complete(end) => end,
        httparse::Status::Partial => return Err(HttpRejectionV1::InvalidRequest),
    };
    if parsed_end != header_end || parsed.version != Some(1) {
        return Err(HttpRejectionV1::InvalidRequest);
    }
    let method = parsed.method.ok_or(HttpRejectionV1::InvalidRequest)?;
    if method != "POST" {
        return Err(HttpRejectionV1::MethodNotAllowed);
    }
    let path = parsed.path.ok_or(HttpRejectionV1::InvalidRequest)?;
    if !path.is_ascii() || path.contains('?') || path != AUTHORITY_CALL_PATH_V1 {
        return Err(HttpRejectionV1::NotFound);
    }

    let mut host = None;
    let mut content_type = None;
    let mut accept = None;
    let mut content_length = None;
    let mut connection = None;
    let mut user_agent = None;
    for header in parsed.headers.iter() {
        let value =
            std::str::from_utf8(header.value).map_err(|_| HttpRejectionV1::InvalidRequest)?;
        if header.name.eq_ignore_ascii_case("host") {
            set_once_v1(&mut host, value)?;
        } else if header.name.eq_ignore_ascii_case("content-type") {
            set_once_v1(&mut content_type, value)?;
        } else if header.name.eq_ignore_ascii_case("accept") {
            set_once_v1(&mut accept, value)?;
        } else if header.name.eq_ignore_ascii_case("content-length") {
            set_once_v1(&mut content_length, value)?;
        } else if header.name.eq_ignore_ascii_case("connection") {
            set_once_v1(&mut connection, value)?;
        } else if header.name.eq_ignore_ascii_case("user-agent") {
            set_once_v1(&mut user_agent, value)?;
        } else {
            // In particular: no Transfer-Encoding, Expect, Upgrade, Cookie,
            // Authorization, Origin, Forwarded, or X-Forwarded-* surface.
            return Err(HttpRejectionV1::InvalidRequest);
        }
    }
    let host = host.ok_or(HttpRejectionV1::InvalidRequest)?;
    if host.is_empty()
        || host.len() > 255
        || !host.is_ascii()
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(HttpRejectionV1::InvalidRequest);
    }
    if content_type != Some(AUTHORITY_CALL_MEDIA_TYPE_V1)
        || accept != Some(AUTHORITY_ACCEPT_VALUE_V1)
        || connection != Some("close")
        || user_agent != Some(STRICT_CLIENT_USER_AGENT_V1)
    {
        return Err(HttpRejectionV1::InvalidRequest);
    }
    let body_len =
        parse_canonical_content_length_v1(content_length.ok_or(HttpRejectionV1::InvalidRequest)?)?;
    if !matches!(
        body_len,
        SIGNED_AUTHORITY_READ_REQUEST_BYTES_V1
            | SIGNED_AUTHORITY_INITIALIZE_REQUEST_BYTES_V1
            | SIGNED_AUTHORITY_CAS_REQUEST_BYTES_V1
    ) || body_len > MAX_SIGNED_AUTHORITY_REQUEST_BYTES_V1
    {
        return Err(HttpRejectionV1::InvalidRequest);
    }

    let buffered_body_len = wire.len().saturating_sub(header_end);
    if buffered_body_len > body_len {
        return Err(HttpRejectionV1::InvalidRequest);
    }
    let mut body = Zeroizing::new(Vec::with_capacity(body_len));
    body.extend_from_slice(&wire[header_end..]);
    while body.len() < body_len {
        let remaining = remaining_timeout_v1(deadline)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| HttpRejectionV1::InvalidRequest)?;
        let mut chunk = Zeroizing::new([0_u8; READ_CHUNK_BYTES_V1]);
        let maximum = (body_len - body.len()).min(chunk.len());
        let read = stream
            .read(&mut chunk[..maximum])
            .map_err(|_| HttpRejectionV1::InvalidRequest)?;
        if read == 0 {
            return Err(HttpRejectionV1::InvalidRequest);
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(ParsedAuthorityRequestV1 { body })
}

fn set_once_v1<'a>(target: &mut Option<&'a str>, value: &'a str) -> Result<(), HttpRejectionV1> {
    if target.replace(value).is_some() {
        return Err(HttpRejectionV1::InvalidRequest);
    }
    Ok(())
}

fn parse_canonical_content_length_v1(value: &str) -> Result<usize, HttpRejectionV1> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(HttpRejectionV1::InvalidRequest);
    }
    let parsed = value
        .parse::<usize>()
        .map_err(|_| HttpRejectionV1::InvalidRequest)?;
    if parsed.to_string() != value {
        return Err(HttpRejectionV1::InvalidRequest);
    }
    Ok(parsed)
}

fn remaining_timeout_v1(deadline: Instant) -> Result<Duration, HttpRejectionV1> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(HttpRejectionV1::InvalidRequest)
}

fn write_problem_v1(
    stream: &mut TcpStream,
    rejection: HttpRejectionV1,
    io_timeout: Duration,
) -> std::io::Result<()> {
    let (status, reason, body) = match rejection {
        HttpRejectionV1::InvalidRequest => (400, "Bad Request", INVALID_REQUEST_BODY_V1),
        HttpRejectionV1::MethodNotAllowed => {
            (405, "Method Not Allowed", METHOD_NOT_ALLOWED_BODY_V1)
        }
        HttpRejectionV1::NotFound => (404, "Not Found", NOT_FOUND_BODY_V1),
        HttpRejectionV1::RequestRejected => (401, "Unauthorized", REQUEST_REJECTED_BODY_V1),
        HttpRejectionV1::ServiceUnavailable => {
            (503, "Service Unavailable", SERVICE_UNAVAILABLE_BODY_V1)
        }
    };
    write_response_v1(
        stream,
        status,
        reason,
        PROBLEM_MEDIA_TYPE_V1,
        body,
        io_timeout,
    )
}

fn write_response_v1(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    io_timeout: Duration,
) -> std::io::Result<()> {
    stream.set_write_timeout(Some(io_timeout))?;
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

pub(crate) struct ConnectionLimiterV1 {
    active: AtomicUsize,
    maximum: usize,
}

impl ConnectionLimiterV1 {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            maximum,
        }
    }

    pub(crate) fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermitV1> {
        let acquired = self
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.maximum).then_some(active + 1)
            })
            .is_ok();
        if acquired {
            Some(ConnectionPermitV1 {
                limiter: Arc::clone(self),
            })
        } else {
            None
        }
    }
}

pub(crate) struct ConnectionPermitV1 {
    limiter: Arc<ConnectionLimiterV1>,
}

impl Drop for ConnectionPermitV1 {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::AcqRel);
    }
}
