//! Closed-world Core Lightning JSON-RPC guard for the BitcoinPIR issuer.
//!
//! The issuer gets a separate Unix socket and can neither reach the custody
//! socket nor select arbitrary CLN methods. Requests and responses are parsed,
//! validated, and reconstructed rather than blindly proxied.

#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::{self, File};
use std::future::Future;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use pir_lightning_backend::{ClnRpcTransportV1, UnixClnRpcSocketPolicyV1, UnixClnRpcTransportV1};
use pir_private_files::reject_extended_acl_v1;
use pir_service_protocol::{
    MAX_BITCOIN_MSAT_V1, MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1, MAX_BOLT11_INVOICE_LEN,
};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::process::Gid;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{self, Instant};
use zeroize::Zeroizing;

const MAX_REQUEST_BYTES_V1: usize = 64 * 1024;
const MAX_RESPONSE_BYTES_V1: usize = 256 * 1024;
const MAX_IN_FLIGHT_V1: usize = 256;
const MAX_INVOICES_PER_MINUTE_V1: u32 = 600;
const MAX_INVOICE_BURST_V1: u32 = 100;
const MAX_INVOICES_PER_RUNTIME_V1: u64 = 100_000;
const TOKEN_MINUTE_NANOS_V1: u128 = 60_000_000_000;
const LISTENER_CHECK_INTERVAL_V1: Duration = Duration::from_secs(1);
const ANONYMOUS_DESCRIPTION_V1: &str = "BitcoinPIR anonymous service capability v1";
const BACKEND_LABEL_PREFIX_V1: &str = "bpir-v1-";
const BACKEND_LABEL_HEX_LEN_V1: usize = 64;

/// Production command-line surface. Numeric identities are explicit so a
/// renamed local account cannot silently change the authority boundary.
#[derive(Parser)]
#[command(name = "bitcoinpir-cln-rpc-guard")]
pub struct Cli {
    /// Guard-created socket exposed only to the configured issuer principal.
    #[arg(long)]
    listen_socket: PathBuf,
    /// Core Lightning's real JSON-RPC socket.
    #[arg(long)]
    upstream_socket: PathBuf,
    /// Effective UID the guard process must run as.
    #[arg(long)]
    guard_uid: u32,
    /// Effective primary GID the guard process must run as.
    #[arg(long)]
    guard_gid: u32,
    /// Exact effective UID accepted on the downstream socket.
    #[arg(long)]
    issuer_uid: u32,
    /// Exact effective primary GID accepted on the downstream socket.
    #[arg(long)]
    issuer_gid: u32,
    /// UID that must own the upstream CLN socket.
    #[arg(long)]
    upstream_expected_uid: u32,
    /// Optional exact group for an upstream mode-0660 socket. Omit only when
    /// the upstream socket is guard-owned and mode 0600.
    #[arg(long)]
    upstream_expected_gid: Option<u32>,
    /// Per-phase wall-clock bound. The upstream transport applies the same
    /// bound to connect, complete request, and complete response.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=30))]
    timeout_seconds: u64,
    /// Maximum simultaneous issuer RPCs; excess connections are closed.
    #[arg(long, default_value_t = 32)]
    max_in_flight: usize,
    /// Root-controlled ceiling applied independently of issuer policy.
    #[arg(long)]
    max_invoice_msat: u64,
    /// Sustained mutating invoice attempts admitted per monotonic minute.
    #[arg(long)]
    max_invoices_per_minute: u32,
    /// Initial token count and bucket capacity. Sustained refill is controlled
    /// by `--max-invoices-per-minute`; this value may not exceed that rate.
    #[arg(long)]
    max_invoice_burst: u32,
    /// Process-generation deadman. Once reached, invoice mutations remain
    /// closed until a trusted operator deliberately restarts the guard.
    #[arg(long)]
    max_invoices_per_runtime: u64,
}

/// Validated immutable runtime policy. It intentionally has no `Debug`
/// implementation so socket paths do not enter structured logs by accident.
pub struct GuardConfig {
    listen_socket: PathBuf,
    upstream_socket: PathBuf,
    guard_uid: u32,
    guard_gid: u32,
    issuer_uid: u32,
    issuer_gid: u32,
    upstream_expected_uid: u32,
    upstream_expected_gid: Option<u32>,
    timeout: Duration,
    max_in_flight: usize,
    max_invoice_msat: u64,
    max_invoices_per_minute: u32,
    max_invoice_burst: u32,
    max_invoices_per_runtime: u64,
}

impl TryFrom<Cli> for GuardConfig {
    type Error = String;

    fn try_from(value: Cli) -> Result<Self, Self::Error> {
        for (name, id) in [
            ("guard UID", value.guard_uid),
            ("guard GID", value.guard_gid),
            ("issuer UID", value.issuer_uid),
            ("issuer GID", value.issuer_gid),
            ("upstream owner UID", value.upstream_expected_uid),
        ] {
            if id == 0 || id == u32::MAX {
                return Err(format!("{name} must be a non-root concrete identity"));
            }
        }
        if value
            .upstream_expected_gid
            .is_some_and(|gid| gid == 0 || gid == u32::MAX)
        {
            return Err("upstream group GID must be a non-root concrete identity".to_owned());
        }
        if !value.listen_socket.is_absolute() || !value.upstream_socket.is_absolute() {
            return Err("both Unix socket paths must be absolute".to_owned());
        }
        if value.listen_socket == value.upstream_socket {
            return Err("downstream and upstream sockets must be different paths".to_owned());
        }
        if value.guard_uid == value.issuer_uid || value.guard_gid == value.issuer_gid {
            return Err("guard and issuer must use distinct UID and primary GID values".to_owned());
        }
        if value.upstream_expected_uid == value.issuer_uid
            || value.upstream_expected_gid == Some(value.issuer_gid)
        {
            return Err(
                "issuer identity must not own or group-access the upstream socket".to_owned(),
            );
        }
        if value.upstream_expected_uid != value.guard_uid && value.upstream_expected_gid.is_none() {
            return Err(
                "a cross-UID upstream socket requires an explicit guard-only group".to_owned(),
            );
        }
        if value
            .upstream_expected_gid
            .is_some_and(|gid| gid != value.guard_gid)
        {
            return Err(
                "the upstream access group must be the pinned guard primary GID".to_owned(),
            );
        }
        if value.timeout_seconds == 0
            || value.timeout_seconds > 30
            || value.max_in_flight == 0
            || value.max_in_flight > MAX_IN_FLIGHT_V1
        {
            return Err(
                "timeout or concurrency limit is outside the fixed safety bound".to_owned(),
            );
        }
        if value.max_invoice_msat == 0 || value.max_invoice_msat > MAX_BITCOIN_MSAT_V1 {
            return Err("invoice amount ceiling is outside the protocol bound".to_owned());
        }
        if value.max_invoices_per_minute == 0
            || value.max_invoices_per_minute > MAX_INVOICES_PER_MINUTE_V1
            || value.max_invoice_burst == 0
            || value.max_invoice_burst > MAX_INVOICE_BURST_V1
            || value.max_invoice_burst > value.max_invoices_per_minute
            || value.max_invoices_per_runtime == 0
            || value.max_invoices_per_runtime > MAX_INVOICES_PER_RUNTIME_V1
        {
            return Err("invoice mutation budget is outside the fixed safety bounds".to_owned());
        }
        Ok(Self {
            listen_socket: value.listen_socket,
            upstream_socket: value.upstream_socket,
            guard_uid: value.guard_uid,
            guard_gid: value.guard_gid,
            issuer_uid: value.issuer_uid,
            issuer_gid: value.issuer_gid,
            upstream_expected_uid: value.upstream_expected_uid,
            upstream_expected_gid: value.upstream_expected_gid,
            timeout: Duration::from_secs(value.timeout_seconds),
            max_in_flight: value.max_in_flight,
            max_invoice_msat: value.max_invoice_msat,
            max_invoices_per_minute: value.max_invoices_per_minute,
            max_invoice_burst: value.max_invoice_burst,
            max_invoices_per_runtime: value.max_invoices_per_runtime,
        })
    }
}

impl GuardConfig {
    fn validate_runtime_identity(&self) -> Result<(), String> {
        let euid = rustix::process::geteuid().as_raw();
        let egid = rustix::process::getegid().as_raw();
        if euid != self.guard_uid || egid != self.guard_gid {
            return Err("effective guard UID/GID does not match the pinned policy".to_owned());
        }
        let supplementary = rustix::process::getgroups()
            .map_err(|_| "read guard supplementary groups failed".to_owned())?;
        let has_group =
            |gid: u32| egid == gid || supplementary.iter().any(|group| group.as_raw() == gid);
        if !has_group(self.issuer_gid) {
            return Err("guard lacks the issuer group needed to publish its socket".to_owned());
        }
        if self
            .upstream_expected_gid
            .is_some_and(|gid| !has_group(gid))
        {
            return Err("guard lacks the group needed to reach the upstream socket".to_owned());
        }
        Ok(())
    }
}

/// Run until SIGINT or SIGTERM, then stop accepting and drain every bounded
/// in-flight call before unlinking the exact listener inode.
pub async fn run(config: GuardConfig) -> Result<(), String> {
    let shutdown = shutdown_signal();
    run_with_shutdown(config, shutdown).await
}

async fn run_with_shutdown<F>(config: GuardConfig, shutdown: F) -> Result<(), String>
where
    F: Future<Output = ()>,
{
    config.validate_runtime_identity()?;
    let upstream_policy = UnixClnRpcSocketPolicyV1 {
        expected_uid: config.upstream_expected_uid,
        expected_gid: config.upstream_expected_gid,
    };
    UnixClnRpcTransportV1::new(
        config.upstream_socket.clone(),
        upstream_policy,
        config.timeout,
    )
    .map_err(|_| "upstream CLN socket failed its ownership boundary".to_owned())?;
    let upstream = Arc::new(ProductionUpstreamV1 {
        socket_path: config.upstream_socket.clone(),
        socket_policy: upstream_policy,
    });
    let runtime_policy = Arc::new(GuardRuntimePolicyV1 {
        max_invoice_msat: config.max_invoice_msat,
        invoice_admission: InvoiceAdmissionV1::new(
            config.max_invoices_per_minute,
            config.max_invoice_burst,
            config.max_invoices_per_runtime,
            std::time::Instant::now(),
        )?,
    });
    let (listener, listener_guard) = create_listener(&config)?;
    let semaphore = Arc::new(Semaphore::new(config.max_in_flight));
    let mut tasks = JoinSet::new();
    let mut check_interval = time::interval(LISTENER_CHECK_INTERVAL_V1);
    check_interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let shutdown = shutdown;
    tokio::pin!(shutdown);
    let fatal = loop {
        tokio::select! {
            _ = &mut shutdown => break None,
            _ = check_interval.tick() => {
                if listener_guard.validate().is_err() {
                    break Some("downstream listener path changed at runtime".to_owned());
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(_) => break Some("accepting the downstream Unix socket failed".to_owned()),
                };
                if listener_guard.validate().is_err() {
                    drop(stream);
                    break Some("downstream listener path changed while accepting".to_owned());
                }
                let credentials = match stream.peer_cred() {
                    Ok(credentials) => credentials,
                    Err(_) => {
                        drop(stream);
                        continue;
                    }
                };
                if !peer_identity_allowed(
                    credentials.uid(),
                    credentials.gid(),
                    config.issuer_uid,
                    config.issuer_gid,
                ) {
                    drop(stream);
                    continue;
                }
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        drop(stream);
                        continue;
                    }
                };
                let upstream = upstream.clone();
                let runtime_policy = runtime_policy.clone();
                let timeout = config.timeout;
                tasks.spawn(async move {
                    serve_connection(stream, upstream, runtime_policy, permit, timeout).await;
                });
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                let _ = joined;
            }
        }
    };
    while tasks.join_next().await.is_some() {}
    drop(listener);
    drop(listener_guard);
    match fatal {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn peer_identity_allowed(
    actual_uid: u32,
    actual_gid: u32,
    expected_uid: u32,
    expected_gid: u32,
) -> bool {
    actual_uid == expected_uid && actual_gid == expected_gid
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        match terminate {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
}

trait GuardUpstreamV1: Send + Sync + 'static {
    fn call(&self, request: &[u8], deadline: std::time::Instant) -> Result<Zeroizing<Vec<u8>>, ()>;
}

struct GuardRuntimePolicyV1 {
    max_invoice_msat: u64,
    invoice_admission: InvoiceAdmissionV1,
}

struct InvoiceAdmissionV1 {
    per_minute: u32,
    burst: u32,
    maximum_per_runtime: u64,
    state: Mutex<InvoiceAdmissionStateV1>,
}

struct InvoiceAdmissionStateV1 {
    token_units: u128,
    admitted: u64,
    updated_at: std::time::Instant,
}

impl InvoiceAdmissionV1 {
    fn new(
        per_minute: u32,
        burst: u32,
        maximum_per_runtime: u64,
        now: std::time::Instant,
    ) -> Result<Self, String> {
        if per_minute == 0
            || per_minute > MAX_INVOICES_PER_MINUTE_V1
            || burst == 0
            || burst > MAX_INVOICE_BURST_V1
            || burst > per_minute
            || maximum_per_runtime == 0
            || maximum_per_runtime > MAX_INVOICES_PER_RUNTIME_V1
        {
            return Err("invoice admission policy is outside its fixed bound".to_owned());
        }
        Ok(Self {
            per_minute,
            burst,
            maximum_per_runtime,
            state: Mutex::new(InvoiceAdmissionStateV1 {
                token_units: u128::from(burst) * TOKEN_MINUTE_NANOS_V1,
                admitted: 0,
                updated_at: now,
            }),
        })
    }

    fn try_admit(&self) -> bool {
        self.try_admit_at(std::time::Instant::now())
    }

    fn try_admit_at(&self, now: std::time::Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let Some(elapsed) = now.checked_duration_since(state.updated_at) else {
            return false;
        };
        let Some(refill) = elapsed.as_nanos().checked_mul(u128::from(self.per_minute)) else {
            return false;
        };
        let capacity = u128::from(self.burst) * TOKEN_MINUTE_NANOS_V1;
        state.token_units = state.token_units.saturating_add(refill).min(capacity);
        state.updated_at = now;
        if state.admitted >= self.maximum_per_runtime || state.token_units < TOKEN_MINUTE_NANOS_V1 {
            return false;
        }
        state.token_units -= TOKEN_MINUTE_NANOS_V1;
        state.admitted += 1;
        true
    }
}

struct ProductionUpstreamV1 {
    socket_path: PathBuf,
    socket_policy: UnixClnRpcSocketPolicyV1,
}

impl GuardUpstreamV1 for ProductionUpstreamV1 {
    fn call(&self, request: &[u8], deadline: std::time::Instant) -> Result<Zeroizing<Vec<u8>>, ()> {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero() && *remaining <= Duration::from_secs(30))
            .ok_or(())?;
        let transport =
            UnixClnRpcTransportV1::new(self.socket_path.clone(), self.socket_policy, remaining)
                .map_err(|_| ())?;
        transport
            .call(request)
            .map(|response| response.copy_for_local_guard())
            .map_err(|_| ())
    }
}

async fn serve_connection<U>(
    mut stream: UnixStream,
    upstream: Arc<U>,
    runtime_policy: Arc<GuardRuntimePolicyV1>,
    permit: OwnedSemaphorePermit,
    timeout: Duration,
) where
    U: GuardUpstreamV1,
{
    let deadline = Instant::now() + timeout;
    let frame = match time::timeout_at(deadline, read_request_frame(&mut stream)).await {
        Ok(Ok(frame)) => frame,
        _ => return,
    };
    let validated = match validate_request(&frame, runtime_policy.max_invoice_msat) {
        Ok(validated) => validated,
        Err(()) => return,
    };
    if matches!(validated.method, AllowedMethodV1::Invoice)
        && !runtime_policy.invoice_admission.try_admit()
    {
        return;
    }
    let method = validated.method;
    let expected_label = validated.expected_label;
    let canonical = validated.canonical;
    let blocking_deadline = deadline.into_std();
    let mut called = tokio::task::spawn_blocking(move || {
        // Keep the concurrency permit in the blocking closure. Timing out the
        // client task detaches (rather than cancels) spawn_blocking work, so
        // releasing this permit early would permit unbounded queued RPCs.
        let _permit = permit;
        let raw = upstream.call(&canonical, blocking_deadline)?;
        sanitize_response(
            method,
            expected_label.as_ref().map(|label| label.as_str()),
            &raw,
        )
    });
    let response = match time::timeout_at(deadline, &mut called).await {
        Ok(Ok(Ok(response))) => response,
        _ => return,
    };
    let written = time::timeout_at(deadline, async {
        stream.write_all(&response).await?;
        stream.write_all(b"\n\n").await?;
        stream.shutdown().await
    })
    .await;
    let _ = written;
}

async fn read_request_frame(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>, ()> {
    let mut frame = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_BYTES_V1 + 3));
    let mut chunk = Zeroizing::new([0_u8; 4096]);
    loop {
        let remaining = (MAX_REQUEST_BYTES_V1 + 3).saturating_sub(frame.len());
        if remaining == 0 {
            return Err(());
        }
        let read_bound = remaining.min(chunk.len());
        let read = stream
            .read(&mut chunk[..read_bound])
            .await
            .map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }
        frame.extend_from_slice(&chunk[..read]);
        if let Some(index) = frame.windows(2).position(|window| window == b"\n\n") {
            if index == 0 || index > MAX_REQUEST_BYTES_V1 || index + 2 != frame.len() {
                return Err(());
            }
            frame.truncate(index);
            return Ok(frame);
        }
        if frame.len() > MAX_REQUEST_BYTES_V1 + 2 {
            return Err(());
        }
    }
}

#[derive(Clone, Copy)]
enum AllowedMethodV1 {
    GetInfo,
    ListInvoices,
    Invoice,
}

struct ValidatedRequestV1 {
    method: AllowedMethodV1,
    expected_label: Option<Zeroizing<String>>,
    canonical: Zeroizing<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelopeV1<'a> {
    #[serde(borrow)]
    jsonrpc: &'a str,
    id: u8,
    #[serde(borrow)]
    method: &'a str,
    #[serde(borrow)]
    params: &'a RawValue,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyParamsV1 {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ListInvoicesParamsV1<'a> {
    #[serde(borrow)]
    label: &'a str,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InvoiceParamsV1<'a> {
    amount_msat: u64,
    #[serde(borrow)]
    label: &'a str,
    #[serde(borrow)]
    description: &'a str,
    expiry: u32,
    exposeprivatechannels: bool,
    deschashonly: bool,
}

#[derive(Serialize)]
struct CanonicalRequestV1<'a, P> {
    jsonrpc: &'static str,
    id: u8,
    method: &'static str,
    params: &'a P,
}

fn validate_request(bytes: &[u8], max_invoice_msat: u64) -> Result<ValidatedRequestV1, ()> {
    if max_invoice_msat == 0 || max_invoice_msat > MAX_BITCOIN_MSAT_V1 {
        return Err(());
    }
    let envelope: RequestEnvelopeV1<'_> = serde_json::from_slice(bytes).map_err(|_| ())?;
    if envelope.jsonrpc != "2.0" || envelope.id != 1 {
        return Err(());
    }
    match envelope.method {
        "getinfo" => {
            let params: EmptyParamsV1 =
                serde_json::from_str(envelope.params.get()).map_err(|_| ())?;
            Ok(ValidatedRequestV1 {
                method: AllowedMethodV1::GetInfo,
                expected_label: None,
                canonical: encode_request("getinfo", &params)?,
            })
        }
        "listinvoices" => {
            let params: ListInvoicesParamsV1<'_> =
                serde_json::from_str(envelope.params.get()).map_err(|_| ())?;
            if !is_canonical_label(params.label) {
                return Err(());
            }
            Ok(ValidatedRequestV1 {
                method: AllowedMethodV1::ListInvoices,
                expected_label: Some(Zeroizing::new(params.label.to_owned())),
                canonical: encode_request("listinvoices", &params)?,
            })
        }
        "invoice" => {
            let params: InvoiceParamsV1<'_> =
                serde_json::from_str(envelope.params.get()).map_err(|_| ())?;
            if params.amount_msat == 0
                || params.amount_msat > max_invoice_msat
                || !is_canonical_label(params.label)
                || params.description != ANONYMOUS_DESCRIPTION_V1
                || params.expiry == 0
                || params.expiry > MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1
                || params.exposeprivatechannels
                || !params.deschashonly
            {
                return Err(());
            }
            Ok(ValidatedRequestV1 {
                method: AllowedMethodV1::Invoice,
                expected_label: Some(Zeroizing::new(params.label.to_owned())),
                canonical: encode_request("invoice", &params)?,
            })
        }
        _ => Err(()),
    }
}

fn encode_request<P: Serialize>(
    method: &'static str,
    params: &P,
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_BYTES_V1 + 2));
    serde_json::to_writer(
        &mut *encoded,
        &CanonicalRequestV1 {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        },
    )
    .map_err(|_| ())?;
    if encoded.is_empty() || encoded.len() > MAX_REQUEST_BYTES_V1 {
        return Err(());
    }
    encoded.extend_from_slice(b"\n\n");
    Ok(encoded)
}

fn is_canonical_label(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(BACKEND_LABEL_PREFIX_V1) else {
        return false;
    };
    hex.len() == BACKEND_LABEL_HEX_LEN_V1
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelopeV1<'a> {
    #[serde(borrow)]
    jsonrpc: &'a str,
    id: u8,
    #[serde(borrow)]
    result: Option<&'a RawValue>,
    #[serde(borrow)]
    error: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct RemoteErrorV1 {
    code: i64,
}

#[derive(Serialize)]
struct SanitizedErrorV1 {
    code: i64,
}

#[derive(Serialize)]
struct SuccessEnvelopeV1<'a, T> {
    jsonrpc: &'static str,
    id: u8,
    result: &'a T,
}

#[derive(Serialize)]
struct ErrorEnvelopeV1 {
    jsonrpc: &'static str,
    id: u8,
    error: SanitizedErrorV1,
}

#[derive(Deserialize, Serialize)]
struct GetInfoResultV1<'a> {
    #[serde(borrow)]
    id: &'a str,
    #[serde(borrow)]
    network: &'a str,
}

#[derive(Deserialize, Serialize)]
struct InvoiceResultV1<'a> {
    #[serde(borrow)]
    bolt11: &'a str,
    #[serde(borrow)]
    payment_hash: &'a str,
    expires_at: u64,
}

#[derive(Deserialize, Serialize)]
struct ListInvoicesResultV1<'a> {
    #[serde(borrow)]
    invoices: Vec<ListedInvoiceV1<'a>>,
}

#[derive(Deserialize, Serialize)]
struct ListedInvoiceV1<'a> {
    #[serde(borrow)]
    label: &'a str,
    #[serde(borrow)]
    payment_hash: &'a str,
    #[serde(borrow)]
    status: &'a str,
    expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    bolt11: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    amount_msat: Option<ClnMsatV1<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    amount_received_msat: Option<ClnMsatV1<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paid_at: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum ClnMsatV1<'a> {
    Integer(u64),
    Text(#[serde(borrow)] &'a str),
}

impl ClnMsatV1<'_> {
    fn value(&self) -> Option<u64> {
        match self {
            Self::Integer(value) => Some(*value),
            Self::Text(value) => value
                .strip_suffix("msat")
                .filter(|digits| {
                    !digits.is_empty()
                        && digits.bytes().all(|byte| byte.is_ascii_digit())
                        && (*digits == "0" || !digits.starts_with('0'))
                })
                .and_then(|digits| digits.parse().ok()),
        }
    }
}

fn sanitize_response(
    method: AllowedMethodV1,
    expected_label: Option<&str>,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ()> {
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES_V1 {
        return Err(());
    }
    let envelope: ResponseEnvelopeV1<'_> = serde_json::from_slice(bytes).map_err(|_| ())?;
    if envelope.jsonrpc != "2.0" || envelope.id != 1 {
        return Err(());
    }
    match (envelope.result, envelope.error) {
        (Some(result), None) => match method {
            AllowedMethodV1::GetInfo => {
                let result: GetInfoResultV1<'_> =
                    serde_json::from_str(result.get()).map_err(|_| ())?;
                if !is_lower_hex(result.id, 66)
                    || !matches!(result.network, "bitcoin" | "testnet" | "signet" | "regtest")
                {
                    return Err(());
                }
                encode_response(&SuccessEnvelopeV1 {
                    jsonrpc: "2.0",
                    id: 1,
                    result: &result,
                })
            }
            AllowedMethodV1::Invoice => {
                let result: InvoiceResultV1<'_> =
                    serde_json::from_str(result.get()).map_err(|_| ())?;
                if result.bolt11.is_empty()
                    || result.bolt11.len() > MAX_BOLT11_INVOICE_LEN
                    || !result
                        .bolt11
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                    || !is_lower_hex(result.payment_hash, 64)
                    || result.expires_at == 0
                {
                    return Err(());
                }
                encode_response(&SuccessEnvelopeV1 {
                    jsonrpc: "2.0",
                    id: 1,
                    result: &result,
                })
            }
            AllowedMethodV1::ListInvoices => {
                let result: ListInvoicesResultV1<'_> =
                    serde_json::from_str(result.get()).map_err(|_| ())?;
                if result.invoices.len() > 1 {
                    return Err(());
                }
                if let Some(invoice) = result.invoices.first() {
                    validate_listed_invoice(invoice, expected_label.ok_or(())?)?;
                }
                encode_response(&SuccessEnvelopeV1 {
                    jsonrpc: "2.0",
                    id: 1,
                    result: &result,
                })
            }
        },
        (None, Some(error)) => {
            let error: RemoteErrorV1 = serde_json::from_str(error.get()).map_err(|_| ())?;
            encode_response(&ErrorEnvelopeV1 {
                jsonrpc: "2.0",
                id: 1,
                error: SanitizedErrorV1 { code: error.code },
            })
        }
        _ => Err(()),
    }
}

fn validate_listed_invoice(invoice: &ListedInvoiceV1<'_>, expected_label: &str) -> Result<(), ()> {
    let amount = invoice.amount_msat.as_ref().and_then(ClnMsatV1::value);
    let received = invoice
        .amount_received_msat
        .as_ref()
        .and_then(ClnMsatV1::value);
    if invoice.label != expected_label
        || !is_canonical_label(invoice.label)
        || !is_lower_hex(invoice.payment_hash, 64)
        || invoice.expires_at == 0
        || match invoice.bolt11 {
            Some(bolt11) => {
                bolt11.is_empty()
                    || bolt11.len() > MAX_BOLT11_INVOICE_LEN
                    || !bolt11
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            }
            None => true,
        }
        || match amount {
            Some(amount) => amount == 0 || amount > MAX_BITCOIN_MSAT_V1,
            None => true,
        }
        || received.is_some_and(|received| received > MAX_BITCOIN_MSAT_V1)
    {
        return Err(());
    }
    match invoice.status {
        "paid"
            if invoice.paid_at.is_some_and(|paid_at| paid_at != 0)
                && received.is_some_and(|value| value != 0) =>
        {
            Ok(())
        }
        "unpaid" | "expired" if invoice.paid_at.is_none() => Ok(()),
        _ => Err(()),
    }
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn encode_response<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, ()> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES_V1));
    serde_json::to_writer(&mut *encoded, value).map_err(|_| ())?;
    if encoded.is_empty() || encoded.len() > MAX_RESPONSE_BYTES_V1 {
        return Err(());
    }
    Ok(encoded)
}

struct ListenerTargetV1 {
    parent: File,
    file_name: OsString,
    path: PathBuf,
    parent_device: u64,
    parent_inode: u64,
}

#[derive(Clone, Copy)]
struct SocketIdentityV1 {
    device: u64,
    inode: u64,
}

struct ListenerGuardV1 {
    target: ListenerTargetV1,
    identity: SocketIdentityV1,
    guard_uid: u32,
    issuer_gid: u32,
}

impl ListenerGuardV1 {
    fn validate(&self) -> Result<(), ()> {
        let parent = rustix::fs::fstat(&self.target.parent).map_err(|_| ())?;
        if parent.st_dev != self.target.parent_device
            || parent.st_ino != self.target.parent_inode
            || !FileType::from_raw_mode(parent.st_mode).is_dir()
            || parent.st_uid != self.guard_uid
            || parent.st_gid != self.issuer_gid
            || parent.st_mode & 0o7777 != 0o710
        {
            return Err(());
        }
        let pinned = rustix::fs::statat(
            &self.target.parent,
            &self.target.file_name,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| ())?;
        if !socket_stat_matches(&pinned, self.identity, self.guard_uid, self.issuer_gid) {
            return Err(());
        }
        let named = fs::symlink_metadata(&self.target.path).map_err(|_| ())?;
        if !named.file_type().is_socket()
            || named.dev() != self.identity.device
            || named.ino() != self.identity.inode
            || named.uid() != self.guard_uid
            || named.gid() != self.issuer_gid
            || named.nlink() != 1
            || named.mode() & 0o7777 != 0o660
        {
            return Err(());
        }
        Ok(())
    }
}

impl Drop for ListenerGuardV1 {
    fn drop(&mut self) {
        let Ok(stat) = rustix::fs::statat(
            &self.target.parent,
            &self.target.file_name,
            AtFlags::SYMLINK_NOFOLLOW,
        ) else {
            return;
        };
        if FileType::from_raw_mode(stat.st_mode).is_socket()
            && stat.st_dev == self.identity.device
            && stat.st_ino == self.identity.inode
            && stat.st_uid == self.guard_uid
            && stat.st_nlink == 1
        {
            let _ = rustix::fs::unlinkat(
                &self.target.parent,
                &self.target.file_name,
                AtFlags::empty(),
            );
        }
    }
}

fn create_listener(config: &GuardConfig) -> Result<(UnixListener, ListenerGuardV1), String> {
    let target = open_listener_target(&config.listen_socket, config.guard_uid, config.issuer_gid)?;
    match rustix::fs::statat(&target.parent, &target.file_name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {}
        Ok(_) => return Err("downstream socket path already exists".to_owned()),
        Err(_) => return Err("inspect downstream socket path failed".to_owned()),
    }
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)
        .map_err(|_| "create downstream Unix socket failed".to_owned())?;
    let address = SockAddr::unix(&target.path)
        .map_err(|_| "downstream Unix socket path is invalid".to_owned())?;
    socket
        .bind(&address)
        .map_err(|_| "bind downstream Unix socket failed".to_owned())?;
    let provisional =
        rustix::fs::statat(&target.parent, &target.file_name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "inspect newly bound downstream socket failed".to_owned())?;
    if !FileType::from_raw_mode(provisional.st_mode).is_socket()
        || provisional.st_uid != config.guard_uid
        || provisional.st_nlink != 1
    {
        let _ = rustix::fs::unlinkat(&target.parent, &target.file_name, AtFlags::empty());
        return Err("new downstream socket has an unexpected identity".to_owned());
    }
    let identity = SocketIdentityV1 {
        device: provisional.st_dev,
        inode: provisional.st_ino,
    };
    let guard = ListenerGuardV1 {
        target,
        identity,
        guard_uid: config.guard_uid,
        issuer_gid: config.issuer_gid,
    };
    rustix::fs::chownat(
        &guard.target.parent,
        &guard.target.file_name,
        None,
        Some(Gid::from_raw_unchecked(config.issuer_gid)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| "assign issuer group to downstream socket failed".to_owned())?;
    rustix::fs::chmodat(
        &guard.target.parent,
        &guard.target.file_name,
        Mode::from_bits_truncate(0o660),
        AtFlags::empty(),
    )
    .map_err(|_| "set downstream socket permissions failed".to_owned())?;
    reject_new_listener_acl(&guard.target.path)?;
    guard
        .validate()
        .map_err(|_| "new downstream socket failed final validation".to_owned())?;
    let backlog = i32::try_from(config.max_in_flight.saturating_mul(2))
        .unwrap_or(i32::MAX)
        .max(1);
    socket
        .listen(backlog)
        .map_err(|_| "listen on downstream Unix socket failed".to_owned())?;
    socket
        .set_nonblocking(true)
        .map_err(|_| "set downstream Unix socket nonblocking failed".to_owned())?;
    let owned = OwnedFd::from(socket);
    let standard = StdUnixListener::from(owned);
    let listener = UnixListener::from_std(standard)
        .map_err(|_| "register downstream Unix socket with runtime failed".to_owned())?;
    guard
        .validate()
        .map_err(|_| "downstream socket changed during activation".to_owned())?;
    Ok((listener, guard))
}

fn socket_stat_matches(
    stat: &rustix::fs::Stat,
    identity: SocketIdentityV1,
    uid: u32,
    gid: u32,
) -> bool {
    FileType::from_raw_mode(stat.st_mode).is_socket()
        && stat.st_dev == identity.device
        && stat.st_ino == identity.inode
        && stat.st_uid == uid
        && stat.st_gid == gid
        && stat.st_nlink == 1
        && stat.st_mode & 0o7777 == 0o660
}

fn open_listener_target(
    path: &Path,
    guard_uid: u32,
    issuer_gid: u32,
) -> Result<ListenerTargetV1, String> {
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "downstream socket must name a file".to_owned())?
        .to_os_string();
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "downstream socket must have an absolute parent".to_owned())?;
    if !parent.is_absolute() {
        return Err("downstream socket path must be absolute".to_owned());
    }
    let parent = normalize_macos_system_root_alias(parent)?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root = rustix::fs::open("/", flags, Mode::empty())
        .map_err(|_| "open filesystem root for downstream socket failed".to_owned())?;
    let mut current = File::from(root);
    validate_listener_ancestor(&current, Path::new("/"), guard_uid)?;
    let components: Vec<_> = parent.components().collect();
    let normal_count = components
        .iter()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    if normal_count == 0 {
        return Err("downstream socket parent must not be filesystem root".to_owned());
    }
    let mut opened_path = PathBuf::from("/");
    let mut normal_index = 0usize;
    for component in components {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir | Component::Prefix(_) => {
                return Err("downstream socket path contains an unsupported component".to_owned())
            }
        };
        normal_index += 1;
        let next = rustix::fs::openat(&current, name, flags, Mode::empty()).map_err(|_| {
            "open downstream socket parent without following symlinks failed".to_owned()
        })?;
        current = File::from(next);
        opened_path.push(name);
        if normal_index == normal_count {
            validate_listener_parent(&current, &opened_path, guard_uid, issuer_gid)?;
        } else {
            validate_listener_ancestor(&current, &opened_path, guard_uid)?;
        }
    }
    let stat = rustix::fs::fstat(&current)
        .map_err(|_| "inspect downstream socket parent failed".to_owned())?;
    Ok(ListenerTargetV1 {
        parent: current,
        file_name: file_name.clone(),
        path: opened_path.join(file_name),
        parent_device: stat.st_dev,
        parent_inode: stat.st_ino,
    })
}

fn validate_listener_ancestor(file: &File, path: &Path, guard_uid: u32) -> Result<(), String> {
    let stat = rustix::fs::fstat(file)
        .map_err(|_| "inspect downstream socket ancestor failed".to_owned())?;
    let mode = stat.st_mode & 0o7777;
    let sticky_root = stat.st_uid == 0 && mode & 0o1000 != 0 && mode & 0o022 != 0;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || (stat.st_uid != 0 && stat.st_uid != guard_uid)
        || (mode & 0o022 != 0 && !sticky_root)
    {
        return Err(format!(
            "downstream socket ancestor is writable or untrusted: {}",
            path.display()
        ));
    }
    reject_listener_directory_acl(file, "downstream socket ancestor")
}

fn validate_listener_parent(
    file: &File,
    path: &Path,
    guard_uid: u32,
    issuer_gid: u32,
) -> Result<(), String> {
    let stat = rustix::fs::fstat(file)
        .map_err(|_| "inspect downstream socket final parent failed".to_owned())?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != guard_uid
        || stat.st_gid != issuer_gid
        || stat.st_mode & 0o7777 != 0o710
    {
        return Err(format!(
            "downstream socket parent must be guard-owned, issuer-grouped, and mode 0710: {}",
            path.display()
        ));
    }
    reject_listener_directory_acl(file, "downstream socket final parent")
}

fn reject_listener_directory_acl(file: &File, description: &str) -> Result<(), String> {
    reject_extended_acl_v1(file, description)?;
    #[cfg(target_os = "linux")]
    {
        let mut attributes = Vec::<u8>::with_capacity(4096);
        rustix::fs::flistxattr(file, rustix::buffer::spare_capacity(&mut attributes))
            .map_err(|_| format!("inspect Linux ACL attributes on {description} failed"))?;
        if attributes
            .split(|byte| *byte == 0)
            .any(|name| name == b"system.posix_acl_access" || name == b"system.posix_acl_default")
        {
            return Err(format!("{description} must not carry a POSIX ACL"));
        }
    }
    Ok(())
}

fn reject_new_listener_acl(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let mut attributes = Vec::<u8>::with_capacity(4096);
        rustix::fs::llistxattr(path, rustix::buffer::spare_capacity(&mut attributes))
            .map_err(|_| "inspect Linux ACL attributes on downstream socket failed".to_owned())?;
        if attributes
            .split(|byte| *byte == 0)
            .any(|name| name == b"system.posix_acl_access" || name == b"system.posix_acl_default")
        {
            return Err("downstream socket must not carry a POSIX ACL".to_owned());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = path;
    Ok(())
}

#[cfg(target_os = "macos")]
fn normalize_macos_system_root_alias(path: &Path) -> Result<PathBuf, String> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Ok(path.to_path_buf());
    }
    let Some(Component::Normal(first)) = components.next() else {
        return Ok(path.to_path_buf());
    };
    let expected = if first == OsStr::new("var") {
        Path::new("private/var")
    } else if first == OsStr::new("tmp") {
        Path::new("private/tmp")
    } else if first == OsStr::new("etc") {
        Path::new("private/etc")
    } else {
        return Ok(path.to_path_buf());
    };
    let alias = Path::new("/").join(first);
    let metadata = fs::symlink_metadata(&alias)
        .map_err(|_| "inspect fixed macOS filesystem alias failed".to_owned())?;
    let actual =
        fs::read_link(&alias).map_err(|_| "read fixed macOS filesystem alias failed".to_owned())?;
    if !metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || actual.as_os_str().as_bytes() != expected.as_os_str().as_bytes()
    {
        return Err("fixed macOS filesystem alias is not byte-exact".to_owned());
    }
    let mut normalized = PathBuf::from("/").join(expected);
    for component in components {
        normalized.push(component.as_os_str());
    }
    Ok(normalized)
}

#[cfg(not(target_os = "macos"))]
fn normalize_macos_system_root_alias(path: &Path) -> Result<PathBuf, String> {
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests;
