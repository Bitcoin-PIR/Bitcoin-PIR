//! Small blocking HTTPS/1.1 client for payment and admission authorities.
//!
//! It deliberately has no redirects, cookies, ambient proxy credentials,
//! response decompression, or request/body logging. Callers must execute it on
//! a blocking worker when integrating it into an asynchronous runtime.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use zeroize::Zeroizing;

const MAX_HTTP_HEADER_BYTES_V1: usize = 32 * 1024;
const MAX_HTTP_HEADERS_V1: usize = 64;
const MAX_HTTP_WIRE_OVERHEAD_V1: usize = 512 * 1024;
const MAX_RESOLVED_SOCKET_ADDRESSES_V1: usize = 32;
const MAX_CONCURRENT_DNS_RESOLVERS_V1: usize = 16;

static ACTIVE_DNS_RESOLVERS_V1: AtomicUsize = AtomicUsize::new(0);

struct DnsResolverPermitV1;

impl DnsResolverPermitV1 {
    fn acquire() -> Result<Self, ()> {
        ACTIVE_DNS_RESOLVERS_V1
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_CONCURRENT_DNS_RESOLVERS_V1).then_some(active + 1)
            })
            .map(|_| Self)
            .map_err(|_| ())
    }
}

impl Drop for DnsResolverPermitV1 {
    fn drop(&mut self) {
        ACTIVE_DNS_RESOLVERS_V1.fetch_sub(1, Ordering::AcqRel);
    }
}

fn deadline_after_v1(timeout: Duration) -> Result<Instant, ()> {
    Instant::now().checked_add(timeout).ok_or(())
}

fn remaining_v1(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "operation deadline elapsed"))
}

fn resolve_socket_addresses_v1(
    authority: String,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, ()> {
    if let Ok(address) = authority.parse::<SocketAddr>() {
        return Ok(vec![address]);
    }
    resolve_socket_addresses_using_v1(authority, deadline, |authority| {
        let mut addresses = Vec::new();
        for address in authority.to_socket_addrs().map_err(|_| ())? {
            if !addresses.contains(&address) {
                if addresses.len() == MAX_RESOLVED_SOCKET_ADDRESSES_V1 {
                    return Err(());
                }
                addresses.push(address);
            }
        }
        (!addresses.is_empty()).then_some(addresses).ok_or(())
    })
}

fn resolve_socket_addresses_using_v1<F>(
    authority: String,
    deadline: Instant,
    resolver: F,
) -> Result<Vec<SocketAddr>, ()>
where
    F: FnOnce(String) -> Result<Vec<SocketAddr>, ()> + Send + 'static,
{
    remaining_v1(deadline).map_err(|_| ())?;
    let permit = DnsResolverPermitV1::acquire()?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name("bpir-strict-https-dns".to_owned())
        .spawn(move || {
            let _permit = permit;
            let _ = sender.send(resolver(authority));
        })
        .map_err(|_| ())?;
    // Dropping the handle detaches the bounded worker. If the platform
    // resolver ignores cancellation, the permit keeps the number of such
    // outstanding threads bounded until their lookups actually return.
    drop(worker);
    let remaining = remaining_v1(deadline).map_err(|_| ())?;
    receiver.recv_timeout(remaining).map_err(|_| ())?
}

fn connect_socket_addresses_using_v1<T, F>(
    addresses: &[SocketAddr],
    deadline: Instant,
    mut connector: F,
) -> Result<T, ()>
where
    F: FnMut(&SocketAddr, Duration) -> io::Result<T>,
{
    if addresses.is_empty() {
        return Err(());
    }
    for (index, address) in addresses.iter().enumerate() {
        let remaining = remaining_v1(deadline).map_err(|_| ())?;
        let candidates_left = u32::try_from(addresses.len() - index).map_err(|_| ())?;
        let fair_share = remaining / candidates_left;
        let attempt_timeout = if fair_share.is_zero() {
            remaining
        } else {
            fair_share
        };
        if let Ok(stream) = connector(address, attempt_timeout) {
            remaining_v1(deadline).map_err(|_| ())?;
            return Ok(stream);
        }
    }
    Err(())
}

struct DeadlineTcpStreamV1 {
    inner: TcpStream,
    deadline: Instant,
}

impl DeadlineTcpStreamV1 {
    const fn new(inner: TcpStream, deadline: Instant) -> Self {
        Self { inner, deadline }
    }
}

impl Read for DeadlineTcpStreamV1 {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = remaining_v1(self.deadline)?;
        self.inner.set_read_timeout(Some(remaining))?;
        self.inner.read(buffer)
    }
}

impl Write for DeadlineTcpStreamV1 {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = remaining_v1(self.deadline)?;
        self.inner.set_write_timeout(Some(remaining))?;
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        remaining_v1(self.deadline)?;
        self.inner.flush()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum HttpsPostErrorV1 {
    /// No HTTP application bytes could have reached the remote authority.
    DefinitelyNotSent,
    /// Some request bytes may have reached the authority; retry only through
    /// the operation's exact idempotency/recovery protocol.
    OutcomeUnknown,
    /// A non-success status whose body passed the same strict content-type,
    /// framing, decompression, and size checks as a success response.
    HttpStatus {
        status: u16,
        body: Zeroizing<Vec<u8>>,
    },
    InvalidResponse,
}

impl std::fmt::Debug for HttpsPostErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DefinitelyNotSent => formatter.write_str("DefinitelyNotSent"),
            Self::OutcomeUnknown => formatter.write_str("OutcomeUnknown"),
            Self::InvalidResponse => formatter.write_str("InvalidResponse"),
            Self::HttpStatus { status, body } => formatter
                .debug_struct("HttpStatus")
                .field("status", status)
                .field("body_len", &body.len())
                .finish(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StrictHttpsClientV1 {
    connect_timeout: Duration,
    io_timeout: Duration,
    tls_config: Arc<ClientConfig>,
}

impl StrictHttpsClientV1 {
    pub fn new(connect_timeout: Duration, io_timeout: Duration) -> Result<Self, String> {
        if connect_timeout.is_zero()
            || io_timeout.is_zero()
            || connect_timeout > Duration::from_secs(60)
            || io_timeout > Duration::from_secs(60)
        {
            return Err("HTTPS timeouts must be in 1ns..=60s".to_owned());
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| "could not configure safe TLS protocol versions".to_owned())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            connect_timeout,
            io_timeout,
            tls_config: Arc::new(tls_config),
        })
    }

    pub fn post(
        &self,
        base_endpoint: &str,
        route: &str,
        request_content_type: &str,
        expected_response_content_type: &str,
        body: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, HttpsPostErrorV1> {
        if body.is_empty()
            || body.len() > 1024 * 1024
            || max_response_bytes == 0
            || max_response_bytes > 1024 * 1024
            || !valid_media_type_v1(request_content_type)
            || !valid_media_type_v1(expected_response_content_type)
        {
            return Err(HttpsPostErrorV1::DefinitelyNotSent);
        }
        let endpoint = HttpsEndpointV1::parse_and_join(base_endpoint, route)
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        // `connect_timeout` is one wall-clock budget for DNS plus every
        // candidate address, rather than a fresh budget for each step.
        let connect_deadline = deadline_after_v1(self.connect_timeout)
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        let socket_addresses =
            resolve_socket_addresses_v1(endpoint.connect_authority(), connect_deadline)
                .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        let tcp = connect_socket_addresses_using_v1(
            &socket_addresses,
            connect_deadline,
            TcpStream::connect_timeout,
        )
        .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        let io_deadline =
            deadline_after_v1(self.io_timeout).map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        tcp.set_nodelay(true)
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;

        let server_name = ServerName::try_from(endpoint.tls_name.clone())
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        let connection = ClientConnection::new(Arc::clone(&self.tls_config), server_name)
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        // rustls can perform several transport reads and writes inside one
        // public `StreamOwned` operation. The wrapper recomputes the remaining
        // timeout for each of those lower-level calls, so handshake and
        // trickled request/response traffic cannot refresh the I/O budget.
        let mut stream = StreamOwned::new(connection, DeadlineTcpStreamV1::new(tcp, io_deadline));
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nAccept: {}\r\nContent-Length: {}\r\nConnection: close\r\nUser-Agent: BitcoinPIR-service-admission/1\r\n\r\n",
            endpoint.path,
            endpoint.host_header,
            request_content_type,
            expected_response_content_type,
            body.len(),
        );
        // Keep bearer material in the caller-owned body only. In particular,
        // do not concatenate NUT-03 proofs into a second ordinary Vec.
        let mut total_written = 0usize;
        for part in [head.as_bytes(), body] {
            let mut part_written = 0usize;
            while part_written < part.len() {
                match stream.write(&part[part_written..]) {
                    Ok(0) => {
                        return Err(if total_written == 0 {
                            HttpsPostErrorV1::DefinitelyNotSent
                        } else {
                            HttpsPostErrorV1::OutcomeUnknown
                        })
                    }
                    Ok(count) => {
                        part_written += count;
                        total_written += count;
                    }
                    Err(_) => {
                        return Err(if total_written == 0 {
                            HttpsPostErrorV1::DefinitelyNotSent
                        } else {
                            HttpsPostErrorV1::OutcomeUnknown
                        })
                    }
                }
            }
        }
        stream
            .flush()
            .map_err(|_| HttpsPostErrorV1::OutcomeUnknown)?;

        let wire_limit = max_response_bytes
            .checked_add(MAX_HTTP_HEADER_BYTES_V1)
            .and_then(|value| value.checked_add(MAX_HTTP_WIRE_OVERHEAD_V1))
            .ok_or(HttpsPostErrorV1::InvalidResponse)?;
        // Payment and NUT-07 responses can contain bearer-adjacent material,
        // raw Y values, or witnesses. Keep every Rust-owned transport copy in
        // zeroizing storage, including error and early-return paths.
        // Allocate the full checked bound once. Growing a `Vec` would free its
        // old allocation without first zeroizing the copied response prefix.
        let mut wire = Zeroizing::new(Vec::with_capacity(wire_limit));
        let mut buffer = Zeroizing::new([0u8; 8 * 1024]);
        loop {
            match stream.read(&mut buffer[..]) {
                Ok(0) => break,
                Ok(count) => {
                    if wire.len().saturating_add(count) > wire_limit {
                        return Err(HttpsPostErrorV1::InvalidResponse);
                    }
                    wire.extend_from_slice(&buffer[..count]);
                }
                Err(_) => return Err(HttpsPostErrorV1::OutcomeUnknown),
            }
        }
        parse_http_response_v1(
            wire.as_slice(),
            expected_response_content_type,
            max_response_bytes,
        )
    }
}

struct HttpsEndpointV1 {
    tls_name: String,
    host_header: String,
    connect_host: String,
    port: u16,
    path: String,
}

impl HttpsEndpointV1 {
    fn parse_and_join(base: &str, route: &str) -> Result<Self, ()> {
        if !base.starts_with("https://")
            || base.contains(['?', '#', '\r', '\n'])
            || route.is_empty()
            || !route.starts_with('/')
            || route.contains(['?', '#', '\r', '\n'])
            || route.contains("//")
            || route.split('/').any(|part| part == "." || part == "..")
        {
            return Err(());
        }
        let remainder = &base["https://".len()..];
        let (authority, base_path) = match remainder.split_once('/') {
            Some((authority, path)) => (authority, format!("/{path}")),
            None => (remainder, String::new()),
        };
        if authority.is_empty()
            || authority.contains('@')
            || base_path.ends_with('/')
            || base_path.contains("//")
            || base_path.contains('%')
            || !authority.is_ascii()
        {
            return Err(());
        }
        let (tls_name, connect_host, port, host_header) = if authority.starts_with('[') {
            let close = authority.find(']').ok_or(())?;
            let host = &authority[1..close];
            let suffix = &authority[close + 1..];
            let port = if suffix.is_empty() {
                443
            } else {
                suffix
                    .strip_prefix(':')
                    .ok_or(())?
                    .parse()
                    .map_err(|_| ())?
            };
            if host.is_empty() || port == 0 {
                return Err(());
            }
            (
                host.to_owned(),
                format!("[{host}]"),
                port,
                if port == 443 {
                    format!("[{host}]")
                } else {
                    format!("[{host}]:{port}")
                },
            )
        } else {
            let (host, port) = match authority.rsplit_once(':') {
                Some((host, port)) if !host.contains(':') => {
                    (host, port.parse::<u16>().map_err(|_| ())?)
                }
                _ => (authority, 443),
            };
            if host.is_empty()
                || port == 0
                || !host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            {
                return Err(());
            }
            (
                host.to_owned(),
                host.to_owned(),
                port,
                if port == 443 {
                    host.to_owned()
                } else {
                    format!("{host}:{port}")
                },
            )
        };
        let path = format!("{base_path}{route}");
        if path.contains("//") || !path.is_ascii() {
            return Err(());
        }
        Ok(Self {
            tls_name,
            host_header,
            connect_host,
            port,
            path,
        })
    }

    fn connect_authority(&self) -> String {
        format!("{}:{}", self.connect_host, self.port)
    }
}

fn valid_media_type_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'-' | b'.'))
}

fn parse_http_response_v1(
    wire: &[u8],
    expected_content_type: &str,
    max_response_bytes: usize,
) -> Result<Vec<u8>, HttpsPostErrorV1> {
    if wire.len()
        > max_response_bytes.saturating_add(MAX_HTTP_HEADER_BYTES_V1 + MAX_HTTP_WIRE_OVERHEAD_V1)
    {
        return Err(HttpsPostErrorV1::InvalidResponse);
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS_V1];
    let mut response = httparse::Response::new(&mut headers);
    let header_len = match response
        .parse(wire)
        .map_err(|_| HttpsPostErrorV1::InvalidResponse)?
    {
        httparse::Status::Complete(length) if length <= MAX_HTTP_HEADER_BYTES_V1 => length,
        _ => return Err(HttpsPostErrorV1::InvalidResponse),
    };
    if response.version != Some(1) {
        return Err(HttpsPostErrorV1::InvalidResponse);
    }
    let status = response.code.ok_or(HttpsPostErrorV1::InvalidResponse)?;
    let mut content_type = None;
    let mut content_length = None;
    let mut chunked = false;
    for header in response.headers.iter() {
        if header.name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() {
                return Err(HttpsPostErrorV1::InvalidResponse);
            }
            let value =
                std::str::from_utf8(header.value).map_err(|_| HttpsPostErrorV1::InvalidResponse)?;
            content_type = Some(value.split(';').next().unwrap_or("").trim());
        } else if header.name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(HttpsPostErrorV1::InvalidResponse);
            }
            let value =
                std::str::from_utf8(header.value).map_err(|_| HttpsPostErrorV1::InvalidResponse)?;
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| HttpsPostErrorV1::InvalidResponse)?,
            );
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !header.value.eq_ignore_ascii_case(b"chunked") {
                return Err(HttpsPostErrorV1::InvalidResponse);
            }
            chunked = true;
        } else if header.name.eq_ignore_ascii_case("content-encoding")
            && !header.value.eq_ignore_ascii_case(b"identity")
        {
            return Err(HttpsPostErrorV1::InvalidResponse);
        }
    }
    if content_type != Some(expected_content_type) || (chunked && content_length.is_some()) {
        return Err(HttpsPostErrorV1::InvalidResponse);
    }
    let encoded_body = &wire[header_len..];
    let mut body = Zeroizing::new(if chunked {
        decode_chunked_v1(encoded_body, max_response_bytes)?
    } else {
        if let Some(expected) = content_length {
            if expected != encoded_body.len() {
                return Err(HttpsPostErrorV1::InvalidResponse);
            }
        }
        if encoded_body.len() > max_response_bytes {
            return Err(HttpsPostErrorV1::InvalidResponse);
        }
        encoded_body.to_vec()
    });
    if body.is_empty() {
        return Err(HttpsPostErrorV1::InvalidResponse);
    }
    if (200..300).contains(&status) {
        // Ownership passes directly to the caller without a second copy. All
        // in-client copies have already been zeroized; payment callers must
        // wrap the returned body immediately, as the transport adapters do.
        Ok(std::mem::take(&mut *body))
    } else {
        Err(HttpsPostErrorV1::HttpStatus { status, body })
    }
}

fn decode_chunked_v1(
    mut encoded: &[u8],
    max_response_bytes: usize,
) -> Result<Vec<u8>, HttpsPostErrorV1> {
    // The caller already enforces a <=1 MiB bound. Preallocating it prevents
    // chunk accumulation from leaving old response prefixes in reallocated
    // buffers that `Zeroizing<Vec<_>>` can no longer reach.
    let mut body = Zeroizing::new(Vec::with_capacity(max_response_bytes));
    loop {
        let line_end = encoded
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(HttpsPostErrorV1::InvalidResponse)?;
        let size_text = std::str::from_utf8(&encoded[..line_end])
            .map_err(|_| HttpsPostErrorV1::InvalidResponse)?;
        if size_text.is_empty() || size_text.contains(';') || size_text.len() > 16 {
            return Err(HttpsPostErrorV1::InvalidResponse);
        }
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| HttpsPostErrorV1::InvalidResponse)?;
        encoded = &encoded[line_end + 2..];
        if size == 0 {
            return if encoded == b"\r\n" {
                Ok(std::mem::take(&mut *body))
            } else {
                Err(HttpsPostErrorV1::InvalidResponse)
            };
        }
        if size > encoded.len().saturating_sub(2)
            || encoded.get(size..size + 2) != Some(b"\r\n")
            || body.len().saturating_add(size) > max_response_bytes
        {
            return Err(HttpsPostErrorV1::InvalidResponse);
        }
        body.extend_from_slice(&encoded[..size]);
        encoded = &encoded[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_resolution_obeys_connect_deadline() {
        let started = Instant::now();
        let deadline = started + Duration::from_millis(100);
        let result =
            resolve_socket_addresses_using_v1("slow.invalid:443".to_owned(), deadline, |_| {
                thread::sleep(Duration::from_secs(1));
                Ok(vec!["127.0.0.1:443".parse().unwrap()])
            });
        assert!(result.is_err());
        assert!(
            started.elapsed() < Duration::from_millis(700),
            "resolver timeout refreshed or failed to bound the caller"
        );
    }

    #[test]
    fn multi_address_connect_shares_one_deadline_fairly() {
        let addresses = [
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        ];
        let mut observed_timeouts = Vec::new();
        let connected = connect_socket_addresses_using_v1(
            &addresses,
            Instant::now() + Duration::from_secs(1),
            |_, timeout| {
                observed_timeouts.push(timeout);
                if observed_timeouts.len() == 1 {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "scripted first-address failure",
                    ))
                } else {
                    Ok(7u8)
                }
            },
        )
        .unwrap();
        assert_eq!(connected, 7);
        assert_eq!(observed_timeouts.len(), 2);
        assert!(observed_timeouts[0] <= Duration::from_millis(500));
        assert!(observed_timeouts[1] > observed_timeouts[0]);
    }

    #[test]
    fn tcp_io_deadline_is_not_refreshed_by_trickled_bytes() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in 0u8..10 {
                thread::sleep(Duration::from_millis(40));
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
            }
        });
        let tcp = TcpStream::connect(address).unwrap();
        let started = Instant::now();
        let mut stream = DeadlineTcpStreamV1::new(
            tcp,
            started.checked_add(Duration::from_millis(120)).unwrap(),
        );
        let mut byte = [0u8; 1];
        let mut received = 0usize;
        let error = loop {
            match stream.read(&mut byte) {
                Ok(0) => panic!("trickle server closed before the deadline"),
                Ok(_) => received += 1,
                Err(error) => break error,
            }
        };
        assert!(received >= 1);
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(
            started.elapsed() < Duration::from_millis(350),
            "per-read timeouts refreshed the absolute I/O deadline"
        );
        drop(stream);
        server.join().unwrap();
    }

    #[test]
    fn endpoint_join_and_bounded_response_parsing_are_strict() {
        let endpoint =
            HttpsEndpointV1::parse_and_join("https://mint.example/api", "/v1/swap").unwrap();
        assert_eq!(endpoint.path, "/api/v1/swap");
        assert!(HttpsEndpointV1::parse_and_join("http://mint.example", "/v1/swap").is_err());
        assert!(HttpsEndpointV1::parse_and_join("https://mint.example/", "/v1/swap").is_err());

        let wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(
            parse_http_response_v1(wire, "application/json", 5).unwrap(),
            b"abcde"
        );
        assert_eq!(
            parse_http_response_v1(wire, "application/json", 4),
            Err(HttpsPostErrorV1::InvalidResponse)
        );

        let error_body = br#"{"code":10001,"detail":"proof verification failed"}"#;
        let error_wire = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            error_body.len(),
            std::str::from_utf8(error_body).unwrap(),
        );
        assert_eq!(
            parse_http_response_v1(error_wire.as_bytes(), "application/json", 1_024),
            Err(HttpsPostErrorV1::HttpStatus {
                status: 400,
                body: Zeroizing::new(error_body.to_vec()),
            })
        );
        let html_wire = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nerror";
        assert_eq!(
            parse_http_response_v1(html_wire, "application/json", 1_024),
            Err(HttpsPostErrorV1::InvalidResponse)
        );
    }
}

#[cfg(test)]
#[path = "adversarial_tests.rs"]
mod adversarial_tests;
