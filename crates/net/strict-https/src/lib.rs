//! Small blocking HTTPS/1.1 client for payment and admission authorities.
//!
//! It deliberately has no redirects, cookies, ambient proxy credentials,
//! response decompression, or request/body logging. Callers must execute it on
//! a blocking worker when integrating it into an asynchronous runtime. HTTP
//! 200 is its only success status; every other status follows the exact error
//! media-type path.

#[cfg(all(feature = "test-only-webpki-root", not(debug_assertions)))]
compile_error!("test-only-webpki-root must never be compiled into a production release");

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore,
    SignatureScheme, StreamOwned,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAX_HTTP_HEADER_BYTES_V1: usize = 32 * 1024;
const MAX_HTTP_HEADERS_V1: usize = 64;
const MAX_HTTP_WIRE_OVERHEAD_V1: usize = 512 * 1024;
const MAX_RESOLVED_SOCKET_ADDRESSES_V1: usize = 32;
const MAX_CONCURRENT_DNS_RESOLVERS_V1: usize = 16;
const MAX_LEAF_SPKI_SHA256_PINS_V1: usize = 2;

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

fn bounded_deadline_after_v1(
    timeout: Duration,
    absolute_deadline: Option<Instant>,
) -> Result<Instant, ()> {
    let stage_deadline = deadline_after_v1(timeout)?;
    match absolute_deadline {
        Some(absolute_deadline) => {
            remaining_v1(absolute_deadline).map_err(|_| ())?;
            Ok(stage_deadline.min(absolute_deadline))
        }
        None => Ok(stage_deadline),
    }
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
    /// A status other than the only accepted success status, HTTP 200, whose
    /// body passed the configured exact error content-type plus the same
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

/// A verifier which accepts a server certificate only when the ordinary
/// rustls/WebPKI verifier succeeds *and* the SHA-256 digest of the leaf
/// certificate's complete DER-encoded SubjectPublicKeyInfo matches a
/// configured pin. The pin is an additional restriction: it never replaces
/// chain, hostname, or validity-time checks. V1 does not configure a CRL set
/// or require an OCSP response and makes no independent revocation claim.
struct WebPkiAndLeafSpkiPinVerifierV1 {
    webpki: Arc<WebPkiServerVerifier>,
    leaf_spki_sha256_pins: Vec<[u8; 32]>,
}

impl std::fmt::Debug for WebPkiAndLeafSpkiPinVerifierV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebPkiAndLeafSpkiPinVerifierV1")
            .field("webpki", &"[DELEGATED]")
            .field("leaf_spki_sha256_pins", &"[REDACTED]")
            .finish()
    }
}

impl ServerCertVerifier for WebPkiAndLeafSpkiPinVerifierV1 {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // The delegated verifier must run first. A matching pin is never
        // sufficient to bypass WebPKI authentication.
        let verified = self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let parsed = ParsedCertificate::try_from(end_entity)?;
        let digest: [u8; 32] = Sha256::digest(parsed.subject_public_key_info().as_ref()).into();
        if !self.leaf_spki_sha256_pins.iter().any(|pin| pin == &digest) {
            return Err(CertificateError::ApplicationVerificationFailure.into());
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.webpki.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        self.webpki.root_hint_subjects()
    }
}

#[derive(Clone)]
pub struct StrictHttpsClientV1 {
    connect_timeout: Duration,
    io_timeout: Duration,
    tls_config: Arc<ClientConfig>,
}

impl std::fmt::Debug for StrictHttpsClientV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StrictHttpsClientV1")
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("tls_config", &"[REDACTED]")
            .finish()
    }
}

impl StrictHttpsClientV1 {
    pub fn new(connect_timeout: Duration, io_timeout: Duration) -> Result<Self, String> {
        validate_timeouts_v1(connect_timeout, io_timeout)?;
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

    /// Constructs a strict HTTPS client with an additional leaf-SPKI pin.
    ///
    /// Every accepted TLS connection must independently pass the normal
    /// WebPKI chain, hostname, and validity-time checks *and* match one of
    /// `leaf_spki_sha256_pins`. Exactly one or two
    /// nonzero, strictly sorted pins are accepted so operators can perform a
    /// bounded key rotation with one canonical representation. This constructor
    /// does not implement TOFU, certificate-fingerprint pinning, or a pin-only
    /// verification mode.
    pub fn new_with_leaf_spki_sha256_pins(
        connect_timeout: Duration,
        io_timeout: Duration,
        leaf_spki_sha256_pins: &[[u8; 32]],
    ) -> Result<Self, String> {
        validate_timeouts_v1(connect_timeout, io_timeout)?;
        validate_leaf_spki_sha256_pins_v1(leaf_spki_sha256_pins)?;
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::new_pinned_with_roots_v1(connect_timeout, io_timeout, leaf_spki_sha256_pins, roots)
    }

    /// Test-only pinned HTTPS constructor with one additional private WebPKI
    /// root. It never replaces WebPKI validation or the mandatory leaf-SPKI
    /// pin, and it is absent from normal production builds.
    #[cfg(feature = "test-only-webpki-root")]
    pub fn new_with_leaf_spki_sha256_pins_and_test_only_webpki_root_pem(
        connect_timeout: Duration,
        io_timeout: Duration,
        leaf_spki_sha256_pins: &[[u8; 32]],
        test_only_root_pem: &[u8],
    ) -> Result<Self, String> {
        use rustls::pki_types::pem::PemObject as _;

        const MAX_TEST_ROOT_PEM_BYTES_V1: usize = 16 * 1024;

        validate_timeouts_v1(connect_timeout, io_timeout)?;
        validate_leaf_spki_sha256_pins_v1(leaf_spki_sha256_pins)?;
        if test_only_root_pem.is_empty() || test_only_root_pem.len() > MAX_TEST_ROOT_PEM_BYTES_V1 {
            return Err("test-only WebPKI root PEM is invalid".to_owned());
        }
        let test_root = CertificateDer::from_pem_slice(test_only_root_pem)
            .map_err(|_| "test-only WebPKI root PEM is invalid".to_owned())?;
        let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        roots
            .add(test_root)
            .map_err(|_| "test-only WebPKI root certificate is invalid".to_owned())?;
        Self::new_pinned_with_roots_v1(connect_timeout, io_timeout, leaf_spki_sha256_pins, roots)
    }

    fn new_pinned_with_roots_v1(
        connect_timeout: Duration,
        io_timeout: Duration,
        leaf_spki_sha256_pins: &[[u8; 32]],
        roots: RootCertStore,
    ) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let webpki =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .map_err(|_| "could not configure WebPKI server verification".to_owned())?;
        let verifier = Arc::new(WebPkiAndLeafSpkiPinVerifierV1 {
            webpki,
            leaf_spki_sha256_pins: leaf_spki_sha256_pins.to_vec(),
        });
        let mut tls_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| "could not configure safe TLS protocol versions".to_owned())?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        // A resumed PSK connection need not present a certificate again. Pin
        // changes must therefore be checked on every strict pinned connection
        // rather than inherited from a prior process-local session.
        tls_config.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            connect_timeout,
            io_timeout,
            tls_config: Arc::new(tls_config),
        })
    }

    /// Validates a configured HTTPS base endpoint without performing DNS or
    /// opening a socket. Startup code can therefore fail closed on malformed
    /// authorities and paths before it accepts work or mutates durable state.
    pub fn validate_base_endpoint(base_endpoint: &str) -> Result<(), String> {
        HttpsEndpointV1::parse_and_join(base_endpoint, "/__bitcoinpir_endpoint_validation_v1")
            .map(|_| ())
            .map_err(|_| "invalid canonical HTTPS base endpoint".to_owned())
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
        self.post_with_error_content_type(
            base_endpoint,
            route,
            request_content_type,
            expected_response_content_type,
            expected_response_content_type,
            body,
            max_response_bytes,
        )
    }

    /// POSTs while pinning distinct success and non-success media types.
    /// This is needed for services that return canonical binary success
    /// objects but a bounded `application/problem+json` rejection. It does not
    /// accept either media type interchangeably: the HTTP status selects the
    /// one exact type that is valid.
    #[allow(clippy::too_many_arguments)]
    pub fn post_with_error_content_type(
        &self,
        base_endpoint: &str,
        route: &str,
        request_content_type: &str,
        expected_response_content_type: &str,
        expected_error_content_type: &str,
        body: &[u8],
        max_response_bytes: usize,
    ) -> Result<Vec<u8>, HttpsPostErrorV1> {
        self.post_with_error_content_type_inner(
            base_endpoint,
            route,
            request_content_type,
            expected_response_content_type,
            expected_error_content_type,
            body,
            max_response_bytes,
            None,
        )
    }

    /// The same strict POST as [`Self::post_with_error_content_type`], bounded
    /// by a caller-supplied absolute monotonic deadline across DNS, every TCP
    /// candidate, TLS, request upload, and response download. The configured
    /// connect and I/O timeouts remain independent upper bounds; the earliest
    /// deadline always wins.
    #[allow(clippy::too_many_arguments)]
    pub fn post_with_error_content_type_until(
        &self,
        base_endpoint: &str,
        route: &str,
        request_content_type: &str,
        expected_response_content_type: &str,
        expected_error_content_type: &str,
        body: &[u8],
        max_response_bytes: usize,
        absolute_deadline: Instant,
    ) -> Result<Vec<u8>, HttpsPostErrorV1> {
        self.post_with_error_content_type_inner(
            base_endpoint,
            route,
            request_content_type,
            expected_response_content_type,
            expected_error_content_type,
            body,
            max_response_bytes,
            Some(absolute_deadline),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn post_with_error_content_type_inner(
        &self,
        base_endpoint: &str,
        route: &str,
        request_content_type: &str,
        expected_response_content_type: &str,
        expected_error_content_type: &str,
        body: &[u8],
        max_response_bytes: usize,
        absolute_deadline: Option<Instant>,
    ) -> Result<Vec<u8>, HttpsPostErrorV1> {
        if body.is_empty()
            || body.len() > 1024 * 1024
            || max_response_bytes == 0
            || max_response_bytes > 1024 * 1024
            || !valid_media_type_v1(request_content_type)
            || !valid_media_type_v1(expected_response_content_type)
            || !valid_media_type_v1(expected_error_content_type)
        {
            return Err(HttpsPostErrorV1::DefinitelyNotSent);
        }
        let endpoint = HttpsEndpointV1::parse_and_join(base_endpoint, route)
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        // `connect_timeout` is one wall-clock budget for DNS plus every
        // candidate address, rather than a fresh budget for each step.
        let connect_deadline = bounded_deadline_after_v1(self.connect_timeout, absolute_deadline)
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
        let io_deadline = bounded_deadline_after_v1(self.io_timeout, absolute_deadline)
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
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
        let accept =
            accept_header_value_v1(expected_response_content_type, expected_error_content_type);
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nAccept: {}\r\nContent-Length: {}\r\nConnection: close\r\nUser-Agent: BitcoinPIR-service-admission/1\r\n\r\n",
            endpoint.path,
            endpoint.host_header,
            request_content_type,
            accept,
            body.len(),
        );
        // Keep bearer material in the caller-owned body only. In particular,
        // do not concatenate NUT-03 proofs into a second ordinary Vec.
        for part in [head.as_bytes(), body] {
            let mut part_written = 0usize;
            while part_written < part.len() {
                match stream.write(&part[part_written..]) {
                    // The first rustls write may drive both the TLS handshake
                    // and an application-data record. If that compound
                    // operation returns an error, the high-level byte count
                    // cannot prove that the peer saw no HTTP bytes. Once a
                    // write is attempted, classify every failure as unknown.
                    Ok(0) => return Err(HttpsPostErrorV1::OutcomeUnknown),
                    Ok(count) => {
                        part_written += count;
                    }
                    Err(_) => return Err(HttpsPostErrorV1::OutcomeUnknown),
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
        // raw Y values, or witnesses. Keep every buffer owned by this adapter
        // in zeroizing storage, including error and early-return paths. This
        // does not cover rustls-internal plaintext queues, crypto-library
        // scratch space, allocator remnants, kernel buffers, or caller-owned
        // copies; those remain documented best-effort residuals.
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
            expected_error_content_type,
            max_response_bytes,
        )
    }
}

fn validate_timeouts_v1(connect_timeout: Duration, io_timeout: Duration) -> Result<(), String> {
    if connect_timeout.is_zero()
        || io_timeout.is_zero()
        || connect_timeout > Duration::from_secs(60)
        || io_timeout > Duration::from_secs(60)
    {
        return Err("HTTPS timeouts must be in 1ns..=60s".to_owned());
    }
    Ok(())
}

fn validate_leaf_spki_sha256_pins_v1(pins: &[[u8; 32]]) -> Result<(), String> {
    if pins.is_empty() || pins.len() > MAX_LEAF_SPKI_SHA256_PINS_V1 {
        return Err("leaf SPKI SHA-256 pin count must be in 1..=2".to_owned());
    }
    if pins.iter().any(|pin| pin.iter().all(|byte| *byte == 0)) {
        return Err("leaf SPKI SHA-256 pins must be nonzero".to_owned());
    }
    if pins.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("leaf SPKI SHA-256 pins must be strictly sorted and distinct".to_owned());
    }
    Ok(())
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
            || !base.is_ascii()
            || base.contains(['?', '#', '\r', '\n'])
            || !valid_endpoint_path_v1(route, false)
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
            || !valid_endpoint_path_v1(&base_path, true)
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
                parse_explicit_port_v1(suffix.strip_prefix(':').ok_or(())?)?
            };
            let canonical_ipv6 = host.parse::<Ipv6Addr>().map_err(|_| ())?.to_string();
            if host != canonical_ipv6 {
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
                Some((host, port)) if !host.contains(':') => (host, parse_explicit_port_v1(port)?),
                _ => (authority, 443),
            };
            let host = canonical_ipv4_or_dns_host_v1(host)?;
            (
                host.clone(),
                host.clone(),
                port,
                if port == 443 {
                    host
                } else {
                    format!("{host}:{port}")
                },
            )
        };
        let path = format!("{base_path}{route}");
        if !valid_endpoint_path_v1(&path, false) {
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

fn canonical_ipv4_or_dns_host_v1(value: &str) -> Result<String, ()> {
    match value.parse::<Ipv4Addr>() {
        Ok(address) if address.to_string() == value => Ok(value.to_owned()),
        Ok(_) => Err(()),
        Err(_) => {
            // Numeric-looking authorities have several legacy, platform-
            // dependent interpretations (for example shortened IPv4 forms).
            // Never hand those to `ToSocketAddrs`; an IP literal has exactly
            // one accepted spelling here.
            if value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
                || !valid_dns_host_v1(value)
            {
                Err(())
            } else {
                Ok(value.to_owned())
            }
        }
    }
}

fn parse_explicit_port_v1(value: &str) -> Result<u16, ()> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(());
    }
    let port = value.parse::<u16>().map_err(|_| ())?;
    // The default port has one canonical spelling: omit it.
    if port == 0 || port == 443 {
        return Err(());
    }
    Ok(port)
}

fn valid_dns_host_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn valid_endpoint_path_v1(value: &str, allow_empty: bool) -> bool {
    if value.is_empty() {
        return allow_empty;
    }
    value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && value.bytes().all(|byte| {
            byte == b'/'
                || byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~')
        })
        && value
            .split('/')
            .skip(1)
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn accept_header_value_v1(success: &str, error: &str) -> String {
    if success == error {
        success.to_owned()
    } else {
        format!("{success}, {error}")
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
    expected_success_content_type: &str,
    expected_error_content_type: &str,
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
            // Response media types are protocol discriminants, not content
            // negotiation hints. Parameters (including a charset) are not an
            // exact match and therefore fail closed.
            content_type = Some(value.trim_matches(|character| matches!(character, ' ' | '\t')));
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
    // The payment protocols all define HTTP 200 as the
    // sole transport success status. Treating another 2xx as success would let
    // an edge or intermediary silently change the protocol contract.
    let expected_content_type = if status == 200 {
        expected_success_content_type
    } else {
        expected_error_content_type
    };
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
    if status == 200 {
        // Ownership passes directly to the caller without a second copy. The
        // adapter-owned application buffers have zeroizing guards; payment
        // callers must wrap the returned body immediately, as the transport
        // adapters do. The rustls/kernel/allocator residuals above still
        // apply.
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
    use rustls::pki_types::pem::PemObject;

    fn test_certificate_v1(pem: &'static [u8]) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem).expect("static test certificate must parse")
    }

    fn test_leaf_spki_pin_v1(leaf: &CertificateDer<'_>) -> [u8; 32] {
        let parsed = ParsedCertificate::try_from(leaf).expect("static leaf certificate must parse");
        Sha256::digest(parsed.subject_public_key_info().as_ref()).into()
    }

    fn test_pinned_verifier_v1(
        root: CertificateDer<'static>,
        pins: &[[u8; 32]],
    ) -> WebPkiAndLeafSpkiPinVerifierV1 {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        roots.add(root).expect("static root certificate must parse");
        let webpki =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .expect("test WebPKI verifier must build");
        WebPkiAndLeafSpkiPinVerifierV1 {
            webpki,
            leaf_spki_sha256_pins: pins.to_vec(),
        }
    }

    #[test]
    fn leaf_spki_pin_is_additive_to_webpki() {
        let root = test_certificate_v1(include_bytes!("testdata/root.pem"));
        let wrong_root = test_certificate_v1(include_bytes!("testdata/wrong-root.pem"));
        let leaf = test_certificate_v1(include_bytes!("testdata/leaf.pem"));
        let pin = test_leaf_spki_pin_v1(&leaf);
        assert_eq!(
            pin,
            [
                0x53, 0xe7, 0x0a, 0xf8, 0x50, 0x41, 0x22, 0xf4, 0xa9, 0x75, 0x53, 0xd4, 0xe0, 0x64,
                0x03, 0xe9, 0xcf, 0xe3, 0xac, 0x93, 0x1d, 0x4c, 0x39, 0xa2, 0x99, 0x08, 0xdc, 0x19,
                0x2d, 0x74, 0x1a, 0xf9,
            ],
            "known vector must hash the complete SPKI DER, not another certificate field"
        );
        let correct_name = ServerName::try_from("authority.example".to_owned()).unwrap();
        let wrong_name = ServerName::try_from("wrong.example".to_owned()).unwrap();
        let valid_time = UnixTime::since_unix_epoch(Duration::from_secs(1_893_456_000));

        let valid = test_pinned_verifier_v1(root.clone(), &[pin]);
        assert!(
            valid
                .verify_server_cert(&leaf, &[], &correct_name, &[], valid_time)
                .is_ok(),
            "matching pin plus valid WebPKI chain/name must pass"
        );
        let rotation = test_pinned_verifier_v1(root.clone(), &[[0x55; 32], pin]);
        assert!(
            rotation
                .verify_server_cert(&leaf, &[], &correct_name, &[], valid_time)
                .is_ok(),
            "either distinct rotation pin may match"
        );
        assert!(
            valid
                .verify_server_cert(&leaf, &[], &wrong_name, &[], valid_time)
                .is_err(),
            "a matching pin must not bypass hostname verification"
        );
        for invalid_time in [
            UnixTime::since_unix_epoch(Duration::from_secs(1_600_000_000)),
            UnixTime::since_unix_epoch(Duration::from_secs(7_300_000_000)),
        ] {
            assert!(
                valid
                    .verify_server_cert(&leaf, &[], &correct_name, &[], invalid_time)
                    .is_err(),
                "a matching pin must not bypass certificate validity time"
            );
        }

        let wrong_pin = test_pinned_verifier_v1(root, &[[0x55; 32]]);
        assert!(
            wrong_pin
                .verify_server_cert(&leaf, &[], &correct_name, &[], valid_time)
                .is_err(),
            "a valid WebPKI certificate with the wrong pin must fail"
        );
        let certificate_der_hash: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        assert_ne!(certificate_der_hash, pin);
        let wrong_hash_scope = test_pinned_verifier_v1(
            test_certificate_v1(include_bytes!("testdata/root.pem")),
            &[certificate_der_hash],
        );
        assert!(
            wrong_hash_scope
                .verify_server_cert(&leaf, &[], &correct_name, &[], valid_time)
                .is_err(),
            "a whole-certificate hash must not be accepted as an SPKI pin"
        );

        let bad_chain = test_pinned_verifier_v1(wrong_root, &[pin]);
        assert!(
            bad_chain
                .verify_server_cert(&leaf, &[], &correct_name, &[], valid_time)
                .is_err(),
            "a matching pin must not bypass chain verification"
        );
    }

    #[test]
    fn pinned_constructor_requires_a_small_distinct_pin_set() {
        let timeout = Duration::from_secs(1);
        assert!(
            StrictHttpsClientV1::new_with_leaf_spki_sha256_pins(timeout, timeout, &[]).is_err()
        );
        assert!(StrictHttpsClientV1::new_with_leaf_spki_sha256_pins(
            timeout,
            timeout,
            &[[1; 32], [2; 32], [3; 32]],
        )
        .is_err());
        assert!(StrictHttpsClientV1::new_with_leaf_spki_sha256_pins(
            timeout,
            timeout,
            &[[1; 32], [1; 32]],
        )
        .is_err());
        assert!(
            StrictHttpsClientV1::new_with_leaf_spki_sha256_pins(timeout, timeout, &[[0; 32]],)
                .is_err()
        );
        assert!(StrictHttpsClientV1::new_with_leaf_spki_sha256_pins(
            timeout,
            timeout,
            &[[2; 32], [1; 32]],
        )
        .is_err());
        assert!(StrictHttpsClientV1::new_with_leaf_spki_sha256_pins(
            timeout,
            timeout,
            &[[1; 32], [2; 32]],
        )
        .is_ok());
    }

    #[test]
    fn caller_absolute_deadline_caps_every_stage() {
        let absolute = Instant::now() + Duration::from_millis(100);
        let bounded = bounded_deadline_after_v1(Duration::from_secs(60), Some(absolute)).unwrap();
        assert_eq!(bounded, absolute);

        let client =
            StrictHttpsClientV1::new(Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        assert_eq!(
            client.post_with_error_content_type_until(
                "https://authority.example",
                "/v1/call",
                "application/octet-stream",
                "application/octet-stream",
                "application/problem+json",
                b"request",
                1_024,
                Instant::now(),
            ),
            Err(HttpsPostErrorV1::DefinitelyNotSent)
        );
    }

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
        assert!(StrictHttpsClientV1::validate_base_endpoint("https://mint.example/api").is_ok());
        assert!(StrictHttpsClientV1::validate_base_endpoint("https://[::1]:8443/api-v1").is_ok());
        assert!(StrictHttpsClientV1::validate_base_endpoint("https://mint.example/").is_err());
        assert!(StrictHttpsClientV1::validate_base_endpoint("https://user@mint.example").is_err());
        assert!(StrictHttpsClientV1::validate_base_endpoint("https://Mint.example").is_err());
        assert!(StrictHttpsClientV1::validate_base_endpoint("https://mint.example:443").is_err());
        assert!(
            StrictHttpsClientV1::validate_base_endpoint("https://mint.example/../api").is_err()
        );

        assert_eq!(
            accept_header_value_v1("application/cbor", "application/problem+json"),
            "application/cbor, application/problem+json"
        );
        assert_eq!(
            accept_header_value_v1("application/json", "application/json"),
            "application/json"
        );

        let wire = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(
            parse_http_response_v1(wire, "application/json", "application/problem+json", 5)
                .unwrap(),
            b"abcde"
        );
        assert_eq!(
            parse_http_response_v1(wire, "application/json", "application/problem+json", 4),
            Err(HttpsPostErrorV1::InvalidResponse)
        );

        let error_body = br#"{"code":10001,"detail":"proof verification failed"}"#;
        let error_wire = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            error_body.len(),
            std::str::from_utf8(error_body).unwrap(),
        );
        assert_eq!(
            parse_http_response_v1(
                error_wire.as_bytes(),
                "application/cbor",
                "application/json",
                1_024,
            ),
            Err(HttpsPostErrorV1::HttpStatus {
                status: 400,
                body: Zeroizing::new(error_body.to_vec()),
            })
        );
        let html_wire = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nerror";
        assert_eq!(
            parse_http_response_v1(
                html_wire,
                "application/json",
                "application/problem+json",
                1_024,
            ),
            Err(HttpsPostErrorV1::InvalidResponse)
        );

        for (status, reason) in [(201, "Created"), (204, "No Content"), (299, "Other")] {
            let success_media = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\n\r\nx"
            );
            assert_eq!(
                parse_http_response_v1(
                    success_media.as_bytes(),
                    "application/cbor",
                    "application/problem+json",
                    1_024,
                ),
                Err(HttpsPostErrorV1::InvalidResponse),
                "non-200 status {status} was accepted with the success media type"
            );

            let problem_media = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/problem+json\r\nContent-Length: 1\r\n\r\nx"
            );
            assert_eq!(
                parse_http_response_v1(
                    problem_media.as_bytes(),
                    "application/cbor",
                    "application/problem+json",
                    1_024,
                ),
                Err(HttpsPostErrorV1::HttpStatus {
                    status,
                    body: Zeroizing::new(b"x".to_vec()),
                }),
                "non-200 status {status} did not remain a non-success result"
            );
        }
    }
}

#[cfg(test)]
#[path = "adversarial_tests.rs"]
mod adversarial_tests;
