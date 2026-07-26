//! Small blocking HTTPS/1.1 client for admission authorities.
//!
//! It deliberately has no redirects, cookies, ambient proxy credentials,
//! response decompression, or request/body logging. Callers must execute it on
//! a blocking worker when integrating it into an asynchronous runtime.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const MAX_HTTP_HEADER_BYTES_V1: usize = 32 * 1024;
const MAX_HTTP_HEADERS_V1: usize = 64;
const MAX_HTTP_WIRE_OVERHEAD_V1: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpsPostErrorV1 {
    /// No HTTP application bytes could have reached the remote authority.
    DefinitelyNotSent,
    /// Some request bytes may have reached the authority; retry only through
    /// the operation's exact idempotency/recovery protocol.
    OutcomeUnknown,
    HttpStatus(u16),
    InvalidResponse,
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
        let socket_addresses = endpoint
            .connect_authority()
            .to_socket_addrs()
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        let mut tcp = None;
        for address in socket_addresses {
            if let Ok(stream) = TcpStream::connect_timeout(&address, self.connect_timeout) {
                tcp = Some(stream);
                break;
            }
        }
        let tcp = tcp.ok_or(HttpsPostErrorV1::DefinitelyNotSent)?;
        tcp.set_read_timeout(Some(self.io_timeout))
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        tcp.set_write_timeout(Some(self.io_timeout))
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        tcp.set_nodelay(true)
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;

        let server_name = ServerName::try_from(endpoint.tls_name.clone())
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        let connection = ClientConnection::new(Arc::clone(&self.tls_config), server_name)
            .map_err(|_| HttpsPostErrorV1::DefinitelyNotSent)?;
        let mut stream = StreamOwned::new(connection, tcp);
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nAccept: {}\r\nContent-Length: {}\r\nConnection: close\r\nUser-Agent: BitcoinPIR-service-admission/1\r\n\r\n",
            endpoint.path,
            endpoint.host_header,
            request_content_type,
            expected_response_content_type,
            body.len(),
        );
        let mut request = Vec::with_capacity(head.len() + body.len());
        request.extend_from_slice(head.as_bytes());
        request.extend_from_slice(body);
        let mut written = 0usize;
        while written < request.len() {
            match stream.write(&request[written..]) {
                Ok(0) => {
                    return Err(if written == 0 {
                        HttpsPostErrorV1::DefinitelyNotSent
                    } else {
                        HttpsPostErrorV1::OutcomeUnknown
                    })
                }
                Ok(count) => written += count,
                Err(_) => {
                    return Err(if written == 0 {
                        HttpsPostErrorV1::DefinitelyNotSent
                    } else {
                        HttpsPostErrorV1::OutcomeUnknown
                    })
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
        let mut wire = Vec::new();
        let mut buffer = [0u8; 8 * 1024];
        loop {
            match stream.read(&mut buffer) {
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
        parse_http_response_v1(&wire, expected_response_content_type, max_response_bytes)
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
    if !(200..300).contains(&status) {
        return Err(HttpsPostErrorV1::HttpStatus(status));
    }
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
    let body = if chunked {
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
    };
    if body.is_empty() {
        return Err(HttpsPostErrorV1::InvalidResponse);
    }
    Ok(body)
}

fn decode_chunked_v1(
    mut encoded: &[u8],
    max_response_bytes: usize,
) -> Result<Vec<u8>, HttpsPostErrorV1> {
    let mut body = Vec::new();
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
                Ok(body)
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
    }
}

#[cfg(test)]
#[path = "service_http_adversarial_tests.rs"]
mod adversarial_tests;
