//! Credit issuer client (docs/CREDITS.md "Issuer API"): a signed
//! `POST /v1/redeem` for every presentation a client makes, `GET /v1/info`
//! for the gas parameters at startup, and the minimal HTTP/1.1 client over
//! rustls with the Mozilla roots that carries both.
//!
//! Trust: the transport authenticates the issuer's host name; the redeem
//! answer is additionally signed by the issuer's Ed25519 key — the same key
//! the server already pins for session grants — and bound to the request
//! nonce, so nothing between server and issuer (a CDN, a proxy) can grant
//! gas. Requests are signed by the server's identity key and carry its
//! operator-signed certificate, so the issuer can settle per server.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pir_credit::issuer::{
    IssuerErrorV1, IssuerInfoV2, RedeemItemV1, RedeemRequestV1, RedeemResponseV1,
    CREDIT_PRESENT_KIND_ARC, CREDIT_PRESENT_KIND_CASHU, ISSUER_API_VERSION, REDEEM_NONCE_LEN,
};
use pir_identity::IdentityCert;
use runtime::protocol::MAX_CREDIT_PRESENT_PAYLOAD_LEN;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::cli::CliArgs;

/// Whole-request budget (connect, TLS, write, read) for one issuer call.
pub(crate) const ISSUER_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest issuer response body the client reads.
const MAX_ISSUER_RESPONSE_BYTES: usize = 1024 * 1024;
const REDEEM_PATH: &str = "/v1/redeem";
const INFO_PATH: &str = "/v1/info";

/// Everything credits need on this server.
pub(crate) struct CreditsV1 {
    pub(crate) issuer: CreditIssuerClientV1,
    /// `--require-credits`: charge metered frames and refuse uncovered ones.
    pub(crate) require: bool,
}

impl CreditsV1 {
    /// `None` without `--credit-issuer-url`. With it, the issuer's answers
    /// need at least one pinned `--session-grant-pubkey` key and the redeem
    /// requests need the server identity to sign with.
    pub(crate) fn from_cli(
        args: &CliArgs,
        identity: Option<(SigningKey, IdentityCert)>,
    ) -> Result<Option<Self>, String> {
        let Some(url) = args.credit_issuer_url.as_deref() else {
            if args.require_credits {
                return Err("--require-credits needs --credit-issuer-url URL".to_owned());
            }
            return Ok(None);
        };
        let url = IssuerUrl::parse(url)?;
        if args.session_grant_pubkeys.is_empty() {
            return Err(
                "--credit-issuer-url needs at least one --session-grant-pubkey FILE: the issuer's redeem answers are verified under that key"
                    .to_owned(),
            );
        }
        let mut issuer_keys = Vec::with_capacity(args.session_grant_pubkeys.len());
        for path in &args.session_grant_pubkeys {
            let key = crate::session_grant::load_public_key(path)?;
            issuer_keys.push(
                VerifyingKey::from_bytes(&key)
                    .map_err(|_| format!("{}: not an Ed25519 public key", path.display()))?,
            );
        }
        let Some((identity_key, cert)) = identity else {
            return Err(
                "--credit-issuer-url needs the server identity (--identity-key-path, --identity-cert-path, --identity-server-id, or the sealed pir2 identity) to sign redeem requests"
                    .to_owned(),
            );
        };
        let server_id = args
            .credit_server_id
            .clone()
            .unwrap_or_else(|| cert.server_id.clone());
        Ok(Some(Self {
            issuer: CreditIssuerClientV1::new(url, server_id, identity_key, &cert, issuer_keys),
            require: args.require_credits,
        }))
    }

    pub(crate) fn startup_log_line(&self) -> String {
        format!(
            "Credits: issuer={} server_id={} {} ({} issuer key(s) pinned)",
            self.issuer.url.display(),
            self.issuer.server_id,
            if self.require {
                "required for metered frames"
            } else {
                "accepted, not charged"
            },
            self.issuer.issuer_keys.len()
        )
    }
}

/// Structural check of a presentation before it costs the issuer a call.
pub(crate) fn validate_presentation(kind: u8, payload: &[u8]) -> Result<(), String> {
    if kind != CREDIT_PRESENT_KIND_CASHU && kind != CREDIT_PRESENT_KIND_ARC {
        return Err(format!(
            "unknown credit presentation kind {kind} (1 = Cashu token, 2 = ARC presentations)"
        ));
    }
    if payload.is_empty() {
        return Err("empty credit presentation".to_owned());
    }
    if payload.len() > MAX_CREDIT_PRESENT_PAYLOAD_LEN {
        return Err("credit presentation above the size limit".to_owned());
    }
    Ok(())
}

/// `https://host[:port][/prefix]`, or `http://` on loopback for tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IssuerUrl {
    https: bool,
    host: String,
    port: u16,
    prefix: String,
}

impl IssuerUrl {
    pub(crate) fn parse(url: &str) -> Result<Self, String> {
        let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(format!(
                "--credit-issuer-url must start with https:// (got {url:?})"
            ));
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse::<u16>()
                    .map_err(|_| format!("--credit-issuer-url: bad port in {authority:?}"))?,
            ),
            None => (authority, if https { 443 } else { 80 }),
        };
        if host.is_empty() || host.contains(['/', '?', '#', '@']) {
            return Err(format!("--credit-issuer-url: bad host in {url:?}"));
        }
        if !https && host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
            return Err(
                "--credit-issuer-url: plain http is allowed on loopback only; use https://"
                    .to_owned(),
            );
        }
        let prefix = path.trim_end_matches('/').to_owned();
        if prefix.contains(['?', '#']) {
            return Err(format!("--credit-issuer-url: query or fragment in {url:?}"));
        }
        Ok(Self {
            https,
            host: host.to_owned(),
            port,
            prefix,
        })
    }

    fn display(&self) -> String {
        let default_port = if self.https { 443 } else { 80 };
        let port = if self.port == default_port {
            String::new()
        } else {
            format!(":{}", self.port)
        };
        format!(
            "{}://{}{}{}",
            if self.https { "https" } else { "http" },
            self.host,
            port,
            self.prefix
        )
    }

    fn host_header(&self) -> String {
        let default_port = if self.https { 443 } else { 80 };
        if self.port == default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// A parsed HTTP/1.1 response: status code and body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

pub(crate) struct CreditIssuerClientV1 {
    url: IssuerUrl,
    server_id: String,
    identity_key: SigningKey,
    identity_cert_hex: String,
    issuer_keys: Vec<VerifyingKey>,
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
}

impl CreditIssuerClientV1 {
    pub(crate) fn new(
        url: IssuerUrl,
        server_id: String,
        identity_key: SigningKey,
        cert: &IdentityCert,
        issuer_keys: Vec<VerifyingKey>,
    ) -> Self {
        Self {
            url,
            server_id,
            identity_key,
            identity_cert_hex: hex::encode(cert.encode()),
            issuer_keys,
            tls: tls_config(),
            timeout: ISSUER_TIMEOUT,
        }
    }

    /// Forward `items` (`(kind, payload)`) to the issuer and return its
    /// verified answer. Transport failures are retried once with the same
    /// nonce; the issuer answers a repeated nonce from its store.
    pub(crate) async fn redeem(&self, items: &[(u8, Vec<u8>)]) -> Result<RedeemResponseV1, String> {
        let nonce: [u8; REDEEM_NONCE_LEN] = rand::random();
        let unix_time = crate::io::current_unix_seconds_v1()?;
        let request = self.build_redeem_request(&nonce, unix_time, items);
        let body =
            serde_json::to_vec(&request).map_err(|e| format!("encode redeem request: {e}"))?;
        let mut last_error = String::new();
        for attempt in 0..2 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            match self.http("POST", REDEEM_PATH, Some(&body)).await {
                Ok(response) => return self.verify_redeem_response(&nonce, &response),
                Err(error) => last_error = error,
            }
        }
        Err(format!("issuer unreachable: {last_error}"))
    }

    /// `GET /v1/info`, parsed and version-checked.
    pub(crate) async fn fetch_info(&self) -> Result<IssuerInfoV2, String> {
        let response = self.http("GET", INFO_PATH, None).await?;
        if response.status != 200 {
            return Err(format!("issuer info: HTTP {}", response.status));
        }
        let info: IssuerInfoV2 =
            serde_json::from_slice(&response.body).map_err(|e| format!("issuer info: {e}"))?;
        if info.version != ISSUER_API_VERSION {
            return Err(format!(
                "issuer info: version {} (this server speaks {ISSUER_API_VERSION})",
                info.version
            ));
        }
        info.gas_params()
            .validate()
            .map_err(|e| format!("issuer info: {e}"))?;
        Ok(info)
    }

    pub(crate) fn build_redeem_request(
        &self,
        nonce: &[u8; REDEEM_NONCE_LEN],
        unix_time: u64,
        items: &[(u8, Vec<u8>)],
    ) -> RedeemRequestV1 {
        let borrowed: Vec<(u8, &[u8])> = items
            .iter()
            .map(|(kind, payload)| (*kind, payload.as_slice()))
            .collect();
        let preimage =
            RedeemRequestV1::signing_preimage(&self.server_id, nonce, unix_time, &borrowed);
        let signature = self.identity_key.sign(&preimage);
        RedeemRequestV1 {
            server_id: self.server_id.clone(),
            identity_cert_hex: self.identity_cert_hex.clone(),
            nonce_hex: hex::encode(nonce),
            unix_time,
            items: items
                .iter()
                .map(|(kind, payload)| RedeemItemV1 {
                    kind: *kind,
                    payload_hex: hex::encode(payload),
                })
                .collect(),
            signature_hex: hex::encode(signature.to_bytes()),
        }
    }

    /// Accept a 200 whose body is a `RedeemResponseV1` signed by a pinned
    /// issuer key over this request's nonce; turn every other answer into
    /// the error the client sees.
    pub(crate) fn verify_redeem_response(
        &self,
        nonce: &[u8; REDEEM_NONCE_LEN],
        response: &HttpResponse,
    ) -> Result<RedeemResponseV1, String> {
        if response.status != 200 {
            return Err(
                match serde_json::from_slice::<IssuerErrorV1>(&response.body) {
                    Ok(error) => format!("issuer refused: {}: {}", error.error, error.message),
                    Err(_) => format!("issuer error: HTTP {}", response.status),
                },
            );
        }
        let answer: RedeemResponseV1 = serde_json::from_slice(&response.body)
            .map_err(|e| format!("issuer answer unreadable: {e}"))?;
        let signature = hex::decode(&answer.issuer_signature_hex)
            .ok()
            .and_then(|bytes| Signature::from_slice(&bytes).ok())
            .ok_or_else(|| "issuer answer: malformed signature".to_owned())?;
        let preimage = RedeemResponseV1::signing_preimage(
            nonce,
            answer.gas_added,
            answer.sat_value,
            answer.items_accepted,
        );
        if !self
            .issuer_keys
            .iter()
            .any(|key| key.verify(&preimage, &signature).is_ok())
        {
            return Err(
                "issuer answer: signature does not verify under a pinned issuer key".to_owned(),
            );
        }
        Ok(answer)
    }

    async fn http(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, String> {
        let mut request = format!(
            "{method} {}{path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: bitcoinpir-unified-server\r\nAccept: application/json\r\nConnection: close\r\n",
            self.url.prefix,
            self.url.host_header()
        )
        .into_bytes();
        if let Some(body) = body {
            request.extend_from_slice(
                format!(
                    "Content-Type: application/json\r\nContent-Length: {}\r\n",
                    body.len()
                )
                .as_bytes(),
            );
        }
        request.extend_from_slice(b"\r\n");
        if let Some(body) = body {
            request.extend_from_slice(body);
        }
        let raw = tokio::time::timeout(self.timeout, self.exchange(&request))
            .await
            .map_err(|_| {
                format!(
                    "issuer {method} {path}: timed out after {}s",
                    self.timeout.as_secs()
                )
            })??;
        parse_http_response(&raw)
    }

    async fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let tcp = TcpStream::connect((self.url.host.as_str(), self.url.port))
            .await
            .map_err(|e| format!("connect {}:{}: {e}", self.url.host, self.url.port))?;
        if self.url.https {
            let name = rustls_pki_types::ServerName::try_from(self.url.host.clone())
                .map_err(|_| format!("{}: not a valid TLS server name", self.url.host))?;
            let stream = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls))
                .connect(name, tcp)
                .await
                .map_err(|e| format!("tls {}: {e}", self.url.host))?;
            exchange_on(stream, request).await
        } else {
            exchange_on(tcp, request).await
        }
    }
}

async fn exchange_on<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &[u8],
) -> Result<Vec<u8>, String> {
    stream
        .write_all(request)
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > MAX_ISSUER_RESPONSE_BYTES {
            return Err("response above the size limit".to_owned());
        }
    }
    Ok(raw)
}

/// Status code and body of one `Connection: close` HTTP/1.1 response
/// (`Content-Length` or chunked transfer encoding).
pub(crate) fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "http: no header terminator".to_owned())?;
    let head = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "http: header is not UTF-8".to_owned())?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(format!("http: bad status line {status_line:?}"));
    }
    let status: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("http: bad status line {status_line:?}"))?;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse()
                    .map_err(|_| format!("http: bad content-length {value:?}"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    let rest = &raw[header_end + 4..];
    let body = if chunked {
        decode_chunked(rest)?
    } else if let Some(len) = content_length {
        if rest.len() < len {
            return Err(format!(
                "http: body truncated ({} of {len} bytes)",
                rest.len()
            ));
        }
        rest[..len].to_vec()
    } else {
        rest.to_vec()
    };
    Ok(HttpResponse { status, body })
}

fn decode_chunked(mut rest: &[u8]) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "http: chunk size line missing".to_owned())?;
        let size_line = std::str::from_utf8(&rest[..line_end])
            .map_err(|_| "http: chunk size not UTF-8".to_owned())?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("http: bad chunk size {size_hex:?}"))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(body);
        }
        if rest.len() < size + 2 {
            return Err("http: chunk truncated".to_owned());
        }
        body.extend_from_slice(&rest[..size]);
        if body.len() > MAX_ISSUER_RESPONSE_BYTES {
            return Err("response above the size limit".to_owned());
        }
        rest = &rest[size + 2..];
    }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_args_from;
    use pir_credit::issuer::REDEEM_RESPONSE_SIGNING_DOMAIN_V1;
    use tokio::net::TcpListener;

    fn args(extra: &[&str]) -> CliArgs {
        let mut argv = vec!["unified_server".to_owned()];
        argv.extend(extra.iter().map(|s| (*s).to_owned()));
        parse_args_from(argv)
    }

    fn identity() -> (SigningKey, IdentityCert) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let cert = IdentityCert {
            version: IdentityCert::CURRENT_VERSION,
            operator_pubkey: [1u8; 32],
            server_id: "pir-test".to_owned(),
            identity_pubkey: key.verifying_key().to_bytes(),
            valid_from: 0,
            valid_until: 0,
            signature: [2u8; 64],
        };
        (key, cert)
    }

    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn client(url: &str) -> CreditIssuerClientV1 {
        let (key, cert) = identity();
        CreditIssuerClientV1::new(
            IssuerUrl::parse(url).unwrap(),
            "pir-test".to_owned(),
            key,
            &cert,
            vec![issuer_key().verifying_key()],
        )
    }

    fn signed_answer(
        nonce: &[u8; REDEEM_NONCE_LEN],
        gas_added: u64,
        sat_value: u64,
        items: u32,
    ) -> String {
        let preimage = RedeemResponseV1::signing_preimage(nonce, gas_added, sat_value, items);
        let signature = issuer_key().sign(&preimage);
        serde_json::to_string(&RedeemResponseV1 {
            gas_added,
            sat_value,
            items_accepted: items,
            issuer_signature_hex: hex::encode(signature.to_bytes()),
        })
        .unwrap()
    }

    #[test]
    fn issuer_url_accepts_https_and_loopback_http_only() {
        let url = IssuerUrl::parse("https://cashier.example/").unwrap();
        assert_eq!(url.port, 443);
        assert_eq!(url.prefix, "");
        assert_eq!(url.display(), "https://cashier.example");
        assert_eq!(url.host_header(), "cashier.example");
        let url = IssuerUrl::parse("https://cashier.example:8443/issuer/").unwrap();
        assert_eq!(url.port, 8443);
        assert_eq!(url.prefix, "/issuer");
        assert_eq!(url.display(), "https://cashier.example:8443/issuer");
        assert_eq!(url.host_header(), "cashier.example:8443");
        assert!(IssuerUrl::parse("http://127.0.0.1:8085").is_ok());
        assert!(IssuerUrl::parse("http://cashier.example").is_err());
        assert!(IssuerUrl::parse("ws://cashier.example").is_err());
        assert!(IssuerUrl::parse("https://").is_err());
        assert!(IssuerUrl::parse("https://cashier.example:x").is_err());
        assert!(IssuerUrl::parse("https://cashier.example/v1?x=1").is_err());
    }

    #[test]
    fn presentations_are_checked_structurally() {
        assert!(validate_presentation(CREDIT_PRESENT_KIND_CASHU, b"cashuB").is_ok());
        assert!(validate_presentation(CREDIT_PRESENT_KIND_ARC, &[1]).is_ok());
        assert!(validate_presentation(0, &[1]).is_err());
        assert!(validate_presentation(3, &[1]).is_err());
        assert!(validate_presentation(CREDIT_PRESENT_KIND_ARC, &[]).is_err());
        assert!(validate_presentation(
            CREDIT_PRESENT_KIND_ARC,
            &vec![0u8; MAX_CREDIT_PRESENT_PAYLOAD_LEN + 1]
        )
        .is_err());
    }

    #[test]
    fn from_cli_needs_url_key_and_identity_together() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("issuer.pub");
        std::fs::write(
            &key_path,
            hex::encode(issuer_key().verifying_key().to_bytes()),
        )
        .unwrap();
        let key_arg = key_path.to_string_lossy().into_owned();
        assert!(CreditsV1::from_cli(&args(&[]), Some(identity()))
            .unwrap()
            .is_none());
        assert!(CreditsV1::from_cli(&args(&["--require-credits"]), Some(identity())).is_err());
        assert!(CreditsV1::from_cli(
            &args(&["--credit-issuer-url", "https://cashier.example"]),
            Some(identity())
        )
        .is_err());
        assert!(CreditsV1::from_cli(
            &args(&[
                "--credit-issuer-url",
                "https://cashier.example",
                "--session-grant-pubkey",
                &key_arg
            ]),
            None
        )
        .is_err());
        let credits = CreditsV1::from_cli(
            &args(&[
                "--credit-issuer-url",
                "https://cashier.example",
                "--session-grant-pubkey",
                &key_arg,
                "--require-credits",
            ]),
            Some(identity()),
        )
        .unwrap()
        .unwrap();
        assert!(credits.require);
        assert_eq!(
            credits.issuer.server_id, "pir-test",
            "defaults to the certificate's server id"
        );
        assert_eq!(
            credits.startup_log_line(),
            "Credits: issuer=https://cashier.example server_id=pir-test required for metered frames (1 issuer key(s) pinned)"
        );
        let credits = CreditsV1::from_cli(
            &args(&[
                "--credit-issuer-url",
                "https://cashier.example",
                "--session-grant-pubkey",
                &key_arg,
                "--credit-server-id",
                "pir9",
            ]),
            Some(identity()),
        )
        .unwrap()
        .unwrap();
        assert!(!credits.require);
        assert_eq!(credits.issuer.server_id, "pir9");
    }

    #[test]
    fn redeem_requests_are_signed_by_the_identity_key() {
        let c = client("https://cashier.example");
        let nonce = [4u8; REDEEM_NONCE_LEN];
        let request = c.build_redeem_request(&nonce, 1_800_000_000, &[(2, vec![0xaa, 0xbb])]);
        assert_eq!(request.server_id, "pir-test");
        assert_eq!(request.nonce_hex, hex::encode(nonce));
        assert_eq!(request.items.len(), 1);
        assert_eq!(request.items[0].payload_hex, "aabb");
        assert_eq!(
            hex::decode(&request.identity_cert_hex).unwrap(),
            identity().1.encode()
        );
        let preimage = RedeemRequestV1::signing_preimage(
            "pir-test",
            &nonce,
            1_800_000_000,
            &[(2, &[0xaa, 0xbb])],
        );
        let signature =
            Signature::from_slice(&hex::decode(&request.signature_hex).unwrap()).unwrap();
        identity()
            .0
            .verifying_key()
            .verify(&preimage, &signature)
            .unwrap();
    }

    #[test]
    fn redeem_answers_must_carry_a_pinned_signature_over_this_nonce() {
        let c = client("https://cashier.example");
        let nonce = [5u8; REDEEM_NONCE_LEN];
        let ok = HttpResponse {
            status: 200,
            body: signed_answer(&nonce, 72_000, 10, 1).into_bytes(),
        };
        let answer = c.verify_redeem_response(&nonce, &ok).unwrap();
        assert_eq!(
            (answer.gas_added, answer.sat_value, answer.items_accepted),
            (72_000, 10, 1)
        );
        // Another nonce: replayed answer.
        assert!(c
            .verify_redeem_response(&[6u8; REDEEM_NONCE_LEN], &ok)
            .is_err());
        // Tampered gas.
        let mut tampered: RedeemResponseV1 = serde_json::from_slice(&ok.body).unwrap();
        tampered.gas_added = 720_000;
        let tampered = HttpResponse {
            status: 200,
            body: serde_json::to_vec(&tampered).unwrap(),
        };
        assert!(c.verify_redeem_response(&nonce, &tampered).is_err());
        // Signed by an unknown key.
        let preimage = RedeemResponseV1::signing_preimage(&nonce, 72_000, 10, 1);
        let foreign = SigningKey::from_bytes(&[8u8; 32]).sign(&preimage);
        let foreign = HttpResponse {
            status: 200,
            body: serde_json::to_vec(&RedeemResponseV1 {
                gas_added: 72_000,
                sat_value: 10,
                items_accepted: 1,
                issuer_signature_hex: hex::encode(foreign.to_bytes()),
            })
            .unwrap(),
        };
        assert!(c.verify_redeem_response(&nonce, &foreign).is_err());
        // Issuer refusals surface their code and message.
        let refused = HttpResponse {
            status: 402,
            body: br#"{"error":"double_spend","message":"tag already seen"}"#.to_vec(),
        };
        assert_eq!(
            c.verify_redeem_response(&nonce, &refused).unwrap_err(),
            "issuer refused: double_spend: tag already seen"
        );
        let opaque = HttpResponse {
            status: 503,
            body: b"<html>".to_vec(),
        };
        assert_eq!(
            c.verify_redeem_response(&nonce, &opaque).unwrap_err(),
            "issuer error: HTTP 503"
        );
        assert!(REDEEM_RESPONSE_SIGNING_DOMAIN_V1.starts_with(b"BPIR-CREDIT-REDEEM-RESPONSE"));
    }

    #[test]
    fn http_responses_parse_content_length_and_chunked_bodies() {
        let r = parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\ncontent-length: 5\r\n\r\nhelloEXTRA").unwrap();
        assert_eq!(
            r,
            HttpResponse {
                status: 200,
                body: b"hello".to_vec()
            }
        );
        let r = parse_http_response(b"HTTP/1.1 402 Payment Required\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;ext\r\nde\r\n0\r\n\r\n").unwrap();
        assert_eq!(
            r,
            HttpResponse {
                status: 402,
                body: b"abcde".to_vec()
            }
        );
        let r = parse_http_response(b"HTTP/1.0 204 No Content\r\n\r\n").unwrap();
        assert_eq!(
            r,
            HttpResponse {
                status: 204,
                body: Vec::new()
            }
        );
        assert!(parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort").is_err());
        assert!(parse_http_response(b"garbage").is_err());
        assert!(parse_http_response(b"SPDY 200\r\n\r\n").is_err());
        assert!(parse_http_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"
        )
        .is_err());
    }

    #[tokio::test]
    async fn redeem_round_trips_through_a_fake_issuer_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let identity_pubkey = identity().0.verifying_key();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = socket.read(&mut chunk).await.unwrap();
                raw.extend_from_slice(&chunk[..n]);
                let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let head = String::from_utf8_lossy(&raw[..end]).to_string();
                let length: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                if raw.len() >= end + 4 + length {
                    assert!(head.starts_with("POST /issuer/v1/redeem HTTP/1.1\r\n"));
                    assert!(head.contains("Host: 127.0.0.1:"));
                    let request: RedeemRequestV1 =
                        serde_json::from_slice(&raw[end + 4..end + 4 + length]).unwrap();
                    // The fake issuer checks the server's signature the real one will check.
                    let nonce: [u8; REDEEM_NONCE_LEN] =
                        hex::decode(&request.nonce_hex).unwrap().try_into().unwrap();
                    let items: Vec<(u8, Vec<u8>)> = request
                        .items
                        .iter()
                        .map(|i| (i.kind, hex::decode(&i.payload_hex).unwrap()))
                        .collect();
                    let borrowed: Vec<(u8, &[u8])> =
                        items.iter().map(|(k, p)| (*k, p.as_slice())).collect();
                    let preimage = RedeemRequestV1::signing_preimage(
                        &request.server_id,
                        &nonce,
                        request.unix_time,
                        &borrowed,
                    );
                    let signature =
                        Signature::from_slice(&hex::decode(&request.signature_hex).unwrap())
                            .unwrap();
                    identity_pubkey.verify(&preimage, &signature).unwrap();
                    assert_eq!(request.server_id, "pir-test");
                    assert_eq!(items, vec![(2u8, vec![0xaa, 0xbb, 0xcc])]);
                    let body = signed_answer(&nonce, 144_000, 20, 1);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                    socket.shutdown().await.unwrap();
                    return;
                }
            }
        });
        let c = client(&format!("http://127.0.0.1:{port}/issuer"));
        let answer = c.redeem(&[(2, vec![0xaa, 0xbb, 0xcc])]).await.unwrap();
        assert_eq!(answer.gas_added, 144_000);
        assert_eq!(answer.sat_value, 20);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn issuer_refusals_and_dead_issuers_are_reported_not_credited() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut chunk = [0u8; 4096];
            let _ = socket.read(&mut chunk).await.unwrap();
            let body = r#"{"error":"token_rejected","message":"already spent"}"#;
            let response = format!(
                "HTTP/1.1 402 Payment Required\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let c = client(&format!("http://127.0.0.1:{port}"));
        assert_eq!(
            c.redeem(&[(1, vec![1])]).await.unwrap_err(),
            "issuer refused: token_rejected: already spent"
        );
        server.await.unwrap();
        // Nothing listens any more: transport failure after the retry.
        let error = c.redeem(&[(1, vec![1])]).await.unwrap_err();
        assert!(
            error.starts_with("issuer unreachable: connect 127.0.0.1:"),
            "{error}"
        );
    }
}
