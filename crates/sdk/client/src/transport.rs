//! Transport abstraction for PIR client wire I/O.
//!
//! All PIR clients' request/response loops flow through the [`PirTransport`]
//! trait. This lets us have:
//!
//! * The default native impl, [`WsConnection`](crate::connection::WsConnection),
//!   which uses `tokio-tungstenite` over `tokio::net::TcpStream`.
//! * A WASM impl, `WasmWebSocketTransport` (in the `wasm_transport` module,
//!   cfg-gated to `target_arch = "wasm32"`), backed by `web-sys::WebSocket`
//!   and `wasm-bindgen-futures::spawn_local`, since the tokio stack doesn't
//!   compile to `wasm32-unknown-unknown`.
//! * An in-memory [`MockTransport`] for testing client state-machines
//!   without a live server (see `#[cfg(test)]` below).
//!
//! The trait carries no opinion about padding, FHE state, or protocol layer —
//! those are client concerns. It only moves opaque byte frames with a shared
//! deadline.
//!
//! # Relationship to [`WsConnection`]
//!
//! `WsConnection` keeps its own inherent methods (`send`, `recv`, `roundtrip`,
//! `close`) — this is the shape callers already use and the concrete type
//! owns the retry/backoff/connect/reconnect surface that doesn't make sense
//! on a generic trait. The [`PirTransport`] impl is a thin delegation layer,
//! so `&mut WsConnection` can be passed wherever `&mut dyn PirTransport` is
//! expected.

use async_trait::async_trait;
use pir_sdk::{PirMetrics, PirResult};
use std::sync::Arc;

/// Generic bidirectional wire transport for PIR clients.
///
/// # Invariants
///
/// * **Frame atomicity**: one call to [`send`](PirTransport::send) or the
///   send half of [`roundtrip`](PirTransport::roundtrip) produces exactly
///   one binary frame on the wire.
/// * **Control frames** (WebSocket ping/pong) MUST be handled internally —
///   callers only ever see binary response frames.
/// * **Close is one-way**: once [`close`](PirTransport::close) has been
///   called, every subsequent `send` / `recv` / `roundtrip` MUST return an
///   error (typically [`PirError::ConnectionClosed`](pir_sdk::PirError::ConnectionClosed))
///   rather than hang.
/// * **Deadlines**: implementations SHOULD enforce a per-operation deadline.
///   A wedged peer must never hang a caller indefinitely — return
///   [`PirError::Timeout`](pir_sdk::PirError::Timeout) instead.
///
/// # Thread safety
///
/// All methods take `&mut self`, so a transport is not shared across tasks —
/// callers serialize requests. The [`Send`] + [`Sync`] bounds let clients
/// that own a transport satisfy the `PirClient: Send + Sync` contract and
/// be spawned onto a multi-threaded runtime. `Sync` is required because
/// `PirClient` implementors hold `Option<Box<dyn PirTransport>>` fields,
/// and `Box<dyn T>` is `Sync` iff `T: Sync`.
///
/// # Padding
///
/// The trait is deliberately padding-agnostic. Clients MUST preserve the
/// K=75 / K_CHUNK=80 / 25-MERKLE padding invariants (see
/// `CLAUDE.md "Query Padding"`) in the byte buffers they hand to `send` /
/// `roundtrip`. A compliant transport won't drop or coalesce padding slots,
/// but it also can't add missing ones — that's the client's job.
#[async_trait]
pub trait PirTransport: Send + Sync {
    /// Send a binary frame, subject to the implementation's request deadline.
    ///
    /// Takes ownership of `data` so implementations can move the buffer into
    /// the sink without copying. Matches the existing
    /// [`WsConnection::send`](crate::connection::WsConnection::send) signature
    /// to keep the refactor zero-behavior-change.
    async fn send(&mut self, data: Vec<u8>) -> PirResult<()>;

    /// Receive the next binary frame, transparently handling ping/pong.
    /// Subject to the implementation's request deadline.
    ///
    /// The returned buffer is the **full** WebSocket binary frame the peer
    /// sent, including any length prefix the PIR wire protocol uses —
    /// unlike [`roundtrip`](PirTransport::roundtrip), which strips the
    /// leading 4-byte length. This asymmetry matches the existing
    /// [`WsConnection`](crate::connection::WsConnection) contract and the
    /// three clients' call sites (all of which do `&resp[4..]` after
    /// `recv`).
    async fn recv(&mut self) -> PirResult<Vec<u8>>;

    /// Send a request and receive a response, subject to a single deadline
    /// covering **both** halves.
    ///
    /// Using one combined deadline (rather than one per half) is what
    /// catches the attack shape where a server accepts a request quickly
    /// but then stalls on the response — otherwise the caller's
    /// effective timeout doubles for free.
    ///
    /// The returned buffer has the **4-byte length prefix already stripped**
    /// (to match the existing
    /// [`WsConnection::roundtrip`](crate::connection::WsConnection::roundtrip)
    /// contract). [`recv`](PirTransport::recv) leaves the prefix in place.
    /// Mixing the two on the same transport is fine.
    async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>>;

    /// Close the transport. Implementations should send a graceful close
    /// frame if the underlying protocol supports it. Returning `Ok` means
    /// "close initiated" — callers must not assume the remote has
    /// acknowledged.
    async fn close(&mut self) -> PirResult<()>;

    /// The endpoint URL or identifier this transport is attached to. Used
    /// for audit logging. The exact format is transport-defined — e.g.
    /// `"wss://pir1.example.com/"` for WebSocket, `"mock://test-1"` for
    /// an in-memory mock.
    fn url(&self) -> &str;

    /// Install a metrics recorder. The transport fires per-frame
    /// [`on_bytes_sent`](PirMetrics::on_bytes_sent) /
    /// [`on_bytes_received`](PirMetrics::on_bytes_received) callbacks
    /// on the installed recorder for every [`send`](PirTransport::send)
    /// / [`recv`](PirTransport::recv) / [`roundtrip`](PirTransport::roundtrip)
    /// call thereafter. The `backend` argument is threaded through to
    /// the callbacks so a single recorder can disambiguate metrics
    /// from multiple transports (e.g. a DPF client holds two).
    ///
    /// Pass `None` to uninstall; pass a fresh `Arc` to replace.
    ///
    /// Default impl: no-op. Transports that care about per-frame byte
    /// counting override this and the relevant send/recv paths;
    /// transports that don't care (e.g. a test-only shim) can ignore
    /// it — the client will still receive aggregated query-level
    /// callbacks fired from above the transport layer.
    fn set_metrics_recorder(
        &mut self,
        _recorder: Option<Arc<dyn PirMetrics>>,
        _backend: &'static str,
    ) {
    }
}

// ─── Blanket impl for Box<T> ───────────────────────────────────────────────
//
// Without this, `&mut Box<dyn PirTransport>` doesn't coerce to
// `&mut dyn PirTransport` at function-call boundaries — the compiler demands
// an impl on the pointer itself. Clients hold their transports as
// `Option<Box<dyn PirTransport>>`, so this coercion is hit on every helper
// call (`fetch_tree_tops`, `verify_bucket_merkle_batch_dpf`, etc.).
//
// The `?Sized` bound lets this cover `Box<dyn PirTransport>` itself, not
// just `Box<WsConnection>` and friends. Each method just forwards to the
// inner value via `**self`.
#[async_trait]
impl<T: PirTransport + ?Sized> PirTransport for Box<T> {
    async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
        (**self).send(data).await
    }

    async fn recv(&mut self) -> PirResult<Vec<u8>> {
        (**self).recv().await
    }

    async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
        (**self).roundtrip(request).await
    }

    async fn close(&mut self) -> PirResult<()> {
        (**self).close().await
    }

    fn url(&self) -> &str {
        (**self).url()
    }

    fn set_metrics_recorder(
        &mut self,
        recorder: Option<Arc<dyn PirMetrics>>,
        backend: &'static str,
    ) {
        (**self).set_metrics_recorder(recorder, backend);
    }
}

// ─── WsConnection delegates to the trait (native only) ─────────────────────

/// The tokio-tungstenite-backed native transport lives in
/// [`crate::connection`] and is only available on
/// `cfg(not(target_arch = "wasm32"))`. The WASM equivalent is
/// [`crate::wasm_transport::WasmWebSocketTransport`].
#[cfg(not(target_arch = "wasm32"))]
use crate::connection::WsConnection;

/// Implemented as a thin delegation to `WsConnection`'s inherent methods.
/// The inherent methods stay the primary API surface (they own retry /
/// backoff / connect / reconnect, which don't generalize); the trait impl
/// is there so a caller can swap in a different transport without changing
/// client code.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl PirTransport for WsConnection {
    async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
        WsConnection::send(self, data).await
    }

    async fn recv(&mut self) -> PirResult<Vec<u8>> {
        WsConnection::recv(self).await
    }

    async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
        WsConnection::roundtrip(self, request).await
    }

    async fn close(&mut self) -> PirResult<()> {
        WsConnection::close(self).await
    }

    fn url(&self) -> &str {
        WsConnection::url(self)
    }

    fn set_metrics_recorder(
        &mut self,
        recorder: Option<Arc<dyn PirMetrics>>,
        backend: &'static str,
    ) {
        WsConnection::set_metrics_recorder(self, recorder, backend);
    }
}

// ─── In-memory mock transport for tests ─────────────────────────────────────

#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    // `pir_sdk::Instant` is the wasm32-friendly re-export of `web_time::Instant`
    // — same source used by `WsConnection::roundtrip` so the mock and the
    // native transport produce comparable `Duration` values when the same
    // recorder is installed against both.
    use pir_sdk::{Instant, PirError};
    use std::collections::VecDeque;
    use std::time::Duration;

    /// A scripted in-memory transport. Tests push canned responses onto the
    /// queue (one `Vec<u8>` per expected `recv` / response half of
    /// `roundtrip`) and every `send` records its payload in `sent`.
    ///
    /// The mock lets state-machine tests run without a WebSocket or tokio
    /// runtime, which is the main value prop of the trait.
    pub(crate) struct MockTransport {
        pub(crate) url: String,
        /// FIFO of canned response frames. Each call to `recv` / the
        /// response-half of `roundtrip` pops one.
        pub(crate) responses: VecDeque<Vec<u8>>,
        /// Record of every payload `send` / `roundtrip` wrote. Tests can
        /// assert on the exact wire bytes a client produced.
        pub(crate) sent: Vec<Vec<u8>>,
        /// Whether `close` has been called — subsequent ops then error.
        pub(crate) closed: bool,
        /// Metrics recorder + backend label installed via
        /// `set_metrics_recorder`. Fires on every send / recv / roundtrip
        /// once installed; `None` = silent.
        pub(crate) metrics: Option<(Arc<dyn PirMetrics>, &'static str)>,
    }

    impl MockTransport {
        pub(crate) fn new(url: &str) -> Self {
            Self {
                url: url.to_string(),
                responses: VecDeque::new(),
                sent: Vec::new(),
                closed: false,
                metrics: None,
            }
        }

        pub(crate) fn enqueue_response(&mut self, data: Vec<u8>) {
            self.responses.push_back(data);
        }

        fn fire_bytes_sent(&self, bytes: usize) {
            if let Some((rec, backend)) = &self.metrics {
                rec.on_bytes_sent(backend, bytes);
            }
        }

        fn fire_bytes_received(&self, bytes: usize) {
            if let Some((rec, backend)) = &self.metrics {
                rec.on_bytes_received(backend, bytes);
            }
        }

        fn fire_roundtrip_end(&self, bytes_out: usize, bytes_in: usize, duration: Duration) {
            if let Some((rec, backend)) = &self.metrics {
                rec.on_roundtrip_end(backend, bytes_out, bytes_in, duration);
            }
        }
    }

    #[async_trait]
    impl PirTransport for MockTransport {
        async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
            if self.closed {
                return Err(PirError::ConnectionClosed("mock closed".into()));
            }
            self.fire_bytes_sent(data.len());
            self.sent.push(data);
            Ok(())
        }

        async fn recv(&mut self) -> PirResult<Vec<u8>> {
            if self.closed {
                return Err(PirError::ConnectionClosed("mock closed".into()));
            }
            let frame = self
                .responses
                .pop_front()
                .ok_or_else(|| PirError::Protocol("mock: no enqueued response".into()))?;
            self.fire_bytes_received(frame.len());
            Ok(frame)
        }

        async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
            if self.closed {
                return Err(PirError::ConnectionClosed("mock closed".into()));
            }
            // Same `Option<Instant>`-threading pattern as
            // `WsConnection::roundtrip` — the clock-read is elided when
            // no recorder is installed, preserving the "no recorder =
            // zero overhead" invariant for the mock too.
            let started_at: Option<Instant> = self.metrics.is_some().then(Instant::now);
            let bytes_out = request.len();
            self.fire_bytes_sent(bytes_out);
            self.sent.push(request.to_vec());
            // Mimic WsConnection::roundtrip's "strip 4-byte length prefix"
            // behaviour — tests enqueue the full frame, the mock returns
            // what a real `roundtrip` would.
            let frame = self
                .responses
                .pop_front()
                .ok_or_else(|| PirError::Protocol("mock: no enqueued response".into()))?;
            if frame.len() < 4 {
                // Short-frame: byte counts already fired for send, recv
                // is suppressed (matches the WsConnection partial-success
                // contract). No on_roundtrip_end either.
                return Err(PirError::Protocol(
                    "mock: enqueued frame too short for length prefix".into(),
                ));
            }
            // Record the full frame length (what came off the wire),
            // not the post-strip payload — that matches what a real
            // transport would observe.
            let bytes_in = frame.len();
            self.fire_bytes_received(bytes_in);
            // Fire on_roundtrip_end only on full success — matches
            // WsConnection::roundtrip's contract.
            if let Some(start) = started_at {
                self.fire_roundtrip_end(bytes_out, bytes_in, start.elapsed());
            }
            Ok(frame[4..].to_vec())
        }

        async fn close(&mut self) -> PirResult<()> {
            self.closed = true;
            Ok(())
        }

        fn url(&self) -> &str {
            &self.url
        }

        fn set_metrics_recorder(
            &mut self,
            recorder: Option<Arc<dyn PirMetrics>>,
            backend: &'static str,
        ) {
            self.metrics = recorder.map(|r| (r, backend));
        }
    }
}
