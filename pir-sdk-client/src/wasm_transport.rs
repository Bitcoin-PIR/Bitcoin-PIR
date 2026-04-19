//! `web-sys::WebSocket`-backed [`PirTransport`] for the browser.
//!
//! This module is compiled only on `wasm32-unknown-unknown`. It bridges the
//! DOM's callback-driven `WebSocket` to the async `PirTransport` trait via
//! an `mpsc` channel:
//!
//! ```text
//!  browser event loop                  async world
//!  ──────────────────                  ───────────
//!  ws.onmessage  ────── Vec<u8> ──►  UnboundedReceiver ──► recv().await
//!  ws.onerror    ────── Err(..)  ──►  UnboundedReceiver ──► recv().await
//!  ws.onclose    ────── Err(..)  ──►  UnboundedReceiver ──► recv().await
//!
//!  send().await  ──► ws.send_with_u8_array(&bytes)   (synchronous)
//!  close().await ──► ws.close()                      (synchronous)
//! ```
//!
//! Callbacks that outlive the `WasmWebSocketTransport::connect` future need
//! to stay alive for the lifetime of the transport — we keep them in
//! `Box<Closure<_>>` fields so Rust doesn't drop them while the JS side
//! still holds a reference.
//!
//! # Send / Sync story
//!
//! `web_sys::WebSocket`, `Closure<_>`, and `Rc<RefCell<_>>` are all
//! `!Send + !Sync`. But `PirTransport: Send + Sync` is a supertrait
//! requirement — without it, `Box<dyn PirTransport>` couldn't be stored in
//! a `DpfClient` that must itself be `Send + Sync` to satisfy `PirClient`.
//! And `#[async_trait]` makes trait-method futures `Send`, which in turn
//! requires all captured state to be `Send`.
//!
//! Fix: wrap every `!Send` field in [`Wasm32Shim<T>`], a thin
//! `#[repr(transparent)]` wrapper that unconditionally implements
//! `Send + Sync`. This is sound because the whole module is gated to
//! `wasm32-unknown-unknown`, which — absent the unstable `+atomics`
//! target feature — is single-threaded: `T` is never actually shared
//! between threads because no such second thread exists. We used to use
//! [`send_wrapper::SendWrapper`] for this, but its runtime thread-id
//! check spuriously fires during teardown of long-lived transports
//! (reproducibly on `close()` after a successful `HarmonyClient` hint
//! phase) even though the JS main thread never changed. `Wasm32Shim`
//! drops the check.
//!
//! # Not a drop-in for `WsConnection`
//!
//! Features deliberately omitted (for now):
//! * **Per-request deadlines** — need a browser timer (`setTimeout`) +
//!   cancellation story. `WsConnection` uses `tokio::time::timeout`; the
//!   equivalent for WASM is a follow-up.
//! * **Reconnect with backoff** — `WsConnection::reconnect` re-handshakes to
//!   the same URL; implementing the same shape in the browser is a follow-up.
//! * **Binary ping/pong** — the browser's `WebSocket` handles these
//!   automatically (RFC 6455 control frames are invisible to JS), so nothing
//!   is needed here.
//!
//! The important invariant *is* preserved: receiving `recv()` /
//! `roundtrip()` yields [`PirError::ConnectionClosed`] / [`PirError::Protocol`]
//! when the remote half goes away, so a wedged peer can't hang a caller
//! forever (the browser closes idle sockets eventually).
//!
//! 🔒 Like the native transport, this module is padding-agnostic. K=75 /
//! K_CHUNK=80 / 25-MERKLE padding lives in the clients that sit above it.

#![cfg(target_arch = "wasm32")]

use crate::transport::PirTransport;
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::StreamExt;
use js_sys::{ArrayBuffer, Uint8Array};
use pir_sdk::{Duration, Instant, PirError, PirMetrics, PirResult};
use std::cell::{Cell, RefCell};
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::sync::Arc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use web_sys::{BinaryType, ErrorEvent, Event, MessageEvent, WebSocket};

/// Transparent wrapper that unconditionally satisfies `Send + Sync`.
///
/// Sound because this module is gated to `wasm32-unknown-unknown` (see
/// the `#![cfg(target_arch = "wasm32")]` at the top), which is
/// single-threaded unless the unstable `+atomics` target feature is
/// enabled — this crate's build config does not enable it, so `T` is
/// never actually sent between threads because no second thread exists.
///
/// Replaces `send_wrapper::SendWrapper` whose runtime thread-id check
/// was observed to spuriously panic during teardown paths ("Dereferenced
/// SendWrapper<T> variable from a thread different to the one it has
/// been created with.") even though wasm is single-threaded. Since the
/// check added no additional safety on this target, removing it is the
/// cleanest fix.
#[repr(transparent)]
struct Wasm32Shim<T>(T);

// Safety: wasm32-unknown-unknown is single-threaded absent +atomics,
// which this crate does not enable. No second thread exists to receive
// a `Send` or observe a `Sync` access, so the impl is trivially sound.
unsafe impl<T> Send for Wasm32Shim<T> {}
unsafe impl<T> Sync for Wasm32Shim<T> {}

impl<T> Wasm32Shim<T> {
    fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for Wasm32Shim<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Wasm32Shim<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// Items the callbacks push onto the `UnboundedReceiver<IncomingFrame>`.
/// A channel of `Result<Vec<u8>, PirError>` would work too, but wrapping in
/// a dedicated enum makes the three terminal cases (closed / error / frame)
/// easy to distinguish in the match arm of `recv`.
enum IncomingFrame {
    /// A binary message from the server — `data` is the raw frame bytes
    /// (what the native `WsConnection::recv` would return, prefix and all).
    Binary(Vec<u8>),
    /// The browser surfaced an `error` event. After this, the socket is
    /// effectively dead and subsequent `recv` / `send` should fail.
    Error(String),
    /// The browser surfaced a `close` event. After this, `recv` returns
    /// [`PirError::ConnectionClosed`].
    Closed(String),
}

/// Owning handles for the four JS-side callbacks.
///
/// `Closure<dyn FnMut(...)>` is the idiomatic `wasm-bindgen` shape for a
/// callback registered on a DOM EventTarget. They must outlive the
/// `WebSocket` or the JS side dereferences freed memory.
#[allow(dead_code)]
struct Callbacks {
    on_open: Option<Closure<dyn FnMut(Event)>>,
    on_message: Option<Closure<dyn FnMut(MessageEvent)>>,
    on_error: Option<Closure<dyn FnMut(ErrorEvent)>>,
    on_close: Option<Closure<dyn FnMut(Event)>>,
}

/// `PirTransport` backed by the browser's `WebSocket`.
///
/// Construct via [`WasmWebSocketTransport::connect`]. The struct is
/// `Send + Sync` thanks to [`Wasm32Shim`] (see module docs); in practice
/// every access must stay on the thread that built it, which on
/// `wasm32-unknown-unknown` is always the only thread.
pub struct WasmWebSocketTransport {
    url: String,
    /// `WebSocket` handle for `send` and `close`. `Wasm32Shim` is sound
    /// because wasm32-unknown-unknown runs single-threaded.
    ws: Wasm32Shim<WebSocket>,
    /// Receives frames the `on_message` closure pushes.
    /// `mpsc::UnboundedReceiver` is `Send` on its own.
    rx: mpsc::UnboundedReceiver<IncomingFrame>,
    /// Closures kept alive for the lifetime of the transport. Held behind
    /// `Rc<RefCell<_>>` so `close()` can drop them to break the Browser →
    /// Closure → Channel reference cycle, then `Wasm32Shim` for the same
    /// single-thread soundness reason as `ws`.
    #[allow(dead_code)]
    callbacks: Wasm32Shim<Rc<RefCell<Callbacks>>>,
    /// Shared flag flipped to `true` by the `on_error` / `on_close`
    /// closures. `send()` / `roundtrip()` short-circuit on it so a
    /// server-side idle-timeout close doesn't send us into
    /// `WebSocket::send_with_u8_array` on a dead socket.
    closed: Wasm32Shim<Rc<Cell<bool>>>,
    /// Optional metrics recorder. Fires per-frame `on_bytes_sent` /
    /// `on_bytes_received` callbacks once installed via
    /// [`PirTransport::set_metrics_recorder`]. `None` = silent.
    /// `Arc<dyn PirMetrics>` is `Send + Sync` so it doesn't need the
    /// `Wasm32Shim` treatment the DOM-bound fields get above.
    metrics_recorder: Option<Arc<dyn PirMetrics>>,
    /// Backend label passed to the recorder's callbacks. Defaults to
    /// `""`; owning clients override via `set_metrics_recorder`.
    metrics_backend: &'static str,
}

impl WasmWebSocketTransport {
    /// Open a WebSocket to `url` and wait for the `open` event.
    ///
    /// Returns an error if the constructor throws (malformed URL, CORS
    /// violation) or if the connection fails before the handshake
    /// completes (network error, server refuses).
    ///
    /// The returned transport is ready for `send` / `recv` / `roundtrip`
    /// immediately — no further handshake is needed.
    pub async fn connect(url: &str) -> PirResult<Self> {
        // Build every !Send value inside this block and assemble the
        // transport + oneshot receiver. By the time we hit the `.await`
        // below, only `Send` things remain in scope, so `async_trait`'s
        // generated future is still `Send`.
        let (open_rx, transport) = build_transport(url)?;

        // Park until the socket finishes its handshake (or fails). The
        // callback closures registered above will send `Ok(())` on `open`
        // and `Err(msg)` on `error` / `close` — whichever fires first.
        match open_rx.await {
            Ok(Ok(())) => Ok(transport),
            Ok(Err(msg)) => Err(PirError::ConnectionFailed(format!(
                "WebSocket connect failed: {}",
                msg
            ))),
            Err(_cancelled) => Err(PirError::ConnectionFailed(
                "WebSocket connect: handshake channel cancelled".into(),
            )),
        }
    }
}

/// Synchronous half of `connect`: builds the JS side (WebSocket, closures,
/// callbacks struct) and returns the finished transport + a oneshot
/// receiver the caller awaits on. Split out so the `await` at the top
/// level doesn't see any `!Send` locals.
fn build_transport(
    url: &str,
) -> PirResult<(
    oneshot::Receiver<Result<(), String>>,
    WasmWebSocketTransport,
)> {
    // `WebSocket::new` throws on invalid URLs; convert the JS exception
    // to a PirError.
    let ws = WebSocket::new(url).map_err(|e| {
        PirError::ConnectionFailed(format!("WebSocket constructor threw: {:?}", e))
    })?;
    // Messages arrive as `ArrayBuffer`. The alternative (`Blob`) needs an
    // async FileReader step per message — wasted work for our binary-only
    // protocol.
    ws.set_binary_type(BinaryType::Arraybuffer);

    let (tx, rx) = mpsc::unbounded::<IncomingFrame>();

    // Sticky flag flipped by `on_error` / `on_close` so a server-side
    // idle-timeout close is observed by the next `send()` without
    // waiting for someone to call `recv()`. Cloned into both callbacks.
    let closed = Rc::new(Cell::new(false));

    // `on_open` fires exactly once, so we use a oneshot to notify
    // the `connect` future. `on_open_result` carries either the
    // `open` event or an early error if `on_error` / `on_close` fired
    // before `on_open`.
    let (open_tx, open_rx) = oneshot::channel::<Result<(), String>>();
    let open_tx = Rc::new(RefCell::new(Some(open_tx)));

    // ─── on_open ────────────────────────────────────────────────────
    let on_open = {
        let open_tx = open_tx.clone();
        Closure::wrap(Box::new(move |_ev: Event| {
            if let Some(tx) = open_tx.borrow_mut().take() {
                let _ = tx.send(Ok(()));
            }
        }) as Box<dyn FnMut(Event)>)
    };
    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

    // ─── on_message ─────────────────────────────────────────────────
    let on_message = {
        let tx = tx.clone();
        Closure::wrap(Box::new(move |ev: MessageEvent| {
            // ArrayBuffer path — only shape we care about (Blob /
            // string paths are filtered out by `set_binary_type`).
            if let Ok(ab) = ev.data().dyn_into::<ArrayBuffer>() {
                let arr = Uint8Array::new(&ab);
                let mut buf = vec![0u8; arr.length() as usize];
                arr.copy_to(&mut buf);
                let _ = tx.unbounded_send(IncomingFrame::Binary(buf));
            }
            // Silent drop for non-binary messages — the server never
            // sends them.
        }) as Box<dyn FnMut(MessageEvent)>)
    };
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

    // ─── on_error ───────────────────────────────────────────────────
    // `ErrorEvent` in the WebSocket context carries almost no useful
    // info (the spec says so — security reasons), so the best we can
    // do is surface a generic message. Real diagnostics come from
    // `on_close`'s `reason` field.
    let on_error = {
        let tx = tx.clone();
        let open_tx = open_tx.clone();
        let closed = closed.clone();
        Closure::wrap(Box::new(move |ev: ErrorEvent| {
            closed.set(true);
            let msg = format!("WebSocket error: {}", ev.message());
            // If the socket errored before `on_open`, unblock the
            // pending `connect` future with a proper error.
            if let Some(ch) = open_tx.borrow_mut().take() {
                let _ = ch.send(Err(msg.clone()));
            }
            let _ = tx.unbounded_send(IncomingFrame::Error(msg));
        }) as Box<dyn FnMut(ErrorEvent)>)
    };
    ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    // ─── on_close ───────────────────────────────────────────────────
    // `CloseEvent` has `.code()` / `.reason()` but we only need a
    // human-readable message. Cast the `Event` to `CloseEvent` via
    // `dyn_into`.
    let on_close = {
        let tx = tx.clone();
        let open_tx = open_tx.clone();
        let closed = closed.clone();
        Closure::wrap(Box::new(move |ev: Event| {
            closed.set(true);
            let reason = ev
                .dyn_into::<web_sys::CloseEvent>()
                .map(|ce| format!("code={} reason={}", ce.code(), ce.reason()))
                .unwrap_or_else(|_| "close".to_string());
            if let Some(ch) = open_tx.borrow_mut().take() {
                let _ = ch.send(Err(reason.clone()));
            }
            let _ = tx.unbounded_send(IncomingFrame::Closed(reason));
        }) as Box<dyn FnMut(Event)>)
    };
    ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

    // Stash the closures so they live as long as the socket.
    let callbacks = Rc::new(RefCell::new(Callbacks {
        on_open: Some(on_open),
        on_message: Some(on_message),
        on_error: Some(on_error),
        on_close: Some(on_close),
    }));

    let transport = WasmWebSocketTransport {
        url: url.to_string(),
        ws: Wasm32Shim::new(ws),
        rx,
        callbacks: Wasm32Shim::new(callbacks),
        closed: Wasm32Shim::new(closed),
        metrics_recorder: None,
        metrics_backend: "",
    };

    Ok((open_rx, transport))
}

impl WasmWebSocketTransport {
    /// Fire `on_bytes_sent` on the installed recorder, if any. No-op
    /// when no recorder is installed — the hot path stays a null check.
    fn fire_bytes_sent(&self, bytes: usize) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_bytes_sent(self.metrics_backend, bytes);
        }
    }

    /// Fire `on_bytes_received` on the installed recorder, if any.
    fn fire_bytes_received(&self, bytes: usize) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_bytes_received(self.metrics_backend, bytes);
        }
    }

    /// Fire `on_roundtrip_end` on the installed recorder, if any.
    /// Called only on a fully-successful roundtrip (both halves succeeded
    /// AND the length-prefix check passed). Partial-failure
    /// (`send` ok / `recv` err, or short frame) deliberately *does not*
    /// fire — the byte callbacks already fired for whatever crossed the
    /// wire, and a downstream consumer can detect "frames sent but no
    /// roundtrip" as `frames_sent - roundtrips_observed > 0`.
    fn fire_roundtrip_end(&self, bytes_out: usize, bytes_in: usize, duration: Duration) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_roundtrip_end(self.metrics_backend, bytes_out, bytes_in, duration);
        }
    }
}

#[async_trait]
impl PirTransport for WasmWebSocketTransport {
    async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
        // `ready_state` returns a `u16`; `WebSocket::OPEN` is `1`. If we
        // try to send on a closing / closed socket the browser throws
        // `InvalidStateError`. We also check the `closed` flag first so
        // a server-side idle-timeout close (observed via `on_close`) is
        // reported cleanly even if the browser's ready_state hasn't
        // flipped yet.
        if self.closed.get() || self.ws.ready_state() != WebSocket::OPEN {
            return Err(PirError::ConnectionClosed(format!(
                "send on non-open socket (state={})",
                self.ws.ready_state()
            )));
        }
        let bytes_out = data.len();
        // `send_with_u8_array` takes `&[u8]` — no owned copy is needed on
        // our side even though the trait takes `Vec<u8>` (so the signature
        // matches `WsConnection::send`).
        self.ws
            .send_with_u8_array(&data)
            .map_err(|e| PirError::ConnectionFailed(format!("WebSocket send threw: {:?}", e)))?;
        // Fire only after a confirmed-OK send; a throw above means the
        // bytes never left the caller, so double-counting them would
        // mislead a recorder.
        self.fire_bytes_sent(bytes_out);
        Ok(())
    }

    async fn recv(&mut self) -> PirResult<Vec<u8>> {
        // The `next()` future resolves when the next callback-pushed
        // `IncomingFrame` lands on the channel — could be a message,
        // error, or close.
        match self.rx.next().await {
            Some(IncomingFrame::Binary(bytes)) => {
                self.fire_bytes_received(bytes.len());
                Ok(bytes)
            }
            Some(IncomingFrame::Error(msg)) => Err(PirError::ConnectionFailed(msg)),
            Some(IncomingFrame::Closed(reason)) => {
                Err(PirError::ConnectionClosed(reason))
            }
            None => Err(PirError::ConnectionClosed(
                "WebSocket receiver dropped".into(),
            )),
        }
    }

    async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
        // `send` / `recv` already fire per-frame byte callbacks, so
        // roundtrip inherits them for free — no extra wiring needed for
        // those. We additionally measure end-to-end roundtrip latency
        // when (and only when) a recorder is installed: capturing
        // `Instant::now()` on every roundtrip would otherwise pay the
        // `performance.now()` JS↔WASM boundary cost for nothing.
        let started_at: Option<Instant> = self.metrics_recorder.is_some().then(Instant::now);
        let bytes_out = request.len();
        self.send(request.to_vec()).await?;
        let full = self.recv().await?;
        // Match the `WsConnection::roundtrip` contract — the 4-byte LE
        // length prefix is stripped before handing the frame up, because
        // every client call site does `&resp[4..]` afterwards.
        if full.len() < 4 {
            return Err(PirError::Protocol(format!(
                "roundtrip frame too short for length prefix ({} bytes)",
                full.len()
            )));
        }
        // `bytes_in` matches what `recv` already counted via
        // `fire_bytes_received` (full raw frame including the 4-byte
        // length prefix), so a recorder sees a consistent view across
        // the byte and roundtrip counters.
        let bytes_in = full.len();
        if let Some(start) = started_at {
            self.fire_roundtrip_end(bytes_out, bytes_in, start.elapsed());
        }
        Ok(full[4..].to_vec())
    }

    async fn close(&mut self) -> PirResult<()> {
        // `WebSocket::close()` is a void function in the browser — errors
        // only surface via `dyn_ref` / `InvalidStateError` for bad codes.
        // Passing no args uses the 1005-no-status-rcvd close code.
        //
        // Skip the call on a socket the server already closed (e.g.
        // idle-timeout): the WebSocket spec defines `close()` on a
        // CLOSED socket as a no-op, but calling through the
        // wasm-bindgen extern boundary is cheaper to avoid. Also marks
        // the socket closed for any concurrent code path that might
        // still be holding a reference.
        self.closed.set(true);
        if self.ws.ready_state() != WebSocket::CLOSED {
            let _ = self.ws.close();
        }
        // Drop the callbacks to break the cycle Browser → Closure →
        // Channel. The `Rc<RefCell<_>>` lets us do it without needing
        // `&mut self` over the full teardown.
        let mut cb = self.callbacks.borrow_mut();
        cb.on_open.take();
        cb.on_message.take();
        cb.on_error.take();
        cb.on_close.take();
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
        self.metrics_recorder = recorder;
        self.metrics_backend = backend;
    }
}
