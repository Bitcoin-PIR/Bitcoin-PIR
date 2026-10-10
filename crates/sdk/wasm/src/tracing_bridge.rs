//! WASM bindings for `tracing` spans.
//!
//! Phase 2+ observability tail: wires a [`tracing-wasm`] subscriber into the
//! browser so the `#[tracing::instrument]` spans laid down on `DpfClient`,
//! `HarmonyClient`, `OnionClient`, `WsConnection`, and
//! `WasmWebSocketTransport` in Phase 1 surface in the browser DevTools
//! console.
//!
//! # Usage
//!
//! ```javascript
//! import init, { initTracingSubscriber } from 'pir-sdk-wasm';
//! await init();
//! initTracingSubscriber();               // once at app startup
//!
//! // All PIR operations now emit spans to the browser console.
//! // Span fields include `backend = "dpf" / "harmony" / "onion"` plus
//! // per-method scalars (db_id, step name, height, batch size, etc.).
//! ```
//!
//! Repeat calls are safe — a [`std::sync::Once`] guard ensures the
//! underlying `tracing::subscriber::set_global_default` only fires on
//! the first call. (Without the guard, `tracing-wasm::set_as_global_default`
//! would panic on the second call because `tracing` allows only one global
//! subscriber per process.)
//!
//! # Relation to `AtomicMetrics`
//!
//! `initTracingSubscriber` and `WasmAtomicMetrics` are independent
//! observability layers:
//!
//! | Layer                | What it surfaces                            | Where it lands |
//! |----------------------|---------------------------------------------|----------------|
//! | `tracing` subscriber | Span enter/exit, events, structured fields  | browser console |
//! | `AtomicMetrics`      | Counters (bytes, frames, query lifecycle)   | JS object via `snapshot()` |
//!
//! Install both — they answer different questions. Tracing is "what is the
//! client doing right now, and in what order"; metrics are "how many of
//! each thing has happened since startup". Neither depends on the other.
//!
//! # Native builds
//!
//! On native (`cargo test -p pir-sdk-wasm`) this function compiles as a
//! no-op — the `tracing-wasm` dep is `cfg(target_arch = "wasm32")`-gated
//! because its underlying `web-sys::console` crate does not link on
//! native. Native tests that care about span capture should install a
//! `tracing-subscriber::fmt` directly (see Phase 1's
//! `tracing_instrument_emits_backend_field_for_<backend>` tests in
//! `pir-sdk-client`).
//!
//! # Bundle size
//!
//! `tracing-wasm` + its transitive `tracing-subscriber` dep add roughly
//! 30-50 KB to the compressed wasm bundle. Callers who don't install the
//! subscriber still pay this cost because the dep is always linked — if
//! that becomes a concern, gate the module behind a cargo feature
//! (`tracing-subscriber` = `["dep:tracing-wasm"]`). Deliberately not
//! done in the first cut to keep the opt-in surface simple.
//!
//! # 🔒 Padding invariants
//!
//! The tracing subscriber is strictly observational. It receives span
//! fields that the `#[tracing::instrument(skip_all, ...)]` attributes in
//! `pir-sdk-client` explicitly whitelist — scalars, URLs, and
//! `&'static str` identifiers only; never binary payloads, hint blobs,
//! or secret keys (`skip_all` guarantees that). There is no code path
//! by which a subscriber can influence the number or content of padding
//! queries sent.
//!
//! [`tracing-wasm`]: https://crates.io/crates/tracing-wasm

use std::sync::Once;
use wasm_bindgen::prelude::*;

static INIT: Once = Once::new();

/// Install a [`tracing-wasm`] subscriber as the global `tracing` default.
///
/// Call once at app startup after `await init()`. Subsequent calls are
/// no-ops (guarded by [`std::sync::Once`]), so invoking from multiple
/// initialization paths is safe.
///
/// On native targets (`cargo test -p pir-sdk-wasm`) the underlying
/// `tracing-wasm::set_as_global_default` is `cfg(target_arch = "wasm32")`
/// guarded, so this function is effectively a no-op there. A native test
/// that wants tracing output should install
/// `tracing_subscriber::fmt::fmt()` directly — see the Phase 1 span
/// smoke tests in `pir-sdk-client` for the canonical pattern.
///
/// [`tracing-wasm`]: https://crates.io/crates/tracing-wasm
#[wasm_bindgen(js_name = initTracingSubscriber)]
pub fn init_tracing_subscriber() {
    INIT.call_once(|| {
        #[cfg(target_arch = "wasm32")]
        {
            tracing_wasm::set_as_global_default();
        }
        // On native, the cfg-gated body is empty. Native-side callers
        // should install `tracing_subscriber::fmt` directly.
    });
}
