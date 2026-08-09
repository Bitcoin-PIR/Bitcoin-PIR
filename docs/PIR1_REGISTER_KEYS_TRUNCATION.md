# OnionPIR `RegisterKeys` over Cloudflare: the 3.1 MB key upload is corrupted in transit

**Status: RESOLVED 2026-05-16.** Root cause — Cloudflare corrupting
the single ~3.1 MB `RegisterKeys` WebSocket message — confirmed and
fixed: transport-level message chunking landed in commit `49db31da`.
Messages over 256 KB are split into `[4B len][0xc7][seq][total][piece]`
frames the peer reassembles (`crates/sdk/client/src/connection.rs`,
`apps/server/src/bin/unified_server.rs`, `web/src/ws.ts`). Deployed to
pir1 + pir2; OnionPIR verified end-to-end over Cloudflare with both
the Rust and browser clients. The debugging history below is retained
for context.

## The short version

OnionPIR key registration creates a **logical ~3.1 MB key payload**
(2.6 MB BV-galois keys + 0.5 MB GSW key + framing). That message:

- **survives a raw TCP / SSH-tunnel transport intact** → server
  registers keys in ~1 ms, full query smoke test passes in 79 s;
- **was corrupted when proxied through Cloudflare**
  (`wss://weikeng1.bitcoinpir.org`) → the server's
  `deserialize_bv_galois_keys` reads a garbage length and burns
  ~55–60 s, then every `answer_query` returns empty → client sees
  `SessionEvicted`.

Proven by elimination: the **same** clean-built test binary
(`integration_test-3399053ae28c1fbd`, verified clean by a 994 µs
registration over the SSH tunnel) fails with a 55.9 s registration
when the only thing changed is `PIR_ONION_URL` from
`ws://127.0.0.1:18091` to `wss://weikeng1.bitcoinpir.org`.

## Three distinct issues were found (don't conflate them)

This single symptom — "slow registration, empty queries" — had
**three independent causes**, discovered one at a time:

1. **Contaminated incremental `onionpir` C++ build.** Flipping the
   `onionpir` pinned git rev fb14f4e↔2402b16 repeatedly without a
   clean rebuild left `libonionpir.a` inconsistent → the *client*
   emitted a malformed galois blob. Fixed by always doing a clean
   rebuild of the `onionpir` crate after a rev change (`cargo clean`
   or `rm -rf target/release/build/onionpir-*`). Affected both
   transports. **Resolved.**

2. **Hint-pool startup CPU thrashing.** `pir-primary` +
   `pir-secondary` both run `--pool-size 8` HarmonyPIR V2 hint
   generation at boot, saturating the 6-core host for ~2 min. A
   client connecting in that window starves the OnionPIR worker
   thread. Fixed by the systemd stagger
   (`deploy/systemd/pir-secondary.service`:
   `After=pir-primary.service` + `ExecStartPre=/bin/sleep 90`).
   **Resolved.**

3. **Cloudflare corrupted the 3.1 MB `RegisterKeys` message before transport
   chunking landed.** This historical issue is **RESOLVED**.

The original Cloudflare problem this whole effort started from — the
OnionPIR INDEX *query* taking 162 s, exceeding CF's ~100 s WebSocket
idle timeout — **is fixed**: the rayon-parallel `AnswerBatch`
(`unified_server.rs`, rev 2402b16) drops INDEX to ~20 s and CHUNK to
~36 s, each well under 100 s. Issue 3 was a *separate* CF limitation
on a single large *message*, not idle time.

## Historical pre-fix evidence

| transport | client binary | registration | result |
|---|---|---|---|
| `ws://127.0.0.1:18091` (SSH tunnel) | 3399053a (clean) | **0.99 ms** | full smoke PASS, 79 s |
| `wss://weikeng1.bitcoinpir.org` (CF) | 3399053a (clean, *same binary*) | **55.9 s / 58.1 s** | SessionEvicted |

Server-side instrumentation on the SSH-tunnel path showed the
message arriving intact (`ws_bin=3145873B`, galois_len=2,621,564,
`body_head=[7c 00 28 00 0a 00 00 00 …]` — a correct
`encode_register_keys` frame). cloudflared's own logs show nothing —
the corruption is silent.

`pir-channel::seal` (the encrypted-channel layer) does **not** chunk:
it AEAD-encrypts the whole plaintext into one
`[magic][seq:8][ct+tag]` frame → still one giant WebSocket message.
So routing `RegisterKeys` through the encrypted channel would not
help.

## Implemented fix: chunk the key upload

Transport-level chunking landed in commit `49db31da`. The Rust connection
layer, server reassembly, and browser WebSocket transport split payloads over
256 KiB into bounded chunk frames and reassemble them before dispatch. The
current implementation is in `crates/sdk/client/src/connection.rs`,
`apps/server/src/bin/unified_server.rs`, and `web/src/ws.ts`.

The old `REQ_REGISTER_KEYS_CHUNK` / `REQ_REGISTER_KEYS_COMMIT` proposal was
not the landed design and is retained only in Git history, not as an open task.

## Current production state

The original production report covered `pir1` serving `main` and
`delta_940611_948454`; the transport implementation now has the chunked path
for both Rust and browser clients. Any future Cloudflare regression should be
tracked as a new incident rather than reopening this resolved issue.
