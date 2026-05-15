# BitcoinPIR bug: the ~3.1 MB OnionPIR `RegisterKeys` payload is truncated in transit

**Status:** root cause partially identified 2026-05-15. The *fact* of
the truncation is established with byte-level evidence; the exact
transport mechanism (which layer drops the bytes) needs one more
focused investigation. This doc records what is known so the next
session — or the reader — can finish it without re-deriving.

## Symptom

OnionPIR end-to-end query (`test_onion_client_query_batch`) against
a pir1 server built from onionpir rev `2402b16` panics with
`SessionEvicted("…all-empty batch…")`. Server-side, "key
registration" takes 55–60 s and every subsequent `answer_query`
returns an empty `Vec`.

## What is proven

1. **The 60 s is inside `deserialize_bv_galois_keys`** (C++ FFI).
   Six gdb backtraces of the worker thread, 9 s apart, all land in
   that function (`vector::assign` → memset, `munmap`/`free`). It is
   looping on a garbage count. See
   [`docs/UPSTREAM_REQUEST_2402b16_REGRESSION.md`](UPSTREAM_REQUEST_2402b16_REGRESSION.md).

2. **The client serializes a perfect blob.** Client-side instrumentation
   in `pir-sdk-client/src/onion.rs::register_keys`:
   ```
   register_keys: galois=2621564B head=[0a 00 00 00 01 08 00 00 08 00 00 00 …]
   ```
   `0a 00 00 00` = `num_keys = 10` (= `TREE_HEIGHT`); total
   `2,621,564 B` = exactly `4 + 10·(12 + 8·2·2048·8)`. Well-formed.

3. **The server receives a truncated, mis-aligned blob.** Server-side
   instrumentation in `runtime/src/bin/unified_server.rs`'s
   `PirCommand::RegisterKeys` handler:
   ```
   RegisterKeys recv: galois=379022B head=[5e a1 10 04 01 00 00 00 8e c8 05 00 …]
   ```
   `379,022 B` ≠ `2,621,564 B` — the galois field is ~14 % of what
   was sent. The leading bytes `5e a1 10 04` are mid-blob garbage
   (read as `num_keys = 67,936,606` → the 60 s loop). The gsw field
   is likewise wrong: client sends `524,296 B`, server sees
   `331,560 B`.

So the ~3.1 MB `RegisterKeys` payload (2.6 MB galois + 0.5 MB gsw +
framing) loses ~2.4 MB somewhere between
`pir-sdk-client::register_keys` calling `conn.roundtrip(&payload)`
and the server's `RegisterKeysMsg::decode` extracting the fields.

## Wire path (where to look)

`encode_register_keys` (`pir-sdk-client/src/onion.rs:2170`) builds:
```
[payload_len u32][REQ_REGISTER_KEYS u8][galois_len u32][galois][gsw_len u32][gsw][db_id?]
```
→ `conn.roundtrip(&payload)` →
  native `WsConnection` (`pir-sdk-client/src/connection.rs`) →
  if an encrypted channel is up, the payload is AEAD-framed by
  `pir-channel` / `pir-runtime-core::channel` →
  `tokio-tungstenite` WebSocket →
  server WS read loop (`unified_server.rs` ~line 2347) →
  channel `open()` decrypt →
  `RegisterKeysMsg::decode(body)` → the malformed `galois_keys` field.

Suspects, in rough priority:

1. **Encrypted-channel frame chunking.** A 3.1 MB plaintext almost
   certainly exceeds one AEAD frame. If the channel splits it into N
   frames and the server-side reassembly completes early (or a single
   frame's plaintext-length field caps the payload), the decoded
   `body` would be one-frame-sized. `379022 + 331560 + 13 ≈ 710 KB` —
   check whether that's a channel max-frame-size.
2. **`tokio-tungstenite` message-size cap.** tungstenite's default
   `max_message_size` is 64 MB and `max_frame_size` 16 MB — 3.1 MB is
   under both, so this is unlikely *unless* the BitcoinPIR transport
   overrides them lower.
3. **`RegisterKeysMsg::decode` mis-parse.** Less likely (the bytes it
   extracts start mid-blob, consistent with a short `body`, not a
   parser bug) but worth ruling out.

## The unresolved puzzle

The fb14f4e end-to-end smoke test **passed** at 15:36 CET the same
day — `registration 1.39 ms`, clean 2.6 MB deserialize — i.e. the
same ~3.1 MB payload reached an fb14f4e server intact. The transport
code (`pir-channel`, `WsConnection`, `tokio-tungstenite`) is
**identical** regardless of the onionpir rev, so a pure size-cap
truncation should fail on fb14f4e too.

Differences between the passing and failing runs, still to be
bisected:
- **Server rev**: fb14f4e (pass) vs 2402b16 (fail). The transport is
  rev-independent, so if this matters it's via timing — the
  thread-safety patch changes lock/scheduling behavior, which could
  expose a race in a multi-frame reassembly path.
- **Server flags**: the 15:36 pass used the systemd unit
  (`--serve-hints --serve-queries --pool-size 8 --pool-dir …`); the
  failing diagnostic runs used a hand-launched
  `--serve-queries --pool-size 0` (no `--serve-hints`). If the hint
  subsystem changes connection setup or buffer sizing, this is a
  confound that must be eliminated.

**Next diagnostic step (do this first):** rebuild pir1 with onionpir
`2402b16` and run it under the *exact* systemd flags
(`--serve-hints --serve-queries --pool-size 8 --pool-dir …`), wait
for hint-pool quiescence, then test. If registration is now fast →
the flag set, not the rev, was the variable, and the transport bug is
flag-conditional. If still 60 s → it is the rev (→ timing/race), and
the encrypted-channel reassembly is the place to instrument
(log frame count + per-frame plaintext length on both ends).

## Interim mitigation

pir1 is rolled back to onionpir `fb14f4e` (commit `b50af83a`), which
serves OnionPIR correctly end-to-end via SSH tunnel. The Cloudflare
100 s timeout (the original reason for wanting `2402b16` +
`.par_iter_mut()`) remains open and is gated behind this truncation
bug + the upstream bounds-check ask.
