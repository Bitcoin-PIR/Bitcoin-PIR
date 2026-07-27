# dev-issuer

**DEV-ONLY** free credential issuer **and** verifier gate for the anonymous
rate-limiting demo (ARC + Cashu Blind Auth). No payment, no Lightning, no PIR
database. **Do not deploy to production.**

It stands in for the old free issuer *and* legacy verifier gate so the
`mint → obtain → present → verify` demonstration runs as one process. The
verify endpoints exercise the same legacy primitives as
`pir_runtime_core::{arc_verifier, cashu_verifier}`; their `0x08`/`0x09` frames
are compatibility/demo frames only. They cannot unlock enforced Payment V1,
whose provider-, scope-, offer- and policy-bound admission messages are a
different protocol.

## Run the demo

```bash
# 1. Start the issuer + gate (writes arc_key.bin + cashu_key.bin in CWD).
cargo run -p dev-issuer
#    → listening on http://127.0.0.1:5601

# 2. Serve the demo page.
cd web && npm run dev
#    → open http://localhost:3001/ratelimit-demo.html
```

Click **Mint** then **Present** in either column. ARC shows one credential
spending down N presentations; Cashu shows a pool of single-use BATs, with a
"Replay last" button to demonstrate double-spend rejection.

## Endpoints (CORS-open)

| Method | Path                  | In                          | Out                         |
|--------|-----------------------|-----------------------------|-----------------------------|
| GET    | `/dev/arc/pubkey`     | —                           | 99-byte `ServerPublicKey`   |
| POST   | `/dev/arc/issue`      | 226-byte `CredentialRequest`| 454-byte `CredentialResponse`|
| POST   | `/dev/arc/verify`     | `[0x08]…` present payload   | 200 ok / 400 reason         |
| GET    | `/dev/cashu/keyset`   | —                           | JSON `{id, pubkey}`         |
| POST   | `/dev/cashu/mint`     | `N×33` blinded points       | `N×33` blind signatures     |
| POST   | `/dev/cashu/verify`   | `[0x09]authA…` payload      | 200 ok / 400 reason         |

## Flags

- `--arc-key <path>` (default `arc_key.bin`) — 128-byte ARC key.
- `--cashu-key <path>` (default `cashu_key.bin`) — 32-byte secp256k1 scalar.
- `--port <n>` (default `5601`).

## Legacy server-gate compatibility test

The issuer prints a launch line for exercising the legacy gate in a disposable
PIR process, e.g.:

```
unified_server --allow-experimental-arc --require-arc --arc-key arc_key.bin \
    --require-cashu --cashu-keyset <id>:<hex>
```

A demo client can then present the same legacy frames over WebSocket
(`web/src/arc-present.ts::sendArcPresentation`, or `cashu-bat`'s
`buildPresentFrame` via `ManagedWebSocket.sendRaw`). The dev-issuer's
`/dev/*/verify` endpoints exist only so the demo needs no PIR database. Do not
reuse these endpoints or frames for Payment V1 production admission.
