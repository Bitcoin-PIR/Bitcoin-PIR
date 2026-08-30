# payment-issuer

The single designated BitcoinPIR credential issuer. It issues and verifies
ARC credentials and Cashu blind-auth tokens. The PIR nodes announce this
endpoint; they verify presentations on wire opcodes `0x08` /
`0x09`. Collection (Lightning) is not implemented here.

Issuance is currently free: anyone who can reach the HTTP surface can mint.
A payment processor (pruned bitcoind + local Lightning node) is later work.

```bash
cargo run -p payment-issuer
# listening on http://127.0.0.1:5601
```

## Endpoints (CORS-open)

| Method | Path                  | In                          | Out                          |
|--------|-----------------------|-----------------------------|------------------------------|
| GET    | `/dev/arc/pubkey`     | —                           | 99-byte `ServerPublicKey`    |
| POST   | `/dev/arc/issue`      | 226-byte `CredentialRequest`| 454-byte `CredentialResponse`|
| POST   | `/dev/arc/verify`     | `[0x08]…` present payload   | 200 ok / 400 reason          |
| GET    | `/dev/cashu/keyset`   | —                           | JSON `{id, pubkey}`          |
| POST   | `/dev/cashu/mint`     | `N×33` blinded points       | `N×33` blind signatures      |
| POST   | `/dev/cashu/verify`   | `[0x09]authA…` payload      | 200 ok / 400 reason          |

## Flags

- `--arc-key <path>` (default `arc_key.bin`) — 128-byte ARC key.
- `--cashu-key <path>` (default `cashu_key.bin`) — 32-byte secp256k1 scalar.
- `--port <n>` (default `5601`).
