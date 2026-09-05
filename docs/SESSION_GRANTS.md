# Session grants (paid queries)

Free PIR queries are open. Paid queries present a **session grant** on
opcode `0x0b` (`REQ_SESSION_GRANT_PRESENT`) before any query-bearing
opcode; the server answers `RESP_SESSION_GRANT_OK { remaining_credits }`
or `RESP_ERROR`. Opcodes `0x08` (ARC) and `0x09` (Cashu blind auth) are
retired and never reassigned.

## Roles

| Role | Where | Holds |
| --- | --- | --- |
| Cashier | separate repository under the Bitcoin-PIR organisation; operator-run, outside the PIR hosts | payment integration (Cashu ecash, Lightning, …) and the grant signing key |
| PIR server (`unified_server`) | pir1 / pir2 | the cashier's **public** key(s) and an in-memory credit ledger |
| Client | browser / SDK | buys a grant from the cashier and presents it once per connection |

The PIR host never holds a payment secret, never contacts a mint, and never
learns what was paid. Prices, payment rails, and the cashier implementation
can change without touching the server binary or the pir2 measured image;
rotating the cashier key is a flag change.

## Grant

`pir_session_grant::SessionGrant` (`crates/trust/session-grant`), 133
bytes, version 1: issuer public key, 16-byte grant id, `issued_at`,
`expires_at`, `credits` (at least 1), and an Ed25519 signature under the
domain tag `BPIR-SESSION-GRANT-V1`. The server tolerates 5 minutes of
clock skew and refuses lifetimes above 30 days.

The cashier signs with a 32-byte Ed25519 seed; `bpir-admin keygen --out
cashier.key` produces one and prints the public key hex.

## Metering

- One credit per **query-bearing request frame**: INDEX / CHUNK / bucket
  Merkle batches, HarmonyPIR query and batch query, ORAM lookup, OnionPIR
  key registration and queries. Info, ping, attest, handshake, announce,
  catalog, DB proofs, HarmonyPIR hints, admin opcodes, and the presentation
  itself are free.
- The credit is spent after the mode gates and before dispatch, so a frame
  this host does not serve costs nothing and a malformed query still costs
  one.
- The ledger is keyed by grant id and shared by all connections of one
  server, so a client can reconnect and keep spending the same grant until it
  is exhausted or expires. Entries are evicted after expiry; a server restart
  clears the ledger, which at worst re-credits still-unexpired grants.
- Servers that pin the same cashier key meter independently (both DPF
  servers charge the same grant); settlement between operator and cashier is
  outside the protocol.
- Padding invariants are untouched: metering counts frames, never contents.

## Server flags

| Flag | Effect |
| --- | --- |
| `--session-grant-pubkey FILE` (repeatable) | Pin a cashier public key: 32 raw bytes or 64 hex characters. Enables verification and metering. |
| `--require-session-grant` | Reject query-bearing frames until a valid grant is presented. Needs at least one pinned key. |

With no pinned key the server refuses `REQ_SESSION_GRANT_PRESENT` with an
error and serves free queries as before. Production activation is an
operator decision routed through
[Production operations](PRODUCTION_OPERATIONS.md).

## Client discovery

The client pins the cashier URL itself. The server announces no payment
endpoint, so a compromised server cannot redirect payments.
