# Session grants (paid queries)

Free PIR queries are open. Paid queries present a **session grant** on
opcode `0x0b` (`REQ_SESSION_GRANT_PRESENT`) before any query-bearing
opcode; the server answers `RESP_SESSION_GRANT_OK { remaining_credits }`
or `RESP_ERROR`. Opcodes `0x08` (ARC) and `0x09` (Cashu blind auth) are
retired and never reassigned.

## Roles

| Role | Where | Holds |
| --- | --- | --- |
| Cashier | [Bitcoin-PIR/cashier](https://github.com/Bitcoin-PIR/cashier); operator-run, outside the PIR hosts | payment integration (Cashu ecash, Lightning, …) and the grant signing key |
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
  key registration and queries.
- One **hint set** (`REQ_HARMONY_HINTS` or `REQ_HARMONY_HINTS_V2`, the
  requests that take an entry from the hint pool) costs
  `--session-grant-hint-credits` credits, default 150. Priced by compute:
  regenerating a pool entry measured 136 CPU-seconds on pir1 against about
  0.9 for a metered DPF frame, and a set serves roughly 26 queries, so the
  amortised cost per HarmonyPIR query is close to a DPF query's. The
  `_V2_HALF` continuation of an already-paid entry is free. A grant that
  cannot cover the whole set is refused with the shortfall named and
  nothing charged.
- Info, ping, attest, handshake, announce, catalog, DB proofs, admin
  opcodes, and the presentation itself are free.
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
| `--session-grant-hint-credits N` | Credits one HarmonyPIR hint set costs (default 150). The cashier advertises the same number in `GET /v1/info` `costs`. |

On pir1 the flags live in the systemd unit. On pir2 they live in the measured
UKI (`scripts/dracut/97bpir-tier3-init/unified-server-run.sh` pins the cashier
public key and the hint-set price next to `--admin-pubkey-hex`), so changing
the key or the price is a new image and a sealed ceremony.

With no pinned key the server refuses `REQ_SESSION_GRANT_PRESENT` with an
error and serves free queries as before. Production activation is an
operator decision routed through
[Production operations](PRODUCTION_OPERATIONS.md); the live cashier and mint
are described in [Cashier and mint](runbooks/cashier-and-mint.md).

## Client flow

The client pins the cashier URL itself (`PRODUCTION_CASHIER_URL` in
`web/src/constants.ts`); the server announces no payment endpoint, so a
compromised server cannot redirect payments. The cashier's HTTP contract is
[Cashier API](CASHIER_API.md).

1. Buy: the page loads the cashier's offers, gets a bolt11 mint quote from
   a listed mint, the user pays the invoice, the page mints the ecash and
   hands the token to the cashier (`web/src/cashu-purchase.ts`, cashu-ts
   loaded on demand). A token from any Cashu wallet can be pasted instead.
   Pending purchases are persisted so a reload or cashier outage never
   loses paid sats.
2. Store: the grant lives in `localStorage` (`web/src/session-grant.ts`).
3. Present: every PIR client (`DpfClient`, `HarmonyClient`, `OnionClient`,
   `OramClient`, their wasm bindings, the three web adapters, and the
   standalone OnionPIR web client) exposes `present_session_grant` /
   `presentSessionGrant` and, when a grant is configured, presents it right
   after the encrypted channel and operator-identity checks. The grant is a
   bearer token, so it is never sent in cleartext. Each server answers with
   its own remaining balance; "session grants not enabled" from a server is
   the free path, not an error.
