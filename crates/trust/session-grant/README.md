# pir-session-grant

Cashier-signed session grants for BitcoinPIR paid queries.

A cashier (operator-run, outside the PIR hosts) takes payment and returns a
short-lived Ed25519-signed `SessionGrant` carrying a credit balance. A PIR
server pins the cashier's public key(s), verifies grants offline, and spends
one credit per query-bearing request frame in an in-memory `GrantLedger`
keyed by grant id, so a client can reconnect and keep using the same grant
until it is exhausted or expires.

The crate is pure cryptography and bookkeeping: no payment integration,
filesystem, clock, or network. Callers supply the current Unix time. The
wire format is documented in `src/lib.rs`; the server integration and
operator flags are described in
[`docs/SESSION_GRANTS.md`](../../../docs/SESSION_GRANTS.md).
