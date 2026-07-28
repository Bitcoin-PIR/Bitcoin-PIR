# BitcoinPIR shared issuer clearing

This crate is the reviewed cryptographic adapter between canonical shared
issuer credentials and `pir-issuer-store`'s atomic redemption typestate. It
verifies provider-bound Free anonymous tickets and Cashu BAT proofs, and wires
the draft-01 ARC verifier only as an explicitly experimental method.

It can construct issuer-signed ledger-credit or blinded Cashu settlement
responses. Blind-signature proof nonces are deterministically derived from an
issuer-secret response key and the exact redeem request so a crash before the
SQLite commit can reconstruct the same candidate response. The store must
commit that exact response, the global credential spend key, and balanced
ledger effects before any success is returned.

This crate has no HTTP, Lightning, enabled real-funds payout adapter, PIR
query, payer identity, invoice, payment hash, or browser data. ARC remains
experimental pending an independent cryptographic review.

## Payout outbox worker boundary

`IssuerPayoutOutboxWorkerV1::run_once` processes at most one durable command
and contains no polling loop, sleep, logging, or automatic backoff. A runner
must apply a bounded delay outside this crate. The durable lease is also capped
at five minutes. The configured external-call timeout must be nonzero and
strictly shorter than the lease. Every executor call receives an absolute Unix
deadline derived from the committed lease; the deadline is strictly before
`lease_until`. The adapter must enforce that deadline across its complete
operation. Timeout and cancellation are explicit call results which the worker
always maps to `OutcomeUnknown`. The worker checks executor readiness before
reading or claiming the outbox, so the shipped
`NoFundsPayoutExecutorV1` cannot create an `InFlight` payout.

For an `Accepted` payout, the worker first commits the signed
`Accepted -> InFlight` transition and only then calls `submit_once`. After that
commit, every restart, expired lease, timeout, and ambiguous response uses only
the executor's non-paying `reconcile` method. It never calls `submit_once` again.
An unknown result deliberately leaves the payout `InFlight`; this can require
manual reconciliation, but it cannot silently refund and repeat a possibly
successful payout.

Before either executor method is reached, the worker reloads the authenticated
store identity, recomputes the outbox command ID from `(issuer_id, payout_id)`,
and compares it with the leased row using a fixed-width comparison. It also
decodes the canonical exact initial/latest response bytes, verifies both issuer
signatures through the configured current/retained settlement-key lineage, and
binds all signed static fields plus the latest state, version and timestamp to
the durable payout row. After `Accepted -> InFlight`, it reloads that row and
requires the exact stored signed successor to equal the response just committed
before calling `submit_once`. Terminal fast paths and lost-CAS winner reloads
use the same verification boundary. A rewritten outbox idempotency key,
tampered historical signature or mismatched durable snapshot therefore fails
closed before it can authorize a new external call.

A real-funds adapter is not included. Any future implementation of
`ExternalPayoutExecutorV1` must durably bind the outbox `command_id` to the
external system's linearizable idempotency/status authority. The SQLite commit
and external transfer are not one atomic transaction, so the worker does not
claim exactly-once real-funds behavior without that external `command_id`
primitive or an equivalent authoritative fence. The adapter may return
`DefinitelyFailed` only after it can prove the command did not transfer value
and can never be submitted by a stale worker (for example, through an
authoritative terminal tombstone or fencing mechanism). All transport errors
and uncertain remote states map to `OutcomeUnknown`. `payout_target_id` is an
opaque but stable provider payout-routing pseudonym: it is not a raw provider
identity, but the issuer/executor can link repeated payouts to the same target.
The adapter and its runner must not log that target, payout ID,
command/idempotency material, signatures, or credential data. Worker progress
has a hand-written redacted `Debug` implementation which omits payout IDs.
