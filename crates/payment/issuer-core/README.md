# BitcoinPIR issuer core

This crate is the transport-neutral orchestration layer for BOLT11 quote
creation, exact recovery, and settlement reconciliation. It composes the
fail-closed `pir-issuer-store`, the `pir-lightning-backend` boundary, and the
signed quote protocol. It reserves idempotency and backend-label state before
calling Lightning, accepts only a concrete signature-verified fixed-amount
BOLT11 invoice, and signs lifecycle transitions only from verified protocol
typestates.

The first reservation persists a narrow acceptable window for the
Lightning-node-assigned invoice timestamp. Exact retries and restarts reuse
that window and the same backend label. A backend outcome-unknown error never
causes the core to allocate another quote or request another invoice under a
new label.

Reconciliation is by the issuer-confidential backend label. Exact on-time
settlement becomes `PaymentSettled`; expiry becomes
`InvoiceExpiredPendingReconcile`; a late settlement is committed only after
the expired-pending state is durably anchored. Amount mismatch and
contradictory backend history fail closed.

This crate deliberately has no HTTP server, production LND/CLN adapter,
credential claim or issuance implementation, wallet, payout logic, provider
ledger, PIR networking, or real-funds integration. Its public results do not
surface payment hashes, preimages, or backend labels, and its error values use
only coarse non-secret classifications. Production deployment remains
disabled until those separate adapters, migrations, operations, and security
reviews exist.
