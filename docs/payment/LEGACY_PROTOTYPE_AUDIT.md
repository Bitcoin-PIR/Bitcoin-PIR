# Legacy Lightning prototype audit

Status: quarantined reference only. Audited 2026-07-25. This directory is not
part of the BitcoinPIR repository and is not an implementation dependency.

## Observed location and provenance

The previously documented prototype exists at
`/Users/cusgadmin/bitcoin-pir/payment`, but it has no `.git` directory and
therefore no repository history, review provenance, or reproducible source
revision. It contains an `ldk-node` application plus local runtime material
under `data/ldk`, including a node database and key seed. Those files are
sensitive operator state and must never be copied into this repository, test
fixtures, logs, commits, containers, or CI artifacts.

## Why it cannot be promoted

The source is useful only for learning the rough `ldk-node` event/API shape.
It violates the v1 security contract in several independent ways:

- `/invoice?amount_sats=N` accepts a client-selected price and multiplies it
  without binding it to a signed provider offer.
- ARC issuance accepts an independent client-selected `num_queries` value, so
  the invoice amount and entitlement count are not cryptographically or
  transactionally coupled.
- credential issuance sends the Lightning payment hash and preimage through
  the application API, and invoice/payment events log payment hashes.
- invoice state and the set of already-issued payment hashes are process-local
  `HashMap`/`HashSet` values. Restart loses payment/issuance bookkeeping;
  concurrent or crash-interrupted issuance has no durable exact replay.
- the payment hash is the public lookup handle and was intended to be polled by
  the PIR server, directly joining the payment artifact to authorization.
- issuance marks a hash used before returning the credential but does not
  atomically persist either that decision or exact response bytes. A crash can
  create both lost-entitlement and duplicate-entitlement outcomes.
- one shared process owns Lightning, ARC and BAT private material without the
  provider/scope/key-lineage, quote-delegation, clearing, ledger and outbox
  boundaries required by the new design.

## Reuse policy

No source file or state file is imported wholesale. A future separately
approved `ldk-node` backend may reimplement only the narrow backend adapter
contract: deterministic invoice label, create fixed-amount invoice, lookup by
stable label/backend ID, and reconcile settlement events. The authoritative
quote, amount, entitlement, idempotency and issuance state remains in the new
issuer store. The backend never decides price or query count and the PIR server
never sees invoice, payment hash, preimage, or backend label.
