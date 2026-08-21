# Anonymous admission and payment integration

This page indexes the Payment V1 admission architecture. Start operating work
at [Production operations](PRODUCTION_OPERATIONS.md).

## Current boundaries

- [`apps/dev-issuer/`](../apps/dev-issuer/) and
  [`RATELIMIT_DEMO.md`](RATELIMIT_DEMO.md) remain a free, process-local
  mechanism demo. They must not be deployed as a payment service.
- Legacy `--require-arc`, `--require-cashu`, `REQ_CREDENTIAL_PRESENT (0x08)`
  and `REQ_CASHU_BAT_PRESENT (0x09)` remain compatibility/demo paths. They do
  not authorize work when the enforced Payment V1 gate is enabled. Even the
  legacy ARC demo requires the explicit `--allow-experimental-arc`
  acknowledgement and remains prohibited in production.
- The untracked lowercase-tree prototype is non-reproducible evidence only.
  It is not a migration source. See
  [`archive/payment/LEGACY_PROTOTYPE_AUDIT.md`](archive/payment/LEGACY_PROTOTYPE_AUDIT.md).
- Payment V1 is implemented in this repository under
  [`crates/protocol/service/`](../crates/protocol/service/),
  [`crates/protocol/service-store/`](../crates/protocol/service-store/),
  [`crates/payment/`](../crates/payment/),
  [`apps/payment-issuer/`](../apps/payment-issuer/), the native/WASM SDKs, and
  the product Web query flow.
- Production activation, remote-server operations, public relay/mint access,
  and real Lightning funds remain separate operator approval gates.

## Current design

Each provider independently signs workload-specific offers. DPF, OnionPIR,
TEE-ORAM, Harmony hint acquisition, and Harmony query execution are distinct
scopes. A client may select a different accepted method for each provider;
neither provider receives a pair identifier or learns the peer provider.

Payment V1 includes:

1. provider-defined Free admission (open best effort, durable IP cohort,
   connection-bound proof of work, or anonymous ticket);
2. direct BOLT11-funded receipt capability, explicitly marked linkable;
3. standard Cashu eCash merchant swap;
4. BitcoinPIR Cashu BAT, provider-local or shared-issuer verified;
5. ARC multi-show capability, kept `experimental` until an independent
   cryptographic review is complete.

BOLT11 terminates at the payment/credential issuer. A PIR server receives only
the exact provider/scope/offer-bound authorization proof; it never receives a
BOLT11 invoice, payment hash, preimage, payer identity, quote identifier, or
peer-provider identifier. Two providers use independently issued capabilities
and independent spent state. A shared online issuer is allowed only as an
explicit correlation and availability trade-off; strict clients reject one
issuer/origin observing both credential flows unless the user gives an
in-memory, one-attempt acknowledgement.

The product Web flow performs that independence sequentially for DPF and
Harmony: it may strictly verify the first role and display that role's signed
policy before the second provider is known. It does **not** acquire or consume a
capability yet. Before dialing the second role it locally verifies that both
pinned operator keys are non-zero and distinct, without sending either peer
choice or key to a server. Once both roles pass identity/catalog/root
consistency, a one-shot tree-top preflight binds the selected `db_id`; only
then may either role acquire or authorize a capability. A second connection or
preflight failure therefore spends neither role and never falls back to an
unverified query. Harmony's large hint acquisition and per-query execution
remain visibly separate roles, scopes and prices; an already persisted exact
hint cache remains inert until the same pre-authorization gate succeeds.

Each staged one-query authorization is also bound to one exact `db_id`.
Multi-database Harmony synchronization remains fail closed until the product
defines and implements a separate per-step or multi-database entitlement
contract; cached hints do not widen the purchased query scope.

## Documentation

- Operations: [Production operations](PRODUCTION_OPERATIONS.md) and its short
  [runbooks](runbooks/).
- Architecture and trust boundaries:
  [`payment/ARCHITECTURE.md`](payment/ARCHITECTURE.md)
- Canonical wire protocol:
  [`payment/PROTOCOL.md`](payment/PROTOCOL.md)
- Persistence and crash semantics:
  [`payment/PERSISTENCE.md`](payment/PERSISTENCE.md)
- Security and privacy invariants:
  [`payment/SECURITY.md`](payment/SECURITY.md)
- Nostr directory protocol and publication boundary:
  [`payment/DIRECTORY_PROTOCOL.md`](payment/DIRECTORY_PROTOCOL.md)
- Retired plans, reviews, acceptance records, and migrations:
  [Payment archive](archive/payment/README.md).
