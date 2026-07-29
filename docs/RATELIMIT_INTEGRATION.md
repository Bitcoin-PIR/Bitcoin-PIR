# Anonymous admission and payment integration

Status: superseding integration index for Payment V1. The old May 2026 plan
described `apps/dev-issuer`, legacy `0x08`/`0x09` presentation frames, and an
untracked `~/bitcoin-pir/payment` prototype as the prospective production
path. That description is retained only in Git history; it is not the current
architecture or an operating instruction.

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
  [`payment/LEGACY_PROTOTYPE_AUDIT.md`](payment/LEGACY_PROTOTYPE_AUDIT.md).
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
Harmony: it strictly verifies and authorizes the first role before enabling the
second provider selector. Failure of the second connection does not reconnect
or spend the first role again, and no PIR query is sent until both roles pass
the identity/catalog/root consistency gate, both exact capabilities authorize,
and one post-authorization tree-top preflight succeeds. That preflight is
one-shot: failure blocks the query without automatically retrying either
capability. Harmony's large hint acquisition and per-query execution remain
visibly separate roles, scopes and prices; an exact verified hint cache can be
filled before choosing the query provider.

Each staged one-query authorization is also bound to one exact `db_id`.
Multi-database Harmony synchronization remains fail closed until the product
defines and implements a separate per-step or multi-database entitlement
contract; cached hints do not widen the purchased query scope.

## Authoritative documentation

- architecture and trust boundaries:
  [`payment/ARCHITECTURE.md`](payment/ARCHITECTURE.md)
- canonical wire protocol:
  [`payment/PROTOCOL.md`](payment/PROTOCOL.md)
- persistence and crash semantics:
  [`payment/PERSISTENCE.md`](payment/PERSISTENCE.md)
- security and privacy invariants:
  [`payment/SECURITY.md`](payment/SECURITY.md). The retained
  [`payment/SECURITY_REVIEW_2026-07-26.md`](payment/SECURITY_REVIEW_2026-07-26.md)
  is a historical snapshot and contains a dated delta for the later schema-v7,
  CLN/CDK, custody, strict-HTTPS and Nostr work;
- current implementation state:
  [`payment/IMPLEMENTATION_STATUS.md`](payment/IMPLEMENTATION_STATUS.md)
- operator and local acceptance procedures:
  [`payment/OPERATOR_RUNBOOK.md`](payment/OPERATOR_RUNBOOK.md) and
  [`payment/LOCAL_ACCEPTANCE.md`](payment/LOCAL_ACCEPTANCE.md)
- Lightning staging and disposable local CLN:
  [`payment/LIGHTNING_STAGING.md`](payment/LIGHTNING_STAGING.md) and
  [`payment/CLN_REGTEST.md`](payment/CLN_REGTEST.md)
- current ProviderStore replacement ceremony:
  [`payment/PROVIDER_STORE_V7_MIGRATION.md`](payment/PROVIDER_STORE_V7_MIGRATION.md)
- Nostr directory protocol and publication boundary:
  [`payment/DIRECTORY_PROTOCOL.md`](payment/DIRECTORY_PROTOCOL.md)
- ARC review gate:
  [`payment/ARC_EXPERIMENTAL_REVIEW.md`](payment/ARC_EXPERIMENTAL_REVIEW.md)

Do not recover production instructions from an older version of this file.
The Payment V1 status and runbook documents above are the maintained sources.
