# pir-service-store

Provider-local, fail-closed SQLite persistence for BitcoinPIR admission
capabilities. This crate deliberately contains no issuer ledger and no
Lightning data.

The normative contract is [`docs/payment/PERSISTENCE.md`](../../../docs/payment/PERSISTENCE.md).
Creating a store and serving an existing store are separate APIs. Serve mode
never creates a missing database. Both public APIs require an
`Arc<dyn RollbackFloorAuthorityV1>` backed by independently durable,
linearizable infrastructure. There is deliberately no public SQLite-only
open/create path: metadata in the database being protected is not an external
rollback authority.

The external record binds the provider ID, one immutable store-instance ID,
schema version, store generation, spend-commit sequence, and a rolling commit
lineage. Every namespace install/close, spend, signed-policy/floor advance,
standard-Cashu intent mutation, and durable IP-quota consumption increments
`store_generation`; a bearer spend
or final Cashu grant claim also increments `spend_commit_seq`. SQLite commits
first, the external compare-and-swap anchor commits second, and the public
operation reports success only after both are confirmed. A lost CAS response
is recoverable: exactly one locally committed successor with the anchored
parent can be submitted idempotently on checked reopen. A database below the
external generation, more than one generation ahead, or at the same generation
with a different commitment fails closed.

The authority must not live in this SQLite file, its WAL, a sidecar restored
with it, or the same atomic backup set. Losing the authority is not repaired by
trusting the database: startup fails until an operator performs the documented
credential-revocation/new-store ceremony.

A remote authority observes provider identity and mutation timing even though
it receives no token, spend key, invoice, client or PIR data. Independent PIR
providers should use separately administered authorities (or provider-local
hardware); sharing one observable authority adds a cross-provider correlation
point. Replicas of one logical provider share one floor by design.

Creation durably checkpoints the initial WAL, syncs the database file, and on
Unix syncs its parent directory. Existing stores are opened with SQLite
`NOFOLLOW`; the final path component must be a regular non-symlink file and
the parent directory must be operator-controlled. A full serve-mode open runs
both `quick_check` and `foreign_key_check` before returning a handle.

Spend keys are unique across the entire logical provider, not merely within a
namespace. This prevents the same serial from being replayed through a second
scope or retained keyset. The store contains no raw IP, query, invoice,
payment hash, or raw capability columns.

Schema v5 adds rollback-anchored `IpRateLimited` buckets keyed only by a
provider-local 32-byte HMAC subject plus scope/offer, highest window, and
count. It stores neither raw IP nor a cross-provider identifier; restart does
not reset quota and lower wall-clock windows fail closed. Schema v4 also stores
the standard-Cashu merchant DFA as public digests,
coarse hour buckets, and an opaque AEAD recovery envelope. The native
`pir-cashu-client` default build implements its persistence trait directly for
`ProviderStore`. `PREPARED -> SUBMITTED` must be externally anchored before
the caller may send NUT-03, and no API transitions a submitted intent back to
prepared. ProviderStore does not auto-migrate prior schemas; see
[`PROVIDER_STORE_V4_MIGRATION.md`](../../../docs/payment/PROVIDER_STORE_V4_MIGRATION.md).

Schemes with a raw verification key that must be exclusive to one
cryptographic lineage (Cashu BAT in v1) install an `ExclusiveKeyLineage` with
their namespace. The store permanently binds `(scheme, raw-key fingerprint)`
to one immutable lineage digest across active and retained policies, closed
namespaces, and restarts. Reusing the same fingerprint in the same lineage is
idempotent; rebinding it to another lineage fails closed. This is a
provider-local configuration guard, not a substitute for using distinct raw
keys for the two independent PIR providers.

Production callers should pass a protocol-level `VerifiedServiceOfferV1` to
`ProviderStore::install_verified_offer_namespace_v1`. It deterministically
derives all namespace fields, refuses a store/provider mismatch, installs the
BAT raw-key lineage guard, and explicitly routes offers whose authoritative
state lives elsewhere. Open/IP/PoW Free grants, standard Cashu, and
shared-issuer redemption return `NotApplicable`; provider-local ARC returns
`UnsupportedExperimental` until its reviewed nullifier and lineage types exist.
The low-level installer is crate-private and exists only for controlled unit
tests; downstream production code has no API that can omit BAT lineage state.

Likewise, raw `SpendRequest` and `PolicyStateUpdate` persistence methods are
crate-private. Runtime integration must use
`verify_provider_local_bearer_spend_v1` plus
`spend_verified_provider_local_v1`, and
`apply_verified_policy_state_v1`. Cashu BAT additionally requires an explicit
reviewed `CashuBatProofVerifierV1`; provider-local ARC remains blocked.
