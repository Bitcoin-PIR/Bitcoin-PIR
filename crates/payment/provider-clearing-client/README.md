# BitcoinPIR provider clearing client

This crate owns provider-side shared-issuer redemption and authenticated
settlement workflow persistence. It never accepts or stores a payer identity,
Lightning invoice, payment hash, preimage, PIR query, result, or peer-provider
identity.

`StrictHttpsProviderSettlementTransportV1` accepts HTTP 200 as the only
transport success status and requires the route-specific success media type.
Every other status must use the bounded problem media type and remains an
outcome-unknown failure after possible request transmission.

Production settlement state can use
`RemoteProviderSettlementFloorAuthorityV1`. It accepts mutation only through
the crate's `AuthenticatedProviderSettlementFloorTransitionV1`, revalidates
the initial or successor relationship, and then performs a fresh signed read
plus exact compare-and-swap through a pinned-HTTPS rollback-authority client.
The logical floor has its own strict magic/version encoding and is sealed by a
client-only AEAD codec bound to the same authority instance, namespace, and
Ed25519 client key. The authority sees a fixed-size opaque record, revision,
and operation timing, but no settlement payload.

Remote, signature, binding, authentication, decoding, timeout, and ambiguous
outcome failures are fail closed. There is no automatic fallback to local
state. `LocalTestSqliteProviderSettlementFloorV1` remains explicitly for
development, tests, and recovery drills; a second SQLite file on the same host
or in the same backup/restore domain is not an independent production rollback
authority.

An outcome-unknown CAS is reconciled in-process with its original operation ID
and exact expected/desired opaque records. If the process itself is lost, V1
performs a fresh authenticated read and converges only when the decoded floor
matches the transition's expected or desired logical state. It does not claim
to replay the same remote operation-log entry across restart. Persisting that
operation identity and the two opaque records before the first network attempt
is required for a stronger cross-process replay guarantee.

Floor-only restart convergence is safe here because the detailed SQLite store
persists an authenticated transition journal before invoking the authority.
Recovery reconstructs only the exact initial floor or an exact one-revision
successor, and `RemoteProviderSettlementFloorAuthorityV1` re-runs
`validate_initial`/`validate_successor` before any CAS. A fresh remote floor
equal to the journal's desired floor means the lost CAS completed; equality
with its expected floor permits exactly that transition. Any other floor,
missing predecessor, unauthenticated transition, or remote outage fails closed.
