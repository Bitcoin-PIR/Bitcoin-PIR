# ProviderStore schema v7 replacement ceremony (archived)

Status: normative pre-production replacement contract. ProviderStore v6 was
never activated in production and there is deliberately no in-place or
automatic v6-to-v7 migration.

## Why v7 replaces v6

Schema v6 treated delivery acknowledgement as the end of local custody
exposure. That is unsafe: delivering a bearer-note artifact does not prove the
recipient reissued or spent those notes. Schema v7 makes the durable states
explicit:

- lot: `Available(1) -> Reserved(2) -> DeliveryAcknowledged(3) -> SpentConfirmed(4)`;
- export: `Reserved(1) -> ArtifactStored(2) -> DeliveryAcknowledged(3) -> SpentConfirmed(4)`.

State 3 remains inside every value and note exposure cap. Only state 4 is
excluded. The state-4 transition requires an exact owner-initiated NUT-07
all-`SPENT` result and writes digest-only retirement evidence bound to the
provider, store instance, precondition rollback floor, export, artifact,
ordered members, persisted note fingerprints, transient Y set and a
domain-separated exact per-export NUT-07 observation digest. A wider HTTP
batch digest is never copied into multiple export rows, avoiding a durable
cross-export batch identifier. Raw Y values and individual note states are not
stored.

## No automatic migration

`ProviderStore::open_existing` accepts exactly schema v7. It never changes
`PRAGMA user_version`, table definitions, store identity, generations, or the
independent rollback floor. A v6 or unknown store fails closed before serving.

Changing the rollback-authority schema binding in place would require a new,
separately reviewed cross-schema CAS protocol. v7 does not add that protocol.
Copying a v6 database and editing its version fields is not a migration and
would create an unverifiable rollback lineage.

## Authorized pre-production replacement

Because v6 was development-only, replace it rather than upgrading it:

1. Stop every process that can open the provider store or its rollback
   authority.
2. Preserve the v6 database, WAL, rollback-floor record, policies and Cashu
   key material read-only for reconciliation. Do not delete or overwrite them.
3. Confirm that no v6 lot represents funds requiring recovery. If any lot may
   contain value, stop and perform a separately reviewed owner-wallet recovery;
   this ceremony is not authorized to discard it.
4. Revoke or retire all development payment policy/key epochs that referenced
   the old store.
5. Choose new paths, a fresh random `store_instance_id`, and a separately
   administered rollback authority. Initialize a fresh v7 store explicitly.
6. Install reviewed policy material and finite exact `(mint_id, unit)` exposure
   caps. Reissue only test capabilities appropriate for the new store.
7. Verify `application_id`, `user_version=7`, schema identity, generation zero,
   the independent floor, private permissions and empty custody/retirement
   inventories before activation.
8. Rehearse export, delivery acknowledgement, non-`SPENT` rejection, exact
   all-`SPENT` confirmation, restart replay and lost-anchor recovery using
   disposable regtest notes.

The old v6 files remain an offline audit artifact. They are never a rollback
target for a v7 binary.

## Failure and rollback rules

- Failure before fresh v7 initialization leaves v6 offline and unchanged.
- Failure after v7 generation zero but before any mutation may be handled only
  by abandoning the exact new paths and starting again with another fresh
  store identity and floor.
- After any v7 mutation, never restore an older database or floor. Repair
  forward from the latest anchored generation.
- Binary rollback is allowed only to a binary that understands and preserves
  schema v7, including `SpentConfirmed` and retirement evidence.
- Missing, malformed or conflicting evidence; any `UNSPENT`, `PENDING` or
  unknown NUT-07 state; a stale precondition floor; or an unavailable mint
  keeps the export in state 3 and keeps its exposure counted.

## Required acceptance evidence

Before any production activation, retain test evidence that v7:

- rejects v6/unknown schemas without writing them;
- counts state-3 lots in runtime and startup exposure checks;
- atomically advances every exact member lot, its export, the digest-only
  evidence row and one rollback-anchored store generation;
- returns one commit and idempotent exact replays under concurrency and after
  restart or a lost rollback-authority response;
- performs no write for non-`SPENT`, missing, malformed, stale or mismatched
  inputs;
- detects missing or tampered evidence on subsequent reads; and
- never persists raw Y values, NUT-07 per-note states, proof secrets, invoices,
  payment hashes, preimages, payer data, query addresses or query results.
