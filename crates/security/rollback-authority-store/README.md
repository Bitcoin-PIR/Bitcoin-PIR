# BitcoinPIR rollback authority store

This crate is the SQLite persistence and request-processing core for one
remote rollback-authority instance. It intentionally contains no HTTP
listener, routing policy, namespace enumeration, online provisioning, delete,
reset, migration, or recovery CLI.

The online processor authenticates the exact provisioned client key before it
opens a linearizable Read or CAS transaction. Every first CAS terminal result,
including `Empty` and `ConflictCurrent`, is committed to the operation log in
the same `BEGIN IMMEDIATE` transaction as the observed record and any applied
mutation. A retry with a fresh call nonce may reuse a stable operation ID only
when its stable operation digest is identical. Responses are signed only after
the transaction commits successfully.

Every fresh authenticated call also commits a bounded `call_log` row containing
the exact request digest and the opaque record snapshot observed at that call's
linearization. Replaying the same signed Read or CAS bytes returns that stored
snapshot and never re-reads a later live floor. A CAS recovery attempt with a
fresh nonce remains a new call, observes current state once, and persists its
own replay snapshot.

## Deployment boundary

This is a **single-instance linearizable authority store**, not an extension of
the detailed provider or issuer database. Production deployments must run it
on a different host and under a different administrator, backup policy,
restore procedure, and failure domain from the detailed store whose rollback
it prevents.

PIR Server 0, PIR Server 1, and the payment/credential issuer each require an
independent authority instance. They must not share one observable authority
instance, namespace database, operation log, host, or administrator. Sharing
would create a correlation surface and collapse the intended separation.

The database uses WAL with `synchronous=FULL`. Its containing directory must
be a real, effective-user-owned `0700` directory and the final database file
must be a non-symlink, single-hard-link, effective-user-owned `0600` regular
file. Creation is exclusive, and opening an existing database requires the
caller-pinned schema identity and authority instance ID; the implementation
never adopts, overwrites, rebinds, or implicitly migrates existing state.

Namespace provisioning is exposed only by the offline provisioner type and is
insert-only. V1 permits exactly one namespace per authority instance and
requires explicit finite operation-row and call-row capacities when
provisioning it. Repeating the exact namespace/key/capacity tuple is
idempotent; a second namespace, key rebind, or either capacity change fails
closed. The online store has no provisioning or destructive API.

The namespace row contains an atomic count of operation-log rows. A new CAS
reserves one row in the same `BEGIN IMMEDIATE` transaction before reading or
mutating the current record; transaction rollback also rolls back the
reservation. Exact operation replay does not reserve again. On capacity
exhaustion, a new CAS fails closed without changing the current record, while
fresh Read, fresh-nonce retry, and exact call replay remain available while
call capacity remains.

The namespace row separately counts `call_log` rows. Every previously unseen
call nonce reserves one row before observing the current record; request digest
or operation reuse with incompatible content fails closed. Exact signed-request
replay consumes no second row and remains available at capacity. Exhausting the
call capacity rejects every new Read and fresh-nonce CAS before current state is
read; this is a hard fail-closed availability boundary, so call capacity must
include all planned startup Reads and recovery attempts. Full store-open
validation checks both stored counters against their exact durable row counts
and checks every CAS call against its stable operation row.

V1 deliberately provides no pruning, expiry, quota increase, or online
migration. Operators must choose the provision-time limit from measured
SQLite-row, WAL, backup, restore, and monitoring footprints for the complete
planned lifetime, leaving substantial free-space headroom. Exhaustion requires
a reviewed authority-identity migration; directly editing counters or limits is
schema/state corruption and is rejected on checked reopen.

Exact operation and call capacity inventory exists only on the offline
provisioner type, after that type's open has completed the full schema,
integrity, and semantic row checks. It returns an explicit unprovisioned state
when no namespace exists. The online request-processor type has no production
inventory or namespace-enumeration API. Treat both exact usages as
activity-sensitive operational data even though neither contains an
identifier.

The current fresh-store-only on-disk schema is version 2. The earlier
development-only schema lacked `call_log`; it is rejected and is never migrated
in place. Because no V1 authority has been production-enabled, operators must
initialize and provision a new store rather than adopting a pre-change drill
database.

## Loss and restore rule

A complete authority loss must never be recovered by restoring an unproven
stale snapshot. The service must stay closed and either rotate to a new,
explicitly trusted authority identity through an offline ceremony or present
an independently protected high-water proof that establishes the restored
state is not behind. Backups alone are not rollback evidence.
