# ProviderStore schema v6 historical note (archived)

> **Superseded before release.** This document records an unreleased
> development schema. It is not an operator runbook, and none of the old v6
> creation, activation or rollback commands are valid for the current tree.
> Use [`PROVIDER_STORE_V7_MIGRATION.md`](./PROVIDER_STORE_V7_MIGRATION.md) for
> the only supported ceremony.

No ProviderStore schema had been activated in production when v6 was replaced.
Schemas v4, v5 and v6 were development-only states on the unreleased Payment
branch. The current server accepts exactly schema v7 and refuses to open or
upgrade v6.

## Why v6 was replaced

V6 introduced provider-owned standard-Cashu custody, exact recovery material,
finite exposure accounting and bounded encrypted export. Its acknowledgement
transition nevertheless released local exposure before external evidence
proved that every exported note was spent. That state transition is unsafe
under crash, retry and dishonest-operator scenarios.

V7 therefore separates:

- `Available`;
- `Reserved`;
- `DeliveryAcknowledged`, which still counts toward exposure; and
- `SpentConfirmed`, reached only after exact all-`SPENT` NUT-07 evidence and
  the atomic provider-store confirmation.

Because the missing v7 state cannot be reconstructed safely from a v6 row,
there is no in-place migration. Pre-release deployments must create a fresh
v7 store and independent rollback authority using the v7 runbook. Previously
issued development capabilities are deliberately invalidated.

If any v6 database may contain real-value inputs or provider custody, preserve
the database, WAL, rollback-floor record, recovery keys, custody keys and
signed policies read-only. Do not initialize another store over it and do not
serve from it. Recovery requires a separately reviewed, database-specific
extraction and reconciliation plan; this repository provides no generic v6
conversion or rollback command.

Historical v6 test evidence may still explain the origin of the custody design,
but it is not acceptance evidence for v7. Current invariants and tests are in
[`PERSISTENCE.md`](../../payment/PERSISTENCE.md),
[`PROVIDER_STORE_V7_MIGRATION.md`](./PROVIDER_STORE_V7_MIGRATION.md), and
[`LOCAL_ACCEPTANCE.md`](./LOCAL_ACCEPTANCE.md).
