# Legacy ProviderStore v4/v5 compatibility note (archived)

The current schema-v7 ceremony and rollback contract is
[`PROVIDER_STORE_V7_MIGRATION.md`](PROVIDER_STORE_V7_MIGRATION.md). This file is
retained only so historical links fail safely.

ProviderStore v4 and v5 existed only on the unreleased payment-development
branch. Neither is a supported serving, initialization, migration or rollback
target. Do not edit either database in place, rebind it to another provider or
advance its rollback floor to make it look current.

For disposable pre-release state, initialize a fresh v7 store and independent
rollback authority. If an old database may contain real-value Cashu inputs or
provider notes, preserve it read-only and stop: it requires a separately
reviewed, database-specific extraction and reconciliation plan. There is no
generic v4/v5-to-v7 migration command.
