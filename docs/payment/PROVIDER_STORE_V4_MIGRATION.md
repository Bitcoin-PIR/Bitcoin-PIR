# ProviderStore first-release initialization

Status: compatibility note for the first Payment V1 release. Despite this
file's historical name, there is no released or production ProviderStore v4
installation to migrate. Schema v4 existed only during development of the
unreleased payment branch. Do not invent a v4-to-v5 production ceremony or
claim that one has been rehearsed.

## Supported state

The first Payment V1 server accepts exactly ProviderStore schema v5. It
verifies `application_id`, `PRAGMA user_version`, the complete normalized table
set, the embedded store identity, and the independent rollback floor before it
can serve an enforced policy. Opening a store never creates tables and never
performs an implicit migration.

Create a fresh store and rollback authority explicitly:

```sh
cargo run --offline -p bpir-admin -- service-store-init --help
```

The two outputs must live in independent backup and restore domains in a real
deployment. The command refuses overwrite and aliases, creates generation-zero
state, applies private file permissions on supported Unix platforms, and
reopens both files through the normal production open-existing path before it
reports success. If a step fails after either file is created, the ceremony is
incomplete: inspect both paths and remove only files proven to belong to that
failed attempt before trying again.

## Development stores are not migration input

Any pre-release v4 database is disposable development state. It must not be
edited, copied and rebound, or imported into a Payment V1 production identity.
Create a new v5 store with a fresh random `store_instance_id`, a new independent
rollback authority, and freshly reviewed policy/key material. Previously issued
development credentials are deliberately invalidated.

This rule avoids pretending that an unaudited conversion preserves every spent
capability, namespace floor, Cashu recovery intent and Free quota clock. It also
keeps the rollback authority independent: rewriting a database and its floor
together would make a stale pair self-consistent.

## Rollback rule

- Before the new v5 store accepts any mutation, an aborted initialization may
  be discarded after its exact paths have been inspected.
- After any admission, spend, policy or recovery mutation, never restore an
  older database or rollback-floor record. Drain traffic and fix forward from
  the latest authoritative state.
- A binary rollback is allowed only when that binary understands schema v5 and
  preserves all current monotonic floors and spent state.
- A future released schema change requires its own versioned, reviewed offline
  migration tool and cutover/rollback plan. This document does not authorize
  such a migration.

## Acceptance evidence

Before release, tests must show that fresh initialization:

- refuses existing files, aliases, symlinks and unsafe parent paths;
- produces owner-only state and reopens the exact identity on Unix;
- leaves partial state visibly marked as an incomplete ceremony rather than
  deleting or adopting it;
- rejects wrong provider identity, wrong schema, stale generation, floor fork
  and lost compare-and-swap state;
- never places an invoice, payment hash, preimage, bearer capability, Cashu
  proof secret, blinding scalar or query data in operator output.
