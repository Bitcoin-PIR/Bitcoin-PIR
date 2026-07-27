# Payment V1 no-funds store staging drill

Status: local/staging deployment preparation. This drill starts no listener,
contacts no Lightning node, mint, relay or remote host, and moves no funds. It
does not authorize production deployment or the use of production secrets.

## What this drill proves

The commands below exercise:

- deterministic two-provider, five-method, five-workload fixture generation;
- explicit issuer schema-v5 and provider schema-v7 initialization;
- owner-only database paths and separately configured rollback authorities;
- the same full `open_existing` integrity and rollback-floor checks used by
  serving startup;
- current-generation backup/restore acceptance and stale restore rejection;
- aggregate row-count and startup-latency observations suitable for defining a
  staging SLO.

Using separate directories under one temporary filesystem makes the command
reproducible, but does **not** prove independent production backup/restore
domains. Production needs separately controlled storage, credentials and
restore procedures.

Prerequisites are the repository-pinned Rust toolchain/lockfile, `jq`, and a
locally installed SQLite shell with `.backup` support. Run in a shell that has
no production Lightning, mint, relay or provider credentials configured.

## 1. Generate the no-funds inventory

Run from the repository root:

```sh
drill_root="$(mktemp -d "${TMPDIR:-/tmp}/bpir-store-drill.XXXXXX")"
scripts/fixtures/generate-payment-v1-no-funds.sh "$drill_root/fixture"

provider_id="$(jq -r '.providers[0].provider_id' "$drill_root/fixture/fixture.json")"
issuer_id="$(jq -r '.providers[0].issuer_id' "$drill_root/fixture/fixture.json")"
jq '{test_only, deterministic, funds_capable, providers: (.providers | length)}' \
  "$drill_root/fixture/fixture.json"
```

The inventory must report `test_only: true`, `deterministic: true`,
`funds_capable: false`, and two providers. Every key in this fixture is public
test material; never attach funds or production data to it.

## 2. Initialize fresh stores

The following directory separation is only a local model:

```sh
install -d -m 0700 \
  "$drill_root/provider-store" "$drill_root/provider-floor" \
  "$drill_root/issuer-store" "$drill_root/issuer-floor"

cargo run --locked --offline -p bpir-admin -- service-store-init \
  --provider-id-hex "$provider_id" \
  --store "$drill_root/provider-store/admission.sqlite3" \
  --rollback-authority "$drill_root/provider-floor/floor.sqlite3"

cargo run --locked --offline -p payment-issuer -- init-store \
  --issuer-id-hex "$issuer_id" \
  --network regtest \
  --store "$drill_root/issuer-store/issuer.sqlite3" \
  --rollback-authority "$drill_root/issuer-floor/floor.sqlite3"
```

The provider command must report schema version 7 and the issuer command
schema version 5. On Unix, each parent must be mode
0700 and each SQLite file mode 0600. Repeating either initialization against
the same paths must fail; it never overwrites or adopts existing state.

## 3. Run serving-equivalent startup checks

These commands start no listener:

```sh
cargo run --locked --offline -p bpir-admin -- service-store-check \
  --provider-id-hex "$provider_id" \
  --store "$drill_root/provider-store/admission.sqlite3" \
  --rollback-authority "$drill_root/provider-floor/floor.sqlite3"

cargo run --locked --offline -p payment-issuer -- check-store \
  --issuer-id-hex "$issuer_id" \
  --network regtest \
  --store "$drill_root/issuer-store/issuer.sqlite3" \
  --rollback-authority "$drill_root/issuer-floor/floor.sqlite3"
```

Each output includes `startup_check_ms` plus aggregate row counts. It never
prints an invoice, payment hash/preimage, capability, IP-derived subject,
query, or secret key.

`check-store` deliberately uses the real recovery path. An exact database /
authority match is read-only, but an SQLite database that is exactly one
legitimate committed successor ahead of its authority can cause the command to
complete the idempotent authority CAS, just as serving startup would. Quiesce
writes and use an isolated restore candidate for a backup drill; do not treat
this command as a generic read-only database viewer.

## 4. Measure and gate startup

Run each check repeatedly on the staging restore candidate and retain only the
aggregate fields. Record at least:

- store file and WAL sizes;
- issuer `quote_rows`, `claim_rows`, `retained_policy_rows`,
  `redemption_rows`, and `payout_rows`;
- provider `namespace_rows`, `spent_capability_rows`,
  `free_rate_limit_bucket_rows`, `cashu_swap_intent_rows`,
  `cashu_custody_lot_rows`, `cashu_custody_note_rows` and
  `cashu_custody_export_batch_rows`;
- cold and warm `startup_check_ms` observations on the intended storage class.

The actual issuer and provider processes emit the same aggregate inventory and
open-check latency during enforced startup. Define an environment-specific
maximum before activation and fail the deployment gate if it is exceeded.
There is intentionally no universal millisecond default: storage class,
retained-history threshold, and recovery objectives are operator decisions.
The current issuer full integrity check is O(all retained quote history), so
active-quote capacity alone is not a startup or disk bound.

## 5. Backup and restore rehearsal

Use a SQLite online-backup implementation while a process may be active. The
`sqlite3` shell is shown only as a local example; pin and audit the actual
production backup tool separately. A SQLite online backup makes each database
internally consistent, but it does not make independently timed store and
authority backups one consistent pair. Quiesce economic/admission writes for
this positive restore rehearsal. Back up the protected store and its rollback
authority through independent jobs and credentials, never one atomic snapshot:

```sh
install -d -m 0700 \
  "$drill_root/provider-store-restore" "$drill_root/provider-floor-restore" \
  "$drill_root/issuer-store-restore" "$drill_root/issuer-floor-restore"

sqlite3 "$drill_root/provider-store/admission.sqlite3" \
  ".backup '$drill_root/provider-store-restore/admission.sqlite3'"
sqlite3 "$drill_root/provider-floor/floor.sqlite3" \
  ".backup '$drill_root/provider-floor-restore/floor.sqlite3'"
sqlite3 "$drill_root/issuer-store/issuer.sqlite3" \
  ".backup '$drill_root/issuer-store-restore/issuer.sqlite3'"
sqlite3 "$drill_root/issuer-floor/floor.sqlite3" \
  ".backup '$drill_root/issuer-floor-restore/floor.sqlite3'"

chmod 0600 \
  "$drill_root/provider-store-restore/admission.sqlite3" \
  "$drill_root/provider-floor-restore/floor.sqlite3" \
  "$drill_root/issuer-store-restore/issuer.sqlite3" \
  "$drill_root/issuer-floor-restore/floor.sqlite3"
```

Run both `check-store` commands again with the four `*-restore` paths. The
restored identities, generations and aggregate counts must match the source.
If independently timed backups straddle a generation, the restored pair must
fail closed; quiesce writes and take a new pair. Do not lower, rewrite or
synthesize an authority record to make a stale store pass.

The deterministic negative and recovery cases are executable with:

```sh
cargo test --locked --offline -p pir-service-store \
  rollback_floor_tests::backup_at_the_exact_anchored_generation_restores_normally
cargo test --locked --offline -p pir-service-store \
  rollback_floor_tests::stale_backup_restore_is_rejected_and_cannot_revive_old_state
cargo test --locked --offline -p pir-service-store \
  rollback_floor_tests::lost_cas_response_recovers_without_a_second_generation

cargo test --locked --offline -p pir-issuer-store --test issuer_store \
  backup_at_the_exact_issuer_generation_restores_normally
cargo test --locked --offline -p pir-issuer-store --test issuer_store \
  stale_backup_restore_is_rejected_by_the_independent_authority
cargo test --locked --offline -p pir-issuer-store --test issuer_store \
  lost_cas_response_recovers_without_a_second_generation
```

These tests exercise actual SQLite backups and the store rollback protocol,
but use deterministic local authorities. Before activation, repeat the drill
against the selected independently durable production authority backend and
its real backup/restore mechanism under separate approval.

## 6. Failure and rollback rule

- Missing, unavailable, stale, forked or wrong-identity authority state must
  fail closed.
- A current database plus current authority may restart normally.
- A stale database must never be made acceptable by restoring or lowering the
  authority with it.
- After any admission/economic mutation, roll back traffic and binary/config
  only if they remain schema-compatible; fix forward from the latest
  authoritative state.
- If the latest state cannot be proven, keep service stopped and use the
  reviewed keyset-revocation/new-store recovery ceremony.

Keep the drill directory only as long as required for local evidence. Inspect
the exact path before removal; never point cleanup commands at an unresolved
variable or a production directory.
