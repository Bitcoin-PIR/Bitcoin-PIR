# Payment persistence contract

Status: normative implementation contract for v1. The SQL below is a schema
shape, not permission to enable a production payment gate.

## Database boundaries

Each logical `provider_id` owns a separate spent database. Two PIR providers,
including two providers run by the same operator, MUST NOT share that database,
its WAL, a spent table, or a remote spent service. The only exception is
replicas advertising the same `provider_id` and the same credential keysets;
those replicas are one logical provider and require one linearizable spend
authority.

The shared issuer uses a different database and process. PIR servers have no
SQL access to it. If two otherwise independent providers use the same issuer,
the issuer becomes common infrastructure and can observe both redemption
streams; no database split can restore the two-server non-collusion assumption.

SQLite WAL files MUST remain on a local filesystem. A WAL on NFS or multiple
active issuer hosts is not a consensus system. Multi-host active/active service
requires a database with linearizable unique constraints and an explicit
failover protocol.

The rollback-floor authority MUST also live in a separate administrative and
backup/restore domain, not merely a different SQLite filename. A VM,
filesystem, volume or backup job that snapshots the main database and its
authority together can restore a stale but mutually consistent pair and
therefore defeats the rollback boundary. Production readiness requires an
independent restore drill and generation/commitment comparison.

## Provider store

The minimal provider-local schema is:

```sql
CREATE TABLE store_identity (
    singleton                  INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    store_instance_id          BLOB NOT NULL UNIQUE CHECK (length(store_instance_id) = 16),
    provider_id                BLOB NOT NULL UNIQUE CHECK (length(provider_id) = 32),
    store_generation           INTEGER NOT NULL CHECK (store_generation >= 0),
    spend_commit_seq           INTEGER NOT NULL CHECK (
        spend_commit_seq >= 0 AND spend_commit_seq <= store_generation
    ),
    rollback_parent_commitment BLOB NOT NULL CHECK (
        length(rollback_parent_commitment) = 32
        AND (
            (store_generation = 0 AND rollback_parent_commitment = zeroblob(32))
            OR (store_generation > 0 AND rollback_parent_commitment != zeroblob(32))
        )
    ),
    rollback_commitment        BLOB NOT NULL CHECK (
        length(rollback_commitment) = 32 AND rollback_commitment != zeroblob(32)
    ),
    schema_version             INTEGER NOT NULL CHECK (schema_version > 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE spend_namespaces (
    namespace_id   BLOB NOT NULL PRIMARY KEY CHECK (length(namespace_id) = 32),
    scheme         INTEGER NOT NULL,
    issuer_id      BLOB NOT NULL CHECK (length(issuer_id) = 32),
    key_id         BLOB NOT NULL CHECK (length(key_id) BETWEEN 1 AND 66),
    binding_digest BLOB NOT NULL CHECK (length(binding_digest) = 32),
    not_after      INTEGER NOT NULL CHECK (not_after >= 0),
    status         INTEGER NOT NULL CHECK (status IN (1, 2)),
    UNIQUE (scheme, issuer_id, key_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE spent_capabilities (
    namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 32),
    spend_key    BLOB NOT NULL PRIMARY KEY CHECK (length(spend_key) = 32),
    FOREIGN KEY (namespace_id)
        REFERENCES spend_namespaces(namespace_id)
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE exclusive_key_lineages (
    scheme          INTEGER NOT NULL CHECK (scheme BETWEEN 1 AND 65535),
    key_fingerprint BLOB NOT NULL CHECK (
        length(key_fingerprint) = 32 AND key_fingerprint != zeroblob(32)
    ),
    lineage_digest  BLOB NOT NULL CHECK (
        length(lineage_digest) = 32 AND lineage_digest != zeroblob(32)
    ),
    PRIMARY KEY (scheme, key_fingerprint)
) STRICT, WITHOUT ROWID;

CREATE TABLE free_ip_rate_limit_buckets (
    subject        BLOB NOT NULL CHECK (length(subject) = 32),
    policy_digest  BLOB NOT NULL CHECK (length(policy_digest) = 32),
    scope_id       BLOB NOT NULL CHECK (length(scope_id) = 32),
    offer_id       INTEGER NOT NULL CHECK (offer_id > 0),
    expires_at     INTEGER NOT NULL CHECK (expires_at > 0),
    count          INTEGER NOT NULL CHECK (count > 0),
    PRIMARY KEY (subject, policy_digest, scope_id, offer_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE free_ip_rate_limit_clock (
    singleton   INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    highest_now INTEGER NOT NULL CHECK (highest_now >= 0)
) STRICT, WITHOUT ROWID;
```

`spend_key` is unique across the entire logical provider, not merely within a
namespace. This is deliberate defense in depth: receipt and anonymous-ticket
serials are issuer/key global, and a configuration error must not make the same
capability spendable again by assigning it a second scope namespace.

`exclusive_key_lineages` is a permanent configuration-safety registry for
schemes whose bearer proof does not itself expose its signed audience. In v1
this is mandatory for provider-local Cashu BAT. `key_fingerprint` is derived
from the canonical raw DHKE verification point, never from a policy-selected
key ID; `lineage_digest` commits the one immutable provider/scope/offer/profile
and key-epoch lineage allowed to use that point. The mapping is not deleted
when a namespace closes. Reinstalling the same mapping is idempotent, while
attempting to bind that raw key to another lineage fails in the same
`BEGIN IMMEDIATE` transaction that installs the namespace. The two independent
PIR providers still require different raw BAT keys: this table is local to one
provider and cannot detect cross-provider key reuse.

For BAT, the global durable spend key is derived from a domain separator, the
fingerprint of the raw DHKE verification point, and the 32-byte token secret.
It deliberately excludes issuer-, offer-, policy-, and audience-derived key
IDs. Rotating or rebinding metadata therefore cannot make one BAT secret
spendable again. The issuer must enforce the corresponding raw-key lineage
constraint across every provider it serves.

`spent_capabilities` has no token timestamp, connection ID, client IP, query
identifier, or insertion-order column. Namespace expiry is a public cohort
property and permits safe garbage collection only after the policy-retention
horizon has closed.

The implemented provider schema version is `5`. Startup rejects every older
or unknown version, a missing required table, extra schema objects, or any
column drift; migration is an explicit offline operator action rather than an
automatic serve-mode side effect.

Policy rollback state is persisted in the same provider transaction domain:

```sql
CREATE TABLE policy_heads (
    provider_id          BLOB NOT NULL PRIMARY KEY CHECK (length(provider_id) = 32),
    highest_policy_epoch INTEGER NOT NULL CHECK (highest_policy_epoch > 0),
    policy_digest        BLOB NOT NULL CHECK (length(policy_digest) = 32),
    signed_policy        BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE credential_epoch_floors (
    scope_id     BLOB NOT NULL CHECK (length(scope_id) = 32),
    scheme       INTEGER NOT NULL,
    issuer_id    BLOB NOT NULL CHECK (length(issuer_id) = 32),
    minimum_epoch INTEGER NOT NULL CHECK (minimum_epoch > 0),
    PRIMARY KEY (scope_id, scheme, issuer_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE cashu_manifest_epoch_floors (
    mint_id       BLOB NOT NULL CHECK (length(mint_id) = 32),
    unit          TEXT NOT NULL,
    minimum_epoch INTEGER NOT NULL CHECK (minimum_epoch > 0),
    PRIMARY KEY (mint_id, unit)
) STRICT, WITHOUT ROWID;
```

The server never accepts a lower policy, a different digest at an already
accepted epoch, a lower credential keyset epoch, or a lower Cashu manifest
epoch. Updating a head and all derived floors is one durable transaction.

### Local spend transaction

Signature/proof verification and expensive parsing occur outside the write
transaction. Immediately before committing, the store repeats the active
namespace and provider identity checks:

```text
verify canonical proof and derive a scheme-specific spend_key
BEGIN IMMEDIATE
verify store provider_id and active namespace
verify the exact independent rollback-floor anchor
INSERT spent_capabilities(namespace_id, spend_key)
increment store_generation and extend the rolling commitment
increment spend_commit_seq
COMMIT
atomically CAS the independently durable rollback-floor anchor
install connection-local grant
send AUTH_GRANTED
```

A unique-key conflict is `AlreadySpent`. `AUTH_GRANTED` is impossible before a
successful SQLite commit and a confirmed external anchor CAS. If SQLite commit
returns an indeterminate I/O outcome, the server closes the connection and
reopens the database to inspect the key; the current connection receives no
grant in either case and the public result is `InternalAfterSpend`. If SQLite
commits but the external CAS cannot be confirmed, the result is
`UnanchoredCommit`, also without a grant. Checked reopen may reconcile exactly
one successor whose recorded parent equals the current external anchor; it
cannot skip generations or choose between forks.

Recommended checked pragmas are:

```text
journal_mode = WAL
synchronous = FULL
foreign_keys = ON
trusted_schema = OFF
temp_store = MEMORY
busy_timeout = a short operator-configured value
```

Every pragma is read back and asserted. Serve mode opens an existing database
read/write and refuses missing, corrupt, wrong-provider, or unknown-version
files. It never silently creates an empty spent database.

### Free admission

- `OpenBestEffort`: no durable token row.
- `IpRateLimited`: `free_ip_rate_limit_buckets` stores only a provider-local
  32-byte `HMAC(rotation_key, provider_id || normalized_ip)`, `scope_id`,
  signed `policy_digest`, `offer_id`, absolute expiry, and count; a separate
  global durable high-water clock rejects rollback before expired buckets are
  deleted. The transaction deletes only expired buckets, then checks a strict
  provider-local capacity before admitting a new subject. It stores no raw IP,
  request timestamp, linkable client ID, or cross-provider identifier; the
  coarse bucket expiry and one provider-global clock high-water are retained
  solely for expiry and rollback enforcement. Each increment is one
  `BEGIN IMMEDIATE` provider-store transaction followed by the external
  rollback-floor CAS; restart never refreshes quota and a lower wall clock
  fails closed.
- `ProofOfWork`: one server-fresh, secure-channel-bound challenge is held in
  connection state and consumed once.
- `AnonymousTicket`: uses `spent_capabilities`.

### Standard Cashu merchant swap

The external mint's atomic NUT-03 invalidation is authoritative. A successful
swap MUST NOT be followed by a second provider-local authoritative spend
insert. The provider persists only encrypted recovery intent:

```sql
CREATE TABLE cashu_swap_intents (
    intent_id               BLOB NOT NULL PRIMARY KEY CHECK (length(intent_id) = 16),
    mint_id                 BLOB NOT NULL CHECK (length(mint_id) = 32),
    input_set_digest        BLOB NOT NULL CHECK (length(input_set_digest) = 32),
    request_digest          BLOB NOT NULL CHECK (length(request_digest) = 32),
    output_set_digest       BLOB NOT NULL CHECK (length(output_set_digest) = 32),
    offer_binding_digest    BLOB NOT NULL CHECK (length(offer_binding_digest) = 32),
    settlement_value        INTEGER NOT NULL CHECK (settlement_value > 0),
    state                   INTEGER NOT NULL CHECK (state BETWEEN 0 AND 4),
    recovery_key_epoch      INTEGER NOT NULL CHECK (recovery_key_epoch > 0),
    recovery_nonce          BLOB NOT NULL CHECK (length(recovery_nonce) BETWEEN 1 AND 64),
    recovery_ciphertext     BLOB NOT NULL CHECK (
        length(recovery_ciphertext) BETWEEN 1 AND 262144
    ),
    created_bucket          INTEGER NOT NULL CHECK (created_bucket >= 0),
    updated_bucket          INTEGER NOT NULL CHECK (updated_bucket >= created_bucket),
    UNIQUE (mint_id, input_set_digest)
) STRICT, WITHOUT ROWID;
```

The ciphertext contains the exact canonical NUT-03 request, ordered blinded
outputs, output secrets, and blinding factors. Its encryption key is not stored
in this database. Proof secrets, `dleq.r`, and wallet recovery material are
never plaintext columns or logs.

```text
PREPARED --externally anchored--> SUBMITTED -> WALLET_STORED -> GRANT_ISSUED
                                   |              ^
                                   -> ATTENTION --|
```

There is deliberately no `SUBMITTED -> PREPARED`, abandoned-unspent, or
resubmit transition. NUT-07 `UNSPENT` is only a point-in-time observation and
cannot prove that an ambiguous NUT-03 will not commit later. The first exact
prepared recovery envelope wins; a replay with a fresh AEAD nonce returns the
existing envelope without a generation change. Changed request, output set,
offer binding, amount, intent ID, or `(mint_id, input_set_digest)` ownership is
a hard conflict.

Every actual state mutation advances `store_generation` and its independent
rollback-floor CAS. The caller may send NUT-03 only after the store returns
success for the anchored `PREPARED -> SUBMITTED` transition. Only
`WALLET_STORED -> GRANT_ISSUED` also advances `spend_commit_seq`. Schema v5 is
strictly opened without implicit migration. Payment V1 has no released v4
production state; fresh initialization and pre-release compatibility rules are
in [`PROVIDER_STORE_V4_MIGRATION.md`](PROVIDER_STORE_V4_MIGRATION.md).

Grant occurs only after input invalidation, full output/signature/DLEQ
verification, and durable storage of the provider's received eCash. A lost
response uses NUT-09 with the identical blinded outputs.

## Issuer store

One issuer database atomically contains:

- one current provider registration plus append-only, digest-addressed
  registration history, operator trust anchors, clearing keys and epoch floors;
- quote intent, deterministic Lightning backend label, invoice mapping and
  exact signed quote response;
- quote claims and exact issuance response bytes;
- Cashu promises and authoritative spent `Y` values;
- shared credential redemptions and nullifiers;
- blind settlement promises and deposited-note spent values;
- double-entry ledger transactions/postings;
- durable outbox work.

New quote reservation atomically checks both a configured outstanding-unpaid
ceiling and a broader active-workflow ceiling. `Reserved` consumes capacity
through its maximum create+invoice+claim recovery horizon; `InvoiceOpen` and
`InvoiceExpiredPendingReconcile` consume it through their immutable claim
deadline. Paid, claimed, late-paid, failed reservations past that horizon and
other horizon-expired rows remain auditable but release admission capacity. An
exact durable replay is checked first and remains recoverable when either
active ceiling is full.

Terminal quote/economic rows are not deleted by overload handling, so active
capacity is deliberately **not** a disk-usage bound. Production must set a disk
quota with free-space/WAL/backup-growth alerts and a tested disk-full shutdown
procedure. No row may be removed until an audited retention/archive design
preserves exact-response recovery, accounting and rollback commitments;
ad-hoc SQL deletion or vacuuming is not an archival mechanism.

Every accepted provider registration epoch is inserted into retained history
in the same rollback-anchored transaction that installs it as current. Account
and payout-target identities remain immutable across rotation. Fresh status
requests and every debt/payout mutation use only the current row; a historical
request key is read only after the issuer has matched the canonical request
digest to the payout's durable **latest** exact status response. V1 retains
this history indefinitely. Schema v5 is still pre-release and includes this
table at fresh initialization; an already-created incompatible v5 database is
rejected rather than implicitly migrated.

Readiness and reconciliation queries use persisted horizon indexes and do not
decode expired quote rows. Full store open still verifies every retained quote
history and provider-registration digest, however, so startup integrity work
remains O(total retained history) until that audited archive format exists.
Monitor retained-row count and startup latency, budget maintenance windows, and
fail activation if the measured bound is exceeded; do not bypass full
verification to make a restart faster.

Authenticated quote-status reads store only a domain-separated nonce digest.
At most 64 live nonce digests may exist for one quote during the five-minute
request-freshness horizon; expired rows are deleted transactionally before the
limit is checked. A saturated client waits for expiry and signs a fresh nonce.
The HTTP process also enforces a separate global status budget, because a
per-quote row bound alone does not bound aggregate rollback-authority CAS work.

Important uniqueness constraints include:

```text
quotes:               UNIQUE(endpoint_kind, idempotency_key_digest)
                      UNIQUE(lightning_backend_id, backend_label)
                      UNIQUE(payment_hash)
quote_claims:          PRIMARY KEY(quote_id)
redeem_operations:     UNIQUE(provider_id, idempotency_key_digest)
redeemed_capabilities: PRIMARY KEY(spend_key)
settlement_promises:   PRIMARY KEY(settlement_keyset_id, blinded_message)
deposit_operations:    UNIQUE(provider_id, idempotency_key_digest)
settlement_keysets:     UNIQUE(issuer_id, settlement_keyset_id)
issuer_settlement_keys:UNIQUE(issuer_id, issuer_settlement_key_id)
settlement_spent_notes:PRIMARY KEY(spend_key)
payouts:                UNIQUE(payout_intent_id), UNIQUE(payout_id)
outbox:                UNIQUE(dedupe_key)
```

`spend_key` is the protocol's domain-separated hash of the raw denomination
public-key fingerprint and authoritative Cashu `Y`; it intentionally excludes
issuer, keyset, provider, and account identifiers. Retained keysets and
settlement-signature keys nevertheless carry an explicit issuer lineage in
their own trusted registries, preventing a handler from mixing two issuers'
verification state.

Payout creation stores the exact initial signed response in the same
transaction as intent consumption, debit/reservation, payout creation and
outbox insertion. Each later transition atomically compares the exact stored
predecessor state/version/time and replaces it with the exact signed successor;
zero or one row may change. Backup/restore cannot synthesize a lower predecessor
that the external rollback floor has already superseded.

Idempotency keys are stored as domain-separated digests, never cleartext.
Before checking current policy/authorization validity, every handler first
looks up an exact previously committed `(idempotency digest, request digest)`:

- same key and same digest: return the exact stored response bytes;
- same key and different digest: conflict;
- no row: validate current authority and create a new operation.

This ordering lets a client recover a committed response after key rotation or
expiry without authorizing new debt under stale authority.

### Atomic redeem

```text
verify registered provider/operator/clearing authority
verify canonical capability and derive spend_key
precompute response, including blind promises, without releasing it
BEGIN IMMEDIATE
repeat provider status and authorization epoch checks
repeat idempotency lookup
insert redemption and unique spend_key
post provider credit + issuer fee, or blind-note liability
insert every blind promise and exact canonical response
COMMIT
return response
```

Blind settlement rules bind one exact issuer-countersigned keyset and a minimum
recovery horizon. The redeem request binds that keyset ID and canonically
ordered blinded messages. A bearer client without the registered provider
clearing key cannot redirect compensation.

### Ledger and outbox

Posted ledger transactions are immutable, contain at least two postings in one
unit, and have `SUM(amount) = 0`. All protocol amounts are at most `i64::MAX`
before conversion to SQLite INTEGER. Business state and the corresponding
outbox row commit together. Workers lease outbox rows briefly; external
Lightning/backend operations use stable labels so at-least-once delivery still
creates one external side effect.

Real payouts remain disabled until separately authorized. Enabling an API type
or fake-backend test is not authorization to send funds.

## Rollback and backup

SQLite online backup guarantees a consistent historical snapshot, not that the
snapshot contains later spends. Restoring it can make a consumed capability
valid again. The provider-store public open/create APIs therefore require a
trusted `RollbackFloorAuthorityV1`; there is no production SQLite-only mode.
The authority record is keyed by `provider_id` and binds:

```text
store_instance_id
provider_id
schema_version
store_generation
spend_commit_seq
rollback_commitment
```

The authority implementation MUST provide a linearizable, durably acknowledged
initialize and compare-and-swap. It MUST be independent of the provider SQLite
file, WAL, filesystem snapshot, sidecar files and atomic backup set. A second
database on the same restore job is not independent. Suitable deployments
include a remote linearizable database with separately controlled backups, or
a hardware/managed monotonic service whose durability and disaster-recovery
contract has been tested. An in-process counter is not suitable.

The floor protocol contains no capability, spend key, invoice, payment hash,
client address, operation, peer-provider or PIR data. It nevertheless exposes
the public provider identity and the timing/rate of durable store mutations.
Two independent PIR providers therefore MUST NOT use one commonly observable
remote floor service unless that new cross-provider timing observer is
explicitly accepted in the threat model. Prefer provider-operated hardware or
separately administered authority instances/credentials. Replicas of the same
logical `provider_id` are already one trust domain and must share its one
linearizable floor. Authority logs follow the same minimization and retention
rules as other provider security telemetry.

`store_generation` advances on every security-relevant mutation: namespace
install, irreversible namespace close, capability spend, and signed
policy/epoch-floor advance. `spend_commit_seq` advances only on spends. The
rolling commitment binds each legitimate successor to its parent and mutation
digest, preventing two cloned stores from silently winning at the same
generation. It is a fork/restore lineage check, not a substitute for host and
database integrity controls against arbitrary privileged row editing.

Startup and mutation semantics are:

- **new store:** the operator chooses a fresh nonzero `store_instance_id`.
  `create` initializes generation zero in the external authority before
  creating SQLite. Initialization is idempotent only for that exact record.
  If filesystem creation then fails, the orphan generation-zero record is
  retained and an exact retry may finish creation; choosing another identity
  fails closed;
- **normal restart/current backup:** SQLite and the authority must match
  exactly. The server double-collects the authority around its SQLite read so a
  healthy concurrent writer is not mistaken for rollback;
- **lost external CAS response:** SQLite may be exactly one generation ahead.
  Reconciliation is allowed only when its recorded parent is the exact current
  authority commitment and its spend sequence did not decrease. One CAS makes
  this idempotent. The operation that lost the response never receives a grant;
- **stale restore:** SQLite below the authority floor is `RollbackDetected`.
  The server does not lower or overwrite the authority;
- **fork:** the same generation with a different commitment, more than one
  unanchored generation, a wrong parent, or a decreased spend sequence is
  rejected;
- **floor loss or outage:** a missing/unavailable authority fails closed. The
  floor is never reconstructed by trusting SQLite metadata;
- **identity mismatch:** one provider's authority record cannot be rebound to
  another `store_instance_id`, provider, or schema version;
- **multi-process concurrency:** `BEGIN IMMEDIATE` serializes the shared SQLite
  file, while the external CAS serializes cloned/forked copies. Replicas must
  share both the same SQLite authority and the same external record.

An old backup becomes intentionally unusable after the external floor advances.
Disaster recovery therefore needs a database backup at the exact currently
anchored generation (or a separately tested incremental/replicated spent
store). A signed backup manifest helps operators select the matching snapshot
but cannot reconstruct missing spend keys and cannot replace the authority.
If the only database backup is stale, safe recovery is to keep service stopped,
revoke/rotate every credential keyset whose spends may be missing, create a new
store identity and initialize a new authority record through an audited
operator ceremony. Production tooling must not expose a `--force-floor` or
"trust restored DB" switch.

Provider startup tests cover normal restart, checked current backup, stale
restore, same-generation fork, cloned-store CAS, lost CAS response, authority
outage/loss, wrong identity, and concurrent writers. Release testing must also
cover WAL recovery, checkpoint timing, corruption, read-only media, disk full,
interrupted migration, and the concrete production authority backend.

## Forbidden persistence and logs

Provider spent storage never contains invoice, payment hash/preimage, quote
ID, claim key, payer, route, raw capability, Cashu proof secret, DLEQ blinding
scalar, ARC presentation/tag, client IP, user agent, connection/session ID,
peer provider, Bitcoin address, PIR share, query result, or exact token time.

Issuer application storage never contains Bitcoin address, PIR share/result,
peer provider, claim private key, browser recovery secret, token unblinding
secret, raw BAT/ARC presentation, cleartext idempotency key, Lightning route,
or an explicit redeem-to-later-unblinded-note serial foreign key. Incoming
payment preimages stay in the Lightning node; the application ledger normally
needs only the payment hash for reconciliation.
