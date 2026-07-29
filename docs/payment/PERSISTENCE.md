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
active issuer hosts is not a consensus system. Two independent ProviderStore
database files MUST NOT be used as active/active replicas, even when both point
at the same external rollback-floor CAS. The fresh grant nonce makes an exact
mutation from two clones produce different successor commitments, so one CAS
wins and the other clone fails closed; that is clone fencing, not replication.
Multi-host active/active requires one reviewed linearizable detailed-state
store with linearizable unique constraints plus an explicit failover protocol.

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

Shared-issuer offers reuse this existing schema through a purpose-tagged
synthetic namespace (`scheme = 0x8001`). After exact canonical issuer-response,
signature, request, authorization and offer verification, the provider derives
a local delivery key with a provider-secret HMAC domain and inserts it into
`spent_capabilities`. The row is not the issuer credential nullifier or a
settlement record. It contains no wire idempotency key, invoice/payment hash,
token/raw credential, browser quote-claim key, or time. The issuer sees the wire
request but lacks the provider secret and cannot derive the stored local key.

The implemented provider schema version is `7`. Startup rejects every older
or unknown version, a missing required table, extra schema objects, or any
column drift; migration is an explicit offline operator action rather than an
automatic serve-mode side effect.

The shared-issuer local-delivery fix requires **no schema bump**: schema v7
already has the namespace and global spend tables needed for it. This is not
permission to reuse a pre-fix empty local-claim state with retained issuer
redeem history. The first production activation is a clean deployment. Any
exceptional recovery that preserves pre-fix ProviderStore or issuer history
must stop every old instance and rotate the provider shared-idempotency secret
or the clearing-authorization digest/epoch before serving. Binary operation is
forward-only after activation; a binary that can grant an issuer replay without
the local delivery claim must never reopen or serve the state.

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
draw a fresh nonzero 256-bit grant-transition nonce from the OS RNG
increment store_generation and extend the nonce-bound rolling commitment
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

Every transition which directly authorizes service work uses a fresh OS-random
256-bit nonce before the SQLite commit. Provider-local spends (including the
shared-issuer delivery claim), Free-IP quota consumption, and the final
standard-Cashu custody/grant transition all increment `spend_commit_seq`. RNG
failure rolls back the transaction and produces no grant. Two cloned files
starting from the same predecessor therefore propose different exact CAS
successors: at most one can anchor, and the loser is fail-closed rather than
accepted through a later transitive floor.

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
  rollback-floor CAS, with a fresh grant nonce and `spend_commit_seq` advance;
  restart never refreshes quota and a lower wall clock fails closed.
- `ProofOfWork`: one server-fresh, secure-channel-bound challenge is held in
  connection state and consumed once.
- `AnonymousTicket`: uses `spent_capabilities`.

### Standard Cashu merchant swap

The external mint's atomic NUT-03 invalidation is authoritative. A successful
swap MUST NOT be followed by a second provider-local authoritative spend
insert. The provider persists an encrypted recovery intent and, before issuing
the grant, a separately encrypted note-only custody lot. The final
custody/grant transaction is nevertheless a provider-local grant transition:
it draws a fresh 256-bit OS nonce, advances `spend_commit_seq`, and must anchor
before `AUTH_GRANTED`:

```sql
CREATE TABLE cashu_swap_intents (
    intent_id               BLOB NOT NULL PRIMARY KEY CHECK (
        length(intent_id) = 16 AND intent_id != zeroblob(16)
    ),
    mint_id                 BLOB NOT NULL CHECK (
        length(mint_id) = 32 AND mint_id != zeroblob(32)
    ),
    manifest_digest         BLOB NOT NULL CHECK (
        length(manifest_digest) = 32 AND manifest_digest != zeroblob(32)
    ),
    unit                    TEXT NOT NULL CHECK (length(unit) BETWEEN 1 AND 64),
    input_set_digest        BLOB NOT NULL CHECK (
        length(input_set_digest) = 32 AND input_set_digest != zeroblob(32)
    ),
    request_digest          BLOB NOT NULL CHECK (
        length(request_digest) = 32 AND request_digest != zeroblob(32)
    ),
    output_set_digest       BLOB NOT NULL CHECK (
        length(output_set_digest) = 32 AND output_set_digest != zeroblob(32)
    ),
    offer_binding_digest    BLOB NOT NULL CHECK (
        length(offer_binding_digest) = 32 AND offer_binding_digest != zeroblob(32)
    ),
    settlement_value        INTEGER NOT NULL CHECK (settlement_value > 0),
    expected_output_count   INTEGER NOT NULL CHECK (expected_output_count BETWEEN 1 AND 64),
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

CREATE TABLE cashu_custody_lots (
    lot_id               BLOB NOT NULL PRIMARY KEY CHECK (
        length(lot_id) = 16 AND lot_id != zeroblob(16)
    ),
    intent_id            BLOB NOT NULL UNIQUE CHECK (
        length(intent_id) = 16 AND intent_id != zeroblob(16)
    ),
    mint_id              BLOB NOT NULL CHECK (
        length(mint_id) = 32 AND mint_id != zeroblob(32)
    ),
    manifest_digest      BLOB NOT NULL CHECK (
        length(manifest_digest) = 32 AND manifest_digest != zeroblob(32)
    ),
    active_keyset_digest BLOB NOT NULL CHECK (
        length(active_keyset_digest) = 32 AND active_keyset_digest != zeroblob(32)
    ),
    note_set_digest      BLOB NOT NULL CHECK (
        length(note_set_digest) = 32 AND note_set_digest != zeroblob(32)
    ),
    unit                 TEXT NOT NULL CHECK (length(unit) BETWEEN 1 AND 64),
    settlement_value     INTEGER NOT NULL CHECK (settlement_value > 0),
    note_count           INTEGER NOT NULL CHECK (note_count BETWEEN 1 AND 64),
    state                INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    sealed_key_epoch     INTEGER NOT NULL CHECK (sealed_key_epoch > 0),
    sealed_nonce         BLOB NOT NULL CHECK (length(sealed_nonce) BETWEEN 1 AND 64),
    sealed_ciphertext    BLOB NOT NULL CHECK (
        length(sealed_ciphertext) BETWEEN 1 AND 262144
    ),
    FOREIGN KEY (intent_id) REFERENCES cashu_swap_intents(intent_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE cashu_custody_notes (
    note_fingerprint BLOB NOT NULL PRIMARY KEY CHECK (
        length(note_fingerprint) = 32 AND note_fingerprint != zeroblob(32)
    ),
    lot_id BLOB NOT NULL CHECK (
        length(lot_id) = 16 AND lot_id != zeroblob(16)
    ),
    FOREIGN KEY (lot_id) REFERENCES cashu_custody_lots(lot_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;
```

The recovery ciphertext contains the exact canonical NUT-03 request, ordered
blinded outputs, output secrets and blinding factors. The custody ciphertext
contains only the normalized mint endpoint, exact signed-manifest digest, its
one-or-two leaf-SPKI SHA-256 pins, unit, active keyset, provider-created
amount/secret/signature notes and their authenticated set digest. The endpoint
and pins are needed so later NUT-07/export operations retain the same
authenticated WebPKI-plus-pin trust boundary after policy rotation. It contains
no user input proof, NUT request/response JSON, offer/intent/query ID or exact
timestamp. Recovery and custody use distinct AEAD keyrings and AAD domains;
neither key is stored in this database. Proof secrets, `dleq.r`, note secrets
and wallet recovery material are never plaintext columns or logs. Custody
decoding is canonical and deny-unknown; older bundles that omit the manifest
digest or pins fail closed and require an explicit reviewed migration, never
ambient endpoint or certificate trust.

```text
PREPARED --externally anchored--> SUBMITTED -> WALLET_STORED -> GRANT_ISSUED
                                   |              ^
                                   -> ATTENTION --|
```

There is deliberately no `SUBMITTED -> PREPARED`, abandoned-unspent, or
resubmit transition. NUT-07 `UNSPENT` is only a point-in-time observation and
cannot prove that an ambiguous NUT-03 will not commit later. HTTP 400 plus a
canonical NUT-00 `{code, detail}` body is also ambiguous: the current
NUT-00/NUT-03 contract specifies the error envelope, not a non-commitment
proof. It therefore follows the same NUT-09/NUT-07-only recovery path and
cannot release exposure. The first exact
prepared recovery envelope wins; a replay with a fresh AEAD nonce returns the
existing envelope without a generation change. Changed request, output set,
offer binding, amount, intent ID, or `(mint_id, input_set_digest)` ownership is
a hard conflict.

Before inserting a new intent, the same `BEGIN IMMEDIATE` transaction sums all
pending intents plus available, reserved and delivery-acknowledged custody for
the exact `(mint_id, unit)`. It rejects any value or note count above the
explicit finite operator cap. The cap must be in `1..=i64::MAX`; no wildcard,
zero or unlimited default exists. Delivery acknowledgement remains inside that
cap. Only a terminal `SpentConfirmed` lot, backed by exact all-`SPENT` NUT-07
evidence, is excluded from local custody exposure.

Every actual state mutation advances `store_generation` and its independent
rollback-floor CAS. The caller may send NUT-03 only after the store returns
success for the anchored `PREPARED -> SUBMITTED` transition. Only
`WALLET_STORED -> GRANT_ISSUED` also advances `spend_commit_seq`; that same
transaction inserts the authenticated custody lot and globally unique
provider-local note fingerprints. Schema v7 is strictly opened without
implicit migration. The explicit v6-to-v7 replacement and validation ceremony
is in [`PROVIDER_STORE_V7_MIGRATION.md`](PROVIDER_STORE_V7_MIGRATION.md).

Grant occurs only after input invalidation, full output/signature/DLEQ
verification, and durable storage of the provider's received eCash. A lost
response uses NUT-09 with the identical blinded outputs.

### Standard Cashu custody export

The online server never emits note secrets. Offline `bpir-admin cashu-custody`
reserves available lots in one rollback-anchored transaction. Selection is
bounded by the requested lot count, 512 total notes and 16 distinct keyset
groups; candidates that would overflow a bound remain `Available`. The batch
stores the exact provider, mint, unit, requested maximum and recipient key ID.
Reusing an export ID with any different field is a conflict.

The store then persists one exact opaque recipient-sealed artifact before the
CLI may release it. The first artifact wins; identical retry returns the same
bytes, while a different artifact conflicts. The X25519+HKDF+
XChaCha20-Poly1305 envelope authenticates export ID, provider ID, recipient key
ID, ephemeral key, nonce and ciphertext length. It is bounded to 256 KiB and
contains one canonical no-memo/no-DLEQ `cashuB` token. Export recipient keys are
provider-specific and separate from online recovery/custody keys.

An explicit acknowledgement transitions the exact materialized batch and all
members together only after an operator asserts that the external wallet took
custody. It does **not** release local exposure and is not proof of NUT-05 melt,
Lightning settlement or provider payout. A lost response is recovered by
reading/releasing the immutable artifact and replaying the exact artifact
digest; reserved/materialized/acknowledged lots are never silently returned to
`Available`.

Exposure is released only by a later explicit owner-side `spent-confirm`. The
command decrypts the exact acknowledged lots, performs one bounded NUT-07
request for a same-mint/unit selection, and accepts only an exact ordered
all-`SPENT` response. Before each per-export transaction it reopens the current
rollback floor and rechecks immutable artifact, ordered member IDs, sealed-lot
binding and transient exact `Y` fingerprints. Durable evidence contains only a
domain-separated per-export observation digest and aggregate commitments; raw
`Y`, per-note state, witness and the wider HTTP-batch digest are not stored.
NUT-07 proves only that the old exported notes were spent. It does not prove
NUT-05, Lightning settlement or provider payout.

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
Quote/claim endpoint keys follow their own browser-generated lifecycle. Shared-
redeem wire idempotency is instead deterministically derived by each provider
as a provider-secret HMAC over the clearing-authorization digest, credential-
binding digest, and canonical credential digest. The issuer can replay the
exact stored response under that wire key but cannot derive the independent
provider-local delivery key.
Before checking current policy/authorization validity, every handler first
looks up an exact previously committed `(idempotency digest, request digest)`:

- same key and same digest: return the exact stored response bytes;
- same key and different digest: conflict;
- no row: validate current authority and create a new operation.

This ordering lets the issuer replay a committed response after key rotation or
expiry without authorizing new debt under stale authority, provided the client
can reproduce the exact original request and idempotency key. The shipped
provider runtime retains neither an old clearing authorization/approval nor the
old authenticated issuer tuple, so it cannot perform that recovery after its
single configured shared-issuer authorization has been replaced. Production V1
must drain and reconcile every outcome-unknown redeem before that rotation; the
issuer replay rule is not a rolling-rotation guarantee for providers.

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

The credential binding's signed `amount` describes credential denomination;
the clearing rule's `accepted_value` describes ledger settlement and must equal
`provider_credit + issuer_fee`. They are separate dimensions and are not
required to be numerically equal.

### Ledger and outbox

Posted ledger transactions are immutable, contain at least two postings in one
unit, and have `SUM(amount) = 0`. All protocol amounts are at most `i64::MAX`
before conversion to SQLite INTEGER. Business state and the corresponding
outbox row commit together. Workers lease outbox rows briefly; external
Lightning/backend operations use stable labels so at-least-once delivery still
creates one external side effect.

Real payouts remain disabled until separately authorized. Enabling an API type
or fake-backend test is not authorization to send funds.

`IssuerPayoutOutboxWorkerV1` is implemented as a fail-closed, no-funds worker
core. It durably signs and commits `Accepted -> InFlight` before calling an
external executor, and every later claim of `InFlight` performs reconciliation
only. The stable command ID is the required executor idempotency identity.
The configured external-call timeout is nonzero and strictly shorter than the
durable lease. Each executor invocation receives an absolute deadline derived
from that committed lease and strictly earlier than `lease_until`; timeout or
cancellation is always `OutcomeUnknown`. `payout_target_id` is not a raw
provider identity, but it is a stable payout-routing pseudonym which lets the
issuer/executor link payouts to the same target and therefore must not be
logged. Worker progress `Debug` output omits payout IDs.
`NoFundsPayoutExecutorV1` is the shipped default and is never ready, so it reads,
claims and mutates no outbox state and cannot move value. No real-funds executor
is implemented or enabled. A future adapter must provide a linearizable durable
command-ID lookup/submission operation or equivalent authoritative no-submit
fence; a process lease plus issuer SQLite cannot manufacture external
exactly-once behavior across a crash.

## Provider settlement payout workflow

Ledger-only balance reads do not create provider payout state.
`ProviderLedgerBalanceClientV1` authenticates with the operator-authorized
clearing key and verifies the exact issuer-signed response against the current
or explicitly retained settlement key. Every send rechecks the authorization
and approval against the caller's current Unix time before transport. It
requires no registration digest,
payout target, provider-request secret, detailed payout SQLite, or payout floor.
Issuer production startup nevertheless registers a distinct provider-request
public key for every authorization. Reusing the clearing key for that column is
rejected: it would make the stored registration unusable by the full settlement
client and collapse the redemption versus payout-recovery signature domains.

`pir-provider-clearing-client` includes a concrete
`SqliteProviderSettlementStateStoreV1` for the provider's exact payout workflow.
It persists the canonical intent request/response, payout request, initial and
latest status responses, origin registration, idempotency key, pending status
request and terminal predecessor history. Every loaded record remains
untrusted until the provider client revalidates its canonical encoding,
signatures, current/retained registration and issuer-key lineage. The store
contains no invoice, payment hash/preimage, payer, Lightning route, PIR query,
peer provider or query result.

The detailed store takes a separately supplied
`ProviderSettlementFloorAuthorityV1`. Its authority value is exactly one of:

```text
Pending(provider, pending_digest, payout_request_digest, predecessor_floor,
        history_length, history_commitment)
Payout(provider, payout state floor, origin_pending_digest,
       history_length, history_commitment)
```

The initial pending value requires no predecessor and empty history. A later
pending value must name the exact current terminal payout as its predecessor.
Pending-to-payout advancement requires the same payout-request digest and an
`Accepted` state at version 1; a status transition is the only route to later
monotonic versions. These fields are explicit authority state rather than facts
hidden only behind the opaque pending commitment.

The history commitment starts from a provider-domain-separated empty anchor and
extends over each archived terminal payout plus its exact origin-pending digest.
The terminal-to-pending floor transition must advance that chain by exactly one;
status transitions must preserve it. Selectively deleting history and rewriting
the detailed current-origin record therefore no longer remains aligned with the
external floor. This protects audit-chain completeness only while the floor is
in a genuinely independent rollback domain; co-restoring the bundled local
SQLite floor still defeats the boundary.

SQLite cannot atomically commit against a genuinely independent authority. The
detailed adapter therefore journals each exact transition before advancing the
authority, then finalizes its local row only after the authority returns the
expected successor. **Startup and ordinary load never reconcile a journal or
advance the authority.** A checked open accepts an unresolved journal only when
the authority is still its exact predecessor or already its exact successor;
ordinary recovery load then returns `recovery required`. The operator must
inspect the exact journal, have `ProviderSettlementClientV1` revalidate every
current/retained registration and issuer key, canonical request/response,
signature, binding and monotonic transition, and pass the resulting opaque
recovery capability back to the store. The store rereads the exact snapshot
digest before authority CAS and again before local finalization. A stale or
hand-built token cannot mutate the authority. Any other floor, a missing exact
record, invalid commitment, provider/store-instance mismatch, malformed record,
schema drift or non-contiguous terminal history fails closed. The adapter never
reconstructs or lowers the authority from detailed SQLite state.

Provider-settlement schema v2 and record magics are a fail-closed boundary, not
an implicit migration. The compact `BPF2` authority value binds a random
nonzero 128-bit `store_instance_id`, provider, strictly increasing transition
revision, exact active-workflow commitment, exact raw-history rolling
commitment, and one of `Pending`, `Payout` or `StatusPending`. Pending status
also records the exact predecessor-state commitment; a status-commit journal
retains the exact predecessor durable bytes until finalization so recovery can
prove that the signed successor answers that exact request and nonce. Old
schema/magic data must be handled by an explicit reviewed migration or clean
initialization ceremony; v2 does not reinterpret it.

Both SQLite files require an effective-user-owned mode-`0600`, single-link
regular final file inside an effective-user-owned, exact mode-`0700` parent.
Every path component is opened relative to the previously pinned directory
descriptor with `O_NOFOLLOW`; an intermediate or final symlink is rejected.
Every ancestor must be root- or effective-user-owned and not group/world
writable. The only writable ancestor exception is a root-owned sticky public
directory such as the platform `/tmp`. On macOS, an ancestor ACL that grants an
`allow` right is rejected, and the final private parent and database must have
no extended ACL at all. Linux V1 enforces DAC owner/mode rules only and must not
be represented as a POSIX/NFSv4/FUSE ACL audit.

SQLite reopens a pathname internally, so each adapter validates the main-file
device/inode immediately before and after `sqlite3_open_v2` (with
`SQLITE_OPEN_NOFOLLOW`) and fails closed if the identity changed. The private
parent is the confidentiality and namespace-integrity boundary for SQLite's
`-wal` and `-shm` sidecars. Sidecars must remain in that directory, under the
same OS account and backup access policy; never publish, relocate, hard-link or
independently restore them. A live database backup must use SQLite's online
backup API or a reviewed checkpoint-and-quiesce procedure. Copying only a live
main file is not a valid backup, and copying main/WAL/SHM at different points in
time is not an atomic backup set. The rollback authority remains outside this
entire database/sidecar backup and restore domain.

`LocalTestSqliteProviderSettlementFloorV1` is intentionally named and exported
only as a local-development, test and recovery-drill implementation. A second
SQLite file—even at a different path—is **not** a production independent
rollback authority. Co-snapshotting or restoring the detailed and floor files
can restore a stale, mutually consistent pair. Production payout activation
still requires a reviewed linearizable implementation in an independent
administrative, failure, backup and restore domain, plus a reviewed real-funds
executor and an authorized payout backend deployment. The existing no-funds
worker core is not that executor.

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
contract has been tested. The implemented authenticated remote-authority
protocol and shared WebPKI-plus-leaf-SPKI-pinned loader provide that transport
boundary. The authority sees a namespace/client binding, opaque fixed-format
record revision and operation timing, not the provider floor plaintext.
Provider/issuer processes never fall back to a local floor when remote
configuration, TLS, signature, AEAD, freshness or CAS reconciliation fails. An
in-process counter is not suitable, and a production deployment plus
restore/failover acceptance drill remain separate release gates.

### Production remote-authority topology (implemented, not deployed)

The strict two-provider default requires separately operated authority
instances for provider 0, provider 1 and their independently selected issuers,
without one service pooling their observations.
“Instance” here means an independently authenticated endpoint or hardware
boundary with separate credentials, administration, security logs, monitoring,
backup/restore policy and failure budget—not merely per-tenant namespace rows
in one shared database. Provider admission state, issuer quote/ledger state and
provider settlement-payout state each use their own typed floor value; one
generic client must never let an operator cross-read or cross-CAS those
namespaces.

The remote protocol exposes only opaque bounded Read/initialize/CAS operations.
Every request is client-signed, every response is authority-signed, and the
transport requires ordinary WebPKI plus an out-of-band leaf-SPKI pin, absolute
deadlines and no list/scan API. Namespace IDs and credentials are provisioned
independently for each logical provider/issuer. The authority must not receive
capabilities, invoices, payment hashes/preimages, payer/IP data, peer-provider
identity, scopes, query addresses, PIR requests or results. Even this minimized
API reveals its authenticated client-key/namespace tenant plus mutation timing
and rate; the operator may know which service that tenant represents.

One common authority service for both PIR legs would therefore add a cross-leg
timing observer and shared availability/administrative boundary. It weakens the
default non-collusion topology even if access control prevents one tenant from
reading another's values. Such a deployment requires an explicit threat-model
exception; it is not the strict default. The repository ships the server,
client and typed adapters, but they are not yet a reviewed/accepted production
deployment; local SQLite floors must not be relabelled as one.

The floor protocol contains no capability, spend key, invoice, payment hash,
client address, operation, peer-provider or PIR data. The provider/issuer ID is
inside the client-sealed opaque value rather than a wire field. It nevertheless
exposes an authenticated namespace/client-key tenant and the timing/rate of
durable store mutations; its network edge can also observe the connecting
provider/issuer host address unless separately hidden.
Two independent PIR providers therefore MUST NOT use one commonly observable
remote floor service unless that new cross-provider timing observer is
explicitly accepted in the threat model. Prefer provider-operated hardware or
separately administered authority instances/credentials. Replicas of the same
logical `provider_id` are already one trust domain and must share its one
linearizable floor. Authority logs follow the same minimization and retention
rules as other provider security telemetry.

`store_generation` advances on every security-relevant mutation: namespace
install, irreversible namespace close, capability spend, and signed
policy/epoch-floor advance. `spend_commit_seq` advances on provider-local
spends, Free-IP admissions and the final standard-Cashu custody/grant
transition. Every grant-producing transition additionally binds a fresh
nonzero 256-bit OS nonce into its successor commitment. The rolling commitment
binds each legitimate successor to its parent and mutation digest, preventing
two cloned stores from silently winning at the same generation. It is a
fork/restore lineage check, not a substitute for host and database integrity
controls against arbitrary privileged row editing.

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
- **multi-process concurrency:** `BEGIN IMMEDIATE` serializes one shared local
  SQLite file. If two cloned files race the same logical grant, the fresh nonces
  make their successor commitments different; the external CAS accepts exactly
  one and the loser fails closed. Independent database-file active/active is
  prohibited and this fencing behavior must not be advertised as HA. A future
  replica design must share one reviewed linearizable detailed-state store and
  one external floor record.

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
ID, browser quote-claim private key, payer, route, raw capability, Cashu proof
secret, DLEQ blinding scalar, ARC presentation/tag, client IP, user agent,
connection/session ID, peer provider, Bitcoin address, PIR share, query result,
or exact token time. It may contain only the independent provider-secret HMAC
delivery key for an exact verified shared-issuer success, in the same minimal
`spent_capabilities(namespace_id, spend_key)` shape as other local claims.

Issuer application storage never contains Bitcoin address, PIR share/result,
peer provider, browser quote-claim private key, provider-local delivery key,
browser recovery secret, token unblinding secret, raw BAT/ARC presentation,
cleartext idempotency key, Lightning route, or an explicit redeem-to-later-
unblinded-note serial foreign key. Incoming
payment preimages stay in the Lightning node; the application ledger normally
needs only the payment hash for reconciliation.
