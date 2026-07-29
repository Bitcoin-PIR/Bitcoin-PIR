# Payment v1 operator runbook

Status: pre-production operating contract. No production deployment, public
relay publication, external mint access or real Lightning operation has been
performed under this plan.

## 1. Choose the topology before choosing prices

Pricing and commercial policy belong in signed offers. Cryptographic and
operational boundaries must be selected separately.

For each logical provider, record:

- one `provider_id`, operator trust anchor and independently operated server;
- the backends/workloads it serves: DPF, Harmony hint, Harmony query, Onion,
  TEE-ORAM;
- one or more signed scopes and entitlement profiles that reflect actual cost;
- accepted acquisition/verification methods;
- provider-local keys and ProviderStore/rollback-authority locations;
- optional issuer/mint/clearing dependencies and their declared privacy mode.

Harmony hint and Harmony query must be separate scopes/offers. A hint provider
may charge more than a query provider. Do not reuse one capability across those
roles.

For Harmony V2Full, one `unified_server` process serves one cold-cache database
binding. Start its pool with `--pool-size N --pool-db-id ID`; omitted
`--pool-db-id` means the existing `db_id=0` behavior. The ID must exist in the
loaded catalog or startup fails. Use a distinct process/port and a distinct
`--pool-dir` for each additional delta database, and publish only the scope
whose exact dataset binding that process can serve. First-version deployment
does not share or multiplex one hint pool across database IDs.

### Harmony V2Full pool filesystem and upgrade contract

The pool directory is a private, single-database state domain, not a cache that
may be shared arbitrarily between releases. The current binary creates and
checks `.hmpool-binding-v1`, which binds the directory to the exact immutable
database/backend/geometry. A missing marker is accepted only for a completely
empty first-use directory at the operating layer; code accepts only a directory
empty of recognized pool/generation state (aside from its private capacity
lock). A mismatch, corrupt marker, markerless ready/generation state, or exact
legacy `.hints.tmp`/`.hints.consumed` residue fails startup and preserves the
artifacts for offline inspection. With a valid matching marker, an older
`.hints.reserved.*` artifact is conservatively recovered under its inode lock.

The first upgrade from any binary that predates this marker/lock protocol must
use this sequence:

1. remove the provider from discovery/traffic and wait for every old process
   and child to exit; do not perform a live or rolling mixed-version upgrade;
2. preserve the old pool directory for rollback/forensics and configure the new
   binary with a newly created, empty, mode-0700 `--pool-dir` on the same host;
3. let the new binary create its own marker and entries; never hand-create,
   copy or edit the marker;
4. if binary rollback is required, stop every new process and point the old
   binary at its preserved old directory or another empty directory. Never
   point an old binary at a marker-bound new directory.

Only a protected local POSIX filesystem with coherent advisory locks, atomic
same-filesystem rename/hardlink and durable file/directory `fsync` semantics is
supported. NFS, FUSE and shared network filesystems are outside the operating
contract. Do not delete, replace, chmod or move the pool directory, capacity
lock, binding marker or ready files while any provider process is live. The
database files underlying a live mmap are immutable for the complete process
lifetime: activate a new checkpoint by atomic namespace replacement and a
process restart, never by in-place write or truncate. Any database fingerprint,
PRP backend or geometry change also requires draining the old process and
starting the new binding with a different fresh empty private pool directory;
preserve the prior directory only for rollback with its exact prior binding.

Credential checking holds an exclusive advisory lock on the selected ready
inode but deliberately performs no rename or directory write. Rejection,
deadline, lost grant or disconnect before the first V2Full main dispatch drops
the lock and returns the unexposed entry. The first main dispatch unlinks and
directory-fsyncs the exact inode before exposing its PRP key; any identity,
unlink or durability error fails closed and sends no key. Graceful shutdown
joins an in-progress generator and can therefore wait for an expensive
generation or filesystem operation. Supervision must first allow an
environment-sized drain deadline and then use a bounded final termination;
after a forced stop, the next current-version startup performs conservative
reconciliation before serving.

For online-authority V2Full, the cross-process ready-entry floor is deliberately
conservative. It counts only paths in the current process's fully validated,
ready `PoolState` snapshot that are lockable during the atomic decision. Do not
interpret an extra `pool_*.hints` filename on disk as usable headroom: a corrupt,
stale, peer-created-but-not-yet-validated or otherwise untrusted path does not
satisfy the floor. Capacity-lock contention fails the hot reservation attempt
immediately rather than blocking a Tokio worker. If a peer process owns the
selected inode lock, the implementation rotates that queue head and examines
the remaining bounded snapshot, so one locked name does not hide a later usable
candidate.

The floor means only that one successful online reservation cannot consume the
last validated, currently lockable entry at that instant. It does not dedicate
that entry to a provider-local request, order callers fairly, or promise
immediate admission: another local caller, process, filesystem race or global
AUTH saturation can still win or cause `ServerBusy`. Provision real headroom
and enforce source-aware admission; do not advertise this mechanism as a paid
priority or fairness guarantee.

The browser chooses provider 0 and provider 1 independently and may discover
the second after completing the first. No configuration, invoice, capability,
log or directory event may introduce a pair ID or peer-provider field.

### Strict-pair default

The default strict profile must use independent issuers or provider-local /
offline-verifiable methods for the two legs. It must not route both providers'
synchronous redemption through one shared online issuer. A shared issuer sees
authenticated provider, scope and redemption timing and can correlate the two
streams through timing/network metadata even when the credentials differ.

If a user deliberately selects two offers backed by the same shared issuer,
surface that common-infrastructure risk before acquisition. Never claim that
blind issuance makes the shared issuer invisible.

Different provider IDs, keys, issuer IDs and domains are necessary hygiene,
not proof of different owners. Until independently sourced operator diversity
or a reviewed signed operator-group/governance assertion is available, the UI
and directory must describe strict-pair checks as visible-correlation checks,
not a cryptographic proof of non-collusion.

## 2. Key and state separation

Use distinct keys for:

- operator/server identity;
- service-policy signing per provider;
- directory Nostr signing;
- issuer root and online quote delegation;
- Lightning node custody;
- direct receipt signing;
- BAT raw DHKE keys (different raw keys for the two providers);
- experimental ARC keys;
- provider clearing authentication;
- per-provider shared-redeem idempotency HMAC secret; never reuse it between
  provider 0 and provider 1 or disclose it to the issuer;
- issuer settlement and payout signing;
- browser/provider recovery encryption;
- standard-Cashu recovery AEAD, received-note custody AEAD and offline export
  recipient keys, all distinct per provider.

Generate supported role-labelled keys with:

```sh
cargo run --offline -p bpir-admin -- service-keygen --help
```

The command intentionally does not generate every issuer/delegation/ARC
artifact. Missing ceremony tooling is not permission to reuse a key from a
different role.

Without `--force`, secret creation is enforced by an atomic no-replace rename;
a concurrent generator cannot truncate the winner's new key. Role-labelled
service keys, admin keys and identity keys require an effective-user-owned
mode-0700 parent. Missing parent components are opened/created one component at
a time without following symlinks; every newly created directory entry is
synced through its containing directory before key generation continues.
The CLI never chmods an existing parent automatically. Before upgrading an
older installation whose secret parent is mode 0755, the operator must inspect
the exact directory owner, contents, links and ACL policy, move unrelated
material if necessary, and only then explicitly change that reviewed directory
to mode 0700. Treat an unexplained ownership, link or ACL mismatch as an
incident, not as a permission-repair opportunity for keygen.
`--force` is an explicit destructive
key-rotation action: it still rejects symlinks, hard-linked files, non-regular
files and files owned by another user, writes and syncs a same-directory
mode-0600 temporary through one pinned directory descriptor, revalidates the
old target, then atomically replaces the prior inode and syncs that descriptor.
The production CLI supports secret generation only on Linux and macOS and
fails closed elsewhere. Never run two force
rotations against one path, and never treat the atomic replacement as a
substitute for a tested backup and public-key rotation record. If the final
directory sync fails after rename, the CLI reports committed-but-durability-
unknown, still prints the new public identity, and explicitly forbids retrying
`--force`; inspect and preserve the exact installed target instead. The command
returns dedicated non-zero exit code `2` only after printing the public identity.
Automation must treat both that exit code and the stable stderr marker
`secret_write_status=committed_durability_unknown` as requiring operator
reconciliation; it must not retry the already-committed rotation.
The stronger `secret_write_status=committed_path_unknown` marker means a
post-commit check could no longer prove that the requested pathname names the
new inode; stop and reconcile the pinned directory inode, target and printed
public identity without retrying rotation.
Keygen explicitly unlocks its pinned parent descriptor before returning, so a
descriptor inherited by a concurrently forked process cannot retain the
advisory lock until that process execs or exits. If a committed write cannot
confirm that unlock, the command still prints the new public identity and exits
`2`; a lock-only incident uses
`secret_write_status=committed_lock_release_unknown`. When path or durability
is already unknown, that primary marker remains authoritative. In every
committed case with an unlock failure, the additional stable marker
`secret_write_lock_release_status=unknown` is emitted. Do not retry; preserve
the printed identity, inspect the exact target, determine whether any duplicated
or inherited descriptor still holds the parent directory open, and diagnose the
unlock error. A pre-commit operation failure remains the primary error and
appends the lock-release failure as secondary diagnostic text.

On macOS, the CLI rejects any extended ACL on a secret parent or an existing
secret. It also clears and re-reads the temporary file's extended ACL before
writing the first secret byte, because an inherited ACL is independent of mode
0600. The component walker recognizes only the three macOS root-owned,
single-link, byte-exact platform aliases `/var -> private/var`, `/tmp ->
private/tmp`, and `/etc -> private/etc`; it restarts at the corresponding
`/private/...` path and still uses `O_NOFOLLOW` for every remaining component.
This is not permission to use or follow any other intermediate symlink.
Linux currently enforces the documented UID/mode DAC contract but does
not enumerate POSIX, NFSv4 or FUSE ACLs. Generate production keys only on an
operator-controlled local filesystem with no default/inherited ACL policy;
Linux mode checks must not be described as a general ACL audit. Same-UID
processes remain inside the operator trust boundary.

A host crash after syncing the private temporary but before its namespace
commit can leave an owner-only
`.bpir-secret-rotation-<32-lower-hex>.tmp` file in the same directory. Keygen
never guesses whether such a file is the intended identity and never deletes it
automatically. Quarantine any residue as live secret material, verify the active
target and recorded public identity first, then use the host's approved
secret-destruction procedure; do not feed the residue into an unreviewed retry.

Secrets must be regular, non-symlink files with restrictive ownership/mode.
Do not put secrets in command output, shell history, environment dumps,
container images, CI artifacts or directory events.

## 3. Persistence and backup domains

Every logical provider has its own ProviderStore. Independent providers must
not share the database, WAL, spent set or remote spend service. Replicas sharing
one `provider_id` and keysets are one logical provider and need one linearizable
spend authority. Payment V1 does not support independent ProviderStore
databases as active/active replicas. A common external rollback-floor CAS can
fence an exact cloned-state race to one winner, but it is not detailed-state
replication and does not make the losing database safe to serve.

The provider/issuer SQLite database and its rollback-floor authority must be in
**independent backup and restore domains**. Merely using two filenames on one
disk or including both in one VM/filesystem snapshot defeats the purpose: an
attacker/operator could restore a stale but mutually consistent pair.

Each SQLite file contains sensitive correlation state (issuer invoices and
payment hashes; provider spends, quota clocks and timing state). On Unix, put
each database in an effective-user-owned exact mode-0700 directory and keep the
main database a single-link regular file with exact mode 0600. Each ancestor is
opened component by component with `O_NOFOLLOW`; it must be root- or
effective-user-owned and not group/world writable, except for a root-owned
sticky public directory such as `/tmp`. Startup also rejects non-regular final
objects, wrong owners, hard links, store/authority inode aliases, and a main
file whose identity changes across SQLite's internal reopen. On macOS, an
ancestor ACL that grants an `allow` right is rejected and neither the final
parent nor database may have any extended ACL. Linux V1 is explicitly DAC-only
and does not audit POSIX, NFSv4 or FUSE ACLs.

The private parent is the protection and namespace-integrity boundary for
SQLite's runtime `-wal` and `-shm` sidecars. Keep main/WAL/SHM under the same OS
account and backup access policy; do not chmod them public, move or hard-link a
sidecar into another directory, or restore one member independently. Back up a
live database through SQLite's online backup API or a reviewed
checkpoint-and-quiesce procedure. Copying only a live main file, or copying the
three files at unrelated instants, is not a valid atomic backup. Never include
the rollback authority in the database/sidecar snapshot or restore domain.

Before activation, document and test:

- who can restore the database and who can advance/restore the authority;
- independent backup media/account/credential paths;
- WAL checkpoint, filesystem sync and directory sync procedure;
- generation/commitment comparison after restart and restore;
- monitoring for missing, lower, forked or unanchored state;
- fail-closed recovery when either side is unavailable.

Do not run SQLite WAL over NFS or treat two active SQLite hosts as a consensus
system. Independent-database multi-host active/active is prohibited in V1. A
future design would require a separately reviewed linearizable detailed store,
replication/failover protocol and privacy analysis, not only a shared floor.

## 4. Build and verify signed configuration

Create and verify provider policies offline:

```sh
cargo run --offline -p bpir-admin -- service-policy sign --help
cargo run --offline -p bpir-admin -- service-policy verify --help
```

For every offer, verify that the signed binding contains the expected provider,
backend/workload, dataset rule, operation profile, entitlement limits, method,
issuer/keyset epoch, expiry/grace and privacy/availability declaration. Client
amount, quota, priority and profile fields are never authoritative.

Policy/key rotation rules:

- epochs increase monotonically; same-epoch forks fail closed;
- paid quote/receipt/key grace covers the full advertised claim/use horizon;
- retained quote, receipt, BAT/ARC and settlement keys are loaded only for
  their declared recovery window;
- rollback never means re-serving an older signed epoch. Issue a new higher
  epoch that disables or changes an offer.

For the issuer, `--quote-delegation`/`--quote-signing-key` are the one explicit
current quote material. Every `--retained-quote-material` is recovery-only: it
may sign an exact idempotent continuation of a durable quote, but it can never
reserve a fresh quote, including after restart when the durable delegation head
has not yet advanced. Keep each retained signer through every still-active
quote's immutable recovery/claim horizon. Startup fails closed if one is
missing; after all such horizons pass it may be removed without deleting quote
history. Never make an old epoch current to perform rollback—deploy a newly
signed higher epoch instead.

Retained quote material must remain under the same issuer root and bind the
same Lightning network and payee as the current issuer instance. Consequently,
an issuer-root rotation or Lightning node identity/payee rotation cannot
recover old quotes in place under the new audience. Keep the old root and node
available until every old recovery/claim horizon has drained, or run a parallel
old recovery instance with its original immutable root/network/payee boundary.
Never weaken delegation, network or payee checks to make an old quote fit a new
instance.

When already-issued credentials must survive a policy rotation, keep each
canonical old policy in an immutable operator-controlled file and repeat:

```text
--service-retained-policy /absolute/path/to/old-policy.bin
```

The current policy still uses the single `--service-policy` path. Startup
fails closed if a retained file is non-canonical, signed for another provider
or key, current/newer, duplicate by digest, missing a configured redemption
adapter, not backed by the local workload/catalog, or missing its exact durable
provider-local spend namespace. A retained file does not reopen a closed
namespace and never enables quote, Free, or PoW acquisition. Keep it only
through the longest signed credential/grace horizon, then remove the flag in a
reviewed configuration rollout. Restarting with the same current and retained
files is idempotent; retain the old receipt/BAT/ARC verification keys for the
same horizon.

V1 has one trusted service-policy verifying key per provider process. That key
**must remain stable for every retained credential grace period**. Rotating the
service-policy signing key while old credentials still need redemption is not
supported: startup intentionally rejects old policies under any other key.
Do not add an unauthenticated old-key list. Delay the policy-key rotation until
all old grace windows end (while rotating credential keys inside signed policy
as needed), or publish a deliberately reviewed future protocol version with an
authenticated policy-key succession proof.

V1 also loads only one shared-issuer clearing authorization per provider.
Create it with the offline provider-operator builder, transfer its printed
digest independently, and have the issuer run the separate approval builder.
Provision a fourth, raw provider-request public key in the same list position;
it must differ from clearing, operator and issuer-settlement keys. Ledger-only
balance reads use the clearing key and need no payout registration, but the
issuer still persists the distinct request key so a future payout/status
workflow cannot inherit collapsed signature domains. Rotation requires a
strictly higher authorization epoch and a new issuer approval; retain an old
issuer settlement public key only for exact historical recovery.

Certificate-key rotation at the same issuer origin must use a newly
operator-signed and issuer-approved two-pin overlap, followed by removal of the
old pin in a later higher authorization epoch. Do not change the signed issuer
origin while a current or retained policy still references the old origin:
the exact endpoint check will make those capabilities fail closed. Keep the old
origin serving through the longest redemption-grace horizon, or wait for a
future multi-authorization migration protocol.

Standard-Cashu custody records retain the exact manifest digest and pin set
that authorized each swap. Before a planned mint leaf-key rotation, publish a
signed two-pin manifest while the old key is still served, then export, spend
and NUT-07-retire every older single-pin lot. An emergency key replacement can
leave those old lots safely uncheckable; do not graft the new pin onto them or
use an unpinned client. Freeze exposure and perform explicit incident
reconciliation until an authenticated custody-migration protocol exists.

Build and self-verify directory artifacts offline, then inspect the explicit
publisher help separately:

```sh
cargo run --offline -p bpir-admin -- directory-artifact --help
cargo run --offline -p bpir-admin -- directory-artifact publish --help
```

Only `directory-artifact publish` opens a relay connection. It reads no signing
key: freeze and review the already-signed entry/checkpoint files, pin the
expected directory public key, and select two through eight credential-free
public `wss://` relay hostnames. Distinct hostnames are not evidence of distinct
operators or infrastructure; audit that independently.

Before the approved publication window, run the intended `publish` invocation
with `--validate-only`. A successful validation performs no DNS or network I/O
and reports `result=validated` for the frozen artifact set and relay hostnames.
Record its event-set digest, then remove only `--validate-only` when publication
is explicitly authorized; any other input change requires a fresh review.

The publisher sends every exact EVENT to every relay, requires one positive
matching NIP-01 OK per event, and uses a bounded total timeout for each relay.
It attempts all relays but exits nonzero on partial success. Preserve the exact
artifacts and rerun them manually after resolving the failed relay; never
advance the external per-`d` timestamp/sequence ledger based on a partial run.
There is no automatic retry, proxy, redirect, relay AUTH, or signing fallback.
Normal output contains only relay hostname, event count and result code.

## 5. Bootstrap stores

Issuer store creation is explicit:

```sh
cargo run --offline -p payment-issuer -- init-store --help
cargo run --offline -p payment-issuer -- check-store --help
```

`init-store` canonicalizes each parent before creation, refuses overwrite and
same-target aliases, requires/creates private parent directories, sets both
files to 0600, and reopens the exact generation-zero store and authority before
reporting success. If any post-creation step fails, the command deliberately
does not delete or reuse either path: inspect both, then manually remove only
files proven to belong to that failed ceremony.

`check-store` runs the production full-history open and rollback-floor path
without starting a listener, then reports aggregate row counts and
`startup_check_ms`. It can complete the one-successor lost-CAS reconciliation
allowed at real startup, so run it only against the intended isolated restore
candidate or during a quiesced startup ceremony.

Provider serving likewise opens an already-created schema-v7 store and exactly
one rollback boundary. Production supplies
`--service-remote-rollback-authority-config`; the shared loader requires
WebPKI plus an out-of-band leaf-SPKI pin and exact authority/client/namespace
keys. The local `--service-rollback-authority` SQLite compatibility path is
development/test-only and serving refuses it without the explicit
`--allow-local-service-rollback-authority-dev` acknowledgement. It never falls
back between the two modes. Create new state with `bpir-admin
service-store-init`; remote initialization requires a preserved explicit
store-instance ID so an ambiguous first CAS can be audited and resumed under
the same ID/config rather than reset. Use the explicit offline replacement
procedure for any v6 candidate rather than improvising an in-place SQLite edit.
See `PROVIDER_STORE_V7_MIGRATION.md` and
`REMOTE_ROLLBACK_AUTHORITY.toml.example`.

The shared-redeem local delivery claim also uses schema v7; do not run a schema
migration for it. First production activation is a clean, forward-only binary
and store ceremony. If any older ProviderStore or issuer redeem-history database
may contain an exact issuer replay without matching local-delivery claims, stop
**all** old issuer/provider instances first. Before serving again, rotate either
the per-provider shared-redeem idempotency secret or the clearing authorization
digest/epoch. Never attach an empty synthetic local-claim namespace to the old
exact issuer replay history: that would make an old signed success deliverable
again.

For every standard-Cashu mint/unit in a current or retained policy, configure
one exact finite value/note exposure cap plus distinct recovery and custody
keyrings. Run `bpir-admin cashu-custody inventory` before activation and
rehearse provider-bound recipient key generation, bounded export, exact replay,
offline decrypt and external-custody-only acknowledgement with disposable
notes. Never acknowledge before a wallet has durably taken custody. ACK remains
inside the configured exposure cap. Rehearse the separate explicit
`cashu-custody spent-confirm` operation against those disposable notes: it must
use one strict-HTTPS NUT-07 request for each selected identical
endpoint/pin/manifest/unit cohort,
accept only exact all-`SPENT`, refresh the rollback floor before each export
commit, stop without automatic retry on partial failure, and make an exact
terminal replay without keys or another mint request. Treat this only as proof
that the old notes were spent, never as NUT-05, Lightning settlement or payout.

Back up store identities, public configuration and recovery procedure without
putting invoice, payment hash/preimage, bearer capability, proof secret,
blinding scalar or query data into operator records.

## 6. Pre-activation checks

Run `LOCAL_ACCEPTANCE.md` first. Then require all of the following before any
public/staging listener:

1. put the loopback-only `payment-issuer serve-cln` behind a separately managed
   TLS edge; retain the built-in process-wide quote/status/mutation/
   reconciliation rates, durable active-quote capacity and connection/body/time
   bounds, then add per-source/distributed budgets, bounded edge queues,
   overload responses, metrics and alerting;
   verify the exact candidate binary rejects `serve-fake` as an unknown
   subcommand. Any binary built with `test-only-fake-lightning` is a local test
   artifact and is forbidden from staging or production activation;
2. validate the implemented global connection/auth semaphores,
   handshake/idle timeouts, the enforced-mode absolute pre-authorization
   deadline (`--service-pre-auth-timeout-ms`, which Ping cannot extend and
   which covers all pre-grant writes/flushes and is rechecked after every
   potentially blocking authorization commit), and size each external
   operation timeout well below it. A provider-store
   authorization can perform more than one remote-authority operation, so no
   per-call timeout comparison replaces the post-commit deadline gate. If an
   in-flight commit finishes after expiry, the server closes without a grant
   response or PIR work. If it finishes before expiry, the result write+flush
   still has only the remaining fixed budget, and ordinary idle handling starts
   only after successful grant delivery (subject to the separate pending-V2Full
   dispatch deadline below). The server does not cancel the commit,
   refund, or resurrect a possibly consumed capability. Then validate the 512
   KiB frame/message cap,
   and 16 MiB per-request / 64 MiB process-wide
   reassembly caps under load; verify the independent fixed per-connection
   preflight budget (32 encoded WebSocket messages and 16 MiB, with atomic
   chunk-group reservation), then add separate reverse-proxy/edge tree-top
   frequency, bandwidth and aggregate egress protection;
   separately load-test the scarce Harmony V2Full reservation path. A
   structurally canonical Standard Cashu/shared-issuer presentation is not
   authoritative until its bounded online check completes, so an attacker can
   temporarily lock up to the authorization-concurrency limit of ready entries
   without consuming them. The dedicated
   `--service-max-concurrent-online-v2full-auth` sub-limit defaults to the
   smaller of 8, `pool-size - 1`, and `service-max-concurrent-auth - 1`; an
   explicit value must also leave both kinds of headroom, and zero disables
   online-authority V2Full offers while retaining provider-local methods. The
   runtime acquires this narrower permit before the global AUTH permit and holds
   it after grant until dispatch/drop. The 30-second-or-shorter absolute
   dispatch deadline is armed only after the complete encrypted
   `AUTH_GRANTED` frame has been written and flushed; a slow successful flush
   does not shorten that dispatch window. Once armed it is immutable, and the
   same instant bounds each pending read and the Pong write for a Ping. Apart
   from bounded WebSocket control handling, the next application frame must be
   the exact encrypted canonical `HarmonyHintsV2` request for the grant-bound
   database; malformed, cleartext, wrong-database and unrelated application
   frames close and restore the still-unexposed reservation. Complete all
   independent tree-top/database preflight on the appropriate provider
   connection before this grant.

   Under the cross-process capacity lock, online reservation checks only the
   current process's fully validated and ready `PoolState` paths for currently
   lockable inodes. The reservation hot path uses a non-blocking capacity-lock
   attempt; lock contention fails non-consumingly. A selected inode locked by a
   peer rotates behind the bounded current snapshot instead of creating
   head-of-line blocking, while unvalidated/corrupt disk surplus cannot count.
   A successful online decision preserves one provider-local entry even while
   the pool is below target, but does not reserve it for a particular caller or
   guarantee fairness/immediate admission. Size
   `--pool-size` with further headroom, set `--service-max-concurrent-auth` and
   `--service-pre-auth-timeout-ms` to the smallest values supported by the
   selected authority latency, keep its HTTP
   connect/operation budgets well below that deadline, and enforce source-aware
   admission or a reviewed edge puzzle before the WebSocket authorization
   path. These controls bound cost and lock duration; they do not create fair
   admission under a distributed attacker. Do not activate a paid V2Full offer
   until the environment's overload test and policy are accepted;
3. independent rollback-authority backup/restore drill, beginning with the
   reproducible no-funds procedure in `STAGING_STORE_DRILL.md` and then
   repeating it against the selected independently administered authority;
4. provision a filesystem quota and alerts for issuer/provider database, WAL,
   free space and backup growth; terminal economic rows remain retained, so
   active admission limits do not bound disk usage and ad-hoc deletion is
   forbidden;
   use the explicit non-serving issuer/provider `check-store` commands to
   record `startup_check_ms` and aggregate row counters, set environment-specific
   activation limits, and reject the rollout if either store exceeds them.
   Public serving logs deliberately emit only a coarse successful-check marker
   and elapsed time, never exact generation, quote, spent, or custody counts;
5. retain the implemented loopback two-provider direct-receipt, Free, BAT and
   experimental-ARC DPF process checks, the feature-gated Standard-Cashu/Free
   two-provider process cell, and the real-process Harmony V2Full
   reserve/reject/disconnect/dispatch/restart lifecycle. Then complete the
   remaining non-DPF process cells and approved external/deployed boundaries;
   the local process tests use
   `NoSevHost`/`dangerous_unpaired_*` and are not production trust-chain
   evidence;
6. retain the disposable local CDK fake-wallet token-import check, then run an
   approved WebPKI Cashu mint NUT-03/recovery/outage canary; separately run an
   approved regtest/signet Core Lightning canary;
7. approved relay split-view/outage drill;
8. logging/metrics review against `SECURITY.md`;
9. ARC kept experimental and optional pending independent review. Local ARC
   integration requires `--allow-experimental-arc` on each configured
   `unified_server` and `payment-issuer`; the acknowledgement without an ARC
   policy/key, or ARC policy/key without the acknowledgement, fails startup.
   This flag never authorizes production deployment.

Built-in listener limits are not a substitute for the first item.
Per-entitlement `max_concurrent_sockets`, Harmony shared-socket accounting, the
process-wide semaphores and the per-connection preflight budget do not replace
aggregate edge controls across many connections.

## 7. Activation order

When separately approved, use this order:

1. freeze exact binaries, hashes, policies, directory artifacts and key IDs;
2. restore/check database and independent rollback authority separately;
3. start issuer/mint/clearing dependencies in private health-check mode;
4. start providers with service admission disabled or unreachable externally;
5. verify identity, binary/attestation, database proof/root and signed policy
   from a strict client;
6. verify edge limits and fail-closed dependency behavior;
7. publish directory artifacts only after live checks match them;
8. enable one method/scope canary at a time, starting with no-funds/staging;
9. observe aggregate/coarse metrics without token/query correlation fields;
10. enable broader traffic only after the canary and recovery drill pass.

Never enable a fallback that bypasses strict verification when issuer, mint,
directory or payment service is unavailable. A separately signed Free offer is
an independent user choice, not an automatic downgrade.

## 8. Runtime failure handling

- Failure before authoritative spend: close/fail the attempt; an unused browser
  capability may be selected later by the user. Do not silently switch offers.
- Outcome unknown during an external mint/issuer mutation: reconcile only the
  exact idempotent transcript. For shared redeem, only a low-level recovery tool
  that explicitly retained the identical proof may reconstruct its deterministic
  provider-secret HMAC wire key and verify the exact signed issuer replay. The
  official Web flow burns/deletes before send and performs no automatic retry.
  Never create fresh outputs/credentials.
- Failure after authoritative spend or browser burn-before-send: treat the
  capability as spent. Do not resurrect it after refresh and do not retry the
  query automatically.
- Failure after the provider-local shared-delivery claim, including loss of the
  encrypted `AUTH_GRANTED` frame, leaves the entitlement consumed. Exact issuer
  replay must hit the same HMAC local claim and fail as already spent; do not
  issue a replacement grant on a new connection.
- Preflight/query/inclusion failure after spend: disconnect, surface the stage,
  and fail closed. Do not display an unverified result.
- Issuer/mint outage: online methods fail closed; already issued unexpired
  provider-local receipt/BAT/ARC capabilities may remain verifiable according
  to policy.
- Directory outage: cached verified state or manual pinned endpoints may be
  used under their normal validity rules; directory data never overrides live
  verification.

## 9. Logging and monitoring

Allowed observability is coarse and aggregate: provider, public policy/scope/
scheme IDs, outcome class, coarse time bucket, aggregate latency/resource
counters and rotating keyed diagnostic digests.

Never log invoice text, payment hash/preimage, route, raw capability/tag/
secret/signature, claim recovery secret, query address/result, peer provider or
pair ID, exact token-specific timestamps, browser vault contents or Cashu
blinding/recovery material. Verify reverse-proxy, Lightning, mint and relay logs
as well as application logs.

Unified-server default logs are startup/aggregate only and omit raw peer IP,
connection/client ID, per-query timing, database/group selection and response
sizes. Normal artifacts do not compile or recognize
`--unsafe-debug-query-logging`. A privacy-dangerous local diagnostic can be
built only with the explicit `test-only-unsafe-query-logging` feature in
Cargo's debug profile; its build script rejects release and other profiles,
including release with forced debug assertions. Its output must use isolated
short retention and must never be joined with payment/issuer logs. Deployment
units must use an ordinary release artifact and must never enable any
`test-only-*` feature.

## 10. Rollback and recovery

There are three different rollback cases:

### Before the first new admission mutation

A code/config canary may be aborted only if the exact existing database,
rollback authority, policy/key horizons and binary schema compatibility remain
valid. Do not lower policy epochs or replace the store with an empty file.

### After any admission/spend mutation

Never restore an older provider/issuer database or its older authority. That
can revive spent capability or duplicate economic state. Roll back traffic and
fix forward using the latest authoritative store. If the latest state cannot be
proved, fail closed and rotate/revoke affected keysets under an explicit
recovery ceremony.

### First-release ProviderStore initialization

There is no released/production v6 state and the shared-delivery correction does
not bump schema v7. Before a fresh v7 store accepts a mutation, an aborted
initialization may be discarded only after inspecting its exact paths. After
the first mutation, never return to a pre-release store or an older v7 snapshot;
drain traffic and fix forward from the latest authoritative state. Never reuse
old issuer exact-replay history with an empty local delivery-claim set; follow
the full-stop-and-rotation procedure in section 5. Any future released schema
change requires a separately reviewed, versioned offline migration tool.

Policy rollback is always a new higher-epoch disable/change policy. Binary
rollback is allowed only when it understands the current schema/wire/policy and
does not discard state. Directory rollback uses a higher-sequence tombstone or
replacement event, never an older event.

## 11. Approval gates

Obtain fresh user approval immediately before any of these actions:

- production deployment or remote-server operation;
- connecting the executable to a real Lightning node or spending/receiving
  real Lightning funds;
- contacting an external Cashu mint with production value;
- publishing provider catalogs to a public Nostr relay;
- installing production keys or performing a production database migration.

ARC additionally requires an independent cryptographic review before it can
leave experimental status.
