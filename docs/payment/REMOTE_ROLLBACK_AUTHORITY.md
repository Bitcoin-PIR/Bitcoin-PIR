# Remote rollback authority deployment

This document describes the production boundary implemented by
`rollback-authority`, `pir-rollback-authority-client`, and the provider/issuer
floor adapters. It is an operator design and ceremony guide, not evidence that
the service has been deployed. Local SQLite rollback floors remain suitable
only for development, tests, and disposable drills.

## Required topology

Run one independent authority instance for each stateful provider or issuer
store in the actual two-provider topology. Common examples are:

| Actual topology | Authority configs supplied to the deployment lint |
| --- | --- |
| both providers are free-only | 2: Provider 0 and Provider 1 |
| both providers use one shared external issuer | 3: Provider 0, Provider 1, and the shared issuer |
| each provider uses its own or a different issuer | 4: Provider 0, Provider 1, Issuer 0, and Issuer 1 |

Every entry must have an independent host, service account, Ed25519 keys,
namespace, TLS key/pin, administrator, logs, and backup/restore domain. A
provider-operated issuer is still a distinct stateful role and therefore has a
separate authority instance and configuration.

Do not place two roles behind one authority service merely by assigning two
namespaces. A shared process, host, TLS edge, administrator, log stream, outage,
or backup/restore action becomes a common timing and availability observer. For
the two PIR providers that weakens the intended non-collusion boundary even
though the authority never sees an invoice, credential, query address, or PIR
result in plaintext.

The detailed store owns business state. The authority stores only an
authenticated monotonic opaque floor and terminal CAS outcomes. The authority
must not receive invoices, payment hashes, preimages, Cashu proofs, ARC
credentials, provider admission frames, query bytes, database records, or
client IP metadata.

## Trust and protocol boundary

Each client authenticates four independent bindings before trusting a floor:

1. ordinary WebPKI validation of the configured HTTPS name;
2. one or two out-of-band leaf-SPKI SHA-256 pins;
3. the configured authority-instance ID and Ed25519 response key; and
4. a distinct client namespace, Ed25519 request key, and value-root key.

The value-root key seals the application floor so the authority cannot decode
its domain state. Signed one-shot `Read`, `Initialize`, and compare-and-swap
requests bind the authority instance, namespace, operation, expected value,
desired value, and fresh call nonce. HTTP 200 is the only success status. A
redirect, different success code, wrong media type, malformed or oversized
body, bad signature, wrong binding, timeout after possible transmission, or
unavailable authority is never treated as success.

The authority durably binds each call nonce to the full request digest and the
opaque record snapshot observed at that call's first linearization. Exact
signed-request replay returns only that snapshot, never a later live floor. A
client recovery Read or CAS retry uses a fresh nonce, creates a separately
bounded call row, and retains the normal fresh-observation/reconciliation
semantics.

The production client has no plaintext, unpinned, local-SQLite, or
use-the-detailed-store fallback. A provider or issuer that cannot authenticate
and reconcile its floor must fail startup or the affected mutation closed.
Its configured operation deadline must contain at least three full attempt
budgets, reserving bounded time for the initial CAS, a fresh Read, and a
reconciliation CAS after an ambiguous response.

## Host and TLS shape

`rollback-authority serve` binds only IPv4 or IPv6 loopback and deliberately
does not implement TLS. Terminate TLS on a reviewed edge on the **same host**.
For its single route the edge must:

- never redirect and never proxy to another authority host;
- disable access logs, request/response sampling, tracing payloads, and error
  pages that reflect request data;
- strip `Cookie`, `Authorization`, `Forwarded`, `X-Forwarded-For`, proxy-client
  certificates, and equivalent identity headers;
- preserve the exact method, route, media types, content length, and response;
- enforce a bounded request body, header timeout, whole-request timeout,
  connection limit, and one request per connection; and
- publish the reviewed leaf certificate whose SPKI digest is transferred to
  the client operator out of band.

The application accepts exactly:

```text
POST /v1/rollback-authority/calls
Content-Type: application/vnd.bitcoinpir.rollback-authority-request-v1
Accept: application/vnd.bitcoinpir.rollback-authority-response-v1, application/problem+json
User-Agent: BitcoinPIR-service-admission/1
Connection: close
```

The fixed user agent is a protocol constant, not an installation or client
identifier. Authentication failures, unknown namespaces, and operation replay
mismatches use the same unsigned HTTP status and fixed problem body. The signed
response remains the only authority-state evidence.

The application listener uses a fixed worker pool and bounded admission queue,
not one thread per connection. `--max-connections` defaults to 32, is restricted
to 1 through 256, and covers queued plus active connections; at most 16 workers
execute requests concurrently. At the bound, the accept loop closes the new
connection immediately without parsing it or synchronously writing an unsigned
503. A client treats that close as an ambiguous possible-send outcome and uses
the same authenticated Read/CAS reconciliation rules. These process bounds do
not replace the edge ACL and rate limits above.

This is wire-level, not timing, indistinguishability. A key lookup miss, an
Ed25519 verification failure, and an operation-log replay mismatch perform
different work and may remain distinguishable to a low-latency observer. The
namespace is a random 256-bit value and must remain out of logs and transcripts;
exposure of provisioning metadata can otherwise turn timing into a namespace
activity oracle. The same-host TLS edge must enforce a narrow source-network
boundary and bounded connection/request rates without pooling observations
from the other PIR provider.

## Offline material ceremony

Use a dedicated mode-0700 directory for each authority and a different
mode-0700 directory for each client. The commands refuse symlinks, hard links,
wrong ownership/modes, and overwrite. They create mode-0600 files and fsync the
file and parent directory.

```sh
rollback-authority generate-authority \
  --secret-out /secure/authority/authority.seed \
  --metadata-out /secure/authority/authority-public.txt

rollback-authority generate-client \
  --secret-out /secure/client/client.seed \
  --value-root-key-out /secure/client/value-root-key.raw \
  --metadata-out /secure/client/client-provisioning.txt

rollback-authority init-store \
  --store /secure/authority/authority.sqlite3 \
  --authority-metadata /secure/authority/authority-public.txt

rollback-authority provision \
  --store /secure/authority/authority.sqlite3 \
  --authority-metadata /secure/authority/authority-public.txt \
  --client-metadata /offline-transfer/client-provisioning.txt \
  --max-operation-rows 1000000 \
  --max-call-rows 4000000
```

Transfer only the authority public metadata and client provisioning metadata
between operators. Never transfer the authority signing seed to the client or
the client signing/value-root keys to the authority. Verify the instance ID,
authority key, namespace, client key, derived authority client-key ID, TLS name,
SPKI pins, and the consuming provider/issuer ID over at least one independent
authenticated channel before building the deployment TOML from
`REMOTE_ROLLBACK_AUTHORITY.toml.example`. The two raw client secrets and every
one of those 32-byte public bindings must be pairwise distinct. A secret that
equals a public identifier is compromised key material, not a valid
configuration.

Before moving the detailed stores to remote mode, run the role-agnostic offline
lint over exactly the authority configs used by that deployment. Repeat
`--config` between two and sixteen times. For a free-only pair:

```sh
bpir-admin rollback-authority-deployment-lint \
  --config /secure/provider0/remote-authority.toml \
  --config /secure/provider1/remote-authority.toml
```

For two providers sharing one external issuer:

```sh
bpir-admin rollback-authority-deployment-lint \
  --config /secure/provider0/remote-authority.toml \
  --config /secure/provider1/remote-authority.toml \
  --config /secure/shared-issuer/remote-authority.toml
```

For two providers using separate issuers:

```sh
bpir-admin rollback-authority-deployment-lint \
  --config /secure/provider0/remote-authority.toml \
  --config /secure/provider1/remote-authority.toml \
  --config /secure/issuer0/remote-authority.toml \
  --config /secure/issuer1/remote-authority.toml
```

The command reads each config with the same owner-only mode-0600,
single-hard-link, non-symlink policy as production parsing. It validates only
public deployment fields: it never reads a referenced client signing seed or
value-root key, opens a network connection, or contacts an authority. It
rejects any repeated endpoint and any within- or cross-deployment collision
among authority instance ID, namespace, authority/client verifying keys,
derived authority client-key ID, and the selected one-or-two TLS leaf-SPKI
pins. Success prints only
`rollback-authority-deployment-set=PASS`; it never prints an endpoint,
identifier, key, namespace, pin, or config path. It assigns no provider or
issuer role to an entry; role meaning remains solely in the operator's reviewed
input list.

This lint covers only the actual topology supplied in that invocation. It is
not a directory-wide inventory or proof that every advertised node was
included. It is necessary but not proof of operational independence: different
DNS names may still terminate on one host, and files may still share an
administrator, log stream, backup, restore, or outage domain. Because the lint
never reads a referenced value-root secret, it also cannot prove that
value-root key bytes differ. The production provider/issuer loader additionally
rejects a consuming business-domain ID that equals either secret or any public
authority binding, but the role-agnostic public lint has no business ID input.
Verify topology coverage, secret separation, business-ID separation, and the
operational boundaries separately during the deployment review.

Generation is deliberately non-transactional across multiple output files. If
a command reports a partial ceremony, stop and inventory every named path. Do
not delete files automatically or rerun against alternate paths. Either finish
an explicitly audited recovery using the preserved outputs or retire all
public identifiers through a new offline ceremony.

The complete public metadata is written only to the requested mode-0600
metadata file. Standard output contains a safe success summary and the escaped
metadata path; it does not print the instance ID, namespace, or public keys.
Treat the metadata file as provisioning-sensitive even though it contains no
secret key, because exposing its random namespace can enable an activity oracle.

`init-store` can also leave a partially initialized database if a failure occurs
after exclusive file creation. When the command reports that possibility, do
not delete, overwrite, or blindly rerun it. Inspect the named path and run
`check-store` with the exact same authority metadata before choosing an audited
recovery or a wholly new ceremony.

## One namespace and finite operation/call capacities

V1 enforces one namespace per authority instance in both the provisioning API
and the database. This is a security boundary, not a utilization suggestion:
provider 0, provider 1, and issuer must never be colocated as namespaces in one
authority. A second namespace, key change, or either capacity change is
rejected; repeating the exact namespace/key/capacity tuple is idempotent.

Provisioning requires an explicit finite `--max-operation-rows` between 1 and
100,000,000. There is no unlimited/default value. Each newly linearized CAS
terminal outcome, including Empty and ConflictCurrent, consumes one durable
row. Exact replay of the same operation ID and digest consumes no additional
row. The counter increment, terminal outcome, and any current-record mutation
share one `BEGIN IMMEDIATE` transaction.

Provisioning also requires an explicit finite `--max-call-rows` between 1 and
100,000,000. Every previously unseen authenticated call nonce, including a
fresh Read and each fresh-nonce CAS attempt for an existing stable operation,
consumes one `call_log` row. The row binds the operation/request digests and the
opaque current-record snapshot observed at that call's linearization. Its
counter reservation, snapshot, operation terminal row when new, and mutation
when applied share the same `BEGIN IMMEDIATE` transaction. An exact signed
request replay consumes no second call row and is answered from its original
snapshot; re-reading the later live record is forbidden.

Choose both limits from expected lifetime mutation, startup-read, and
recovery-attempt rates and measurements of the exact staged SQLite build.
Include the main database, WAL/checkpoint peaks,
WAL-consistent backups, restore rehearsal, monitoring margin, and filesystem
reserve; keep substantial additional headroom rather than treating the quota as
a disk limit. As a lower-bound intuition only, an applied/conflict row carries
more than 700 bytes of fixed payload and keys before SQLite page/index/WAL
overhead, so 100,000,000 rows is already more than 70 GB before that overhead.

V1 has no safe pruning, expiry, quota expansion, or online migration. When the
operation quota is exhausted, a new CAS returns service unavailable before the
current record is read or changed; fresh Read and existing-operation retries
remain available only while call capacity remains. When call capacity is
exhausted, every new nonce fails before current state is observed, while exact
signed-request replay remains available from its durable snapshot. Alert well
before either exhaustion. Continuing service requires a separately reviewed
authority-identity migration that proves and transfers the high-water state;
never edit the stored limit/counter or delete operation rows.

Run `rollback-authority check-store` locally in each authority's private
operator domain to perform the full integrity check and retrieve exact
`operation_rows_used`, `operation_rows_max`, `call_rows_used`, and
`call_rows_max`. The command fails explicitly
for an unprovisioned store. Exact usage is activity-sensitive: never forward it
to a shared Provider 0/Provider 1/issuer dashboard, log, trace, or alert event.
If centralized infrastructure must receive saturation health, export only a
separately reviewed coarse local threshold state that cannot join exact counts
or timing across roles.

The current fresh-store-only on-disk schema is version 2. The prior
development-only schema did not persist exact-call snapshots and is rejected;
there is no in-place migration. No production authority was enabled on that
schema, so recreate and reprovision any local/staging drill store rather than
adopting it.

## Store initialization and restart

Remote provider/issuer initialization requires a caller-generated nonzero
16-byte store-instance ID. Generate and record that public ID before the first
remote request. If the authority commits and the local HTTP/process response or
detailed-store write is lost, retry and inspect using the **same** config,
store-instance ID, provider/issuer identity, and network. Creating a new ID or
resetting/lowering the remote namespace can make a rolled-back detailed store
appear current.

Every normal restart performs a fresh authenticated authority read before the
detailed store is accepted. Expected predecessor, exact successor, and
operation-replay cases are reconciled according to the domain adapter. Any
other authenticated value, uninitialized namespace where initialized state is
required, inaccessible authority, or unverifiable response is a hard failure.

Provider serving uses:

```text
--service-store <provider.sqlite3>
--service-remote-rollback-authority-config <remote-authority.toml>
```

Issuer serving uses:

```text
--store <issuer.sqlite3>
--remote-rollback-authority-config <remote-authority.toml>
```

The local provider path additionally requires
`--allow-local-service-rollback-authority-dev`; production must not use it.
The local issuer `serve-cln` path likewise requires
`--allow-local-rollback-authority-dev`. The acknowledgement flag is rejected
when a remote config is selected, so it cannot silently change the production
mode.

## Rotation

One or two SPKI pins allow a bounded certificate-key overlap. Install the new
pin in the private client config, verify connectivity, rotate the edge leaf,
then remove the old pin. Never use the second slot as an unreviewed permanent
fallback.

Changing an authority instance ID, authority Ed25519 key, namespace, client
request key, value-root key, provider/issuer identity, store-instance ID, or
domain encoding is an authority-identity migration, not a routine key reload.
It requires an offline ceremony that proves the current high-water state and
explicitly binds the new instance. V1 provides no online reset, delete,
namespace rebind, or implicit migration endpoint.

## Backup, restore, and loss

Back up these domains separately:

- authority signing seed;
- SQLite authority database using a WAL-consistent SQLite procedure;
- client request-signing seed and value-root key; and
- detailed provider/issuer store and its own sensitive operational material.

A backup copy is not freshness evidence. Before production activation, rehearse
restore while independently proving that the restored authority floor is at
least the latest accepted value. Restoring an unproven stale snapshot is
forbidden. Complete authority-state loss fails closed and requires either a
separately protected high-water proof or explicit authority-identity rotation.
Losing either client secret makes that namespace unusable; copying it into a
replacement/shared authority defeats separation.

Monitor only coarse health and saturation outside the request path. Never log
request bodies, response bodies, namespace IDs, operation IDs, opaque values,
client addresses, exact request timing, or detailed-store identifiers. Alerts
for an unreachable or inconsistent authority must identify the role locally,
not join Provider 0, Provider 1, and issuer observations in a common event
record.

## Staging acceptance before production

For each authority instance selected by the actual deployment topology, record
all of the following without real Lightning funds:

1. material generation, provisioning, config loading, and public-fingerprint
   cross-check;
2. successful fresh initialize/read/CAS/restart against the TLS edge;
3. rejection of bad WebPKI, each wrong/removed SPKI pin, wrong Ed25519 key,
   wrong namespace/client seed/value-root key, unsafe file modes, and unknown
   config fields;
4. response-loss reconciliation after a committed CAS and a definitely-not-sent
   retry with the same durable operation, plus exact Read/CAS request replay
   before and after a later floor change and process restart proving the first
   per-call snapshot is returned;
5. authority outage and stale/inconsistent-state startup failure with no local
   fallback;
6. concurrent mutations showing one linearized domain successor;
7. WAL-consistent backup plus isolated restore drill with a separately checked
   high-water value; and
8. edge verification that access logs and identity-header forwarding are
   disabled and HTTP 200 is the sole success code.

The private-root TLS feature used by the process harness is debug-test-only.
Production configuration parsing rejects its field, and a release build with
that feature is required to fail compilation. Never deploy an assertions-enabled
test artifact or a binary whose reviewed Cargo feature set is unavailable.

Only after these checks, pushed CI, independent review, and separate deployment
approval may the remote mode replace local test floors. That approval still
does not authorize a real-funds payout executor, public Lightning liquidity, or
production Nostr publication.
