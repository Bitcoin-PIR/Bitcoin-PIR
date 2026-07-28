# BitcoinPIR remote rollback authority service

This application is the production process boundary around
`pir-rollback-authority-protocol` and `pir-rollback-authority-store`. It
provides offline, insert-only administration commands and one deliberately
small loopback HTTP endpoint. It does not provide remote administration,
namespace enumeration, delete, reset, migration, database recovery, or TLS.

## Commands

All material and database parents must already be real directories owned by
the effective user with mode `0700`. Secret and metadata files are created
exclusively with mode `0600`; symlinks, hard links, non-regular files, and
overwrite are rejected.

```text
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

rollback-authority check-store \
  --store /secure/authority/authority.sqlite3 \
  --authority-metadata /secure/authority/authority-public.txt

rollback-authority serve \
  --bind 127.0.0.1:8099 \
  --store /secure/authority/authority.sqlite3 \
  --authority-secret /secure/authority/authority.seed \
  --authority-metadata /secure/authority/authority-public.txt \
  --expected-authority-pubkey-hex <64-lowercase-hex-pin>
```

Generation writes canonical, minimal public metadata only to `--metadata-out`.
Standard output contains a safe success summary and the escaped metadata path,
not the instance ID, namespace, or public keys. `generate-client` also creates
an independent raw 32-byte
`AuthorityValueRootKeyV1` at `--value-root-key-out`; it is needed by the client
to seal opaque floor values and is not provisioning metadata. Signing seeds
and the value root key are never printed. Every ceremony preflights all output
targets as mutually distinct and absent before writing. If any generation step
reports a partial ceremony, stop and inspect the named output paths; the tool
never deletes or overwrites material automatically.

`init-store` is also deliberately non-destructive after a partial failure. If
it reports that partial initialization may remain, do not delete, overwrite, or
blindly rerun the command. Inspect the exact path and use `check-store` with the
same authority metadata before deciding the recovery ceremony.

## Namespace, operation, and exact-call capacity

V1 permits exactly one provisioned namespace per authority instance. The
provision command therefore requires finite, explicit `--max-operation-rows`
and `--max-call-rows`; neither has an unlimited or implicit default. Repeating
the exact namespace, client key, and both capacities is idempotent, while a
second namespace, key rebind, or capacity change fails closed.

Every newly linearized CAS terminal outcome consumes one durable operation-log
row. An exact replay of the same operation ID and digest does not consume a
second row. V1 has no safe prune, expiry, quota expansion, or online migration
operation. Provision against measured SQLite, WAL, backup, restore, and
monitoring capacity for the intended authority lifetime, with substantial free
space and operational headroom. Exhaustion rejects a new CAS before reading or
changing the current record; authenticated reads and exact replays remain
available while call capacity remains.

Every fresh authenticated Read and every fresh-nonce CAS attempt consumes one
durable call row. Its request digest, CAS disposition when applicable, and
opaque observed-record snapshot are committed atomically. Replaying the same
signed request returns that first snapshot and consumes no row; a fresh nonce
continues to perform a fresh Read or normal stable-operation CAS
reconciliation. Call-capacity exhaustion rejects new calls before reading live
state, while exact signed-request replay remains available. Size this separate
capacity for all lifetime startup reads and retry attempts. Replacing or
enlarging either exhausted capacity requires a reviewed authority-identity
migration rather than editing the database.

`check-store` performs the full offline integrity/row-invariant check and, for
a provisioned store, prints only the exact operation and call used/max counters
plus a coarse provisioned status. It fails
explicitly if no namespace has been provisioned. These counters reveal one
role's mutation activity: collect them only in that authority's private
operator domain, never in a shared Provider 0/Provider 1/issuer log or event.
Export only independently reviewed coarse saturation alerts.

This service creates on-disk schema version 2. Development databases created by
the earlier schema (which lacked durable exact-call snapshots) are rejected and
have no in-place migration; initialize and provision a fresh store.

## HTTP and TLS boundary

The online listener refuses every non-loopback bind address. It serves exactly
one route:

```text
POST /v1/rollback-authority/calls
Content-Type: application/vnd.bitcoinpir.rollback-authority-request-v1
Accept: application/vnd.bitcoinpir.rollback-authority-response-v1, application/problem+json
User-Agent: BitcoinPIR-service-admission/1
```

Connections accept one bounded HTTP/1.1 request and are then closed. Chunked
encoding, redirects, CORS, cookies, ambient authorization, forwarded client
identity headers, and request pipelining are unsupported. Responses always use
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, an exact content
length, and `Connection: close`. Authentication, unknown-namespace, and
operation-replay failures deliberately share one status and fixed problem
body. The service does not log peer addresses, headers, namespaces, keys,
records, request bodies, or response bodies.

The listener uses a fixed worker pool and a bounded admission queue. The
default `--max-connections` is 32, the accepted range is 1 through 256, and the
worker count is the smaller of that limit and 16. The connection permit covers
both queued and active work. Once the bound is reached, the accept loop closes
the new connection immediately without parsing it or synchronously writing an
unsigned overload response. Clients must treat that close as an ambiguous
possible-send outcome and perform normal authenticated reconciliation. The TLS
edge must still enforce a narrow source-network ACL and conservative connection
and request-rate limits.

The fixed user agent is a protocol constant emitted by the strict HTTPS client,
not a per-installation identifier. All other request headers are rejected.

TLS must terminate at a reviewed edge on the **same host**. That edge must:

- listen remotely only on the intended TLS endpoint while this process remains
  loopback-only;
- disable access logs and all header/body sampling for this route;
- strip cookies, authorization, `Forwarded`, `X-Forwarded-For`, and equivalent
  client identity headers rather than forwarding them;
- preserve the exact method, path, media types, content length, body bounds,
  and connection-close behavior;
- never redirect this endpoint;
- expose a certificate/SPKI that clients pin independently of the authority's
  Ed25519 response key.

At startup, `serve` requires an explicit Ed25519 public-key pin and checks that
it matches both the authority metadata and the secret signing seed. The client
must pin that authority key in addition to the TLS edge SPKI.

## Independence, backup, and restore

PIR Server 0, PIR Server 1, and an issuer each require a separate authority
instance, host, operator/admin domain, signing key, namespace database, backup,
and restore process. Never share one observable authority instance between
them, and never place this database in the same backup/restore domain as the
detailed store whose rollback it prevents.

Back up the signing seed offline and back up the SQLite database with a
SQLite-aware, WAL-consistent procedure. A backup is not itself freshness
evidence. Complete loss must fail closed: do not restore an unproven stale
snapshot. Recovery requires either a separately protected high-water proof or
an explicit offline authority-identity rotation ceremony accepted by clients.

Each provisioned client must separately back up its Ed25519 signing seed and
its value root key. Loss of either client secret makes the namespace unusable;
copying either secret into another authority instance defeats the intended
instance separation. Client-secret backups must not be stored in the
authority database or its backup domain.
