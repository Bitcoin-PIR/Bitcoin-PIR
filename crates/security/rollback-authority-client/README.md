# Remote rollback-authority client

`pir-rollback-authority-client` is the blocking, fail-closed client for
`pir-rollback-authority-protocol`. It is transport-only infrastructure; it is
not wired directly into a provider/issuer store in this crate.

## Production transport invariants

- The only public production constructor requires a canonical `https://`
  endpoint and one or two distinct leaf-SPKI SHA-256 pins.
- A pin is an additional restriction on ordinary rustls/WebPKI chain,
  hostname, validity-time, and configured revocation verification. It cannot
  bypass WebPKI and is not TOFU. TLS session resumption is disabled so every
  connection rechecks the certificate and pin.
- The one fixed route is `POST /v1/rollback-authority/calls`. HTTP 200 is the
  only success status; request, success, and error media types are exact and
  distinct. Redirects, decompression, cookies, proxies, and plaintext fallback
  are unavailable.
- Request and response bodies are bounded by the protocol's fixed V1 wire
  sizes. Every unsigned HTTP status, malformed response, bad signature,
  truncated/oversized response, or response for a different attempt is
  `OutcomeUnknown` after a request may have been sent.
- An absolute caller deadline bounds the whole workflow. Each network attempt
  is additionally bounded by `attempt_timeout`; no lower-level step refreshes
  either deadline.

## CAS durability and recovery

Create a `DurableAuthorityCasOperationV1` and durably store its nonzero
`operation_id` plus the exact encoded `expected` and `desired` opaque records
before the first network attempt. Every attempt signs a new call nonce but
retains that operation ID and those records.

`compare_and_swap_until` makes exactly one attempt. On `DefinitelyNotSent`, a
caller may make another freshly signed attempt with the same durable
operation. On `OutcomeUnknown`, use
`reconcile_unknown_compare_and_swap_until`: it performs a fresh one-shot Read,
then a freshly signed CAS with the same durable operation so the authority's
operation log can return an authenticated terminal result. It never reuses an
old signed request, response, Read nonce, or Read transcript.

The authority nevertheless persists one bounded replay snapshot for every
fresh call nonce. If a transport or intermediary duplicates exact signed bytes,
the duplicate is bound to the first request digest and response snapshot and
cannot observe a later live floor. This does not change client recovery:
freshness always comes from a newly signed Read, and a CAS retry always gets a
new nonce while retaining the stable operation.

If an application deliberately chooses not to persist the opaque operation,
it cannot claim operation-log continuity after a process crash. It may only
perform a fresh Read, authenticate/decrypt the live domain value, and apply an
explicit domain-level state convergence policy.

## Sensitive data

`Debug` implementations redact the endpoint, namespace binding, authority
key, operation ID, and opaque records. Protocol and response buffers use
zeroizing owners where the underlying APIs permit it. This is best-effort and
does not erase rustls internals, allocator remnants, kernel buffers, or remote
authority logs.

## Shared production deployment config

Provider and issuer processes must use
`load_remote_rollback_authority_deployment_for_business_domain_v1`, passing
their exact provider or issuer ID, rather than independently reimplementing key
and TLS setup. There is no exported production loader that omits the business
domain. The loader accepts one owner-owned mode-0600 TOML file in an
owner-owned mode-0700 directory. Unknown fields are rejected. Both referenced
secret paths must be absolute, owner-owned mode-0600 regular files with one
hard link. The raw 32-byte Ed25519 seed, raw 32-byte value-root key, business
ID, authority instance/key, namespace, client key and derived client-key ID,
and one-or-two TLS leaf-SPKI pins must be role-distinct. The configured client
public key must match the signing seed before any network request.

```toml
schema = "bitcoinpir_remote_rollback_authority_v1"
endpoint = "https://rollback-authority.example"
authority_instance_id_hex = "<64 lowercase hex>"
authority_verifying_key_hex = "<64 lowercase hex>"
namespace_hex = "<64 lowercase hex>"
client_verifying_key_hex = "<64 lowercase hex>"
client_signing_seed_path = "/absolute/private/client.seed"
value_root_key_path = "/absolute/private/value-root.key"
leaf_spki_sha256_pins_hex = ["<64 lowercase hex>"]
connect_timeout_ms = 5000
io_timeout_ms = 5000
attempt_timeout_ms = 10000
operation_timeout_ms = 30000
```

Exactly one or two distinct, nonzero SPKI pins are required. Connect and I/O
timeouts may not exceed the per-attempt deadline. The whole logical operation
deadline must contain at least three complete attempt budgets so an ambiguous
initial CAS still has bounded room for a fresh Read and reconciliation CAS.
The loader performs no network request; the first store open always performs a
fresh authenticated remote Read and fails closed if the authority is
unreachable or inconsistent.

For offline deployment-set linting,
`load_remote_rollback_authority_deployment_descriptor_v1` reads the same strict
owner-only config but never opens either referenced secret. Its opaque,
redacted descriptor is accepted by
`validate_independent_remote_rollback_authority_deployments_v1`, which accepts
the two through sixteen configs in one actual deployment topology and rejects
repeated endpoints, authority instance IDs, namespaces, any authority/client
verifying-key reuse across roles, and any overlapping TLS SPKI pin. The
validator is role-agnostic: the caller supplies exactly the authorities used by
the topology being reviewed. This public-config check is necessary but cannot
prove that the supplied list covers a directory's global node population, that
different DNS names resolve to different hosts, that the unread value-root key
bytes are distinct, or that operators, logs, backups, and failure domains are
actually independent.
