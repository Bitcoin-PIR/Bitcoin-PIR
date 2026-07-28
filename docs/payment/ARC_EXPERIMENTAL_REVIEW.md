# ARC experimental integration review

Status: implementation and review gate. ARC is in the v1 integration/test
scope, but it MUST remain advertised as `experimental` and MUST NOT be enabled
in production before an independent cryptographic review.

## Confirmed implementation baseline

The workspace pins `https://github.com/Bitcoin-PIR/arc.git` at
`de6c1709eee0faa32985d5a452be11904ee95de4`. The crate describes itself as a
Rust port of `draft-ietf-privacypass-arc-crypto-01` over P-256 and exercises the
working-group proof vectors. As of 2026-07-27, the IETF Datatracker still lists
`draft-ietf-privacypass-arc-crypto-01` as the latest revision, while its working
group state is `Dead WG Document`. Draft alignment and passing vectors are
necessary primitive-level evidence; they are neither an independent security
audit nor evidence that BitcoinPIR implements the complete Privacy Pass ARC
issuance/redemption framing.

Primary sources:

- ARC cryptographic draft:
  <https://github.com/ietf-wg-privacypass/draft-arc/blob/main/draft-ietf-privacypass-arc-crypto.md>
- ARC issuance/redemption protocol draft:
  <https://github.com/ietf-wg-privacypass/draft-arc/blob/main/draft-ietf-privacypass-arc-protocol.md>
- IETF Datatracker status:
  <https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/>

The existing code under `crates/protocol/runtime/src/arc_verifier.rs`,
`apps/dev-issuer`, and the old WASM/Web presentation path is a demo baseline,
not the v1 production adapter:

- it uses the constant request context `bitcoin-pir-v1`, rather than a
  provider/scope/keyset-bound context;
- it stores tags in a process-local `HashMap` and removes a context at
  connection close, so restart and connection churn do not provide durable
  replay protection;
- it uses a connection/demo presentation context instead of one fixed
  cryptographic rate-limit origin;
- it can load the ARC issuer/private-verification key directly into the PIR
  process;
- the old `0x08` frame and `/dev/arc/*` endpoints are not bound to a verified
  service policy or operation grant.

Those paths remain compatibility/demo fixtures only. They cannot authorize a
v1 query and must not be silently wrapped by the new gate.

The v1 `unified_server` and `payment-issuer` additionally require the explicit
`--allow-experimental-arc` acknowledgement for every current/retained ARC
policy and ARC private-key configuration. Supplying the acknowledgement without
an ARC configuration also fails closed. Startup emits a prominent warning. The
flag exists only for isolated integration testing and does not override the
production prohibition above.

## Required fixed contexts

ARC derives its deterministic per-nonce tag generator from
`presentation_context`. Changing that value between connections creates a new
tag namespace and defeats a durable per-credential presentation limit.
Therefore neither ARC context may contain a connection ID, WebSocket session,
client role (`server 0/1`), selected peer, query identifier, Bitcoin address,
invoice, payment hash, or current policy digest.

V1 derives two independent 32-byte contexts from the exact long-lived
credential binding:

```text
arc_request_context = SHA256(
  "BitcoinPIR/credential-request-context/v1"
  || credential_binding_digest
)

arc_presentation_context = SHA256(
  "BitcoinPIR/credential-presentation-context/v1"
  || credential_binding_digest
)
```

`credential_binding_digest` commits to the issuer identity and signature plus
provider, scope, offer, scheme,
entitlement profile, presentation limit, keyset epoch, raw ARC public key and
validity horizon. Reusing one raw ARC key across different binding lineages is
forbidden permanently, including after expiry. Omitting the policy digest lets
an exactly retained binding survive a policy epoch transition through its
declared grace window without changing the ARC origin.

The browser creates one ARC credential per independently selected provider
binding. It never derives an A/B pair from one credential and never reuses the
same client secret across issuance requests.

## Provider-local verification

Private/keyed verification is intrinsic to ARC. A provider-local ARC offer is
valid only when that provider (or a provider-local isolated sidecar in the same
trust domain) owns the matching ARC secret key. The adapter must:

1. decode and byte-for-byte re-encode the presentation with the pinned ARC
   library and the signed presentation limit;
2. obtain request/presentation contexts only from the verified credential
   binding;
3. verify the proof with the exact registered ARC key;
4. serialize the returned P-256 tag canonically;
5. derive a provider-global spend key from a domain separator, raw ARC public
   key fingerprint, binding digest, and canonical tag;
6. commit that spend key through the provider store and its external rollback
   floor before returning `AUTH_GRANTED`.

The runtime adapter never owns an in-memory authoritative seen-tag set.
Signature/proof work occurs before the short store transaction; the store
repeats the namespace/binding checks before its unique insert. Exact proof
replay, replay after disconnect/restart, and concurrent replay yield one
durable consumer.

Loading a provider-local secret into the main PIR process expands that
process's key-compromise impact. The preferred deployment is a local isolated
verifier sidecar or hardware-backed boundary with a fixed-context API, but that
does not change the provider-local trust domain. Key bytes, scalar components,
or detailed proof failures never enter logs.

## Shared-issuer verification and clearing

A shared ARC issuer MUST NOT distribute its secret verification key to PIR
providers. The provider authenticates to the issuer/clearing service and sends
one canonical provider-bound presentation plus an idempotency digest. The
issuer atomically:

- verifies the provider registration and current clearing authorization;
- verifies ARC under the exact binding and fixed contexts;
- inserts the issuer-global tag/spend key;
- records the redemption operation;
- credits the authenticated provider (or creates its exact blind settlement
  promises) and posts the issuer fee;
- commits the exact signed response and external rollback-floor successor.

Only that committed issuer response can create a connection grant. The issuer
learns provider, scope and redemption timing; the signed offer privacy flags
must declare this. A bearer client cannot change the credited provider or
settlement destination.

## Browser state

The browser persists the next ARC nonce before a presentation can leave WASM.
The update is transactional in IndexedDB and serialized across tabs with Web
Locks. If send/ACK outcome is unknown, that nonce remains burned; the browser
does not recreate an earlier `PresentationState` or retry the query.

Credential bytes, client secrets and nonce state are encrypted at rest where
the platform permits. They are never stored in `localStorage`, URL parameters,
analytics, console logs, or an invoice-to-query record. Deleting browser state
can discard remaining quota; recovery from a stale browser backup must not
resurrect a nonce.

## Independent review gate

Before ARC can move from experimental to stable, an external reviewer must at
least assess:

- exact correspondence of the pinned Rust implementation to draft-01 and
  working-group vectors, including transcript/domain separation;
- proof parsing, point/scalar canonicality, subgroup/identity handling and
  malformed-input resource bounds;
- nonce range proof behavior, including rejection of unsupported limit 1 and
  verification of permitted limit 2, non-powers of two and the configured
  maximum;
- tag uniqueness/replay behavior under the fixed BitcoinPIR contexts;
- issuer maliciousness, key compromise, multi-key/key-rotation and raw-key
  lineage assumptions;
- client state rollback, multi-tab races and failure between nonce persistence
  and network send;
- side channels and denial-of-service cost before durable consumption;
- the fork's maintenance, dependency, MSRV, fuzzing and disclosure posture.

Functional integration tests do not close this gate.

## Required v1 tests

- pinned working-group issuance/presentation vectors decode and re-encode;
- end-to-end issue/finalize/present/verify for provider-local and shared-online
  fake adapters;
- wrong request context, presentation context, provider, scope, offer, keyset,
  limit, public key and expiry all fail;
- same credential has distinct tags for valid sequential nonces, while exact
  nonce replay has the same tag and is rejected durably;
- presentation context cannot vary by connection or client input;
- disconnect/restart/concurrent replay has exactly one spend commit;
- issuer/provider key rotation retains only explicitly allowed old bindings;
- old `0x08` and `/dev/arc/*` paths cannot grant under v1 enforced mode;
- ARC is rejected if configured `stable`, if the adapter is absent, or if the
  external rollback authority is unavailable;
- native/WASM serialization interoperability and IndexedDB nonce-burn tests;
- shared issuer response credits only the authenticated provider and contains
  no peer-provider or query identifier.
