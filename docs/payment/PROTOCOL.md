# BitcoinPIR service authorization protocol v1

Status: normative wire and API draft. Integer encodings are little-endian.
Every variable-length field has an explicit maximum; decoders reject trailing
bytes unless the structure defines padding.

## Canonical identifiers

```rust
pub type ProviderId = [u8; 32];
pub type ScopeId = [u8; 32];
pub type PolicyDigest = [u8; 32];

pub struct ServiceScopeV1 {
    pub provider_id: ProviderId,
    pub backend: BackendId,
    pub workload: WorkloadId,
    pub protocol_version: u16,
    pub dataset: DatasetBindingV1,
    pub operation_profile: u16,
    pub entitlement_profile: u16,
}
```

Canonical hashes are domain separated:

```text
scope_id = SHA256("BitcoinPIR/service-scope/v1" || encode(ServiceScopeV1))
policy_digest = SHA256(
  "BitcoinPIR/service-policy-digest/v1" || canonical_signed_policy_bytes
)
```

`canonical_signed_policy_bytes` is exactly `ServicePolicyV1::encode`, including
its deterministic Ed25519 signature. It is not JSON and not the unsigned
signing preimage.

`BackendId` values:

| Value | Name |
|---:|---|
| 1 | `DpfPirV1` |
| 2 | `HarmonyPirV2` |
| 3 | `OnionPirV1` |
| 4 | `TeeOramV1` |

`WorkloadId` values:

| Value | Name |
|---:|---|
| 1 | `DpfEvaluateJobV1` |
| 2 | `HarmonyHintBundleV1` |
| 3 | `HarmonyQueryJobV1` |
| 4 | `OnionEvaluateJobV1` |
| 5 | `TeeOramQueryV1` |

No field represents client slot, peer provider, provider pair, or common query
ID.

## Signed service policy

```rust
pub struct ServicePolicyV1 {
    pub provider_id: ProviderId,
    pub policy_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub auth_padding_class: AuthPaddingClassV1,
    pub scopes: Vec<ServiceScopePolicyV1>, // max 64
    pub signing_key_id: [u8; 16],
    pub signature: [u8; 64],
}

pub struct ServiceScopePolicyV1 {
    pub scope: ServiceScopeV1,
    pub limits: EntitlementLimitsV1,
    pub offers: Vec<ServiceOfferV1>, // max 16
}

pub struct ServiceOfferV1 {
    pub offer_id: u32,
    pub acquisition: AcquisitionMethod,
    pub free_mode: FreeModeV1,
    pub free_quota: u32,
    pub free_window_seconds: u32,
    pub free_pow_difficulty_bits: u8,
    pub priority_class: u16,
    pub authorization: AuthScheme,
    pub verification: VerificationMode,
    pub deployment_status: DeploymentStatus,
    pub price: PriceV1,
    pub issuer_id: [u8; 32],
    pub key_id: Vec<u8>, // max 64
    pub credential_binding: Option<CredentialKeyBindingV1>,
    pub cashu_mint_manifest: Option<StandardCashuMintManifestV1>,
    pub endpoint: String, // max 512, HTTPS or onion HTTPS
    pub invoice_expiry_seconds: u32,
    pub claim_window_seconds: u32,
    pub minimum_credential_validity_seconds: u32,
    pub retired_policy_grace_seconds: u32,
    pub credential_count: u32,
    pub credential_presentation_limit: u32,
    pub privacy_leakage: PrivacyLeakageV1,
}
```

The endpoint syntax is method-specific. `bolt11_v1` requires one canonical
HTTPS **origin** because the client appends fixed Payment V1 paths; a signed
path would otherwise be interpreted differently by Rust and Web clients.
Standard Cashu may use a canonical HTTPS base path because its NUT endpoints
are relative to the mint URL. Credentials, query strings, fragments, IP
literals, noncanonical ports and path traversal are rejected in both cases.

The canonical policy encoding begins with `version:u8 = 1`. `free_mode` is
`NotFree`, `OpenBestEffort`, `IpRateLimited`, `ProofOfWork`, or
`AnonymousTicket`. A Free offer must choose a non-`NotFree` value; every paid
offer must use `NotFree`. This keeps the server-selected free admission rule in
signed policy instead of an attacker-controlled proof tag.

For `IpRateLimited`, `free_quota` grants are available in each
`free_window_seconds`; both are non-zero. `ProofOfWork` instead sets only
`free_pow_difficulty_bits`. Open, anonymous-ticket, and paid offers keep those
numeric fields zero. Anonymous-ticket quota comes from its issuer/key binding.
`priority_class` is a non-zero, provider-defined opaque class carried in the
signed policy; it conveys no client-selected entitlement. Payment V1 preserves
the field for directory display and a future provider scheduler, but the current
`unified_server` does **not** use it to order connections, admission, or backend
work. Operators must therefore not advertise paid-priority guarantees yet.

The four time windows are independent. A BOLT11 offer's retained-policy grace
must cover invoice expiry + claim window + minimum credential validity. A purchase
issues exactly signed `credential_count` independent credentials; each has the
signed `credential_presentation_limit`. Only ARC may have a per-credential
presentation limit greater than one, and the pinned experimental ARC
draft-01 construction requires that limit to be at least two: limit one has
no presentation base and cannot satisfy its nonce-commitment sum check. This
is the authoritative
amount-to-entitlement mapping; the invoice amount never controls a caller-
supplied count.

BAT and ARC use coarse keyset cohorts with an absolute signed `not_after`; they
do not embed a unique per-token relative expiry. The issuer may issue only while
the cohort has at least `minimum_credential_validity_seconds` remaining. This
preserves a larger anonymity set. Direct receipts carry their own absolute
`not_after` and must provide at least the same advertised minimum.

Privacy is a signed set of admitted leakage flags, not a single optimistic
label: `IP_RATE_BUCKET`, `DIRECT_PAYMENT_TO_SPEND`,
`ISSUER_ISSUANCE_TIMING`, `ISSUER_REDEMPTION_TIMING`,
`ISSUER_LEARNS_PROVIDER`, and `PROVIDER_LOCAL_BEARER`. Validation computes the
minimum flags from acquisition + authorization + verification. An operator may
declare additional known flags, but it cannot omit a required one.

`AuthPaddingClassV1::Class16KiB` is wire value `1` and means exactly 16,384
plaintext bytes excluding outer opcode/record framing. Unknown class IDs fail
closed; callers cannot choose arbitrary lengths.

Prices are commercial policy and use explicit units:

```rust
pub enum PriceV1 {
    Free,
    MilliSatoshi(u64),
    Cashu { unit: String, amount: u64 },
}
```

The server derives all limits from its loaded signed policy. Wire values only
select an existing scope/offer.

## PIR wire messages

Four opcode values are reserved after a repository-wide collision check:

| Request | Opcode | Response | Opcode |
|---|---:|---|---:|
| `REQ_SERVICE_POLICY_V1` | `0x0d` | `RESP_SERVICE_POLICY_V1` | `0x0d` |
| `REQ_AUTH_BEGIN_V1` | `0x0e` | `RESP_AUTH_RESULT_V1` | `0x0e` |
| `REQ_POW_CHALLENGE_V1` | `0x0f` | `RESP_POW_CHALLENGE_V1` | `0x0f` |
| `REQ_HARMONY_ATTACH_V1` | `0x10` | `RESP_HARMONY_ATTACH_V1` | `0x10` |

The old `0x08` ARC and `0x09` Cashu BAT frames remain legacy demo messages and
never unlock a v1 production grant.

### Policy request

```text
REQ_SERVICE_POLICY_V1:
  current:  [version:u8 = 1]
  retained: [version:u8 = 1][selector:u8 = 1][exact_policy_digest:32]

RESP_SERVICE_POLICY_V1:
  [version:u8 = 1]
  [policy_len:u32]
  [signed_policy:policy_len]
```

The policy request may be sent only after strict server authentication and
secure-channel upgrade. The server rejects a cleartext request even if a
connection has a channel object available. The one-byte current request is
wire-identical to the original V1 request. A retained policy is returned only
for an exact non-zero digest configured by that provider; there is no
enumeration, "latest old policy", or digest-omitting historical lookup.

A retained response is redemption-only. The server verifies the same provider
and policy signing key, an epoch lower than the current policy, an exact signed
scope/offer with a provider-bound credential, and
`now <= policy.expires_at + offer.retired_policy_grace_seconds`. It also
requires the exact provider-local spent namespace to have been durably
installed while that policy was current. Retained policies never create new
quotes, Free/Open/IP grants, or PoW challenges. `AUTH_BEGIN_V1` remains bound to
the digest most recently served on that secure connection; a current/retained
request/auth mismatch fails with `PolicyChanged` before credential commit.

### Authorization request

All `AUTH_BEGIN_V1` plaintext bodies are padded to one policy-advertised frame
class before AEAD sealing. The first class is 16 KiB. A future larger class is
an explicit admitted length leak; it is not selected from a secret query
property.

```rust
pub struct AuthBeginV1 {
    pub policy_digest: [u8; 32],
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub scheme: AuthScheme,
    pub key_id: Vec<u8>,       // max 64
    pub operation: OperationStartV1,
    pub proof: Vec<u8>,        // max 12 KiB in class 1
    pub padding: Vec<u8>,      // fills exact class
}
```

The padded canonical encoding begins with `version:u8 = 1`; the in-memory
structure does not duplicate that constant. Padding is canonical all-zero
bytes so it cannot become a client-controlled tagging channel.

The executable wire-shape contract fixes the complete request record, not only
the authorization body:

```text
body                         16,384 bytes
opcode || body               16,385 bytes
0xfe || sequence || AEAD(...) 16,410 bytes
u32 length || sealed payload 16,414 bytes
```

The last number is the BitcoinPIR application record and excludes WebSocket,
TLS and lower-layer framing. Each provider receives its own independently
selected authorization request; the contract contains no peer-server or pair
identifier.

`OperationStartV1` contains only preconditions the server can cheaply validate
before spending:

```rust
pub enum OperationStartV1 {
    DpfQuery { db_id: u8 },
    HarmonyHint {
        db_id: u8,
        transport: HintTransport,
        session_token: Option<[u8; 16]>,
        primary_side: Option<HarmonyHintSideV1>,
    },
    HarmonyQuery { db_id: u8 },
    OnionSession { db_id: u8 },
    TeeOramQuery { db_id: u8 },
}
```

The response is one of:

```rust
pub enum AuthResultV1 {
    Granted {
        scope_id: ScopeId,
        enforced_profile: u16,
        expires_in_ms: u32,
        harmony_attach: Option<HarmonyAttachGrantV1>,
    },
    Rejected {
        code: AuthRejectCode,
        retry_after_ms: u32,
    },
}
```

`AUTH_BEGIN_V1` requests are the fixed 16 KiB privacy class. A network observer
without the secure-channel key cannot infer the authorization scheme, service
scope, operation variant or proof length from the request record length. It can
still observe that an authorization occurred and its traffic timing. The
provider decrypts the request and necessarily learns the selected scheme,
scope, operation, credential presentation and arrival time.

V1 result bodies are canonical but variable length, so a ciphertext observer
can distinguish response shapes such as a grant from a rejection. Padding
result bodies and traffic timing are compatible future privacy hardening; V1
makes no claim that either is hidden.

`retry_after_ms` is advisory for acquiring a new entitlement or selecting a
different provider. It never authorizes resending a spent proof.

The only supported server-side decoding path is
`bind_auth_begin_v1(request, verified_offer, trusted_catalog, arc_adapter)`.
It verifies the outer policy/scope/offer/scheme/key selectors, binds every
operation field to provider-local trusted catalog state, and selects the proof
decoder only from the signed offer. Its returned `BoundAuthAttemptV1` proves
structural and policy/catalog binding only: it is not a grant and cannot skip
method-specific cryptographic verification, online redemption, or durable
consumption. The low-level proof dispatcher is crate-private.

Public rejection codes are deliberately coarse:

| Value | Code | Consumption |
|---:|---|---|
| 1 | `UnsupportedVersion` | no |
| 2 | `UnsupportedScheme` | no |
| 3 | `ScopeUnavailable` | no |
| 4 | `WrongScope` | no |
| 5 | `InvalidOrSpent` | verifier-dependent; client assumes spent |
| 6 | `ServerBusy` | no, only if decided before spend |
| 7 | `SecureChannelRequired` | no |
| 8 | `PolicyChanged` | no |
| 9 | `InternalAfterSpend` | yes |

The response never distinguishes bad signature, unknown serial, duplicate,
wrong amount, or expired token beyond the codes necessary to avoid accidental
consumption before verification.

## Server grant state machine

```text
PRE_AUTH
  allow: announce, attest, handshake, catalog, DB proof, signed policy
  meter: at most 32 verification/preflight WebSocket messages and 16 MiB of
         actual encoded egress per connection; reserve chunk groups atomically
  deny: all paid backend work

AUTH_VERIFY
  1. require current frame encrypted
  2. match policy digest, scope, offer, key binding, operation and DB
  3. reserve/check local scarce capacity without consuming proof
  4. verify proof or perform issuer redeem
  5. durable atomic spent commit
  6. install connection-local grant
  7. return Granted

GRANTED
  allow only the entitlement profile's backend opcode DFA and counters
  reject auth for a second operation on the same connection

COMPLETE/CLOSED
  clear volatile grant; never remove durable spent state
```

The grant contains server-internal counters and no client-chosen budget. It
includes mandatory tree-top/sibling verification requests for the authorized
job. Completing verification does not create another charge.

The pre-authorization egress budget is independent of the connection timeout,
connection semaphore, frame-size cap and signed post-grant response budget.
It counts bytes after secure-channel sealing and outer framing, and counts
actual WebSocket Binary messages. A multi-chunk tree-top reserves its complete
message/byte group before sending the first chunk. Exhaustion makes the
connection terminal and cannot be reset by another opcode; `AUTH_BEGIN` itself
is excluded so a successful credential commit is never stranded merely by
charging its small result against the preflight budget.

Harmony V2 hint-half transport is one provider-local logical operation. The
first authenticated connection durably consumes once and creates a short-lived
operation bound to the existing random `session_token`; the second socket may
attach to that operation. It cannot create a second grant or extend limits.
The first side and second side are explicit, distinct values. `AuthGrantedV1`
returns a random operation ID and attach secret; `REQ_HARMONY_ATTACH_V1` repeats
the full provider/policy/scope/offer/operation/database/profile binding and is
also an exact 16 KiB encrypted body. A pending slot makes one transition only:
waiting to attached or waiting to expired. The attach secret is not a reusable
credential and is never shared with another provider.

For a proof-of-work Free offer, `REQ_POW_CHALLENGE_V1` and its response are
exact 16 KiB encrypted bodies. The challenge binds provider, policy, scope,
offer, the canonical operation digest, and
`Session::service_authorization_exporter_v1()`. Difficulty is at most 32 bits,
TTL is at most 300 seconds, and each connection has at most one outstanding
challenge. A valid solution consumes that challenge once and cannot be moved
to another secure channel.

## Proof payloads

### `free_v1`

The payload is either empty or a provider-policy-defined free ticket/PoW proof.
Its subtype is in the signed offer, not controlled by an untrusted payload tag.

### `bolt11_paid_receipt_v1`

```rust
pub struct PaidReceiptV1 {
    pub issuer_id: [u8; 32],
    pub key_id: [u8; 16],
    pub serial: [u8; 32],
    pub binding: PaidReceiptBindingV1,
    pub not_before: u64,
    pub not_after: u64,
    pub signature: [u8; 64],
}

pub struct PaidReceiptBindingV1 {
    pub scope_id: ScopeId,
    pub offer_id: u32,
    pub policy_digest: PolicyDigest,
    pub entitlement_profile: u16,
}
```

The canonical receipt encoding begins with `version:u8 = 1`. The live signed
policy delegates the direct-receipt key by `issuer_id` and `key_id`; the PIR
server's configured verifying key must derive that exact key ID. Policy signing
and receipt signing keys are never reused.

Signature domain:

```text
Ed25519.Sign(receipt_key,
  "BitcoinPIR/paid-receipt-signature/v1" || canonical_fields_without_signature)
```

Invoice, payment hash, payment preimage, payer identifier, and HTTP recovery
secret are forbidden fields.

### `cashu_ecash_v1`

The payload is a bounded canonical list of normalized NUT-00 proofs. V1 does
not carry a Cashu token envelope, mint URL, unit, witness, or DLEQ object on the
PIR wire. The accepted mint URL/issuer, unit, accepted input keysets, active
output keyset, exact amount, and scope come from the signed embedded manifest
and offer. Client-provided token metadata cannot redirect the provider to an
arbitrary mint.

Before sending inputs to the accepted mint, the provider creates and durably
stores the exact blinded outputs and their blinding secrets. It calls NUT-03
`/v1/swap`, verifies the response and DLEQ, then installs the service grant. A
lost response is recovered with NUT-09 `/v1/restore` using those same blinded
outputs. The provider must not retry spent inputs with new outputs.

The value rule includes NUT-02 input fees:

```text
gross_inputs - ceil(sum(input_fee_ppk once per input proof) / 1000)
  == signed offer price
```

V1 requires exact value and has no user-change branch. The authorization proof
codec rejects witness and proof-level `dleq.r/e/s`; those fields never cross
the PIR wire. Merely stripping `r` before forwarding would still expose it to
a provider that could collude with the mint.

### `bpir_cashu_bat_v1`

```rust
pub struct BitcoinPirCashuBatProofV1 {
    pub secret_raw: [u8; 32],
    pub c: [u8; 33],
}
```

The exact BAT key ID is the outer, policy-checked `AuthBeginV1.key_id`; it is
not duplicated inside the fixed 66-byte proof. Its provider-local spend key is
derived from `BAT_SPEND_DOMAIN`, a fingerprint of the canonical raw DHKE
verification point, and `secret_raw`. It deliberately excludes policy-,
issuer-, audience-, offer-, epoch-, and key-ID metadata. Rebinding metadata or
rotating an audience-derived key ID therefore cannot make the same bearer
secret spendable again.

The raw BAT verification point is itself exclusive to one immutable
provider/scope/offer/profile/key-epoch lineage. The provider records that
mapping permanently in `exclusive_key_lineages`; a shared issuer enforces the
same rule across every provider it serves. The two independent PIR providers
must use different raw BAT keys. A provider-local registry cannot detect a key
mistakenly reused by another provider.

The key binding supplies `scope_id`, amount 1, `unit=auth`, validity, and
entitlement profile.

The wallet verifies DLEQ during blind issuance and then presents only the
outer policy-selected key ID plus `(secret_raw, C)`. It may retain issuance evidence in a vault record
separate from the spendable proof, but a BAT presentation or shared redeem MUST NOT
contain or forward `dleq.r`; revealing the blinding scalar to the issuer
restores an issuance-to-spend link.

### `arc_v1`

The payload contains only the ARC presentation and key ID. Request context,
presentation context, fixed limit, scope, and epoch are deterministically
derived from the trusted key binding. A reviewed typed ARC adapter must decode
and re-encode the exact presentation, verify it under those fixed contexts,
and return the authoritative per-presentation tag/nullifier used for durable
consumption. Until that adapter and its persistent multi-show state are wired,
provider-local ARC admission is unsupported rather than emulated with the old
process-local seen-tag set. ARC remains `experimental` in every policy.

## Durable spend contract

Locally verified, token-backed schemes adapt to one interface:

```rust
pub trait SpendStore {
    fn spend_once(
        &self,
        namespace: SpendNamespace,
        spend_key: [u8; 32],
    ) -> Result<SpendOutcome, SpendError>;
}

pub enum SpendOutcome { Inserted, AlreadySpent }
```

The successful insert is atomic, durable before `Granted`, and survives
restart. Concurrent inserts for one key have exactly one winner. The row
contains only namespace and spend key. It has no timestamp, insertion order,
connection metadata, invoice, payment hash/preimage, payer, query address,
result, peer, or client pair ID.

Open/IP-limited Free admission is not a bearer-token spend. It uses a separate
admission transaction: Open is connection-local best effort; IP-limited mode
atomically increments a rotating keyed bucket in its signed window; PoW
atomically consumes a server challenge until its expiry. Anonymous free tickets
are token-backed and use `spend_once`. No branch invents a stable spend key for
an empty proof.

For standard Cashu NUT-03 swap and shared-issuer online redeem, the external
mint/issuer transaction is the authoritative durable spend boundary. Before
calling it, the provider persists the exact request transcript and recovery
data. An ambiguous response is recovered with NUT-09 or the issuer's
idempotent lookup using that identical request. It MUST NOT add a second local
commit whose crash boundary disagrees with the external spender.

Provider-local logs use a keyed, rotation-scoped hash of spend keys rather than
raw token serials. The durable database may contain the minimum raw hash needed
for uniqueness but is access-controlled separately from query logs.

For paid receipts the uniqueness key is derived from `(issuer_id, key_id,
serial)`, not the scope. Receipt serials are issuer-unique; reusing one serial
under another scope must collide instead of buying another spend. The
integration-safe verifier also checks the issuer-root delegation, exact
current/retained policy, binding validity, and redemption grace.

## Issuer and clearing HTTP API

All request/response bodies are versioned canonical JSON for control-plane
metadata plus base64url canonical binary blobs for cryptographic values.
Production uses HTTPS or onion HTTPS. The API never accepts a Bitcoin address
or peer-provider field.

### Offer and acquisition

```text
GET  /v1/offers/{scope_id}
POST /v1/quotes/bolt11
POST /v1/quotes/{quote_id}/status
POST /v1/quotes/{quote_id}/claim
POST /v1/mint/quote/bolt11             # NUT-04
GET  /v1/mint/quote/bolt11/{quote_id}  # NUT-04 status
POST /v1/mint/bolt11                   # NUT-04
POST /v1/arc/issue
```

Before creating an intent, the client verifies an issuer-root-signed short-lived
quote-key delegation for the expected Lightning network and payee. The
delegation key ID and digest include the exact issuer, network, payee, key
epoch, validity interval and online Ed25519 key. A durable guard per
`(issuer, network, payee)` rejects a lower epoch or a different delegation at
an already accepted epoch. The advanced guard is committed before an invoice
is displayed or paid.

`POST /v1/quotes/bolt11` carries the canonical binary
`Bolt11QuoteIntentV1`. It includes the verified provider/policy/scope/offer,
the exact delegation digest, commercial and credential terms reconstructed
from the signed offer, a random quote-creation idempotency key, and a fresh
browser-generated BIP340 x-only claim public key. The issuer never accepts a
client-selected amount or entitlement count. The signed response is a
`Bolt11QuoteV1` snapshot; a JSON HTTP wrapper, if used, transports that exact
binary value without reinterpreting its fields. A diagnostic rendering is:

```json
{
  "version": 1,
  "quote_id": "opaque-random-id",
  "invoice": "lnbc...",
  "amount_msat": 1000,
  "expires_at": 1780000000,
  "state": "unpaid"
}
```

The issuer parses the original invoice text with pinned
`lightning-invoice` 0.34.0 and cross-checks the extracted facts with the
pure-Rust `bech32`/`k256` verifier used by WASM. Parsing verifies syntax,
semantic fields and the recoverable ECDSA signature; BitcoinPIR additionally
requires an exact lowercase serialization round-trip, a fixed non-zero
millisatoshi amount, and one of Bitcoin, testnet, signet or regtest (simnet is
rejected). The parsers use an explicit `n` payee when present and otherwise
recover the payee from the signature. The opaque parsed-facts type has private
fields and no production caller-asserted constructor. The issuer checks the
invoice digest, network, payee, amount and relative expiry against the intent.
The BOLT11
creation time is assigned by the Lightning node (LND and Core Lightning do not
accept a caller-selected creation timestamp), then checked from the signed
invoice against a bounded clock policy and used to derive the exact expiry and
claim horizons before signing the snapshot. It is not part of the backend's
idempotency request, so a reserved quote can recover the same node-created
invoice after issuer restart. The delegated quote key must remain valid
through the full claim deadline; quote snapshots bind its exact root-signed
delegation digest. A client accepts a snapshot only after repeating those
invoice checks in Rust/WASM. Native builds deliberately run both parser paths
and fail if any extracted fact differs; browser builds use only the pure-Rust
verifier and never accept caller-asserted facts.

The quote-creation idempotency key maps to one immutable request body and
quote. Reusing it with different scope/offer is an error. `claim` uses a fresh,
independent idempotency key for that HTTP endpoint; it is covered by the claim
signature and must not be silently replaced by the quote-creation key. The
claim is idempotent: after payment it returns the same issuance response or
safely resumes a blind issuance transcript. A lost HTTP response does not
create extra entitlement.

Quote status is not an unauthenticated lookup by opaque ID. Each poll posts a
canonical `Bolt11QuoteStatusRequestV1`, signed with the quote's BIP340 claim
key, over the issuer, quote ID, original quote-request digest, claim public
key, current Unix time, and a fresh 32-byte nonce. The issuer first loads only
the internal verification row, checks the binding and BIP340 signature, then
atomically consumes `(quote_id, nonce)` for the bounded five-minute freshness
window before returning the invoice/status snapshot. A quote ID in an HTTP log
is therefore insufficient to retrieve private payment state.

Every signed `Bolt11QuoteV1` carries a lifecycle `state_version` and transition
time. `InvoiceOpen` starts at version 1; each committed transition increments
the version exactly once. The issuer store performs a compare-and-swap on the
expected predecessor version before signing/persisting the exact response. The
browser retains the highest verified exact snapshot in its recovery vault and
rejects lower versions, a different snapshot at the same version, or a state
that is unreachable on either the normal or late-settlement path. A status
handler never treats a browser-supplied snapshot as payment evidence, and a
claim handler loads `PaymentSettled`, `LateSettledReconcile`, or the exact
already-claimed replay from the authoritative issuer store.

`claim` carries `Bolt11QuoteClaimV1` and the exact ordered
`CredentialIssuanceRequestV1`. The latter has its own digest. The claim embeds
that digest and a new claim idempotency key, and contains a BIP340 Schnorr
signature by the quote's x-only claim key over:

```text
SHA256(
  "BitcoinPIR/bolt11-quote-claim-bip340-signature/v1"
  || canonical_v1(
       issuer_id,
       quote_id,
       quote_request_digest,
       credential_request_digest,
       claim_pubkey_xonly,
       claim_idempotency_key))
```

Direct receipt, BAT and ARC each have a distinct canonical issuance request
and response shape. A receipt response must contain the exact signed count and
globally unique serials. A BAT response echoes every ordered blinded message
and carries NUT-12 `e/s`; only the wallet's DLEQ adapter can upgrade those
tuples to usable promises, and no `r` field exists. An ARC response is only a
canonical pending-finalize tuple for the reviewed ARC adapter. Standard Cashu
issuance is deliberately excluded and continues to use NUT-04, including its
NUT-20 signature domain where applicable. These rules
prevent someone who learns an opaque paid quote ID from stealing or redirecting
issuance. The claim private key is unique per quote, is a browser recovery
secret, and is never sent to the server, PIR wire, or query history.

The quote row snapshots `scope_id`, `offer_id`, `policy_digest`, price,
entitlement profile, issuance count, receipt/keyset ID, the exact delegation
digest, and later the exact credential request/claim response bytes. A paid quote is
claimable for its advertised claim window even after a new policy epoch is
published. The PIR server retains the corresponding retired receipt policy and
verification key until every issued receipt's `not_after`; policy rotation must
not strand an already-paid entitlement.

The browser stores the quote intent, exact quote-key delegation, highest signed
quote snapshot, claim private key and recovery metadata in IndexedDB, separately
from PIR query history. Closing/reopening the page can authenticate a status
poll and claim issued credentials without storing an invoice-to-address
record. The claim private key is never exported into URL parameters, logs, or
`localStorage`.

### Online redeem

```text
POST /v1/redeems
```

Standard Cashu eCash uses the accepted mint's NUT-03 `/v1/swap` and NUT-09
`/v1/restore`; it is not sent to a BitcoinPIR-specific clearing endpoint. The
custom endpoint above is only for issuer-issued anonymous tickets, BitcoinPIR
BAT, and ARC capabilities. The canonical request carries and signs the scheme.

Each accepts exactly one service scope, proof/ticket, one random idempotency
key, provider clearing authentication, and either an account-credit request or
fixed-value blinded settlement outputs. The issuer atomically:

1. validates key binding, scope and value;
2. rejects a spent proof;
3. marks it spent;
4. records one redemption outcome;
5. credits the account or signs the permitted blinded outputs;
6. commits before responding.

Provider clearing authentication is mandatory even for blinded settlement
outputs. Otherwise the bearer-ticket holder can steal the provider's
compensation by redeeming first. The same idempotency key and request digest
returns the same response. A new idempotency key cannot redeem the same token
twice.

### Settlement

Executable ledger-only `payment-issuer` routes:

```text
POST /v1/settlement/balance
POST /v1/settlement/payout-intents
POST /v1/settlement/payouts
POST /v1/settlement/payout-status
```

The following are transport-neutral model/store surfaces only and are **not
routed by `payment-issuer`** in V1:

```text
GET  /v1/settlement/keysets
POST /v1/settlement/deposits
```

The modeled deposit is authenticated, batched, idempotent, and double-spend
safe, but serving it requires a separate retained-keyset operations ceremony
that is not enabled. This distinction also keeps the executable HTTP listener
at the smaller ledger-envelope bound rather than the deposit-only 64-note
bound. Actual Lightning payout is an operator action outside the query path
and requires separate production/funds approval in this project.

Every retained settlement Cashu keyset registry is local trusted context bound
to one `issuer_id`; a matching keyset ID from a different issuer lineage is
rejected before note verification or ledger credit. Settlement-signature keys
use a separate trusted keyring containing one current key and retained
historical keys for the same `issuer_id`. Historical payout responses are
resolved by their signed `issuer_settlement_key_id`, so rotating the current
key does not strand an in-flight payout.

Payout is intentionally two-step. The provider first requests an issuer-signed
intent that fixes account, opaque payout target ID, unit, value, fee, total
debit, expiry, and intent ID. It then signs an execution request for that exact
intent and executes that exact intent once. The issuer database must enforce
`UNIQUE(payout_intent_id)` in the same transaction that consumes the intent,
reserves/debits the account, creates the payout, and inserts one durable
outbox command; HTTP idempotency alone is insufficient.

The protocol exposes no public raw initial-payout signer. Its production API
requires a `VerifiedPayoutExecutionV1` and an issuer-store callback that commits
intent consumption, debit/reservation, payout, exact signed response, and
outbox atomically; a lost uniqueness race returns no signed success response.

Fresh status polling uses a current provider-registration key, a fresh nonce,
the exact original payout request, and the issuer-signed initial response. A
fresh nonce commits a same-state signed successor through exact-predecessor
CAS, so its signed `state_version` and `updated_at` increase. If that HTTP
response is lost, an exact retry of the request matching the durable latest
status returns the identical stored bytes, including after ordinary provider
registration expiry or provider request-key rotation; only then may the issuer
resolve the request's registration digest in its append-only local history and
verify the historical key. That history cannot authorize a successor. A
different nonce continues to require the current registration, even while the
old registration's signed validity window has not expired. Registration
history is retained indefinitely in V1 because only the latest exact status
response is stored per payout. States progress only along
`Accepted -> InFlight -> Succeeded|Failed`, and terminal states cannot reverse.
Producing a status successor likewise requires a store compare-and-swap over
the exact verified predecessor `(payout_id, request digest, ledger transaction,
state, state_version, updated_at)`. A committed issuer-side successor increments
the version by exactly one; concurrent workers cannot publish divergent
success/failure branches from the same predecessor. Polling verification may
observe a larger jump when intermediate committed snapshots were not fetched.
Recovery does not require an expired debt-creating clearing authorization.
These protocol types and a fake backend move no real funds.

## Invoice lifecycle

The payment service persists an invoice intent and deterministic Lightning
backend label before calling `AddInvoice`/equivalent, then persists the returned
invoice mapping before returning it to the browser. State is:

```text
RESERVED -> INVOICE_OPEN -> PAYMENT_SETTLED -> CREDENTIAL_CLAIMED
                         \-> EXPIRED_PENDING_RECONCILE
                               \-> LATE_SETTLED_RECONCILE
                                     \-> CREDENTIAL_CLAIMED
```

- Amount is selected exclusively from the signed offer. Amountless invoices
  are forbidden for entitlement purchases.
- Routing fee is paid by the payer and does not reduce the invoice amount.
- An invoice settled for the encoded amount is paid; underpayment cannot
  settle a fixed-amount BOLT11 invoice.
- Overpayment does not create more entitlement. It produces the same fixed
  issuance count.
- Late/expired behavior follows the Lightning backend's settled state. If a
  backend reports a genuinely settled payment, issuance occurs once even if
  the wall-clock expiry passed during notification loss.
- Payment hash and preimage stay in the payment ledger/Lightning node boundary.
  They are never copied to credentials, PIR logs, directory events, or wire.
- Notification streams use durable cursors when the Lightning backend provides
  them; startup also reconciles nonterminal quotes by lookup/polling.
- If the process dies after invoice creation but before the mapping commit,
  startup resolves the deterministic backend label and attaches the recovered
  invoice/payment hash to the pre-existing quote. A backend without stable
  create-or-lookup semantics is not production-compatible.
- Refunds are not automatic. Lightning refund is a new outgoing payment that
  needs a destination invoice and leaks another correlation edge. Product
  policy may offer manual support, but query failure does not trigger it.

## Browser vault

Credentials live in IndexedDB, indexed by:

```text
(issuer_id, provider_id, scope_id, scheme, key_id, token_id)
```

One Web Lock plus an IndexedDB transaction changes a token from `available` to
`burned` before constructing/sending `AUTH_BEGIN_V1`. ARC persists the next
nonce/tag state before send. Multi-tab races therefore have one winner.

Invoices and payment hashes are never stored in `localStorage`. The IndexedDB
quote-recovery vault necessarily contains the exact signed quote (including
its invoice), claim key and highest state version so it can verify recovery;
it is a separate object store from address/query history and credentials.
Query history contains no foreign key or stable identifier referencing quote
records. A successful claim may delete the invoice text while retaining the
minimum signed/digested recovery evidence required by product policy.
