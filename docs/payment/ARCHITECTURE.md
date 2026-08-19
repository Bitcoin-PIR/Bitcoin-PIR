# BitcoinPIR service payment architecture

Status: normative design for the first implementation. No production payment
gate may be enabled until the release gates in this document and
`SECURITY.md` pass.

## Decisions

BitcoinPIR treats payment as a provider-local service authorization problem,
not as a two-server transaction.

1. A client chooses each PIR provider independently. A provider neither knows
   nor needs to know the other provider selected by the client.
2. Every offer is for one exact service scope: provider audience, backend,
   workload role, protocol version, dataset class, operation profile, and
   entitlement profile.
3. HarmonyPIR hint and query work are separate scopes. Hint work is expected to
   cost more and may be provided by a different operator.
4. Free, direct BOLT11 receipt, standard Cashu eCash, BitcoinPIR Cashu BAT, and
   ARC are first-version authorization schemes. ARC remains `experimental`
   until an independent cryptographic review is complete.
5. Payment acquisition is separate from query authorization. A Lightning
   invoice is never a PIR credential and is never sent on the PIR wire.
6. A provider may run its own issuer or use a shared issuer/clearing service.
   A shared service verifies or redeems tickets and creates auditable provider
   settlement value.
7. The central directory is not a server, database, payment, or policy
   authorization root. It is nevertheless a centralized curation, Sybil, and
   availability boundary when the client has no independent operator pins or
   diversity source. The client verifies the live server and its live service
   policy before acquiring or presenting a credential, selects locally, and
   treats operator independence as a separate product assertion.
8. Query authorization has at-most-once consumption. There is no cross-server
   reserve, atomic commit, automatic refund, query retry, or half-credit
   restoration.
9. Payment, issuance, redemption, and settlement HTTP operations are still
   idempotent. That requirement does not imply retrying a PIR query.
10. Mandatory preflight and result verification are included in the service
    entitlement. They are never optional paid add-ons.

## Components and trust boundaries

```text
                         curated discovery only
                 +-------------------------------+
                 | Central directory / Nostr key |
                 +---------------+---------------+
                                 |
                     candidate providers/offers
                                 v
+----------------+       +-------+---------+       +----------------+
| Browser vault  |<----->| BitcoinPIR Web |<----->| Lightning wallet|
+----------------+       +--+-----+-----+--+       +-------+--------+
                          |       |     |                  |
                          |       | anonymous acquisition |
                          |       v                        v
                          |  +----+------------------------+--+
                          |  | payment / credential issuer   |
                          |  | quote, payment, mint, clearing |
                          |  +----+------------------------+--+
                          |       ^                        |
              strict     |             | strict
              verify +   |             | verify +
              encrypted  |             | encrypted
                          v             v
                    +-----+----+   +----+-----+
                    | PIR Srv A|   | PIR Srv B|
                    +-----+----+   +----+-----+
                          |             |
                 optional independent online redeem
                          |             |
                          +------+------+
                                 |
                                 v
                         issuer / clearing DB
```

There is no A-to-B edge. If both providers happen to use the same issuer, that
issuer becomes common infrastructure and can correlate redemption timing. It
still must not receive a pair ID, common query ID, Bitcoin address, result, or
PIR request contents.

### End-to-end sequence

The diagram uses one issuer for compactness. Provider 0 and provider 1 may use
different issuers or different methods; `capability 0` and `capability 1` are
independent, provider-bound objects and carry no common purchase/query ID.

```mermaid
sequenceDiagram
    participant B as Browser
    participant W as Lightning wallet
    participant I as Payment or credential issuer
    participant P0 as PIR Server 0
    participant P1 as PIR Server 1

    B->>P0: Connect and request verified bootstrap
    P0-->>B: Attestation, identity, binary, database proof, policy
    B->>B: Verify pins, secure channel, root and tree tops
    B->>P1: Connect later and request verified bootstrap
    P1-->>B: Independent attestation, identity, database proof, policy
    B->>B: Verify independently and choose exact offer per provider

    opt Provider 0 offer requires Lightning-funded issuance
        B->>I: Idempotent quote request for exact provider 0 offer
        I-->>B: Signed fixed-amount BOLT11 quote
        B->>W: Display invoice only after provider 0 verification
        W->>I: Lightning payment
        B->>I: Private-key-authenticated status or blind claim
        I-->>B: capability 0 or recoverable issuance state
        B->>B: Persist capability 0 without query history
    end

    opt Provider 1 offer requires Lightning-funded issuance
        B->>I: Independent idempotent quote for exact provider 1 offer
        I-->>B: Independent signed BOLT11 quote
        B->>W: Display provider 1 invoice
        W->>I: Independent Lightning payment
        B->>I: Private-key-authenticated status or blind claim
        I-->>B: capability 1 or recoverable issuance state
        Note over B,I: No provider-pair or common query identifier
    end

    B->>P0: Encrypted AUTH_BEGIN with capability 0
    P0->>P0: Validate exact scope; spend/redeem and claim one local grant delivery
    P0-->>B: AUTH_GRANTED
    B->>P1: Encrypted AUTH_BEGIN with capability 1
    P1->>P1: Validate exact scope; spend/redeem and claim one local grant delivery
    P1-->>B: AUTH_GRANTED

    par Independent PIR work
        B->>P0: Authorized backend request or PIR share 0
        P0-->>B: Response 0 and verification material
    and
        B->>P1: Authorized backend request or PIR share 1
        P1-->>B: Response 1 and verification material
    end
    B->>B: Combine and verify inclusion or Merkle result
    B-xP0: Disconnect
    B-xP1: Disconnect
```

## Identity and key separation

The following keys have different compromise and rotation domains and must not
be reused:

- offline operator Ed25519 key: certifies stable provider/server identity;
- online server identity key: signs the boot channel manifest and live service
  policy;
- directory Nostr secp256k1 key: publishes the curated provider list;
- Lightning node keys/macaroons or RPC credentials;
- issuer/mint signing keys, separated by scheme and keyset;
- online quote-response key, delegated by the offline issuer root;
- direct-receipt signing key;
- settlement-credit mint key;
- provider clearing authentication key or mTLS identity;
- per-provider shared-redeem idempotency HMAC secret, never shared with another
  provider or the issuer;
- provider settlement-wallet keys.

The stable provider audience is:

```text
provider_id = SHA256(
  "BitcoinPIR/provider-id/v1"
  || operator_ed25519_pubkey
  || u32le(len(stable_server_id_utf8))
  || stable_server_id_utf8
)
```

URLs, IP addresses, client ordering (`server 0` versus `server 1`), and peer
identity are deliberately absent.

## Service scopes

`scope_id` is the SHA-256 of the canonical `ServiceScopeV1` encoding. The
canonical structure is defined in `PROTOCOL.md`.

First-version workload identifiers are:

| Workload | Entitlement unit | Notes |
|---|---|---|
| `dpf_evaluate_job_v1` | one bounded logical DPF query job | A DPF share is symmetric; no client slot is encoded. |
| `harmony_hint_bundle_v1` | one complete, bounded hint bundle | Includes INDEX, CHUNK, sibling hints, and the declared V2 capacity. |
| `harmony_query_job_v1` | one bounded logical Harmony query job | Assumes a locally cached compatible hint. |
| `onion_evaluate_job_v1` | one bounded OnionPIR session | Includes key registration, query phases, and mandatory Merkle work. |
| `tee_oram_query_v1` | one bounded encrypted ORAM job | Optional policy entry; never a fallback from PIR. |

For `dpf_evaluate_job_v1`, one logical input means one admitted, privacy-padded
INDEX batch job. The public K INDEX groups are padding/work units, not K user
inputs. CHUNK and PIR-evaluated Merkle-sibling frames add no logical input, but
are accepted only after an INDEX job and continue to consume the exact signed
frame, byte, response, wall-time, and work-unit budgets. A later INDEX batch
starts another logical job only while the DFA is still in its consecutive
INDEX phase and is rejected terminally when `max_logical_inputs` is already
exhausted. Once any CHUNK or Merkle follow-up is admitted, INDEX rollback is
forbidden.

Harmony pricing/accounting uses a padded INDEX pair as its logical unit, not an
address and not the public `K*(T-1)` index count. The strict V1 query connection
accepts only batch opcode `0x43` and walks level 0 pair(s), level 1 pair(s),
then level 10+/20+ Merkle work without rollback. A PBC plan requiring multiple
INDEX pairs (for example a large `N > K` batch) therefore needs a higher signed
round profile; it cannot silently fit inside a one-job capability. The current
strict secure-channel client closes optional secondary query sockets, so this
profile is deliberately single-socket. Legacy unpadded `0x42` is not a paid V1
fallback.

An Onion logical input is one padded INDEX ciphertext frame. Registration,
CHUNK, and both Merkle families add no logical input but remain bounded by
their actual ciphertext/work/byte/frame budgets. The server admits exactly one
registration followed by monotonic INDEX -> CHUNK -> Merkle INDEX -> Merkle
DATA phases. LRU key eviction is a failed session, not authority to register or
replay automatically on the already-spent grant.

For a warm Harmony cache no hint capability is presented. For a cold cache,
one V2Full hint capability authorizes the main INDEX+CHUNK bundle and the same
connection's bounded, full-group legacy level-10+/20+ sibling-hint sequence.
The main response does not complete the grant. V2Half remains a separate
two-socket operation. Fixture capacity for these deterministic flows is an
integration bound, not a quoted commercial price; production policies must be
derived from the deployed database's sibling depths and response sizes.

V2Full is not restricted by the wire protocol to the main database: its
canonical request carries an optional non-zero `db_id`. Each pool remains bound
to one loaded immutable database and one private pool directory. The legacy
single-pool form uses `--pool-db-id` (default `0`); a complete provider may
instead repeat `--harmony-pool-db <db_id>=<pool-dir>` to install an explicit
in-process map. Admission and dispatch look up the authenticated database ID,
and a V2Half token retains the database selected by its first half. The
authorized client must use V2Full for the granted database and must not
downgrade a committed grant to V1 if that exact pool becomes unavailable.

V2Full capacity is connection-bound before spend. After the untrusted request
is structurally bound to the current signed offer and local database, the
provider atomically reserves one pool entry, then verifies/redeems and commits
the credential. Empty capacity is a non-consuming `ServerBusy`. Rejection or a
disconnect before main-hint dispatch returns the still-unexposed entry; main
dispatch consumes it permanently. The in-memory reservation handle is local to
one connection, not a wire identifier or an external reservation service; its
advisory inode lock is nevertheless visible to every conforming process sharing
the pool. Online-authority V2Full first acquires its narrower class permit and
then the global AUTH permit. A grant transfers the class permit into the pending
reservation until dispatch, disconnect or its post-grant deadline. That
deadline is armed only after the complete encrypted `AUTH_GRANTED_V1` frame has
been written and flushed, so a slow successful grant flush does not spend the
client's dispatch window. Once armed, the 30-second-or-shorter absolute instant
is immutable: every pending read and Ping/Pong write is bounded by the same
instant and no control or application frame can reset it. Apart from bounded
WebSocket control handling, the only accepted application frame while the
reservation is pending is the exact encrypted canonical `HarmonyHintsV2`
request for the database bound into the grant; a cleartext, malformed,
wrong-database or unrelated application frame closes the connection and drops
the unexposed reservation.

Under the shared capacity lock, an online reservation counts only **currently
lockable** ready paths that are already present in that process's fully
validated, ready `PoolState` snapshot. A canonical-looking file discovered only
on disk, including corrupt or not-yet-validated surplus, cannot satisfy the
floor. The hot path uses a non-blocking capacity-lock attempt; contention is a
non-consuming overload result rather than a Tokio worker blocked on `flock`.
If the selected ready inode is already locked by a peer process, it is rotated
to the back and the bounded current snapshot is examined for another validated
candidate, preventing a locked queue head from hiding usable capacity.

Each successful online reservation leaves at least one such validated,
currently lockable entry at that atomic decision point for provider-local
methods, even while the target pool is partially filled. This is only an
online-consumption floor: it neither reserves that last entry for a particular
provider-local caller nor guarantees fairness, priority or immediate admission.
No reservation ID leaves the filesystem boundary.

An entitlement profile fixes all resource limits used by the server state
machine: maximum logical inputs, padded rounds, bytes, frames, hint groups,
concurrent sockets, wall-clock lifetime, and backend-specific CPU/memory
limits. Client-provided amounts, limits, priority, or profile descriptions are
not authoritative.

Dataset binding supports three explicit modes:

- `class`: valid for a signed dataset class such as verified mainnet UTXO
  snapshots and compatible deltas;
- `catalog_epoch`: valid only while the signed policy epoch is active;
- `manifest_root`: valid only for one exact verified manifest root.

An offer must state its mode. The initial operator policy should normally use
`class` for query credentials that should survive routine database refreshes,
and `manifest_root` or `catalog_epoch` for expensive Harmony hint bundles.

## Offer model

A service scope can advertise more than one `ServiceOfferV1`:

```text
acquisition:
  free | bolt11 | cashu_ecash

authorization:
  free_grant | paid_receipt | cashu_ecash | cashu_bat | arc_presentation

verification/settlement:
  provider_local | shared_issuer_online | standard_cashu_mint_online
```

These axes must not be collapsed into one ambiguous `payment_method` string.
For example, one BOLT11 acquisition may issue either a linkable direct
receipt, a batch of single-use Cashu BATs, or a multi-presentation ARC
credential. BAT and ARC are authorization outputs, not additional acquisition
methods.

Commercial policy is data, not protocol logic. Prices, free quotas, priority,
issuer fees, and settlement shares appear in signed policy entries. The
protocol only enforces the selected scope and entitlement.

## Scheme behavior

### Free

`free_v1` creates the same connection-local service grant as paid methods.
Provider policy may choose open best-effort, an IP-derived bucket, proof of
work, or an issuer-issued anonymous free ticket. The policy must declare its
privacy class. IP quota is functional but not anonymous.

The exact choice is the signed `FreeModeV1` field. A proof payload cannot
select or upgrade the mode.

IP-limited offers sign the grant count and window (for example, per minute or
per hour); PoW offers sign the difficulty target; anonymous-ticket quotas are
bound by the issuer/keyset. Every offer also names a provider-local opaque
priority class. In Payment V1 this class is signed and displayed but is not yet
enforced by the current server scheduler; it must not be presented as a paid
quality-of-service guarantee.

Free traffic cannot silently receive a paid entitlement profile. A busy server
may reject free acquisition before credential consumption. A future scheduler
may map the signed class to provider-local service levels, but it must make its
capacity decision before consuming a credential; that scheduler is outside the
current V1 implementation.

### Direct BOLT11 receipt

The provider's payment service creates a fixed-amount BOLT11 invoice bound in
its private ledger to one `scope_id`, `offer_id`, `policy_digest`, entitlement
profile, and issuance count.
After settlement it signs one or more `PaidReceiptV1` values.

The receipt contains a random serial, scope, offer, policy digest, profile,
validity interval, key ID, and signature. It contains no invoice string,
payment hash, or preimage.
The provider can nevertheless link its own receipt serial to the invoice in
its ledger. The policy labels this method `linkability = provider_payment`.

The browser binds quote ownership to a fresh claim key and signs every claim;
learning a paid quote ID is not sufficient to steal issuance. The live policy
delegates a separate receipt-signing key. An issuer-root-signed quote-key
delegation fixes the Lightning network, payee, epoch, validity window and
online response key; the quote intent commits its exact digest. A durable
per-issuer/network/payee rollback guard is advanced before displaying an
invoice. Paid quote claim windows and issued
receipt lifetimes survive routine policy rotation through an explicit retained
policy/key grace window.

### Standard Cashu eCash

The browser sends standard Cashu proofs from a mint explicitly accepted by the
offer. Underpayment is rejected; a backend-reported overpayment purchases only
the exact fixed entitlement committed by the offer. A receiver prevents double
spend by swapping/redeeming with the mint. A provider-local spent cache is not
a substitute for mint redemption when the same eCash is accepted elsewhere.

The provider-signed Cashu manifest binds the canonical mint endpoint and one or
two sorted, distinct, nonzero leaf-SPKI SHA-256 pins as well as the accepted
keysets and unit. Every NUT request derives its complete transport trust tuple
from that already verified manifest: ordinary WebPKI chain, hostname and time
validation must pass and the leaf must match a signed pin. There is no global
endpoint/pin override, TOFU, pin-only mode or unpinned fallback. Two pins allow
a bounded signed rotation; an old policy or custody artifact without this trust
tuple fails closed rather than silently inheriting ambient transport settings.

The provider must generate and durably save the blinding secrets and blinded
outputs before it submits the user's proofs to the mint's NUT-03 swap. It grants
service only after the mint invalidates the inputs and returns valid signatures
for those outputs. If the swap response is lost, the provider recovers the
same outputs with NUT-09; it must never replay the inputs with new outputs.
NUT-02 input fees are included in the exact-value calculation. A wallet token
may contain the known NUT-12 `dleq.e/s/r` metadata used for wallet recovery.
The browser accepts only that bounded known shape and first verifies the
NUT-12 `e/s/r` proof against the signed manifest denomination key and the
proof's exact `secret` and `C`. It then strips all DLEQ material locally and
emits a canonical `StandardCashuSpendV1`; an invalid proof, unknown field,
witness or NUT-10 condition fails closed. The PIR server decoder therefore
never receives `dleq.r` or any proof-level DLEQ value. Forwarding that material
would let a provider collude with the mint to link issuance to spend.

The provider stores two separately authenticated ciphertext domains. Recovery
custody contains the exact NUT-03/NUT-09 request, output secrets and blindings;
note custody contains only provider-created received notes and the minimum
mint/keyset metadata needed to move them into an external wallet. A finite cap
per exact mint/unit limits unresolved value and note count before NUT-03. Grant
issuance and note-custody insertion are one rollback-anchored transaction.

Offline export reserves a bounded cohort, persists one immutable artifact
bound to a provider-specific recipient key, and only then releases its bytes.
The encrypted artifact contains a canonical standard `cashuB` token with no
BitcoinPIR identifier, memo or DLEQ metadata. An explicit acknowledgement says
only that an external wallet took custody and does not release local exposure.
Only a later owner-initiated, exact all-`SPENT` NUT-07 confirmation releases
that exposure. The state check is one bounded same-mint/unit operation outside
the PIR query path; every export gets independent digest-only evidence, and no
raw `Y`, witness or wider HTTP-batch identifier is persisted. Neither ACK nor
spent confirmation proves a NUT-05 melt, Lightning settlement or provider
payout.

This is a merchant use of standard Cashu eCash and remains distinct from Cashu
BAT. First-version offers require exact value after input fees and do not
support merchant-generated change outputs for the client.

### BitcoinPIR Cashu BAT

`bpir_cashu_bat_v1` is a single-operation capability derived from the Cashu
NUT-22 blind-auth shape. It uses `unit=auth`, amount 1, a keyset bound to one
scope/profile, and issuance-time DLEQ verification.

BitcoinPIR consumes a BAT when durable authorization succeeds, before the
expensive query runs. That differs from NUT-22's mint-API error-consumption
guidance and is therefore named as a BitcoinPIR protocol rather than claimed
as an unmodified NUT-22 implementation.

Provider-specific public keysets allow private-key verification by a provider's
own issuer sidecar. A shared issuer is shared infrastructure only: v1 still
requires a distinct raw DHKE key for every `(provider_id, scope_id, offer_id,
entitlement_profile, epoch)`. One V1 signing keyset MUST NOT span provider
audiences; doing so would make a V1 blind BAT transferable across providers or
require an issuance-to-proof mapping that destroys blind issuance.

The durable BAT spend key uses the raw DHKE public-key fingerprint and token
secret, not the audience-derived key ID. Both the provider store and shared
issuer retain a permanent raw-key lineage registry so policy/key-ID rebinding
cannot reset the spent namespace. This does not replace the requirement that
the two independent PIR providers use different raw keys.

Issuer-wide BAT V2 does not weaken or reinterpret that V1 rule. It uses a new
scheme value and a separate issuer-signed acceptance-class artifact. Provider
policies commit only a stable class ID; the later artifact commits one fresh
raw-key epoch, identical commercial/entitlement terms, and the canonical exact
provider-policy members allowed to receive that credential. The raw key may be
shared only inside that signed member set. A member or policy rotation uses a
fresh raw key/epoch and retains the old artifact; different terms use a new
class ID. The class codec/policy shape and issuer-store v6 registry are the only
implemented V2 components at this stage. They prevent V1/V2 raw-key rebinding
and class rollback, but do not yet expose V2 acquisition, redemption or
provider admission.

V1 does not send Cashu DLEQ blinding material to a provider for public-key-only
offline verification and later batch redemption. Although such a receiver can
verify a NUT-12 transcript, a malicious or compromised provider could forward
the linking material to the issuer. Shared-provider settlement therefore uses
online issuer redeem without DLEQ, followed by optionally blind and delayed
settlement-note deposit.

### ARC

One ARC credential can authorize several operations through unlinkable
presentations, up to a fixed issuer-chosen limit. Each keyset is bound to one
scope, profile, epoch, and presentation limit. The server ignores any client
claim about the limit or context.

For a provider-local issuer, the provider can verify and persist authoritative
presentation tags only through the reviewed typed ARC adapter and durable
multi-show store; the existing process-local demo set is not production state.
For a shared issuer, ARC verification is online because the current ARC
construction requires issuer secret material. Shared-issuer verification must
not copy the shared private key into providers.

ARC is experimental. Production policy must not advertise it without an
explicit experimental flag, and clients must show that status.

## Shared issuer and provider settlement

The clearing API has two settlement modes.

### Identified online credit

The provider authenticates each redemption. The issuer atomically marks the
ticket spent and credits the provider account. This is simplest and is a
supported compatibility mode, but the issuer learns provider, scope, token,
and exact query-time redemption.

### Authenticated blind settlement credit

The ledger-unlinkability mode is:

```text
provider                                       shared issuer
   | authenticated redeem + ticket/tag + blinded     |
   | fixed-value outputs                              |
   |------------------------------------------------>|
   | verify + atomic spent commit + blind signatures |
   |<------------------------------------------------|
   | unblind and durably store settlement notes      |
   |                                                 |
   | delayed/batched authenticated deposit           |
   |------------------------------------------------>|
   | credit provider account; mark notes spent       |
```

The online request is authenticated with a registered provider clearing key or
mTLS identity. Authentication is mandatory: without it, the client that owns a
bearer ticket could redeem first and direct the provider compensation to its
own blinded outputs. The issuer therefore learns the provider, scope, token,
and redemption time in the first version.

The operator-signed provider clearing authorization also binds the exact
canonical issuer redeem origin and one or two sorted, distinct, nonzero
leaf-SPKI SHA-256 pins. The provider appends only the fixed `/v1/redeems` path
and requires both ordinary WebPKI and a signed pin on every request. Endpoint
or certificate rotation therefore requires an authenticated authorization
rotation; process-wide URL or pin configuration cannot retarget redemption.

Shared redeem has two deliberately different at-most-once layers. The issuer's
atomic redeem is authoritative for credential validity and settlement. The
provider derives the wire `idempotency_key` deterministically with a
provider-local secret HMAC over the exact clearing authorization digest,
credential binding digest and credential digest. An exact retry therefore asks
the issuer for the same signed success bytes; a changed credential or binding
cannot alias it. The issuer does not receive that HMAC secret.

Only after canonical response parsing, signature verification and an exact
request/offer match does the provider derive a second, domain-separated HMAC
key from the verified redeem coordinates and claim it in the provider's own
rollback-protected `ProviderStore` synthetic namespace (`0x8001`). This is a
local **grant-delivery claim**, not a credential nullifier or a second economic
redeem. The first claim may issue `AUTH_GRANTED`; an exact issuer replay reaches
`InvalidOrSpent` locally and cannot issue a second grant. Provider 0 and
provider 1 use separate secrets and stores and never share this claim set.

Three private/keyed objects must not be conflated:

- the browser's quote-claim private key authenticates quote status/claim and is
  never stored by a provider;
- the provider-to-issuer wire idempotency key identifies the exact redeem
  transcript; and
- the provider-local delivery key/digest gates one local grant and may appear
  only in the minimal `spent_capabilities` row for the synthetic namespace.

The provider stores no invoice, payment hash, preimage, raw credential, browser
claim key or exact token timestamp in that spent row. The issuer cannot derive
the local delivery key and participating providers cannot compare it.

If the provider loses the issuer HTTP response after possible commit, only a
low-level caller that explicitly retained the identical proof may resend the
same deterministic transcript and verify the issuer's exact signed replay. The
official Web flow deletes/burns the presentation before sending it and performs
no automatic shared-redeem retry. If local delivery has committed but the
encrypted `AUTH_GRANTED` frame is lost, the entitlement remains consumed; V1
does not reconstruct a query grant on a new connection.

The settlement notes are still blindly signed. That prevents a direct database
join from their later deposited serials back to the original ticket and allows
safe delayed/batched deposit, but it does **not** hide the provider at online
redeem. Tor, OHTTP, or common ingress can hide network origin from parts of the
path, but not provider identity from an issuer that verifies the clearing
signature. Hiding that identity would require an additional anonymous member
credential or a zero-knowledge proof of provider-bound output ownership and is
outside v1.

Every entitlement maps to fixed settlement denominations. The issuer's atomic
transaction conserves value:

```text
accepted ticket value = provider credit + issuer fee
```

`accepted ticket value` is the clearing rule's economic value. It is independent
of the credential binding's protocol `amount` field: for example a BAT may carry
the fixed auth amount `1` while its clearing rule accepts value `10` and splits
that into provider credit `9` plus issuer fee `1`. Code and policy must verify
both facts independently; neither may be inferred from the other.

Blind settlement rules are countersigned by the issuer and commit to one exact
Cashu keyset: unit, zero input fee, expiry, denomination public keys, and
keyset ID. The provider includes that ID and canonically ordered blinded
outputs in its signed redeem request, so the issuer cannot switch keysets after
seeing the blinded messages.

The provider accepts returned blind promises only after a Cashu adapter verifies
NUT-12 over the exact denomination public key, `B_`, `C_`, `e` and `s`. The
provider persists the unblinded notes before serving. A later deposit is
authenticated under a current provider registration and verified against an
independently retained, unexpired settlement keyset; it does not require the
old debt-creating clearing authorization to remain current. The issuer's Cashu
adapter derives authoritative `Y` values, and a global denomination-key-plus-Y
spent key is inserted atomically with the provider credit.

The retained keyset registry is explicitly bound to the issuer/root lineage;
the same keyset ID copied from another issuer is never sufficient. Issuer
settlement-signature rotation uses a trusted current-plus-retained keyring
indexed by the key ID inside each signed response. A historical initial payout
response may therefore remain verifiable while all new responses use the
current registration key.

Those retained registries are issuer/ledger recovery mechanisms, not a
provider-runtime retained-authorization mechanism. V1
`SharedIssuerAdmissionCommitterV1` loads one clearing authorization, approval
key and issuer settlement key. A provider-side redeem that is still pending
when one of those bindings rotates has no automatic retained-key recovery path;
operators must drain or explicitly reconcile it before rotation.

Payouts remain outside the query path. A signed payout intent is consumed once
under a database uniqueness constraint in the same transaction as account
reserve/debit, payout creation and durable outbox insertion. Status recovery
binds the exact initial signed response and advances a monotonic signed state
version to an irreversible terminal state. Both initial success signing and
status-successor signing are coupled to issuer-store commit interfaces; status
commit uses an exact-predecessor compare-and-swap, so two workers cannot commit
different terminal branches from the same state version.

The issuer may learn scope and redemption time. It never receives the Bitcoin
address, PIR shares, result, peer identity, or a cross-provider operation ID.

This is a no-explicit-pair-ID guarantee, not anonymity against the shared
issuer. It can observe provider, scope, client/network metadata, and sparse
purchase/redemption timing and may infer that independent events share a user.
Browser flows therefore use no issuer account, cookie, or reusable HTTP
session; they prefer independent anonymous ingress and acquire standard bundles
ahead of queries. These reduce inference but do not recreate the two-server
non-collusion guarantee against common infrastructure.

## Two-provider behavior

The client may find one provider and later find the second. It independently
selects an accepted method for each. Examples include:

- provider A free, provider B direct Lightning;
- provider A Cashu eCash, provider B ARC;
- Harmony hint from provider H and Harmony query from provider Q.

BitcoinPIR receipts, BATs, ARC presentations, and anonymous free tickets are
provider-specific. A single such capability is never submitted to both
providers, and no credential is derived into a correlated A/B pair. Standard
Cashu eCash is intentionally transferable money rather than a provider-bound
capability; the wallet atomically selects it for one provider, and the mint's
global spent state rejects reuse. Neither case adds a pair identifier.

As a local safety check, the client rejects two selected providers whose
strictly verified policies expose the same raw BAT or ARC verification-key
fingerprint. Both raw-key comparisons happen before any explicit shared-issuer
override is considered. The comparison stays entirely in the client; neither
provider, issuer, nor directory receives the selected peer or a pair
identifier.

The same local check rejects a shared issuer/origin and a shared Lightning
payee by default. These are separate explicit acknowledgements in the native
API. The Web product combines them into one clearly labelled, in-memory-only,
single-attempt consent for users who deliberately select a pooled issuer. Even
then, provider origins and provider-specific policy, operator, receipt, BAT and
ARC keys must remain distinct.

The Web trusted bootstrap does not contain a provider-wide Lightning payee.
Each provider instead has a bounded `lightningPayeeTrust` array. Every entry
binds an exact signed-offer issuer identity, credential-free canonical HTTPS
issuer origin, Lightning network and compressed payee identity:

```json
{
  "lightningPayeeTrust": [{
    "issuerIdHex": "<64 lowercase hex>",
    "issuerOrigin": "https://issuer.example",
    "network": "signet",
    "expectedPayeePubkeyHex": "<02 or 03 followed by 64 lowercase hex>"
  }]
}
```

The issuer origin above is taken from the exact signed `ServiceOfferViewV1`;
it is not the provider's independent `wss://` PIR endpoint. Duplicate
`(issuerIdHex, canonical issuerOrigin, network)` tuples are rejected even when
they repeat the same payee. A non-BOLT11 offer receives no payee context. A
BOLT11 offer with zero or more than one exact trust match fails before invoice
acquisition or capability retirement.

If the client reaches only one provider, any capability already durably spent
there remains spent. The product deliberately provides no automatic recovery
or refund. The UI should acquire/present as late as possible and explain this
at-most-once policy before a paid method is selected.

Rejecting an identical issuer ID, origin, provider key, or directory operator
key catches visible reuse; accepting different values is not proof that the
operators are independent. The same organization can run multiple keys and
domains. Strong diversity claims must come from a separately authenticated
operator-group assertion or an explicit user trust decision, not inference from
cryptographic identifiers.

## Strict query ordering

For each provider, the required order is:

1. connect;
2. verify runtime attestation, operator identity, and binary pin;
3. complete the secure-channel upgrade;
4. fetch and verify the database proof;
5. verify the production root pin and live service policy;
6. run the non-consuming, cheap readiness check and fetch/verify reusable
   Merkle tree tops when that backend exposes them before authorization;
7. prepare or acquire an anonymous capability;
8. send an encrypted `AUTH_BEGIN_V1` for a concrete operation header;
9. after `AUTH_GRANTED_V1`, issue only the opcodes allowed by the grant's
   backend state machine. A pending Harmony V2Full hint reservation is stricter:
   all independent preflight is already complete, and the next application
   frame must be the exact encrypted bound-database `HarmonyHintsV2` main
   dispatch before its immutable post-flush deadline;
10. verify inclusion/Merkle results automatically;
11. close the connection(s).

Clients must not pay a direct provider before steps 2-6 succeed. Readiness is
coarse and non-reserving: it reduces avoidable paid failures but is not a
capacity promise and creates no retry/refund right. A previously
acquired issuer token may be prepared earlier, but it must not be presented to
an unverified server. Payment-service failure or unsupported policy fails
closed; strict mode never falls back to an unverified or plaintext query.

The server validates cheap operation preconditions before the durable spend:
scope active, database present, profile allowed, backend mode enabled, and any
scarce Harmony hint capacity available. It then verifies and durably spends
the proof before returning a grant. A failure after that commit consumes the
entitlement by design.

## Directory publication

The first directory can be centralized. It publishes NIP-01 signed,
NIP-78 `kind:30078` addressable events using a dedicated Nostr key. The `d` tag
is `bitcoinpir-service-directory-v1:<provider_id-hex>`; content is canonical
JSON containing endpoint hints, operator identity fingerprint, last observed
policy digest, policy epoch, monotonic directory sequence, validity deadline,
active/tombstone status, and health metadata. Endpoint and policy assertions
also carry an inner operator signature; the outer Nostr event signature proves
what the directory published, not what the provider authorized.

The V1 profile permits only the canonical `d` and coarse-shard `s` tags. Every
logical sequence/checkpoint advance must also advance NIP-01 `created_at`, and
the client uses a shard only after its complete verified entry-event set exactly
matches the signed checkpoint. Arbitrary tags are rejected so the directory
wire shape has nowhere to carry an invoice, payment hash, credential, selected
peer, or pair identifier.

Directory data is untrusted authorization input. The client must compare the
discovered identity and policy digest with the live, strictly verified server.
A mismatch is a hard error, not a warning or fallback. When no independent
operator pin or diversity source exists, the directory still controls which
candidates the client sees and can mount a Sybil or split-view selection
attack. Live verification does not prove that two differently keyed providers
are independently controlled. The same limitation applies to issuer IDs and
origins: one operator can rotate keys and domains, so unequal metadata removes
an obvious join but is not evidence of independent administration.

Clients fetch a complete or coarse-sharded catalog and select providers and
payment methods locally. They do not ask the directory for a specific pair,
backend, address, or method at query time. A client keeps the highest sequence
seen for each `(directory key, provider_id)`, rejects expired/lower-sequence
events, and honors signed tombstones. Manual endpoint import with an operator
fingerprint remains a supported escape hatch from directory availability.
Clients compare signed catalog checkpoints across configured relays and retain
same-sequence forks as evidence; a single directory/relay view cannot itself
establish provider independence. The exact envelope and rollback rules are in
`DIRECTORY_PROTOCOL.md`.

## Deployment shape

The monorepo owns the protocol, SDK integration, server gate, Web wallet, test
harness, and deployment contracts. Payment/issuer functionality is a separate
binary and process so Lightning and mint secrets are not present in the PIR
server. A later repository split is allowed only after the API, version pin,
offline dependency snapshot, and cross-repository test contract are stable.

`apps/dev-issuer` remains a free demo and compatibility fixture. It is not
renamed into or used as the production payment service.

## External standards used

- BOLT11 invoice encoding and fixed amounts:
  <https://github.com/lightning/bolts/blob/master/11-payment-encoding.md>
  The implementation pins `lightning-invoice` 0.34.0 and
  `lightning-types` 0.3.1 with default features disabled; both source archives
  and Cargo checksums are vendored for offline native builds. Native parsing is
  cross-checked against the pure-Rust `bech32`/`k256` verifier used on wasm.
  The opaque verified-facts type remains unconstructible by callers on both
  targets; direct BOLT11 therefore cannot fall back to asserted invoice facts.
- Cashu proof and token model:
  <https://github.com/cashubtc/nuts/blob/main/00.md>
- Cashu swap: <https://github.com/cashubtc/nuts/blob/main/03.md>
- Cashu keysets and input fees:
  <https://github.com/cashubtc/nuts/blob/main/02.md>
- Cashu interrupted-swap recovery:
  <https://github.com/cashubtc/nuts/blob/main/09.md>
- Cashu Lightning mint quotes:
  <https://github.com/cashubtc/nuts/blob/main/04.md>
- Cashu DLEQ: <https://github.com/cashubtc/nuts/blob/main/12.md>
- Cashu blind-auth tokens:
  <https://github.com/cashubtc/nuts/blob/main/22.md>
- Cashu quote request signatures:
  <https://github.com/cashubtc/nuts/blob/main/20.md>
- Nostr base events: <https://github.com/nostr-protocol/nips/blob/master/01.md>
- Nostr application-specific addressable data:
  <https://github.com/nostr-protocol/nips/blob/master/78.md>
