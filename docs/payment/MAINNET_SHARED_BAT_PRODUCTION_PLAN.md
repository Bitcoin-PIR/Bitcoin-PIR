# Mainnet issuer-wide BAT production plan

Status: **issuer-wide product contract revised on 2026-08-18; pir2 sealed-key
contract selected on 2026-08-19; protocol and production profiles not yet
source-ready; no production activation is authorized**. The
earlier unmerged draft implemented a shared issuer with provider-specific BATs,
twelve raw BAT key lineages and provider-side payment stores. That shape is
superseded by this plan and must not be rendered or activated. The independent
pir1 Harmony db0/db1 multi-pool slice has been reviewed and re-landed without
the superseded payment profile.

This is the ordered source-to-production plan. It does not authorize rendering
private inputs, installing files on a host, building or switching a VPSBG UKI,
publishing the Web client or directory, creating an invoice, moving funds, or
starting a production service.

## Approved product contract

The production query product supports db0 and db1 across all four backends.
Every provider scope offers exactly:

1. provider-local Free proof of work; and
2. a blinded BitcoinPIR Cashu BAT acquired from the shared online issuer.

A BAT is an issuer-wide bearer credential, not a provider-owned credential. A
credential in one reviewed acceptance class may be presented to any provider
offer listed by that class. The provider and exact scope are selected at
redemption rather than permanently fixed at issuance.

The issuer is the sole durable BAT spend and settlement authority. The first
successful issuer commit consumes one BAT globally, regardless of which
provider wins. Every later presentation of that credential, including at
another provider, is invalid or spent. A request that needs two paid provider
legs uses two independent BATs; one BAT is never a pair entitlement and is not
independently spendable once per provider.

Different prices or entitlement shapes use different acceptance classes. A
class fixes its BAT-relevant commercial terms and exact eligible provider
offers. Its raw BAT key lineage is scoped to the issuer, acceptance class and
key epoch, not to one provider or scope. A raw key may be shared only among
members of that one class, whose price, credential count, validity and
entitlement shape must agree. It must not be reused across classes. The exact
number of production key lineages therefore follows the reviewed class set; it
is not hard-coded as twelve.

BOLT11 is the issuer-side acquisition mechanism for BAT. It is not a separate
provider entitlement. A PIR provider must not receive the invoice, payment
hash, preimage, payer route, payer identity or quote-claim secret. Direct
BOLT11 receipts, Standard Cashu and experimental ARC are excluded from this
production profile. Their generic protocol/test code may remain, but no
retained or current production policy may advertise them.

The provider coverage remains:

| Provider | Production workloads | Databases | Public service role |
| --- | --- | --- | --- |
| pir1 | DPF evaluate, Harmony hint, Onion evaluate | db0 + db1 | ordinary provider on the approved Hetzner application host |
| pir2 | DPF evaluate, Harmony query, Direct TEE-ORAM | db0 + db1 | measured VPSBG provider |

The two providers retain distinct service identities, signed policies,
database roots and live admission sessions. They do not retain independent BAT
spent sets or durable delivery ledgers. The closed pir1 and pir2 BAT paths have
no payment ProviderStore, provider-side shared-redeem idempotency secret, local
delivery-claim table or provider payment rollback-authority client. Any
unrelated runtime state must be named separately and must not be described as
BAT authority.

Only the issuer retains durable payment state: quote/claim state, global BAT
spend history, redemption outcomes, provider credit and its rollback floor.
The issuer must know the selected provider before crediting it, but that
authentication is separate from BAT validity. pir1 keeps its ordinary-host
provider authentication credential. pir2 keeps a long-lived clearing signing
credential so the issuer can authenticate the stable pir2 accounting
relationship. It is not a BAT spend key and creates no pir2 payment database.

The current client and directory contract also keeps pir2's long-lived service
identity signing key. The clearing and service-identity seeds are distinct
roles and MUST NOT be the same key. They are stored together only as fields in
one measurement-bound sealed envelope described below. pir2 never holds a BAT
mint key, issuer settlement private key, Lightning secret, policy-signing key
or operator-signing key.

One approved Hetzner application server may co-locate pir1, the issuer,
directory relay and public edge in the explicitly centralized deployment mode.
Co-location does not merge their service identities or filesystem ownership.
The issuer's rollback-protected store is the only BAT spend domain; pir2 has no
payment rollback domain. No public or warm-fallback port 8092 is part of this
topology: the expected private listeners remain pir1 on `127.0.0.1:8191`, the
issuer on `127.0.0.1:5610`, and VPSBG on port 8091 behind its approved edge.

## pir2 persistent-disk and sealed-key decision

SEV-SNP protects private guest memory; it does not automatically encrypt files
on the VPS virtual disk. The current Tier 3 initramfs mounts the ordinary ext4
rootfs read-write at `/sysroot` and bind-mounts `/sysroot/home/pir/data`.
Neither that path nor the current `/sysroot/root/bitcoinpir-identity` path uses
LUKS, dm-crypt, fscrypt or a sealed-key implementation. Virtio disk I/O also
crosses shared guest/host memory. The current plaintext identity and beta
payment files therefore are not acceptable V2 private inputs.

VPSBG supplies a persistent virtual disk and permits customer-managed disk
encryption, but it does not supply a documented KMS, vTPM, stable derived-key
service or managed secret injection. This plan therefore does not claim that
the existing disk is encrypted and does not depend on an undocumented VPSBG
service.

For the two small long-lived V2 secrets, the selected source design is one
canonical AEAD sealed envelope on the untrusted persistent rootfs, not a full
LUKS filesystem:

1. The envelope contains two independently generated Ed25519 seeds: one for
   service identity and one for provider-to-issuer clearing authentication.
   One signing seed is never reused for both roles.
2. The sealed-secret module inside the measured `unified_server` obtains an
   AMD SEV-SNP derived key through `SNP_GET_DERIVED_KEY` on `/dev/sev-guest`.
   V2 selects the
   VCEK root (`root_key_select = 0`), VMPL 0 and guest-field mask `0x9`
   (`MEASUREMENT | GUEST_POLICY`). Firmware also always mixes HostData and the
   launch ID/Author key. V1 of this envelope deliberately does not select the
   optional TCB or Guest SVN fields; their platform-dependent stability is not
   invented as a release requirement. The ABI version and complete request
   bytes are source constants and evidence fields.
3. HKDF-SHA256 domain-separates the derived material for this envelope schema
   and pir2 deployment. XChaCha20-Poly1305 authenticates a canonical envelope
   whose AAD binds schema version, purpose, provider/server IDs, the complete
   derivation request, the signed release-artifact digest, expected measurement
   and full guest policy, both public-key IDs, the pre-reserved identity
   generation and the pre-reserved clearing-authorization epoch. Persistence
   uses temp file, `fsync`, rename and parent directory `fsync`; a partial write
   never becomes current.
4. Only ciphertext, nonce and non-secret metadata persist under a
   measurement-namespaced V2 path on the rootfs. `unified_server` decrypts
   directly into zeroizing memory and constructs the two signing keys without
   creating a plaintext file, including under `/run`. Core dumps and swap are
   disabled for the sealed profile. An explicitly absent first-generation
   envelope may enter inert enrollment-only state; a corrupt, undecryptable or
   unexpected existing envelope halts the provider. There is no
   plaintext-rootfs, tmpfs-file, UKI-embedded or network-fetched secret
   fallback. The operator-signed public release artifact is not a secret and
   confers no identity or clearing authority.
5. The envelope is credential persistence, not payment persistence. It contains
   no BAT, invoice, idempotency root, ProviderStore, rollback client, Direct
   ORAM page key, database state or issuer secret.

The unsealing process runs from the measured initramfs. The mutable
stock-rootfs binary is never allowed to unseal the V2 envelope. Mixing
`GUEST_POLICY` into the derived key is not itself policy validation: before
generation and every open, the runtime also reuses the strict attestation
checks for VMPL 0, DEBUG disabled, MIGRATE_MA disabled and the approved TCB
floor.

The expected measurement, full guest policy, TCB floor and derived-key request
do not come from the envelope header or mutable rootfs metadata. After the exact
candidate UKI is built and reviewed, its expected measurement must be
independently reproduced from those exact bytes, the pinned VPSBG OVMF and exact
launch inputs. The current repository has not yet demonstrated reliable
pre-upload prediction, so the first release uses one fresh-nonce,
observation-only attested boot to collect the live report and exact launch
metadata without deriving a key, writing an envelope, building ORAM or serving.
The offline reproduction must then equal that observed report; merely copying
an observed measurement is not approval. A future release may omit this boot
only after an independently reviewed deterministic prediction path exists.

Only after that equality passes does the operator sign a public sealed-release
artifact that binds the exact UKI digest, reproduced measurement, full policy,
TCB floor, complete derived-key request, provider/server IDs, and the already
reserved identity generation and clearing-authorization epoch. The measured
runtime verifies that artifact against a source-pinned operator public key and
compares a fresh local report to it before generating or opening credentials.
The external ceremony verifier separately validates the AMD certificate chain
and the same exact fields. A signature-valid artifact for any other UKI,
measurement, policy, provider or reserved generation is rejected.

The first source milestone includes a derived-key/enrollment-probe mode in the
same final runtime. Production use additionally requires a separately approved
VPSBG ceremony using the one exact final candidate UKI—never a different probe
UKI. Boot 0 generates the two fresh but not-yet-authorized role seeds and their
sealed envelope. Clean reboots 1 and 2 must both open that original envelope
and report identical public-key fingerprints. Only then may the operator sign
the IdentityCert and the issuer activate the pre-reserved clearing public key
and epoch.

Boot 0 and each reboot use a different verifier-generated nonce and the current
per-boot attested channel public key. The measured runtime binds the ceremony
ordinal, nonce, channel key, signed release-artifact digest, public-key
fingerprints and reserved generations into the canonical enrollment receipt,
then binds that receipt digest into fresh SNP `REPORT_DATA`. The external
verifier validates the current AMD chain/report, nonce, channel, exact release
fields and fingerprints, and rejects a nonce or receipt from any earlier boot.
The probe records only PASS/FAIL, public fingerprints and non-secret report
measurement, policy, HostData, ID/Author-key identity and TCB fields; it never
emits the derived key, its digest or a private seed. Each reboot is expected to
take about five minutes, has a ten-minute hard stop, and uses control-plane
running state plus the fresh enrollment result as its progress signal. A
successful probe is evidence only for that VPSBG guest, launch metadata,
hardware/firmware state and measurement. A TCB change, host migration, VM
replacement or different UKI measurement is not assumed to retain the derived
key. Any probe failure stops this design for production and returns the unlock
decision for review; it never enables a fallback automatically.

A UKI measurement change uses a new measurement namespace and fresh role
seeds. After the same-final-UKI reboot ceremony above, it publishes an attested
receipt binding both public keys, then receives an operator-signed identity
certificate and issuer clearing authorization through a signature-verifying
public-artifact installation path. Only after those artifacts verify may that
image serve. The prior UKI, sealed envelope, certificate, clearing authorization
and client/directory measurement pin remain valid together for the bounded
rollback window. After the new image passes acceptance, revoke the old clearing
epoch and old client/directory measurement authorization. Replaying an older
envelope after that point cannot reactivate it. These replaceable credentials
do not promise recovery across physical-host loss; a replacement
measurement generates new keys and obtains new authorizations. No backup of
the old private seeds is required because no user funds or BAT spend history
depends on recovering them. A future requirement to preserve the exact same
private key across hardware would need an independently held recovery wrap and
a separate decision; its recovery key must never live on this disk.

Full-disk LUKS is deliberately outside this first implementation. The public
database inputs already have independent integrity/root verification, Direct
ORAM uses a per-boot guest-generated page key, and adding cryptsetup plus a
block-device unlock/recovery lifecycle would not remove the need for a trusted
unlock root. Reconsider a small encrypted volume only if a later profile adds a
substantial persistent confidential dataset.

Authoritative capability references: the Linux kernel documents
[`SNP_GET_DERIVED_KEY`](https://docs.kernel.org/virt/coco/sev-guest.html#snp-get-derived-key)
as a guest sealing-key interface; AMD defines the VCEK/VMRK roots and mandatory
versus selected KDF fields in the
[SEV-SNP Firmware ABI](https://docs.amd.com/go/en-US/56860_PUB_1.59_SEV_SNP);
and VPSBG documents customer-built measured images and optional disk
verification, not a managed unseal service, in its
[Measured Boot guide](https://www.vpsbg.eu/blog/introducing-measured-boot-secure-server-images).

## Minimal first-spend and failure contract

The issuer-wide BAT protocol must use a new version. Existing provider-specific
`bpir_cashu_bat_v1` tokens, bindings, key registrations and wallet records are
never reinterpreted as cross-provider credentials.

Before consuming a BAT, the issuer authenticates the requesting provider/
account authorization and verifies that the authenticated provider, signed
policy digest, scope and offer are either current or an exact retained,
unexpired member of the credential's acceptance class. A definitive
retry-safe rejection for request authentication, target or class compatibility
creates no credential-spend, redemption, ledger or provider-credit mutation.
Invalid proof, expired credential/class or already-spent remains terminal. The
successful transaction atomically:

1. inserts the globally unique credential spend key;
2. credits exactly one selected provider;
3. records the exact redemption and ledger outcome; and
4. records the exact signed success outcome for the committing request.

Only after commit may that same in-process request return the recorded success;
network delivery is outside the transaction and is never claimed atomic.

V2 does not reuse V1's provider-secret HMAC `idempotency_key`. Phase B must
freeze a canonical public request/attempt identifier and its signature binding,
or remove that field in the versioned request. The identifier may correlate
one attempt for audit, but it cannot make a committed success grantable again.

The issuer returns a grantable success only for the request that performs the
first durable global commit. Once that commit exists, every later presentation
of the BAT—including a byte-identical V2 attempt replay, another connection or
another provider—returns invalid or spent. The issuer may retain the exact
response for audit and ledger recovery, but its provider API does not release
that old success as a second grantable response.

The provider verifies that one fresh issuer success against the exact current
or retained, unexpired policy bound to that request and connection, installs at
most one in-memory connection grant, and starts no backend work until the grant
has been written to that connection. It exposes no API that accepts a stored
issuer response from a client. No durable provider delivery claim is written.

Web/provider may retain and re-present a BAT only after a request known to be
definitely not sent or an issuer-signed `RetrySafeNonConsuming` rejection
limited to request authentication, target or class-compatibility failure. That
response proves only that this attempt made no mutation; the next presentation
remains subject to issuer-global first-spend and may still be spent if another
request won. Invalid proof, expired or spent is terminal even when the failed
attempt creates no new mutation. A timeout after request bytes may have reached
the issuer, a lost or malformed success, provider crash after issuer commit, or
loss of the final authorization frame is outcome-unknown and burns the BAT.
Neither provider nor Web automatically resubmits an outcome-unknown credential,
and no refund is inferred. This explicit availability trade-off is the smallest
contract that removes the persistent provider delivery claim. Cross-connection
recovery may be designed later, but it must not be smuggled into this release
as another provider payment store.

## Disposition of the current source draft

The superseded source draft contained two different kinds of work:

- **independently re-landed:** pir1 exact-db Harmony multi-pool routing,
  cross-db V2Half token isolation and their narrow tests;
- **replace:** provider-specific BAT policy bindings, the fixed
  2-policy/12-BAT/2-clearing issuer shape, provider-side
  ProviderStore/idempotency/rollback requirements, and client checks that
  reject one reviewed BAT class across two providers.

Two provider policies are still required because pir1 and pir2 advertise
different workloads, roots and limits. They no longer imply twelve independent
raw BAT lineages. Until the replacement work below is complete, the source PR
remains a draft and is not a production source candidate even when its old CI
is green.

## P0/P1 source blockers

### 1. define the acceptance class and a new BAT wire version

Add a new canonical BAT version rather than weakening V1. Freeze the signed
acceptance-class fields and signature ownership before implementation. Each
class maps one immutable raw-key lineage to one or more exact provider policy
members. Issuer startup must reject member disagreement on price, credential
count, validity, entitlement shape or epoch, and reject one raw key appearing
in more than one class.

Class/member rotation must preserve the promised BAT validity. Stop new
issuance before retirement and retain each exact signed member for at least its
invoice/claim/minimum-credential-validity and retired-policy grace horizon.
During that horizon the issuer may redeem only the exact retained, unexpired
member; after it expires the credential is terminal. A normal policy or dataset
rotation must not silently invalidate an otherwise promised BAT.

Acquisition mints a class credential. It may begin from a selected UI offer,
but the wallet record is bound to issuer, class and key epoch—not permanently
to that provider/policy/scope/offer.

### 2. make issuer registration and redemption globally authoritative

Replace the one-raw-key/one-provider registry row with an immutable
raw-key/class record plus exact provider/scope membership rows. Preserve the
global unique credential-spend key. The issuer validates membership before
first-spend, makes concurrent pir1/pir2 redemptions race on the same global row,
credits only the winner, and never returns a grantable replay after commit.

Legacy V1 namespaces and histories remain isolated. No migration may relabel a
provider-specific key or wallet BAT as issuer-wide.

### 3. add an exact-policy, payment-storeless shared-BAT provider mode

The current storeless activation accepts only Free-PoW, while the paid path
assumes a ProviderStore. Add a closed mode for exactly Free-PoW plus the new
issuer-online BAT. It pins one reviewed current policy and may carry only the
finite exact signed retained policies still inside their promised V2 grace.
Those public policy bytes are immutable release inputs, not a payment store;
they are removed only after the corresponding horizon. The mode refuses
payment ProviderStore, shared-idempotency, provider payment rollback, local BAT
mint, Direct receipt, Standard Cashu and ARC inputs.

Use the same first-spend response contract for pir1 and pir2. The provider may
keep bounded connection-local terminal state, but no BAT state survives a
restart. The issuer accepts only current or exact retained/unexpired class
members within their signed grace, and rejects unregistered or expired policy
digests during every redemption.

### 4. implement pir2 measurement-bound sealed credentials

Add the selected in-process sealed-envelope path. Extend the existing SEV guest
interface with a narrow, mockable `SNP_GET_DERIVED_KEY` wrapper using the
existing typed SEV ABI; do not hand-code response offsets and do not replace or
weaken the current report-verification path. Freeze one canonical envelope
codec, HKDF labels, AEAD AAD and rootfs namespace. The module must refuse
unsupported firmware/kernel ABI, a failed strict report-policy check,
derivation-parameter drift, AEAD failure, unexpected public keys or
authorization epochs.

Add an explicit enrollment-only startup for an absent first-generation
envelope. It generates fresh, distinct service-identity and clearing seeds
inside the measured guest, seals them before exposing only their public keys,
and emits a fresh-nonce/current-channel attested enrollment receipt that binds
both public keys, the signed release artifact, reserved generations and the
exact measurement/policy. Add a narrow signature-verifying installer for the
public IdentityCert and issuer clearing authorization. Paid/query serving
remains disabled until both verify. An existing envelope failure never silently
creates replacement credentials.

Remove the plaintext persistent identity and beta clearing-key paths from the
closed V2 profile. Do not migrate those old bytes into the envelope: their
historical host exposure makes fresh V2 credentials the safer and simpler
boundary. Do not add ProviderStore, a shared-idempotency key, provider payment
rollback, a secret-release broker or a second signing use for either seed.

Minimum source map:

- add `crates/protocol/runtime/src/snp_sealed_secrets.rs` for the typed SEV
  derived-key adapter, strict report-policy gate, canonical envelope,
  enrollment receipt inputs, atomic ciphertext persistence and zeroizing key
  handoff; reuse the locked `sev` crate plus existing HKDF,
  `chacha20poly1305` and `zeroize` dependencies;
- add one sealed-envelope/enrollment option group to
  `apps/server/src/bin/unified_server.rs`, including the signed release artifact
  and fresh verifier-nonce receipt inputs. Its observation mode must not call
  `SNP_GET_DERIVED_KEY`, create an envelope, build ORAM or serve; the closed pir2
  profile accepts the sealed group and rejects every plaintext identity/
  clearing-key option or mixed mode;
- add one narrow offline measurement-equality/release-artifact command to the
  existing admin tooling. It consumes the exact reviewed UKI, pinned OVMF and
  launch tuple, independently computes the measurement, verifies equality with
  the fresh observation report and refuses release signing on mismatch; it does
  not turn a captured measurement into an expected value;
- add narrow owner-only reservation operations: the issuer store durably and
  uniquely reserves an inactive clearing epoch, while the identity authority's
  append-only registry durably and uniquely reserves an inactive identity
  generation. Readback is required; activation must match the reservation and
  generated public key exactly, and a duplicate/conflicting reservation fails;
- change
  `scripts/dracut/97bpir-tier3-init/unified-server-run.sh` to invoke the same
  measured `/usr/local/bin/unified_server` sealed preflight before provider
  policy/auth startup and before any Direct ORAM build. An absent envelope
  enrolls and exits inert; an envelope without both public authorizations
  performs the reboot probe and exits inert; only a ready envelope with both
  public artifacts verified may proceed to ORAM build and serving. The script
  passes only the ciphertext-envelope and public artifact paths, removes the
  mutable-rootfs `unified_server` fallback, sets core size to zero and refuses
  any active swap before unsealing;
- change `scripts/dracut/97bpir-tier3-init/unified-server-finish.sh` together
  with the run script so a successful inert observation/enrollment/probe writes
  one atomic, current-boot marker bound to its receipt digest and exits with a
  dedicated status. The finish hook must take that service down after the first
  success instead of counting it as a failure and restarting it; exits without
  the exact marker retain the existing bounded failure-retry behavior;
- change
  `scripts/dracut/96bpir-unified-server/module-setup.sh` and its existing UKI
  contract test so a production sealed profile cannot embed a private identity
  key; and
- add only the focused runtime, CLI and Tier 3 script tests listed in Phase D.

### 5. update policy, SDK, Web and deployment profiles

Keep the complete db0/db1 provider scopes, but replace provider-specific BAT
bindings with acceptance-class membership. The strict SDK and Web may allow a
shared raw-key fingerprint only when both verified offers prove membership in
the same signed class; copied keys, mismatched terms and cross-class reuse still
fail closed.

The Web vault stores the new BAT by issuer, class and key epoch/fingerprint.
Legacy provider-bound BATs are not automatically migrated. At redemption the
selected verified offer must prove membership in the stored class before the
credential leaves the vault.

The closed issuer profile requires two provider policies, the reviewed nonzero
set of issuer-wide class keysets, two provider accounting/authentication
relationships, issuer settlement/rollback material and Mainnet Lightning quote
material. It does not require twelve BAT keys merely because there are twelve
provider scopes.

## Source implementation sequence

### Phase A — land this revised contract

Update this plan and its directly linked handoff text before changing protocol
code. Mark the provider-specific 2/12/2 and provider-store assumptions as
superseded.

Acceptance:

- issuer-wide first-spend, class compatibility and the absence of a provider
  payment store are unambiguous;
- the one-BAT/one-winning-provider rule is explicit;
- V1 is not silently reinterpreted;
- Harmony multi-pool routing is separated from and re-landed without the
  superseded payment work;
- pir2's distinct long-lived authentication roles and the measurement-bound
  sealed-envelope decision are explicit, while implementation and the VPSBG
  capability canary remain P1 work; and
- no runtime, database, browser, UKI or production state changes.

### Phase B — implement the issuer and V2 wire core

Implement canonical acceptance classes, class-bound acquisition records,
cross-provider redemption membership, global first-spend and non-replayable
grant success. Freeze the V2 public attempt-ID/removal wire and signature
contract without a provider HMAC root. Keep V1 parsing and history isolated for
compatibility/recovery.

Source checkpoint (2026-08-19): the first Phase-B slice implements the stable
class ID, scheme-6 policy shape, canonical issuer-signed class/key-epoch
artifact and rollback-protected issuer-store v6 registry. Complete artifacts
are registered atomically against exact current provider policy heads; older
epochs remain retained, common terms cannot change under one class ID, and raw
BAT keys cannot cross V1/V2 ownership. Existing V1 acquisition, issuance,
redeem and ProviderStore paths still reject scheme 6. This checkpoint is not a
usable V2 purchase or redemption path; the remaining Phase-B work below is
unchanged. Version-5 issuer stores require a separately reviewed explicit
migration or isolated legacy retention and are never upgraded at startup.

Acceptance:

- one BAT acquired through a class member can redeem at another compatible
  provider member;
- concurrent pir1/pir2 redemption has exactly one issuer winner and one ledger
  credit;
- invalid provider/account authorization or incompatible
  class/scope/provider/policy input rejects before spend;
- exact replay, sequential cross-provider replay and replay after issuer
  restart return invalid or spent, never a grantable success; and
- no provider-local state participates in global credential validity.

### Phase C — implement payment-storeless providers and pir2 sealed credentials

Add the exact-policy shared-BAT provider mode, remove payment-store inputs from
the pir1/pir2 closed profiles, and implement the sealed credential path from
blocker 4.

Acceptance:

- pir1 and pir2 start the closed profile without payment ProviderStore,
  shared-idempotency secret or provider payment rollback client;
- the current plus finite exact retained/unexpired policy set is fully pinned
  at startup and cannot be mutated through provider state;
- one fresh issuer success produces at most one in-memory grant;
- any replay after first commit fails at the issuer;
- a pir2 restart has no payment database to restore; a V2 BAT acquired before
  the restart remains eligible only if its redemption performs the first issuer
  commit, while every BAT already spent at the issuer remains invalid after the
  restart;
- pir2 starts only after the two distinct seeds decrypt in process from the
  exact measurement-bound envelope and their public authorizations verify;
- an explicitly absent first-generation envelope exposes enrollment only,
  while corrupt/wrong-measurement existing envelopes halt; neither falls back
  to a plaintext rootfs or UKI key; and
- no host mutation, UKI build or deployment is needed to run the source tests.

### Phase D — update policies, clients, profiles and focused tests

Replace the provider-specific templates, issuer unit, render gates and wallet
selection model. Preserve the already-correct db0/db1 roots and the
independently re-landed Harmony multi-pool routing.

The meaningful minimum checks are:

1. canonical codec and acceptance-class equivalence tests;
2. one real BAT concurrently presented to pir1/pir2, with one issuer DB winner;
3. exact, sequential and post-restart replay rejection;
4. submit one valid BAT first with invalid provider/account authorization and
   then to an incompatible member, prove issuer spend, redemption, ledger and
   provider-credit state remain unchanged after both, then redeem that same BAT
   successfully at a compatible authenticated member;
5. one narrow policy/member rotation case proving an exact retained, unexpired
   member redeems during its signed grace and fails after expiry;
6. no-ProviderStore provider process/restart coverage;
7. mock derived-key request/ABI and sealed-envelope round trips, including
   wrong signed release artifact/measurement/policy/AAD, tamper, cross-purpose
   use, role-key equality, replayed verifier nonce/old-channel receipt, absent
   device/ioctl and plaintext-fallback rejection, plus one exact measurement-
   equality/signing refusal fixture;
8. focused SDK/Web class selection and vault tests, including two paid legs
   reserving two distinct wallet records and credential-spend keys while reuse
   of one record or payload fails;
9. inject an issuer-committed/lost-response outcome and prove Web/provider do
   not automatically resubmit, all later and post-restart presentations are
   spent, while only a definitely-not-sent request or issuer-signed
   `RetrySafeNonConsuming` auth/target/class rejection permits re-presentation
   still subject to issuer-global first-spend; and
10. one static Tier 3 script/finish-hook check proving sealed preflight precedes
    Direct ORAM construction, inert observation/enrollment/probe exits without
    deriving or persisting a secret, building ORAM or starting the paid
    provider, and its current-boot success marker suppresses the first runit
    restart while ordinary failures retain the existing bounded retries; and
11. narrow issuer/identity reservation tests proving uniqueness, inactive
    readback and exact activation matching; and
12. positive plus mutation-negative closed-profile render checks proving the
    V2 pir2 profile contains one ciphertext-envelope path and no plaintext
    identity/clearing key, ProviderStore, idempotency or rollback input.

Do not add a database build, ORAM bulk build, UKI build, live Lightning node,
production browser or broad repository suite merely to make CI look complete.
Run a broader existing Payment PR profile only if the final diff crosses a
boundary not covered by these focused checks.

### Phase E — materialize a private release

After the source PR is merged, a separately authorized ceremony freezes:

- the exact commit, binaries and db0/db1 backend roots;
- the two final signed provider policies;
- each acceptance class, exact member set and fresh V2 key epoch;
- a fresh issuer store only when inventory proves no old store exists or keeps
  the old instance isolated, otherwise a reviewed additive, non-reinterpreting
  migration that preserves the existing rollback identity and complete
  history;
- pir1 provider authentication and accounting authorization;
- the exact pir2 derived-key ABI/request parameters, strict full guest-policy
  and TCB-floor source, measurement-namespaced ciphertext path,
  enrollment-receipt schema and IdentityCert/issuer-authorization
  public-artifact paths;
- one candidate pir2 clearing-authorization epoch above the issuer floor and
  one candidate identity generation, to be authoritatively reserved after the
  issuer store and identity-authority registry are ready but before release
  signing or Boot 0; and
- Mainnet Lightning quote material, risk limits and recovery evidence.

Phase E freezes the inputs and schema for the later signed release artifact,
but it cannot freeze an exact expected measurement until Phase F builds and
reviews the exact candidate UKI. It creates neither a sealed envelope nor a
pir2 payment store.

Inventory whether any private provider-specific BAT or Direct Mainnet plan,
keyset, quote, claim, wallet credential or store was ever materialized. If one
exists, stop old issuance and either retain its isolated recovery instance
through every immutable horizon or run a narrow reviewed migration that
preserves every V1 quote, claim, spend, redemption, ledger record and rollback
floor. Never reinterpret V1 state as V2 or blank-initialize over issuer
spend/history state. A supported migration requires its own focused preservation
test; otherwise the isolated legacy instance is the only permitted path.

Prepare, freeze and privately stage issuer support, both matching provider
policies, and the Web/directory discovery candidates. Do not publish any of
them or expose V2 acquisition in this phase. Publication remains in Phase F
after the issuer and all advertised class members agree on the exact class.

This phase may prepare inert/stopped artifacts only. It does not authorize UKI
operations, service start, publication, invoice creation or funds.

### Phase F — deploy and accept one boundary at a time

The later operator sequence is:

1. initialize or explicitly migrate and recovery-test the issuer store and its
   rollback authority;
2. under a separate issuer approval, atomically reserve one unique inactive
   pir2 clearing epoch above the durable issuer floor and read it back;
3. under a separate identity-authority approval, atomically reserve one unique
   inactive pir2 identity generation and read it back. Candidate numbers from
   Phase E are not reservations, and neither reservation has a public key or
   active authority yet;
4. install stopped issuer and pir1 bundles on the approved Hetzner host;
5. start and verify the issuer privately with no funds and with V2 quote/BAT
   acquisition disabled;
6. start and verify pir1 privately, including issuer authentication;
7. build and offline-review the exact pir2 UKI, then freeze its exact bytes and
   digest without yet accepting an expected measurement;
8. upload that approved UKI;
9. switch/reboot once to that exact UKI in observation-only mode. Before any
   key derivation, envelope write, Direct ORAM build or serving, establish the
   current per-boot attested channel, bind a fresh verifier nonce into the SNP
   report, collect the non-secret launch inputs/report and stop after one runit
   attempt;
10. independently reproduce the expected measurement from the exact reviewed
    UKI, pinned OVMF and collected launch inputs, and require equality with the
    fresh observation report. A mismatch or inability to reproduce stops the
    release; the observed value is never copied into trust by itself;
11. under a separate release-artifact signing approval, sign the public artifact
    binding that exact UKI/reproduced measurement, full guest policy, TCB floor,
    derived-key request, provider/server IDs and both authoritative inactive
    reservations;
12. separately authorize another switch/reboot to that exact UKI. Before any
    Direct ORAM build, inert
    Boot-0 preflight establishes the current per-boot attested channel, receives
    and verifies the signed public release artifact plus a fresh verifier nonce,
    compares the fresh report to every signed release field, generates the two
    still-unauthorized seeds and atomic sealed envelope, persists only the signed
    public artifact plus ciphertext, and emits only the nonce/channel-bound
    attested public fingerprints; the success marker then stops this runit
    service after that single Boot-0 attempt;
13. separately authorize clean reboot 1 with a new verifier nonce and verify
   that the exact same UKI opens the original envelope with identical public
   fingerprints and a fresh current-channel report within its ten-minute hard
   stop, without starting ORAM or the paid provider and without a same-boot
   runit retry;
14. separately authorize clean reboot 2 with another new nonce and repeat the
    same verification;
15. independently verify the observation receipt plus all three enrollment/
    unseal receipts, AMD chains, nonces/channels, exact signed release fields,
    reserved generations and identical public fingerprints where applicable;
    an old receipt or nonce is not acceptance evidence;
16. under a separate identity-authority approval, sign the IdentityCert for the
    exact pre-reserved identity generation;
17. under a separate issuer approval, register the clearing public key and
    activate only the exact pre-reserved clearing epoch while the old rollback
    credentials remain valid;
18. install those signed public artifacts through the reviewed installer,
    start pir2's closed profile and verify measurement, provider authentication,
    policy and database roots;
19. while pir2 remains private and V2 acquisition remains disabled, perform a
    bounded no-funds readiness and Free-PoW query canary;
20. deploy matching Web measurement/proof/policy/class pins without directory
    publication and with the V2 acquisition UI/request path fail-closed;
21. separately sign and publish directory entries, then read them back while
    the issuer V2 quote/acquisition path and Web acquisition remain disabled;
22. only after explicit real-value canary approval, enable the bounded private
    acquisition path, buy at least two fresh BATs and
    prove both first-wins directions: BAT-A succeeds at pir1 then fails at
    pir2; BAT-B succeeds at pir2 then fails at pir1. Use separate fresh BATs for
    any paid two-leg query acceptance, then close the canary window;
23. after that evidence is accepted, separately authorize and read back public
    V2 BAT acquisition in the issuer and matching Web UI; and
24. after the new generation is accepted and its rollback grace ends, under a
    separate issuer approval revoke the old clearing authorization; then under
    its own publication approval revoke the old client/directory measurement
    authorization. Retain the old UKI, envelope and public records as recovery
    evidence; do not delete or relabel them.

Every action that changes external state has its own approval, progress signal,
hard stop and rollback owner. Success at one action does not authorize the
next. A created but unpaid invoice is not BAT acquisition evidence.

## Explicit non-goals for the source work

- rebuilding, relabeling or cleaning the accepted db0/db1 database lineage;
- restoring the retired Hetzner warm-fallback listener or port 8092;
- making one BAT independently spendable once per provider;
- retaining provider-specific V1 BATs in the new production policy;
- adding Direct BOLT11, Standard Cashu or ARC to a production policy;
- adding a provider payment store merely to recover an ambiguous connection;
- embedding a production secret in Git, a public UKI, CI or evidence; or
- generating invoices, funding wallets, opening channels, sending value or
  claiming that source-ready and production-live are equivalent.
