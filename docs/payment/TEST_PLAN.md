# Payment integration and fault test plan

Status: normative release plan. Not every item below is implemented. The
currently reproducible no-funds coverage and its precise limitations are in
`LOCAL_ACCEPTANCE.md`; `IMPLEMENTATION_STATUS.md` lists release blockers. In
particular, the canonical five-method/backend matrix remains deterministic
wire/gate evidence. Separate loopback tests execute direct receipt at every
backend and Free, strict-TLS Standard Cashu, provider-local BAT and experimental
ARC through production committers, ProviderStore and all five backend handlers.
A separate Chromium boundary now executes generated WASM against a
real loopback no-funds issuer. A third harness launches two issuers and two
providers through browser admission, proof-bound Merkle preflight and one real
encrypted two-server DPF query. The extended CDK lifecycle has passed its final
2026-07-28 current-tree opt-in run, as has the forced two-hop three-node CLN
runner. The final pinned-Linux matrix reran the feature-gated Standard-Cashu/
Free provider-process cell, Harmony lifecycle and the remaining Rust/process
boundaries successfully. The complete-query Free/ARC browser extension is
also covered by a final isolated-target current-tree 3/3 pass; its companion
real-WASM/real-loopback-issuer case passed 1/1 with the two explicit CLN cases
skipped by default. Pushed CI remains a per-commit merge gate. The current focused
shared-redeem/clone-fencing P0 suites pass 93/93 service-store tests and 6/6
provider-clearing shared-grant tests; these are not an aggregate full-suite
claim. The feature-gated provider-process method matrix now closes all 25
method/workload cells with production committers and backend handlers.
Remaining unexecuted boundaries include an external public-WebPKI mint,
persistent public-network Lightning and a deployed complete-query
browser/issuer/two-provider E2E. One authorized short-lived public-relay
publish/readback smoke with disposable keys has run; production-catalog
publication and monitored relay operation remain unexecuted.

## Positive conformance matrix

Every cell must exercise a real secure-channel authorization frame, durable
consumption, the backend state machine, and mandatory verification. A unit test
of a mint alone does not satisfy a cell.

| Scope | Free | BOLT11 receipt | Cashu eCash | Cashu BAT | ARC experimental |
|---|---:|---:|---:|---:|---:|
| DPF evaluate job | required | required | required | required | required |
| Harmony hint bundle | required | required | required | required | required |
| Harmony query job | required | required | required | required | required |
| Onion evaluate job | required | required | required | required | required |
| TEE-ORAM query job | required | required | required | required | required |

Mixed-provider scenarios:

- DPF provider A Free, provider B ARC;
- DPF provider A BOLT11 receipt, provider B Cashu BAT;
- DPF provider A Cashu eCash, provider B Free;
- Harmony hint ARC, query Cashu eCash;
- first provider selected and completed before the second is discovered;
- no packet, log, state row, or API body contains a peer/common ID.

### Implemented loopback process acceptance

`cargo test --offline -p runtime --test payment_v1_process_e2e` and
`cargo test --offline -p runtime --test payment_v1_methods_process_e2e`
launch two independent provider child processes on explicit `127.0.0.1`
listeners. Both perform the real WebSocket and encrypted-channel handshake,
verify each provider's exact signed manifest-root policy, execute a valid DPF
frame, enforce the signed frame limit and reject replay after restart.

The first test covers provider-specific direct receipts. The same provider-1
receipt is rejected at provider 0 and subsequently accepted at provider 1, so
it detects accidental cross-provider burn/shared spent state; a misspelled
bind flag must also exit before listening. The second covers Free open,
provider-local durable IP quota, an actual Cashu BAT blind/DLEQ/unblind proof,
and real experimental ARC issuance/presentation. It verifies independent
provider keys/quotas, cross-provider BAT/ARC rejection, and durable quota,
BAT-spend and ARC-nullifier rejection after both provider processes restart.

The dedicated Harmony V2Full lifecycle process boundary is:

```sh
cargo test --locked --offline -p runtime \
  --test payment_v1_harmony_pool_process_e2e
```

It launches one real `unified_server` with a private on-disk pool and verifies
secure-channel/policy binding, invalid-proof non-consumption, pre-dispatch
disconnect restoration, first-dispatch durable consumption, restart with the
matching marker and fail-closed inode replacement. A 2026-07-28 focused
closeout repeated its one test three times successfully; the final pinned-
Linux matrix subsequently passed the current case 1/1, hint pool 56/56 and
`unified_server` 64/64. Pushed CI remains separate per candidate commit.

The dedicated no-funds OnionPIR process boundary is:

```sh
cargo test --locked --offline -p runtime \
  --test payment_v1_onion_process_e2e
```

It launches two independent real `unified_server` providers and builds a
one-row Onion fixture through the public `onionpir` API. It covers cleartext
and encrypted pre-authorization rejection, wrong-provider non-consumption,
same-provider wrong-backend/workload non-consumption, one real chunked key
registration, and successful decryption of production INDEX, CHUNK, Merkle
INDEX-sibling and Merkle DATA-sibling worker responses. It also terminalizes
extra registration, phase skip, wrong round and a second logical job after
the capability has been atomically consumed, then rejects receipt replay after
ProviderStore/process restart. The generated Merkle sibling ciphertexts are
real handler/decryption evidence; the tiny fixture does not claim an end-user
inclusion proof against a production Bitcoin database.

The four non-receipt methods also cross every non-DPF production process
boundary under the Standard-Cashu private-root test feature:

```sh
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_process_e2e \
  all_non_receipt_methods_commit_before_real_harmony_query_and_replay_after_restart \
  -- --exact
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_harmony_pool_process_e2e \
  all_non_receipt_methods_restore_pre_dispatch_and_burn_on_real_hint_dispatch \
  -- --exact
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_onion_process_e2e \
  all_non_receipt_methods_commit_before_real_onion_job_and_replay_after_restart \
  -- --exact
cargo test --locked --offline -p runtime \
  --features cuckoo-oram,standard-cashu-process-e2e \
  --test payment_v1_tee_oram_process_e2e \
  all_non_receipt_methods_commit_before_real_tee_oram_and_replay_after_restart \
  -- --exact
```

These tests share one fixture for Free-IP, strict-TLS Standard Cashu, Cashu
BAT and experimental ARC, but do not share or replace any production
committer. Every AUTH frame is encrypted and uses the exact signed
provider/backend/workload scope. A deliberately wrong operation is rejected
before the same proof succeeds, each real backend handler returns its native
result, and provider restart preserves Free-IP quota, Cashu input, BAT serial
and ARC nullifier rejection. Cashu wrong-scope and replay attempts are also
proved not to reach the mint. Harmony full hints additionally use two
independent capabilities per method: the first proves pre-dispatch disconnect
restores the same ready inode, while the second proves first dispatch unlinks
that inode before exposing its PRP and remains spent after restart. ARC remains
experimental; matrix coverage does not satisfy its independent review gate.

A separate non-default process test exercises the production provider remote
rollback-authority selection and client path:

```sh
cargo test --locked --offline -p runtime \
  --features remote-authority-process-e2e \
  --test payment_v1_process_e2e \
  remote_authority_process::remote_authority_real_process_tls_provider_e2e \
  -- --exact
```

It runs the real `rollback-authority` application, a same-host-style TLS edge,
and `unified_server` in distinct OS processes, with every listener restricted
to loopback. The edge presents a `localhost` leaf signed by a committed
test-only CA. The client still performs normal rustls/WebPKI chain, hostname,
validity and signature verification and independently checks the complete leaf
SPKI SHA-256 pin. The test initializes the provider store through the remote
opaque-floor CAS, authorizes and durably consumes a direct receipt, executes a
DPF frame, restarts both authority and provider, rejects replay, and proves
wrong CA, wrong pin and offline authority all fail before the provider listens.
Authority process logs are checked not to contain its instance, namespace,
keys, invoice, payment hash or preimage.

The same feature also contains a three-business-domain topology test:

```sh
cargo test --locked --offline -p runtime \
  --features remote-authority-process-e2e \
  --test payment_v1_process_e2e \
  three_authority_process::three_authority_real_process_topology_e2e \
  -- --exact
```

It starts three independent child copies of the current test harness, each of
which invokes production `rollback_authority::run`, plus three independent TLS
edge child harnesses. Provider 0, provider 1 and issuer authority domains have
separate authority SQLite databases, authority/client/value-root keys,
namespaces, ports and distinct localhost TLS leaf/SPKI pins. The public
deployment-set validator rejects repeated pins or namespaces; raw remote
clients prove wrong-pin, unprovisioned-client and cross-domain configurations
fail with their exact remote-call classifications. The parent test directly
calls the production provider/issuer Store adapters to exercise correct-domain
opens and a crossed provider authority. It independently stops one provider
authority backend and then the issuer authority backend while each TLS edge
continues listening: the affected Store returns
`RollbackAuthorityUnavailable`, while the other two Stores remain independently
openable and authenticated through their own authorities. Restart against the
original authority database recovers the exact issuer store generation and
commitment. A separate stale-provider-authority case first
proves that the restored backup returns an authenticated empty floor, and the
provider adapter then requires the exact `RollbackFloorMissing` result.
Restoring the current database is required for recovery. This test does **not**
launch `unified_server`, `payment-issuer`, or an installed authority binary. It
is a single-host process/file topology test and does not establish different
operators, machines, administrative domains or backup custody.

The corresponding issuer-binary boundary is exercised separately:

```sh
cargo test --locked --offline -p payment-issuer \
  --features remote-authority-process-e2e \
  --test remote_authority_process_e2e \
  payment_issuer_remote_authority_real_process_tls_e2e \
  -- --exact
```

It runs the real `payment-issuer` binary, rollback-authority application and
test-TLS edge in three distinct OS processes. Remote `init-store` performs the
generation-zero CAS and its mandatory reopen; a subsequent fresh issuer process
performs `check-store`. Restarting the authority against its original durable
store preserves that floor. Wrong CA, wrong SPKI pin and a reachable TLS edge
with the authority offline all fail closed. Captured logs must not contain the
namespace, authority/client/secret keys, invoice, payment hash, preimage or any
remote config path.

Private-CA trust is unavailable in default builds. Only the explicit
`test-only-webpki-root` feature adds the
`test_only_webpki_root_pem_path` parser field; the root must be an absolute,
owner-owned mode-0600 regular single-link file under an owner-owned mode-0700
directory. The default client test proves the same field is rejected by
`deny_unknown_fields`. Neither production binary build nor deployment may
enable either test feature, and a non-debug provider or payment-issuer build
with it fails at compile time. The crate's build script separately rejects a
Cargo release profile even if that profile manually enables Rust debug
assertions; `debug_assertions` is not treated as the production boundary. The
checked-in test leaf private keys have no production trust or secrecy value,
and the E2Es require no OpenSSL command or network access.

Fake Lightning has a separate artifact boundary. Default `payment-issuer`
builds contain neither `serve-fake` nor `/__test/fake/settle`; local no-funds
tests must explicitly enable `test-only-fake-lightning`. The issuer build
script and source guard reject that feature in every Cargo release profile,
including one that forces debug assertions on.

These are deliberately local rollback-boundary tests. The provider case uses
`NoSevHost`, deterministic keys and SDK `dangerous_unpaired_*` helpers; the
issuer case covers store initialization/open rather than acquisition or query
wiring. They do not satisfy production identity/binary pin, hardware proof,
database proof/trusted-root, Merkle preflight/inclusion, real issuer/browser,
external dependency, or non-DPF process-level cells.

The repository relay has a separate real-process two-relay test:

```sh
cargo test --locked --offline -p bitcoinpir-directory-relay \
  --test payment_v1_two_relay_process_e2e \
  two_relay_real_process_catalog_e2e -- --exact --ignored
```

Two copies of the repository's production `bitcoinpir-directory-relay` binary
use different owner-only configs, SQLite files and runtimes, plus four distinct
loopback listeners: one public read lane and one private publisher lane per
relay. Every accepted signed `EVENT` uses a publisher lane, and every accepted
ID/catalog `REQ` plus returned `EVENT`/`EOSE` uses the corresponding public
lane. Deliberate wrong-lane probes must close; an exact-ID public readback
proves the rejected EVENT sentinel was not persisted. The client
cryptographically verifies the same complete 16-shard catalog from both,
proves both stale-head views remain independently valid before requiring the
exact split-view rejection, rejects one-relay-offline, resolves a lost positive
ACK with a public-lane bounded-backoff ID barrier followed by an idempotent
same-event publisher-lane retry, and verifies both listeners return after each
independent process restart. The test deliberately does not infer relay-operator
or host independence from local process separation.

Payment CI also runs the stopped-only artifact recipe itself in a dedicated
Ubuntu job. The job pulls the exact digest-pinned Rust image, archives the
checked-out commit, completes both clean builds, atomically publishes the
owner-only temporary artifact, and exercises both independent-rebuild gates.
`create-manifest` performs two clean rebuilds before publication; after the
atomic rename, `verify-build` performs two more clean rebuilds against the
published path before the final seal. The recipe therefore performs six
empty-target builds in total. The artifact stays under the ephemeral runner
directory and is neither uploaded nor installed; a passing job does not resolve
`relay-selection.toml`, replace `/usr/bin/false`, open a listener, or activate
the relay.

A separate non-default Standard Cashu process test is implemented and wired
into Payment CI:

```sh
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_standard_cashu_process_e2e \
  standard_cashu_real_process_tls_two_provider_e2e -- --exact
```

It starts a deterministic TLS NUT-03 mint and two independent real
`unified_server` processes. Provider 0 selects Standard Cashu while provider 1
independently selects Free/OpenBestEffort; the client establishes both bound
secure channels, verifies separate signed policies, authorizes each provider,
preflights proof-bound arity-8 tree tops, executes a real two-server DPF query
and explicitly verifies the Merkle absence result. Reopening both providers on
their original durable stores rejects the Cashu bearer without a second swap.
Fresh provider pairs then prove wrong CA, wrong signed leaf-SPKI pin and an
offline mint all fail closed without another mint spend. The private root is a
feature-gated, owner-only deterministic test fixture; normal WebPKI hostname,
time, chain and signed leaf-SPKI checks remain mandatory, the CLI flag is absent
from default builds, and release builds with the feature are compile-rejected.

The process cell passed a dedicated local branch run before later Harmony-only
server-gate refinements, then passed the final current-tree pinned-Linux matrix
1/1 with warnings denied and the ordinary CLI/release-feature rejection guards.
Pushed CI remains authoritative per candidate commit.
It is not public-mint evidence: an approved external public-WebPKI Cashu mint
remains a production-only acceptance gate. Those remaining boundaries are
listed in `LOCAL_ACCEPTANCE.md`. Separately,
`scripts/payment-v1-cdk-regtest-e2e.sh` uses
a disposable loopback CDK 0.17.3 fake-wallet mint. Default mode now builds the
current `bpir-admin` and generated JS/WASM with Cargo locked/offline before the
mint starts. Its historical `--browser-only` run passed with a real CDK
`cashuB` token imported by the then-present generated package in Chromium,
persisted and retired through the encrypted browser vault, and emitted as
owner-only canonical provider wire bytes. Current browser-only mode does not
build and therefore requires an explicit prebuilt-artifact acknowledgement plus
SHA-256 pins for `bpir-admin`, package metadata, JavaScript and WASM. The
untouched HTTP token must fail; because Cashu proofs do not bind the wallet
mint-URL metadata, the private test fixture relabels only that CBOR text field.
Default mode signs `https://localhost:<port>` plus the fixed test leaf-SPKI pin
and feeds the exact browser bytes to a real Standard Cashu `unified_server`.
The feature-gated test-only TLS proxy maps only that exact identity to the
loopback CDK HTTP listener; there is no production plaintext fallback. An
independent Free `unified_server` completes the pair. The joined ignored test
requires two secure channels, exact manifest-root policy, proof-bound preflight,
DPF and Merkle verification, restarts both providers, and proves provider-local
replay rejection leaves the CDK proxy attempt count at one. A second independent
8-sat note then runs the native custody NUT-03/NUT-07 lifecycle. This is not an
admin-retirement, public-WebPKI, production attestation or independent
production rollback-floor cell.

A separate non-default shared-issuer process cell joins the provider and
clearing boundary without creating an invoice or contacting Lightning:

```sh
issuer_e2e_target_dir="$PWD/target/payment-issuer-shared-e2e"
cargo build --locked --offline \
  -p payment-issuer \
  --features test-only-fake-lightning \
  --bin payment-issuer \
  --target-dir "$issuer_e2e_target_dir"
cargo build --locked --offline \
  -p bpir-admin \
  --bin bpir-admin \
  --target-dir "$issuer_e2e_target_dir"
BITCOINPIR_PAYMENT_ISSUER_BIN="$issuer_e2e_target_dir/debug/payment-issuer" \
BITCOINPIR_BPIR_ADMIN_BIN="$issuer_e2e_target_dir/debug/bpir-admin" \
  cargo test --locked --offline \
    -p runtime \
    --features shared-issuer-process-e2e \
    --test payment_v1_shared_issuer_process_e2e \
    shared_issuer_real_process_tls_e2e -- --exact
```

It launches a real `payment-issuer`, a redeem/balance-only private WebPKI TLS edge, one
real shared-BAT `unified_server`, and an independently selected Free/Open peer.
After reading one complete canonical issuer HTTP 200 bound to the redeem request
digest, the test edge persists a one-shot test marker and deliberately drops
that downstream response. This proves the issuer commit escaped its application
boundary while the provider must fail closed with no local delivery claim. The
issuer and provider then restart against their original stores and rollback
floors. Replaying the identical proof must reproduce the same canonical-body,
request and idempotency-key SHA-256 digests, recover exactly one local grant and
leave the issuer ledger at one credit/sequence; a later replay cannot create a
second grant. The digest transcript is a fixed-size, test-local oracle and does
not persist the raw envelope, credential, idempotency key, HTTP metadata, peer
address or timing. The same run uses `bpir-admin` to build both clearing
artifacts and installs a distinct
provider-request public key, verifies signed balances across issuer restart,
then—after exact response-loss recovery reaches a known local-delivery
result—rotates the authorization epoch and issuer settlement key with explicit
old-key retention. Provider restart/replay after rotation cannot create a
second grant. The test is not evidence for recovering an outcome-unknown
operation across rotation; V1 requires a drain/reconciliation boundary. Wrong
CA, wrong signed pin
and offline issuer fail before issuer HTTP application handling and create no
local claim or ledger account. CI additionally denies warnings for the exact
runtime/test targets and proves the test-only WebPKI feature cannot compile in
a release profile. The current preparation branch has static source evidence
only until that Linux CI cell passes; it is not public ingress, production
rollback-authority, real Lightning or payout-executor evidence.

### First-version executable path ledger

This ledger is a source-level audit of the executable seams, not a claim that a
fresh run passed. A check mark in separate columns does not mean one execution
joined those columns. In particular, the five-method/backend matrix uses an
authoritative-committer double, so it proves canonical wire/gate dispatch but
not a live method adapter. The feature-gated process supplement separately
uses the production Free, Standard Cashu, BAT and experimental ARC committers
and all five native backend handlers.

| Method | Web / generated-WASM boundary | Real provider wire / process | Authoritative state boundary | One same-run browser-to-store path |
|---|---|---|---|---|
| Direct BOLT11 receipt | yes: `payment-real-issuer` and `payment-two-provider` | yes: dedicated process cases reach DPF, Harmony hint/query, Onion and TEE-ORAM handlers | provider-local receipt spend survives restart | yes: `payment-two-provider` joins real Chromium, generated WASM, fake-settlement issuer, encrypted provider wire, `unified_server`, ProviderStore and a verified DPF query |
| Cashu BAT | yes: generated-WASM issuer acquisition in the opt-in CLN case and in the no-funds two-provider browser case | yes: `payment_v1_methods_process_e2e` plus the feature-gated non-DPF process supplement reach all five backends | real blind/DLEQ/unblind proof and durable provider-local spend/restart rejection | yes: the no-funds `payment-two-provider` BAT leg joins issuer, browser, provider and store |
| Free | yes: the no-funds `payment-two-provider` Chromium variant selects the exact signed one-request/one-hour `ip-rate-limited` offer, including the IP-rate-bucket leakage flag, and creates no invoice | yes: durable IP-limited Free reaches all five native backend handlers | IP quota is durable and restart-tested; the browser topology also requires a second secure connection to receive `server-busy`; open best effort intentionally has no spent row | yes: browser, generated WASM, exact signed Free/IP mode, real provider/store gate, durable same-provider rejection and verified DPF/Merkle query share one process topology; the final isolated-target current-tree run passed 3/3 |
| ARC experimental | yes: generated-WASM acquisition/presentation exists in the opt-in CLN case and the no-funds two-provider browser variant | yes: the real ARC adapter reaches all five native backend handlers | provider-local tag/nullifier persistence and restart rejection | yes: local issuer, browser persist-before-release, real provider/store replay rejection and verified DPF/Merkle query share one topology; the final isolated-target current-tree run passed 3/3, and ARC remains experimental/review-blocked |
| Standard Cashu eCash | yes: CDK default mode imports a real `cashuB` through freshly rebuilt current JS/WASM; browser-only accepts only explicitly acknowledged, SHA-256-pinned prebuilt runtime artifacts | yes: feature-gated strict-TLS NUT-03 cases reach all five native backend handlers | real ProviderStore swap/custody and real-CDK NUT-03/NUT-12 exist; the process cells use durable provider stores and prove local replay rejection without a second mint request, but not an independent production floor | not one same-run browser topology: the browser/CDK boundary and real-provider process boundary each have a final current-tree pass, but are separate executions |

The updated CDK default-mode closure item completed on 2026-07-28: the exact
Chromium-emitted spend reached the Standard-Cashu runtime committer and
ProviderStore, with the focused deterministic committer test retained as a
default gate. The final current-tree matrix completed the Standard-Cashu
provider-process rerun 1/1, and the isolated-target Chromium rerun completed the
Free/experimental-ARC topology 3/3. Remaining minimum production closure,
without changing Payment V1 wire semantics, is a same-run generated-WASM
Chromium-to-Standard-Cashu-provider join against an approved public-WebPKI
endpoint and independently operated production rollback floor. The existing
private root remains compile-time test-only and cannot enter a release.

Direct receipt, BAT, Free, experimental ARC and the Standard Cashu process cell
now have final coordinated current-tree rerun evidence; they do not need
another protocol adapter. The Free and ARC additions are browser/process
composition work and are wired into the same default local/CI command. Standard
Cashu still lacks a single joined
browser-to-provider run and an external public-WebPKI mint observation; the
feature-gated private-CA process cell is deliberately not either production
claim.

The serving-harness acknowledgement audit found two `serve-cln` construction
sites: the CLI parse test and `payment-real-issuer.global-setup.ts`; both include
`--allow-local-rollback-authority-dev` when using a local issuer floor. The two
Rust provider-process harnesses and `payment-two-provider.global-setup.ts` all
include `--allow-local-service-rollback-authority-dev` with a local provider
floor. `serve-fake` is compiled only with the explicit
`test-only-fake-lightning` debug/test feature and is a test-only exemption,
while init/check/custody commands are non-serving and therefore do not need
either acknowledgement. Default and release issuer CLIs treat `serve-fake` as
an unknown subcommand.

## Negative protocol tests

- wrong provider audience;
- wrong backend, workload, dataset rule, operation profile, or entitlement;
- Harmony query token used for hints and vice versa;
- provider A token used at provider B;
- client rejects a selected provider pair that advertises the same raw BAT or
  ARC verification-key fingerprint, before any shared-issuer override and
  without making a pair-specific network call;
- stale or unknown policy digest;
- Free proof attempts to select or upgrade a different signed free mode;
- forged free quota/window/PoW target/priority is ignored or rejected;
- client-forged amount, limit, priority, ARC context, or profile;
- cleartext service-policy or auth request after/before handshake;
- valid auth followed by an unrelated backend opcode;
- second logical operation attempted on one grant;
- resource counter/byte/frame/wall-clock exhaustion;
- truncated, oversized, noncanonical, duplicate, or trailing fields;
- auth padding not exactly an advertised class;
- detailed verifier error is not exposed to client.

## Consumption and persistence tests

For provider-local receipt, anonymous ticket, BAT, ARC, and settlement credit:

- first spend succeeds; replay fails;
- 2, 8, and 64 concurrent spends have exactly one winner;
- process killed before commit leaves unspent;
- process killed after commit but before response remains spent;
- restart rejects spent proof;
- backup/restore runbook detects stale ledger rollback.

For shared-issuer redeem and every HTTP state transition:

- only HTTP 200 is a success; 201, 204, 299 and every other status remain a
  non-success even when paired with a success-shaped media type or body;
- the provider deterministically derives the wire idempotency key with its own
  HMAC secret over the exact clearing authorization, credential binding and
  credential digests; the issuer cannot derive the provider-local delivery key;
- exact retry returns the identical stored signed response bytes, and the same
  idempotency key with a changed request digest fails;
- only after exact response canonical/signature/request/offer verification does
  the provider claim the separately domain-separated HMAC delivery key in its
  rollback-protected synthetic namespace; first claim alone grants;
- exact replay of Free, BAT or experimental ARC at one provider never grants
  twice, while another provider has an independent secret/store and no shared
  spent set;
- 8 concurrent handlers of one exact issuer success have one local grant
  winner and seven fail-closed losers;
- an invalid issuer response creates no local claim, and a store for the wrong
  provider fails before transport;
- authorization validity is checked only after exact committed-request lookup,
  so a low-level caller that explicitly retained the identical proof can recover
  a lost response after rotation by replaying only that transcript;
- official Web deletes/burns the presentation before send and does not
  automatically retry shared redeem; loss after the local claim or loss of
  `AUTH_GRANTED` consumes the entitlement; and
- a fixture with binding `amount = 1`, clearing `accepted_value = 10`, provider
  credit `9` and issuer fee `1` proves protocol amount is independent of the
  clearing value split.

For standard Cashu eCash, the external mint's atomic NUT-03 invalidation is the
only authoritative spend boundary. The PIR provider must not add a second
local authoritative input-spend commit after a successful swap. Its final local
custody/grant transition still uses a fresh nonzero 256-bit nonce and advances
`spend_seq` so cloned-state exact CAS attempts cannot both be treated as the
same granted successor.

For every provider grant transition:

- fresh OS randomness is nonzero and bound into the committed successor;
- provider-local spend, Free-IP and final Standard-Cashu grant increment
  `spend_seq`;
- two callers starting from cloned detailed state and racing the same external
  CAS have exactly one anchored winner; the loser fails closed; and
- independent ProviderStore databases are rejected as an active/active design,
  rather than being treated as replicas of one spend authority.

ARC-specific:

- client changes presentation context;
- client resets nonce;
- client inflates presentation limit;
- key epoch rotates;
- tags persist until the declared keyset retirement horizon.

Cashu-specific:

- invalid/missing DLEQ fails wallet acquisition;
- concrete NUT-12 verification matches the official challenge and blind
  signature vectors and rejects point/scalar/proof tampering;
- wallet unblinding succeeds only after DLEQ verification and an exact local
  `(secret, r) -> B_` reconstruction; issuer note verification rejects unknown
  mint keys, bad signatures, witnesses, and NUT-10-shaped secrets;
- wrong keyset/unit/amount fails;
- exact-value swap includes NUT-02 input fees and conserves value;
- provider persists blinded outputs before swap;
- `PREPARED -> SUBMITTED` advances ProviderStore generation and its independent
  rollback-floor CAS before NUT-03 is sent;
- a lost or failed submit CAS response performs zero NUT-03 calls; checked
  restart observes `SUBMITTED` and uses only NUT-09/NUT-07;
- HTTP 400 with a canonical NUT-00 error body remains outcome-unknown because
  NUT-00/NUT-03 defines no atomic non-commitment proof; the intent and exposure
  remain durable and every retry uses only NUT-09/NUT-07;
- exact replay and 2/8 concurrent prepare, submit, and grant callers each have
  one durable mutation winner under `UNIQUE(mint_id, input_set_digest)`;
- restoring a `PREPARED` backup after submit/grant fails against the external
  floor and cannot revive NUT-03 or the grant;
- lost swap response is recovered with NUT-09 using identical outputs;
- browser import accepts only the bounded known NUT-12 `dleq.e/s/r` shape,
  strips it locally, and proves none of it crosses the PIR wire; witness,
  NUT-10 and unknown proof fields fail closed;
- BAT presentation and shared redeem contain no DLEQ proof/blinding scalar;
- BAT spend keys remain identical when only policy/audience-derived metadata is
  rebound, while different raw DHKE keys produce different spend keys;
- one BAT raw key cannot be installed under another provider/scope/offer/profile
  or key epoch, including after namespace close and process restart;
- duplicate proof inside one request fails atomically;
- standard V4 short/full IDs and base64 variants are accepted only by the
  wallet import layer and normalize to one full-ID binary PIR proof;
- distinct recovery and custody keys/AAD cannot decrypt each other's records;
- finite value/note exposure is enforced atomically before NUT-03 for the exact
  mint/unit, including 2/8 concurrent admissions and overflow boundaries;
- `WALLET_STORED -> GRANT_ISSUED` atomically inserts exactly one encrypted
  note-only lot plus globally unique provider-local note fingerprints;
- export selection never exceeds 512 notes or 16 keyset groups, leaves
  overflow lots available and permits more than 16 lots sharing one keyset;
- export ID replay requires the same provider/mint/unit/max-lots/recipient key,
  persists/releases one exact envelope and conflicts on changed bytes;
- recipient-sealed export tampering, wrong provider/key, noncontributory X25519
  keys, truncation/trailing data and size overflow fail closed;
- custody acknowledgement requires the exact artifact digest and transitions
  the batch/members atomically without claiming NUT-05/Lightning/payout or
  releasing finite custody exposure;
- explicit `spent-confirm` batches only same-mint/unit exports into one bounded
  strict-HTTPS NUT-07 request, performs no polling or automatic retry, and
  rejects missing/extra/reordered/duplicate `Y`, unknown states, oversized
  witnesses and any `UNSPENT`/`PENDING` note without a retirement write;
- all-`SPENT` confirmation binds the immutable artifact, exact ordered member
  IDs, sealed-lot metadata and stored note fingerprints; each per-export commit
  refreshes the current rollback floor and persists only its own observation
  digest rather than the wider HTTP-batch digest;
- exact terminal replay requires neither custody keys nor another mint request;
  a partial multi-export commit stops, reports prior commits and is safe to
  rerun explicitly, while NUT-07 evidence never claims settlement or payout;
- the opt-in disposable CDK runner imports one real padded V4 token with known
  DLEQ wallet metadata through both the freshly rebuilt default-mode or
  explicitly hash-pinned browser-only JS/WASM ABI and the native Rust logic;
  Chromium rejects the untouched loopback-HTTP
  token, accepts only an owner-only metadata-relabelled token against the exact
  signed CDK keyset, stores it in the encrypted vault, emits only canonical
  provider proof bytes, and leaves no token or endpoint in `localStorage`;
- the extended CDK case reconstructs a spend only from authenticated custody,
  uses a second independently keyed client/store for the successor NUT-03, then
  observes first-custody all-`SPENT` and successor-custody all-`UNSPENT` through
  exact NUT-07 without placing the bearer in process argv; two consecutive
  opt-in local branch runner invocations completed this lifecycle;
- Cashu eCash and BAT decoders reject each other's encodings.

## Backend state-machine tests

### DPF

- grant covers the expected INDEX, CHUNK, and Merkle rounds only;
- consecutive INDEX batches consume one logical input each, while the first
  CHUNK/Merkle follow-up permanently forbids an INDEX rollback on that grant;
- padding invariants remain unchanged;
- two independent providers accept unrelated schemes;
- no slot index is added to capability or logs.

### Harmony hint

- warm cache performs no hint authorization;
- cold cache consumes once, serves the V2Full main INDEX/CHUNK bundle, then
  accepts the same-db full-group legacy level-10+/20+ sibling-hint sequence on
  the same socket without marking the grant complete after the main request;
- a provider process bound with `--pool-db-id N` accepts canonical V2Full only
  for that loaded database, including non-zero delta IDs, and rejects another
  database before any hint frame is served;
- after a Payment V1 V2Full grant, the SDK sends V2Full for that exact database
  even when `db_id != 0`; pool-unavailable never falls back to V1 and losing
  local main-hint state never retries the already-consumed main bundle;
- V2Full decoding rejects a non-zero reserved byte, redundant zero `db_id`,
  truncated bodies and trailing bytes;
- concurrent V2Full authorization attempts for one available entry have one
  reservation winner; losers receive non-consuming `ServerBusy`, and no
  credential verification/commit runs for them;
- authorization rejection, grant-response loss, deadline expiry and disconnect
  before main dispatch return the unexposed connection-local reservation,
  while the first main dispatch consumes it and never returns it after a
  possible partial send;
- the post-grant dispatch deadline is armed only after the complete encrypted
  `AUTH_GRANTED` frame is written and flushed; a slow successful flush does not
  reduce the dispatch window, and subsequent Ping/Pong or application traffic
  cannot reset the immutable instant;
- apart from bounded WebSocket control handling, a pending V2Full reservation
  accepts only the exact encrypted canonical `HarmonyHintsV2` main request for
  its bound database; cleartext, malformed, wrong-database and unrelated
  application frames close without exposing the reserved key;
- returning a reservation cannot grow the queue beyond its configured target
  when the background generator refilled concurrently;
- sibling-before-main, wrong DB/level, partial or duplicate group sets,
  skipped/repeated/rollback levels and budget exhaustion terminalize;
- fixture budgets cover the deterministic production-shaped main+sibling flow
  and are explicitly not commercial pricing;
- V2 half two-socket attach consumes once;
- wrong/random/expired session token cannot attach;
- scarce V2Full hint capacity is atomically reserved before spend and the
  reserved entry, not a later global `try_take`, serves the granted connection;
- online floor accounting considers only paths in the current process's fully
  validated, ready `PoolState` snapshot and requires them to be currently
  lockable; corrupt/unvalidated canonical-looking disk surplus cannot satisfy
  the floor;
- the hot reservation path uses a non-blocking capacity-lock attempt; a locked
  selected inode rotates behind the bounded current snapshot so it cannot hide
  a later usable candidate, while pool-wide lock/floor ambiguity fails
  non-consumingly;
- capacity, durable/legacy reservation, generation, staged and reconciliation
  inode guards explicitly unlock on normal/error/drop paths; the main operation
  error wins, while success followed by unlock failure fails closed;
- a real child-process barrier test locks one of two validated inodes from a
  separate OS process and proves online admission cannot take the remaining
  floor entry while provider-local reservation can use it;
- the floor prevents a successful online reservation from consuming the final
  validated lockable entry at that instant; it does not guarantee fairness,
  priority or immediate admission for any provider-local caller;
- a real `unified_server` subprocess with a private disk pool proves that an
  invalid proof does not rename/delete the ready artifact, a granted connection
  that disconnects before main dispatch returns the unexposed entry, the first
  main dispatch consumes the exact locked inode before any PRP preamble, and a
  current-version restart accepts the matching binding marker;
- subprocess fault injection that removes or replaces the locked ready name
  between grant and main dispatch must fail closed without a PRP preamble; a
  bounded watchdog must turn any lock-order or shutdown hang into a test
  failure;
- an upgrade fixture starts with markerless legacy state and verifies fail-start
  preservation; the operating test must never run old and new binaries against
  one live pool directory;
- stress coverage opens more structurally valid but invalid remote-method
  authorizations than ready entries and verifies bounded locks, no regeneration
  burn, deadline release and the configured overload response. This is DoS
  evidence, not proof of fair admission against distributed sources;
- cached compatible hint causes no hint authorization/redeem;
- hint and sibling capacity limits cannot be exceeded.

### Harmony query

- `payment_v1_process_e2e` launches two independent provider processes and
  executes the canonical level-0 h0/h1 plus level-1 h0/h1 four-frame query at
  each provider under distinct Harmony scopes/offers/credential keys. It also
  checks DPF-to-Harmony scope mismatch non-consumption, terminal-DFA rejection,
  and durable Harmony replay rejection after restart without naming a hint
  provider;
- query server does not learn hint provider;
- query grant cannot fetch hints;
- cached hint metadata is compatible with policy/dataset binding;
- required Merkle traffic remains allowed after query frames;
- enforced V1 rejects legacy single-group opcode `0x42` and admits only K-padded
  `0x43` batches;
- level-0 and level-1 h0/h1 pairs require exact consecutive round IDs; a half
  pair cannot transition phase, and phase skip/rollback terminalizes;
- only the even level-0 pair start consumes one logical input; K*(T-1) padding
  consumes work units only;
- N>K/collision plans needing another INDEX pair fail under a one-round profile
  and succeed only under a higher signed `max_logical_inputs` profile.

### Onion

- the real-process `payment_v1_onion_process_e2e` boundary reaches and decrypts
  production INDEX, CHUNK and both Merkle-sibling workers with a public-API
  fixture and a real chunked key registration;
- one grant covers exactly one key registration followed by bounded INDEX,
  CHUNK, Merkle INDEX and Merkle DATA phases;
- INDEX/CHUNK round IDs are exact and monotonic; Merkle pass round is exactly
  zero, with same-family repetition allowed only for additional padded passes;
- extra key registration, phase skip and rollback terminalize;
- an all-empty key-eviction result fails closed without automatic
  re-registration or replay;
- registration ACK and every query response reject canonical errors, wrong
  opcodes/rounds, truncation and trailing bytes;
- Merkle tree-top/sibling requests remain mandatory and bounded.

DPF, Harmony query/full-hint and Onion tests must also assert connection-close
semantics: these variable-length operations have no inferred success/`END`
transition, so closing the socket discards only volatile DFA state and never
refunds or unspends the already committed capability.

### TEE-ORAM

- one entitlement covers exactly one bounded logical browser request group,
  including every frame produced by its fixed batch planner;
- the server accounts every frame/input/byte/work unit against the signed grant
  and accepts no second logical request group;
- abort, truncation, extra frames and concurrent reuse cannot reopen a completed
  or spent grant;
- cleartext ORAM and an ORAM operation under any PIR/Harmony/Onion scope fail
  closed.

The default Payment CI realizes this boundary with a deterministic no-funds
process test:

```sh
cargo test --locked --offline -p runtime --features cuckoo-oram \
  --test payment_v1_tee_oram_process_e2e
cargo clippy --locked --offline -p runtime --features cuckoo-oram \
  --bin unified_server --test payment_v1_tee_oram_process_e2e \
  --no-deps -- -D warnings
```

It constructs real direct INDEX/CHUNK Circuit ORAM images, authenticated
sidecars and separate trusted controller state, then crosses a real
`unified_server` secure channel and provider-local paid-receipt gate. It
checks provider/backend/workload mismatches before ORAM work, exact handler
output, one-frame completion, durable replay rejection and authenticated ORAM
reopen after process restart. The fixture is `NoSevHost`, deterministic and
uses a local SQLite rollback floor; production trust-chain and data evidence
remain separate acceptance gates.

## Invoice lifecycle tests

- invoice created only after quote row is durable;
- crash after Lightning invoice creation but before the mapping commit recovers
  by deterministic backend label and leaves no orphan payable invoice;
- fixed amount/network/expiry are parsed and checked;
- the quote intent binds the exact root-signed quote-key delegation;
- quote-key rollback and same-epoch delegation forks fail before invoice
  display, including after restart;
- a delegation whose validity does not cover the complete claim deadline is
  rejected;
- unpaid, settled, expired, canceled, and backend-unknown states;
- notification lost, lookup reconciliation finds settlement;
- HTTP response lost after payment; claim recovers same issuance;
- leaked quote ID without the claim private key cannot claim issuance;
- leaked quote ID cannot read invoice/status; status requires a fresh BIP340
  claim-key request and a replayed `(quote_id, nonce)` is rejected;
- stale quote snapshots, changed quote IDs, same-version forks and unreachable
  lifecycle successors fail against the browser's highest stored snapshot;
- two concurrent transition workers race one predecessor version and exactly
  one issuer-store CAS/signature commits;
- claim ignores client-provided quote status and succeeds only from an
  authoritative store row in settled/late-settled or exact claimed replay;
- the production BOLT11 adapter accepts an official signed vector, exercises
  both explicit and signature-recovered payees, maps Bitcoin/testnet/signet/
  regtest exactly, and rejects bad signatures, simnet, wrong HRP/network,
  wrong payee, amountless/zero invoices, wrong amount, altered expiry,
  uppercase/mixed-case and any non-canonical round-trip;
- claim signature cannot be replayed with changed blinded outputs;
- BIP340 claim/status adapters use prehash verification (no accidental second
  SHA-256) and pass official positive and negative BIP340 vectors;
- injected DNS plus all candidate addresses share one connect deadline, and
  the deadline-enforcing TCP wrapper rejects a trickled response without
  refreshing the full-request I/O deadline; a full rustls-plus-HTTP trickle
  integration remains separate staging evidence;
- a trickled CLN Unix-socket response exceeds one RPC wall-clock deadline and
  remains response-lost-after-write; the semantic precommit suite covers
  unavailable-before-write, while a deterministic real Unix-transport
  zero-byte-write failure case remains an evidence gap;
- BitcoinPIR quote claims reject NUT-20-domain signatures and standard NUT-04
  claims reject BitcoinPIR-domain signatures;
- paid old-policy quote and receipt remain usable through the declared grace
  window, then fail closed;
- the original current-policy request remains exactly `[version=1]`; retained
  lookup requires selector plus the exact non-zero digest and rejects missing,
  unknown, wrong, zero, truncated or trailing selectors/digests;
- retained startup rejects current/newer, duplicate, wrong-provider/key,
  free-only and missing durable namespace configurations; exact reload after a
  restart is idempotent;
- a retained response permits only its exact provider-bound scope/offer during
  grace; Free/PoW acquisition and request/auth digest substitution fail before
  credential commit;
- native and Web/WASM retained handles are secure-channel-exporter-bound and
  expose redemption only; acquisition, Free and PoW remain current-policy only;
- verification, policy and Merkle/tree-top preflight responses consume the
  exact final encoded WebSocket message count and byte length from a separate
  fixed per-connection budget; exhausting either dimension is terminal and a
  later opcode cannot reset it;
- a chunked preflight response reserves its complete encoded message group and
  byte length before the first message is sent, so an over-budget tree-top is
  rejected without a partial response;
- service authorization and Harmony attach responses do not consume the
  preflight budget, so preflight accounting cannot strand an otherwise valid
  credential commit response;
- the enforced pre-authorization deadline treats equality as expired and is
  rechecked after a potentially blocking durable authorization commit; a late
  result sends no grant response and permits no backend work, while explicit
  legacy mode is unaffected and the already-started commit is not cancelled;
- deterministic permanently-`Pending` sink tests prove that the same fixed
  deadline interrupts `poll_ready`, a grouped Merkle tree-top preflight flush,
  a granted AUTH-result flush after durable commit, and a complementary Harmony
  `Attached` flush; gate `Granted` never replaces the deadline before
  `auth_result_delivered`;
- successful Harmony `Attached` delivery marks the connection only after flush,
  while rejection leaves the deadline armed; Harmony encoding, ordinary flush
  error, or deadline expiry keeps the independent backend-delivery guard closed
  and sends no PIR work, and an invalid granted AUTH result cannot fall back to
  a diagnostic send after the gate has committed;
- a source-level forbidden-field scan proves default unified-server connection
  logs contain no raw peer/client identifier, per-query timing, selected
  database/group, sequence/round identifier or request/response size; normal
  artifacts do not recognize `--unsafe-debug-query-logging`. The switch exists
  only under `test-only-unsafe-query-logging` in a debug artifact, and both
  ordinary release and release with forced debug assertions reject that
  feature at build time;
- issuer restart in each state;
- issuer `init-store` refuses overwrite, public parents and canonical aliases,
  emits mode-0600 files, verifies exact generation-zero identity, and reopens
  both independent files before success; failure never auto-deletes unknown
  partial state;
- issuer and enforced provider startup reject final-component symlinks,
  group/world-accessible files, non-private parents and store/rollback paths
  resolving to one inode; SQLite WAL/SHM remain confined by the private parent;
- provider/issuer init, check and serving CLIs require exactly one local-test
  SQLite floor or remote config; missing/both choices and an otherwise ignored
  partial flag fail closed. `unified_server` rejects local mode without its
  explicit dev acknowledgement and rejects that acknowledgement in remote mode;
- remote init requires a caller-preserved nonzero store-instance ID while local
  init rejects an injected ID. Bad config/key/namespace/pin/permission/timeout,
  unavailable authority and inconsistent authenticated floor all fail before
  serving or custody work, with no local/unpinned fallback;
- CORS `--allow-origin` accepts only one canonical exact HTTPS origin or HTTP
  localhost origin and rejects userinfo, path, query, fragment, default/non-
  canonical ports, uppercase hosts and every ASCII control/whitespace byte;
- restoring an internally consistent but stale issuer backup fails against an
  independently persisted monotonic floor before any quote/claim is served;
- page close/reopen restores quote without localStorage invoice history;
- one sat cannot obtain a higher price/bundle;
- overpayment does not increase issuance;
- routing fee is not treated as underpayment;
- late settlement issues once if backend says settled;
- no automatic refund/query-credit restore.

## Deployment evidence tests

- runtime-evidence accepts only the exact local-files NSS profile and checks
  stable root-owned policy snapshots, identity-relevant `getent` projections,
  every user's `id -G`, UID/GID uniqueness and protected-group closure;
- a final policy snapshot detects `/etc/nsswitch.conf`, `/etc/passwd` or
  `/etc/group` drift during later live checks;
- two bounded full `/proc/<pid>/task/<tid>` scans must produce identical
  protected UID/GID holder records, record `CapInh`, `CapPrm`, `CapEff`,
  `CapAmb`, and `CapBnd`, and reject reviewed dangerous active capabilities on
  non-root threads; managed masks must fit the exact rendered policy (Caddy
  only `CAP_NET_BIND_SERVICE`, HAProxy/business services zero). An unmanaged
  stale holder, wrong cgroup, changed credential/capability, omitted MainPID,
  pass race, DAC/ownership/set-ID/SETFCAP bypass or legacy evidence fails;
- an exact managed-unit cgroup may contain master/worker processes only with the
  unit's complete reviewed UID/GID/group set, and a post-scan generation check
  rebinds MainPID, InvocationID and ControlGroup;
- post-scan directory/socket snapshots must still equal the pre-scan inode,
  type, owner, group, mode, ACL/xattr/capability and stat-command evidence;
- real Ubuntu procfs enumeration and an Alpine repeated-`Groups:` regression run
  without skips; evidence count/byte/time bounds fail closed;
- stopped-edge evidence requires every manifest unit inactive/dead with
  MainPID 0 and empty ControlGroup, every runtime socket absent, every service
  account UID/GID-pinned with a nologin/false shell and locked shadow password,
  and an empty protected-holder closure across both passes; active units,
  present sockets, login-capable/unlocked accounts, namespace drift and legacy
  evidence fail closed;
- target activation invalidates all old connected FDs, approves the exact
  stopped-edge evidence digest before any listener, recreates the volatile
  listeners in HAProxy-before-Caddy order, collects a fresh live digest, and
  independently proves execution in the host initial PID namespace;
- public and publisher relay listeners reject deliberate wrong-lane EVENTs and
  prove their exact event IDs absent before a correct-lane publication.
- Caddy source validation rejects additive binds/upstreams, imports, invokes,
  snippets, named routes and non-v2 proxy transports; pinned adapted JSON has
  exactly the two reviewed listener/host/socket graphs, and both cross-bind
  HTTP probes return 4xx without changing any of the four backend counters.

## Directory tests

- outer Nostr signature and inner operator assertion both verify;
- a deterministic, process-local NIP-01 fake relay accepts the real signed
  `EVENT` publish envelopes, applies addressable-event replacement, and serves
  the Rust-generated 16-shard `REQ`/`EVENT`/`EOSE` flow into the production
  WASM catalog verifier and durable rollback/selectability boundary;
- that publish-to-read harness carries two independent providers with distinct
  directory, operator and policy keys and no peer/pair identifier; relay
  tampering, a wrong pinned directory key, expiry and a replayed older catalog
  all fail closed;
- stale, expired, lower-sequence, wrong-key, and malformed events fail closed;
- unexpected Nostr tags/JSON fields cannot carry payment or selected-peer
  artifacts, and logical revisions require strictly increasing NIP-01
  `created_at` values;
- signed tombstone supersedes every lower sequence;
- same-epoch catalog checkpoint forks across relays fail closed;
- a complete shard must exactly match the checkpoint's sorted provider,
  sequence, and event-ID tuples before any entry is selectable;
- a consistent directory catalog is explicitly not treated as proof of
  independent provider control;
- catalog download does not send a requested provider pair or payment method;
- live verified policy/identity mismatch overrides directory discovery;
- native publication verifies a frozen EVENT against an explicit directory-key
  pin and sends its exact bytes without loading a signing key;
- every relay/event requires one matching positive NIP-01 OK; false,
  unexpected, out-of-order, duplicate, missing, `NOTICE`/`CLOSED`, non-text,
  oversized and timed-out replies fail closed;
- two through eight relay hostnames are all attempted, partial success is a
  nonzero result, and an exact artifact can be rerun without automatic retry;
- publisher `--validate-only` applies the exact artifact/key/time/relay checks
  and never invokes the relay transport;
- staging readback loads no key, applies a WebSocket transport payload limit,
  requests only frozen event IDs and requires each exact event value once plus
  EOSE; raw URL normalization aliases, symlink/FIFO/device/changing files and
  per-file or cumulative size violations fail before dialing; publish/readback
  success remains distinct from catalog deployment;
- manual endpoint plus pinned operator fingerprint works without the directory.

Real-money tests are excluded until separately approved. Regtest/signet or a
deterministic fake Lightning backend is used by default.

The default-Signet staging preflight focused suite additionally requires:

- all three role-specific channel/gossip topologies pass only with exact,
  distinct compressed node keys, public active channels and same-SCID
  bidirectional gossip; payer/router/issuer also enforce the configured
  spendable/receivable threshold in the payer-to-router-to-issuer direction;
- old Core, wrong chain/challenge/genesis, IBD, excessive height lag, wrong CLN
  identity/network/version, unknown/inactive plugins, private/disconnected
  channels, missing/low directional liquidity estimates, missing gossip, SCB
  mismatch and stale/unconfirmed backup receipts fail closed;
- config and receipt TOML reject unknown fields; binary/plugin, config, Core
  RPC cookie, socket and receipt paths reject symlinks, unsafe owner/mode and
  writable protected parents;
- Core CLI arguments require exact Signet, loopback host, non-zero port and the
  configured owner-only cookie while rejecting `-conf`, inline credentials,
  implicit auth, special/mutating modes and cookie path substitution; and
- the mock command layer invokes only the documented read-only Core/CLN RPC
  methods and never wallet, address, channel-open, payment or shutdown methods.

The backup-receipt tests prove only strict parsing, protected-file handling,
exact `getinfo -> staticbackup` command order, SCB-digest binding, atomic
receipt replacement, explicit parent-lock release, primary-error precedence
and fail-closed unlock failure after success. Both long acknowledgement flags record an **operator
assertion**; they do not prove an offline copy exists or can be restored.
`staticbackup`/SCB is static channel-recovery material, not a live/dynamic CLN
database backup. A datastore-specific backup/replication and restore rehearsal
remains a separate Signet acceptance requirement.

The admin and hint-pool suites exercise success/error/drop reuse and repeated
default-parallel contention. A future deterministic regression should keep an
inherited duplicate descriptor alive in a child while proving explicit unlock
releases the shared open-file-description lock; the current five-round stress
evidence does not by itself create that exact fork barrier.

The Rust publisher reader has a deterministic every-field snapshot-stability
test plus FIFO/symlink/oversize cases. The Node readback suite covers the same
object-type and size boundaries but does not yet deterministically mutate a
regular file during its read; that remains a P2 coverage gap, not permission to
accept a changing artifact.

## Shared clearing and settlement tests

- identified redeem credits only the authenticated provider;
- blind redeem also requires provider authentication and signs exactly the
  fixed settlement denomination;
- bearer client cannot redirect settlement to its own blinded outputs;
- invalid ticket cannot obtain a blinded signature;
- atomic failure signs no output and leaves ticket unspent, or commits both;
- provider unblinds and stores note before serving in the test harness;
- delayed batched deposit credits the right total;
- duplicate settlement-note deposit rejected;
- arbitrary compressed points without valid NUT-12 fail blind-promise
  verification;
- a structurally valid settlement note without a valid Cashu signature or
  spending-condition witness never reaches the ledger; the adapter-derived
  authoritative `Y` is the only spent identifier input;
- retained settlement keyset expiry fails closed, while an expired historical
  clearing authorization does not block recovery under a current provider
  registration;
- a valid retained keyset copied into another issuer lineage is rejected before
  deposit verification or credit;
- issuer fee plus provider credit equals accepted value, while the credential
  binding `amount` is independently authenticated and need not equal that value;
- shared-issuer-online and standard-Cashu verification fail closed before PIR
  work when their issuer/mint is unavailable;
- a previously issued, unexpired provider-local receipt, BAT, anonymous ticket,
  or experimental ARC credential remains verifiable during an issuer outage;
- privacy documentation states that issuer learns provider at redeem;

The retained-key cases above exercise issuer-side settlement deposit and
historical response verification only. They do not exercise, and must not be
read as, provider-runtime recovery of an in-flight shared redeem across a
clearing-authorization, approval-key or issuer-settlement-key rotation. V1 has
one such active binding in `SharedIssuerAdmissionCommitterV1`; pending provider
redeems must be drained/reconciled before rotation.
- an anonymizing ingress claim is tested separately from clearing-key
  authentication and never presented as hiding provider from the issuer.
- one signed payout intent cannot create two payouts under different HTTP
  idempotency keys; intent consume, debit, payout and outbox are atomic;
- payout status binds the original signed response, rejects payout-ID
  substitution, stale/lower versions and terminal reversal; a fresh nonce
  commits a latest signed successor, while an exact retry returns the same
  durable bytes after restart, registration expiry and provider request-key
  rotation without allowing an old-key fresh request; retained-registration
  digest tampering and wrong-provider lookup fail closed, and once a newer
  latest status commits the older exact request is no longer replayable;
- rotating the current issuer settlement key does not strand an initial payout
  response signed by a retained key, while a missing/wrong-issuer keyring fails
  closed;
- two workers signing `Succeeded` and `Failed` from the same exact predecessor
  race one store CAS; exactly one commits and the loser returns no response.

The settlement HTTP/service, transport-neutral provider client, settlement-v2
SQLite store and no-funds payout worker expose focused local suites for these
boundaries. Historical pre-v2 results cover the append-only registration
history and earlier provider-client cases; the current-tree store/worker results
must be recorded afresh rather than inferred from those counts. Historical
registration is valid only after a durable latest response, exact canonical
request digest and provider match have been established; it is never authority
for a fresh status request or financial mutation. Whole-tree CI remains the
release record for interactions outside these focused cases.

The initial-payout persist-before-send P1 is closed by the provider-client
typestate. The client durably prepares
the exact initial payout envelope before transport submission, exposes only a
persisted/restored marker to submit, recovers the identical request after an
outcome-unknown/restart and atomically installs the verified response plus
rollback floor. A next payout starts only from a `Succeeded`/`Failed`
predecessor, atomically CASes and archives it and forms one monotonic
repeat-payout chain. Fresh preparation uses real current time, the current
provider registration and current issuer key; retained material is valid only
for exact committed replay. The concrete SQLite provider store and no-funds
issuer outbox worker now exist, as does the concrete strict-WebPKI HTTPS
provider-settlement transport. Production activation still requires a
genuinely independent floor adapter and a separately reviewed real-funds
executor whose external system provides linearizable durable command-ID
submission/lookup or an equivalent no-submit fence, plus deployment acceptance.
A local lease is not an external exactly-once primitive.

## Browser tests

- IndexedDB schema migration and rollback;
- Web Lock + transaction makes one multi-tab spender win;
- token is burned before send;
- ARC next nonce is committed before send;
- refresh does not resurrect a burned token;
- quota inventory is separated by provider/scope/scheme/keyset;
- quote recovery is not linked to address/query history;
- strict verification failure prevents invoice creation and presentation;
- payment service failure cannot select an insecure/free fallback unless the
  user explicitly selects a separately advertised Free offer.
- current-policy rotation does not strand an exact-digest retained capability
  or BOLT11 recovery record during its signed grace; a missing, altered or
  wrong-scheme retained binding fails closed before presentation.
- provider legs are prepared, frozen, acquired and authorized independently;
  the pair correlation guard runs once both exact verified selections exist and
  again immediately before the query.
- staged DPF/Harmony adapter tests require a role-1 transport failure to leave
  role 0's strict transport and signed-policy path intact, without a role-0
  disconnect or capability attempt; native lifecycle tests retain
  proof/tree-top bindings until the final leg closes, clear a session-bound
  hint grant with its hint transport, close same-role Harmony secondary
  transports on secure upgrade, and consume attestation seeds before a
  fallible handshake.
- staged product tests permit first-leg signed-policy display with zero tree-top
  requests, then connect the second exact role and complete exactly one shared
  pre-authorization preflight before either capability path is enabled. They
  require fail-closed one-shot behavior after a preflight mismatch and no query
  after either authorization failure. Final readiness is bound to the exact
  paid `db_id`; attempts to query or verify another database are rejected.
  Disconnecting either pair while that
  preflight is in flight must invalidate its generation so late completion
  cannot restore query readiness or stale proof UI state.
- credential-issuance claim recovery may retain and replay its exact blind
  transcript, but shared-redeem presentation does not: official Web burns/deletes
  before send, performs no automatic retry and never restores a lost post-claim
  grant.

The implemented real-browser subset runs with:

```sh
cd web
npm run test:e2e:payment-vault
npm run test:e2e:payment-real-issuer
npm run test:e2e:payment-two-provider
```

From the repository root, the real-CDK standard-Cashu default mode builds the
current admin/WASM artifacts offline before starting the disposable mint:

```sh
scripts/payment-v1-cdk-regtest-e2e.sh
```

It requires separately pinned CDK 0.17.3 binaries, `wasm-pack 0.14.0`, and the
offline Cargo cache. It starts only a disposable loopback fake-wallet mint and
uses no Lightning or real funds. It continues from the Chromium output into
`standard_cashu_real_cdk_browser_provider_two_server_e2e`, then uses a second
independent note for `real_cdk_nut03_swap_verifies_dleq_and_commits_custody`.
The former is the real `unified_server`/Free-peer/DPF/Merkle/restart boundary;
the latter is the separate native custody lifecycle.

No-Cargo `--browser-only` is prebuilt-artifact evidence, not current-tree build
evidence. It requires
`BITCOINPIR_CDK_BROWSER_ONLY_ACKNOWLEDGE_PREBUILT=1`, an absolute
`BITCOINPIR_BPIR_ADMIN`, and explicit SHA-256 pins in
`BITCOINPIR_BPIR_ADMIN_SHA256`, `BITCOINPIR_WASM_PACKAGE_JSON_SHA256`,
`BITCOINPIR_WASM_JS_SHA256` and `BITCOINPIR_WASM_BINARY_SHA256`. The runner
must fail before mint startup if any acknowledgement, artifact or pin is absent
or mismatched. `LOCAL_ACCEPTANCE.md` contains the complete invocation.

The first command uses two same-origin Chromium tabs and the production
vault/acquisition controller to cover Web Lock contention, single-use validation release versus
delete-before-return commit, ARC persist-before-presentation, page reload,
byte-identical paid-claim replay, one-winner recovery, atomic capability
installation and zero payment-material `localStorage` writes. Its SDK is a
Vite-selected test-only state-machine double and issuer HTTP is locally
intercepted. This is not evidence for generated Rust/WASM cryptography, a
running issuer/provider, a wallet, a full query lifecycle, strict PIR
verification, deployment or remote interoperability. The existing product
controller unit test separately executes a query sentinel while making
`localStorage.setItem` fail on any call.

The second command adds a distinct acquisition boundary: current generated
Rust/WASM verifies the signed fixture policy and direct-receipt issuance, while
real Chromium talks over HTTP to a real loopback `payment-issuer serve-fake`.
It covers exact-price fake settlement, authenticated status, lost-response
exact claim replay after reload, issuer idempotency, atomic vault installation,
WASM capability validation/single-use consumption, and the absence of invoice
or query-sentinel bytes from claims and `localStorage`. Its provider channel
exporter and signed policy response framing are test fixtures; it does not
launch a provider, execute a query, use a wallet/Lightning node or real funds,
or exercise BAT/ARC acquisition in the default fake-backend CI job. Its
Playwright setup explicitly enables `test-only-fake-lightning` only for this
fake-backend mode; the default issuer artifact and CLN-regtest mode omit it.
The opt-in local CLN-regtest variant adds generated-WASM BAT/ARC acquisition,
payment,
lost-claim-response and reload recovery without real funds; it is not a default
release gate. That first phase still does not launch a PIR provider; the newly
composed joined phase then launches two providers and carries fresh
direct/BAT/experimental-ARC capabilities through their gates and a verified DPF
query.

The third command is wired to use current generated WASM, two distinct
loopback fake issuers and two distinct loopback providers. It verifies the
explicit `NoSevHost` boundary, every pinned synthetic catalog/database-proof
field and independent signed policies. Its first selection acquires direct
receipt/BAT capabilities. Its second selection uses the exact signed
one-request/one-hour Free/IP-rate-limited mode and IP-rate-bucket leakage
disclosure on provider 0 without any invoice or issuer request, and
generated-WASM experimental-ARC issuance on provider 1 with explicit
issuer/provider opt-in and a fixture-dedicated key. Only this loopback harness
gives provider 0 the explicit direct-peer-IP trust flag. Both selections reach
the real provider admission gates. The tests check durable second-connection
Free rejection, an unaffected provider-1 ARC presentation, single-use or
ARC-presentation replay, provider-leg independence, no implicit Free downgrade,
and the absence of original invoices, payment hashes and the actual 20-byte query scripthash
from the named provider observations. After both grants commit, each success
variant verifies generated tree tops against the installed proof root, executes
one real DPF query and requires an explicit inclusion/absence verdict before
exposing a result summary. The direct receipt remains issuer-linkable by
design. ARC remains experimental pending independent review. The synthetic
report is report-data binding rather than an AMD signature, and the all-zero
fixture is not a production database. Its admission-only predecessor passed
both cases on 2026-07-27; the complete-query plus Free/experimental-ARC
extension later passed a dedicated local branch run. The final isolated-target
current-tree rerun passed all three cases. It remains local synthetic evidence,
not production-attestation or deployed-origin acceptance; exact-head CI is a
separate merge gate.

### Opt-in CLN-to-provider joined boundary

The local-only command below now composes the real-CLN acquisition suite with a
second browser/two-issuer/two-provider topology:

```sh
scripts/payment-v1-cln-regtest-e2e.sh --acknowledge-local-regtest-only
```

The joined case pays three distinct routed invoices (direct receipt, Cashu BAT
and experimental ARC), claims the provider-bound capabilities through current
generated WASM, submits them to two production `unified_server` admission
gates, then requires proof-bound tree-top preflight, an encrypted DPF query and
explicit Merkle inclusion/absence verification. It also rejects direct/BAT/ARC
presentation replay and the second durable Free/IP admission, and searches the
named provider wire/log observations for the invoices, payment hashes,
preimages and query sentinel. Both credential issuers use independent IDs,
origins, policy/credential keys and stores; the disposable three-node CLN
topology intentionally gives them one shared payee node, so the result models a
shared settlement operator and does not claim settlement-level unlinkability.

This is not a default PR job: CI typechecks the joined TypeScript/config and
syntax-checks the opt-in runner without starting Core or CLN. The final
2026-07-28 current-tree opt-in command exited 0 after an offline WASM rebuild.
Its three-node acquisition/recovery phase passed 3/3, its joined provider/query
phase passed 1/1, and cleanup left no owned Core/CLN process or private runtime
directory. This remains local regtest evidence only. Its explicit `NoSevHost`,
local rollback-floor acknowledgements and all-zero database remain synthetic
test boundaries. ARC remains experimental and review-blocked.

## Formal Payment V1 lock

The current product lock is implemented and must remain a release gate:

```sh
python3 verification/scripts/verify_formal_lock.py
cargo test --locked --offline -p pir-sdk --features serde --test wire_shape_contract
cargo test --locked --offline -p pir-runtime-core --test payment_authorization_wire_contract
```

It binds `Bitcoin-PIR/protocol-proofs` commit
`c519f1960aa9567ac324856f30c71071b04a4a17`, manifest SHA-256
`5763b9a4e5e40f7eed1f1f1eadeb44950c6b4172ea55c995ca24f062e0ee860d`,
product contract SHA-256
`648227ffba4946b5adc55291bdb77eb452d93a5c03c553a17dc6f5d053b97bf7`
and content-addressed record SHA-256
`c97d8fff7b072154e78fb0388a076cb849a2d99e9968be7a9cd0d838268b54d8`.
The record was produced by passing GitHub EasyCrypt run
[`30202980581`](https://github.com/Bitcoin-PIR/protocol-proofs/actions/runs/30202980581).
Product CI checks out that exact revision, validates source/manifest/toolchain
bindings and reruns the trusted EasyCrypt command. A Payment wire-contract
change must not merge until the external proof, record and product lock are
advanced together.

This lock is evidence for its declared wire-shape claims only. It does not
cover payment cryptography, XSS, edge abuse, operator custody or deployment.

## Fault matrix

| Stage | Failure before durable spend | Failure after durable spend | Recovery |
|---|---|---|---|
| strict server verification | no payment/presentation | impossible | reject provider |
| invoice creation | no entitlement | n/a | retry idempotent quote API |
| Lightning settlement notification | quote remains reconcilable | payment ledger says paid | lookup/poll then claim once |
| credential issuance | paid quote remains `ISSUING` | issuance response may be lost | resume same blind transcript/idempotent claim |
| connect/readiness before proof selection | token remains in vault | n/a | no automatic retry; user may later select an unused token |
| proof burned locally, send outcome unknown | n/a | browser treats token as burned | no query retry and no resurrection after refresh |
| shared-issuer redeem HTTP response lost | issuer may have committed | exact signed replay may exist; provider local claim may or may not have committed | only an explicit low-level caller retaining the identical proof may replay the deterministic transcript; official Web does not retry |
| shared local-delivery claim / `AUTH_GRANTED` loss | n/a | entitlement is locally claimed | close; no second grant, query retry, refund or resurrection |
| auth verification or post-commit deadline expiry | local proof remains unspent; external intent is recoverable | external mint/issuer commit or local spend commit means spent, including a result returned after the connection deadline | close without grant/backend work; finish identical reconciliation only if the connection remains in-budget, otherwise no query retry/refund/resurrection |
| spent commit/ACK | n/a | spent | no restoration |
| preflight | n/a | spent | disconnect, surface failure |
| query | n/a | spent | disconnect, surface failure |
| inclusion verification | n/a | spent | fail closed; never display unverified result |
| Cashu custody export reservation | no lots reserved | exact members remain reserved | rerun the same export ID and recipient; never choose fresh members |
| Cashu export artifact delivery | reserved lots, no released artifact until durable persist | exact artifact is durable | `export-replay` writes byte-identical artifact; never reseal |
| external-wallet custody acknowledgement | provider still counts reserved exposure | exact batch/members acknowledged and still counted | replay exact artifact digest; ACK means custody only and does not release exposure |
| explicit custody NUT-07 check | no retirement write | no write unless the exact response is all `SPENT` | no polling/automatic retry; operator may explicitly rerun the same selection |
| sequential multi-export spent confirmation | no export retired yet | earlier exports may be terminal while a later fresh-floor commit fails | stop and report the position; exact rerun skips terminal exports without mint/key access and rechecks only remaining exports |
| settlement deposit | notes retained before commit | ledger may have committed | idempotent deposit lookup/retry |
| provider payout submission | exact canonical request must be persisted before send | issuer payout may have committed | resend only the persisted request; verify and atomically install response plus floor |

## CI layers

The ordinary offline CI suite includes a deterministic adversarial corpus for
every public Payment V1 canonical decoder, the provider service-opcode boundary
and the strict issuer/mint HTTP response parser. It covers truncation, exact
fixed-frame boundaries, malformed `u16`/`u32` lengths, oversized top-level
messages, non-canonical padding, duplicate `Content-Length`, `CL`+`TE`, invalid
chunk sizes and endpoint/header injection. Corpus count and maximum allocation
are fixed in the tests, so this gate is reproducible and cannot become an
unbounded CI fuzz job. It is not evidence that later coverage-guided or
long-running fuzzing has been completed.

The explicit commands are:

```sh
cargo test --locked --offline -p pir-service-protocol --test payment_v1_adversarial
cargo test --locked --offline -p pir-runtime-core --test service_admission_adversarial
cargo test --locked --offline -p pir-strict-https
cargo test --locked --offline -p pir-rollback-authority-protocol
cargo test --locked --offline -p pir-rollback-authority-client
cargo test --locked --offline -p pir-rollback-authority-store
cargo test --locked --offline -p pir-service-store
cargo test --locked --offline -p pir-provider-clearing-client shared_grant_tests
cargo test --locked --offline -p runtime --lib hint_pool
cargo test --locked --offline -p runtime --bin unified_server
cargo test --locked --offline -p runtime --test payment_v1_onion_process_e2e
cargo clippy --locked --offline -p runtime \
  --bin unified_server \
  --test payment_v1_process_e2e \
  --test payment_v1_methods_process_e2e \
  --test payment_v1_harmony_pool_process_e2e \
  --test payment_v1_onion_process_e2e \
  --no-deps -- -D warnings
cargo clippy --locked --offline -p runtime \
  --features remote-authority-process-e2e \
  --bin unified_server \
  --test payment_v1_process_e2e \
  --no-deps -- -D warnings
cargo test --locked --offline -p runtime \
  --features cuckoo-oram \
  --test payment_v1_tee_oram_process_e2e
cargo clippy --locked --offline -p runtime \
  --features cuckoo-oram \
  --bin unified_server \
  --test payment_v1_tee_oram_process_e2e \
  --no-deps -- -D warnings
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_standard_cashu_process_e2e \
  standard_cashu_real_process_tls_two_provider_e2e -- --exact
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_process_e2e \
  all_non_receipt_methods_commit_before_real_harmony_query_and_replay_after_restart \
  -- --exact
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_harmony_pool_process_e2e \
  all_non_receipt_methods_restore_pre_dispatch_and_burn_on_real_hint_dispatch \
  -- --exact
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_onion_process_e2e \
  all_non_receipt_methods_commit_before_real_onion_job_and_replay_after_restart \
  -- --exact
cargo test --locked --offline -p runtime \
  --features cuckoo-oram,standard-cashu-process-e2e \
  --test payment_v1_tee_oram_process_e2e \
  all_non_receipt_methods_commit_before_real_tee_oram_and_replay_after_restart \
  -- --exact
cargo clippy --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --bin unified_server \
  --test payment_v1_standard_cashu_process_e2e \
  --no-deps -- -D warnings
cargo test --locked --offline -p pir-cashu-client \
  --features insecure-dev-sqlite-store --test cdk_nut03_interop --no-run
(cd web && npx --no-install tsc \
  -p tsconfig.payment-cdk-cashu-e2e.json --pretty false)
```

1. fast codec/model/property and bounded adversarial decoder tests;
2. durable store crash/concurrency tests;
   rollback-authority coverage includes exact signed Read/CAS replay before and
   after later floor advancement and reopen, fresh-nonce CAS reconciliation,
   nonce/request mismatch rejection, independent operation/call quota
   exhaustion, and stored-counter corruption;
3. issuer HTTP and fake-Lightning integration;
4. unified-server secure-channel/backend matrix plus Harmony hint-pool and
   binary-target tests, with warnings denied for the explicitly selected
   runtime/process feature graphs, including the bounded pre-auth write deadline
   regression cases;
5. native SDK and WASM tests;
6. browser Playwright tests in the dedicated no-real-funds Chromium job:
   fake-SDK multi-tab fault injection, real-WASM/loopback-fake-issuer
   direct-receipt acquisition, and browser/two-issuer/two-provider DPF query
   with direct/BAT plus Free/experimental-ARC selections and proof-bound Merkle
   verification;
7. pinned-action CI and pinned `wasm-pack 0.14.0 --locked` installation under
   Rust 1.94.1, without a remote shell installer or ambient `wasm-opt`;
   generation is Cargo locked/offline, the Pages job builds the real workspace,
   its build dependencies have no Pages/OIDC write authority, Node is fixed to
   supported LTS 24.18.0, all WASM toolchain/vendor/trust inputs trigger the
   gates, and Pages reruns TypeScript/unit and all three no-funds Chromium
   Payment boundaries before publishing. A main-branch push builds and uploads
   the candidate only; production deploy requires a separate manual dispatch
   selected on `main` with `confirm_production_deploy=true`, and that run
   rebuilds/retests the selected main ref rather than promoting an earlier push
   artifact. After lockfile-pinned `npm ci`, the YAML 1.2 semantic Pages gate
   checker locks the exact condition, boolean-default-false input,
   `needs: build`, no-`always()` rule, protected environment, unique
   job-confined Pages/OIDC write permissions and deployment actions, rejection
   of anchors/aliases/merge keys, `write-all`, Actions-write permissions,
   reusable-workflow delegation, extra jobs and sibling workflows outside the
   exact contents-read permission boundary, decoded-Unicode positive controls,
   and the trigger truth table. Payment CI and the Pages build both execute it,
   and every workflow change is included in the Payment-CI path filter. This
   repository-static/default-`GITHUB_TOKEN` test does not exclude dispatch via
   an external PAT or GitHub App token;
8. fuzz, dependency, forbidden-field, formal-contract, and offline-build jobs;
9. compile-only coverage for the feature-gated ignored CDK custody target and,
   through the executed Standard Cashu process-test crate, the ignored
   browser/real-CDK/two-provider target; actual CDK execution remains an opt-in
   disposable loopback fake-wallet run alongside approved regtest/signet
   canaries; no mainnet funds in CI.

## Production-only acceptance gates

None of the default commands may use funds or remote infrastructure. Separate
approval and an isolated experimental/staging environment are required for:

- a persistent or externally operated Core Lightning regtest/signet node and
  wallet lifecycle, an external WebPKI-trusted Cashu mint, and
  production-catalog public Nostr relay interoperability including TLS, relay
  policy, control frames and independently operated relay selection;
- a browser/issuer/two-provider topology with production
  identity/attestation/binary/database pins and mandatory Merkle verification;
- standard Cashu and Harmony hint/query, Onion and TEE-ORAM provider-process
  success plus fault injection;
- a rollback-floor authority deployed in a failure and administrative domain
  independent from each provider/issuer database, including restore/failover
  drills;
- production TLS/edge limits, source-aware abuse controls, telemetry, overload
  tests, supervision, backup and key-custody review;
- a repository ruleset that prevents unreviewed direct `main` pushes and makes
  the Payment/security gates required, plus a fresh check of default workflow
  permissions, Pages build mode, PAT/GitHub-App credential governance, and that
  the mutable `github-pages` environment remains main-only with a required
  reviewer;
- deployed-origin enforcement of the locally tested hash-pinned browser CSP,
  including an edge `frame-ancestors 'none'` response header, runtime-
  dependency review, resolution of documented upstream/vendor audit warnings,
  and user manual acceptance;
- independent ARC cryptographic and implementation review.

Passing local CI does not authorize any of these activities. The opt-in CDK
runner uses a disposable loopback fake-wallet mint only; the current opt-in CLN
runner uses three disposable local nodes and valueless regtest coins only. No remote
server, external CLN/Cashu service, production-catalog Nostr service or real
Lightning funds were used to establish the default local-suite evidence in
this document. The separately authorized short-lived empty-catalog public
Nostr smoke is recorded in `LOCAL_ACCEPTANCE.md` and does not satisfy this
production gate.
