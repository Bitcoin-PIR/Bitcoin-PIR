# Payment v1 local acceptance

Status: no-funds developer acceptance. The default quick/full commands do not
deploy, contact a Lightning node or Cashu mint, publish to a Nostr relay, or
operate a public PIR server. A separate opt-in interoperability command starts
one disposable loopback-only CDK fake-wallet mint; it uses no Lightning or real
funds and never contacts a public mint. A separately authorized 2026-07-27
Nostr smoke contacted public relays with one short-lived empty checkpoint and
is recorded explicitly under “Directory checks”; it is not part of either
default command.

## Prerequisites

- run from the repository root;
- use the repository-pinned Rust toolchain and lockfile;
- have the `wasm32-unknown-unknown` target installed for full mode;
- have `wasm-pack 0.14.0` (the CI-pinned version) and its compatible
  `wasm-bindgen` tools preinstalled; full mode regenerates the ignored WASM
  package with Cargo locked and offline before TypeScript. The local script
  checks `wasm-pack` directly and fails closed if `wasm-bindgen` is absent or
  incompatible; it does not install or silently replace either tool;
- have `web/node_modules` populated from the pinned lockfile before full mode;
- have the Playwright-pinned Chromium runtime installed before full mode
  (`cd web && npx playwright install chromium` installs it separately; the
  acceptance script never downloads a browser);
- do not set production Lightning, mint, relay or server credentials in the
  shell used for this check.

The acceptance script forces Cargo offline and does not edit source. Quick mode
never starts a listener. Full mode starts temporary `unified_server` children,
a fake `payment-issuer` and Vite test servers whose listeners are explicitly
bound to `127.0.0.1`; the process and Playwright runners kill and wait for every
child before returning.

## One-command checks

Focused check:

```sh
scripts/payment-v1-local-check.sh --quick
```

Full local check:

```sh
scripts/payment-v1-local-check.sh --full
```

Optional real-CDK token-format and provider-side NUT-03/NUT-12 interoperability
(outside the default offline suite) requires exact `cdk-mintd` and `cdk-cli`
0.17.3 binaries:

```sh
BITCOINPIR_CDK_MINTD=/absolute/path/to/cdk-mintd \
BITCOINPIR_CDK_CLI=/absolute/path/to/cdk-cli \
  scripts/payment-v1-cdk-regtest-e2e.sh
```

The runner binds a random `127.0.0.1` port, creates only fake-wallet ecash,
passes owner-only token/keyset files to an ignored production-WASM import test,
stops the child and removes its private temporary directory. It validates
padded V4 `cashuB`, current `m,u,t` structure and local stripping of known
NUT-12 wallet metadata. It also exercises the provider's NUT-03/NUT-12 swap and
custody path. One exact NUT-07 request proves the original NUT-03 inputs are
`SPENT` and the newly committed custody outputs are `UNSPENT` through an
explicit test-only loopback endpoint mapping. It does not prove custody
`UNSPENT -> SPENT` or execute admin retirement against CDK: cdk-cli 0.17.3
accepts custody receive only as a bearer token in process argv, which this
runner deliberately refuses to expose.

The full command mirrors the Rust/WASM portions of
`.github/workflows/payment-platform.yml`, regenerates the WASM JS/TypeScript
bindings, and adds the Web unit suite plus the local Chromium multi-tab vault
and real-WASM/no-funds-issuer boundaries. It fails instead of bootstrapping
`wasm-pack`/`wasm-bindgen`, installing JavaScript packages, or downloading
Chromium when those prerequisites are absent.

Payment browser CI, the general Web PR gate and the Pages build all install
`wasm-pack 0.14.0` and lockfile-matched `wasm-bindgen-cli 0.2.114` with Cargo
`--locked` under Rust 1.94.1; none executes a remote `curl | sh` installer or
lets `wasm-pack` download a CLI during the build. Generation uses
`--mode no-install`, `--no-opt`, and Cargo locked/offline, so it neither
downloads tools nor executes an unpinned `wasm-opt` found on the runner PATH.
The Pages build uses the real workspace graph rather than rewriting the root
manifest, and only the separate deploy job receives Pages write/OIDC
permissions; third-party build steps run with contents read-only. Newly used
workflow actions are exact-SHA pinned, Node is fixed to supported LTS
`24.18.0`, and the Payment/Web path filters include the toolchain, vendor and
trust inputs needed by the generated WASM. A Payment/security UI change cannot
skip the Payment browser boundaries, and the Pages job reruns strict TypeScript
and unit tests plus both no-funds Chromium Payment boundaries before publishing.
The existing scheduled strict-production browser canary uses the same fixed
runner/Node/action boundary; it was not triggered by this work. A cold local
smoke of the exact pinned installation commands passed; the exact
locked/offline/no-install/no-opt build command is checked below, and pushed
workflow runs remain authoritative.

As a historical 2026-07-26 baseline before the later CLN/CDK/custody/Nostr
changes, after that day's Payment implementation source edits stopped,
`scripts/payment-v1-local-check.sh --full` completed with exit code zero. It
included four passing multi-tab vault cases, one passing
generated-WASM/real-loopback-issuer case, 326 passing Web unit tests, both
provider process suites, the five-method x five-workload matrix, dedicated
Payment clippy with warnings denied, wasm32 checking and fresh WASM generation.
The pushed workflow run remains the authoritative CI record before merge.

The current 2026-07-27 closeout run used a fresh isolated Cargo target and one
build job so concurrent review processes could not share artifacts or locks:

```sh
CARGO_TARGET_DIR=/tmp/bitcoinpir-final-20260727 \
CARGO_BUILD_JOBS=1 \
  scripts/payment-v1-local-check.sh --full
```

It completed with exit code zero after source edits stopped. The run included
the complete offline Rust platform/payment suite, 39 unified-server tests, both
provider-process suites, 10 Node Nostr readback cases, Payment clippy with
warnings denied, wasm32 and fresh WASM generation, strict TypeScript and bundle
builds, **333 passing Web unit tests** with two intentional skips, all four
Chromium multi-tab vault cases, and the generated-WASM/real-loopback-issuer
case. Its two opt-in CLN Playwright cases were intentionally skipped because
the default full run never starts a Lightning node.

Separate opt-in no-real-funds evidence on 2026-07-27 also passed:

- `scripts/payment-v1-cln-regtest-e2e.sh
  --acknowledge-local-regtest-only`: 3/3 against disposable Bitcoin Core and
  two Core Lightning nodes, including a real local channel/routed BOLT11
  payment and generated-WASM BAT/experimental-ARC acquisition. The first
  attempt timed out in Playwright global setup while another reviewer held the
  shared Cargo target lock; its children were cleaned and the isolated retry
  passed, so it is recorded as infrastructure contention rather than a
  protocol failure.
- `scripts/payment-v1-cdk-regtest-e2e.sh` with exact CDK 0.17.3 binaries: the
  real V4 import case and provider NUT-03/NUT-12 plus input-`SPENT` / fresh
  custody-`UNSPENT` NUT-07 case both passed. Custody `UNSPENT -> SPENT` and
  admin retirement were intentionally not attempted because CDK 0.17.3's CLI
  would place the bearer token in process argv. The verified official
  Apple-arm64 SHA-256 digests were
  `78390b850e6e24f11af1848f54004bdf7439771d81970b115241922435e944b9`
  (`cdk-cli`) and
  `05b2e8cb01c2500a0200264947eb5b41cb82fcfc02263de6c0c1af7d531b89ab`
  (`cdk-mintd`).
- `npm audit --omit=dev --audit-level=moderate` reported zero vulnerabilities;
  `cargo audit` reported no vulnerability finding and the four allowed
  upstream/vendor warnings listed below.

These records used no public Lightning network, real funds, public Cashu mint,
remote PIR server, production catalog or production database. GitHub checks on
the pushed commit remain authoritative before merge.

The exact `--no-opt` package generated locally on 2026-07-26 contained a
`pir_sdk_wasm_bg.wasm` of 3,600,060 bytes raw and 1,195,176 bytes with gzip.
The real-WASM loopback Chromium case loaded that package successfully. This is
a release-size baseline, not evidence for CDN compression or deployed-origin
latency; those remain part of staging/manual acceptance.

Supply-chain checks are recorded separately because they are not part of the
offline acceptance script and may consult locally installed audit databases or
package-registry metadata:

```sh
cargo audit
cd web
npm audit --omit=dev --audit-level=moderate
```

On 2026-07-26 the npm command reported zero vulnerabilities. `cargo audit`
exited zero with no vulnerability finding and four allowed warnings: indirect
unmaintained `bincode 1.3.3`, indirect `memmap2 0.9.10`
(RUSTSEC-2026-0186; 0.9.11 is not yet supplied by the current vendor and this
tree does not call `advise_range`/`flush_range`), indirect `rand 0.8.5`
(RUSTSEC-2026-0097; 0.8.6 is not yet supplied and this tree has no triggering
custom logger), and indirect yanked `spin 0.9.8` through SEV/tracing. Record
these as vendored-upstream residuals, not as zero warnings, and do not refresh
the complete vendor tree as an incidental Payment change.

## What “five methods accepted” means

| Method | Focused command/boundary | What it proves | What it does not prove |
|---|---|---|---|
| Free | `cargo test --offline -p pir-service-store free_ip_rate_limit`, the runtime matrix, and `payment_v1_methods_process_e2e` | open and durable IP-quota authorization through the real provider process plus canonical Free authorization at every backend gate | public-IP attribution behind a real proxy or production DDoS resistance |
| Direct BOLT11 receipt | `cargo test --offline -p pir-lightning-backend`, issuer lifecycle tests, `direct_receipt_production_committer_spend_survives_store_restart`, and optional `scripts/payment-v1-cln-regtest-e2e.sh --acknowledge-local-regtest-only` | fake lifecycle/state tests, signed receipt admission and replay rejection across ProviderStore restart, plus a real local CLN socket/channel/BOLT11 payment and generated-WASM acquisition path | a public-network or real-value wallet payment, production ingress, or production Lightning operations |
| Standard Cashu eCash | `cargo test --offline -p pir-cashu-client`, `cargo test --offline -p pir-cashu-custody`, ProviderStore custody tests, the runtime matrix, and optional `scripts/payment-v1-cdk-regtest-e2e.sh` | exact swap/recovery/grant-to-custody state machine, finite exposure through ACK, bounded immutable export, in-process exact NUT-07 all-SPENT retirement with digest-only evidence, backend admission with deterministic transports, and real CDK V4 import plus provider-side NUT-03/NUT-12 verification, custody commit, original-input `SPENT` and fresh-custody `UNSPENT` | an unmodified provider process against a public WebPKI mint, custody `UNSPENT -> SPENT`/admin retirement against real CDK, public-mint interoperability, real-value custody or payout |
| Cashu BAT | `cargo test --offline -p pir-payment-crypto --features provider-store --test provider_store_bat_adapter`, the runtime matrix, and `payment_v1_methods_process_e2e` | real blind/DLEQ/unblind proof through a real provider process and provider-local durable BAT spend/restart rejection | a public/shared Cashu service or production key custody |
| ARC experimental | `cargo test --offline -p pir-arc-adapter --features provider-store`, the runtime matrix, and `payment_v1_methods_process_e2e` | real draft-01 issuance/presentation through a real provider process plus nonce/tag persistence and restart rejection | independent cryptographic review, complete IETF protocol interoperability, or permission to advertise ARC as stable |

The cross-product test is:

```sh
cargo test --offline -p pir-runtime-core --test service_admission_matrix
```

It encodes and decodes the canonical authorization frame and exercises Free,
direct receipt, standard Cashu, BAT and experimental ARC against DPF, Harmony
full hints, Harmony queries, Onion and TEE-ORAM gate state. It is a wire/gate
integration test, not five live external payment integrations. Focused
production-adapter tests supplement the synthetic committers used to make the
matrix deterministic.

## Loopback two-provider process boundary

Full mode and payment-platform CI run:

```sh
cargo test --offline -p runtime --test payment_v1_process_e2e
cargo test --offline -p runtime --test payment_v1_methods_process_e2e
```

These no-funds tests launch two independent logical providers as real OS child
processes and communicate over real TCP/WebSocket connections. Each provider
has a distinct provider ID, policy key, method keys, ProviderStore and rollback
authority. Both listeners are explicitly `127.0.0.1`-only, and the first test
also proves that a misspelled `--bind-addres` flag exits non-zero before opening
a listener.

The direct-receipt test covers cleartext backend rejection, ephemeral-bound
attestation exchange, secure-channel upgrade, exact signed manifest-root
policy verification, encrypted pre-authorization rejection, provider-specific
direct-receipt authorization, a valid DPF request/response, signed one-frame
limit rejection, and durable replay rejection after provider 0 is restarted.
The exact provider-1 receipt is first rejected by provider 0 and then succeeds
at provider 1, proving that the wrong-provider rejection neither burns it nor
consults a shared cross-provider spent set.

The method-adapter test repeats the real wire and DPF execution boundary for
Free open, durable provider-local IP quota, provider-local Cashu BAT and
experimental ARC. BAT uses an actual blind/sign/DLEQ/unblind proof; ARC uses
the pinned implementation's issuance and presentation path. It rejects a
provider-0 BAT/ARC presentation at provider 1, proves provider-local quota
independence, and rejects quota/BAT/ARC replay after both providers restart
against their own stores.

This test intentionally observes `NoSevHost` and uses SDK
`dangerous_unpaired_*` helpers. It validates the local secure wire and Payment
V1 gate, not production server identity, binary pinning, hardware attestation,
production database proof/trusted-root pinning, Merkle tree-top/inclusion
verification, or an attested build. Its receipt is constructed from public
deterministic fixture keys: no issuer process, browser, wallet, Lightning node,
external Cashu mint, Nostr relay or real funds participate. Only the DPF
backend is executed through real processes. Standard Cashu success still uses
the deterministic mint transport in `pir-cashu-client`: the production HTTPS
client trusts only the fixed WebPKI roots, so this suite does not add a test CA
or TLS bypass. The five-method x five-workload in-process matrix remains the
process-independent coverage for standard Cashu, Harmony, Onion and TEE-ORAM.
The separate opt-in CDK runner exercises the real provider-side client against
a loopback CDK mint through an exact test-only endpoint mapping; it does not
alter or exercise the unified-server production WebPKI transport.

## Standard Cashu custody boundary

Full mode and Payment Platform CI include:

```sh
cargo test --offline -p pir-cashu-client
cargo test --offline -p pir-cashu-custody
cargo test --offline -p pir-service-store cashu_custody
cargo test --offline -p bpir-admin cashu_custody

# Optional: requires separately installed CDK 0.17.3 binaries and uses only a
# disposable loopback fake-wallet mint.
scripts/payment-v1-cdk-regtest-e2e.sh
```

Together these cover separate recovery/custody AEAD domains, finite exact
mint/unit caps before submission, atomic grant-plus-note custody, cross-intent
note uniqueness, 512-note/16-keyset export selection, overflow lots left
available, immutable recipient binding, persist-before-release, byte-identical
replay, recipient-sealed envelope authentication, owner-only output and
explicit external-custody-only acknowledgement, ACK-still-counted exposure,
strict ordered NUT-07 parsing, same-mint/unit multi-export batching, exact
all-`SPENT` retirement, current-floor refresh and key/network-free terminal
replay. The default full-mode portion uses generated fake notes and an
in-process NUT-07 transport; it does not prove that a wallet accepted or
redeemed the exported token, nor that an external mint interoperates. The
opt-in CDK runner additionally obtains a real padded V4 token, checks the
official full NUT-02 V2 keyset derivation, executes the production provider-side
NUT-03 request and NUT-12 DLEQ verification, commits the received notes to
custody, and proves restart/resume does not send a second swap. Its transport
maps only the signed synthetic test identity to the validated loopback mint;
production HTTPS/WebPKI behavior is unchanged.

## Fake Lightning and issuer checks

The deterministic fake Lightning backend is an in-process test backend. Run:

```sh
cargo test --offline -p pir-lightning-backend
cargo test --offline -p pir-issuer-core
cargo test --offline -p pir-issuer-service
cargo test --offline -p payment-issuer
```

The commands cover deterministic invoice creation/lookup, settlement-state
mapping, exact idempotent quote recovery, quote/status/claim transitions,
credential preparation and listener safety helpers. They do not pay an invoice.

The store bootstrap command can be smoke-tested without starting a listener.
Use separate private parents even in the acceptance example so the layout does
not accidentally normalize same-directory rollback storage:

```sh
acceptance_dir="$(mktemp -d)"
install -d -m 0700 "$acceptance_dir/store" "$acceptance_dir/floor"
cargo run --offline -p payment-issuer -- init-store \
  --store "$acceptance_dir/store/issuer.sqlite" \
  --rollback-authority "$acceptance_dir/floor/rollback.sqlite" \
  --issuer-id-hex 0101010101010101010101010101010101010101010101010101010101010101 \
  --network regtest
```

Remove the temporary directory after inspection using the platform's normal
temporary-file cleanup or a carefully targeted command. The two SQLite files
being different does not model independent production backup domains.

Both `payment-issuer` listeners are deliberately loopback-only:

```sh
cargo run --offline -p payment-issuer -- serve-fake --help
cargo run --offline -p payment-issuer -- serve-cln --help
cargo test --offline -p payment-issuer fake_server_refuses_non_loopback
```

Starting either listener requires an existing issuer store/rollback authority,
an exact root-signed quote-key delegation and matching key, fake Lightning key
and derivation seed, credential derivation key, and at least one exact signed
service policy. Receipt, BAT, experimental ARC and clearing offers require their
additional key/authorization material. The committed deterministic no-funds
fixture generator assembles those artifacts for two providers and all five
workloads/methods, but it does not start listeners or a browser. Do not describe
the issuer/fixture commands above as an HTTP/browser/two-server E2E test; the
separate loopback process test covers provider wire/gate behavior only.

Generate and validate that fixture without funds or external services:

```sh
fixture_root="$(mktemp -d)"
scripts/fixtures/generate-payment-v1-no-funds.sh "$fixture_root/generated"
test -s "$fixture_root/generated/fixture.json"
```

## Shared clearing and provider settlement client

Run the issuer store/service, HTTP listener and provider client boundaries with:

```sh
cargo test --offline -p pir-issuer-store
cargo test --offline -p pir-issuer-service
cargo test --offline -p pir-provider-clearing-client
cargo test --offline -p payment-issuer settlement_http
```

These suites cover canonical bounded settlement HTTP envelopes, authenticated
balance/payout-intent/payout/status calls, payout state verification, response
loss and exact latest-status replay. For a **status successor**, the provider
client persists the exact pending envelope before send, then commits its
successor state and mandatory external rollback floor together through its
state-store boundary.
Issuer provider registrations are append-only history: an old request key may
authenticate only a byte-identical durable latest-status replay after its
canonical request digest and provider have matched; fresh status and every
financial mutation require the current registration.

The final append-only history implementation passes its three focused
issuer-store cases and the issuer-service payout/restart case. The provider
settlement client passes all ten focused cases and warnings-as-errors clippy.
Those cases prove that an initial payout is persisted before POST; an
outcome-unknown restart resends exact bytes and creates one economic payout;
tampered intent/registration/pending floors fail closed; fresh preparation uses
real current time/current registration/current issuer key; and concurrent or
repeated payouts preserve one monotonic terminal-predecessor chain. This closes
the send-before-persist implementation P1.

The dated current-tree acceptance record above supplies the exact command and
counts; pushed branch CI remains authoritative before merge. The client is
transport-neutral and the repository still does not select a production
transport, concrete persistent
`ProviderSettlementStateStoreV1`, truly independent floor adapter or payout
worker. Therefore no passing library test enables production settlement.

The bundled rollback authority is another SQLite file. Even when these tests
pass, it does not demonstrate an independent production failure or
administrative domain. Production needs a reviewed linearizable adapter and a
deployment/restore drill in which database and floor cannot be rolled back
together.

## Directory checks

Offline directory codecs, split-view rules, publisher artifact generation, and
the transport-neutral native publisher session:

```sh
cargo test --offline -p pir-directory-nostr
cargo test --offline -p bpir-admin directory_artifact
cargo test --offline -p bpir-admin directory_publish
cargo test --offline -p pir-sdk-wasm \
  signed_publish_to_fake_relays_reads_two_independent_providers_and_fails_closed
cargo run --offline -p bpir-admin -- directory-artifact --help
node --check scripts/payment-v1-nostr-readback.mjs
node --test scripts/payment-v1-nostr-readback.test.mjs
node scripts/payment-v1-nostr-readback.mjs --help
```

The focused WASM test passes a real Rust-generated publisher artifact through
two deterministic process-local NIP-01 relay implementations, all 16 shards,
the production catalog verifier and rollback state. It covers two independent
providers plus tamper, wrong-key, expiry and rollback rejection. These commands
do not contact or publish to a public Nostr relay and do not prove public-relay
interoperability. The admin publisher tests additionally use transport-neutral
in-memory WebSockets to prove exact EVENT bytes, ordered positive OK handling,
all-relay attempts, nonzero partial failure, timeout and rejection of false,
duplicate/unexpected/missing, non-text and oversized replies. They deliberately
do not prove WebPKI, public relay policy, operator independence, or compatibility
with relays that inject Ping/Pong control frames during the publish exchange.

The staging-only readback script resolves the lockfile-pinned `ws` dependency
from `web/node_modules`, disables compression and redirects, and applies a
transport-level `maxPayload` before parsing relay data. It never reads a key or
publishes. Given the already Rust-verified frozen artifact, it requests exact
event IDs and requires every event value exactly once plus EOSE from each
relay. JSON object field ordering is not treated as event data.

On 2026-07-27, a separately authorized public smoke generated a disposable
directory key and a 30-minute empty 16-shard checkpoint. The same immutable
artifact received 16/16 matching positive OKs from both `wss://nos.lol` and
`wss://relay.primal.net`; ID-filtered readback then returned all 16 exact event
values and EOSE from both. `wss://relay.damus.io` failed at the transport
boundary for publish and readback and was correctly excluded from success.
The disposable private key and local artifact were deleted after the test.
The event contained no provider entry, payment or query data. This establishes
one public WebPKI/relay-policy interoperability observation only: it is not a
production catalog, a durability SLA, or proof that the two successful
hostnames have independent operators/infrastructure.

## Formal Payment V1 wire-shape lock

Validate the product-owned lock and content-addressed verification record:

```sh
python3 verification/scripts/verify_formal_lock.py
cargo test --locked --offline -p pir-sdk --features serde --test wire_shape_contract
cargo test --locked --offline -p pir-runtime-core --test payment_authorization_wire_contract
```

The current lock binds
`Bitcoin-PIR/protocol-proofs@c519f1960aa9567ac324856f30c71071b04a4a17`,
manifest SHA-256
`5763b9a4e5e40f7eed1f1f1eadeb44950c6b4172ea55c995ca24f062e0ee860d`
and product contract SHA-256
`648227ffba4946b5adc55291bdb77eb452d93a5c03c553a17dc6f5d053b97bf7`.
The matching GitHub EasyCrypt run is
[`30202980581`](https://github.com/Bitcoin-PIR/protocol-proofs/actions/runs/30202980581),
and its downloaded record is
`verification/records/formal/c97d8fff7b072154e78fb0388a076cb849a2d99e9968be7a9cd0d838268b54d8.json`.
The record's SHA-256 is the filename digest. The first command validates that
commit, manifest, record, trusted toolchain description and current product
contract agree; the Payment formal-proof CI additionally checks out the exact
proof revision and reruns EasyCrypt with the product-owned trusted command.

These checks prove only the stated formal wire-shape contract and its explicit
assumptions/non-claims. They do not exercise funds, a remote service or any
external payment infrastructure. Any contract change requires a new external
proof run, downloaded content-addressed record and explicit relock.

## Chromium multi-tab payment-vault boundary

Full mode and Payment Platform CI run:

```sh
cd web
npm run test:e2e:payment-vault
```

The command typechecks its test harness, starts only a temporary Vite listener
on `127.0.0.1`, and launches real headless Chromium pages in one same-origin
browser context. It exercises native browser IndexedDB, non-extractable
WebCrypto keys and Web Locks. The tests show that two tabs cannot take the same
single-use capability, an ARC state advances durably before each distinct
presentation is released, local proof validation failure leaves the encrypted
record available, and successful validation deletes it before payload release.
They also fault-inject a paid claim whose first HTTP response is lost, reload
the page, race two restoring tabs, require byte-identical claim replay with one
winner, atomically install one capability, and observe no payment-material
write through `localStorage`. The existing product-controller unit test
separately executes a query sentinel while making every
`localStorage.setItem` call fail; the Chromium harness itself does not execute
a PIR query.

This is deliberately a browser-storage and controller boundary. A test-only
SDK state-machine double is selected only by `vite.payment-test.config.ts`, and
Playwright intercepts the local issuer requests. It does **not** exercise the
generated Rust/WASM cryptography, a `payment-issuer` process, a wallet or
Lightning node, either PIR provider, strict proof-chain verification, a
deployed page, or any remote network. The separate WASM, issuer, provider and
process suites remain necessary.

## Chromium real-WASM/no-funds issuer acquisition boundary

Full mode and Payment Platform CI also run:

```sh
cd web
npm run test:e2e:payment-real-issuer
```

This command typechecks a separate harness, uses the freshly generated
`pir-sdk-wasm` package, starts a deterministic `funds_capable=false` regtest
fixture and a real loopback `payment-issuer serve-fake`, and opens real
headless Chromium. The browser verifies the signed service policy with WASM,
selects its exact DPF direct-receipt offer, creates a quote over HTTP, injects
the test-only fake settlement for the policy's exact millisatoshi price, polls
the authenticated status, and claims an issuer-signed capability. The first
successful claim response is deliberately lost after the issuer commit;
following a page reload, encrypted IndexedDB recovery sends a byte-identical
claim, receives the issuer's idempotent replay, atomically installs one
capability, verifies it against the signed policy in WASM, and consumes it once.
The test also requires zero `localStorage` writes and confirms that neither the
invoice nor a query sentinel appears in claim bytes.

The generated fixture advertises an invalid HTTPS issuer hostname so it cannot
be mistaken for a deployable endpoint. A test-only fetch adapter accepts only
that exact fixture origin and maps its paths to the random loopback issuer; it
does not relax production endpoint validation. The fake-settlement route is
the only payment source in the default full local check: no wallet, Core
Lightning socket, external Cashu mint, Nostr relay, remote network or real
funds participate there. The separate opt-in CLN-regtest runner connects the
production adapter to disposable local CLN nodes and pays a real BOLT11 invoice
using valueless regtest coins. The provider-side
secure-channel exporter is synthetic, and this boundary does not launch either
PIR provider, execute a PIR query, verify the production proof chain, or cover
BAT/ARC acquisition in its default fake-backend run. The opt-in CLN-regtest
variant covers generated-WASM BAT/ARC acquisition and recovery without real
funds, but still does not launch a PIR provider.

## Expected acceptance record

Record the commit, platform/toolchain, command mode, pass/fail result and any
skipped boundary. Do not record invoices, payment hashes, preimages, raw
capabilities, query addresses, results, browser vault records or secret paths.

At minimum, a release candidate needs evidence for:

1. all offline Rust payment packages;
2. unified-server admission/DoS-guard unit tests, wiring check and the
   loopback two-provider process tests;
3. wasm32 check plus fresh generated WASM bindings;
4. Web unit tests and both local Chromium payment boundaries;
5. five-method × five-workload matrix;
6. persistence/restart/concurrency suites;
7. deterministic no-funds fixture generation;
8. the locked product contract and exact external EasyCrypt record;
9. an approved staging network E2E once its edge controls are implemented.

## Not exercised by this procedure

- public-network or real-value Lightning payment, routing, notification or
  refund behavior (the opt-in runner covers a local CLN socket, local channel
  routing and a paid regtest BOLT11 invoice);
- an unmodified unified-server provider NUT-03 path against a public/WebPKI
  Cashu mint (the opt-in local CDK runner covers the same provider-side client,
  real CDK response and custody commit, but uses an exact test-only loopback
  transport mapping);
- production-catalog publication, ongoing public-relay durability and
  DNS/egress-rebinding controls (one short-lived empty public-relay
  publish/readback compatibility smoke is recorded above);
- an actually independent production rollback-floor adapter and restore domain;
- production TLS/reverse proxy, quote-spam controls, load tests for the global
  connection/auth limits, or tree-top bandwidth overload at the edge;
- production identity/binary pins, remote servers, hardware attestation,
  production database proofs/trusted roots, or production databases;
- process-level Harmony hint/query, Onion or TEE-ORAM execution (their
  canonical gate states are covered in-process);
- a deployed browser-to-issuer-to-provider main-page network E2E (the visible
  main-page controller is covered by unit tests; the local Chromium suites
  separately cover fake-SDK multi-tab behavior and real-WASM/direct-receipt
  issuer acquisition, but neither executes the provider/query path);
- independent ARC review;
- final browser XSS/CSP/dependency review and deployed-origin manual testing;
- user manual acceptance.

All of the above remain explicit gates. Production deployment, remote server
operations and real Lightning funds require fresh user approval.
