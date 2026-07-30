# Payment v1 local acceptance

Status: no-funds developer acceptance. The default quick/full commands do not
deploy, contact a Lightning node or Cashu mint, publish to a Nostr relay, or
operate a public PIR server. A separate opt-in interoperability command starts
one disposable loopback-only CDK fake-wallet mint; it uses no Lightning or real
funds and never contacts a public mint. A separately authorized 2026-07-27
Nostr smoke contacted public relays with one short-lived empty checkpoint and
is recorded explicitly under “Directory checks”; it is not part of either
default command.

Current-tree verification notice: the dated pass records below predate the
settlement-v2 SQLite adapter, no-funds payout worker, Signet backup-receipt
ceremony, browser/two-issuer/two-provider harness and the extended CDK custody
spend case. They remain historical evidence for the exact older tree only. Do
not report their aggregate counts as current. The extended CDK lifecycle has
since passed a final current-tree opt-in run, as has the forced two-hop three-
node CLN runner. The final pinned-Linux Rust/process matrix and isolated-target
Web/browser closeout are recorded separately below, as are the focused Harmony
and shared-redeem/clone-fencing results. Exact-head pushed CI remains a distinct
merge gate; no local result is production-network, deployed-origin or real-
funds acceptance.

This document is the **source merge** acceptance boundary only. The later
deployment phases are **private no-funds**, **public Signet**, and **production
mainnet**. Passing any command below does not authorize a remote-host mutation,
bounded service activation, persistent Signet identity/wallet/channel,
faucet/test-coin use, external Cashu-mint access, public Nostr publication,
VPSBG UKI change, production-key installation/use, or a mainnet/real-value
operation; each is an independent approval gate. Production mainnet is
additionally blocked because the repository does not yet implement a reviewed
mainnet deployment preflight.

Use [DEPLOYMENT_INPUT_MATRIX.md](DEPLOYMENT_INPUT_MATRIX.md) to inventory the
non-secret inputs for a later approved phase and start any proposed render plan
from [render-plan-skeletons/](render-plan-skeletons/). Those files do not turn
local acceptance into deployment approval.

## Prerequisites

- run from the repository root;
- use the repository-pinned Rust toolchain and lockfile;
- have the `wasm32-unknown-unknown` target installed for full mode;
- have `wasm-pack 0.14.0` (the CI-pinned version) and its compatible
  `wasm-bindgen` tools preinstalled; full mode regenerates the ignored WASM
  package with Cargo locked and offline before TypeScript. The local script
  checks `wasm-pack` directly and fails closed if `wasm-bindgen` is absent or
  incompatible; it does not install or silently replace either tool;
- have `web/node_modules` populated by `npm ci` from the pinned lockfile before
  full mode; the static Pages guard loads its exact YAML parser from that
  dependency boundary, while the same install supplies the remaining Web and
  Playwright dependencies. Quick mode exits before this guard and does not need
  `node_modules`;
- have the Playwright-pinned Chromium runtime installed before full mode
  (`cd web && npx playwright install chromium` installs it separately; the
  acceptance script never downloads a browser);
- do not set production Lightning, mint, relay or server credentials in the
  shell used for this check.

The acceptance script forces Cargo offline and does not edit source. Quick mode
starts no persistent service process, although focused unit tests briefly bind
loopback TCP or Unix-domain listeners. Full mode starts temporary
`unified_server` children, a fake `payment-issuer` and Vite test servers whose
listeners are explicitly bound to `127.0.0.1`; the process and Playwright
runners kill and wait for every child before returning.

## One-command checks

Focused check:

```sh
scripts/payment-v1-local-check.sh --quick
```

Full local check:

```sh
scripts/payment-v1-local-check.sh --full
```

Optional real-CDK browser import, real-provider query, and native custody
interoperability (outside the default offline suite) requires exact
`cdk-mintd` and `cdk-cli` 0.17.3 binaries. Apple-arm64 uses the recorded
official hashes below by default; other platforms must also provide both
expected SHA-256 values through `BITCOINPIR_CDK_MINTD_SHA256` and
`BITCOINPIR_CDK_CLI_SHA256`:

```sh
BITCOINPIR_CDK_MINTD=/absolute/path/to/cdk-mintd \
BITCOINPIR_CDK_CLI=/absolute/path/to/cdk-cli \
  scripts/payment-v1-cdk-regtest-e2e.sh
```

Append `--check-binaries` to validate only the version/hash pins without
starting the fake mint, creating a bearer token, or invoking Cargo.
Default mode first runs `cargo build --locked --offline -p bpir-admin` and an
offline, locked `wasm-pack 0.14.0` build of the current workspace, before it
starts the disposable mint. It prints SHA-256 digests for the resulting admin
binary and three runtime WASM package files so an acceptance record can bind
the browser evidence to those exact artifacts.

`--browser-only` deliberately avoids Cargo and therefore cannot establish
current source-to-artifact correspondence. It fails closed unless the operator
sets `BITCOINPIR_CDK_BROWSER_ONLY_ACKNOWLEDGE_PREBUILT=1`, supplies an absolute
`BITCOINPIR_BPIR_ADMIN` path, and pins that binary plus the generated package
metadata, JavaScript and WASM bytes:

```sh
BITCOINPIR_CDK_BROWSER_ONLY_ACKNOWLEDGE_PREBUILT=1 \
BITCOINPIR_BPIR_ADMIN=/absolute/path/to/bpir-admin \
BITCOINPIR_BPIR_ADMIN_SHA256=<64-lowercase-hex> \
BITCOINPIR_WASM_PACKAGE_JSON_SHA256=<64-lowercase-hex> \
BITCOINPIR_WASM_JS_SHA256=<64-lowercase-hex> \
BITCOINPIR_WASM_BINARY_SHA256=<64-lowercase-hex> \
BITCOINPIR_CDK_MINTD=/absolute/path/to/cdk-mintd \
BITCOINPIR_CDK_CLI=/absolute/path/to/cdk-cli \
  scripts/payment-v1-cdk-regtest-e2e.sh --browser-only
```

The four browser-artifact hashes must come from a trusted build/provenance
record; copying hashes from an unverified working directory only acknowledges
stale artifacts and is not release evidence. With valid pins, browser-only
creates one fake-wallet token, imports it through those exact prebuilt
artifacts in Chromium, exercises encrypted-vault install/retirement, emits an
owner-only canonical spend, and exits without invoking Cargo.

The runner verifies version and binary hashes, disables proxying for loopback,
binds a random `127.0.0.1` port, requires the ready endpoint to identify the
exact child it started, creates only fake-wallet ecash,
passes bearer fixtures and canonical spend only through owner-only files,
bounds every CDK/curl call, disables Playwright traces/screenshots/video, uses
a TERM-to-KILL cleanup deadline, and removes its marker-bound private temporary
directory. It validates padded V4 `cashuB`, current `m,u,t` structure, local
stripping of known NUT-12 wallet metadata, and either the freshly rebuilt
default-mode or hash-pinned browser-only JS/WASM ABI. Chromium must reject the
untouched HTTP token. Because the Cashu proofs do not bind wallet mint-URL
metadata, the private test fixture relabels only that CBOR text. Default mode
uses a signed `https://localhost:<port>` identity and a test-only strict-TLS
proxy whose private CA and leaf SPKI are fixed in the feature-gated process
test; browser-only mode uses a non-routable synthetic identity. Neither path
adds a production plaintext or pinless fallback. Default mode mints two
independent 8-sat notes. Chromium turns the first into canonical provider wire
bytes, then a real Standard Cashu `unified_server` and an independent Free peer
complete two secure channels, exact manifest-root policy checks, preflight,
DPF, Merkle verification, provider restart and local replay rejection without
a second CDK request. The second note is reserved for the native importer and
custody lifecycle. That native ignored test expects four exact NUT-07 observations:
original inputs become `SPENT`, first custody is initially `UNSPENT`, a second
independent BitcoinPIR client spends that authenticated custody through NUT-03,
and the first custody then becomes `SPENT` while successor custody is
`UNSPENT`. The bearer stays in memory and is never passed through `cdk-cli`
argv. Two consecutive local branch script invocations passed this lifecycle;
each executed two real NUT-03 swaps and four exact NUT-07 checks before the
browser-output/gate/restart join was added. The joined default-mode provider
test later passed a dedicated local branch run. The final 2026-07-28
default-mode run repeated it against the current tree and is recorded below.
The predecessor `--browser-only` case passed before the current
acknowledgement-and-provenance guard was added; guarded browser-only mode still
needs its own current-guard run. The runner does not execute the admin
retirement command against CDK, use a public-WebPKI mint, or establish a
production rollback authority.

Test-only heap limitation: JavaScript `String` values are immutable, so the
temporary `cashuB` strings cannot be deterministically zeroized. The harness
clears all mutable byte/number buffers in `finally`, disables trace/media
capture, keeps fixture/spend files owner-only, and relies on short-lived
Chromium/worker teardown plus private-directory deletion for the remaining
string copies. This is evidence hygiene, not a production secret-memory claim.

The full command mirrors the default Rust/WASM portions of
`.github/workflows/payment-platform.yml`, including the Harmony hint-pool
library tests, the selected `unified_server` binary/process targets and the
feature-enabled remote-authority, Standard Cashu and shared-issuer targets. It regenerates the
WASM JS/TypeScript bindings and adds the Web unit suite plus the local Chromium
multi-tab vault, real-WASM/no-funds-issuer and browser/two-provider full local
DPF-query boundaries. It
fails instead of bootstrapping
`wasm-pack`/`wasm-bindgen`, installing JavaScript packages, or downloading
Chromium when those prerequisites are absent.

Both gates deny warnings only for the explicitly selected runtime binary and
process-test targets with `--no-deps`; they do not claim a workspace
dependency-wide `cargo clippy --tests` run. Payment Platform CI additionally
compiles the feature-gated ignored CDK provider test with
`--features insecure-dev-sqlite-store --test cdk_nut03_interop --no-run`.
It also typechecks the separate CDK Playwright harness/config without starting
a mint or browser. Those static steps prove the optional interop targets remain
buildable; they do not replace an opt-in default-mode CDK execution with pinned
CDK binaries.

Payment browser CI, the general Web PR gate and the Pages build all install
`wasm-pack 0.14.0` and lockfile-matched `wasm-bindgen-cli 0.2.114` with Cargo
`--locked` under Rust 1.94.1; none executes a remote `curl | sh` installer or
lets `wasm-pack` download a CLI during the build. Generation uses
`--mode no-install`, `--no-opt`, and Cargo locked/offline, so it neither
downloads tools nor executes an unpinned `wasm-opt` found on the runner PATH.
The Pages build uses the real workspace graph rather than rewriting the root
manifest, and only the separate deploy job receives Pages write/OIDC
permissions; third-party build steps run with contents read-only. A push to
`main` runs the complete build/test job and produces the candidate artifact,
but the deploy job is skipped. Production publication requires a separate
manual `workflow_dispatch` selected on `main` with
`confirm_production_deploy=true`, after the operator approval required by this
runbook. That manual run rebuilds and retests the exact selected `main` ref; it
does not promote the artifact from an earlier push run. After lockfile-pinned
`npm ci`, Payment CI and the Pages build execute the YAML 1.2 semantic
`payment-v1-pages-deploy-gate.mjs` guard. It requires the exact
manual/main/boolean condition, `needs: build`, no `always()` override, the
protected `github-pages` environment, and unique Pages/OIDC write permissions
plus configure/deploy actions confined to that job. It rejects
anchors/aliases/merge keys, `write-all`, Actions-write permissions, reusable-
workflow delegation, extra jobs and any sibling workflow outside the exact
contents-read permission boundary, while all workflow changes trigger Payment
CI; decoded Unicode-escape controls and the fail-closed trigger truth table run
internally. This is a repository-static/default-`GITHUB_TOKEN` boundary. It
cannot exclude an external PAT or GitHub App token invoking the Actions API, so
repository default workflow permissions, rulesets, credential governance,
Pages build mode and the mutable environment policy (including required
reviewers and main-only deployment) must all be rechecked before publication.
Newly used
workflow actions are exact-SHA pinned, Node is fixed to supported LTS
`24.18.0`, and the Payment/Web path filters include the toolchain, vendor and
trust inputs needed by the generated WASM. A Payment/security UI change cannot
skip the Payment browser boundaries, and the Pages job reruns strict TypeScript
and unit tests plus all three no-funds Chromium Payment boundaries before
publishing.
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

The historical 2026-07-27 closeout run used a fresh isolated Cargo target and
one build job so concurrent review processes could not share artifacts or
locks:

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

The first pushed closeout commit (`394988fc`) then exposed a real
rollback-floor acknowledgement race in GitHub run `30231837753`: the Free
quota concurrency test expected three successful callers but observed two.
The database never over-granted quota. Instead, writer A committed generation
1, writer B reconciled and advanced the same database through generation 2,
and writer A's delayed authority CAS response conservatively reported its
already-committed mutation as unanchored.

The correction passes the exact still-open SQLite connection that performed
each COMMIT into post-commit anchoring. A superseding authority floor is
accepted only after that same connection reconciles to the stable, identical
lineage; an authority advance from a cloned database fork remains fail closed.
All 13 provider-store mutation call sites use this boundary. Deterministic
tests cover both same-database transitive confirmation and a conflicting
cloned-fork rejection. Independent review repeated each new test 100 times,
repeated the real SQLite Free concurrency case 500 times with exactly three
successes every time, and passed all 79 service-store unit tests, both
service-store documentation tests and warnings-as-errors clippy.

After that code correction, the following complete local command also exited
zero:

```sh
CARGO_BUILD_JOBS=1 scripts/payment-v1-local-check.sh --full
```

It reran the complete offline Rust/platform suite, both provider-process
boundaries, service-store 79/79 plus 2/2 documentation tests, Payment clippy,
wasm32 and fresh WASM generation, 333 Web unit tests with two intentional
skips, the four Chromium multi-tab cases and the generated-WASM/real-loopback-
issuer case. The final staging-document and static-label amendments were made
before the Web/typecheck/unit/bundle/Chromium stages. Pushed GitHub CI on the
correcting commit remains authoritative before merge.

Separate opt-in no-real-funds evidence on 2026-07-27 also passed for the older
tree captured by this historical record:

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

The current CDK test extends that older case with a second NUT-03 spend directly
from authenticated custody memory, then checks first-custody
`UNSPENT -> SPENT` and independent successor-custody `UNSPENT`. On 2026-07-27,
two consecutive local branch invocations of
`scripts/payment-v1-cdk-regtest-e2e.sh` passed
that extension. Each invocation ran one native test of the WASM import logic,
two real NUT-03 swaps and four real NUT-07 observations. The official CDK 0.17.3 hashes
remained the values recorded above. No bearer appeared in process argv, no
Lightning node or real funds participated, and no CDK child or bearer temporary
file remained after either run.

Also on 2026-07-27, the dedicated `--browser-only` case passed in Chromium with
local CDK 0.17.3 binaries and explicitly supplied SHA-256 pins
`a84b791d6add5add40f20d5f78985262a39d845965c7c3b5718ffc74145ba432`
(`cdk-mintd`) and
`f1a253ee3fdb2d7866d2117ead86bc6b482154f4938e046956e2555c6ca5d80c`
(`cdk-cli`). This records the exact local artifacts used, not official-release
provenance. The untouched HTTP token was rejected, the metadata-relabelled
fixture imported through generated JS/WASM, the encrypted-vault count moved
from one to zero, and `localStorage` remained empty. The private runtime and
bearer files were removed and no CDK process remained.
This historical invocation predates the current mandatory prebuilt
`bpir-admin`/WASM provenance pins and is not a pass record for that new guard.

On 2026-07-29 the current same-run extension passed against locally built
Linux-arm64 CDK 0.17.3 binaries. Their local build digests were
`0421e150ac7d201c0211a6fea144f864d5f5ec081a2365b189720a5860237aa7`
(`cdk-mintd`, fakewallet+SQLite) and
`e894d9ce0696db34ba547ecd6cc50f9a760ec1cad77628388dd7e4c7acdb8243`
(`cdk-cli`, no default features); these identify the tested local builds and
are not official-release provenance. Mint, CLI, both providers and all Rust
tests ran in one Linux container with CDK reachable only on container loopback.
Chromium imported the first note through the Linux-built current-tree WASM and
wrote the owner-only canonical spend. The ignored real-CDK process case passed
1/1, including independent Free authorization, two secure channels, exact-root
preflight, DPF/Merkle, two-provider restart and replay rejection with the TLS
proxy attempt count still one. The second-note WASM parser and native
NUT-03/NUT-07 custody cases each passed 1/1. CDK stdout and file logs contained
no `cashuB` bearer, payment-hash/preimage field or BOLT invoice value. This used
fakewallet notes only: no Lightning node, invoice payment, public mint, remote
PIR service or real funds participated. Exact-commit CI remains authoritative
before merge.

### 2026-07-28 current-tree CDK default-mode closeout

The opt-in, no-funds default-mode runner completed with exit status 0 using
CDK 0.17.3 binaries at explicitly supplied absolute paths and these exact local
SHA-256 pins:

- `cdk-mintd`:
  `a84b791d6add5add40f20d5f78985262a39d845965c7c3b5718ffc74145ba432`;
- `cdk-cli`:
  `f1a253ee3fdb2d7866d2117ead86bc6b482154f4938e046956e2555c6ca5d80c`.

The invocation also set `CARGO_INCREMENTAL=0` and `CARGO_BUILD_JOBS=2`. It
built the current-tree `bpir-admin` and generated WASM package, passed the
Chromium import/vault case 1/1, the ignored native `pir-sdk-wasm` CDK interop
case 1/1, and the ignored `pir-cashu-client` provider custody case 1/1. Its
terminal success record was:

```text
CDK 0.17.3 fakewallet NUT-03/NUT-07 input-SPENT, custody-UNSPENT->SPENT, successor-UNSPENT interoperability: PASS
```

The gate first exposed two test-harness drifts: the synthetic signed manifest
omitted the now-required leaf-SPKI pin field, and the ignored provider test
imported an obsolete trusted-catalog type. Both were corrected before the
successful complete rerun; neither failed attempt is counted as a protocol
pass. After exit, no `cdk-mintd` child and no `bitcoinpir-cdk.*` private runtime
directory remained. This proves the stated disposable fake-wallet boundaries,
not public-mint interoperability, production WebPKI, Lightning participation,
real-value custody or production payout.

### 2026-07-28 current-tree CLN regtest closeout

The explicitly acknowledged local-only command completed with exit status 0:

```sh
CARGO_NET_OFFLINE=true \
  scripts/payment-v1-cln-regtest-e2e.sh --acknowledge-local-regtest-only
```

It rebuilt the current WASM package offline and started one isolated disposable
`bitcoind` plus three Core Lightning nodes in issuer, router and payer roles.
The payer had no direct issuer channel; the two announced local channels forced
the tested payments over the payer -> router -> issuer route. The first
Playwright phase passed 3/3 in 1.7 minutes: exact lost-response recovery plus
direct receipt, routed Cashu BAT, and routed experimental ARC. The joined
provider/query phase passed 1/1 in 1.1 minutes after paying new routed direct,
BAT and ARC invoices, for 4/4 browser cases overall. Its terminal success
record was:

```text
payment-v1 CLN regtest E2E: PASS (temporary regtest only; no real funds)
```

After exit, no marker-owned `bitcoind`, `lightningd` or `bitcoinpir-cln`
process and no `bitcoinpir-cln.*` private runtime directory remained. This is
current-tree evidence for the local production-CLN adapter, generated-WASM
acquisition/recovery and joined synthetic two-provider DPF/Merkle boundary. It
is not Signet, public-network, real-funds, production-ingress, production
attestation or deployed-origin acceptance; ARC remains experimental.

### 2026-07-29 CLN bootstrap and bundle-layout gate

The current-tree bootstrap work was exercised without creating a persistent
wallet, contacting a remote node or using funds. The focused Lightning-staging Rust
suite passed 32/32, the full `bpir-admin` suite passed 125/125, and the scoped
warnings-denied clippy invocation passed. The deployment-template gate passed
24/24 and the rendered-artifact gate passed 79/79.

The executable-closure check was also tested against the official Core
Lightning v26.06.6 image pinned by digest:

```text
elementsproject/lightningd@sha256:094be3630f865c795649d6063a8796afa0f78e82a0c311bb34f2b0bd570c819a
```

Because the deployment target is x86-64 while the development host is arm64,
the manifest-list check was repeated under QEMU against its explicit linux/amd64
child digest
`sha256:f8f1ec25ea6dfbc9fab1e3dd918e15f7c4a3f5bb97b87bb6490d4c8a7c71ee6b`.
It reported `v26.06.6`, passed `--test-daemons-only --offline`, contained the
same eight required subdaemons and accepted the native 32-byte identity format.

A minimal copied layout containing the pinned CLI, HSM tool, daemon, required
plugins and required `libexec/c-lightning` subdaemons passed
`lightningd --test-daemons-only --offline`. Removing `lightning_hsmd` was
rejected, and the positive invocation with an explicit empty config made no
wallet or network-state mutation. The final bootstrap gate additionally uses
the fixed eight-call sequence with empty `listfunds`, and the rendered layout
requires a pre-existing owner-read-only native 32-byte `hsm_secret`. A
disposable native 32-byte seed was accepted by the same pinned image's
`lightning-hsmtool getnodeid` and produced an exact compressed public node ID;
no seed bytes were printed or retained. This is evidence for the bootstrap RPC
sequence, activation-sentinel separation and bundled executable closure only.
It is not evidence for a persistent Signet identity, an isolated identity
restore, faucet funding, channel recovery, production secrets or a production
deployment.

### 2026-07-28 focused Harmony closeout

After the final V2Full reservation/lifecycle changes, the focused Rust 1.94.1
commands completed successfully:

```sh
cargo test --locked --offline -p runtime --lib hint_pool
cargo test --locked --offline -p runtime --bin unified_server
cargo test --locked --offline -p runtime \
  --test payment_v1_harmony_pool_process_e2e
```

The original closeout passed 54/54 hint-pool tests and 64/64 `unified_server`
tests. A later full-matrix run exposed fork/exec descriptor-inheritance
contention, after which capacity and inode locks gained explicit-unlock guards.
The resulting current suite passed 56/56 five times under default parallelism
and 56/56 single-threaded, plus warnings-denied runtime-lib clippy. The one-case
real provider-process lifecycle E2E passed three consecutive focused
invocations and then 1/1 in the final pinned-Linux matrix. The repeated results
remain separately identified rather than being folded into a false unique
aggregate count.

The focused coverage includes: mmap ownership through worker shutdown; exact
pool binding and conservative reconciliation; non-blocking capacity-lock
contention; rejection of corrupt/unvalidated floor surplus; rotation of a
peer-locked queue head; a real child-process barrier proving the online floor;
explicit capacity/durable/generation/staged/reconciliation inode unlock with
primary-error precedence and success-plus-unlock-error fail-closed behavior;
grant/disconnect/first-dispatch/restart and replaced-inode fail-closed behavior;
and the immutable post-grant dispatch window. That window starts only after the
complete encrypted `AUTH_GRANTED` frame is written and flushed, bounds pending
reads plus Ping/Pong with the same absolute instant, and cannot be reset. Apart
from bounded WebSocket control handling, the pending connection accepts only
the exact encrypted canonical `HarmonyHintsV2` request for the grant-bound
database.

The online floor counts only fully validated, ready paths in the current local
`PoolState` snapshot that are lockable during the atomic decision. It prevents
a successful online reservation from taking the final such entry at that
instant; it does not reserve that entry for a particular provider-local caller
or prove fairness, priority or immediate admission.

### 2026-07-28 focused operator-receipt lock closeout

The full `bpir-admin` suite passed 106/106 five times under default parallelism,
then 106/106 single-threaded; the package's warnings-denied clippy gate also
passed. Atomic backup-receipt writes now explicitly release the pinned parent
directory lock after every ordinary success/error path. A primary operation
error is never hidden by an unlock error; a successful operation followed by an
unlock failure fails closed. Immediate third-write reuse is covered. The suite
does not yet contain a deterministic child that holds an inherited duplicate
descriptor across a fork barrier, so that stronger regression remains a P2
test improvement rather than a production activation claim.

### 2026-07-28 focused shared-redeem and clone-fencing P0 closeout

The following current-tree, offline focused commands passed:

```sh
cargo test --locked --offline -p pir-service-store
cargo test --locked --offline -p pir-provider-clearing-client shared_grant_tests
```

The service-store result was 93/93. It includes the exact cloned-state races in
which two callers construct the same external floor CAS but fresh nonzero
256-bit grant nonces make only one successor anchor; the other caller fails
closed for generic spend, Free-IP admission and final Standard-Cashu grant. It
also covers `spend_seq` advancement, shared-issuer namespace separation and
sensitive request Debug redaction.

The shared-grant provider-clearing result was 6/6. It covers exact signed issuer
response replay for Free/BAT/experimental-ARC without a second grant, eight
concurrent exact responders with one winner, explicit identical-proof recovery
after an outcome-unknown transport result, invalid issuer response without a
local claim, wrong-provider store rejection before transport, and the real
issuer-service ExactReplay-to-provider-local-claim boundary. The fixture
uses credential-binding `amount = 1`, while the clearing rule has
`accepted_value = 10`, `provider_credit = 9` and `issuer_fee = 1`, proving that
protocol amount and clearing value are independent.

These tests exercise the low-level retained-identical-proof recovery API. They
do not authorize the official browser to retain or automatically retry a shared
redeem presentation: Web deletes/burns it before send. If local delivery has
committed and `AUTH_GRANTED` is lost, the entitlement stays consumed. This is
focused local evidence only. The same code was subsequently covered by the
passing final pinned-Linux aggregate; pushed CI remains a separate per-commit
merge gate.

The DPF and Harmony retained send methods are deliberately exported only as
`dangerous_unpaired_*` in Rust and `dangerousUnpaired*` in JavaScript. Their
ordinary one-sided names do not exist. The Web DPF/Harmony adapters call the
low-level entry points only behind strict pair transport/readiness checks and
the product layer must freeze the exact two-provider payment context before it
retires either capability. Onion and TEE-ORAM remain single-provider APIs.

### 2026-07-28 final pinned-Linux Rust/process matrix

A clean Rust 1.94.1 Docker target ran the final current tree offline with no
external payment network, funds or remote service. Its 27-package aggregate
reported 1294 passed and 41 explicit opt-in/documentation ignored cases. The
dedicated stages additionally passed BAT 1/1, ARC 14/14 plus two doc tests,
warnings-denied Payment clippy, 22 fake-Lightning/debug tests, 84 bounded
adversarial/rollback tests, hint pool 56/56, `unified_server` 64/64 and the
debug parser 1/1.

Real loopback process stages passed direct receipt 2/2, five-method 1/1,
Harmony 1/1, remote rollback-root/provider/issuer 1/1 each and strict-TLS
Standard Cashu 1/1. Release guards rejected test WebPKI roots in five
configurations, fake Lightning in three and unsafe query logging in two. CDK
compile-only coverage, the two-provider x five-workload x five-method
`funds_capable=false` fixture, and CDK/CLN runner validation also passed. The
repeated dedicated stages bring the non-unique summary total to 1546 passed;
that number must not be presented as a unique test count. All 16 original logs
were scanned for failure and payment/key-secret markers, SHA-256 inventoried
and retained outside Git.

This matrix proves the stated local Rust/process and build-guard boundaries.
It is not a public Lightning/Cashu/Nostr, production attestation/database,
deployed-origin browser or real-funds result, and it does not replace pushed CI
for the exact candidate commit.

### 2026-07-28 final Web/browser closeout

Strict TypeScript, the production bundle plus CSP verifier, and the full unit
suite passed with 348 tests and two intentional skips. The corrected cross-tab
policy-checkpoint test passed 100 consecutive focused runs; 25 complete
parallel Vitest runs each passed the same 348/2 boundary. The real Chromium
vault suite passed 4/4.

The current generated-WASM/real-loopback-issuer boundary passed its one default
no-funds case; the two CLN-only cases were intentionally skipped. The browser/
two-issuer/two-provider boundary passed 3/3, covering direct/BAT consumption,
cross-provider rejection and Free/experimental-ARC through one verified DPF/
Merkle query. The first real-issuer attempt timed out before any browser
assertion or service start because macOS indexing stalled a workspace-target
compile. An offline, non-incremental, single-job prebuild in an owner-private
isolated target completed, both suites then passed, their children exited, and
the exact temporary target was removed. This was a local build-cache incident,
not a protocol failure.

The semantic Pages gate, exact `yaml@2.9.0` dependency check, diff check and
production-dependency npm audit also passed; the audit reported zero
vulnerabilities. These local results do not replace exact-head CI or deployed-
origin/manual acceptance.

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
| Free | `cargo test --offline -p pir-service-store free_ip_rate_limit`, the runtime matrix, the feature-gated non-receipt process matrix, `payment_v1_process_e2e`, `payment_v1_methods_process_e2e`, and `npm run test:e2e:payment-two-provider` | open and durable IP-quota authorization through real DPF, Harmony hint/query, Onion and TEE-ORAM provider processes, including wrong-operation non-burn and restart-persistent quota rejection; the default process test additionally boots exact-pinned storeless Free-PoW with no store/authority, completes challenge/solution/AUTH/real DPF and rejects cross-exporter replay; the Chromium variant joins an exact signed quota-1/window-3600 IP-rate-limited offer and verified DPF/Merkle execution | public-IP attribution behind a real proxy, a generated-browser PoW case, production SEV/UKI measurement, or production DDoS resistance |
| Direct BOLT11 receipt | `cargo test --offline -p pir-lightning-backend`, issuer lifecycle tests, `direct_receipt_production_committer_spend_survives_store_restart`, and optional `scripts/payment-v1-cln-regtest-e2e.sh --acknowledge-local-regtest-only` | fake lifecycle/state tests, signed receipt admission and replay rejection across ProviderStore restart, plus a real local CLN socket and generated-WASM acquisition path; the final current-tree opt-in run passed the forced payer -> router -> issuer route and joined verified provider queries | a public-network or real-value wallet payment, production ingress, or production Lightning operations |
| Standard Cashu eCash | `cargo test --offline -p pir-cashu-client`, `cargo test --offline -p pir-cashu-custody`, ProviderStore custody tests, the runtime matrix, optional `scripts/payment-v1-cdk-regtest-e2e.sh`, and the feature-gated Standard-Cashu/non-receipt process commands below | exact swap/recovery/grant-to-custody state machine, generated-JS/WASM plus real-CDK NUT-03/NUT-12, and strict-TLS NUT-03 swap through real DPF, Harmony hint/query, Onion and TEE-ORAM provider processes; wrong-operation and replay rejection do not make an extra mint request | an approved external public-WebPKI mint, an independent production rollback floor, admin retirement against real CDK, public-mint interoperability, real-value custody or payout |
| Cashu BAT | `cargo test --offline -p pir-payment-crypto --features provider-store --test provider_store_bat_adapter`, the runtime matrix, `payment_v1_methods_process_e2e`, and the feature-gated non-receipt process matrix | real blind/DLEQ/unblind proofs through DPF, Harmony hint/query, Onion and TEE-ORAM provider processes, plus provider-local durable serial rejection after restart | a public/shared Cashu service or production key custody |
| ARC experimental | `cargo test --offline -p pir-arc-adapter --features provider-store`, the runtime matrix, `payment_v1_methods_process_e2e`, the feature-gated non-receipt process matrix, and `npm run test:e2e:payment-two-provider` | real draft-01 issuance/presentation through DPF, Harmony hint/query, Onion and TEE-ORAM provider processes plus nullifier persistence and restart rejection; the Chromium variant additionally joins generated-WASM local issuance, persist-before-release, real ProviderStore replay rejection and verified DPF/Merkle execution | independent cryptographic review, complete IETF protocol interoperability, browser-driven provider restart, or permission to advertise ARC as stable |

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

The production-process cross-product supplement is feature-gated only because
its Standard Cashu leg installs a private test CA. One shared fixture prepares
Free-IP, strict-TLS Standard Cashu, BAT and experimental ARC offers/proofs; the
real `unified_server`, production committer, ProviderStore and native backend
handler are never replaced. It runs the four exact tests named in
`docs/payment/TEST_PLAN.md`. Together with the dedicated direct-receipt tests
and DPF method-adapter tests, this closes all 25 method/workload cells. Each
non-receipt cell checks encrypted AUTH, exact signed scope/workload,
wrong-operation non-burn, native handler output and restart-persistent method
state. Harmony hint uses two capabilities per method to separately prove
pre-dispatch reservation restoration and first-dispatch durable consumption.
ARC remains experimental despite this coverage.

### 2026-07-29 provider-process matrix closeout

The candidate based on `eb08d956` passed the four focused matrix commands in
`TEST_PLAN.md` on Linux/arm64 in `bpir-rust-ci:1.94.1` (1/1 each). A combined
`cuckoo-oram,standard-cashu-process-e2e` run of all four process test binaries
then passed 9/9, including every pre-existing direct-receipt process test. The
pre-existing strict-TLS two-provider Standard Cashu process case separately
passed 1/1. Both targeted Clippy invocations passed with warnings denied: the
Standard-Cashu server plus Harmony-query/hint and Onion targets, and the
combined-feature TEE-ORAM target. No public mint, external network, remote
provider, production attestation, Lightning node or funds participated. The
ARC leg used the required explicit experimental opt-in and is not a
cryptographic-review claim.

## Loopback provider process boundaries

Full mode and payment-platform CI run:

```sh
cargo test --offline -p runtime --test payment_v1_process_e2e
cargo test --offline -p runtime --test payment_v1_methods_process_e2e
cargo test --offline -p runtime --test payment_v1_harmony_pool_process_e2e
cargo test --offline -p runtime --test payment_v1_onion_process_e2e
cargo test --locked --offline -p runtime --features cuckoo-oram \
  --test payment_v1_tee_oram_process_e2e
```

The first two no-funds tests launch real OS child processes and communicate over
real TCP/WebSocket connections. Their stateful two-provider fixtures give each
provider a distinct provider ID, policy key, method keys, ProviderStore and
rollback authority. The first test binary also has a distinct single-provider
storeless Free-PoW fixture with no ProviderStore or authority. Every listener
is explicitly `127.0.0.1`-only, and the first test also proves that a misspelled
`--bind-addres` flag exits non-zero before opening a listener.

The direct-receipt test covers cleartext backend rejection, ephemeral-bound
attestation exchange, secure-channel upgrade, exact signed manifest-root
policy verification, encrypted pre-authorization rejection, provider-specific
and workload-specific direct-receipt authorization, a valid DPF
request/response, and a complete four-frame K-padded Harmony INDEX/CHUNK query
through the real handler. DPF and Harmony use distinct signed scopes, globally
unique offer IDs and credential keys. A DPF receipt rejected at the Harmony
scope remains usable for DPF; a completed Harmony DFA is terminal; both DPF
and Harmony spends remain rejected after provider 0 restarts. The exact
provider-1 DPF receipt is first rejected by provider 0 and then succeeds at
provider 1, proving that the wrong-provider rejection neither burns it nor
consults a shared cross-provider spent set. No hint server is configured or
named by this query-provider test.

The same process binary now exercises the narrow VPSBG-oriented storeless
mode. It pins the exact domain-separated digest of one canonical signed policy
containing only provider-local Free-PoW, starts `unified_server` without a
ProviderStore or rollback argument, obtains a server-fresh challenge on the
encrypted channel, solves it, receives `AUTH_GRANTED`, and reaches one real DPF
handler frame. A second connection has a different secure-channel exporter and
no outstanding challenge, so replaying the old solution is rejected. The
temporary runtime tree is checked for provider/rollback SQLite, WAL and SHM
files. Startup negatives cover the wrong digest, an otherwise valid Free-open
policy, retained/store/rollback/Free-IP/BAT/shared inputs and legacy ARC/Cashu
keys. This does not prove a measured UKI: the exact digest must be included in
that UKI, and every signed policy update requires a new UKI/measurement/client
pin ceremony.

The method-adapter test repeats the real wire and DPF execution boundary for
Free open, durable provider-local IP quota, provider-local Cashu BAT and
experimental ARC. BAT uses an actual blind/sign/DLEQ/unblind proof; ARC uses
the pinned implementation's issuance and presentation path. It rejects a
provider-0 BAT/ARC presentation at provider 1, proves provider-local quota
independence, and rejects quota/BAT/ARC replay after both providers restart
against their own stores.

The Onion process test launches two independently keyed providers and reaches
the production OnionPIR workers with a one-row fixture generated through the
public `onionpir` API. It proves wrong-provider and structurally wrong-scope
failures do not consume the receipt, then performs one real chunked key
registration and decrypts INDEX, CHUNK and both Merkle-sibling response
ciphertexts. Extra registration, phase skip, wrong round and a second logical
job fail closed after the atomic spend, and replay stays rejected across a
ProviderStore/process restart. Its tiny Merkle fixture exercises sibling
ciphertext generation/decryption, not full production inclusion verification.

These loopback process tests intentionally observe `NoSevHost` and use SDK
`dangerous_unpaired_*` helpers. It validates the local secure wire and Payment
V1 gate, not production server identity, binary pinning, hardware attestation,
production database proof/trusted-root pinning, Merkle tree-top/inclusion
verification, or an attested build. Its receipt is constructed from public
deterministic fixture keys: no issuer process, browser, wallet, Lightning node,
external Cashu mint, Nostr relay or real funds participate. The direct-receipt
test executes both DPF and Harmony query backends; the method-adapter test
executes DPF, and the dedicated backend tests execute Harmony hints, Onion and
TEE-ORAM. The five-method x five-workload in-process matrix remains
deterministic wire/gate evidence, while the feature-gated process supplement
exercises the same cross-product through production committers and handlers.
The Harmony process test launches one real Harmony V2Full hint provider with a
private disk pool and checks invalid-proof non-consumption, per-method
pre-dispatch disconnect restoration, first-dispatch durable consumption,
matching-marker restart and replaced-inode fail-closed behavior.

The fourth process test uses the production `cuckoo-oram` feature. It builds a
tiny direct INDEX/CHUNK Circuit ORAM through the same public library API used
by `oramctl build-direct`, including authenticated sidecars and a separate
trusted controller-state directory. A paid direct receipt crosses the real
encrypted admission gate and reaches the direct ORAM handler; the response is
checked against the two exact source chunk records and the fixed response
padding budget. Same-key receipts bound to another provider or a DPF scope,
and a raw DPF operation under the TEE-ORAM scope, fail before ORAM work. The
grant admits one frame only, spent receipt replay remains rejected after
restart, and a fresh receipt proves that the authenticated ORAM state reopens
and remains usable. The pinned Linux run passed 1/1 plus warnings-denied
clippy. This is local `NoSevHost`/deterministic-fixture evidence, not production
attestation, DB proof, remote rollback-floor or browser evidence.

The separate opt-in CDK runner exercises the real provider-side client against
a loopback CDK mint through an exact test-only endpoint mapping.

An additional non-default Standard Cashu process cell is implemented:

```sh
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_standard_cashu_process_e2e \
  standard_cashu_real_process_tls_two_provider_e2e -- --exact
```

It starts a deterministic TLS NUT-03 responder and two real providers with
independent identities, policies, stores and payment selections. The Cashu
provider uses the exact signed mint endpoint and leaf-SPKI pin; the peer selects
Free/OpenBestEffort without learning or sharing that choice. The client uses
attestation-bound secure channels, verifies both policies, authorizes both
sides, preflights proof-bound arity-8 tree tops, executes a two-server DPF query
and explicitly verifies the Merkle absence result. It restarts both providers
against their original stores, rejects bearer replay without a second NUT-03,
then proves wrong CA, wrong signed pin and offline mint fail closed without
another mint spend.

The pinned-CDK runner additionally invokes the ignored same-run case after
Chromium writes its owner-only canonical spend:

```sh
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_standard_cashu_process_e2e \
  standard_cashu_real_cdk_browser_provider_two_server_e2e \
  -- --ignored --exact
```

The runner supplies only owner-only temporary database, policy, spend and
endpoint bindings. The test recomputes the prepared manifest and bucket roots,
requires an exact manifest-root DPF scope, terminates the fixed private-CA TLS
identity at a loopback-only proxy to the actual CDK HTTP listener, and launches
the Standard Cashu and Free providers with independent identities, policy keys,
stores and rollback databases. It then performs secure-channel policy
authorization on both sides, proof-bound tree-top preflight, a two-server DPF
query and Merkle absence verification. After both providers restart, replay is
rejected from provider-local state and the proxy's durable attempt count remains
one. Provider/proxy logs are checked against bearer/proof/invoice material; the
runner separately checks CDK stdout and file logs for bearer values, payment
hash/preimage fields and BOLT invoice strings.

The private CA hook exists only under the named debug-only feature. Its root
must be an owner-only bounded file; normal WebPKI chain, hostname, time and the
signed SPKI pin remain mandatory. Default `unified_server` builds reject the
test-root CLI flag, and release compilation with the feature is forbidden. The
test source and CI commands are present. The final pinned-Linux current-tree
matrix passed the process case 1/1, warnings-denied clippy and ordinary-CLI/
release-feature rejection guards. The test uses deterministic public material
and `NoSevHost`; it does not prove an
external public-WebPKI mint, production server identity/attestation or an
independent production rollback floor.

An additional non-default shared-issuer process cell is also part of full mode
and Payment Platform CI:

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

This is the executable provider-to-shared-clearing seam: a real issuer behind
a private signed-pin TLS edge, a real paid provider and an independent Free
peer. The edge reads one complete canonical issuer success, then drops that
response after the issuer commit while retaining only three test-local SHA-256
digests. The provider fails closed without a local claim. Restarting both issuer
and provider against their original stores/floors and replaying the exact proof
must reproduce all three digests, recover exactly one provider-local grant and
leave exactly one issuer ledger credit/sequence; a later replay cannot create a
second grant. The same run invokes the production `bpir-admin` builders for
both clearing artifacts, provisions a distinct provider-request public key,
verifies freshly signed balances before and after an issuer restart, then—only
after the lost-response operation reaches a known local-delivery result—rotates
the authorization epoch and issuer settlement key with explicit old-key
retention. The restarted provider keeps the credential at-most-once. This does
not claim that V1 recovers an outcome-unknown redeem across authorization
rotation; operators must drain and reconcile before rotating. Wrong-CA,
wrong-pin and offline issuer
dependencies fail before the issuer HTTP application without invoice creation
or real funds. It does not prove public
source-fair ingress, independent production rollback domains, real Lightning,
automated payout, or target-host systemd state. The source is wired into CI,
but this preparation branch must not record a pass until the Linux cell has run
on the exact candidate commit.

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
official full NUT-02 V2 keyset derivation, imports it through the checked-in
generated JS/WASM package in Chromium, and persists/retires it through the
encrypted browser vault. Default mode sends those exact canonical browser
bytes to the real admission gate and standard-Cashu committer, executes the
provider-side NUT-03 request and NUT-12 DLEQ verification, commits received
notes to custody, and checks same-process and reopened-store replay rejection.
The current same-run extension uses the first independent note for Chromium and
the real `unified_server` provider, routes only its NUT-03 swap through the
feature-gated private-CA TLS proxy, completes the independent Free peer plus
DPF/Merkle query, and proves restart replay is rejected without another CDK
touch. A second independent note is then spent by the native custody test,
which observes the first custody lot become all-`SPENT` and successor custody
remain all-`UNSPENT`. Production HTTPS/WebPKI behavior is unchanged; the
private root feature is compile-rejected in release profiles.

## Fake Lightning and issuer checks

The deterministic fake Lightning backend is an in-process test backend. Run:

```sh
cargo test --offline -p pir-lightning-backend
cargo test --offline -p pir-issuer-core
cargo test --offline -p pir-issuer-service
cargo test --offline -p payment-issuer
cargo test --offline -p payment-issuer --features test-only-fake-lightning
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

The production-capable listener is deliberately loopback-only. The fake
listener exists only in an explicitly feature-enabled debug/test artifact:

```sh
cargo run --offline -p payment-issuer \
  --features test-only-fake-lightning -- serve-fake --help
cargo run --offline -p payment-issuer -- serve-cln --help
cargo test --offline -p payment-issuer fake_server_refuses_non_loopback
```

Default artifacts have no `serve-fake` parser variant, fake backend, or
`/__test/fake/settle` route. Release builds reject
`test-only-fake-lightning` in both the crate build script and source, including
when release debug assertions are forced on. The no-funds browser runners add
the feature only when their selected backend is `fake`; CLN-regtest builds do
not enable it.

Starting either available listener requires an existing issuer store/rollback
authority, an exact root-signed quote-key delegation and matching key,
credential derivation key, and at least one exact signed service policy. The
fake mode additionally requires its deterministic signing key and derivation
seed; CLN mode requires its checked local RPC socket configuration. Receipt,
BAT, experimental ARC and clearing offers require their additional
key/authorization material. The committed deterministic no-funds
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
cargo test --offline -p pir-issuer-clearing payout_worker
cargo test --offline -p payment-issuer settlement_http
```

These suites cover canonical bounded settlement envelopes, the production
authenticated balance route, and a private Rust unit-fixture switch for the
otherwise non-routed payout-intent/payout/status HTTP roundtrip. They exercise
payout state verification, response loss and exact latest-status replay without
making payout part of the production/default binary's HTTP product. Production
returns unknown-path before parsing or store access for all three payout paths.
For a **status successor**, the provider
client persists the exact pending envelope before send, then commits its
successor state and mandatory external rollback floor together through its
state-store boundary.
Issuer provider registrations are append-only history: an old request key may
authenticate only a byte-identical durable latest-status replay after its
canonical request digest and provider have matched; fresh status and every
financial mutation require the current registration.

The historical pre-v2 record passed the then-focused append-only-history,
issuer-service and provider-client cases. Those cases proved that an initial
payout is persisted before POST; an
outcome-unknown restart resends exact bytes and creates one economic payout;
tampered intent/registration/pending floors fail closed; fresh preparation uses
real current time/current registration/current issuer key; and concurrent or
repeated payouts preserve one monotonic terminal-predecessor chain. This closes
the send-before-persist implementation P1. The current settlement-v2 store and
payout-worker cases require fresh result recording; this document deliberately
does not infer a new count from the older run.

The dated historical acceptance record above supplies the old command and
counts; a new current-tree record and pushed branch CI remain authoritative
before merge. The client is transport-neutral. The repository now includes a
concrete persistent SQLite `ProviderSettlementStateStoreV1` and a no-funds
`IssuerPayoutOutboxWorkerV1`. It also includes the concrete strict-WebPKI HTTPS
provider-settlement transport, but none of these components is deployed. A
truly independent floor adapter and real-funds executor remain absent. The
worker persists `InFlight` before the first submission and reconciles rather
than resubmitting after restart, but a real adapter must itself provide a
linearizable durable command-ID lookup/submission primitive or equivalent
no-submit fence. No passing library test enables production settlement.

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

The full local script and Payment CI additionally select the real two-relay
process topology explicitly (the test is ignored by ordinary package runs so
`--quick` still starts no service process):

```sh
cargo test --locked --offline -p bitcoinpir-directory-relay \
  --test payment_v1_two_relay_process_e2e \
  two_relay_real_process_catalog_e2e -- --exact --ignored
```

It launches two copies of the repository's production
`bitcoinpir-directory-relay` binary and covers separate config/SQLite/runtime
state plus four distinct loopback listeners. Every accepted signed `EVENT`
publication uses a publisher lane; every accepted ID/catalog `REQ` and returned
`EVENT`/`EOSE` uses a public lane. Deliberate wrong-lane probes must close, and
an exact-ID public readback proves the rejected EVENT sentinel was not
persisted. The test covers complete 16-shard signed readback, one relay offline, two
independently valid but conflicting stale-head views with an exact split-view
error, a public-lane lost-ACK durability barrier followed by an idempotent
publisher-lane retry, and readiness of both listeners after independent restart.
The remote-authority full-mode cell also selects
`three_authority_process::three_authority_real_process_topology_e2e`. That test
spawns three authority child test harnesses which invoke production
`rollback_authority::run` and three TLS-edge child harnesses; the parent process
calls production ProviderStore/IssuerStore adapters directly. The
deployment-set validator owns duplicate-pin/namespace rejection, raw clients
own wrong-pin/client/cross-domain transport assertions, and the production
adapters own crossed-provider, independently isolated provider- and
issuer-authority outages, exact same-generation issuer recovery and stale-floor
assertions. During each authority outage the other two Stores remain
independently openable and authenticated through their own authorities. It does
not launch `unified_server`, `payment-issuer`, or installed
binaries. These new commands require their first Linux CI run on the candidate
commit; no passing result is claimed here, and same-host processes do not prove
operational independence.

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

That lost-response case is **credential issuance claim recovery**, where the
browser retains the exact blind issuance transcript. It is not provider-side
shared-redeem presentation recovery. For service authorization, the official
Web path deletes/burns the proof before sending and performs no automatic retry.

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
funds. That acquisition/recovery phase itself does not launch a PIR provider;
the same opt-in command now follows it with the joined two-provider boundary
documented below.

## Chromium browser/two-issuer/two-provider DPF query boundary

Full mode and Payment Platform CI are wired to run:

```sh
cd web
npm run test:e2e:payment-two-provider
```

The harness uses current generated WASM and a deterministic no-funds fixture to
launch two separate loopback `payment-issuer serve-fake` processes and two
separate loopback `unified_server` processes. All eight issuer/provider detailed
store and local rollback-floor paths are distinct. The browser establishes both
secure channels, checks the fixture's explicit `NoSevHost` boundary, verifies
every pinned catalog/database-proof field, installs that verified proof, fetches
each independently signed provider policy. One exact selection acquires a
direct receipt for provider 0 and Cashu BAT for provider 1. A second exact
selection sends provider 0's signed Free/IP-rate-limited authorization with
quota `1`, window `3600` and the IP-rate-bucket leakage disclosure without
creating an invoice or making any request to its issuer, while provider 1
acquires and advances an explicitly experimental ARC credential through
generated WASM and the real local issuer. The ARC issuer and provider both
require explicit experimental opt-in and use a fixture-dedicated key; provider
IDs, policy keys, issuer identities and durable state paths remain independent
across the pair. Direct-peer-IP attribution is explicitly enabled only for
provider 0 inside this loopback harness. The tests submit each selection to the
real provider gates, require provider 0's second secure connection to receive
durable `server-busy`, prove provider 1 can still consume another independent
ARC presentation, check ARC-presentation replay and the no-Free-downgrade
failure path, and check that original BOLT11 invoice bytes, payment hashes and the actual
20-byte query scripthash are absent from the named provider WebSocket/log
observations. After both grants commit, each success selection fetches and
proof-binds generated arity-8 tree tops, performs one real encrypted two-server
DPF query and requires an explicit successful inclusion/absence verdict before
exposing the minimal not-found result summary. The direct receipt remains
issuer-linkable by design, and ARC remains experimental pending independent
review.

This is a complete **local DPF query/verification E2E** within a deliberately
synthetic trust boundary. Its report proves report-data byte binding only; it is
not an AMD SEV-SNP signature, production identity/binary attestation or a
production database. The generated bucket-Merkle files and super-root are real
and mutually bound, but they commit only to the deterministic all-zero fixture.
Raw outgoing WebSocket ciphertext absence is only a plaintext-regression check;
the protocol structure and minimized provider logs carry the stronger boundary.
On 2026-07-27 the preceding admission-only revision passed both Chromium cases
(`2 passed`). The complete-query plus Free/experimental-ARC extension later
passed its dedicated local branch run. The final 2026-07-28 isolated-target
current-tree rerun passed all three complete-query cases. Exact-head pushed CI
and deployed-origin/manual acceptance remain separate gates.

## Opt-in real-CLN joined provider/query boundary

The same two-provider harness now has an explicit `cln-regtest` backend invoked
only through:

```sh
scripts/payment-v1-cln-regtest-e2e.sh --acknowledge-local-regtest-only
```

After the existing real-CLN acquisition/recovery cases, the joined case starts
two independent `payment-issuer serve-cln` processes and two production
`unified_server` gate processes. It routes and pays three new invoices through
the disposable payer -> router -> issuer topology, claims direct-receipt, Cashu
BAT and experimental-ARC capabilities in generated WASM, consumes them in the
provider stores, rejects their replay, and completes mandatory tree-top
preflight, encrypted DPF execution and explicit Merkle inclusion/absence
verification. It checks the provider observations for invoice, payment-hash,
preimage and query-sentinel leakage and requires zero `localStorage` writes.

The two payment/credential issuers retain separate identities, origins, policy
and credential keys, stores and rollback floors. They intentionally share the
one CLN payee in this minimal three-node test, which models a shared settlement
operator that can correlate payment timing; it does not weaken the independent
PIR provider keys/stores, and no invoice, hash or preimage is sent to either PIR
server. This is not part of the default offline/PR run. CI performs only runner
syntax and harness TypeScript/config checks. The forced two-hop three-node
runner passed its final 2026-07-28 current-tree opt-in run, 3/3 acquisition and
1/1 joined provider/query cases, with owned process/runtime cleanup confirmed.
This is not a public-network or real-funds claim. The explicit `NoSevHost`,
local rollback floors and deterministic all-zero database remain
non-production boundaries, and ARC remains experimental pending independent
review.

## Source-fair cold-activation evidence

The historical pinned Ubuntu 24.04/HAProxy 2.8.16/Caddy 2.11.3 audit container passed the
five deployment, rendered-artifact, runtime-evidence, source-fair and Nostr
readback suites 154/154 with no skip. This includes real Linux `getent`, `id -G`, procfs
all-thread scanning, all active capability sets plus `CapBnd`, rejection tests
for CHOWN/DAC_OVERRIDE/FOWNER/SETFCAP and managed-unit capability expansion,
locked service-account policy validation, the stopped-edge evidence validator,
pinned Caddy adapted-JSON closure, and 4xx/no-backend cross-bind probes.
That Caddy version is no longer production evidence. Current edge CI resolves
the exact Caddy 2.11.4 OCI index/binary. The separate existing-Caddy admin-UDS
process test also runs Caddy 2.11.4 with Node 22.22.2, proves root API readback,
non-root service-UID `EACCES` after descriptor-pinned `setpriv` clears
capabilities and supplementary groups, exact root-owned DAC metadata, absent
TCP 2019, a real import-override regression, permission-drift rejection, and a
same-process reload through the UDS. The exact adapter suite also proves all 21
non-canonical Unicode whitespace separators and both quoted `admin` directive
forms can change the real adapted listener and are rejected by the gate, and
proves the exact candidate adapter output and live `/config/` readback have the
same strict-parsed canonical JSON digest and size. This
branch also adds an isolated real-systemd-PID-1 lifecycle test. It refuses to
overwrite any existing Caddy unit/config/runtime path, starts the byte-exact
fixture twice as distinct cold generations, proves stop-time directory/socket
removal and start-time root:root `0700`/`0200` recreation, validates both real
32-lowercase-hex systemd InvocationIDs through the production gate, proves
effective `LimitCORE=0`, `MemorySwapMax=0`, `StandardOutput=null` and
`StandardError=null`, confirms a failing request sentinel is absent from
journald, and repeats UDS readback, TCP-2019 absence and same-PID reload checks.
A current target-host
cold ceremony and its independently transferred evidence remain required. This
does not isolate UID 0 or `CAP_DAC_OVERRIDE`. A current-tree pinned Ubuntu 24.04 /
HAProxy 2.8.16 / Caddy 2.11.4 targeted run passed the 15 source-fair template
and real-process tests with no skip. A fresh complete aggregate using the final
branch remains required before activation.

This is deterministic compatibility evidence, not target-host activation. The
actual candidate must first collect an independently digest-pinned
`collect-stopped-edge` record while Caddy and HAProxy are fully stopped and all
Unix listeners are absent. Only after a bounded edge activation is approved and
both `ACTIVATION-APPROVED` and `EDGE-ACTIVATION-APPROVED` are provisioned may it
start HAProxy then Caddy and collect a separate digest-pinned `collect-live`
record. Both must run from the target host's independently confirmed initial
PID namespace; a warm reload, container-only record or evidence without its
complete transferred SHA-256 is not accepted. At the end of a private no-funds
drill, stop Caddy and then HAProxy, confirm the listener set is empty, and revoke
`EDGE-ACTIVATION-APPROVED`.

## 2026-07-30 P1-3 preflight owner/mode contract

The current worktree passed the focused static-config/dynamic-receipt closeout:

```sh
cargo test --locked --offline -p bpir-admin
node --test scripts/payment-v1-deployment-template-gate.test.mjs \
  scripts/payment-v1-rendered-artifact-gate.test.mjs
cargo clippy --locked --offline -p bpir-admin --all-targets --no-deps -- -D warnings
```

Results were 139/139 Rust tests and 104/104 Node tests, with the target package
warnings-denied clippy clean. In addition, the exact
`protected_config_real_linux_uid_gid_and_mode_contract` test passed as root in
the existing `bpir-rust-ci:1.94.1` Linux container with networking disabled.
That real-kernel matrix changes the child EUID, effective GID and supplementary
groups and covers root/config-group `0440`, wrong owner/mode/EUID, missing and
extra groups, a writable direct parent and a writable ancestor. The normal
macOS run also executes the platform-independent identity/group-set matrix.

The broader dependency-linting form without `--no-deps` remains non-green under
the local Rust 1.94.1 toolchain because the pre-existing
`pir-identity::signing_preimage` triggers Clippy's `too_many_arguments`; that is
not reported as passing evidence for this closeout.

## 2026-07-30 P1-1 CLN InvocationID lease closeout

The current dirty CLN worktree passed the short-lease remediation checks in a
network-disabled, root-run `bpir-rust-ci:1.94.1-tools` container with the source
mounted read-only and `CARGO_TARGET_DIR` confined to the container's `/tmp`:

```sh
cargo fmt --package bpir-admin -- --check
cargo test --locked --offline -p bpir-admin
BPIR_REQUIRE_ROOT_CREDENTIAL_TEST=1 cargo test --locked --offline \
  -p bpir-admin \
  lightning_staging::tests::protected_config_real_linux_uid_gid_and_mode_contract \
  -- --exact --nocapture
cargo clippy --locked --offline -p bpir-admin --all-targets --no-deps -- -D warnings
node --test scripts/payment-v1-deployment-template-gate.test.mjs \
  scripts/payment-v1-rendered-artifact-gate.test.mjs \
  scripts/payment-v1-linux-runtime-evidence.test.mjs
```

Results were 140/140 Rust tests, the separately forced real-root contract 1/1,
and 190 Node tests with 168 passed, 22 platform-specific skips and zero
failures. Package-scoped formatting and warnings-denied Clippy were clean. The
source gate passed directly, and Actionlint passed for this workflow after
excluding its three pre-existing informational `SC2016` findings outside the
new root-test step.

The Node runtime suite includes typed D-Bus dependency arrays and
`TimeoutStopUSec`, stale-manager/missing-edge/lookalike/timeout mutations, and
final-snapshot drift. Rust additionally covers commit-time backup-age
revalidation, exact watchdog environment parsing and Linux abstract notify
sockets.

The new required relationship and service-property fields intentionally bump
the live request, collector identity and evidence kind from v4 to v5. Existing
v4 render requests or evidence must not be translated or reused; render a new
v5 request and collect fresh target-host evidence after `daemon-reload`.

This establishes source and deterministic compatibility evidence only. It does
not prove target-systemd formatting, a live CLN InvocationID mapping, watchdog
enforcement, BindsTo propagation, fresh CLN identity bootstrap or production
activation; those remain target-host gates.

## Expected acceptance record

Record the commit, platform/toolchain, command mode, pass/fail result and any
skipped boundary. Do not record invoices, payment hashes, preimages, raw
capabilities, query addresses, results, browser vault records or secret paths.

Keep the record external to this dated document and begin it with the following
fail-closed fields. Fill them from the actual post-merge artifacts; never infer
a merge SHA or CI conclusion from a local worktree:

| Field | Initial value before independent verification |
| --- | --- |
| `merged_source_commit` | `UNSET_AFTER_MERGE` |
| `exact_head_ci_urls_and_conclusions` | `UNSET_AFTER_MERGE` |
| `local_acceptance_source_commit` | exact tested commit, or `UNSET` |
| `render_plan_digest` | `NOT_APPLICABLE_SOURCE_MERGE` |
| `remote_runtime_evidence_digest` | `NOT_APPLICABLE_SOURCE_MERGE` |

At minimum, a release candidate needs evidence for:

1. all offline Rust payment packages;
2. unified-server admission/DoS-guard and Harmony hint-pool unit tests, wiring
   check and the loopback two-provider process tests;
3. wasm32 check plus fresh generated WASM bindings;
4. Web unit tests and all three local Chromium payment boundaries, including
   browser/two-issuer/two-provider local DPF query and Merkle verification;
5. five-method × five-workload matrix;
6. persistence/restart/concurrency suites;
7. deterministic no-funds fixture generation;
8. the locked product contract and exact external EasyCrypt record;
9. the stopped-edge and fresh-live source-fair activation evidence pair;
10. an approved staging network E2E once its edge controls are implemented.

## Not exercised by this procedure

- public-network or real-value Lightning payment, routing, notification or
  refund behavior (the opt-in runner covers a local CLN socket, local channel
  routing and a paid regtest BOLT11 invoice);
- an unmodified unified-server provider NUT-03 path against a public/WebPKI
  Cashu mint (the opt-in local CDK runner covers the same provider-side client,
  real CDK response and custody commit, but uses an exact test-only loopback
  transport mapping, including the current in-memory custody-spend lifecycle);
- production-catalog publication, ongoing public-relay durability and
  DNS/egress-rebinding controls (one short-lived empty public-relay
  publish/readback compatibility smoke is recorded above);
- an actually independent production rollback-floor adapter and restore domain;
- production TLS/reverse proxy, quote-spam controls, load tests for the global
  connection/auth limits, or tree-top bandwidth overload at the edge;
- production identity/binary pins, remote servers, hardware attestation,
  production database proofs/trusted roots, or production databases;
- production-grade process fixtures for Harmony, Onion or TEE-ORAM (their
  local real-provider-process boundaries use deterministic/no-SEV fixtures and
  do not establish production attestation, data or inclusion-proof evidence);
- a deployed browser-to-issuer-to-provider main-page network E2E (the visible
  main-page controller is covered by unit tests; the local Chromium harness
  reaches two real issuers and two real providers and executes a DPF query with
  Merkle verification, but uses `NoSevHost`, synthetic proof material and an
  all-zero test database rather than production identity/attestation/data);
- independent ARC review;
- a resolved and hash-frozen directory-relay selection; the committed
  `UNRESOLVED` relay state is an activation blocker, not a passing local test;
- a production Standard Cashu mint. Until an exact mint, WebPKI/pins, unit,
  custody limits and recovery/outage plan are approved, every mint-dependent
  Standard Cashu offer in the current policy must be omitted. The checked-in
  profiles reject retained-policy flags and payloads. The
  complete `provider-v1` profile still has fixed Standard-Cashu inputs and must
  remain unmaterialized and inactive without that mint approval. The distinct
  `provider-no-standard-cashu-v1` profile may be used only after its own plan
  approval: it binds a separate unit, NSS identity, state/configuration paths
  and activation sentinel, and carries BAT/shared-issuer material but no
  Standard-Cashu recovery, custody or exposure inputs. Its current acquisition
  policy must omit Standard Cashu. This checked-in profile is zero-retained:
  the gates reject retained-policy flags and payloads, so it has no old-policy
  redemption route. Startup fails if current method coverage or Cashu
  configuration checks fail. This does not establish a
  production mint or authorize
  external mint access. A
  still smaller deployment may instead select `provider-direct-v1`, whose exact
  nine-payload closure omits BAT and shared-issuer material as well and includes
  an owner-only remote rollback config, client-signing seed and value-root key.
  Its current
  acquisition routes may use only Free open-best-effort, Free proof-of-work,
  provider-local Free anonymous tickets and direct BOLT11 receipts. This is
  also a zero-retained closed profile. The Cashu validator rejects Standard
  Cashu in the current policy; current method coverage rejects BAT, shared
  online, ARC and every other unavailable applicable route. The unit also
  carries no Free-IP
  adapter material. It has a
  separate unit/account/paths/sentinel and makes no paid-QoS claim. Before any
  provider-profile switch, stop and deauthorize the old unit, prove it inactive
  with no `8191` listener, and create only the new profile sentinel. For the
  same logical provider, first stop issuance/admission, wait through the
  longest old policy/capability/grace horizon, fully retire/reconcile Standard
  Cashu custody, and drain shared-issuer redeems to known outcomes. Static gates
  cannot prove that drain, so separately reviewed transition evidence is
  mandatory. Only then may a stopped-state migration preserve the
  stable server ID, operator key and derived provider ID, policy-signing key,
  provider identity certificate/key, ProviderStore/store-instance identity,
  spend and replay history, remote authority instance/key, namespace, client-
  verifying-key identity, client-signing seed, value-root key and floor. The
  TOML may be re-rendered only with the new canonical secret paths. Rotating an
  authority-identity field requires a separately reviewed migration ceremony
  because V1 has no online rebind/reset; a blank
  store in the new profile directory is forbidden. Otherwise the deployment
  must use and publish a genuinely new provider/server identity;
- a reviewed mainnet deployment preflight. The current Lightning preflight is
  default-Signet-specific and cannot authorize mainnet;
- deployed-origin CSP/header enforcement, dependency closeout and manual
  testing;
- a repository ruleset that requires the Payment/security checks and prevents
  unreviewed direct `main` pushes (the 2026-07-28 read-only check found no branch
  protection/ruleset, while the mutable Pages environment was main-only), plus
  a Pages required-reviewer policy and review of PAT/GitHub-App credentials able
  to dispatch Actions;
- user manual acceptance.

All of the above remain explicit gates. Remote server mutation, bounded service
activation, persistent Signet custody, faucet/test-coin use, external Cashu-mint
access, public Nostr publication, VPSBG UKI build/upload/reboot, production-key
installation/use and mainnet/real Lightning funds require separate fresh
approvals; none implies another.
