# Payment v1 local acceptance

Status: no-funds developer acceptance. This procedure does not deploy, contact
a Lightning node or Cashu mint, publish to a Nostr relay, or operate a public
PIR server.

## Prerequisites

- run from the repository root;
- use the repository-pinned Rust toolchain and lockfile;
- have the `wasm32-unknown-unknown` target installed for full mode;
- have compatible `wasm-pack` and `wasm-bindgen` tools preinstalled; full mode
  regenerates the ignored WASM package with Cargo offline before TypeScript;
- have `web/node_modules` populated from the pinned lockfile before full mode;
- do not set production Lightning, mint, relay or server credentials in the
  shell used for this check.

The acceptance script forces Cargo offline and does not edit source. Quick mode
never starts a listener. Full mode starts temporary `unified_server` children
whose listeners are explicitly bound to `127.0.0.1`; the process test kills
and waits for every child before returning.

## One-command checks

Focused check:

```sh
scripts/payment-v1-local-check.sh --quick
```

Full local check:

```sh
scripts/payment-v1-local-check.sh --full
```

The full command mirrors the Rust/WASM portions of
`.github/workflows/payment-platform.yml`, regenerates the WASM JS/TypeScript
bindings, and adds the Web unit suite. It fails instead of bootstrapping
`wasm-pack`/`wasm-bindgen` or installing JavaScript packages from the network
when those prerequisites are absent.

## What “five methods accepted” means

| Method | Focused command/boundary | What it proves | What it does not prove |
|---|---|---|---|
| Free | `cargo test --offline -p pir-service-store free_ip_rate_limit` plus the runtime matrix | durable quota accounting and canonical Free authorization reaches every backend gate | public-IP attribution behind a real proxy or production DDoS resistance |
| Direct BOLT11 receipt | `cargo test --offline -p pir-lightning-backend`, issuer lifecycle tests and `direct_receipt_production_committer_spend_survives_store_restart` | fake invoice state, signed receipt admission and replay rejection across ProviderStore restart | a real wallet/node payment or production issuer listener |
| Standard Cashu eCash | `cargo test --offline -p pir-cashu-client` plus the runtime matrix | exact swap/recovery state machine, mint response validation and backend admission with deterministic test transports | compatibility or availability of an external mint |
| Cashu BAT | `cargo test --offline -p pir-payment-crypto --features provider-store --test provider_store_bat_adapter` plus the runtime matrix | real blind/DLEQ/unblind verifier boundary and provider-local durable BAT spend | a public/shared Cashu service or production key custody |
| ARC experimental | `cargo test --offline -p pir-arc-adapter` plus the runtime matrix | draft-01 adapter, nonce/tag persistence, concurrent one-winner semantics and backend admission | independent cryptographic review or permission to advertise ARC as stable |

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
```

This no-funds test launches two independent logical providers as real OS child
processes and communicates over real TCP/WebSocket connections. Each provider
has a distinct provider ID, policy key, issuer/receipt key, ProviderStore and
rollback authority. Both listeners are explicitly `127.0.0.1`-only, and the
test also proves that a misspelled `--bind-addres` flag exits non-zero before
opening a listener.

The covered sequence is cleartext backend rejection, ephemeral-bound
attestation exchange, secure-channel upgrade, exact signed manifest-root
policy verification, encrypted pre-authorization rejection, provider-specific
direct-receipt authorization, a valid DPF request/response, signed one-frame
limit rejection, and durable replay rejection after provider 0 is restarted.
The exact provider-1 receipt is first rejected by provider 0 and then succeeds
at provider 1, proving that the wrong-provider rejection neither burns it nor
consults a shared cross-provider spent set.

This test intentionally observes `NoSevHost` and uses SDK
`dangerous_unpaired_*` helpers. It validates the local secure wire and Payment
V1 gate, not production server identity, binary pinning, hardware attestation,
production database proof/trusted-root pinning, Merkle tree-top/inclusion
verification, or an attested build. Its receipt is constructed from public
deterministic fixture keys: no issuer process, browser, wallet, Lightning node,
external Cashu mint, Nostr relay or real funds participate. Only the DPF
backend is executed through a real process; the five-method x five-workload
in-process matrix and focused adapters remain the coverage for Cashu eCash,
BAT, experimental ARC, Harmony, Onion and TEE-ORAM.

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

## Directory checks

Offline directory codecs, split-view rules and publisher artifact generation:

```sh
cargo test --offline -p pir-directory-nostr
cargo test --offline -p bpir-admin directory_artifact
cargo run --offline -p bpir-admin -- directory-artifact --help
```

These commands do not contact or publish to a Nostr relay.

## Expected acceptance record

Record the commit, platform/toolchain, command mode, pass/fail result and any
skipped boundary. Do not record invoices, payment hashes, preimages, raw
capabilities, query addresses, results, browser vault records or secret paths.

At minimum, a release candidate needs evidence for:

1. all offline Rust payment packages;
2. unified-server admission/DoS-guard unit tests, wiring check and the
   loopback two-provider process test;
3. wasm32 check plus fresh generated WASM bindings;
4. Web unit tests;
5. five-method × five-workload matrix;
6. persistence/restart/concurrency suites;
7. deterministic no-funds fixture generation;
8. an approved staging network E2E once its edge controls are implemented.

## Not exercised by this procedure

- real Lightning payment, routing, notification or refund behavior;
- an actual Core Lightning socket connection or paid invoice (the executable
  adapter and deterministic RPC mapping tests are covered);
- external Cashu mint interoperability;
- public Nostr relay behavior;
- production TLS/reverse proxy, quote-spam controls, load tests for the global
  connection/auth limits, or tree-top bandwidth overload at the edge;
- production identity/binary pins, remote servers, hardware attestation,
  production database proofs/trusted roots, or production databases;
- process-level Harmony hint/query, Onion or TEE-ORAM execution (their
  canonical gate states are covered in-process);
- a deployed browser-to-issuer-to-provider main-page network E2E (the visible
  main-page controller is covered by unit tests);
- independent ARC review;
- user manual acceptance.

All of the above remain explicit gates. Production deployment, remote server
operations and real Lightning funds require fresh user approval.
