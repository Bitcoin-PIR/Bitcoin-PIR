# Repository Boundaries

BitcoinPIR is the production integration repository. It owns the code that
turns independently versioned PIR implementations and proof producers into a
fail-closed, deployable Bitcoin lookup service.

This document is normative for repository moves. A move is not complete when
files disappear from this repository; it is complete only when the new source
of truth is versioned, pinned, tested, and consumed without copying source.

## Ownership model

| Owner | Responsibility | Must remain here |
|---|---|---|
| `Bitcoin-PIR/Bitcoin-PIR` | Wire protocol, database catalog, production clients and server, strict trust policy, deployment integration | Consumer-side proof verifiers, trusted-root installation, attestation and operator-pin policy, Merkle preflight, production Web app |
| `Bitcoin-PIR/harmonypir` | Generic HarmonyPIR protocol and reusable client state machine | Bitcoin database orchestration and BitcoinPIR wire framing do not move upstream |
| `Bitcoin-PIR/attested-builder` | Reproducible database/root-bundle producer | The production client verifier remains here until a stable, versioned verifier API exists |
| `Bitcoin-PIR/bhtm` | BHTM proof producer | Production pinning and proof consumption |
| `Bitcoin-PIR/oram` | ORAM implementation and proof producer | Production ORAM policy and live deployment binding |
| [`Bitcoin-PIR/protocol-proofs`](https://github.com/Bitcoin-PIR/protocol-proofs) | Formal protocol and wire-shape specifications | A lock to an exact proof commit and the generated contract binding it compiles |
| [`Bitcoin-PIR/proof-registry`](https://github.com/Bitcoin-PIR/proof-registry) | Immutable generated DB/BHTM/ORAM proof bundles and verification records | Exact bundle locks, current-verifier rechecks, generated TS/Rust production pins |
| `Bitcoin-PIR/whitepaper` | Paper sources and research evaluation | Product and operator documentation |
| `Bitcoin-PIR/website` | Documentation website | The production query application |
| `Bitcoin-PIR/playground` | Demos and experimental applications | Reusable SDK source; demos consume released or commit-pinned packages |

## Target layout of this repository

The directory migration keeps Cargo package names stable while grouping code by
responsibility:

```text
apps/
  server/                 production server and diagnostic binaries
  admin/                  operator CLI
  web/                    production browser application
crates/
  protocol/               BitcoinPIR protocol and database primitives
  trust/                  identity, attestation, and DB-proof verification
  sdk/
    core/
    client/
    server/
    wasm/
tools/
  db-builder/
  block-reader/
ops/                      deployment and reproducible-build integration
verification/
  locks/                  exact external proof and evidence pins
  contracts/              generated implementation-surface contracts
  records/                content-addressed CI evidence
  scripts/                fetch and re-verification entry points
  toolchains/             product-owned trusted verifier definitions
docs/
```

This is a staged target, not permission for one large path-only rewrite. Each
move must update workspace paths, package manifests, CI path filters, docs, and
offline build inputs in the same pull request.

## Dependency rules

1. Upstream protocol repositories must not depend on BitcoinPIR integration
   crates. Dependency arrows point from this repository to upstream libraries.
2. Bindings are thin. WASM, Python, and JNI wrappers must call the same native
   state machine instead of reimplementing request shape or state transitions.
3. Demos and documentation sites consume published or exact-commit packages;
   they do not vendor copies of `web/src`, generated WASM, or Rust sources.
4. Git dependencies use an exact full commit. Production/offline builds also
   bind the corresponding vendored source snapshot by digest.
5. Generated artifacts are content-addressed and immutable. Mutable deployment
   records reference them rather than modifying them.

## Formal-proof coupling

Moving the EasyCrypt sources does not weaken the proof gate. The main
repository retains `verification/locks/formal-proofs.json`, which binds:

- the full `protocol-proofs` commit;
- the product-owned, digest-pinned EasyCrypt/solver verifier;
- the digest of the protocol contract covered by the proof;
- the proof claims and explicit non-claims;
- the digest of the upstream CI run record.

Links to the proof repository's default branch are navigational only. The
production trust input is the lock's exact commit, manifest digest, generated
binding, and product-owned re-verification. The content-addressed run record is
durable audit metadata with a navigational Actions URL, but is not an
authenticated attestation and is not trusted on its own.

CI checks out the exact proof commit, compares the generated contract digest,
independently validates the proof source set, and reruns `Theorem.ec` with a
product-owned, digest-locked EasyCrypt verifier and a fixed command. It does not
trust a mutable `Makefile`, Dockerfile, or verifier script from the proof
repository. Undeclared `.ec`/`.eca` inputs, `easycrypt.project`, symlinks, and
precompiled proof artifacts are rejected before compilation. Contract surface
identifiers are stable package/module names rather
than physical paths, so directory-only moves do not pretend to be protocol
changes. The locked proof is nevertheless rerun for every pull request,
merge-group revision, and push to `main`; there is no path allowlist that a
newly added encoding surface could bypass. A badge or a `passed: true` field is
not a trust input.
The durable statement is that a specific proof tree and its deterministically
generated contract binding passed a specific verifier. This remains narrower
than a full refinement proof from Rust or TypeScript into EasyCrypt.

Changes to protocol framing, backend round shape, database selection, padding,
or query-dependent branching must update the contract and proof lock. Pure
documentation and path-only changes do not require a new proof when the
contract digest is unchanged.

## Generated-proof coupling

Formal proofs and production evidence are different artifacts:

- `protocol-proofs` establishes abstract wire-shape claims;
- `proof-registry` records immutable database, BHTM, and ORAM evidence;
- this repository decides which evidence is trusted in production and reruns
  consumer-side verification.

The production lock identifies each bundle by registry commit, manifest path,
raw manifest SHA-256, verification profile, and verification-record SHA-256.
Web assets and Rust/TypeScript pins are generated from this lock and
checked with `git diff --exit-code`.

Historical failures or revocations are appended; an old successful record is
never rewritten. Current code must still recheck all low-cost verification
steps rather than trusting the recorded status.

## Migration gates

Before deleting a source directory from this repository:

1. the destination repository has CI and an exact commit or release;
2. old and new implementations pass shared golden vectors;
3. all consumers use the new version without source copying;
4. a fresh checkout builds with `--locked --offline` where required;
5. production trust checks remain fail-closed;
6. compiled server and UKI changes are accounted for in a controlled pin
   rotation and deployment plan.

`vendor/` is handled last. It may leave Git only after a content-addressed
source bundle reproduces the current hermetic offline build from a fresh
checkout.

## Staged migration order

Repository cleanup follows dependency and trust boundaries, not directory
count. The current milestone consists of:

1. consuming the generic HarmonyPIR remote client from an exact upstream
   commit and removing the local `harmonypir-wasm` implementation;
2. grouping the four SDK packages under `crates/sdk/` without changing their
   Cargo package names or public APIs; and
3. moving EasyCrypt sources to `protocol-proofs` while retaining an exact,
   fail-closed proof lock and trusted re-verification in this repository.

After that milestone merges, use this order:

1. Import the production DB, BHTM, and ORAM bundles from `web/public/proofs/`
   into `proof-registry`. Add `verification/locks/generated-proofs.json`, rerun
   the current consumer verifier in this repository, and generate browser
   assets from the lock before deleting the original files.
2. Reconcile the two `rootbundle` implementations. **Complete:**
   `attested-builder` now has CI, shared golden vectors, compatibility tests,
   and protected `rootbundle-v*` releases; this repository pins the exact
   release commit and verifies retained production payloads before removing
   the nested copy.
3. Merge the remaining `pdf/` source changes into `Bitcoin-PIR/whitepaper` and
   delete the generated-paper copy here after a reproducible build comparison.
   **Complete:** the exact upstream commit and generated PDF digest are pinned
   in `verification/locks/whitepaper.json`; two clean builds were byte-identical.
4. Move in-repository crates in small path-only pull requests: trust crates,
   protocol/runtime crates, server/admin applications, then tools/ops/docs.
   Package names and public APIs remain stable.
5. Extract a reusable `packages/web-client` while keeping the production Web
   application and strict trust policy here. Make `playground` consume that
   package instead of vendored source.
6. Only then consider standalone repositories for `explorer`, the Electrum
   plugin, and the development issuer. Each must consume the shared strict
   client flow before becoming an official external repository.
7. Treat full builder extraction and `vendor/` replacement as the final phase,
   gated on byte-identical output and a fresh hermetic offline build.

The duplicate sources of truth identified for this phase have been removed or
replaced by exact consumer locks and generated assets. Root-level production
crates are primarily a layout problem and should be grouped in this repository
rather than split into many tightly coupled repositories.
