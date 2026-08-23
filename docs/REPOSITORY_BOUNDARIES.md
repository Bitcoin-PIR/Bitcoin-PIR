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
| `Bitcoin-PIR/attested-builder` | Native full-build V2 database + BuildEvidence producer (see that repo's README) | Client verifiers, pin tables, and live `verify-live` stay here |
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

### Product-owned EasyCrypt verifier distribution and rollback

The verifier lock has two fail-closed distribution modes. **Phase B is active**:
the lock names a real, immutable, attested OCI digest, and the formal job pulls
that digest before recompiling the proof. A digest placeholder is invalid. The
alternate `bootstrap` mode deliberately has no OCI image digest and rebuilds
`verification/toolchains/easycrypt.Dockerfile` locally; it is retained only as
an explicit reviewed rollback path.

The `Publish attested EasyCrypt verifier` workflow is not callable from a PR. It
can publish only from `main` after its own workflow or the EasyCrypt Dockerfile
changes, an explicit `main` dispatch, or the weekly clean rebuild. A lock or
validator-only change therefore cannot cause an unnecessary cold rebuild. It
publishes a temporary discovery tag only to obtain an OCI digest; that tag is
never a trust input. The workflow attests and verifies the final
`ghcr.io/bitcoin-pir/bitcoinpir-easycrypt-verifier@sha256:...` digest before
reporting it.

The ordinary formal job now pulls the exact lock digest, checks its RepoDigest
and OCI source / revision labels, authenticates to GHCR with its read-only
GitHub token, verifies the GitHub provenance attestation for the protected
publisher workflow, and still runs `easycrypt compile -I . Theorem.ec`. It never
uses a tag or a fallback image. Rollback is another reviewed lock change to an
earlier attested digest; returning to `bootstrap` intentionally restores the
local build rather than trusting a mutable reference.

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

1. **Partial:** `verification/locks/generated-proofs.json` exists and is
   the ORAM lock in Flow H.0. Bundles still live in-tree under
   `web/public/proofs/`. Deleting those files after generating browser
   assets from the lock is remaining cleanup, not a missing proof
   family.
2. Reconcile the two `rootbundle` implementations. **Complete:**
   `attested-builder` now has CI, shared golden vectors, compatibility tests,
   and protected `rootbundle-v*` releases; this repository pins the exact
   release commit and verifies retained production payloads before removing
   the nested copy.
3. Merge the remaining `pdf/` source changes into `Bitcoin-PIR/whitepaper` and
   delete the generated-paper copy here after a reproducible build comparison.
   **Complete:** the exact upstream commit and generated PDF digest are pinned
   in `verification/locks/whitepaper.json`; two clean builds were byte-identical.
4. **Complete:** move in-repository crates in small path-only pull requests:
   trust crates, protocol/runtime crates, server/admin/development-issuer
   applications, then database-builder/block-reader tools. Package names and
   public APIs remain stable.
5. Extract a reusable `packages/web-client` while keeping the production Web
   application and strict trust policy here. Make `playground` consume that
   package instead of vendored source.
6. Only then consider a standalone repository for the development issuer,
   which must consume the shared strict client flow before becoming an
   official external repository. (The Electrum plugin and the `explorer`
   bitcoinjs adapter were both removed 2026-08-14/15 — each had fallen
   behind the protocol, and the owner is considering direct BDK
   integration instead.)
7. Treat full builder extraction and `vendor/` replacement as the final phase,
   gated on byte-identical output and a fresh hermetic offline build.

The duplicate sources of truth identified for this phase have been removed or
replaced by exact consumer locks and generated assets. Production crates and
tools are grouped by responsibility without splitting tightly coupled
integration code across more repositories. The production Web app remains
here; package extraction is a future API-design project, not unfinished
directory cleanup.
