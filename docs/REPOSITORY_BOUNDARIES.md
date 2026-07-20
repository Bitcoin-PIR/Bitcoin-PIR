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
| `Bitcoin-PIR/protocol-proofs` | Formal protocol and wire-shape specifications | A lock to an exact proof commit and the implementation contract it proves |
| planned `Bitcoin-PIR/proof-registry` | Immutable generated DB/BHTM/ORAM proof bundles and verification records | Exact bundle locks, current-verifier rechecks, generated TS/Rust production pins |
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
  scripts/                fetch and re-verification entry points
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
repository retains a lock containing:

- the full `protocol-proofs` commit;
- the digest-pinned EasyCrypt/solver toolchain;
- the digest of the protocol contract covered by the proof;
- the proof claims and explicit non-claims;
- the digest of the verification attestation.

CI checks out the exact proof commit, compares the generated contract digest,
and reruns the proof. A badge or a `passed: true` field is not a trust input.
The durable statement is that a specific proof tree passed a specific verifier
for a specific implementation contract.

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
raw manifest SHA-256, verification profile, and verification-attestation
SHA-256. Web assets and Rust/TypeScript pins are generated from this lock and
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
