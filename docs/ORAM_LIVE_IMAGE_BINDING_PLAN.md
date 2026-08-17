# Direct ORAM input and live-runtime binding

Status: **regenerate-on-boot model active; public db0 input proof implemented**
as of 2026-08-12.

The measured VPSBG production runtime starts Direct ORAM from fixed database
inputs inside SEV-SNP. The attached image is volatile operational state: query
it with `scripts/vpsbg-production-status.sh` and use `web/src/attest-pin.ts` plus
`docs/data-retention/` for the reviewed identity and point-in-time release
record. The runtime does not reuse a previously published ORAM image as the
user's trust anchor. This choice determines what the browser proof must
establish and removes the need for a byte-reproducible ORAM output ceremony.

## Security statement

The browser establishes this chain:

```text
AMD-signed database BuildEvidence V2 (full-build, no predecessor)
  -> exact server database MANIFEST.toml
  -> typed [direct_oram] input hashes, sizes, record counts, and layout
  -> live db0 proof for the same manifest root
  -> live AMD-verified, production-pinned runtime for the same manifest root
  -> measured startup path regenerates Direct ORAM before serving queries
```

The user therefore learns which database inputs the measured runtime is
required to use. The TEE is responsible for generating and maintaining the
mutable ORAM state and for authenticating later page accesses.

This proof does **not** claim that the current mutable ORAM files are
byte-for-byte equal to an archived build output. Such equality is neither
stable after ORAM accesses nor required by the selected security model.

## Runtime responsibilities

The public input proof does not replace these measured-runtime controls:

- copy fixed direct inputs and database evidence into SEV-protected `/run`
  before hashing/building, avoiding a disk hash/build TOCTOU;
- require predecessor-free BuildEvidence V2 and the typed `[direct_oram]`
  binding before `oramctl` starts;
- generate secret ORAM initialization randomness from OS entropy and never
  publish or log it;
- keep controller state, authenticated roots, lookup metadata, keys, stash,
  and other trusted mutable state inside `/run`;
- authenticate persistent bulk meta/payload/hash pages against that trusted
  state; and
- refuse to listen until runtime attestation, secure-channel setup, database
  proof checks, and Direct ORAM initialization succeed.

Controller authentication roots remain security-critical inside the TEE. They
are intentionally not static browser proof inputs: each boot produces fresh
runtime state, and an outer JSON copy of a root would not prove that the live
measured process installed that copy.

## Public source-proof contract

`web/public/proofs/oram-source/current.json` is a closed manifest. It references
only these non-sensitive artifacts:

1. `build-evidence.bin`;
2. its raw AMD SEV-SNP report;
3. `root-bundle-payload.bin`;
4. `database.manifest.sha256`;
5. `all-artifacts.manifest.sha256`;
6. the exact server database `MANIFEST.toml`; and
7. the AMD ARK, ASK, and VCEK certificates already used by the trust-chain
   verifier.

Every reference has an exact path, SHA-256, and size. The verifier rejects an
expanded or incomplete artifact set.

The browser then checks:

1. artifact SHA-256 and size;
2. strict BuildEvidence V2 decoding and `evidence_mode=full_build`;
3. no predecessor evidence/report hashes;
4. the BuildParamsV2 digest;
5. root bundle and all three manifest hashes committed by BuildEvidence;
6. the narrow typed `[direct_oram]` table, including exact 64-bit decimal
   values and bytes/record consistency;
7. domain-separated `REPORT_DATA` recomputation;
8. AMD ARK/ASK/VCEK chain and report signature against the pinned builder
   measurement;
9. the production db0 V2 pin, including builder binary and commit;
10. the current live db0 proof's server-manifest root; and
11. the current runtime's `verified-vcek`, `reportDataMatch`, VCEK-chain,
    production-pin, and manifest-root results.

The verifier runs after strict ORAM connection preflight. A static artifact
bundle alone cannot produce a verified source badge.

## Deliberately excluded from Web

The following are not browser source-proof artifacts:

- ORAM output file hashes or sizes;
- `SHA256SUMS` for a historical ORAM output directory;
- ORAM build logs or operator run metadata;
- static controller state or controller authentication roots;
- a historical ORAM implementation commit that is not part of the live
  measured runtime pin;
- an operator-authored `liveDeployment` assertion;
- raw database contents; or
- RNG seeds, page keys, controller/service/admission/payment private keys, and
  memory dumps.

Output hashes and controller roots may remain in offline operational archives
for debugging, recovery, and performance comparison. They do not gate the
browser badge and must not be described as additional user security.

## Negative fixtures

`web/src/__tests__/fixtures/oram-source-proof-v1-leaked/` preserves the exact
legacy v1 evidence only to prove fail-closed handling. Its disclosed RNG seed
makes it permanently ineligible for Web publication or production proof use.

Focused mutation tests cover the actual trust chain: wrong builder
commit/binary pin, substituted input manifest, changed REPORT_DATA, mismatched
live database/runtime manifest root, insufficient live runtime attestation,
and v1 evidence. Output-hash and static-controller-root mutations were removed
because those fields are no longer part of the security claim.

## When a stronger design would be needed

A genesis image identity, authenticated state-transition lineage, or external
anti-rollback witness is relevant only if a future deployment reuses mutable
ORAM state across boots and wants to make that reuse a public claim. Such a
change would require a new threat model, runtime attestation fields, protocol
schema, UKI rebuild, and production authorization. It is not part of the
current regenerate-on-boot product requirement.
