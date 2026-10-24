# Security policy

Bitcoin PIR serves private UTXO lookups. A privacy break is a security
vulnerability here, not a bug: anything that lets a server, a network
observer or another client learn which addresses a user asked about.

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a
security problem.

Report it privately through GitHub: **Security → Report a vulnerability**
on this repository
(<https://github.com/Bitcoin-PIR/Bitcoin-PIR/security/advisories/new>).
The report reaches the maintainer only.

Include what you can: the affected component and commit or deployed pin,
the steps or script that shows the problem, its impact, and whether you
ran it against a production host. A proof of concept against a local
build (`cargo test`, the regtest fixtures, the `web/` dev server) is
preferred. Your own queries against the live servers are fine; do not
degrade the service for others while testing.

## What to expect

The project is maintained by one person.

- Acknowledgement within 7 days.
- An assessment and a fix plan within 30 days. Privacy-invariant and
  fund-safety problems come first.
- Coordinated disclosure: the fix ships with a GitHub advisory that
  credits you unless you ask otherwise. If a fix needs more than 90 days
  we agree a disclosure date with you.

## Scope

In scope:

- The protocol and server (`crates/`, `apps/`), the Rust SDK and WASM
  (`crates/sdk`), the browser client (`web/`), the service directory
  (`crates/directory`, `apps/directory-relay`), and the database,
  deployment and attestation tooling (`tools/`, `scripts/`, `deploy/`).
- The privacy invariants in
  [`docs/VERIFICATION_OVERVIEW.md`](docs/VERIFICATION_OVERVIEW.md): fixed
  query padding, Merkle item-count symmetry, CHUNK round-presence
  symmetry, HarmonyPIR request-count symmetry, INDEX Merkle group
  symmetry. A way to tell found from not-found, or one address from
  another, on the wire is a vulnerability.
- Attestation and trust pins ([`web/src/attest-pin.ts`](web/src/attest-pin.ts)):
  a way to pass verification with a binary, measurement or database root
  other than the pinned one.
- The production deployment described in
  [`docs/SECURITY_POSTURE.md`](docs/SECURITY_POSTURE.md): pir1 (Hetzner),
  the MacBook node and the Direct ORAM TEE host.

Out of scope:

- The admitted trade-off that the per-query CHUNK Merkle item count
  reveals the approximate UTXO count (documented in
  `docs/VERIFICATION_OVERVIEW.md`).
- Volume denial of service against the free, best-effort lanes; they are
  rate-limited by design.
- Vulnerabilities in upstream dependencies, Bitcoin Core, Cloudflare or
  the hosting providers. Report those upstream, and tell us if they affect
  this deployment.
- The credit issuer and the Cashu mint: report those to
  [Bitcoin-PIR/issuer](https://github.com/Bitcoin-PIR/issuer/security/advisories/new).

## Supported versions

Only the `main` branch and the deployed pins recorded in
`web/src/attest-pin.ts` receive fixes. Older tags do not.
