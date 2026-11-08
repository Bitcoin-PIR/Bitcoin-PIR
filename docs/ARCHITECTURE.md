# Architecture

BitcoinPIR serves private lookups over a published Bitcoin UTXO database
generation. This page maps the running system to its code; wire contracts
stay in [Protocol v1](PROTOCOL.md), privacy claims in
[Verification overview](VERIFICATION_OVERVIEW.md), and the reference deployment
in [Project state](PROJECT_STATE.md).

## System boundaries

```text
Browser application / native Rust client / playground
  |
  +-- directory relay --> verified catalog --> provider candidates
  |                                             |
  +-- manual endpoint --------------------------+
                                                |
                               provider verification + encrypted channel
                                                |
                                   database proofs + private lookup
                                                |
                                      Merkle verification + results

Optional paid lane: client wallet --> issuer/mint; PIR server --> issuer
Data supply: attested-builder + BHTM --> proof bundles + tables --> nodes
```

The directory supplies candidates, not query routing or proof that a node
is trustworthy. Clients connect to the chosen providers themselves. The
issuer handles payment, not database production or provider discovery. The
builder produces the data and evidence; it does not participate in a lookup.
These are separate roles even where the reference deployment puts several
on one host.

## Code map

| Area | Responsibility and consumers |
| --- | --- |
| [`crates/protocol/core`](../crates/protocol/core) | Shared hashes, cuckoo/PBC parameters, codecs and Merkle primitives, used by clients, runtime and development builders. |
| [`crates/protocol/channel`](../crates/protocol/channel) | X25519/HKDF handshake and authenticated encrypted frames, shared by the Rust clients and server. |
| [`crates/protocol/runtime`](../crates/protocol/runtime) | Server-side wire types, mapped tables, evaluation, manifests, attestation, identity and database-proof helpers; consumed by the server application. |
| [`apps/server`](../apps/server) | `unified_server` (Cargo package `runtime`): listener, request dispatch, backend execution, hint pool and access/credit metering. Flags select the node's role and served backends. |
| [`crates/sdk/core`](../crates/sdk/core) | `pir-sdk`: common result/catalog types, `PirClient`, sync plans and delta merge. |
| [`crates/sdk/client`](../crates/sdk/client) | `pir-sdk-client`: DPF, HarmonyPIR, OnionPIR and Direct ORAM clients, transport, channel, identity, database verification, credits and native directory discovery. |
| [`crates/sdk/wasm`](../crates/sdk/wasm) | Browser bindings for DPF, HarmonyPIR and ORAM clients, catalog verification, proof and Merkle helpers. Browser OnionPIR uses the separate TypeScript/SEAL path, not a `WasmOnionClient`. |
| [`web/src`](../web/src) | Reusable TypeScript adapters, standalone OnionPIR, discovery, verification and wallet code exported through `index.ts`; `sync-controller.ts` coordinates snapshot/delta state. [`web/index.html`](../web/index.html) owns the application UI. |
| [`crates/trust`](../crates/trust) | Operator certificates (`identity`), SEV-SNP verification (`attest-verify`), builder/database evidence (`db-attest`) and credit models (`pir-credit`). |
| [`crates/directory/nostr`](../crates/directory/nostr) | Signed assertions, announcements, entries, checkpoints, catalog verification and rollback floors, shared by tools and clients. |
| [`apps/directory-relay`](../apps/directory-relay) | Directory-only Nostr relay: public catalog reads/node announcements and a separate publisher lane. |
| [`apps/admin`](../apps/admin) | `bpir-admin`: identity, attestation and database verification tools, plus `directory-artifact` signing, announcement, collection and publication commands. |
| [`tools/db-builder`](../tools/db-builder) | Development database pipeline. Production evidence comes from the external attested-builder, not this local pipeline. |
| [`scripts`](../scripts), [`deploy`](../deploy) | Release, diagnosis, data publication and measured-boot integration; their operating entry point is [Production operations](PRODUCTION_OPERATIONS.md). |

External protocol implementations, the issuer, the attested producer, proof
registry and playground are mapped in
[Repository boundaries](REPOSITORY_BOUNDARIES.md). The EasyCrypt model lives
in the external protocol-proofs repository; it is not a proof of the entire
Rust/TypeScript implementation.

## Lookup and trust

The reference clients verify a directory catalog or use a manual endpoint,
then attest the chosen server, bind an encrypted channel to it, verify its
identity where configured, and verify the database evidence and roots. A
query runs against that database; Merkle checks establish consistency of
returned items with those roots. A valid Merkle path alone does not establish
that the root describes the correct Bitcoin state.

| Backend | Query path | Privacy assumption |
| --- | --- | --- |
| OnionPIR | One server evaluates FHE queries. Native Rust uses the OnionPIR engine; the browser uses `onionpir_client.ts` and SEAL. | Cryptographic privacy from the FHE primitive; no TEE required. |
| Direct ORAM | One attested SEV-SNP guest receives queries inside the encrypted channel and accesses its ORAM pages. | Trust in the measured guest and AMD SEV-SNP; the guest sees the query, its host is meant not to. |
| DPF | Client sends one query share to each of two servers and combines replies. | The two operators do not collude. |
| HarmonyPIR | Hint setup from the hint server, then queries to the query server, with client-side hint state. | Non-collusion in the deployed two-server arrangement. |

OnionPIR and Direct ORAM are first-class in the reference deployment. DPF
and HarmonyPIR are optional; its two slots are run by the same maintainer,
not independent operators. The no-TEE hosts' binary hashes are
self-reported metadata, not hardware-backed evidence against a malicious
operator. Direct ORAM's binary and channel binding are backed by the pinned
measurement and verified AMD chain/platform policy. Pins and their source
comments are in [`attest-pin.ts`](../web/src/attest-pin.ts); operator and
endpoint configuration is in
[`production-providers.ts`](../web/src/production-providers.ts).

The three PIR paths share fixed query padding, CHUNK round-presence and
INDEX Merkle symmetry. Approximate CHUNK/UTXO count remains an admitted
leak; Direct ORAM has its own padded request model. Details and the limits
of the formal model are in [Verification overview](VERIFICATION_OVERVIEW.md).
Sync planning and delta merging are distinct from proof verification: an
incremental merge needs the corresponding prior result state, not only its
height.

## Discovery lifecycle

An operator signs an assertion binding its key, stable server ID and
endpoints. A node can send that public assertion and its backend hints to
the relay without holding the operator's private key. This directory
announcement is separate from the live `REQ_ANNOUNCE` identity handshake.

The workstation publisher collects announcements and checks each node's
identity, role and access hints live. It signs provider entries and the 16
shard checkpoints with the directory publisher key. Clients verify those
events, expiry and rollback floors before offering per-backend candidates;
the live provider still undergoes its own verification. Publisher state
keeps provider sequences and assertion history across runs.

The reference directory uses one relay and explicitly reports
`centralized-single-relay` / degraded: there is no independent relay-view
cross-check. Node announcements are held in relay memory, while the signed
catalog has persistent storage. Re-announcing restores the former after a
restart; it does not renew an operator assertion. The contracts are in
[Directory protocol](DIRECTORY_PROTOCOL.md), the publisher in
[Directory relay](runbooks/directory-relay.md), and the node procedure in
[Operator guide §8](OPERATOR_GUIDE.md#8-get-listed).

## Data and payments

Nodes load a catalog of full and delta databases, table artifacts and proof
directories. Production data and evidence come from attested-builder/BHTM;
the public bundle distributes existing artifacts with a committed hash list,
not newly attested data. Runtime attestation, builder evidence, Bitcoin
anchors and Merkle proofs establish different links in the chain; none
alone establishes all of them. The current provenance exception and retained
source artifacts are described in
[Database artifact retention](DATABASE_ARTIFACT_RETENTION.md), and the next
generation's path in [Database rebuild](DATABASE_REBUILD.md).

Each provider advertises access lanes in `GET_INFO_JSON`. A paid client
presents Cashu ecash as credits, and the server redeems it at the issuer and
meters gas per frame. Free/best-effort or API-key operation does not need a
local Lightning stack. ARC and Payment V1 session grants are retired. The
payment contract is [Credits and gas](CREDITS.md); operational details are
in [Issuer and mint](runbooks/issuer-and-mint.md).

## Release and distribution

Server builds, no-TEE transition pins, measured ORAM images, Pages deployment
and playground re-vendoring are separate release steps, ordered by the
[Release checklist](RELEASE.md). A source merge does not deploy a host or
the application. Leaving a host out of a release leaves its existing pin and
runtime intact.

SDK registry publication is deferred. The native SDK is consumed from
source; the playground continues to vendor `web/src` and built WASM and
records its source in `vendor/SOURCE_COMMIT.txt`. There is no new crates.io
or npm release as part of the hand-over documentation.
