# Retired integrated cold-edge hardening design

Status: historical design note only. The implementation route was intentionally
retired on 2026-08-17 and is not a production requirement, deployment runbook,
security gate, or backlog item. Any future implementation must be designed
again against the then-current codebase and threat model.

## Decision

Do not restore the former `codex/payment-v1-integrated-cold-evidence` branch or
its evidence schemas, transaction scripts, fixtures, and service templates.
That branch explored adding Payment V1 ingress to an existing root-owned Caddy
service, with a source-aware HAProxy edge and a publisher network namespace.
The shared topology expanded the trust, privacy, outage, and rollback scope to
all sites and ACME state already owned by Caddy. Proving that topology safe
became substantially more complex than the product path justified.

Prefer a small, isolated Payment V1 edge service when this work is revisited.
Sharing an existing reverse proxy should require a concrete operational need,
an explicit threat model, and evidence that isolation is not practical.

## Original motivation

The hardening was not a password-storage feature. It attempted to reduce the
chance that payment-sensitive requests, capabilities, credentials, or error
context would be persisted or exposed through the host and edge-service
runtime. Its useful design concerns were:

- prevent sensitive stdout and stderr from being copied into journald;
- suppress service core dumps and avoid swap-backed copies where justified;
- avoid an unnecessary TCP administration endpoint;
- restrict administration to a local Unix socket with narrow ownership and
  permissions;
- avoid passing secrets or configuration authority through ambient environment
  variables;
- distinguish an approved process generation from an automatic restart or warm
  reload; and
- retain an explicit, recoverable rollback boundary for a cold change.

The second half of the experiment attempted to prove that both the old Caddy
and source-aware edge were stopped and that subsequent evidence came from
fresh, ordered process generations on the same boot.

## Why the route was retired

The implementation coupled a Payment V1 change to a shared root Caddy service,
its other sites, its global options, and its ACME state. A cold transition also
created an outage and required rollback authority over unrelated service state.

Review then expanded the mechanism from a few runtime controls into a large
evidence system: multiple plan and receipt schemas, compiler-generated bundles,
process-generation lineage, exact file metadata, crash journals, atomic
rollback, namespace receipts, and a recursive HAProxy ELF loader and shared-
library closure. Successive reviews found new proof gaps and caused another
round of evidence binding instead of converging on a deployable product path.

The complexity was disproportionate to the risk and value of this topology.
It also made the implementation likely to drift rapidly from the main codebase.
The functional-beta path subsequently favored a smaller and more isolated
deployment boundary. The old implementation never became an approved or
merged production route.

## Principles worth carrying forward

### 1. Minimize the sensitive process boundary

Run Payment V1 ingress separately from unrelated sites and administrative
state. Give it a dedicated service identity, runtime directory, configuration,
and narrowly scoped sockets. Do not make a shared reverse proxy part of the
payment trust boundary merely because it already exists.

### 2. Make persistence an explicit choice

Default secret-bearing processes to no raw request, authorization, invoice, or
capability logging. If operational logs are required, define structured fields
and redaction rules rather than discarding all diagnostics. Disable core dumps
at the service boundary. A host-wide core-dump policy is a separate operational
decision and should not be silently introduced by a Payment V1 deployment.

Prefer purpose-built credential delivery or owner-readable files over ambient
environment variables. Define retention and deletion behavior for every
credential-bearing artifact.

### 3. Keep administration local and least-privileged

Do not expose a TCP admin listener unless a real remote-administration use case
requires it. Prefer a Unix socket owned by the service or a dedicated operator
group, with the smallest usable permission set. Root-only access may be used
when required, but it is not isolation from UID 0 or capabilities that bypass
DAC.

### 4. Prove only the generation facts the operation needs

For a cold activation, a future implementation will normally need to bind:

- the reviewed configuration and executable versions;
- the previous service identity or generation;
- a confirmed stopped boundary;
- the new service identity or generation;
- post-start configuration readback and health checks; and
- the exact rollback preimage or a simpler replaceable deployment artifact.

Do not automatically bind every inode, timestamp, loaded shared object, helper
binary, and transient runtime path. Add such evidence only when a concrete
attacker or failure mode can defeat the smaller proof.

### 5. Bound rollback and unknown outcomes

Before mutation, define which bytes or deployment artifact restore the prior
state, what health checks establish recovery, and when the result must be
classified as unknown rather than successful. Keep the transaction small
enough that an operator can understand and rehearse it. Avoid rollback schemes
that require control over unrelated sites or shared ACME state.

## Deliberately discarded design elements

The following were properties of the abandoned implementation, not contracts
to preserve:

- its numbered JSON plan and receipt schemas;
- large compiler-derived file generations;
- stopped/fresh evidence collectors for the shared Caddy topology;
- exact device, inode, mtime, ctime, and size binding for most runtime inputs;
- recursive ELF loader and shared-library closure for HAProxy;
- publisher-namespace receipts tied to a particular Caddy InvocationID;
- crash-journal and rename-exchange transaction machinery;
- exact systemd unit layouts, paths, UIDs, and socket modes; and
- the assumption that the existing root Caddy service must host Payment V1.

These ideas may be reconsidered if a future threat model independently requires
them, but old code or schema compatibility is not a reason to do so.

## Future re-entry criteria

Start a fresh design from the future main branch only when there is a concrete
Payment V1 deployment need. Before implementation, record:

1. the chosen edge topology and why a dedicated service is or is not possible;
2. the sensitive data that can cross the edge and its allowed persistence;
3. the minimum P0/P1 runtime properties and observable acceptance tests;
4. the outage and rollback budget;
5. the smallest process-generation evidence needed for that operation; and
6. which requirements are product requirements versus optional defence in
   depth.

A suitable first implementation should use a small service-level test for log,
core-dump, credential, and admin-socket behavior, plus one bounded cold-start
and rollback integration test. Expand the proof only in response to a specific
validated failure mode.

Remote-host mutation, production credentials, outage, deployment, or funds
remain separately authorized operations; this design note grants none of them.
