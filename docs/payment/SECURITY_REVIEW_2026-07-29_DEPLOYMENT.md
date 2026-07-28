# Payment V1 deployment security review — 2026-07-29

Status: pre-PR review of `codex/payment-deployment-prep`. This document is not
production approval. It records source-level findings, closure evidence and
the remaining live activation decisions. No remote host, public Nostr relay,
Lightning wallet, channel or real-value payment was touched during this review.

## Reviewed boundary

The focused review covered:

- the repository directory-only Nostr relay and its SQLite archive/head model;
- the Core Lightning Unix-RPC guard and the `pir-lightning-backend` transport;
- production `payment-issuer` routing and shared-issuer ledger accrual;
- Hetzner provider, issuer, CLN, edge and directory templates;
- independent rollback-authority templates and clients;
- source, rendered-bundle and Linux runtime evidence gates; and
- the proposed topology in which Hetzner hosts new public services while the
  existing VPSBG provider remains unchanged except for a later minimal
  Payment V1 admission integration.

No P0 source flaw was found in this focused pass. That does not convert ARC
into reviewed cryptography: ARC remains experimental and production-disabled.

## Findings closed in this preparation branch

### Production payout surface

The first production shared-issuer product is ledger accrual, not automated
value transfer. The public edge exposes only `POST /v1/redeems` and
`POST /v1/settlement/balance`. The three payout paths are rejected as unknown
before application decoding/authentication/store work and are absent from the
non-test route handlers. A private Rust unit fixture retains the
transport-neutral payout state-machine roundtrip; there is no CLI, feature or
environment switch that enables it in production.

The dormant payout target, fee and intent-TTL configuration has been removed
from the production CLI, unit and ledger-only constructor in this branch. The
issuer settlement signing key remains necessary because redeem and balance
responses are signed, and retained verifying keys remain necessary for exact
redeem/approval recovery across key rotation.

### Core Lightning socket isolation and deadman

`apps/cln-rpc-guard` reconstructs a strict allowlist of `getinfo`, private-label
`listinvoices` and bounded anonymous `invoice` requests and responses. It does
not pass CLN error payloads, invoices, payment hashes or preimages through
logs. Kernel peer credentials, parent/socket owner/mode/link checks and Linux
ACL rejection protect both Unix socket boundaries.

The production guard unit uses `Restart=no`. Its per-runtime invoice counter is
a custody deadman; an automatic crash loop would reset that bound. Guard exit
stops the bound issuer and a new generation requires an explicit operator
review/start ceremony.

### Source and rendered deployment closure

The source gate freezes all pre-existing active provider units and the measured
VPSBG run script, rejects activatable `.in` templates, validates closed command
lines and forbids fake Lightning, test trust roots, ARC, local rollback and
legacy credential gates in the first production profile.

The rendered gate requires an externally approved plan digest, one closed
profile, exact artifact dependencies and hash manifests, target-derived file
classes, bounded/sorted trees and no placeholder, extra file, symlink,
hardlink, reset, drop-in, environment-file, credential or cross-profile path.
Secret ownership is bound to the exact consuming service identity rather than
an arbitrary non-root UID/GID.

The Linux collector is deliberately root-only and live-only. It binds the
approved plan/manifest to machine ID, boot ID, uptime, a fresh internal
challenge, installed bytes, owner/mode/link state, ACLs, xattrs, file
capabilities, NSS, effective systemd state and `systemd-analyze verify`.
Long-running units additionally bind `MainPID`/invocation and the real
`/proc/<pid>` UID/GID/supplementary-group set across a no-restart collection
window. The reviewed preflight is the sole active-exited one-shot and instead
must prove a successful zero-status completion in the current boot. Offline
review is meaningful only with an independently transferred full evidence
digest.

Runtime-evidence v2 narrows NSS to a provable local-files profile: exactly
`passwd: files`, `group: files`, and inherited group-based `initgroups`. Stable
root-owned snapshots of `/etc/nsswitch.conf`, `/etc/passwd`, and `/etc/group`
must agree around NSS enumeration, with the complete identity-relevant `getent`
projection, and with a final confirmation after the remaining live checks;
`id -G` is checked for every account under a monotonic deadline. The live pass
leaves non-identity passwd/group fields hash-bound rather than semantically
compared. The stopped-edge pass additionally binds `/etc/shadow` and requires
each service account to be UID/GID-pinned, login-disabled and password-locked. Duplicate
UID/GID aliases and extra protected-group primary, explicit, or effective
members fail closed. Remote/cached or optionally enumerable NSS providers are
not accepted by this V1 claim.

Runtime-evidence v2 also closes credentials retained in the kernel after an NSS
edit. Two bounded full process/thread scans must produce the same protected
holder records and fail on any non-root CAP_SETUID/CAP_SETGID holder. Each
protected holder is bound by UID, all four GIDs, supplementary group
set, PID/TID, inode, start time and exact current systemd cgroup; all managed
MainPIDs and a post-scan unit generation confirmation are mandatory. HAProxy's
master and worker are allowed only because both remain in its reviewed unit
cgroup with the same reviewed credentials.

The scan does not prove ownership of an already-connected Unix socket FD after
`SCM_RIGHTS` transfer. Source-fair activation consequently requires a cold
connection reset. Stop Caddy and HAProxy, then run `collect-stopped-edge` while
all units are inactive/dead and every manifest socket is absent. It requires
locked/non-login service accounts plus an empty protected-credential closure;
only then start HAProxy before Caddy and collect new-generation live evidence,
without a warm reload. The collector also binds its namespace to a
visible systemd PID 1, while the operator must independently attest that this
is the target host's initial PID namespace rather than a private namespace.
This is a trusted-root/authentication-policy argument, not proof against a
compromised root or future local privilege escalation.

These gates are source and staging controls, not hardware attestation. Their
first real systemd/Linux execution on the target Hetzner staging host remains
mandatory.

The collector is also part of the trusted-root TCB. The evidence digest binds
the transferred result, not the honesty of target root or the script that
created it. The activation ceremony must independently verify and run the
collector bytes from the frozen commit; adding the collector script itself to
the approved rendered manifest remains a defense-in-depth follow-up.

## P1 production activation blockers

### Source-fair public admission

The source-fair follow-up supplies separate stock-Caddy and HAProxy layers for
the public Hetzner edge. Four protected PROXY-v2 Unix sockets feed independent,
short-lived provider, issuer, directory-reader and directory-publisher source
buckets. Every successful `track-sc` is checked explicitly, so full-table
allocation failure rejects rather than admitting an unaccounted request. The
business services receive only new source-free loopback connections.

The source templates now enforce the following design requirements:

1. an ephemeral source-fair connection/request boundary in front of the
   public provider, issuer and directory surfaces;
2. do not persist IP/request records or forward source identity into the PIR,
   payment, directory or rollback business processes;
3. the signed directory publisher has a separate private ingress, an exact
   WireGuard/private-route client-IP check in both Caddy and HAProxy, a WebPKI
   server certificate compatible with the current credential-free publisher,
   a dedicated activation sentinel, and reserved connection/operation/egress
   budget;
4. each rollback authority binds one private address and its systemd unit
   allows only the sole client's exact private IP; the current strict client
   uses WebPKI/SPKI plus signed requests rather than an unsupported one-sided
   mTLS configuration; and
5. both edge processes have null output, zero core limits and zero cgroup swap.

The public-reader and private-publisher sites currently share the pinned Caddy
process and its process-level resource budget; all lanes also share one HAProxy
process and cgroup despite separate frontend/table/connection/egress limits.
Public pre-routing TCP/TLS or HAProxy process-level pressure can still affect
publisher availability. This is an explicit residual V1 availability boundary,
not evidence of complete ingress isolation; a deployment needing a hard
publisher boundary must split both edge layers into separately evidenced units.
The two relay listeners also share one mutex-protected SQLite store. Reserved
admission slots prevent public work from consuming publisher lane capacity,
but an active public database operation can still delay a publisher write;
V1 does not claim storage-level availability isolation.

This remains a P1 **activation** blocker until the exact pinned Linux binaries
pass the no-skip behavior suite and target-host evidence proves the effective
units, source-fair sockets, negative starvation cases, zero current/max swap,
zero hard/soft core limits, and `kernel.core_pattern=|/usr/bin/false`, including
the handler's canonical root-owned bytes and metadata. The same ceremony must
perform the stopped-edge proof and cold Caddy/HAProxy connection reset from the
initial host PID namespace, followed by a fresh live proof; a warm-reload
snapshot is rejected. Linux pipe core handlers
may ignore `RLIMIT_CORE`; the unit directive alone is not proof.

The directory unit remains `UNRESOLVED` with `ExecStart=/usr/bin/false`, so the
repository cannot accidentally activate it before this boundary and the final
source/binary/config pins are reviewed.

### Independent rollback domains

“New services run on Hetzner” applies to the relay, payment/credential issuer,
CLN guard/edge and an optional new provider. It must not place Provider 0,
Provider 1 and issuer rollback authorities on that same host or administration
domain. Each stateful detailed store needs its own authority host, service
account, TLS/key material, administrator, log stream and backup/restore domain.
Co-location removes the independent anti-rollback and non-collusion failure
boundary even though authority values are opaque.

### VPSBG hostile-host state custody

The prepared VPSBG change is only a non-executable Free/PoW service-auth
argument fragment. Its ProviderStore and remote-authority client secrets would
still reside in host-visible `/home/pir/data`; ordinary file modes do not hide
them from the VPSBG operator. Production activation therefore requires either
attestation-gated key release/sealing or explicit user acceptance that the
VPSBG host joins this trust boundary. Until that decision, the live VPSBG
service and measured UKI remain unchanged.

### Real staging evidence and resource isolation

No source test proves the installed Linux filesystem, systemd serialization,
supplementary groups, mount namespace, cgroup limits, CLN/Bitcoin socket shape
or restart behavior. A private no-funds staging drill must run the live
collector and access probes. Memory/task/file-descriptor/OOM budgets also need
workload measurements before co-locating relay, issuer, CLN and provider on one
Hetzner host; arbitrary unmeasured limits are not safe defaults.

## P2 follow-up boundaries

- A dedicated source-fair edge implementation and its privacy review should be
  versioned separately from commercial pricing. Anonymous PoW for quote
  creation is an optional second layer, not a substitute for authority ACLs.
- The directory relay needs an activatable rendered profile only after the
  merged source commit, source archive, `Cargo.lock`, binary, config and
  publisher public-key digests are frozen. Two independently operated relay
  origins are still required; two DNS aliases on one Hetzner host are not
  independent.
- The payout protocol/store/worker code remains useful future work, but no real
  executor or automatic value-transfer product is enabled in V1.
- ARC needs a separate cryptographic and implementation review before any
  production policy may advertise it. Its integration tests do not satisfy
  that review.

## Invariants that remain mandatory

1. Each PIR provider independently publishes and enforces its own signed
   backend/workload scope, method, amount and limits. There is no pair ID or
   shared spent set between the two PIR servers.
2. DPF, Harmony hint, Harmony query, Onion and TEE-ORAM scopes are distinct.
   V1 uses `priority_class = 1` only and makes no paid-QoS claim.
3. The browser verifies provider identity/binary/attestation where available,
   upgrades the secure channel, verifies database proof/root and current signed
   policy before retiring or transmitting a capability.
4. Paid authorization commits before expensive backend work. Any ambiguity or
   dependency outage fails closed; strict mode never falls back to plaintext,
   unsigned policy, an unverified server or a free query.
5. Provider-local one-use credentials have independent server-specific spent
   state. Shared-issuer redemption credits only the authenticated provider and
   sends neither query bytes nor a cross-provider pair identifier to the
   issuer.
6. BOLT11 direct receipt is an explicitly linkable option. The privacy-preferred
   path purchases blinded BAT/Cashu/ARC capabilities; PIR providers never see
   the invoice or payment hash. The Web UI must display the method-specific
   leakage rather than flattening every payment into the same privacy claim.
7. No normal log contains invoice strings, payment hashes, preimages, Cashu or
   ARC proofs, capability identifiers, query addresses/results, request bodies
   or forwarded client IPs.
8. ARC remains visibly experimental, opt-in and production-disabled.
9. Production deployment, DNS/public relay publication, remote host mutation,
   Lightning wallet/channel creation and real-value operations require the
   user's separate approval.

## Required evidence before activation

- green Linux CI for all Payment V1 crates, process E2Es and warnings-denied
  builds, including release rejection of every test-only feature;
- reviewed merged commit and exact reproducible source/binary/config hashes;
- passing rendered-profile gate and target-host stopped-edge/fresh-live
  evidence pair, each bound to its independently transferred full digest;
- independent rollback-authority topology lint plus private-network negative
  tests;
- no-funds local regtest and persistent default-Signet Lightning drills,
  including backup/restore and lost-response reconciliation;
- source-fair starvation and cgroup pressure tests;
- cold Caddy/HAProxy stop, locked service-account/empty protected-credential
  closure before listener creation, HAProxy-before-Caddy re-creation and
  host-initial-PID-namespace evidence, with no warm reload or surviving
  connection graph;
- target-host no-core/no-swap evidence, including the host core pattern;
- private provider/issuer/directory canaries with strict client verification;
  and
- final manual browser acceptance by the user before public routing changes.
