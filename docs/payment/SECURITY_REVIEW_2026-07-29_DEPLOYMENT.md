# Payment V1 deployment security review — 2026-07-29

Status: source-review record for the deployment-preparation tree built on the
merged Payment V1 source. It is not production approval. It records source-level
findings, closure evidence and the remaining live activation decisions. No
remote host, public Nostr relay, persistent Lightning wallet/channel or
real-value payment was touched during this review.

## Deployment phases and independent approvals

The deployment state must always name exactly one of these phases:

| Phase | Meaning | What this review permits |
| --- | --- | --- |
| Source merge | reviewed source and exact-head CI only | merge and preserve exact source evidence; no service activation |
| Private no-funds | loopback/private, unrouted target-host drill with synthetic credentials and no valuable coins | offline-render any approved closed plan; remotely install/start only the edge profile after separate remote-host and bounded activation approvals, then stop it and revoke its role sentinel |
| Public Signet | persistent staging-only Bitcoin/CLN identities, test coins/channels and public staging ingress | only after separate approvals for remote mutation, persistent Signet custody and each public publication |
| Production mainnet | public production service with production keys and potentially real funds | blocked: the repository has no reviewed mainnet deployment preflight |

An approval for one row or action does not authorize another. In particular,
remote-host mutation, bounded private service activation, persistent Signet
wallet/channel creation, faucet/test-coin handling, external Cashu-mint access,
public Nostr publication, VPSBG UKI build/upload/reboot, install or use of
production keys, and any mainnet/real-value operation are separate approval
gates. DNS/public routing is also an activation action, not a source-merge
consequence.

The deployment input inventory is maintained in
[DEPLOYMENT_INPUT_MATRIX.md](DEPLOYMENT_INPUT_MATRIX.md). Start a render plan
from the fail-closed examples in
[render-plan-skeletons/](render-plan-skeletons/); neither document is an
activation instruction and neither may contain secrets.

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

The official Ubuntu 24.04 CLN v26.06.6 archive has a runtime dependency on
`libpq.so.5`, which is absent from the inspected Hetzner host. Installing a
package is not an acceptable workaround while dpkg is unhealthy. The closed
issuer profile instead requires one private `libpq.so.5` below an independent
digest-equals-file root, permits no second object in that loader directory, and binds
the CLN unit to that directory with its sole literal environment assignment.
Source, rendered and offline-runtime gates reject omission, path widening and
`LD_PRELOAD`; this keeps the upstream CLN archive identity distinct from the
Ubuntu library identity. Live evidence must still prove the target loader resolution.

Target-host probing also found two release-specific configuration hazards.
CLN v26.06.6 dereferences a null later-config entry in `clear-plugins`, and
`invoices-onchain-fallback=false` is invalid because that option is a
no-argument opt-in whose secure default is already false. Both spellings are
now forbidden. The exact official 27-plugin tree is retained at its compiled
path, 25 disallowed members are exact-disabled and installed mode `0444`, and
only `bcli`/`chanbackup` remain executable. This double condition is needed
because the documented `plugin start` RPC can bypass a disable list. The unit
also masks `/srv/lightning/plugins`, while layout verification rejects it and
the network-local lookalike; the prior verifier checked only the latter even
though CLN scans the former. Runtime acceptance must prove exactly two active,
non-dynamic plugins after a complete start.

A post-merge independent deployment-plan review found one P1 ambiguity and six
P2 documentation/gate drifts before activation. The current `provider-v1`
profile was incorrectly described as renderable after omitting Standard-Cashu
offers even though its closed unit requires Cashu custody/recovery/exposure
material; it remains blocked until a production mint is selected. The separate
closed `provider-no-standard-cashu-v1` profile now provides a no-Standard-Cashu path
with its own unit, service identity, runtime/configuration paths, activation
sentinel and render-plan skeleton. It retains BAT/shared-issuer material, omits
all Standard-Cashu recovery/custody/exposure inputs, and relies on unchanged
runtime Cashu-configuration checks to reject Standard Cashu in its current
policy. The checked-in unit and render plan are zero-retained and reject old-
policy flags or payloads. The still smaller closed
`provider-direct-v1` profile has its own unit/account/paths/sentinel and exact
nine-payload allowlist, including its owner-only remote rollback config,
client-signing seed and value-root key. It carries no BAT or shared-issuer
material either. The Cashu validator rejects Standard Cashu in the current
policy; current method coverage rejects BAT, shared-issuer, ARC and every other route outside the
built-in Free/direct material boundary. The unit independently omits Free-IP
adapter material. Private no-funds is
now edge-only for remote installation/live evidence, service start has its own
bounded approval, and every closed service unit requires its exact
profile-specific activation-sentinel set in addition to the global sentinel. The
edge sentinel is revoked after the private drill. Both independent relay views
are shown, source commit binding is correctly assigned to the external approval
tuple, and external mint access has one consistent approval boundary. The
render gate now rejects both invalid replacement-marker forms in payload paths
and repository example deployment IDs, with dedicated negative tests.

The Linux collector is deliberately root-only and live-only. It binds the
approved plan/manifest to machine ID, boot ID, uptime, a fresh internal
challenge, installed bytes, owner/mode/link state, ACLs, xattrs, file
capabilities, NSS, effective systemd state and `systemd-analyze verify`.
Long-running units additionally bind `MainPID`/invocation and the real
`/proc/<pid>` UID/GID/supplementary-group set across a no-restart collection
window. At the time of this review, the preflight was the sole active-exited
one-shot and instead had to prove a successful zero-status completion in the
current boot. That finding is superseded in the current worktree: the
preflight is now a live `Type=notify` supervisor with a short lease bound to
one exact CLN InvocationID, and runtime evidence requires its MainPID,
`NotifyAccess=main`, exact watchdog, typed dependency graph and typed stop
timeout, with a final snapshot that rejects stale manager state. These additions
were introduced before the current runtime-evidence v7; the discussion below
records the earlier reviewed baseline that v7 retains. Offline review is meaningful only with
an independently transferred full evidence digest.

Runtime-evidence v7 retains the files-authoritative NSS closed set: both
`passwd` and `group` must use exactly `files`, or both must use exactly
`files systemd`, with inherited group-based `initgroups`. Only the latter exact
Ubuntu fallback sequence is accepted; mixed sequences, reversed order, action
brackets and every other source fail closed. Stable root-owned snapshots of
`/etc/nsswitch.conf`, `/etc/passwd`, and `/etc/group` must agree around NSS
enumeration with the complete identity-relevant `getent` projection. `id -G` is
checked for every account under a monotonic deadline, and the full getent/id
projection is repeated after the remaining checks and must be identical. The live pass
leaves non-identity passwd/group fields hash-bound rather than semantically
compared. The stopped-edge pass additionally binds `/etc/shadow` and requires
each service account to be UID/GID-pinned, login-disabled and password-locked. Duplicate
UID/GID aliases and extra protected-group primary, explicit, or effective
members fail closed. SSSD, LDAP, winbind, NIS, `compat`, DNS and arbitrary
remote/cached or optionally enumerable NSS providers are not accepted by this
V1 claim; the sole reviewed systemd fallback passes only while its complete
enumeration projection remains exactly the local-files projection.

Runtime-evidence v7 also closes credentials and capabilities retained in the
kernel after an NSS edit. Two bounded full process/thread scans must produce
the same protected-holder records, record all four active sets plus `CapBnd`,
and fail on a reviewed dangerous active capability held by non-root. Each
protected holder is bound by UID, all four GIDs, supplementary group
set, PID/TID, inode, start time and exact current systemd cgroup; all managed
MainPIDs and a post-scan unit generation confirmation are mandatory. HAProxy's
master and worker are allowed only because both remain in its reviewed unit
cgroup with the same reviewed credentials and zero capabilities. Only the
Caddy units may retain `CAP_NET_BIND_SERVICE`; every managed `CapBnd` and active
set is checked against that exact systemd policy.

Runtime-evidence v7 also stops treating systemd's structured `Conditions`
property as printable `systemctl show` text. Ubuntu 24.04's systemd 255 renders
that property as `[unprintable]`. The collector therefore pins `/usr/bin/busctl`
in its trusted-command closure, parses the exact `a(sbbsi)` D-Bus shape, and
requires the complete condition set, negation bits, evaluated-success result
and current path truth to match the rendered unit before and after collection.
On 2026-07-29 this was exercised against a temporary Ubuntu 24.04 arm64
container running systemd `255.4-1ubuntu8.16`: an active transient unit with one
existing positive path and one absent negated path produced
`Conditions=[unprintable]` through `systemctl`, while `busctl --json=short`
returned the exact two `a(sbbsi)` tuples with `result = 1` and
`ConditionResult=yes`. The temporary container and derived test image were then
removed.

The same printable-text failure affects service credentials. On the target
systemd 255 host, `systemctl show --value` returned `[unprintable]` for
`LoadCredential`, `LoadCredentialEncrypted`, `SetCredential` and
`SetCredentialEncrypted`, while typed Service-interface reads returned empty
`a(ss)`, empty `a(ss)`, empty `a(say)` and empty `a(say)` values respectively.
The [upstream systemd v255 Service D-Bus vtable](https://github.com/systemd/systemd/blob/v255/src/core/dbus-execute.c#L1043-L1047)
also exposes `ImportCredential` as typed `as`; its target-host scalar rendering
was not part of that observation.
V7 therefore removes the four Load/Set fields from the scalar systemctl schema,
keeps all five credential fields in the combined typed Service-interface request list,
and accepts only the exact typed empty arrays. The typed snapshots are included
in live, stopped-edge and stopped-relay evidence and are repeated during final
sealing. `[unprintable]` is never special-cased as empty. This schema change
invalidates v6 live/runtime requests, v3 stopped-edge and v2 stopped-relay evidence.

Runtime evidence also treats private-file loader compatibility as a distinct
invariant from ordinary readability. Every secret's final parent is bound to
the consumer EUID and exact mode `0700`; all ancestors follow the loader's
Linux DAC ownership, write-bit and root-sticky rules. The live collector adds a
separate, stricter rejection of named/default POSIX ACLs, xattrs and
capabilities on descriptor-pinned directory components; the Rust loader itself
does not claim a Linux POSIX/NFSv4/FUSE ACL audit. Installed-file content and
extended metadata are collected against one opened inode, while parent paths
are walked component-by-component from pinned descriptors. Both closures are
revalidated after the long host probes. The final lightweight typed-credential,
structured-Conditions and unit-generation pass runs only after those expensive
secret commands finish, immediately before evidence construction. These checks
prevent a green evidence record for files that would fail closed on the next
service restart or for a pathname swapped between hashing and metadata
collection.

The scan does not prove ownership of an already-connected Unix socket FD after
`SCM_RIGHTS` transfer. Source-fair activation consequently requires a cold
connection reset. Stop Caddy and HAProxy, then run `collect-stopped-edge` while
all units are inactive/dead and every manifest socket is absent. It requires
locked/non-login service accounts plus an empty protected-credential closure;
only then, under the separate bounded service-activation approval, start
HAProxy before Caddy and collect new-generation live evidence, without a warm
reload. The collector also binds its namespace to a
visible systemd PID 1, while the operator must independently attest that this
is the target host's initial PID namespace rather than a private namespace.
This is a trusted-root/authentication-policy argument, not proof against a
compromised root or future local privilege escalation.

These gates are source and staging controls, not hardware attestation. Their
first real systemd/Linux execution on the target Hetzner staging host remains
mandatory.

The collector and its two local imports are also part of the trusted-root TCB.
The exact closure is the runtime collector, rendered-artifact gate and
deployment-template gate from one frozen commit. Release tests exact-match all
static local and `node:` specifiers and reject alternate dynamic, CommonJS and
worker loaders; all three scripts must be transferred and hash-verified
together. The evidence digest binds
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
The Caddy source gate now closes exact per-site binds and the global upstream
multiset, forbids imports/invokes/snippets/named routes, and accepts only PROXY
v2. Pinned adapted-JSON tests bind the two listener/host/socket graphs and 404
wrong-bind fallbacks. HAProxy owns the Unix sockets, so both pinned edge
processes remain in the source-assertion TCB: a compromised HAProxy could
self-connect and fabricate a preamble just as a compromised Caddy could send
one. PROXY v2 and the duplicate source check are not authentication against
either process.

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

A read-only 2026-07-30 target snapshot confirms why this remains a live gate:
the existing Caddy unit has `MemorySwapMax=infinity`, hard
`LimitCORE=infinity`, `StandardOutput=journal` and `StandardError=inherit`;
the host has an 8 GiB active swap device and an apport pipe core handler. The
current Caddy process had zero `VmSwap` at that instant, and its adapted JSON
had no configured global or access log sink, but journald already contained
structured request-error records with remote-address metadata. These are
pre-migration observations, not reusable activation evidence. Clearing the old
mixed-service journal is a separate destructive retention decision.

The directory selection is now resolved to exact source, binary, manifest,
config and publisher-public-key pins in an explicitly degraded centralized
mode. Resolution is not activation: the unit has no `[Install]` section and
requires three separately provisioned startup sentinels. Stopped and
fresh-live evidence remain mandatory before routing, and the publisher private
key remains outside the relay host and deployment bundle.

A follow-up non-activating `bhtm-caddy-admin-uds-v1` maintenance gate addresses
two parts of the existing-root-Caddy TCB: its admin endpoint and implicit
stdout/stderr-to-journald path. It derives only an
exact config/unit candidate from exact old bytes, rejects Caddy imports and
environment indirection, strips `--environ`, pins the independently inventoried
production Caddy v2.11.4 binary at exact `/usr/local/bin/caddy` plus the cold
executor, admin-UDS gate, Node v22.22.2, probe, `setpriv`, and systemd `255`, and
forces effective `LimitCORE=0`, `MemorySwapMax=0`, `StandardOutput=null` and
`StandardError=null`. The adapted
JSON privacy gate rejects explicit global, access and request-scoped log sinks.
The cold plan now binds strict-parsed canonical adapted JSON digests and sizes
for both the old disk preimage and candidate. Before stop, descriptor-pinned
Caddy adapts the exact old bytes and that digest must equal the live TCP-admin
`/config/` readback; the loaded unit must also have the exact fragment and old
Exec commands, `NeedDaemonReload=no`, no drop-ins, `EnvironmentFile`, or
`PassEnvironment`. A committed root `/config/` readback must reproduce the
candidate digest.
The read-only gate does not invoke Caddy. The separate source-hash-closed cold
executor runs the plan-pinned binary against the exact candidate rather than
accepting an unproven caller-supplied adapter artifact.
It requires a cold new systemd generation before a root-owned `0700` runtime
directory can exist. The isolation claim covers only capability-free
unprivileged non-root processes; UID 0 and `CAP_DAC_OVERRIDE` remain trusted.
Committed evidence requires root readback through a mode-`0200` UDS,
`CapEff=0`, cleared groups and `EACCES` for the complete approved non-root
service-UID inventory, absent IPv4 and IPv6 TCP 2019, and unchanged site health.
A mixed or unknown config/unit pair stays stopped; an ambiguous start is
outcome-unknown and prohibits automatic rollback. The executor requires Linux
root, exact systemd `255`, an exclusive lock, same-boot/PID/Invocation/preimage
pins and a pre-existing exact `kernel.core_pattern=|/usr/bin/false`; it never
changes that sysctl. It has not been installed or run and is not host or
deployment evidence.

Boot identity remains a hyphenated UUID, while a live systemd `InvocationID`
is independently bound as a nonzero 32-character lowercase hexadecimal value.
Using UUID syntax for both would make every real overlay activation fail
closed, so the real PID 1 lifecycle feeds its actual InvocationIDs through the
same production validator.

An undeployed `integrated-existing-bhtm-caddy-v1` alternative now models the
actual existing `bhtm-caddy.service` edge without pretending it is the isolated
stock-Caddy unit above. Its bundle closes the source-fair half and its separate
plan pins the exact mutable preimage/process generation. Installation uses a
content-addressed `renameat2(RENAME_EXCHANGE)` helper, keeps the swapped-out
preimage until a terminal receipt is durably and atomically published with
`RENAME_NOREPLACE`, and has deterministic digest-pair recovery. This closes
ordinary read-to-rename, partial-final-receipt and crash windows, but expands
the TCB to the existing root Caddy's remaining global options, ACME, zero-RTT,
plugin, site, UID-0 and other resource configuration. The overlay now requires a
canonical committed admin-UDS receipt whose hardened binary/config/unit and
InvocationID equal its target preimage; it cannot perform that cold migration
itself. Its executor now revalidates the full canonical hardening plan/receipt,
pins canonical adapted JSON, and repeats fresh descriptor-sealed UDS/root/UID/
TCP/boot/generation probes before exchange and after reload/health. Live root
readback must equal the hardening prerequisite's adapted digest before exchange
and the overlay candidate's adapted digest after reload/health. Recovery may
initially accept either reviewed digest across an ambiguous exchange/reload
boundary, but must re-probe the exact outcome-specific generation before
terminal state, cleanup or return. It also
binds current effective unit properties (including no drop-ins, the approved
`ExecStart` and UDS `ExecReload`, daemon-reload state, environment-name policy,
runtime-directory/identity/umask/core/swap/output settings) plus exact MainPID
argv/start ticks
and absence of process `CADDY_ADMIN`; environment values are not retained.
Stable runtime boundaries are repeated immediately before exchange and reload.
Recovery validates persisted monotonic windows unchanged, so corrupt evidence
cannot be made acceptable by in-memory timestamp normalization. The profile
cannot erase the remaining risk or substitute a warm reload receipt for cold
stopped-edge/fresh-live evidence.
It also retains the exact RFC1918/ULA private-publisher prerequisite; the
currently inspected Hetzner host has no such route, so the profile is not yet
deployable there.

The transaction's crash boundary additionally treats a helper error as an
unknown return value rather than evidence that no rename occurred. It
supplementally fsyncs and twice classifies the exact pair; any unclassified pair
forbids rollback, terminalization and cleanup. Phase journals and the lock owner
publish through owner-only pending files, file fsync, no-replace rename and
parent fsync. Recovery supplementally fsyncs and stably rereads the complete
visible phase journal before it can authorize a file-pair mutation. A visible
final receipt is not durable evidence until its parent
fsync and root:root/mode-0400/single-link metadata are reconfirmed. Prepared
state binds every mutable transaction directory identity across recovery.
Automatic rollback is forbidden until the installed pair's `exchanged`
predecessor is durable, and any failed abort-state publication preserves its
candidate for explicit recovery. A durable committed receipt remains attached
to later journal-finalization errors, while non-terminal cleanup errors remain
secondary evidence rather than masking the initiating failure. The
rename helper protocol v4 verifies the expected supervisor PID and
`/proc/<pid>/stat` start ticks before and after installing its parent-death
signal; subreaper adoption therefore cannot authorize a delayed mutation. The
tested delayed child cannot rename after its supervisor dies, while an already in-flight atomic
rename remains subject to the exact-pair classification above. Real Linux fault
tests cover open, partial/complete write,
file fsync, rename, parent fsync, applied-then-error, parent death and repeated
recovery boundaries. The root-only publication and lock suites run under the
CI root invocation rather than being accepted as skipped tests. These are
source/test properties, not host activation
evidence.

After source merge, an independent read-only audit of merge
`49dc56bb735a6df6a1665c91f0636188d65a66b5` and exact Payment V1 source parent
`4beeea7543c5e8fdb8e571210ce0d4ad1a4affd4` found no P0/P1/P2 in the repository
directory relay's lane separation, publisher/kind/namespace validation,
replacement/idempotency, SQLite durability/snapshot, resource bounds,
correlation logging or shutdown paths. The source gate/readback suite passed
80/80; the relay library/binary suite passed 24/24 in Linux Docker; exact-head
CI covered the real two-relay process topology. This is source-review evidence,
not a resolved binary/config/key selection or target-host activation claim.

This is not a documentation-only placeholder: exact source/archive/lockfile/
binary/config/publisher-public-key digests are frozen and reproducibly checked,
but public directory deployment and catalog publication remain blocked on
target-host evidence and separate activation/routing/publication approvals. A
production Nostr private key is never a relay payload and its existence does
not authorize using or publishing it.

### Independent rollback domains

“New services run on Hetzner” applies to the relay, payment/credential issuer,
CLN guard/edge and an optional new provider. It must not place Provider 0,
Provider 1 and issuer rollback authorities on that same host or administration
domain. Each stateful detailed store needs its own authority host, service
account, TLS/key material, administrator, log stream and backup/restore domain.
Co-location removes the independent anti-rollback and non-collusion failure
boundary even though authority values are opaque.

### VPSBG hostile-host state custody (resolved for the storeless Free-PoW scope)

This finding applied to the earlier ProviderStore-based VPSBG proposal. The
current fragment selects an exact-digest-pinned, storeless runtime that accepts
only provider-local `FreeV1` proof-of-work offers and opens no ProviderStore,
WAL/SHM or rollback-authority client. There is consequently no payment-store or
authority secret for attestation-gated release in this narrow profile. The
provider ID, policy verification key, exact domain-separated policy digest and
launch arguments must instead be measured in the UKI; changing any signed
policy byte requires a newly measured UKI and client pins. Adding a retained
policy, durable quota, payment, Cashu, BAT, ARC or shared-issuer method revives
the original P1 custody finding and requires the ordinary independent store
and rollback-authority design. The live VPSBG service and measured UKI remain
unchanged until the separately approved UKI ceremony.

### Real staging evidence and resource isolation

No source test proves the installed Linux filesystem, systemd serialization,
supplementary groups, mount namespace, cgroup limits, CLN/Bitcoin socket shape
or restart behavior. The private no-funds staging drill must run the edge
stopped/fresh collector and access probes. Provider/authority live evidence
belongs to their later activation gates, and issuer live evidence starts only
after the persistent-Signet-custody approval because CLN startup creates
persistent identity/wallet state. Memory/task/file-descriptor/OOM budgets also
need workload measurements before co-locating relay, issuer, CLN and provider
on one Hetzner host; arbitrary unmeasured limits are not safe defaults.

## P2 follow-up boundaries

- A dedicated source-fair edge implementation and its privacy review should be
  versioned separately from commercial pricing. Anonymous PoW for quote
  creation is an optional second layer, not a substitute for authority ACLs.
- The resolved directory relay profile still needs target-host stopped/live
  evidence, activation and routing review. Its selected centralized mode is
  explicitly degraded; two DNS aliases on one Hetzner host must never be
  presented as independent relay origins.
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
9. Remote host mutation, bounded service activation, persistent Signet
   identity/wallet/channel creation, Signet faucet/test-coin use, external
   Cashu-mint access, DNS/public Nostr publication, VPSBG UKI
   build/upload/reboot, production-key installation/use, and mainnet/real-value
   operations each require a separate approval. No approval implies another.
10. A Standard Cashu offer, or any other Cashu offer that depends on an
    external mint, must be omitted from the current policy and, in any future
    profile that permits retention, every retained signed-policy byte sequence
    until an exact production mint, WebPKI/pin
    set, unit, custody limits and recovery/outage procedure have been selected
    and approved. Local CDK fake-
    wallet evidence is not such a mint. The closed `provider-v1` profile always
    carries those inputs and remains blocked when the offers are omitted. Use
    only a separate no-Standard-Cashu profile in that case. The
    `provider-no-standard-cashu-v1` current policy may use BAT/shared-issuer
    routes; `provider-direct-v1` may not. All three checked-in provider plans
    are zero-retained: their gates reject `--service-retained-policy` and any
    retained-policy payload. Startup fails closed on any
    unavailable applicable route. The three provider units
    also require the other two provider sentinels to be absent at start. A
    profile switch must stop and deauthorize the old unit, prove it inactive
    with no `8191` listener, then authorize and start only the new unit; systemd
    conditions are not continuous revocation. For the same logical provider,
    this first requires new issuance/admission to stop, every old capability
    and grace horizon to expire, Standard Cashu custody to be fully retired or
    reconciled, and all shared-issuer redeems to have known outcomes. The static
    render gate cannot prove that drain; separately reviewed transition
    evidence is mandatory. Only then may a stopped migration preserve the
    stable server ID, operator key and derived provider ID, policy-signing key,
    provider identity certificate/key, ProviderStore/store-instance identity,
    spent and replay history, remote authority instance/key, namespace, client-
    verifying-key identity, client-signing seed, value-root key and floor. The TOML may be re-
    rendered only with the new canonical secret paths. Rotating an authority-
    identity field requires a separately reviewed migration ceremony because
    V1 has no online rebind/reset; an empty
    replacement store is forbidden. Without that continuity, the new
    profile must use a new provider/server identity and distinct directory
    entry.

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
- separately approved private provider/issuer canaries with strict client
  verification, and a directory canary only after relay selection is resolved;
  and
- final manual browser acceptance by the user before public routing changes.

The repository's Lightning deployment preflight is default-Signet-specific.
It is not a mainnet preflight, and a user approval cannot convert it into one.
Production mainnet remains blocked until a versioned mainnet preflight,
configuration profile, negative tests and security review are implemented.

### Post-merge evidence register

Do not backfill this dated source review with guessed CI or deployment values.
Create an external, non-secret activation record and fill each row from
independently verified artifacts. `UNSET` means the phase must not advance.

| Evidence field | Required value | Current source-review value |
| --- | --- | --- |
| merged source commit | exact 40-hex commit reachable from the approved base | `49dc56bb735a6df6a1665c91f0636188d65a66b5` (source parent `4beeea7543c5e8fdb8e571210ce0d4ad1a4affd4`) |
| exact-head CI | workflow URLs, conclusion and tested head | `UNSET_FOR_FINAL_DEPLOYMENT_CLOSEOUT_HEAD` |
| rendered plan | approved plan digest and selected skeleton/profile | `UNSET_BEFORE_RENDER` |
| installed target evidence | stopped-edge and fresh-live full-file digests | `UNSET_BEFORE_REMOTE_DRILL` |
| relay selection | resolved source/archive/lockfile/binary/config/key pins | `RESOLVED`: exact pins are committed in `deploy/payment-v1/relay-selection.toml.example`; centralized-single-relay is an explicitly accepted degraded-assurance mode, not an independent-relay claim |
| Lightning network gate | approved default-Signet preflight record, or a future reviewed mainnet profile | `UNSET`; mainnet profile not implemented |
| Cashu mint | approved production endpoint, pins, unit and custody/recovery record, or explicit offer omission bound to `provider-no-standard-cashu-v1` or `provider-direct-v1` | `UNSET`; omit mint-dependent offers, keep `provider-v1` blocked, and use only an exact separately approved no-Standard-Cashu profile |
