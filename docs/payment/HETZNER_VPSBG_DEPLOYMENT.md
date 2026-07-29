# Hetzner and VPSBG Payment V1 deployment preparation

Status: non-activating deployment contract. This document does not authorize a
remote host change, public Nostr publication, a VPSBG UKI upload/reboot, or use
of real Lightning funds.

## Phase boundary and deployment inputs

This contract separates four phases: **source merge**, **private no-funds**,
**public Signet**, and **production mainnet**. Source merge changes no host.
Private no-funds may install an unrouted candidate and collect live evidence,
but only after a remote-host approval and with no persistent Lightning state,
public catalog or valuable coins. Public Signet adds persistent staging-only
wallets/channels, test coins and public staging surfaces under their own
approvals. Production mainnet is not currently renderable: the implemented
deployment preflight is default-Signet-specific and no reviewed mainnet
preflight exists.

Use [DEPLOYMENT_INPUT_MATRIX.md](DEPLOYMENT_INPUT_MATRIX.md) as the non-secret
input inventory and begin each proposed closed render plan from
[render-plan-skeletons/](render-plan-skeletons/). A skeleton remains inert
until every required value and external approval record is present; do not put
private keys, macaroon/cookie material, invoices or bearer proofs in either
artifact.

These approvals are independent: remote Hetzner mutation; persistent Signet
identity/wallet/channel creation; Signet faucet/test-coin handling; DNS or
public Nostr publication; VPSBG UKI build/upload/reboot; production-key
installation/use; and mainnet/real-value activity. Approval of one never
implies another.

## Topology

The first deployment shape keeps provider selection independent. A client may
select one Hetzner provider and later select the VPSBG provider; neither server
needs to know the other's identity or payment method.

```text
                         separately administered hosts
                       +-------------------------------+
                       | provider-0 rollback authority |
                       | provider-1 rollback authority |
                       | issuer rollback authority     |
                       +-------------------------------+
                              ^ pinned HTTPS/CAS
                              |
  Hetzner                     |                    VPSBG Tier 3
  +----------------------+    |                    +----------------------+
  | Payment V1 provider  |----+                    | existing PIR process |
  | payment-issuer + CLN |----+                    | + enforced V1        |
  | directory-only relay|                         | + Free/PoW only      |
  | same-host TLS edges |                         | no issuer/relay/mint |
  +----------------------+                         +----------------------+
```

The rollback authorities are not extra processes on the Hetzner provider or
VPSBG detailed-store hosts. Provider 0, Provider 1, and the issuer require
separate authority hosts, service accounts, TLS keys, Ed25519 keys, namespaces,
administrators, logs, and backup/restore domains. Co-location is permitted only
for an explicitly non-production exercise.

Each `edge-rollback-authority-v1` instance is also network-specific. Its Caddy
listener binds one reviewed RFC1918/ULA address, systemd denies every address
except loopback and the sole client's exact private IP, and the rendered
profile closes over a static TLS certificate and owner-only key. The existing
rollback client verifies WebPKI plus the configured leaf SPKI pin and signs the
application request; it currently has no TLS client-certificate support. Do
not turn on server-side mTLS alone. V1 therefore requires a narrow WireGuard or
equivalent routed private link, the exact client-IP filter, and the
`ROLLBACK-AUTHORITY-PRIVATE-INGRESS-APPROVED` sentinel. A later mTLS design must
add client certificate/key custody and real-handshake tests atomically.

## Frozen active-service boundary

This preparation does not modify or replace:

- `deploy/systemd/pir-primary.service`;
- `deploy/systemd/pir-secondary.service`;
- `deploy/systemd/pir-vpsbg.service`;
- `deploy/systemd/dev-issuer.service`;
- `deploy/systemd/cloudflared.service`; or
- `scripts/dracut/97bpir-tier3-init/unified-server-run.sh`.

The deployment-template gate pins the SHA-256 of each file. It also verifies
that none of those active definitions contains Payment V1 enforcement flags.
This makes the preparation PR unable to activate charging by changing an old
unit in place.

All files below `deploy/payment-v1/` are inputs. Systemd templates use the
`.service.in` suffix, omit `[Install]`, and require an activation sentinel. The
VPSBG `.args.in` is a non-executable argument fragment with no shebang or exec;
it cannot start a process by itself.

## Hetzner provider

`deploy/payment-v1/systemd/hetzner-provider.service.in` describes a new
loopback-bound process rather than a drop-in for either active provider. It
requires:

- strict `--require-service-auth-v1` enforcement;
- one frozen signed current policy and provider/policy-key pins;
- an existing provider spend store;
- a separately hosted remote rollback authority;
- bounded connections, authorization concurrency, WebSocket handshake, idle,
  and absolute pre-authorization timeouts; and
- identity, binary and database material that remains subject to the existing
  strict client verification chain.

The template contains no ARC, local rollback, fake/test trust, legacy gate, or
source-IP Free quota option. It binds to loopback because the current public
path uses a proxy; `--service-trust-direct-peer-ip` would otherwise treat the
proxy as the user and is forbidden.

The first Hetzner production profile loads all reviewed non-ARC method material:

- a provider-local Cashu BAT key. Issuance and provider verification use the
  same DHKE scalar and exact policy binding: generate it once, verify the
  derived public key against the policy, then copy it through an approved
  secret-transfer ceremony to the issuer and this provider. Compromise of
  either copy can forge BATs for that provider. Operators unwilling to share
  this private scalar must omit the provider-local BAT offer and use the
  shared-issuer online redemption method instead;
- separate Standard Cashu recovery and custody AEAD epoch keyrings, with byte
  reuse forbidden, plus an explicit finite value/note exposure limit for each
  mint/unit;
- one operator-signed shared clearing authorization and matching issuer
  approval, with pinned operator and issuer-settlement public keys;
- a provider clearing signing key, separately generated shared-redeem
  idempotency HMAC key, and non-zero minimum authorization epoch.

Direct BOLT11 receipts require no provider secret beyond their signed policy
binding. Every method advertised by the current or retained signed policies
must have its complete runtime material. `validate_policy_method_coverage_v1`
rejects startup if any method is missing; operators must remove an offer from
the policy rather than weakening this check. Extra retained keys are permitted
only for a documented rotation/grace window. ARC remains unavailable.

No production Standard Cashu mint has been selected merely because local CDK
interop passes. Unless the render plan names an approved exact production mint
origin, WebPKI/leaf pins, unit, exposure caps, recovery keyrings and outage/
retirement procedure, omit every mint-dependent Cashu offer from both current
and retained signed policies. Do not render fake-wallet or loopback test mint
material as a substitute.

The signed policy is the commercial and resource contract. Every backend and
operation needs its own scope. In particular, Harmony hint generation and
Harmony query execution are distinct scopes with separately selected limits,
payment method and price. V1 has no class-aware work scheduler, so every first-
release offer must use `priority_class = 1` and neither directory nor UI may
promise paid QoS. A general "one query" price must not be silently reused
across DPF-PIR, HarmonyPIR hint, HarmonyPIR query, OnionPIR, or Direct ORAM
workloads.

Do not start the new Hetzner hint pool alongside another live pool without the
existing capacity/stagger review. A public cutover follows a private canary and
must not create concurrent cold-pool generation that starves query work.

## Hetzner issuer

`deploy/payment-v1/systemd/hetzner-payment-issuer.service.in` runs only
`payment-issuer serve-cln`. The application listener is `127.0.0.1:5610`; a
reviewed same-host WebPKI TLS edge is the only public origin. The Core Lightning
RPC Unix socket has exact expected UID/GID and a bounded call timeout.

This is the only renderable issuer unit. It has `Requires`, `After`, and
`BindsTo` dependencies on the exact CLN service, method-allowlist guard, and
successful live preflight, plus separate global, Lightning-custody, and
backup/restore sentinels. There is no generic alternate unit that can use the
global activation sentinel while bypassing either boundary.

The issuer detailed store uses its own remote rollback authority. Quote,
credential-derivation, direct-receipt, Cashu BAT, issuer-settlement, clearing,
and redeem-derivation keys remain role-separated. Clearing is integrated into
the issuer process; there is no separate clearing daemon.

The production unit contains no `serve-fake`, fake signing seed, local rollback
acknowledgement, ARC key, experimental acknowledgement, or test-only WebPKI
root. The public edge forwards only `/v1/redeems` and the authenticated
`/v1/settlement/balance` lookup. Payout-intent, payout and payout-status are not
V1 production routes. The production CLI and unit accept no payout target, fee
or intent TTL; the shared service is constructed explicitly in ledger-only mode
and fails closed at the payout method boundary as well. The store schema's
required non-zero payout-target field receives one fixed domain-separated
disabled sentinel that is neither operator nor request input and is never a
value-transfer destination.

Registration remains append-only and fail closed. A pre-production store that
already registered the same provider epoch with a different payout target will
not be silently rewritten and will fail issuer startup. Do not edit that SQLite
row in place: either initialize the first production ledger-only store with the
reviewed sentinel-bearing build, or design and review a separate authenticated
offline migration before preserving such a prototype store.

The rendered issuer unit also requires
`provider-request-verifying.key`, the raw public half of a provider-owned
`provider-request-ed25519` key. It is deliberately separate from the online
clearing, provider-operator and issuer-settlement keys. For each provider,
install authorization, approval and request public key in the same CLI order;
any count mismatch, invalid key or key reuse aborts startup. The provider keeps
the request secret offline while V1 remains ledger-only. Authorization and
approval bytes must come from the independent `bpir-admin payment-artifact
clearing-authorization` and `clearing-approval` ceremonies; rotation advances
the authorization epoch and retains only reviewed historical issuer settlement
public keys.

`BITCOINPIR_WEB_ORIGIN` is one complete canonical HTTPS origin. Every
`*_PUBKEY_HEX` placeholder is public verification material, never a private
seed. The renderer must type- and length-check these values and reject any
unresolved placeholder before producing a unit. The CLN RPC socket is
network-specific at `/srv/lightning/<network>/lightning-rpc`; the rendered
issuer unit, CLN configuration and read-only Lightning preflight must agree on
that exact path, UID, GID, filesystem ownership and mode.

The daemon-owned/guard-group parent (`0710`) and native CLN socket (`0660`) are
not accessible to the long-running issuer. A separately pinned guard is the
only long-running non-CLN principal in that group; it parses and reconstructs
bounded JSON-RPC, permits exactly `getinfo`, private-label `listinvoices`, and
bounded anonymous `invoice`, and exposes a guard-UID/issuer-GID `0660` socket
below a distinct `0710` directory. The issuer mount namespace also marks
`/srv/lightning` and `/srv/bitcoin` inaccessible.

The guard unit uses `Restart=no`. Its finite per-runtime invoice counter is a
custody deadman, so an automatic crash loop must not reset it. Guard exit stops
the issuer through the unit dependency; starting a new generation requires an
operator to inspect the failure, account for the prior generation and perform
an explicit start.

The live preflight uses a third, dedicated UID—not the issuer UID—with temporary
membership in the native CLN and Bitcoin-cookie groups. It validates the exact
cross-UID `0710`/`0660` CLN shape and bitcoind-UID/cookie-GID `0710`/`0640`
cookie shape. The supplied CLN configuration and prerequisite record remain
default-Signet-only with `real_funds_authorized = false`; Linux artifact/runtime
evidence, restore drills, remote installation and any real funds remain
separate activation gates.

## Hetzner directory relay

The directory publisher key is a dedicated offline BIP340 key and is never
installed on the relay. The relay sees only public signed directory events; it
must accept writes only from the pinned publisher and only kind `30078`.
The production publisher URL remains a canonical credential-free `wss://`
hostname because `bpir-admin directory publish` uses WebPKI server
authentication and no client certificate. Split DNS or an explicit private
route resolves that hostname to the relay's private bind; Caddy and HAProxy
both require the separately approved exact publisher-client address before the
relay performs the signed-event check.

`deploy/payment-v1/relay-selection.toml.example` deliberately starts with
`status = "UNRESOLVED"`. While unresolved, the relay service has
`ExecStart=/usr/bin/false` and requires a separate
`RELAY-SELECTION-RESOLVED` sentinel. The selection may become resolved only in a
reviewed PR that freezes the repository's directory-only relay interface and
records:

- a full 40-hex source commit;
- source archive and Cargo.lock SHA-256;
- exact binary SHA-256 and `--version` output;
- exact bounded config SHA-256; and
- the pinned directory publisher public key.

Mutable branches, mutable container tags, `nostr-rs-relay` 0.9.0 at
`ff65ec2acd781150a585a78e1c60b0cdb104698e`, and its 0.10.0/master at
`b5c1f642e4f4c3b9c54f5d18d66f4c53642076b4` fail the repository gate. No
generic third-party relay template is supplied.

A resolved relay must bind distinct public-reader and private-publisher
application listeners to loopback, use the same-host WSS edge, disable
access/event/body/IP logging, disable NIP-42 for the current publisher, retain
the NIP-01 addressable-event replacement ordering, and enforce the
BitcoinPIR bounds: 262,176-byte outer EVENT message, 192 KiB content, kind
30078, and a deployment-config size no greater than 16 KiB. At least two relay
hostnames are still required for directory use; two aliases on one Hetzner host
do not provide operator or failure independence.

The reviewed process interface is intentionally narrow: exactly
`bitcoinpir-directory-relay --config /absolute/owner-only.toml`, with no CLI
overrides. The TOML must declare `profile = "bitcoinpir-directory-relay-v1"` and
contain exactly `public_listen`, `publisher_listen`, `database`,
`directory_pubkey_hex`, the four global connection/operation/rate/egress caps,
matching `max_public_*` and `max_publisher_*` reservations whose exact sums
equal each global cap, `max_egress_bytes_per_connection`, `max_archive_events`, `max_archive_bytes`,
`handshake_timeout_seconds`, `idle_timeout_seconds`,
`connection_timeout_seconds`, `operation_timeout_seconds`, and
`egress_timeout_seconds`; unknown fields and missing fields fail closed.
`deploy/payment-v1/directory-relay.toml.example` fixes the database below the
unit's only writable StateDirectory at
`/var/lib/bitcoinpir-directory-relay/relay.sqlite3`. The config must be mode
0400 or 0600 under a private parent directory.

The relay has separate public-read and private-publisher accept loops and
acquires a lane reservation before a shared global reservation. The public
listener rejects EVENT writes; the publisher listener rejects REQ reads. This
prevents public load from consuming the publisher's connection, operation,
rate, or egress allocation. The relay reserves the exact complete snapshot response against a per-
connection cumulative byte budget before sending its first EVENT, and applies
a separate process-wide egress byte rate. The example intentionally does not
allow the event-count and maximum-event-size dimensions to be saturated at the
same time. Public ID readback is capped at 64 unique IDs, charged globally at
one work unit per eight IDs, executed as one bounded SQL query, and also charged
against a fixed 256-unit cumulative connection work budget. This prevents a
single valid REQ from turning one operation-rate token into thousands of
serialized SQLite point lookups. `max_archive_bytes` counts immutable canonical event JSON BLOB bytes;
it is not a SQLite file, WAL, index, or filesystem hard limit. Provision a
separate filesystem quota/free-space alarm, choose a finite archive lifetime
capacity, and rehearse consistent database-plus-WAL backup/restore. Immutable
events are never automatically deleted because frozen ID readback and duplicate
idempotency depend on them.

An independent read-only relay audit of merge `49dc56bb735a6df6a1665c91f0636188d65a66b5`
and its exact Payment V1 source parent
`4beeea7543c5e8fdb8e571210ce0d4ad1a4affd4` found no P0/P1/P2 source issue.
The source gate/readback suite passed 80/80, the relay library/binary suite
passed 24/24 in Linux Docker, and the exact-head CI exercised the real
two-relay process topology. This closes only the implementation-audit item.
Relay selection remains unresolved until the exact source archive, Cargo.lock,
Linux binary, bounded config and publisher public-key pins are recorded, two
genuinely independent relay failure domains are approved, and target-host
runtime/fault evidence passes.

Accordingly, no public relay service or catalog publication belongs in a
rendered plan today. The locally held publisher key, if any, is not relay
selection evidence and its installation/use requires its own approval.

## VPSBG minimal change

The current Tier 3 process is runit inside a measured UKI and has no systemd or
SSH administration path.
`deploy/payment-v1/vpsbg/vpsbg-free-pow-service-auth.args.in` is therefore only
a reviewable set of arguments to merge into the existing measured script's
final `unified_server` exec during a later UKI ceremony. It is not a replacement
run script: it contains no shebang, exec, ORAM path, ORAM build/verification,
identity, attestation, database startup, port/bind, cloudflared or service-tree
logic. The existing query, ORAM, attestation, identity, database and cloudflared
behavior remains authoritative.

The frozen VPSBG policy must contain only current `FreeV1` ProofOfWork offers.
It may expose multiple backend-specific scopes, but every offer has
`free_mode = proof-of-work`, a non-zero bounded difficulty, no issuer/key
binding, and a zero price. Before baking, inspect the canonical signed policy
and verify its SHA-256 against the UKI manifest. The CLI alone cannot prove the
contents of a signed policy.

The VPSBG template deliberately has no:

- issuer, Lightning, Cashu mint, BAT, ARC or directory relay;
- provider-local or shared issuer credential key;
- Free IP HMAC key or direct-peer-IP trust;
- local rollback database or local-development acknowledgement; or
- online-authority method material; a Free-PoW-only policy creates no online
  V2Full authorization route and needs no V2Full override flag.

### P1 activation blocker: VPSBG hostile-host secrecy

The existing Tier 3 `/home/pir/data` is supplied by a host-visible rootfs. The
repository does not yet implement SEV-SNP sealing, a vTPM, or
attestation-gated key release for this data. An effective-user-owned mode-0700
subtree and single-link mode-0600 files protect only against ordinary accounts
inside the guest. They do not protect against the VPSBG operator: the VPSBG
host can read or copy the ProviderStore and the remote rollback client's
Ed25519 seed/value-root key material.

This is an activation blocker even for the Free-PoW canary while it requires a
ProviderStore. Before production activation, the user must explicitly approve
one of two designs:

1. implement and review attestation-gated key release or equivalent sealing; or
2. expand the trust boundary and accept that the VPSBG host can steal these
   availability/rollback credentials.

The second choice also abandons the remote authority's anti-rollback guarantee
*against the VPSBG host itself*: a host that steals the client signing and
value-root keys can create correctly signed Read/CAS traffic that the
independent authority cannot distinguish from the guest. The authority still
separates other failure and administration domains, but it no longer protects
the detailed store from a malicious VPSBG operator.

Owner-only permissions remain required defense in depth, but must never be
presented as hostile-host secrecy. The provider rollback authority itself
remains on an independently administered remote host.

Any binary, policy, run-script or initramfs change requires a new UKI, preserved
previous known-good UKI, portal upload, reboot, fresh SEV-SNP measurement,
binary hash, attestation verification and client pin update. Those are remote
activation actions and require separate approval.

## Rendering and preflight

### P1 activation blocker: live source-fair evidence

The source tree now supplies a pinned-stock-Caddy front and pinned-HAProxy-2.8
source-fair layer. Caddy sends PROXY v2 only over four protected Unix sockets;
HAProxy keeps independent two-minute memory-only provider, issuer,
quote-source/global, public-directory, and private-publisher buckets, then
opens a source-free loopback connection to each business service. There is no
header fallback, log, peers section, stats socket, StateDirectory, server-state
file, or source-state recovery. The publisher uses a different private bind,
an exact WireGuard/private-route client-IP check in both Caddy and HAProxy, a
WebPKI server certificate, a dedicated ingress-approval sentinel, a separate
application listener and stick table, and a reserved application budget.
Rollback authorities remain outside the public HAProxy behind their one
client's private boundary.
The public and publisher sites nevertheless share one pinned Caddy process and
its process-level CPU/memory/task/file budget, while all lanes share one
HAProxy process/cgroup despite distinct frontend budgets. Public pre-routing
TCP/TLS or HAProxy process-level pressure can therefore reduce publisher
availability. Treat that as an explicit V1 residual risk, or split both
publisher edge layers into separately rendered and evidenced units when a hard
availability boundary is required.
The two relay lanes also share one process and mutex-protected SQLite store;
their reservations isolate admission capacity but not the duration of an
already-running database operation.
Both edge units require effective `StandardOutput=null` and
`StandardError=null`, closing the remaining journald path for request errors
that might contain a live peer address. They also set `LimitCORE=0` and
`MemorySwapMax=0`; rendered/live checks bind hard and soft core limits, current
and maximum cgroup swap, and reject drift. Linux can ignore `RLIMIT_CORE` when
`kernel.core_pattern` names a pipe handler, so edge live evidence additionally
requires the exact host policy `kernel.core_pattern=|/usr/bin/false` and binds
that handler's canonical root-owned bytes and metadata into the trusted-command
evidence. A default systemd-coredump or apport pipe is not accepted as
non-persistent evidence.

The code does not by itself clear this P1 blocker. Before public activation,
the exact rendered Linux host must prove both units active, the volatile
directory `0750`, all four sockets `0660` with the source-fair UID/GID, exact
local-files NSS/supplementary-group membership, effective memory/task/file limits, and no
drop-ins. It must also prove zero current/max swap, zero hard/soft core limits,
and the safe host core pattern. The exact pinned Caddy and HAProxy binaries must pass the real
fairness/leak suite without skipped tests. HAProxy sees traffic only after
Caddy accepts TCP/TLS and parses HTTP, so separate Caddy-front slowloris,
header, handshake, firewall, and volumetric evidence is also mandatory. These
are availability/privacy controls, not commercial pricing policy.

The V1 NSS statement is deliberately narrow. The activation host must use
`passwd: files` and `group: files` with no separate `initgroups:` entry. The
collector binds stable snapshots of `/etc/nsswitch.conf`, `/etc/passwd`, and
`/etc/group` around enumeration and confirms them again after the remaining
live checks, requires ordinary `getent` identity-relevant account/group
projections to agree, and checks every enumerated account with `id -G`.
The live pass hash-binds but does not semantically compare password, GECOS,
home, shell and group-password fields. The mandatory stopped-edge pass also
reads stable `/etc/passwd` and `/etc/shadow` snapshots and requires every
manifest-bound service account to have the pinned UID/GID, a
`/usr/sbin/nologin` or `/bin/false` shell, and a locked password. It rejects
UID/GID aliases and any
extra primary, explicit, or effective member of a protected group. A host using
SSSD, LDAP, winbind, NIS or systemd UserDB cannot pass V1 merely because its
currently visible `getent` output looks complete; such a backend needs an
authoritative backend-specific generation/completeness proof.

Because removing a user from NSS does not revoke credentials already held by a
Linux thread, the v3 collector also executes two bounded full `/proc` PID/TID
passes and records `CapInh`, `CapPrm`, `CapEff`, `CapAmb`, and `CapBnd`. It
rejects every non-root thread with a reviewed dangerous active capability; for
managed processes, every mask must be a subset of the rendered systemd policy,
so only Caddy may use `CAP_NET_BIND_SERVICE` and HAProxy must remain at zero.
Any protected UID/GID holder
must have the exact service credentials in
the exact current systemd unit cgroup; both holder snapshots must agree, every
long-running MainPID must be present, and MainPID/InvocationID/ControlGroup are
confirmed once more after the scan. A protected holder observed outside the
unit blocks activation; the discrete scans are not a continuous-time process
monitor.

This does not discover a connected Unix socket FD already transferred with
`SCM_RIGHTS` to a process that later dropped the protected credential. The
mandatory activation ceremony is therefore cold: stop public Caddy and
source-fair HAProxy so every old accepted connection is dead, then run
`collect-stopped-edge` while both units are inactive/dead and every manifest
socket is absent. The pass must show an empty protected-credential closure,
locked/non-login service accounts and no non-root dangerous active-capability holder.
Only after that evidence and its complete digest are approved may HAProxy
start, followed by Caddy; `collect-live` then binds the new generation.
Evidence from a warm reload is invalid. Run both collectors directly in the
host's initial PID namespace. The collector binds itself to the visible
systemd PID 1 namespace, but the operator must independently rule out a private
PID namespace or systemd container. This closes ordinary reacquisition under
the trusted-root/authentication-policy boundary, not a compromised root or new
local-privilege exploit.

1. Freeze exact BitcoinPIR commit, binaries, policies, directory artifacts,
   authority metadata and key-role inventory.
2. Complete the selected
   [render-plan skeleton](render-plan-skeletons/) using only values inventoried
   in [DEPLOYMENT_INPUT_MATRIX.md](DEPLOYMENT_INPUT_MATRIX.md), approve its
   digest externally, then run
   `node scripts/payment-v1-deployment-template-gate.mjs` on the unrendered
   repository inputs.
3. Render into a new private staging directory; never render over an active
   unit or runit script. Treat the VPSBG file only as reviewed patch input for
   the existing final exec after its ORAM build/verification logic.
4. Reject any unresolved placeholder. Verify binary/config/policy hashes and
   owner/mode/single-link rules.
5. Run `systemd-analyze verify` on Linux for rendered systemd units. After the
   VPSBG arguments are merged, run `sh -n` and `shellcheck` on the complete
   measured run script; do not execute or lint the argument fragment as a
   standalone service.
   Reject any Lightning rendering other than default Signet, and require the
   prerequisite record to retain `real_funds_authorized = false`; the guarded
   socket topology does not authorize mainnet or real-value use.
6. Run each provider/issuer `check-store` and the complete multi-role
   `rollback-authority-deployment-lint` before any listener starts.
7. Confirm provider, issuer and authority application origins are loopback;
   confirm same-host TLS edges have no redirects, access logs, identity headers
   or unpinned certificate path. For the public Hetzner edge, run
   `payment-v1-source-fair-edge.test.mjs` with the exact pinned Caddy and
   HAProxy binaries and treat any skip as failure. The HAProxy binary must be a
   currently maintained 2.8.x build with `+SYSTEMD` in `haproxy -vv`, because
   the unit uses `Type=notify` and `-Ws`; the CI package is only compatibility
   evidence. Confirm the publisher bind and client address are distinct,
   same-family RFC1918/ULA addresses; the static certificate is a WebPKI chain
   for the canonical publisher hostname; Caddy and HAProxy reject every other
   direct/PROXY source; the private route prevents source spoofing; the
   publisher-private-ingress sentinel is present only after that review; and
   rollback port 8099 is absent from HAProxy. For every rollback edge, confirm
   the private bind, exact sole-client IP filter, static TLS/SPKI pin, and
   private-ingress sentinel; do not claim mTLS with the current client.
8. From the host initial PID namespace, stop public Caddy and then source-fair
   HAProxy and reset failed unit state. With both units inactive/dead and every
   manifest socket absent, run `collect-stopped-edge`; transfer and approve the
   complete evidence SHA-256. It must prove exact locked/non-login service
   accounts, an empty protected-UID/GID closure and no non-root dangerous active
   capability holder. Only then start HAProxy before Caddy, with no warm reload,
   and start the remaining
   private/unrouted canaries. Verify identity, binary/attestation,
   database proof/root, signed policy, remote rollback failure behavior and
   exact method/scope matching from a strict client.
9. Collect `collect-live` root Linux evidence immediately after both fresh edge
   units are active; require
   PID-namespace/systemd-PID1 binding, identical all-thread holder passes, and the
   exact runtime directory/socket type, owner, group and mode records plus
   effective `MemoryMax`/`TasksMax`, zero current/max swap, zero hard/soft core
   limits, and `kernel.core_pattern=|/usr/bin/false`. Publish directory artifacts only after
   every advertised live value matches.
10. Provision an activation sentinel and change public routing only under the
    separately approved activation plan.

Remote server changes, persistent Signet custody and test-coin handling, public
Nostr/DNS publication, VPSBG UKI build/upload/reboot, production-key
installation/use, and mainnet/real Lightning funds remain separate approval
gates. A private no-funds approval does not authorize public Signet; a Signet
approval does not authorize mainnet. Mainnet also remains technically blocked
until its own reviewed preflight and negative tests exist.

The source-template gate is deliberately **not** rendered-artifact evidence.
For a future `RESOLVED` relay it checks canonical metadata shape and source-unit
binding only; it does not fetch the claimed commit or recompute an archive,
`Cargo.lock`, binary, config, policy or publisher-key digest. Repeated-digit
test hashes are accepted only inside negative/shape fixtures.

`scripts/payment-v1-rendered-artifact-gate.mjs` now renders and verifies one
closed profile from an externally digest-approved plan. It recomputes every
digest from exact staged bytes, rejects unresolved placeholders and extra or
cross-profile artifacts, validates class/path/owner/mode/link rules and emits a
manifest-derived runtime-evidence request. It still does not prove installation.
On the exact Linux staging host, a root operator must run
`scripts/payment-v1-linux-runtime-evidence.mjs collect-live`, pin the expected
machine/boot and approved plan/manifest digests, and transfer the resulting
full-file evidence digest over the approved out-of-band channel. The verifier
checks effective systemd state, process credentials for long-running units,
the successful exited state of the reviewed one-shot preflight, installed
bytes, NSS, ACLs, xattrs, capabilities and `systemd-analyze verify`. Until that
live evidence passes, these inputs remain deployment preparation rather than
an activatable bundle.

The live file is trusted-root operational evidence, not hardware attestation.
Before collection, independently verify the collector script from the frozen
commit and its exact Node/helper environment. The out-of-band evidence digest
detects later handoff changes but cannot establish that the target root or the
collector was honest; the current manifest does not self-attest those script
bytes.

## Failure and rollback

The strict mode never falls back to an old credential gate, unsigned policy,
local rollback file, plaintext transport, free query, or unverified provider.
Issuer or remote-authority outage fails the affected acquisition/mutation
closed. A purchased capability remains governed by its normal idempotent
claim/redemption semantics; deployment automation does not synthesize refunds
or retry a PIR query automatically.

Hetzner rollback changes routing back to the previously verified process and
preserves both detailed stores and remote authority floors; it never restores a
stale store snapshot or lowers an authority. VPSBG rollback selects the
preserved previous known-good UKI through the portal and restores the matching
client measurement/binary pins. It does not edit the measured run script in
place.
