# Hetzner and VPSBG Payment V1 deployment preparation

Status: non-activating deployment contract. This document does not authorize a
remote host change, public Nostr publication, a VPSBG UKI upload/reboot, or use
of real Lightning funds.

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

A resolved relay must bind its application listener to loopback, use a
same-host WSS edge, disable access/event/body/IP logging, disable NIP-42 for the
current publisher, retain the NIP-01 addressable-event replacement ordering,
and enforce the
BitcoinPIR bounds: 262,176-byte outer EVENT message, 192 KiB content, kind
30078, and a deployment-config size no greater than 16 KiB. At least two relay
hostnames are still required for directory use; two aliases on one Hetzner host
do not provide operator or failure independence.

The reviewed process interface is intentionally narrow: exactly
`bitcoinpir-directory-relay --config /absolute/owner-only.toml`, with no CLI
overrides. The TOML must declare `profile = "bitcoinpir-directory-relay-v1"` and
contain exactly the required fields `profile`, `listen`, `database`,
`directory_pubkey_hex`, `max_connections`, `max_in_flight_operations`,
`max_operations_per_second`, `max_egress_bytes_per_second`,
`max_egress_bytes_per_connection`, `max_archive_events`, `max_archive_bytes`,
`handshake_timeout_seconds`, `idle_timeout_seconds`,
`connection_timeout_seconds`, `operation_timeout_seconds`, and
`egress_timeout_seconds`; unknown fields and missing fields fail closed.
`deploy/payment-v1/directory-relay.toml.example` fixes the database below the
unit's only writable StateDirectory at
`/var/lib/bitcoinpir-directory-relay/relay.sqlite3`. The config must be mode
0400 or 0600 under a private parent directory.

The relay reserves the exact complete snapshot response against a per-
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

This preparation remains unresolved until the final implementation audit and
exact binary/config pins are recorded.

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

### P1 activation blocker: source-fair admission

The supplied stock-Caddy templates have only global upstream connection caps;
the issuer, relay and rollback-authority applications also use global budgets.
A single low-bandwidth source can therefore starve anonymous quote creation,
directory read/publish capacity, or rollback-floor calls without possessing a
credential. Do not publicly activate these surfaces until the reviewed host or
network layer supplies ephemeral source-fair admission without request/IP
logging or source headers to the business services. Reserve a distinct private
publisher ingress/budget for the directory, and place every rollback authority
behind its one client's WireGuard, mTLS or equivalent narrow allowlist. These
controls and their negative tests are required live deployment evidence, not a
commercial pricing decision.

1. Freeze exact BitcoinPIR commit, binaries, policies, directory artifacts,
   authority metadata and key-role inventory.
2. Run `node scripts/payment-v1-deployment-template-gate.mjs` on the unrendered
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
   or unpinned certificate path.
8. Start private/unrouted canaries. Verify identity, binary/attestation,
   database proof/root, signed policy, remote rollback failure behavior and
   exact method/scope matching from a strict client.
9. Publish directory artifacts only after every advertised live value matches.
10. Provision an activation sentinel and change public routing only under the
    separately approved activation plan.

Production deployment, remote server changes, public relay writes, UKI
upload/reboot, and real Lightning funds remain separate approval gates.

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
