# Payment V1 deployment templates

These files are review inputs, not installed service definitions. Every service
template ends in `.in`, has no `[Install]` section, and requires both the global
`/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED` sentinel and the exact
profile-specific activation-sentinel set after rendering. The global sentinel
alone cannot satisfy any closed profile. The VPSBG input is only a
non-executable argument fragment; it is neither a runit service nor a
replacement for the measured Tier 3 run script.

## Phase and input boundary

These templates support review and rendering; they do not collapse the four
deployment phases:

| Phase | Template consequence |
| --- | --- |
| Source merge | run source/CI gates only; do not render or install |
| Private no-funds | any approved closed plan may be rendered offline; remote install/start is edge-only, requires separate remote-host and bounded activation approvals, and ends by stopping the edge and revoking `EDGE-ACTIVATION-APPROVED` |
| Public Signet | only a separately approved default-Signet profile with staging-only persistent identities/test coins and separately approved public surfaces |
| Production mainnet | blocked; no reviewed mainnet deployment preflight/profile exists |

The role gate is machine-enforced per unit:

| Render profile or blocked role | Required role-specific activation sentinel(s) | Sentinel(s) that must be absent |
| --- | --- | --- |
| `edge-hetzner-v1` | `EDGE-ACTIVATION-APPROVED` | — |
| `issuer-lightning-signet-v1` | `SIGNET-ISSUER-ACTIVATION-APPROVED` | — |
| `provider-v1` | `PROVIDER-ACTIVATION-APPROVED` | `PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED`, `PROVIDER-DIRECT-ACTIVATION-APPROVED` |
| `provider-no-standard-cashu-v1` | `PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED` | `PROVIDER-ACTIVATION-APPROVED`, `PROVIDER-DIRECT-ACTIVATION-APPROVED` |
| `provider-direct-v1` | `PROVIDER-DIRECT-ACTIVATION-APPROVED` | `PROVIDER-ACTIVATION-APPROVED`, `PROVIDER-NO-STANDARD-CASHU-ACTIVATION-APPROVED` |
| `rollback-authority-v1` | `ROLLBACK-AUTHORITY-ACTIVATION-APPROVED` | — |
| `edge-rollback-authority-v1` | `ROLLBACK-EDGE-ACTIVATION-APPROVED` | — |
| unresolved directory relay unit | `RELAY-ACTIVATION-APPROVED` in addition to the still-blocking relay-selection gate | — |

Provisioning one row's sentinel never authorizes another row. The rendered
artifact gate validates the complete exact `ConditionPathExists=` set for every
closed profile. A host may stage several provider templates but may run only one
provider profile. The negative sentinel conditions are evaluated when systemd
starts a unit; they do not stop an already running process. Switching therefore
requires an explicit ceremony: stop the old unit, remove its positive sentinel,
prove that the old unit is inactive and port `8191` has no listener, confirm all
other provider sentinels are absent, then create exactly the new profile's
positive sentinel and start only its unit. Never create the new sentinel first
or rely on a bind failure to perform the switch.

The three profiles deliberately use separate `StateDirectory=` roots. That
does not authorize a fresh `provider.sqlite3` for the same provider. All three
checked-in provider templates are **zero-retained closed profiles**:
the source and rendered gates reject both `--service-retained-policy` and any
retained-policy payload. They are safe for a new provider identity, or for a
same-identity transition only after new issuance/admission has stopped, the
longest old policy/capability/grace horizon has elapsed, Standard Cashu custody
has been fully exported/retired/reconciled, and every shared-issuer redeem has
a known outcome. The static render gate cannot prove that drain; a same-
identity transition therefore needs separately reviewed transition evidence.
If any old credential or outcome-unknown operation remains, keep the old
profile available under its original identity or deploy a genuinely new
provider identity instead.

After that drain, an identity-preserving profile change also requires a
separately reviewed, stopped offline migration that preserves the
stable server ID, operator key and derived provider ID, policy-signing key,
provider identity certificate/key, ProviderStore/store-instance identity,
spent and replay state, remote authority instance/key, namespace, client-
verifying-key identity, client-signing seed, value-root key and floor before
`open_existing` and the new profile's preflight may pass. Re-render the TOML
only with the new profile's canonical secret paths. Rotating any authority-
identity field requires a separately reviewed migration ceremony; V1 has no
online rebind or reset. Otherwise
deploy a genuinely new provider/server identity and directory entry; never
reset state merely to make the new unit start.

Inventory non-secret values in
[DEPLOYMENT_INPUT_MATRIX.md](../../docs/payment/DEPLOYMENT_INPUT_MATRIX.md) and
copy the matching fail-closed plan shape from
[render-plan-skeletons/](../../docs/payment/render-plan-skeletons/). Do not put
secrets in either artifact. An approval for remote mutation, bounded service
activation, persistent Signet custody, faucet/test-coin handling, external
Cashu-mint access, public Nostr/DNS publication, VPSBG UKI build/upload/reboot,
production-key installation/use, or mainnet/real-value operation authorizes
only that action.

The templates divide responsibilities as follows:

- `systemd/hetzner-provider.service.in` is the paid/provider process on Hetzner.
  Its signed policy, not the unit, binds backend-specific scopes and prices.
  Harmony hint generation and Harmony query execution must remain separate
  scopes because they have different costs. The first production profile loads
  provider-local BAT, Standard Cashu recovery/custody/exposure controls, and one
  fully authorized shared issuer; direct receipt needs no provider secret and
  ARC remains forbidden. A provider-local BAT offer deliberately shares one
  policy-bound DHKE scalar between its issuer and that provider; compromise of
  either copy can forge that BAT lineage. Omit this method and use online
  shared-issuer redemption when that shared-secret boundary is unacceptable.
  Any Standard Cashu offer in the current policy must be omitted unless the render
  plan selects an approved production mint origin, WebPKI/pins, unit, finite
  custody/exposure limits and recovery/outage procedure. The local CDK fake-
  wallet mint is never a production
  dependency. The closed `provider-v1` unit always loads those Standard-Cashu
  inputs and remains blocked without the production-mint selection gate. Select
  the distinct `provider-no-standard-cashu-v1` unit and plan when the current
  policy omits Standard Cashu.
  That profile uses a separate
  service identity, configuration/state paths and activation sentinel, retains
  provider-local BAT and the approved shared issuer, and carries no Cashu
  recovery, custody or exposure field. The runtime Cashu-configuration
  validator rejects Standard Cashu in the configured current policy. This
  zero-retained profile carries no old-policy redemption route. Do not form either
  profile by deleting or adding arguments ad hoc.
  The still smaller `provider-direct-v1` profile uses another independent unit,
  account, state/configuration root, sentinel and exact nine-payload allowlist.
  It loads no BAT, Standard-Cashu, shared-issuer, ARC or Free-IP material. Its
  current policy may advertise only Free open-best-effort, Free proof-of-work,
  provider-local Free anonymous tickets and direct BOLT11 receipts. It accepts
  no retained policy or retained credential-redemption route. Its nine payloads
  include the owner-only remote rollback config,
  client-signing seed and value-root key. Startup coverage rejects every other
  applicable route. It makes no
  paid-QoS claim, and removing BAT/shared fields from either larger profile does
  not create this profile.
- `systemd/hetzner-cln-rpc-guard.service.in` is the only principal other than
  CLN and the dedicated one-shot preflight that may traverse the native CLN
  socket directory. It parses and reconstructs bounded JSON-RPC, permits only
  the issuer's exact `getinfo`, `listinvoices`, and `invoice` shapes, and emits
  a separate issuer-group socket below a boot-created `0710` directory. Its
  per-runtime invoice deadman is protected by `Restart=no`; a crash stops the
  bound issuer until an operator explicitly reviews and starts a new guard
  generation.
- `systemd/hetzner-payment-issuer.service.in` is the sole loopback-only Core
  Lightning issuer and integrated clearing unit. It requires and binds to the
  exact CLN unit, RPC guard, and successful live preflight, and it never runs a
  fake settlement backend. The issuer has no native CLN or Bitcoin-cookie
  group and `/srv/lightning` plus `/srv/bitcoin` are inaccessible in its mount
  namespace; the source-fair socket namespace is inaccessible as well. The
  public edge exposes only credential redemption and
  authenticated provider-balance lookup; payout-intent, payout and
  payout-status routes are not part of the V1 production product. Its command
  has no payout target, fee, or intent-TTL argument; the source gate rejects
  reintroducing any of those flags. Every clearing authorization/approval pair
  also names one distinct provider-request public-key file; this future
  payout-recovery/status identity is never filled with the clearing key even
  though current production serving is ledger-only.
- `systemd/rollback-authority.service.in` is instantiated only on a separately
  administered authority host. Provider 0, Provider 1, and the issuer each need
  their own host, keys, database, TLS edge, administrator, logs, and backup
  domain. Its `edge-rollback-authority-v1` profile binds Caddy only to one
  RFC1918/ULA address, admits only the sole client's exact private IP at the
  systemd network boundary, uses a static TLS certificate compatible with the
  existing strict SPKI-pinned client, and requires a separate private-ingress
  sentinel. It does not pretend that server-only mTLS is deployable before the
  client also has reviewed certificate/key support.
- `systemd/hetzner-directory-relay.service.in` is deliberately blocked while
  `relay-selection.toml.example` is `UNRESOLVED`. It is a deployment contract
  for the repository's directory-only relay, not a generic Nostr relay unit.
  A future resolved service may pass only one absolute owner-only TOML path via
  `--config`; direct command-line overrides remain forbidden.
- `systemd/payment-v1-source-fair-edge.service.in` runs pinned HAProxy 2.8
  without a StateDirectory, logs, peers, stats, or persisted source state. It
  owns a volatile `0750` runtime directory and four `0660` PROXY-v2 Unix
  sockets. Provider, issuer, public directory, and private publisher lanes have
  independent short-lived source tables and budgets.
- `systemd/payment-v1-public-edge.service.in` runs pinned stock Caddy and binds
  its lifecycle to the source-fair unit. It clears client headers, carries the
  source only in PROXY v2 over those Unix sockets, and has no source-header
  fallback. Both edge units send stdout/stderr to `null`, disable core limits
  and swap for the service cgroups, and rendered/live evidence rejects
  journal/core/swap drift. The publisher hostname binds a
  distinct private address; Caddy and HAProxy both require the publisher's
  exact WireGuard/private-route source IP, while a WebPKI server certificate
  keeps the existing credential-free `bpir-admin` WSS client compatible. The
  Nostr signature and pinned directory key remain the publication authority.
  Both units require a separate publisher-private-ingress sentinel. Rollback
  authorities do not use this public HAProxy.
- `vpsbg/vpsbg-free-pow-service-auth.args.in` is the only VPSBG change described
  by this directory. It lists the enforced Payment V1 arguments that a reviewed
  UKI rebuild would append to the existing query-only provider's final exec. It
  deliberately omits that measured script's ORAM build/verification, identity,
  database, attestation and cloudflared logic so it cannot be mistaken for a
  standalone replacement. It does not add an issuer, relay, mint, Lightning
  node, Cashu/ARC key, or rollback-authority process to VPSBG.

Production templates use only remote rollback authorities. Issuer and rollback
authority application listeners remain on loopback behind separately reviewed,
same-host TLS edges. ARC, fake Lightning, local rollback flags, legacy payment
gates, test-only trust roots, and source-IP Free quotas behind a proxy are
forbidden.

The checked-in Lightning preflight is default-Signet-specific. Its successful
result is neither mainnet evidence nor permission to render mainnet. Mainnet
requires a new reviewed preflight/profile and negative tests before any
production or real-funds approval can be acted on.

The signed policy is the price/resource contract. DPF query, Harmony hint,
Harmony query, Onion query and Direct ORAM require distinct scopes and may have
different prices or methods. V1 has no class-aware scheduler, so every initial
offer must use `priority_class = 1`; neither the directory nor Web UI may claim
paid QoS.

The VPSBG owner/mode rules do not provide secrecy from its hosting operator.
The deployment document records this as a P1 activation blocker rather than
treating guest-local filesystem permissions as hostile-host protection.

Run the repository gate before reviewing a rendered deployment:

```sh
node scripts/payment-v1-deployment-template-gate.mjs
node --test scripts/payment-v1-deployment-template-gate.test.mjs
BPIR_HAPROXY_BIN=/absolute/pinned/haproxy \
BPIR_CADDY_BIN=/absolute/pinned/caddy \
  node --test scripts/payment-v1-source-fair-edge.test.mjs
```

The gate also pins hashes of the pre-existing active systemd units and the
measured Tier 3 runit script. A change to those files is outside this preparation
slice and fails closed.

This source-template gate is not proof of installed bytes. Use
`scripts/payment-v1-rendered-artifact-gate.mjs` to render one closed deployment
profile from an externally digest-approved plan, recompute every referenced
artifact/hash manifest, and reject placeholders, extra files, symlinks and
cross-profile dependencies. Then use
`scripts/payment-v1-linux-runtime-evidence.mjs` as root on the exact Linux host
to bind effective systemd state, running process identities, NSS, ACLs, xattrs,
capabilities, boot and host identity to that manifest. The Hetzner edge request
also binds the live runtime directory and all four socket types, owners, groups,
and modes. Edge live evidence additionally requires hard/soft core limits of
zero, zero current/max cgroup swap, and the host-wide
`kernel.core_pattern=|/usr/bin/false`; the collector also hashes and validates
that exact root-owned, canonical, one-link, non-writable handler.
For every manifest secret, live evidence mirrors the Linux private-file
loader's DAC contract: the final parent must be owned by the consuming service
EUID at exact mode `0700`, while every ancestor must satisfy the root/EUID
ownership, write-bit and root-sticky exception. Independently, the runtime
collector is stricter and rejects named/default POSIX ACLs, xattrs and file
capabilities on the opened chain; this does not imply that the Rust loader
audits Linux POSIX, NFSv4 or FUSE ACLs. A successful `test -r` probe is not a
substitute. Each directory component is opened from its pinned parent with
`O_NOFOLLOW`; installed-file and parent-directory metadata probes refer to
pinned descriptors, with canonical pathnames rebound before and after
collection and again after every long probe. Private nanosecond
ctime/mtime fingerprints span those confirmations to reject rename-away-and-back
ABA; they are collector-local comparison state and are not emitted into the
runtime evidence schema. Only after those expensive secret checks finish does
the collector perform its final lightweight structured-Conditions and unit-
generation pass, immediately followed by evidence construction.
`LimitCORE=0` alone is not sufficient when a
kernel pipe handler ignores the resource limit. Offline review without the externally transferred full evidence
digest is not activation evidence. HAProxy admission begins only after Caddy
has accepted TCP/TLS and parsed HTTP; it does not replace independent
Caddy-front slowloris, header, file-descriptor, memory, task, firewall, or
volumetric limits.

The public edge has a mandatory two-evidence cold-start ceremony. While Caddy
and HAProxy are inactive/dead and every Unix listener is absent, run
`collect-stopped-edge`. It proves the manifest-bound service accounts are
password-locked and login-disabled, no process/thread retains a protected
UID/GID, no non-root thread retains a reviewed dangerous active capability,
and the stopped unit
and socket-absence snapshots remain stable around both procfs passes. Only then
start HAProxy followed by Caddy and run `collect-live` against the new
generation. Neither command permits caller-authored evidence or challenge
material; offline verification requires the complete independently transferred
evidence digest. A warm reload is not an accepted replacement.

Runtime-evidence v4 accepts only a local-files NSS authority (`passwd: files`,
`group: files`, and no explicit `initgroups:` line). It snapshots the canonical
root-owned `/etc/nsswitch.conf`, `/etc/passwd`, and `/etc/group` around NSS
enumeration and confirms the same files again at the end of live collection,
requires `getent` identity and membership projections to match those files, and
checks `id -G` for every enumerated user. In live evidence, password, GECOS,
home, shell and group-password fields are snapshot-bound but are not semantic
identity comparisons; stopped-edge evidence additionally requires each service
account's shell and locked shadow-password state described above.
SSSD, LDAP, winbind, NIS and `systemd` UserDB are outside this
V1 proof profile. The collector is trusted-root operational evidence rather
than attestation: independently pin the exact collector script from the frozen
commit before running it; the evidence-file digest alone does not prove an
honest collector.

The same evidence performs two bounded scans of every numeric Linux process
and thread, records all active capability sets plus `CapBnd`, and rejects a
non-root holder of any reviewed dangerous active capability. Managed masks
must be subsets of the rendered systemd policy: only Caddy may use
`CAP_NET_BIND_SERVICE`, while HAProxy and business services must have zero. A retained
protected service UID or GID is accepted only
inside that service's exact current systemd cgroup with the full expected
credential set; every long-running MainPID and the final unit generation are
reconfirmed. This closes stale kernel credentials that a later `/etc/group`
edit would not revoke.

The exact production HAProxy must be a currently maintained 2.8.x build whose
`haproxy -vv` feature list contains `+SYSTEMD`; the unit uses `Type=notify` and
`-Ws`. CI's distribution package is only a compatibility baseline, not the
production binary pin. The exact pinned bytes must pass the suite without any
binary-dependent skip.

See `docs/payment/HETZNER_VPSBG_DEPLOYMENT.md` for topology, rendering,
activation, rollback, and remote-approval boundaries.

The directory service is still deliberately non-activatable while
`relay-selection.toml.example` is `UNRESOLVED`. Do not include it in a public
render, install a publisher key, or publish a catalog merely because the rest
of a profile passes. Relay resolution, key installation/use and public Nostr
publication are distinct reviewed/approved steps. Resolution also records one
explicit directory transport mode: strict mode retains two to eight distinct
WSS origins, while centralized mode accepts exactly one and must be presented as
degraded. No render infers independent operators from origin count.
