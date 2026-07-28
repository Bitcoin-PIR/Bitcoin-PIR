# Payment V1 deployment templates

These files are review inputs, not installed service definitions. Every service
template ends in `.in`, has no `[Install]` section, and requires an explicit
`/etc/bitcoinpir/payment-v1/ACTIVATION-APPROVED` sentinel after rendering. The
VPSBG input is only a non-executable argument fragment; it is neither a runit
service nor a replacement for the measured Tier 3 run script.

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
  reintroducing any of those flags.
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
UID/GID, no non-root thread retains CAP_SETUID/CAP_SETGID, and the stopped unit
and socket-absence snapshots remain stable around both procfs passes. Only then
start HAProxy followed by Caddy and run `collect-live` against the new
generation. Neither command permits caller-authored evidence or challenge
material; offline verification requires the complete independently transferred
evidence digest. A warm reload is not an accepted replacement.

Runtime-evidence v2 accepts only a local-files NSS authority (`passwd: files`,
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
and thread and rejects a non-root CAP_SETUID/CAP_SETGID holder. A retained
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
