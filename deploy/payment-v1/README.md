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
  namespace. The public edge exposes only credential redemption and
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
  domain.
- `systemd/hetzner-directory-relay.service.in` is deliberately blocked while
  `relay-selection.toml.example` is `UNRESOLVED`. It is a deployment contract
  for the repository's directory-only relay, not a generic Nostr relay unit.
  A future resolved service may pass only one absolute owner-only TOML path via
  `--config`; direct command-line overrides remain forbidden.
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
capabilities, boot and host identity to that manifest. Offline review without
the externally transferred full evidence digest is not activation evidence.

See `docs/payment/HETZNER_VPSBG_DEPLOYMENT.md` for topology, rendering,
activation, rollback, and remote-approval boundaries.
