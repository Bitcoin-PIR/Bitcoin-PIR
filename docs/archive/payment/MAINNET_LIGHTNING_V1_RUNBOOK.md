# Mainnet Lightning V1 source-readiness runbook (archived)

Status: **superseded source handoff; do not materialize or activate the current
Mainnet skeletons**. The 2026-08-18 owner decision changed BAT from a
provider-specific credential to an issuer-wide credential with global
first-spend and no provider payment store. The replacement source sequence is
normative in
[`MAINNET_SHARED_BAT_PRODUCTION_PLAN.md`](MAINNET_SHARED_BAT_PRODUCTION_PLAN.md).
The 2026-08-19 pir2 decision additionally retains distinct identity and
clearing seeds only in a measurement-bound sealed envelope; it does not make
the existing VPSBG rootfs an encrypted disk.
This runbook remains useful only for old-Direct inventory and approval
boundaries until its profiles and commands are rewritten. It authorizes no
private rendering, remote installation, VPSBG image work, node contact,
invoice creation, payment, funding, channel changes, publication, or service
activation.

## Superseded unmerged draft shape

An unmerged source draft proposed the following **rejected shape**. Current
`main` instead still contains the older Direct Mainnet issuer unit and stateful
single-pool provider profile; neither shape is the production target:

- `pir1` is the ordinary Hetzner provider for DPF evaluate, Harmony hint and
  Onion evaluate, for both db0 and db1;
- `pir2` is the measured VPSBG provider for DPF evaluate, Harmony query and
  Direct TEE-ORAM, for both db0 and db1; and
- each of those twelve provider/database/workload scopes offers only
  provider-local Free-PoW and one provider-specific BitcoinPIR Cashu BAT.

The single issuer loads exactly two signed policies, twelve distinct raw BAT
key lineages and two clearing authorization/approval/request-key triplets in
fixed pir1/pir2 order. Each provider has one clearing relationship shared by
its six scopes. Operator, clearing and request-verification role keys are
distinct within and across both relationships. BOLT11 is only the issuer-side
BAT acquisition mechanism: neither provider receives invoice, payment-hash,
preimage, route or payer data. Direct BOLT11 receipts, Standard Cashu, ARC and
payout inputs are outside this production profile.

The approved replacement keeps the two provider roles but uses issuer-wide BAT
acceptance classes. One BAT may be submitted to any compatible provider and is
consumed exactly once globally by the issuer. pir1 and pir2 have no durable BAT
spent/delivery store. The fixed twelve-lineage requirement, provider-specific
raw credentials and pir2 payment ProviderStore in the rejected draft must not
be carried into a release.

## Focused source check

The browserless entry point currently checked into `main` validates the older
Direct V1 profile:

```sh
scripts/payment-v1-mainnet-lightning-v1-check.sh
```

The unmerged draft changed that entry point to validate fixed 2/12/2 inputs.
Do not cite either pass as evidence for the issuer-wide contract. The script
remains only a regression aid until Phase D of the revised plan replaces its
provider-specific/Direct assertions. It produces no private plan, deployment
artifact or live evidence and does not make the checked-in Mainnet skeleton
renderable.

The installed `bpir-admin mainnet-lightning-v1 lint-profile` command is
offline. Its `preflight` subcommand is different: it performs read-only local
Core/CLN checks only after an approved private profile is present. It never
creates an invoice or pays one, and its RPC behavior is not permission to start
a wallet process.

## Inventory and retain any old Direct state

Before materializing the shared-BAT profile, the release owner must determine
whether the old Mainnet Direct profile was ever privately rendered, installed
or run. The checked-in empty skeleton is not evidence that no private copy or
runtime state exists. Keep the inventory owner-only and record only digests and
absence/presence conclusions in review evidence. It must cover every approved
host and backup domain, including old rendered plans/bundles, issuer and
provider identities, stores plus WAL/SHM, rollback-authority instances/floors,
quote and receipt key lineages, quote delegations, outstanding quote/claim/
recovery horizons, Direct capability grace periods, and the selected CLN
identity/wallet/channel backups.

If the inventory proves no old private material or runtime ever existed, an
independent reviewer records that conclusion and the locations checked. If any
old state exists:

1. stop new Direct issuance and provider admission;
2. preserve the exact stores, floors, identities, keys and backup domains;
3. drain every immutable quote, claim, recovery and capability/grace horizon,
   or retain the isolated old issuer/provider recovery runtime and its exact
   issuer root, network, payee and signing lineages until the last horizon; and
4. record the final retention or destruction decision before removing any old
   key or state.

The shared-BAT profile has no Direct receipt key and cannot silently inherit
that recovery obligation. Never blank-initialize over an old store, pair old
issuer history with an empty provider claim namespace, or reuse an identity or
rollback namespace unless a separately reviewed migration preserves its full
spend/replay/floor history.

## pir2 V2 sealed-credential blocker

The revised pir2 profile has no payment ProviderStore, shared-idempotency
secret or payment rollback client. The selected V2 design retains distinct
service-identity and clearing signing seeds in one measurement-bound AEAD
envelope on the untrusted persistent rootfs. Only the measured initramfs may
derive its VCEK-root sealing key through `/dev/sev-guest`; plaintext exists only
in zeroizing process memory. The two signing roles must not reuse one key, and the envelope
must not contain BAT/payment state.

This remains a production P1 until the derived-key/envelope implementation,
strict report-policy and signed exact-release checks, pre-ORAM sealed preflight,
fresh-key enrollment, fail-closed plaintext-fallback rejection, an
observation-only boot whose measurement is independently reproduced from the
exact reviewed UKI, and the fresh-nonce Boot-0 plus exact-final-UKI
two-clean-reboot canary pass before either public key is authorized. Every boot
receipt must bind the current attested channel and reject an earlier nonce. A
different measurement, physical host, TCB environment or VM instance is a
credential rotation, not an assumed unlock path. The existing plaintext
identity, Free-PoW and functional-beta images are not substitutes.

## Private materialization and live boundary

The checked-in `issuer-lightning-mainnet-v1` skeleton is an empty legacy V1
placeholder, while the provider skeletons are older stateful V1 profiles. The
unmerged fixed-2/12/2 draft is also superseded. None encodes the approved V2
contract, and none may be privately completed as a substitute.
After the V2 source, old-state inventory and pir2 P1 are closed, new owner-only
plans must bind the exact binaries/configuration, two policies, reviewed
acceptance classes and fresh key epochs, provider accounting/authentication
relationships, the issuer's sole BAT store/rollback domain, service identities,
database roots, quote delegation, CLN identity/backups and risk limits. Secret
values never belong in Git, CI output or this runbook.

Rendering, installation, custody/backup acceptance, pir1 private start, issuer
private start, VPSBG UKI build, upload, switch/reboot, post-boot measurement,
Web/directory publication, no-funds canaries and real-value acceptance are
separate approvals and stop conditions. Keep
`MAINNET-LIGHTNING-V1-ACTIVATION-APPROVED` absent until the exact applicable
stage is approved. A green source check, rendered bundle or read-only preflight
does not authorize the next stage or establish Mainnet-live status.
