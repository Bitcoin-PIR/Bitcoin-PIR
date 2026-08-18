# Mainnet Lightning V1 source-readiness runbook

Status: **source work only; production activation is blocked**. This is the
operator handoff for the Mainnet shared-BAT topology. It does not authorize
private rendering, remote installation, VPSBG image work, node contact,
invoice creation, payment, funding, channel changes, publication, or service
activation.

## Frozen production shape

The production product has one shared online BOLT11-to-BAT issuer and two
independently selected PIR providers:

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

Using one issuer is an explicit correlation and availability tradeoff. It does
not merge provider identities, policies, ProviderStores, idempotency material,
rollback-authority namespaces or query requests, and it never creates a pair
identifier or shared raw credential.

## Focused source check

From the repository root, run the existing browserless entry point:

```sh
scripts/payment-v1-mainnet-lightning-v1-check.sh
```

It uses locked/offline Cargo plus focused source/template, rendered-artifact
and Web shared-BAT contracts. It is not full Payment V1 CI and produces no
private plan, deployment artifact or live evidence. A pass does not close the
pir2 custody blocker below and does not make the checked-in empty Mainnet plan
skeleton renderable.

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

## pir2 hostile-host custody blocker

The stateful pir2 shared-BAT provider needs provider identity material, its
clearing/idempotency secrets, ProviderStore keys and remote rollback-authority
client secrets. The repository does not yet identify a reviewed way to
provision and retain those secrets inside the measured guest while treating
the VPSBG host as hostile. They must not be embedded in a public UKI or treated
as confidential merely because they are placed on an unprotected mutable host
path.

This is a production P1 blocker. Until a reviewed measured-guest
provisioning/sealing and recovery contract exists, no pir2 shared-BAT plan or
UKI may be called production-activatable, and the complete two-provider product
may not be called production-ready. The existing storeless Free-PoW and
functional-beta VPSBG images are not substitutes for this stateful profile.

## Private materialization and live boundary

The checked-in `issuer-lightning-mainnet-v1` plan skeleton deliberately has no
payloads, identities, hashes, risk limits or node inputs and must fail the
render gate unchanged. After the old-state inventory and pir2 P1 are closed, a
separately authorized owner-only plan must bind the exact issuer, pir1 and pir2
binaries/configuration, two policies, twelve BAT lineages, two clearing
relationships, three independent store/rollback domains, service identities,
database roots, quote delegation, CLN identity/backups and risk limits. Secret
values never belong in Git, CI output or this runbook.

Rendering, installation, custody/backup acceptance, pir1 private start, issuer
private start, VPSBG UKI build, upload, switch/reboot, post-boot measurement,
Web/directory publication, no-funds canaries and real-value acceptance are
separate approvals and stop conditions. Keep
`MAINNET-LIGHTNING-V1-ACTIVATION-APPROVED` absent until the exact applicable
stage is approved. A green source check, rendered bundle or read-only preflight
does not authorize the next stage or establish Mainnet-live status.
