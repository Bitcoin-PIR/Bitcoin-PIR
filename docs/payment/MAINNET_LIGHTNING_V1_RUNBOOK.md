# Mainnet Lightning V1 source-readiness runbook

Status: **source-ready; live approval pending**. This is a short operator
handoff for the versioned `direct-bolt11-dpf` Mainnet profile. It does not
authorize rendering, remote installation, node contact, invoice creation,
payment, funding, channel changes, or service activation.

## Source entry point

From the repository root, run the focused browserless check:

```sh
scripts/payment-v1-mainnet-lightning-v1-check.sh
```

It uses locked/offline Cargo, source/template and rendered-artifact contract
tests, plus the Web independent Direct BOLT11/DPF pair contract. It is not full
Payment V1 CI and produces no deployment artifact or live evidence. The normal
broader browserless profiles remain in [../../TESTING.md](../../TESTING.md).

The installed `bpir-admin mainnet-lightning-v1 lint-profile` command is offline.
Its `preflight` subcommand is deliberately different: it is a read-only local
Core/CLN preflight and may run only after the approvals below and a rendered,
approved profile are present. It never creates an invoice or executes a payment.
This describes the CLI's RPC behavior, not permission to start a wallet process.

## Before a live preflight

The intended Direct+Direct query uses two independently rendered instances of
this issuer profile plus two matching `provider-direct-v1` profiles, one pair
for each query leg. They must use different provider and issuer IDs, public
origins, CLN payee node IDs, receipt keys and invoices. The checked-in systemd
names are host-local singletons, so the two issuer instances belong on separate
approved hosts or failure domains rather than being duplicated on one host.

The user must approve the target host and provide the following **non-secret**
identifiers, paths, ownership IDs, and SHA-256 pins for each rendered profile:

- Mainnet issuer ID, expected CLN payee node ID, Bitcoin Core/CLN executable
  paths and their protected-parent paths/hashes;
- matching provider ID, signed `provider-direct-v1` policy and directory entry,
  provider/issuer public origins, database pins and receipt-verification key;
- local Core RPC endpoint/cookie-file path, local CLN `network=bitcoin` RPC
  socket path, and the preflight UID/GID layout;
- quote-delegation and backup-receipt file paths plus hashes, and digests for
  identity, channel-recovery, and datastore restore evidence;
- explicit risk caps: maximum invoice, total exposure, invoices per runtime,
  maximum payment attempts (V1 requires one), and an approved backup age; and
- the actual Mainnet CLN node selected for each issuer, public inbound liquidity
  sufficient for its invoice cap, and the separately approved funding/exposure
  envelope. Do not put wallet secrets, signing keys, cookie contents, invoices,
  preimages, or seed material in the profile or this repository.

Required approvals remain separate: rendering inputs and plan, remote-host
mutation/install, custody and Mainnet funds/liquidity, creating the activation
sentinel, and any later invoice/payment acceptance. A passing source check or
read-only preflight grants none of them.

## Live boundary

Keep the `MAINNET-LIGHTNING-V1-ACTIVATION-APPROVED` sentinel absent until all
listed inputs and approvals are recorded. An operator must explicitly start and
inspect the Core unit first. The preflight, guard, and issuer use
`Requisite=`, `After=`, and `PartOf=` for Core: they fail if Core is not already
active and do not pull it into service. The guard and issuer then require a
successful RPC-read-only preflight. Record host-specific observed evidence
separately; do not reinterpret this document or a green source check as
Mainnet-live status.
