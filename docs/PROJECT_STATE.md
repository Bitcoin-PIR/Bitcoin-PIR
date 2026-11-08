# Project state and maintenance

The reference deployment and its remaining maintainer dependencies. This is
an orientation page, not a live health report. [Architecture](ARCHITECTURE.md)
maps the code; [Production operations](PRODUCTION_OPERATIONS.md) routes
changes. Release evidence stays in the pin PRs and
[history](history/README.md), and the remaining work is tracked in
[#429](https://github.com/Bitcoin-PIR/Bitcoin-PIR/issues/429).

## What runs where

| Location | Workload | Operating entry |
| --- | --- | --- |
| pir1, Hetzner (no TEE) | DPF server 0, HarmonyPIR hints and OnionPIR. Also the issuer, Cashu mint, Core Lightning and directory relay, behind the Cloudflare tunnel. | [Flow D](PRODUCTION_OPERATIONS.md#d-pir1-hetzner-binary--auth), [issuer/mint](runbooks/issuer-and-mint.md), [directory](runbooks/directory-relay.md) |
| MacBook (no TEE) | DPF server 1 and HarmonyPIR queries, run best-effort by its operator through launchd and a tunnel. No rented replacement server. | [Flow I](PRODUCTION_OPERATIONS.md#i-pir2-macbook-node--local-then-auth), [worked runbook](runbooks/pir2-macbook-replacement.md) |
| Direct ORAM host, VPSBG | SEV-SNP measured runtime serving Direct ORAM only. No SSH in the production measured guest; runtime upgrades and data-disk work use separate flows. | [Flow E](PRODUCTION_OPERATIONS.md#e-direct-oram-host-runtime-uki-and-measured-boot--local-then-auth), [Flow F](PRODUCTION_OPERATIONS.md#f-vpsbg-data-disk-window--auth) |
| Mac Studio | Operator/directory signing keys, directory publication, release coordination and retained artifacts. | [Keys](KEY_MANAGEMENT.md), [directory publisher](runbooks/directory-relay.md#publish-or-update-entries), [retention](DATABASE_ARTIFACT_RETENTION.md) |
| GitHub Pages | Application at <https://app.bitcoinpir.org/>; playground at <https://sdk.bitcoinpir.org/> in its separate repository. | [Flow C](PRODUCTION_OPERATIONS.md#c-web--github-pages--local-then-auth), [playground release step](RELEASE.md#11-playground--auth) |
| Cloudflare R2 | Public generation bundle at `data.bitcoinpir.org`, independent of pir1's query traffic. | [Data bundle](runbooks/data-bundle.md) |

pir1 and the MacBook run r14. The Direct ORAM host retains its existing r13
runtime; r14 did not rebuild or switch it. The current build identities and
source revisions are the pin definitions/comments in
[`attest-pin.ts`](../web/src/attest-pin.ts) and the ORAM release records in
[`data-retention/`](data-retention/), not a duplicate list here. The closing
[r14 release record](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/478#issuecomment-6717336032)
links both client deployments and the final preflight.

OnionPIR and Direct ORAM are first-class. DPF/HarmonyPIR depend on the
best-effort MacBook; the reference pair has one maintainer, not two
independent operators. pir1 offers best-effort lanes with paid priority;
the other nodes are best-effort/free. Per-backend access and provider
endpoints are reported by the live servers and directory. The reference
client configuration is in
[`production-providers.ts`](../web/src/production-providers.ts).

## Data age and provenance

The published generation is 948454, anchored at the Bitcoin block mined on
2026-05-08. It includes the full database and the 940611→948454 delta, not
transactions after that block. This is a fixed snapshot, not a continuously
updated view of Bitcoin; its age is the time since that block date. The
application states this above the backend tabs in
[`web/index.html`](../web/index.html).

The public bundle has 128 files, about 57.3 GB; its catalog and hash list
are in [`deploy/data-bundles/948454/`](../deploy/data-bundles/948454).
Pins bind the database proofs, not merely the download URL. The accepted
mixed-provenance lineage and irreplaceable snapshots are mapped in
[Database artifact retention](DATABASE_ARTIFACT_RETENTION.md).

No new generation is currently planned. Before the next rebuild, D2 still
needs a decision on v1 proof transport: the native V2 producer emits no v1
sidecar, while DPF/HarmonyPIR proof transport and existing staging/runtime
paths expect one. The other rebuild prerequisites and cost estimates are in
[Database rebuild §2](DATABASE_REBUILD.md#2-prerequisites). The serving ORAM
host is not a spare builder.

## Routine operation and remaining manual work

| Activity | Automation today | Maintainer dependency |
| --- | --- | --- |
| Node reachability | [Node monitor](../.github/workflows/node-monitor.yml) probes hourly and manages `node-down` issues. | A WebSocket upgrade is not a successful private lookup or a full attestation check; diagnosis uses [Flow A](PRODUCTION_OPERATIONS.md#a-diagnose--read). |
| Directory publication | Mac Studio launchd `org.bitcoinpir.directory-publish`, daily at 10:00 local (UTC+8); opens and closes the publisher tunnel for the run. | Workstation, login session, network and signing material remain necessary; logs and recovery are in the [directory runbook](runbooks/directory-relay.md#publish-or-update-entries). |
| MacBook directory announcement | `org.bitcoinpir.directory-announce`, RunAtLoad and daily 09:30 local (Asia/Singapore, UTC+8), before publication; no KeepAlive. | Node/session/network availability and an unexpired public assertion. Loading the job successfully does not demonstrate a later calendar trigger. |
| Directory monitoring | Daily CI verifies the catalog and manages a `directory-stale` issue when unreadable, short of 16 shards or less than 7 days from expiry. | This reports expiry; it does not sign a replacement assertion. |
| Releases | [D1 checklist](RELEASE.md), preflight and per-target scripts. | Host switches, no-TEE transition publication, MacBook operator coordination and Pages/playground publication remain distinct steps. |
| Payments and recovery | Issuer settlement ledgers; encrypted offline backup and a documented restore procedure. | Paid third-party lanes are by arrangement, with manual Lightning settlement; backups, account access and recovery remain operator-owned. See [issuer/mint](runbooks/issuer-and-mint.md) and [security posture](SECURITY_POSTURE.md#backups). |

MacBook announcement files are `~/bpir-node/directory/announce.sh` and
`~/Library/LaunchAgents/org.bitcoinpir.directory-announce.plist`, with
`directory-announce.out.log` / `directory-announce.err.log` under
`~/bpir-node/logs/`. This job is separate from the PIR service
`org.bitcoinpir.pir2-macbook`; its normal post-run state is `not running`.

Re-announcing reuses a signed public assertion; it is not renewal. The
operator key stays on the Mac Studio. Renewal signs a higher assertion epoch
there and supplies the new public file to the MacBook before expiry, as in
[Operator guide §8](OPERATOR_GUIDE.md#8-get-listed). Keeping
the same operator key and stable server ID preserves the provider ID; the
publisher ledger preserves sequence continuity. No automatic assertion
renewal is installed.

For a fresh read, `scripts/production-status.sh` queries host state and
public attestation without restarting anything; `BPIR_ADMIN` can select an
existing built admin tool. `bpir-admin attest` also checks pir1's public
binary when supplied its expected pin (the status script's pir1 stage is
SSH service/port health only). The
[directory readback](runbooks/directory-relay.md#read--health)
verifies the client view without signing or publishing. The ORAM progress
HTTP endpoint being unavailable while `unified_server` owns the port is
expected; it is not, alone, evidence that the host is down.

Key locations, account ownership, backup coverage and the accepted Milan
residual risk are in [Security posture](SECURITY_POSTURE.md), not an implied
claim of unattended operation. The pir1 initramfs tooling decision remains
open before its next kernel change.

## Monthly cost coverage

| Item | Recorded amount / basis |
| --- | --- |
| Public data bundle, R2 | About **US$0.70/month** for one 57 GB generation under the pricing assumptions in [Data bundle](runbooks/data-bundle.md#why-r2); free egress. This is an estimate, not an invoice or a promise of zero request charges. |
| pir1, Hetzner | Recurring host invoice not recorded in this repository; amount needs maintainer confirmation. The issuer/mint/relay share the host, not separate documented rentals. |
| Direct ORAM host, VPSBG | Recurring host/storage invoice not recorded here; amount needs maintainer confirmation. |
| MacBook and Mac Studio | Existing operator-owned hardware, not new VPS rentals. Electricity, network and hardware amortization are not recorded. |
| Domains, Pages, tunnels and CI | Account-plan charges, renewals and usage charges are not inventoried here; no zero-cost assumption. |
| Future attested database build | No standing builder rental. [Rebuild estimates](DATABASE_REBUILD.md#24-time-and-money-estimates) are historical planning figures, not current monthly serving costs. |

A defensible total is not available until the host invoices and shared
account costs are supplied. Lightning liquidity, channel funds and paid
query revenue are separate from the hosting estimate; they are not silently
netted against it.

## Deferred scope

- **SDK registry release (E2):** deferred by the maintainer. No crates.io/npm
  publication or registry-token setup now; the playground keeps vendoring
  source and built WASM. SDK publication/semver work is not represented as
  complete.
- **Database pipeline (D2):** procedure documented, transport decision and
  the next rebuild deferred; keep the current generation in service.
- Next-generation ladder database, remote-ORAM client, GCE OnionPIR profile,
  playground credits wallet UI and Fly.io migration remain outside the
  current hand-over scope.
- PACT/MoLE (ACT) credentials remain deferred pending working-group progress.

The final hand-over/release remains open in
[#429](https://github.com/Bitcoin-PIR/Bitcoin-PIR/issues/429). The existing
operator guide, public data bundle, discovery and payment defaults let
another operator bring up a node, but do not transfer the reference
deployment's accounts, signing keys or funds.
