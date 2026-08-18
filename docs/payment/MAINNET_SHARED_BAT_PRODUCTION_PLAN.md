# Mainnet shared-BAT production plan

Status: **source implementation in progress; no production activation is
authorized**. This plan records the approved product shape and the smallest
source-to-production sequence. It does not authorize rendering with private
keys, installing files on a host, building or switching a VPSBG UKI, publishing
the Web client or directory, creating an invoice, moving funds, or starting a
production service.

## Approved product contract

The production query product supports db0 and db1 across all four backends.
Every provider scope offers exactly:

1. provider-local Free proof of work; and
2. a blinded, provider-specific BitcoinPIR Cashu BAT acquired from the shared
   online issuer.

BOLT11 is the issuer-side acquisition mechanism for BAT. It is not a separate
provider entitlement. A PIR provider must not receive the invoice, payment
hash, preimage, payer route, or payer identity. Direct BOLT11 receipts,
Standard Cashu and experimental ARC are excluded from this production profile.
Their generic protocol/test code may remain in the repository, but no retained
or current production policy may advertise them.

The two complete provider policies are:

| Provider | Production workloads | Databases | Public service role |
| --- | --- | --- | --- |
| pir1 | DPF evaluate, Harmony hint, Onion evaluate | db0 + db1 | ordinary provider on the approved Hetzner application host |
| pir2 | DPF evaluate, Harmony query, Direct TEE-ORAM | db0 + db1 | measured VPSBG provider |

Each policy therefore has six scopes and six BAT offers. The shared issuer
loads both signed policies and exactly twelve independent raw BAT key lineages.
The two providers keep distinct identities, policies, ProviderStores, clearing
authorizations, request-verification keys, idempotency secrets and rollback
authority namespaces. None of the twelve BAT raw keys may be reused across a
scope or provider. Each provider has one clearing relationship shared by its
six scopes; the pir1 and pir2 clearing-role keys must differ from one another,
and the roles inside each relationship remain separated.

One approved Hetzner application server may co-locate the pir1 provider,
shared issuer, directory relay and public edge in the explicitly centralized
deployment mode. Co-location does not merge their service identities, stores,
filesystem ownership or rollback domains. The production providers and issuer
still require three independently recoverable rollback-authority failure
domains. No public or warm-fallback port 8092 is part of this topology: the
expected private application listeners are pir1 on `127.0.0.1:8191`, the
issuer on `127.0.0.1:5610`, and the existing VPSBG provider on port 8091 behind
its approved public edge.

## P0/P1 source blockers

The following are correctness requirements, not optional hardening work.

### 1. pir1 must load both Harmony databases in one process

The current `unified_server` accepts only one Harmony V2Full pool. A complete
pir1 policy contains exact db0 and db1 Harmony-hint scopes, while startup
validation requires every advertised scope to be locally serviceable. The
current single-pool process therefore cannot start with the approved policy.

Add a repeatable database-to-pool mapping while preserving the existing
single-pool CLI for old profiles. Admission, reservation and dispatch must look
up the exact authenticated `db_id`. A pending V2Half token must also retain its
database ID so two halves cannot cross databases. This is an internal server
change; the existing Payment V1 and Harmony request wires already bind the
database ID.

### 2. pir1 and pir2 need closed shared-BAT provider profiles

The pir1 profile must use a schema-v7 ProviderStore, a remote rollback
authority and shared clearing material, with separate db0/db1 Harmony pools.
It must not load a provider-local BAT mint key, direct-receipt material,
Standard Cashu or ARC.

The pir2 measured profile must replace the historical storeless/beta startup
route with a fresh stateful ProviderStore, remote rollback authority and shared
clearing material. It must not reuse the beta provider identity, local rollback
SQLite database, capability lineage or clearing state. Its exact signed policy
digest and runtime inputs must be part of the later measured-image release.

Before calling the pir2 profile source-ready, the repository must identify a
reviewed way to provision and retain its provider secret material without
placing secrets in the public UKI or treating an unprotected mutable host path
as confidential. If no such measured-guest provisioning/sealing contract
exists, pir2 BAT activation remains blocked and this source phase records the
gap instead of claiming production readiness.

### 3. the Mainnet issuer must be a closed two-provider BAT issuer

The issuer already supports repeated policy, BAT-key and clearing inputs. The
closed Mainnet profile must load exactly two policies, twelve BAT keys and two
provider clearing triplets in a fixed pir1/pir2 order. It keeps the shared
issuer settlement key, redeem-response derivation key, remote rollback
authority and Mainnet Lightning quote material, while excluding direct
receipt, Standard Cashu, ARC and payout inputs.

The issuer unit must be able to read the root-owned Mainnet quote-delegation
artifact. Clearing-role validation must reject reuse of any provider clearing,
request-verification or operator role key across the two provider
relationships, in addition to the existing within-provider separation.

## Source implementation sequence

### Phase A — freeze this contract

Land this plan before changing runtime or deployment profiles. Update older
status/runbook language that still presents Direct BOLT11 or a storeless beta
as the intended production topology.

Acceptance:

- the approved methods, provider roles and exact 2-policy/12-lineage issuer
  shape are stated once and linked from the operator entry points;
- source readiness, private materialization, host mutation, VPSBG operations,
  public publication and real-value operation remain separate gates; and
- no database rebuild, browser run, UKI build or production mutation occurs.

### Phase B — close the executable source profiles

Implement exact-db Harmony multi-pool routing, the pir1 shared-BAT provider
profile, the closed Mainnet shared-BAT issuer profile and the pir2 measured
stateful profile. Render skeletons remain deliberately invalid until an
owner-only release plan supplies reviewed private inputs. Production secrets,
rendered plans and signed evidence are never committed or printed in CI.

Acceptance:

- pir1 can validate and serve both Harmony scopes in one process, and a
  cross-db V2Half continuation fails closed;
- provider profiles expose only the adapters and private inputs needed for
  Free-PoW plus shared BAT;
- the issuer profile requires exactly 2 policies, 12 distinct BAT keys and 2
  distinct clearing relationships; and
- pir2 either has a reviewed confidential provisioning contract or remains
  explicitly blocked from activation.

### Phase C — run only boundary-relevant checks and merge the source PR

Use browserless, focused checks. The meaningful minimum is:

1. narrow Rust tests for multi-pool parsing/routing and cross-db token
   isolation;
2. one issuer parser/key-separation test for the exact 2/12/2 shape;
3. positive and mutation-negative render/deployment gate tests for each new
   closed profile; and
4. the existing focused shared-BAT acquisition/selection contract.

Do not add a database build, ORAM bulk build, UKI build, live Lightning node,
production browser or broad repository suite merely to make CI look complete.
Run a broader existing Payment PR profile only if the final code diff crosses a
boundary not covered by the focused checks above.

### Phase D — materialize a private release

After the source PR is merged, a separately authorized ceremony must freeze
the exact commit and current db0/db1 backend roots, render and independently
review both unsigned policies, derive scope IDs, create twelve fresh BAT
lineages and bindings, then sign and independently verify the final canonical
policies. Only after the signed binding digests are final may the ceremony
build and sign the two provider clearing authorizations and the matching two
issuer approvals. The private render plan must bind exact binaries, configs,
store paths and instance identities, rollback-authority client configs,
initialization/check receipt references, service owners and Mainnet risk
limits. It does not claim to hash-lock live SQLite/WAL bytes or a changing
rollback generation.

Before replacing the old Direct Mainnet source profile, inventory whether any
private Direct issuer/provider plan or store was ever materialized or run. If
one exists, stop new issuance and either drain every immutable quote,
claim/recovery horizon or retain the old issuer root/network/payee recovery
instance until that horizon ends. Never blank-initialize over an existing
spend/history store or remote-floor identity.

This phase may prepare inert/stopped artifacts only. It does not authorize UKI
upload/switch/reboot, service start, Web/directory publication, invoice
creation or funds.

### Phase E — deploy and accept one boundary at a time

The later operator sequence is:

1. initialize fresh identities or explicitly verify/quiesce and migrate an
   approved existing store; recovery-test the pir1, pir2 and issuer stores with
   their independent rollback authorities;
2. install the stopped pir1 and issuer bundles on the approved Hetzner host;
3. start pir1 privately, collect its exact evidence, reach the stated stop
   condition and stop it if the approved window requires;
4. start the issuer privately, collect its exact no-funds evidence, reach the
   stated stop condition and stop it if the approved window requires;
5. build and offline-review the exact pir2 UKI under the VPSBG measured-boot
   runbook;
6. upload the approved UKI;
7. switch/reboot to that exact image in its approved window;
8. verify the post-boot measurement, runtime identity, policy and database
   roots before accepting pir2;
9. deploy the matching Web proof/policy pins without directory publication;
10. separately sign and publish the matching directory entries, then read them
    back under the approved directory mode;
11. perform a bounded no-funds readiness check and Free-PoW query canary; and
12. only after an explicit real-value approval, perform a capped Mainnet
    BOLT11-to-BAT-to-query acceptance.

Every numbered action that changes external state has its own approval,
progress signal, hard stop and rollback owner. Success at one action does not
authorize the next. A created but unpaid invoice is not BAT acquisition
evidence; only the separately approved real-value acceptance can make that
claim.

## Explicit non-goals for the source PR

- rebuilding, relabeling or cleaning the accepted db0/db1 database lineage;
- restoring the retired Hetzner warm-fallback listener or port 8092;
- adding Direct BOLT11, Standard Cashu or ARC to a production policy;
- embedding a production secret in a Git artifact, public UKI, CI secret or
  evidence file;
- generating real invoices, funding a wallet, opening channels or sending
  value; or
- claiming that source-ready, rendered, installed, measured, routed and
  real-value-live are equivalent states.
