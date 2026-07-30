# Payment V1 deployment input matrix

Status: pre-production input and approval register. This document is not an
activation plan and contains no host-specific values. Remote host changes,
bounded service activation, external Cashu-mint access, public directory
publication, Lightning wallet/channel operations, public routing and real funds
remain separately approved actions.

The purpose of this register is to keep the non-secret deployment facts for a
Payment V1 rollout in one place without turning the repository into a store for
private plans, credentials or correlation data. A deployment owner should copy
this matrix into an owner-only, out-of-repository record and fill one row per
failure domain. The materialized render plans described in
[`render-plan-skeletons/README.md`](render-plan-skeletons/README.md) remain in
the same private operating domain and are never committed.

## 1. Rules that apply before any value is collected

- A provider, issuer, public edge, detailed store and rollback authority are
  separate roles. Co-location must be recorded explicitly; it does not erase a
  failure or correlation boundary.
- Provider 0 and provider 1 are selected independently. No pair ID, peer
  provider, shared request ID, shared token, invoice, payment hash, query
  address or query result belongs in a deployment plan or evidence record.
- Provider-specific operator, policy, receipt, BAT, Cashu custody/recovery,
  shared-clearing and rollback-authority keys remain distinct. A shared issuer
  or Lightning payee is an explicit browser opt-in and a declared correlation
  boundary, not the default topology.
- DPF query, Harmony hint, Harmony query, Onion query and Direct ORAM are
  separate signed scopes. Harmony hint and query roles must not be collapsed
  into one price or entitlement merely because one operator offers both.
- Commercial price and quota decisions live in signed offers/policies. This
  matrix records the selected policy digest and scope bindings; it does not
  invent prices.
- The render gate accepts only the eight closed profiles listed below. The
  `directory-relay-v1` profile is stopped-only: it renders only the bounded
  config and an `ExecStart=/usr/bin/false` unit, carries no binary payload, and
  cannot use the live collector.
- ARC stays experimental and is not enabled by the provider deployment
  profile until its separate cryptographic review and activation decision.
- Every unknown, missing or conflicting trust input is `UNSET` and blocks the
  relevant phase. Approval must never be inferred from a populated hostname,
  public key or digest.

## 2. Deployment phases

Every completed private register names exactly one phase. An approval or PASS
in one row does not imply any later row.

| Phase | Permitted scope after its own approvals | Explicitly excluded |
| --- | --- | --- |
| Source merge | Merge the reviewed source and record exact-head CI/security-review evidence. | Any host mutation, materialized production plan, service start, key use, publication or funds. |
| Private no-funds | Privately materialize/render any approved closed plan for offline review. Remote installation and start in this phase are limited to the `edge-hetzner-v1` bundle and require separate remote-host-mutation and bounded private-service-activation approvals. Collect stopped-edge and fresh-live evidence, then stop the edge and revoke its profile-specific activation sentinel. Provider, issuer and authority bundles remain uninstalled/stopped. | Persistent Lightning identity/wallet/channel state, faucet/test coins, public DNS/Nostr/catalog/routing, production-key use and valuable funds. |
| Public Signet | After separate approvals, create staging-only persistent identities/wallets/channels, handle default-Signet test coins and expose approved staging surfaces. | Production identities, mainnet, real-value funds and any unresolved relay/mint-dependent offer. |
| Production mainnet | No current action is permitted. | The repository has no reviewed mainnet deployment preflight/profile; user approval cannot substitute for that missing implementation and negative tests. |

Remote host mutation, bounded private service activation, persistent Signet
custody, faucet/test-coin handling, public DNS or Nostr publication, VPSBG UKI
build/upload/reboot, production-key installation/use, and mainnet/real-value
operation are independent approvals even when they occur in the same proposed
phase.

## 3. Failure-domain and profile register

Fill a separate instance row for every deployed profile. An exact host may
appear in more than one row only after the co-location and correlated-failure
decision is approved explicitly.

| Profile or maintenance contract | Intended role and failure domain | Required independent inputs | Phase approvals | Required evidence before routing |
| --- | --- | --- | --- | --- |
| `edge-hetzner-v1` | Public Caddy edge plus source-fair HAProxy edge. This process sees client network metadata transiently and must not be the detailed provider/issuer store. | Public bind; four public DNS names; exact private publisher bind/client addresses; Caddy/HAProxy binaries; publisher TLS certificate/key; service UIDs/GIDs. | Remote host change; private publisher ingress; stopped-edge collection; bounded private service activation/fresh start; public routing. | Approved plan/manifest digests; stopped-edge evidence digest; fresh-live evidence digest; WebPKI/DNS/firewall checks; exact Caddy and HAProxy version/hash evidence. |
| `bhtm-caddy-admin-uds-v1` | Non-rendered cold-maintenance prerequisite for the exact existing root `bhtm-caddy.service`; removes the TCP admin listener, closes service core/swap/output paths and restricts the admin UDS by root-owned DAC metadata. This does not isolate UID 0 or `CAP_DAC_OVERRIDE`. The checked-in local-host executor is source-hash closed but neither installed nor approved to run. | Exact old Caddyfile/unit/`/usr/local/bin/caddy`/active generation; approved canonical old adapted-JSON digest/size equal to the live TCP-admin readback; loaded old fragment/Exec commands with `NeedDaemonReload=no`, no drop-ins or environment files; deterministic candidate hashes; exact cold executor, gate, probe, Node 22.22.2, `setpriv` and systemd 255 pins; same-boot privileged process/capability evidence; canonical hash-bound public/direct/TLS site-probe inventory; complete ACME and non-root service-UID inventories; candidate canonical adapted-JSON digest/size proving no explicit log sink; exact old rollback bytes. | Separate remote host mutation; cold Caddy outage; explicit existing-site and lost-Caddy-diagnostics risk acceptance; transaction-executor/outage approval; separate prior `kernel.core_pattern=|/usr/bin/false` ceremony; real-systemd-PID1 lifecycle gate; activation and rollback authority. | New nonzero 32-lowercase-hex systemd InvocationID; effective `LimitCORE=0`, `MemorySwapMax=0`, `StandardOutput=null` and `StandardError=null`; exact host `kernel.core_pattern=|/usr/bin/false`; no drop-ins, `CADDY_ADMIN`, `--environ`, imports, environment substitutions or configured log sinks; exact adapted UDS JSON; root API canonical readback digest equal to the candidate; root:root `0700` runtime directory and `0200` socket; IPv4/IPv6 TCP 2019 refused; every inventoried non-root UID gets `EACCES` with `CapEff=0` and cleared groups; all public/direct/TLS site probes before/after; durable canonical committed receipt. |
| `integrated-existing-bhtm-caddy-v1` | Alternative append-only overlay for the exact existing root `bhtm-caddy.service`, plus source-fair HAProxy. It widens Payment V1 trust/failure/privacy scope to all existing Caddy global options, ACME state and sites; it is never evidence that those controls were otherwise hardened. | Canonical owner-only committed `bhtm-caddy-admin-uds-v1` receipt whose binary/config/unit/InvocationID equal this overlay's exact preimages; managed Caddy block; exact admin-UDS gate/probe, overlay gate/executor and Node pins; content-addressed rename-exchange helper and manifest; HAProxy bundle/runtime pins; four distinct DNS names; public bind; distinct RFC1918/ULA publisher bind/client route; WebPKI publisher certificate/key; sealed transaction parents. The currently inspected host lacks that private route. | Separate remote host change; explicit existing-root-Caddy risk acceptance; private-route provisioning; private publisher ingress; source-fair fresh start; one reload transaction; public routing. | Approved hardening/receipt/render/overlay-plan digests; distinct exact hardened-preimage and overlay-candidate adapted-JSON pins; exact Caddyfile/helper pins; no configured Caddy log sink and null effective service streams; append-only phase journal and atomically published terminal receipt; same hardened Caddy PID/InvocationID/active generation; WebPKI+hostname+leaf and WebSocket-accept health proofs; separate cold-edge evidence. A warm overlay receipt cannot replace stopped-edge/fresh-start evidence. |
| `edge-rollback-authority-v1` | Private TLS edge for exactly one rollback-authority client. It is network-specific and lives with the authority, not the protected detailed store. | Private bind; sole client private address; WebPKI hostname/certificate/key; Caddy binary; service UID/GID; WireGuard or equivalent routed boundary. | Authority-host change; sole-client private ingress; fresh start. | Plan/manifest/runtime digests; exact client-address/firewall evidence; leaf SPKI pin readback from the client configuration; TLS hostname/readiness evidence. |
| `issuer-lightning-signet-v1` | Payment issuer, Core Lightning, CLN RPC guard and read-only default-Signet preflight. This domain knows invoices/payment hashes and must never receive PIR queries. | Exact Core/CLN/admin/guard/issuer binaries; default-Signet topology; Lightning payee key; quote delegation; issuer keys/policies; protected stores; four service identities; backup/restore records. | Remote host change; Signet identity/wallet creation; test-coin receipt; channel changes; custody approval; backup/restore approval; issuer activation. | Plan/manifest/runtime digests; default-Signet preflight; exact node/network/payee readback; CLN/Core binary/config pins; guard deadman state; store and independent rollback-floor evidence; backup/restore rehearsal. |
| `provider-v1` | One logical PIR provider and its detailed ProviderStore. This checked-in unit is a zero-retained clean-activation profile. | Provider identity/server ID; provider/operator/policy keys; one signed current policy; database catalog/root pins; unified server binary; provider-local BAT/Cashu/clearing material; issuer settlement trust; rollback authority; service UID/GID. | Remote host change; database/policy acceptance; provider activation; directory publication. | Plan/manifest/runtime digests; explicit absence of retained-policy flags/payloads; binary and database proof pins; current method-coverage startup pass; store/rollback-floor backup and restore evidence; strict client query verification; signed directory-event readback. |
| `provider-no-standard-cashu-v1` | One logical PIR provider whose current policy omits Standard Cashu. It is a zero-retained alternative closed profile, not a field-deleted `provider-v1`. | Separate unit/NSS identity/state/config roots; provider identity/server ID; provider/operator/policy keys; one signed current policy with no Standard Cashu offer; database catalog/root pins; unified server binary; provider-local BAT and shared-clearing material; issuer settlement trust; owner-only rollback config/client-signing/value-root secrets; service UID/GID. No retained policy or Cashu recovery/custody/exposure input is accepted. | Remote host change; database/policy acceptance; no-Standard-Cashu provider activation; directory publication. | Plan/manifest/runtime digests; absence of retained-policy and Standard-Cashu flags/material; current-policy Cashu/method coverage startup pass; binary/database/store/rollback/client/directory evidence equal to the provider row. |
| `provider-direct-v1` | One logical PIR provider whose current policy is limited to Free open-best-effort, Free proof-of-work, provider-local Free anonymous ticket and direct BOLT11 receipt. It is zero-retained. | Separate unit/NSS identity/state/config roots; provider identity/server ID and policy key; one signed matching current policy; database catalog/root pins; unified server binary; owner-only rollback config/client-signing/value-root secrets; service UID/GID. No retained policy, BAT, Standard Cashu, shared issuer, ARC or Free-IP material is accepted. | Remote host change; database/policy acceptance; direct-provider activation; directory publication. | Plan/manifest/runtime digests; exact nine-payload and zero-retained closure; current-policy coverage pass; binary/database/store/rollback/client/directory evidence equal to the provider row. |
| `rollback-authority-v1` | One independent monotonic rollback authority. Each provider and issuer uses its own authority instance and backup/administrative domain. | Authority public key; binary; private authority seed in its protected input domain; authority metadata; service UID/GID; independent store/backup owner. | Independent host change; authority identity ceremony; authority activation; protected client registration. | Plan/manifest/runtime digests; public-key readback; monotonic CAS/restart/restore drill; independent backup-domain record; private-edge evidence. |

VPSBG's existing measured provider is intentionally outside these seven render
profiles. Its Free/PoW Payment V1 argument fragment, UKI measurement, upload,
reboot and client-pin migration retain their separate ceremony. Do not place a
Hetzner issuer, mint, relay or rollback authority into that failure domain just
to simplify the plan.

That VPSBG fragment selects only the exact-pinned storeless Free-PoW runtime.
Record both the ordinary policy-file SHA-256 and the distinct
`ServicePolicyV1::policy_digest()` over complete signed canonical bytes. The
latter must be a literal measured launch input; policy renewal, expiry extension,
difficulty, scope, dataset, limit or any signed-byte change requires a new UKI,
fresh attestation measurement and client pin migration. No ProviderStore,
rollback client, retained policy, Free-IP state or payment/credential input is
valid in this profile.

## 4. Non-secret input register

The following values are safe to review as public or operational metadata, but
the completed record can still reveal topology. Keep the materialized register
owner-only and disclose only the minimum approved subset.

| Input class | Exact facts to record | Owner / independent reviewer | Binding and rejection rule |
| --- | --- | --- | --- |
| Source | Merged 40-hex commit, approved base, exact-head CI URLs/conclusions, render-gate script digest, runtime-evidence collector digest and Node/toolchain versions. | Release owner / security reviewer. | The external plan-approval record and every evidence record name the frozen source. Schema-v1 plans instead bind exact template source hashes and payload bytes; they do not contain a source-commit field. A later source, gate or collector byte requires a new review and digest ceremony. |
| Deployment identity | Unique `deployment_id`, one closed `deployment_profile`, target environment, logical role and change ticket/approval handle. | Deployment owner / change approver. | Profile changes are not aliases. Cross-profile artifacts or an unreviewed directory-relay profile fail closed. |
| Failure domain | Host/provider account, administrator group, detailed-store location, rollback-authority location, backup account/media and whether any role is co-located. | Infrastructure owner / privacy reviewer. | Co-location and shared administrators are declared correlations. Detailed stores and their rollback floors must have independent restore domains. |
| NSS identity | Exact service unit, user, group, numeric UID/GID, supplementary groups, locked-login state and local-files NSS source. | Host owner / runtime-evidence reviewer. | Numeric identities in a skeleton are examples only. Runtime values must exactly match the externally approved plan and the effective service processes. |
| Public origins | Canonical Web HTTPS origin; provider public WSS origin; issuer HTTPS origin; public directory WSS origin; private publisher HTTPS hostname; rollback-authority HTTPS hostname. | Product/network owner / trust reviewer. | Credential-free canonical origins only. Scheme, host, port and path are signed/pinned where required; redirects or ambient defaults are rejected. |
| Address boundary | Public numeric bind; publisher private bind and sole client IP; authority private bind and sole client IP; expected IP family; WireGuard/private-route identifiers; anti-spoofing and firewall rule evidence. | Network owner / independent network reviewer. | Public/private/client addresses are distinct. Private roles require RFC1918/ULA addresses and exact sole-client enforcement; hostname alone is insufficient. |
| TLS pins | WebPKI hostnames, certificate chain/expiry, leaf SPKI SHA-256 pins where the application client requires them, certificate rotation overlap and readback evidence. | TLS owner / client trust owner. | Store public certificate/SPKI metadata only. A private key, ACME account credential or DNS API credential is forbidden. Pin rotation requires matching client/config evidence before traffic. |
| Provider identity | Stable server ID, operator Ed25519 public key, derived provider ID, policy signing public key, identity-certificate public fields and binary/attestation pins. | Provider operator / client trust reviewer. | Recompute provider ID from the reviewed operator key and stable server ID. The two PIR legs cannot reuse an operator key, provider ID, policy key or WSS origin. |
| Policy and workload | Signed policy digest, scope IDs, database IDs/fingerprints, database proof/trusted root, backend/workload, Harmony hint/query split, accepted methods, price/entitlement and `priority_class`. | Provider commercial owner / protocol reviewer. | Price is policy, not protocol state. Every advertised method must pass runtime material coverage; initial V1 offers use `priority_class = 1`. |
| Issuer identity | Issuer ID/public root, exact issuer HTTPS origin, quote-delegation digest/public key, direct-receipt public key, settlement public key and issuer policy bindings. | Issuer owner / provider and browser trust reviewers. | Issuer metadata never substitutes for provider identity. Provider clearing authorization/approval must bind the same reviewed issuer origin and keys. |
| Lightning topology | `signet`, exact issuer payee node public key, payer/router/issuer staging node roles, announced channel edges/capacity floor, Core chain/challenge/genesis, peer/bootstrap policy and routing test evidence. | Lightning custody owner / independent staging reviewer. | BOLT11 prefix alone is not network evidence. The current profile is default-Signet only; mainnet and custom signets require a separately reviewed profile. |
| Cashu topology | Approved production mint ID, canonical HTTPS endpoint, unit, keyset IDs/public keys, certificate/SPKI pins, custody/recovery epochs, exposure limits and outage/retirement policy; or explicit omission from the current policy and every retained signed policy in a future profile that permits retention. | Mint/provider owner / Cashu reviewer. | Record only public keyset and policy metadata. Mint seed, unspent proofs, blind factors and recovery ciphertext are forbidden. Local CDK, fake-wallet and loopback mints are test evidence, never production selection. The checked-in provider profiles are zero-retained; a provider must not advertise Cashu without complete pinned material. |
| Shared issuer topology | Per-provider clearing authorization/approval digests, operator public key, issuer settlement public key, minimum authorization epoch and whether browser issuer/payee-sharing opt-in is required. | Provider and issuer owners / privacy reviewer. | Provider 0 and provider 1 use independent authorization and idempotency material. Never create a pair ID or shared raw credential. Shared issuer/payee is surfaced as correlation risk. |
| Binary payload pins | SHA-256 of exact Caddy, HAProxy, Core, CLN bundle members, `bpir-admin`, guard, issuer, provider and rollback-authority bytes plus source/build provenance. | Build/release owner / binary reviewer. | Compute from staged regular files, not documentation. Every digest path and one-entry/closed manifest must agree. Test or repeated-digit hashes are not production evidence. |
| Configuration and policy pins | SHA-256 of exact rendered configs, signed policies, quote delegation, clearing artifacts, rollback client configs, database catalog and backup receipt. | Role owner / plan reviewer. | Review canonical bytes before hashing. A digest records bytes; it does not approve their semantics or prove installation. |
| Persistence | Store path role, filesystem/ACL policy, backup method, WAL/SHM handling, independent rollback floor, recovery generation/commitment and restore authority. | Data owner / recovery reviewer. | Do not record database contents. A store and its rollback authority cannot share one restore snapshot/domain. Stale restore or lower floor fails closed. |
| Render ownership | Every rendered/payload target, artifact class, owner UID/GID, mode, staged relative input name and source digest. | Deployment preparer / independent plan reviewer. | Private inputs are single-link regular files under an owner-only root. Secret targets are mode `0400` and owned by their one exact consuming service; each installed final parent is that service EUID's exact mode-`0700` directory, with loader-compatible ancestors. |

## 5. Approval matrix

An approval record contains only the action scope, exact plan/source/evidence
digests, approved organizational role or signing-key identifier, timestamp and
result. It does not contain a credential, personal identifier or command-line
secret. A later phase cannot retroactively supply an earlier approval.

| Gate | Minimum approved statement | Blocks until present | Does not authorize |
| --- | --- | --- | --- |
| Source freeze | Exact merged commit and exact-head CI/security-review result are accepted for this profile. | Any plan rendering. | Host access or deployment. |
| Plan digest | Canonical digest of the complete private materialized plan was independently recomputed and accepted. | Bundle rendering/verification. | Installing the bundle. |
| Remote host mutation | Exact host/profile/change window and rollback owner are approved. | File installation, account creation or service-manager changes. | Service activation, public routing, persistent Signet state, UKI mutation, key use or funds. |
| Bounded private service activation | Exact host, render profile, unit set, plan/manifest digests, synthetic/no-funds inputs, unrouted/private listener boundary, start/stop window, evidence collector and rollback owner are approved. Provision the global sentinel and that profile's exact role-specific sentinel set only for the approved window, then stop the units and revoke the role-specific set. | First start or fresh-live collection for those exact units while the complete sentinel set is present. | Any other profile/unit, use of a different profile's sentinel, persistent Signet identity/state, faucet/test coins, production-key use, public DNS/Nostr/routing, mainnet or funds. |
| VPSBG UKI build/upload/reboot | Exact source, measured inputs, expected UKI/client pins, portal action, reboot window and rollback image are approved. | Any VPSBG UKI build intended for deployment, upload, selection or reboot. | Hetzner changes, public routing, key use or funds. |
| Private ingress | Exact private bind, sole client, route and anti-spoofing/firewall boundary are accepted. | Publisher or rollback-authority edge start. | Public ingress. |
| Persistent Signet identity/custody | Exact staging-only node identities, wallet/channel custody owners, peers, backup domains and channel mutation plan are accepted. | Persistent default-Signet identity/wallet creation and channel open/close/change. | Requesting test coins, public exposure, production-key use, mainnet or real funds. |
| Signet faucet/test coins | Exact staging wallet, faucet/source, bounded test-coin amount, purpose and disposal record are accepted. | Requesting, receiving, spending or forwarding Signet test coins. | Persistent identity/channel mutation unless its separate gate passed; mainnet or real funds. |
| Production-key installation/use | Exact role, public key ID, host/failure domain, installation target, intended signing/decryption action, rotation owner and rollback are accepted. | Installing, loading or using a production Nostr/provider/issuer/TLS/custody key. | Relay selection, publication, routing, Signet custody, mainnet or funds. |
| Production Cashu mint selection | Exact production origin, WebPKI/leaf pins, unit, public keysets, custody/recovery epochs, exposure caps and outage/retirement policy are accepted. If mint-dependent offers are omitted from the current policy, record that omission and do not materialize or activate `provider-v1`: its closed unit and skeleton always carry Standard-Cashu inputs. Select exactly `provider-no-standard-cashu-v1` when BAT/shared issuer are required, or `provider-direct-v1` when only its built-in Free/direct routes are declared. Both checked-in catalogs are zero-retained and reject Standard-Cashu inputs; the Cashu validator checks the configured current policy. Local CDK/fake/loopback mints do not satisfy this gate. | Materializing mint-dependent provider fields, rendering `provider-v1` without mint approval, or advertising a Standard Cashu offer from either no-Standard-Cashu profile. | Contacting the mint, transferring value or public publication. |
| External Cashu mint access | Exact approved mint, operation, value/exposure budget, network window and recovery owner are accepted. | Connecting to, issuing from, redeeming with or otherwise mutating an external mint. | Adding an offer whose selection/policy gate did not pass. |
| Backup/restore | Independent store, authority, Lightning identity/channel and datastore recovery drills have passed. | Issuer/provider/authority activation. | Restoring an older production snapshot. |
| Stopped-edge | Cold stopped-edge evidence digest passed out-of-band verification. | First HAProxy/Caddy start, together with the separate bounded private-service-activation approval. | Service activation by itself, routing traffic or any later phase. |
| Stopped relay preparation | The `directory-relay-v1` plan/manifest and v2 stopped-relay evidence digest passed out-of-band verification; config metadata is exactly UID 62951, GID 62952, mode 0400 for the real loader, its final parent is consumer-owned mode 0700, the real EUID access probe passed, and typed `a(sbbsi)` Conditions prove selection remains unresolved. | Review of installed blocked-unit/config shape only after a separately approved installation; it never permits a start. | Relay selection, `RESOLVED`, binary installation, live evidence, key use, listener start, routing or publication. |
| Fresh-live | Exact fresh runtime-evidence digest and readbacks passed. | Directory publication or route change. | Future restart generations. |
| Relay selection | Current state is `UNRESOLVED`. It passes only after exact relay source/commit, canonical archive digest, archive-contained `Cargo.lock`, digest-pinned Linux-amd64 Git/Tar versions, reproducible-build manifest, two byte-identical clean Linux-amd64 builds, two gate-private verifier rebuilds, closed-world descriptor fast seals before/after publication, full verification of the published path, selected binary/version, config bytes, publisher-key pin, explicit `strict-multi-relay` or `centralized-single-relay` mode, failure-domain declaration and an independent clean-host/operator reproduction are recorded. Centralized mode records its degraded acceptance; strict origin count is not evidence of independent operators. | A reviewed PR may replace the blocked unit only after the artifact verifier and independent reproduction pass. The same-EUID build output is preparation evidence only; installation requires independently pinned digests and a separately reviewed root-owned target that the build EUID cannot modify. | Treating two builds on one Docker daemon as independent supply-chain consensus; treating fast seals as protection against the invoking EUID or root after PASS; installation, live evidence, production-key use, listener start, event publication or routing. |
| Directory publication | The relay-selection and fresh-live gates passed, and the exact signed non-secret provider events, selected relay destination(s), explicit directory mode, publisher key/action and mode-matched readback plan are approved. Strict mode requires `2..8` distinct exact credential-free WSS origins with no path; centralized mode requires exactly one and remains visibly degraded. | Public Nostr event submission. | Advertising an inactive method/scope, DNS change, automatic mode fallback or later event. |
| Public routing | Exact provider/issuer/edge endpoints and rollback procedure are approved. | DNS/firewall/load-balancer exposure. | Mainnet charging. |
| Mainnet implementation | `BLOCKED_UNIMPLEMENTED`: a versioned mainnet profile/preflight, mainnet-specific chain/network/custody checks, negative tests and security review do not exist. | Any mainnet plan, wallet/node connection, invoice, route, canary or service claim. | User approval cannot satisfy or bypass this technical gate. |
| Mainnet/real-value operation | `BLOCKED_BY_MAINNET_IMPLEMENTATION`; after that implementation passes, an additional exact wallet/payee, operation, amount/risk cap, time window, custody owner and rollback/refund decision must be approved. | Sending, receiving or putting at risk any real Lightning/Cashu value. | Production software readiness, key installation, routing or future payments. |
| Manual acceptance | User verified strict provider identity, secure channel, database proof/root, tree tops, payment acquisition/admission and result inclusion behavior. | General availability. | Relaxing fail-closed behavior. |

## 6. Evidence register

Use `UNSET` until the exact artifact exists. Do not paste evidence bodies into
this repository.

| Evidence field | Value recorded out of repository | Required cross-check |
| --- | --- | --- |
| Source head | Commit plus CI/workflow URLs and independent review conclusion. | Commit is reachable from approved base and equals the built source. |
| Canonical plan | Deployment ID/profile and externally approved plan SHA-256. | Independent recomputation over strict parsed canonical JSON. |
| Rendered bundle | Manifest SHA-256 and deterministic second-render result. | Gate `verify` passes against the same plan, source and private inputs. |
| Host identity | Expected machine-ID digest and, for live evidence, exact boot ID. | Matches the intended failure-domain row. |
| Stopped edge | Full-file evidence SHA-256 and offline verification result. | Both edge services are stopped and listeners absent before first start. |
| Stopped relay preparation | Full-file v2 stopped-relay evidence SHA-256 and offline verification result. | The sole relay unit is loaded but inactive/dead, has exactly `/usr/bin/false`, has no `ExecStartPre`, typed `a(sbbsi)` Conditions prove `RELAY-SELECTION-RESOLVED` absent, config UID/GID/mode are 62951/62952/0400, the config is consumer-readable under a descriptor-bound 0700 final parent, and no protected UID/GID holder exists. Live evidence is forbidden while selection is unresolved. |
| Fresh live | Full-file evidence SHA-256, collection time and offline verification result. | Exact units, files, NSS, ACLs, capabilities, process identities and runtime paths match the manifest. |
| Network/TLS | DNS/WebPKI/SPKI/private-route/firewall readback record. | Exact origin and sole-client pins agree with policy/client configs. |
| Provider strict path | Browser/native acceptance record for identity, attestation where available, binary pin, secure-channel upgrade, database proof/root, tree tops and inclusion verification. | Any failed strict check closes the attempt; no plaintext/free downgrade. |
| Payment topology | Issuer/payee/mint public identities and sharing declaration. | No invoice/payment hash/preimage/query linkage appears in provider evidence. |
| Store recovery | Backup/restore rehearsal and rollback-floor generation/commitment comparison. | Store and authority restore domains are independent; neither floor decreased. |
| Lightning staging | Default-Signet preflight, backup receipt digest, route/payment/reconciliation/restart evidence. | Exact Core/CLN/payee/network pins agree; no mainnet claim. |
| Cashu mint | Production selection approval and exact origin/pins/unit/keysets/custody/exposure evidence, or an explicit record that mint-dependent offers were omitted from the current policy, `provider-v1` was not materialized/activated, and the exact zero-retained `provider-no-standard-cashu-v1` or `provider-direct-v1` plan/runtime evidence passed. | Local CDK/fake/loopback evidence cannot satisfy production selection. External mint contact requires separate approval; neither no-Standard-Cashu profile authorizes or configures it. |
| Relay selection | `UNRESOLVED` until source/commit/canonical archive/archive lockfile/pinned Git-Tar versions/build-manifest/two-clean-build binary/version/config/publisher-key pins, explicit directory mode, failure-domain declaration and independent audit are recorded. | `payment-v1-directory-relay-artifact-gate.mjs verify-selection` must recompute every byte binding; directory installation/publication cannot advance while this field is `UNRESOLVED`, and centralized mode must remain visibly degraded. |
| Directory publication | Signed event IDs and mode-matched relay readback after relay-selection and fresh-live approval. | Event policy/origins/pins and strict-multi versus centralized-single choice equal the active verified service and approved publisher action. |
| Rollback | Previous known-good manifest/runtime evidence and rollback decision owner. | Rollback changes routing/binary generation without stale store restore or lower authority. |

## 7. Forbidden sensitive fields

The following material must never appear in this matrix, a render plan, Git,
PR/CI output, evidence JSON, shell history, directory/Nostr events or ordinary
application logs. A digest or public key may be recorded only where the tables
above call for it.

| Forbidden material | Why it is forbidden / approved handling |
| --- | --- |
| BOLT11 invoices, payment hashes, preimages, payer identities, wallet labels, route details tied to a quote, or invoice status exports | They can link settlement to acquisition or a query. Keep only inside the issuer's protected durable store and wallet boundary for the minimum required lifecycle. |
| Lightning `hsm_secret`, signer/wallet seeds, macaroon/rune material, Core RPC cookies, SCB bytes, dynamic datastore backups, private channel backups or wallet credentials | Custody secrets. Use the dedicated encrypted backup/restore domain; record only approved public identities and receipt/digest evidence. |
| Provider identity private keys, operator/policy signing seeds, issuer quote/receipt/settlement keys, BAT raw private keys, ARC secret keys, Cashu mint seeds, custody/recovery/idempotency keys, rollback-authority seeds, rollback client request-signing seeds/value-root keys or TLS private keys | Role secrets. Stage as owner-only payload files outside the repository; the plan contains only relative opaque source labels, target metadata and expected digests. |
| Cashu unspent proofs, bearer tokens, blind factors, DLEQ secrets, recovery bundles, ARC credentials, BAT capabilities, direct receipts or authorization presentations | Bearer/privacy-sensitive authorization material. Never use them as deployment fixtures or evidence. |
| PIR query addresses, DPF shares, Harmony hints tied to a user, Onion/ORAM requests, returned records, Merkle paths tied to a request, provider pair IDs or browser vault contents | Query privacy material. Deployment evidence proves process/config state, not user traffic. |
| Raw issuer/provider SQLite files, WAL/SHM files, spent sets, invoice tables, timing logs, IP/source tables or database backups | Durable correlation and authorization state. Use protected backup/recovery procedures and record only non-sensitive commitments/status. |
| SSH private keys, passwords, API tokens, DNS/ACME credentials, cloud account identifiers, faucet/session tokens, authentication cookies or approval signing credentials | External control-plane secrets. Keep in the approved credential manager and never substitute them for an approval handle. |
| Real local absolute private-input paths, usernames/home directories, secret filenames outside the reviewed installation catalog, internal ticket contents or personal identifiers | They are unnecessary for deterministic rendering and leak operator topology. Plans use relative names beneath an explicitly supplied owner-only input root. |
| Exact client IPs observed from production traffic or request timestamps/ordering correlated across issuer and provider | Correlation material. Edge source state is bounded and ephemeral; evidence must not include traffic records. |

If forbidden material reaches Git, CI, a PR, an evidence transfer or a public
relay, stop the phase and treat it as an incident. Do not attempt to make the
artifact safe merely by deleting a later commit; rotate or invalidate the
affected secret/capability and follow the repository/hosting retention policy.

## 8. Minimum phase handoff

For each phase, hand the next reviewer only:

1. the selected closed profile and non-secret failure-domain row;
2. frozen source and tool digests;
3. the canonical plan digest through an independent channel, not the private
   plan itself unless that reviewer is authorized for the private plan;
4. the relevant full-file evidence digest plus an authorized offline copy;
5. explicit approval handles for the exact next action; and
6. unresolved fields, written as `UNSET`, that keep later actions blocked.

This handoff deliberately separates source review, plan approval, installation,
activation, public routing, directory publication, Lightning custody and manual
acceptance. Passing one gate never silently passes another.
