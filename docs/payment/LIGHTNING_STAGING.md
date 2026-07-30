# Lightning staging strategy

Status: deployment design as of 2026-07-29. This document does not authorize a
remote-host change, persistent Signet identity/wallet/channel, faucet/test-coin
use, mainnet funds or production-key operation.

## Deployment-phase mapping

- **Source merge** keeps disposable local regtest and exact-head CI green.
- **Private no-funds** may validate any approved issuer plan and payload
  entirely offline, but remote installation/start in this phase is edge-only.
  It must not install/start CLN or collect issuer fresh-live evidence: CLN
  startup creates persistent identity/wallet state under `/srv/lightning/signet`,
  which requires the separate Public-Signet custody approval. No public traffic
  is accepted.
- **Public Signet** creates staging-only persistent identities, wallets and
  channels and may acquire test coins, but only under separate approvals for
  remote mutation, persistent custody, faucet/test-coin handling and any public
  ingress or Nostr publication.
- **Production mainnet** is blocked on current source. The implemented
  deployment preflight is default-Signet-specific; no reviewed mainnet
  preflight or render profile exists.

No approval in one phase implies another. Use
[DEPLOYMENT_INPUT_MATRIX.md](DEPLOYMENT_INPUT_MATRIX.md) for non-secret network,
binary, identity and custody inputs and
[render-plan-skeletons/](render-plan-skeletons/) for fail-closed plan shapes.
Neither file authorizes execution or may contain wallet/key material.

## Decision

Payment V1 uses three complementary Lightning test boundaries:

1. **Disposable local regtest** is the deterministic CI and fault-injection
   baseline. It covers three real Core Lightning processes, two announced local
   channels, a payer -> router -> issuer BOLT11 payment, issuer settlement
   observation and browser recovery without accounts, remote infrastructure or
   valuable coins. There is no payer-to-issuer channel, so the payment path is
   forced through the router and exercises actual gossip and multi-hop routing.
2. **Mutinynet** is an optional external interoperability smoke. Its public
   faucet can fund, pay an invoice or open a channel. The separately documented
   Voltage-hosted path uses LND and can provide a deliberate CLN-to-LND check;
   this runbook does not assume an implementation for the public faucet node.
   Mutinynet is a centrally operated custom signet using an experimental
   Bitcoin fork, so it is not the long-lived staging trust anchor.
3. **Bitcoin default signet with three self-controlled CLN nodes** is the
   preferred long-lived staging topology:

   ```text
   payer  --channel-->  router  --channel-->  issuer
   ```

   Two direct, controlled channels remove any dependency on an undocumented
   public signet routing graph while still exercising multi-hop BOLT11,
   confirmations, cross-host transport, node restart and the issuer's checked
   Unix-socket adapter. In V1 both channels must use `announce=true`: the CLN
   invoice adapter fixes `exposeprivatechannels=false` and therefore supplies
   no private-channel route hint. Wait for the required announcement depth and
   confirm that payer gossip includes `router -> issuer` before testing two-hop
   payment. Announced channels expose the three test node identities, topology
   and capacity, so use staging-only identities that will never be reused.

Payment V1 intentionally supports only the frozen `bitcoin`, `testnet`,
`signet` and `regtest` network discriminants. Core Lightning now has a distinct
`testnet4` network identifier, so treating it as the existing `testnet` value
would fail the issuer's exact node-network check. Testnet4 is therefore not a
V1 staging option. Adding it would require separating BOLT11 currency from
exact chain identity in a versioned protocol/schema change, followed by
Rust/WASM/Web/store/formal-lock migration; it cannot be an operator alias. This
is also the conservative operational choice: draft BIP95 (2026-06-22) proposes
Testnet5 as a replacement after sustained Testnet4 difficulty-exception
exploitation made that network hard to use. Testnet3 likewise must not be used
for a new deployment.

Protocol support for the `bitcoin` discriminant is not mainnet deployment
readiness. The only implemented deployment preflight below requires default
Signet constants and `network=signet`; it must fail on mainnet. Do not edit a
Signet config or bypass this probe to create a mainnet profile.

## Network identity must be explicit

BOLT11 human-readable prefixes are `lnbc` for mainnet, `lntb` for Bitcoin
testnet, `lntbs` for signet and `lnbcrt` for regtest. Multiple test networks can
share a prefix; default signet and custom signets both use `lntbs`. An invoice
prefix is therefore not sufficient network evidence.

The current `serve-cln` adapter verifies the configured coarse network name,
the exact `lightning-cli getinfo` payee identity, signed quote-delegation
network/payee bindings and decoded BOLT11 currency/payee. It cannot distinguish
default signet from a custom signet: both CLN and BOLT11 report `signet` /
`lntbs`. The deployment wrapper must additionally verify Bitcoin Core's chain,
the default-signet challenge and the approved peer/bootstrap configuration.
Those external default-challenge checks are a staging gate and are not
currently performed by the issuer executable.

The default-Signet deployment preflight must require Bitcoin Core v29 or newer
and compare both observable constants exactly:

```text
signet_challenge = 512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae
genesis_hash      = 00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6
```

A missing `signet_challenge` field fails closed; V1 does not infer default
Signet from the shared `lntbs` prefix, CLN's coarse `signet` value, DNS seeds or
peer names.

Every staging startup must fail closed unless all of the following agree:

- the configured Bitcoin network;
- the Bitcoin node's reported chain;
- `lightning-cli getinfo`'s exact network;
- the signed quote delegation's network and pinned Lightning payee key; and
- the decoded BOLT11 currency and payee.

Mutinynet additionally requires its exact signet challenge, Bitcoin peer set
and Lightning peers to be pinned. A generic `--network=signet` is not proof
that the node joined Mutinynet.

The Core RPC cookie has an access policy independent of the CLN socket
policy. Omitting `bitcoin.rpc_cookie.access_policy` preserves schema V1's
`same-uid-owner-only` layout: the preflight EUID must equal the bitcoind UID,
the final cookie directory is exact mode 0700, and the single-link cookie is
exact mode 0600. `cross-uid-setgid-shared-group` requires the separate
`bitcoin.rpc_cookie.cross_uid_access` table, a root:root mode-0755 broad
parent (normally `/srv/bitcoin`), exactly one directly nested
bitcoind-UID/cookie-GID mode-2710 setgid network directory, and a
bitcoind-UID/cookie-GID mode-0640 cookie with link count one. The preflight
must run under its separately pinned EUID and have that cookie GID as its
effective or supplementary group. Configure bitcoind with
`rpccookieperms=group` and the cookie-only group so it creates the required
0640 file. Bitcoind keeps its separate primary group and does not receive the
cookie group; the setgid directory supplies the cookie's group inheritance.
The preflight never changes ownership or permissions. The obsolete
`cross-uid-shared-group` cookie-policy spelling and its mode-0710 directory
shape are rejected rather than silently reinterpreted. Bitcoin
Core documents that cookie read access is a powerful RPC trust boundary and
supports `owner`, `group`, or `all` via
[`rpccookieperms`](https://github.com/bitcoin/bitcoin/blob/master/src/init.cpp).

The cookie group must be different from the native CLN RPC group. CLN requires
the cookie group for its bcli plugin; only CLN and the dedicated read-only
preflight supervisor receive it. The long-lived payment issuer and CLN RPC guard must
never list the cookie group in `Group=`, `SupplementaryGroups=`, container
membership, `/etc/group` membership, ACLs, or an interactive login. Grant it
to CLN and with unit-scoped `SupplementaryGroups=bitcoinpir-bitcoin-rpc` on the
preflight lease service; do not add the preflight or issuer account
persistently to that group. Activation evidence must inspect rendered units
and the live issuer, guard, preflight and CLN processes' `Groups:` sets.
Otherwise issuer or guard compromise could gain the much larger Bitcoin Core
RPC authority. Whenever Core uses
cross-UID mode, the config validates Core and CLN daemon owners/groups as
distinct and requires both policies to name the same preflight EUID without
reusing either subsystem's identity fields.

Cookie validation canonicalizes the broad parent, final directory and cookie;
walks every parent component using `O_NOFOLLOW`; applies the platform ACL
policy; and opens the cookie itself with `O_NOFOLLOW`. It checks type,
UID/GID, exact mode, link count and bounded size on the same open file
descriptor before and after reading, rereads that descriptor from offset zero,
requires both bounded reads to match byte-for-byte and equal the pinned size,
validates the cookie format without logging it, then
rechecks the named path and parent namespace. A symlink, hardlink, replacement,
permission/ACL change, truncation or other metadata drift fails closed.
The omitted-policy default is compatible only with a genuinely same-UID Core
layout. If CLN is already split-UID while Core names a different bitcoind UID,
the two required preflight EUIDs conflict and static validation fails; the
operator must add the explicit Core cross-UID table rather than obtaining an
implicit policy downgrade.

The CLN plugin snapshot is also closed: every `plugin list` item must contain
exactly `name`, `active` and `dynamic` with the expected JSON types. The
observed path set must equal the pinned executable allowlist, every plugin must
be active, and every plugin must report `dynamic=false`. Missing or unknown
item fields, duplicate or unexpected paths, dynamically managed plugins and
response-shape drift all fail closed.

The CLN adapter's timeout is one process-local monotonic budget covering
socket metadata validation, connect, complete request write and complete
response read. Filesystem metadata calls cannot be force-cancelled by that
budget. At construction and again before every RPC, the adapter opens every
socket-parent component with `O_NOFOLLOW`, requires trusted non-writable
ancestors and applies the platform ACL policy. A same-UID deployment requires
an effective-user-owned exact mode-0700 final parent and mode-0600 socket (an
explicit matching group metadata pin may also accompany that owner-only
socket). A
cross-UID deployment additionally requires an explicit trusted group, an exact
daemon-owner/group mode-0710 final parent and mode-0660 socket; this permits
traversal and connection but not directory listing or name replacement. It
also checks the final `lightning-rpc` socket's type, UID/GID and device/inode
before and after connect. Deployment preflight
uses the same two socket layouts explicitly: an omitted
`lightning.rpc_access_policy` retains the schema-V1
`same-uid-owner-only` staging policy, while
`cross-uid-shared-group` additionally requires the strict
`lightning.cross_uid_access` table. Cross-UID preflight must run as the exact
configured dedicated preflight EUID with the socket GID present as its effective or
supplementary group. It pins a canonical root-owned mode-0755 broad parent
(normally `/srv/lightning`), one directly nested CLN-owned/group-owned
mode-0710 network directory, and the CLN-owned/group-owned mode-0660 socket.
The same-UID policy instead requires the preflight EUID/socket UID to agree,
an exact mode-0700 final parent, and an exact mode-0600 socket. Both modes
require socket link count one and reject namespace or metadata drift across
the component-by-component validation.

The Core-cookie and CLN-socket parent walks reject symlinks,
writable/untrusted ancestors and extended ACL grants wherever the shared
private-files policy can inspect them. On
macOS this includes the extended ACL checks; the current Linux implementation
is deliberately DAC-only until a reviewed POSIX/NFS ACL parser exists. The
preflight therefore does not claim to detect Linux POSIX/NFS ACL grants and
operators must keep this tree on a local filesystem whose ACL policy is
disabled or separately enforced. Deployment preflight also independently pins
the broader protected executable/configuration boundary.
Keep that tree on a protected local Unix/POSIX filesystem; NFS/FUSE stalls,
another process under the same UID and root compromise are operator
trust-boundary failures. These checks harden local routing but are not
cryptographic CLN peer authentication. After any application byte is written, timeout, EOF,
oversize, framing or JSON failure is outcome-unknown and recovery must use the
same durable label/request rather than a new idempotency identity.

## Phased identity and channel activation

CLN startup and issuer activation are deliberately separate phases. Requiring
a channel-backup restore receipt before the first CLN start would be circular:
the node must run before its node ID can be checked and before any channel
recovery material exists. The checked-in units therefore use these gates:

1. The Core Lightning unit requires the global deployment approval, the
   Signet-staging approval, the Lightning-custody approval and the identity-
   restore approval. It does **not** require issuer activation or channel-
   backup restore approval.
2. With no funding and before any peer/channel mutation, run
   `bpir-admin lightning-staging bootstrap-preflight` against each payer,
   router and issuer. It requires the exact default-Signet chain/genesis,
   configured node ID and CLN version, pinned binaries/plugins, bounded height
   lag, protected Core cookie/CLN socket, zero `listpeerchannels` entries, zero
   `listfunds` outputs/channels and an empty `staticbackup`. It makes only eight
   read-only RPC calls and does not read the later backup receipt or query
   gossip.
3. Record the three resulting public node IDs and compare them with both the
   offline `lightning-hsmtool getnodeid` result and the independently reviewed
   configuration. Identity generation or restore must be interactive: mnemonic
   words or HSM passphrases must never enter argv, environment variables,
   command logs, this repository or deployment receipts.
4. Only after that zero-channel bootstrap result may the separately approved
   Signet faucet/funding and channel ceremony proceed. After every channel
   mutation, export and restore-test current channel recovery material and take
   a supported datastore backup/restore rehearsal.
5. Only the RPC guard, full `preflight` and issuer units require the additional
   issuer-activation and channel-backup-restore approvals. Full preflight then
   checks exact channels, directional liquidity, gossip and the fresh receipt.

`bootstrap-preflight` is a one-way phase gate, not a recovery mode. It fails if
any peer-channel, wallet-output, funded-channel or SCB entry already exists and
must never be used to waive a full preflight after funding or channels exist.
Before the first daemon start, the rendered layout gate also requires the
restored native 32-byte `hsm_secret` with exact owner and mode `0400`; an absent
secret cannot trigger CLN's implicit identity generation. Mnemonic containers
and encrypted-HSM startup are outside this V1 Signet profile. The approval
sentinel files are operator decisions, not cryptographic backup proof; source
preparation does not create them.

## Read-only deployment preflight

This command is a **default-Signet preflight only**. A mainnet deployment needs
a separately versioned implementation with mainnet-specific chain/network,
peer/bootstrap, custody, amount/risk and negative-test policy, followed by
security review. User approval alone cannot fill that missing code boundary.

Before funding, run `bpir-admin lightning-staging bootstrap-preflight --config
<absolute TOML path> --config-protected-parent <absolute directory>
--config-expected-uid 0 --config-expected-gid <preflight gid>
--config-reader-expected-uid <preflight uid>`. After channels and
restore evidence exist, run `bpir-admin lightning-staging preflight --config
<absolute TOML path>
--config-protected-parent <absolute directory> --config-expected-uid 0
--config-expected-gid <preflight gid> --config-reader-expected-uid
<preflight uid>` on each payer, router and issuer host before an acceptance
run. The config must be a root-owned, preflight-group-owned mode-`0440`
single-link regular file directly below a canonical root-owned,
non-group/world-writable directory boundary. Every ancestor from `/` to that
boundary is opened component-by-component with `O_NOFOLLOW` and must also be
root-owned with no group/other write bit; a root-owned file below `/tmp` is
therefore rejected rather than relying on sticky-directory semantics. These trust
arguments are deliberately outside the config, so an untrusted config cannot
declare itself trusted. Start from
`docs/payment/LIGHTNING_STAGING_PREFLIGHT.toml.example`. The command is a
fixed, read-only probe: it calls only Core `getnetworkinfo`,
`getblockchaininfo`, `getblockhash 0` and CLN `getinfo`, `plugin list`,
`listpeerchannels`, `listfunds`, source-filtered `listchannels`, and
`staticbackup`. The bootstrap form calls `listfunds`, requires it and
`staticbackup` to be empty, and does not read a backup receipt or call
`listchannels`. Neither form has an address, faucet, channel mutation, payment,
SSH or remote
execution path.

The production issuer unit does not use a successful `preflight` invocation as
a permanent latch. It runs `preflight-supervisor` as a systemd `Type=notify`
service. Before sending `READY=1`, the supervisor reads the root-owned
`/run/systemd/units/invocation:bitcoinpir-core-lightning.service` symlink,
requires its target to be one canonical non-zero 128-bit lowercase invocation
ID, completes the full preflight, reads the symlink again, and requires the
generation to be unchanged. It then atomically writes a private mode-`0600`
lease at `/run/bitcoinpir-lightning-preflight/lease.toml`. The lease names only
the CLN invocation ID and its check/expiry timestamps; it contains no invoice,
payment hash, node ID, channel state, balance, capability or query data.

The supervisor renews after a 20-second sleep and every lease is valid for
exactly 180 seconds. A cooperative 55-second aggregate async deadline covers
each whole renewal, so the 20-second sleep plus the maximum asynchronous round
leaves 15 seconds before the 90-second watchdog. Blocking filesystem calls are
bounded by systemd rather than Tokio's cooperative timeout: the exact
`TimeoutStartSec=120` covers the first pre-`READY` round, and the watchdog
covers steady-state renewals. Each
renewal first verifies the exact pinned `/usr/bin/busctl` and
the manager's typed `ServiceWatchdogs=true`, then reopens and revalidates the protected static config,
complete runtime group set, binaries/plugins, Core/CLN state, backup receipt
and the CLN invocation mapping before and after the checks. `WatchdogSec=90`
closes a hung renewal before the lease can expire. The guard and issuer each
have a 30-second stop bound, leaving roughly 60 seconds of additional margin
between worst-case watchdog-plus-stop propagation and lease expiry. The
supervisor feeds that watchdog only after a completed renewal, never before
starting one.
Immediately before lease commit it reads wall time again and rechecks the
already-validated backup receipt age, so a forward clock step during RPC probes
cannot extend a newly stale receipt into another lease.
Any mismatch, RPC/config/filesystem/clock/notify/write
failure, CLN restart, or expired watchdog makes the supervisor fail; it never
automatically restarts. Both the RPC guard and issuer `BindsTo=` the supervisor,
so they stop rather than continuing under a stale result. The guard also
`Requires=` and starts after the first `READY=1`, and the issuer starts only
after both. A lease file by itself is never authorization: the active exact
supervisor generation and systemd dependency graph are mandatory. Recovery is
an explicit operator review and service start, not an automatic retry. Each new
preflight and guard generation additionally consumes its own root:root
mode-`0600` token below the root-only
`/run/bitcoinpir-lightning-operator-approvals` directory; there is no issuer
token. This keeps an explicit CLN restart from resetting either downstream
deadman without a fresh ceremony.

Target-host live evidence reads the manager's typed D-Bus `After`, `Before`,
`BindsTo` and `Requires` arrays, initial/final typed
`ServiceWatchdogs`, `ExecStartPreEx`, `WatchdogUSec` and
`WatchdogTimestampMonotonic`, and requires every relationship rendered from
the reviewed units to remain present; implicit systemd dependencies are
allowed. Each watchdog property pass records the immediately following boot
uptime, rejects future or 90-second-stale timestamps, and permits only
nondecreasing timestamps between passes. It also requires the typed
`TimeoutStopUSec` to equal each rendered
`TimeoutStopSec`, and repeats both snapshots in the final lightweight sealing
pass. Therefore an installed new unit with a stale, not-yet-reloaded manager
definition cannot satisfy activation evidence.

The config owner is fixed to UID 0 in V1. `--config-expected-gid` pins the
dedicated read-only service group and `--config-reader-expected-uid` pins the
actual non-root EUID; the reader must have that GID as its effective or a
supplementary group. After the trusted config is parsed, the process's complete
effective-plus-supplementary GID set must equal exactly the config-reader GID
plus the configured cross-UID Bitcoin-cookie and CLN-RPC groups. Missing and
extra groups both fail closed. These values are neither the Core-cookie nor CLN-socket
owner/group. For the published cross-UID example, run the command as the
dedicated preflight UID with its config group plus both unit-scoped
`bitcoinpir-bitcoin-rpc` and `bitcoinpir-cln-guard` groups.
`bitcoin.rpc_cookie.expected_uid/gid` remain the bitcoind UID and
cookie-only GID; `lightning.expected_uid/gid` remain the CLN UID and its
different shared group GID. The dedicated preflight EUID is configured
independently in both cross-UID tables and must agree. None of these identity
sets may be substituted for another.

The preflight fails closed on an unknown TOML field and checks all of the
following before emitting one bounded `result=PASS` line:

- pinned, absolute bitcoind/bitcoin-cli/lightningd/lightning-cli paths,
  SHA-256 values, owners and non-writable executable modes, all below explicit
  protected parent boundaries without writable or symlinked descendants;
- an explicit loopback Core RPC address and non-zero port plus one exact
  `rpccookiefile` path. Same-UID mode requires the exact preflight/bitcoind
  EUID, a mode-0700 final directory and a mode-0600 single-link cookie.
  Cross-UID mode requires the exact preflight EUID plus effective or
  supplementary cookie-only GID, root:root 0755 on the broad parent, exactly
  one bitcoind-UID/cookie-GID setgid 2710 network directory below it, and a
  bitcoind-UID/cookie-GID 0640 single-link cookie. The cookie path is canonical
  and `O_NOFOLLOW`-opened, its parents and ACL policy are checked, and the same
  descriptor's identity/size plus two matching bounded content reads and the
  named namespace are checked before and after access. The cookie is never logged;
  `-conf`, inline credentials, implicit port/cookie selection and non-loopback
  RPC targets are forbidden. Exact empty command-line `rpcuser`/`rpcpassword`
  values must clear any credentials from the automatically read datadir config,
  forcing use of the pinned cookie;
- Core v29+, exact configured subversion, `chain=signet`, the exact default
  challenge and genesis, `initialblockdownload=false`, and bounded header lag;
- exact CLN role identity, version, `network=signet`, height lag and an exact
  active, `dynamic=false` plugin allowlist whose executable hashes are also
  pinned; the plugin response and each item have closed JSON shapes;
- a canonical `lightning-rpc` path with no symlinked component, exact runtime
  EUID and (for cross-UID) effective/supplementary shared-group membership.
  Same-UID staging requires an owner/GID-pinned non-writable tree, exact 0700
  final parent and exact 0600 socket. Cross-UID requires root:root 0755 on the
  broad parent, exactly one CLN-UID/shared-GID 0710 network directory below it,
  and a CLN-UID/shared-GID 0660 socket. Socket link count must be one, and
  owner/mode/inode/link metadata must not drift during validation;
- exactly one connected, reestablished, `CHANNELD_NORMAL`, public announced
  channel per role edge, plus bidirectional active gossip for the required
  edges. In particular the payer must see `router <-> issuer`;
- a bounded `minimum_route_liquidity_msat` between 100,000 and 100,000,000
  msat. Payer requires that much spendable toward router; router requires it
  receivable from payer and spendable toward issuer; issuer requires it
  receivable from router. Missing CLN estimates fail closed;
- a fresh owner-only backup receipt bound to the role node ID and current
  `staticbackup` digest.

The SCB digest is
`SHA256("bitcoinpir-cln-staticbackup-v1\0" || u32be(len) || scb || ...)`
over decoded SCB entries sorted bytewise. The receipt is strict TOML with only
`schema_version=1`, `node_id_hex`, `recorded_at_unix`,
`staticbackup_digest_hex`, `identity_secret_backup_confirmed=true`, and
`channel_state_backup_confirmed=true`. It stores no SCB or wallet secret and
must be mode `0600` below its configured protected parent. A receipt is an
operator assertion backed by the rehearsed external backup domain; its
presence on the live host does not cryptographically prove that an offline
copy is recoverable. The preflight treats `staticbackup` output as recovery
secret material. As a best-effort process-memory control, its owned command
stdout allocation and decoded-entry allocations use zeroizing storage on
success, parse failure, command failure and timeout paths; the JSON view
borrows from that stdout allocation instead of owning another SCB string. No
SCB value is included in `Debug`, preflight stdout or error text. This is not a
forensic-erasure guarantee: the SHA-256 implementation's internal block
buffer, compiler-generated copies, allocator behavior, and subprocess, kernel
or OS buffers remain residual P2 exposure outside those owned allocations.

After the external backup and restore drill, create or refresh that receipt
with the narrowly scoped local ceremony. Before the first ceremony, deployment
must provision `/var/lib/bitcoinpir-lightning-preflight` as the exact preflight
UID/GID at mode `0700`; systemd's matching `StateDirectory=` contract maintains
that boundary for later unit starts. Run the ceremony as that exact preflight
UID with the same config, CLN-guard and Bitcoin-cookie supplementary groups as
the preflight unit and no additional groups:

```text
bpir-admin lightning-staging record-backup-receipt \
  --config /etc/bitcoinpir/payment-v1/lightning/preflight.toml \
  --config-protected-parent /etc/bitcoinpir/payment-v1/lightning \
  --config-expected-uid 0 \
  --config-expected-gid 995 \
  --config-reader-expected-uid 995 \
  --acknowledge-identity-secret-offline-backup-restore-checked \
  --acknowledge-channel-state-recovery-backup-restore-checked
```

Both acknowledgement flags are mandatory. They are deliberately long because
the tool is recording the operator's assertion, not performing the external
backup or restore test. The command reuses the protected config boundary,
validates the pinned `lightningd` and `lightning-cli` files and protected CLN
socket, then calls exactly CLN `getinfo` followed by `staticbackup`. It requires
the reported node ID to equal the configured ID for that host's exact role, as
well as the configured CLN version and `network=signet`. It uses the local
system clock; there is no operator-supplied timestamp option.

The ceremony never prints or writes SCB bytes. It writes only the strict
non-secret digest receipt to `backup.receipt`, which production config places
at `/var/lib/bitcoinpir-lightning-preflight/backup-receipt.toml` under the
preflight-owned systemd `StateDirectory` (directory mode `0700`, receipt mode
`0600`). V1 `bpir-admin` hard-pins that exact directory and receipt path and
requires the configured receipt UID/GID to equal the trusted preflight reader
UID/config-reader GID supplied on the command line; alternate writable state
locations or identities fail closed. The receipt is dynamic state and
therefore is not a rendered `/etc` payload and has no static checksum manifest.
A random same-directory temporary regular file is forced to mode `0600`,
written and synced, then atomically renamed over the prior receipt. The command
takes a nonblocking advisory lock on the opened parent directory, uses
no-replace semantics for a previously absent target, and snapshots/rechecks an
existing target before replacement. Errors before the atomic rename remove a
temporary created by this invocation and leave the prior valid receipt
untouched. An error reported by the parent-directory `fsync` or explicit
unlock happens **after** the namespace commit and therefore has an
outcome-unknown result: the old or new complete receipt may be named and its
durability is not established. The operator must inspect the exact protected
target and rerun the restore-check ceremony; do not assume the old receipt
survived and do not synthesize a second receipt. A power loss has the same
old-or-new complete-file boundary. None of these cases can justify accepting a
partial receipt, and the next preflight still fails closed if the receipt is
missing, stale or mismatched.

Most importantly, a successful ceremony is still only an operator assertion.
It cannot prove that an offline copy exists, that either backup can actually be
restored, or that a supported live/dynamic CLN database backup or replication
stream exists. `staticbackup`/`emergency.recover` is channel recovery material,
not a dynamic `lightningd.sqlite3` backup. Keep the separate datastore-specific
backup/replication and restore rehearsal required below. The command does not
copy `hsm_secret`, signer seeds, SCBs or any CLN database.

Binary hashing plus exact RPC version checks validate the configured Core/CLN
artifacts and each node's self-report. They do not attest either running daemon
process image. The service manager must therefore use the same canonical
pinned daemon paths; process-executable evidence remains a deployment and
manual-acceptance gate.

This preflight deliberately does not call `getpeerinfo`. Its
`spendable_msat`/`receivable_msat` checks are CLN estimates that can change with
HTLCs and on-chain fees; they are not routing or payment proofs. Therefore
`result=PASS` is not evidence that the approved Core peer/bootstrap policy is
active or that 1--100 sat one/two-hop payments are routable. The immutable Core
service configuration and peer/bootstrap set remain deployment-audit inputs,
and acceptance must still execute actual one-hop and two-hop payments required
by the test plan.

As a local no-network field-shape observation on 2026-07-27, Bitcoin Core
31.1's temporary default-Signet node returned the exact challenge and genesis
above, `chain=signet`, and numeric RPC version `310100`. This confirms the
fields used by the preflight but is not public-network or deployment evidence.

## Wallet and channel custody

BitcoinPIR does not need a hosted wallet account. Each persistent staging node
must create its own CLN identity under a dedicated OS user on the final staging
host. Test and future production node identities must never be reused.

Before opening a persistent channel, operators must accept and rehearse:

- one offline backup of the node's `hsm_secret` or configured signer seed;
- an updated `emergency.recover` after channel changes;
- supported live CLN database replication appropriate to the selected
  datastore/plugin, or a file backup taken only while `lightningd` is stopped;
- separate custody for any offline-backup encryption passphrase (the V1 live
  file remains the exact native 32-byte, mode-`0400` format and does not enable
  `--encrypted-hsm`); and
- restore/failover without reverting channel state.

Never copy a running CLN SQLite file as a backup. A stale or inconsistent
channel database can lose test funds and makes a production rehearsal invalid.

Do not generate a production-mainnet node identity until the production host,
signer/HSM boundary, backup domain and real-funds ceremony are separately
approved.

## External test inputs

Local regtest needs no user account or faucet.

For a Mutinynet smoke, use its free GitHub device-OAuth path. Do not use its
L402 option because that spends real mainnet sats. Treat the faucet as a
correlation boundary: it can observe the GitHub identity, IP, node public key,
invoice and timing. Use only disposable identities and synthetic Payment V1
scopes.

For default-signet staging, only after the separate persistent-Signet and
faucet/test-coin approvals, create payer, router and issuer addresses on the
approved staging hosts. A visible public Signet Lightning graph is optional
interoperability evidence, not a routing, liquidity or availability dependency;
the acceptance topology remains the three explicitly connected nodes below. A
minimal routing smoke can start with roughly
25,000 signet sats each for payer and router and two roughly 20,000-sat
announced channels. The 20,000-sat size is a conservative BitcoinPIR staging
policy, not a Core Lightning protocol minimum: the pinned `fundchannel` RPC
accepts amounts down to its current 546-sat dust floor. This budget leaves only
a small on-chain fee and usable-liquidity margin; keep invoices at 1--100 sats
and do not use this minimal topology for destructive recovery drills. The
preferred fault/close/restart allocation remains about 150,000 sats
each for payer and router, each funding a roughly 100,000-sat outbound channel.
An additional 50,000 issuer sats is optional on-chain closing/recovery-test
margin; receiving the two-hop payment does not require it and it does not
create reverse Lightning liquidity. Thus about 50,000 sats can bootstrap the
minimal smoke, while about 350,000 sats is practical and 500,000 sats is a
comfortable upper fault-drill budget. These are budgets, not a promise that a
faucet will provide them. Faucet requests must target fresh staging node
addresses; never import faucet-facing keys into a production-mainnet node.

No real query address, result, payer identity or production capability may be
used in any public-test-network experiment.

## Acceptance sequence

1. Keep `scripts/payment-v1-cln-regtest-e2e.sh` green as a local release gate.
2. On an approved disposable public host, perform one Mutinynet CLN-to-LND
   invoice/payment/status/restart smoke using only test identities.
3. Build the three-node default-signet topology with two staging-only announced
   channels, verify gossip propagation, then verify one- and two-hop payments,
   lost HTTP response recovery, issuer restart, CLN restart, channel outage,
   expiry and exact-price rejection.
4. Test and record the two distinct privacy lanes. For BAT/experimental-ARC and
   other anonymous issuer lanes, the PIR provider must not receive an invoice,
   payment hash, preimage or payer identity. For direct receipt, the PIR query
   wire carries only the signed receipt, but the provider-operated payment
   service intentionally can link invoice to receipt serial; the UI and policy
   must label that method `DIRECT_PAYMENT_TO_SPEND`.
5. Do not run a mainnet canary on the current source. After staging, first
   implement and review the missing mainnet preflight/profile and its negative
   tests; then obtain independent approvals for remote production mutation,
   production-key installation/use and real funds. Public test networks cannot
   prove production wallet coverage or routing.

## Primary references

- [Core Lightning configuration and networks](https://docs.corelightning.org/docs/configuration)
- [Core Lightning `fundchannel` amount and readiness semantics](https://docs.corelightning.org/reference/fundchannel)
- [Core Lightning local regtest example](https://github.com/ElementsProject/lightning)
- [Core Lightning chain parameters](https://github.com/ElementsProject/lightning/blob/master/bitcoin/chainparams.c)
- [BOLT11 payment encoding](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)
- [BIP94: Testnet4](https://github.com/bitcoin/bips/blob/master/bip-0094.mediawiki)
- [Draft BIP95: proposed Testnet5 replacement](https://github.com/bitcoin/bips/blob/master/bip-0095.md)
- [BIP325: signet](https://github.com/bitcoin/bips/blob/master/bip-0325.mediawiki)
- [Mutinynet faucet API and limits](https://faucet.mutinynet.com/llms.txt)
- [Mutinynet Bitcoin fork releases](https://github.com/benthecarman/bitcoin/releases)
- [Voltage Mutinynet LND environment](https://docs.voltage.cloud/dev-sandbox-mutinynet)
- [Core Lightning backup guidance](https://docs.corelightning.org/docs/backup)
