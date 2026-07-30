# Hetzner Core Lightning path templates

These files are non-activating review inputs. They create no wallet, node
identity, channel or funds, and they do not authorize a remote-host change.
The first persistent identity ceremony, Signet funding, public peer/channel
work, mainnet use and real-value funds each remain separately approved actions.

## Frozen runtime boundary

`lightningd` is launched with exactly one explicit, absolute `--conf` path.
Core Lightning treats an explicit config as the complete file configuration,
so it does not also load mutable `config` files from the base or network data
directory. The rendered file must contain no `include` line. Command-line
arguments contain no RPC password, HSM passphrase, seed, macaroon or other
secret.

The rendered bundle manifest must enumerate and hash every shipped CLN binary,
subdaemon, shared object and the only two allowed plugins. For the pinned
v26.06.6 profile the mandatory executable closure is `lightningd`,
`lightning-cli`, `lightning-hsmtool`, `lightning_channeld`,
`lightning_closingd`, `lightning_connectd`, `lightning_gossipd`,
`lightning_gossip_compactd`, `lightning_hsmd`, `lightning_onchaind`,
`lightning_openingd`, `bcli` and `chanbackup`; omission of any one fails the
rendered-artifact gate. CLI tools and `lightningd` live below `bin/`; the eight
mandatory subdaemons retain the upstream `libexec/c-lightning/` layout that
`lightningd` resolves relative to its own executable. `lightning_dualopend` and
`lightning_websocketd` are deliberately absent: the closed config enables
neither experimental dual funding nor a WebSocket listener. Additional
bundle-local shared libraries may be
enumerated and pinned, but cannot replace that closure. The service performs
strict bundle/config/layout checks before launch, including upstream
`lightningd --test-daemons-only` against the exact rendered config. That probe
executes the mandatory subdaemon version handshake but creates no wallet,
identity or database state. `clear-plugins` removes the
default plugin set; only pinned `bcli` and `chanbackup` are restored as
important plugins. Consequently there is no gRPC, REST, Commando, WebSocket
proxy, recklessrpc, dynamic plugin directory or remote Lightning RPC surface.
The native socket is an administrative CLN RPC surface, not a method-scoped
capability. It is reachable only by CLN, the dedicated preflight supervisor, and
the separately pinned `bitcoinpir-cln-rpc-guard`. The long-running issuer
reaches only the guard's second Unix socket. The guard parses and reconstructs
bounded JSON-RPC and allows exact `getinfo`, private-label `listinvoices`, and
anonymous bounded `invoice` requests; it reconstructs minimal responses and
never forwards a payment preimage. The guard remains part of the Lightning
custody TCB, while compromise of the issuer no longer grants arbitrary CLN RPC.

The exact runtime socket is:

```text
/srv/lightning/@LIGHTNING_NETWORK@/lightning-rpc
```

Provision `/srv/lightning/@LIGHTNING_NETWORK@` as
`bitcoinpir-lightning:bitcoinpir-cln-guard` mode `0710`; render the numeric CLN
UID and guard-only GID into all templates. `rpc-file-mode=0660` yields a socket
owned by that UID/GID and is the cross-UID shape required by the guard's
`UnixClnRpcTransportV1`: final parent `0710`, socket `0660`, no symlink and no
extended ACL. Every regular CLN datastore/secret file remains CLN-owned,
single-link and owner-only; the layout verifier rejects any group/world file
permission.

`cln-rpc-guard-tmpfiles.conf.in` creates guard/issuer mode-`0710` runtime root
and final directories plus the root:root mode-`0700`
`/run/bitcoinpir-lightning-operator-approvals` parent. It deliberately creates
no approval token. The guard creates its downstream
socket as guard-UID/issuer-GID mode `0660`, validates kernel peer credentials,
and fails on a stale or replaced path. The issuer has no guard-native group,
cannot traverse `/srv/lightning`, and cannot bypass the method guard. The
dedicated preflight UID receives both the native CLN group and the
Bitcoin-cookie group; it is deliberately not the issuer UID.

`hetzner-payment-issuer.service.in` is the only renderable issuer unit and is
installed as `bitcoinpir-payment-issuer.service`. It binds the guarded socket
path and requires both the guard and successful live preflight. There is
deliberately no generic or alternate issuer unit: a second runnable template
would make it too easy to bypass either boundary.

## Bitcoin RPC and network boundary

The config fixes Core RPC to loopback and omits all RPC user/password options,
so a password can never appear in the rendered config or process arguments.
Bitcoin Core must create its cookie as bitcoind-UID/`bitcoinpir-bitcoin-rpc`
GID mode `0640` below a bitcoind-owned/group mode-`0710` final directory. Only
CLN and the dedicated preflight UID receive that group; neither the issuer nor
the CLN guard does. The preflight checks the exact EUID/supplementary GID,
canonical no-symlink path, single-link regular file, ACL policy, and metadata
stability around the same open file descriptor. Do not insert an RPC password
into this template or give the cookie group to the issuer.

The P2P bind and announced address are exact rendered values. They are not an
HTTP/RPC service and are not proxied by the Payment V1 edge. DNS discovery is
disabled; peer/bootstrap endpoints must be pinned and reviewed separately.

The current repository preflight deliberately accepts only Bitcoin default
Signet and exact `network=signet`. Therefore `@LIGHTNING_NETWORK@` must render to
`signet` for the first deployment/acceptance phase. Rendering `bitcoin` cannot
activate the issuer: the preflight service fails closed until a separately
reviewed production-mainnet preflight is implemented and real funds are
approved. `testnet`, `testnet4`, custom Signet and persistent `regtest` are not
accepted aliases.

The supplied prerequisite record consequently keeps `network = "UNRESOLVED"`
and `real_funds_authorized = false`. The first rendered acceptance environment
must set the network to Signet; changing that field to `bitcoin` is not a
mainnet approval mechanism.

## Remaining activation gates

The templates require the cross-UID CLN and Bitcoin-cookie validators plus the
method guard; none has a source-level bypass flag. Activation still requires a
Linux rendered-artifact/runtime-evidence pass, exact binary/config hashes,
separate restore rehearsals, and live default-Signet preflight evidence. The
repository preflight deliberately rejects mainnet, custom Signet, testnet and
regtest. Mainnet support, any real-value wallet/channel, remote installation,
and the corresponding custody decision remain separate reviewed and approved
work. A generated node ID or test liquidity is not that approval.

## Bootstrap, backup and activation prerequisites

The first CLN start and issuer activation are intentionally different phases.
The CLN unit requires the global, Signet-staging, Lightning-custody and
identity-restore sentinels. It deliberately does not require issuer activation
or channel-backup restore, because those facts cannot exist before a fresh node
has run and channels have been created. Identity generation/restoration must be
an interactive offline ceremony; never put a mnemonic or HSM passphrase in an
argument, environment variable, render plan, log or receipt.

The V1 live-host format is deliberately narrower than CLN's full key-format
surface: `/srv/lightning/signet/hsm_secret` must already exist as the native
32-byte seed, owned by the Lightning UID/GID with exact mode `0400`, before the
daemon can start. The layout verifier rejects an absent secret, preventing CLN
from silently generating a different identity. Mnemonic containers and
`--encrypted-hsm` require a separately reviewed non-interactive unlock design;
they are not accepted by this Signet profile. Offline backup encryption remains
independent of the live-host file format.

Immediately after the first no-funds start, and before any address, funding or
channel operation, run `bpir-admin lightning-staging bootstrap-preflight`. It
must match the independently derived node ID, exact default Signet, pinned
runtime and plugin closure, and must observe zero peer channels, zero on-chain
wallet outputs, zero funded channels plus an empty `staticbackup`. A non-zero
result is not recoverable by relabelling the phase.

Before the RPC guard, full preflight and issuer activation sentinels are
provisioned, all of the following must then be true and independently recorded:

1. the node identity secret or approved signer seed has an offline,
   restore-tested backup in a separate custody domain;
2. current `staticbackup`/`emergency.recover` material has been exported and
   restore-tested after channel changes;
3. the dynamic CLN datastore has supported live replication, or a cold backup
   taken only while `lightningd` was stopped, plus a restore rehearsal;
4. rollback/failover does not restore stale channel state;
5. the owner-only backup receipt has been written by
   `bpir-admin lightning-staging record-backup-receipt`; and
6. the CLN UID's pre-start layout verifier passes before `lightningd` starts;
   it rejects namespace symlinks, ACLs, unexpected special files, non-private
   datastore files, hard links, and the wrong socket owner/group/mode; and
7. `bitcoinpir-lightning-preflight.service` passes as its dedicated preflight UID against
   the running exact binaries, plugins, Core chain, node identity, channels,
   liquidity, strict cross-UID socket metadata and fresh backup receipt.

The issuer UID cannot traverse the native CLN namespace at all. The dedicated
preflight UID can traverse but cannot list the mode-`0710` CLN directory. For
that reason the live preflight does not rerun the recursive datastore verifier;
it relies on the verifier run by the CLN UID before startup, then exercises the
repository's per-RPC secure path walker and exact socket check as the issuer.
Granting directory read permission merely to rerun `find` would violate the
cross-UID privacy boundary.

`staticbackup` is not a live database backup. `emergency.recover` is separate
encrypted channel-recovery material updated by `chanbackup`; both are distinct
from a dynamic datastore backup. Never copy a running SQLite CLN database. The
global, Signet-staging, Lightning-custody and identity-restore approvals in the
CLN unit, and the additional issuer-activation and backup/restore approvals on
the guard/preflight/issuer units, are operator gates, not cryptographic proof.
The issuer additionally requires both the live preflight lease supervisor and
RPC guard. The supervisor is `Type=notify`, reads the root-owned systemd
InvocationID mapping before and after every full check, renews a private
180-second `/run/bitcoinpir-lightning-preflight/lease.toml` after the initial
pass and after each 20-second sleep, and places the complete renewal under a
cooperative 55-second async deadline. Blocking filesystem calls are bounded by
exact `TimeoutStartSec=120` before the first `READY`, then by the systemd
watchdog. It verifies the
exact pinned `/usr/bin/busctl` and typed system-manager
`ServiceWatchdogs=true` before every round, including the first `READY=1`.
With `WatchdogSec=90` and `Restart=no`, it feeds the watchdog only after a
completed renewal, so a hang is killed before the 180-second lease expires. The guard and issuer both bind to
that process; the guard also requires it and cannot start before its initial
`READY=1`. CLN generation change, renewal failure or watchdog expiry therefore
stops both downstream services. The volatile lease file alone never authorizes
either service.

Every explicit preflight/guard generation requires fresh root-owned regular
mode-`0600` tokens at the exact paths below. Provision both only after reviewing
the intended generation; systemd records each positive condition result and
the first privileged pre-start command atomically removes its corresponding
token. There is intentionally no issuer token.

```sh
install -o root -g root -m 0600 /dev/null \
  /run/bitcoinpir-lightning-operator-approvals/preflight-generation-approved
install -o root -g root -m 0600 /dev/null \
  /run/bitcoinpir-lightning-operator-approvals/guard-generation-approved
```

Do not recreate either token as part of boot, daemon reload, ordinary restart,
or automated recovery. Runtime evidence requires the root-only parent metadata,
the manager-recorded successful token conditions, absent consumed paths, and
typed `ExecStartPreEx` proof that only these two exact `unlink` commands used
the `privileged` execution flag.

Start from `docs/payment/LIGHTNING_STAGING_PREFLIGHT.toml.example` and render
the exact Hetzner paths/hashes/UIDs into
`/etc/bitcoinpir/payment-v1/lightning/preflight.toml`. Install that file as
root:`bitcoinpir-lightning-preflight` mode `0440` below a root-owned,
non-group/world-writable parent; every ancestor must satisfy the same root/no-
write policy. The preflight process must have exactly its primary config group
and the two declared cookie/RPC supplementary groups, with no extras. Its
checksum manifest, plus the `bpir-admin`, layout verifier, CLN bundle and
`lightningd.conf` manifests, are static root-owned deployment inputs. The
config also pins exact `/usr/bin/busctl` owner/path/hash metadata; its digest is
bound to the render plan's `BUSCTL_SHA256`. The
backup receipt is different: the ceremony writes it as preflight-owned mode
`0600` dynamic state below the unit's mode-`0700`
`/var/lib/bitcoinpir-lightning-preflight` `StateDirectory`. The V1 admin binary
pins that exact directory/file and ties its UID/GID to the trusted preflight
reader identity/config group; do not package it under `/etc` or give it a
static checksum manifest.
