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
subdaemon, shared object and the only two allowed plugins. The service performs
strict bundle/config/layout checks before launch. `clear-plugins` removes the
default plugin set; only pinned `bcli` and `chanbackup` are restored as
important plugins. Consequently there is no gRPC, REST, Commando, WebSocket
proxy, recklessrpc, dynamic plugin directory or remote Lightning RPC surface.
The native socket is an administrative CLN RPC surface, not a method-scoped
capability. It is reachable only by CLN, the dedicated one-shot preflight, and
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
and final directories. The guard creates its downstream
socket as guard-UID/issuer-GID mode `0660`, validates kernel peer credentials,
and fails on a stale or replaced path. The issuer has no guard-native group,
cannot traverse `/srv/lightning`, and cannot bypass the method guard. The
dedicated preflight UID temporarily receives both the native CLN group and the
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

## Backup and activation prerequisites

Before the global activation sentinel is provisioned, all of the following
must be true and independently recorded:

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

`staticbackup` is not a live database backup. Never copy a running SQLite CLN
database. The two approval sentinels in the CLN unit are operator gates, not
cryptographic proof; the issuer additionally requires both the live preflight
oneshot and RPC guard, which are bound to the CLN unit lifecycle.

Start from `docs/payment/LIGHTNING_STAGING_PREFLIGHT.toml.example` and render
the exact Hetzner paths/hashes/UIDs into
`/etc/bitcoinpir/payment-v1/lightning/preflight.toml`. The preflight config,
backup receipt, `bpir-admin`, layout verifier, CLN bundle and `lightningd.conf`
all have separate root-owned checksum manifests.
