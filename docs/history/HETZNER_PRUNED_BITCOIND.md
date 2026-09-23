# pir1 pruned Bitcoin Core (operator log)

Live host state is still queried, not inferred:
`scripts/production-status.sh`. This file is the operator log for the
pir1 pruned-Core install. It is not a Payment V1 activation, not a CLN
deploy, and not permission to fund anything.

Query Core (after the cookie exists; do not print the cookie):

```sh
ssh -o UserKnownHostsFile=deploy/known_hosts \
    -o StrictHostKeyChecking=yes -o BatchMode=yes \
    root@65.21.91.217 \
    'sudo -u bitcoinpir-bitcoind /opt/bitcoinpir/bitcoin-core/*/bin/bitcoin-cli \
      -datadir=/srv/bitcoin -rpcconnect=127.0.0.1 -rpcport=8332 \
      getblockchaininfo'
```

## Scope

Authorized 2026-08-31: prune-from-start on pir1, Core only, CLN later.

| Decision | Value |
| --- | --- |
| Host | pir1 (`65.21.91.217`), same box as `pir-primary` |
| Mode | `prune=10000` from first start; never archival-then-prune |
| Disk floor | stop bitcoind if `/` available **&lt; 80G** (protects `/home/pir/data`) |
| RPC | loopback, cookie only, port 8332 |
| P2P | listen 8333 (UFW allow) |
| Wallet | disabled |
| CLN / issuer / funds / sentinels | **out of scope** |

Templates stay **off** `deploy/payment-v1/` so the closed Payment tree
gate is unchanged. Installed files live on the host; exact text is
copied below.

## Status

| Phase | State | When (UTC) | Evidence |
| --- | --- | --- | --- |
| 0 decisions | done | 2026-08-31 | this file |
| 1 repo templates | skipped | 2026-08-31 | would break `payment-v1-deployment-template-gate` unreviewed-path check |
| 2 users/dirs/unit, no start | done | 2026-08-31T01:29Z | UID 980 / cookie GID 981; `/srv/bitcoin` mode 2710; unit inactive until Phase 3 |
| 3 start IBD | done | 2026-08-31T01:30Z | `bitcoinpir-bitcoind` active+enabled; UFW 8333; RPC 127.0.0.1:8332; cookie 0640 single-link |
| IBD caught up | done | 2026-08-31T10:40Z | `initialblockdownload=false`, `blocks=headers=964867`, `pruned=true`, `/srv/bitcoin` 24G |
| 4 CLN | Phase B no-funds node running | 2026-08-31T11:00Z | [`HETZNER_MAINNET_CLN.md`](HETZNER_MAINNET_CLN.md) |
| 5 funds/issuer | not authorized | | |

## Host facts at kickoff (2026-08-31T01:23:54Z)

Queried live. Do not treat as pins.

- `/` 929G, **693G avail**, PIR data shares this filesystem
- `pir-primary` active, `cloudflared` active, `pir-secondary` inactive
- RAM ~122Gi available
- Core **v31.1.0** already under `/opt/bitcoinpir/bitcoin-core/<bundle>/bin/`
- no bitcoind/CLN process; 8332/8333/9735 closed
- `/srv` empty; UFW allows 22/80/443 only
- UID 980 and GID 980/981 were free (avoid 990–995; 995 is `bitcoinpir-mainnet-issuer`)

## Identities (live, not a pin file)

| Name | Role | Planned |
| --- | --- | --- |
| `bitcoinpir-bitcoind` | daemon uid/primary gid | UID/GID **980**, nologin, home `/srv/bitcoin` |
| `bitcoinpir-bitcoin-rpc` | cookie group only | GID **981**; **not** a supplementary group of bitcoind, issuer, or guard |
| `/srv/bitcoin` | datadir + cookie parent | `bitcoinpir-bitcoind:bitcoinpir-bitcoin-rpc` mode **2710** setgid |
| `/etc/bitcoinpir/payment-v1/bitcoin/bitcoin.conf` | Core config | root:root 0644 |
| `bitcoinpir-bitcoind.service` | unit | `/etc/systemd/system/bitcoinpir-bitcoind.service` |

Cookie after first start should be `/srv/bitcoin/.cookie`, owner
bitcoind, group cookie-gid, mode **0640**, single link. Never log it.

## IBD watch

| | |
| --- | --- |
| Expected | 12–48 h on this i7-8700 |
| Hard stop | 3 h with no `blocks`/`headers` movement, or `df` avail **&lt; 80G** |
| Progress | `getblockchaininfo`: `blocks`, `headers`, `verificationprogress`, `pruned`, `size_on_disk`, `initialblockdownload` |
| Do not | restart `pir-primary`, swap databases, or rsync large PIR artifacts during IBD |

## Installed bitcoin.conf (host copy)

```
chain=main
server=1
daemon=0
disablewallet=1
txindex=0
prune=10000
dbcache=4096
datadir=/srv/bitcoin
listen=1
bind=0.0.0.0
port=8333
discover=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=8332
rpccookiefile=/srv/bitcoin/.cookie
rpccookieperms=group
printtoconsole=1
```

No `rpcuser` / `rpcpassword`. No `-conf` on `bitcoin-cli` (preflight
forbids that later); bitcoind itself is started with an explicit
`-conf=` outside the datadir.

## Installed unit (host copy)

`User=bitcoinpir-bitcoind`, `Group=bitcoinpir-bitcoind`, no cookie
supplementary group. `ReadWritePaths=/srv/bitcoin`.
`Restart=on-failure`. `[Install] WantedBy=multi-user.target` so a
reboot does not throw away IBD. Binary path is the already-present
Core bundle under `/opt/bitcoinpir/bitcoin-core/` (query the host;
do not paste the bundle id here).

## Log

Append-only. Newest at the bottom.

- 2026-08-31: Phase 0 accepted. Phase 1 skipped (closed template tree).
  Starting Phase 2 on pir1.
- 2026-08-31T01:29Z: Phase 2 on pir1. Users `bitcoinpir-bitcoind` (980)
  and group `bitcoinpir-bitcoin-rpc` (981). Datadir `/srv/bitcoin`
  `2710` setgid. Config and systemd unit installed. Process not started.
- 2026-08-31T01:30Z: Phase 3. UFW allow 8333/tcp. `systemctl enable
  --now bitcoinpir-bitcoind`. Cookie
  `bitcoinpir-bitcoind:bitcoinpir-bitcoin-rpc` mode 0640, 1 link.
  Listen: `0.0.0.0:8333`, `127.0.0.1:8332`. `pir-primary` still active.
  First RPC: `chain=main pruned=true ibd=true blocks=0 headers=0`.
  ~40s later journal at header pre-sync ~280000. Disk still 693G avail.
- 2026-08-31T10:40Z: IBD complete. `blocks=headers=964867`,
  `verificationprogress=1`, `initialblockdownload=false`,
  `pruned=true`, `pruneheight=959297`. `/srv/bitcoin` 24G
  (blocks 9.9G, chainstate 14G, debug.log 226M). Root 668G avail.
  `pir-primary` still active. Harmless periodic
  `socket(AF_NETLINK)` errors from the systemd namespace (Core still
  follows the chain). Phase 4 CLN still not authorized.
- 2026-08-31T10:43Z: Phase A CLN inventory only. See
  [`HETZNER_MAINNET_CLN.md`](HETZNER_MAINNET_CLN.md). No lightningd,
  no identity, no sentinels.
