# pir1 mainnet CLN (operator log)

Companion to [`HETZNER_PRUNED_BITCOIND.md`](HETZNER_PRUNED_BITCOIND.md).
Live host state is still queried, not inferred. This file is not a
Payment V1 activation, not permission to start `lightningd`, and not
permission to create `hsm_secret` or fund channels.

Authorized 2026-08-31: **Phase A only** — inventory the gap between the
synced pruned Core and a mainnet receive-only CLN. No process, no
identity, no sentinel, no plugin chmod.

## Status

| Phase | State | When (UTC) | Evidence |
| --- | --- | --- | --- |
| A inventory | done | 2026-08-31T10:43Z | this file; host probe below |
| B no-funds CLN bootstrap | done | 2026-08-31T11:00Z | `bitcoinpir-mainnet-lightning` active; network=bitcoin; height tracks Core; plugins `bcli`+`chanbackup`; 0 channels / 0 outputs |
| C channels / inbound | not authorized | | |
| D guard + issuer | not authorized | | |

## What already fits

Queried 2026-08-31T10:43Z on pir1.

- Core at tip, `pruned=true`, `initialblockdownload=false`.
- Cookie `/srv/bitcoin/.cookie` is `bitcoinpir-bitcoind:bitcoinpir-bitcoin-rpc`
  mode 0640, one link — matches CLN `bcli` and mainnet preflight
  (`rpccookiefile=/srv/bitcoin/.cookie`, port 8332).
- Pinned CLN **v26.06.6** and `lightning-cli` are on disk under
  `/opt/bitcoinpir/core-lightning/`. `bpir-admin` and `payment-issuer`
  bundles are also present. No `cln-rpc-guard` dir (needed only in D).
- `deploy/payment-v1/lightning/lightningd.conf.in` already takes
  `network=@LIGHTNING_NETWORK@`. The rendered-artifact gate accepts
  `bitcoin` for profile `issuer-lightning-mainnet-v1`.
- Mainnet unit
  `deploy/payment-v1/systemd/issuer-lightning-mainnet-v1-core.service.in`
  already: `WorkingDirectory=/srv/lightning/bitcoin`,
  `Requires=@BITCOIND_SYSTEMD_UNIT@` (live name
  `bitcoinpir-bitcoind.service`),
  `SupplementaryGroups=bitcoinpir-bitcoin-rpc`, no `[Install]`,
  mainnet sentinels (not Signet).
- `pay` and every built-in except `bcli`/`chanbackup` are already
  `disable-plugin=` in that conf.
- Issuer must not hold the cookie group: live
  `bitcoinpir-mainnet-issuer` (UID 995 / GID 986) is **not** in
  `bitcoinpir-bitcoin-rpc`. Keep it that way.

## Gaps that block even a no-funds start

### 1. Layout verifier is Signet-hardcoded

`deploy/payment-v1/lightning/verify-layout.sh.in` line 25:

```
[ "${bpir_lightning_network}" = 'signet' ] || bpir_fail
```

Mainnet Core unit runs this as `ExecStartPre`. File is in
`REVIEWED_PREPARATION_HASHES`. Allowing `bitcoin` is a reviewed source
change plus gate hash update. Do not bypass by skipping the verifier.

The same script also requires a live `hsm_secret` **before**
`lightningd` starts: exactly 32 bytes, owner CLN, mode `400`. First
identity therefore cannot be “just start lightningd”. Offline generate
→ restore the inode → then start. That is Phase B Human work.

### 2. Mainnet skeleton must stay empty

`docs/payment/render-plan-skeletons/issuer-lightning-mainnet-v1.plan.json.example`
is an empty placeholder. Archive
`docs/archive/payment/MAINNET_LIGHTNING_V1_RUNBOOK.md` says **do not
materialize or activate** it. Phase B, if authorized, should follow the
same host-side pattern as pruned Core (files on the host, off the
closed `deploy/payment-v1/` tree), or a separately reviewed source
change — not filling that skeleton.

Keep `MAINNET-LIGHTNING-V1-ACTIVATION-APPROVED` absent until that stage
is explicitly approved.

### 3. `pid-file` vs mainnet RuntimeDirectory

`lightningd.conf.in` hardcodes

`pid-file=/run/bitcoinpir-core-lightning/lightningd.pid`

Signet unit RuntimeDirectory is `bitcoinpir-core-lightning`. Mainnet
unit RuntimeDirectory is `bitcoinpir-mainnet-core-lightning`. Same
conf cannot boot the mainnet unit as written. Needs a placeholder or a
mainnet-specific conf. Also in the reviewed-hash set.

### 4. Host identities and directories (not created)

Live: no `bitcoinpir-mainnet-lightning`, no `*-cln-guard`, no
`*-lightning-preflight`, no `*-cln-rpc-guard`. No `/srv/lightning`.
No lightning unit, no `lightningd.conf` on the host, no 9735 listener,
UFW has 8333 only.

`bitcoinpir-mainnet-issuer` **already exists** (UID 995) with
`/var/lib/bitcoinpir-mainnet-bat-v2-issuer/issuer.sqlite3`. Do not
blank-init over it; it is issuer state, not CLN, but it is live
durable state.

Free UIDs/GIDs at probe time (do not use 980/981/986/995/990–994):
**970–979, 982–984**. Suggested later assignment (not applied):

| Name | Role | Suggested |
| --- | --- | --- |
| `bitcoinpir-mainnet-lightning` | CLN daemon | UID **982**, primary GID = cln-guard |
| `bitcoinpir-mainnet-cln-guard` | native RPC socket group | GID **983** |
| `bitcoinpir-mainnet-lightning-preflight` | read-only preflight | UID **984**; supplementary: cln-guard + `bitcoinpir-bitcoin-rpc` |
| `bitcoinpir-mainnet-cln-rpc-guard` | method guard (Phase D) | new UID from remaining free set |
| `bitcoinpir-bitcoin-rpc` | Core cookie | GID **981** already; **CLN + preflight only** |
| `bitcoinpir-mainnet-issuer` | issuer (Phase D) | UID **995** already; **never** cookie group |

Layout once created: `/srv` and `/srv/lightning` root:root `755`;
`/srv/lightning/bitcoin` CLN-uid:cln-guard `710`.

### 5. Plugin modes

Host plugin dir: all 27 plugins `root:root` `0755`, including `pay`.
Templates want `bcli` and `chanbackup` `0555`, the rest `0444`, plus
systemd `InaccessiblePaths=/srv/lightning/plugins`. chmod is Phase B
host work on the already-pinned bundle (content hashes unchanged).

### 6. P2P address still a placeholder

Conf needs `@CLN_P2P_BIND_ADDR@` / `@CLN_P2P_ANNOUNCE_ADDR@`. pir1
public IP is `65.21.91.217`. 9735 is not in UFW. Choosing bind vs
announce (IP vs DNS) is an operator decision in Phase B.

### 7. Sentinels and hash-pins absent (correct for A)

Host has only `RELAY-ACTIVATION-APPROVED` and `RELAY-SELECTION-RESOLVED`.
Mainnet CLN unit also wants `ACTIVATION-APPROVED`,
`MAINNET-LIGHTNING-V1-ACTIVATION-APPROVED`,
`LIGHTNING-CUSTODY-APPROVED`,
`LIGHTNING-IDENTITY-RESTORE-APPROVED`. Do not create them in A.

No `/etc/bitcoinpir/payment-v1/lightning/*.sha256` pin files, no
`/usr/local/libexec/bitcoinpir/verify-lightning-layout`.

## Phase B would need (not authorized)

1. Reviewed source: verifier accepts `network=bitcoin`; pid-file matches
   mainnet RuntimeDirectory; update `REVIEWED_PREPARATION_HASHES`.
2. Operator: 32-byte `hsm_secret` generated in isolation, node id
   recorded, inode restored mode `400` before first `lightningd`.
3. Host: users/dirs above, plugin modes, rendered `lightningd.conf`
   with `network=bitcoin` and cookie-only Core RPC, unit
   `Requires=bitcoinpir-bitcoind.service`, UFW 9735 if announced.
4. Start order: `--test-daemons-only --offline` then real start.
   Success: `getinfo` network=bitcoin, height tracks Core, plugins
   exactly `bcli`+`chanbackup`, **zero channels, zero funds**.
5. Still no issuer, no guard required for a no-funds node, no
   `MAINNET-LIGHTNING-V1-ACTIVATION-APPROVED` unless you explicitly
   want the templated unit’s ConditionPathExists.

## Log

- 2026-08-31T10:43Z: Phase A probe. Core still at 964867. No
  `/srv/lightning`, no CLN unit, no Lightning sentinels, plugins all
  `0755`. `bitcoinpir-mainnet-issuer` sqlite already present. No
  host mutation.
- 2026-08-31T11:00Z: Phase B. Users 982 (`bitcoinpir-mainnet-lightning`,
  groups cln-guard + cookie), 983 (`bitcoinpir-mainnet-cln-guard`),
  984 (`bitcoinpir-mn-preflight`; name shortened — 32-char groupadd
  limit). Issuer 995 still not in cookie group. `/srv/lightning/bitcoin`
  `710`, `hsm_secret` 32 bytes mode `400`. Plugins `bcli`/`chanbackup`
  `0555`, others `0444`. Host-side layout verifier accepts `bitcoin`.
  Unit `Requires=bitcoinpir-bitcoind.service`, no Payment sentinels.
  `--test-daemons-only --offline` then start: layout PASS.
  `getinfo` network=bitcoin, blockheight=964867 (matches Core),
  plugins exactly bcli+chanbackup, 0 peers / 0 channels / 0 outputs.
  P2P `0.0.0.0:9735`, announce `65.21.91.217:9735`. Recurring
  `Unable to estimate any fees` is expected until mempool fee data
  exists; receive-only and unfunded. Node id from `hsmtool getnodeid`
  / `getinfo` (query live; do not treat this log as a pin). Phase C/D
  not authorized.
