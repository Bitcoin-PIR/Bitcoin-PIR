# Operate the issuer and the mint

Paid queries are sold outside the PIR hosts' measured images: a Cashu
**mint** turns Lightning payments into ecash, and the **issuer** — the
credit issuer — sells ARC credentials for that ecash and verifies every
presentation a PIR server forwards ([Credits and gas](../CREDITS.md)).
Both run on pir1. This page is the operator record; the HTTP contract is
[Credits and gas](../CREDITS.md) "Issuer API" and the issuer's source is
[Bitcoin-PIR/issuer](https://github.com/Bitcoin-PIR/issuer).

Live state is always queried, never inferred from this page.

## Layout on pir1

| Component | Unit | User | Listens | Config | State |
| --- | --- | --- | --- | --- | --- |
| Mint (`cdk-mintd`, CLN backend) | `bitcoinpir-mint.service` | `bitcoinpir-mint` (+ `bitcoinpir-mainnet-cln-guard` for the RPC socket) | `127.0.0.1:8085` | `/etc/bitcoinpir/mint/config.toml` | `/var/lib/bitcoinpir-mint/` (SQLite) |
| Issuer (`bpir-issuer`) | `bpir-issuer.service` | `bpir-issuer` | `127.0.0.1:8095` | `/etc/bitcoinpir/issuer/config.toml` | `/var/lib/bitcoinpir-issuer/` (`wallet.sqlite`, `grants.jsonl`) |
| Lightning node | `bitcoinpir-mainnet-lightning.service` | `bitcoinpir-mainnet-lightning` | `0.0.0.0:9735` | `/etc/bitcoinpir/payment-v1/lightning/lightningd.conf` | `/srv/lightning/bitcoin/` |

The issuer binary is installed content-addressed under
`/opt/bitcoinpir/issuer/<sha256>/bpir-issuer` with a `current`
symlink the unit runs; the mint binary is the retained `cdk-mintd`
bundle under `/opt/bitcoinpir/cdk/<sha256>/`. Both services are
published through the pir1 Cloudflare tunnel as
`https://issuer.bitcoinpir.org` (→ 8095) and
`https://mint.bitcoinpir.org` (→ 8085); the browser pins the issuer
URL (`PRODUCTION_ISSUER_URL`), and the issuer's `mints` list names the
mint.

## Secrets (Human-only to create; back up offline)

| File | Owner, mode | Contents | If lost |
| --- | --- | --- | --- |
| `/etc/bitcoinpir/mint/seed` | `bitcoinpir-mint`, 0400 | BIP39 phrase (`bpir-issuer mnemonic`) | every issued ecash becomes unredeemable |
| `/etc/bitcoinpir/issuer/grant.key` | `bpir-issuer`, 0600 | 32-byte Ed25519 issuer seed (`bpir-issuer keygen`; the file name predates credits); signs `/v2/redeem` answers | rotate: new key, re-pin every server |
| `/etc/bitcoinpir/issuer/wallet.seed` | `bpir-issuer`, 0600 | 64-byte Cashu wallet seed | the issuer's ecash claim on the mint is lost |
| `/etc/bitcoinpir/issuer/grant.pub` | root, 0644 | 64 hex, the issuer public key servers pin (`--credit-issuer-pubkey`) | regenerate with `bpir-issuer pubkey` |
| `/etc/bitcoinpir/issuer/arc.seed` | `bpir-issuer`, 0600 | 32-byte ARC master seed (`bpir-issuer arc-seed`); every epoch's issuer keys derive from it | every issued credential becomes unspendable; buyers must be refunded out of band |

`bpir-issuer keygen`, `wallet-seed`, and `mnemonic` never print the
secret; `keygen` and `pubkey` print only the public key.

## Server pins

- pir1: `pir-primary.service` passes `--credit-issuer-url
  https://issuer.bitcoinpir.org` and `--credit-issuer-pubkey
  /etc/bitcoinpir/issuer/grant.pub`.
- pir2 (the MacBook node): the same two flags in its launchd plist
  ([pir2 MacBook replacement](pir2-macbook-replacement.md)).
- The Direct ORAM host serves ORAM free (`--access oram=best-effort:2`), so
  its measured UKI carries no issuer pins.
- Credits ([Credits and gas](../CREDITS.md)): the issuer's redeem answers
  verify under `grant.pub`, and each server signs its redeem requests with
  its identity key, so the issuer's `operator_pubkeys` must list the
  operator key that signed that server's identity certificate. What each
  backend charges is the server's access policy (`--require-credits`,
  `--access`; CREDITS.md "Access policy").
- Gas meter: each server prints one `[meter op=0x.. db=N] last 3600s: n=…
  gas_mean=… cpu_mean_ms=… wall_mean_ms=… egress_mean_kib=… inflight_max=…`
  line per opcode and database per hour plus a `[meter] last 3600s: …`
  total, and its gas table at startup (`[gas db=N] …`, also under `"gas"`
  in `GET_INFO_JSON`). Aggregates only; the calibration they check is in
  [Credits and gas](../CREDITS.md).
- Pricing input: each server prints one `[hint-pool db=N] last 3600s:
  generated=K wall_mean_s=… wall_max_s=…` line per hour (journal of
  `pir-primary` on pir1; the measured guest's console log on pir2) — the
  wall seconds per generated hint set for capacity planning and the hint
  price. It is an aggregate on the hour boundary; no per-entry timing is
  logged in production builds.

## Read — health

```sh
ssh root@65.21.91.217 'systemctl is-active bitcoinpir-mint bpir-issuer bitcoinpir-mainnet-lightning'
curl -sS https://issuer.bitcoinpir.org/v2/info      # gas parameters, mints, packs, ARC epoch
curl -sS https://mint.bitcoinpir.org/v1/info         # mint name, nuts
curl -sS https://mint.bitcoinpir.org/v1/keysets      # one active sat keyset
```

On pir1, money and ledger:

```sh
sudo -u bpir-issuer /opt/bitcoinpir/issuer/current/bpir-issuer balance --config /etc/bitcoinpir/issuer/config.toml
tail -n 20 /var/lib/bitcoinpir-issuer/grants.jsonl     # pending / credentialed / redeemed / failed per token
CLI=$(ls /opt/bitcoinpir/core-lightning/*/bin/lightning-cli | head -1)
sudo -u bitcoinpir-mainnet-lightning "$CLI" --lightning-dir=/srv/lightning --network=bitcoin listpeerchannels
sudo -u bitcoinpir-mainnet-lightning "$CLI" --lightning-dir=/srv/lightning --network=bitcoin listinvoices
```

A `pending` line without a later `credentialed`, `redeemed` or `failed`
line for the same token key means the process died or timed out mid-swap; the issuer
reports such tokens honestly (402 with a message) and logs at error
level. Reconcile against the wallet balance before refunding anyone.

## Where the money is

Buyers pay the mint's Lightning invoices, so revenue accumulates as the
Lightning node's channel balance (`to_us_msat`). The issuer's ecash is
a claim on the operator's own mint; `pay` is disabled in
`lightningd.conf`, so the mint cannot melt and nothing pays out through
the issuer. Moving sats out means enabling `pay` (a reviewed change to
the receive-only CLN posture) or closing a channel to chain.

Inbound liquidity is a Human step. The first channel was bought on
Amboss Magma through its API (`liquidity.buy` with the node's
`pubkey@host:port`; the web UI refuses to link a node that has no channel
in the graph). Keep the order id and session key with the operator's
private records. Keep a small on-chain balance in CLN for anchor-channel
fee bumping.

## Credits (v2): configuration and settlement

`bpir-issuer` serves the credits contract under `/v2/`
([Credits and gas](../CREDITS.md)); the session-grant contract under `/v1/`
is retired.
Everything credits need is in `config.toml`; an existing file keeps working
without these tables, which leaves `POST /v2/redeem` refusing every server
and `/v2/credentials` unsold.

```toml
[gas]                       # docs/CREDITS.md "Rate card"; defaults shown
credit_sat = 10
gas_per_credit = 72000
base_gas_per_frame = 20
egress_gas_per_mb = 1000

# Operator identity keys (64 hex) whose certified servers may redeem: the
# `operatorPubkey` values of PIR1_PROVIDER and PIR2_PROVIDER in
# web/src/production-providers.ts (pir1 and pir2 are certified by
# different operator keys; list both).
operator_pubkeys = ["<pir1 operator pubkey hex>", "<pir2 operator pubkey hex>"]
redeem_max_skew_secs = 300

[arc]                       # Human: `bpir-issuer arc-seed --out /etc/bitcoinpir/issuer/arc.seed`
seed_path = "/etc/bitcoinpir/issuer/arc.seed"
epoch_secs = 7776000        # 90 days
grace_secs = 2592000        # 30 days
presentation_limit = 100
[[arc.credential_offers]]   # credits must equal presentation_limit
credits = 100
sat = 1000
```

`chown bpir-issuer:bpir-issuer /etc/bitcoinpir/issuer/arc.seed && chmod
0600 …`, then `systemctl restart bpir-issuer`; the startup log line says
`arc=true` and `operator_keys=2`. `GET /v2/info` must then show the `arc`
section and the pack.

- Every redemption is appended to `/var/lib/bitcoinpir-issuer/redeem.jsonl`
  (the replay index for `(server_id, nonce)` and the per-server ledger with
  the ARC tags each epoch consumed). `bpir-issuer settlement --config
  /etc/bitcoinpir/issuer/config.toml` prints redemptions, gas, and sat per
  server: what each server earned.
- `grants.jsonl` records `redeemed` (a token spent through a server) and
  `credentialed` (a token that bought a credential) states, so a token can
  never be used twice; `issued` lines are v1 session grants from before
  the retirement and replay only as spent tokens.
- Back up `arc.seed` with the other secrets; rotating it is a new epoch's
  worth of refunds, not a key rotation (issued credentials are bound to the
  seed's per-epoch keys).

## Change packs or mints

Edit `/etc/bitcoinpir/issuer/config.toml` (`[[arc.credential_offers]]`,
`mints`, `cors_origins`) and `systemctl restart bpir-issuer`. The browser
reads the packs from `/v2/info` on every load; credentials already issued
keep their presentations. A mint fee (`input_fee_ppk` in the mint config)
is absorbed by the operator: the issuer validates the token's face value
and records the amount actually credited.

## Upgrade the issuer

```sh
sudo -u pir -H bash -c 'cd /home/pir/src/issuer && git fetch origin && git checkout --detach <rev> && cargo build --locked --release'
SRC=/home/pir/src/issuer/target/release/bpir-issuer; SHA=$(sha256sum "$SRC" | cut -d" " -f1)
install -D -o root -g root -m 0755 "$SRC" /opt/bitcoinpir/issuer/$SHA/bpir-issuer
ln -sfn /opt/bitcoinpir/issuer/$SHA /opt/bitcoinpir/issuer/current && systemctl restart bpir-issuer
```

The issuer contract types come from `pir-credit`, pinned by git revision
in the issuer's `Cargo.toml`; bump it together with any change to
`pir_credit::issuer`.

## x402 (Lightning) purchases: guard and issuer configuration

The issuer never opens the node socket. It reaches Core Lightning through
`bpir-cln-rpc-guard` (issuer repository, `cln-rpc-guard/`), which runs in
the socket's group and forwards only `invoice`, `listinvoices`, and
`waitinvoice` with bounded parameters. Both binaries build from the issuer
checkout (`cargo build --locked --release` produces `bpir-issuer` and
`bpir-cln-rpc-guard`); install the guard next to the issuer under the same
content-addressed directory.

1. Account and unit (once): `useradd --system --no-create-home --shell
   /usr/sbin/nologin bitcoinpir-mainnet-cln-rpc-guard`, then install
   `deploy/bpir-cln-rpc-guard.service` from the issuer repository
   (`User=` that account, `SupplementaryGroups=bitcoinpir-mainnet-cln-guard`
   to open `/srv/lightning/bitcoin/lightning-rpc`, `Group=bpir-issuer` and
   `UMask=0007` so `/run/bpir-cln-rpc-guard/rpc.sock` is `0660` for the
   issuer). `systemctl enable --now bpir-cln-rpc-guard`; the startup line
   lists the allowlist and bounds. This is Phase D of the CLN operator log.
2. Node key: the `payTo` every invoice must be signed by. Read it from the
   node (`getinfo` → `id`) as the lightning account, or from the recorded
   `hsmtool getnodeid` output; 66 lowercase hex.
3. Issuer config: add the `[x402]` table (`config.example.toml`):
   `guard_socket = "/run/bpir-cln-rpc-guard/rpc.sock"`, `node_pubkey_hex`,
   `public_url = "https://issuer.bitcoinpir.org"` (the request binding
   names this host; the `cashier.bitcoinpir.org` alias cannot serve x402),
   `max_timeout_secs = 900`, `label_prefix = "bpir-x402-"` (equal to the
   guard's `--label-prefix`). Restart the issuer; the startup log shows
   `x402 exact/lnbtc enabled`.
4. Check: `curl -si -X POST https://issuer.bitcoinpir.org/v2/credentials -H
   'content-type: application/json' -d '{"credits":100,"sat":1000,"request_hex":"00"}'`
   must answer `400` (bad request bytes) rather than `402`, and with a real
   blinded request the answer is `402` with a `PAYMENT-REQUIRED` header whose
   invoice decodes to the node key. Pay one invoice from any wallet and
   confirm `GET /v2/x402/invoices/<payment_hash>` turns `paid`.

Money paid over x402 lands in the node's channel balance, not in the Cashu
wallet; `bpir-issuer settlement` and `balance` do not include it. Invoice
creation is limited per client address and globally (`[x402]`), and the
guard limits it again.

## Rename cutover (cashier → issuer, 2026-09)

The service was named *cashier* until 2026-09-28; pir1 still runs
`bpir-cashier.service` as user `bpir-cashier` from `/opt/bitcoinpir/cashier`
until this cutover is done. Nothing about keys or pins changes: the issuer
key file, the ARC seed, the wallet, and the servers' `--credit-issuer-pubkey`
stay as they are. Order:

1. **Human (Cloudflare dashboard):** on the pir1 tunnel add the public
   hostname `issuer.bitcoinpir.org` → `http://localhost:8095`, identical to
   `cashier.bitcoinpir.org`. Keep the old hostname: pir2 image 321 bakes
   `PIR2_CREDIT_ISSUER_URL=https://cashier.bitcoinpir.org` into its UKI, so
   the alias lives until the next Tier 3 campaign ships the new value.
2. Build the renamed binary from the merged `Bitcoin-PIR/issuer` revision
   (the checkout moves with the repository; GitHub redirects the old URL):

   ```sh
   sudo -u pir -H bash -c 'mv /home/pir/src/cashier /home/pir/src/issuer && cd /home/pir/src/issuer && git remote set-url origin https://github.com/Bitcoin-PIR/issuer.git && git fetch origin && git checkout --detach <rev> && cargo build --locked --release'
   ```

3. Rename the account and move the directories; contents and ownership
   (uid 971) are unchanged, only names move:

   ```sh
   systemctl stop bpir-cashier
   usermod -l bpir-issuer bpir-cashier && groupmod -n bpir-issuer bpir-cashier
   mv /etc/bitcoinpir/cashier /etc/bitcoinpir/issuer
   mv /var/lib/bitcoinpir-cashier /var/lib/bitcoinpir-issuer
   mv /opt/bitcoinpir/cashier /opt/bitcoinpir/issuer
   ```

4. Install the binary content-addressed as in "Upgrade the issuer", install
   `deploy/bpir-issuer.service` from the issuer repository, then
   `systemctl disable --now bpir-cashier; systemctl daemon-reload;
   systemctl enable --now bpir-issuer`. The old unit file is kept as a
   backup next to the new one. Expected downtime: the build (minutes) runs
   before the stop; the stop-to-start window is seconds.
5. Verify `curl https://issuer.bitcoinpir.org/v2/info` and the old hostname
   both answer with `"service": "bitcoinpir-issuer"` and the unchanged
   `issuer_pubkey`, then run `bpir-issuer balance` and `settlement` against
   the moved state.
6. Only now merge the main-repository rename PR (it points
   `PRODUCTION_ISSUER_URL` at the new hostname), deploy Pages, and re-vendor
   the playground.

## Rotate the issuer key

1. `bpir-issuer keygen --out /etc/bitcoinpir/issuer/grant.key.new`
   (Human), then `bpir-issuer pubkey` into a new `grant.pub`.
2. Pin the new public key on every server **before** switching the
   issuer (`--credit-issuer-pubkey` is repeatable, so both keys verify
   during the overlap; pir2 needs a new image with the new
   `PIR2_CREDIT_ISSUER_PUBKEY_HEX`).
3. Move the new key into place and restart the issuer; a server that pins
   only the old key refuses its redeem answers until it is re-pinned.

## Known limits

- `decode`, `listchannels`, and `listnodes` are unavailable on this CLN
  (the `offers` and `topology` plugins are disabled); use a public
  explorer or a local bolt11 parser.
- A public channel is payable only after its announcement (6
  confirmations plus gossip propagation); CLN adds route hints only for
  private channels (`expose_private_channels = true` in the mint config).
- The mint runs `cdk-mintd` 0.17.3 and the issuer `cdk` 0.18 wallet
  code; the NUT protocol is compatible, but keep both within one minor
  version of each other when upgrading.
