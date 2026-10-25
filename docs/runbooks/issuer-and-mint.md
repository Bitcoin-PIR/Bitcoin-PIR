# Operate the issuer and the mint

Paid queries are sold outside the PIR hosts' measured images: a Cashu
**mint** turns Lightning payments into ecash, and the **issuer** — the
credit issuer — redeems the ecash every PIR server forwards and sells
ecash from its own wallet over x402 ([Credits and gas](../CREDITS.md)).
Both run on pir1. This page is the operator record; the HTTP contract is
[Credits and gas](../CREDITS.md) "Issuer API" and the issuer's source is
[Bitcoin-PIR/issuer](https://github.com/Bitcoin-PIR/issuer).

Live state is always queried, never inferred from this page.

## Layout on pir1

| Component | Unit | User | Listens | Config | State |
| --- | --- | --- | --- | --- | --- |
| Mint (`cdk-mintd`, CLN backend) | `bitcoinpir-mint.service` | `bitcoinpir-mint` (+ `bitcoinpir-mainnet-cln-guard` for the RPC socket) | `127.0.0.1:8085` | the configuration record in the mint database (`config show`, below); import document `/etc/bitcoinpir/mint/config-0.18.toml` | `/var/lib/bitcoinpir-mint/` (SQLite) |
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

Since 2026-10-24 the mint runs `cdk-mintd` 0.18 (`/opt/bitcoinpir/cdk/be94a652…/`):
the unit starts it with `--work-dir /var/lib/bitcoinpir-mint` only, and
the configuration lives in the mint database. The document it was
initialized from is `/etc/bitcoinpir/mint/config-0.18.toml` (root,
0640, group `bitcoinpir-mint`); the seed stays in
`/etc/bitcoinpir/mint/seed` and the document references it as
`file:`. The legacy `/etc/bitcoinpir/mint/config.toml` is no longer
read. To change the configuration, edit the document, then as the mint
user:

```sh
M=/opt/bitcoinpir/cdk/be94a6526e7ccd4fadbece4239964ec1bb8bbf5b2333c53244ef3cd4b0a42316/cdk-mintd
sudo -u bitcoinpir-mint $M --work-dir /var/lib/bitcoinpir-mint config validate --file /etc/bitcoinpir/mint/config-0.18.toml
sudo -u bitcoinpir-mint $M --work-dir /var/lib/bitcoinpir-mint config apply --file /etc/bitcoinpir/mint/config-0.18.toml
systemctl restart bitcoinpir-mint
sudo -u bitcoinpir-mint $M --work-dir /var/lib/bitcoinpir-mint config show      # the stored document
```

`config rollback` stages the previous applied document (one is kept).
The 0.17.3 bundle (`57ccebba…`) and the pre-upgrade database copy under
`/root/mint-upgrade-0.18.2-20261024T080640Z/` allow a downgrade; a 0.17
binary must never run against the 0.18 database.

## Secrets (Human-only to create; back up offline)

| File | Owner, mode | Contents | If lost |
| --- | --- | --- | --- |
| `/etc/bitcoinpir/mint/seed` | `bitcoinpir-mint`, 0400 | BIP39 phrase (`bpir-issuer mnemonic`) | every issued ecash becomes unredeemable |
| `/etc/bitcoinpir/issuer/grant.key` | `bpir-issuer`, 0600 | 32-byte Ed25519 issuer seed (`bpir-issuer keygen`; the file name predates credits); signs `/v2/redeem` answers | rotate: new key, re-pin every server |
| `/etc/bitcoinpir/issuer/wallet.seed` | `bpir-issuer`, 0600 | 64-byte Cashu wallet seed | the issuer's ecash claim on the mint is lost |
| `/etc/bitcoinpir/issuer/grant.pub` | root, 0644 | 64 hex, the issuer public key servers pin (`--credit-issuer-pubkey`) | regenerate with `bpir-issuer pubkey` |
| `/etc/bitcoinpir/issuer/arc.seed` | `bpir-issuer`, 0600 | Retired: the 32-byte ARC master seed of the retired ARC credentials. The ARC-free issuer does not read it; the file stays on pir1 until the operator deletes it (Human) | nothing once the ARC-free issuer runs |

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
  `pir-primary` on pir1) — the
  wall seconds per generated hint set for capacity planning and the hint
  price. It is an aggregate on the hour boundary; no per-entry timing is
  logged in production builds.

## Read — health

```sh
ssh root@65.21.91.217 'systemctl is-active bitcoinpir-mint bpir-issuer bitcoinpir-mainnet-lightning'
curl -sS https://issuer.bitcoinpir.org/v2/info      # gas parameters, mints, rate card
curl -sS https://mint.bitcoinpir.org/v1/info         # mint name, nuts
curl -sS https://mint.bitcoinpir.org/v1/keysets      # one active sat keyset
```

On pir1, money and ledger:

```sh
sudo -u bpir-issuer /opt/bitcoinpir/issuer/current/bpir-issuer balance --config /etc/bitcoinpir/issuer/config.toml
tail -n 20 /var/lib/bitcoinpir-issuer/grants.jsonl     # pending / redeemed / failed per token, x402_ecash_pending / x402_ecash_issued per x402 sale
CLI=$(ls /opt/bitcoinpir/core-lightning/*/bin/lightning-cli | head -1)
sudo -u bitcoinpir-mainnet-lightning "$CLI" --lightning-dir=/srv/lightning --network=bitcoin listpeerchannels
sudo -u bitcoinpir-mainnet-lightning "$CLI" --lightning-dir=/srv/lightning --network=bitcoin listinvoices
```

A `pending` line without a later `redeemed` or `failed` line for the
same token key means the process died or timed out mid-swap; the issuer
reports such tokens honestly (402 with a message) and logs at error
level. Reconcile against the wallet balance before refunding anyone. An
`x402_ecash_pending` line without a later `x402_ecash_issued` is a paid
sale whose mint answer is unknown; the buyer's identical retry finishes
it (NUT-09 restore first).

## Where the money is

Buyers pay the mint's Lightning invoices or, over x402, the issuer's on
the same node, so revenue accumulates as the Lightning node's channel
balance (`to_us_msat`). The issuer's ecash is
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
without these tables, which leaves `POST /v2/redeem` refusing every server.

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
```

Then `systemctl restart bpir-issuer`; the startup log line says
`operator_keys=2`.

ARC credentials are retired. The issuer's config rejects unknown fields,
so before the ARC-free issuer is deployed, delete the `[arc]` table and
every `[[arc.credential_offers]]` from the live `config.toml`; with them the
new binary refuses to start (``unknown field `arc` ``).

- Every redemption is appended to `/var/lib/bitcoinpir-issuer/redeem.jsonl`
  (the replay index for `(server_id, nonce)` and the per-server ledger).
  `bpir-issuer settlement --config
  /etc/bitcoinpir/issuer/config.toml` prints redemptions, gas, and sat per
  server: what each server earned.
- `grants.jsonl` records every token spent through a server (`redeemed`),
  so a token can never be used twice, and every x402 ecash sale
  (`x402_ecash_pending`, `x402_ecash_issued`); `issued` lines (v1 session
  grants) and `credentialed` / `x402_credentialed` lines (ARC credentials)
  are from before those retirements and replay only as spent tokens and
  claimed payments.

## Change mints

Edit `/etc/bitcoinpir/issuer/config.toml` (`mints`, `cors_origins`) and
`systemctl restart bpir-issuer`. The browser reads the mints from
`/v2/info` on every load and buys from the first, which is also the one
the issuer sells from. A mint fee (`input_fee_ppk` in the mint config)
lowers what a redemption books (the issuer books what the mint actually
credited); on an ecash sale the issuer pays the input fee of its own
inputs.

## Upgrade the issuer

```sh
sudo -u pir -H bash -c 'cd /home/pir/src/issuer && git fetch origin && git checkout --detach <rev> && cargo build --locked --release'
SRC=/home/pir/src/issuer/target/release/bpir-issuer; SHA=$(sha256sum "$SRC" | cut -d" " -f1)
install -D -o root -g root -m 0755 "$SRC" /opt/bitcoinpir/issuer/$SHA/bpir-issuer
install -D -o root -g root -m 0755 /home/pir/src/issuer/target/release/bpir-cln-rpc-guard /opt/bitcoinpir/issuer/$SHA/bpir-cln-rpc-guard
ln -sfn /opt/bitcoinpir/issuer/$SHA /opt/bitcoinpir/issuer/current && systemctl restart bpir-issuer bpir-cln-rpc-guard
```

Every release directory must hold both binaries: `bpir-cln-rpc-guard.service`
runs `current/bpir-cln-rpc-guard` too. The releases of 2026-10-11 shipped
only `bpir-issuer`; the running guard survived from memory until the restart
of 2026-10-24 failed with 203/EXEC. The release of that day (`cec57eba…`)
carries both binaries again and the guard unit runs `current/` as before.
After a release, confirm both processes run from the new directory:

```sh
for u in bpir-issuer bpir-cln-rpc-guard; do readlink /proc/$(systemctl show -p MainPID --value $u)/exe; done
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
4. Check: `curl -si -X POST https://issuer.bitcoinpir.org/v2/x402/ecash -H
   'content-type: application/json' -d '{"sat":10,"outputs":[]}'`
   must answer `400 invalid_request` rather than `402`, and with real
   blinded outputs (the web client's x402 top-up) the answer is `402` with
   a `PAYMENT-REQUIRED` header whose invoice decodes to the node key. Pay
   one invoice from any wallet and confirm
   `GET /v2/x402/invoices/<payment_hash>` turns `paid`.

Money paid over x402 lands in the node's channel balance, not in the Cashu
wallet; `bpir-issuer settlement` and `balance` do not include it. The
ecash each sale hands out comes from the issuer's Cashu wallet (the first
mint in `mints`), so keep a float there and watch it with `bpir-issuer
balance`; tokens redeemed through `/v2/redeem` swap back into the same
wallet. A sale the wallet cannot cover is answered `503 float_exhausted`
before any invoice is made. `[x402] ecash_min_sat` and `ecash_max_sat`
(defaults 10 and 20,000) bound one sale. Invoice creation is limited per
client address and globally (`[x402]`), and the guard limits it again.

## Rotate the issuer key

1. `bpir-issuer keygen --out /etc/bitcoinpir/issuer/grant.key.new`
   (Human), then `bpir-issuer pubkey` into a new `grant.pub`.
2. Pin the new public key on every server (pir1's unit, the pir2
   MacBook's plist) **before** switching the issuer
   (`--credit-issuer-pubkey` is repeatable, so both keys verify during the
   overlap).
3. Move the new key into place and restart the issuer; a server that pins
   only the old key refuses its redeem answers until it is re-pinned.

## Known limits

- `decode`, `listchannels`, and `listnodes` are unavailable on this CLN
  (the `offers` and `topology` plugins are disabled); use a public
  explorer or a local bolt11 parser.
- A public channel is payable only after its announcement (6
  confirmations plus gossip propagation); CLN adds route hints only for
  private channels (`expose_private_channels = true` in the mint config).
- The mint runs `cdk-mintd` 0.18.2 and the issuer `cdk` 0.18 wallet
  code; keep both within one minor version of each other when upgrading.
