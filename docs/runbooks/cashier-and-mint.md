# Operate the cashier and the mint

Paid queries are sold outside the PIR hosts' measured images: a Cashu
**mint** turns Lightning payments into ecash, and the **cashier** turns
that ecash into cashier-signed [session grants](../SESSION_GRANTS.md)
that the PIR servers meter. Both run on pir1. This page is the operator
record; the HTTP contract is [Cashier API](../CASHIER_API.md) and the
cashier's source is
[Bitcoin-PIR/cashier](https://github.com/Bitcoin-PIR/cashier).

Live state is always queried, never inferred from this page.

## Layout on pir1

| Component | Unit | User | Listens | Config | State |
| --- | --- | --- | --- | --- | --- |
| Mint (`cdk-mintd`, CLN backend) | `bitcoinpir-mint.service` | `bitcoinpir-mint` (+ `bitcoinpir-mainnet-cln-guard` for the RPC socket) | `127.0.0.1:8085` | `/etc/bitcoinpir/mint/config.toml` | `/var/lib/bitcoinpir-mint/` (SQLite) |
| Cashier (`bpir-cashier`) | `bpir-cashier.service` | `bpir-cashier` | `127.0.0.1:8095` | `/etc/bitcoinpir/cashier/config.toml` | `/var/lib/bitcoinpir-cashier/` (`wallet.sqlite`, `grants.jsonl`) |
| Lightning node | `bitcoinpir-mainnet-lightning.service` | `bitcoinpir-mainnet-lightning` | `0.0.0.0:9735` | `/etc/bitcoinpir/payment-v1/lightning/lightningd.conf` | `/srv/lightning/bitcoin/` |

The cashier binary is installed content-addressed under
`/opt/bitcoinpir/cashier/<sha256>/bpir-cashier` with a `current`
symlink the unit runs; the mint binary is the retained `cdk-mintd`
bundle under `/opt/bitcoinpir/cdk/<sha256>/`. Both services are
published through the pir1 Cloudflare tunnel as
`https://cashier.bitcoinpir.org` (→ 8095) and
`https://mint.bitcoinpir.org` (→ 8085); the browser pins the cashier
URL (`PRODUCTION_CASHIER_URL`), and the cashier's `mints` list names the
mint.

## Secrets (Human-only to create; back up offline)

| File | Owner, mode | Contents | If lost |
| --- | --- | --- | --- |
| `/etc/bitcoinpir/mint/seed` | `bitcoinpir-mint`, 0400 | BIP39 phrase (`bpir-cashier mnemonic`) | every issued ecash becomes unredeemable |
| `/etc/bitcoinpir/cashier/grant.key` | `bpir-cashier`, 0600 | 32-byte Ed25519 seed (`bpir-cashier keygen`) | rotate: new key, re-pin every server |
| `/etc/bitcoinpir/cashier/wallet.seed` | `bpir-cashier`, 0600 | 64-byte Cashu wallet seed | the cashier's ecash claim on the mint is lost |
| `/etc/bitcoinpir/cashier/grant.pub` | root, 0644 | 64 hex, the public key servers pin | regenerate with `bpir-cashier pubkey` |

`bpir-cashier keygen`, `wallet-seed`, and `mnemonic` never print the
secret; `keygen` and `pubkey` print only the public key.

## Server pins

- pir1: `pir-primary.service` passes
  `--session-grant-pubkey /etc/bitcoinpir/cashier/grant.pub`. The free
  path stays open until `--require-session-grant` is added, which is an
  operator decision.
- pir2: the flags live in `unified-server-run.sh` inside the measured UKI,
  so pinning requires a new image (Flow E/G). Until then pir2 answers
  "session grants not enabled" and the client treats it as the free path.

## Read — health

```sh
ssh root@65.21.91.217 'systemctl is-active bitcoinpir-mint bpir-cashier bitcoinpir-mainnet-lightning'
curl -sS https://cashier.bitcoinpir.org/v1/info      # pubkey, mints, offers, ttl
curl -sS https://mint.bitcoinpir.org/v1/info         # mint name, nuts
curl -sS https://mint.bitcoinpir.org/v1/keysets      # one active sat keyset
```

On pir1, money and ledger:

```sh
sudo -u bpir-cashier /opt/bitcoinpir/cashier/current/bpir-cashier balance --config /etc/bitcoinpir/cashier/config.toml
tail -n 20 /var/lib/bitcoinpir-cashier/grants.jsonl     # pending / issued / failed per token
CLI=$(ls /opt/bitcoinpir/core-lightning/*/bin/lightning-cli | head -1)
sudo -u bitcoinpir-mainnet-lightning "$CLI" --lightning-dir=/srv/lightning --network=bitcoin listpeerchannels
sudo -u bitcoinpir-mainnet-lightning "$CLI" --lightning-dir=/srv/lightning --network=bitcoin listinvoices
```

A `pending` line without a later `issued` or `failed` line for the same
token key means the process died or timed out mid-swap; the cashier
reports such tokens honestly (402 with a message) and logs at error
level. Reconcile against the wallet balance before refunding anyone.

## Where the money is

Buyers pay the mint's Lightning invoices, so revenue accumulates as the
Lightning node's channel balance (`to_us_msat`). The cashier's ecash is
a claim on the operator's own mint; `pay` is disabled in
`lightningd.conf`, so the mint cannot melt and nothing pays out through
the cashier. Moving sats out means enabling `pay` (a reviewed change to
the receive-only CLN posture) or closing a channel to chain.

Inbound liquidity is a Human step. The first channel was bought on
Amboss Magma through its API (`liquidity.buy` with the node's
`pubkey@host:port`; the web UI refuses to link a node that has no channel
in the graph). Keep the order id and session key with the operator's
private records. Keep a small on-chain balance in CLN for anchor-channel
fee bumping.

## Change offers or TTL

Edit `/etc/bitcoinpir/cashier/config.toml` (`[[offers]]`,
`grant_ttl_secs`, `mints`, `cors_origins`) and
`systemctl restart bpir-cashier`. The browser reads offers from
`/v1/info` on every load; grants already issued keep their credits. A
mint fee (`input_fee_ppk` in the mint config) is absorbed by the
operator: the cashier validates the token's face value and records the
amount actually credited.

## Upgrade the cashier

```sh
sudo -u pir -H bash -c 'cd /home/pir/src/cashier && git fetch origin && git checkout --detach <rev> && cargo build --locked --release'
SRC=/home/pir/src/cashier/target/release/bpir-cashier; SHA=$(sha256sum "$SRC" | cut -d" " -f1)
install -D -o root -g root -m 0755 "$SRC" /opt/bitcoinpir/cashier/$SHA/bpir-cashier
ln -sfn /opt/bitcoinpir/cashier/$SHA /opt/bitcoinpir/cashier/current && systemctl restart bpir-cashier
```

The grant format comes from `pir-session-grant` pinned by git revision in
the cashier's `Cargo.toml`; bump it together with any server-side change
to the crate.

## Rotate the grant key

1. `bpir-cashier keygen --out /etc/bitcoinpir/cashier/grant.key.new`
   (Human), then `bpir-cashier pubkey` into a new `grant.pub`.
2. Pin the new public key on every server **before** switching the
   cashier (`--session-grant-pubkey` is repeatable, so both keys can be
   accepted during the overlap; pir2 needs a new image).
3. Move the new key into place, restart the cashier; unexpired grants
   under the old key stay valid on servers that still pin it.

## Known limits

- `decode`, `listchannels`, and `listnodes` are unavailable on this CLN
  (the `offers` and `topology` plugins are disabled); use a public
  explorer or a local bolt11 parser.
- A public channel is payable only after its announcement (6
  confirmations plus gossip propagation); CLN adds route hints only for
  private channels (`expose_private_channels = true` in the mint config).
- The mint runs `cdk-mintd` 0.17.3 and the cashier `cdk` 0.18 wallet
  code; the NUT protocol is compatible, but keep both within one minor
  version of each other when upgrading.
