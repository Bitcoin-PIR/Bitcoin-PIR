# Directory relay (pir1)

The directory-only Nostr relay serves the BitcoinPIR service directory
([Directory protocol](../DIRECTORY_PROTOCOL.md)): signed provider entries and
per-shard checkpoints that clients fetch before they know any query. It is
`apps/directory-relay` (`bitcoinpir-directory-relay`), not a general-purpose
Nostr relay: the public lane answers only the directory `REQ`/`CLOSE` shapes,
the publisher lane accepts only `EVENT`s signed by the pinned directory key.

Today there is one relay, on pir1. Clients therefore run the protocol's
explicit `centralized-single-relay` mode (shown as centralized/degraded); a
second relay on another operator domain enables the strict two-origin mode
without any protocol change.

## Layout on pir1

| Component | Unit | User | Listens | Config | State |
| --- | --- | --- | --- | --- | --- |
| Relay (`bitcoinpir-directory-relay`) | `bpir-directory-relay.service` | `bpir-directory-relay` | `127.0.0.1:8096` public lane (`REQ`/`CLOSE`); `127.0.0.1:8097` publisher lane (`EVENT`), never exposed | `/etc/bitcoinpir/directory-relay/config.toml` (0400, service-owned) | `/var/lib/bitcoinpir-directory-relay/relay.sqlite3` (+ WAL) |

The binary is installed content-addressed under
`/opt/bitcoinpir/directory-relay/<sha256>/bitcoinpir-directory-relay` with a
`current` symlink the unit runs, like the issuer. The public lane is published
through the pir1 Cloudflare tunnel as `wss://directory.bitcoinpir.org`
(ingress → `http://127.0.0.1:8096`); the publisher lane stays on loopback and
is reached only through an SSH port-forward. Templates:
[`deploy/directory-relay/config.toml.example`](../../deploy/directory-relay/config.toml.example),
[`deploy/systemd/bpir-directory-relay.service`](../../deploy/systemd/bpir-directory-relay.service).

## Keys (Human-only to create; back up offline)

| Key | Where | Used by |
| --- | --- | --- |
| Directory publisher key (BIP340) | Mac Studio, `.keys/directory/directory-nostr.key`, made by `mkdir -m 700 -p .keys/directory && bpir-admin directory-artifact keygen --out .keys/directory/directory-nostr.key` | Signs entry, tombstone and checkpoint events offline. Never copied to pir1; the relay only pins its public key. |
| Operator identity key (Ed25519) | Mac Studio, the existing `bpir-admin` operator key that signs the servers' identity certificates | Signs each provider's operator assertion (`--operator-signing-key`). |

The directory public key (`directory_pubkey_xonly=` printed by `keygen`) goes
into the relay config (`directory_pubkey_hex`) and into the web client pin
(`PRODUCTION_DIRECTORY` in `web/src/production-providers.ts`). A new
publisher key is a new trust namespace: rotate it only with a client pin
update, never in place.

## Install (first time)

As root on pir1:

```sh
useradd --system --home /var/lib/bitcoinpir-directory-relay --shell /usr/sbin/nologin bpir-directory-relay
install -d -o root -g root -m 0755 /opt/bitcoinpir/directory-relay
install -d -o bpir-directory-relay -g bpir-directory-relay -m 0700 /etc/bitcoinpir/directory-relay
# Render deploy/directory-relay/config.toml.example: replace
# DIRECTORY_PUBLISHER_PUBKEY_HEX with the keygen output, keep the ports.
install -o bpir-directory-relay -g bpir-directory-relay -m 0400 config.toml /etc/bitcoinpir/directory-relay/config.toml
install -o root -g root -m 0644 deploy/systemd/bpir-directory-relay.service /etc/systemd/system/bpir-directory-relay.service
```

Build and install the binary (same pattern as the issuer). The relay's
checkout is `/home/pir/src/BitcoinPIR-directory` (once: `sudo -u pir -H git
clone https://github.com/Bitcoin-PIR/Bitcoin-PIR.git
/home/pir/src/BitcoinPIR-directory`):

```sh
sudo -u pir -H bash -c '. $HOME/.cargo/env && cd /home/pir/src/BitcoinPIR-directory && git fetch origin && git checkout --detach <rev> && cargo build --locked --release -p bitcoinpir-directory-relay'
SRC=/home/pir/src/BitcoinPIR-directory/target/release/bitcoinpir-directory-relay; SHA=$(sha256sum "$SRC" | cut -d" " -f1)
install -D -o root -g root -m 0755 "$SRC" /opt/bitcoinpir/directory-relay/$SHA/bitcoinpir-directory-relay
ln -sfn /opt/bitcoinpir/directory-relay/$SHA /opt/bitcoinpir/directory-relay/current
systemctl daemon-reload && systemctl enable --now bpir-directory-relay
```

Then add the public hostname `directory.bitcoinpir.org → http://localhost:8096`
to the pir1 tunnel (Human: the tunnel is managed in the Cloudflare dashboard,
Zero Trust → Networks → Tunnels → Public Hostname; it applies without a
cloudflared restart).

## Read — health

```sh
systemctl status bpir-directory-relay --no-pager
ss -ltnp | grep -E '127\.0\.0\.1:809[67]'
journalctl -u bpir-directory-relay --since -1h --no-pager
```

The relay logs no event content at any level. A plain HTTPS `GET` on
`https://directory.bitcoinpir.org` is not a health check (WebSocket-only, like
the PIR endpoints); read the catalog back as a client sees it (build the WASM
package first with `wasm-pack build crates/sdk/wasm --target web --out-dir
pkg`):

```sh
node scripts/directory-readback.mjs \
  --relay wss://directory.bitcoinpir.org --centralized-single-relay \
  --directory-pubkey-hex "$DIRECTORY_PUBKEY"
```

`bpir-admin directory-artifact publish --validate-only` checks the artifact
side.

## Publish or update entries

All signing happens on the Mac Studio; pir1 never sees a private key.
Entries and checkpoints expire after at most 31 days, so the whole catalog is
re-signed and republished at least monthly, and after any provider change, by
[`scripts/directory-publish.sh`](../../scripts/directory-publish.sh). Its
directory `.keys/directory/` holds the publisher key, `providers.tsv` (one
line per provider: name, `server_id`, endpoint, role, attestation,
`NAME=ACCESS` backends mirroring the live `GET_INFO_JSON`, and the operator's
key file, the operator's own assertion file, or `retired`), the `ledger.tsv`
the script keeps (per provider the directory sequence and assertion epoch,
and the checkpoint epoch; all strictly increase) and each run's artifacts.

```sh
ssh -N -o UserKnownHostsFile=deploy/known_hosts -o StrictHostKeyChecking=yes \
  -L 8097:127.0.0.1:8097 root@65.21.91.217 &
scripts/directory-publish.sh .keys/directory --validate-only   # signs and checks; publishes nothing
scripts/directory-publish.sh .keys/directory                   # signs again, publishes, records, reads back
kill %1
```

One run signs a fresh assertion for each provider whose operator key is
local (valid 30 days, `VALID_DAYS`), probes each endpoint for the entry's
health class, signs the next entry (or a tombstone for `retired`), signs the
next 16 checkpoints over all of them, publishes everything through the
publisher lane (one positive `OK` per event; replaying an exact artifact is
idempotent), writes the ledger, and reads the catalog back from
`wss://directory.bitcoinpir.org` through the client verifier. A retired
server stays in the checkpoint set; a replaced key or `server_id` is a new
provider id. A third-party operator sends their own assertion
([operator guide](../OPERATOR_GUIDE.md) §8); an
entry cannot outlive it, so its `valid_until` goes in the line's last column.

## Upgrade the relay

```sh
sudo -u pir -H bash -c '. $HOME/.cargo/env && cd /home/pir/src/BitcoinPIR-directory && git fetch origin && git checkout --detach <rev> && cargo build --locked --release -p bitcoinpir-directory-relay'
SRC=/home/pir/src/BitcoinPIR-directory/target/release/bitcoinpir-directory-relay; SHA=$(sha256sum "$SRC" | cut -d" " -f1)
install -D -o root -g root -m 0755 "$SRC" /opt/bitcoinpir/directory-relay/$SHA/bitcoinpir-directory-relay
ln -sfn /opt/bitcoinpir/directory-relay/$SHA /opt/bitcoinpir/directory-relay/current && systemctl restart bpir-directory-relay
```

Previous `<sha256>` directories stay for rollback (`ln -sfn` back, restart).

## Backup and recovery

The SQLite file and its WAL are one state domain; copy them together only
while the service is stopped, or rebuild instead: every event the relay holds
is an immutable artifact the operator keeps next to the ledger, so a lost or
corrupt database is recovered by starting an empty one and republishing the
current entries and checkpoints. `max_archive_events` / `max_archive_bytes`
in the config are capacity decisions, not eviction; the archive only grows.

## Known limits

- One relay means `centralized-single-relay` on the client: no relay
  split-view cross-check. The second origin for strict mode must be another
  host and operator domain.
- The relay is memory-capped at 512 MiB by the unit and rate-limited per lane
  by the config; raise the public lane limits before announcing the directory
  widely.
