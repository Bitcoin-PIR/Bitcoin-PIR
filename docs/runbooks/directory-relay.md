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
| Directory publisher key (BIP340) | Mac Studio, `.keys/directory-nostr.key`, made by `bpir-admin directory-artifact keygen --out .keys/directory-nostr.key` | Signs entry, tombstone and checkpoint events offline. Never copied to pir1; the relay only pins its public key. |
| Operator identity key (Ed25519) | Mac Studio, the existing `bpir-admin` operator key that signs the servers' identity certificates | Signs each provider's operator assertion (`--operator-signing-key`). |

The directory public key (`directory_pubkey_xonly=` printed by `keygen`) goes
into the relay config (`directory_pubkey_hex`) and into the client pin (web
and SDK, follow-up change). A new publisher key is a new trust namespace:
rotate it only with a client pin update, never in place.

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

Build and install the binary (same pattern as the issuer):

```sh
sudo -u pir -H bash -c 'cd /home/pir/src/BitcoinPIR && git fetch origin && git checkout --detach <rev> && cargo build --locked --release -p bitcoinpir-directory-relay'
SRC=/home/pir/src/BitcoinPIR/target/release/bitcoinpir-directory-relay; SHA=$(sha256sum "$SRC" | cut -d" " -f1)
install -D -o root -g root -m 0755 "$SRC" /opt/bitcoinpir/directory-relay/$SHA/bitcoinpir-directory-relay
ln -sfn /opt/bitcoinpir/directory-relay/$SHA /opt/bitcoinpir/directory-relay/current
systemctl daemon-reload && systemctl enable --now bpir-directory-relay
```

Then add the tunnel ingress `directory.bitcoinpir.org → http://127.0.0.1:8096`
to the pir1 cloudflared configuration (Human; the tunnel config is not in
this repository) and restart cloudflared.

## Read — health

```sh
systemctl status bpir-directory-relay --no-pager
ss -ltnp | grep -E '127\.0\.0\.1:809[67]'
journalctl -u bpir-directory-relay --since -1h --no-pager
```

The relay logs no event content at any level. A plain HTTPS `GET` on
`https://directory.bitcoinpir.org` is not a health check (WebSocket-only, like
the PIR endpoints); read the catalog with the client or the readback tool once
they are restored, or with `bpir-admin directory-artifact publish
--validate-only` for the artifact side.

## Publish or update entries

All signing happens on the Mac Studio; pir1 never sees a private key.

1. Build the artifacts with the commands in
   [Directory protocol](../DIRECTORY_PROTOCOL.md#publisher-artifacts-and-relay-transport):
   one `assertion` per server (operator key, the server's identity
   `server_id`, its public `wss://` endpoint), one `entry` per server
   (`--role`, `--attestation`, `--backend NAME=ACCESS` mirroring the live
   `GET_INFO_JSON`), then one `checkpoints` bundle over every current entry
   and tombstone. Keep the per-provider directory sequence and the last
   `created_at` per `d` coordinate in a ledger next to the key
   (`.keys/directory/ledger.txt`): both must strictly increase.
2. Open the publisher lane and publish through it:

```sh
ssh -N -L 8097:127.0.0.1:8097 pir-hetzner &
bpir-admin directory-artifact publish \
  --artifact pir1.entry.event.json \
  --artifact pir2.entry.event.json \
  --artifact oram.entry.event.json \
  --artifact checkpoints.json \
  --relay ws://127.0.0.1:8097 --loopback-publisher --centralized-single-relay \
  --directory-pubkey-hex "$DIRECTORY_PUBKEY" \
  --now-unix "$(date +%s)" \
  --validate-only
```

   `--validate-only` checks the frozen artifacts, key pin and relay set
   without network I/O; rerun without it to publish. The relay answers one
   positive `OK` per event; replaying an exact artifact is idempotent, a
   negative `OK` is a failure.

3. Verify the public lane returns the new heads (client or readback tool),
   then record the published sequence/epoch in the ledger.

A retired server gets a `tombstone` at the next sequence and stays in the
checkpoint set; a replaced key or `server_id` is a new provider id.

## Upgrade the relay

```sh
sudo -u pir -H bash -c 'cd /home/pir/src/BitcoinPIR && git fetch origin && git checkout --detach <rev> && cargo build --locked --release -p bitcoinpir-directory-relay'
SRC=/home/pir/src/BitcoinPIR/target/release/bitcoinpir-directory-relay; SHA=$(sha256sum "$SRC" | cut -d" " -f1)
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
