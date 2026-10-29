# Run a BitcoinPIR node

For an operator who wants to serve BitcoinPIR lookups from a machine of their
own: what a node is, what it needs, and how to build, identify, run, expose,
list and maintain it. Nothing here needs the maintainer's hosts, keys or
scripts; the reference deployment's procedures are in
[Production operations](PRODUCTION_OPERATIONS.md), and the
[server-1 MacBook runbook](runbooks/pir2-macbook-replacement.md) is a worked
example. Pinned values (binary hashes, measurements, database roots, operator
keys) live in [`web/src/attest-pin.ts`](../web/src/attest-pin.ts) and
[`web/src/production-providers.ts`](../web/src/production-providers.ts), never
here; the commands below print your own.

## 1. What a node is

One `unified_server` process (package `runtime`, `apps/server`) serving one
database generation on one WebSocket port. Its flags pick the backends:

| Backend | Servers per lookup | Status | Serving flags | Privacy rests on |
| --- | --- | --- | --- | --- |
| OnionPIR (FHE) | 1 | first-class | `--role primary --serve-queries` | lattice hardness, not the operator |
| Direct ORAM | 1 | first-class | measured runtime image running `--oram-only` (§6.5) | AMD SEV-SNP; without it the operator sees every query |
| DPF | 2: server 0 and server 1 | optional | `--serve-queries` on both | the two operators not colluding |
| HarmonyPIR | 2: hint server and query server | optional | hint `--serve-hints --pool-size N`; query `--serve-queries` | the two operators not colluding |

`--serve-queries` answers every query backend the node has data for: DPF,
HarmonyPIR queries, and OnionPIR when `--role primary` loaded its files
(`--role secondary` never does). The role does not affect DPF: the client
decides which key each server gets. Requests the flags do not enable are
refused per frame. Node shapes in use are in §6.1. The two sides of a pair
belong to different operators; running both gives clients no privacy against
you.

Before any query a client checks, on every backend
([Verification overview](VERIFICATION_OVERVIEW.md) covers what the wire
reveals):

1. `REQ_ATTEST` (fresh nonce): channel key, self-reported `binary_sha256` and
   `git_rev`, a manifest root per database. The binary hash must match the pin
   (or the transition build during an upgrade).
2. An X25519 handshake to that key opens the encrypted channel.
3. `REQ_ANNOUNCE`: the certificate verifies under the pinned operator key
   inside its validity window; the identity key signs the channel key (which
   must be the handshake key), binary hash, git rev and manifest roots.
4. The database proof (`proof_dir` v1 for DPF and HarmonyPIR, `proof_v2_dir`
   v2 for OnionPIR and Direct ORAM) verifies and matches the database pins;
   tree tops hash to its root and results carry Merkle proofs. A node can
   refuse to answer; it cannot contradict the pinned roots unnoticed.
5. `credits.access` in GET_INFO_JSON says which backends charge.

| Tier | Nodes | Added checks | Binary pin |
| --- | --- | --- | --- |
| No TEE | OnionPIR, DPF, HarmonyPIR | none | self-reported: catches drift from the published build, not a malicious operator |
| SEV-SNP | Direct ORAM | MEASUREMENT pin (OVMF + UKI, which contains `unified_server`); VCEK→ASK→ARK chain to a pinned ARK fingerprint; platform TCB floor; REPORT_DATA binds nonce, channel key, binary hash, git rev and manifest roots | hardware-backed through MEASUREMENT; operator identity optional |

## 2. Hardware

Reference: pir1, Intel i7-8700 (6 cores, 12 threads), 125 GB RAM, NVMe; its
per-lookup measurements on the current generation are in
[Credits and gas](CREDITS.md#measurements-2026-09-09). *Estimate* marks
derived values.

| Node | RAM | Disk | CPU per single-address lookup | Egress per lookup |
| --- | --- | --- | --- | --- |
| Server 1 (DPF + HarmonyPIR query) | ≥ 32 GB (server-1 runbook floor); a DPF lookup scans 18.4 GB of tables, best kept in page cache | ≥ 60 GB free per generation | DPF 7.7 CPU-s; HarmonyPIR query ≈ 50 ms (analytical) | DPF 9.6 MB; HarmonyPIR 46 MB |
| OnionPIR | 64 GB (*estimate*: a lookup scans ≈ 28 GB of NTT data) | same | 664 CPU-s, ≈ 55 s on 12 threads | 6.5 MB down, 15 MB up |
| Server 0 + hint server | as OnionPIR when combined | same, plus the pool directory | DPF 7.7 CPU-s; 130 CPU-s per hint-pool entry, 142 per fresh HarmonyPIR client | 131 MB per fresh HarmonyPIR client |
| Direct ORAM | 8 GB SEV-SNP guest, 4 vCPU (reference: AMD EPYC Milan) | proofs, ≈ 5 GB of `oram-direct-inputs/`, the ORAM pages | gas model 2 ms per padded slot (provisional) | small |

x86_64 builds enable AES-NI, SSSE3, SSE4.1 and PCLMULQDQ
(`.cargo/config.toml`) and compile the OnionPIR engine for `x86-64-v3`
(AVX2): Haswell or newer, or any Zen. Apple Silicon works. OS: Linux
(reference: Ubuntu 24.04) or macOS; `bpir-admin` is Unix-only. Staging the
next generation beside the current one needs a second generation's disk.

## 3. Data

A node serves the generation clients pin: the attested-builder output named by
the database pins in `web/src/attest-pin.ts`. Databases built locally
(`scripts/build_full.sh`, `tools/db-builder`) are for development; their
proofs do not match those pins.

### 3.1 Download

Generation 948454 is published at `https://data.bitcoinpir.org/948454/`: the
six directories the catalog names, byte for byte from pir1's data disk, with
`SHA256SUMS` over all 128 files and the catalog with relative paths at the
root. The same hash list is committed as
`deploy/data-bundles/948454/SHA256SUMS`, so a copy can be checked against
this repository rather than against the bucket it came from. The publishing
side is [Data bundle](runbooks/data-bundle.md).

| Directory | Size | Read by |
| --- | --- | --- |
| `checkpoints/948454_deterministic` | 47.6 GB | every node |
| `deltas/940611_948454_canonical_20260615` | 5.0 GB | every node |
| `attestations/mainnet_948454_oram_sev_snp/run` | 4.6 GB, all of it `oram-direct-inputs/` | the proof of `db_id` 0; `oram-direct-inputs/` only by a Direct ORAM node |
| the other three `attestations/*` | < 1 MB | proofs |

```sh
scripts/data-bundle.sh fetch https://data.bitcoinpir.org/948454 /srv/bpir/data                     # everything, 57 GB
scripts/data-bundle.sh fetch https://data.bitcoinpir.org/948454 /srv/bpir/data oram-direct-inputs  # without the 4.6 GB only Direct ORAM reads
```

`fetch` downloads `SHA256SUMS` and `databases.toml`, then every listed file,
resumable (re-run after an interruption; files that already match are
skipped), and ends with `sha256sum -c`. Point the node at
`/srv/bpir/data/databases.toml`. Any HTTP client does instead: the paths in
`SHA256SUMS` are the URLs under the generation.

### 3.2 Catalog and checks

`databases.toml` of the reference catalog. Paths are relative to the file.
Keep names, types, heights and order: the first entry is `db_id` 0, and
clients pin per `db_id`.

```toml
[[database]]
name = "main"
type = "full"
path = "checkpoints/948454_deterministic"
proof_dir = "attestations/mainnet_948454_oram_sev_snp/run"   # without oram-direct-inputs/
proof_v2_dir = "attestations/mainnet_948454_v2_sev_snp"
base_height = 0
height = 948454
[[database]]
name = "delta_940611_948454"
type = "delta"
path = "deltas/940611_948454_canonical_20260615"
proof_dir = "attestations/delta_940611_948454_sev_snp"
proof_v2_dir = "attestations/delta_940611_948454_v2_sev_snp"
base_height = 940611
height = 948454
```

| Files, per database | Read by | At startup |
| --- | --- | --- |
| `MANIFEST.toml` in `path`, and every file it lists | every node but Direct ORAM | a missing file or SHA-256 mismatch stops startup; `*_cuckoo.bin` files are checked for presence only |
| `batch_pir_cuckoo.bin`, `chunk_pir_cuckoo.bin`, `merkle_bucket_*` | DPF, HarmonyPIR; opened on every non-ORAM node | |
| `onion_*`, `merkle_onion_*` | OnionPIR, with `--role primary` | listed in the manifest, so needed by every role |
| `build-evidence.bin`, `build-evidence.sev-snp-report.bin`, `root-bundle-payload.bin`, `database.manifest.sha256`, `all-artifacts.manifest.sha256`, `server-db/MANIFEST.toml` in each of `proof_dir` and `proof_v2_dir` | served as the database proof | a missing file stops startup |
| `proof_v2_dir/oram-direct-inputs/` | Direct ORAM | checked by the measured image (§6.5) |

A non-ORAM node needs 53 GB per generation (57 GB with the Direct ORAM
inputs), about 30 GB of it OnionPIR files. Startup hashes about 34 GB; a few
minutes before `Listening` is normal.

Verify a copy:

1. Hash what the server does not: each database's `*_cuckoo.bin` files and
   `MANIFEST.toml`, against the generation's `SHA256SUMS` (`fetch` checks
   every file; `sha256sum -c deploy/data-bundles/<generation>/SHA256SUMS`
   from the data directory checks a copy against this repository's list).
2. Verify each proof directory offline with expected values from the matching
   pin in `web/src/attest-pin.ts` (`PRODUCTION_DB_PROOF_PINS` for `proof_dir`,
   `PRODUCTION_ONION_DB_PROOF_V2_PINS` for `proof_v2_dir`), never from a server
   or the proof itself; a delta adds `--expect-from-height` and
   `--expect-from-block-hash`:

   ```sh
   bpir-admin db-proof verify --proof-dir data/attestations/mainnet_948454_v2_sev_snp \
     --expect-build-kind snapshot --expect-height 948454 --expect-block-hash <blockHashHex> \
     --expect-muhash <muhashHex> --expect-bucket-root <bucketSuperRootHex> \
     --expect-onion-root <onionSuperRootHex> --expect-params-hash <paramsHashHex> \
     --expect-network-magic <networkMagicHex> --expect-builder-git-commit <builderGitCommit> \
     --expect-builder-binary-sha256 <builderBinarySha256Hex>
   ```

3. Once the node runs, `bpir-admin db-proof verify-live --server
   ws://127.0.0.1:8091 --db-id N --expect-…` checks the v1 proof it serves.

## 4. Build

Prerequisites: git, a C/C++ compiler and CMake (the OnionPIR engine is C++),
rustup. `rust-toolchain.toml` pins the toolchain, which rustup installs on
first use; dependencies are vendored.

```sh
# Debian/Ubuntu: sudo apt install build-essential cmake git curl
# macOS:         xcode-select --install && brew install cmake
curl https://sh.rustup.rs -sSf | sh -s -- -y
git clone https://github.com/Bitcoin-PIR/Bitcoin-PIR.git && cd Bitcoin-PIR
git checkout --detach <commit>    # any change, even an untracked file, adds -dirty to git_rev
cargo build --locked --release -p runtime --bin unified_server
cargo build --locked --release -p bpir-admin
strip --strip-debug target/release/unified_server   # Linux; macOS strip has no such flag
target/release/unified_server --version
SHA=$(shasum -a 256 target/release/unified_server | cut -d' ' -f1)
sudo mkdir -p /opt/bitcoinpir/unified_server/$SHA
sudo cp target/release/unified_server /opt/bitcoinpir/unified_server/$SHA/
sudo ln -sfn /opt/bitcoinpir/unified_server/$SHA /opt/bitcoinpir/unified_server/current
sudo cp target/release/bpir-admin /usr/local/bin/
```

`--version`, given alone, prints `unified_server <version> git_rev=<commit>
binary_sha256=<hex>` and exits. `binary_sha256` is what a client pins and must
be a hash, not `unavailable`. It changes with the commit, toolchain, OS,
linked libraries and stripping: publish the hash of the file you run. Intel
HEXL (`scripts/install_hexl.sh`, x86_64) speeds up OnionPIR when the build
finds it; otherwise a portable shim is compiled in. Default builds log no
per-query data (the feature `test-only-unsafe-query-logging` logs peers,
request shapes and timing). `nix build` is a development harness only.

Reproducing a reference binary: the pins are hashes of the files the hosts
run, built as above from the commit `web/reproduce.html` names; that page
keeps the commands and the current hashes. With the toolchain
`rust-toolchain.toml` pins, `--locked`, and
`RUSTFLAGS="--remap-path-prefix=$PWD=/build/repo --remap-path-prefix=$HOME=/build"
SOURCE_DATE_EPOCH=0`, the Rust objects carry no checkout path, but the
OnionPIR C++ objects still embed theirs, and the bytes also depend on the
C++ compiler, the linker, whether HEXL was found, and the `strip` version:
expect a functional rebuild, and compare `git_rev` and behaviour, not bytes.

## 5. Identity

| Key | Made with | Kept | Signs | Pinned by |
| --- | --- | --- | --- | --- |
| Operator key (Ed25519) | `bpir-admin keygen` | offline workstation, backed up | identity certificates, directory assertions | clients, the directory, an issuer |
| Server identity key (Ed25519) | `bpir-admin keygen` on the node | the node, mode 0600 | the REQ_ANNOUNCE bundle, credit redeem requests | nobody: the certificate binds it |
| Identity certificate | `bpir-admin sign-identity` | the node | — | binds `server_id` and identity key to the operator key for a validity window |

Steps 1 and 3 are Human and offline; the operator key never reaches the node.

```sh
# 1. Workstation, once. Prints the operator public key (64 hex): publish it.
bpir-admin keygen --out ~/bpir-operator/operator.key
# 2. Node. Prints the identity public key; copy only that to the workstation.
sudo -u bpir bpir-admin keygen --out /srv/bpir/identity/server.key
# 3. Workstation. One certificate per server_id.
bpir-admin sign-identity --operator-key-path ~/bpir-operator/operator.key \
  --server-id alice-s1 --identity-pubkey-hex <identity public key> \
  --valid-until $(( $(date +%s) + 365*86400 )) --out alice-s1.cert
# 4. Node.
sudo install -o bpir -g bpir -m 0644 alice-s1.cert /srv/bpir/identity/
```

Pass `--identity-key-path`, `--identity-cert-path` and `--identity-server-id`
together; startup prints `Identity announce: enabled (server_id=…)`. If they
disagree the node serves without REQ_ANNOUNCE (`Identity announce: DISABLED`),
and with credits configured it refuses to start. `server_id` is part of the
certificate, the announcement, the issuer's settlement account and the
directory `provider_id` (derived from operator key and `server_id`): keep it
stable and unique per node. `keygen` writes a raw 32-byte seed and keeps an
existing file unless `--force`; `--valid-until 0` means no expiry.

| Rotation | Steps | Clients |
| --- | --- | --- |
| Certificate renewal (clients reject one outside its window) | step 3 with the same identity key; replace the file; restart | nothing |
| Identity key | steps 2–4; restart | nothing: they pin the operator key |
| Operator key | new key, new certificates | a new provider: every pin of the old key changes (client lists, an issuer's `operator_pubkeys`, the directory, which tombstones the old `provider_id`) |

## 6. Run

### 6.1 Flags

Common to the shapes below: `--bind-address 127.0.0.1 --port 8091 --config
/srv/bpir/data/databases.toml --connection-idle-timeout-ms 300000` and the
three `--identity-*` flags.

| Node | Role flags |
| --- | --- |
| OnionPIR | `--role primary --serve-queries` |
| Server 1: DPF + HarmonyPIR query | `--role secondary --serve-queries` |
| Server 0 + hint server (+ OnionPIR) | `--role primary --serve-queries --serve-hints --pool-size 8 --pool-dir /srv/bpir/hint-pool` |

`unified_server --help` lists every flag; defaults are in
`apps/server/src/bin/unified_server/cli.rs`: bind `[::]` (all interfaces), port
8091, `--max-connections 128`, `--websocket-handshake-timeout-ms 10000`,
`--connection-idle-timeout-ms 30000`. `--config` overrides `--data-dir`. The
hint pool serves `db_id` 0; `--pool-dir` keeps generated entries across
restarts (each is still served once) and drops entries of another generation.

### 6.2 Access lanes

`--access BACKEND=MODE`, at most once per backend (`dpf`, `harmony`, `onion`,
`oram`):

| Mode | Behaviour |
| --- | --- |
| `free` | never charges; every backend's default without `--require-credits` |
| `paid` | charges credits and refuses an uncovered frame; needs an issuer (§6.3) |
| `best-effort[:N[:GAS_PER_HOUR]]` | charges a connection whose credits cover the frame; otherwise serves it free, N at a time (default 1), queued FIFO up to `--free-queue-wait-ms` (default 10000), within an optional hourly gas budget; beyond that `free capacity busy` |

Free frames run on `--free-threads` threads (default 1; nice 10 on Linux), so
paid work keeps the other cores; OnionPIR runs on its own threads, so its lane
limits concurrency, not priority. Startup prints the policy (`Access: dpf=…
harmony=… onion=… oram=…`); GET_INFO_JSON publishes it and clients follow it.
Examples: free with no issuer, no flag; one OnionPIR lookup at a time,
`--access onion=best-effort:1`; one core of DPF for anyone,
`--access dpf=best-effort:1`; the reference server 1, `--require-credits
--access dpf=best-effort:2 --access harmony=best-effort:2 --free-threads 2`.

API keys let chosen clients in unmetered: `bpir-admin api-key new --label NAME`
prints the key once (for the client) and its `SHA256HEX LABEL` line (append it
to the `--api-key-file`, restart). A key file without keys stops startup. A key
identifies its holder's connections to you.

### 6.3 Payments

The default for a node outside the reference deployment is no payment
(decided 2026-10-26, #429): no issuer flags, `free` or `best-effort` lanes
(§6.2) so the host stays responsive, and API keys for the clients you want
unmetered. There is nothing to fund and nothing to settle; a key holder
skipping the free queue is the only priority a free node gives.

**Charging through the reference issuer, by arrangement.** The project's
issuer (`https://issuer.bitcoinpir.org`) books credits for other operators'
servers on request. It admits a server whose identity certificate (§5) is
signed by an operator key in its `operator_pubkeys`, keeps a ledger of gas
and sat per `server_id`, and holds the money in its wallet. Clients need
nothing new: the web page and the playground buy ecash from that issuer
already, and a credit spends on every server it serves. To join, open an
issue (§10) with your operator public key (64 hex, never the key file) and
your `server_id`s; the project adds the key ([Issuer and
mint](runbooks/issuer-and-mint.md), "Admit another operator's servers") and
you start with `--credit-issuer-url https://issuer.bitcoinpir.org
--credit-issuer-pubkey FILE` (the issuer public key the MacBook node pins,
[pir2 MacBook replacement](runbooks/pir2-macbook-replacement.md)) and the
lanes you want to charge: `--access BACKEND=paid`, or `best-effort` with a
budget, and `--require-credits` when nothing is free. Prices are the
issuer's gas parameters, the same for every server it serves ([Credits and
gas](CREDITS.md), "Rate card"). Settlement is a ledger entry: `bpir-issuer
settlement` on the issuer host shows what each `server_id` earned, and
paying it out is a Lightning transfer the project makes at the agreed
interval. The protocol has no automatic payout, so this is an agreement
between operators, not a market.

**Your own issuer.** Everything the reference deployment runs is open: the
issuer (`bpir-issuer`, repository `Bitcoin-PIR/issuer`), a Cashu mint
(`cdk-mintd`) and a Lightning node behind `cln-rpc-guard`; [Issuer and
mint](runbooks/issuer-and-mint.md) is the complete recipe, and your servers
then pin your issuer's URL and key. The limit is on the client side: neither
a server's `GET_INFO_JSON` nor the directory names an issuer, so the
reference web page and the playground buy only from the reference issuer,
and the Rust SDK meters and presents ecash it is given without buying any.
A node with its own issuer is paid only by clients built to buy from it.
Publishing an issuer per server is a possible extension, not planned.

Mechanics ([Credits and gas](CREDITS.md)): without issuer flags a node takes
no payment and runs `free` and `best-effort` lanes; `paid` and
`--require-credits` refuse to start without an issuer. Credits are Cashu
ecash: the node forwards a presented token to the issuer (`POST
/v2/redeem`), which redeems it at the mint and answers with signed gas; the
node holds no payment secret. It needs `--credit-issuer-url https://ISSUER`,
`--credit-issuer-pubkey FILE` (the issuer's Ed25519 key, 64 hex) and the
identity flags, which sign every redeem request. An issuer accepts only
servers certified by an operator key in its `operator_pubkeys`, bounds clock
skew (300 s in the reference configuration) and books gas and sat per
`server_id`.

### 6.4 Service

Linux: create the user (`sudo useradd --system --home /srv/bpir --shell
/usr/sbin/nologin bpir`) and `/srv/bpir/identity` (owner `bpir`, mode 0700),
make `/srv/bpir/data` readable by `bpir`, run the `ExecStart` line once by
hand as `bpir`, then install the unit (the reference host's own unit is
[`deploy/systemd/pir-primary.service`](../deploy/systemd/pir-primary.service)):

```ini
# /etc/systemd/system/bpir-node.service
[Unit]
Description=BitcoinPIR node (unified_server)
After=network-online.target
Wants=network-online.target

[Service]
User=bpir
ExecStart=/opt/bitcoinpir/unified_server/current/unified_server \
    --bind-address 127.0.0.1 --port 8091 --role secondary --serve-queries \
    --config /srv/bpir/data/databases.toml \
    --identity-key-path /srv/bpir/identity/server.key \
    --identity-cert-path /srv/bpir/identity/alice-s1.cert --identity-server-id alice-s1 \
    --connection-idle-timeout-ms 300000 \
    --access dpf=best-effort:2 --access harmony=best-effort:2 --free-threads 2
Restart=on-failure
LimitNOFILE=65535
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
# hint servers with --pool-dir: ReadWritePaths=/srv/bpir/hint-pool

[Install]
WantedBy=multi-user.target
```

`sudo systemctl daemon-reload && sudo systemctl enable --now bpir-node`;
`journalctl -u bpir-node` should show `hints=no, queries=yes`,
`Manifest verified: N files` per database (current generation: 23, then 20),
`Identity announce: enabled`, `Access: …`, one `[gas db=N]` line per database,
then `Listening on ws://127.0.0.1:8091`. A manifest mismatch panics before
`Listening` (`manifest verification failed`), which the supervisor turns into
a restart loop.

macOS: a LaunchAgent with the same arguments, under your user's paths
([MacBook runbook](runbooks/pir2-macbook-replacement.md) §9 has the plist and a
self-rolling-back switch procedure). It runs only while its user is logged
in; keep the Mac awake (`sudo pmset -a sleep 0 disablesleep 1`).
`launchctl bootout` returns before launchd releases the service: wait until
`launchctl print` no longer finds it, or `bootstrap` fails with
`5: Input/output error`.

### 6.5 Direct ORAM node

Direct ORAM runs inside an AMD SEV-SNP guest booted from the BitcoinPIR
runtime UKI ([UKI build](runbooks/uki-build.md)): `unified_server` built with
`--features cuckoo-oram`, plus a run script that reads `oram-direct-inputs/`
into guest memory, checks it against hashes baked into the image, rebuilds the
ORAM every boot (encrypted, authenticated pages on the data disk; controller
state in guest memory) and starts `--oram-only --access oram=best-effort:2
--free-threads 2`. The image is operator-agnostic: the data disk
(`/home/pir/data`) supplies `databases.toml`, the proof directories, the
chip's VCEK chain (`vcek/`) and the tunnel token (`cloudflared/tunnel.env`,
`TUNNEL_TOKEN=…`). Clients accept the node only if its launch MEASUREMENT
equals a pin; MEASUREMENT covers the UKI bytes and depends on the OVMF build
and the vCPU count and type. The image bakes the database generation, so each
generation brings a new image and pin. The reference host is a VPSBG
measured-boot VM, which `scripts/vpsbg-*.sh` target.

## 7. Expose

The server speaks plain WebSocket on one TCP port; clients reach a public node
at `wss://HOST`.

- Bind `127.0.0.1` and terminate TLS on the same host: a Cloudflare Tunnel
  (the reference) or any reverse proxy that passes WebSocket upgrades. Without
  `--bind-address` the server listens on every interface with plain `ws://`;
  firewall the port. The terminator sees the attest and handshake exchange,
  then ciphertext from clients on the encrypted channel; on a node without a
  TEE the operator-signed identity (§5) keeps it from substituting its own
  channel key.
- Cloudflare Tunnel: Zero Trust → Networks → Tunnels → Create a tunnel →
  Cloudflared; public hostname with service type `HTTP`, URL `localhost:8091`.
  Connector: `sudo cloudflared service install <TOKEN>` (macOS after `brew
  install cloudflared`), or on Linux
  [`deploy/systemd/cloudflared.service`](../deploy/systemd/cloudflared.service)
  (runs as user `cloudflared`) with `TUNNEL_TOKEN=…` in
  `/etc/cloudflared/tunnel.env` (mode 0600). Connectors of one tunnel share its
  traffic: one tunnel per node.
- The endpoint accepts WebSocket upgrades only; a plain HTTPS `GET` through
  the tunnel gets 502. Probe with an upgrade (§9).
- A directory endpoint is a canonical `wss://` URL: lowercase DNS name with a
  dot (no IP literal), no `:443`, no trailing slash, query or fragment.
- Outbound, the node only calls the issuer, over HTTPS, when credits are on.

## 8. Get listed

A node needs no listing to be used: SDK clients take any endpoint (for example
`simple_query --server0 URL --server1 URL`). Listing is how clients find it.

**Production client list.** The web client at <https://app.bitcoinpir.org/>
(and the playground, which vendors `web/src`) connects to the providers in
`web/src/production-providers.ts`, one per slot: server 0 (DPF server 0,
HarmonyPIR hints, OnionPIR), server 1 (DPF server 1, HarmonyPIR queries) and
Direct ORAM, with pins in `web/src/attest-pin.ts`. A node takes a slot through
a reviewed change to both files: endpoint, operator public key, and binary
SHA-256 (no TEE) or MEASUREMENT and ARK fingerprint (SEV-SNP). Ask in an issue
first; every later binary change then goes through a transition pin (§9).

**Service directory.** The directory publisher signs one Nostr entry per
provider and publishes it, with signed checkpoints, to a directory-only relay
([Directory protocol](DIRECTORY_PROTOCOL.md),
[Directory relay](runbooks/directory-relay.md)). There is one relay, so
clients use the explicit `centralized-single-relay` mode and show the catalog
as centralized/degraded. The browser client reads and verifies the catalog
(`web/src/nostr-directory.ts`) and offers its providers per backend
(`web/src/directory-providers.ts`): a listed server appears in the page's
provider selects with the trust tier the directory asserts for it
(operator identity, or SEV-SNP against the client's known-good MEASUREMENT),
and is closed against the live server after connecting.

1. Sign an operator assertion on the workstation (`--stable-server-id` is the
   certificate's `server_id`). It prints `provider_id`,
   `operator_pubkey_ed25519` and `assertion_digest`.

   ```sh
   NOW=$(date +%s)
   bpir-admin directory-artifact assertion --operator-signing-key ~/bpir-operator/operator.key \
     --stable-server-id alice-s1 --assertion-epoch 1 --not-before "$NOW" \
     --valid-until $((NOW + 30*86400)) --endpoint wss://pir.alice.example \
     --now-unix "$NOW" --out alice-s1.assertion.bin
   ```

2. Send the publisher, in an issue, `base64 < alice-s1.assertion.bin`, the
   printed lines, its `--valid-until` (your entry cannot outlive it), and the
   entry's claims: `role` (`primary`/`secondary`),
   attestation (`none`/`sev-snp`) and, per backend you serve, its access class
   (`free`, `paid` or `best-effort`, as your `Access:` startup line shows).
3. The publisher builds your entry with the directory key (`directory-artifact
   entry`), rebuilds the 16 shard checkpoints and publishes them.
4. An assertion lasts at most 31 days. Before it lapses, sign the next one with
   `--assertion-epoch` one higher and send it; likewise when an endpoint, role,
   backend or access class changes. To leave, ask for a tombstone.

A client fetches all 16 shards, requires complete signed checkpoints, verifies
your assertion, runs the checks of §1 against your endpoint, and requires your
live identity, role, attestation and every listed access class to match the
entry; a mismatch drops the entry, with no fallback. An SEV-SNP node that
announces no identity is matched by its attestation instead (pinned
MEASUREMENT, report bound to the channel key). To see your entry as clients
do (after `wasm-pack build crates/sdk/wasm --target web --out-dir pkg`):

```sh
node scripts/directory-readback.mjs --relay wss://directory.bitcoinpir.org \
  --centralized-single-relay --directory-pubkey-hex <PRODUCTION_DIRECTORY key>
```

## 9. Operate

**Health.** The `curl` probe prints 101 when the endpoint accepts a WebSocket
upgrade (it then waits out `-m`):

```sh
H=pir.alice.example
curl -s -o /dev/null -w '%{http_code}\n' --http1.1 -m 10 -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "https://$H"
bpir-admin attest "wss://$H" --expect-binary "$SHA"   # Status: NoSevHost; non-zero exit on mismatch
bpir-admin channel-test "wss://$H"                    # handshake, encrypted ping and info
```

A DPF pair end to end: `cargo build --locked --release -p pir-sdk-client
--example simple_query`, then `target/release/examples/simple_query --server0
wss://… --server1 wss://… <40-hex HASH160(scriptPubKey)>`. The log has no
per-request lines, only hourly aggregates: `[meter op=0x.. db=N] last 3600s:
…`, `[meter] last 3600s: …`, `[access BACKEND] last 3600s: free_served=…
free_gas=… busy=…` (a growing `busy` means the free lane is full) and, on hint
servers, `[hint-pool db=0] last 3600s: generated=…`. The repository's hourly
monitor (`scripts/node-monitor.sh`) probes the reference nodes only.

**Upgrade the binary.** (1) Build the new commit (§4) into a new
`/opt/bitcoinpir/unified_server/<SHA>/`, leaving the running one in place.
(2) If a client list pins your binary, get the pin set to the new hash with the
running hash as `transitionBinarySha256Hex` and wait until it is deployed; a
pin without the running build marks your node mismatched until you switch.
(3) Point `current` at the new directory, `sudo systemctl restart bpir-node`,
wait for `Listening` and rerun the health checks (macOS: the runbook's switch
procedure). (4) Ask for the transition hash to be removed. Rollback: point
`current` back at the previous directory and restart; until step 4 the pin
still accepts it.

**Upgrade the data.** A new generation changes the database pins in
`web/src/attest-pin.ts`. Stage it beside the current one, verify it (§3),
write the new `databases.toml` next to the old, replace the old one atomically
(`mv`) and restart. Until servers and pins agree, old clients report the new
proof as a mismatch or new clients the old one; either order is safe. Both
sides of a DPF or HarmonyPIR pair must serve the same generation. Hint-pool
entries of the old generation are dropped at startup. Keep the previous
generation and its `databases.toml` until you no longer need to roll back.

## 10. Help

Questions, listing requests and bugs:
<https://github.com/Bitcoin-PIR/Bitcoin-PIR/issues>. Include the `--version`
line, the endpoint, the `server_id` and the startup log up to `Listening`;
never keys, API keys or tunnel tokens. Terms: [Glossary](../GLOSSARY.md).
