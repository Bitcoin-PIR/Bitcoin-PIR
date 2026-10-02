# pir2 replacement on a MacBook (no TEE), 2026-10

pir2 (VPSBG SEV-SNP, `wss://weikeng2.bitcoinpir.org`) is deactivated on
2026-10-02 around 05:32 UTC. A MacBook takes over its two serving roles,
**DPF server 1** and the **HarmonyPIR query server**, without a TEE, at
`wss://bitcoin-pir-weikeng-laptop.chenweikeng.com`. Direct ORAM pauses (it needs a TEE).
OnionPIR runs on pir1 and is not affected.

## Who does what

| Party | Does |
|---|---|
| MacBook session (this runbook) | everything on the MacBook |
| Mac Studio session "VPS服务器配置优化" | holds the pir2 operator key and pir1 root SSH: grants read-only rsync on pir1, signs the identity certificate, ships the website switch (Flow C) |
| The user | Cloudflare tunnel, `sudo` steps, relays messages between the two sessions if Remote Control messaging is not set up |

Hard rules:

- Never put a secret in git or chat: the tunnel token and the server
  identity key stay on the MacBook.
- Touch pir1 only through the read-only rsync key from step 2.
- Do not edit web pins; the Mac Studio session does that.
- Stop and report on any hash mismatch or startup failure. Do not "fix"
  data by hand.
- Do not run the leakage test suite on the MacBook.

## 0. Preflight (report the output)

```sh
sysctl -n hw.memsize hw.ncpu machdep.cpu.brand_string
sw_vers -productVersion
df -h ~
```

Required: at least 32 GB RAM and at least 60 GB free disk. If either is
short, stop and report. Startup reads the 15.5 GB OnionPIR NTT file into
memory to hash it: the first node (36 GB M3 Max) peaked at a 31.1 GB memory
footprint and took 196 s to reach `Listening`, so 36 GB has little
headroom.

The user runs, once (keeps the MacBook awake, including with the lid
closed); keep it on AC power, Ethernet if possible:

```sh
sudo pmset -a sleep 0 disablesleep 1
```

## 1. Workspace

```sh
REPO=~/bitcoin-pir          # this clone, branch ops/pir2-macbook-replacement
NODE=~/bpir-node
mkdir -p "$NODE"/{data,identity,bin,logs}
brew install cmake rsync    # rsync 3.x: macOS ships an old/openrsync build
```

## 2. Read-only access to pir1

```sh
ssh-keygen -t ed25519 -f ~/.ssh/bpir_pir1_ro -N '' -C pir2-macbook-ro
cat ~/.ssh/bpir_pir1_ro.pub
```

Send the public key line to the Mac Studio session. It installs it on
pir1 restricted to `rrsync -ro /home/pir/data` (read-only, nothing else).
Remote paths below are therefore relative to `/home/pir/data`. Test:

```sh
export RSYNC_RSH="ssh -i $HOME/.ssh/bpir_pir1_ro -o IdentitiesOnly=yes -o UserKnownHostsFile=$REPO/deploy/known_hosts -o StrictHostKeyChecking=yes"
/opt/homebrew/bin/rsync --list-only root@65.21.91.217:checkpoints/948454_deterministic/
```

## 3. Copy the databases (about 50 GB; start early, resumable)

```sh
RS="/opt/homebrew/bin/rsync -a --partial --info=progress2"
cd "$NODE/data"
for d in checkpoints/948454_deterministic \
         deltas/940611_948454_canonical_20260615 \
         attestations/mainnet_948454_v2_sev_snp \
         attestations/delta_940611_948454_sev_snp \
         attestations/delta_940611_948454_v2_sev_snp; do
  mkdir -p "$d" && $RS "root@65.21.91.217:$d/" "$d/"
done
mkdir -p attestations/mainnet_948454_oram_sev_snp/run
$RS --exclude oram-direct-inputs/ \
  root@65.21.91.217:attestations/mainnet_948454_oram_sev_snp/run/ \
  attestations/mainnet_948454_oram_sev_snp/run/
```

The OnionPIR files inside db0 (about 30 GB) are required even though this
node does not serve OnionPIR: the server checks that every file listed in
`MANIFEST.toml` exists and hashes the non-cuckoo ones at startup.

## 4. Build (in parallel with step 3)

Prerequisites: Xcode Command Line Tools (`xcode-select --install`) and
rustup (`curl https://sh.rustup.rs -sSf | sh -s -- -y`); the pinned
toolchain in `rust-toolchain.toml` installs itself.

```sh
cd "$REPO"
git switch ops/pir2-macbook-replacement
cargo build --locked --release -p runtime --bin unified_server
cargo build --locked --release -p bpir-admin
cargo build --locked --release -p pir-sdk-client --example simple_query
target/release/unified_server --version   # binary_sha256 must be a hash, not "unavailable"
SHA=$(shasum -a 256 target/release/unified_server | cut -d' ' -f1)
mkdir -p "$NODE/bin/$SHA" && cp target/release/unified_server "$NODE/bin/$SHA/"
echo "$SHA"                                # report this: it becomes the web pin
```

This branch carries the fix that makes macOS report a real binary hash;
without it strict web clients reject the node.

## 5. Verify the copied data

```sh
cd "$NODE/data"
shasum -a 256 checkpoints/948454_deterministic/MANIFEST.toml \
              deltas/940611_948454_canonical_20260615/MANIFEST.toml
# expect c19e96751139093b016fbcce130bbda24f1e3193b5bb82b44ed5a0a46b96a483
#        6775f9c4f31d1643bc5aa6a040cb496d34268d9465a3ca43ee5e50f474f00d04
shasum -a 256 checkpoints/948454_deterministic/{batch_pir_cuckoo,chunk_pir_cuckoo,onion_chunk_cuckoo}.bin \
              deltas/940611_948454_canonical_20260615/{batch_pir_cuckoo,chunk_pir_cuckoo,onion_chunk_cuckoo}.bin
# expect, in order (attested builder's signed artifact list):
# 52530b693fcd4fb3a2b85fd8667f382d49d120350062c3afdb2e2d0da589ffc0
# 9457ccec90a8d66f538da1237d217369c1ca4b1c5640c44a546f6452c7e9403d
# 19cb42ee45abe7d42d5f0df23b4b2f97bbc921fae029890a9d3916425c4e6624
# 7b05ed55e7b2d0f381c3d857c349dc6b1291772693a82a5de98815bc6b6ef48a
# 0821688912c24fb8d863dd87b9087bb4440e684241ad38f167a15159737d140d
# 16056d06a12cee34349d1def2603740e0abc714ac5a351b127d9f3d3663d02ef
```

All other files are hash-checked by `unified_server` against
`MANIFEST.toml` at startup; it refuses to start on a mismatch.

## 6. Configuration

`$NODE/data/databases.toml` (identical catalog to pir1; paths are
relative to this file):

```toml
[[database]]
name = "main"
type = "full"
path = "checkpoints/948454_deterministic"
proof_dir = "attestations/mainnet_948454_oram_sev_snp/run"
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

Credit issuer public key (same key pir1 and pir2 use):

```sh
printf '%s\n' 59392a0738106c4954c317f9bfae2e4918fe809fa0c49fdf23493ce709b9c6e0 > "$NODE/issuer.pub"
```

## 7. Server identity

```sh
"$REPO/target/release/bpir-admin" generate-identity --purpose server --out "$NODE/identity/server.key"
```

Send the printed identity **public** key (64 hex) to the Mac Studio
session. It signs a certificate with the pir2 operator key
(`30e02d80…`, already trusted by the issuer and the web client) for
server id `pir2-macbook-v1` and returns it as base64:

```sh
base64 -d > "$NODE/identity/pir2-macbook-v1.cert" <<'EOF'
<paste the base64 from the Mac Studio session>
EOF
```

## 8. First run in the foreground

```sh
"$NODE/bin/$SHA/unified_server" \
  --bind-address 127.0.0.1 --port 8091 \
  --role secondary --serve-queries \
  --config "$NODE/data/databases.toml" \
  --identity-key-path "$NODE/identity/server.key" \
  --identity-cert-path "$NODE/identity/pir2-macbook-v1.cert" \
  --identity-server-id pir2-macbook-v1 \
  --max-connections 128 --websocket-handshake-timeout-ms 10000 \
  --connection-idle-timeout-ms 300000 \
  --credit-issuer-pubkey "$NODE/issuer.pub" \
  --credit-issuer-url https://issuer.bitcoinpir.org \
  --require-credits --access dpf=best-effort:2 --free-threads 2
```

Expect `Manifest verified: 23 files` (db0), `Manifest verified: 20 files`
(db1), then `Listening`. Startup hashes about 34 GB; a few minutes is
normal. Report the startup time and peak memory. Stop it with Ctrl-C once
it listens, then go to step 9.

## 9. launchd service

`~/Library/LaunchAgents/org.bitcoinpir.pir2-macbook.plist` (replace
`USER` and `SHA`; same flags as step 8):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>org.bitcoinpir.pir2-macbook</string>
  <key>ProgramArguments</key><array>
    <string>/Users/USER/bpir-node/bin/SHA/unified_server</string>
    <string>--bind-address</string><string>127.0.0.1</string>
    <string>--port</string><string>8091</string>
    <string>--role</string><string>secondary</string>
    <string>--serve-queries</string>
    <string>--config</string><string>/Users/USER/bpir-node/data/databases.toml</string>
    <string>--identity-key-path</string><string>/Users/USER/bpir-node/identity/server.key</string>
    <string>--identity-cert-path</string><string>/Users/USER/bpir-node/identity/pir2-macbook-v1.cert</string>
    <string>--identity-server-id</string><string>pir2-macbook-v1</string>
    <string>--max-connections</string><string>128</string>
    <string>--websocket-handshake-timeout-ms</string><string>10000</string>
    <string>--connection-idle-timeout-ms</string><string>300000</string>
    <string>--credit-issuer-pubkey</string><string>/Users/USER/bpir-node/issuer.pub</string>
    <string>--credit-issuer-url</string><string>https://issuer.bitcoinpir.org</string>
    <string>--require-credits</string>
    <string>--access</string><string>dpf=best-effort:2</string>
    <string>--free-threads</string><string>2</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>/Users/USER/bpir-node/logs/unified_server.out.log</string>
  <key>StandardErrorPath</key><string>/Users/USER/bpir-node/logs/unified_server.err.log</string>
</dict></plist>
```

```sh
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.bitcoinpir.pir2-macbook.plist
launchctl print gui/$(id -u)/org.bitcoinpir.pir2-macbook | grep -E "state|pid"
```

A LaunchAgent runs while the user is logged in; keep the MacBook logged
in.

## 10. Cloudflare tunnel (the user)

Cloudflare Zero Trust → Networks → Tunnels → Create a tunnel →
Cloudflared → name `pir2-macbook` → install the connector on macOS:

```sh
brew install cloudflared
sudo cloudflared service install <TOKEN>   # token stays on this machine
```

Public hostname: `bitcoin-pir-weikeng-laptop.chenweikeng.com` (the
operator's own zone; no code binds the domain), service type `HTTP`, URL
`localhost:8091`.

Do **not** add a connector to the existing weikeng2 tunnel: pir2 is still
attached until it expires, and Cloudflare would split traffic between
the two machines.

## 11. Verify

```sh
A="$REPO/target/release/bpir-admin"
$A attest ws://127.0.0.1:8091 --expect-binary "$SHA"       # noSevHost, binary hash matches
$A channel-test ws://127.0.0.1:8091
$A attest wss://bitcoin-pir-weikeng-laptop.chenweikeng.com --expect-binary "$SHA"
$A channel-test wss://bitcoin-pir-weikeng-laptop.chenweikeng.com
# simple_query takes the 40-hex HASH160(scriptPubKey) (see web/src/hash.ts),
# not the scriptPubKey. This is HASH160 of example_spks.json main[0]; it has
# one UTXO at 948454.
SH=de2e69f96b7e622f6ad39609b6d8554b37e8aba3
"$REPO/target/release/examples/simple_query" \
  --server0 wss://weikeng1.bitcoinpir.org --server1 wss://bitcoin-pir-weikeng-laptop.chenweikeng.com "$SH"
```

DPF is free on a best-effort basis on both servers, so the DPF query
needs no credits. HarmonyPIR is paid; it is checked from the website
after the switch.

## 12. Report to the Mac Studio session

`$SHA`, server id `pir2-macbook-v1`, the public URL, the outputs of step
11, RAM/CPU from step 0, startup time and peak memory from step 8. The
Mac Studio session then switches the website's second-server slot to
this node (non-TEE pin, ORAM paused) through Flow C.
