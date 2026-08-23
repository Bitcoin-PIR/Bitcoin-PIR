# Owner key and ceremony asset management

All private keys, ceremony artifacts, and API tokens live in
**`.keys/`** and **`.secrets/`** at the repository root.
Both are git-ignored (see `.gitignore`) and must never be committed.

## `.keys/` — operator private keys and ceremony artifacts

| File | Purpose |
| --- | --- |
| `pir1-operator.key` | pir1 provider-operator Ed25519 seed |
| `pir1-policy.key` | pir1 service-policy signing Ed25519 seed |
| `pir1-clearing.key` | pir1 provider-clearing Ed25519 seed |
| `pir1-server-identity.key` | pir1 server identity Ed25519 seed |
| `pir2-operator.key` | pir2 provider-operator Ed25519 seed (used by `pir2-sealed-release`) |
| `pir2-policy.key` | pir2 service-policy signing Ed25519 seed |
| `issuer-root.key` | Issuer-root Ed25519 seed (BAT V2 class signing) |
| `issuer-settlement.key` | Issuer-settlement Ed25519 seed (accounting approval) |
| `bat-current.key` | Cashu BAT secp256k1 scalar for the current class epoch |
| `credential-derivation.key` | Credential derivation seed |
| `quote.key` | Quote-delegation seed |
| `redeem-derivation.key` | Redeem idempotency seed |
| `vpsbg-ssh.key` | SSH Ed25519 key for the VPSBG Ubuntu host |

### `.keys/pir2-ceremony/` — sealed ceremony artifacts

Subdirectory holding AMD certs (ARK/ASK/VCEK PEMs), per-epoch
`release.bin`, `credentials.envelope.bin`, `identity.cert`,
`public-artifact-set.env`, BAT V2 class/authorization/approval
binaries, and per-ordinal `startup.env` files.

## `.secrets/` — API tokens

| File | Purpose |
| --- | --- |
| `vpsbg-api-token` | VPSBG control-plane API bearer token |

VPSBG scripts default to these repository paths. They do not fall back
to `~/.config/bitcoinpir`. Override with `VPSBG_API_TOKEN_FILE` or
`--token-file` only when the repository file is the wrong credential.

## VPSBG file modification procedure

This is Flow F in [Production operations](PRODUCTION_OPERATIONS.md).
Use [`scripts/vpsbg-data-disk.sh`](../scripts/vpsbg-data-disk.sh). It
detaches measured boot with `{"kernel_image_id":null}`, stop/starts the
guest, and SSHes with `.keys/vpsbg-ssh.key` plus
[`deploy/vpsbg_known_hosts`](../deploy/vpsbg_known_hosts). `open` and
`close` each require an explicit `--image-id` and `--apply`; `put` does
not call `close`.

```sh
scripts/vpsbg-data-disk.sh open --server-id 25285 --image-id CURRENT --dry-run
scripts/vpsbg-data-disk.sh open --server-id 25285 --image-id CURRENT --apply
scripts/vpsbg-data-disk.sh put --local /absolute/file \
  --remote /home/pir/data/relative/path --apply
scripts/vpsbg-data-disk.sh close --server-id 25285 --image-id CURRENT --apply
```

A sealed `startup.env` must be placed at
`/home/pir/data/pir2-sealed/startup.env`. Never build a dedicated
"provisioner UKI" to write files to the data disk. The provisioner
approach (`scripts/dracut/97bpir-pir2-sealed-provisioner/`) was an
error; the leftover builder is unused by the production UKI.
