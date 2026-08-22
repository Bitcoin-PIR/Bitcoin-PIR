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

## VPSBG file modification procedure

To modify files on the VPSBG data disk (`/home/pir/data/`):

1. **Disable measured boot** via the VPSBG API:
   `POST /v1/servers/25285/measured-boot` with `image_id: null`.
2. **Stop then start** the server:
   `POST /v1/servers/25285/stop` → wait → `POST /v1/servers/25285/start`.
3. **SSH in** using `ssh -i .keys/vpsbg-ssh.key root@87.120.8.198`.
4. Modify files directly on the data disk.
5. **Re-enable measured boot** by switching to the desired UKI image:
   `scripts/vpsbg-measured-boot.sh switch --server-id 25285 --image-id <ID> --apply`.

Never build a dedicated "provisioner UKI" to write files to the data
disk. The provisioner approach (scripts/dracut/97bpir-pir2-sealed-provisioner/)
was an error and has been removed.
