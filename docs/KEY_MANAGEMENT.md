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

The owner identity-authority activation certificate and the sealed runtime
certificate are different wire artifacts. `GenerationBoundIdentityCertV2`
belongs to the owner authority store and is not accepted at the runtime
`identity.cert` path. The current sealed runtime requires a legacy
`IdentityCert` V1 signed for the same enrolled identity public key. Its
`server_id` must be copied from the signature-verified sealed `release.bin`
`stable_server_id`; do not infer that value from the authority-store record.
Keep both certificates because the V2 artifact proves the reserved generation
activation while the V1 artifact is the runtime compatibility certificate.

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
stock guest, and SSHes with `.keys/vpsbg-ssh.key` plus
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

`close` reattaches the selected measured-boot image but does not call the
VPSBG `/start` endpoint. `PASS action=close` therefore proves attachment, not
that the guest is running. Read back control-plane status; starting a stopped
guest is a separate explicitly authorized production action.

VPSBG may complete the detach while the immediately following stop request
returns HTTP 423. After that response, read status before retrying anything. If
status already reports `boot_mode=stock`, rerun `open` so it waits for stock
SSH without detaching again. If status still reports measured boot, stop and
investigate instead of repeating the mutation.

Power-state reads race with the platform: a successful `close` reattaches the
image and VPSBG then auto-starts the guest, but an immediate status snapshot
can still report the guest as stopped, and an explicit stop request can take
tens of seconds to settle. Always re-read the nested `state.running` value
before concluding the final power state; never infer it from the first
snapshot or from the HTTP response alone.

A sealed `startup.env` must be placed at
`/home/pir/data/pir2-sealed/startup.env`. Never build a dedicated
"provisioner UKI" to write files to the data disk. The provisioner
approach (`scripts/dracut/97bpir-pir2-sealed-provisioner/`) was an
error; the leftover builder is unused by the production UKI.
