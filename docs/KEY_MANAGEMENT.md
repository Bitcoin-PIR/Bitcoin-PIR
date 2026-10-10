# Owner key and ceremony asset management

All private keys, ceremony artifacts, and API tokens live in
**`.keys/`** and **`.secrets/`** at the repository root.
Both are git-ignored (see `.gitignore`) and must never be committed.

## `.keys/` — operator private keys and ceremony artifacts

| File | Purpose |
| --- | --- |
| `pir1-operator.key` | pir1 provider-operator Ed25519 seed |
| `pir1-server-identity.key` | pir1 server identity Ed25519 seed |
| `pir2-operator.key` | pir2 provider-operator Ed25519 seed |
| `vpsbg-ssh.key` | SSH Ed25519 key for the VPSBG Ubuntu host |

Key files of the retired Payment V1 roles (policy, clearing, issuer, BAT,
quote, redeem) may still exist locally; nothing in the repository reads them.

`.keys/pir2-ceremony/` holds the artifacts of the retired sealed-identity
release (AMD certs, `release.bin`, `credentials.envelope.bin`,
`identity.cert`, `startup.env`). Nothing in the repository reads them; keep
them while a rollback to a sealed image is possible.

## `.secrets/` — API tokens

| File | Purpose |
| --- | --- |
| `vpsbg-api-token` | VPSBG control-plane API bearer token |

VPSBG scripts default to these repository paths. They do not fall back
to `~/.config/bitcoinpir`. Override with `VPSBG_API_TOKEN_FILE` or
`--token-file` only when the repository file is the wrong credential.

## VPSBG file modification procedure

This is Flow F in [Production operations](PRODUCTION_OPERATIONS.md).
Use [`scripts/vpsbg-data-disk.sh`](../scripts/vpsbg-data-disk.sh). `open`
prints the live image ID, detaches measured boot with
`{"kernel_image_id":null}`, and waits until the stock guest answers SSH
(`.keys/vpsbg-ssh.key` plus
[`deploy/vpsbg_known_hosts`](../deploy/vpsbg_known_hosts)), nudging it with
a stop or start when the platform leaves it on the old kernel or powered off.
`close` reattaches the image you name.

```sh
scripts/vpsbg-data-disk.sh open
scripts/vpsbg-data-disk.sh put --local /absolute/file --remote /home/pir/data/relative/path
scripts/vpsbg-data-disk.sh close --image-id IMAGE_ID_PRINTED_BY_OPEN
```

`close` does not call the VPSBG `/start` endpoint; read back control-plane
status for the final power state.

Power-state reads race with the platform: a successful `close` reattaches the
image and VPSBG then auto-starts the guest, but an immediate status snapshot
can still report the guest as stopped, and an explicit stop request can take
tens of seconds to settle. Always re-read the nested `state.running` value
before concluding the final power state; never infer it from the first
snapshot or from the HTTP response alone.

Never build a dedicated "provisioner UKI" to write files to the data
disk; that approach was tried, judged an error, and removed.
