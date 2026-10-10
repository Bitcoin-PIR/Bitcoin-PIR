# deploy/ — what is tracked and what is local-only

This directory mixes reviewed, secret-free deployment source files with
local operational state. `.gitignore` allowlists exact paths (so a new file
cannot silently pass local use while disappearing from commits); everything
not listed below is local-only by construction.

## Tracked (secret-free operational facts)

| Path | What it is |
|---|---|
| `installimage.conf` | Hetzner installimage config for the pir1 host (partitioning/RAID; no credentials) |
| `known_hosts` | Pinned SSH public host keys for the Hetzner host (65.21.91.217) — the host-key-swap defense used by the ops runbooks |
| `vpsbg_known_hosts` | Pinned SSH public host keys for the VPSBG host (server 26939, 212.73.134.61; stock-rootfs windows only) |
| `systemd/*.service` | The host service units: `pir-primary` / `pir-secondary` (Hetzner), `pir-vpsbg` (VPSBG Slice 2), `cloudflared`, `bpir-directory-relay` (pir1 directory relay). Copies of what runs on the hosts; the units contain no secrets (the admin key in `pir-vpsbg.service` is the public half) |
| `directory-relay/config.toml.example` | Directory relay configuration template (loopback listeners, lane limits, directory public key placeholder); rendered on pir1 per `docs/runbooks/directory-relay.md` |

These files are *facts about the deployment*, not activation levers: editing
them here changes nothing on a host. Applying a unit change to a host is a
production operation requiring explicit authorization
(`docs/PRODUCTION_OPERATIONS.md`).

## Local-only (never commit)

| Path | What it is | Why untracked |
|---|---|---|
| `cloudflared_tunnel.env` | Cloudflare tunnel token | **Secret.** Backup story: the tunnel can be re-issued from the Cloudflare dashboard |
| `uki/*.efi` (+ `.meta`, `.sha256`) | Built Tier 3 UKI release images (~110–314 MB each) | Release artifacts, far beyond repo size budget; identity is pinned in `web/src/attest-pin.ts` and recorded in `docs/data-retention/`; retention policy in `docs/DATABASE_ARTIFACT_RETENTION.md` |
| `attested-builder-runs/` | Attested-builder run outputs | Build evidence, retained per `docs/DATABASE_ARTIFACT_RETENTION.md` |
| `logs/` | Ad-hoc operation logs | Scratch |

If you add a new secret-free deployment source file, extend the exact-path
allowlist in `.gitignore` and this table in the same commit.
