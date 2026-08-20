# Production operations

Start here for an authorized production change. Check the current handoff first:
[CURRENT_PRODUCTION_STATE.md](CURRENT_PRODUCTION_STATE.md).
For the ordered end-to-end path, use the
[BitcoinPIR production workflow skill](../.agents/skills/bitcoinpir-production-workflow/SKILL.md).

| Operation | Runbook | Command | Successful handoff |
| --- | --- | --- | --- |
| Build a UKI | [UKI build](runbooks/uki-build.md) | `scripts/build_uki_tier3.sh` | `PASS uki_build` |
| Upload, switch, or roll back a VPSBG image | [VPSBG image](runbooks/vpsbg-image.md) | `scripts/vpsbg-measured-boot.sh` | `PASS action=...` |
| Prepare Payment V1 artifacts | [Payment artifacts](runbooks/payment-artifacts.md) | `scripts/payment-v1-artifacts.sh` | `PASS artifact=...` |
| Initialize issuer state | [Issuer state](runbooks/issuer-state.md) | `scripts/payment-v1-issuer-state.sh` | `PASS issuer_state=...` |
| Run the pir2 sealed release | [Sealed release](runbooks/pir2-sealed-release.md) | `scripts/pir2-sealed-ceremony.sh` | `PASS sealed_release` or `PASS sealed_phase_config=...` |
| Start the private publisher network | [Private start](runbooks/payment-private-start.md) | `scripts/payment-v1-activate.sh private` | `PASS private_start` |
| Prepare final production enablement | [Production enablement](runbooks/production-enable.md) | `scripts/payment-v1-activate.sh production` | `PASS production_source_readiness` |

Before a command changes a remote host, image, service, identity, or funds,
confirm the authorization for this run. Each script prints its next required
input and a `NEXT_STEP` line.

For the retained database inputs and artifact locations, see
[Database artifact retention](DATABASE_ARTIFACT_RETENTION.md). Technical
payment references remain in [`docs/payment/`](payment/); prior plans and
evidence are in [`docs/archive/payment/`](archive/payment/README.md).
