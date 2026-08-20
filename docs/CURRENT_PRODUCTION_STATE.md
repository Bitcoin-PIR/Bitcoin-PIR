# Current production state

Last updated: 2026-08-21

This documentation change confirms that
`deploy/payment-v1/bat-v2-source-ready/README.md` matches `fce7970c`. This PR
changes only documentation, orchestration scripts, and repo-local skills. It
does not refresh or change a live environment.

| Area | Current handoff | Read or continue with |
| --- | --- | --- |
| VPSBG image | Not refreshed in this documentation change. | `scripts/vpsbg-measured-boot.sh status --server-id SERVER_ID` |
| Tier 3 UKI | Not built, uploaded, or switched in this documentation change. | `scripts/build_uki_tier3.sh` |
| Payment artifacts | No production artifacts were generated in this documentation change. | `scripts/payment-v1-artifacts.sh --help` |
| Issuer state | Not initialized or checked in this documentation change. | `scripts/payment-v1-issuer-state.sh --help` |
| pir2 sealed release | No sealed phase was run in this documentation change. | `scripts/pir2-sealed-ceremony.sh phase --help` |
| Payment service | No private publisher was started and no production source check was run in this documentation change. | `scripts/payment-v1-activate.sh --help` |

Use [PRODUCTION_OPERATIONS.md](PRODUCTION_OPERATIONS.md) for the complete
workflow. Put historical evidence and retired plans in
[archive/payment/](archive/payment/README.md), not in this page.
