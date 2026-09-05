# Anonymous admission and payment integration

Free PIR queries are open. Paid queries present a designated issuer's
cashu/ARC credential on opcodes `0x08` (`REQ_CREDENTIAL_PRESENT`) and
`0x09` (`REQ_CASHU_BAT_PRESENT`). The PIR node verifies the presentation
and announces the issuer endpoint; it does not issue credentials or run
clearing.

## Current boundaries

- [`apps/payment-issuer/`](../apps/payment-issuer/) issues and verifies
  ARC and Cashu credentials. Issuance is currently free (no Lightning
  collection).
- `--require-arc` / `--require-cashu` on the PIR server enable the
  `0x08`/`0x09` verifiers
  (`pir_runtime_core::{arc_verifier,cashu_verifier}`). ARC still needs
  `--allow-experimental-arc`.
- The former Payment V1 signed-policy, directory, clearing, and PoW
  surfaces are deleted; their records live only in git history.
- Production activation, issuer deployment, and Lightning collection
  remain separate operator approval gates
  ([Production operations](PRODUCTION_OPERATIONS.md)).
