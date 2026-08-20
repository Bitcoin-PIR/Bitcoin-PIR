# Prepare final production enablement

Use [`scripts/payment-v1-activate.sh`](../../scripts/payment-v1-activate.sh)
with the `production` subcommand. The current repository entry performs the
source-readiness handoff before a rendered installation and activation
transaction is selected.

## Inputs

The source-readiness command accepts no additional input.

## Run

```sh
scripts/payment-v1-activate.sh production --dry-run
scripts/payment-v1-activate.sh production
```

Success prints `PASS production_source_readiness` and `NEXT_STEP`. Continue by
preparing the reviewed rendered installation and activation transaction named
by that handoff.
