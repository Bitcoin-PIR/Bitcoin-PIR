# Payment V1 deployment source contract

This short file is an input to the deployment-template gate. Start operator
work at [Production operations](../PRODUCTION_OPERATIONS.md); the earlier
deployment preparation is retained in
[the payment archive](../archive/payment/HETZNER_VPSBG_DEPLOYMENT.md).

## Storeless measured-policy boundary

The VPSBG storeless profile opens no ProviderStore or rollback authority. A
policy change requires a new measured UKI. The exact protocol digest argument and the script that supplies it MUST be
versioned together. The template gate
reports missing live source-fair evidence as a P1 activation blocker.

## VPSBG Premium + Free-PoW functional beta

This remains a separate stateful source profile; it is not an extension of the
storeless profile. Use [Current production state](../CURRENT_PRODUCTION_STATE.md)
for the current handoff and [Production enablement](../runbooks/production-enable.md)
for the executable preflight entry.
