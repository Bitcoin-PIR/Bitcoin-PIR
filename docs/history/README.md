# Historical operations evidence

These records preserve prior observations, plans, and incidents. They are not
current operating instructions and must not override
[Production operations](../PRODUCTION_OPERATIONS.md) or its read-only
control-plane status command. In particular, prior generation, database,
measurement, attestation, and timing values are historical evidence, not values
the current status command can infer.

- [Full Direct ORAM UKI preflight (2026-08-11)](../ORAM_FULL_UKI_PREFLIGHT_2026-08-11.md)
  — point-in-time preflight; its image slots, generation, capacities, and timing
  are stale until queried again.
- [ORAM Tier 3 production handoff](../ORAM_TIER3_PRODUCTION_HANDOFF.md)
  — historical deployment evidence and superseded activation context.
- [Production rollout remainder (2026-08-07)](../PROD_ROLLOUT_REMAINDER_2026-08-07.md)
  — deferred rollout plan and notes, not an active checklist.
- [Server warmup removal rollout](../SERVER_WARMUP_REMOVAL_ROLLOUT.md)
  — completed/superseded rollout record.
- [Phase 3 Slice 3 recovery](../PHASE3_SLICE3_RECOVERY.md)
  — historical recovery procedure; not the supported measured-boot release path.
- [ORAM live image binding plan](../ORAM_LIVE_IMAGE_BINDING_PLAN.md)
  — design plan, not proof of a current live binding.
