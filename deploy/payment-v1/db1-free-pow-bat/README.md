# db0 + db1 Free-PoW + BAT provider policies

These are complete, non-activating source templates for the approved BitcoinPIR
product policy. They are not fragments to append to an old beta policy.

- `pir1-service-policy.toml.in` covers pir1 DPF evaluation, Harmony hints and
  Onion evaluation for db0 and db1.
- `pir2-service-policy.toml.in` covers pir2 DPF evaluation, Harmony queries and
  Direct ORAM for db0 and db1.

Every scope has exactly two stable offers: provider-local Free proof of work and
a blinded BitcoinPIR Cashu BAT redeemed through the shared issuer. BOLT11 is the
issuer-side BAT acquisition mechanism, not a direct provider receipt offer.
Neither policy advertises Standard Cashu or experimental ARC.

## Dataset roots

Use the strict root that the named backend actually resolves:

- DPF and Harmony use the verified DB-proof V1 sidecar
  `server-db/MANIFEST.toml` root;
- Onion uses the verified V2 proof sidecar root;
- Direct ORAM uses the verified loaded server-manifest root.

The root placeholders are deliberately separated by provider, db and proof
family. Do not replace them with one generic database root.

## Rendering order

1. Read `docs/DB1_FREE_POW_BAT_IMPLEMENTATION_PLAN.md` and the database
   retention map. Resolve the exact current db0/db1 roots without rebuilding.
2. Render one complete policy per provider with fresh policy epochs and
   independently reviewed limits, profiles, Free-PoW difficulty and BAT prices.
3. Run `bpir-admin service-policy scope-ids` on each rendered unsigned policy.
4. Create a fresh BAT key lineage and credential binding for every scope/offer
   pair. The relative `credential_binding_path` values are unique within each
   provider configuration tree.
5. Sign the complete policy. Install matching canonical policy bytes and BAT
   lineages on the provider and issuer only during a separately authorized
   release.
6. Build the provider clearing authorization and issuer approval for exactly
   the BAT bindings present in that signed policy.

The two providers must use independent provider IDs, policy keys, stores,
clearing keys and BAT audiences. Do not copy a db0 binding into db1 or share one
raw token between providers.

The legacy functional-beta all-methods template remains an integration fixture.
The VPSBG Premium + Free-PoW beta remains historical source for its narrower
db0 experiment. Neither is an input to these complete policies.

Static source validation:

```sh
node scripts/payment-v1-deployment-template-gate.mjs
node --test scripts/payment-v1-deployment-template-gate.test.mjs
```

Rendering, signing with production keys, provider/issuer installation, pir1 or
VPSBG release, public proof publication and any real-value payment require their
separate operator approvals.
