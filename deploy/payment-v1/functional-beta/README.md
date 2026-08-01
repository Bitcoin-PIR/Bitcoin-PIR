# Hetzner functional-beta all-methods profile

This profile is the shortest functional Payment V1 path. It is intentionally
separate from the production deployment profiles and does not add host
hardening or production rollback-authority dependencies.

Use only freshly generated, non-deterministic keys and artifacts for any
public listener. `payment-v1-no-funds-fixture` is useful as a shape/E2E
generator, but its keys are public test vectors and its output must never be
published or installed on an Internet-facing service.

The signed service policy is authoritative. A single provider process can
advertise workload-specific offers for:

- Free (`open-best-effort` or proof of work);
- direct BOLT11 receipts;
- standard Cashu eCash with online mint verification;
- BitcoinPIR Cashu BAT;
- experimental ARC.

The provider argument superset loads both provider-local BAT/ARC adapters and
one shared issuer. For the first beta, use `shared-issuer-online` in BAT and ARC
offers: the issuer validates/redeems the capability and performs provider
ledger bookkeeping. The same process can later advertise provider-local
BAT/ARC offers without changing the runtime binary. ARC must remain
`deployment_status = "experimental"` and requires the explicit opt-in flags.

## Required binaries and state

- `unified_server`, with the ordinary database/identity/backend arguments plus
  `provider-all-methods.args.in`;
- `payment-issuer serve-cln` plus `issuer-all-methods.args.in`;
- `bpir-admin` for keys, policy/binding artifacts, and one-time store creation;
- one Signet Core Lightning RPC socket for the issuer;
- one HTTPS standard Cashu mint whose canonical manifest is embedded in the
  signed policy.

Initialize the two local beta stores once, before either service starts:

```sh
bpir-admin service-store-init \
  --provider-id-hex "$PROVIDER_ID_HEX" \
  --store /var/lib/bitcoinpir-provider-functional-beta/provider.sqlite3 \
  --rollback-authority /var/lib/bitcoinpir-provider-functional-beta/rollback.sqlite3

payment-issuer init-store \
  --store /var/lib/bitcoinpir-payment-issuer-functional-beta/issuer.sqlite3 \
  --rollback-authority /var/lib/bitcoinpir-payment-issuer-functional-beta/rollback.sqlite3 \
  --issuer-id-hex "$ISSUER_ID_HEX" \
  --network signet
```

## Artifact order

1. Generate independent operator, policy, issuer-root, quote, receipt, BAT,
   ARC, clearing, provider-request, derivation, Cashu recovery/custody and
   idempotency keys with `bpir-admin service-keygen`.
2. Fill the operator public key and stable server ID in the unsigned policy
   TOML, then run `bpir-admin service-policy scope-ids --config ...`. This
   prints the provider ID and all five scope IDs without reading not-yet-built
   credential bindings.
3. Build one direct-receipt, BAT and ARC credential binding per scope. The same
   receipt/BAT/ARC public key may be reused, but each binding is independently
   bound to its exact scope and offer ID.
4. Build the standard Cashu manifest. Put its mint ID and manifest digest in
   every standard-Cashu offer.
5. Sign the complete policy and install the exact same canonical policy bytes
   for provider and issuer.
6. Build the provider clearing authorization with settlement rules for every
   shared BAT/ARC binding, then build the issuer approval. Install the matching
   copies on both sides.
7. Build the Signet quote delegation against the live CLN node ID, initialize
   the stores, and start issuer then provider.

The example prices in the no-funds five-workload fixture are integration
values, not commercial policy. Keep DPF, Harmony hint, Harmony query, Onion and
TEE-ORAM as distinct scopes; in particular, do not reuse the cheaper Harmony
query price for hint generation.

## Deliberate beta boundaries

- The local SQLite rollback arguments are functional-beta state, not a
  production rollback boundary.
- There is no automatic refund/retry layer in this profile.
- Standard Cashu cannot be advertised until a concrete mint endpoint, SPKI
  pin, keysets and exposure limits have been rendered.
- The two PIR providers must render independent provider IDs, policy keys,
  stores, clearing keys, idempotency keys, BAT/ARC lineages and policies. They
  do not name or discover each other through this profile.
