# Testing entry points

Use the repository-owned payment check as the default local and agent entry:

```sh
scripts/payment-v1-local-check.sh
```

It is the `--quick` profile: one focused locked/offline service-admission test,
no browser, no external network, and no privileged environment. It is the only
profile agents should run by default.

```text
--quick    Default focused service-admission check; no browser or deployment audit.
--pr       Deterministic offline Rust, process, WASM, Web typecheck, Web unit
           tests, and production bundle; it does not first run --quick.
--deploy-template-audit
           Explicit static deployment/template, renderer, runtime-evidence,
           publisher, namespace, Caddy, and relay-gate audit; no deployment.
--browser  Explicit opt-in: --pr plus local headless Chromium payment checks.
--full     Explicit compatibility alias for --browser.
```

Run `--deploy-template-audit` only while changing or preparing a Payment
deployment template. Run `--browser` or `--full` only when browser coverage is explicitly requested.
AI manual browser inspection also requires an explicit user request. Automatic
headless browser checks belong only to an explicit browser profile, nightly, or
release validation.

Historical acceptance records in `docs/payment/LOCAL_ACCEPTANCE.md` and related
rollout documents record prior evidence; they are not current operating entry
points. Production deployment, public-server canaries, and real-fund flows are
separate approved operations.

## Mainnet Lightning V1 source readiness

For changes limited to the versioned Mainnet Lightning V1 source profile, use:

```sh
scripts/payment-v1-mainnet-lightning-v1-check.sh
```

It runs the focused offline Rust profile/CLI contract, deployment source and
rendered-artifact contracts, and the Web independent Direct BOLT11/DPF pair
contract. It does not run the broader Payment V1 suite, a browser, a render,
remote Core/CLN, or any funds flow. See
[`docs/payment/MAINNET_LIGHTNING_V1_RUNBOOK.md`](payment/MAINNET_LIGHTNING_V1_RUNBOOK.md)
for the source-ready versus live-approval boundary.
