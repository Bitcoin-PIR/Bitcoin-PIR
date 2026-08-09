# Testing entry points

Use the repository-owned payment check as the default local and agent entry:

```sh
scripts/payment-v1-local-check.sh
```

It is the `--quick` profile: locked/offline, no browser, no external network,
and no privileged environment. It is the only profile agents should run by
default.

```text
--quick    Default focused deterministic checks; no browser.
--pr       Quick plus deterministic offline Rust, process, WASM, Web typecheck,
           Web unit tests, and production bundle; no Playwright/Chromium.
--browser  Explicit opt-in: --pr plus local headless Chromium payment checks.
--full     Explicit compatibility alias for --browser.
```

Run `--browser` or `--full` only when browser coverage is explicitly requested.
AI manual browser inspection also requires an explicit user request. Automatic
headless browser checks belong only to an explicit browser profile, nightly, or
release validation.

Historical acceptance records in `docs/payment/LOCAL_ACCEPTANCE.md` and related
rollout documents record prior evidence; they are not current operating entry
points. Production deployment, public-server canaries, and real-fund flows are
separate approved operations.
