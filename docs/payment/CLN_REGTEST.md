# Local Core Lightning regtest E2E

This is an explicitly opt-in, local-only integration check for the V1 BOLT11
acquisition path. It proves that the browser can obtain and validate a real
regtest BOLT11 invoice from `payment-issuer serve-cln`, pay it through a second
Core Lightning node, observe durable settlement, recover an intentionally lost
claim response, and consume the resulting provider-bound capability.

The current browser suite exercises direct BOLT11 receipts, Lightning-funded
Cashu BAT capabilities, and Lightning-funded ARC capabilities. ARC remains
experimental and this local result is not a substitute for its independent
cryptographic review.

It does **not** use real funds and is not a production-node procedure.

## Safety boundary

[`scripts/payment-v1-cln-regtest-e2e.sh`](../../scripts/payment-v1-cln-regtest-e2e.sh)
creates all state beneath a fresh owner-only `mktemp` directory under the
canonical `/tmp` path. The short parent is intentional: unlike CLN's CLI, the
issuer opens the verified RPC socket by absolute path, which must fit strict
platform `AF_UNIX` path limits. The script rejects an unexpectedly long socket
path before starting anything. It starts:

- one Bitcoin Core node forced to `regtest`, with P2P discovery and listening
  disabled and RPC bound only to `127.0.0.1` on an OS-selected high port;
- one native Core Lightning invoice/issuer node forced to `regtest`; and
- one independent native Core Lightning payer node forced to `regtest`.

Every `bitcoin-cli` and `lightning-cli` call carries the temporary data path and
an explicit `regtest` selector. Startup then fails closed unless Bitcoin Core
and both CLN nodes independently report `regtest`. The script never reads or
writes the default `~/.bitcoin` or `~/.lightning` trees. The payer receives only
freshly mined regtest coins and opens a private, loopback-only channel.

The script does not enable shell tracing and does not print an invoice, payment
hash, or preimage. CLN and Bitcoin Core output goes only to the temporary
directory, which the exit trap removes after stopping the exact PIDs it
started. If PID ownership cannot be proven from that unique temporary path, the
trap refuses to signal the PID or delete the directory and reports the path for
manual inspection.

The disposable regtest invoice is necessarily passed as an argument to the
local payer's `lightning-cli xpay` process and may therefore be visible briefly
to same-host process inspection. This is another reason the script is forbidden
for real invoices or shared production hosts.

## Prerequisites

Install these native commands on the development host:

- `bitcoind` and `bitcoin-cli` with regtest support;
- `lightningd` and `lightning-cli`; CLN must provide `xpay` (v24.11 or newer);
- `jq`, `python3`, Node.js, and npm;
- the repository's Web dependencies (`cd web && npm ci`); and
- the already built local `crates/sdk/wasm/pkg/pir_sdk_wasm_bg.wasm` package.

The Rust crates used by the test must already be available to Cargo offline.
The Web Playwright Chromium installation must also already be present. The
script deliberately does not install tools, download crates, or contact a
public Lightning service.

## Run

From the repository root:

```sh
scripts/payment-v1-cln-regtest-e2e.sh --acknowledge-local-regtest-only
```

The exact acknowledgement is mandatory. There is no environment-only shortcut
and no option to point this script at an existing or remote Bitcoin/CLN node.

The script performs the following sequence:

1. resolve and validate the repository and native dependencies;
2. allocate fresh private data directories and unique high loopback ports;
3. start and verify one isolated Bitcoin Core regtest;
4. mine disposable regtest coins;
5. start and verify two independent CLN regtest identities;
6. fund the payer and confirm a private payer-to-issuer channel;
7. export only the temporary CLN socket, payer directory, and issuer public key;
8. run `npm run test:e2e:payment-cln-regtest`; and
9. stop only the three owned processes and remove their temporary state.

Interrupting the command with `INT`, `TERM`, or `HUP`, or any test failure,
runs the same cleanup path.

## What this does not establish

A passing local check does not validate public Lightning routing, production
liquidity, TLS/edge configuration, node key custody, backup/restore, payout
operations, monitoring, an external Cashu mint, a public Nostr relay, or the
two-provider production deployment. No production or staging rollout should be
enabled from this result alone.

On a browser-test failure, Playwright may retain a regtest trace beneath
`web/test-results/payment-cln-regtest`. Treat it as test-sensitive diagnostic
data and do not publish it without inspection, even though the coins and
invoices belong only to the disposable regtest.
