# Local Core Lightning regtest E2E

This is an explicitly opt-in, local-only integration check for the V1 BOLT11
acquisition and provider-admission path. A passing run proves that the browser
can obtain and validate a real regtest BOLT11 invoice from `payment-issuer
serve-cln`, pay it from a payer through a distinct router to the issuer, observe
durable settlement, recover an intentionally lost claim response, and consume
the resulting provider-bound capability. A second joined browser topology then
takes independently issued direct-receipt, BAT and experimental-ARC
capabilities through two unmodified `unified_server` gates before mandatory
tree-top preflight, one real encrypted DPF query and explicit Merkle
inclusion/absence verification.

The current command exercises direct BOLT11 receipts, Lightning-funded Cashu
BAT capabilities, and Lightning-funded ARC capabilities twice: once for
acquisition/recovery, and once in the joined provider/query topology. ARC
remains experimental and this local result is not a substitute for its
independent cryptographic review.

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
- one native Core Lightning invoice/issuer node forced to `regtest`;
- one independent native Core Lightning router node forced to `regtest`; and
- one independent native Core Lightning payer node forced to `regtest`.

The joined phase launches two independent payment/credential issuer processes
with distinct issuer identities, HTTP origins, policy and credential keys, and
durable stores. For this deliberately minimal three-CLN-node topology, both
issuer processes settle invoices through the same checked CLN invoice node.
That models the allowed case where providers participate in one settlement
service, but the CLN operator can correlate both payment flows; it is not
evidence for independent Lightning operators. The two PIR providers still have
distinct provider IDs, policy keys, method keys, stores, rollback floors and
listeners, and neither receives an invoice, payment hash or preimage.

Every `bitcoin-cli` and `lightning-cli` call carries the temporary data path and
an explicit `regtest` selector. Startup then fails closed unless Bitcoin Core
and all three CLN nodes independently report `regtest`. The script never reads
or writes the default `~/.bitcoin` or `~/.lightning` trees. The payer and router
receive only freshly mined regtest coins. They open two `announce=true` channels
on unique loopback ports. `--developer --dev-allow-localhost` makes those
otherwise-invalid localhost announcements usable only inside this isolated
test. There is deliberately no payer-to-issuer channel; payer gossip must learn
the public, active `router -> issuer` direction before the browser test starts.

The amounts occupy distinct layers and must not be conflated:

| Layer | Current disposable-regtest value | Purpose |
|---|---:|---|
| Core-to-CLN wallet funding | 5 BTC each to payer and router | Deliberately oversized valueless regtest wallet balance; not a faucet or production recommendation |
| Lightning channel capacity | 1,000,000 sat for payer -> router and 1,000,000 sat for router -> issuer | Gives deterministic outbound liquidity and ample fee/anchor reserve margin |
| BOLT11 invoice amount | 1 sat direct receipt; 4 sat BAT; 4 sat experimental ARC | Exact prices from the current DPF fixture; acquisition/recovery and joined-provider phases each make three payments, delivering 18 sat total across the complete command, plus routing fees paid by payer |

Six blocks are mined after both channel opens so CLN can lock in and announce
them. The script then requires all four local peer views to be
`CHANNELD_NORMAL` and the payer's remote gossip view to mark `router -> issuer`
both public and active. These values are test determinism margins, not minimum
requirements and not guidance for the persistent Signet topology.

Every synchronous Core/CLN CLI call also runs under its own ten-second hard
deadline. The surrounding readiness loops remain bounded separately, so a
wedged RPC client cannot turn a nominal startup or cleanup timeout into an
unbounded hang.

The script does not enable shell tracing and does not print an invoice, payment
hash, or preimage. CLN and Bitcoin Core output goes only to the temporary
directory, which the exit trap removes after stopping the exact PIDs it
started. If PID ownership cannot be proven from that unique temporary path, the
trap refuses to signal the PID or delete the directory and reports the path for
manual inspection.

An early marker-bound trap covers failures between creation of the outer
runtime directory and installation of the full PID-aware trap. The nested
issuer/provider browser harness likewise deletes its private runtime only after
every exact child has confirmed exit; if termination fails, it retains and
reports that owner-only evidence directory instead of unlinking a live child's
store or log.

The disposable regtest invoice is necessarily passed as an argument to the
local payer's `lightning-cli xpay` process and may therefore be visible briefly
to same-host process inspection. This is another reason the script is forbidden
for real invoices or shared production hosts.

`xpay` also returns the disposable preimage to the short-lived Node test. The
joined case verifies it against the invoice hash, searches the named provider
observations for it, and zeroizes its mutable `Buffer` after the assertion.
Node's immutable JSON/stdout strings cannot be guaranteed zeroized, so traces,
screenshots and video are disabled for that case and the entire process remains
local-regtest-only.

## Prerequisites

Install these native commands on the development host:

- `bitcoind` and `bitcoin-cli` with regtest support;
- `lightningd` and `lightning-cli`; CLN must provide `xpay` (v24.11 or newer);
- `jq`, `python3`, Node.js, npm, and the pinned `wasm-pack` toolchain;
- the repository's Web dependencies (`cd web && npm ci`); and
- the installed `wasm32-unknown-unknown` Rust target.

Before starting Bitcoin Core or CLN, the script rebuilds
`crates/sdk/wasm/pkg` with `wasm-pack --locked --offline`; it never accepts a
possibly stale generated WASM file merely because that file exists. The Rust
crates used by the test must already be available to Cargo offline.
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
2. rebuild the generated browser WASM package with Cargo forced offline;
3. allocate fresh private data directories and unique high loopback ports;
4. start and verify one isolated Bitcoin Core regtest;
5. mine disposable regtest coins;
6. start and verify three independent CLN regtest identities;
7. fund the payer and router, confirm two announced channels, and require the
   payer to learn the active `router -> issuer` gossip direction;
8. export only the temporary CLN socket, payer directory, and issuer public key;
9. run `npm run test:e2e:payment-cln-regtest`, first for lost-response
   acquisition recovery and then for the joined two-provider DPF/Merkle path;
   and
10. stop only the four owned processes and remove their temporary state.

Interrupting the command with `INT`, `TERM`, or `HUP`, or any test failure,
runs the same cleanup path.

## What this does not establish

A passing local check does not validate public Lightning routing, production
liquidity, TLS/edge configuration, node key custody, backup/restore, payout
operations, monitoring, an external Cashu mint, a public Nostr relay, or the
two-provider production deployment. No production or staging rollout should be
enabled from this result alone. The joined test's explicit `NoSevHost` report
binding and deterministic all-zero database are not production attestation,
identity/binary pins or a production database proof.

On an acquisition/recovery browser-test failure, Playwright may retain a
regtest trace beneath `web/test-results/payment-cln-regtest`. Treat it as
test-sensitive diagnostic data and do not publish it without inspection, even
though the coins and invoices belong only to the disposable regtest. The
joined-provider config disables trace, screenshot and video persistence
because that browser sees three additional invoices and claim exchanges.
