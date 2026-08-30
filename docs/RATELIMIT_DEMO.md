# Anonymous Rate-Limiting Demo (ARC + Cashu)

A self-contained, browser-runnable demo of the two anonymous rate-limiting
schemes, end-to-end: **mint → obtain → present → verify**, with a live quota
meter, exhaustion, and replay/double-spend rejection.

It exists so the headline claim — *rate-limit queries without deanonymizing
the user* — can be seen working, not just asserted. Every byte boundary is
also covered by automated tests (see "What's tested" below); the demo is the
human-visible capstone.

> **This is a legacy mechanism demo, not Payment V1 or production rate
> limiting** (free issuance, process-local state, co-located dev gate). Its
> `0x08`/`0x09` frames cannot unlock the enforced Payment V1 server gate. For
> the maintained architecture and integration index, see
> [`RATELIMIT_INTEGRATION.md`](RATELIMIT_INTEGRATION.md).

## Run it

Two processes, no Lightning, no PIR database:

```bash
cargo run -p payment-issuer        # issuer + verify gate on http://127.0.0.1:5601
npm --prefix web run dev           # Vite on http://localhost:3001
# open http://localhost:3001/ratelimit-demo.html
```

The page checks issuer reachability on load (green banner = good; red banner
tells you to start payment-issuer).

## What you'll see

**ARC column (multi-show, experimental):** one credential is designed to
authorise *N* presentations without a stable presentation identifier under the
draft ARC assumptions. This privacy claim remains subject to independent
cryptographic review.
- **Mint credential** → blinds a request in WASM (226 B), sends it to the
  issuer, finalises the 454 B response into a 131 B credential.
- **Present once** → each presentation is accepted by the gate; the quota
  meter ticks 8→0; at 0 the button disables (exhausted).
- **Replay last (rejected)** → re-sends the previous presentation; the gate
  rejects it (`duplicate ARC tag — nonce reused`). Each nonce is single-use
  even though the credential is multi-show.
- **Run to exhaustion** → mints then presents until the meter empties.

**Cashu column (single-show):** a pool of one-time Blind Auth Tokens (BATs).
- **Mint BAT pool** → for each BAT: blind a fresh secret (WASM), batch the
  blinded points to the mint, unblind each returned signature.
- **Spend one** → each BAT is accepted once; the meter drains.
- **Replay last (double-spend)** → re-spends a used BAT; the gate rejects it
  (`BAT already spent`).
- **Mint + spend all** → mints then spends the whole pool.

## ARC vs Cashu

| | ARC | Cashu Blind Auth |
|---|---|---|
| Shape | One credential, *N* presentations | Pool of *N* one-time tokens |
| Crypto | Algebraic MAC (P-256) + range proof | BDHKE (secp256k1) |
| Rate limit | Range proof bounds the nonce to `[0, limit)`; tags dedup per context | One token = one query; spent-set dedup |
| Unlinkability goal | Experimental: presentations should be mutually unlinkable under the draft assumptions | Blind issuance aims to unlink tokens from issuance |
| Wire (present) | `REQ_CREDENTIAL_PRESENT` (0x08) | `REQ_CASHU_BAT_PRESENT` (0x09), `authA…` |
| Issued blob | 131-byte credential | `{id, secret, C}` per BAT |
| Best when | Many queries per credential, fixed budget | Simple pay-per-query metering |

Both are redundant for the basic goal; the project ships both so the
trade-off can be demonstrated.

## Architecture

```
mint ── payment-issuer ── obtain ── browser (WASM) ── present ── payment-issuer gate ── verify
        (free, HTTP)            blind / finalize             (same crypto as the
                                                              PIR server's gate)
```

- **mint / obtain** — `WasmArcCredentialRequest` (`crates/sdk/wasm/src/arc.rs`) and
  `WasmCashuBlind` (`crates/sdk/wasm/src/cashu.rs`) do the blinding/finalising in
  WASM so secrets never reach JS; `web/src/payment-client.ts` +
  `web/src/cashu-bat.ts` orchestrate the HTTP calls.
- **present / verify** — `presentArc` / `presentCashu` post the *exact*
  `0x08` / `0x09` frame payloads (built by `ArcCredentialManager` /
  `CashuBatPool`) to the issuer's `/dev/arc/verify` /
  `/dev/cashu/verify`.

> **Demo vs Payment V1.** The dev-issuer co-locates the verify gate so the demo
> needs no PIR database. The gate runs the *identical* crypto to
> `pir_runtime_core::{arc_verifier, cashu_verifier}` (the same
> `arc::verify_presentation`; the same Cashu `C == k·hash_to_curve(secret)` +
> spent-set). Those legacy verifier primitives remain useful test baselines,
> but production-shaped admission uses the signed, provider/scope/offer-bound
> Payment V1 messages and durable store. The old present frames are not
> translated into a Payment V1 grant.

The credential issuer here is **free** (no payment). Production Payment V1
does not reuse these endpoints or legacy frames. Its issuer acquisition APIs
and signed, provider-bound credential protocol are documented separately in
[`payment/PROTOCOL.md`](payment/PROTOCOL.md).

## What's tested (no browser required)

- `cargo test -p pir-runtime-core --lib arc_verifier` — full ARC issue →
  present → verify loop with a shared key; wrong-key + replay rejection.
- `cargo test -p pir-sdk-wasm --lib` — WASM ARC obtain leg; a WASM-blinded
  Cashu BAT verified under the real `CashuVerifier` (h2c + BDHKE cross-check).
- `cargo test -p payment-issuer` — HTTP round-trips for ARC + Cashu, and the
  verify gate (present → accept, replay → reject) for both schemes.
- `npm --prefix web test` — `payment-client` HTTP + present helpers.

## Files

| Area | File |
|---|---|
| Issuer + gate | [`apps/payment-issuer/`](../apps/payment-issuer/) (`README.md` has endpoint details) |
| WASM obtain | [`crates/sdk/wasm/src/arc.rs`](../crates/sdk/wasm/src/arc.rs), [`crates/sdk/wasm/src/cashu.rs`](../crates/sdk/wasm/src/cashu.rs) |
| HTTP client | [`web/src/payment-client.ts`](../web/src/payment-client.ts) |
| BAT pool | [`web/src/cashu-bat.ts`](../web/src/cashu-bat.ts), [`web/src/credential-manager.ts`](../web/src/credential-manager.ts) |
| Demo page | [`web/ratelimit-demo.html`](../web/ratelimit-demo.html), [`web/src/ratelimit-demo.ts`](../web/src/ratelimit-demo.ts) |
| Legacy/demo server gate | [`apps/server/src/bin/unified_server/`](../apps/server/src/bin/unified_server/) (`--allow-experimental-arc --require-arc` / `--require-cashu`) |
