# Anonymous Rate Limiting — Status & Production Integration Plan

Status doc for the ARC + Cashu anonymous rate-limiting work. Captures what's
**shipped** (a self-contained *demo*) vs. what's needed to turn it into
**real production rate limiting**, plus a sequenced plan and the open
decisions. Companion to [`RATELIMIT_DEMO.md`](RATELIMIT_DEMO.md) (how to run
the demo).

_Last updated: 2026-05-26, after PR #14 (`cf7a154f`)._

---

## 1. What's shipped (and what it is / isn't)

A **mechanism demo**, live and working end-to-end:

- **Demo page:** `https://sdk.bitcoinpir.org/rate-limiting` (playground
  `app/rate-limiting/`).
- **Issuer:** `https://issuer.bitcoinpir.org` → `dev-issuer` on Hetzner pir1
  (systemd `dev-issuer.service`, bound `127.0.0.1:5601`, Cloudflare tunnel
  public hostname).
- **Full loop, both schemes:** mint → obtain (WASM blinding) → present →
  verify, with quota, exhaustion, ARC anti-replay, Cashu double-spend
  rejection.

**It is NOT production rate limiting.** Critical caveats:

- **Free issuance.** `dev-issuer` hands out credentials for free (no payment),
  so anyone can mint unlimited fresh credentials — it demonstrates the
  *cryptography/UX*, not an actual limiter.
- **Co-located dev gate.** `dev-issuer` also runs the *verify* gate (so the
  demo needs no PIR DB). The real PIR servers (`pir1`/`pir2`) are **NOT
  gated** — `--require-arc`/`--require-cashu` are off (turning them on today
  would lock out every user; see §3.3).
- **In-memory state.** The dev-issuer's spent-set / tag-dedup is per-process
  (lost on restart). Fine for a demo, not for production.
- **Dev-grade issuer.** Hand-rolled HTTP, no hardening, `publish = false`,
  labelled DO NOT DEPLOY TO PRODUCTION.

---

## 2. Where the pieces live (code map)

| Layer | Location | State |
|---|---|---|
| Server verify (ARC) | `pir-runtime-core/src/arc_verifier.rs` | ✅ done; real key load via `from_secret_key_file` |
| Server verify (Cashu) | `pir-runtime-core/src/cashu_verifier.rs` | ✅ done (BDHKE + spent-set) |
| Server gate | `runtime/src/bin/unified_server.rs` (`--require-arc` / `--require-cashu` / `--arc-key` / `--cashu-keyset`) | ✅ opt-in, **off in prod** |
| WASM obtain | `pir-sdk-wasm/src/arc.rs` (`WasmArcCredentialRequest`, `WasmArcPresentationState`), `pir-sdk-wasm/src/cashu.rs` (`WasmCashuBlind`) | ✅ done |
| Web obtain/present | `web/src/payment-client.ts`, `cashu-bat.ts`, `credential-manager.ts`, `arc-present.ts` | ✅ done (point at issuer; HTTP) |
| Demo issuer + gate | `dev-issuer/` (free issuance + co-located verify) | ✅ DEV ONLY; deployed `deploy/systemd/dev-issuer.service` |
| Demo UI | `web/ratelimit-demo.html` + `web/src/ratelimit-demo.ts`; playground `app/rate-limiting/` | ✅ done |
| **Real payment service** | `~/bitcoin-pir/payment` (axum + LDK Lightning) | ⚠️ feature-complete prototype, **NOT in git, never deployed** |

**Payment service detail** (the real issuer that replaces `dev-issuer`):
- ARC issuance: `payment/src/arc_issuer.rs` + `api/credential.rs`
  (`POST /credential/issue`, after a paid `POST /invoice`).
- Cashu mint: `payment/src/cashu_keyset.rs` + `api/cashu_auth.rs`
  (`POST /auth/blind/mint`).
- Real LDK Lightning node (BOLT11 invoices, auto-sweep). Admin endpoints
  ed25519-authed. `HANDOFF_ARC.md` exists but is **stale** (describes
  already-built code as TODO).
- Known gaps: no amount→entitlement enforcement (pay 1 sat → 10k creds),
  in-memory invoice/replay state, no DLEQ on BATs, not version-controlled,
  no deploy infra.

---

## 3. The gap: demo → production

Five things stand between the demo and real rate limiting.

### 3.1 Real issuance (replace free `dev-issuer` with the payment service)
- Version-control + harden + deploy `~/bitcoin-pir/payment` (it currently
  isn't even a git repo).
- **Enforce amount → entitlement** (sats paid ⇒ ARC presentation_limit /
  number of BATs). Today both issuers ignore the paid amount.
- The browser client (`payment-client.ts`) currently talks to the
  **dev-issuer's free endpoints** (`/dev/arc/issue`, `/dev/cashu/mint`). The
  real flow is `POST /invoice` → pay (Lightning) → poll `/payment/{hash}` →
  `POST /credential/issue` (ARC) / `POST /auth/blind/mint` (Cashu). That's a
  new client module (`payment-client.ts` would gain `requestInvoice` /
  `pollPayment` and the paid issue/mint calls; note the payment service takes
  base64 bodies where the dev-issuer takes raw binary).

### 3.2 Present in the real query path (not just the demo)
- Today only the demo presents a credential. Production needs the **PIR query
  clients** to present **before** querying: `web/src/dpf-adapter.ts`,
  `harmonypir-adapter.ts`, `onionpir_client.ts` (and the Rust SDK clients in
  `pir-sdk-client/src/{dpf,harmony,onion}.rs`).
- The present helpers exist: `arc-present.ts::sendArcPresentation(ws, mgr)`
  sends `REQ_CREDENTIAL_PRESENT` (0x08) over the **WebSocket** to the PIR
  server; the Cashu equivalent builds `REQ_CASHU_BAT_PRESENT` (0x09) via
  `CashuBatPool.buildPresentFrame`. Wire one of these into each adapter's
  connect/first-query path when a credential is configured.
- The server gate already whitelists info/ping/attest/handshake + the
  presentation itself, and rejects PIR opcodes until a credential is
  presented (`unified_server.rs` ARC/Cashu gate, ~L2810).

### 3.3 Gate the production PIR servers (carefully)
- Flip `--require-arc` / `--require-cashu` on `pir-primary` / `pir-secondary`
  (Hetzner) and the VPSBG `--serve-queries` unit, sharing keys via
  `--arc-key <arc_key.bin>` / `--cashu-keyset <id>:<hex>`.
- **Rollout hazard:** the moment a server requires credentials, every client
  that doesn't present is rejected. Plan a migration: ship the
  presenting-client first (web + SDK), give it time to propagate, **then**
  gate — or gate a *new* endpoint/port and migrate clients to it, leaving the
  un-gated endpoint until deprecation. Do NOT gate the live `weikeng1/2`
  endpoints out from under existing users.
- For the SEV-SNP (pir2) host this also means the gate keys are part of the
  attested config — decide whether the ARC/Cashu keys live inside or outside
  the measured boot.

### 3.4 Durable + multi-server state
- Persist the spent-set (Cashu) and per-context tag-dedup (ARC) across
  restarts (the verifiers currently use in-memory `HashSet`/`HashMap`).
- **Two-server spent-set coordination:** with non-colluding pir1/pir2, a BAT
  spent at one must be rejected at the other — needs a shared/replicated
  spent-set or a per-server token partition. This is a genuine design problem
  (don't hand-wave it).

### 3.5 Credential UX in the real wallet/client
- The demo page is throwaway UI. Production needs credential
  acquisition/storage/quota surfacing in the actual wallet path (e.g. the BDK
  wallet — see `docs/BDK_WALLET_PROTOTYPE.md` — and/or the production web
  client), including localStorage persistence (`ArcCredentialManager` already
  serializes) and low-balance warnings (`ARC_LOW_WARNING`).

---

## 4. Privacy considerations (do not skip)

Credential presentation adds frames to the wire (`0x08`/`0x09`) — verify they
don't undermine the documented privacy invariants (`CLAUDE.md`):
- ARC presentations are **unlinkable** across queries (that's the point);
  Cashu BATs are unlinkable to issuance. The *presence* of a presentation
  frame is uniform per session, so it shouldn't add a query-distinguishing
  side channel — but confirm the present happens once per session at a fixed
  point, not per-query in a way that correlates with query content.
- The EasyCrypt leakage model (`proofs/easycrypt/`) currently does **not**
  cover credential frames. If rate limiting ships to production, extend the
  wire-shape model + the leakage integration tests to include the
  presentation frame.

---

## 5. Suggested sequencing

1. **Decide scheme(s):** ARC, Cashu, or both in production (they're redundant
   for the basic goal — see the comparison in `RATELIMIT_DEMO.md`). ARC suits
   "N queries per paid credential"; Cashu suits "pay per query".
2. **Payment service to prod:** version-control, add amount→entitlement, add
   persistence, deploy (its own host or alongside the issuer). Replace the
   free `dev-issuer`.
3. **Presenting clients:** wire `present()` into the web adapters + Rust SDK
   clients behind a config flag (default off). Ship + let propagate.
4. **Durable + multi-server spent-set.** Solve §3.4.
5. **Gate a migration endpoint**, move clients over, then deprecate the
   un-gated one. Update the leakage model (§4).
6. **Wallet UX** (§3.5).

---

## 6. Open decisions

- ARC vs Cashu vs both for production?
- Where does issuance live, and what payment rails (Lightning only? Cashu mint
  backing)? Pricing model (per query / per credential / subscription)?
- Two-server spent-set: shared store vs token partition vs accept single-host
  weakening?
- Do the gate keys live inside the SEV-SNP measured boot (pir2)?
- Is rate limiting even desired on the *public* demo endpoints, or only on a
  future paid tier?

---

## 7. Operational notes

- **dev-issuer (current):** `cargo run -p dev-issuer` locally, or the deployed
  systemd unit on pir1 (`/home/pir/dev-issuer/`, keys in that dir). Prints a
  ready-to-paste `unified_server --require-arc --arc-key … --require-cashu
  --cashu-keyset …` line for testing the real WS gate.
- **Swapping issuers:** the demo's `payment-client.ts` is the seam — point its
  base URL at the real payment service and add the invoice/poll/paid-issue
  calls. The WASM obtain bindings (`WasmArcCredentialRequest` / `WasmCashuBlind`)
  and the present path are reusable as-is.
- **Security:** the `TUNNEL_TOKEN` in `deploy/cloudflared_tunnel.env` is a
  committed live secret — rotate it. The dev-issuer keys (`arc_key.bin`,
  `cashu_key.bin`) on pir1 are demo keys; production issuance must use the
  payment service's keys (and the gate must load the matching key).
