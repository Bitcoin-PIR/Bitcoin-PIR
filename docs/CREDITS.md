# Credits and gas (paid queries, v2)

Paid queries are priced in **gas**, paid in **credits**, and verified
**online at the issuer**. This page is the design and the contract every
side codes against; it supersedes [Session grants](SESSION_GRANTS.md), which
stay accepted on opcode `0x0b` until every client presents credits.

| Concept | Meaning |
| --- | --- |
| gas | Work. One gas is one CPU-millisecond on the reference machine (pir1, Intel i7-8700, CPU time summed over all threads). Every metered request kind has a formula in public database geometry (`pir_credit::gas`), so a database of any size prices itself and a provider on other hardware changes only its price per gas. |
| credit | Money. One credit is `credit_sat` satoshis (10). The issuer publishes `gas_per_credit` (72,000): the one knob that anchors prices to a fiat target. |
| issuer | The operator-run service that sells credits, verifies every presentation a server forwards, keeps the global double-spend state, and settles with each server in gas. It is the cashier of [Cashier API](CASHIER_API.md), extended (`Bitcoin-PIR/cashier`). |
| presentation | What a client sends on `REQ_CREDIT_PRESENT`: a Cashu token (proofs in sat) or ARC presentations (one credit each). |
| meter | The per-server hourly aggregate of gas, CPU, wall time, and egress per opcode (`pir_credit::meter`), the observability that keeps the calibration honest. |

## Roles

| Role | Holds | Does |
| --- | --- | --- |
| Mint (`cdk-mintd`, unchanged) | Lightning backend, ecash keys | Lightning → ecash; double-spend check on swap |
| Issuer | ARC issuer key per epoch, a mint wallet, the global ARC tag set, the settlement ledger | sells ARC credentials for ecash; answers `POST /v2/redeem` from servers; books gas per server |
| PIR server | the issuer URL and TLS pin, its own identity key (already certified by the operator) | derives its gas table at startup, forwards presentations, keeps a per-connection gas balance, meters every frame |
| Client | ecash, ARC credentials | pays, presents exactly the gas a round needs before sending it |

The PIR host holds no payment secret and no spent set. Two servers can
share one issuer, and the same credential spends on either: a credit is
global, so a two-server DPF lookup pays both servers from one budget.

## Rate card

Worst-case prices for one lookup on a fresh connection with the 2026-09
parameters (`GasParams::PRODUCTION_2026_09`: `credit_sat` 10,
`gas_per_credit` 72,000, `base_gas_per_frame` 20, `egress_gas_per_mb`
1,000). Long connections and batches pay exact gas, which is less.

| Flow | Gas | Credits presented | sat |
| --- | --- | --- | --- |
| OnionPIR single address (pir1) | 669,870 | 10 | 100 |
| HarmonyPIR fresh client: 8 hint sets on pir1, 13 query frames on pir2 | 274,677 | 4 + 1 | 50 |
| HarmonyPIR later lookup, one new connection | 517 | 1 | 10 |
| DPF single address, both servers | 26,045 | 1 + 1 | 20 |
| DPF batch of 75 addresses, both servers (estimate) | 37,710 | 1 + 1 | 20 |
| Direct ORAM single address (pir2, estimate) | 2,070 | 1 | 10 |

The rounding margins are thin on purpose: OnionPIR sits at 9.3 credits,
the HarmonyPIR hint side at 3.8. Retune `gas_per_credit` inside the window
68,540–74,430 when the databases grow or BTC moves; the rate card follows.

## Gas model

`work_gas(db, op)` is computed from the loaded tables at startup
(`unified_server` prints one `[gas db=N] …` line per database and exposes
the table under `"gas"` in `GET_INFO_JSON`). A frame is priced at
`work + base_gas_per_frame + egress_gas_per_mb × response_bytes / 10^6`;
the egress part is charged after the response is known.

| Request | Formula (calibration in `pir_credit::Calibration::PIR1_2026_09`) | Checkpoint 948454 |
| --- | --- | --- |
| DPF INDEX / CHUNK round, sibling pass | 18.9 ns × bins × groups + 261 ms per 10^9 bytes scanned | 1,380 / 4,550; sibling passes 456, 57, 7 (INDEX L0–L2) and 914, 114, 14 (CHUNK L0–L2) |
| tree tops | 5 | 5 |
| OnionPIR key registration | 200 | 200 |
| OnionPIR INDEX query | 15,700 ms per 10^9 bytes of NTT-form INDEX data | 197,506 |
| OnionPIR CHUNK query | 26,000 ms per 10^9 bytes of the shared NTT store | 403,260 |
| OnionPIR sibling query | 21,000 per query | 21,000 |
| HarmonyPIR pool entry (`HINTS_V2`) | 1.016 µs × (INDEX cells + CHUNK cells) | 129,970 |
| HarmonyPIR `HINTS` at a sibling level | 0.71 µs × cells of that level | 3,780 / 470 / 60 and 7,570 / 950 / 120 |
| HarmonyPIR `HINTS_V2_HALF` | 0 (continuation of a paid entry) | 0 |
| HarmonyPIR query frame | 100 ns × groups × (round(√(2·bins)) − 1) × sub-queries per group | 8 (INDEX), 12 (CHUNK) |
| Direct ORAM lookup | 2 ms × padded script-hash slots | 2 per slot (provisional) |

Everything else (info, ping, attest, handshake, announce, catalog, DB
proofs, sealed receipts, admin, the presentation itself) is free.

### Measurements (2026-09-09)

Method: sample the `unified_server` process CPU on pir1
(`/proc/<pid>/stat`, all threads, 50 ms cadence) while the SDK leakage-dump
examples ran single-address lookups from a laptop with a fresh client per
lookup; align phases with the client's timestamps. Two lookups per backend
agreed within 1%.

| Backend | Server CPU per single-address lookup | Notes |
| --- | --- | --- |
| DPF (per server) | 7.7 s | INDEX 1.4, CHUNK 4.6, nine sibling passes 1.8; 18.4 GB scanned; the fit lands 18% above the measured sibling total |
| OnionPIR | 664 s | key registration 0.2, INDEX 197, CHUNK 403, three sibling queries 63; twelve threads busy for 55 s |
| HarmonyPIR hint side | 142 s per fresh client | one pool-entry regeneration 130 (the docs' 136), six on-demand sibling sets 13 |
| HarmonyPIR query side, Direct ORAM | not measured (pir2 is sealed) | analytical: ~50 ms of random reads per HarmonyPIR lookup; ~0.3 MB of AEAD and hash I/O per ORAM address |

Egress per lookup: DPF 9.6 MB, OnionPIR 6.5 MB down and 15 MB up,
HarmonyPIR 131 MB for a fresh client. A HarmonyPIR pool entry serves 532
lookups (INDEX) or 730 (CHUNK); the smallest sibling set serves 23, so a
client that refreshes everything when the smallest set runs out pays 5.9
CPU-seconds per lookup and one that refreshes per level 0.8.

## Metering on the server

- Every metered frame is classified before dispatch
  (`credit_meter::metered_op_for_frame`), timed in process CPU and wall
  time, and its response bytes counted. The hourly `[meter op=0x.. db=N]
  last 3600s: n=… gas_mean=… cpu_mean_ms=… wall_mean_ms=… egress_mean_kib=…
  inflight_max=…` lines plus a `[meter] last 3600s: frames=… gas_total=…
  cpu_total_s=…` total are aggregates only; no per-request line exists.
- With an issuer configured (`--credit-issuer-url`), each connection keeps
  a gas balance (`credit_gate`). A presentation is forwarded to the issuer
  (`credit_issuer`) and, on success, adds `gas_added`; with
  `--require-credits` a metered frame is admitted only if the balance
  covers its work plus base fee and is charged before dispatch; egress is
  charged after, so the balance may dip below zero by one response and the
  next frame waits for a top-up. Nothing carries across connections, so a
  client presents exactly what the next round costs (one issuer round trip
  per lookup) and loses nothing on disconnect. Three rejected
  presentations close the connection.
- Without `--require-credits` metered frames stay free and are still
  metered; presentations are still verified and credited, which is the
  rollout state for checking the issuer path end to end.
- Session grants (`0x0b`) keep working during the migration; a connection
  with an attached grant is charged the grant's credit table instead of
  gas.

### Server flags

| Flag | Effect |
| --- | --- |
| `--credit-issuer-url URL` | Enable credits. `https://` (or `http://` on loopback for tests). Presentations go to `URL/v2/redeem`; `URL/v2/info` supplies the gas parameters at startup (the built-in 2026-09 set applies when it is unreachable). Needs at least one `--session-grant-pubkey FILE`: redeem answers are signed by that key. Needs the server identity (`--identity-*` or the sealed pir2 identity) to sign redeem requests. |
| `--credit-server-id ID` | Name the server settles under at the issuer; defaults to the identity certificate's server id. |
| `--require-credits` | Charge metered frames to the connection balance and refuse uncovered ones. |

Redeem requests are signed by the server's identity key and carry its
operator-signed certificate; answers are signed by the issuer key over the
request nonce, so a CDN or proxy between the two cannot grant gas. The
transport is HTTPS with the Mozilla roots compiled in (no CA files on the
sealed pir2 guest). One issuer call has a 15-second budget and one retry
with the same nonce.

## Protocol

`REQ_CREDIT_PRESENT` (`0x12`): `[kind u8][len u32 LE][payload]`, at most
64 KiB, encrypted channel only (the payload is bearer material). Kinds are
`pir_credit::issuer::CREDIT_PRESENT_KIND_CASHU` (1, a Cashu token) and
`CREDIT_PRESENT_KIND_ARC` (2, one or more ARC presentations). The server
answers `RESP_CREDIT_OK` (`0x12`): `[gas_added u64 LE][gas_balance i64
LE]`, or `RESP_ERROR` with the issuer's reason. Opcodes `0x08`, `0x09`,
and `0x0d`–`0x10` stay retired.

## Issuer API (v2)

All bodies are JSON; the types live in `pir_credit::issuer` so both
repositories share them. The credits contract is served under `/v2/`;
`/v1/` keeps the session-grant contract ([Cashier API](CASHIER_API.md))
until every client has moved.

- `GET /v2/info` → `IssuerInfoV2`: `credit_sat`, `gas_per_credit`,
  `base_gas_per_frame`, `egress_gas_per_mb`, `mints`, `offers` (credits
  for sat), `arc` (epoch, presentation limit, issuer public key,
  presentation context, validity), and an informational `rate_card`.
- `POST /v2/credentials` (client): pays with a Cashu token and a blinded
  ARC credential request; returns the credential response. Idempotent per
  token, as `POST /v1/grants` is today.
- `POST /v2/redeem` (server) → `RedeemRequestV1`: `server_id`, the
  operator-signed identity certificate, a 16-byte nonce, `unix_time`, the
  presented items verbatim, and an Ed25519 signature by the server's
  identity key over `RedeemRequestV1::signing_preimage`. The issuer pins
  the operator keys allowed to certify servers, verifies each item (swaps
  Cashu proofs at the mint; verifies ARC presentations under the epoch key
  and refuses a repeated tag), books `sat_value` to the server's settlement
  account, and answers `RedeemResponseV1 { gas_added, sat_value,
  items_accepted }`. A repeated `(server_id, nonce)` returns the stored
  answer, so a server that lost the response retries safely. Servers never
  forward client addresses.
- Settlement: the issuer holds the money and a per-server ledger of gas
  and sat; paying a foreign server operator is outside the protocol.

ARC parameters: the `Bitcoin-PIR/arc` fork (P-256, Cloudflare draft
ciphersuite), presentation limit 100 per credential (one credential per
1,000-sat pack, so the denomination never shows), presentation context
fixed per epoch (`"BitcoinPIR/credits/v1" ‖ epoch`, hence one global tag
set), `m2` = epoch, epochs of 90 days plus 30 days of grace. Cashu proofs
convert at `gas_per_credit / credit_sat` gas per sat.

## Privacy

The mint sees the invoice and the buyer's address; the issuer sees the
ecash, the blinded ARC request, and the buyer's address at purchase, and
later `(server_id, time, presentation)` for every redemption; a server sees
the connection and the presentation. Presentations are unlinkable to
issuance (blind signatures, ARC), so nothing ties a lookup to a purchase.
What remains is timing, the client's address at the server, the size of
the anonymity set, and the possibility of an issuer that tags a user with
a private key: clients compare the issuer key and epoch against
`/v2/info` and the SDK's pinned values. Query contents were never visible
to anyone; PIR hides them regardless of payment.

## Status

| Step | Where | State |
| --- | --- | --- |
| Gas model, parameters, meter, issuer contract types | `crates/trust/pir-credit` | done |
| `REQ_CREDIT_PRESENT` / `RESP_CREDIT_OK`, gas table and hourly meter in `unified_server`, `GET_INFO_JSON` "gas" | this repository | done (the opcode answers "credits not enabled" until an issuer is configured) |
| Issuer client, per-connection balance, `--credit-issuer-url` / `--require-credits` | `unified_server` | done (issuer side pending, so production stays without the flags) |
| `/v2/redeem` for Cashu tokens, `/v2/info`, settlement ledger | `Bitcoin-PIR/cashier` | next |
| ARC issuance and verification (`/v2/credentials`, ARC items on `/v2/redeem`) | `Bitcoin-PIR/cashier` | after that |
| ARC client, purchase flow, present-per-round | `crates/sdk/wasm`, `web/`, `crates/sdk/client` | after the issuer |
| Retire `0x0b` | protocol registry | after every client presents credits |
