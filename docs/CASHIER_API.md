# Cashier HTTP contract (v1)

The cashier sells [session grants](SESSION_GRANTS.md) for Cashu ecash. It is
operator-run, lives in its own repository under the Bitcoin-PIR
organisation, and is the only component that holds the grant signing key or
talks to a mint. The PIR servers pin its **public** key; the browser pins
its **URL** (`PRODUCTION_CASHIER_URL` in `web/src/constants.ts`). This page
is the contract both sides code against; the implementation is free to add
fields, never to change the meaning of the ones below.

All responses are JSON. The cashier must send CORS headers for the web
origin (`Access-Control-Allow-Origin`, `Access-Control-Allow-Headers:
content-type`) because the browser calls it directly. Clients send no
cookies and no referrer.

## `GET /v1/info`

```json
{
  "service": "bitcoinpir-cashier",
  "version": 1,
  "cashier_pubkey_hex": "<64 hex: Ed25519 key the PIR servers pin>",
  "mints": ["https://mint.example"],
  "offers": [
    { "credits": 1000, "amount": 210, "unit": "sat" }
  ],
  "grant_ttl_secs": 86400
}
```

- `mints`: https mint URLs whose ecash the cashier accepts. The browser
  obtains ecash from one of them (Lightning invoice → mint quote → proofs)
  or the user pastes a token from any Cashu wallet drawing on one of them.
- `offers`: fixed packs. A client pays exactly `amount` of `unit` for
  `credits`; there is no fractional pricing.
- `grant_ttl_secs`: lifetime the cashier stamps on issued grants (bounded by
  the server-side maximum of 30 days).

## `POST /v1/grants`

Request:

```json
{
  "offer": { "credits": 1000, "amount": 210, "unit": "sat" },
  "token": "cashuB…"
}
```

The cashier verifies that `offer` is one it currently lists, that the token
draws on an accepted mint and is worth exactly `amount` `unit`, swaps
(receives) the token at the mint, and only then issues a grant:

```json
{
  "grant_base64": "<133 bytes, docs/SESSION_GRANTS.md>",
  "grant_id_hex": "<32 hex>",
  "credits": 1000,
  "issued_at": 1800000000,
  "expires_at": 1800086400
}
```

The browser decodes the grant and refuses a response whose embedded fields
disagree with `offer` or with the metadata above.

Errors are `{ "error": "<code>", "message": "<text>" }` with these codes:

| Status | `error` | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | malformed body, unknown offer, token not parseable |
| 400 | `wrong_amount` | token value is not exactly `offer.amount` |
| 400 | `mint_not_accepted` | token draws on a mint not in `mints` |
| 402 | `token_rejected` | the mint refused the swap (already spent, bad signature) |
| 503 | `mint_unavailable` | the mint could not be reached; the token was not consumed |

## Idempotency and failure atomicity

A client that loses the response must be able to re-send the same request
safely. The cashier therefore treats `(token)` as the idempotency key: once a
token has been swapped, every later `POST /v1/grants` carrying the same
token returns the grant it produced (same grant id, same bytes) until that
grant expires. Deriving `grant_id` from the token's proof secrets (for
example the first 16 bytes of SHA-256 over the sorted secrets) makes this
natural and keeps grant ids unique across cashier restarts.

If the swap at the mint fails before the mint accepted the token, the token
is still spendable by the client and the cashier answers 503 or 402 without
issuing anything. The cashier must never issue a grant for a token it did
not successfully receive.

## Settlement

Each PIR server meters credits independently and keeps only an in-memory
ledger; the cashier holds the money. Settlement between operator and cashier
(for example a per-server tally of accepted grants) is outside this contract
and outside the wire protocol.

## Privacy

The cashier sees the buyer's IP address and the token, like any web
service. The grant id links a purchase to the connections that spend it, so
an operator running both cashier and server can correlate purchase time with
query timing and count — never with query contents, which PIR hides. Users
who want to hide the purchase link should reach the cashier over Tor or a
VPN; the client sends nothing else identifying.

## Client flow (browser)

1. `GET /v1/info`; show `offers`.
2. Lightning path: mint quote (bolt11) at a listed mint for `amount`; the
   user pays the invoice; the page polls the quote, mints the proofs, and
   encodes a `cashuB…` token (`web/src/cashu-purchase.ts`). Paste path: the
   user pastes a token from any Cashu wallet.
3. `POST /v1/grants`; store the grant (`web/src/session-grant.ts`).
4. On every PIR connection, after the encrypted channel is up, present the
   grant with `REQ_SESSION_GRANT_PRESENT`; the server answers the remaining
   credits for that server.

Pending purchases (quote id, then the minted token) are persisted so a
reload or a cashier outage never loses paid sats.
