# BitcoinPIR Lightning backend boundary

This crate defines the narrow interface between the payment/credential issuer
and a Lightning node. It is not used by a PIR server. The interface carries no
Bitcoin query, address, result, peer-provider identifier, credential, ARC
state, Cashu proof, or payer identity.

`FakeLightningNodeV1` exists only for deterministic local and integration
tests. It creates cryptographically valid BOLT11 strings, but it is not a
wallet, does not route payments, and MUST NOT be configured with production
keys or real funds.

`CoreLightningBackendV1<UnixClnRpcTransportV1>` is a native, local-host
production adapter, but nothing enables or invokes it by default. It follows
Core Lightning's documented `invoice`/`listinvoices` JSON-RPC contract over a
Unix socket. It component-walks and rechecks the protected socket parent,
supports exact mode-0700 same-UID or explicit owner/group mode-0710 cross-UID
deployment, and verifies the socket type, owner, optional exact group,
permissions, and inode across connect. It bounds every frame and uses the CLN
double-newline framing. Production activation, node custody, backups, channel
liquidity, monitoring, and any real-funds test still require the user's
separate approval.

The adapter always performs `listinvoices(label)` before `invoice`, recovers a
CLN duplicate-label race by another lookup, and reports every unverified
post-write response as outcome-unknown. It reparses the signed BOLT11 and
cross-checks the RPC payment hash, amount and expiry on creation and lookup.
CLN may include `payment_preimage` in a paid `listinvoices` response; the
adapter does not deserialize or expose it and zeroizes the bounded raw response
buffer after parsing.

CLN's high-level `invoice` RPC hashes a supplied description rather than
accepting an arbitrary precomputed hash. This adapter therefore requires the
public, query-independent description
`BitcoinPIR anonymous service capability v1`, passes `deschashonly=true`, and
disables private-channel route hints. Issuer orchestration must use
`anonymous_invoice_description_hash_v1()` in its exact backend request.
Remote CLN, LND, LDK, or other adapters remain separate reviewed work.

## Contract

- The issuer supplies a high-entropy, endpoint-domain-separated backend label
  and exact network, payee, amount, expiry, and description hash. The actual
  BOLT11 creation timestamp is returned by the node and verified from the
  signed invoice; it is deliberately not caller-selected because LND and Core
  Lightning assign it themselves.
- `create_or_get_invoice` is idempotent for the complete request. Reusing a
  label with any changed field is a conflict.
- An adapter must not acknowledge invoice creation until the invoice can be
  recovered by that label after a lost response or issuer restart.
- A fixed-amount invoice is mandatory. Amountless invoices and zero/excessive
  amounts fail closed.
- The returned BOLT11 is still parsed and signature-verified by
  `CreatedInvoiceV1::verify_for_request` and `pir-service-protocol` before it
  is signed into a quote. The first check also binds the invoice-embedded
  payment hash to the backend response; only the resulting private-field
  typestate is accepted by issuer orchestration.
- A settlement observation includes the amount actually accepted and an
  opaque evidence digest. The issuer rejects underpayment; an overpayment is
  recorded but grants only the fixed entitlement in the signed offer.
- Payment preimages remain inside the Lightning node adapter. This API cannot
  return them. Payment hashes and invoice strings remain issuer-confidential
  and never enter the PIR wire or provider spent database.
- Invoice expiry is not proof that a payment can never settle. A later lookup
  can report a late settlement, which the issuer reconciles through its signed
  lifecycle state machine.

Routing fees are paid by the payer's wallet in addition to the invoice amount;
they do not increase the purchased entitlement. Overpayment also never changes
credential count. V1 has no automatic Lightning refund protocol;
any exceptional operator refund is a separate, explicitly authenticated
workflow and must not reveal a PIR query.
