# BitcoinPIR issuer credential signing

This crate is the narrow, transport-neutral signing boundary for the stable
BOLT11 credential methods:

- linkable direct paid receipts; and
- blinded BitcoinPIR Cashu BAT capabilities with NUT-12 DLEQ proofs.

It deliberately does **not** create or observe Lightning invoices, decide
prices, persist claims, release HTTP responses, redeem credentials, or issue
experimental ARC credentials. The caller must first establish a signed,
settled quote and must persist the exact issuance response with
`IssuerStore::record_claim` before releasing it. Exact store replay returns the
stored bytes; it must not call the signer again.

Serials and DLEQ nonces are deterministically derived from an issuer-secret
key and the exact quote/request transcript. This makes an unreleased response
safe to reconstruct after a pre-commit process crash without maintaining an
RNG journal. The derivation key is as sensitive as the BAT mint signing key:
disclosure of a historical DLEQ nonce can disclose the corresponding mint
secret key. Production key custody must therefore seal, back up, rotate, and
audit the derivation key alongside the signing keys.

The BAT issuer sees only blinded points. The later provider sees the
unblinded BAT secret and signature, not the quote, invoice, payment hash,
claim key, or blinded issuance transcript. Direct receipts intentionally do
not provide that unlinkability.
