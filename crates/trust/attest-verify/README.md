# pir-attest-verify

Browser-side AMD SEV-SNP attestation chain verifier for BitcoinPIR.

Parses the 1184-byte SNP attestation report, verifies its ECDSA-P384
signature against a VCEK certificate, and (when given the full chain)
verifies VCEK ← ASK ← ARK with RSA-PSS signatures. Pure Rust; compiles
to wasm32. Uses RustCrypto's `sev = "7"` crate with `crypto_nossl`.

Used by `pir-sdk-wasm` to give the browser a fully trustless
attestation check — no proxy to AMD's KDS endpoint, no Cloudflare
Worker, no fetched-at-runtime root cert. The unified_server bundles
the VCEK (and optionally ASK) in its AttestResult; the verifier
checks the chain against an operator-pinned ARK fingerprint baked
into the WASM bundle.
