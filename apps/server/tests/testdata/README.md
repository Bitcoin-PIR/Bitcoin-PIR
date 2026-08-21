# Payment process E2E TLS fixtures

These files are public, test-only TLS material for the non-default
process-E2E test features. The leaf is valid for `localhost` from
2026-07-27 through 2126-07-03 and is signed by the included private test CA.
Its complete DER SubjectPublicKeyInfo SHA-256 is:

```text
e91550521f8e17b21d99f7e00b99c08be1b1f31fe57772ac8f904ea50c6a609b
```

The committed leaf private key is not a production secret. No production
binary trusts this root: the additional trust-anchor API and deployment field
exist only behind an explicit non-default Cargo feature, while ordinary builds
continue to reject that field through `deny_unknown_fields`.
