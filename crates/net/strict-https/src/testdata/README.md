# Strict HTTPS certificate fixtures

These public test-only certificates form one RSA-2048 root and one leaf for
`authority.example`, plus an unrelated root. The leaf is valid from
2026-07-27 through 2126-07-03; verifier tests use fixed `UnixTime` values and
do not depend on the machine clock.

The expected SHA-256 of the leaf's complete DER-encoded SubjectPublicKeyInfo
is:

```text
53e70af8504122f4a97553d4e06403e9cfe3ac931d4c39a29908dc192d741af9
```

The whole-certificate DER hash is deliberately different and is covered as a
negative pin-scope test. No private key is committed because these unit tests
exercise certificate verification directly rather than operating a TLS test
server. A deterministic end-to-end TLS 1.2/TLS 1.3 handshake test with a
deliberately corrupt server `CertificateVerify` signer remains an integration
test item. The implementation delegates all TLS signature methods to rustls;
the unit tests here cover the WebPKI-plus-pin certificate decision itself.
