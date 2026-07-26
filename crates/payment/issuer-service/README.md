# BitcoinPIR issuer service core

Transport-neutral, body-in/body-out handlers for quote creation, authenticated
status polling, paid credential claims, and shared-issuer redemption. Network
listeners, TLS, request-size enforcement, and operator configuration belong to
the `payment-issuer` application.

The crate never accepts a Bitcoin address, PIR request, peer-provider ID,
invoice payment hash, or preimage from an HTTP caller. Exact signed/canonical
bodies are committed before release. ARC support remains experimental.
