# BitcoinPIR Core Lightning RPC guard

This process is the only payment-issuer-side principal permitted to reach the
Core Lightning JSON-RPC socket. It exposes a second Unix socket to exactly one
configured issuer UID/GID and accepts only the RPC surface used by
`pir-lightning-backend`:

- `getinfo` with empty parameters;
- `listinvoices` with one canonical private BitcoinPIR backend label;
- `invoice` with a bounded amount and expiry, the fixed anonymous description,
  and privacy-preserving flags.

The guard rejects batch requests, notifications, unknown or duplicate fields,
extra methods, malformed framing, oversized input, and socket identity changes.
It reconstructs requests before forwarding them and reconstructs responses
before returning them. In particular, a CLN `payment_preimage` is never exposed
to the issuer.

Four explicit root-controlled limits contain a compromised issuer's ability to
grow CLN's invoice database:

- `--max-invoice-msat` caps every invoice independently of the issuer's signed
  offer policy;
- `--max-invoices-per-minute` and `--max-invoice-burst` form a monotonic token
  bucket for the mutating `invoice` method;
- `--max-invoices-per-runtime` is a generation deadman. Once consumed, invoice
  creation stays closed until a trusted operator deliberately restarts the
  guard.

The binary also rejects configurations above its compiled safety ceilings:
600 invoice attempts per minute, a burst of 100, or 100,000 invoice attempts
per process generation. The amount ceiling may not exceed the protocol-wide
Bitcoin maximum, but production units should pin a materially smaller value
that matches their signed offer policy. All four arguments must be owned and
pinned by the service manager; they are not issuer-controlled API parameters.

The runtime counter is intentionally not resettable over the issuer socket and
the guard never logs labels, hashes, invoices, or response bodies. It is not a
durable accounting ledger: a host reboot or root-initiated service start creates
a new generation. The reviewed production unit therefore uses `Restart=no`;
guard failure also stops the bound issuer and requires an explicit operator
review/start ceremony. An automatic restart policy would erase this containment
property. Settlement accounting remains the issuer store's responsibility.

The token bucket and generation deadman apply only to the mutating `invoice`
method. `getinfo` and `listinvoices` remain constrained by the connection
deadline and `--max-in-flight`, but do not have a sustained request-rate quota.
A compromised issuer can therefore still impose bounded concurrent read load
on CLN even though it cannot grow the invoice database without consuming the
independent invoice budgets.

The upstream CLN socket remains a custody boundary. In a split-UID deployment,
it should be owned by the CLN UID and the guard's pinned primary group at mode
`0660`; its parent is `0710`. The issuer must not be a member of that group. The
downstream guard directory is owned by the guard UID and issuer GID at mode
`0710`; the guard creates its socket as `0660` and verifies the connecting
issuer's kernel peer credentials.

Kernel peer credentials expose only the connection's effective UID/GID, not
the issuer account's complete supplementary-group list. Provisioning must
therefore independently verify that the issuer account is not a member of the
guard/CLN socket group. On Linux the guard rejects POSIX ACLs on the relevant
directories and sockets. On macOS the parent-directory ACL is checked, but an
ACL attached directly to an already-existing upstream CLN socket is outside the
current transport check and must be prohibited by deployment policy.

The binary deliberately refuses root UIDs/GIDs, an upstream owner or group
shared with the issuer, stale listener paths, and permissive or replaceable
directories. It does not delete an existing socket automatically after a
crash; an operator must first establish that the old process is dead and then
remove the stale path.
