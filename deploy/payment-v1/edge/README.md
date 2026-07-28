# Payment V1 production edge templates

These are non-activating review inputs. They do not authorize DNS changes,
certificate issuance, public listeners, a remote-host change, or production
deployment. Rendered files remain blocked by the Payment V1 activation
sentinel and by exact binary/configuration hash manifests.

The reviewed edge binary is stock Caddy. Do not add modules. Pin the complete
single-file binary, its exact `caddy version` output, the rendered Caddyfile,
and the rendered systemd unit before activation. The Caddy admin API,
persistent autosaved configuration, HTTP redirects, 0-RTT, debug/trace,
access logs and request/header/body logs are disabled. Operational logging is
limited to non-request ERROR events; `http.log.access` and `http.log.error`
are excluded explicitly.

## Public surfaces

`hetzner-public.Caddyfile.in` exposes exactly three independent TLS names:

| Public surface | Exact public path | Loopback upstream | Protocol bound |
| --- | --- | --- | --- |
| PIR provider | `/v1/pir` | `127.0.0.1:8191` | WebSocket upgrade; application frames are capped by `unified_server` at 512 KiB |
| payment/credential issuer | the enumerated `/v1/...` paths in the template | `127.0.0.1:5610` | HTTP/1.1; body at most 66,445 bytes |
| directory relay | `/v1/directory` | `127.0.0.1:8080` | WebSocket upgrade; relay frames are capped by the relay at 2 MiB |

The edge does not inspect upgraded WebSocket frames. The application servers'
fixed frame limits therefore remain part of the security boundary. The edge
does bound the TLS handshake HTTP headers and the pre-upgrade request body.
Do not replace either backend with one lacking those frame limits.

The three loopback ports are cross-file invariants, not deployment choices:
the rendered edge, application unit, and application configuration must agree
exactly. In particular, the directory-only relay configuration already fixes
`127.0.0.1:8080`; rendering `7447` or any other relay upstream must fail the
rendered-artifact gate.

`rollback-authority.Caddyfile.in` is rendered separately on each independent
authority host. It exposes only `POST /v1/rollback-authority/calls`, caps the
body at 1,404 bytes, and proxies to `127.0.0.1:8099`. Its upstream header
rewrite is deliberately narrower than a normal reverse proxy: the authority's
strict parser accepts no `Forwarded`, `X-Forwarded-*`, `Via`, authorization,
cookie, transfer-encoding, expect or upgrade headers and requires
`Connection: close`.

No edge forwards a client IP or proxy identity header to an application
upstream. The edge host itself still observes source IP, TLS timing, SNI and
traffic volume. This topology does not claim network-observer unlinkability.

## Rate and concurrency boundary

Stock Caddy has no bundled request-rate module, and this template forbids
unreviewed third-party modules. It therefore applies fixed upstream connection
ceilings rather than maintaining a new per-IP identity table: provider 128,
issuer 128, directory relay 64, and rollback authority 32. The corresponding
applications remain authoritative and fail closed at the same or tighter
bounds. In particular, the issuer enforces quote 60/minute, status 600/minute,
mutation 120/minute, and reconciliation 120/minute budgets; the directory
relay enforces 64 operations/second; and the provider combines 128 total
connections with its Payment V1 authentication/concurrency and signed-policy
quota gates. A rendered-artifact validator must compare those values across
edge, unit, application configuration, and signed policy instead of treating
the prose as configuration.

Volumetric protection before Caddy is a separate host/network deployment
decision. It must not reintroduce credential-bearing access logs or forward a
source-IP header into PIR, issuer, relay, or authority application logs.

The global ceilings above are vulnerable to low-bandwidth starvation and are
not production availability protection: one source can occupy the WebSocket
pool, consume the anonymous quote budget, or hold the authority queue. Public
activation is blocked until a reviewed edge/network control enforces ephemeral
source-fair connection and request admission without persistent IP/request
logs or forwarding source identity to the business services. Directory
publishing additionally needs a separately reserved private ingress/budget.
Every rollback authority must be reachable only through its client-specific
private boundary (for example WireGuard, mutually authenticated TLS, or an
equivalent narrow firewall allowlist), never as an ordinary public endpoint.

## Rendering and activation boundary

Replace every `@...@` token with a reviewed value; tokens must not remain in a
rendered file. Public host tokens are bare lower-case DNS names without a
scheme, path, port, wildcard or trailing dot. Loopback ports are fixed in the
templates and must match the corresponding application unit.

Render `systemd/payment-v1-edge.service.in` with one absolute Caddyfile path.
Create root-owned, non-writable checksum manifests whose sole entries are the
exact absolute binary and rendered-config paths. The service performs strict
`sha256sum --check` and `caddy validate` before `caddy run`. Provisioning the
sentinel, starting the unit and changing DNS remain separate approved actions.

Certificate automation may contact the configured public CA and stores state
under `/var/lib/bitcoinpir-payment-edge`. If certificate issuance is not the
reviewed production choice, replace automatic management with separately
reviewed certificate/key custody before rendering; never place a private key
on a command line. `auto_https disable_redirects` intentionally permits
certificate management but forbids HTTP-to-HTTPS redirects.
