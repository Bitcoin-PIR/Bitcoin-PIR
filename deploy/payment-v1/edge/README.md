# Payment V1 production edge templates

These files are non-activating review inputs. They do not authorize listeners,
DNS, certificates, deployment, remote-host changes, or funds. A rendered edge
still requires the activation, edge-preflight, and source-fair-preflight
sentinels plus exact binary/configuration hash manifests.

## Public-edge trust boundary

The Hetzner public path is deliberately two layers:

```text
Internet
  -> pinned stock Caddy (TLS, SNI/routes, 5 s header deadline, 16 KiB headers)
  -> root-created 0750 runtime directory and four 0660 Unix sockets
     carrying PROXY protocol v2 only
  -> pinned HAProxy 2.8 (ephemeral source-fair admission and egress limits)
  -> fixed loopback application listener (no PROXY protocol or source header)
```

Caddy and HAProxy have separate UIDs and GIDs. Caddy receives only the
`bitcoinpir-source-fair-edge` supplementary group needed to connect to the
four sockets. HAProxy owns the socket directory and sockets. Provider, issuer,
and directory processes have that runtime path hidden with
`InaccessiblePaths=`. The rendered/live gates pin the group topology and check
the current directory/socket type, UID, GID, and mode twice around live unit
collection. A world-writable socket, extra group member, symlink, stale socket,
wrong owner, or changed path fails closed.

There is no header fallback. Caddy clears all incoming headers before adding
the small fixed application set and sends the real network source only in a
PROXY-v2 preamble to a protected Unix socket. HAProxy consumes that preamble,
deletes source, proxy, correlation, trace, authorization, cookie, and Via
headers as applicable, and opens a new loopback TCP connection without
`send-proxy`. The business process therefore sees HAProxy's loopback peer and
never receives the source address.

This does not make the edge host blind: Caddy and HAProxy necessarily observe
source address and timing while a request is live. It prevents that data from
becoming business state or a durable payment/query join key.

## Surfaces and isolated lanes

`hetzner-public.Caddyfile.in` and `source-fair-haproxy.cfg.in` define four
independent lanes:

| Lane | Ingress | HAProxy socket | Application | Global connections | Per-source connections |
| --- | --- | --- | --- | ---: | ---: |
| PIR provider | public HTTPS/WSS `/v1/pir` | `provider.sock` | `127.0.0.1:8191` | 128 | 8 |
| payment issuer | public HTTPS enumerated routes | `issuer.sock` | `127.0.0.1:5610` | 128 | 8 |
| directory readers | public WSS `/v1/directory` | `directory-public.sock` | `127.0.0.1:8080` | 48 | 4 |
| directory publisher | private-route, exact-source WSS `/v1/directory` | `directory-publisher.sock` | `127.0.0.1:8081` | 4 | 2 |

The publisher listener binds a distinct RFC1918/ULA address and hostname and
requires the publisher's exact RFC1918/ULA WireGuard/private-route source in
both Caddy's direct-peer matcher and HAProxy's authenticated PROXY-v2 source
check. Its static server certificate must contain a WebPKI chain valid for the
publisher hostname because the current `bpir-admin` publisher is a
credential-free canonical WSS client. The HAProxy table, connection budget,
egress budget, application listener, and relay application reservation are
distinct from public readers. Source filtering is an ingress/DoS boundary,
not publication authority: every accepted event still requires the pinned
Nostr key and exact signed profile.

The public and publisher sites still share one pinned Caddy process, UID,
memory/task/file cgroup limits, and TLS scheduler. All four lanes likewise
share one HAProxy master/worker and its process-level CPU, memory, task and file
budget even though their frontends, stick tables, connection limits and egress
limits are distinct. A public pre-routing TCP/TLS flood or HAProxy process-level
pressure can therefore reduce publisher availability. V1 treats the private
address, strict source filtering, process limits, and reserved lane budgets as
a bounded residual risk; deployments that require a hard publisher
availability boundary must split both publisher edge layers into separately
rendered/evidenced units before activation.

Both relay lanes also share one process and one mutex-protected SQLite store.
Lane/global connection, operation, rate, and egress reservations stop public
work from occupying the publisher's reserved admission slots, but they do not
make database execution fully independent: an already-running public read can
briefly contend with a publisher write. This is a second explicit V1
availability boundary; strict storage isolation would require independently
designed state/replication semantics rather than another semaphore.

Rollback authorities are excluded from this public HAProxy. Each authority
keeps its separately rendered Caddy/application unit. The V1 edge binds only
one RFC1918/ULA address, accepts only its sole client's exact private IP through
the systemd network filter, uses a static TLS server certificate, and retains
the existing strict server-SPKI pin plus signed request authentication. This is
intended for one narrow WireGuard/private route, not an Internet interface.
The current client deliberately uses no TLS client certificate; enabling mTLS
only on Caddy would break every request, so mTLS requires a later coordinated
client certificate/key, private-file, gate, and real-handshake change. Adding
`127.0.0.1:8099` or an authority route to the public source-fair configuration
fails the source gate.

## Ephemeral source fairness

HAProxy has six isolated stick tables: provider, issuer, quote-source,
quote-global, directory-reader, and directory-publisher. Source tables use an
IPv6 key, map IPv4 as `/32`, aggregate IPv6 as `/64`, contain at most 4,096
entries (64 for the publisher), expire after two minutes, and use `nopurge`.
When a table is full, a new source is rejected rather than evicting an active
bucket. HAProxy has no StateDirectory, peers, stats socket, server-state file,
Lua/SPOE hook, access log, or source-table recovery; restart intentionally
forgets every source bucket.

The issuer additionally permits at most six quote creations per source and 60
globally per rolling minute. Every lane has both a shared-source egress limiter
and a per-stream limiter. Application frame, operation, credential, signed
policy, and store limits remain authoritative after edge admission.

Source buckets are an availability control, not identity or commercial state.
Users behind one NAT or one IPv6 `/64` share a bucket and can interfere with
one another; attackers with many addresses can distribute load. Global
volumetric attacks and TLS-handshake floods still need separately reviewed
host/network protection that does not persist request identities.

## Caddy is independently bounded

HAProxy starts only after Caddy has accepted TCP, completed TLS, and parsed an
HTTP request. HAProxy therefore does not protect Caddy from TCP/TLS slowloris,
handshake exhaustion, oversized headers, or pre-routing floods. Caddy retains
its own 5-second header deadline, 16 KiB header cap, 15-second request-body
deadline, 60-second idle deadline, disabled 0-RTT, strict SNI, bounded
connections, `MemoryMax=512 MiB`, `TasksMax=512`, and `LimitNOFILE=4096`.
HAProxy separately has `MemoryMax=256 MiB`, `TasksMax=128`,
`LimitNOFILE=2048`, and `maxconn 320`. Both units set `LimitCORE=0` and
`MemorySwapMax=0`.

Do not claim that HAProxy covers the Caddy front door. Linux SYN queues,
firewall limits, certificate-handshake pressure, and any upstream DDoS control
must be measured independently. An absolute Caddy write deadline remains zero
because it would terminate valid long-lived WebSockets; application and
HAProxy tunnel/egress limits bound the upgraded path.

## Logging and privacy

Caddy's admin API, autosave, access/request/error namespaces, debug/trace,
redirects, and 0-RTT are disabled. HAProxy has exactly `no log`. Neither layer
may emit raw IPs, SNI/path/request headers, PROXY frames, invoices, payment
hashes, credential material, or query timing to application or durable logs.
Both edge units set `StandardOutput=null` and `StandardError=null`; the rendered
and live gates require those exact effective values so a Caddy or HAProxy
request-path error cannot persist a peer address in journald. They also require
the effective hard and soft core limits, cgroup swap maximum, and current swap
usage to remain zero. Because Linux pipe-style core handlers can ignore
`RLIMIT_CORE`, live edge evidence separately requires the host-wide
`kernel.core_pattern` to equal `|/usr/bin/false` and binds the exact handler's
root ownership, canonical path, one-link/non-writable metadata and SHA-256. A
systemd-coredump/apport pipe is not accepted merely because the unit says
`LimitCORE=0`.
Non-request process-health events may be retained only when they cannot
contain request context.

## Rendering and activation evidence

The `edge-hetzner-v1` rendered profile is closed over:

- the public Caddyfile and public Caddy unit;
- the HAProxy 2.8 configuration and source-fair unit;
- exact Caddy and HAProxy binaries and one-entry hash manifests;
- the rendered-config hash manifests; and
- publisher WebPKI server certificate and owner-only private key.

The public bind, publisher private bind, and publisher client placeholders are
three distinct numeric addresses. The two publisher addresses must use the
same IP family and both be RFC1918 or ULA. The source-fair unit creates only a
volatile `RuntimeDirectory=`, while the public Caddy unit requires and binds to
that active unit and checks all four sockets before start. Neither template has
an `[Install]` section. Both units additionally require
`DIRECTORY-PUBLISHER-PRIVATE-INGRESS-APPROVED`; creating it asserts that the
private route, anti-spoofing firewall, WebPKI hostname, and exact client IP were
reviewed, not merely that a placeholder was rendered.

Before an activation sentinel may be approved, run all of the following with
the exact pinned Linux binaries:

```sh
node scripts/payment-v1-deployment-template-gate.mjs
node --test scripts/payment-v1-deployment-template-gate.test.mjs
BPIR_HAPROXY_BIN=/absolute/pinned/haproxy \
BPIR_CADDY_BIN=/absolute/pinned/caddy \
  node --test scripts/payment-v1-source-fair-edge.test.mjs
```

The behavior suite validates the complete rendered Caddy template, starts real
HAProxy, proves same-source slot rejection without cross-source starvation,
checks per-source/global quote limits, verifies forbidden headers and source
addresses do not reach a mock business service, rejects an unauthorized
publisher source at both Caddy and HAProxy, and exercises the selected Caddy
binary's Unix+PROXY-v2 transport. A skipped binary-dependent test is not
production evidence.
CI fixes this compatibility baseline to stock Caddy 2.11.3 (required for the
explicit `0rtt off` server directive) and HAProxy 2.8.x with `+SYSTEMD` support.
The production HAProxy must be a currently maintained 2.8.x release, show
`+SYSTEMD` in `haproxy -vv`, and be pinned by exact approved bytes and a
one-entry hash manifest; the CI distribution package is only compatibility
evidence.

Finally render the closed profile, run `systemd-analyze verify`, start only an
unrouted canary, and collect root Linux evidence with
`payment-v1-linux-runtime-evidence.mjs`. The evidence must show both units
active with exact effective resource/hardening values, no drop-ins, exact
process/group identities, zero current/max swap, zero hard/soft core limits,
the safe host core pattern, and the five runtime path records. Public routing
is a later, separately approved action.

The separate `edge-rollback-authority-v1` rendered profile additionally closes
over its static server certificate and owner-only private key. Its unit has no
persistent StateDirectory, exposes only the private bind, allows loopback plus
the exact sole-client private IP, and will not start without
`ROLLBACK-AUTHORITY-PRIVATE-INGRESS-APPROVED`. The root live collector binds its
volatile runtime directory and the same no-journal/no-core/no-swap controls.
