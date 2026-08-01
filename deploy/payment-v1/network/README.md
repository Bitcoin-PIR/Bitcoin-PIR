# Directory publisher network namespace

This directory is a non-activating review input for the same-host centralized
directory publisher. It does not authorize a listener, Caddy change, firewall
change, public Nostr write, DNS/certificate issuance, or service start.

The fixed V1 topology is:

```text
publisher process (no key, one shot)
  /run/netns/bpir-directory-publisher
  bpir-pub-c = 10.203.0.2/30
        |
        | veth; no default route; IPv6 disabled
        |
  bpir-pub-h = 10.203.0.1/30
  host Caddy private publisher SNI :443
```

The native helper uses Linux syscalls/rtnetlink directly and never invokes
`ip`, `mount`, a shell, or another mutation utility. An append-only transaction
journal records each intent before its kernel mutation. Namespace mount
placeholders have recorded device/inode identities; both veth endpoints have
transaction-specific aliases and random locally-administered MACs. Recovery
removes only those exact objects. A fixed-name object without that journal, or
any alias/MAC/inode mismatch, is an unknown preimage and is left untouched.

After setup, a host monitor and a child already resident in the publisher
namespace drop all effective/permitted capabilities and install a seccomp
allowlist. They continuously require the exact /30 addresses, namespace inode,
veth identity, no default route, disabled namespace IPv6, and a closed set of
down/no-alias kernel fallback tunnel devices. Either monitor exiting makes the
unit fail. `Restart=no` prevents a fault loop. `ExecStopPost=... cleanup` is the
only teardown path and uses the durable identities.

The helper unit deliberately cannot use systemd filesystem/mount-namespace
hardening such as `ProtectSystem=`: such a private mount namespace would hide
the nsfs bind mount from `NetworkNamespacePath=` consumers. This is why the
helper is content-addressed, has only `CAP_SYS_ADMIN`/`CAP_NET_ADMIN` during
setup/cleanup, contains no exec path, and self-sandboxes before monitoring.

The publisher service reads three already-signed frozen artifacts and a public
directory-key pin. It cannot read a signing key, has files-only name service,
has no usable resolver or default route, can reach only `10.203.0.1`, performs
one bounded command, and has no restart/retry path. Its systemd sandbox permits
only AF_INET, replaces host `/run` with a private read-only tmpfs, and runs the
content-addressed helper's host-runtime-visibility and negative AF_UNIX socket
probes inside that same sandbox before the real publisher starts. A partial
Nostr write is reconciled manually with the exact same artifacts.

## Activation inputs retained by this slice

This source slice intentionally does not claim deployability. All of the
following remain mandatory before an installed Caddy transaction or service
start:

1. The checked-in relay selection is `RESOLVED` for the reviewed
   content-addressed directory-only relay and explicitly records degraded
   `centralized-single-relay` mode. Relay activation remains separately
   sentinel-gated.
2. `directory-publisher-netns-v1` is the only rendered/runtime profile for this
   slice. It closes over the content-addressed helper and `bpir-admin`, their
   hash manifests, the two units, the Caddy drop-in, the three files-only name
   service inputs, the frozen signed artifacts and the network policy. An
   installed file not present in that manifest is not an approved substitute.
   Its render plan must also pin the exact committed
   `deploy/payment-v1/relay-selection.toml.example` SHA-256. Rendering accepts
   only `status=RESOLVED`, `directory_mode=centralized-single-relay`, and a
   selection publisher key exactly equal to
   `DIRECTORY_PUBLISHER_PUBKEY_HEX`. The manifest records that digest/key/mode
   together with one canonical credential-free `wss://host` origin; the
   runtime request binds the manifest digest for later ceremony checks.
3. The one files-only publisher hostname remains an explicit deployment input.
   The checked-in example retains an `UNRESOLVED` marker and cannot render. The
   integrated-Caddy transaction has one private site block and performs an
   authorized TLS health check with that exact SNI, so the exact DNS SAN must
   be present in the pinned certificate. This is deliberately one centralized
   relay, not two independent relays hidden behind aliases. The publisher uses
   the explicit `--centralized-single-relay` mode and its CLI receipt marks the
   run `centralized=true degraded=true`; strict/default publication remains
   2..8 distinct relay hosts.
4. The rendered policy and Linux runtime collector close the UFW contract. The
   installed rule set must prepend one exact input allow before an
   interface-wide deny and must prepend forwarding denial in both directions.
   `ufw prepend` is required so unrelated pre-existing global allows cannot run
   first:

   ```text
   ufw prepend deny in on bpir-pub-h from any to any
   ufw prepend allow in on bpir-pub-h from 10.203.0.2 to 10.203.0.1 proto tcp port 443
   ufw route prepend deny in on bpir-pub-h from any to any
   ufw route prepend deny out on bpir-pub-h from any to any
   ```

   This is a stateful UFW policy, not a claim that the base/before chains accept
   no other packet classes. Ubuntu's reviewed UFW pre-rules retain the exact
   connection-tracking exception for `ct state related,established` (and the
   iptables equivalent). Each IPv4/IPv6 INPUT/FORWARD before chain must contain
   exactly one such accept before its user-chain jump. Beyond that mandatory
   stateful rule, the reviewed IPv4 optional allowlist permits loopback INPUT,
   selected ICMP error/echo-request types, DHCP client traffic (UDP 67 to 68),
   mDNS (`224.0.0.251:5353`) and SSDP (`239.255.255.250:1900`); FORWARD may
   additionally include only selected ICMP accepts. The IPv6 optional allowlist
   analogously permits loopback INPUT, selected ICMPv6/ND/MLD compatibility
   forms, DHCPv6 (UDP 547 to 546), mDNS (`[ff02::fb]:5353`) and the reviewed UFW
   SSDP destination (`[ff02::f]:1900`); IPv6 FORWARD may additionally include
   only selected ICMPv6 control accepts.
   These early accepts can run before the interface-wide user deny. The
   `bpir-pub-h` user-chain rule is therefore only the authorization boundary
   for a **new TCP/443** flow that reaches that chain, not a claim that every
   other packet class reaches it. Zero host forwarding, no namespace default
   route and no NAT remain independently evidence-bound.

   Runtime evidence binds two semantic passes of raw `ufw status numbered`,
   `ufw show raw`, nft base/before/user chains for IPv4 and IPv6, forwarding
   sysctls, the nsfs mount, and the effective systemd dependency graph around a
   bounded UFW dry-run reload. The disposable firewall harness additionally
   performs a real reload and revalidates the same rules. The helper never edits
   the host firewall; production rule installation/reload remains an explicit
   deployment action.
5. `bhtm-caddy.service` is a shared process, but the dependency direction is
   deliberately `Wants=` plus `After=` only. Namespace teardown cannot stop the
   shared Caddy process. Stopping/restarting Caddy may stop the namespace through
   the namespace unit's one-way `PartOf=` relation. Runtime evidence rejects any
   effective reverse `Requires=`, `BindsTo=` or `PartOf=` edge from Caddy.
6. The content-addressed namespace owner is also the publication-time firewall
   generation guard. Before any namespace mutation it opens a host-netns
   `NFNLGRP_NFTABLES` subscription, takes the root-owned, single-link
   `/run/xtables.lock` with `LOCK_EX|LOCK_NB`, and requires an empty event queue.
   It retains both descriptors after dropping every capability and installing
   seccomp. During the complete namespace-owner lifetime it rejects lock-inode
   drift or any queued nftables generation message; queue overflow is a hard
   failure. After the client monitor reports ready, the parent repeats the
   complete stop/firewall/child/topology barrier immediately before READY.
   Graceful exit repeats the firewall checks before releasing the lock. The
   publisher's existing `BindsTo=` can make this owner lifetime contain its
   `ExecStart` interval.

   Cooperative UFW/iptables mutations cannot acquire the standard xtables lock.
   A direct nftables mutation bypasses that lock but is retained by the kernel
   notification queue and fails the owner within the bounded monitor loop. The
   continuous monitor alone does not prove that the earlier `firewall.json`
   snapshot equals the live starting generation. The policy therefore remains
   `activation_blocked=true`, and the publisher requires the intentionally
   unavailable `PUBLISHER-LIVE-FIREWALL-LINEAGE-IMPLEMENTED` condition. Do not
   create it. A future implementation must, after subscription and lock
   acquisition but before owner READY, re-collect and semantically validate the
   live UFW/raw/nft/forwarding state and bind owner InvocationID, boot ID, rule
   digest and the exact publication approval into durable receipt lineage.
   Planned firewall maintenance must first stop namespace ownership. An
   adversarial host root can kill or bypass any same-host monitor; the declared
   boundary is non-adversarial privileged maintenance.

Pure checks do not need privileges:

```sh
node scripts/payment-v1-publisher-netns-gate.mjs
node --test scripts/payment-v1-publisher-netns-gate.test.mjs
```

The privileged harness is opt-in and is evidence only for the disposable Linux
kernel on which it ran. It must not be run on Hetzner or another persistent
host merely to obtain test evidence:

```sh
BPIR_PUBLISHER_NETNS_PRIVILEGED_TEST=I_UNDERSTAND_DISPOSABLE_HOST \
  scripts/payment-v1-publisher-netns-privileged-e2e.sh
```

The private-ingress harness additionally runs Caddy v2.11.4 with the exact
source-address matcher and a real TLS/WebSocket backend. It requires a
disposable root environment and proves host-namespace 404 versus
receipt-bound publisher-netns 101:

```sh
BPIR_PUBLISHER_PRIVATE_HEALTH_TEST=I_UNDERSTAND_DISPOSABLE_HOST \
BPIR_CADDY_BIN=/usr/local/bin/caddy \
  scripts/payment-v1-publisher-private-health-privileged-e2e.sh
```

The UFW/nft reload harness is even more destructive and refuses to run outside
a marked disposable container:

```sh
BPIR_PUBLISHER_FIREWALL_TEST=I_UNDERSTAND_DISPOSABLE_CONTAINER \
  scripts/payment-v1-publisher-firewall-privileged-e2e.sh
```

The namespace harness additionally proves exclusive xtables-lock ownership,
lock-identity drift detection, fail-closed termination after a direct nftables
generation mutation, and a deterministic real nft mutation after client-ready
but before the final parent barrier that must produce no READY. The exact
systemd-255 PID-1 harness proves the
`Requires`/`After` precondition, in-flight `BindsTo` stop and post-success
deauthorization semantics.

## Activation ceremony

The rendered network profile is installation input, not start authority. The
separate source-closed ceremony in
`scripts/payment-v1-publisher-netns-ceremony.mjs` binds the installed files,
external sentinels, canonical firewall output, Caddy/publisher preimages,
runtime command inodes and current boot before it starts only the namespace
unit. Its rollback has a distinct short-lived receipt-bound approval and stops
only that unit. A start that reaches terminal systemd `failed/failed` may be
cleared only by a third, short-lived approval binding the durable start intent,
original activation approval and exact failed InvocationID; that path invokes
only fixed-argv `systemctl reset-failed` after no-job/no-process/no-topology
proofs. Its durable reset intent survives short-lived approval expiry; only a
fresh approval for the identical complete failed-attempt tuple may continue it,
and the receipt preserves both approval digests. None of the three paths
changes Caddy, the firewall, publication state or the offline publisher key
boundary. Exact order, crash recovery, reboot scope and remaining blockers are in
`docs/payment/PUBLISHER_NETNS_CEREMONY.md`.
