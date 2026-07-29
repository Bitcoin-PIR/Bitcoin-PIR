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

1. The relay selection and content-addressed relay binary are still resolved
   in their own reviewed PR. The checked-in relay unit remains blocked.
2. `directory-publisher-netns-v1` is the only rendered/runtime profile for this
   slice. It closes over the content-addressed helper and `bpir-admin`, their
   hash manifests, the two units, the Caddy drop-in, the three files-only name
   service inputs, the frozen signed artifacts and the network policy. An
   installed file not present in that manifest is not an approved substitute.
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
6. This slice deliberately has no publication-time firewall-generation guard.
   Its network policy records `activation_blocked=true`, and the publisher unit
   requires the intentionally unavailable
   `PUBLISHER-FIREWALL-GENERATION-GUARD-IMPLEMENTED` sentinel. The current live
   collector proves only two stable point-in-time snapshots around its own UFW
   dry-run; it does **not** prove that the firewall stayed unchanged while a
   prior one-shot publication ran. Do not create that sentinel or activate the
   publisher until a separately reviewed pre/post wrapper or continuous
   generation monitor hard-binds the exact publication interval.

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

The UFW/nft reload harness is even more destructive and refuses to run outside
a marked disposable container:

```sh
BPIR_PUBLISHER_FIREWALL_TEST=I_UNDERSTAND_DISPOSABLE_CONTAINER \
  scripts/payment-v1-publisher-firewall-privileged-e2e.sh
```
