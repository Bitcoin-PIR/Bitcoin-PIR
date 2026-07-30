# Bitcoin Core default-Signet closed profile

Status: source implementation and local render/evidence-schema tests complete;
not installed, not activated, and not a custody or funds approval.

`bitcoin-core-signet-v1` is the sole owner of the Bitcoin Core executable,
configuration, provenance receipt, hash manifests, service identity and data
namespace used by the Payment V1 Signet stack. The issuer profile no longer
ships `bitcoin-cli`, a Core manifest, or an arbitrary bitcoind unit alias. Core
Lightning depends on exactly `bitcoinpir-bitcoin-core-signet.service` and reads
only the separately installed content-addressed `bitcoin-cli` and Core manifest.

## Closed artifact and identity boundary

The profile renders exactly these source inputs:

- `deploy/payment-v1/bitcoin-core/bitcoin.conf.in` to
  `/etc/bitcoinpir/payment-v1/bitcoin-core/bitcoin.conf`;
- `deploy/payment-v1/bitcoin-core/verify-layout.sh.in` to
  `/usr/local/libexec/bitcoinpir/verify-bitcoin-core-signet-layout`; and
- `deploy/payment-v1/systemd/hetzner-bitcoin-core-signet.service.in` to
  `/etc/systemd/system/bitcoinpir-bitcoin-core-signet.service`.

It accepts exactly seven private payloads: `bitcoind`, `bitcoin-cli`, the
two-entry binary manifest, the rendered-config manifest, the layout-verifier
manifest, one canonical provenance receipt, and its one-entry manifest. Both
binaries live under
`/opt/bitcoinpir/bitcoin-core/<approved-archive-sha256>/bin/`; the archive digest
is a bundle identity, while the receipt separately binds each extracted binary
digest. Every shipped file is root-owned and immutable to the service account.

The exact service identity is deliberately static:

| Object | Exact value |
| --- | --- |
| unit | `bitcoinpir-bitcoin-core-signet.service` |
| user / UID | `bitcoinpir-bitcoind` / `52928` |
| primary group / GID | `bitcoinpir-bitcoind` / `52928` |
| cookie group / GID | `bitcoinpir-bitcoin-rpc` / `52929` |
| base directory | `/srv/bitcoin`, root:root `0755` |
| Signet directory | `/srv/bitcoin/signet`, 52928:52929 `2710` (setgid) |
| RPC cookie | `/srv/bitcoin/signet/.cookie`, 52928:52929 `0640`, one link |

The checked-in verifier permits `signet` as the broad data root's only direct
child, rejects nested cross-device boundaries, and recursively rejects
symlinks, hard-linked files, special files,
named/default ACLs, any group/world access on non-cookie files or nested
directories, unexpected owners, wallet paths, `settings.json` and `debug.log`.
The cookie may be absent while Core is stopped; whenever present it must be a
75-byte single-link regular file matching the canonical `__cookie__:` shape
without printing its contents, and running live evidence requires it.

The service has primary GID 52928 and no supplementary groups. It deliberately
does not hold cookie GID 52929: owner access lets `bitcoind` write its namespace,
while the setgid Signet directory makes the generated cookie inherit GID 52929.
The renderer and fresh live evidence require the kernel `Groups:` vector to
contain only 52928. This prevents the daemon itself from becoming a general
member of the read-sharing group.

An operator may use commands equivalent to the following only within a
separately approved stopped-install ceremony. These are documentation, not an
authorization to run them:

```sh
/usr/sbin/groupadd --gid 52928 bitcoinpir-bitcoind
/usr/sbin/groupadd --gid 52929 bitcoinpir-bitcoin-rpc
/usr/sbin/useradd --uid 52928 --gid 52928 --no-create-home \
  --home-dir /nonexistent --shell /usr/sbin/nologin bitcoinpir-bitcoind
/usr/bin/install -d -o root -g root -m 0755 /srv/bitcoin
/usr/bin/install -d -o 52928 -g 52929 -m 2710 /srv/bitcoin/signet
```

The stopped-host checklist must confirm exact account records, nologin shell
and locked password state. Fresh runtime evidence then binds files-authoritative
NSS resolution, absence of UID/GID aliases and the real process credentials.
Do not renumber these identities ad hoc, add the bitcoind/issuer/guard users to
the cookie group, or make it the bitcoind primary group. Only Core Lightning
and the dedicated preflight identity may receive that supplementary group in
their own separately reviewed profiles. With directory mode `2710` and cookie
mode `0640`, those two readers can traverse/read; the issuer and guard cannot.

This DAC shape is not yet an end-to-end issuer activation claim. The currently
checked-in Rust Lightning preflight requires exact mode `0710` for the cross-UID
cookie directory and therefore correctly stops on `2710`. Before joint
Core/issuer activation, a separately versioned preflight change must require
the setgid `2710` shape and pass its own Rust, renderer and live-evidence review.
Do not weaken this Core profile back to `0710` or bypass that preflight.

## Default-Signet and network policy

The configuration is an exact closed list. It selects `chain=signet`, disables
the wallet and the mutable `settings.json` layer, remote REST/RPC, inbound P2P,
Tor listening/discovery, DNS lookup, DNS seeds, forced seeds,
debug/file/console logging and core dumps. RPC is cookie-only on IPv4 loopback
port `38332`. P2P remains outbound-only over IPv4 and IPv6, and `blocksonly=0`
is explicit so the later Lightning stack can relay transactions.

The template intentionally omits both `signetchallenge` and `signetseednode`.
In Bitcoin Core, explicitly setting even the bytes of the default challenge
selects the custom-Signet construction path and discards the compiled default
fixed-seed/assume-valid set. This profile instead uses `fixedseeds=1` with
`dnsseed=0`; bootstrap therefore trusts only the fixed default-Signet seeds
compiled into the externally approved content-addressed Core binary. The later
live Lightning preflight independently verifies the exact default challenge and
genesis. A custom challenge, explicit seed, DNS seed, peer override, mainnet,
testnet or regtest requires a new profile and negative tests.

## Provenance receipt

`provenance.json` is private render input but contains no secret. It must use
canonical JSON and exactly record:

- schema `1`, release, GNU/Linux target and archive filename;
- the externally approved archive SHA-256, equal to the content-address root;
- separate `bitcoind` and `bitcoin-cli` SHA-256 values;
- one exact 40-hex `guix.sigs` commit;
- a sorted, unique list of full signer fingerprints; and
- a threshold of at least three distinct valid signatures, with the observed
  valid count no smaller than the threshold.

The renderer recomputes the receipt encoding, rejects extra/missing fields,
binds both binary digests to the actual payloads and hash-binds the receipt.
Release signatures and Guix attestations remain independent trust inputs; a
download URL or one release-manager signature alone is insufficient.

A read-only local candidate inspection on 2026-07-30 observed the following;
these values are evidence for a future external approval record, not embedded
trust anchors and not installation authority:

| Candidate fact | Observed value |
| --- | --- |
| release / target | `31.1` / `x86_64-linux-gnu` |
| archive SHA-256 | `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e` |
| `bitcoind` SHA-256 | `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08` |
| `bitcoin-cli` SHA-256 | `4e3a0fde23ec768a61cdd193602be937b29b6e8f21bcb614af87a2786bf86034` |
| `guix.sigs` commit | `3f072b34a069b4e3a1aa42bd82070eb2f98247c8` |
| locally valid distinct builder signatures | `11` |

An external read-only ABI probe on the intended Hetzner target then staged the
two candidate binaries in a root-only temporary path without configuration or
data. The exact `bitcoind` and `bitcoin-cli` digests above both reported
`v31.1.0`; `ldd` resolved only the loader, glibc, libm and libpthread; and
`pgrep bitcoind` was empty before and after the probe. This narrows binary/host
compatibility risk, but it is not installation, start, provenance approval or
live-profile evidence.

Before materialization, an independent reviewer must reproduce the archive,
signature and extracted-binary results from clean inputs, choose and record the
accepted threshold/fingerprints, and approve the complete canonical render-plan
digest out of band.

## Lifecycle and evidence

The unit has no `[Install]` section. It requires both the global sentinel and
the Core-only `SIGNET-BITCOIN-CORE-STAGING-APPROVED` sentinel. It does not
consume the Lightning custody, Lightning restore or issuer activation
sentinels, and Core installation does not authorize any CLN or issuer start.

The intended sequence is:

1. source gate and complete Node tests pass at the accepted commit;
2. independently approve provenance plus the canonical private plan digest;
3. render and verify the dependency-closed bundle offline;
4. under a separate stopped-host-mutation approval, provision exact locked NSS
   identities/directories and install the verified files while every activation
   sentinel is absent and the unit remains inactive;
5. independently verify installed bytes, unit load state, no drop-ins, directory
   metadata and no listener/process before considering first start;
6. only under a separate default-Signet/Core-start approval, create the exact
   two sentinels and start this one unit; and
7. immediately collect fresh v6 live evidence. The existing live schema now
   binds `/srv/bitcoin`, `/srv/bitcoin/signet` and the regular `.cookie` path,
   including owner/mode/link/stat/ACL/xattr/capability evidence and effective
   systemd/process/NSS state.

The profile does not add a Core-specific stopped collector. Until one is
reviewed, stopped installation is supported by offline bundle verification plus
the explicit stopped-host checklist above; the first-start acceptance claim
requires the integrated generic live record. Remove the Core-specific sentinel
and stop the unit after any bounded drill. Chain data is staging state, not a
wallet backup, and this profile cannot create or load a wallet.

The first network exercise is deliberately no-funds: start only this walletless
Core profile, synchronize default Signet, collect fresh live evidence and verify
the exact chain/challenge/genesis before any CLN identity, channel or invoice
exists. A later real BOLT11 test uses a second self-controlled payer node and a
direct private Signet channel to the issuer under separate custody,
faucet/test-coin and channel approvals. Public faucets and public routing are
non-deterministic follow-up evidence, never an acceptance dependency. Mutinynet
uses a custom Signet challenge and a Bitcoin Core fork, so it cannot be reached
by editing this profile; it requires a separately versioned custom-Signet
profile and review. Disposable upstream CLN regtest remains the deterministic
integration layer.

## Remaining gates

Source completion does not satisfy any of the following:

- external approval of the release/provenance receipt and complete render-plan
  SHA-256;
- a reviewed stopped-install transaction/rollback procedure and exact target
  host authorization;
- target-host NSS, filesystem, systemd-version, firewall and outbound-network
  evidence;
- first-start/default-Signet sync approval and fresh live evidence;
- live default challenge/genesis/chain verification before CLN or issuer use;
- Lightning identity/custody, backup/restore, channel, faucet/test-coin and
  issuer activation approvals; or
- a mainnet implementation and security review.

This Core profile also does not close the Core Lightning binary's dynamic
library dependencies. The reviewed CLN v26.06.6 Ubuntu 24 amd64 archive needs
`libsqlite3.so.0`, `libpq.so.5` and `libsodium.so.23`. The currently observed
Hetzner target has compatible glibc and the SQLite/libsodium libraries but lacks
`libpq.so.5`, while its dpkg/kernel package state is damaged. Do not run `apt`
to repair or install around that condition. Before any stopped CLN installation
or CLN start claim, select a separately reviewed dependency-closed CLN bundle
or another explicit immutable provisioning method and prove its complete
loader closure. Bitcoin Core render/live evidence cannot be used as evidence
that CLN is startable.

Read-only feasibility work found that the Ubuntu Noble `libpq5`
`16.14-0ubuntu0.24.04.1` package candidate (observed `.deb` SHA-256 prefix
`a7000b...`) yields a regular `libpq.so.5` (observed SHA-256 prefix
`ad59c3...`), and an offline Ubuntu 24 container ran both CLN binaries'
`--version` commands when that single library was supplied through a temporary
`LD_LIBRARY_PATH`; the target already has the library's observed transitive
libc/GSSAPI/LDAP/SSL dependencies. This is feasibility evidence only. A later
CLN runtime-library-bundle change must pin the complete hashes, loader path,
transitive closure and service sandbox without ambient `LD_LIBRARY_PATH` or
package-manager mutation.
