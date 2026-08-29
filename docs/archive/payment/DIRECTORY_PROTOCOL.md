# Nostr service-directory protocol

Status: implementation contract for the v1 discovery lane. Directory data is
never runtime, database, live-policy, payment, or query authorization by
itself. Without an independent operator pin, however, the pinned directory key
is the provider-identity/endpoint discovery and Sybil trust root. It is also a
centralized curation, split-view, diversity-claim, and availability boundary.
The manual endpoint plus independently pinned operator path bypasses this
directory trust.

## Trust model

The directory publisher has one dedicated Nostr secp256k1 key. That key MUST
NOT be a PIR operator, runtime identity, service-policy, issuer, Lightning,
receipt, BAT, ARC, clearing, settlement, or payout key.
Publisher startup compares its x-only public key with every configured
secp256k1 role and fails on equality. Because equal public bytes cannot detect
reuse across different algorithms, provisioning must also use a separately
generated secret file, custody policy, backup and rotation record; copying a
Lightning or Ed25519 seed into the Nostr key file is forbidden even when the
derived public encodings differ.

Each listed provider supplies an inner assertion signed by its Ed25519 operator
key. For a directory-discovered provider with no independent operator pin, the
pinned directory key is the discovery and Sybil trust boundary for that
operator key: the inner signature prevents relay alteration and binds the later
live identity, but does not independently prove who controls the newly
discovered key. The assertion separately carries the provider's service-policy
Ed25519 key; reusing the operator key for policy signing is forbidden. Neither
signature replaces the live strict-verification sequence:

1. verify the pinned directory Nostr key and NIP-01 event;
2. verify the inner operator assertion, derive its `provider_id`, and retain
   its distinct non-zero `policy_signing_key_ed25519`;
3. use the endpoint only as a connection hint;
4. verify runtime attestation, identity, binary pin and secure channel;
5. verify database proof/root and the live service policy under exactly the
   asserted policy-signing key;
6. require the live provider/operator identity, policy-signing key, policy
   epoch and policy digest to equal the selected directory assertion before
   relying on any advertised offer.

A mismatch is a hard failure for that discovered entry. It never causes a
fallback to an unsigned endpoint, plaintext transport, a different payment
method, or a directory-supplied price.

The directory is allowed to curate, omit, delay, reorder, or tombstone entries;
that is availability and discovery policy. It cannot authorize a provider or
an offer. Manual endpoint import plus a separately pinned operator key remains
available when the directory is unavailable.

Strictly verifying two live servers proves only that each server matches its
own advertised identity, binary and database. It does not prove that their two
operator keys are controlled by independent parties. A client relying only on
one directory therefore inherits that directory's Sybil/independence claim.
V1 exposes this limitation rather than presenting different keys or sequential
selection as cryptographic proof of non-collusion.

## Nostr envelope

V1 uses a NIP-78 addressable event:

```text
kind = 30078
pubkey = pinned dedicated directory Nostr public key
tags contains exactly these two tags, in this order:
  ["d", "bitcoinpir-service-directory-v1:<provider_id-lower-hex>"]
  ["s", "bitcoinpir-service-directory-shard-v1:<provider-id-high-nibble>"]
content = canonical JSON DirectoryEntryV1
```

The V1 profile rejects every additional tag, including otherwise valid generic
NIP-78 tags. This strict shape prevents an honest implementation from adding an
invoice, payment hash, credential identifier, selected peer, or other
correlation field. A relay cannot add or change a tag without invalidating the
NIP-01 event ID and signature. Clients fetch a complete catalog or a coarse
public shard; they MUST NOT ask a relay or directory API for a chosen
two-provider pair, Bitcoin address, query, backend operation, or payment
method.

NIP-01 replacement coordinates are exactly `(kind, pubkey, d)`. A later
`created_at` wins; at an equal timestamp the lexicographically lower event ID
wins. BitcoinPIR additionally requires `created_at` to increase strictly when
an entry sequence or checkpoint epoch advances. The publisher therefore MUST
persist the last timestamp per `d` coordinate and wait for the next Unix second
instead of publishing two logical revisions at one timestamp. An application
sequence/epoch fork is rejected rather than resolved by relay tie-breaking.

The publisher also emits coarse-shard catalog-checkpoint events under a
distinct `d` namespace. A checkpoint commits to its epoch, validity window,
shard rule, and the sorted `(provider_id, directory_sequence, event_id)` set.
The default strict discovery mode requires two to eight configured exact,
credential-free WSS origins with no path component,
compares the newest same-epoch checkpoints, and fails closed on different
roots. This makes a seen split view detectable; it cannot stop a malicious
directory publisher or coordinated relays from presenting one consistent
malicious catalog everywhere. V1 also has an explicitly named
`centralized-single-relay` mode for exactly one origin. That mode is displayed
as centralized/degraded and provides no relay split-view or relay-outage
cross-check. It does not weaken event signatures, checkpoint completeness,
anti-rollback persistence, or later live provider verification.

Before any entry in a shard is selectable, the client sorts the verified entry
events by `provider_id` and requires an exact match with every checkpoint tuple.
Missing, additional, duplicated, wrong-shard, foreign-publisher, stale-event-ID,
or substituted entries invalidate the shard. Tombstones remain in the
checkpoint set even though only active entries are offered for selection.
The client first commits every entry floor and the checkpoint floor through the
durable CAS interface, then constructs the selectable shard from those
persisted typestates. A failed or conflicting durable write leaves the shard
unselectable.
The relay transport must wait for NIP-01 `EOSE` before declaring the initial
shard complete; a timeout, `CLOSED`, disconnect, or missing `EOSE` leaves that
relay's shard unusable rather than accepting a partial catalog.

The V1 browser adapter defaults to `strict-multi-relay`: it opens two to eight
distinct exact `wss://host[:nondefault-port]` origins, obtains all 16
Rust-generated semantic `REQ` filters, validates every fixed field, then
re-encodes their exact relay-profile field order before sending them to each
relay. This re-encoding is required because the JSON bridge may sort map
members even though the relay profile fixes the `authors`, `kinds`, `#s` order.
It forwards raw `EVENT` envelopes unchanged to the strict Rust/WASM verifier.
A relay contributes a view only after every subscription reaches `EOSE`; at
least two complete views are required, and one failed member of an exact
two-origin configuration never causes fallback to centralized mode. With more
than two configured origins, strict mode intentionally accepts at least two
complete views; all complete views are compared by WASM and incomplete origins
contribute nothing. This is a strict multi-origin threshold, not centralized
fallback. The separate `centralized-single-relay` UI/API option accepts exactly
one origin and calls the distinctly named
`verifyCentralizedSingleRelayEventBatch` WASM entry point whose input also
carries that mode. The low-level WASM methods verify event batches, not
transport history: the Web adapter must first enforce the canonical origin
grammar and 16 EOSE-complete subscriptions. The strict method is correspondingly
named `verifyStrictRelayEventBatch`; neither name claims WASM independently
observed URL origins or EOSE.
The returned selectable catalog records the mode and degraded assurance, but
the encrypted rollback state contains neither mode nor relay URL. The adapter
applies all entry plus 16 checkpoint transitions in one digest-CAS transaction under a
directory-key Web Lock. Rust withholds the selectable catalog until it receives
the exact post-commit successor bytes. Its selectable result includes the
minimum `valid_until` across all 16 authenticated checkpoints and every entry,
including tombstones. One page-wide nondecreasing wall-clock plus
monotonic-elapsed floor is rechecked after CAS and before admission,
offer/payment, token import/use, authorization, and query. This floor prevents
a later in-page local-clock rollback or stall from resurrecting expired trust,
but the browser clock is not an authenticated time oracle and a page reload
starts a new time floor: a forward jump can only force fail-closed
refresh/denial. Expiry clears active
directory trust, closes attempts, and blocks silent downgrade to the manual
bootstrap path; the user must refresh explicitly (or explicitly replace the
trusted bootstrap to choose manual operation).

Mode, ordered relay origins, pinned publisher key, and trusted-bootstrap
revision form one immutable refresh intent. Editing any input synchronously
invalidates its generation, clears active directory trust, and closes attempts.
A stale relay response or IndexedDB CAS may finish, preserving only its
anti-rollback floor, but its catalog result can never become active. Refresh is
explicit and never triggered by an address query, provider selection, or
payment event.

### Catalog-checkpoint content

There are 16 public shards. `shard = provider_id[0] >> 4`, rendered as one
lowercase hexadecimal nibble. A checkpoint uses the same kind/publisher and the
same strict two-tag shape:

```text
["d", "bitcoinpir-service-directory-checkpoint-v1:<shard-nibble>"]
["s", "bitcoinpir-service-directory-shard-v1:<shard-nibble>"]
```

Its canonical content is:

```json
{
  "v": 1,
  "shard": 2,
  "checkpoint_epoch": 17,
  "not_before": 1770000000,
  "valid_until": 1770086400,
  "entries": [
    {
      "provider_id": "32-byte-lower-hex",
      "directory_sequence": 42,
      "event_id": "32-byte-lower-hex"
    }
  ],
  "catalog_root": "32-byte-lower-hex"
}
```

Entries are strictly increasing by `provider_id`; duplicates, zero IDs,
zero sequences, wrong-shard providers and more than 1,024 entries fail closed.
The root is:

```text
SHA256(
  "BitcoinPIR/directory-catalog-checkpoint-root/v1"
  || version_u8(1)
  || shard_u8
  || checkpoint_epoch_u64_le
  || not_before_u64_le
  || valid_until_u64_le
  || entry_count_u32_le
  || for each sorted entry:
       provider_id_32 || directory_sequence_u64_le || event_id_32
)
```

## Canonical content

The wire implementation will serialize fields in the order below, without
insignificant whitespace, and then require parse-and-reserialize equality.
Byte arrays are fixed-length lowercase hex. Integers are unsigned JSON integers
within their stated Rust type. Strings are UTF-8 and reject control characters.
Unknown fields, duplicate object keys, duplicate endpoints, and unsorted lists
fail closed.

```json
{
  "v": 1,
  "provider_id": "32-byte-lower-hex",
  "directory_sequence": 42,
  "directory_valid_until": 1780000000,
  "status": "active",
  "operator_assertion": {
    "v": 1,
    "operator_pubkey_ed25519": "32-byte-lower-hex",
    "stable_server_id": "provider-chosen-stable-id",
    "provider_id": "32-byte-lower-hex",
    "assertion_epoch": 7,
    "not_before": 1770000000,
    "valid_until": 1780000000,
    "endpoints": [
      {"transport": "wss", "url": "wss://pir.example.invalid/v1"}
    ],
    "policy_signing_key_ed25519": "distinct-nonzero-32-byte-lower-hex",
    "policy_epoch": 11,
    "policy_digest": "32-byte-lower-hex",
    "signature_ed25519": "64-byte-lower-hex"
  },
  "catalog_hints": [],
  "health": {
    "class": "unknown",
    "observed_bucket": 1770000400
  }
}
```

`status` is `active` or `tombstone`. An active entry requires a complete
operator assertion. A tombstone carries `operator_assertion: null`, empty
catalog hints, and only removes this directory's discovery recommendation; it
does not revoke a separately pinned provider.

`catalog_hints` is a bounded, sorted mirror used only to avoid connecting to
obviously unsuitable providers. Each hint names a `scope_id`, backend,
workload, and the acquisition/authorization/deployment modes claimed by the
directory. Prices and entitlements remain authoritative only in the exact live
policy whose key and digest are signed by the provider assertion. The client
compares the provider ID, operator identity, policy-signing key, policy epoch,
policy digest and every selected hint with that strictly verified live policy
before showing or purchasing it. Matching a hint
means the same scope ID, backend, workload, acquisition method, authorization
scheme and deployment status exist together in one live offer. The directory
does not publish or bind prices, entitlements, offer IDs, credential keys, or
payment artifacts.

`health` is coarse directory observation, not a provider promise. V1 buckets
observation time to at least five minutes and exposes no client-specific probe,
capacity reservation, payment success, query count, latency sample, peer
selection, or per-method usage.

## Inner operator assertion

The Ed25519 signature is over a domain-separated canonical binary preimage,
not over JSON text:

```text
"BitcoinPIR/directory-operator-assertion/v1"
|| version_u8
|| operator_pubkey_ed25519_32
|| len_u16(stable_server_id) || stable_server_id_utf8
|| provider_id_32
|| assertion_epoch_u64_le
|| not_before_u64_le
|| valid_until_u64_le
|| endpoint_count_u8
|| for each endpoint sorted by (transport, url):
     transport_u8 || len_u16(url) || url_utf8
|| policy_signing_key_ed25519_32
|| policy_epoch_u64_le
|| policy_digest_32
```

The verifier derives
`provider_id = derive_provider_id(operator_pubkey, stable_server_id)` and
requires exact equality with both the assertion and Nostr `d` tag. The policy
key must be non-zero and distinct from the operator key; the live policy
signature must verify with that exact asserted key. Endpoints
are limited to canonical secure schemes supported by the client (`wss` in the
initial browser transport); redirects, URL userinfo, fragments, IP literals,
non-canonical ports and ambiguous paths are rejected. `assertion_epoch`,
`policy_epoch`, timestamps and both validity windows are non-zero and ordered.

Operator assertion epochs are monotonic per `provider_id`. A different inner
assertion at an already retained epoch is an operator equivocation and fails
closed even if the directory sequence is newer.

## Client rollback state

The transport-neutral API order is:

1. build all-shard NIP-01 `REQ` messages with
   `full_catalog_req_json_v1`;
2. after relay `EOSE`, authenticate all bounded events, group them by
   `(kind,pubkey,d)`, and select the NIP-01 winner using
   `nip01_addressable_replacement_order_v1` (later timestamp, then lower ID);
3. durably accept each selected event with
   `verify_and_persist_directory_entry_v1` and
   `verify_and_persist_directory_checkpoint_v1`;
4. construct the selectable shard with
   `bind_persisted_directory_shard_catalog_v1`;
5. select providers/method hints locally;
6. after the normal strict connection and policy verification, call
   `bind_directory_entry_to_live_policy_v1` before displaying or acquiring an
   offer.

Steps 2 through 6 fail closed. Relay or storage failure does not bypass the
directory pin, operator assertion, secure channel, database verification, live
policy verification, or payment gate.

For each `(directory_nostr_pubkey, provider_id)` the client durably retains:

```text
highest_directory_sequence
event_id_at_highest_sequence
event_created_at_at_highest_sequence
status_at_highest_sequence
highest_operator_assertion_epoch
operator_assertion_digest_at_highest_epoch
highest_checkpoint_epoch
catalog_root_at_highest_epoch
event_id_at_highest_epoch
event_created_at_at_highest_epoch
```

Rules:

- lower directory sequence: reject as rollback;
- same sequence and same NIP-01 event ID: exact replay;
- same sequence and different event ID/content: directory equivocation, reject;
- higher sequence with a non-increasing NIP-01 `created_at`: reject;
- lower operator assertion epoch: reject;
- same operator epoch and different assertion digest: operator equivocation,
  reject;
- expired entry/assertion: do not use for a new connection;
- an entry validity interval longer than the V1 cap, measured from the signed
  Nostr `created_at`, is rejected (including tombstones);
- higher signed tombstone: suppress the entry for this directory key;
- a later active entry must have both a higher directory sequence and a higher
  valid operator assertion epoch.
- same catalog-checkpoint epoch with a different root or event ID: directory
  split view/equivocation, reject and retain evidence;
- higher checkpoint epoch with a non-increasing `created_at`: reject;

Rollback state is not synchronized between the two selected providers and
contains no pair identifier. Browser synchronization, if enabled later, must
not upload selection history under an account shared with payment activity.

## Privacy and logging

Directory events contain no invoice, payment hash, preimage, claim key,
credential, Cashu proof, ARC state, IP-derived bucket, query address, PIR
share/result, or peer-provider identity. Publisher logs retain only aggregate
catalog ingestion/validation results; serving the static catalog does not log
provider-specific selection parameters.

This schema guarantee cannot prevent a malicious publisher from using event
timing, omissions, ordering, key choice, or Schnorr auxiliary randomness as a
subliminal channel. The directory is already a centralized discovery observer;
production operation therefore separates its key and logs from Lightning,
issuer and PIR services and publishes the same static events to every relay.

V1 has no in-band directory-key rotation message. A new publisher key is a new
trust namespace and becomes usable only through an authenticated client/config
update that pins it explicitly. Rotation never deletes the old key's retained
fork evidence or silently transfers its monotonic floors to an unauthenticated
key.

Clients download before they know the Bitcoin query. Provider filtering and
pair construction happen locally. A provider never receives the directory
event ID or the selected peer as part of service authorization.

Fetching only one shard from a relay reveals that coarse shard to the relay and
the client's network observer. The browser implementation therefore MUST
default to fetching all 16 shards in one catalog refresh, cache the public
result independently of query state, and never refresh in response to a Bitcoin
address or payment event.
Low-bandwidth single-shard fetch remains an explicit privacy tradeoff, never a
method/provider-pair lookup API.

## Repository directory-only relay profile

`apps/directory-relay` implements the server-side subset needed by this
protocol. It is not a general-purpose Nostr relay. The sole process interface
is `bitcoinpir-directory-relay --config /absolute/owner-only.toml`; the
configuration fixes distinct public and publisher loopback listeners, one
absolute SQLite database, one pinned non-zero directory publisher key and
explicit global plus per-lane concurrency, ingress, egress, archive and
timeout bounds. Every pair of lane reservations must add exactly to its global
cap. No publisher private key is present.

The accepted client messages are only the exact canonical NIP-01 `EVENT`,
`REQ`, and `CLOSE` shapes used here. EVENT requires the pinned key, kind 30078,
valid signature, canonical JSON, and the exact `d`/`s` namespaces. There is no
generic subscription language, live push, NIP-42 AUTH, NOTICE, or application
heartbeat path. A reverse proxy may handle WebSocket control frames, but it
must not log frames or silently transform application messages.
The public listener accepts only `REQ`/`CLOSE`; the publisher listener accepts
only `EVENT`. Each connection or operation acquires its lane reservation before
the shared global reservation, and rate/egress gates apply at both levels.
These reservations preserve publisher admission capacity under public load,
but both lanes share the process and mutex-protected SQLite store, so they are
not a storage-level availability boundary.

SQLite keeps an immutable event archive and a separate addressable-event head.
An unseen current event, its archive counters, and any head replacement commit
in one `BEGIN IMMEDIATE` transaction. Positive `OK` is possible only after that
commit returns. An exact archived duplicate is positively idempotent even if it
has since expired or lost the replacement race; an unseen expired event is
rejected. If a started write's durable result cannot be recovered, the relay
closes without sending a false negative acknowledgement.

REQ first freezes the ordered event-ID set and exact logical response bytes.
Pages are then loaded from the non-deleting archive, so concurrent replacements
cannot create a mixed snapshot. The relay reserves the complete EVENT-plus-EOSE
response against the connection's cumulative egress budget before sending a
prefix, streams bounded pages under a process-wide byte rate and emits EOSE
only after the frozen set is complete. A configured budget may deliberately
prevent the count and maximum-event-size limits from being saturated together;
clients treat a closed/over-budget view as unusable, never as a partial catalog.

ID-filter readback is limited to 64 unique IDs and is intended only for
commit probes and bounded recovery, not archive enumeration. It is executed as
one bounded SQL `IN` query and reordered to the canonical request order before
the snapshot is frozen. Global admission charges one work unit per eight IDs,
and every connection has a cumulative 256-unit work budget in addition to the
message, concurrency, byte, idle and absolute-lifetime limits. Catalog filters
remain one work unit because each shard is one indexed SQL query; clients still
fetch all 16 shards independently of query state.

Shutdown first stops acceptance, signals every tracked connection, calls the
SQLite interrupt handle and then drains all connection tasks; blocking workers
are not detached. SQLite interruption makes a current statement return, but a
filesystem that stalls inside an uninterruptible kernel write can still exceed
the service stop timeout. Activation therefore still requires a Linux shutdown
fault drill rather than treating this source property as timing proof.

The archive event/byte caps are permanent capacity decisions, not an eviction
policy. `max_archive_bytes` counts canonical event JSON BLOB bytes rather than
SQLite/WAL/index disk usage. Operators must add filesystem quota and free-space
monitoring, back up the database and WAL as one consistent state domain, and
restore only a fully checked copy with the same publisher key and configured
capacity. Strict mode still requires two distinct WSS origins; centralized mode
requires exactly one explicit origin. Two origins or processes on one machine
do not create independent operator, network, storage, backup, or outage domains.
They can detect accidental view divergence but provide substantially weaker
availability and adversarial split-view resistance than independent operators.
Neither arrangement makes a relay a trust root: clients authenticate the
publisher's events and still execute the full live provider trust chain.

## Publisher artifacts and relay transport

The `assertion`, `entry`, and `checkpoints` commands build signed artifacts
offline. Keep the Ed25519 operator key, Ed25519 service-policy key, and BIP340
directory key in separately generated files and custody domains. The builders
reject operator/policy key equality, detect reuse of the directory secret seed
for either Ed25519 role when those roles are present, and accept repeatable
`--reserved-xonly-pubkey-hex` pins for other secp256k1 roles.

First generate and verify an operator assertion from the canonical signed
policy. Every endpoint must be a canonical public `wss://` URL:

```sh
bpir-admin directory-artifact assertion \
  --policy service-policy.bin \
  --policy-signing-key-hex "$POLICY_PUBKEY" \
  --operator-signing-key operator.key \
  --stable-server-id pir-a \
  --assertion-epoch 1 \
  --not-before "$NOW" \
  --valid-until "$VALID_UNTIL" \
  --endpoint wss://pir-a.example/v1 \
  --now-unix "$NOW" \
  --out directory-assertion.bin
```

Then generate the provider's addressable entry. Catalog hints are derived from
the verified policy instead of being accepted as CLI input. The health time is
public coarse metadata and must be floored to a 300-second boundary:

```sh
bpir-admin directory-artifact entry \
  --assertion directory-assertion.bin \
  --policy service-policy.bin \
  --policy-signing-key-hex "$POLICY_PUBKEY" \
  --directory-signing-key directory-nostr.key \
  --directory-sequence 1 \
  --directory-valid-until "$VALID_UNTIL" \
  --created-at "$NOW" \
  --health-class available \
  --health-observed-bucket "$FLOORED_NOW" \
  --now-unix "$NOW" \
  --out pir-a.entry.event.json
```

If a provider is replaced by a different provider ID, publish a tombstone for
the retired ID at the next directory sequence. A tombstone contains neither an
operator assertion nor catalog hints, so it cannot advertise the retired
provider. Include it with the active entries when rebuilding the complete
checkpoint set; this keeps an addressable relay's returned entry set exactly
bound to the new checkpoint.

```sh
bpir-admin directory-artifact tombstone \
  --provider-id-hex "$RETIRED_PROVIDER_ID" \
  --directory-signing-key directory-nostr.key \
  --directory-sequence "$NEXT_SEQUENCE" \
  --directory-valid-until "$VALID_UNTIL" \
  --health-class unavailable \
  --health-observed-bucket "$FLOORED_NOW" \
  --created-at "$NOW" \
  --now-unix "$NOW" \
  --out retired-provider.tombstone.event.json
```

Finally build a complete checkpoint set. Pass every current active or
tombstone entry exactly once. The output is one JSON array containing exactly
16 independently signed NIP-01 `["EVENT", event]` messages, including empty
shards:

```sh
bpir-admin directory-artifact checkpoints \
  --directory-signing-key directory-nostr.key \
  --entry-event pir-a.entry.event.json \
  --entry-event pir-b.entry.event.json \
  --checkpoint-epoch 1 \
  --not-before "$NOW" \
  --valid-until "$VALID_UNTIL" \
  --created-at "$NOW" \
  --now-unix "$NOW" \
  --out directory-checkpoints.json
```

All inputs are bounded and parsed fail closed. Secret keys use a single-file-
descriptor `O_NOFOLLOW`, owner and mode check; outputs are self-verified before
an atomic same-directory write and are mode `0600`. Existing outputs are not
replaced unless `--force` is explicit. No-clobber creation is one atomic
filesystem operation, including under concurrent invocations. `--force` changes only the local
artifact file: key rotation, relay publishing and deployment remain separate
operator actions. Publishing must send the emitted EVENT messages unchanged
to every configured relay and persist the last `created_at` for each `d`
coordinate before advancing an entry sequence or checkpoint epoch.

The explicit `publish` command is the only directory-artifact command that
opens the network. It accepts one or more already-signed canonical entry EVENT
files and/or exact 16-message checkpoint arrays; it never accepts or reads a
signing key. Pin the expected directory public key and publish the same frozen
artifacts to between two and eight relay hostnames in the default strict mode:

```sh
bpir-admin directory-artifact publish \
  --artifact pir-a.entry.event.json \
  --artifact directory-checkpoints.json \
  --relay wss://relay-one.example \
  --relay wss://relay-two.example:8443 \
  --directory-pubkey-hex "$DIRECTORY_PUBKEY" \
  --now-unix "$NOW" \
  --relay-timeout-seconds 60
```

An operator who explicitly accepts centralized/degraded relay availability may
instead publish to exactly one relay. Merely supplying one `--relay` is rejected;
the named opt-in is mandatory and is included in every bounded outcome line:

```sh
bpir-admin directory-artifact publish \
  --artifact pir-a.entry.event.json \
  --artifact directory-checkpoints.json \
  --relay wss://relay-one.example \
  --centralized-single-relay \
  --directory-pubkey-hex "$DIRECTORY_PUBKEY" \
  --now-unix "$NOW" \
  --relay-timeout-seconds 60
```

Exactly one relay is accepted only when the invocation also carries
`--centralized-single-relay`. This explicit degraded mode is intended for the
current centrally operated directory: it does not claim relay redundancy,
operator independence, or failure independence. Zero relays, one relay without
the flag, and the flag with multiple relays all fail before DNS or network I/O.

Run that exact command with `--validate-only` first. It performs the complete
artifact, key-pin, time and relay-set validation and prints the same bounded
relay-host/event-count/event-set-digest fields with `result=validated`, plus the
publication mode and explicit `centralized`/`degraded` booleans, but it does not
resolve, connect to or write to a relay. Removing only that flag is the explicit
network-publication boundary for the reviewed frozen inputs.

Before dialing, every EVENT is verified through the production entry or
checkpoint parser against that key and time. Duplicate IDs, noncanonical bytes,
mixed/incomplete checkpoint bundles, and expired or malformed events fail
closed. Relay URLs must be exact canonical credential-free public `wss://`
origins with no path component;
strict-mode hostnames must be distinct. Different hostnames do **not** prove different operators,
registrable domains, infrastructure, or legal control; the directory operator
must audit those independence properties when selecting relays.

Each relay gets one direct WebPKI TLS WebSocket and each exact EVENT text is
followed by exactly one bounded NIP-01 `["OK", id, true, ...]`. V1 intentionally
rejects `false`, unknown/out-of-order/duplicate/missing OK, `NOTICE`, `CLOSED`,
oversized replies, and every non-text WebSocket message including Ping/Pong.
There is no proxy, credential, redirect, relay-auth or automatic retry path.
The single timeout bounds connect plus all sends and acknowledgements for that
relay. This strict control-frame policy must be included in relay compatibility
testing; a relay that injects Ping/Pong during the short publish exchange is not
compatible with this V1 publisher.

Publishing to multiple relays is not atomic. Strict mode attempts every relay,
prints only relay hostname, event count and a bounded result code, and exits
nonzero if any relay fails; it never silently converts that invocation to
centralized mode. Centralized mode likewise exits nonzero when its only relay
fails. Each line also includes the explicit directory mode/assurance and one domain-separated
digest of the sorted event-ID/signature set, never an event ID. It never logs
event content, signature or ID. An
operator may safely rerun the exact immutable artifact: positive OK for an
already-stored event is treated as success, while a negative OK is always a
failure. Preserve artifacts and the external per-`d` `created_at`/sequence
ledger before advancing; the transport does not mutate that ledger.

For an approved staging readback, `scripts/payment-v1-nostr-readback.mjs`
loads no key and has no publish operation. It uses the Web package's
lockfile-pinned WebSocket implementation with redirect/compression disabled and
a transport-level payload limit, validates raw relay URLs with the Rust
publisher's canonical grammar, and reads stable regular artifacts under one
cumulative 5 MiB budget. Symlink, FIFO, device, mutation and oversized inputs
fail before network I/O. Both the Rust publisher artifact loader and the
staging readback tool require a trusted local Unix/POSIX filesystem. Same-FD
pre/post metadata checks reject observable identity, mode, size, mtime or ctime
changes, but `O_NONBLOCK` does not give a stalled NFS/FUSE regular-file read a
wall-clock deadline and a privileged or malicious filesystem can forge
metadata. Non-Unix publisher input fails closed. The tool requests the frozen
artifact's exact IDs and
requires the exact publisher-reported set digest, recomputes each NIP-01 event
ID, and requires every exact event value once followed by EOSE from each relay.
A centralized readback invocation likewise requires the explicit
`--centralized-single-relay` flag and exactly one relay; strict readback retains
the default two-to-eight range and never falls back after a failure.
A
positive publish OK and successful immediate readback are compatibility
observations, not a durability SLA or proof of relay-operator independence.
Canonical hostname syntax also does not prevent DNS rebinding; production
operators must add DNS and egress policy when private-network access is in the
publisher/readback threat model.

## Required implementation tests

- locked NIP-01 canonical-preimage/event-ID fixture, independent secp256k1
  signature verification, and a kind-30078 `d` tag fixture;
- canonical JSON rejects whitespace/order aliases, duplicate keys, uppercase
  hex and unknown fields;
- inner Ed25519 signature, provider derivation and endpoint canonicalization;
- wrong directory key, wrong operator key, malformed event and expiry;
- lower/same-sequence fork and lower/same-epoch operator fork;
- NIP-01 later-timestamp/lower-ID replacement ordering and rejection of logical
  revisions with non-increasing timestamps;
- tombstone precedence and later valid reactivation;
- live identity/provider/policy mismatch overrides discovery;
- complete shard membership exactly matches a signed checkpoint;
- unexpected tags and JSON fields capable of carrying payment or peer artifacts
  fail closed;
- catalog fetch request shape contains no pair, query, address, or method;
- one relay without the named centralized opt-in rejects, one with the opt-in
  verifies and is marked centralized/degraded, strict two-origin mode still
  compares split views, and zero, more than eight, or centralized-plus-two
  inputs reject before dialing;
- failure of either member in an exact two-origin strict refresh never invokes
  the centralized verifier or accepts the remaining view;
- selectable expiry equals the minimum of every checkpoint and every entry,
  including tombstones;
  expiry during/after CAS or immediately before admission, payment, token,
  authorization, or query clears the catalog and cannot fall back to a manual
  anchor;
- mode, ordered relay set, publisher key, and bootstrap-revision changes race
  safely against relay/IndexedDB completion: old results never activate;
- exact publisher transport requires positive per-event/per-relay OK, rejects
  false, duplicate, unexpected, missing, non-text, oversized and timed-out
  replies, and reports partial success as a command failure;
- readback rejects URL normalization aliases, symlink/FIFO/device/changing
  artifacts and per-file or cumulative size violations before any relay dial;
- a manual endpoint path works only when explicitly bootstrapped without an
  active/invalidated directory requirement; directory expiry never silently
  selects that path.

External specifications:

- NIP-01 basic event format and signature:
  <https://github.com/nostr-protocol/nips/blob/master/01.md>
- NIP-78 application-specific addressable data:
  <https://github.com/nostr-protocol/nips/blob/master/78.md>
