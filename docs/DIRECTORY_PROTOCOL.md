# Nostr service-directory protocol

Status: implementation contract for the v1 discovery lane. Directory data is
never runtime, database, access-policy, payment, or query authorization by
itself.

History: the directory was designed and implemented inside the Payment V1
tree (July–August 2026) and removed with it before any production
publication. It was restored in October 2026 as a standalone lane: the
operator assertion no longer carries a service-policy signing key, epoch or
digest, and catalog hints mirror the server's published access policy
(`credits.access` in `GET_INFO_JSON`), its DPF `role` and its attestation
tier instead of Payment V1 offers. The codec lives in
`crates/directory/nostr` (`pir-directory-nostr`); the operator commands are
`bpir-admin directory-artifact …`; the browser client is
`web/src/nostr-directory.ts` over the WASM verifier in
`crates/sdk/wasm/src/directory.rs`; the operator readback is
`scripts/directory-readback.mjs`. Without an independent operator pin,
however, the pinned directory key
is the provider-identity/endpoint discovery and Sybil trust root. It is also a
centralized curation, split-view, diversity-claim, and availability boundary.
The manual endpoint plus independently pinned operator path bypasses this
directory trust.

## Trust model

The directory publisher has one dedicated Nostr secp256k1 key. That key MUST
NOT be a PIR operator, runtime identity, issuer, Lightning, or API-key
signing key.
Publisher startup compares its x-only public key with every configured
secp256k1 role and fails on equality. Because equal public bytes cannot detect
reuse across different algorithms, provisioning must also use a separately
generated secret file, custody policy, backup and rotation record; copying a
Lightning or Ed25519 seed into the Nostr key file is forbidden even when the
derived public encodings differ.

Each listed provider supplies an inner assertion signed by its Ed25519 operator
key: the same key that signs the server's REQ_ANNOUNCE `IdentityCert`. For a
directory-discovered provider with no independent operator pin, the pinned
directory key is the discovery and Sybil trust boundary for that operator key:
the inner signature prevents relay alteration and binds the later live
identity, but does not independently prove who controls the newly discovered
key. Neither signature replaces the live strict-verification sequence:

1. verify the pinned directory Nostr key and NIP-01 event;
2. verify the inner operator assertion and derive its `provider_id` from the
   asserted operator key and `stable_server_id`;
3. use the endpoint only as a connection hint;
4. verify the REQ_ANNOUNCE identity bundle, the attestation tier of the
   secure channel (binary pin, or SEV-SNP measurement), and the channel
   binding;
5. verify the database proof/root and read the server's published `role`
   and access policy (`GET_INFO_JSON`);
6. require the live operator key and `server_id` to derive the selected
   `provider_id`, and every catalog hint (backend, role, access class,
   attestation) to be served live, before relying on any hint
   (`bind_directory_entry_to_live_identity_v1`).

A provider whose hints claim `attestation = sev-snp` and whose server
announces no identity (REQ_ANNOUNCE answers "not configured", as on the
Direct ORAM TEE host) is bound in step 6 by its attestation instead of an
identity bundle: the SEV-SNP report binds the channel key (REPORT_DATA), its
VCEK chain verifies to the AMD root, and its MEASUREMENT matches the client's
pin. Its operator still signs the inner assertion, but nothing live closes
that operator key and `server_id`: for such a provider the directory key is
the trust root for who operates it, while the attestation is the trust root
for what it runs. A server that does announce an identity is held to it
whatever its tier.

A mismatch is a hard failure for that discovered entry. It never causes a
fallback to an unsigned endpoint, plaintext transport, a different access
class, or a directory-supplied price.

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
The strict discovery mode reads two to eight distinct relays, compares the
checkpoints of the relays that answered, and rejects a shard whose relays
return different checkpoints at one epoch. This makes a seen split view
detectable; it cannot stop a malicious directory publisher or coordinated
relays from presenting one consistent malicious catalog everywhere. V1 also
has an explicitly named `centralized-single-relay` mode for exactly one
relay. Its catalog is reported centralized/degraded and has no relay
split-view or relay-outage cross-check. It does not weaken event signatures,
checkpoint completeness, anti-rollback persistence, or later live provider
verification.

Before any entry in a shard is selectable, the client sorts the verified entry
events by `provider_id` and requires an exact match with every checkpoint tuple.
Missing, additional, duplicated, wrong-shard, foreign-publisher, stale-event-ID,
or substituted entries invalidate that relay's view of the shard. Tombstones
remain in the checkpoint set even though only active entries are offered for
selection. The client stores the advanced entry and checkpoint floors before
it uses the catalog; a failed write fails the refresh.
The relay transport waits for NIP-01 `EOSE` on all 16 subscriptions; a
timeout, `CLOSED`, disconnect, or missing `EOSE` leaves that relay without a
view rather than contributing a partial catalog.

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
    "signature_ed25519": "64-byte-lower-hex"
  },
  "catalog_hints": [
    {"backend": "dpf", "role": "primary", "access": "best-effort", "attestation": "none"},
    {"backend": "onion", "role": "primary", "access": "paid", "attestation": "none"}
  ],
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

`catalog_hints` is a bounded (64), sorted mirror used only to avoid connecting
to obviously unsuitable providers. Each hint names one `backend` (`dpf`,
`harmony`, `onion`, `oram`), the server's DPF `role` (`primary` or
`secondary`), the coarse `access` class (`free`, `paid`, `best-effort`) and
the `attestation` tier (`none` or `sev-snp`). Hints are strictly sorted by
`(backend, access)`, name each backend at most once, and carry the same role
and attestation for the whole entry. Prices, gas, concurrency and budgets
remain authoritative only in the live server. The client compares the
provider ID, operator identity, role, attestation and every hint with the
strictly verified live server before using it; matching a hint means the live
`credits.access` publishes the same backend with the same access class, and
the live `role` and attestation tier equal the hint. The directory does not
publish or bind prices, credit parameters, issuer keys, or payment artifacts.

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
```

The verifier derives
`provider_id = derive_provider_id(operator_pubkey, stable_server_id)` and
requires exact equality with both the assertion and Nostr `d` tag. Endpoints
are limited to canonical secure schemes supported by the client (`wss` in the
initial browser transport); redirects, URL userinfo, fragments, IP literals,
non-canonical ports and ambiguous paths are rejected. `assertion_epoch`,
timestamps and the validity window are non-zero, ordered and at most 31 days.

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
3. accept each selected event against the retained floors, either through a
   durable store with `verify_and_persist_directory_entry_v1` and
   `verify_and_persist_directory_checkpoint_v1`, or with
   `prepare_directory_entry_acceptance_v1` /
   `prepare_directory_checkpoint_acceptance_v1` and storing the proposed
   states before use (the browser verifier);
4. construct the selectable shard with
   `bind_persisted_directory_shard_catalog_v1`;
5. select providers/method hints locally;
6. after the normal strict connection, identity and access-policy
   verification, call `bind_directory_entry_to_live_identity_v1` before
   displaying or using the provider.

A failure in steps 2 through 4 rejects that view of the shard, in step 6 that
provider. Relay or storage failure does not bypass the directory pin,
operator assertion, secure channel, database verification, live identity
verification, or credit gate.

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

### Browser client

`refreshNostrDirectoryV1` (`web/src/nostr-directory.ts`) takes the mode, the
relay list and the pinned directory key (`PRODUCTION_DIRECTORY` in
`web/src/production-providers.ts` for production). It sends the 16 `REQ`
messages from the WASM export `directoryCatalogRequestsV1`, byte-exact for the
relay profile, to every relay, and keeps a relay's view only once every
subscription reached `EOSE`; it then sends `CLOSE` for each. A relay that
times out, closes, answers `CLOSED` or malformed JSON, or sends more than
16 MiB contributes no view and is reported. The raw `EVENT` messages of the
complete views go unchanged to `verifyDirectoryCatalogV1`
(`crates/sdk/wasm/src/directory.rs`), so duplicate JSON fields cannot be
normalized away before Rust authenticates them. Per relay and shard, the
verifier checks every event against the pinned key and the current time,
keeps the NIP-01 head of each coordinate, applies the stored floors
(`prepare_directory_*_acceptance_v1`) and requires the exact checkpoint
membership (`bind_persisted_directory_shard_catalog_v1`). Across relays it
rejects a shard whose accepted views carry different checkpoints at one
epoch and otherwise takes the newest epoch. A failed view is reported with
its relay and shard; a shard without an accepted view is reported and offers
no provider.

The result lists, per backend, the candidate providers (operator key,
`server_id`, endpoints, role, trust tier (operator identity or SEV-SNP),
the access class of every listed backend, and health), the earliest expiry
over the accepted checkpoints and entries (tombstones included), every
rejection, and `degraded`: false only when all 16 shards came from at least
two relays that returned the same checkpoint, so a centralized catalog is
always degraded. A strict refresh with a relay down yields the catalog of the
remaining relays, reported degraded; whether to use it is the caller's
choice. `directoryBindingMismatchV1` closes a candidate against the live
server (step 6 of the trust model).

The floors are one `localStorage` value per directory key
(`bitcoinpir.directory-floors.v1.<key>`) holding the codec's encoded entry
and checkpoint states, written before the catalog is returned. They are the
public floors of the whole catalog, contain no mode, relay URL, query or
selection, and are stored unencrypted. Two tabs that verify at the same
moment may race; the later write wins. Refresh is explicit and never
triggered by an address query, provider selection, or payment event; the
caller refreshes again before the catalog's expiry.

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
protocol; running it on pir1 is [Directory relay](runbooks/directory-relay.md).
It is not a general-purpose Nostr relay. The sole process interface
is `bitcoinpir-directory-relay --config /absolute/config.toml`; the
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

The `keygen`, `assertion`, `entry`, and `checkpoints` commands build keys and
signed artifacts offline. Keep the Ed25519 operator key and the BIP340
directory key in separately generated files and custody domains. The builders
detect reuse of the directory secret seed as an Ed25519 operator seed and
accept repeatable `--reserved-xonly-pubkey-hex` pins for other secp256k1
roles.

Generate the directory key once, inside an owner-only `0700` directory:

```sh
bpir-admin directory-artifact keygen --out /path/private/directory-nostr.key
```

Then generate and verify an operator assertion with the operator key that
signs the server's identity certificate and the exact `server_id` that
certificate carries. Every endpoint must be a canonical public `wss://` URL:

```sh
bpir-admin directory-artifact assertion \
  --operator-signing-key operator.key \
  --stable-server-id pir-a \
  --assertion-epoch 1 \
  --not-before "$NOW" \
  --valid-until "$VALID_UNTIL" \
  --endpoint wss://pir-a.example/v1 \
  --now-unix "$NOW" \
  --out directory-assertion.bin
```

Then generate the provider's addressable entry. Catalog hints are given as
`--backend BACKEND=ACCESS` flags that must mirror the server's published
`credits.access`, with the server's `role` and attestation tier. The health
time is public coarse metadata and must be floored to a 300-second boundary:

```sh
bpir-admin directory-artifact entry \
  --assertion directory-assertion.bin \
  --directory-signing-key directory-nostr.key \
  --directory-sequence 1 \
  --directory-valid-until "$VALID_UNTIL" \
  --created-at "$NOW" \
  --role primary \
  --attestation none \
  --backend dpf=best-effort \
  --backend harmony=paid \
  --backend onion=paid \
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

The relay's publisher lane is loopback-only and is never published behind
TLS. To reach it, the operator runs the publisher on the relay host or opens
an SSH port-forward and adds `--loopback-publisher`; every `--relay` must
then be exactly `ws://127.0.0.1:PORT`, and plain `ws://` to any other host
is still rejected:

```sh
ssh -N -L 8097:127.0.0.1:8097 relay-host &
bpir-admin directory-artifact publish \
  --artifact pir-a.entry.event.json \
  --artifact directory-checkpoints.json \
  --relay ws://127.0.0.1:8097 \
  --loopback-publisher \
  --centralized-single-relay \
  --directory-pubkey-hex "$DIRECTORY_PUBKEY" \
  --now-unix "$NOW"
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

The readback, `scripts/directory-readback.mjs`, loads no key and has no
publish operation. It reads all 16 shards from each `--relay` (two to eight,
or exactly one with `--centralized-single-relay`) the way the browser client
does, verifies them with the same WASM verifier (build `crates/sdk/wasm/pkg`
first) and prints each relay's outcome, every accepted shard (epoch, agreeing
relay views, checkpoint event ID), every provider and every rejection. With
`--artifact` (the files given to `publish`) it also requires each relay to
serve every artifact event as the head of its coordinate. It exits nonzero on
any failed relay, rejection or missing event. A positive publish OK and a
successful immediate readback are compatibility observations, not a
durability SLA or proof of relay-operator independence.

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
- live identity/provider/role/attestation/access mismatch overrides discovery,
  and a server without an announce identity binds only as an SEV-SNP provider
  with a pinned attestation;
- complete shard membership exactly matches a signed checkpoint;
- unexpected tags and JSON fields capable of carrying payment or peer artifacts
  fail closed;
- catalog fetch request shape contains no pair, query, address, or method;
- one relay without the named centralized opt-in rejects, one with the opt-in
  verifies and is marked centralized/degraded, strict two-origin mode still
  compares split views, and zero, more than eight, or centralized-plus-two
  inputs reject before dialing;
- a failed member of a strict refresh is reported and leaves a degraded
  catalog from the remaining views; a tampered event or signature rejects only
  that relay's view of its shard; an older catalog after a newer one is
  rejected as a rollback and leaves the floors unchanged;
- the catalog expiry equals the minimum of every accepted checkpoint and
  entry, including tombstones;
- exact publisher transport requires positive per-event/per-relay OK, rejects
  false, duplicate, unexpected, missing, non-text, oversized and timed-out
  replies, and reports partial success as a command failure;
- a manual endpoint path works only when explicitly bootstrapped without an
  active/invalidated directory requirement; directory expiry never silently
  selects that path.

External specifications:

- NIP-01 basic event format and signature:
  <https://github.com/nostr-protocol/nips/blob/master/01.md>
- NIP-78 application-specific addressable data:
  <https://github.com/nostr-protocol/nips/blob/master/78.md>
