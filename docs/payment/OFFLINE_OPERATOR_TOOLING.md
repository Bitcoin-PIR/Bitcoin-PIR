# Payment V1 offline operator tooling

`bpir-admin` primarily provides offline builders for Payment V1 keys, signed
protocol artifacts, provider persistence, and a deterministic integration
fixture. No command starts a listener, creates a Lightning invoice, or moves
funds. Explicit network exceptions are: `cashu-custody spent-confirm` performs
one bounded NUT-07 HTTPS check; `directory-artifact publish` sends already-signed
public artifacts to configured Nostr relays; and provider store init/check or
custody commands selected with `--remote-rollback-authority-config` perform the
fresh signed Read/CAS operations required by the pinned-HTTPS floor. The local
SQLite compatibility variants and every other builder/inspection path remain
offline.

Production deployment, remote-server operations, and real Lightning funds are
separate ceremonies and are not authorized by running these commands.

## Secret keys

Generate one role per file. The CLI never prints secret bytes. On supported
Linux and macOS it creates or rewrites only regular files owned by the
effective user and sets mode `0600`; symlinks fail closed. Secret generation is
production-supported
only on Linux and macOS, where a pinned, non-group/world-writable parent directory and
file/directory durability operations are available. Bare output names remain
valid and refer to the current directory.

```sh
bpir-admin service-keygen --role issuer-root-ed25519 --out issuer-root.key
bpir-admin service-keygen --role quote-ed25519 --out quote-online.key
bpir-admin service-keygen --role bip340-claim --out claim-test.key
bpir-admin service-keygen --role credential-derivation --out credential-derivation.key
bpir-admin service-keygen --role redeem-derivation --out redeem-derivation.key
bpir-admin service-keygen --role free-ip-hmac --out free-ip-hmac.key
bpir-admin service-keygen --role cashu-recovery-aead --out cashu-recovery-1.key
bpir-admin service-keygen --role cashu-custody-aead --out cashu-custody-1.key
bpir-admin service-keygen --role provider-shared-idempotency-hmac --out shared-idempotency.key
bpir-admin service-keygen --role clearing-ed25519 --out provider-clearing.key
bpir-admin service-keygen --role provider-request-ed25519 --out provider-request.key
bpir-admin service-keygen --role receipt-ed25519 --out receipt.key
bpir-admin service-keygen --role cashu-bat --out bat.key
bpir-admin service-keygen --role cashu-ecash --out cashu-denomination.key
bpir-admin service-keygen --role arc-experimental --out arc.key
```

Other supported roles are `policy-ed25519`, `anonymous-ticket-ed25519`, and
`directory-nostr`. The six symmetric or derivation
roles (`credential-derivation`, `redeem-derivation`, and the four roles added
above) print only a domain-separated operator fingerprint, never a public key
or secret. Do not
reuse one raw key across roles, providers, BAT offers, ARC lineages, recovery
epochs, custody epochs, or shared-issuer relationships. `bip340-claim` is
normally browser-generated; the operator command exists for isolated tests and
recovery fixtures, not as a recommendation to centralize browser claim keys.

ARC uses a 128-byte four-scalar key and remains experimental pending an
independent cryptographic review.

## Nostr directory publication

Directory assertion, entry, and checkpoint construction remains offline and is
documented in `DIRECTORY_PROTOCOL.md`. The separate publish transport accepts
no secret or signing-key argument. It verifies exact canonical artifacts
against an explicit BIP340 directory-public-key pin, then sends them unchanged
to two through eight credential-free public `wss://` relay hostnames.

It requires one positive NIP-01 OK for each event on each relay, applies one
bounded total timeout per relay, does not use proxies, redirects, relay AUTH or
automatic retries, and exits nonzero on partial success. Exact artifacts are
idempotent and may be rerun manually. Distinct hostnames are only a syntactic
guard; selecting relays with genuinely independent operators and infrastructure
is an operator responsibility. The local transport-neutral WebSocket tests do
not establish public-relay or WebPKI interoperability. Publisher artifact
loading, like readback below, is supported only from a trusted local
Unix/POSIX filesystem: metadata stability checks do not make a stalled
NFS/FUSE read deadline-bounded or defend against a privileged filesystem.

The same `directory-artifact publish` invocation may include `--validate-only`.
That mode fully validates the artifact bytes, directory-key pin, verification
time and relay set, emits only bounded host/count/digest metadata, and returns
without DNS or network I/O. Remove only that flag at the separately approved
publication boundary.

After an explicitly approved staging publish, read the same frozen public
artifact back without exposing a signing key:

```sh
node scripts/payment-v1-nostr-readback.mjs \
  --artifact directory-checkpoints.json \
  --relay wss://relay-one.example \
  --relay wss://relay-two.example/nostr \
  --expected-set-digest-hex "$EVENT_SET_DIGEST_FROM_PUBLISH" \
  --timeout-ms 60000
```

This helper requires the lockfile-pinned `ws` development dependency already
installed under `web/node_modules`. It disables redirects and compression,
sets a transport-level maximum payload, requests only the frozen event IDs and
requires every exact event value once plus EOSE on every relay. The publisher
prints one domain-separated event-set digest on every bounded outcome line;
readback requires that exact public digest and recomputes every NIP-01 event ID
before dialing, so a success transcript is bound to the Rust-verified set. Raw relay URLs
must pass the same canonical grammar as the Rust publisher. Artifact inputs
share one 5 MiB limit and must remain the same regular file across a bounded,
non-symlink/nonblocking open and read; FIFO, device, mutation and size races
fail closed. Run it on a local POSIX filesystem; `O_NONBLOCK` is not a
wall-clock bound for a stalled NFS/FUSE regular file. It has no publish path
and never reads a key. Public relay smoke,
production catalog publication and ongoing directory operation remain three
separate states. The hostname grammar is syntactic; use production DNS/egress
controls if relay-name rebinding to private networks is in scope.

## Root-signed quote-key delegation

The online quote signer is Ed25519. The Lightning payee identity is a separate
compressed secp256k1 public key owned by the selected Lightning backend.

```sh
bpir-admin payment-artifact quote-delegation \
  --issuer-root-key issuer-root.key \
  --quote-signing-key quote-online.key \
  --network regtest \
  --expected-payee-pubkey-hex "$PAYEE_COMPRESSED_HEX" \
  --key-epoch 1 \
  --not-before 1700000000 \
  --not-after 1900000000 \
  --out quote-key-delegation-v1.bin
```

Before writing, the command signs `Bolt11QuoteKeyDelegationV1`, decodes the
exact bytes, verifies the issuer/network/payee/epoch/time binding, and checks
that the verified online key is the input quote key. It prints only public IDs
and digests.

## Credential-key bindings

`payment-artifact credential-binding` supports every scheme that uses
`CredentialKeyBindingV1`:

- `free-anonymous-ticket` (open or rate-limited Free does not use a binding);
- `bolt11-direct-receipt`;
- `cashu-bat`;
- `arc-experimental`.

Standard Cashu eCash deliberately does not use this structure; it uses the
strict mint manifest below. The builder derives protocol-mandated key IDs for
anonymous tickets, direct receipts, and BAT. ARC defaults to the canonical
public-key fingerprint, while allowing an explicit bounded ARC key ID. Every
output is encoded, decoded, and verified against the exact issuer,
provider/scope/offer, scheme, epoch, profile, presentation limit, and key ID
before it is written.

```sh
bpir-admin payment-artifact credential-binding \
  --issuer-root-key issuer-root.key \
  --provider-id-hex "$PROVIDER_ID" \
  --scope-id-hex "$SCOPE_ID" \
  --offer-id 24 \
  --scheme cashu-bat \
  --keyset-epoch 1 \
  --entitlement-profile 102 \
  --not-before 1700000000 \
  --not-after 1900000000 \
  --verification-key-hex "$BAT_COMPRESSED_PUBKEY" \
  --out cashu-bat-binding-v1.bin
```

Non-ARC schemes are forced to one presentation. ARC defaults to four and must
remain in `DeploymentStatus::Experimental`; the protocol rejects an ARC limit
below two.

## Strict standard Cashu manifest

The builder accepts strict TOML with unknown fields rejected. It derives each
NUT-02 V2 keyset ID from sorted denomination keys, requires exactly one active
output keyset, requires NUT-03/NUT-07/NUT-09/NUT-12, sorts accepted input
keysets, requires one or two sorted, distinct, nonzero leaf-SPKI SHA-256 pins,
checks expiry horizons, and roundtrips the canonical binary output. Ordinary
WebPKI chain, hostname and validity checks remain mandatory; the pins are an
additional signed identity/rotation restriction, not a CA replacement. The
manifest itself is not a detached signature: its canonical digest and full
bytes are embedded in the provider's signed service policy.
Artifacts generated before the signed pin field are not accepted as a pinless
compatibility mode; regenerate the manifest and re-sign the containing policy.

```toml
manifest_epoch = 1
mint_endpoint = "https://mint.example.org"
leaf_spki_sha256_pins_hex = ["<64 lowercase hex>"]
unit = "sat"
accepted_inputs_valid_through = 1900000000
active_output_valid_through = 1900604800

[[keysets]]
active = true
input_fee_ppk = 0
final_expiry = 1901000000

[[keysets.keys]]
amount = 1
public_key_hex = "02..."

[[keysets.keys]]
amount = 2
public_key_hex = "03..."
```

```sh
bpir-admin payment-artifact cashu-manifest \
  --config cashu-manifest.toml \
  --out standard-cashu-mint-manifest-v1.bin
```

## Shared-issuer clearing authorization and approval

The provider operator and issuer run separate offline ceremonies. The provider
first prepares a strict TOML authorization source. V1 tooling intentionally
constructs only `AuthCredit` plus `LEDGER_CREDIT`; blind settlement and payout
cannot be enabled by adding a TOML field. Unknown fields fail closed.

```toml
authorization_id_hex = "<32 lowercase hex>"
authorization_epoch = 1
provider_id_hex = "<64 lowercase hex>"
issuer_id_hex = "<64 lowercase hex>"
redeem_endpoint = "https://issuer.example"
redeem_leaf_spki_sha256_pins_hex = ["<64 lowercase hex>"]
settlement_account_id_hex = "<64 lowercase hex>"
clearing_verifying_key_hex = "<64 lowercase hex>"
not_before = 1700000000
not_after = 1900000000

[[rules]]
credential_binding_digest_hex = "<64 lowercase hex>"
accepted_value = 10
provider_credit = 9
issuer_fee = 1
denomination_profile = 1
```

```sh
bpir-admin payment-artifact clearing-authorization \
  --operator-signing-key provider-operator.key \
  --config clearing-authorization.toml \
  --out provider-clearing-authorization.bin
```

The builder checks value conservation, canonical endpoint and pins, unique
binding digests, validity, exact roundtrip and operator signature before it
writes. It rejects reuse of the operator key as the online clearing key. Record
the printed `authorization_digest` through an independent channel before the
issuer ceremony.

```sh
bpir-admin payment-artifact clearing-approval \
  --authorization provider-clearing-authorization.bin \
  --issuer-settlement-signing-key issuer-settlement.key \
  --expected-authorization-digest-hex "$AUTHORIZATION_DIGEST" \
  --expected-provider-id-hex "$PROVIDER_ID" \
  --expected-issuer-id-hex "$ISSUER_ID" \
  --expected-operator-key-hex "$PROVIDER_OPERATOR_PUBLIC_KEY" \
  --minimum-authorization-epoch 1 \
  --approved-at 1700000000 \
  --not-after 1900000000 \
  --out provider-clearing-approval.bin
```

The issuer command verifies all out-of-band expectations and the exact digest
before signing. It rejects settlement-key reuse with either provider key, then
decodes and verifies its own canonical approval before writing. Rotation uses
a strictly higher authorization epoch and a new approval; an approval cannot
be replaced under the same authorization digest in the durable issuer store.

Provision a fourth, distinct public key beside the two artifacts:

```sh
# `service-keygen` prints this public key while retaining the provider secret.
bpir-admin service-keygen \
  --role provider-request-ed25519 \
  --out provider-request.key
```

Install only its raw 32-byte public half at the issuer and pass it once per
matching authorization with
`--clearing-provider-request-verifying-key`. The clearing key signs redemption
and balance requests. The provider-request key is reserved for payout recovery
and status; ledger-only mode does not use it, but production registration still
keeps the domains distinct so a future payout client cannot inherit a
same-key registration. Provider code that only reads the identified ledger can
use `ProviderLedgerBalanceClientV1`; it validates the authorization, approval,
epoch floor, current/retained issuer settlement keys, canonical signed response
and exact nonce without inventing a payout registration or target.

## Provider store initialization

`unified_server` opens existing state only. Production uses the shared
owner-only remote-authority config from
`REMOTE_ROLLBACK_AUTHORITY.toml.example`; generate and preserve a public,
nonzero 16-byte store-instance ID before the first network attempt:

```sh
install -d -m 0700 /srv/bitcoinpir/provider-state

bpir-admin service-store-init \
  --provider-id-hex "$PROVIDER_ID" \
  --store /srv/bitcoinpir/provider-state/admission.sqlite3 \
  --remote-rollback-authority-config /private/provider/remote-authority.toml \
  --store-instance-id-hex "$STORE_INSTANCE_ID"
```

The remote config, its two distinct secret files, provider ID, WebPKI identity,
leaf-SPKI pins, authority key, client key, derived authority client-key ID,
namespace and timeouts are checked by the shared fail-closed loader. Every raw
32-byte secret and public role binding must be distinct. Initialization creates
the provider store only after
the remote authority accepts the exact generation-zero floor, then reloads the
config and reopens through a fresh authenticated Read. If the response or a
later local step fails, the remote CAS may already be committed: retain the
same config and store-instance ID and audit/resume that exact ceremony. Never
reset/lower the authority or hide ambiguity by choosing another ID.

The old local SQLite floor remains available only for isolated development,
tests and restore drills. Local mode rejects `--store-instance-id-hex` and
generates a fresh random ID:

```sh
install -d -m 0700 /mnt/local-test-floor/bitcoinpir

bpir-admin service-store-init \
  --provider-id-hex "$PROVIDER_ID" \
  --store /srv/bitcoinpir/provider-state/admission.sqlite3 \
  --rollback-authority /mnt/local-test-floor/bitcoinpir/floor.sqlite3
```

Different local filenames or directories do not establish an independent
production failure/administrative domain. Every admin command emits a warning
when this compatibility mode is selected. Public serving additionally requires
`--allow-local-service-rollback-authority-dev`; remote mode rejects that flag.

Initialization is intentionally not an overwrite or adoption operation. If
authority creation succeeds but provider-store creation fails, treat both
paths as an incomplete, unusable ceremony. Inspect them, then manually remove
only files proven to have been created by that failed attempt before rerunning.
The CLI never automatically deletes ambiguous state.

Validate an existing provider store and independent rollback authority without
starting a listener:

```sh
bpir-admin service-store-check \
  --provider-id-hex "$PROVIDER_ID" \
  --store /srv/bitcoinpir/provider-state/admission.sqlite3 \
  --remote-rollback-authority-config /private/provider/remote-authority.toml
```

The command uses the serving-equivalent `open_existing` path and prints only
identity, generation, aggregate row counts and `startup_check_ms`. An exact
store/authority match is read-only; exactly one legitimate unanchored
successor may complete its idempotent authority CAS, as at real startup. Every
Cashu-custody subcommand accepts the same exact-one local/remote choice. See
`STAGING_STORE_DRILL.md` for the no-funds backup/restore and SLO procedure.

## Standard Cashu custody and export

The online provider uses two independent owner-only AEAD keyrings: one for
NUT-03/NUT-09 recovery material and another for received-note custody. Configure
an exact finite exposure cap for every accepted mint/unit; do not reuse either
keyring across providers. Inspect the exact server options with:

```sh
cargo run --offline -p runtime --bin unified_server -- --help
```

The standard-Cashu portion of each provider's serving configuration has this
shape (paths and caps are operator-specific):

```sh
--service-cashu-recovery-key 1=/private/provider-0/cashu-recovery-1.key \
--service-cashu-recovery-active-epoch 1 \
--service-cashu-custody-key 1=/private/provider-0/cashu-custody-1.key \
--service-cashu-custody-active-epoch 1 \
--service-cashu-exposure-limit "$MINT_ID:sat:100000:512"
```

Repeat a key option to retain old epochs during rotation. The same epoch
number in the two domains is allowed, but the raw key bytes must differ. Every
configured cap must correspond to the exact current policy manifest, and every
referenced manifest must have exactly one cap; unused or missing entries fail
startup. The three checked-in provider deployment profiles are zero-retained.
In a future, separately reviewed retention-capable profile, the same one-cap
rule would also apply to each retained policy manifest.

Offline custody operations are grouped under:

```sh
bpir-admin cashu-custody --help
bpir-admin cashu-custody recipient-keygen --help
bpir-admin cashu-custody inventory --help
bpir-admin cashu-custody export-prepare --help
bpir-admin cashu-custody export-replay --help
bpir-admin cashu-custody decrypt --help
bpir-admin cashu-custody acknowledge --help
bpir-admin cashu-custody spent-confirm --help
```

Generate one distinct provider-bound recipient keypair on the external-wallet
side. Move only its public artifact to the provider operator. `export-prepare`
requires an explicit nonzero export ID, exact mint/unit, maximum lot count,
that provider-bound public artifact and every historical online custody-key
epoch needed to decrypt selected lots. It atomically reserves at most 512
notes/16 keyset groups, constructs a canonical no-memo/no-DLEQ `cashuB`, seals
it to the recipient and persists the exact envelope before writing `--out`.

If output delivery is lost, use `export-replay`; never invent a new export ID
for the same reserved notes. On the recipient workstation, `decrypt` writes an
owner-only `cashuB` file and never prints the bearer token. Import and secure
that token in the chosen wallet before acknowledgement. `acknowledge` requires
the exact artifact digest and the long, explicit
`--confirm-external-wallet-took-custody-not-settlement` flag. ACK records only
external-wallet custody: it does **not** release local exposure and does not
assert NUT-05, Lightning settlement or provider payout.

Release exposure later with one explicit, operator-initiated NUT-07 check:

```sh
bpir-admin cashu-custody spent-confirm \
  --provider-id-hex "$PROVIDER_ID" \
  --store /srv/bitcoinpir/provider-state/admission.sqlite3 \
  --remote-rollback-authority-config /private/provider/remote-authority.toml \
  --export-id-hex "$EXPORT_ID_1" \
  --export-id-hex "$EXPORT_ID_2" \
  --custody-key "1=/private/provider-0/cashu-custody-1.key" \
  --confirm-nut07-old-notes-spent-not-settlement-or-payout
```

Every selected nonterminal export must already be delivery-acknowledged and
must resolve to the same canonical mint endpoint and unit. Repeated export IDs
are checked in one bounded strict-HTTPS request; there is no `curl`, redirect,
ambient proxy credential, polling or automatic retry. The response must contain
the same ordered `Y` values and one canonical state for every note, and every
state must be `SPENT` before any retirement write begins. Each export then uses
a fresh current rollback-floor snapshot and its own observation digest, so the
wider HTTP-batch digest is never stored as a cross-export link.

If a later per-export commit fails after an earlier one committed, the command
reports the exact position and stops. Rerun the same export-ID selection
explicitly: terminal exports replay without contacting the mint or loading
custody keys, while remaining acknowledged exports are checked once again.
NUT-07 proves only that these old notes are spent; it does not prove settlement
or payout. Schedule it independently of PIR queries because state checks can
otherwise strengthen sender/receiver timing correlation. Store only aggregate
inventory/IDs/digests in the ceremony record—no token, note secret, raw `Y`,
witness, recovery ciphertext or query identifier.

## Deterministic no-funds fixture

Generate the full local integration fixture with either command:

```sh
scripts/fixtures/generate-payment-v1-no-funds.sh /tmp/bpir-payment-v1-fixture

# equivalent
cargo run --locked --offline -p bpir-admin -- \
  payment-v1-no-funds-fixture \
  --acknowledge-deterministic-test-keys \
  --out /tmp/bpir-payment-v1-fixture
```

The fixture is byte-for-byte deterministic and contains:

- two cryptographically independent providers, issuer roots, quote keys,
  fake-regtest payees, policy keys, mint keys, BAT keys, and ARC keys;
- independent fake-Lightning signing and derivation secrets for offline/local
  issuer tests (still no listener is started by the generator);
- all five workloads: DPF evaluate, Harmony hint, Harmony query, Onion
  evaluate, and TEE-ORAM query;
- all five accepted methods on every workload: Free, direct BOLT11 receipt,
  standard Cashu eCash, Cashu BAT, and experimental ARC;
- workload-specific prices and limits, including the larger Harmony hint
  budget;
- canonical quote delegations, credential bindings, Cashu manifests, and
  signed service policies;
- an inventory at `fixture.json` with `funds_capable: false` and relative paths.

Every fixture secret is a publicly known deterministic test vector. Never
connect it to a real Lightning node, put funds behind it, deploy it, or use it
with production data. `--force` overwrites only known fixture paths and never
removes unrelated files.
