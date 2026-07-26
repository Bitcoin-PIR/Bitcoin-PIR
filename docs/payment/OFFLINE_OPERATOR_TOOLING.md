# Payment V1 offline operator tooling

`bpir-admin` provides offline builders for Payment V1 keys, signed protocol
artifacts, provider persistence, and a deterministic integration fixture. None
of these commands starts a listener, talks to a Lightning node, creates an
invoice, or moves funds.

Production deployment, remote-server operations, and real Lightning funds are
separate ceremonies and are not authorized by running these commands.

## Secret keys

Generate one role per file. The CLI never prints secret bytes. On Unix it
creates or rewrites only regular files owned by the effective user and sets
mode `0600`; symlinks fail closed.

```sh
bpir-admin service-keygen --role issuer-root-ed25519 --out issuer-root.key
bpir-admin service-keygen --role quote-ed25519 --out quote-online.key
bpir-admin service-keygen --role bip340-claim --out claim-test.key
bpir-admin service-keygen --role credential-derivation --out credential-derivation.key
bpir-admin service-keygen --role redeem-derivation --out redeem-derivation.key
bpir-admin service-keygen --role receipt-ed25519 --out receipt.key
bpir-admin service-keygen --role cashu-bat --out bat.key
bpir-admin service-keygen --role cashu-ecash --out cashu-denomination.key
bpir-admin service-keygen --role arc-experimental --out arc.key
```

Other supported roles are `policy-ed25519`, `anonymous-ticket-ed25519`,
`clearing-ed25519`, and `directory-nostr`. Do not reuse one raw key across
roles, providers, BAT offers, or ARC lineages. `bip340-claim` is normally
browser-generated; the operator command exists for isolated tests and recovery
fixtures, not as a recommendation to centralize browser claim keys.

ARC uses a 128-byte four-scalar key and remains experimental pending an
independent cryptographic review.

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
keysets, checks expiry horizons, and roundtrips the canonical binary output.
The manifest itself is not a detached signature: its canonical digest and full
bytes are embedded in the provider's signed service policy.

```toml
manifest_epoch = 1
mint_endpoint = "https://mint.example.org"
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

## Provider store initialization

`unified_server` opens existing state only. Create the provider-local store and
its rollback-floor authority explicitly before first startup:

```sh
install -d -m 0700 /srv/bitcoinpir/provider-state
install -d -m 0700 /mnt/independent-floor/bitcoinpir

bpir-admin service-store-init \
  --provider-id-hex "$PROVIDER_ID" \
  --store /srv/bitcoinpir/provider-state/admission.sqlite3 \
  --rollback-authority /mnt/independent-floor/bitcoinpir/floor.sqlite3
```

Both paths must be absent, must differ after canonicalizing their parents, and
their parent directories must be owned by the effective user with no
group/world permissions. The command creates the rollback authority, creates
the provider store with a random nonzero store-instance ID (or an explicit
16-byte `--store-instance-id-hex`), sets both database files to `0600`, then
reopens both through the same checked APIs used at startup.

The two files should be in different backup/restore and rollback domains;
different filenames alone do not provide rollback protection. A same-directory
configuration emits a warning but is useful for isolated local tests.

Initialization is intentionally not an overwrite or adoption operation. If
authority creation succeeds but provider-store creation fails, treat both
paths as an incomplete, unusable ceremony. Inspect them, then manually remove
only files proven to have been created by that failed attempt before rerunning.
The CLI never automatically deletes ambiguous state.

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
