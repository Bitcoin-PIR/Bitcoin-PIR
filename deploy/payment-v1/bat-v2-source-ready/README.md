# BAT V2 offline artifact source templates

These strict TOML templates are inert inputs for the offline `bpir-admin`
builders. They do not contain keys, do not render a production service, and do
not authorize deployment, publication, Lightning use, or funds.

The safe construction order is:

1. preallocate one nonzero 32-byte class ID;
2. render and sign the exact pir1 and pir2 provider policies with
   `authorization = "cashu-bat-v2"`, `key_id_hex = <class-id>`, and no
   `credential_binding_path`;
3. generate one fresh owner-only BAT scalar with
   `bpir-admin service-keygen --role cashu-bat`;
4. fill `bat-v2-class.toml.in`, then run
   `bpir-admin payment-artifact bat-v2-class --issuer-root-key ... --bat-key ...`;
5. fill one copy of `provider-accounting-authorization.toml.in` for each
   provider, then run `bat-v2-accounting-authorization`; and
6. independently countersign each exact authorization with
   `bat-v2-accounting-approval`, supplying its printed authorization digest.

Every referenced policy/class path is resolved relative to its TOML file. The
builders bounded-read canonical signed bytes, verify all signatures and exact
digests, project class members from the signed policies, and write only after
self-verification. An acceptance class derives its public key from the supplied
private BAT scalar; the public key cannot be substituted in the TOML.

The old `db1-free-pow-bat` templates still contain provider-bound V1 bindings.
They are not BAT V2 render inputs and must not be completed or deployed as the
issuer-wide product. Versioned issuer/pir1/pir2 render profiles and the public
class catalog are separate source slices.

## Versioned source profile

`source-profile.json.in` is the closed public render contract for the issuer,
pir1, and pir2. It deliberately requires one current and at least one retained
signed policy/class epoch for each provider. This is a source-ready rotation
continuity contract, not permission to fabricate history: retained entries
must be real, previously issued canonical artifacts. A deployment with no real
retained epoch stays blocked until a new profile version explicitly permits it.

The schema accepts at most eight retained policies per provider and eight
retained classes. Every pir2 retained artifact has its own digest-derived
immutable runtime path and file SHA-256; the canonical artifact-set file is
itself SHA-256-bound into the current-boot Ready-preflight attempt token. Both
Ready invocations repeat the exact retained-policy and class arguments. The
existing Rust loaders remain authoritative for canonical decoding, signatures,
member coverage, class forks, unused classes, and role-key separation.

`pir1-storeless-bat-v2-provider.service.in` is the only profile that names a
plaintext clearing seed. The measured pir2 run path accepts only the sealed
Ready key injection and rejects plaintext/V1 clearing fallbacks. The issuer
unit registers current/retained public policy and class sets plus exactly one
current accounting triple per provider; it creates no retained-accounting
runtime.

Run the browserless source gate with:

```sh
node scripts/payment-bat-v2-source-profile-gate.mjs
node --test scripts/payment-bat-v2-source-profile-gate.test.mjs
```

These templates remain inert: rendering, private materialization, UKI builds,
VPSBG operations, installation, activation, Lightning use, and funds need
their own approval.
