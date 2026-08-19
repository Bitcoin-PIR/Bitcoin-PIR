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
