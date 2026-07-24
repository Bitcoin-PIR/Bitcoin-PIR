# Root bundle compatibility policy

`rootbundle` is a wire-format and trust-boundary crate. Changes to its
canonical payload, signing preimage, decoder, or quorum semantics require:

1. updating the checked-in vectors under `testdata/` with the
   `golden_vector` example;
2. explaining why existing production bundle bytes remain accepted, or
   introducing a new explicitly versioned format and signing domain;
3. passing both the rootbundle compatibility job and the complete workspace
   test job; and
4. cutting a protected `rootbundle-vMAJOR.MINOR.PATCH` tag before downstream
   consumers move their exact git revision.

The seeds used by the golden vector are public test constants. They are not
builder credentials. Downstream compatibility tests should verify the exact
payload and signed-bundle hex from this directory before removing any local
copy of the implementation.
