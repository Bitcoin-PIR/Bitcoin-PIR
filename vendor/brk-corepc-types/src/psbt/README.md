# PSBT

A bunch of types and conversion code for supporting PSBTs (and
possibly raw transactions). This stuff could have been in one of the
`raw_transaction` modules but reaching into `v17` from, for example,
`v23::raw_transaction` doesn't seem right.

Note that because PSBT was designed to be backwards compatible this
stuff should work with all versions.
