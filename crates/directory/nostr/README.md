# pir-directory-nostr

Transport-free codec and anti-rollback state machine for the BitcoinPIR
service directory published over Nostr (NIP-01 / NIP-78, kind 30078).

The protocol is specified in
[`docs/DIRECTORY_PROTOCOL.md`](../../../docs/DIRECTORY_PROTOCOL.md). This
crate owns:

- the strict NIP-01 event parser and BIP340 verifier (`event`);
- the provider entry and tombstone content (`entry`), including the inner
  Ed25519 **operator assertion** that binds endpoints to an operator key and
  a stable server id (`assertion`);
- the per-shard catalog checkpoints (`checkpoint`);
- the publisher-side signing helpers and `REQ` filters (`publisher`);
- the durable compare-and-swap rollback state and the live identity binding
  (`state`).

Directory output is candidate metadata only. It never establishes runtime,
database, access-policy, payment, or two-provider independence trust: the
client still runs the full live verification (REQ_ANNOUNCE identity, binary
or SEV pin, secure channel, database proof) against every discovered
provider.

The crate performs no network or storage I/O and owns no randomness
boundary; callers supply relay bytes, a `DirectoryRollbackStoreV1`
implementation and BIP340 auxiliary randomness.
