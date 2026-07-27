# Lightning staging strategy

Status: deployment design as of 2026-07-27. This document does not authorize
mainnet funds or remote production changes.

## Decision

Payment V1 uses three complementary Lightning test boundaries:

1. **Disposable local regtest** is the deterministic CI and fault-injection
   baseline. It covers two real Core Lightning processes, a real local channel,
   BOLT11 payment, issuer settlement observation and browser recovery without
   accounts, remote infrastructure or valuable coins.
2. **Mutinynet** is an optional external interoperability smoke. Its public
   faucet can fund, pay an invoice or open a channel. The separately documented
   Voltage-hosted path uses LND and can provide a deliberate CLN-to-LND check;
   this runbook does not assume an implementation for the public faucet node.
   Mutinynet is a centrally operated custom signet using an experimental
   Bitcoin fork, so it is not the long-lived staging trust anchor.
3. **Bitcoin default signet with three self-controlled CLN nodes** is the
   preferred long-lived staging topology:

   ```text
   payer  --channel-->  router  --channel-->  issuer
   ```

   Two direct, controlled channels remove any dependency on an undocumented
   public signet routing graph while still exercising multi-hop BOLT11,
   confirmations, cross-host transport, node restart and the issuer's checked
   Unix-socket adapter. In V1 both channels must use `announce=true`: the CLN
   invoice adapter fixes `exposeprivatechannels=false` and therefore supplies
   no private-channel route hint. Wait for the required announcement depth and
   confirm that payer gossip includes `router -> issuer` before testing two-hop
   payment. Announced channels expose the three test node identities, topology
   and capacity, so use staging-only identities that will never be reused.

Payment V1 intentionally supports only the frozen `bitcoin`, `testnet`,
`signet` and `regtest` network discriminants. Core Lightning now has a distinct
`testnet4` network identifier, so treating it as the existing `testnet` value
would fail the issuer's exact node-network check. Testnet4 is therefore not a
V1 staging option. Adding it would require separating BOLT11 currency from
exact chain identity in a versioned protocol/schema change, followed by
Rust/WASM/Web/store/formal-lock migration; it cannot be an operator alias. This
is also the conservative operational choice: draft BIP95 (2026-06-22) proposes
Testnet5 as a replacement after sustained Testnet4 difficulty-exception
exploitation made that network hard to use. Testnet3 likewise must not be used
for a new deployment.

## Network identity must be explicit

BOLT11 human-readable prefixes are `lnbc` for mainnet, `lntb` for Bitcoin
testnet, `lntbs` for signet and `lnbcrt` for regtest. Multiple test networks can
share a prefix; default signet and custom signets both use `lntbs`. An invoice
prefix is therefore not sufficient network evidence.

The current `serve-cln` adapter verifies the configured coarse network name,
the exact `lightning-cli getinfo` payee identity, signed quote-delegation
network/payee bindings and decoded BOLT11 currency/payee. It cannot distinguish
default signet from a custom signet: both CLN and BOLT11 report `signet` /
`lntbs`. The deployment wrapper must additionally verify Bitcoin Core's chain,
the default-signet challenge and the approved peer/bootstrap configuration.
Those external default-challenge checks are a staging gate and are not
currently performed by the issuer executable.

Every staging startup must fail closed unless all of the following agree:

- the configured Bitcoin network;
- the Bitcoin node's reported chain;
- `lightning-cli getinfo`'s exact network;
- the signed quote delegation's network and pinned Lightning payee key; and
- the decoded BOLT11 currency and payee.

Mutinynet additionally requires its exact signet challenge, Bitcoin peer set
and Lightning peers to be pinned. A generic `--network=signet` is not proof
that the node joined Mutinynet.

The CLN adapter's timeout is one process-local monotonic budget covering
socket metadata validation, connect, complete request write and complete
response read. Filesystem metadata calls cannot be force-cancelled by that
budget. Keep `lightning-rpc` and every checked parent on a protected local
Unix/POSIX filesystem; NFS/FUSE stalls, a writable parent, another process
under the same UID and root compromise are operator trust-boundary failures.
UID/mode/device/inode checks harden local routing but are not cryptographic CLN
peer authentication. After any application byte is written, timeout, EOF,
oversize, framing or JSON failure is outcome-unknown and recovery must use the
same durable label/request rather than a new idempotency identity.

## Wallet and channel custody

BitcoinPIR does not need a hosted wallet account. Each persistent staging node
must create its own CLN identity under a dedicated OS user on the final staging
host. Test and future production node identities must never be reused.

Before opening a persistent channel, operators must accept and rehearse:

- one offline backup of the node's `hsm_secret` or configured signer seed;
- an updated `emergency.recover` after channel changes;
- supported live CLN database replication appropriate to the selected
  datastore/plugin, or a file backup taken only while `lightningd` is stopped;
- separate custody for any HSM-secret encryption passphrase; and
- restore/failover without reverting channel state.

Never copy a running CLN SQLite file as a backup. A stale or inconsistent
channel database can lose test funds and makes a production rehearsal invalid.

Do not generate a production-mainnet node identity until the production host,
signer/HSM boundary, backup domain and real-funds ceremony are separately
approved.

## External test inputs

Local regtest needs no user account or faucet.

For a Mutinynet smoke, use its free GitHub device-OAuth path. Do not use its
L402 option because that spends real mainnet sats. Treat the faucet as a
correlation boundary: it can observe the GitHub identity, IP, node public key,
invoice and timing. Use only disposable identities and synthetic Payment V1
scopes.

For default-signet staging, first create payer, router and issuer addresses on
the approved staging hosts. A practical initial allocation is about 150,000
signet sats each for payer and router. Each funds its roughly 100,000-sat
outbound channel, the pinned CLN version's default 10,000-sat minimum effective
capacity, emergency reserve and fees. An additional 50,000 issuer sats is
optional on-chain closing/recovery-test margin; receiving the two-hop payment
does not require it and it does not create reverse Lightning liquidity. Thus
about 350,000 sats is practical and 500,000 sats is a comfortable upper budget,
not a promise that a faucet will provide that amount. Test invoices should
remain 1--100 sats. Faucet requests must target fresh staging node addresses;
never import faucet-facing keys into a production-mainnet node.

No real query address, result, payer identity or production capability may be
used in any public-test-network experiment.

## Acceptance sequence

1. Keep `scripts/payment-v1-cln-regtest-e2e.sh` green as a local release gate.
2. On an approved disposable public host, perform one Mutinynet CLN-to-LND
   invoice/payment/status/restart smoke using only test identities.
3. Build the three-node default-signet topology with two staging-only announced
   channels, verify gossip propagation, then verify one- and two-hop payments,
   lost HTTP response recovery, issuer restart, CLN restart, channel outage,
   expiry and exact-price rejection.
4. Test and record the two distinct privacy lanes. For BAT/experimental-ARC and
   other anonymous issuer lanes, the PIR provider must not receive an invoice,
   payment hash, preimage or payer identity. For direct receipt, the PIR query
   wire carries only the signed receipt, but the provider-operated payment
   service intentionally can link invoice to receipt serial; the UI and policy
   must label that method `DIRECT_PAYMENT_TO_SPEND`.
5. A tightly capped mainnet canary remains a separate approval after staging;
   public test networks cannot prove production wallet coverage or routing.

## Primary references

- [Core Lightning configuration and networks](https://docs.corelightning.org/docs/configuration)
- [Core Lightning local regtest example](https://github.com/ElementsProject/lightning)
- [Core Lightning chain parameters](https://github.com/ElementsProject/lightning/blob/master/bitcoin/chainparams.c)
- [BOLT11 payment encoding](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)
- [BIP94: Testnet4](https://github.com/bitcoin/bips/blob/master/bip-0094.mediawiki)
- [Draft BIP95: proposed Testnet5 replacement](https://github.com/bitcoin/bips/blob/master/bip-0095.md)
- [BIP325: signet](https://github.com/bitcoin/bips/blob/master/bip-0325.mediawiki)
- [Mutinynet faucet API and limits](https://faucet.mutinynet.com/llms.txt)
- [Mutinynet Bitcoin fork releases](https://github.com/benthecarman/bitcoin/releases)
- [Voltage Mutinynet LND environment](https://docs.voltage.cloud/dev-sandbox-mutinynet)
- [Core Lightning backup guidance](https://docs.corelightning.org/docs/backup)
