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
   faucet can fund, pay an invoice or open a channel, and its Lightning side is
   operated with LND. This is useful for a CLN-to-LND check, but Mutinynet is a
   centrally operated custom signet using an experimental Bitcoin fork. It is
   not the long-lived staging trust anchor.
3. **Bitcoin Testnet4 with three self-controlled CLN nodes** is the preferred
   long-lived staging topology:

   ```text
   payer  --channel-->  router  --channel-->  issuer
   ```

   Two direct, controlled channels remove any dependency on an undocumented
   public testnet routing graph while still exercising multi-hop BOLT11,
   confirmations, cross-host transport, node restart and the issuer's checked
   Unix-socket adapter.

Default signet is a fallback if Testnet4 operations prove unsuitable. Testnet3
must not be used for a new deployment; it is deprecated in favor of Testnet4.

## Network identity must be explicit

BOLT11 human-readable prefixes are `lnbc` for mainnet, `lntb` for Bitcoin
testnet, `lntbs` for signet and `lnbcrt` for regtest. Testnet3 and Testnet4 both
use `lntb`; default signet and custom signets also share `lntbs`. An invoice
prefix is therefore not sufficient network evidence.

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
- continuous, consistent CLN database backup appropriate to the selected
  datastore/plugin; and
- restore/failover without reverting channel state.

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

For Testnet4 staging, first create payer and router addresses on the approved
staging hosts. A practical initial request is about 150,000 testnet4 sats for
each of those two nodes (about 300,000 total), sufficient for two roughly
100,000-sat channels plus mining fees. Smaller 60,000--100,000-sat allocations
can work if faucet limits require them; test invoices should remain 1--100 sats.

No real query address, result, payer identity or production capability may be
used in any public-test-network experiment.

## Acceptance sequence

1. Keep `scripts/payment-v1-cln-regtest-e2e.sh` green as a local release gate.
2. On an approved disposable public host, perform one Mutinynet CLN-to-LND
   invoice/payment/status/restart smoke using only test identities.
3. Build the three-node Testnet4 topology and verify one- and two-hop payments,
   lost HTTP response recovery, issuer restart, CLN restart, channel outage,
   expiry and exact-price rejection.
4. Run the browser/issuer/two-provider staging flow while PIR providers see
   only anonymous credentials or provider-local receipts, never invoice,
   payment hash, preimage or payer data.
5. A tightly capped mainnet canary remains a separate approval after staging;
   public test networks cannot prove production wallet coverage or routing.

## Primary references

- [Core Lightning configuration and networks](https://docs.corelightning.org/docs/configuration)
- [Core Lightning local regtest example](https://github.com/ElementsProject/lightning)
- [Core Lightning chain parameters](https://github.com/ElementsProject/lightning/blob/master/bitcoin/chainparams.c)
- [BOLT11 payment encoding](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)
- [BIP94: Testnet4](https://github.com/bitcoin/bips/blob/master/bip-0094.mediawiki)
- [BIP325: signet](https://github.com/bitcoin/bips/blob/master/bip-0325.mediawiki)
- [Mutinynet faucet API and limits](https://faucet.mutinynet.com/llms.txt)
- [Mutinynet Bitcoin fork releases](https://github.com/benthecarman/bitcoin/releases)
- [Core Lightning backup guidance](https://docs.corelightning.org/docs/backup)
