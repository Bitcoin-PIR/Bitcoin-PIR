# Plan: Anonymous Rate Limiting for BitcoinPIR Web Frontend

## Summary

Integrate ARC (Anonymous Rate-limited Credentials) and Cashu Blind Auth
(NUT-22) as two alternative anonymous rate-limiting mechanisms into the
BitcoinPIR web frontend and SDK. Both sit at the transport/protocol
layer — verified before any PIR handler runs — so they work with all
three PIR backends (DPF, HarmonyPIR, OnionPIR) without protocol changes.

---

## Architecture overview

```
┌─────────────────────────────────────────────────┐
│  Browser                                         │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │DPF       │  │HarmonyPIR│  │OnionPIR       │  │
│  │Adapter   │  │Adapter   │  │Client (TS)    │  │
│  └────┬─────┘  └────┬─────┘  └───────┬───────┘  │
│       │              │               │           │
│  ┌────┴──────────────┴───────────────┴───────┐   │
│  │  CredentialManager                        │   │
│  │  - ARC: issuance state + nonce counter     │   │
│  │  - Cashu: BAT pool + minting              │   │
│  └────────────────────┬──────────────────────┘   │
│                       │                          │
│  ┌────────────────────┴──────────────────────┐   │
│  │  ManagedWebSocket (ws.ts)                 │   │
│  │  - sendRaw() wraps credential in header   │   │
│  └────────────────────┬──────────────────────┘   │
└───────────────────────┼──────────────────────────┘
                        │  WebSocket
┌───────────────────────┼──────────────────────────┐
│  Server (unified_server)                         │
│  ┌────────────────────┴──────────────────────┐   │
│  │  CredentialVerifier (new handler)         │   │
│  │  - ARC: verify presentation, track tags   │   │
│  │  - Cashu: verify BAT, track spent secrets │   │
│  │  - If invalid → close connection           │   │
│  └────────────────────┬──────────────────────┘   │
│                       │                          │
│  ┌────────────────────┴──────────────────────┐   │
│  │  Existing PIR handlers (DPF/Harmony/      │   │
│  │  OnionPIR) — unchanged                    │   │
│  └───────────────────────────────────────────┘   │
└──────────────────────────────────────────────────┘
```

Two new protocol opcodes:
- `REQ_CREDENTIAL_ISSUE` (0x07) — client requests a credential (ARC) or
  blind-signed BATs (Cashu)
- `REQ_CREDENTIAL_PRESENT` (0x08) — client presents a credential /
  BAT with each PIR query batch

---

## Phase 1: ARC integration

### 1a. Rust crate: `pir-arc-client`

New crate at `pir-arc-client/` (or a module in `pir-sdk-client` behind a
feature flag). Wraps the `arc` crate (already owned by Bitcoin-PIR org).

```
pir-arc-client/
  Cargo.toml           → depends on arc (git), rand, serde
  src/
    lib.rs             → re-exports
    issuance.rs        → create_credential_request, finalize_credential
    presentation.rs    → present (nonce → presentation), track nonce state
    types.rs           → ArcCredential, ArcPresentation, serialization
```

**Key types:**

```rust
struct ArcCredential {
    inner: arc::Credential,          // opaque from the arc crate
    limit: u64,
    nonce: u64,
}

struct ArcPresentation {
    nonce: u64,
    payload: Vec<u8>,                // serialized arc::Presentation
    tag: [u8; 32],                   // deterministic tag for server-side dedup
}

fn request_issuance(rng: &mut impl Rng, request_ctx: &[u8]) -> (Vec<u8>, ArcIssuanceState);
fn finalize_credential(state: ArcIssuanceState, response: &[u8]) -> Result<ArcCredential>;
fn present(cred: &mut ArcCredential, pres_ctx: &[u8]) -> Result<ArcPresentation>;
```

### 1b. Server-side ARC verifier

New module in `pir-runtime-core` (or a separate crate):

```
pir-runtime-core/src/
  arc_verifier.rs      → ArcVerifier struct, tag dedup, issuance handling
```

**Key types:**

```rust
struct ArcVerifier {
    server_key: arc::ServerKey,         // long-lived MAC signing key
    seen_tags: HashMap<[u8; 32], u64>,  // tag → expiry timestamp, pruned periodically
    max_presentations: u64,             // default limit for new credentials
}

impl ArcVerifier {
    fn handle_issue(&self, request: &[u8], auth_token: &[u8]) -> Result<Vec<u8>>;
    fn verify_presentation(&mut self, presentation: &[u8], pres_ctx: &[u8]) -> Result<()>;
}
```

`handle_issue` accepts a blinded credential request. The `auth_token`
parameter is an out-of-band authorization proof (e.g., a paid invoice
hash, a CAPTCHA solution, a one-time invite code). The verifier checks
this before signing — the specific policy is pluggable.

### 1c. Wire protocol

Two new request types in `pir-runtime-core/src/protocol.rs`:

```rust
pub const REQ_CREDENTIAL_ISSUE: u8 = 0x07;
pub const REQ_CREDENTIAL_PRESENT: u8 = 0x08;
```

**Issuance flow (one-time per session):**
```
Client → Server:  [4B len][0x07][auth_method: u8][auth_payload_len: u16][auth_payload][blinded_request]
Server → Client:  [4B len][0x07][limit: u8][blinded_response]
```

`auth_method` identifies the out-of-band auth: `0x01` = pre-shared token,
`0x02` = payment hash, `0x03` = CAPTCHA proof. Extensible.

**Presentation flow (every PIR query batch):**
```
Client → Server:  [4B len][0x08][pres_ctx_len: u8][pres_ctx][presentation_payload]
Server → Client:  [4B len][0x08][status: u8]
                                                       │
                                         0x00 = valid ─┤ 0x01 = exhausted
                                                        0x02 = invalid
                                                        0x03 = duplicate tag
```

`pres_ctx` is an epoch or connection identifier (e.g., the 32-byte
session key established during attestation). This scopes the tag
uniqueness check so that reconnecting with a fresh session resets the
tag namespace.

### 1d. Client-side integration (web frontend)

**New file: `web/src/credential-manager.ts`**

```typescript
interface CredentialManager {
  readonly remaining: number;
  initialize(): Promise<void>;           // issue or restore from localStorage
  present(): Promise<Uint8Array>;        // produce presentation bytes for REQ_CREDENTIAL_PRESENT
  persist(): void;                       // save state to localStorage
}

class ArcCredentialManager implements CredentialManager {
  private credential: ArcCredential | null;
  private presCtx: Uint8Array;           // session key from attestation

  async initialize(authToken: Uint8Array): Promise<void> { ... }
  async present(): Promise<Uint8Array> { ... }
  get remaining(): number { ... }
  persist(): void { ... }
}
```

**Modified: `web/src/ws.ts` — `ManagedWebSocket`**

Add an optional `credentialManager?: CredentialManager` to
`ManagedWsConfig`. Before each `sendRaw()`, if a credential manager is
configured, prepend a `REQ_CREDENTIAL_PRESENT` frame. The server
processes it and either responds `0x00` (proceed) or disconnects.

Alternative (simpler for MVP): leave `ManagedWebSocket` untouched and
instead add a wrapper in each adapter that calls
`credentialManager.present()` before each query batch and passes the
presentation bytes alongside the PIR payload. The server processes
`0x08` first, then falls through to the PIR handler.

**Recommendation:** use the wrapper-in-adapter approach for MVP. It
requires no changes to `ManagedWebSocket` and lets us iterate on the
credential flow independently.

**Modified: `web/src/dpf-adapter.ts`**

```typescript
class BatchPirClientAdapter {
  private credManager: CredentialManager | null;

  constructor(config: BatchPirConfig) {
    if (config.credentialMode === 'arc') {
      this.credManager = new ArcCredentialManager(config.authToken);
    }
  }

  async connect(): Promise<void> {
    // ... existing connect logic ...
    if (this.credManager) {
      await this.credManager.initialize();
    }
  }

  async queryBatch(scriptHashes, onProgress?, dbId?) {
    if (this.credManager) {
      const pres = await this.credManager.present();
      // attach pres to the first PIR frame, or send as a preamble
    }
    // ... existing query logic ...
  }
}
```

Same pattern for `HarmonyPirClientAdapter` and `OnionPirWebClient`.

### 1e. WASM bridge for ARC

ARC uses P-256 + SHAKE128 + algebraic MAC operations. These are not
trivial to implement in pure TypeScript. Two options:

**Option A: Compile the `arc` crate to WASM.** Add a
`pir-sdk-wasm/src/arc.rs` module that exposes `WasmArcCredential` and
`WasmArcPresentation` to JS. This is the cleanest path since the `arc`
crate is pure Rust with no native deps. Exposed API:

```typescript
// In sdk-bridge.ts
interface WasmArcCredential {
  limit(): number;
  nonce(): number;
  present(presCtx: Uint8Array): WasmArcPresentation;
  toBytes(): Uint8Array;
  static fromBytes(bytes: Uint8Array): WasmArcCredential;
}

interface WasmArcPresentation {
  nonce(): number;
  payload(): Uint8Array;
  tag(): Uint8Array;
}
```

**Option B: Port ARC crypto to pure TypeScript.** The `arc` crate is
~1500 lines. Porting P-256 operations, hash-to-curve (RFC 9380),
Schnorr proofs, and Pedersen range proofs to TS would be error-prone
and a maintenance burden. **Rejected.**

**Decision: Option A — compile `arc` to WASM.**

### 1f. Server-side: unified_server.rs changes

In the request dispatch loop, add a pre-handler check:

```rust
// Before dispatching to PIR handlers:
if req_type == REQ_CREDENTIAL_ISSUE {
    return handle_credential_issue(&mut verifier, &payload).await;
}
if server_config.require_credentials {
    // REQ_CREDENTIAL_PRESENT must precede every PIR batch
    let (pres_ctx, presentation) = decode_credential_present(&payload)?;
    verifier.verify_presentation(&presentation, &pres_ctx)?;
    // If verification passes, strip the credential prefix and fall
    // through to the PIR handler with the remaining payload
    return dispatch_pir_handler(stripped_payload).await;
}
```

Configurable via CLI flag: `--require-credentials arc` or
`--require-credentials cashu` or `--require-credentials any`.

---

## Phase 2: Cashu Blind Auth (NUT-22) integration

### 2a. Rust crate: `pir-cashu-auth`

```
pir-cashu-auth/
  Cargo.toml           → depends on secp256k1 (or k256), serde
  src/
    lib.rs             → re-exports
    bdhke.rs           → BDHKE blind signing (hash_to_curve, blind, sign, unblind, verify)
    bat.rs             → BAT minting, serialization, verification
    types.rs           → BlindAuthToken, AuthKeyset
```

Cashu's BDHKE is simpler than ARC — secp256k1 scalar multiplication and
hash-to-curve. The `cdk` crate exists but is heavy (full wallet + mint).
We only need the BDHKE + BAT primitives, which are ~300 lines of Rust.

### 2b. Server-side Cashu verifier

```rust
struct CashuAuthVerifier {
    auth_keyset: AuthKeyset,            // k (private), K = kG (public)
    spent_secrets: HashSet<[u8; 32]>,   // SHA256(secret) → seen
    bat_max_mint: u32,                  // max BATs per minting request
}

impl CashuAuthVerifier {
    fn handle_bat_mint(&self, blinded_messages: &[BlindedMessage], cat: &[u8]) -> Result<Vec<BlindSignature>>;
    fn verify_bat(&mut self, bat: &BlindAuthToken) -> Result<()>;
}
```

### 2c. Client-side: BAT management

`CashuCredentialManager` implements the same `CredentialManager`
interface but manages a pool of single-use BATs:

```typescript
class CashuCredentialManager implements CredentialManager {
  private bats: BlindAuthToken[];       // unspent BATs
  private presCtx: Uint8Array;

  async initialize(cat: Uint8Array): Promise<void> {
    // 1. Mint batch of BATs using CAT
    // 2. Store in memory
  }

  async present(): Promise<Uint8Array> {
    const bat = this.bats.pop();
    if (!bat) throw new Error("No BATs remaining — re-mint required");
    return serializeBat(bat);
  }

  get remaining(): number { return this.bats.length; }
}
```

The Cashu BDHKE operations (hash-to-curve, point arithmetic) are
lightweight enough to implement in pure TypeScript, using the Web Crypto
API or a minimal secp256k1 WASM module. No need for a full `cdk` crate
in the browser.

### 2d. BDHKE in TypeScript

Use `@noble/secp256k1` (already available via npm, pure JS, ~50KB) for:

```typescript
import { secp256k1 } from '@noble/curves/secp256k1';

function hashToCurve(secret: Uint8Array): Point { ... }
function blind(secret: Uint8Array, r: bigint): { blinded: Point; r: bigint } { ... }
function unblind(blindedSig: Point, r: bigint, pubkey: Point): Point { ... }
function verify(secret: Uint8Array, sig: Point, pubkey: Point): boolean { ... }
```

---

## Phase 3: Shared infrastructure

### 3a. CredentialManager interface (TS)

```typescript
// web/src/credential-manager.ts

export type CredentialMode = 'none' | 'arc' | 'cashu';

export interface CredentialManager {
  readonly mode: CredentialMode;
  readonly remaining: number;

  /** One-time setup: issue credential (ARC) or mint BATs (Cashu). */
  initialize(authPayload: Uint8Array): Promise<void>;

  /** Produce the bytes for a REQ_CREDENTIAL_PRESENT frame. */
  present(): Promise<Uint8Array>;

  /** Serialize state for persistence. */
  serialize(): Uint8Array;

  /** Restore from persisted state. */
  static deserialize(mode: CredentialMode, bytes: Uint8Array): CredentialManager;
}
```

### 3b. Adapter integration point

Each adapter gets a `credentialMode` option in its config:

```typescript
interface BatchPirConfig {
  server0Url: string;
  server1Url: string;
  // ... existing fields ...

  /** Anonymous rate limiting mode. */
  credentialMode?: CredentialMode;       // default: 'none'

  /** Auth payload for credential issuance:
   *  - ARC: opaque auth token (pre-shared key, payment hash, etc.)
   *  - Cashu: Clear Authentication Token (CAT) from OAuth
   */
  authPayload?: Uint8Array;

  /** Server URL for credential issuer (if different from PIR server). */
  credentialIssuerUrl?: string;
}
```

The `connect()` method in each adapter:
1. Opens WebSocket(s) as before
2. If `credentialMode !== 'none'`:
   a. Issue/recover credential from `credentialIssuerUrl`
   b. Store credential state
3. Proceed with existing attestation + catalog flow

The `queryBatch()` method in each adapter:
1. `credManager.present()` → presentation bytes
2. Send `REQ_CREDENTIAL_PRESENT` frame with presentation
3. If server responds `0x00` (valid), proceed with PIR query
4. If server responds otherwise, throw or disconnect

### 3c. Persistence

Both ARC credentials and Cashu BAT pools survive page reloads via
`localStorage`:

```typescript
const STORAGE_KEY = 'bitcoinpir.credential';

function persistCredential(manager: CredentialManager): void {
  const data = {
    mode: manager.mode,
    state: arrayBufferToBase64(manager.serialize()),
    savedAt: Date.now(),
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}

function restoreCredential(): CredentialManager | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  const data = JSON.parse(raw);
  return CredentialManager.deserialize(data.mode, base64ToArrayBuffer(data.state));
}
```

ARC credentials also persist their nonce counter. Cashu BATs persist the
unspent token pool. Both are encrypted at rest if the browser supports
`localStorage` encryption (or we can add a simple AEAD wrapper).

### 3d. UI integration

In `index.html`, add a small credential status indicator near the
connection status:

```
[Credential: ARC • 47/50 queries remaining]  [Re-issue]
[Credential: Cashu • 12 BATs remaining]      [Mint more]
```

When `remaining` drops below a threshold (e.g., 5), show a warning and
suggest re-issuance. When exhausted, block queries and prompt the user.

### 3e. Server configuration

New fields in the server config / CLI:

```
--require-credentials <arc|cashu|any>
    Require anonymous credentials for all PIR queries.
    'arc' — ARC presentations only
    'cashu' — Cashu BATs only
    'any' — accept either

--credential-issuer-key <path>
    Path to the credential issuer's long-lived key file (PEM or raw).
    For ARC: P-256 keypair. For Cashu: secp256k1 keypair.

--credential-auth-policy <path>
    Path to a TOML/JSON file defining the out-of-band auth policy
    (what auth_method values are accepted, what limits to assign).
```

---

## Implementation order

### Step 1: ARC WASM module (1-2 days)
- Add `pir-sdk-wasm/src/arc.rs` — WASM bindings for `arc` crate
- Expose `WasmArcCredential`, `WasmArcPresentation`
- Test with the `arc` crate's test vectors

### Step 2: Server-side ARC verifier (1 day)
- Add `REQ_CREDENTIAL_ISSUE` / `REQ_CREDENTIAL_PRESENT` protocol opcodes
- Implement `ArcVerifier` in `pir-runtime-core`
- Wire into `unified_server.rs` request dispatch
- Test with a Rust integration test

### Step 3: Client-side ARC (1 day)
- Implement `ArcCredentialManager` in `web/src/credential-manager.ts`
- Wire into `BatchPirClientAdapter` (DPF) as first backend
- End-to-end test: issue → query 50 times → verify exhaustion

### Step 4: Extend to all backends (0.5 day)
- Add `credentialMode` to `HarmonyPirClientAdapter`
- Add `credentialMode` to `OnionPirWebClient`
- UI indicator in `index.html`

### Step 5: Cashu Blind Auth (2 days)
- Implement BDHKE primitives in TS using `@noble/secp256k1`
- Implement `CashuCredentialManager`
- Implement server-side `CashuAuthVerifier`
- Wire into protocol handlers
- End-to-end test

### Step 6: Polish (1 day)
- localStorage persistence
- Re-issue flow (user-triggered + automatic when near exhaustion)
- UI polish: credential status, remaining counter, warning thresholds
- Server config: CLI flags, policy file format

**Total: ~7-8 days**

---

## Design decisions & trade-offs

### Why ARC first
- Already owned by the Bitcoin-PIR org (`arc` crate)
- IETF standard — citable, with test vectors
- Multi-show with cryptographic rate limiting is the stronger primitive
- Compiles to WASM cleanly (pure Rust, no native deps)

### Why both ARC and Cashu
- ARC gives cryptographic rate limiting with ZK presentations — best
  privacy, but requires WASM (~50KB) and P-256
- Cashu Blind Auth gives simpler crypto (BDHKE, secp256k1) and is already
  deployed in the Bitcoin ecash ecosystem — lower barrier, but requires
  periodic BAT re-minting
- Offering both lets the server operator choose their trust/UX trade-off

### Why at the transport layer, not in PIR
- Keeps PIR handlers unchanged
- Works across all three PIR backends with zero protocol changes
- Server can enforce rate limiting even if client chooses a different
  PIR backend mid-session
- The `PirTransport` trait already supports wrapping (see
  `SecureChannelTransport` in `channel.rs`)

### Why localStorage persistence
- Simpler than IndexedDB for small credential state (~200 bytes for ARC,
  ~1KB for a Cashu BAT pool of 50)
- Survives page reloads — critical for HarmonyPIR which already uses
  IndexedDB for hint persistence
- Can be upgraded to IndexedDB if BAT pools grow large

### What this does NOT cover
- The out-of-band auth policy (who gets credentials, why) is
  intentionally pluggable — it's the server operator's policy, not a
  protocol concern
- Payment integration for credential purchase is out of scope for the
  initial implementation
- Sybil resistance (one person obtaining multiple credentials) is not
  addressed — that requires the out-of-band auth layer to enforce
  uniqueness (e.g., phone verification, government ID, etc.)
