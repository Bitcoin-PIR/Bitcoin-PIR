/**
 * Test-only BOLT11 WASM double for the local browser concurrency suite.
 *
 * The production acquisition controller is exercised unchanged. Vite aliases
 * only that controller's sdk-bridge import to this module in
 * `vite.payment-test.config.ts`; production builds never include this file.
 */

const QUOTE_ID_HEX = '66'.repeat(32);
const INVOICE = 'lnbc1browserrecoveryfixture';

export class FakeBolt11AcquisitionV1 {
  private freed = false;

  constructor(
    private hasQuote = false,
    private settled = false,
    private claimMarker = 0,
  ) {}

  static restore(state: Uint8Array): FakeBolt11AcquisitionV1 {
    if (!(state instanceof Uint8Array)
        || state.length !== 4
        || state[0] !== 1
        || state[1] > 1
        || state[2] > 1) {
      throw new Error('invalid fake BOLT11 recovery state');
    }
    return new FakeBolt11AcquisitionV1(state[1] === 1, state[2] === 1, state[3]);
  }

  free(): void {
    this.freed = true;
  }

  quote_intent_bytes(): Uint8Array {
    this.requireLive();
    return new Uint8Array([1, 2]);
  }

  quote_key_checkpoint_bytes(): Uint8Array {
    this.requireLive();
    return new Uint8Array([7, 7]);
  }

  recovery_state_bytes(): Uint8Array {
    this.requireLive();
    return new Uint8Array([
      1,
      this.hasQuote ? 1 : 0,
      this.settled ? 1 : 0,
      this.claimMarker,
    ]);
  }

  accept_initial_quote(bytes: Uint8Array): void {
    this.requireLive();
    requireBytes(bytes, [2], 'initial quote');
    this.hasQuote = true;
  }

  invoice(): string {
    this.requireLive();
    if (!this.hasQuote) throw new Error('quote is not installed');
    return INVOICE;
  }

  quote_id_hex(): string {
    this.requireLive();
    return QUOTE_ID_HEX;
  }

  quote_status(): 'invoice-open' | 'payment-settled' {
    this.requireLive();
    return this.settled ? 'payment-settled' : 'invoice-open';
  }

  invoice_expires_at_unix(): string {
    this.requireLive();
    return '9999999999';
  }

  claim_deadline_unix(): string {
    this.requireLive();
    return '9999999999';
  }

  build_status_request(): Uint8Array {
    this.requireLive();
    return new Uint8Array([3, 4]);
  }

  accept_status(bytes: Uint8Array): void {
    this.requireLive();
    requireBytes(bytes, [3], 'status');
    this.settled = true;
  }

  prepare_claim(): Uint8Array {
    this.requireLive();
    if (!this.settled) throw new Error('payment is not settled');
    if (this.claimMarker === 0) this.claimMarker = 9;
    return new Uint8Array([8, this.claimMarker]);
  }

  finish_claim(bytes: Uint8Array): {
    readonly scheme: 'bolt11-direct-receipt';
    count(): number;
    capability(index: number): Uint8Array;
    free(): void;
  } {
    this.requireLive();
    requireBytes(bytes, [4], 'issuance response');
    return {
      scheme: 'bolt11-direct-receipt',
      count: () => 1,
      capability: (index) => {
        if (index !== 0) throw new Error('capability index is out of range');
        return new Uint8Array([10, 11]);
      },
      free: () => undefined,
    };
  }

  private requireLive(): void {
    if (this.freed) throw new Error('fake BOLT11 handle was freed');
  }
}

const sdk = {
  initial_bolt11_quote_key_checkpoint_v1: () => new Uint8Array([1]),
  WasmBolt11AcquisitionV1: FakeBolt11AcquisitionV1,
};

export function requireSdkWasm(): typeof sdk {
  return sdk;
}

function requireBytes(actual: Uint8Array, expected: number[], label: string): void {
  if (actual.length !== expected.length
      || actual.some((byte, index) => byte !== expected[index])) {
    throw new Error(`unexpected ${label} bytes`);
  }
}
