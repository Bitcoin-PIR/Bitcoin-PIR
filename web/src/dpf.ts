/**
 * DPF wrapper for libdpf.
 *
 * DPF domain exponent (dpf_n) is passed as a parameter rather than
 * hardcoded, since different databases have different sizes.
 */

import { Dpf } from 'libdpf';

export interface DpfKeyPair {
  key0: Uint8Array;
  key1: Uint8Array;
}

const dpf = Dpf.withDefaultKey();

/**
 * Generate DPF keys for a specific index in the 2^dpf_n domain.
 * Returns (key0_for_server0, key1_for_server1).
 *
 * @param index - The target bin index
 * @param dpfN - DPF domain exponent (computed from bins_per_table)
 */
export async function genDpfKeys(index: number, dpfN: number): Promise<DpfKeyPair> {
  const [k0, k1] = await dpf.gen(BigInt(index), dpfN);
  return {
    key0: k0.toBytes(),
    key1: k1.toBytes(),
  };
}
