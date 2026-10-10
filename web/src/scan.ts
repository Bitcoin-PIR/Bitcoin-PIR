/**
 * Scan an OnionPIR index result for a matching tag.
 *
 * OnionPIR slot layout: [8B tag LE][4B entryId LE][2B byteOffset LE][1B numEntries]
 * 15 bytes per slot, 256 slots per bin = 3840B.
 *
 * @param data       - Raw bin bytes
 * @param expectedTag - 8-byte tag as bigint
 * @param slotsPerBin - Number of slots (e.g. 256 for OnionPIR index)
 * @param slotSize    - Bytes per slot (e.g. 15 for OnionPIR)
 */
export function findEntryInOnionPirIndexResult(
  data: Uint8Array,
  expectedTag: bigint,
  slotsPerBin: number,
  slotSize: number,
): { entryId: number; byteOffset: number; numEntries: number } | null {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  for (let slot = 0; slot < slotsPerBin; slot++) {
    const off = slot * slotSize;
    if (off + slotSize > data.length) break;
    const slotTag = dv.getBigUint64(off, true);
    if (slotTag === expectedTag && slotTag !== 0n) {
      return {
        entryId: dv.getUint32(off + 8, true),
        byteOffset: dv.getUint16(off + 12, true),
        numEntries: data[off + 14],
      };
    }
  }
  return null;
}
