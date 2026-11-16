import type { DatabaseProofPin } from '../../db-proof.js';

/** Archived native V2 delta, independent of the active ORAM catalog. */
export const HISTORICAL_ORAM_DELTA_PIN: DatabaseProofPin = {
  dbId: 1,
  buildKind: 'delta',
  fromHeight: 940611,
  height: 948454,
  fromBlockHashHex: '000000000000000000002c41243b3d74d135942031ef15f547bca1ce8f85eb99',
  fromMuhashHex: 'aebb29df12e045ef5279036263aba3b8f8e9e816e05b04a58f57e63b3b25756b',
  blockHashHex: '00000000000000000001ef683c02c383315db7e917c69d20f79e05985560a4e4',
  muhashHex: 'cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee',
  bucketSuperRootHex: 'e2ba2eee6788424309a95f771893d5401cc8e3ceec6188dc2708900e211a910a',
  onionSuperRootHex: 'f86baa3966a61cdcd70d8c0ad9bed233f591806eb351db2ae35ac0192a3fe997',
  paramsHashHex: 'fe6f516696bafaa2226cc1bdc7888c7c69dd263a84817dd0f18cf8027123c45d',
  networkMagicHex: 'f9beb4d9',
  builderBinarySha256Hex: 'cf973a833f9b892743e451da4c2937c82865b12d8901c48ac4483b5e0696ba6f',
  builderGitCommit: '8d9d21a6be560236cb666269cf1f93a3de53bb1f',
  onionEntrySize: 3_328,
  proofVersion: 2,
  onionTotalPackedEntries: 116_030,
  onionIndexBinsPerTable: 965,
  onionChunkBinsPerTable: 4_792,
  onionIndexSlotsPerBin: 221,
  onionIndexSlotSize: 15,
};
