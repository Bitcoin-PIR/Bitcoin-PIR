package com.bitcoinpir.placement;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * PBC (Probabilistic Batch Codes) cuckoo placement for round planning.
 * Ports planRounds / cuckooPlace from web/src/pbc.ts.
 *
 * Each query has NUM_HASHES candidate groups. We pack as many queries as
 * possible into each round (one query per group), using cuckoo-style
 * eviction to maximize utilization.
 */
public final class PbcPlanner {
    private PbcPlanner() {}

    private static final int MAX_KICKS = 500;

    /**
     * Plan query rounds for batch PIR.
     *
     * @param itemGroups  itemGroups[i] = candidate group indices for item i
     * @param numGroups   total number of groups (K or K_CHUNK)
     * @return list of rounds; each round is a list of [itemIndex, groupId] pairs
     */
    public static List<int[][]> planRounds(int[][] itemGroups, int numGroups) {
        List<Integer> remaining = new ArrayList<>();
        for (int i = 0; i < itemGroups.length; i++) {
            remaining.add(i);
        }

        List<int[][]> rounds = new ArrayList<>();

        while (!remaining.isEmpty()) {
            int[] groupOwner = new int[numGroups];
            Arrays.fill(groupOwner, -1);

            List<Integer> placedLocal = new ArrayList<>();
            int[][] candGroups = new int[remaining.size()][];
            for (int li = 0; li < remaining.size(); li++) {
                candGroups[li] = itemGroups[remaining.get(li)];
            }

            for (int li = 0; li < candGroups.length; li++) {
                if (placedLocal.size() >= numGroups) break;

                int[] saved = Arrays.copyOf(groupOwner, numGroups);
                if (cuckooPlace(candGroups, groupOwner, li, numGroups)) {
                    placedLocal.add(li);
                } else {
                    System.arraycopy(saved, 0, groupOwner, 0, numGroups);
                }
            }

            // Build round entries
            List<int[]> roundEntries = new ArrayList<>();
            for (int b = 0; b < numGroups; b++) {
                if (groupOwner[b] >= 0) {
                    int localIdx = groupOwner[b];
                    roundEntries.add(new int[]{remaining.get(localIdx), b});
                }
            }

            if (roundEntries.isEmpty()) {
                // Could not place any items — give up to avoid infinite loop
                break;
            }

            // Remove placed items from remaining
            Set<Integer> placedOrigIdx = new HashSet<>();
            for (int li : placedLocal) {
                placedOrigIdx.add(remaining.get(li));
            }
            remaining.removeIf(placedOrigIdx::contains);

            rounds.add(roundEntries.toArray(new int[0][]));
        }

        return rounds;
    }

    /**
     * Try to place item {@code qi} into the group assignment, using cuckoo eviction.
     *
     * @param candGroups   candidate groups for all local items
     * @param groups       current assignment (group → local item index, -1 = empty)
     * @param qi           local item index to place
     * @param numGroups    total number of groups
     * @return true if placed successfully
     */
    private static boolean cuckooPlace(int[][] candGroups, int[] groups, int qi, int numGroups) {
        int current = qi;

        for (int kick = 0; kick < MAX_KICKS; kick++) {
            int[] cands = candGroups[current];

            // Try to find an empty group
            for (int group : cands) {
                if (groups[group] < 0) {
                    groups[group] = current;
                    return true;
                }
            }

            // Evict a random occupant from one of our candidate groups
            int evictGroup = cands[kick % cands.length];
            int evicted = groups[evictGroup];
            groups[evictGroup] = current;
            current = evicted;
        }

        return false;
    }
}
