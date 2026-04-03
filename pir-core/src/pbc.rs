//! PBC (Probabilistic Batch Code) cuckoo placement and multi-round planning.
//!
//! Used by both the build pipeline (assigning items to cuckoo tables) and
//! clients (planning which chunk queries go in which round).

/// Cuckoo-place item `qi` into one of its candidate buckets with eviction.
/// Returns true if placed, false if `max_kicks` exceeded.
///
/// `cand_buckets[qi]` must yield the candidate bucket indices for item `qi`.
pub fn pbc_cuckoo_place<C: AsRef<[usize]>>(
    cand_buckets: &[C],
    buckets: &mut [Option<usize>],
    qi: usize,
    max_kicks: usize,
    num_hashes: usize,
) -> bool {
    let cands = cand_buckets[qi].as_ref();
    for &c in cands {
        if buckets[c].is_none() {
            buckets[c] = Some(qi);
            return true;
        }
    }

    let mut current_qi = qi;
    let mut current_bucket = cands[0];

    for kick in 0..max_kicks {
        let evicted_qi = buckets[current_bucket].unwrap();
        buckets[current_bucket] = Some(current_qi);
        let ev_cands = cand_buckets[evicted_qi].as_ref();

        for offset in 0..num_hashes {
            let c = ev_cands[(kick + offset) % num_hashes];
            if c == current_bucket {
                continue;
            }
            if buckets[c].is_none() {
                buckets[c] = Some(evicted_qi);
                return true;
            }
        }

        let mut next_bucket = ev_cands[0];
        for offset in 0..num_hashes {
            let c = ev_cands[(kick + offset) % num_hashes];
            if c != current_bucket {
                next_bucket = c;
                break;
            }
        }
        current_qi = evicted_qi;
        current_bucket = next_bucket;
    }

    false
}

/// Plan multi-round PBC placement for items with candidate buckets.
/// Returns rounds, each round is a `Vec<(item_index, bucket_id)>`.
pub fn pbc_plan_rounds<C: AsRef<[usize]> + Clone>(
    item_buckets: &[C],
    num_buckets: usize,
    num_hashes: usize,
    max_kicks: usize,
) -> Vec<Vec<(usize, usize)>> {
    let mut remaining: Vec<usize> = (0..item_buckets.len()).collect();
    let mut rounds = Vec::new();

    while !remaining.is_empty() {
        let round_cands: Vec<C> = remaining.iter().map(|&i| item_buckets[i].clone()).collect();
        let mut bucket_owner: Vec<Option<usize>> = vec![None; num_buckets];
        let mut placed_local = Vec::new();

        for li in 0..round_cands.len() {
            if placed_local.len() >= num_buckets {
                break;
            }
            let saved = bucket_owner.clone();
            if pbc_cuckoo_place(&round_cands, &mut bucket_owner, li, max_kicks, num_hashes) {
                placed_local.push(li);
            } else {
                bucket_owner = saved;
            }
        }

        let mut round_entries = Vec::new();
        for b in 0..num_buckets {
            if let Some(local_idx) = bucket_owner[b] {
                round_entries.push((remaining[local_idx], b));
            }
        }

        if round_entries.is_empty() {
            eprintln!(
                "PBC placement: could not place any items, {} remaining",
                remaining.len()
            );
            break;
        }

        let placed_orig: Vec<usize> = placed_local.iter().map(|&li| remaining[li]).collect();
        remaining.retain(|idx| !placed_orig.contains(idx));
        rounds.push(round_entries);
    }

    rounds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbc_cuckoo_place_simple() {
        // 3 items, 5 buckets, each item has 2 candidate buckets
        let cands: Vec<Vec<usize>> = vec![
            vec![0, 1],
            vec![1, 2],
            vec![2, 3],
        ];
        let mut buckets = vec![None; 5];

        assert!(pbc_cuckoo_place(&cands, &mut buckets, 0, 100, 2));
        assert!(pbc_cuckoo_place(&cands, &mut buckets, 1, 100, 2));
        assert!(pbc_cuckoo_place(&cands, &mut buckets, 2, 100, 2));

        // All items placed
        let placed: Vec<usize> = buckets.iter().filter_map(|&x| x).collect();
        assert_eq!(placed.len(), 3);
    }

    #[test]
    fn test_pbc_plan_rounds() {
        // 5 items, 3 buckets — needs at least 2 rounds
        let cands: Vec<Vec<usize>> = vec![
            vec![0, 1],
            vec![1, 2],
            vec![0, 2],
            vec![0, 1],
            vec![1, 2],
        ];

        let rounds = pbc_plan_rounds(&cands, 3, 2, 100);
        assert!(rounds.len() >= 2);

        // All items should be placed
        let mut all_items: Vec<usize> = rounds.iter().flat_map(|r| r.iter().map(|&(i, _)| i)).collect();
        all_items.sort();
        assert_eq!(all_items, vec![0, 1, 2, 3, 4]);
    }
}
