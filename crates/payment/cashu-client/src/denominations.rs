//! Deterministically bounded exact-denomination selection.

use std::collections::{BTreeMap, BTreeSet};

use pir_service_protocol::{
    StandardCashuMintManifestV1, MAX_CASHU_DENOMINATION_KEYS, MAX_SERVICE_VALUE_V1,
    MAX_STANDARD_CASHU_PROOFS_V1,
};

use crate::CashuClientErrorV1;

/// Maximum distinct reachable sums retained by the exact solver.
pub const MAX_CASHU_DENOMINATION_SOLVER_STATES_V1: usize = 65_536;
/// Maximum denomination edges examined by the exact solver.
pub const MAX_CASHU_DENOMINATION_SOLVER_TRANSITIONS_V1: usize = 1_000_000;

#[derive(Clone, Copy)]
struct SolverLimitsV1 {
    max_outputs: usize,
    max_states: usize,
    max_transitions: usize,
}

const DEFAULT_SOLVER_LIMITS_V1: SolverLimitsV1 = SolverLimitsV1 {
    max_outputs: MAX_STANDARD_CASHU_PROOFS_V1,
    max_states: MAX_CASHU_DENOMINATION_SOLVER_STATES_V1,
    max_transitions: MAX_CASHU_DENOMINATION_SOLVER_TRANSITIONS_V1,
};

/// Select denominations whose sum is exactly `value`.
///
/// The signed manifest is validated before use. A greedy exact solution is a
/// fast path only; otherwise a breadth-first search exhausts every distinct
/// reachable sum up to the proof-count bound. Complexity exhaustion is
/// reported separately from a proved absence of an exact bounded solution.
pub fn solve_cashu_output_denominations_v1(
    manifest: &StandardCashuMintManifestV1,
    value: u64,
) -> Result<Vec<u64>, CashuClientErrorV1> {
    manifest
        .encode()
        .map_err(|_| CashuClientErrorV1::InvalidManifest)?;
    let denominations = manifest
        .active_output_keyset
        .keys
        .iter()
        .map(|key| key.amount)
        .collect::<Vec<_>>();
    solve_denominations_with_limits_v1(&denominations, value, DEFAULT_SOLVER_LIMITS_V1)
}

fn solve_denominations_with_limits_v1(
    denominations: &[u64],
    value: u64,
    limits: SolverLimitsV1,
) -> Result<Vec<u64>, CashuClientErrorV1> {
    if value == 0 || value > MAX_SERVICE_VALUE_V1 {
        return Err(CashuClientErrorV1::InvalidOutputMaterial);
    }
    if denominations.is_empty()
        || denominations.len() > MAX_CASHU_DENOMINATION_KEYS
        || limits.max_outputs == 0
        || limits.max_outputs > MAX_STANDARD_CASHU_PROOFS_V1
        || limits.max_states == 0
        || limits.max_transitions == 0
    {
        return Err(CashuClientErrorV1::InvalidManifest);
    }

    let mut ascending = denominations.to_vec();
    ascending.sort_unstable();
    if ascending[0] == 0 || ascending.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CashuClientErrorV1::InvalidManifest);
    }
    if value % ascending.iter().copied().reduce(gcd_v1).unwrap_or(1) != 0 {
        return Err(CashuClientErrorV1::NoExactDenominationSolution);
    }

    let descending = ascending.iter().rev().copied().collect::<Vec<_>>();
    if let Some(solution) = exact_greedy_fast_path_v1(&descending, value, limits.max_outputs) {
        return Ok(solution);
    }

    // Positive denominations make a previously reached sum with more coins
    // strictly dominated by its shortest path. Thus one predecessor per sum
    // is sufficient for exhaustive breadth-first search by proof count.
    let mut parents = BTreeMap::<u64, (u64, u64)>::new();
    let mut frontier = BTreeSet::from([0u64]);
    let mut retained_states = 1usize;
    let mut transitions = 0usize;

    for _ in 0..limits.max_outputs {
        let mut next_frontier = BTreeSet::new();
        for previous_sum in frontier {
            for denomination in &descending {
                transitions = transitions
                    .checked_add(1)
                    .ok_or(CashuClientErrorV1::DenominationSearchLimitExceeded)?;
                if transitions > limits.max_transitions {
                    return Err(CashuClientErrorV1::DenominationSearchLimitExceeded);
                }
                let Some(next_sum) = previous_sum.checked_add(*denomination) else {
                    continue;
                };
                if next_sum > value || parents.contains_key(&next_sum) {
                    continue;
                }
                retained_states = retained_states
                    .checked_add(1)
                    .ok_or(CashuClientErrorV1::DenominationSearchLimitExceeded)?;
                if retained_states > limits.max_states {
                    return Err(CashuClientErrorV1::DenominationSearchLimitExceeded);
                }
                parents.insert(next_sum, (previous_sum, *denomination));
                if next_sum == value {
                    return reconstruct_solution_v1(&parents, value, limits.max_outputs);
                }
                next_frontier.insert(next_sum);
            }
        }
        if next_frontier.is_empty() {
            break;
        }
        frontier = next_frontier;
    }

    Err(CashuClientErrorV1::NoExactDenominationSolution)
}

fn exact_greedy_fast_path_v1(
    descending: &[u64],
    value: u64,
    max_outputs: usize,
) -> Option<Vec<u64>> {
    let mut remaining = value;
    let mut solution = Vec::new();
    for denomination in descending {
        while remaining >= *denomination && solution.len() < max_outputs {
            solution.push(*denomination);
            remaining -= *denomination;
        }
    }
    (remaining == 0 && !solution.is_empty()).then_some(solution)
}

fn reconstruct_solution_v1(
    parents: &BTreeMap<u64, (u64, u64)>,
    value: u64,
    max_outputs: usize,
) -> Result<Vec<u64>, CashuClientErrorV1> {
    let mut current = value;
    let mut solution = Vec::new();
    while current != 0 {
        let (previous, denomination) = parents
            .get(&current)
            .copied()
            .ok_or(CashuClientErrorV1::NoExactDenominationSolution)?;
        solution.push(denomination);
        if solution.len() > max_outputs || previous >= current {
            return Err(CashuClientErrorV1::NoExactDenominationSolution);
        }
        current = previous;
    }
    solution.sort_unstable_by(|left, right| right.cmp(left));
    let exact_sum = solution
        .iter()
        .try_fold(0u64, |sum, amount| sum.checked_add(*amount));
    if exact_sum != Some(value) {
        return Err(CashuClientErrorV1::NoExactDenominationSolution);
    }
    Ok(solution)
}

fn gcd_v1(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_search_finds_solution_missed_by_greedy() {
        let solution =
            solve_denominations_with_limits_v1(&[4, 6], 8, DEFAULT_SOLVER_LIMITS_V1).unwrap();
        assert_eq!(solution, vec![4, 4]);
    }

    #[test]
    fn duplicate_denominations_are_rejected() {
        assert_eq!(
            solve_denominations_with_limits_v1(&[1, 1, 2], 4, DEFAULT_SOLVER_LIMITS_V1),
            Err(CashuClientErrorV1::InvalidManifest)
        );
    }

    #[test]
    fn gcd_proves_no_exact_solution() {
        assert_eq!(
            solve_denominations_with_limits_v1(&[4, 6], 7, DEFAULT_SOLVER_LIMITS_V1),
            Err(CashuClientErrorV1::NoExactDenominationSolution)
        );
    }

    #[test]
    fn proof_count_bound_is_enforced() {
        assert_eq!(
            solve_denominations_with_limits_v1(&[1], 65, DEFAULT_SOLVER_LIMITS_V1),
            Err(CashuClientErrorV1::NoExactDenominationSolution)
        );
    }

    #[test]
    fn exact_solution_is_sorted_and_bounded() {
        let solution =
            solve_denominations_with_limits_v1(&[1, 5, 10, 25], 41, DEFAULT_SOLVER_LIMITS_V1)
                .unwrap();
        assert_eq!(solution.iter().sum::<u64>(), 41);
        assert!(solution.len() <= MAX_STANDARD_CASHU_PROOFS_V1);
        assert!(solution.windows(2).all(|pair| pair[0] >= pair[1]));
    }

    #[test]
    fn malicious_input_size_is_rejected_before_search() {
        let denominations = (1..=MAX_CASHU_DENOMINATION_KEYS as u64 + 1).collect::<Vec<_>>();
        assert_eq!(
            solve_denominations_with_limits_v1(&denominations, 100, DEFAULT_SOLVER_LIMITS_V1),
            Err(CashuClientErrorV1::InvalidManifest)
        );
    }

    #[test]
    fn complexity_exhaustion_is_not_reported_as_no_solution() {
        let limits = SolverLimitsV1 {
            max_outputs: MAX_STANDARD_CASHU_PROOFS_V1,
            max_states: 2,
            max_transitions: 2,
        };
        assert_eq!(
            solve_denominations_with_limits_v1(&[2, 3], 7, limits),
            Err(CashuClientErrorV1::DenominationSearchLimitExceeded)
        );
    }
}
