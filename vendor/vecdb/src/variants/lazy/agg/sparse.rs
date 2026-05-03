use crate::{AggFold, ReadableVec, VecIndex, VecValue};

/// Sparse aggregation: emits `Option<T>` per output index.
///
/// `Some(last_value)` when the range contains source elements,
/// `None` when the range is empty.
pub struct Sparse;

impl<T: VecValue, SI: VecIndex> AggFold<Option<T>, SI, SI, T> for Sparse {
    #[inline]
    fn try_fold<S: ReadableVec<SI, T> + ?Sized, B, E, F: FnMut(B, Option<T>) -> Result<B, E>>(
        source: &S,
        mapping: &[SI],
        from: usize,
        to: usize,
        init: B,
        mut f: F,
    ) -> Result<B, E> {
        let source_len = source.len();

        let mut indices: Vec<usize> = Vec::with_capacity(to - from);
        let mut slot_map: Vec<Option<u32>> = Vec::with_capacity(to - from);

        (from..to).for_each(|idx| {
            let current_first = mapping[idx].to_usize();
            let next_first = mapping
                .get(idx + 1)
                .map(|h| h.to_usize())
                .unwrap_or(source_len);

            if next_first == 0 || current_first >= next_first {
                slot_map.push(None);
            } else {
                slot_map.push(Some(indices.len() as u32));
                indices.push(next_first - 1);
            }
        });

        let values = source.read_sorted_at(&indices);

        slot_map.iter().try_fold(init, |acc, slot| match slot {
            None => f(acc, None),
            &Some(vi) => f(acc, Some(values[vi as usize].clone())),
        })
    }

    #[inline]
    fn collect_one<S: ReadableVec<SI, T> + ?Sized>(
        source: &S,
        mapping: &[SI],
        index: usize,
    ) -> Option<Option<T>> {
        let source_len = source.len();
        let current_first = mapping[index].to_usize();
        let next_first = mapping
            .get(index + 1)
            .map(|h| h.to_usize())
            .unwrap_or(source_len);

        if next_first == 0 || current_first >= next_first {
            return Some(None);
        }
        Some(source.collect_one_at(next_first - 1))
    }
}

