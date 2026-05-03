use std::collections::BTreeMap;

use crate::StoredVec;

/// Trait for creating read-only clones of composite types.
///
/// For stored vecs, delegates to [`StoredVec::read_only_clone`].
/// For containers (Option, BTreeMap, cohort groups), propagates to inner types.
/// For Traversable-derived types with `M: StorageMode`, the derive macro
/// generates an impl that maps `Self<Rw>` → `Self<Ro>`.
pub trait ReadOnlyClone {
    type ReadOnly;
    fn read_only_clone(&self) -> Self::ReadOnly;
}

// --- Blanket impl for all StoredVec types ---

impl<V: StoredVec> ReadOnlyClone for V {
    type ReadOnly = V::ReadOnly;

    #[inline]
    fn read_only_clone(&self) -> V::ReadOnly {
        <V as StoredVec>::read_only_clone(self)
    }
}

// --- Option ---

impl<T: ReadOnlyClone> ReadOnlyClone for Option<T> {
    type ReadOnly = Option<T::ReadOnly>;

    #[inline]
    fn read_only_clone(&self) -> Option<T::ReadOnly> {
        self.as_ref().map(ReadOnlyClone::read_only_clone)
    }
}

// --- Array ---

impl<T: ReadOnlyClone, const N: usize> ReadOnlyClone for [T; N] {
    type ReadOnly = [T::ReadOnly; N];

    fn read_only_clone(&self) -> [T::ReadOnly; N] {
        self.each_ref().map(ReadOnlyClone::read_only_clone)
    }
}

// --- BTreeMap ---

impl<K: Clone + Ord, V: ReadOnlyClone> ReadOnlyClone for BTreeMap<K, V> {
    type ReadOnly = BTreeMap<K, V::ReadOnly>;

    fn read_only_clone(&self) -> BTreeMap<K, V::ReadOnly> {
        self.iter()
            .map(|(k, v)| (k.clone(), v.read_only_clone()))
            .collect()
    }
}
