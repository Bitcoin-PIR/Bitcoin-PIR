use crate::{
    ImportableVec, ReadableCloneableVec, ReadableVec, TypedVec, VecIndex, VecValue, WritableVec,
};

/// Super trait combining all common stored vec traits.
pub trait StoredVec:
    ImportableVec + TypedVec + WritableVec<Self::I, Self::T> + ReadableCloneableVec<Self::I, Self::T>
where
    Self::I: VecIndex,
    Self::T: VecValue,
{
    /// The concrete lean read-only type returned by [`read_only_clone`](StoredVec::read_only_clone).
    type ReadOnly: ReadableVec<Self::I, Self::T> + Clone + 'static;

    /// Creates a lean read-only clone that only carries fields needed for disk reads.
    fn read_only_clone(&self) -> Self::ReadOnly;
}
