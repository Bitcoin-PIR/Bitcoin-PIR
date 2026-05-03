use crate::{ReadableVec, StoredVec};

/// Marker trait that selects between read-write and read-only storage.
///
/// Composite types use `M::Stored<V>` for stored vec fields.
/// When `M = Rw`, the field is `V` itself (identity) with full write access.
/// When `M = Ro`, the field is `V::ReadOnly` — a lean read-only clone (~40-48 bytes).
pub trait StorageMode: 'static {
    type Stored<V: StoredVec + 'static>: ReadableVec<V::I, V::T> + 'static;
}

/// Read-write mode. `Stored<V>` is the identity — the full read-write vec.
pub struct Rw;

impl StorageMode for Rw {
    type Stored<V: StoredVec + 'static> = V;
}

/// Read-only mode. `Stored<V>` is `V::ReadOnly` — a lean clone for disk reads.
pub struct Ro;

impl StorageMode for Ro {
    type Stored<V: StoredVec + 'static> = V::ReadOnly;
}
