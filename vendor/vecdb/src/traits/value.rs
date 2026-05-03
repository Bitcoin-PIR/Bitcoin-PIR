use std::fmt::Debug;

/// Marker trait for types that can be stored as values in a vector.
///
/// This trait is automatically implemented for any type that satisfies the
/// required bounds. No manual implementation is needed.
pub trait VecValue
where
    Self: Sized + Debug + Clone + Send + Sync + 'static,
{
}

impl<T> VecValue for T where T: Sized + Debug + Clone + Send + Sync + 'static {}
