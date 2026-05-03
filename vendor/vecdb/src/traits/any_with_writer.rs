use crate::{AnyReadableVec, Formattable, ReadableVec, TypedVec, ValueWriter, VecIteratorWriter};

pub trait AnyVecWithWriter: AnyReadableVec {
    /// Create a value writer that can be advanced row by row
    fn create_writer(&self, from: Option<i64>, to: Option<i64>) -> Box<dyn ValueWriter + '_>;
}

impl<V> AnyVecWithWriter for V
where
    V: TypedVec,
    V: ReadableVec<V::I, V::T>,
    V::T: Formattable,
{
    fn create_writer(&self, from: Option<i64>, to: Option<i64>) -> Box<dyn ValueWriter + '_> {
        let from_usize = from.map(|i| self.i64_to_usize(i)).unwrap_or(0);
        let to_usize = to
            .map(|i| self.i64_to_usize(i))
            .unwrap_or_else(|| self.len());

        let values = self.collect_range_at(from_usize, to_usize);
        Box::new(VecIteratorWriter {
            iter: values.into_iter(),
        })
    }
}
