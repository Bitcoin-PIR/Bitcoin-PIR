use schemars::{JsonSchema, Schema, SchemaGenerator};

use crate::{AnyVec, TypedVec};

/// Trait for vectors whose value type implements JsonSchema.
/// Provides access to the JSON Schema of the value type.
pub trait AnyVecWithSchema: AnyVec {
    /// Returns the JSON Schema for the value type.
    fn value_schema(&self) -> Schema;
}

impl<V> AnyVecWithSchema for V
where
    V: TypedVec,
    V::T: JsonSchema,
{
    fn value_schema(&self) -> Schema {
        V::T::json_schema(&mut SchemaGenerator::default())
    }
}
