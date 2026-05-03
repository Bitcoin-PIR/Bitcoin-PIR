use pco::data_types::Number;

pub trait TransparentPco<T> {}

pub trait Pco
where
    Self: TransparentPco<Self::NumberType>,
{
    type NumberType: Number;
}
