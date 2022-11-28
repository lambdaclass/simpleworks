use anyhow::Result;
use ark_ff::Field;

pub trait ToFieldElements<F: Field> {
    fn to_field_elements(&self) -> Result<Vec<F>>;
}
