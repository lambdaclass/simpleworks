use super::traits::ToFieldElements;
use anyhow::Result;
use ark_ff::Field;
use ark_r1cs_std::{uint128::UInt128, R1CSVar};

impl<F: Field> ToFieldElements<F> for UInt128<F> {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let bits_le = self.to_bits_le();
        let mut result = Vec::with_capacity(128);
        for boolean_gadget_value in bits_le.iter() {
            if boolean_gadget_value.value()? {
                result.push(F::one())
            } else {
                result.push(F::zero())
            }
        }

        Ok(result)
    }
}