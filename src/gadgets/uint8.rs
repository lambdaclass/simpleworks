use super::ToFieldElements;
use super::UInt8Gadget;
use anyhow::Result;
use ark_ff::Field;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::ToBitsGadget;

impl<F: Field> ToFieldElements<F> for UInt8Gadget {
    fn to_field_elements(&self) -> Result<Vec<F>> {
        let bits_le = self.to_bits_le()?;
        let mut result = Vec::with_capacity(8);
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
