use super::traits::IsWitness;
use ark_ff::Field;
use ark_r1cs_std::prelude::Boolean;

impl<F: Field> IsWitness<F> for Boolean<F> {
    fn is_witness(&self) -> anyhow::Result<bool>
        where
            Self: ark_r1cs_std::ToBytesGadget<F>, {
        if let ark_r1cs_std::prelude::Boolean::Is(bool)
        | ark_r1cs_std::prelude::Boolean::Not(bool) = self
        {
            Ok(bool.variable().is_witness())
        } else {
            Ok(false)
        }
    }
}
