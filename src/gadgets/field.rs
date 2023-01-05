use super::traits::IsWitness;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;

impl<F: Field + PrimeField> IsWitness<F> for FpVar<F> {
    fn is_witness(&self) -> anyhow::Result<bool>
    where
        Self: ark_r1cs_std::ToBytesGadget<F>,
    {
        if let FpVar::Var(v) = self {
            Ok(v.variable.is_witness())
        } else {
            Ok(false)
        }
    }
}
